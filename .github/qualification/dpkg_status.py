"""Qualify installed Debian metadata against the actual package outputs."""

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
from urllib.parse import unquote, urlparse

BASE = "15f9fc8d39ba3178c313e61d94feb3f6eb88f95f"
PRODUCT = "0d9d0d0f4500b3111ae0c2509c1d359b8fad61d1"
ROOT = Path.cwd()
SMOKE = ROOT / "e2e/smoke"
WORK = Path(os.environ["RUNNER_TEMP"]) / "dpkg-status"
PUBLIC = WORK / "public"
PUBLIC.mkdir(parents=True, exist_ok=True)
REPORT = {"source": PRODUCT, "base": BASE, "phases": {}, "started": time.time()}
CHANGED = subprocess.check_output(["git", "diff", "--name-only", BASE, PRODUCT], text=True).splitlines()
RESTORE = ["apt/private/translate_dependency_set.bzl", "apt/private/dpkg_status.bzl"]
REPOS = ["status_packages", "status_custom", "status_repacked"]


def command(args: list[str], cwd: Path, name: str) -> subprocess.CompletedProcess:
    result = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (WORK / (name + ".log")).write_text(result.stdout + result.stderr)
    return result


def phase(name: str, action) -> None:
    row = {"started": time.time(), "status": "INCOMPLETE"}
    REPORT["phases"][name] = row
    try:
        action(row)
        row["status"] = "PASS"
    except Exception as error:
        row["error"] = str(error)[:3000]
    row["finished"] = time.time()
    (PUBLIC / "verdict.json").write_text(json.dumps(REPORT, indent=2) + "\n")
    print(name, row["status"], flush=True)


def bazel(args: list[str], cwd: Path, name: str, expected: int = 0) -> str:
    result = command(["bazel", *args], cwd, name)
    if result.returncode != expected:
        lines = [line for line in (result.stdout + result.stderr).splitlines() if "ERROR:" in line or "error:" in line]
        raise RuntimeError(f"{name}: exit {result.returncode}, expected {expected}: " + "\n".join(lines[:12]))
    return result.stdout


def test(row: dict, name: str, cwd: Path, labels: list[str], flags: list[str], expected: dict[str, str]) -> None:
    bep = WORK / (name + ".bep.json")
    result = command(["bazel", "test", *flags, "--nocache_test_results", "--test_output=errors", "--build_event_json_file=" + str(bep), *labels], cwd, name)
    row["exit"] = result.returncode
    events = [json.loads(line) for line in bep.read_text().splitlines()] if bep.exists() else []
    summaries = {event["id"]["testSummary"]["label"]: event["testSummary"]["overallStatus"] for event in events if "testSummary" in event}
    row["summaries"] = summaries
    row["bep_sha256"] = hashlib.sha256(bep.read_bytes()).hexdigest() if bep.exists() else None
    xml = []
    for event in events:
        if "testResult" not in event:
            continue
        for output in event["testResult"].get("testActionOutput", []):
            if output["name"] == "test.xml":
                path = Path(unquote(urlparse(output["uri"]).path))
                xml.append({"owner": event["id"]["testResult"], "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "xml": path.read_text()})
    row["tests"] = xml
    assert result.returncode == (3 if "FAILED" in expected.values() else 0), (name, result.returncode)
    assert summaries == expected, (name, summaries, expected)
    assert len(xml) == len(expected), (name, len(xml), len(expected))


def query_files(label: str, arch: str, name: str) -> list[tuple[str, str]]:
    text = bazel(["cquery", label, "--platforms=//:linux_" + arch, "--output=starlark", "--starlark:expr=[(f.path, str(f.owner)) for f in target.files.to_list()]"], SMOKE, name)
    lines = [line for line in text.splitlines() if line.startswith("[") and line.endswith("]")]
    assert len(lines) == 1, (label, lines)
    return ast.literal_eval(lines[0])


def sanitize(key: str) -> str:
    return key.removeprefix("/").replace("+", "-").replace(":", "-").replace("~", "_").replace("/", "_").replace("=", "_")


def inventory(row: dict, arch: str, repos: list[str], stock: bool = False) -> None:
    execroot = Path(bazel(["info", "execution_root"], SMOKE, "execroot-" + arch).splitlines()[-1])
    lockpath, _ = query_files("@status_packages//:lock.json", arch, "lock-" + arch)[0]
    lock = json.loads((execroot / lockpath).read_text())
    packages = lock["packages"]
    rows = []
    row["inventories"] = rows
    for repo in repos:
        files = query_files("@" + repo + "//:packages", arch, repo + "-data-" + arch)
        raw = {}
        for path, owner in files:
            matches = [key for key in packages if owner.endswith("+" + sanitize(key) + "//:data") or owner.endswith("~" + sanitize(key) + "//:data")]
            if len(matches) == 1:
                raw[matches[0]] = path
            else:
                assert repo == "status_repacked" and owner.endswith("//tzdata/" + arch + ":" + arch), (repo, path, owner, matches)
                # Inspect the real repacker action inputs; these remain raw package outputs.
                graph = json.loads(bazel(["aquery", 'mnemonic("Flatten", @status_repacked//tzdata/' + arch + ")", "--platforms=//:linux_" + arch, "--output=jsonproto"], SMOKE, "flatten-" + arch))
                fragments = {item["id"]: item for item in graph["pathFragments"]}
                def path_for(number):
                    item = fragments[number]
                    return (path_for(item["parentId"]) + "/" if item.get("parentId") else "") + item["label"]
                artifacts = {item["id"]: path_for(item["pathFragmentId"]) for item in graph["artifacts"]}
                depsets = {item["id"]: item for item in graph["depSetOfFiles"]}
                def inputs(number):
                    item = depsets[number]
                    return [artifacts[n] for n in item.get("directArtifactIds", [])] + [path for child in item.get("transitiveDepSetIds", []) for path in inputs(child)]
                assert len(graph["actions"]) == 1, len(graph["actions"])
                for dep in {path for number in graph["actions"][0].get("inputDepSetIds", []) for path in inputs(number)}:
                    for key in packages:
                        if re.search(r"external/[^/]*[+~]" + re.escape(sanitize(key)) + r"/", dep) and dep.endswith(".tar.gz"):
                            raw[key] = dep
        assert raw, (repo, files)
        payloads = []
        for key, path in sorted(raw.items()):
            payload = execroot / path
            assert payload.is_file(), path
            with tarfile.open(payload) as archive:
                assert any(member.isfile() for member in archive), path
            payloads.append({"package": key, "path": path, "sha256": hashlib.sha256(payload.read_bytes()).hexdigest()})
        expected = sorted((packages[key]["name"], packages[key]["version"], packages[key]["architecture"]) for key in raw)
        statuspath, _ = query_files("@" + repo + "//:dpkg_status", arch, repo + "-status-" + arch)[0]
        statusfile = execroot / statuspath
        with tarfile.open(statusfile) as archive:
            text = archive.extractfile("./var/lib/dpkg/status").read().decode()
        actual = []
        for paragraph in text.strip().split("\n\n"):
            fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))
            actual.append((fields["Package"], fields["Version"], fields["Architecture"]))
        actual.sort()
        rows.append({"repo": repo, "architecture": arch, "payloads": payloads, "expected": expected, "actual": actual, "status_sha256": hashlib.sha256(statusfile.read_bytes()).hexdigest()})
        assert len(actual) == len(set(actual)), (repo, "duplicate metadata", actual)
        assert all(architecture in (arch, "all") for _, _, architecture in actual), actual
        if stock and repo == "status_packages":
            assert [name for name, _, _ in actual] == ["bash", "coreutils", "ncurses-base"], actual
            assert len(expected) == 16 and len(actual) == 3, (actual, expected)
        else:
            assert actual == expected, (repo, actual, expected)
        assert len(actual) == (3 if stock and repo == "status_packages" else {"status_packages": 16, "status_custom": 1, "status_repacked": 15}[repo]), (repo, actual)


def formatting(row: dict) -> None:
    row["output"] = bazel(["run", "@buildifier_prebuilt//:buildifier", "--", "-mode=fix", *[str(ROOT / path) for path in CHANGED]], ROOT, "format")[-500:]
    bazel(["run", "@buildifier_prebuilt//:buildifier", "--", "-mode=check", *[str(ROOT / path) for path in CHANGED]], ROOT, "format-check")


def owners(row: dict) -> None:
    # Use the supplier's actual unit-test inventory, without a new test harness.
    labels = bazel(["query", 'kind(".*_test rule", //apt/tests:*)', "--output=label"], ROOT, "unit-query")
    labels = sorted(line for line in labels.splitlines() if line.startswith("//"))
    assert len(labels) > 20, labels
    test(row, "unit", ROOT, labels, [], dict.fromkeys(labels, "PASSED"))


def smoke(row: dict, arch: str, stock: bool = False) -> None:
    repos = REPOS[:2] if stock else REPOS
    expected = {"//:" + repo + "_test": "FAILED" if stock and repo == "status_packages" else "PASSED" for repo in repos}
    test(row, ("stock-" if stock else "candidate-") + arch, SMOKE, list(expected) + ["@" + repo + "//:packages" for repo in repos], ["--platforms=//:linux_" + arch], expected)
    inventory(row, arch, repos, stock)


def scan() -> None:
    for path in PUBLIC.iterdir():
        assert path.name in {"verdict.json", "generated.patch"} and path.is_file() and not path.is_symlink()
        assert path.stat().st_size < 4_000_000
        assert not re.search(rb"(?i)(?:authorization:|x-buildbuddy-api-key|gh[pousr]_[a-z0-9]{20}|github_pat_)", path.read_bytes()), path.name


if sys.argv[1:] == ["--scan"]:
    scan()
    raise SystemExit(0)


assert subprocess.check_output(["git", "rev-parse", "HEAD^"], text=True).strip() == PRODUCT
assert subprocess.check_output(["git", "rev-parse", "HEAD^^"], text=True).strip() == BASE
phase("format", formatting)
phase("unit", owners)
original = {path: (ROOT / path).read_bytes() for path in RESTORE}
try:
    for path in RESTORE:
        (ROOT / path).write_bytes(subprocess.check_output(["git", "show", BASE + ":" + path]))
    phase("stock-amd64", lambda row: smoke(row, "amd64", True))
finally:
    for path, contents in original.items():
        (ROOT / path).write_bytes(contents)
phase("candidate-amd64", lambda row: smoke(row, "amd64"))
phase("candidate-arm64", lambda row: smoke(row, "arm64"))
# Retain canonical generated changes for the final source commit; no handwritten lock.
allowed = CHANGED + ["e2e/smoke/bullseye.lock.json"]
patch = subprocess.check_output(["git", "diff", "--", *allowed])
(PUBLIC / "generated.patch").write_bytes(patch)
REPORT["generated_patch_sha256"] = hashlib.sha256(patch).hexdigest()
REPORT["finished"] = time.time()
REPORT["verdict"] = "PASS" if all(row["status"] == "PASS" for row in REPORT["phases"].values()) else "INCOMPLETE"
(PUBLIC / "verdict.json").write_text(json.dumps(REPORT, indent=2) + "\n")
scan()
print(REPORT["verdict"], flush=True)
raise SystemExit(REPORT["verdict"] != "PASS")
