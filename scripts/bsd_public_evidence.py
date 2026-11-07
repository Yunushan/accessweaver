"""Closed public projection of an existing disposable BSD guest report.

The legacy report/log bundle and its verifier contract remain separate. This
projection exports no accounts, paths, console text or raw test output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

MODULE = "github.com/Yunushan/accessweaver/"
TARGETS = {osname + "/" + arch for osname in ("freebsd", "openbsd") for arch in ("amd64", "arm64")}
SOURCES = ("scripts/bsd_public_evidence.py", "scripts/test_bsd_public_evidence.py", "scripts/test_bsd_guest.py", "scripts/test-bsd-guest.py", "scripts/test-openbsd-guest.py", "scripts/bsd_packaged_candidate.py", "scripts/build-all.sh", ".github/workflows/bsd.yml", ".github/workflows/openbsd.yml", ".github/workflows/bsd-candidate.yml", "go.mod", "go.sum")
PHASES = {"build", "source-build", "image-download", "image-prepare", "firmware-prepare", "guest-boot", "guest-identity", "payload-transfer", "guest-cli", "guest-unit-tests", "installer-media", "installer-boot", "guest-installation", "installed-guest-boot", "packaged-backup-roundtrip"}

def exact_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None

def number(value, maximum=10_000_000, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("public counter differs")
    return value

def flag(report, key):
    value = report.get(key, False)
    if type(value) is not bool:
        raise ValueError("public flag differs")
    return value

BUILD_STEPS = {"not-observed", "package-discovery", "package-compile", "source-cli-build", "packaged-cli-copy", "source-archive", "transport-archive", "complete"}
BUILD_KINDS = {"none", "command-failed", "helper-timeout", "invalid-build-input", "build-assertion", "build-exception"}
BUILD_CAUSES = {"unspecified", "helper-output-limit", "unsupported-package-path", "unexpected-test-module", "unexpected-package-count", "source-archive-limit", "source-changed", "payload-limit"}

def public_build(raw):
    if not isinstance(raw, dict):
        raise ValueError("public build object differs")
    step, kind, cause = raw.get("step", "not-observed"), raw.get("failureKind", "none"), raw.get("failureCause", "unspecified")
    if step not in BUILD_STEPS or kind not in BUILD_KINDS or cause not in BUILD_CAUSES:
        raise ValueError("public build codes differ")
    result = {"step": step, "plannedPackages": number(raw.get("plannedPackages", 0), 64),
              "completedPackages": number(raw.get("completedPackages", 0), 64),
              "currentPackageID": raw.get("currentPackageID"), "failureKind": kind,
              "failureCause": cause, "failureExitCode": raw.get("failureExitCode")}
    if result["currentPackageID"] is not None:
        number(result["currentPackageID"], 63)
    if result["failureExitCode"] is not None:
        number(result["failureExitCode"], 255, -255)
    if result["completedPackages"] > result["plannedPackages"]:
        raise ValueError("public build progress differs")
    return result

def project(report, source, tree, target, hashes, legacy_digest):
    if target not in TARGETS or not re.fullmatch(r"[a-f0-9]{40}", source) or not re.fullmatch(r"[a-f0-9]{40}", tree):
        raise ValueError("public identity differs")
    if set(hashes) != set(SOURCES) or not all(exact_hash(h) for h in hashes.values()):
        raise ValueError("public source hashes differ")
    if legacy_digest is not None and not exact_hash(legacy_digest):
        raise ValueError("public report digest differs")
    report = {} if report is None else report
    if not isinstance(report, dict):
        raise ValueError("public input report differs")
    osname, arch = target.split("/")
    sdk = report.get("hostSDK", {})
    identity = report.get("guestIdentity", {})
    cli = report.get("executedCLI", {})
    if not all(isinstance(v, dict) for v in (sdk, identity, cli)):
        raise ValueError("public identity object differs")
    package_rows, plan = [], []
    records = report.get("packages", [])
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError("public package count differs")
    seen = set()
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("public package record differs")
        name, directory, filename = (record.get(k) for k in ("package", "directory", "file"))
        if (not isinstance(name, str) or not name.startswith(MODULE) or name in seen or
                not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name[len(MODULE):]) or
                any(part in (".", "..") for part in name[len(MODULE):].split("/")) or
                not isinstance(directory, str) or directory != name[len(MODULE):] or
                filename != "tests/" + hashlib.sha256(name.encode()).hexdigest()[:20] + ".test" or
                not exact_hash(record.get("sha256"))):
            raise ValueError("public package identity differs")
        seen.add(name)
        row = {"id": i, "binarySHA256": record["sha256"], "exitCode": number(record.get("returnCode"), 255, -255),
               "passedTestInstances": number(record.get("passedTestInstances")), "skippedTestInstances": number(record.get("skippedTestInstances"))}
        package_rows.append(row)
        plan.append({k: record[k] for k in ("package", "directory", "file", "sha256")})
    expected = number(report.get("crossCompiledPackages", 0), 64)
    release = identity.get("release")
    release_ok = (isinstance(release, str) and re.fullmatch(r"15\.1-RELEASE(?:-p[0-9]+)?", release) is not None) if osname == "freebsd" else release == "8.0"
    uid = identity.get("uid")
    guest_ok = identity.get("OS") == {"freebsd": "FreeBSD", "openbsd": "OpenBSD"}[osname] and identity.get("machine") == arch and type(uid) is int and uid > 0 and identity.get("user") == "awtest" and release_ok
    compiler_ok = sdk == {"GOOS": "linux", "GOARCH": arch, "GOHOSTOS": "linux", "GOHOSTARCH": arch, "GOVERSION": "go1.27.3", "GOTOOLCHAIN": "local"}
    cli_ok = all(cli.get(k) == v for k, v in {"commit": source, "sourceState": "clean", "platform": osname, "arch": arch, "goVersion": "go1.27.3"}.items()) and exact_hash(report.get("cliSHA256"))
    image_ok = flag(report, "imageDigestVerified") if osname == "freebsd" else flag(report, "installerMediaDigestVerified") and flag(report, "installerMetadataSignatureVerified") and flag(report, "installerCompleted") and flag(report, "seedRemovedBeforeTargetExecution")
    checks = {"sourceMatches": report.get("sourceCommit") == source and report.get("target") == target,
              "hostCompilerMatches": compiler_ok, "ordinaryGuestIdentityMatches": bool(guest_ok), "executedCLIIdentityMatches": cli_ok,
              "imageInputsAuthenticated": image_ok, "transportedExecutableHashesVerified": flag(report, "allTransportedExecutableHashesVerified"),
              "guestExecutionPassed": flag(report, "guestExecutionPassed"),
              "ownedEmulatorsStopped": flag(report, "ownedEmulatorStopped" if osname == "freebsd" else "ownedEmulatorsStopped"),
              "ownedCapsuleRemoved": flag(report, "ownedCapsuleRemoved"), "completePackageSetPassed": bool(expected and len(package_rows) == expected and all(p["exitCode"] == 0 for p in package_rows))}
    checks["cleanupConfirmed"] = checks["ownedEmulatorsStopped"] and checks["ownedCapsuleRemoved"] and not flag(report, "cleanupFailed")
    passed = all(checks.values())
    phase = report.get("failurePhase")
    stage = "complete" if passed else "report-unavailable" if legacy_digest is None else phase if isinstance(phase, str) and phase in PHASES else "producer-failure"
    result = {"schemaVersion": 2, "sourceCommit": source, "sourceTree": tree, "sourceSHA256": dict(hashes), "target": target,
              "scope": "disposable-bsd-guest-core", "expectedGoVersion": "go1.27.3", "stage": stage, "outcome": "passed" if passed else "failed",
              "checks": checks, "build": public_build(report.get("buildObservations", {})), "counts": {"expectedPackages": expected, "completedPackages": len(package_rows),
              "passedTestInstances": sum(p["passedTestInstances"] for p in package_rows), "skippedTestInstances": sum(p["skippedTestInstances"] for p in package_rows)},
              "packages": package_rows, "packagePlanSHA256": hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
              "legacyReportSHA256": legacy_digest, "packagedCandidateExecuted": flag(report, "packagedCandidateExecuted"),
              "productionQualificationComplete": False, "platformQualificationComplete": False, "hardwareQualificationComplete": False, "readinessGatesPromoted": 0}
    if len(json.dumps(result).encode()) > 32768:
        raise ValueError("public report byte budget differs")
    validate_public(result)
    return result

PUBLIC_KEYS = {"schemaVersion", "sourceCommit", "sourceTree", "sourceSHA256", "target", "scope", "expectedGoVersion", "stage", "outcome", "checks", "build", "counts", "packages", "packagePlanSHA256", "legacyReportSHA256", "packagedCandidateExecuted", "productionQualificationComplete", "platformQualificationComplete", "hardwareQualificationComplete", "readinessGatesPromoted"}
CHECK_KEYS = {"sourceMatches", "hostCompilerMatches", "ordinaryGuestIdentityMatches", "executedCLIIdentityMatches", "imageInputsAuthenticated", "transportedExecutableHashesVerified", "guestExecutionPassed", "ownedEmulatorsStopped", "ownedCapsuleRemoved", "completePackageSetPassed", "cleanupConfirmed"}

def validate_public(data):
    if not isinstance(data, dict) or set(data) != PUBLIC_KEYS or type(data["schemaVersion"]) is not int or data["schemaVersion"] != 2:
        raise ValueError("public schema differs")
    if (not re.fullmatch(r"[a-f0-9]{40}", data["sourceCommit"]) or not re.fullmatch(r"[a-f0-9]{40}", data["sourceTree"]) or
            data["target"] not in TARGETS or data["scope"] != "disposable-bsd-guest-core" or data["expectedGoVersion"] != "go1.27.3"):
        raise ValueError("public source or target differs")
    if set(data["sourceSHA256"]) != set(SOURCES) or not all(exact_hash(v) for v in data["sourceSHA256"].values()):
        raise ValueError("public hash set differs")
    if set(data["checks"]) != CHECK_KEYS or not all(type(v) is bool for v in data["checks"].values()):
        raise ValueError("public check set differs")
    if set(data["counts"]) != {"expectedPackages", "completedPackages", "passedTestInstances", "skippedTestInstances"}:
        raise ValueError("public count set differs")
    number(data["counts"]["expectedPackages"], 64);number(data["counts"]["completedPackages"], 64)
    for k in ("passedTestInstances", "skippedTestInstances"):
        number(data["counts"][k], 640_000_000)
    if not isinstance(data["packages"], list) or len(data["packages"]) != data["counts"]["completedPackages"]:
        raise ValueError("public package set differs")
    for i, row in enumerate(data["packages"]):
        if set(row) != {"id", "binarySHA256", "exitCode", "passedTestInstances", "skippedTestInstances"} or row["id"] != i or type(row["id"]) is not int or not exact_hash(row["binarySHA256"]):
            raise ValueError("public package schema differs")
        number(row["exitCode"], 255, -255);number(row["passedTestInstances"]);number(row["skippedTestInstances"])
    if any(data["counts"][k] != sum(p[k] for p in data["packages"]) for k in ("passedTestInstances", "skippedTestInstances")):
        raise ValueError("public package totals differ")
    if not exact_hash(data["packagePlanSHA256"]) or data["legacyReportSHA256"] is not None and not exact_hash(data["legacyReportSHA256"]):
        raise ValueError("public report hashes differ")
    complete = bool(data["counts"]["expectedPackages"] and
                    data["counts"]["completedPackages"] == data["counts"]["expectedPackages"] and
                    all(row["exitCode"] == 0 for row in data["packages"]))
    if data["checks"]["completePackageSetPassed"] != complete:
        raise ValueError("public completion check differs")
    if not isinstance(data["build"], dict) or set(data["build"]) != {"step", "plannedPackages", "completedPackages", "currentPackageID", "failureKind", "failureCause", "failureExitCode"} or public_build(data["build"]) != data["build"]:
        raise ValueError("public build schema differs")
    passed = all(data["checks"].values())
    if passed and (data["build"]["step"] != "complete" or data["build"]["failureKind"] != "none" or data["build"]["failureExitCode"] is not None or data["build"]["completedPackages"] != data["counts"]["expectedPackages"]):
        raise ValueError("public successful build differs")
    if passed and data["legacyReportSHA256"] is None:
        raise ValueError("public successful report requires producer digest")
    if (data["outcome"] != ("passed" if passed else "failed") or data["stage"] not in PHASES | {"complete", "report-unavailable", "producer-failure"} or
            (data["stage"] == "complete") != passed or type(data["packagedCandidateExecuted"]) is not bool or
            any(data[k] is not False for k in ("productionQualificationComplete", "platformQualificationComplete", "hardwareQualificationComplete")) or data["readinessGatesPromoted"] != 0 or type(data["readinessGatesPromoted"]) is not int):
        raise ValueError("public qualification scope differs")
    return data

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate report field")
        result[key] = value
    return result

def command(repo, args):
    result = subprocess.run(args, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=15)
    if len(result.stdout) > 32768:
        raise ValueError("source command budget differs")
    return result.stdout.decode("ascii").strip()

def guard():
    if (platform.system() != "Linux" or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.geteuid() == 0):
        raise RuntimeError("hosted public evidence only")
    repo = Path(__file__).resolve().parents[1]
    source = os.environ.get("GITHUB_SHA", "")
    if (Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve() != repo or not re.fullmatch(r"[a-f0-9]{40}", source) or
            command(repo, ["git", "rev-parse", "HEAD"]) != source or command(repo, ["git", "status", "--porcelain=v1", "--untracked-files=normal"])):
        raise RuntimeError("clean exact hosted source required")
    return repo, source

def write_public(repo, osname, arch, data):
    validate_public(data)
    if data["target"] != osname + "/" + arch:
        raise ValueError("public output target differs")
    folder = repo / "build" / ("bsd-public-checks" if osname == "freebsd" else "openbsd-public-checks")
    for directory in (repo / "build", folder):
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir() or directory.resolve() != directory:
            raise ValueError("public output redirect differs")
        info = directory.stat()
        if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError("public output ownership differs")
    target = folder / (osname + "-" + arch + ".json")
    encoded = json.dumps(data, sort_keys=True) + "\n"
    if len(encoded.encode()) > 32768:
        raise ValueError("public output budget differs")
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(encoded)
    return target

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os", required=True, choices=("freebsd", "openbsd"));parser.add_argument("--arch", required=True, choices=("amd64", "arm64"));args = parser.parse_args()
    repo, source = guard();os.umask(0o077)
    tree = command(repo, ["git", "rev-parse", "HEAD^{tree}"])
    hashes = {n: hashlib.sha256((repo / n).read_bytes()).hexdigest() for n in SOURCES}
    legacy = repo / "build" / ("bsd-native-checks" if args.os == "freebsd" else "openbsd-native-checks") / (args.os + "-" + args.arch + ".json")
    report, digest = None, None
    if legacy.exists():
        parent = legacy.parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or parent.resolve() != parent or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("unsafe legacy metadata directory")
        fd = os.open(legacy, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o022 or not 0 < info.st_size <= 524288:
                raise ValueError("unsafe legacy metadata")
            raw = stream.read(524289)
            after = os.fstat(stream.fileno())
        if len(raw) != info.st_size or len(raw) > 524288 or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("legacy metadata changed or exceeded budget")
        report, digest = json.loads(raw, object_pairs_hook=unique), hashlib.sha256(raw).hexdigest()
    data = project(report, source, tree, args.os + "/" + args.arch, hashes, digest)
    if command(repo, ["git", "status", "--porcelain=v1", "--untracked-files=normal"]):
        raise ValueError("source changed during projection")
    write_public(repo, args.os, args.arch, data)
    print(json.dumps({"target": data["target"], "outcome": data["outcome"], "stage": data["stage"]}))
    return 0 if data["outcome"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
