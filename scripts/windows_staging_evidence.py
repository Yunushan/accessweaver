"""Run the native staging fixtures while publishing only fixed failure evidence."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCES = (
    "scripts/windows_staging_evidence.py",
    "scripts/test_signed_release_manifest.py",
    "scripts/signed_release_manifest.py",
    "scripts/sbom.py",
)
TESTS = frozenset((
    "test_real_cms_windows_lifecycle_gate",
    "test_windows_staging_holds_directory_chain_through_publication_and_readback",
    "test_windows_staging_detector_requires_exact_success_and_uses_signed_pins",
    "test_windows_staging_detector_pins_script_through_execution",
    "test_windows_staging_holds_approved_setup_and_parents_through_launch",
    "test_windows_staging_wait_timeout_leaves_real_process_running",
    "test_windows_staging_reserves_attempt_before_launch_and_refuses_replay",
    "test_windows_staging_launches_inert_fixture_with_fixed_arguments",
    "test_windows_staging_refuses_a_redirected_parent",
))
SOURCE_PATHS = {str((ROOT / name).resolve()): name for name in SOURCES}
EXCEPTIONS = {
    kind: kind.__name__ for kind in (
        AssertionError, OSError, FileNotFoundError, PermissionError, TimeoutError,
        ValueError, TypeError, RuntimeError, ImportError, ModuleNotFoundError,
        subprocess.CalledProcessError, subprocess.TimeoutExpired,
    )
}


class DiscardOutput:
    def __init__(self):
        self.count = 0

    def write(self, value):
        self.count += len(value)
        if self.count > 2 << 20:
            raise RuntimeError("Fixture output limit exceeded")
        return len(value)

    def flush(self):
        pass


class FixedResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.fixed = []

    def record(self, test, err):
        name = getattr(test, "_testMethodName", None)
        name = name if name in TESTS else "unselected-test"
        frames = []
        for frame, line in traceback.walk_tb(err[2]):
            source = SOURCE_PATHS.get(str(Path(frame.f_code.co_filename).resolve()))
            if source:
                frames.append({"source": source, "line": line})
        row = {"test": name, "exception": EXCEPTIONS.get(err[0], "other"),
               "frames": frames[-5:]}
        for key in ("returncode", "winerror", "errno"):
            value = getattr(err[1], key, None)
            if type(value) is int and -(1 << 31) <= value < (1 << 31):
                row[key] = value
        self.fixed.append(row)

    def addFailure(self, test, err):
        self.failures.append((test, ""))
        self.record(test, err)

    def addError(self, test, err):
        self.errors.append((test, ""))
        self.record(test, err)

    def addSubTest(self, test, subtest, err):
        if err:
            if issubclass(err[0], test.failureException):
                self.addFailure(test, err)
            else:
                self.addError(test, err)

    def addSkip(self, test, reason):
        self.skipped.append((test, ""))

    def addExpectedFailure(self, test, err):
        self.expectedFailures.append((test, ""))
        self.record(test, err)


def summarize(result):
    passed = (result.wasSuccessful() and result.testsRun == len(TESTS)
              and not result.skipped and not result.expectedFailures)
    return {
        "schemaVersion": 1, "outcome": "passed" if passed else "failed",
        "tests": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "expectedFailures": len(result.expectedFailures),
        "unexpectedSuccesses": len(result.unexpectedSuccesses),
        "fixedFailures": result.fixed, "productionQualificationComplete": False,
    }


def selected_names(suite):
    names = []
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            names.extend(selected_names(test))
        else:
            names.append((test.__class__.__module__, test.__class__.__name__,
                          getattr(test, "_testMethodName", None)))
    return names


def main():
    if os.name != "nt":
        raise SystemExit("Windows staging evidence requires native Windows")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                            capture_output=True, text=True, timeout=10).stdout.strip()
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise SystemExit("Invalid source identity")
    pins = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in SOURCES}
    loader = unittest.TestLoader()
    loader.testNamePatterns = ["*test_windows_staging_*",
                              "*test_real_cms_windows_lifecycle_gate*"]
    output = DiscardOutput()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        suite = loader.discover(str(ROOT / "scripts"),
                                pattern="test_signed_release_manifest.py")
        selected = selected_names(suite)
        expected = {("test_signed_release_manifest", "SignedReleaseManifestTests", name)
                    for name in TESTS}
        if len(selected) != len(TESTS) or set(selected) != expected:
            raise RuntimeError("Windows staging selection changed")
        result = FixedResult()
        suite.run(result)
    report = {**summarize(result), "sourceCommit": commit, "sourceSHA256": pins}
    destination = ROOT / "build/windows-update-staging/status.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if len(encoded.encode()) > 64 << 10:
        raise SystemExit("Fixed report limit exceeded")
    destination.write_text(encoded, encoding="utf-8")
    print(json.dumps({key: report[key] for key in
                      ("outcome", "tests", "failures", "errors", "skipped")}))
    return 0 if report["outcome"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
