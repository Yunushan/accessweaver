import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import bsd_public_evidence as evidence

SOURCE = "a" * 40
TREE = "b" * 40
HASHES = {name: "c" * 64 for name in evidence.SOURCES}

def fixture(osname="freebsd", arch="amd64"):
    name = evidence.MODULE + "internal/jsoninput"
    return {"schemaVersion": 1, "sourceCommit": SOURCE, "target": osname + "/" + arch,
            "hostSDK": {"GOOS": "linux", "GOARCH": arch, "GOHOSTOS": "linux", "GOHOSTARCH": arch, "GOVERSION": "go1.27.4", "GOTOOLCHAIN": "local"},
            "guestIdentity": {"OS": {"freebsd": "FreeBSD", "openbsd": "OpenBSD"}[osname], "release": "15.1-RELEASE" if osname == "freebsd" else "8.0", "machine": arch, "uid": 1000, "user": "awtest"},
            "executedCLI": {"commit": SOURCE, "sourceState": "clean", "platform": osname, "arch": arch, "goVersion": "go1.27.4", "version": "PRIVATE_SYNTHETIC_VALUE"},
            "buildObservations": {"step": "complete", "plannedPackages": 1, "completedPackages": 1},
            "publicTestObservations": [{"packageID": 0, "catalogSHA256": "a" * 64, "rootCount": 1, "fileCount": 1, "failedRootIDs": [], "assertionLocations": [], "unknownFailureNames": 0, "truncated": False}],
            "cliSHA256": "d" * 64, "guestExecutionPassed": True, "allTransportedExecutableHashesVerified": True,
            "imageDigestVerified": True, "installerMediaDigestVerified": True, "installerMetadataSignatureVerified": True, "installerCompleted": True, "seedRemovedBeforeTargetExecution": True,
            "ownedEmulatorStopped": True, "ownedEmulatorsStopped": True, "ownedCapsuleRemoved": True, "crossCompiledPackages": 1,
            "packages": [{"package": name, "directory": "internal/jsoninput", "file": "tests/" + hashlib.sha256(name.encode()).hexdigest()[:20] + ".test", "sha256": "e" * 64, "returnCode": 0, "passedTestInstances": 7, "skippedTestInstances": 2, "logSHA256": "f" * 64, "privatePath": "PRIVATE_SYNTHETIC_VALUE"}],
            "qemuVersion": "PRIVATE_SYNTHETIC_VALUE", "profile": "PRIVATE_SYNTHETIC_VALUE"}

def projected(report=None, osname="freebsd", arch="amd64"):
    return evidence.project(fixture(osname, arch) if report is None else report, SOURCE, TREE, osname + "/" + arch, HASHES, "f" * 64)

class PublicBSDReportTests(unittest.TestCase):
    def test_four_target_success_drops_accounts_paths_messages_and_unknowns(self):
        for osname in ("freebsd", "openbsd"):
            for arch in ("amd64", "arm64"):
                with self.subTest(os=osname, arch=arch):
                    result = projected(osname=osname, arch=arch)
                    self.assertEqual(result["outcome"], "passed")
                    self.assertEqual(result["counts"], {"expectedPackages": 1, "completedPackages": 1, "passedTestInstances": 7, "skippedTestInstances": 2})
                    encoded = json.dumps(result)
                    for private in ("PRIVATE_SYNTHETIC_VALUE", "awtest"):
                        self.assertNotIn(private, encoded)
                    for private_key in ("uid", "logSHA256", "privatePath", "qemuVersion"):
                        self.assertNotIn(json.dumps(private_key) + ":", encoded)
                    self.assertFalse(result["productionQualificationComplete"])
                    self.assertEqual(result["readinessGatesPromoted"], 0)

    def test_missing_and_incomplete_reports_cannot_pass(self):
        empty = evidence.project(None, SOURCE, TREE, "openbsd/arm64", HASHES, None)
        self.assertEqual(empty["stage"], "report-unavailable")
        self.assertEqual(empty["outcome"], "failed")
        report = fixture();report["crossCompiledPackages"] = 2
        self.assertFalse(projected(report)["checks"]["completePackageSetPassed"])
        self.assertEqual(projected(report)["outcome"], "failed")

    def test_each_required_positive_check_is_fail_closed(self):
        for key in ("imageDigestVerified", "guestExecutionPassed", "allTransportedExecutableHashesVerified", "ownedEmulatorStopped", "ownedCapsuleRemoved"):
            report = fixture();report[key] = False
            self.assertEqual(projected(report)["outcome"], "failed", key)
        for key in ("installerMediaDigestVerified", "installerMetadataSignatureVerified", "installerCompleted", "seedRemovedBeforeTargetExecution"):
            report = fixture("openbsd");report[key] = False
            self.assertEqual(projected(report, osname="openbsd")["outcome"], "failed", key)
        report = fixture();report["cleanupFailed"] = True
        self.assertEqual(projected(report)["outcome"], "failed")

    def test_wrong_identity_root_stale_source_and_failed_package_cannot_pass(self):
        for field, value in (("uid", 0), ("machine", "arm64"), ("user", "PRIVATE_SYNTHETIC_VALUE"), ("release", "private")):
            report = fixture();report["guestIdentity"][field] = value
            self.assertEqual(projected(report)["outcome"], "failed")
        report = fixture();report["sourceCommit"] = "b" * 40
        self.assertEqual(projected(report)["outcome"], "failed")
        report = fixture();report["packages"][0]["returnCode"] = 1
        self.assertEqual(projected(report)["outcome"], "failed")

    def test_type_confusion_paths_duplicates_unknown_source_hashes_and_sink_fields_refused(self):
        for key in ("crossCompiledPackages", "guestExecutionPassed"):
            report = fixture();report[key] = "PRIVATE_SYNTHETIC_VALUE"
            with self.assertRaises(ValueError):projected(report)
        for key, value in (("directory", "../private"), ("file", "other"), ("sha256", "private"), ("passedTestInstances", True)):
            report = fixture();report["packages"][0][key] = value
            with self.assertRaises(ValueError):projected(report)
        report = fixture();report["packages"].append(copy.deepcopy(report["packages"][0]))
        with self.assertRaises(ValueError):projected(report)
        with self.assertRaises(ValueError):evidence.project(fixture(), SOURCE, TREE, "freebsd/amd64", {**HASHES, "private": "a" * 64}, "f" * 64)
        data = projected();data["profile"] = "PRIVATE_SYNTHETIC_VALUE"
        with self.assertRaises(ValueError):evidence.validate_public(data)
        with self.assertRaises(ValueError):json.loads('{"a":1,"a":2}', object_pairs_hook=evidence.unique)

    def test_forged_completion_schema_and_dot_segments_are_refused(self):
        for change in (lambda d: d.update(schemaVersion=True),
                       lambda d: d.update(legacyReportSHA256=None),
                       lambda d: d["counts"].update(expectedPackages=2),
                       lambda d: d["packages"][0].update(exitCode=1),
                       lambda d: d["testDiagnostics"][0].update(private="PRIVATE_SYNTHETIC_VALUE"),
                       lambda d: d["testDiagnostics"][0].update(packageID=True)):
            data = projected();change(data)
            with self.assertRaises(ValueError):evidence.validate_public(data)
        for suffix in ("../private", "internal/./private", "internal/../private"):
            report = fixture();row = report["packages"][0];name = evidence.MODULE + suffix
            row.update(package=name, directory=suffix, file="tests/" + hashlib.sha256(name.encode()).hexdigest()[:20] + ".test")
            with self.assertRaises(ValueError):projected(report)
        for phase in ("guest-identity", "guest-unit-tests", "payload-transfer", "installed-guest-boot"):
            report = fixture();report.update(guestExecutionPassed=False, failurePhase=phase)
            self.assertEqual(projected(report)["stage"], phase)

    def test_build_progress_exports_only_fixed_codes_and_bounded_counters(self):
        report = fixture();report.update(guestExecutionPassed=False, failurePhase="build")
        report["buildObservations"] = {"step": "package-compile", "plannedPackages": 27, "completedPackages": 3, "currentPackageID": 3, "failureKind": "command-failed", "failureExitCode": 1, "private": "PRIVATE_SYNTHETIC_VALUE"}
        data = projected(report)
        self.assertEqual(data["build"]["currentPackageID"],3)
        self.assertEqual(data["build"]["failureKind"],"command-failed")
        self.assertNotIn("PRIVATE_SYNTHETIC_VALUE",json.dumps(data))
        for change in ({"step":"PRIVATE_SYNTHETIC_VALUE"}, {"plannedPackages":True}, {"currentPackageID":64}, {"failureExitCode":"private"}, {"completedPackages":28}):
            report["buildObservations"].update(change)
            with self.assertRaises(ValueError):projected(report)
            report["buildObservations"].update(step="package-compile",plannedPackages=27,currentPackageID=3,failureExitCode=1,completedPackages=3)

    def test_failure_phase_is_closed_and_no_failure_text_is_exported(self):
        report = fixture();report.update(guestExecutionPassed=False, failurePhase="PRIVATE_SYNTHETIC_VALUE", failureType="PRIVATE_SYNTHETIC_VALUE")
        result = projected(report)
        self.assertEqual(result["stage"], "producer-failure")
        self.assertNotIn("PRIVATE_SYNTHETIC_VALUE", json.dumps(result))

    def test_exclusive_output_and_target_binding(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-bsd-public-") as name:
            root = Path(name).resolve()
            try:
                self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
                data = projected();target = evidence.write_public(root, "freebsd", "amd64", data)
                raw = target.read_bytes()
                with self.assertRaises(FileExistsError):evidence.write_public(root, "freebsd", "amd64", data)
                self.assertEqual(target.read_bytes(), raw)
                with self.assertRaises(ValueError):evidence.write_public(root, "openbsd", "amd64", data)
            finally:
                self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
                self.assertTrue(root.name.startswith("accessweaver-bsd-public-"))

    def test_producer_failure_codes_drop_exception_text_and_command_arguments(self):
        import importlib.util
        import subprocess
        spec = importlib.util.spec_from_file_location("bsd_guest_public_fixture", Path(__file__).with_name("test-bsd-guest.py"))
        producer = importlib.util.module_from_spec(spec);spec.loader.exec_module(producer)
        errors = (RuntimeError("PRIVATE_SYNTHETIC_VALUE"), ValueError("bounded helper output exceeded"), TimeoutError("PRIVATE_SYNTHETIC_VALUE"), producer.CommandFailure(subprocess.CompletedProcess(["PRIVATE_SYNTHETIC_VALUE"], 1, b"PRIVATE_SYNTHETIC_VALUE")))
        for error in errors:
            data = producer.build_failure_observations(error)
            self.assertNotIn("PRIVATE_SYNTHETIC_VALUE", json.dumps(data))
            evidence.public_build(data)
        self.assertEqual(producer.build_failure_observations(errors[1])["failureCause"], "helper-output-limit")
        self.assertEqual(producer.build_failure_observations(errors[3])["failureExitCode"], 1)

    def test_guard_refuses_local_before_source_commands(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(evidence, "command") as command:
            with self.assertRaises(RuntimeError):evidence.guard()
            command.assert_not_called()

if __name__ == "__main__":
    unittest.main()
