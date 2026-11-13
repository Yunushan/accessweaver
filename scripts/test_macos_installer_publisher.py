import hashlib
import os
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from test_macos_deployment import image

import verify_macos_installer_publisher as publisher


SPEC = importlib.util.spec_from_file_location("deployment_builder", Path(__file__).with_name("build-macos-deployment.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


TEAM = "A12345BCDE"
PIN = "ab" * 32
PACKAGE_OUTPUT = (
    "Package: candidate.pkg\n"
    "   Status: signed by a developer certificate issued by Apple for distribution\n"
    "   Certificate Chain:\n"
    f"    1. Developer ID Installer: Approved Publisher ({TEAM})\n"
    f"       SHA256 Fingerprint: {':'.join(['AB'] * 32)}\n"
    "    2. Developer ID Certification Authority\n"
    f"       SHA256 Fingerprint: {':'.join(['CD'] * 32)}\n"
)


class PublisherTests(unittest.TestCase):
    def test_approved_leaf_and_rejections(self):
        publisher.check_leaf(PACKAGE_OUTPUT, TEAM, PIN)
        for output, team, pin in (
            (PACKAGE_OUTPUT, "XXXXXXXXXX", PIN),
            (PACKAGE_OUTPUT, TEAM, "cd" * 32),
            (PACKAGE_OUTPUT.replace("Developer ID Installer:", "Developer ID Application:"), TEAM, PIN),
            (PACKAGE_OUTPUT.replace("SHA256 Fingerprint", "SHA1 Fingerprint", 1), TEAM, PIN),
            (PACKAGE_OUTPUT + PACKAGE_OUTPUT, TEAM, PIN),
        ):
            with self.subTest(team=team, pin=pin), self.assertRaises(ValueError):
                publisher.check_leaf(output, team, pin)

    def test_digest_precedes_native_checks_and_failures_stop(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(publisher.sys, "platform", "darwin"):
            directory = Path(tmp)
            payload = b"synthetic fixed package bytes"
            (directory / "accessweaver-fixture.pkg").write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            with patch.object(publisher, "tool") as tool, self.assertRaises(ValueError):
                publisher.verify(directory, "d" * 64, TEAM, PIN)
            tool.assert_not_called()

            with patch.object(publisher, "tool", side_effect=[PACKAGE_OUTPUT, "", ""]) as tool:
                report = publisher.verify(directory, digest, TEAM, PIN)
                calls = [call.args[0] for call in tool.call_args_list]
                self.assertEqual([x[:-1] for x in calls], [
                    ["/usr/sbin/pkgutil", "--check-signature"],
                    ["/usr/sbin/spctl", "--assess", "--type", "install"],
                    ["/usr/bin/xcrun", "stapler", "validate"],
                ])
                self.assertTrue(all(x[-1].parent != directory and x[-1] == calls[0][-1] for x in calls))
                self.assertEqual(report["artifactSHA256"], digest)
                self.assertTrue(report["stapledTicketValidated"])

            for stage in range(3):
                completed = [PACKAGE_OUTPUT, "", ""][:stage]
                failure = subprocess.CalledProcessError(1, "fixture")
                with patch.object(publisher, "tool", side_effect=completed + [failure]) as tool:
                    with self.assertRaises(subprocess.CalledProcessError):
                        publisher.verify(directory, digest, TEAM, PIN)
                    self.assertEqual(tool.call_count, stage + 1)

    def test_stage_detector_only_from_verified_package_with_exact_pin(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(publisher.sys, "platform", "darwin"):
            root = Path(temporary)
            directory = root / "input"
            directory.mkdir()
            package = directory / "candidate.pkg"
            package.write_bytes(b"fixture package")
            package_digest = publisher.digest(package)
            helper_bytes = image("arm64")
            helper_digest = hashlib.sha256(helper_bytes).hexdigest()
            destination = root / "accessweaver-installer"
            calls = []
            mode = "approved"

            def tool(arguments):
                executable, action, *_ = arguments
                calls.append((executable, action))
                if action == "--check-signature":
                    return PACKAGE_OUTPUT
                if action == "--expand-full":
                    self.assertEqual(publisher.digest(arguments[-2]), package_digest)
                    expanded = arguments[-1]
                    scripts = expanded / "Scripts"
                    scripts.mkdir(parents=True)
                    helper = scripts / "postinstall"
                    helper.write_bytes(helper_bytes if mode != "wrong-architecture" else image("amd64"))
                    if mode == "hardlink":
                        os.link(helper, scripts / "alias")
                if executable == "/usr/bin/codesign":
                    self.assertEqual(arguments[1:4], ["--verify", "--strict", "--all-architectures"])
                    self.assertIn(f'certificate leaf[subject.OU] = "{TEAM}"', arguments[-2])
                    self.assertEqual(arguments[-1].read_bytes(), helper_bytes)
                    self.assertFalse(destination.exists() and mode != "existing")
                    if mode == "wrong-publisher":
                        raise subprocess.CalledProcessError(1, arguments)
                return ""

            def verify(digest=helper_digest):
                return publisher.verify(directory, package_digest, TEAM, PIN, detector_output=destination,
                                        detector_sha256=digest, architecture="arm64")

            with patch.object(publisher, "tool", side_effect=tool):
                for mode, digest, error in (
                    ("wrong-pin", "d" * 64, ValueError),
                    ("wrong-architecture", helper_digest, ValueError),
                    ("hardlink", helper_digest, ValueError),
                    ("wrong-publisher", helper_digest, subprocess.CalledProcessError),
                ):
                    with self.subTest(mode=mode), self.assertRaises(error):
                        verify(digest)
                    self.assertFalse(destination.exists())
                    self.assertEqual(sorted(p.name for p in root.iterdir()), ["input"])
                mode = "approved"
                calls.clear()
                report = verify()
                self.assertEqual(calls, [
                    ("/usr/sbin/pkgutil", "--check-signature"), ("/usr/sbin/spctl", "--assess"),
                    ("/usr/bin/xcrun", "stapler"), ("/usr/sbin/pkgutil", "--expand-full"),
                    ("/usr/bin/codesign", "--verify"),
                ])
                self.assertEqual(report["managedDetector"], {
                    "architecture": "arm64", "sha256": helper_digest, "developerIDApplicationVerified": True,
                })
                self.assertEqual(destination.read_bytes(), helper_bytes)
                self.assertEqual(destination.stat().st_nlink, 1)
                destination.write_bytes(b"existing assignment")
                mode = "existing"
                with self.assertRaises(FileExistsError):
                    verify()
                self.assertEqual(destination.read_bytes(), b"existing assignment")

            with patch.object(publisher, "tool") as native:
                for output, pin, arch in (
                    (destination, None, "arm64"),
                    (directory / "accessweaver-installer", helper_digest, "arm64"),
                    (root / "other", helper_digest, "arm64"),
                    (destination, helper_digest, "x64"),
                ):
                    with self.assertRaises(ValueError):
                        publisher.verify(directory, package_digest, TEAM, PIN, detector_output=output,
                                         detector_sha256=pin, architecture=arch)
                native.assert_not_called()

    def test_signing_options_require_complete_approved_identity(self):
        settings = ("Fixture application", "Fixture installer", TEAM, PIN.upper(), "Fixture profile")
        self.assertIsNone(builder.publisher_options(None, None, None, None, None))
        self.assertEqual(builder.publisher_options(*settings), (*settings[:3], PIN, settings[-1]))
        for index in range(len(settings)):
            rejected = list(settings)
            rejected[index] = None
            with self.assertRaises(ValueError):
                builder.publisher_options(*rejected)
        with self.assertRaises(ValueError):
            builder.publisher_options(*settings[:-1], "--wait")

    def test_notary_submission_follows_certificate_and_requires_acceptance(self):
        context = ("Fixture application", "Fixture installer", TEAM, PIN, "Fixture profile")
        unsigned, signed = Path("unsigned.pkg"), Path("signed.pkg")
        for status in ("Accepted", "Invalid", "In Progress"):
            calls = MagicMock()
            calls.run.return_value.stdout = ('{"status":"' + status + '"}').encode()
            with patch.multiple(builder, run=calls.run, check_package_certificate=calls.certificate,
                                check_package_publisher=calls.publisher):
                if status == "Accepted":
                    builder.sign_package(unsigned, signed, context)
                else:
                    with self.assertRaises(ValueError):
                        builder.sign_package(unsigned, signed, context)
            names = [call[0] for call in calls.mock_calls]
            self.assertEqual(names, ["run", "certificate", "run", "run", "publisher"]
                             if status == "Accepted" else ["run", "certificate", "run"])
            if status == "Accepted":
                self.assertEqual(calls.run.call_args.args[0], ["/usr/bin/xcrun", "stapler", "staple", signed])
        with patch.object(builder, "run") as run, patch.object(builder, "check_package_certificate", side_effect=ValueError):
            with self.assertRaises(ValueError):
                builder.sign_package(unsigned, signed, context)
            run.assert_called_once()

    def test_code_signature_verifies_team_and_bundle_identifier(self):
        context = ("Fixture application", "Fixture installer", TEAM, PIN, "Fixture profile")
        with patch.object(builder, "run") as run:
            builder.sign_code(Path("AccessWeaver.app"), context, bundle=True)
        sign, verify = [call.args[0] for call in run.call_args_list]
        self.assertIn("--timestamp", sign)
        self.assertIn("runtime", sign)
        self.assertIn("--all-architectures", verify)
        self.assertIn(f'certificate leaf[subject.OU] = "{TEAM}"', verify[-2])
        self.assertIn(f'identifier "{builder.BUNDLE_ID}"', verify[-2])

    @unittest.skipUnless(publisher.sys.platform == "darwin", "requires macOS package verifier")
    def test_native_pkgutil_refuses_unsigned_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            payload = b"synthetic unsigned package bytes"
            (directory / "accessweaver-fixture.pkg").write_bytes(payload)
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                publisher.verify(directory, hashlib.sha256(payload).hexdigest(), TEAM, PIN)


if __name__ == "__main__":
    unittest.main()
