import hashlib
import os
import importlib.util
from pathlib import Path
import subprocess
import sys
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

    def test_verify_packaged_application_without_staging_detector(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(publisher.sys, "platform", "darwin"):
            directory = Path(temporary)
            package = directory / "approved.pkg"
            package.write_bytes(b"inert macOS package")
            package_digest = publisher.digest(package)

            for architecture in ("amd64", "arm64"):
                for outcome in ("approved", "wrong-architecture", "wrong-publisher"):
                    def tool(args):
                        if args[1] == "--check-signature":
                            return PACKAGE_OUTPUT
                        if args[1] == "--expand-full":
                            core = args[-1] / "Payload" / publisher.BUNDLE_NAME / "Contents" / "MacOS" / "accessweaver"
                            core.parent.mkdir(parents=True)
                            wrong_arch = "amd64" if architecture == "arm64" else "arm64"
                            core.write_bytes(image(wrong_arch if outcome == "wrong-architecture" else architecture))
                        if args[0] == "/usr/bin/codesign":
                            self.assertEqual(args[1:4], ["--verify", "--strict", "--all-architectures"])
                            self.assertIn(f'certificate leaf[subject.OU] = "{TEAM}"', args[-2])
                            self.assertIn(f'identifier "{publisher.BUNDLE_ID}"', args[-2])
                            self.assertEqual(args[-1].name, publisher.BUNDLE_NAME)
                            if outcome == "wrong-publisher":
                                raise subprocess.CalledProcessError(1, args)
                        return ""

                    with self.subTest(architecture=architecture, outcome=outcome), \
                            patch.object(publisher, "tool", side_effect=tool) as native:
                        if outcome == "approved":
                            report = publisher.verify(directory, package_digest, TEAM, PIN, architecture=architecture)
                            self.assertTrue(report["packagedApplicationDeveloperIDVerified"])
                            self.assertEqual(report["packagedApplicationArchitecture"], architecture)
                            self.assertNotIn("managedDetector", report)
                            self.assertEqual(native.call_count, 5)
                        else:
                            error = ValueError if outcome == "wrong-architecture" else subprocess.CalledProcessError
                            with self.assertRaises(error):
                                publisher.verify(directory, package_digest, TEAM, PIN, architecture=architecture)
                            self.assertEqual(native.call_count, 4 if outcome == "wrong-architecture" else 5)
                    self.assertEqual(list(directory.iterdir()), [package])

    def test_managed_deployment_checks_both_phase_entries_and_helper_publisher(self):
        approved_certificate = b"approved Developer ID Application leaf"
        application_pin = hashlib.sha256(approved_certificate).hexdigest()
        helper = image("arm64")
        phases = '<preinstall file="./preinstall"/><postinstall file="./postinstall"/>'
        for scenario, error in (
            ("approved", None),
            ("redirected-phase", "phase entry points differ"),
            ("duplicate-scripts", "phase entry points differ"),
            ("different-helpers", "do not use the same helper"),
            ("wrong-architecture", "matching thin native 64-bit executable"),
            ("different-certificate", "leaf certificate differs"),
            ("helper-changed", "helper changed during publisher verification"),
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                package = root / "approved.pkg"
                expanded = root / "expanded"
                app = expanded / "Payload" / publisher.BUNDLE_NAME
                scripts = expanded / "Scripts"
                signature_subjects = []
                certificate_subjects = []

                def tool(args, *, cwd=None):
                    if args[1] == "--expand-full":
                        core = app / "Contents" / "MacOS" / "accessweaver"
                        core.parent.mkdir(parents=True)
                        core.write_bytes(helper)
                        scripts.mkdir()
                        native = image("amd64") if scenario == "wrong-architecture" else helper
                        (scripts / "postinstall").write_bytes(native)
                        (scripts / "preinstall").write_bytes(
                            native + b"changed" if scenario == "different-helpers" else native
                        )
                        entries = phases.replace("./postinstall", "./other") if scenario == "redirected-phase" else phases
                        section = f"<scripts>{entries}</scripts>"
                        if scenario == "duplicate-scripts":
                            section += "<scripts/>"
                        (expanded / "PackageInfo").write_text(
                            f'<pkg-info identifier="{publisher.PACKAGE_ID}">{section}</pkg-info>',
                            encoding="utf-8",
                        )
                    elif args[1] == "--verify":
                        self.assertEqual(args[:4], ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures"])
                        self.assertIn(f'certificate leaf[subject.OU] = "{TEAM}"', args[-2])
                        signature_subjects.append(args[-1])
                    elif args[1] == "--display":
                        self.assertEqual(args[:3], ["/usr/bin/codesign", "--display", "--extract-certificates"])
                        subject = args[-1]
                        certificate_subjects.append(subject)
                        certificate = approved_certificate
                        if subject == scripts / "postinstall":
                            if scenario == "different-certificate":
                                certificate = b"unapproved leaf"
                            if scenario == "helper-changed":
                                for phase in ("preinstall", "postinstall"):
                                    (scripts / phase).write_bytes(helper + b"changed")
                        (cwd / "codesign0").write_bytes(certificate)
                    else:
                        self.fail(f"Unexpected command: {args}")
                    return ""

                with patch.object(publisher, "tool", side_effect=tool):
                    if error is None:
                        publisher.verify_packaged_deployment(package, TEAM, "arm64", application_pin)
                    else:
                        with self.assertRaisesRegex(ValueError, error):
                            publisher.verify_packaged_deployment(package, TEAM, "arm64", application_pin)
                expected = [app]
                if scenario in ("approved", "different-certificate", "helper-changed"):
                    expected.append(scripts / "postinstall")
                self.assertEqual(signature_subjects, expected)
                self.assertEqual(certificate_subjects, expected)

    @unittest.skipUnless(sys.platform in ("darwin", "win32", "linux"), "requires native exclusive rename")
    def test_detector_publication_recovers_after_process_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expanded = root / "expanded"
            scripts = expanded / "Scripts"
            scripts.mkdir(parents=True)
            content = image("arm64")
            for phase in ("preinstall", "postinstall"):
                (scripts / phase).write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            parent = root / "output"
            parent.mkdir()
            destination = parent / "accessweaver-installer"
            child = """
import os
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import verify_macos_installer_publisher as publisher

expanded, destination = map(Path, sys.argv[2:4])
publish = publisher.publish_staged_file

def interrupt(staged, final):
    publish(staged, final)
    os._exit(73)

with patch.object(publisher, "tool"), patch.object(publisher, "publish_staged_file", side_effect=interrupt):
    publisher.stage_detector(expanded, sys.argv[4], "arm64", sys.argv[5], destination, destination.parent.lstat())
"""
            process = subprocess.run([sys.executable, "-c", child, str(Path(publisher.__file__).parent),
                                      str(expanded), str(destination), TEAM, digest],
                                     timeout=20, capture_output=True)
            self.assertEqual(process.returncode, 73, process.stderr.decode(errors="replace"))
            original = destination.stat()
            self.assertEqual(original.st_nlink, 1)
            with patch.object(publisher, "tool"):
                publisher.stage_detector(expanded, TEAM, "arm64", digest, destination, parent.lstat())
            self.assertTrue(os.path.samestat(original, destination.stat()))
            self.assertEqual(destination.read_bytes(), content)
            displaced = root / "original-output"
            parent_info = parent.lstat()
            parent.rename(displaced)
            parent.mkdir()
            with patch.object(publisher, "tool") as native, self.assertRaisesRegex(
                ValueError, "Detector output directory changed"
            ):
                publisher.stage_detector(expanded, TEAM, "arm64", digest, destination, parent_info)
            native.assert_not_called()
            self.assertEqual(list(parent.iterdir()), [])
            self.assertEqual((displaced / destination.name).read_bytes(), content)

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

            leaf_bytes = b"synthetic Developer ID Application DER bytes"
            leaf_pin = hashlib.sha256(leaf_bytes).hexdigest()

            def tool(arguments, *, cwd=None):
                executable, action, *_ = arguments
                if action == "--display":
                    self.assertEqual(arguments[2], "--extract-certificates")
                    self.assertTrue(cwd.is_dir())
                    is_helper = arguments[-1].name != publisher.BUNDLE_NAME
                    if mode == "missing-app-leaf" and not is_helper:
                        return ""
                    wrong_leaf = ((mode == "wrong-leaf-app" and not is_helper)
                                  or (mode == "wrong-leaf-helper" and is_helper))
                    (cwd / "codesign0").write_bytes(b"different leaf" if wrong_leaf else leaf_bytes)
                    (cwd / "codesign1").write_bytes(b"inert intermediate")
                    return ""
                calls.append((executable, action))
                if action == "--check-signature":
                    return PACKAGE_OUTPUT
                if action == "--expand-full":
                    self.assertEqual(publisher.digest(arguments[-2]), package_digest)
                    expanded = arguments[-1]
                    scripts = expanded / "Scripts"
                    scripts.mkdir(parents=True)
                    helper = scripts / "postinstall"
                    detector = helper_bytes if mode != "wrong-architecture" else image("amd64")
                    helper.write_bytes(detector)
                    (scripts / "preinstall").write_bytes(detector if mode != "phase-mismatch" else b"unexpected")
                    core = expanded / "Payload" / publisher.BUNDLE_NAME / "Contents" / "MacOS" / "accessweaver"
                    core.parent.mkdir(parents=True)
                    core.write_bytes(image("amd64" if mode == "wrong-app-architecture" else "arm64"))
                    if mode == "hardlink":
                        os.link(helper, scripts / "alias")
                if executable == "/usr/bin/codesign":
                    self.assertEqual(arguments[1:4], ["--verify", "--strict", "--all-architectures"])
                    self.assertIn(f'certificate leaf[subject.OU] = "{TEAM}"', arguments[-2])
                    self.assertFalse(destination.exists() and mode not in ("existing", "conflict", "output-hardlink", "wrong-mode"))
                    target = arguments[-1]
                    if target.name == publisher.BUNDLE_NAME:
                        self.assertIn(f'identifier "{publisher.BUNDLE_ID}"', arguments[-2])
                        if mode == "wrong-app-publisher":
                            raise subprocess.CalledProcessError(1, arguments)
                    else:
                        self.assertNotIn(" and identifier ", arguments[-2])
                        self.assertEqual(target.read_bytes(), helper_bytes)
                        if mode == "wrong-publisher":
                            raise subprocess.CalledProcessError(1, arguments)
                        if mode == "changed-after-signature":
                            target.write_bytes(b"changed after signature")
                return ""

            def verify(digest=helper_digest, application_pin=None):
                return publisher.verify(directory, package_digest, TEAM, PIN, detector_output=destination,
                                        detector_sha256=digest, architecture="arm64",
                                        application_certificate_sha256=application_pin)

            with patch.object(publisher, "tool", side_effect=tool):
                for mode, digest, error in (
                    ("wrong-pin", "d" * 64, ValueError),
                    ("wrong-architecture", helper_digest, ValueError),
                    ("wrong-app-architecture", helper_digest, ValueError),
                    ("wrong-app-publisher", helper_digest, subprocess.CalledProcessError),
                    ("phase-mismatch", helper_digest, ValueError),
                    ("hardlink", helper_digest, ValueError),
                    ("wrong-publisher", helper_digest, subprocess.CalledProcessError),
                    ("changed-after-signature", helper_digest, ValueError),
                ):
                    with self.subTest(mode=mode), self.assertRaises(error):
                        verify(digest)
                    self.assertFalse(destination.exists())
                    self.assertEqual(sorted(p.name for p in root.iterdir()), ["input"])
                for mode, error in (
                    ("wrong-leaf-app", ValueError), ("wrong-leaf-helper", ValueError),
                    ("missing-app-leaf", FileNotFoundError),
                ):
                    with self.subTest(mode=mode), self.assertRaises(error):
                        verify(application_pin=leaf_pin)
                    self.assertFalse(destination.exists())

                mode = "approved"
                app_report = publisher.verify(directory, package_digest, TEAM, PIN, architecture="arm64",
                                              application_certificate_sha256=leaf_pin.upper())
                self.assertEqual(app_report["applicationCertificateSHA256"], leaf_pin)
                self.assertNotIn("managedDetector", app_report)
                self.assertFalse(destination.exists())
                calls.clear()
                report = verify(application_pin=leaf_pin)
                self.assertEqual(report["applicationCertificateSHA256"], leaf_pin)
                self.assertEqual(calls, [
                    ("/usr/sbin/pkgutil", "--check-signature"), ("/usr/sbin/spctl", "--assess"),
                    ("/usr/bin/xcrun", "stapler"), ("/usr/sbin/pkgutil", "--expand-full"),
                    ("/usr/bin/codesign", "--verify"), ("/usr/bin/codesign", "--verify"),
                ])
                self.assertTrue(report["packagedApplicationDeveloperIDVerified"])
                self.assertEqual(report["managedDetector"], {
                    "architecture": "arm64", "sha256": helper_digest, "developerIDApplicationVerified": True,
                })
                self.assertEqual(destination.read_bytes(), helper_bytes)
                self.assertEqual(destination.stat().st_nlink, 1)
                mode = "existing"
                before = destination.stat()
                retry = verify(application_pin=leaf_pin)
                self.assertEqual(retry, report)
                self.assertEqual(destination.stat().st_ino, before.st_ino)
                self.assertEqual(destination.stat().st_mtime_ns, before.st_mtime_ns)
                mode = "conflict"
                destination.write_bytes(b"existing assignment")
                with self.assertRaisesRegex(ValueError, "differs from the approved digest"):
                    verify()
                self.assertEqual(destination.read_bytes(), b"existing assignment")
                destination.write_bytes(helper_bytes)
                mode = "output-hardlink"
                alias = root / "alias"
                os.link(destination, alias)
                with self.assertRaisesRegex(ValueError, "bounded regular package file"):
                    verify()
                self.assertEqual(alias.read_bytes(), helper_bytes)
                alias.unlink()
                if os.name == "posix":
                    mode = "wrong-mode"
                    destination.chmod(0o644)
                    with self.assertRaisesRegex(ValueError, "mode 0755"):
                        verify()
                    self.assertEqual(destination.read_bytes(), helper_bytes)

            with patch.object(publisher, "tool") as native:
                for output, pin, arch in (
                    (destination, None, "arm64"),
                    (directory / "accessweaver-installer", helper_digest, "arm64"),
                    (root / "other", helper_digest, "arm64"),
                    (root / "missing" / "accessweaver-installer", helper_digest, "arm64"),
                    (destination, helper_digest, "x64"),
                ):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        publisher.verify(directory, package_digest, TEAM, PIN, detector_output=output,
                                         detector_sha256=pin, architecture=arch)
                for arch, invalid_pin in ((None, leaf_pin), ("arm64", "wrong")):
                    with self.assertRaises(ValueError):
                        publisher.verify(directory, package_digest, TEAM, PIN, architecture=arch,
                                         application_certificate_sha256=invalid_pin)
                native.assert_not_called()

    def test_signing_options_require_complete_approved_identity(self):
        settings = ("Fixture application", "Fixture installer", TEAM, PIN.upper(), "Fixture profile")
        self.assertIsNone(builder.publisher_options(None, None, None, None, None))
        with self.assertRaises(ValueError):
            builder.publisher_options(*settings)
        with self.assertRaises(ValueError):
            builder.publisher_options("", "", "", "", "", "")
        self.assertEqual(builder.publisher_options(*settings, "CD" * 32).application_fingerprint, "cd" * 32)
        with self.assertRaises(ValueError):
            builder.publisher_options(*settings, "invalid")
        with self.assertRaises(ValueError):
            builder.publisher_options(None, None, None, None, None, PIN)
        for index in range(len(settings)):
            rejected = list(settings)
            rejected[index] = None
            with self.assertRaises(ValueError):
                builder.publisher_options(*rejected, "cd" * 32)
        with self.assertRaises(ValueError):
            builder.publisher_options(*settings[:-1], "--wait", "cd" * 32)

    def test_notary_submission_follows_certificate_and_requires_acceptance(self):
        context = builder.publisher_options("Fixture application", "Fixture installer", TEAM, PIN, "Fixture profile", "cd" * 32)
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
        context = builder.publisher_options("Fixture application", "Fixture installer", TEAM, PIN, "Fixture profile", "cd" * 32)
        with patch.object(builder, "run") as run, patch.object(builder, "check_application_certificate"):
            builder.sign_code(Path("AccessWeaver.app"), context, bundle=True)
        sign, verify = [call.args[0] for call in run.call_args_list]
        self.assertIn("--timestamp", sign)
        self.assertIn("runtime", sign)
        self.assertIn("--all-architectures", verify)
        self.assertIn(f'certificate leaf[subject.OU] = "{TEAM}"', verify[-2])
        self.assertIn(f'identifier "{builder.BUNDLE_ID}"', verify[-2])

    def test_signed_builder_checks_exact_certificate_for_both_executable_subjects(self):
        context = builder.publisher_options("Fixture application", "Fixture installer", TEAM, PIN, "Fixture profile",
                                            "cd" * 32)
        for path, bundle in ((Path("AccessWeaver.app"), True), (Path("accessweaver-installer"), False)):
            calls = MagicMock()
            with self.subTest(path=path), patch.multiple(builder, run=calls.run,
                                                         check_application_certificate=calls.check_leaf):
                builder.sign_code(path, context, bundle=bundle)
                self.assertEqual([call[0] for call in calls.mock_calls], ["run", "run", "check_leaf"])
                calls.check_leaf.assert_called_once_with(path, "cd" * 32)
                calls.reset_mock()
                calls.run.side_effect = [None, subprocess.CalledProcessError(1, "codesign")]
                with self.assertRaises(subprocess.CalledProcessError):
                    builder.sign_code(path, context, bundle=bundle)
                calls.check_leaf.assert_not_called()
                calls.run.side_effect = None
                calls.check_leaf.side_effect = ValueError("Fixture certificate mismatch")
                with self.assertRaisesRegex(ValueError, "certificate mismatch"):
                    builder.sign_code(path, context, bundle=bundle)

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
