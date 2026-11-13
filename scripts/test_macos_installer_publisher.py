import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_macos_installer_publisher as publisher


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
