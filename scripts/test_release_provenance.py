import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from verify_release_provenance import BUNDLE_NAME, REPOSITORY, WORKFLOW, validate_identity, verification_command, verify

COMMIT = "a" * 40
REF = "refs/heads/main"


class ProvenanceTests(unittest.TestCase):
    def test_identity_is_independently_required_and_fully_pinned(self):
        for commit, ref in [("unknown", REF), ("a" * 7, REF), (COMMIT, "main"), (COMMIT, "refs/tags/x\n"), (COMMIT, "refs/heads/a/../main")]:
            with self.subTest(commit=commit, ref=ref), self.assertRaises(ValueError):
                validate_identity(commit, ref)
        command = verification_command(Path("artifact"), Path("bundle"), COMMIT, REF)
        for flag, expected in {"--repo": REPOSITORY, "--signer-workflow": WORKFLOW, "--source-digest": COMMIT,
                               "--signer-digest": COMMIT, "--source-ref": REF, "--hostname": "github.com",
                               "--cert-oidc-issuer": "https://token.actions.githubusercontent.com",
                               "--predicate-type": "https://slsa.dev/provenance/v1"}.items():
            self.assertEqual(command[command.index(flag) + 1], expected)
        self.assertIn("--deny-self-hosted-runners", command)
        self.assertNotIn("--execute-native", command)

    def fixture(self, root):
        artifacts = []
        for os_name in ("windows", "linux", "darwin", "freebsd", "openbsd"):
            for arch in ("amd64", "arm64"):
                extension = ".zip" if os_name == "windows" else ".tar.gz"
                name = f"accessweaver-preview-{os_name}-{arch}{extension}"
                (root / name).write_bytes(b"fixture archive")
                artifacts.append({"goos": os_name, "goarch": arch, "file": name})
        (root / "BUILD-MANIFEST.json").write_text(json.dumps({"sourceCommit": COMMIT, "sourceState": "clean", "unsigned": True, "artifacts": artifacts}), encoding="utf-8")
        (root / "SHA256SUMS.txt").write_bytes(b"fixture checksums")
        (root / BUNDLE_NAME).write_bytes(b"fixture bundle (NOT a signature)")

    def test_authentication_precedes_metadata_and_no_fallback_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            (root / "BUILD-MANIFEST.json").write_text("untrusted malformed metadata", encoding="utf-8")
            with patch("verify_release_provenance.subprocess.run", side_effect=subprocess.CalledProcessError(1, "gh")) as run, patch("verify_release_provenance.verify_contents") as contents:
                with self.assertRaisesRegex(ValueError, "Cryptographic"):
                    verify(root, COMMIT, REF)
                self.assertEqual(run.call_count, 1)
                contents.assert_not_called()

    def test_every_subject_authenticated_before_content_check(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            with patch("verify_release_provenance.subprocess.run") as run, patch("verify_release_provenance.verify_contents") as contents:
                result = verify(root, COMMIT, REF)
                self.assertEqual(run.call_count, 12)
                contents.assert_called_once_with(root.resolve(), execute_native=False)
                subjects = {Path(call.args[0][3]).name for call in run.call_args_list}
                self.assertEqual(subjects, {p.name for p in root.iterdir()} - {BUNDLE_NAME})
                self.assertEqual(result["subjectsVerified"], 12)
                self.assertFalse(result["publisherSignatureVerified"])

    def test_missing_bundle_extra_files_and_wrong_manifest_fail_closed(self):
        for mode in ("missing", "extra", "wrong-source", "modified"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                self.fixture(root)
                if mode == "missing":
                    (root / BUNDLE_NAME).unlink()
                elif mode == "extra":
                    (root / "extra.exe").write_bytes(b"not attested")
                else:
                    manifest_path = root / "BUILD-MANIFEST.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["sourceCommit" if mode == "wrong-source" else "sourceState"] = "b" * 40 if mode == "wrong-source" else "modified"
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                with patch("verify_release_provenance.subprocess.run"), patch("verify_release_provenance.verify_contents") as contents:
                    with self.assertRaises((ValueError, OSError)):
                        verify(root, COMMIT, REF)
                    contents.assert_not_called()


if __name__ == "__main__":
    unittest.main()
