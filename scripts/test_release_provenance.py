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

    def test_authentication_and_content_checks_use_the_same_private_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            original = {path.name: path.read_bytes() for path in root.iterdir()}
            authenticated = []

            def authenticate(command, **_):
                subject = Path(command[3])
                bundle = Path(command[command.index("--bundle") + 1])
                self.assertNotEqual(subject.parent, root.resolve())
                self.assertEqual(bundle.parent, subject.parent)
                self.assertEqual(subject.read_bytes(), original[subject.name])
                self.assertEqual(bundle.read_bytes(), original[BUNDLE_NAME])
                if not authenticated:
                    self.assertEqual(subject.name, "BUILD-MANIFEST.json")
                    for name in original:
                        (root / name).write_bytes(b"replacement")
                    (root / "extra.exe").write_bytes(b"late extra")
                authenticated.append(subject)

            def check_contents(directory, *, execute_native):
                self.assertFalse(execute_native)
                self.assertEqual(len(authenticated), 12)
                self.assertEqual({path.name for path in authenticated}, original.keys() - {BUNDLE_NAME})
                self.assertEqual({path.parent for path in authenticated}, {directory.resolve()})
                self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, original)

            with patch("verify_release_provenance.subprocess.run", side_effect=authenticate), patch(
                "verify_release_provenance.verify_contents", side_effect=check_contents
            ) as contents:
                result = verify(root, COMMIT, REF)
                contents.assert_called_once()
                self.assertFalse(contents.call_args.args[0].exists())
                self.assertEqual(result["subjectsVerified"], 12)
                self.assertFalse(result["publisherSignatureVerified"])

    def test_tag_must_match_authenticated_manifest_version_and_release_label(self):
        for label, version, accepted in (
            ("v1.2.3-alpha", "1.2.3-alpha", True),
            ("v1.2.4-alpha", "1.2.3-alpha", False),
            ("v1.2.3-alpha", "1.2.3", False),
            (None, None, False),
        ):
            with self.subTest(label=label, version=version), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                self.fixture(root)
                path = root / "BUILD-MANIFEST.json"
                manifest = json.loads(path.read_text(encoding="utf-8"))
                if label is not None:
                    manifest.update(releaseLabel=label, version=version)
                path.write_text(json.dumps(manifest), encoding="utf-8")
                with patch("verify_release_provenance.authenticate") as authenticate, patch("verify_release_provenance.verify_contents") as contents:
                    if accepted:
                        verify(root, COMMIT, "refs/tags/v1.2.3-alpha")
                        self.assertEqual(authenticate.call_count, 12)
                        contents.assert_called_once()
                    else:
                        with self.assertRaisesRegex(ValueError, "label and version"):
                            verify(root, COMMIT, "refs/tags/v1.2.3-alpha")
                        authenticate.assert_called_once()
                        contents.assert_not_called()

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
