import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import stage_packaged_native as candidate

COMMIT = "a" * 40
REF = "refs/heads/main"


class StagingTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "release"
        source.mkdir()
        artifacts = []
        for system in ("windows", "linux", "darwin", "freebsd", "openbsd"):
            for arch in ("amd64", "arm64"):
                suffix = ".zip" if system == "windows" else ".tar.gz"
                name = "accessweaver-preview-" + system + "-" + arch + suffix
                (source / name).write_bytes(b"original archived binary")
                artifacts.append({"goos": system, "goarch": arch, "file": name, "sha256": hashlib.sha256(b"original archived binary").hexdigest()})
        info = {"commit": COMMIT, "sourceState": "clean", "platform": "linux", "arch": "arm64", "version": "0.1.0-alpha", "builtAt": "2026-11-01T00:00:00Z", "goVersion": "go1.27.3"}
        (source / "BUILD-MANIFEST.json").write_text(json.dumps({"sourceCommit": COMMIT, "sourceState": "clean", "version": info["version"], "builtAt": info["builtAt"], "artifacts": artifacts}), encoding="utf-8")
        (source / "SHA256SUMS.txt").write_bytes(b"fixture checksums")
        (source / "BUILD-PROVENANCE.sigstore.json").write_bytes(b"fixture, NOT a signature")
        return source, info

    def test_authentication_precedes_interpretation_and_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, _ = self.fixture(root)
            (source / "BUILD-MANIFEST.json").write_bytes(b"untrusted malformed metadata")
            with patch.object(candidate, "host_target", return_value=("linux", "arm64")), patch.object(candidate, "verify_provenance", side_effect=ValueError("bad signature")), patch.object(candidate, "inspect_archive") as inspect:
                with self.assertRaisesRegex(ValueError, "bad signature"):
                    candidate.stage(source, root / "out", ("linux", "arm64"), COMMIT, REF)
                inspect.assert_not_called()
                self.assertFalse((root / "out").exists())

    def test_authenticated_snapshot_cannot_be_replaced_through_original_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, info = self.fixture(root)
            def authenticate(snapshot, commit, ref, gh):
                self.assertNotEqual(snapshot, source)
                self.assertEqual((commit, ref), (COMMIT, REF))
                (source / "accessweaver-preview-linux-arm64.tar.gz").write_bytes(b"changed after copying")
                (source / "BUILD-MANIFEST.json").write_bytes(b"changed metadata")
                return {"subjectsVerified": 12}
            def inspect(path, archive_root, binary_name):
                self.assertEqual(path.read_bytes(), b"original archived binary")
                self.assertEqual(binary_name, "accessweaver")
                return info, b"verified executable"
            with patch.object(candidate, "host_target", return_value=("linux", "arm64")), patch.object(candidate, "verify_provenance", side_effect=authenticate), patch.object(candidate, "inspect_archive", side_effect=inspect):
                receipt = candidate.stage(source, root / "out", ("linux", "arm64"), COMMIT, REF)
            self.assertTrue(receipt["authenticatedBeforeStaging"])
            self.assertFalse(receipt["publisherSignatureVerified"])
            self.assertEqual((root / "out" / "accessweaver").read_bytes(), b"verified executable")
            self.assertEqual(receipt["binarySha256"], hashlib.sha256(b"verified executable").hexdigest())
            self.assertEqual(json.loads((root / "out" / "candidate.json").read_text())["sourceCommit"], COMMIT)

    def test_wrong_host_existing_destination_and_input_overlap_fail_before_authentication(self):
        for mode in ("host", "existing", "overlap", "unsupported", "wrong-commit", "wrong-ref"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, _ = self.fixture(root)
                destination = root / "out"
                target = ("linux", "arm64")
                if mode == "existing":
                    destination.mkdir()
                    (destination / "preserved").write_bytes(b"keep")
                if mode == "overlap":
                    destination = source / "output"
                if mode == "unsupported":
                    target = ("freebsd", "amd64")
                with patch.object(candidate, "host_target", return_value=("windows", "amd64") if mode == "host" else ("linux", "arm64")), patch.object(candidate, "verify_provenance") as auth:
                    with self.assertRaises((ValueError, FileExistsError)):
                        candidate.stage(source, destination, target, "unknown" if mode == "wrong-commit" else COMMIT, "main" if mode == "wrong-ref" else REF)
                    auth.assert_not_called()
                if mode == "existing":
                    self.assertEqual((destination / "preserved").read_bytes(), b"keep")

    def test_unexpected_or_oversize_snapshot_stops_before_authentication(self):
        for mode in ("extra", "oversize", "directory"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, _ = self.fixture(root)
                if mode == "extra":
                    (source / "unattested.exe").write_bytes(b"extra")
                else:
                    item = source / "SHA256SUMS.txt"
                    item.unlink()
                    if mode == "oversize":
                        with item.open("wb") as stream:
                            stream.truncate((128 << 20) + 1)
                    else:
                        item.mkdir()
                with patch.object(candidate, "host_target", return_value=("linux", "arm64")), patch.object(candidate, "verify_provenance") as auth:
                    with self.assertRaises(ValueError):
                        candidate.stage(source, root / "out", ("linux", "arm64"), COMMIT, REF)
                    auth.assert_not_called()

    def test_native_archive_and_identity_cannot_be_substituted(self):
        for mode in ("digest", "arch", "source", "missing-target"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, info = self.fixture(root)
                if mode in ("digest", "missing-target"):
                    path = source / "BUILD-MANIFEST.json"
                    manifest = json.loads(path.read_text())
                    if mode == "digest":
                        next(a for a in manifest["artifacts"] if a["goos"] == "linux" and a["goarch"] == "arm64")["sha256"] = "0" * 64
                    else:
                        manifest["artifacts"] = []
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                if mode == "arch":
                    info["arch"] = "amd64"
                if mode == "source":
                    info["commit"] = "b" * 40
                with patch.object(candidate, "host_target", return_value=("linux", "arm64")), patch.object(candidate, "verify_provenance", return_value={"subjectsVerified": 12}), patch.object(candidate, "inspect_archive", return_value=(info, b"executable")):
                    with self.assertRaises(ValueError):
                        candidate.stage(source, root / "out", ("linux", "arm64"), COMMIT, REF)
                    self.assertFalse((root / "out").exists())


    def test_freebsd_guest_staging_authenticates_exact_archive_on_matching_linux_host(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, info = self.fixture(root)
                info.update(platform="freebsd", arch=arch)
                def inspect(path, archive_root, binary_name):
                    self.assertEqual(path.name, "accessweaver-preview-freebsd-" + arch + ".tar.gz")
                    self.assertEqual(path.read_bytes(), b"original archived binary")
                    return info, b"verified archived FreeBSD executable"
                with patch.object(candidate, "host_target", return_value=("linux", arch)), patch.object(candidate, "verify_provenance", return_value={"subjectsVerified": 12}) as auth, patch.object(candidate, "inspect_archive", side_effect=inspect):
                    receipt = candidate.stage_freebsd_guest(source, root / "out", ("freebsd", arch), COMMIT, REF)
                auth.assert_called_once()
                self.assertEqual(receipt["executionEnvironment"], "disposable-freebsd-guest")
                self.assertEqual(receipt["target"], "freebsd/" + arch)
                self.assertTrue(receipt["authenticatedBeforeStaging"])
                self.assertFalse(receipt["publisherSignatureVerified"])
                self.assertEqual((root / "out/accessweaver").read_bytes(), b"verified archived FreeBSD executable")

    def test_freebsd_staging_refuses_wrong_host_or_target_before_authentication(self):
        for host, target in ((("windows", "amd64"), ("freebsd", "amd64")),
                             (("freebsd", "amd64"), ("freebsd", "amd64")),
                             (("linux", "arm64"), ("freebsd", "amd64")),
                             (("linux", "amd64"), ("openbsd", "amd64")),
                             (("linux", "amd64"), ("linux", "amd64"))):
            with self.subTest(host=host, target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, _ = self.fixture(root)
                with patch.object(candidate, "host_target", return_value=host), patch.object(candidate, "verify_provenance") as auth:
                    with self.assertRaises(ValueError):
                        candidate.stage_freebsd_guest(source, root / "out", target, COMMIT, REF)
                    auth.assert_not_called()
                self.assertFalse((root / "out").exists())

    def test_freebsd_staging_never_interprets_unauthenticated_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, _ = self.fixture(root)
            (source / "BUILD-MANIFEST.json").write_bytes(b"malformed untrusted metadata")
            with patch.object(candidate, "host_target", return_value=("linux", "amd64")), patch.object(candidate, "verify_provenance", side_effect=ValueError("bad signature")), patch.object(candidate, "inspect_archive") as inspect:
                with self.assertRaisesRegex(ValueError, "bad signature"):
                    candidate.stage_freebsd_guest(source, root / "out", ("freebsd", "amd64"), COMMIT, REF)
                inspect.assert_not_called()
                self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
