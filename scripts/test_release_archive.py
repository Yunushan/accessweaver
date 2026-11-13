import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

from release_archive import epoch_from_timestamp, timestamp, write_archive
import verify_release as release


class ArchiveTests(unittest.TestCase):
    def test_epoch_validation_and_roundtrip(self):
        for epoch in ("0", "1", "1760000001", "4294967295"):
            self.assertEqual(epoch_from_timestamp(timestamp(epoch)), int(epoch))
        for value in ("", "-1", "1.5", " 1", "1\n", "4294967296", "99999999999999999"):
            with self.subTest(epoch=value), self.assertRaises(ValueError):
                timestamp(value)

    def test_metadata_changes_do_not_change_archive_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary, notice = root / "exe", root / "notice"
            binary.write_bytes(b"same executable bytes")
            notice.write_text("same notice\n", encoding="utf-8")
            pairs = [(binary, "candidate/accessweaver"), (notice, "candidate/LICENSE")]
            for extension in (".zip", ".tar.gz"):
                first, second = root / ("first" + extension), root / ("second" + extension)
                os.utime(binary, (1700000000, 1700000000))
                binary.chmod(0o600)
                write_archive(first, pairs, 1760000001, executable="candidate/accessweaver")
                os.utime(binary, (1800000000, 1800000000))
                os.utime(notice, (1800000010, 1800000010))
                binary.chmod(0o755)
                write_archive(second, list(reversed(pairs)), 1760000001, executable="candidate/accessweaver")
                self.assertEqual(first.read_bytes(), second.read_bytes(), extension)
                if extension == ".zip":
                    with zipfile.ZipFile(first) as archive:
                        for entry in archive.infolist():
                            self.assertEqual(entry.create_system, 3)
                            expected = 0o755 if entry.filename.endswith("accessweaver") else 0o644
                            self.assertEqual(stat.S_IMODE(entry.external_attr >> 16), expected)
                            self.assertEqual(entry.date_time, (2025, 10, 9, 8, 53, 20))
                else:
                    self.assertEqual(int.from_bytes(first.read_bytes()[4:8], "little"), 1760000001)
                    self.assertEqual(first.read_bytes()[3] & 8, 0, "gzip must not embed the output filename")
                    with tarfile.open(first) as archive:
                        for entry in archive.getmembers():
                            self.assertEqual((entry.uid, entry.gid, entry.uname, entry.gname), (0, 0, "", ""))
                            self.assertEqual(entry.mtime, 1760000001)
                            expected = 0o755 if entry.name.endswith("accessweaver") else 0o644
                            self.assertEqual(entry.mode, expected)

    def test_content_and_epoch_changes_change_archive_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            for extension in (".zip", ".tar.gz"):
                output = root / ("candidate" + extension)
                def digest(epoch):
                    write_archive(output, [(source, "root/file")], epoch, executable="root/file")
                    return hashlib.sha256(output.read_bytes()).digest()
                source.write_bytes(b"original")
                original = digest(1760000000)
                self.assertNotEqual(original, digest(1760000004))
                source.write_bytes(b"changed")
                self.assertNotEqual(original, digest(1760000000))

    def test_zip_clamps_old_epochs_without_changing_build_timestamp(self):
        self.assertEqual(timestamp("0"), "1970-01-01T00:00:00Z")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            source.write_bytes(b"old")
            output = root / "old.zip"
            write_archive(output, [(source, "root/file")], 0, executable="root/file")
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.infolist()[0].date_time, (1980, 1, 1, 0, 0, 0))

    @unittest.skipUnless(hasattr(time, "tzset"), "tzset is unavailable on Windows")
    def test_host_timezone_does_not_affect_zip(self):
        previous = os.environ.get("TZ")
        try:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                source = root / "source"
                source.write_bytes(b"same")
                results = []
                for zone in ("UTC0", "EST5EDT"):
                    os.environ["TZ"] = zone
                    time.tzset()
                    output = root / (zone + ".zip")
                    write_archive(output, [(source, "root/file")], 1760000001, executable="root/file")
                    results.append(output.read_bytes())
                self.assertEqual(results[0], results[1])
        finally:
            if previous is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous
            time.tzset()


class ArchiveMemberValidationTests(unittest.TestCase):
    def write_members(self, path, names):
        if path.suffix == ".zip":
            with zipfile.ZipFile(path, "w") as archive:
                for name in names:
                    archive.writestr(name, b"x")
        else:
            with tarfile.open(path, "w:gz") as archive:
                for name in names:
                    member = tarfile.TarInfo(name)
                    member.size = 1
                    archive.addfile(member, io.BytesIO(b"x"))

    def test_archive_rejects_path_aliases_and_file_directory_conflicts(self):
        cases = [
            (["root//file"], "Unsafe archive entry"),
            (["root/./file"], "Unsafe archive entry"),
            (["root/docs/NUL.txt"], "Unsafe archive entry"),
            (["root/docs/AUX"], "Unsafe archive entry"),
            (["root/docs/stream:payload"], "Unsafe archive entry"),
            (["root/docs/file."], "Unsafe archive entry"),
            (["root/docs/readme", "root/docs/README"], "Conflicting archive entry"),
            (["root/docs", "root/docs/file"], "Conflicting archive directory"),
            (["root/docs/file", "root/docs"], "Conflicting archive entry"),
            (["root/docs/one", "root/DOCS/two"], "Conflicting archive directory"),
        ]
        with tempfile.TemporaryDirectory() as folder:
            for extension in (".zip", ".tar.gz"):
                path = Path(folder) / ("candidate" + extension)
                for names, error in cases:
                    with self.subTest(extension=extension, names=names):
                        self.write_members(path, names)
                        with self.assertRaisesRegex(ValueError, error):
                            release.inspect_archive(path, "root", "accessweaver")

    def test_archive_rejects_nonregular_zip_member_and_member_overflow(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "candidate.zip"
            with zipfile.ZipFile(path, "w") as archive:
                member = zipfile.ZipInfo("root/device")
                member.create_system = 3
                member.external_attr = (stat.S_IFIFO | 0o600) << 16
                archive.writestr(member, b"")
            with self.assertRaisesRegex(ValueError, "Unsafe archive entry"):
                release.inspect_archive(path, "root", "accessweaver")
            for extension in (".zip", ".tar.gz"):
                path = Path(folder) / ("candidate" + extension)
                self.write_members(path, ["root/first", "root/second"])
                with patch.object(release, "MAX_ARCHIVE_MEMBERS", 1), self.assertRaisesRegex(ValueError, "member count"):
                    release.inspect_archive(path, "root", "accessweaver")


class ReleaseVerificationTests(unittest.TestCase):
    def fixture(self, directory):
        manifest = dict(unsigned=True, sourceState="clean", sourceCommit="a" * 40,
                        targetExecutionTested=False, version="1.0.0-alpha", builtAt="fixture", artifacts=[])
        # Put the host first to detect execution before later validation.
        targets = [("windows", "amd64")] + sorted(release.TARGETS - {("windows", "amd64")})
        checksums = {}
        for system, arch in targets:
            name = f"accessweaver-preview-{system}-{arch}" + (".zip" if system == "windows" else ".tar.gz")
            data = name.encode()
            (directory / name).write_bytes(data)
            checksums[name] = hashlib.sha256(data).hexdigest()
            manifest["artifacts"].append(dict(goos=system, goarch=arch, file=name, sha256=checksums[name], bytes=len(data)))
        data = json.dumps(manifest).encode()
        (directory / "BUILD-MANIFEST.json").write_bytes(data)
        checksums["BUILD-MANIFEST.json"] = hashlib.sha256(data).hexdigest()
        (directory / "SHA256SUMS.txt").write_text("".join(f"{h}  {n}\n" for n, h in checksums.items()), encoding="utf-8")
        return manifest

    def test_native_execution_occurs_only_after_every_archive_passes(self):
        for damaged in (False, True):
            with self.subTest(damaged=damaged), tempfile.TemporaryDirectory() as folder:
                directory = Path(folder)
                manifest = self.fixture(directory)
                if damaged:
                    path = directory / manifest["artifacts"][-1]["file"]
                    path.write_bytes(b"x" * path.stat().st_size)

                def inspect(path, _root, _binary_name):
                    self.assertNotEqual(path.parent, directory)
                    item = next(row for row in manifest["artifacts"] if row["file"] == path.name)
                    info = dict(version=manifest["version"], commit=manifest["sourceCommit"],
                                sourceState=manifest["sourceState"], builtAt=manifest["builtAt"],
                                platform=item["goos"], arch=item["goarch"])
                    return info, path.read_bytes()

                with (
                    patch.object(release.sys, "platform", "win32"),
                    patch.object(release.platform, "machine", return_value="AMD64"),
                    patch.object(release, "inspect_archive", side_effect=inspect) as inspect_archive,
                    patch.object(release, "execute_metadata") as execute,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    if damaged:
                        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
                            release.verify(directory, execute_native=True)
                        execute.assert_not_called()
                    else:
                        release.verify(directory, execute_native=True)
                        self.assertEqual(inspect_archive.call_count, 10)
                        execute.assert_called_once()
                        self.assertEqual(execute.call_args.args[:2],
                                         (manifest["artifacts"][0]["file"].encode(), "accessweaver.exe"))

    def test_unexpected_release_file_is_refused_before_archive_inspection(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            self.fixture(directory)
            (directory / "unexpected.exe").write_bytes(b"not part of the release")
            with (
                patch.object(release, "inspect_archive") as inspect,
                patch.object(release, "execute_metadata") as execute,
                self.assertRaisesRegex(ValueError, "Unexpected release input"),
            ):
                release.verify(directory, execute_native=True)
            inspect.assert_not_called()
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
