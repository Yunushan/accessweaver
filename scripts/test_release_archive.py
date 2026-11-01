import hashlib
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
import unittest
import zipfile

from release_archive import epoch_from_timestamp, timestamp, write_archive


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


if __name__ == "__main__":
    unittest.main()
