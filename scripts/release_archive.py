"""Stable metadata for unsigned portable archives; no installer/signing claim."""
from datetime import datetime, timezone
import gzip
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile


MAX_EPOCH = 0xFFFFFFFF  # gzip timestamp range; also representable by ZIP


def timestamp(epoch):
    if not isinstance(epoch, str) or not re.fullmatch(r"[0-9]{1,10}", epoch):
        raise ValueError("SOURCE_DATE_EPOCH must be an integer between 0 and 4294967295")
    value = int(epoch)
    if value > MAX_EPOCH:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer between 0 and 4294967295")
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch_from_timestamp(value):
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def tracked_release_documents(root):
    """Use the repository's tracked documentation as the archive inventory."""
    listed = subprocess.check_output(
        ["git", "ls-files", "--cached", "-z", "--", "docs/"], cwd=root, timeout=30,
    )
    paths = sorted({Path(name.decode("utf-8")) for name in listed.split(b"\0") if name})
    for path in paths:
        source = root / path
        if any((root / parent).is_symlink() for parent in (path, *path.parents)) or not source.is_file():
            raise ValueError("Tracked release documentation must be a regular file: " + path.as_posix())
    return paths


def write_archive(archive, pairs, epoch, executable):
    """Ignore host uid, permissions, file times, paths and timezone.

    Content, member names, toolchain and compression-library versions remain
    rebuild inputs. ZIP timestamps cannot precede 1980 and have 2-second precision.
    """
    timestamp(str(epoch))  # reject invalid/out-of-range epochs before writing
    pairs = sorted(pairs, key=lambda pair: pair[1])
    if archive.suffix == ".zip":
        date = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc)
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for source, name in pairs:
                info = zipfile.ZipInfo(name, date.timetuple()[:6])
                info.create_system = 3
                mode = 0o755 if name == executable else 0o644
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, Path(source).read_bytes(), compresslevel=9)
    else:
        with archive.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output:
                    for source, name in pairs:
                        info = tarfile.TarInfo(name)
                        info.size = Path(source).stat().st_size
                        info.mode = 0o755 if name == executable else 0o644
                        info.mtime = epoch
                        # TarInfo defaults to uid/gid 0 and empty owner names.
                        with Path(source).open("rb") as content:
                            output.addfile(info, content)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "timestamp":
        sys.exit("Usage: release_archive.py timestamp SOURCE_DATE_EPOCH")
    try:
        print(timestamp(sys.argv[2]))
    except ValueError as error:
        sys.exit(str(error))
