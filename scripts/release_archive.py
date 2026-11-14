"""Stable metadata for unsigned portable archives; no installer/signing claim."""
from datetime import datetime, timezone
import gzip
import hashlib
from pathlib import Path
import re
import shutil
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


def zip_member_timestamp(epoch):
    """Represent the UTC build time using ZIP's date range and precision."""
    epoch = max(epoch, 315532800)
    return datetime.fromtimestamp(epoch - epoch % 2, timezone.utc).timetuple()[:6]


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


def stage_release_documents(root, destination):
    paths = tracked_release_documents(root)
    for path in paths:
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with (root / path).open("rb") as source, target.open("xb") as output:
            shutil.copyfileobj(source, output)


def write_archive(archive, pairs, epoch, executable):
    """Ignore host uid, permissions, file times, paths and timezone.

    Content, member names, toolchain and compression-library versions remain
    rebuild inputs. ZIP timestamps cannot precede 1980 and have 2-second precision.
    """
    timestamp(str(epoch))  # reject invalid/out-of-range epochs before writing
    pairs = sorted(pairs, key=lambda pair: pair[1])
    if archive.suffix == ".zip":
        date = zip_member_timestamp(epoch)
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for source, name in pairs:
                info = zipfile.ZipInfo(name, date)
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


def validate_release_binaries(directory):
    """Require one output for every portable target before assembling archives."""
    from verify_release import TARGETS, release_file, MAX_FILE

    names = {
        f"accessweaver-{system}-{arch}" + (".exe" if system == "windows" else "")
        for system, arch in TARGETS
    }
    if {path.name for path in directory.iterdir()} != names | {"BUILD-INFO.json"}:
        raise ValueError("Expected exactly the ten portable release binaries and build metadata")
    release_file(directory / "BUILD-INFO.json", 64 << 10)
    for name in sorted(names):
        release_file(directory / name, MAX_FILE)
    return [directory / name for name in sorted(names)]


def publish_release_directory(staged, destination, names):
    """Publish a complete portable release, or confirm an identical prior run."""
    from verify_release import publish_staged_file, release_file, MAX_FILE

    try:
        if sys.platform.startswith(("freebsd", "openbsd")):
            # These hosts use rename with a lock on the common output parent.
            # Cooperating packagers cannot replace an existing release.
            import fcntl
            import os

            descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                if os.path.lexists(destination):
                    raise FileExistsError(destination)
                os.rename(staged, destination)
            finally:
                os.close(descriptor)
        else:
            publish_staged_file(staged, destination)
    except (FileExistsError, NotADirectoryError, IsADirectoryError):
        if (destination.is_symlink() or not destination.is_dir()
                or getattr(destination.lstat(), "st_file_attributes", 0) & 0x400
                or {path.name for path in destination.iterdir()} != names):
            raise ValueError("Release output already exists with a different inventory")
        for name in sorted(names):
            left, right = staged / name, destination / name
            release_file(right, MAX_FILE)
            with left.open("rb") as first, right.open("rb") as second:
                if hashlib.file_digest(first, "sha256").digest() != hashlib.file_digest(second, "sha256").digest():
                    raise ValueError("Release output already exists with different bytes")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "timestamp":
            print(timestamp(sys.argv[2]))
        elif len(sys.argv) == 4 and sys.argv[1] == "stage-docs":
            stage_release_documents(Path(sys.argv[2]), Path(sys.argv[3]))
        else:
            sys.exit("Usage: release_archive.py timestamp SOURCE_DATE_EPOCH | stage-docs SOURCE DESTINATION")
    except ValueError as error:
        sys.exit(str(error))
