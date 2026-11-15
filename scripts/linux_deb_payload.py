"""Inspect the AccessWeaver Debian payload without extracting it to disk."""
import hashlib
from pathlib import PurePosixPath
import subprocess
import tarfile

from verify_release import require


def payload_hashes(package, env=None):
    recorded = {}
    with subprocess.Popen(["/usr/bin/dpkg-deb", "--fsys-tarfile", package],
                          stdout=subprocess.PIPE, env=env) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for item in archive:
                name = PurePosixPath(item.name)
                binary = name == PurePosixPath("usr/bin/accessweaver")
                docs = name.is_relative_to("usr/share/doc/accessweaver")
                data = name.is_relative_to("usr/share/accessweaver")
                parents = {".", "usr", "usr/bin", "usr/share", "usr/share/doc"}
                require(item.uid == item.gid == 0 and not name.is_absolute()
                        and ".." not in name.parts and (binary or docs or data or str(name) in parents and item.isdir()),
                        "Package payload extends beyond the controller and documentation")
                if item.isdir():
                    require(item.mode == 0o755, "Unexpected package directory mode")
                else:
                    require(item.isfile() and item.mode == (0o755 if binary else 0o644),
                            "Unexpected package file type or mode")
                    require(str(name) not in recorded, "Unexpected duplicate payload path")
                    with archive.extractfile(item) as stream:
                        recorded[str(name)] = hashlib.file_digest(stream, "sha256").hexdigest()
        require(process.wait(timeout=30) == 0, "Failed to inspect native payload")
    expected = {"usr/bin/accessweaver"}
    expected.update({"usr/share/doc/accessweaver/copyright", "usr/share/doc/accessweaver/SECURITY.md"})
    expected.update("usr/share/accessweaver/" + name for name in (
        "BUILD-INFO.json", "SBOM.cdx.json", "THIRD_PARTY.md", "licenses/Go-runtime-LICENSE"))
    require(expected <= recorded.keys(), "Package is missing the controller, metadata or notices")
    return recorded
