#!/usr/bin/env python3
"""Build a Debian package from a pinned AccessWeaver Linux portable archive."""
import argparse
import errno
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile

from release_archive import epoch_from_timestamp
from verify_release import MAX_FILE, inspect_archive, publish_staged_file, release_file, require

PACKAGE = "accessweaver"
BINARY = Path("usr/bin/accessweaver")
DOCS = Path("usr/share/doc/accessweaver")
DATA = Path("usr/share/accessweaver")
ELF_MACHINE = {"amd64": 62, "arm64": 183}
ROOT_FILES = {"BUILD-INFO.json", "SBOM.cdx.json", "LICENSE", "README.md", "README.tr.md",
              "THIRD_PARTY.md", "SECURITY.md"}
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
                     r"(?:-(alpha|beta|rc)(?:\.(0|[1-9][0-9]*))?)?")


def debian_version(version):
    require(isinstance(version, str) and len(version) <= 80 and VERSION.fullmatch(version),
            "Expected a stable x.y.z version or an alpha, beta or rc prerelease with optional .N")
    return version.replace("-", "~", 1)


def copy_pinned_archive(source, frozen, pin):
    # Match the bytes that will be parsed, even if the original name is replaced.
    before = release_file(source, MAX_FILE)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(source, flags), "rb") as stream, frozen.open("xb") as output:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and (opened.st_dev, opened.st_ino, opened.st_size)
                == (before.st_dev, before.st_ino, before.st_size),
                "Portable archive changed before snapshot")
        digest = hashlib.sha256()
        size = 0
        for block in iter(lambda: stream.read(1 << 20), b""):
            size += len(block)
            require(size <= before.st_size, "Portable archive grew during snapshot")
            digest.update(block)
            output.write(block)
        require(size == before.st_size and digest.hexdigest() == pin, "Portable archive SHA-256 mismatch")


def check_elf(binary, arch):
    require(len(binary) >= 64 and binary[:7] == b"\x7fELF\x02\x01\x01",
            "Expected a little-endian 64-bit Linux ELF executable")
    kind, machine, version = struct.unpack_from("<HHI", binary, 16)
    require(kind in (2, 3) and machine == ELF_MACHINE[arch] and version == 1,
            "ELF executable does not match the requested Debian architecture")


def stage_payload(archive, root, payload):
    # inspect_archive has already checked every entry for regular type, bounds and aliases.
    # Build only the two package-owned subtrees and never extract paths through tarfile.
    installed = []
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            relative = Path(member.name.removeprefix(root + "/"))
            if relative == Path("accessweaver"):
                location = BINARY
            else:
                require(str(relative) in ROOT_FILES or relative.parts[0] in ("licenses", "docs")
                        and len(relative.parts) > 1, "Unexpected portable archive payload")
                if relative == Path("LICENSE"):
                    location = DOCS / "copyright"
                elif relative.as_posix() in ("BUILD-INFO.json", "SBOM.cdx.json", "THIRD_PARTY.md") or relative.parts[0] == "licenses":
                    location = DATA / relative
                else:
                    location = DOCS / relative
            destination = payload / location
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, destination.open("xb") as output:
                shutil.copyfileobj(source, output, 1 << 20)
            destination.chmod(0o755 if location == BINARY else 0o644)
            installed.append(location)
    return installed


def build(archive, pin, arch, maintainer, destination):
    require(arch in ELF_MACHINE and re.fullmatch(r"[a-f0-9]{64}", pin), "Expected a Debian target and pinned SHA-256")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,'()&/_-]{0,126} <[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}>",
                         maintainer), "Expected a packaging maintainer in Name <email> format")
    required_name = re.fullmatch(rf"accessweaver-[A-Za-z0-9][A-Za-z0-9._-]*-linux-{arch}\.tar\.gz", archive.name)
    require(len(archive.name) <= 255 and required_name, "Expected a release archive basename for the requested target")
    require(destination.is_dir() and not destination.is_symlink(), "Expected an existing ordinary output directory")
    destination = destination.resolve(strict=True)
    parent = destination.stat()
    with tempfile.TemporaryDirectory(prefix=".accessweaver-deb-", dir=destination) as temporary:
        staging = Path(temporary)
        frozen = staging / archive.name
        copy_pinned_archive(archive, frozen, pin)
        root = archive.name.removesuffix(".tar.gz")
        identity, binary = inspect_archive(frozen, root, PACKAGE)
        require(identity.get("platform") == "linux" and identity.get("arch") == arch
                and identity.get("sourceState") == "clean"
                and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", identity.get("commit", "")),
                "Expected matching clean Linux build identity")
        version = debian_version(identity.get("version"))
        epoch = epoch_from_timestamp(identity["builtAt"])
        check_elf(binary, arch)

        output = destination / f"{PACKAGE}_{version}_{arch}.deb"
        # Skip compression for an existing name. Publication still uses an exclusive rename.
        if os.path.lexists(output):
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), output)
        payload = staging / "payload"
        installed = stage_payload(frozen, root, payload)
        control_dir = payload / "DEBIAN"
        control_dir.mkdir()
        installed_size = sum(((payload / name).stat().st_size + 1023) // 1024 for name in installed)
        control = (f"Package: {PACKAGE}\nVersion: {version}\nArchitecture: {arch}\n"
                   f"Maintainer: {maintainer}\nInstalled-Size: {installed_size}\n"
                   "Section: net\nPriority: optional\n"
                   "Homepage: https://github.com/Yunushan/accessweaver\n"
                   "Description: AccessWeaver desktop network workflow controller\n"
                   " Command-line controller and local dashboard for external network engines.\n")
        (control_dir / "control").write_text(control, encoding="ascii")
        # dpkg --verify uses MD5; the trusted release input is checked with SHA-256.
        with (control_dir / "md5sums").open("w", encoding="ascii") as sums:
            for location in sorted(installed):
                with (payload / location).open("rb") as stream:
                    digest = hashlib.file_digest(stream, lambda: hashlib.md5(usedforsecurity=False)).hexdigest()
                sums.write(f"{digest}  {location.as_posix()}\n")
        paths = [payload, *payload.rglob("*")]
        for path in paths:
            if path.is_dir():
                path.chmod(0o755)
            elif path.parent == control_dir:
                path.chmod(0o644)
            os.utime(path, (epoch, epoch))

        staged = staging / output.name
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": str(epoch)}
        subprocess.run(["/usr/bin/dpkg-deb", "--root-owner-group", "--uniform-compression",
                        "--threads-max=1", "-Zxz", "-z3", "--build", payload, staged],
                       check=True, env=env, timeout=180, stdout=subprocess.DEVNULL)
        release_file(staged, MAX_FILE)
        staged.chmod(0o644)
        with staged.open("rb") as stream:
            os.fsync(stream.fileno())
        current = destination.stat()
        require((current.st_dev, current.st_ino) == (parent.st_dev, parent.st_ino)
                and not destination.is_symlink(), "Output directory changed during package build")
        publish_staged_file(staged, output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--sha256", required=True, help="Expected archive digest from the verified release")
    parser.add_argument("--arch", choices=ELF_MACHINE, required=True)
    parser.add_argument("--maintainer", required=True, help="Public Debian package contact (Name <email>)")
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(build(args.archive, args.sha256, args.arch, args.maintainer, args.output_directory))
    except (KeyError, TypeError, ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Debian package build failed: {error}\n")


if __name__ == "__main__":
    main()
