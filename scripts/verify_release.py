#!/usr/bin/env python3
"""Verify portable release integrity, contents and consistent source identity.

This does not verify publisher signatures or certify target networking behavior.
Only --execute-native runs a binary, and only for the current OS/architecture.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

from sbom import validate as validate_sbom

HOST_PLATFORM = sys.platform
MAX_FILE = 128 << 20
MAX_SET = 256 << 20
MAX_ARCHIVE_MEMBERS = 4096
MAX_MEMBER_BYTES = 64 << 20
MAX_UNCOMPRESSED_BYTES = 256 << 20
WINDOWS_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?", re.IGNORECASE)
PROVENANCE_BUNDLE = "BUILD-PROVENANCE.sigstore.json"
TARGETS = {(os_name, arch) for os_name in ("windows", "linux", "darwin", "freebsd", "openbsd") for arch in ("amd64", "arm64")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def zip_members(archive):
    for item in archive.infolist():
        mode = item.external_attr >> 16
        regular = (not item.is_dir() and not item.external_attr & 0x10
                   and (item.create_system != 3 or stat.S_IFMT(mode) in (0, stat.S_IFREG)))
        yield item.orig_filename, item.file_size, regular and not item.flag_bits & 1


def inspect_archive(path, root, binary_name):
    if path.suffix == ".zip":
        archive = zipfile.ZipFile(path)
        members = zip_members(archive)
        read = archive.read
    else:
        archive = tarfile.open(path, "r:gz")
        members = ((item.name, item.size, item.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    and item.sparse is None) for item in archive)
        def read(name):
            with archive.extractfile(name) as source:
                return source.read()
    with archive:
        names = set()
        file_keys = set()
        directories = {}
        total = 0
        for name, size, regular in members:
            require(len(names) < MAX_ARCHIVE_MEMBERS, "Archive member count exceeds limit")
            parts = name.split("/")
            require(regular and len(parts) > 1 and parts[0] == root and all(
                re.fullmatch(r"[A-Za-z0-9._-]+", part) and not part.endswith(".")
                and not WINDOWS_DEVICE.fullmatch(part) for part in parts
            ), "Unsafe archive entry")
            key = name.lower()
            require(key not in file_keys and key not in directories, "Conflicting archive entry")
            prefix = parts[0]
            for part in parts[1:-1]:
                prefix += "/" + part
                parent = prefix.lower()
                require(parent not in file_keys and directories.setdefault(parent, prefix) == prefix,
                        "Conflicting archive directory")
            require(0 <= size <= MAX_MEMBER_BYTES, "Oversized archive entry")
            total += size
            require(total <= MAX_UNCOMPRESSED_BYTES, "Archive uncompressed size exceeds limit")
            names.add(name)
            file_keys.add(key)
        for name in (binary_name, "BUILD-INFO.json", "SBOM.cdx.json", "LICENSE", "THIRD_PARTY.md", "SECURITY.md", "licenses/Go-runtime-LICENSE", "licenses/SplitWire-Turkey-MIT.txt"):
            require(f"{root}/{name}" in names, f"Missing release file: {name}")
        info = json.loads(read(f"{root}/BUILD-INFO.json"))
        binary = read(f"{root}/{binary_name}")
        bom = json.loads(read(f"{root}/SBOM.cdx.json"))
        validate_sbom(bom, binary, info)
        components = [bom["metadata"]["component"]] + bom.get("components", [])
        for component in components:
            for prop in component.get("properties", []):
                if prop["name"] != "accessweaver:license-evidence":
                    continue
                for evidence in json.loads(prop["value"]):
                    name = evidence["path"]
                    require(re.fullmatch(r"licenses/[A-Za-z0-9._-]+", name), "Unexpected SBOM notice path")
                    require(f"{root}/{name}" in names and hashlib.sha256(read(f"{root}/{name}")).hexdigest() == evidence["sha256"], "Missing or changed SBOM license evidence")
        return info, binary


def release_file(path, maximum):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and 0 < info.st_size <= maximum, "Expected a bounded regular release file")
    return info


def snapshot(source, destination, count):
    directory = source.lstat()
    require(stat.S_ISDIR(directory.st_mode) and not source.is_symlink()
            and not getattr(directory, 'st_file_attributes', 0) & 0x400, 'Expected a real input directory')
    names = set()
    total = 0
    with os.scandir(source) as entries:
        for entry in entries:
            require(len(names) < count and entry.name not in names, 'Unexpected extra input')
            path = source / entry.name
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and not getattr(before, 'st_file_attributes', 0) & 0x400
                    and 0 < before.st_size <= MAX_FILE, 'Expected a bounded regular single-link input')
            total += before.st_size
            require(total <= MAX_SET, 'Input set exceeds snapshot bound')
            flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_nlink)
                require(stat.S_ISREG(opened.st_mode) and identity(opened) == identity(before), 'Input changed before snapshot')
                with (destination / entry.name).open('xb') as output:
                    copied = 0
                    while True:
                        block = os.read(descriptor, min(1 << 20, MAX_FILE + 1 - copied))
                        if not block:
                            break
                        copied += len(block)
                        require(copied <= before.st_size, 'Input changed or exceeded its snapshot bound')
                        output.write(block)
                require(copied == before.st_size and identity(os.fstat(descriptor)) == identity(before), 'Input changed during snapshot')
            finally:
                os.close(descriptor)
            names.add(entry.name)
    require(len(names) == count, 'Missing release inputs')
    return names


def publish_staged_file(staged, destination):
    """Publish without replacement or an extra link on supported rename hosts."""
    if HOST_PLATFORM == "win32":
        # Python's Windows rename refuses an existing destination.
        os.rename(staged, destination)
        return
    if HOST_PLATFORM == "darwin":
        rename_exclusive = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).renamex_np
        rename_exclusive.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename_exclusive.restype = ctypes.c_int
        result = rename_exclusive(os.fsencode(staged), os.fsencode(destination), 4)  # RENAME_EXCL
    elif HOST_PLATFORM.startswith("linux"):
        try:
            rename_exclusive = ctypes.CDLL(None, use_errno=True).renameat2
        except AttributeError as error:
            raise OSError(errno.ENOTSUP, "Exclusive file rename is unavailable") from error
        rename_exclusive.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename_exclusive.restype = ctypes.c_int
        at_fdcwd = -100
        result = rename_exclusive(at_fdcwd, os.fsencode(staged),
                                  at_fdcwd, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        # Keep the existing staging behavior on other verification hosts.
        os.link(staged, destination)
        return
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def native_metadata_json(executable, arguments, environment):
    with tempfile.TemporaryFile() as output:
        subprocess.run([str(executable), *arguments], env=environment, check=True,
                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, timeout=30)
        output.seek(0)
        data = output.read(4097)
    require(0 < len(data) <= 4096, "Native metadata response exceeds inspection bounds")
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_metadata_keys)


def unique_metadata_keys(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "Duplicate native metadata field")
    return result


def execute_metadata(binary, binary_name, info):
    with tempfile.TemporaryDirectory(prefix="accessweaver-release-check-") as temporary:
        exe = Path(temporary) / binary_name
        exe.write_bytes(binary)
        exe.chmod(0o700)
        state = Path(temporary) / "must-not-create-user-state"
        environment = dict(os.environ, ACCESSWEAVER_HOME=str(state), ACCESSWEAVER_NO_BROWSER="1")
        require(native_metadata_json(exe, ["version", "--json"], environment) == info,
                "Runtime identity differs from packaged metadata")
        tag = "v" + info["version"]
        comparison = native_metadata_json(exe, ["system", "check-version", tag], environment)
        require(isinstance(comparison, dict)
                and comparison.keys() == {"version", "currentVersion", "updateAvailable"}
                and comparison["version"] == tag and comparison["currentVersion"] == info["version"]
                and comparison["updateAvailable"] is False,
                "Update comparison differs from the packaged version")
        require(not state.exists(), "Metadata commands unexpectedly wrote user state")


def verify(directory, execute_native=False):
    manifest_path = directory / "BUILD-MANIFEST.json"
    release_file(manifest_path, 1 << 20)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    require(manifest.get("unsigned") is True, "Unsigned packaging must be labeled accurately")
    require(manifest.get("sourceState") in ("clean", "modified", "unknown"), "Missing source modification state")
    commit = manifest.get("sourceCommit")
    require(isinstance(commit, str) and (commit == "unknown" or re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit)),
            "Invalid source commit")
    sdk = manifest.get("goVersion")
    match = re.fullmatch(r"go version (\S+) [a-z0-9]+/[a-z0-9]+", sdk) if isinstance(sdk, str) else None
    require(match is not None, "Invalid release Go toolchain identity")
    go_version = match.group(1)
    require(manifest.get("targetExecutionTested") is False, "Packaging must not imply target execution")

    artifacts = manifest["artifacts"]
    require(isinstance(artifacts, list) and len(artifacts) == len(TARGETS), "Release must contain exactly the ten documented targets")
    targets = set()
    archive_names = set()
    for item in artifacts:
        target = item["goos"], item["goarch"]
        require(target in TARGETS and target not in targets, "Invalid or duplicate release target")
        targets.add(target)
        name = item["file"]
        extension = ".zip" if target[0] == "windows" else ".tar.gz"
        require(re.fullmatch(r"accessweaver-[A-Za-z0-9._-]+-" + target[0] + "-" + target[1] + re.escape(extension), name), "Unexpected archive name")
        archive_names.add(name)

    checksum_path = directory / "SHA256SUMS.txt"
    release_file(checksum_path, 64 << 10)
    checksums = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9._-]+)", line)
        require(match is not None, "Invalid checksum entry")
        digest, name = match.groups()
        require(name not in checksums, "Duplicate checksum entry")
        checksums[name] = digest
    require(set(checksums) == archive_names | {manifest_path.name}, "Unexpected or omitted checksum files")
    require(checksums[manifest_path.name] == hashlib.sha256(manifest_bytes).hexdigest(), "Manifest checksum differs")

    expected_files = set(checksums) | {checksum_path.name}
    with os.scandir(directory) as entries:
        names = set()
        for entry in entries:
            require(entry.name in expected_files or entry.name == PROVENANCE_BUNDLE, "Unexpected release input")
            names.add(entry.name)
    require(expected_files <= names, "Missing release input")
    if PROVENANCE_BUNDLE in names:
        release_file(directory / PROVENANCE_BUNDLE, 16 << 20)

    host_os = {"win32": "windows", "darwin": "darwin", "linux": "linux"}.get(sys.platform, sys.platform.split("-")[0])
    host_arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    native = None
    for item in artifacts:
        target = item["goos"], item["goarch"]
        name = item["file"]
        path = directory / name
        size = release_file(path, 128 << 20).st_size
        require(size == item["bytes"] and checksums[name] == item["sha256"], f"Artifact identity mismatch: {name}")
        extension = ".zip" if target[0] == "windows" else ".tar.gz"
        binary_name = "accessweaver.exe" if target[0] == "windows" else "accessweaver"
        # Inspect the exact private copy whose bytes passed the digest check.
        with tempfile.TemporaryDirectory(prefix="accessweaver-archive-check-") as temporary:
            frozen = Path(temporary) / name
            digest = hashlib.sha256()
            copied = 0
            with path.open("rb") as source, frozen.open("xb") as output:
                for block in iter(lambda: source.read(1 << 20), b""):
                    copied += len(block)
                    require(copied <= size, "Release archive grew during verification")
                    digest.update(block)
                    output.write(block)
            require(copied == size and digest.hexdigest() == checksums[name], f"Checksum mismatch: {name}")
            info, binary = inspect_archive(frozen, name[:-len(extension)], binary_name)
        for key, expected in {"version": manifest["version"], "commit": manifest["sourceCommit"], "sourceState": manifest["sourceState"], "builtAt": manifest["builtAt"], "platform": target[0], "arch": target[1], "goVersion": go_version}.items():
            require(info.get(key) == expected, f"Inconsistent {key}: {name}")
        if execute_native and target == (host_os, host_arch):
            native = binary, binary_name, info
    if execute_native:
        require(native is not None, "No artifact matches the current host")
        execute_metadata(*native)
    print(f"Verified {len(targets)} archives, checksums, required notices and source identity; native metadata execution={execute_native}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--execute-native", action="store_true")
    arguments = parser.parse_args()
    try:
        verify(arguments.directory, arguments.execute_native)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"Release verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
