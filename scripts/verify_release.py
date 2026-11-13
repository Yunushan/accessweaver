#!/usr/bin/env python3
"""Verify portable release integrity, contents and consistent source identity.

This does not verify publisher signatures or certify target networking behavior.
Only --execute-native runs a binary, and only for the current OS/architecture.
"""
import argparse
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


def execute_metadata(binary, binary_name, info):
    with tempfile.TemporaryDirectory(prefix="accessweaver-release-check-") as temporary:
        exe = Path(temporary) / binary_name
        exe.write_bytes(binary)
        exe.chmod(0o700)
        state = Path(temporary) / "must-not-create-user-state"
        environment = dict(os.environ, ACCESSWEAVER_HOME=str(state), ACCESSWEAVER_NO_BROWSER="1")
        result = subprocess.run([str(exe), "version", "--json"], env=environment, check=True,
                                capture_output=True, text=True, timeout=30)
        require(json.loads(result.stdout) == info, "Runtime identity differs from packaged metadata")
        subprocess.run([str(exe), "system", "check-version", "v" + info["version"]], env=environment,
                       check=True, capture_output=True, timeout=30)
        require(not state.exists(), "Metadata commands unexpectedly wrote user state")


def verify(directory, execute_native=False):
    manifest_path = directory / "BUILD-MANIFEST.json"
    release_file(manifest_path, 1 << 20)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    require(manifest.get("unsigned") is True, "Unsigned packaging must be labeled accurately")
    require(manifest.get("sourceState") in ("clean", "modified", "unknown"), "Missing source modification state")
    require(manifest.get("sourceCommit") == "unknown" or re.fullmatch(r"[a-f0-9]{40,64}", manifest.get("sourceCommit", "")), "Invalid source commit")
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
        for key, expected in {"version": manifest["version"], "commit": manifest["sourceCommit"], "sourceState": manifest["sourceState"], "builtAt": manifest["builtAt"], "platform": target[0], "arch": target[1]}.items():
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
