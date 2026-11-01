#!/usr/bin/env python3
"""Verify portable release integrity, contents and consistent source identity.

This does not verify publisher signatures or certify target networking behavior.
Only --execute-native runs a binary, and only for the current OS/architecture.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

TARGETS = {(os_name, arch) for os_name in ("windows", "linux", "darwin", "freebsd", "openbsd") for arch in ("amd64", "arm64")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect_archive(path, root, binary_name):
    if path.suffix == ".zip":
        archive = zipfile.ZipFile(path)
        members = [(item.filename, item.file_size, not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16)) for item in archive.infolist()]
        read = archive.read
    else:
        archive = tarfile.open(path, "r:gz")
        members = [(item.name, item.size, item.isfile()) for item in archive.getmembers()]
        def read(name):
            with archive.extractfile(name) as source:
                return source.read()
    with archive:
        names = set()
        total = 0
        for name, size, regular in members:
            parts = PurePosixPath(name).parts
            require(regular and "\\" not in name and parts and parts[0] == root and len(parts) > 1 and ".." not in parts, f"Unsafe archive entry: {name}")
            require(name not in names, f"Duplicate archive entry: {name}")
            require(0 <= size <= 64 << 20, f"Oversized archive entry: {name}")
            names.add(name)
            total += size
        require(total <= 256 << 20, "Archive uncompressed size exceeds limit")
        for name in (binary_name, "BUILD-INFO.json", "LICENSE", "THIRD_PARTY.md", "SECURITY.md", "licenses/Go-runtime-LICENSE", "licenses/SplitWire-Turkey-MIT.txt"):
            require(f"{root}/{name}" in names, f"Missing release file: {name}")
        info = json.loads(read(f"{root}/BUILD-INFO.json"))
        return info, read(f"{root}/{binary_name}")


def verify(directory, execute_native=False):
    manifest_path = directory / "BUILD-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("unsigned") is True, "Unsigned packaging must be labeled accurately")
    require(manifest.get("sourceState") in ("clean", "modified", "unknown"), "Missing source modification state")
    require(manifest.get("sourceCommit") == "unknown" or re.fullmatch(r"[a-f0-9]{40,64}", manifest.get("sourceCommit", "")), "Invalid source commit")
    require(manifest.get("targetExecutionTested") is False, "Packaging must not imply target execution")
    checksums = {}
    for line in (directory / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9._-]+)", line)
        require(match is not None, "Invalid checksum entry")
        digest, name = match.groups()
        require(name not in checksums, "Duplicate checksum entry")
        checksums[name] = digest
        require(hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest, f"Checksum mismatch: {name}")
    require(checksums.get(manifest_path.name) == hashlib.sha256(manifest_path.read_bytes()).hexdigest(), "Manifest checksum missing")
    targets = set()
    artifact_names = set()
    host_os = {"win32": "windows", "darwin": "darwin", "linux": "linux"}.get(sys.platform, sys.platform.split("-")[0])
    host_arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    executed = False
    for item in manifest["artifacts"]:
        target = item["goos"], item["goarch"]
        require(target in TARGETS and target not in targets, f"Invalid/duplicate target: {target}")
        targets.add(target)
        name = item["file"]
        extension = ".zip" if target[0] == "windows" else ".tar.gz"
        require(re.fullmatch(r"accessweaver-[A-Za-z0-9._-]+-" + target[0] + "-" + target[1] + re.escape(extension), name), "Unexpected archive name")
        artifact_names.add(name)
        path = directory / name
        require(path.stat().st_size == item["bytes"] and checksums.get(name) == item["sha256"], f"Artifact identity mismatch: {name}")
        root = name[:-len(extension)]
        binary_name = "accessweaver.exe" if target[0] == "windows" else "accessweaver"
        info, binary = inspect_archive(path, root, binary_name)
        for key, expected in {"version": manifest["version"], "commit": manifest["sourceCommit"], "sourceState": manifest["sourceState"], "builtAt": manifest["builtAt"], "platform": target[0], "arch": target[1]}.items():
            require(info.get(key) == expected, f"Inconsistent {key}: {name}")
        if execute_native and target == (host_os, host_arch):
            with tempfile.TemporaryDirectory(prefix="accessweaver-release-check-") as temporary:
                exe = Path(temporary) / binary_name
                exe.write_bytes(binary)
                exe.chmod(0o700)
                state = Path(temporary) / "must-not-create-user-state"
                environment = dict(os.environ, ACCESSWEAVER_HOME=str(state), ACCESSWEAVER_NO_BROWSER="1")
                result = subprocess.run([str(exe), "version", "--json"], env=environment, check=True, capture_output=True, text=True, timeout=30)
                require(json.loads(result.stdout) == info, "Runtime identity differs from packaged metadata")
                subprocess.run([str(exe), "system", "check-version", "v" + info["version"]], env=environment, check=True, capture_output=True, timeout=30)
                require(not state.exists(), "Metadata commands unexpectedly wrote user state")
                executed = True
    require(targets == TARGETS, "Release must contain exactly the ten documented targets")
    require(set(checksums) == artifact_names | {manifest_path.name}, "Unexpected or omitted checksum files")
    require(not execute_native or executed, "No artifact matches the current host")
    print(f"Verified {len(targets)} archives, checksums, required notices and source identity; native metadata execution={executed}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--execute-native", action="store_true")
    arguments = parser.parse_args()
    try:
        verify(arguments.directory, arguments.execute_native)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"Release verification failed: {error}", file=sys.stderr)
        sys.exit(1)
