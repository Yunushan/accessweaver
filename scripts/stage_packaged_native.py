#!/usr/bin/env python3
"""Authenticate a private candidate snapshot and stage one target executable.

Never executes release code. Source commit/ref and native target are independent
inputs; the authenticated distribution metadata cannot choose those expectations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import zipfile
import re

from verify_release import inspect_archive, require
from verify_release_provenance import authenticated_snapshot, validate_identity, REPOSITORY, WORKFLOW

NATIVE_TARGETS = {(p, a) for p in ("windows", "linux", "darwin") for a in ("amd64", "arm64")}


def host_target():
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    return system, arch


def stage(directory, destination, target, commit, ref, gh="gh"):
    validate_identity(commit, ref)
    require(target in NATIVE_TARGETS and target == host_target(), "Requested packaged target must match this native host")
    return _stage_snapshot(directory, destination, target, commit, ref, gh)


def stage_freebsd_guest(directory, destination, target, commit, ref, gh="gh"):
    return _stage_bsd_guest(directory, destination, target, commit, ref, gh, "freebsd")


def stage_openbsd_guest(directory, destination, target, commit, ref, gh="gh"):
    return _stage_bsd_guest(directory, destination, target, commit, ref, gh, "openbsd")


def _stage_bsd_guest(directory, destination, target, commit, ref, gh, goos):
    validate_identity(commit, ref)
    require(target in {(goos, "amd64"), (goos, "arm64")} and host_target() == ("linux", target[1]),
            "BSD guest staging requires its explicit OS and a matching native Linux host architecture")
    return _stage_snapshot(directory, destination, target, commit, ref, gh, guest=goos)


def _stage_snapshot(directory, destination, target, commit, ref, gh, guest=False):
    # This helper never executes release code. Each public entry point enforces
    # its own disjoint native-host or explicit BSD-guest staging contract.
    resolved_input = directory.resolve(strict=True)
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    require(destination.name not in ("", ".", "..") and not destination.exists() and not destination.is_symlink(), "Staging destination must not exist")
    require(not destination.is_relative_to(resolved_input) and not resolved_input.is_relative_to(destination), "Staging and candidate inputs must be separate")
    with authenticated_snapshot(directory, commit, ref, gh) as (snapshot, provenance):
        manifest_bytes = (snapshot / "BUILD-MANIFEST.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        require(manifest.get("sourceCommit") == commit and manifest.get("sourceState") == "clean", "Authenticated manifest source mismatch")
        matches = [a for a in manifest["artifacts"] if (a["goos"], a["goarch"]) == target]
        require(len(matches) == 1, "Expected one authenticated native artifact")
        item = matches[0]
        suffix = ".zip" if target[0] == "windows" else ".tar.gz"
        require(isinstance(item["file"], str) and Path(item["file"]).name == item["file"] and item["file"].endswith(suffix), "Invalid authenticated archive selection")
        archive = snapshot / item["file"]
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        require(archive_hash == item["sha256"], "Authenticated native archive digest mismatch")
        name = "accessweaver.exe" if target[0] == "windows" else "accessweaver"
        info, binary = inspect_archive(archive, item["file"][:-len(suffix)], name)
        for key, expected in {"commit": commit, "sourceState": "clean", "platform": target[0], "arch": target[1], "version": manifest["version"], "builtAt": manifest["builtAt"]}.items():
            require(info.get(key) == expected, "Packaged build identity mismatch: " + key)
        require(0 < len(binary) <= 64 << 20, "Packaged executable exceeds native staging bound")
        receipt = {"schemaVersion": 1, "sourceCommit": commit, "sourceRef": ref, "repository": REPOSITORY, "workflow": WORKFLOW,
                   "target": "/".join(target), "archive": item["file"], "archiveSha256": archive_hash,
                   "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
                   "bundleSha256": hashlib.sha256((snapshot / "BUILD-PROVENANCE.sigstore.json").read_bytes()).hexdigest(),
                   "binary": name, "binarySha256": hashlib.sha256(binary).hexdigest(), "build": info,
                   "provenanceSubjectsVerified": provenance["subjectsVerified"], "authenticatedBeforeStaging": True,
                   "publisherSignatureVerified": False, "productionQualificationComplete": False}
        if guest:
            receipt["executionEnvironment"] = "disposable-" + guest + "-guest"
        destination.mkdir(mode=0o700)
        executable = destination / name
        with executable.open("xb") as stream:
            stream.write(binary)
        executable.chmod(0o700)
        require(hashlib.sha256(executable.read_bytes()).hexdigest() == receipt["binarySha256"], "Staged executable changed")
        with (destination / "candidate.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?")
    parser.add_argument("--download-root", type=Path, help="Workflow download root; PACKAGE_DIRECTORY supplies its dist/label child")
    parser.add_argument("--into", type=Path, required=True)
    parser.add_argument("--target", default=os.environ.get("ACCESSWEAVER_EXPECT_GOOS", "") + "/" + os.environ.get("ACCESSWEAVER_EXPECT_GOARCH", ""))
    parser.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--source-ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--gh", default="gh")
    guests = parser.add_mutually_exclusive_group()
    guests.add_argument("--freebsd-guest", action="store_true", help="Stage a FreeBSD archive for a matching-architecture Linux-hosted disposable guest; never execute it here")
    guests.add_argument("--openbsd-guest", action="store_true", help="Stage an OpenBSD archive for a matching-architecture Linux-hosted disposable guest; never execute it here")
    args = parser.parse_args()
    try:
        require((args.directory is None) != (args.download_root is None), "Choose a candidate directory or workflow download root")
        if args.download_root is not None:
            package = os.environ.get("PACKAGE_DIRECTORY", "")
            require(re.fullmatch(r"dist/[A-Za-z0-9][A-Za-z0-9._-]*", package) is not None, "Invalid workflow package directory")
            args.directory = args.download_root / package.removeprefix("dist/")
        staging = stage_openbsd_guest if args.openbsd_guest else stage_freebsd_guest if args.freebsd_guest else stage
        receipt = staging(args.directory, args.into, tuple(args.target.split("/")), args.source_commit, args.source_ref, args.gh)
        print(json.dumps(receipt))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print("Packaged native staging failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
