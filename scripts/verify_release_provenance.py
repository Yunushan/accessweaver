#!/usr/bin/env python3
"""Authenticate every portable release subject with independently pinned identity.

Uses the trusted GitHub CLI/Sigstore verifier. Never executes a release binary.
Expected source commit/ref must come from a trusted channel, not this directory.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import zipfile

from verify_release import TARGETS, require, verify as verify_contents

REPOSITORY = "Yunushan/accessweaver"
WORKFLOW = REPOSITORY + "/.github/workflows/release.yml"
BUNDLE_NAME = "BUILD-PROVENANCE.sigstore.json"
PREDICATE = "https://slsa.dev/provenance/v1"


def validate_identity(commit, ref):
    require(re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit), "Expected a full trusted source commit")
    require(re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+", ref) and ".." not in ref and "//" not in ref,
            "Expected a complete trusted heads/tags ref")


def regular_file(path, maximum):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum,
            "Release input must be a bounded regular file: " + path.name)


def verification_command(path, bundle, commit, ref, gh="gh"):
    validate_identity(commit, ref)
    return [gh, "attestation", "verify", str(path.resolve()),
            "--bundle", str(bundle.resolve()), "--hostname", "github.com",
            "--repo", REPOSITORY, "--signer-workflow", WORKFLOW,
            "--source-digest", commit, "--signer-digest", commit, "--source-ref", ref,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--predicate-type", PREDICATE, "--deny-self-hosted-runners", "--format", "json"]


def authenticate(path, bundle, commit, ref, gh):
    try:
        subprocess.run(verification_command(path, bundle, commit, ref, gh), check=True,
                       capture_output=True, text=True, timeout=120)
    except subprocess.CalledProcessError as error:
        # Do not echo a child process's entire response/environment into logs.
        raise ValueError("Cryptographic provenance verification failed: " + path.name) from error


def verify(directory, commit, ref, gh="gh"):
    validate_identity(commit, ref)
    directory = directory.resolve()
    bundle = directory / BUNDLE_NAME
    regular_file(bundle, 16 << 20)
    # Bound enumeration and reject auxiliary files/links rather than accepting an
    # unattested installer, script or extra archive next to the verified set.
    names = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            require(len(names) < 13, "Release directory has unexpected extra entries")
            require(entry.name not in names, "Duplicate release input")
            regular_file(directory / entry.name, 128 << 20)
            names.add(entry.name)
    require(len(names) == 13 and {BUNDLE_NAME, "BUILD-MANIFEST.json", "SHA256SUMS.txt"} <= names,
            "Expected ten archives, manifest, checksums and provenance bundle")
    manifest_path = directory / "BUILD-MANIFEST.json"
    regular_file(manifest_path, 1 << 20)
    regular_file(directory / "SHA256SUMS.txt", 64 << 10)
    # Authenticate metadata BEFORE interpreting it as the artifact selection.
    authenticate(manifest_path, bundle, commit, ref, gh)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("sourceCommit") == commit and manifest.get("sourceState") == "clean",
            "Authenticated manifest does not describe the expected clean source")
    require(manifest.get("unsigned") is True, "Current core binaries must retain their unsigned label")
    targets, archives = set(), set()
    require(isinstance(manifest.get("artifacts"), list) and len(manifest["artifacts"]) == 10,
            "Expected ten authenticated artifact descriptions")
    for item in manifest["artifacts"]:
        target = item["goos"], item["goarch"]
        require(target in TARGETS and target not in targets, "Unexpected or duplicated target")
        name = item["file"]
        extension = ".zip" if target[0] == "windows" else ".tar.gz"
        require(isinstance(name, str) and re.fullmatch(r"accessweaver-[A-Za-z0-9._-]+-" + target[0] + "-" + target[1] + re.escape(extension), name),
                "Unexpected authenticated archive name")
        targets.add(target)
        archives.add(name)
    require(names == archives | {BUNDLE_NAME, "BUILD-MANIFEST.json", "SHA256SUMS.txt"},
            "Unattested or omitted release input")
    subjects = [directory / "SHA256SUMS.txt"] + [directory / name for name in sorted(archives)]
    for subject in subjects:
        authenticate(subject, bundle, commit, ref, gh)
    # Existing content checks validate all archive paths, notices, checksums and
    # embedded identities. No --execute-native path is enabled by this verifier.
    verify_contents(directory, execute_native=False)
    return {"repository": REPOSITORY, "workflow": WORKFLOW, "sourceCommit": commit,
            "sourceRef": ref, "subjectsVerified": 12, "hostedRunnerRequired": True,
            "publisherSignatureVerified": False, "productionQualificationComplete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--gh", default="gh", help="trusted GitHub CLI executable")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.directory, args.source_commit, args.source_ref, args.gh)))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print("Release provenance verification failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
