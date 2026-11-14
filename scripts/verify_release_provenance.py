#!/usr/bin/env python3
"""Authenticate every portable release subject with independently pinned identity.

Uses the trusted GitHub CLI/Sigstore verifier. Never executes a release binary.
Expected source commit/ref must come from a trusted channel, not this directory.
"""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

from verify_release import PROVENANCE_BUNDLE as BUNDLE_NAME, artifact_names, require, snapshot, verify as verify_contents

REPOSITORY = "Yunushan/accessweaver"
WORKFLOW = REPOSITORY + "/.github/workflows/release.yml"
PREDICATE = "https://slsa.dev/provenance/v1"


def validate_identity(commit, ref):
    require(re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit), "Expected a full trusted source commit")
    require(re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+", ref) and ".." not in ref and "//" not in ref,
            "Expected a complete trusted heads/tags ref")


def validate_run_id(run_id):
    require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", run_id),
            "Expected an independently approved GitHub Actions run ID")


def authenticate_run(command, run_id, *, command_failure=None):
    """Check the invocation in the certificate returned by the trusted verifier."""
    validate_run_id(run_id)
    command = [*command, "--jq", ".[] | .verificationResult.signature.certificate.runInvocationURI"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        if command_failure is not None:
            raise command_failure(result)
        raise ValueError("GitHub cryptographic provenance verification failed")
    prefix = re.escape(f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/")
    # A rerun can reuse successful jobs from a previous attempt of the same run.
    require(any(re.fullmatch(prefix + r"[1-9][0-9]{0,19}", line) for line in result.stdout.splitlines()),
            "Verified attestation does not match the expected GitHub Actions run")


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


def authenticate(path, bundle, commit, ref, gh, *, run_id=None):
    command = verification_command(path, bundle, commit, ref, gh)
    if run_id is not None:
        authenticate_run(command, run_id)
        return
    try:
        subprocess.run(command, check=True,
                       capture_output=True, text=True, timeout=120)
    except subprocess.CalledProcessError as error:
        # Do not echo a child process's entire response/environment into logs.
        raise ValueError("Cryptographic provenance verification failed: " + path.name) from error


@contextmanager
def authenticated_snapshot(directory, commit, ref, gh="gh", *, run_id=None):
    """Keep the authenticated release files available to a trusted caller."""
    validate_identity(commit, ref)
    if run_id is not None:
        validate_run_id(run_id)
    with tempfile.TemporaryDirectory(prefix="accessweaver-provenance-") as temporary:
        private = Path(temporary)
        names = snapshot(directory, private, 13)
        yield private, _verify_snapshot(private, names, commit, ref, gh, run_id=run_id)


def verify(directory, commit, ref, gh="gh", *, run_id=None):
    with authenticated_snapshot(directory, commit, ref, gh, run_id=run_id) as (_, provenance):
        return provenance


def _verify_snapshot(directory, names, commit, ref, gh, *, run_id=None):
    require({BUNDLE_NAME, "BUILD-MANIFEST.json", "SHA256SUMS.txt"} <= names,
            "Expected ten archives, manifest, checksums and provenance bundle")
    bundle = directory / BUNDLE_NAME
    regular_file(bundle, 16 << 20)
    manifest_path = directory / "BUILD-MANIFEST.json"
    regular_file(manifest_path, 1 << 20)
    regular_file(directory / "SHA256SUMS.txt", 64 << 10)
    # Authenticate metadata BEFORE interpreting it as the artifact selection.
    authenticate(manifest_path, bundle, commit, ref, gh, run_id=run_id)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("sourceCommit") == commit and manifest.get("sourceState") == "clean",
            "Authenticated manifest does not describe the expected clean source")
    if ref.startswith("refs/tags/"):
        tag = ref.removeprefix("refs/tags/")
        require(manifest.get("releaseLabel") == tag and manifest.get("version") == tag.removeprefix("v"),
                "Authenticated manifest release label and version must match the expected tag")
    require(manifest.get("unsigned") is True, "Current core binaries must retain their unsigned label")
    archives = artifact_names(manifest)
    require(names == archives | {BUNDLE_NAME, "BUILD-MANIFEST.json", "SHA256SUMS.txt"},
            "Unattested or omitted release input")
    subjects = [directory / "SHA256SUMS.txt"] + [directory / name for name in sorted(archives)]
    for subject in subjects:
        authenticate(subject, bundle, commit, ref, gh, run_id=run_id)
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
    parser.add_argument("--workflow-run-id", help="require package attestations from this GitHub Actions run")
    parser.add_argument("--gh", default="gh", help="trusted GitHub CLI executable")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.directory, args.source_commit, args.source_ref, args.gh, run_id=args.workflow_run_id)))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print("Release provenance verification failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
