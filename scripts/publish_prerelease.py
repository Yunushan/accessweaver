#!/usr/bin/env python3
"""Publish a verified portable build through a draft without replacing assets."""

import argparse
from contextlib import contextmanager, redirect_stdout
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from threading import Timer
from urllib.parse import urlencode

from verify_release import TARGETS, inspect_archive, snapshot
from verify_release_provenance import (BUNDLE_NAME, REPOSITORY, WORKFLOW, authenticate_run, validate_identity,
                                       verification_command, verify)
from verify_release_rebuild import digest

REMOTE = "https://github.com/" + REPOSITORY + ".git"
MAX_BUNDLE = 16 << 20
QUALIFICATION_BUNDLE = "qualification.sigstore.json"


def git_tag_commit(tag):
    ref = "refs/tags/" + tag
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", REMOTE, ref, ref + "^{}"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    refs = {}
    for line in result.stdout.splitlines():
        oid, name = line.split("\t", 1)
        if name not in (ref, ref + "^{}") or name in refs or not re.fullmatch(r"[a-f0-9]{40}", oid):
            raise ValueError("Unexpected remote tag lookup result")
        refs[name] = oid
    return refs.get(ref + "^{}", refs.get(ref)) if ref in refs else None


def gh(*args):
    return subprocess.run(
        ["gh", "release", *args, "--repo", "github.com/" + REPOSITORY],
        capture_output=True, text=True, timeout=240,
    )


def require_success(result):
    if result.returncode != 0:
        raise ValueError("GitHub release operation failed")
    return result.stdout


def view(tag):
    result = gh("view", tag, "--json", "databaseId,tagName,isDraft,isPrerelease,assets")
    if result.returncode == 1 and result.stderr.strip() == "release not found":
        return None
    return json.loads(require_success(result))


def upload_asset(release_id, path, expected_digest):
    query = urlencode({"name": path.name})
    endpoint = f"https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?{query}"
    result = subprocess.run(
        ["gh", "api", "--hostname", "github.com", "--method", "POST", endpoint,
         "--header", "Content-Type: application/octet-stream", "--input", str(path)],
        capture_output=True, text=True, timeout=240,
    )
    asset = json.loads(require_success(result))
    if (not isinstance(asset, dict) or asset.get("name") != path.name
            or asset.get("state") != "uploaded" or asset.get("digest") != expected_digest):
        raise ValueError("Uploaded release asset could not be verified")


def promote_draft(release_id):
    # Use the record whose assets were verified. A fresh tag lookup could
    # resolve to a different release if another actor replaced the draft.
    result = subprocess.run(
        ["gh", "api", "--hostname", "github.com", "--method", "PATCH",
         f"repos/{REPOSITORY}/releases/{release_id}", "--field", "draft=false", "--silent"],
        capture_output=True, text=True, timeout=240,
    )
    require_success(result)


def missing_assets(release, tag, expected, *, allow_existing_bundle=False):
    if (
        type(release.get("databaseId")) is not int
        or release["databaseId"] <= 0
        or release.get("tagName") != tag
        or release.get("isPrerelease") is not True
        or type(release.get("isDraft")) is not bool
        or not isinstance(release.get("assets"), list)
    ):
        raise ValueError("Release identity or prerelease state differs")
    names = set()
    for asset in release["assets"]:
        name = asset["name"]
        if (
            name in names or name not in expected
            or asset.get("state") != "uploaded"
            or (asset.get("digest") != expected[name]
                and not (allow_existing_bundle and name == BUNDLE_NAME
                         and isinstance(asset.get("digest"), str)
                         and re.fullmatch(r"sha256:[a-f0-9]{64}", asset["digest"])))
        ):
            raise ValueError("Release contains an unexpected, incomplete or different asset")
        names.add(name)
    missing = sorted(expected.keys() - names)
    if missing and not release["isDraft"]:
        raise ValueError("Published release is missing verified assets")
    return missing


def download_existing_bundle(asset_id, size):
    command = [
        "gh", "api", "--hostname", "github.com", "--method", "GET",
        f"repos/{REPOSITORY}/releases/assets/{asset_id}",
        "--header", "Accept: application/octet-stream",
    ]
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as child:
        # The deadline covers both the bounded read and process exit.
        deadline = Timer(240, child.kill)
        deadline.start()
        try:
            data = child.stdout.read(size + 1)
            if len(data) != size:
                raise ValueError("Existing provenance bundle length differs")
            if child.wait() != 0:
                raise ValueError("Existing provenance bundle could not be downloaded")
            return data
        finally:
            deadline.cancel()
            deadline.join()
            if child.poll() is None:
                child.kill()


def reuse_existing_bundle(directory, release, commit, tag, expected):
    bundle = next((asset for asset in release["assets"] if asset["name"] == BUNDLE_NAME), None)
    if bundle is None or bundle["digest"] == expected[BUNDLE_NAME]:
        return expected
    api_url = bundle.get("apiUrl")
    asset_url = rf"https://api\.github\.com/repos/{re.escape(REPOSITORY)}/releases/assets/([1-9][0-9]{{0,18}})"
    asset_id = re.fullmatch(asset_url, api_url) if isinstance(api_url, str) else None
    size = bundle.get("size")
    if asset_id is None or type(size) is not int or not 0 < size <= MAX_BUNDLE:
        raise ValueError("Existing provenance bundle metadata differs")

    data = download_existing_bundle(asset_id[1], size)
    if "sha256:" + hashlib.sha256(data).hexdigest() != bundle["digest"]:
        raise ValueError("Existing provenance bundle bytes differ")
    # Verify the existing bundle against the private snapshot's exact subjects
    # before writing to GitHub, including on an already published prerelease.
    (directory / BUNDLE_NAME).write_bytes(data)
    verify(directory, commit, "refs/tags/" + tag)
    return {**expected, BUNDLE_NAME: bundle["digest"]}


def verify_target_execution(report, receipt, system):
    target = receipt["target"]
    identity = {
        "schemaVersion": 1, "sourceCommit": receipt["sourceCommit"], "target": target,
        "productionQualificationComplete": False,
    }
    if system in {"freebsd", "openbsd"}:
        emulator_flag = "ownedEmulatorStopped" if system == "freebsd" else "ownedEmulatorsStopped"
        identity.update({
            "packagedCandidate": receipt, "executedCLI": receipt["build"],
            "cliSHA256": receipt["binarySha256"], "guestExecutionPassed": True,
            "packagedCandidateExecuted": True, "allTransportedExecutableHashesVerified": True,
            "ownedCapsuleRemoved": True, emulator_flag: True,
            "packagedBackupChecks": {
                "encryptedBackupCreated": True, "archiveAuthenticated": True, "restoredProfileMatched": True,
                "wrongPassphraseRejected": True, "backupNoPlaintext": True, "offlineOnly": True,
                "settingsChanged": False, "productionQualificationComplete": False,
            },
        })
    else:
        identity.update({
            "sourceRef": receipt["sourceRef"], "archiveSha256": receipt["archiveSha256"],
            "binarySha256": receipt["binarySha256"], "build": receipt["build"],
            "authenticatedCandidateExecuted": True, "backupAndRecoveryVerified": True,
            "loopbackDiagnosticsVerified": True, "unixControllerVerified": system != "windows",
            "windowsDiscoveryVerified": system == "windows", "publisherSignatureVerified": False,
        })
    if (not isinstance(report, dict) or {"failurePhase", "failureType", "cleanupFailed"} & report.keys()
            or any(type(report.get(key)) is not type(value) or report[key] != value for key, value in identity.items())):
        raise ValueError("Packaged execution evidence does not match " + target)


def authenticate_qualification(path, bundle, commit, ref, run_id):
    authenticate_run(verification_command(path, bundle, commit, ref), run_id)


def verify_native_qualification(directory, package, manifest, commit, ref, expected, run_id=None):
    """Bind each target's staging receipt to the executable in the authenticated package."""
    artifacts = {(item["goos"], item["goarch"]): item["file"] for item in manifest["artifacts"]}
    folders = {"release-qualified-" + "-".join(target) for target in TARGETS}
    if directory.is_symlink() or {path.name for path in directory.iterdir()} != folders:
        raise ValueError("Expected one successful packaged qualification receipt for each desktop target")
    verified_reports = {}
    for system, arch in sorted(TARGETS):
        target = f"{system}/{arch}"
        folder = directory / f"release-qualified-{system}-{arch}"
        with tempfile.TemporaryDirectory(prefix="accessweaver-qualified-") as temporary:
            frozen = Path(temporary)
            names = {"candidate.json", "execution.json"}
            if run_id is not None:
                names.add(QUALIFICATION_BUNDLE)
            if snapshot(folder, frozen, len(names), maximum_file=1 << 20) != names:
                raise ValueError("Unexpected packaged qualification files for " + target)
            candidate = frozen / "candidate.json"
            execution_path = frozen / "execution.json"
            if candidate.stat().st_size > 16 << 10:
                raise ValueError("Packaged qualification receipt exceeds its size bound")
            bundle_digest = None
            if run_id is not None:
                bundle = frozen / QUALIFICATION_BUNDLE
                for subject in (candidate, execution_path):
                    authenticate_qualification(subject, bundle, commit, ref, run_id)
                bundle_digest = digest(bundle)
            candidate_bytes = candidate.read_bytes()
            execution_bytes = execution_path.read_bytes()
            receipt = json.loads(candidate_bytes)
            execution = json.loads(execution_bytes)
        if not isinstance(receipt, dict):
            raise ValueError("Packaged qualification does not match " + target)

        archive = artifacts[system, arch]
        binary_name = "accessweaver.exe" if system == "windows" else "accessweaver"
        suffix = ".zip" if system == "windows" else ".tar.gz"
        build, executable = inspect_archive(package / archive, archive.removesuffix(suffix), binary_name)
        identity = {
            "schemaVersion": 1, "repository": REPOSITORY, "workflow": WORKFLOW,
            "sourceCommit": commit, "sourceRef": ref, "target": target,
            "archive": archive, "archiveSha256": expected[archive].removeprefix("sha256:"),
            "manifestSha256": expected["BUILD-MANIFEST.json"].removeprefix("sha256:"),
            "bundleSha256": expected[BUNDLE_NAME].removeprefix("sha256:"),
            "binary": binary_name, "binarySha256": hashlib.sha256(executable).hexdigest(),
            "build": build, "authenticatedBeforeStaging": True, "provenanceSubjectsVerified": 12,
            "publisherSignatureVerified": False, "productionQualificationComplete": False,
        }
        if system in {"freebsd", "openbsd"}:
            identity["executionEnvironment"] = f"disposable-{system}-guest"
        if receipt.keys() != identity.keys() or any(
            type(receipt[key]) is not type(value) or receipt[key] != value for key, value in identity.items()
        ):
            raise ValueError("Packaged qualification does not match " + target)
        verify_target_execution(execution, receipt, system)
        verified_reports[target] = {
            "candidate.json": hashlib.sha256(candidate_bytes).hexdigest(),
            "execution.json": hashlib.sha256(execution_bytes).hexdigest(),
        }
        if bundle_digest is not None:
            verified_reports[target][QUALIFICATION_BUNDLE] = bundle_digest
    return verified_reports


@contextmanager
def verified_candidate(directory, commit, ref, rebuild_checksums_sha256, native_qualification, run_id=None):
    validate_identity(commit, ref)
    with tempfile.TemporaryDirectory(prefix="accessweaver-publish-") as temporary:
        frozen = Path(temporary)
        names = snapshot(directory, frozen, 13)
        verify(frozen, commit, ref)
        expected = {name: "sha256:" + digest(frozen / name) for name in names}
        if (rebuild_checksums_sha256 is not None
                and expected.get("SHA256SUMS.txt") != "sha256:" + rebuild_checksums_sha256):
            raise ValueError("Published candidate differs from the authenticated rebuild reference")
        qualification = None
        if native_qualification is not None:
            manifest = json.loads((frozen / "BUILD-MANIFEST.json").read_bytes())
            reports = verify_native_qualification(native_qualification, frozen, manifest, commit, ref, expected, run_id)
            canonical = json.dumps(reports, sort_keys=True, separators=(",", ":")).encode("ascii")
            qualification = {
                "schemaVersion": 1,
                "sourceCommit": commit,
                "sourceRef": ref,
                "repository": REPOSITORY,
                "workflow": WORKFLOW,
                "workflowRunID": run_id,
                "manifestSHA256": expected["BUILD-MANIFEST.json"].removeprefix("sha256:"),
                "provenanceBundleSHA256": expected[BUNDLE_NAME].removeprefix("sha256:"),
                "rebuildReferenceChecksumsSHA256": rebuild_checksums_sha256,
                "qualificationSHA256": hashlib.sha256(canonical).hexdigest(),
                "targetEvidenceSHA256": reports,
            }
        yield frozen, expected, qualification


def publish(directory, commit, ref, *, rebuild_checksums_sha256=None, native_qualification=None,
            expected_qualification_sha256=None, run_id=None):
    prefix = "refs/tags/v"
    if not ref.startswith(prefix) or "/" in ref[len(prefix):] or ref == prefix:
        raise ValueError("Prerelease publication requires a version tag")
    tag = ref.removeprefix("refs/tags/")
    with verified_candidate(directory, commit, ref, rebuild_checksums_sha256, native_qualification, run_id) as candidate:
        frozen, expected, qualification = candidate
        if expected_qualification_sha256 is not None and (
            qualification is None or qualification["qualificationSHA256"] != expected_qualification_sha256
        ):
            raise ValueError("Packaged qualification inputs differ from the read-only verification job")
        publish_verified(frozen, tag, commit, expected)


def publish_verified(directory, tag, commit, expected):
    if git_tag_commit(tag) != commit:
        raise ValueError("Remote release tag does not resolve to the verified commit")
    release = view(tag)
    if release is None:
        try:
            require_success(gh(
                "create", tag, "--verify-tag", "--draft", "--prerelease",
                "--title", f"AccessWeaver {tag} (unsigned alpha)",
                "--notes", "Unsigned alpha core builds. See README and docs/TESTING.md for scope.",
            ))
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            # A concurrent publisher or a lost response can leave a valid
            # draft. Inspect the tag once and never repeat the create request.
            create_error = error
        else:
            create_error = None
        release = view(tag)
        if release is None or release.get("isDraft") is not True:
            raise ValueError("Created release draft could not be verified") from create_error
        if git_tag_commit(tag) != commit:
            raise ValueError("Remote release tag changed during draft creation")
    missing_assets(release, tag, expected, allow_existing_bundle=True)
    expected = reuse_existing_bundle(directory, release, commit, tag, expected)
    missing = missing_assets(release, tag, expected)
    release_id = release["databaseId"]
    if not release["isDraft"]:
        verify_published_release(release, release_id, tag, commit, expected)
        return
    # Upload the time-bound provenance last so a partially uploaded build
    # can usually resume from a new attestation without fetching the old one.
    pending = set(missing)
    for name in sorted(missing, key=lambda name: (name == BUNDLE_NAME, name)):
        if name not in pending:
            continue
        try:
            upload_asset(release_id, directory / name, expected[name])
        except (ValueError, OSError, subprocess.SubprocessError):
            # A transport failure can occur after GitHub stored the bytes.
            # Recover only after the original draft confirms the exact asset.
            observed = view(tag)
            if (observed is None or observed.get("databaseId") != release_id
                    or observed.get("isDraft") is not True):
                raise
            pending = set(missing_assets(observed, tag, expected))
            if name in pending:
                raise
    release = view(tag)
    if release is None or release.get("databaseId") != release_id or missing_assets(release, tag, expected):
        raise ValueError("Release draft identity or asset verification is incomplete")
    if git_tag_commit(tag) != commit:
        raise ValueError("Remote release tag changed before publication")
    if release["isDraft"]:
        try:
            promote_draft(release_id)
        except (ValueError, OSError, subprocess.SubprocessError):
            # The server may have applied the PATCH before the response failed.
            # Reconcile once and never repeat the mutation on uncertain state.
            verify_published_release(view(tag), release_id, tag, commit, expected)
            return
        release = view(tag)
    verify_published_release(release, release_id, tag, commit, expected)


def verify_published_release(release, release_id, tag, commit, expected):
    if (release is None or release.get("databaseId") != release_id
            or release.get("isDraft") is not False or missing_assets(release, tag, expected)):
        raise ValueError("Published prerelease could not be verified")
    if git_tag_commit(tag) != commit:
        raise ValueError("Remote release tag changed during publication")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--rebuild-checksums-sha256", required=True,
                        help="SHA-256 of the authenticated checksum file from the successful rebuild comparison")
    parser.add_argument("--native-qualification", type=Path, required=True,
                        help="directory containing the ten successful packaged target receipts")
    parser.add_argument("--verify-only", action="store_true",
                        help="verify package, rebuild and qualification without accessing release state")
    parser.add_argument("--expected-qualification-sha256",
                        help="digest of target evidence and attestation files from the read-only verification job")
    parser.add_argument("--workflow-run-id", required=True, help="expected GitHub Actions run ID for the target attestations")
    args = parser.parse_args()
    if not re.fullmatch(r"[1-9][0-9]{0,19}", args.workflow_run_id):
        parser.error("expected a numeric GitHub Actions run ID")
    if args.verify_only:
        if args.expected_qualification_sha256 is not None:
            parser.error("--expected-qualification-sha256 is only accepted for publication")
    elif not re.fullmatch(r"[a-f0-9]{64}", args.expected_qualification_sha256 or ""):
        parser.error("publication requires --expected-qualification-sha256 from the verification job")
    try:
        if args.verify_only:
            with redirect_stdout(sys.stderr):
                with verified_candidate(args.directory.absolute(), args.source_commit, args.source_ref,
                                        args.rebuild_checksums_sha256, args.native_qualification, args.workflow_run_id) as candidate:
                    _, _, qualification = candidate
            print(json.dumps(qualification, indent=2))
        else:
            publish(args.directory.absolute(), args.source_commit, args.source_ref,
                    rebuild_checksums_sha256=args.rebuild_checksums_sha256, native_qualification=args.native_qualification,
                    expected_qualification_sha256=args.expected_qualification_sha256, run_id=args.workflow_run_id)
            print("Verified prerelease assets are published.")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile):
        message = ("Prerelease candidate verification failed." if args.verify_only else
                   "Prerelease verification or publication failed; inspect the draft and keep existing assets intact.")
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
