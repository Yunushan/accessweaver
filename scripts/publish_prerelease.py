#!/usr/bin/env python3
"""Publish a verified portable build through a draft without replacing assets."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from threading import Timer
from urllib.parse import urlencode

from verify_release_provenance import BUNDLE_NAME, REPOSITORY, validate_identity, verify
from verify_release_rebuild import digest, snapshot

REMOTE = "https://github.com/" + REPOSITORY + ".git"
MAX_BUNDLE = 16 << 20


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


def publish(directory, commit, ref):
    validate_identity(commit, ref)
    prefix = "refs/tags/v"
    if not ref.startswith(prefix) or "/" in ref[len(prefix):] or ref == prefix:
        raise ValueError("Prerelease publication requires a version tag")
    tag = ref.removeprefix("refs/tags/")
    with tempfile.TemporaryDirectory(prefix="accessweaver-publish-") as temporary:
        frozen = Path(temporary)
        names = snapshot(directory, frozen, 13)
        verify(frozen, commit, ref)
        expected = {name: "sha256:" + digest(frozen / name) for name in names}
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
    args = parser.parse_args()
    try:
        publish(args.directory.absolute(), args.source_commit, args.source_ref)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("Prerelease verification or publication failed; inspect the draft and keep existing assets intact.",
              file=sys.stderr)
        return 1
    print("Verified prerelease assets are published.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
