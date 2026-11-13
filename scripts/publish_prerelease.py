#!/usr/bin/env python3
"""Publish a verified portable build through a draft without replacing assets."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlencode

from verify_release_provenance import REPOSITORY, validate_identity, verify
from verify_release_rebuild import digest, snapshot

REMOTE = "https://github.com/" + REPOSITORY + ".git"


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


def missing_assets(release, tag, expected):
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
            or asset.get("digest") != expected[name]
        ):
            raise ValueError("Release contains an unexpected, incomplete or different asset")
        names.add(name)
    missing = sorted(expected.keys() - names)
    if missing and not release["isDraft"]:
        raise ValueError("Published release is missing verified assets")
    return missing


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
        require_success(gh(
            "create", tag, "--verify-tag", "--draft", "--prerelease",
            "--title", f"AccessWeaver {tag} (unsigned alpha)",
            "--notes", "Unsigned alpha core builds. See README and docs/TESTING.md for scope.",
        ))
        release = view(tag)
        if release is None or release.get("isDraft") is not True:
            raise ValueError("Created release draft could not be verified")
    missing = missing_assets(release, tag, expected)
    release_id = release["databaseId"]
    if not release["isDraft"]:
        return
    for name in missing:
        upload_asset(release_id, directory / name, expected[name])
    release = view(tag)
    if release is None or release.get("databaseId") != release_id or missing_assets(release, tag, expected):
        raise ValueError("Release draft identity or asset verification is incomplete")
    if git_tag_commit(tag) != commit:
        raise ValueError("Remote release tag changed before publication")
    if release["isDraft"]:
        promote_draft(release_id)
    release = view(tag)
    if (release is None or release.get("databaseId") != release_id
            or release.get("isDraft") is not False or missing_assets(release, tag, expected)):
        raise ValueError("Published prerelease could not be verified")


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
