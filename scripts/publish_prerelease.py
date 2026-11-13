#!/usr/bin/env python3
"""Publish a verified portable build through a draft without replacing assets."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from verify_release_provenance import REPOSITORY, validate_identity, verify

REMOTE = "https://github.com/" + REPOSITORY + ".git"


def git_tag_commit(tag):
    ref = "refs/tags/" + tag
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", REMOTE, ref, ref + "^{}"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    refs = {}
    for line in result.stdout.splitlines():
        digest, name = line.split("\t", 1)
        refs[name] = digest
    return refs.get(ref + "^{}", refs.get(ref))


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
    result = gh("view", tag, "--json", "tagName,isDraft,isPrerelease,assets")
    if result.returncode == 1 and result.stderr.strip() == "release not found":
        return None
    return json.loads(require_success(result))


def missing_assets(release, tag, expected):
    if (
        release.get("tagName") != tag
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
    verify(directory, commit, ref)
    expected = {}
    for file in directory.iterdir():
        with file.open("rb") as stream:
            expected[file.name] = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    if len(expected) != 13:
        raise ValueError("Verified release asset count differs")

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
    if not release["isDraft"]:
        return
    if missing:
        require_success(gh("upload", tag, *(str(directory / name) for name in missing)))
    release = view(tag)
    if release is None or missing_assets(release, tag, expected):
        raise ValueError("Release draft asset verification is incomplete")
    if git_tag_commit(tag) != commit:
        raise ValueError("Remote release tag changed before publication")
    if release["isDraft"]:
        require_success(gh("edit", tag, "--draft=false"))
    release = view(tag)
    if release is None or release.get("isDraft") is not False or missing_assets(release, tag, expected):
        raise ValueError("Published prerelease could not be verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-ref", required=True)
    args = parser.parse_args()
    try:
        publish(args.directory.resolve(), args.source_commit, args.source_ref)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("Prerelease verification or publication failed; inspect the draft and keep existing assets intact.",
              file=sys.stderr)
        return 1
    print("Verified prerelease assets are published.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
