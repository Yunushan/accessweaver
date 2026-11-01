#!/usr/bin/env python3
"""Exercise actual GitHub CLI rejection against a real signed preview bundle."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from verify_release_provenance import BUNDLE_NAME, verification_command


def check(directory, commit, ref, gh="gh"):
    path = directory / "BUILD-MANIFEST.json"
    base = verification_command(path, directory / BUNDLE_NAME, commit, ref, gh)
    def run(command, success):
        result = subprocess.run(command, capture_output=True, timeout=120)
        if (result.returncode == 0) != success:
            raise ValueError("Unexpected GitHub CLI provenance acceptance result")
    run(base, True)
    rejected = []
    for flag, value in [("--source-digest", "0" * len(commit)), ("--source-ref", "refs/tags/invalid-provenance-probe"),
                        ("--signer-workflow", "Yunushan/accessweaver/.github/workflows/ci.yml"),
                        ("--repo", "octocat/Hello-World")]:
        command = list(base)
        command[command.index(flag) + 1] = value
        run(command, False)
        rejected.append(flag)
    with tempfile.TemporaryDirectory(prefix="accessweaver-provenance-probe-") as temporary:
        changed = Path(temporary) / path.name
        changed.write_bytes(path.read_bytes() + b"\n")
        command = list(base)
        command[3] = str(changed)
        run(command, False)
        rejected.append("changed-subject-digest")
    # Prevent persistent service/authentication/network failure from passing all
    # negative cases without a working signature verifier at the end.
    run(base, True)
    return {"sourceCommit": commit, "sourceRef": ref, "rejected": rejected,
            "realBundleVerifiedBeforeAndAfter": True, "productionQualificationComplete": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--gh", default="gh")
    args = parser.parse_args()
    print(json.dumps(check(args.directory, args.source_commit, args.source_ref, args.gh)))
