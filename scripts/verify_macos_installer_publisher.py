#!/usr/bin/env python3
"""Verify the publisher and stapled notarization of one approved macOS package."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from verify_release import require
from verify_release_rebuild import digest, snapshot


FINGERPRINT = re.compile(r"[a-fA-F0-9]{64}")
DEVELOPER_INSTALLER = re.compile(r"(?m)^[ \t]+1\.[ \t]+Developer ID Installer: [^\r\n]+ \(([A-Z0-9]{10})\)[ \t]*$")
CERTIFICATE_FINGERPRINT = re.compile(r"[a-fA-F0-9]{2}(?:[ :]*[a-fA-F0-9]{2}){31}")


def check_leaf(output, team, fingerprint):
    leaves = list(DEVELOPER_INSTALLER.finditer(output))
    require(len(leaves) == 1 and leaves[0][1] == team, "Package has no matching Developer ID Installer leaf")
    following_lines = output[leaves[0].end():].splitlines()[1:]
    for line in following_lines:
        if re.match(r"^[ \t]+\d+\.", line):
            break
        label = re.fullmatch(r"[ \t]*SHA256 Fingerprint:[ \t]*(.+?)[ \t]*", line)
        if label:
            value = label[1]
            require(CERTIFICATE_FINGERPRINT.fullmatch(value) is not None, "Invalid package leaf fingerprint")
            require(re.sub(r"[ :]", "", value).lower() == fingerprint, "Package publisher certificate differs")
            return
    raise ValueError("Package leaf fingerprint is missing")


def tool(arguments):
    with tempfile.TemporaryFile() as output:
        subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                       check=True, timeout=90, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
        output.seek(0)
        data = output.read(65537)
    require(len(data) <= 65536, "Publisher tool output exceeded limit")
    return data.decode("utf-8", errors="strict")


def check_package_certificate(package, team, certificate_sha256):
    check_leaf(tool(["/usr/sbin/pkgutil", "--check-signature", package]), team, certificate_sha256)


def check_package_publisher(package, team, certificate_sha256):
    check_package_certificate(package, team, certificate_sha256)
    tool(["/usr/sbin/spctl", "--assess", "--type", "install", package])
    tool(["/usr/bin/xcrun", "stapler", "validate", package])


def verify(directory, artifact_sha256, team, certificate_sha256):
    require(sys.platform == "darwin", "macOS is required for Developer ID verification")
    require(FINGERPRINT.fullmatch(artifact_sha256) and FINGERPRINT.fullmatch(certificate_sha256)
            and re.fullmatch(r"[A-Z0-9]{10}", team), "Invalid approved publisher inputs")
    artifact_sha256 = artifact_sha256.lower()
    certificate_sha256 = certificate_sha256.lower()
    with tempfile.TemporaryDirectory(prefix="accessweaver-macos-publisher-") as temporary:
        root = Path(temporary)
        name, = snapshot(directory, root, 1)
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\.pkg", name), "Expected a flat macOS package")
        package = root / name
        require(digest(package) == artifact_sha256, "Package digest differs from the approved release")
        check_package_publisher(package,team,certificate_sha256)
    return {
        "schemaVersion": 1,
        "scope": "macos-package-publisher",
        "artifactSHA256": artifact_sha256,
        "developerTeamID": team,
        "publisherCertificateSHA256": certificate_sha256,
        "developerIDInstallerVerified": True,
        "gatekeeperAccepted": True,
        "stapledTicketValidated": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="private directory containing only the approved .pkg")
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--publisher-certificate-sha256", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.directory, args.artifact_sha256, args.team_id, args.publisher_certificate_sha256)
    except (ValueError, OSError, subprocess.SubprocessError):
        print("macOS publisher verification failed. Check the approved digests, Developer ID, Gatekeeper and ticket.",
              file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
