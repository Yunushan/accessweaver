#!/usr/bin/env python3
"""Verify the publisher and stapled notarization of one approved macOS package."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from macos_installer import macho_identity
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


def developer_application_requirement(team):
    require(re.fullmatch(r"[A-Z0-9]{10}", team), "Invalid Developer ID team")
    return ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
            'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
            f'and certificate leaf[subject.OU] = "{team}"')


def stage_detector(package, team, architecture, approved_sha256, destination):
    expanded = package.parent / "expanded"
    tool(["/usr/sbin/pkgutil", "--expand-full", package, expanded])
    for path in (expanded, expanded / "Scripts"):
        require(stat.S_ISDIR(path.lstat().st_mode), "Expected an ordinary expanded script directory")
    helper = expanded / "Scripts" / "postinstall"
    before = helper.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 < before.st_size <= 16 << 20, "Expected a bounded regular package helper")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(helper, flags), "rb") as source:
        info = os.fstat(source.fileno())
        require(os.path.samestat(before, info) and info.st_nlink == 1 and stat.S_ISREG(info.st_mode)
                and info.st_size == before.st_size, "Package helper changed before verification")
        data = source.read(info.st_size + 1)
    require(len(data) == info.st_size, "Package helper size changed")
    macho_identity(data, architecture)

    with tempfile.TemporaryDirectory(prefix=".accessweaver-detector-", dir=destination.parent) as temporary:
        staged = Path(temporary) / destination.name
        with staged.open("xb") as stream:
            stream.write(data)
            stream.flush()
            staged.chmod(0o755)
            os.fsync(stream.fileno())
        require(digest(staged) == approved_sha256, "Package helper differs from the approved digest")
        tool(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
              "-R=" + developer_application_requirement(team), staged])
        os.link(staged, destination)


def verify(directory, artifact_sha256, team, certificate_sha256, *,
           detector_output=None, detector_sha256=None, architecture=None):
    require(sys.platform == "darwin", "macOS is required for Developer ID verification")
    require(FINGERPRINT.fullmatch(artifact_sha256) and FINGERPRINT.fullmatch(certificate_sha256)
            and re.fullmatch(r"[A-Z0-9]{10}", team), "Invalid approved publisher inputs")
    if any(value is not None for value in (detector_output, detector_sha256, architecture)):
        require(detector_output is not None and detector_output.name == "accessweaver-installer"
                and not detector_output.parent.resolve().is_relative_to(directory.resolve())
                and detector_sha256 is not None and FINGERPRINT.fullmatch(detector_sha256)
                and architecture in ("amd64", "arm64"), "Invalid managed detector staging inputs")
        detector_sha256 = detector_sha256.lower()
    artifact_sha256 = artifact_sha256.lower()
    certificate_sha256 = certificate_sha256.lower()
    with tempfile.TemporaryDirectory(prefix="accessweaver-macos-publisher-") as temporary:
        root = Path(temporary)
        name, = snapshot(directory, root, 1)
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\.pkg", name), "Expected a flat macOS package")
        package = root / name
        require(digest(package) == artifact_sha256, "Package digest differs from the approved release")
        check_package_publisher(package, team, certificate_sha256)
        if detector_output is not None:
            stage_detector(package, team, architecture, detector_sha256, detector_output)
    report = {
        "schemaVersion": 1,
        "scope": "macos-package-publisher",
        "artifactSHA256": artifact_sha256,
        "developerTeamID": team,
        "publisherCertificateSHA256": certificate_sha256,
        "developerIDInstallerVerified": True,
        "gatekeeperAccepted": True,
        "stapledTicketValidated": True,
    }
    if detector_output is not None:
        report["managedDetector"] = {
            "architecture": architecture, "sha256": detector_sha256,
            "developerIDApplicationVerified": True,
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="private directory containing only the approved .pkg")
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--publisher-certificate-sha256", required=True)
    parser.add_argument("--detector-output", type=Path, help="new accessweaver-installer path in a trusted directory")
    parser.add_argument("--detector-sha256", help="approved script-file:postinstall SHA-256")
    parser.add_argument("--architecture", choices=("amd64", "arm64"), help="approved managed detector target")
    args = parser.parse_args()
    try:
        result = verify(args.directory, args.artifact_sha256, args.team_id, args.publisher_certificate_sha256,
                        detector_output=args.detector_output, detector_sha256=args.detector_sha256,
                        architecture=args.architecture)
    except (ValueError, OSError, subprocess.SubprocessError):
        print("macOS publisher verification failed. Check the approved digests, Developer ID, Gatekeeper and ticket.",
              file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
