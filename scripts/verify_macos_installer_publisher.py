#!/usr/bin/env python3
"""Verify the publisher and stapled notarization of one approved macOS package."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from xml.etree.ElementTree import ParseError

from macos_deployment import PACKAGE_ID
from macos_installer import BUNDLE_ID, BUNDLE_NAME, macho_identity
from macos_package_archive import xml
from verify_release import publish_staged_file, require
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


def tool(arguments, *, cwd=None):
    with tempfile.TemporaryFile() as output:
        subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                       check=True, timeout=90, cwd=cwd, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
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


def read_expanded_file(path, maximum, *, mode=None):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 < before.st_size <= maximum, "Expected a bounded regular package file")
    if mode is not None:
        require(stat.S_IMODE(before.st_mode) == mode, "Expected a detector with mode 0755")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        info = os.fstat(source.fileno())
        def identity(entry):
            return entry.st_dev, entry.st_ino, entry.st_mode, entry.st_nlink, entry.st_size, entry.st_mtime_ns

        require(stat.S_ISREG(info.st_mode) and identity(info) == identity(before),
                "Package file changed before verification")
        data = source.read(info.st_size + 1)
        require(len(data) == info.st_size and identity(os.fstat(source.fileno())) == identity(before)
                and identity(path.lstat()) == identity(before), "Package file changed during verification")
    return data


def verify_detector_bytes(path, approved_sha256):
    data = read_expanded_file(path, 16 << 20, mode=0o755 if os.name == "posix" else None)
    require(hashlib.sha256(data).hexdigest() == approved_sha256, "Package helper differs from the approved digest")


def check_application_certificate(path, approved_sha256):
    # codesign writes the embedded chain as codesign0 (leaf), codesign1, etc.
    with tempfile.TemporaryDirectory(prefix="accessweaver-application-chain-") as temporary:
        directory = Path(temporary)
        tool(["/usr/bin/codesign", "--display", "--extract-certificates", path], cwd=directory)
        leaf = read_expanded_file(directory / "codesign0", 64 << 10)
        require(hashlib.sha256(leaf).hexdigest() == approved_sha256,
                "Developer ID Application leaf certificate differs from the approved fingerprint")


def verify_packaged_application(package, team, architecture, application_pin=None):
    expanded = package.parent / "expanded"
    tool(["/usr/sbin/pkgutil", "--expand-full", package, expanded])
    payload = expanded / "Payload"
    app = payload / BUNDLE_NAME
    contents = app / "Contents"
    executables = contents / "MacOS"
    for path in (expanded, payload, app, contents, executables):
        require(stat.S_ISDIR(path.lstat().st_mode), "Expected an ordinary expanded package directory")

    core = read_expanded_file(executables / "accessweaver", 64 << 20)
    macho_identity(core, architecture)
    requirement = developer_application_requirement(team)
    tool(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
          "-R=" + requirement + f' and identifier "{BUNDLE_ID}"', app])
    if application_pin is not None:
        check_application_certificate(app, application_pin)
    return expanded


def read_packaged_helper(expanded, architecture):
    scripts = expanded / "Scripts"
    require(stat.S_ISDIR(scripts.lstat().st_mode), "Expected an ordinary expanded package scripts directory")
    data = read_expanded_file(scripts / "postinstall", 16 << 20)
    require(read_expanded_file(scripts / "preinstall", 16 << 20) == data,
            "Expanded package scripts do not use the same helper")
    macho_identity(data, architecture)
    return data


def check_helper_publisher(helper, team, application_pin):
    tool(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
          "-R=" + developer_application_requirement(team), helper])
    if application_pin is not None:
        check_application_certificate(helper, application_pin)


def verify_packaged_deployment(package, team, architecture, application_pin):
    expanded = verify_packaged_application(package, team, architecture, application_pin)
    try:
        metadata = xml(read_expanded_file(expanded / "PackageInfo", 256 << 10))
    except ParseError as error:
        raise ValueError("Invalid deployment package metadata") from error
    sections = metadata.findall("scripts")
    require(metadata.tag == "pkg-info" and metadata.get("identifier") == PACKAGE_ID and len(sections) == 1
            and len(sections[0]) == 2 and {phase.tag: phase.get("file") for phase in sections[0]} == {
                "preinstall": "./preinstall", "postinstall": "./postinstall",
            }, "Deployment package phase entry points differ")

    data = read_packaged_helper(expanded, architecture)
    check_helper_publisher(expanded / "Scripts" / "postinstall", team, application_pin)
    require(read_packaged_helper(expanded, architecture) == data,
            "Expanded package helper changed during publisher verification")


def stage_detector(expanded, team, architecture, approved_sha256, destination, parent_info, application_pin=None):
    parent = destination.parent

    def check_parent():
        current = parent.lstat()
        require(stat.S_ISDIR(current.st_mode) and os.path.samestat(current, parent_info),
                "Detector output directory changed during verification")

    check_parent()
    data = read_packaged_helper(expanded, architecture)

    with tempfile.TemporaryDirectory(prefix=".accessweaver-detector-", dir=parent) as temporary:
        staged = Path(temporary) / destination.name
        with staged.open("xb") as stream:
            stream.write(data)
            stream.flush()
            staged.chmod(0o755)
            os.fsync(stream.fileno())
        verify_detector_bytes(staged, approved_sha256)
        check_helper_publisher(staged, team, application_pin)
        verify_detector_bytes(staged, approved_sha256)
        check_parent()
        try:
            publish_staged_file(staged, destination)
        except FileExistsError:
            # A retry or concurrent publication may already own the name.
            pass
    check_parent()
    verify_detector_bytes(destination, approved_sha256)
    check_parent()


def verify(directory, artifact_sha256, team, certificate_sha256, *,
           detector_output=None, detector_sha256=None, architecture=None,
           application_certificate_sha256=None):
    require(sys.platform == "darwin", "macOS is required for Developer ID verification")
    require(FINGERPRINT.fullmatch(artifact_sha256) and FINGERPRINT.fullmatch(certificate_sha256)
            and re.fullmatch(r"[A-Z0-9]{10}", team), "Invalid approved publisher inputs")
    if architecture is not None:
        require(architecture in ("amd64", "arm64"), "Invalid approved application architecture")
    if application_certificate_sha256 is not None:
        require(architecture is not None and FINGERPRINT.fullmatch(application_certificate_sha256),
                "Developer ID Application certificate pin requires an approved architecture and SHA-256")
        application_certificate_sha256 = application_certificate_sha256.lower()
    if detector_output is not None or detector_sha256 is not None:
        require(detector_output is not None and detector_output.name == "accessweaver-installer"
                and not detector_output.parent.resolve().is_relative_to(directory.resolve())
                and detector_sha256 is not None and FINGERPRINT.fullmatch(detector_sha256)
                and architecture is not None, "Invalid managed detector staging inputs")
        parent = detector_output.parent
        parent_info = parent.lstat()
        require(stat.S_ISDIR(parent_info.st_mode), "Expected a real detector output directory")
        detector_output = parent.resolve(strict=True) / detector_output.name
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
        if architecture is not None:
            expanded = verify_packaged_application(package, team, architecture, application_certificate_sha256)
            if detector_output is not None:
                stage_detector(expanded, team, architecture, detector_sha256, detector_output, parent_info,
                               application_certificate_sha256)
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
    if architecture is not None:
        report["packagedApplicationDeveloperIDVerified"] = True
        report["packagedApplicationArchitecture"] = architecture
    if application_certificate_sha256 is not None:
        report["applicationCertificateSHA256"] = application_certificate_sha256
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
    parser.add_argument("--application-certificate-sha256",
                        help="approved Developer ID Application leaf DER SHA-256 for the app and any staged detector")
    parser.add_argument("--detector-output", type=Path, help="new accessweaver-installer path in a trusted directory")
    parser.add_argument("--detector-sha256", help="approved script-file:postinstall SHA-256")
    parser.add_argument("--architecture", choices=("amd64", "arm64"), help="verify the packaged application's Developer ID and this native architecture")
    args = parser.parse_args()
    try:
        result = verify(args.directory, args.artifact_sha256, args.team_id, args.publisher_certificate_sha256,
                        detector_output=args.detector_output, detector_sha256=args.detector_sha256,
                        architecture=args.architecture, application_certificate_sha256=args.application_certificate_sha256)
    except (ValueError, OSError, subprocess.SubprocessError):
        print("macOS publisher verification failed. Check the approved digests, Developer ID, Gatekeeper and ticket.",
              file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
