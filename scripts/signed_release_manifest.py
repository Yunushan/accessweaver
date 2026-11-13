#!/usr/bin/env python3
"""Prepare or authenticate the final publisher-signed Windows and macOS release subjects."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile

from macos_installer import version_parts
from verify_release import require
from verify_release_provenance import REPOSITORY, regular_file, validate_identity
from verify_release_rebuild import digest, snapshot

MANIFEST = "SIGNED-RELEASE.json"
SIGNATURE = "SIGNED-RELEASE.p7s"


def release_subjects(commit, ref):
    validate_identity(commit, ref)
    require(ref.startswith("refs/tags/v"), "Expected an approved release tag")
    version = ref.removeprefix("refs/tags/v")
    version_parts(version)
    subjects = {}
    for arch in ("amd64", "arm64"):
        windows = f"accessweaver-{version}-windows-{arch}"
        setup = windows + "-setup.exe"
        subjects[setup] = ("windows/" + arch, "installer")
        subjects[setup + ".cdx.json"] = ("windows/" + arch, "installer-sbom")
        subjects[windows + ".exe"] = ("windows/" + arch, "payload")
        subjects[windows + ".exe.cdx.json"] = ("windows/" + arch, "payload-sbom")
        package = f"accessweaver-{version}-darwin-{arch}-deployment-experimental.pkg"
        subjects[package] = ("darwin/" + arch, "installer")
        subjects[package + ".cdx.json"] = ("darwin/" + arch, "installer-sbom")
    return subjects


def encode_manifest(root, commit, ref, subjects):
    return (json.dumps({
        "schemaVersion": 1,
        "scope": "accessweaver-signed-desktop-release",
        "repository": REPOSITORY,
        "sourceCommit": commit,
        "sourceRef": ref,
        "subjects": [
            {"file": name, "target": target, "role": role,
             "size": (root / name).stat().st_size, "sha256": digest(root / name)}
            for name, (target, role) in sorted(subjects.items())
        ],
    }, indent=2) + "\n").encode("utf-8")


def prepare(directory, output, commit, ref):
    subjects = release_subjects(commit, ref)
    require(output.name == MANIFEST and output.parent.resolve() != directory.resolve(),
            "Write the manifest outside the source artifact directory")
    with tempfile.TemporaryDirectory(prefix="accessweaver-signed-release-") as temporary:
        root = Path(temporary)
        require(snapshot(directory, root, len(subjects)) == subjects.keys(), "Unexpected signed release subjects")
        manifest = encode_manifest(root, commit, ref, subjects)
        with output.open("xb") as stream:
            stream.write(manifest)


def authenticate(root, certificate, fingerprint, openssl):
    # One independently supplied DER certificate is the trust anchor. Do not
    # accept embedded signer certificates or consult the host CA bundle.
    regular_file(certificate, 65536)
    info = certificate.lstat()
    require(not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "Approval certificate path is a reparse point")
    with certificate.open("rb") as stream:
        der = stream.read(65537)
    require(0 < len(der) <= 65536 and hashlib.sha256(der).hexdigest() == fingerprint,
            "Approval certificate differs from the independently approved fingerprint")
    trusted = root / "APPROVED-RELEASE-CERTIFICATE.pem"
    trusted.write_text(ssl.DER_cert_to_PEM_cert(der), encoding="ascii")
    subprocess.run(
        [openssl, "cms", "-verify", "-binary", "-inform", "DER",
         "-in", str(root / SIGNATURE), "-content", str(root / MANIFEST),
         "-certfile", str(trusted), "-nointern", "-noverify", "-out", str(root / "VERIFIED-CONTENT")],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=30,
    )
    output = root / "VERIFIED-CONTENT"
    regular_file(output, 65536)
    require(output.read_bytes() == (root / MANIFEST).read_bytes(),
            "Approval signature does not cover the exact manifest")


def verify(directory, certificate, certificate_sha256, commit, ref, openssl="openssl"):
    subjects = release_subjects(commit, ref)
    require(re.fullmatch(r"[a-fA-F0-9]{64}", certificate_sha256)
            and not certificate.resolve().is_relative_to(directory.resolve()),
            "Expected an independently pinned approval certificate outside the release directory")
    certificate_sha256 = certificate_sha256.lower()
    with tempfile.TemporaryDirectory(prefix="accessweaver-signed-release-") as temporary:
        root = Path(temporary)
        names = snapshot(directory, root, len(subjects) + 2)
        require(names == subjects.keys() | {MANIFEST, SIGNATURE}, "Unexpected signed release inventory")
        regular_file(root / MANIFEST, 65536)
        regular_file(root / SIGNATURE, 1 << 20)
        authenticate(root, certificate, certificate_sha256, openssl)
        expected = encode_manifest(root, commit, ref, subjects)
        require((root / MANIFEST).read_bytes() == expected, "Signed release manifest or subject bytes differ")
        return {
            "schemaVersion": 1, "scope": "accessweaver-signed-desktop-release",
            "sourceCommit": commit, "sourceRef": ref, "subjectsVerified": len(subjects),
            "organizationApprovalSignatureVerified": True, "approvalCertificateSHA256": certificate_sha256,
            "nativePublisherChecksPerformed": False, "productionQualificationComplete": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prepare_args = commands.add_parser("prepare")
    prepare_args.add_argument("--output", type=Path, required=True)
    verify_args = commands.add_parser("verify")
    verify_args.add_argument("--approval-certificate", type=Path, required=True)
    verify_args.add_argument("--approval-certificate-sha256", required=True)
    verify_args.add_argument("--openssl", default="openssl", help="trusted OpenSSL executable")
    for command in (prepare_args, verify_args):
        command.add_argument("directory", type=Path)
        command.add_argument("--source-commit", required=True)
        command.add_argument("--source-ref", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            prepare(args.directory, args.output, args.source_commit, args.source_ref)
        else:
            print(json.dumps(verify(args.directory, args.approval_certificate, args.approval_certificate_sha256,
                                    args.source_commit, args.source_ref, args.openssl)))
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Signed release inventory or organization approval verification failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
