#!/usr/bin/env python3
"""Prepare or authenticate the final publisher-signed Windows and macOS release subjects."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile

from macos_installer import parse_release_version, version_parts
from sbom import prop_map, validate_digest
from verify_release import require
from verify_release_provenance import REPOSITORY, regular_file, validate_identity
from verify_release_rebuild import digest, snapshot

MANIFEST = "SIGNED-RELEASE.json"
SIGNATURE = "SIGNED-RELEASE.p7s"
MAX_REBOOT_EVIDENCE = 16
MAX_SBOM_BYTES = 4 << 20
SHA256 = r"[a-f0-9]{64}"
WINDOWS_DETECTION_FIELDS = (
    "target", "installMode", "previousVersion", "previousPayloadSHA256",
    "uninstallerSHA256", "publisherCertificateSHA256", "rebootEvidenceSHA256",
)
REBOOT_CHECKS = (
    "passed", "guestRebootVerified", "installedPayloadVerifiedBeforeRestart",
    "installedPayloadVerified", "uninstallerIdentityVerified", "installedTreeVerified",
    "registrationPreserved", "registrationRemoved", "packageFilesRemoved",
    "userProfileVerifiedAfterReboot", "userProfilePreservedAfterUninstall",
)
REVOCATION_FIELDS = {
    "sourceCommits": r"[a-f0-9]{40}|[a-f0-9]{64}",
    "sourceRefs": r"refs/tags/v[A-Za-z0-9._+-]+",
    "subjectSHA256": SHA256,
    "approvalCertificateSHA256": SHA256,
}


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


def inventory(root, subjects):
    return [
        {"file": name, "target": target, "role": role,
         "size": (root / name).stat().st_size, "sha256": digest(root / name)}
        for name, (target, role) in sorted(subjects.items())
    ]


def macos_detector_digest(document, identity):
    components = {entry["bom-ref"]: entry for entry in document["components"]}
    helper = components["helper:application"]
    require(helper.get("type") == "application" and helper.get("version") == identity["version"],
            "macOS detector build identity differs")
    values = prop_map(helper)
    for key, field in (("source-commit", "commit"), ("source-state", "sourceState"),
                       ("target-os", "platform"), ("target-arch", "arch")):
        require(values.get("accessweaver:" + key) == identity[field], "macOS detector build identity differs")

    hashes = helper.get("hashes")
    require(isinstance(hashes, list) and len(hashes) == 1 and isinstance(hashes[0], dict),
            "Invalid macOS detector digest")
    pin = hashes[0].get("content")
    require(isinstance(pin, str) and re.fullmatch(SHA256, pin)
            and hashes == [{"alg": "SHA-256", "content": pin}], "Invalid macOS detector digest")
    for phase in ("preinstall", "postinstall"):
        entry = components["script-file:" + phase]
        require(entry.get("type") == "file" and entry.get("name") == phase and entry.get("hashes") == hashes,
                "macOS package script differs from its detector")
    return pin


def validate_release_sboms(root, files, commit, version):
    documents = {}
    macos_detectors = []
    try:
        for subject in files:
            if subject["role"] not in ("installer", "payload"):
                continue
            name = subject["file"] + ".cdx.json"
            path = root / name
            regular_file(path, MAX_SBOM_BYTES)
            document = decode_json(path.read_bytes())
            platform, arch = subject["target"].split("/")
            identity = {"version": version, "commit": commit, "sourceState": "clean",
                        "platform": platform, "arch": arch}
            validate_digest(document, subject["sha256"], identity)
            documents[subject["target"], subject["role"]] = document
            if platform == "darwin":
                macos_detectors.append({
                    "target": subject["target"], "version": version, "packageSHA256": subject["sha256"],
                    "detectorSHA256": macos_detector_digest(document, identity),
                })
        for target in ("windows/amd64", "windows/arm64"):
            payload = documents[target, "payload"]["metadata"]["component"]
            installer = documents[target, "installer"]
            packaged = next((entry for entry in installer["components"]
                             if entry["bom-ref"] == "payload-application"), None)
            require(packaged == {**payload, "bom-ref": "payload-application"},
                    "Windows installer SBOM payload differs from the signed payload SBOM")
    except (AttributeError, KeyError, TypeError, RecursionError) as error:
        raise ValueError("Malformed signed release SBOM") from error
    return len(documents), macos_detectors


def windows_subjects(subjects):
    return {(subject["target"], subject["role"]): subject["sha256"] for subject in subjects
            if subject["target"].startswith("windows/") and subject["role"] in ("installer", "payload")}


def windows_payload_sboms(subjects):
    return {subject["target"]: subject["sha256"] for subject in subjects if subject["role"] == "payload-sbom"}


def detection_key(entry):
    return entry["target"], entry["installMode"], entry["previousVersion"], entry["previousPayloadSHA256"]


def validate_detection(entries, subjects, version):
    require(isinstance(entries, list) and 0 < len(entries) <= MAX_REBOOT_EVIDENCE,
            "Invalid Windows detection inventory size")
    targets = windows_subjects(subjects)
    for entry in entries:
        require(isinstance(entry, dict) and entry.keys() == set(WINDOWS_DETECTION_FIELDS)
                and all(isinstance(value, str) for value in entry.values()),
                "Malformed Windows detection entry")
        target = entry["target"]
        require((target, "installer") in targets and entry["installMode"] in ("clean", "upgrade"),
                "Unsupported Windows detection path")
        for field in ("uninstallerSHA256", "publisherCertificateSHA256", "rebootEvidenceSHA256"):
            require(re.fullmatch(SHA256, entry[field]), "Malformed Windows detection digest")
        previous_version = entry["previousVersion"]
        previous_payload = entry["previousPayloadSHA256"]
        if entry["installMode"] == "upgrade":
            version_parts(previous_version)
            require(previous_version != version and re.fullmatch(SHA256, previous_payload)
                    and previous_payload != targets[target, "payload"], "Invalid previous Windows package")
        else:
            require(previous_version == previous_payload == "", "Unexpected previous Windows package")

    keys = [detection_key(entry) for entry in entries]
    require(len(keys) == len(set(keys)), "Duplicate Windows detection path")


def load_detection_evidence(directory, evidence, subjects, version):
    require(len(evidence) <= MAX_REBOOT_EVIDENCE, "Too many Windows reboot reports")
    targets = windows_subjects(subjects)
    payload_sboms = windows_payload_sboms(subjects)
    entries = []
    for path, fingerprint in evidence:
        content = independently_pinned_file(directory, path, fingerprint, maximum=8192)
        report = decode_json(content)
        require(isinstance(report, dict) and type(report.get("schemaVersion")) is int
                and report["schemaVersion"] in (5, 6) and report.get("stage") == "complete"
                and all(report.get(field) is True for field in REBOOT_CHECKS),
                "Windows reboot qualification is incomplete")
        architecture = report.get("architecture")
        mode = report.get("installMode")
        require(architecture in ("amd64", "arm64") and mode in ("clean", "upgrade"),
                "Unsupported Windows reboot path")
        target = "windows/" + architecture
        require(report.get("version") == version and report.get("setupSHA256") == targets[target, "installer"]
                and report.get("payloadSHA256") == targets[target, "payload"],
                "Windows reboot evidence differs from the signed release subjects")
        if report["schemaVersion"] == 6:
            require(report.get("payloadSBOMSHA256") == payload_sboms[target]
                    and report.get("installedPayloadSBOMVerified") is True
                    and report.get("installedPayloadPublisherVerified") is True,
                    "Windows reboot evidence does not verify the signed payload publisher and release SBOM")
        require(mode != "upgrade" or report.get("userProfilePreservedThroughUpgrade") is True,
                "Windows upgrade qualification is incomplete")
        downgrade = report.get("downgradeRequested")
        require(type(downgrade) is bool
                and report.get("downgradeRefused") is downgrade
                and report.get("downgradeStatePreserved") is downgrade
                and (not downgrade or mode == "upgrade"), "Windows downgrade evidence is inconsistent")
        entries.append({
            "target": target, "installMode": mode,
            "previousVersion": report.get("previousVersion"),
            "previousPayloadSHA256": report.get("previousPayloadSHA256"),
            "uninstallerSHA256": report.get("uninstallerSHA256"),
            "publisherCertificateSHA256": report.get("publisherSHA256"),
            "rebootEvidenceSHA256": fingerprint.lower(),
        })
    validate_detection(entries, subjects, version)
    return entries


def encode_manifest(commit, ref, subjects, windows_detection=()):
    manifest = {
        "schemaVersion": 2 if windows_detection else 1,
        "scope": "accessweaver-signed-desktop-release",
        "repository": REPOSITORY,
        "sourceCommit": commit,
        "sourceRef": ref,
        "subjects": subjects,
    }
    if windows_detection:
        manifest["windowsDetection"] = [
            {field: entry[field] for field in WINDOWS_DETECTION_FIELDS}
            for entry in sorted(windows_detection, key=detection_key)
        ]
    return (json.dumps(manifest, indent=2) + "\n").encode("utf-8")


def prepare(directory, output, commit, ref, *, windows_reboot_evidence=()):
    subjects = release_subjects(commit, ref)
    require(output.name == MANIFEST and output.parent.resolve() != directory.resolve(),
            "Write the manifest outside the source artifact directory")
    with tempfile.TemporaryDirectory(prefix="accessweaver-signed-release-") as temporary:
        root = Path(temporary)
        require(snapshot(directory, root, len(subjects)) == subjects.keys(), "Unexpected signed release subjects")
        files = inventory(root, subjects)
        version = ref.removeprefix("refs/tags/v")
        validate_release_sboms(root, files, commit, version)
        entries = []
        if windows_reboot_evidence:
            entries = load_detection_evidence(directory, windows_reboot_evidence, files, version)
        manifest = encode_manifest(commit, ref, files, entries)
        with output.open("xb") as stream:
            stream.write(manifest)


def independently_pinned_file(directory, path, fingerprint, *, maximum=65536):
    require(re.fullmatch(r"[a-fA-F0-9]{64}", fingerprint)
            and not path.resolve().is_relative_to(directory.resolve()),
            "Expected an independently pinned file outside the release directory")
    regular_file(path, maximum)
    info = path.lstat()
    require(not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "Independently pinned input is a reparse point")
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    require(0 < len(content) <= maximum and hashlib.sha256(content).hexdigest() == fingerprint.lower(),
            "Input differs from the independently approved fingerprint")
    return content


def unique_members(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "Duplicate JSON member")
    return result


def decode_json(content):
    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=unique_members)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Malformed JSON input") from error


def revocations(content):
    policy = decode_json(content)
    require(isinstance(policy, dict) and policy.keys() == REVOCATION_FIELDS.keys() | {"schemaVersion"}
            and type(policy["schemaVersion"]) is int and policy["schemaVersion"] == 1,
            "Unsupported revocation policy")
    for field, pattern in REVOCATION_FIELDS.items():
        values = policy[field]
        require(isinstance(values, list) and len(values) <= 512
                and all(isinstance(value, str) and re.fullmatch(pattern, value) for value in values),
                "Malformed revocation entry")
        require(len(values) == len(set(values)), "Duplicate revocation entry")
    return policy


def authenticate(root, der, openssl):
    # One independently supplied DER certificate is the trust anchor. Do not
    # accept embedded signer certificates or consult the host CA bundle.
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


def update_order(numbers, prerelease):
    identifiers = tuple((0, int(value)) if value.isdigit() else (1, value) for value in prerelease)
    return numbers, not prerelease, identifiers


def managed_update(files, target, current_version, candidate_version):
    current_numbers, current_prerelease = parse_release_version(current_version)
    candidate_numbers, candidate_prerelease = parse_release_version(candidate_version)
    installer = next((item for item in files if item["target"] == target and item["role"] == "installer"), None)
    require(installer is not None, "Expected a supported managed update target")
    if not current_prerelease and candidate_prerelease:
        decision = "channel-mismatch"
    else:
        current = update_order(current_numbers, current_prerelease)
        candidate = update_order(candidate_numbers, candidate_prerelease)
        decision = "upgrade" if candidate > current else "current" if candidate == current else "older"
    return {
        "target": target, "currentVersion": current_version, "candidateVersion": candidate_version,
        "decision": decision, "updateAvailable": decision == "upgrade",
        "installer": installer["file"], "installerSHA256": installer["sha256"],
    }


def verify(directory, certificate, certificate_sha256, commit, ref, openssl="openssl",
           *, revocation_list, revocation_list_sha256, current_version=None, target=None):
    require((current_version is None) == (target is None),
            "Managed update evaluation requires an installed version and target")
    subjects = release_subjects(commit, ref)
    der = independently_pinned_file(directory, certificate, certificate_sha256)
    certificate_sha256 = certificate_sha256.lower()
    policy = revocations(independently_pinned_file(directory, revocation_list, revocation_list_sha256))
    require(commit not in policy["sourceCommits"] and ref not in policy["sourceRefs"]
            and certificate_sha256 not in policy["approvalCertificateSHA256"],
            "Release source or approval signer is revoked")
    with tempfile.TemporaryDirectory(prefix="accessweaver-signed-release-") as temporary:
        root = Path(temporary)
        names = snapshot(directory, root, len(subjects) + 2)
        require(names == subjects.keys() | {MANIFEST, SIGNATURE}, "Unexpected signed release inventory")
        regular_file(root / MANIFEST, 65536)
        regular_file(root / SIGNATURE, 1 << 20)
        authenticate(root, der, openssl)
        files = inventory(root, subjects)
        manifest_bytes = (root / MANIFEST).read_bytes()
        manifest = decode_json(manifest_bytes)
        require(isinstance(manifest, dict), "Malformed signed release manifest")
        entries = manifest.get("windowsDetection", [])
        version = ref.removeprefix("refs/tags/v")
        if "windowsDetection" in manifest:
            validate_detection(entries, files, version)
            entries = sorted(entries, key=detection_key)
        expected = encode_manifest(commit, ref, files, entries)
        require(manifest_bytes == expected, "Signed release manifest or subject bytes differ")
        revoked_subjects = set(policy["subjectSHA256"])
        require(all(subject["sha256"] not in revoked_subjects for subject in files)
                and all(not revoked_subjects.intersection(
                    entry[field] for field in ("uninstallerSHA256", "rebootEvidenceSHA256",
                                               "previousPayloadSHA256", "publisherCertificateSHA256")
                ) for entry in entries),
                "Release subject or Windows detection evidence is revoked")
        sboms_verified, macos_detectors = validate_release_sboms(root, files, commit, version)
        require(all(entry["detectorSHA256"] not in revoked_subjects for entry in macos_detectors),
                "macOS detector is revoked")
        report = {
            "schemaVersion": 1, "scope": "accessweaver-signed-desktop-release",
            "sbomArtifactBindingsVerified": sboms_verified, "macosDetection": macos_detectors,
            "sourceCommit": commit, "sourceRef": ref, "subjectsVerified": len(subjects),
            "organizationApprovalSignatureVerified": True, "approvalCertificateSHA256": certificate_sha256,
            "revocationListSHA256": revocation_list_sha256.lower(), "revocationCheckPassed": True,
            "nativePublisherChecksPerformed": False, "productionQualificationComplete": False,
        }
        if target is not None:
            report["managedUpdate"] = managed_update(files, target, current_version, version)
        if entries:
            targets = windows_subjects(files)
            payload_sboms = windows_payload_sboms(files)
            report["schemaVersion"] = 2
            report["windowsDetection"] = [
                {**entry, "version": version, "setupSHA256": targets[entry["target"], "installer"],
                 "payloadSHA256": targets[entry["target"], "payload"],
                 "payloadSBOMSHA256": payload_sboms[entry["target"]]}
                for entry in entries
            ]
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prepare_args = commands.add_parser("prepare")
    prepare_args.add_argument("--output", type=Path, required=True)
    prepare_args.add_argument("--windows-reboot-evidence", nargs=2, metavar=("PATH", "SHA256"),
                              action="append", default=[], help="independently pinned Windows reboot result")
    verify_args = commands.add_parser("verify")
    verify_args.add_argument("--approval-certificate", type=Path, required=True)
    verify_args.add_argument("--approval-certificate-sha256", required=True)
    verify_args.add_argument("--revocation-list", type=Path, required=True)
    verify_args.add_argument("--revocation-list-sha256", required=True)
    verify_args.add_argument("--openssl", default="openssl", help="trusted OpenSSL executable")
    verify_args.add_argument("--current-version", help="installed version from trusted endpoint inventory")
    verify_args.add_argument("--target", choices=("windows/amd64", "windows/arm64", "darwin/amd64", "darwin/arm64"),
                             help="native managed endpoint target")
    for command in (prepare_args, verify_args):
        command.add_argument("directory", type=Path)
        command.add_argument("--source-commit", required=True)
        command.add_argument("--source-ref", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            prepare(args.directory, args.output, args.source_commit, args.source_ref,
                    windows_reboot_evidence=[(Path(path), pin) for path, pin in args.windows_reboot_evidence])
        else:
            print(json.dumps(verify(args.directory, args.approval_certificate, args.approval_certificate_sha256,
                                    args.source_commit, args.source_ref, args.openssl,
                                    revocation_list=args.revocation_list,
                                    revocation_list_sha256=args.revocation_list_sha256,
                                    current_version=args.current_version, target=args.target)))
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Signed release inventory, approval or revocation verification failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
