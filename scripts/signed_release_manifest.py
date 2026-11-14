#!/usr/bin/env python3
"""Prepare or authenticate the final publisher-signed Windows and macOS release subjects."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile

from macos_installer import parse_release_version, version_parts
from sbom import WINDOWS_BUILD_INFO_PROPERTY, prop_map, validate_digest
from verify_macos_installer_publisher import check_package_publisher, verify_packaged_deployment
from verify_release import publish_staged_file as publish_staged_installer, release_file, require
from verify_release_provenance import REPOSITORY, regular_file, validate_identity
from verify_release_rebuild import MAX_FILE, digest, snapshot

MANIFEST = "SIGNED-RELEASE.json"
SIGNATURE = "SIGNED-RELEASE.p7s"
MAX_REBOOT_EVIDENCE = 16
MAX_SBOM_BYTES = 4 << 20
SHA256 = r"[a-f0-9]{64}"
WINDOWS_DETECTION_FIELDS = (
    "target", "installMode", "previousVersion", "previousPayloadSHA256",
    "uninstallerSHA256", "publisherCertificateSHA256", "rebootEvidenceSHA256",
)
WINDOWS_PAYLOAD_PUBLISHER = "payloadPublisherCertificateSHA256"
WINDOWS_BUILD_INFO = "buildInfoSHA256"
WINDOWS_PREVIOUS_BUILD_INFO = "previousBuildInfoSHA256"
WINDOWS_PREVIOUS_TRUST_FIELDS = ("previousPayloadSBOMSHA256", "previousPayloadPublisherSHA256")
WINDOWS_DOWNGRADE_FIELDS = ("previousSetupSHA256", "previousPublisherSHA256")
REBOOT_CHECKS = (
    "passed", "guestRebootVerified", "installedPayloadVerifiedBeforeRestart",
    "installedPayloadVerified", "uninstallerIdentityVerified", "installedTreeVerified",
    "registrationPreserved", "registrationRemoved", "packageFilesRemoved",
    "userProfileVerifiedAfterReboot", "userProfilePreservedAfterUninstall",
)
REBOOT_REPORT_DIGESTS = (
    "detectorSHA256", "fixtureSHA256", "commonSHA256", "publisherVerifierSHA256",
    "installedTreeSHA256", "registrationSHA256",
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


def validate_release_sboms(root, files, commit, version, entries):
    documents = {}
    macos_detectors = []
    windows_build_info = {}
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
            properties = prop_map(installer["metadata"]["component"])
            if WINDOWS_BUILD_INFO_PROPERTY in properties:
                pin = properties[WINDOWS_BUILD_INFO_PROPERTY]
                require(isinstance(pin, str) and re.fullmatch(SHA256, pin),
                        "Malformed Windows installer SBOM build metadata digest")
                windows_build_info[target] = pin
        for entry in entries:
            if WINDOWS_BUILD_INFO in entry and entry["target"] in windows_build_info:
                require(entry[WINDOWS_BUILD_INFO] == windows_build_info[entry["target"]],
                        "Windows reboot build metadata differs from the signed installer SBOM")
    except (AttributeError, KeyError, TypeError, RecursionError) as error:
        raise ValueError("Malformed signed release SBOM") from error
    return len(documents), macos_detectors, windows_build_info


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
    build_info_by_target = {}
    for entry in entries:
        require(isinstance(entry, dict) and all(isinstance(value, str) for value in entry.values()),
                "Malformed Windows detection entry")
        trust_fields = set(WINDOWS_PREVIOUS_TRUST_FIELDS).intersection(entry)
        publisher_fields = {WINDOWS_PAYLOAD_PUBLISHER}.intersection(entry)
        downgrade_fields = set(WINDOWS_DOWNGRADE_FIELDS).intersection(entry)
        build_info_fields = {WINDOWS_BUILD_INFO, WINDOWS_PREVIOUS_BUILD_INFO}.intersection(entry)
        if WINDOWS_PREVIOUS_BUILD_INFO in build_info_fields:
            require(WINDOWS_BUILD_INFO in build_info_fields and entry.get("installMode") == "upgrade"
                    and trust_fields == set(WINDOWS_PREVIOUS_TRUST_FIELDS),
                    "Malformed previous Windows build metadata evidence")
        require(entry.keys() == set(WINDOWS_DETECTION_FIELDS) | trust_fields | publisher_fields
                | downgrade_fields | build_info_fields
                and (not trust_fields or trust_fields == set(WINDOWS_PREVIOUS_TRUST_FIELDS)
                     and entry["installMode"] == "upgrade"), "Malformed Windows detection entry")
        if downgrade_fields:
            require(downgrade_fields == set(WINDOWS_DOWNGRADE_FIELDS) and entry["installMode"] == "upgrade"
                    and all(re.fullmatch(SHA256, entry[field]) for field in downgrade_fields),
                    "Malformed Windows downgrade evidence digests")
        for field in trust_fields | publisher_fields | build_info_fields:
            require(re.fullmatch(SHA256, entry[field]), "Malformed Windows payload trust digest")
        target = entry["target"]
        require((target, "installer") in targets and entry["installMode"] in ("clean", "upgrade"),
                "Unsupported Windows detection path")
        if WINDOWS_BUILD_INFO in entry:
            pin = entry[WINDOWS_BUILD_INFO]
            require(build_info_by_target.setdefault(target, pin) == pin,
                    "Windows reboot reports disagree on candidate build metadata")
        for field in ("uninstallerSHA256", "publisherCertificateSHA256", "rebootEvidenceSHA256"):
            require(re.fullmatch(SHA256, entry[field]), "Malformed Windows detection digest")
        previous_version = entry["previousVersion"]
        previous_payload = entry["previousPayloadSHA256"]
        if downgrade_fields:
            require(entry["previousSetupSHA256"] != targets[target, "installer"],
                    "Windows downgrade evidence names the candidate installer")
        if entry["installMode"] == "upgrade":
            version_parts(previous_version)
            require(update_order(*parse_release_version(previous_version)) < update_order(*parse_release_version(version))
                    and re.fullmatch(SHA256, previous_payload)
                    and previous_payload != targets[target, "payload"], "Invalid previous Windows package")
        else:
            require(previous_version == previous_payload == "", "Unexpected previous Windows package")

    keys = [detection_key(entry) for entry in entries]
    require(len(keys) == len(set(keys)), "Duplicate Windows detection path")


def validate_schema_11_reboot_report(report, mode):
    fields = {
        "schemaVersion", "runID", "stage", "architecture", "version", "installMode", "previousVersion",
        "previousPayloadSHA256", "previousPayloadTrustVerified", "downgradeRequested", "downgradeRefused",
        "downgradeStatePreserved", "userProfilePreservedThroughUpgrade", "setupSHA256", "payloadSHA256",
        "publisherSHA256", "payloadPublisherSHA256", "payloadSBOMSHA256", "installedPayloadSBOMVerified",
        "installedPayloadPublisherVerified", "installedBuildInfoVerified", "uninstallerSHA256",
        "userProfileOpenedByInstalledController", "setupExitCode", "setupRequestedRestart",
        WINDOWS_BUILD_INFO, WINDOWS_PREVIOUS_BUILD_INFO, *WINDOWS_PREVIOUS_TRUST_FIELDS, *WINDOWS_DOWNGRADE_FIELDS,
        *REBOOT_CHECKS, *REBOOT_REPORT_DIGESTS,
    }
    require(report.keys() == fields, "Windows reboot evidence differs from the current report schema")
    run_id = report["runID"]
    require(isinstance(run_id, str) and re.fullmatch(r"[a-f0-9]{32}", run_id)
            and all(isinstance(report[field], str) and re.fullmatch(SHA256, report[field])
                    for field in REBOOT_REPORT_DIGESTS),
            "Windows reboot evidence has invalid run or fixture identity")
    exit_code = report["setupExitCode"]
    require(type(exit_code) is int and exit_code in (0, 3010)
            and report["setupRequestedRestart"] is (exit_code == 3010),
            "Windows reboot evidence has inconsistent Setup restart status")
    require(report["userProfilePreservedThroughUpgrade"] is (mode == "upgrade"),
            "Windows reboot evidence has inconsistent profile preservation")


def load_detection_evidence(directory, evidence, subjects, version):
    require(len(evidence) <= MAX_REBOOT_EVIDENCE, "Too many Windows reboot reports")
    targets = windows_subjects(subjects)
    payload_sboms = windows_payload_sboms(subjects)
    entries = []
    for path, fingerprint in evidence:
        content = independently_pinned_file(directory, path, fingerprint, maximum=8192)
        report = decode_json(content)
        require(isinstance(report, dict) and type(report.get("schemaVersion")) is int
                and report["schemaVersion"] in (5, 6, 7, 8, 9, 10, 11) and report.get("stage") == "complete"
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
        if report["schemaVersion"] >= 6:
            require(report.get("payloadSBOMSHA256") == payload_sboms[target]
                    and report.get("installedPayloadSBOMVerified") is True
                    and report.get("installedPayloadPublisherVerified") is True,
                    "Windows reboot evidence does not verify the signed payload publisher and release SBOM")
        if report["schemaVersion"] >= 7:
            require(report.get("userProfileOpenedByInstalledController") is True,
                    "Windows reboot evidence does not verify installed controller profile readback")
        if report["schemaVersion"] >= 8:
            prior_trust = report.get("previousPayloadTrustVerified")
            prior_pins = (report.get("previousPayloadSBOMSHA256"), report.get("previousPayloadPublisherSHA256"))
            if mode == "upgrade":
                require(prior_trust is True and all(isinstance(pin, str) and re.fullmatch(SHA256, pin) for pin in prior_pins),
                        "Windows upgrade evidence does not verify the previous installed payload publisher and SBOM")
            else:
                require(prior_trust is False and prior_pins == ("", ""), "Clean Windows evidence contains prior payload trust data")
        require(mode != "upgrade" or report.get("userProfilePreservedThroughUpgrade") is True,
                "Windows upgrade qualification is incomplete")
        downgrade = report.get("downgradeRequested")
        require(type(downgrade) is bool
                and report.get("downgradeRefused") is downgrade
                and report.get("downgradeStatePreserved") is downgrade
                and (not downgrade or mode == "upgrade"), "Windows downgrade evidence is inconsistent")
        entry = {
            "target": target, "installMode": mode,
            "previousVersion": report.get("previousVersion"),
            "previousPayloadSHA256": report.get("previousPayloadSHA256"),
            "uninstallerSHA256": report.get("uninstallerSHA256"),
            "publisherCertificateSHA256": report.get("publisherSHA256"),
            "rebootEvidenceSHA256": fingerprint.lower(),
        }
        if mode == "upgrade" and report["schemaVersion"] >= 8:
            entry.update({field: report[field] for field in WINDOWS_PREVIOUS_TRUST_FIELDS})
        if report["schemaVersion"] >= 9:
            entry[WINDOWS_PAYLOAD_PUBLISHER] = report.get("payloadPublisherSHA256")
        if report["schemaVersion"] >= 10:
            require(report.get("installedBuildInfoVerified") is True,
                    "Windows reboot evidence does not verify installed build metadata")
            entry[WINDOWS_BUILD_INFO] = report.get(WINDOWS_BUILD_INFO)
        if report["schemaVersion"] == 11:
            validate_schema_11_reboot_report(report, mode)
            prior_build_info = report.get(WINDOWS_PREVIOUS_BUILD_INFO)
            if mode == "upgrade":
                entry[WINDOWS_PREVIOUS_BUILD_INFO] = prior_build_info
            else:
                require(prior_build_info == "", "Clean Windows evidence contains prior build metadata")
        if downgrade:
            entry.update({field: report.get(field) for field in WINDOWS_DOWNGRADE_FIELDS})
        else:
            require(all(report.get(field, "") == "" for field in WINDOWS_DOWNGRADE_FIELDS),
                    "Windows reboot evidence has unused downgrade inputs")
        entries.append(entry)
    validate_detection(entries, subjects, version)
    return entries


def encode_manifest(commit, ref, subjects, windows_detection=()):
    has_payload_publisher = any(WINDOWS_PAYLOAD_PUBLISHER in entry for entry in windows_detection)
    has_previous_trust = any(WINDOWS_PREVIOUS_TRUST_FIELDS[0] in entry for entry in windows_detection)
    has_downgrade = any(WINDOWS_DOWNGRADE_FIELDS[0] in entry for entry in windows_detection)
    schema = 3 if has_previous_trust else 2 if windows_detection else 1
    if has_payload_publisher:
        schema = 4
    if has_downgrade:
        schema = 5
    if any(WINDOWS_BUILD_INFO in entry for entry in windows_detection):
        schema = 6
    if any(WINDOWS_PREVIOUS_BUILD_INFO in entry for entry in windows_detection):
        schema = 7
    manifest = {
        "schemaVersion": schema,
        "scope": "accessweaver-signed-desktop-release",
        "repository": REPOSITORY,
        "sourceCommit": commit,
        "sourceRef": ref,
        "subjects": subjects,
    }
    if windows_detection:
        manifest["windowsDetection"] = [
            {field: entry[field] for field in WINDOWS_DETECTION_FIELDS + WINDOWS_PREVIOUS_TRUST_FIELDS
             + (WINDOWS_PAYLOAD_PUBLISHER,) + WINDOWS_DOWNGRADE_FIELDS
             + (WINDOWS_BUILD_INFO, WINDOWS_PREVIOUS_BUILD_INFO) if field in entry}
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
        entries = []
        if windows_reboot_evidence:
            entries = load_detection_evidence(directory, windows_reboot_evidence, files, version)
        validate_release_sboms(root, files, commit, version, entries)
        manifest = encode_manifest(commit, ref, files, entries)
        with output.open("xb") as stream:
            stream.write(manifest)


def independently_pinned_file(directory, path, fingerprint, *, maximum=65536):
    require(re.fullmatch(r"[a-fA-F0-9]{64}", fingerprint)
            and not path.resolve().is_relative_to(directory.resolve()),
            "Expected an independently pinned file outside the release directory")
    before = release_file(path, maximum)
    expected = file_identity(before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        require(file_identity(os.fstat(stream.fileno())) == expected,
                "Independently pinned input changed before verification")
        content = stream.read(before.st_size + 1)
        require(len(content) == before.st_size
                and file_identity(os.fstat(stream.fileno())) == expected
                and file_identity(release_file(path, maximum)) == expected,
                "Independently pinned input changed during verification")
    require(hashlib.sha256(content).hexdigest() == fingerprint.lower(),
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


def load_windows_upgrade_inventory(directory, path, fingerprint):
    content = independently_pinned_file(directory, path, fingerprint, maximum=4096)
    record = decode_json(content)
    fields = {"schemaVersion", "target", "version", "payloadSHA256", "payloadSBOMSHA256",
              "payloadPublisherSHA256"}
    require(isinstance(record, dict) and type(record.get("schemaVersion")) is int
            and record["schemaVersion"] in (1, 2), "Malformed Windows upgrade inventory")
    digests = ("payloadSHA256", "payloadSBOMSHA256", "payloadPublisherSHA256")
    if record["schemaVersion"] == 2:
        fields.add(WINDOWS_BUILD_INFO)
        digests += (WINDOWS_BUILD_INFO,)
    require(record.keys() == fields and record["target"] in ("windows/amd64", "windows/arm64")
            and isinstance(record["version"], str), "Malformed Windows upgrade inventory")
    for field in digests:
        require(isinstance(record[field], str) and re.fullmatch(SHA256, record[field]),
                "Malformed Windows upgrade inventory digest")
    return record


def revocation_time(value):
    require(isinstance(value, str) and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ), "Expected a revocation policy timestamp in UTC")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def require_current_revocation_policy(policy, *, now=None):
    if policy["schemaVersion"] == 2:
        effective = datetime.now(timezone.utc) if now is None else now
        issued = revocation_time(policy["issuedAt"])
        expires = revocation_time(policy["expiresAt"])
        require(issued <= effective < expires, "Revocation policy is outside its validity window")


def revocations(content, *, minimum_sequence=None, now=None):
    policy = decode_json(content)
    require(isinstance(policy, dict) and type(policy.get("schemaVersion")) is int
            and policy["schemaVersion"] in (1, 2), "Unsupported revocation policy")
    fields = REVOCATION_FIELDS.keys() | {"schemaVersion"}
    if minimum_sequence is not None:
        require(type(minimum_sequence) is int and minimum_sequence > 0,
                "Expected a positive minimum revocation sequence")
    if policy["schemaVersion"] == 2:
        fields |= {"sequence", "issuedAt", "expiresAt"}
    require(policy.keys() == fields, "Unsupported revocation policy")
    if policy["schemaVersion"] == 2:
        sequence = policy["sequence"]
        require(type(sequence) is int and sequence > 0, "Invalid revocation policy sequence")
        require(minimum_sequence is None or sequence >= minimum_sequence,
                "Revocation policy sequence is below the approved minimum")
    else:
        require(minimum_sequence is None, "A sequenced revocation policy is required")
    for field, pattern in REVOCATION_FIELDS.items():
        values = policy[field]
        require(isinstance(values, list) and len(values) <= 512
                and all(isinstance(value, str) and re.fullmatch(pattern, value) for value in values),
                "Malformed revocation entry")
        require(len(values) == len(set(values)), "Duplicate revocation entry")
    require_current_revocation_policy(policy, now=now)
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


def select_windows_upgrade(detection, update, installed_digest, installed_trust):
    require(update["updateAvailable"], "Candidate is not an eligible managed upgrade")
    matches = [
        entry for entry in detection
        if entry["target"] == update["target"] and entry["installMode"] == "upgrade"
        and entry["previousVersion"] == update["currentVersion"]
        and entry["previousPayloadSHA256"] == installed_digest.lower()
    ]
    require(len(matches) == 1, "No approved reboot evidence matches the installed Windows payload")
    entry = matches[0]
    if installed_trust or WINDOWS_PREVIOUS_BUILD_INFO in entry:
        require(all(field in installed_trust and entry.get(field) == installed_trust[field]
                    for field in WINDOWS_PREVIOUS_TRUST_FIELDS),
                "No approved reboot evidence matches the installed Windows SBOM and publisher")
    if WINDOWS_PREVIOUS_BUILD_INFO in entry or WINDOWS_PREVIOUS_BUILD_INFO in installed_trust:
        require(WINDOWS_PREVIOUS_BUILD_INFO in entry
                and entry[WINDOWS_PREVIOUS_BUILD_INFO] == installed_trust.get(WINDOWS_PREVIOUS_BUILD_INFO),
                "No approved reboot evidence matches the installed Windows build metadata")
    return entry


def check_windows_publisher(artifact, approved_digest, publisher_pin):
    system_directory = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(system_directory, len(system_directory))
    require(0 < length < len(system_directory), "Windows system directory could not be resolved")
    shell = Path(system_directory.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    script = Path(__file__).resolve().with_name("verify-windows-installer-publisher.ps1")
    with tempfile.TemporaryFile() as output:
        subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-File", script, "-Artifact", artifact,
             "-ArtifactSHA256", approved_digest, "-PublisherCertificateSHA256", publisher_pin],
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, check=True, timeout=90,
        )
        output.seek(0)
        content = output.read(4097)
    require(0 < len(content) <= 4096, "Windows publisher report exceeds inspection bounds")
    record = decode_json(content)
    expected = {
        "schemaVersion": 1, "scope": "windows-publisher-signature", "artifactSHA256": approved_digest,
        "publisherCertificateSHA256": publisher_pin, "embeddedSignatureVerified": True,
        "timestampPresent": True,
    }
    require(record == expected and type(record["schemaVersion"]) is int
            and record["embeddedSignatureVerified"] is True and record["timestampPresent"] is True,
            "Windows publisher report differs from the approved artifact or signer")


def file_identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns, info.st_nlink


def verify_staged_update(path, size, approved_digest):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size
            and not getattr(before, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "Expected a bounded ordinary staged installer")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and file_identity(opened) == file_identity(before),
                "Staged installer changed before verification")
        result = hashlib.sha256()
        remaining = size
        while remaining:
            block = stream.read(min(remaining, 1 << 20))
            require(block, "Staged installer changed during verification")
            result.update(block)
            remaining -= len(block)
        require(not stream.read(1) and file_identity(os.fstat(stream.fileno())) == file_identity(before)
                and file_identity(path.lstat()) == file_identity(before),
                "Staged installer changed during verification")
        require(result.hexdigest() == approved_digest, "Staged installer differs from the approved digest")


def staging_directory_identity(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "Expected a real managed update staging directory")
    return info.st_dev, info.st_ino


def copy_approved_installer(source_path, staged, size):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    before = source_path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size
            and not getattr(before, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "Signed installer snapshot differs from the approved size or file type")
    with os.fdopen(os.open(source_path, flags), "rb") as source:
        opened = os.fstat(source.fileno())
        require(stat.S_ISREG(opened.st_mode) and os.path.samestat(before, opened)
                and opened.st_size == size and opened.st_nlink == 1,
                "Signed installer snapshot changed before staging")
        with staged.open("xb") as output:
            remaining = size
            while remaining:
                block = source.read(min(1 << 20, remaining))
                require(block, "Signed installer snapshot was truncated during staging")
                output.write(block)
                remaining -= len(block)
            require(not source.read(1), "Signed installer snapshot grew during staging")
            output.flush()
            os.fsync(output.fileno())


def stage_managed_update(root, directory, update, policy, *, size, directory_identity):
    require(type(size) is int and 0 < size <= MAX_FILE, "Expected a bounded signed installer size")

    def check_directory():
        require(staging_directory_identity(directory) == directory_identity,
                "Managed update staging directory changed during verification")

    name = update["installer"]
    source_path = root / name
    destination = directory / name
    approved_digest = update["installerSHA256"]
    check_directory()
    try:
        verify_staged_update(destination, size, approved_digest)
    except FileNotFoundError:
        pass
    else:
        check_directory()
        require_current_revocation_policy(policy)
        return

    check_directory()
    with tempfile.TemporaryDirectory(prefix=".accessweaver-update-", dir=directory) as temporary:
        staged = Path(temporary) / name
        copy_approved_installer(source_path, staged, size)
        verify_staged_update(staged, size, approved_digest)
        check_directory()
        # Copy and digest verification can each consume the remaining validity.
        require_current_revocation_policy(policy)
        try:
            publish_staged_installer(staged, destination)
        except FileExistsError:
            # Another publisher won the name. Verify its file after cleanup.
            pass
    check_directory()
    verify_staged_update(destination, size, approved_digest)
    check_directory()
    require_current_revocation_policy(policy)


def verify(directory, certificate, certificate_sha256, commit, ref, openssl="openssl",
           *, revocation_list, revocation_list_sha256, current_version=None, target=None, stage_directory=None,
           current_payload_sha256=None, current_payload_sbom_sha256=None, current_payload_publisher_sha256=None,
           current_build_info_sha256=None, minimum_revocation_sequence=None, windows_upgrade_inventory=None, macos_publisher=None,
           windows_publisher=None, windows_payload_publisher=None):
    if windows_upgrade_inventory is not None:
        require(all(value is None for value in (
            current_version, target, current_payload_sha256, current_payload_sbom_sha256,
            current_payload_publisher_sha256, current_build_info_sha256,
        )), "Windows upgrade inventory cannot be combined with explicit installed identity inputs")
        path, fingerprint = windows_upgrade_inventory
        record = load_windows_upgrade_inventory(directory, path, fingerprint)
        current_version, target = record["version"], record["target"]
        current_payload_sha256 = record["payloadSHA256"]
        current_payload_sbom_sha256 = record["payloadSBOMSHA256"]
        current_payload_publisher_sha256 = record["payloadPublisherSHA256"]
        current_build_info_sha256 = record.get(WINDOWS_BUILD_INFO)
    require((current_version is None) == (target is None),
            "Managed update evaluation requires an installed version and target")
    if current_payload_sha256 is not None:
        require(target in ("windows/amd64", "windows/arm64")
                and isinstance(current_payload_sha256, str)
                and re.fullmatch(r"[a-fA-F0-9]{64}", current_payload_sha256),
                "Qualified upgrade selection requires a Windows target and an installed payload SHA-256")
    installed_trust = {}
    if current_payload_sbom_sha256 is not None or current_payload_publisher_sha256 is not None:
        pins = (current_payload_sbom_sha256, current_payload_publisher_sha256)
        require(current_payload_sha256 is not None and all(
            isinstance(pin, str) and re.fullmatch(r"[a-fA-F0-9]{64}", pin) for pin in pins
        ), "Installed Windows trust matching requires the payload, SBOM and publisher SHA-256 digests")
        installed_trust = dict(zip(WINDOWS_PREVIOUS_TRUST_FIELDS, (pin.lower() for pin in pins)))
    if current_build_info_sha256 is not None:
        require(installed_trust and isinstance(current_build_info_sha256, str)
                and re.fullmatch(r"[a-fA-F0-9]{64}", current_build_info_sha256),
                "Installed Windows build metadata matching requires all installed trust pins")
        installed_trust[WINDOWS_PREVIOUS_BUILD_INFO] = current_build_info_sha256.lower()
    if windows_publisher is not None or windows_payload_publisher is not None:
        require(sys.platform == "win32" and target in ("windows/amd64", "windows/arm64")
                and current_version is not None, "Native publisher verification requires Windows and a Windows managed update target")
        require(isinstance(windows_publisher, str) and re.fullmatch(r"[a-fA-F0-9]{64}", windows_publisher),
                "Expected the approved Windows setup publisher certificate digest")
        if windows_payload_publisher is not None:
            require(re.fullmatch(r"[a-fA-F0-9]{64}", windows_payload_publisher),
                    "Expected the approved Windows payload publisher certificate digest")
        windows_publisher = windows_publisher.lower()
        payload_publisher = (windows_payload_publisher or windows_publisher).lower()
    if macos_publisher is not None:
        require(sys.platform == "darwin" and target in ("darwin/amd64", "darwin/arm64") and current_version is not None,
                "Native publisher verification requires macOS and a macOS managed update target")
        team, installer_pin, application_pin = macos_publisher
        require(re.fullmatch(r"[A-Z0-9]{10}", team) and all(
            re.fullmatch(r"[a-fA-F0-9]{64}", pin) for pin in (installer_pin, application_pin)
        ), "Expected the approved macOS team and both publisher certificate digests")
        installer_pin, application_pin = installer_pin.lower(), application_pin.lower()
    if stage_directory is not None:
        require(target is not None, "Managed update staging requires an installed version and target")
        stage_directory_id = staging_directory_identity(stage_directory)
        stage_directory = stage_directory.resolve(strict=True)
        require(staging_directory_identity(stage_directory) == stage_directory_id,
                "Managed update staging directory changed during resolution")
        require(not stage_directory.is_relative_to(directory.resolve()),
                "Stage the installer outside the release input directory")
    subjects = release_subjects(commit, ref)
    der = independently_pinned_file(directory, certificate, certificate_sha256)
    certificate_sha256 = certificate_sha256.lower()
    policy = revocations(independently_pinned_file(directory, revocation_list, revocation_list_sha256),
                         minimum_sequence=minimum_revocation_sequence)
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
                    + WINDOWS_PREVIOUS_TRUST_FIELDS + (WINDOWS_PAYLOAD_PUBLISHER,)
                    + WINDOWS_DOWNGRADE_FIELDS + (WINDOWS_BUILD_INFO, WINDOWS_PREVIOUS_BUILD_INFO) if field in entry
                ) for entry in entries),
                "Release subject or Windows detection evidence is revoked")
        sboms_verified, macos_detectors, windows_build_info = validate_release_sboms(root, files, commit, version, entries)
        require(not revoked_subjects.intersection(windows_build_info.values()),
                "Windows installer SBOM build metadata is revoked")
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
        if windows_build_info or entries:
            targets = windows_subjects(files)
            payload_sboms = windows_payload_sboms(files)
            identities = {
                target: {
                    "target": target, "version": version, "setupSHA256": targets[target, "installer"],
                    "payloadSHA256": targets[target, "payload"], "payloadSBOMSHA256": payload_sboms[target],
                }
                for target in payload_sboms
            }
            if windows_build_info:
                report["windowsBuildMetadata"] = [
                    {**identities[target], WINDOWS_BUILD_INFO: pin}
                    for target, pin in sorted(windows_build_info.items())
                ]
            if entries:
                report["schemaVersion"] = manifest["schemaVersion"]
                report["windowsDetection"] = [{**entry, **identities[entry["target"]]} for entry in entries]
        if current_payload_sha256 is not None:
            update = report["managedUpdate"]
            update["windowsUpgradeDetection"] = select_windows_upgrade(
                report.get("windowsDetection", ()), update, current_payload_sha256, installed_trust
            )
        if windows_publisher is not None:
            update = report["managedUpdate"]
            require(update["updateAvailable"], "Candidate is not an eligible managed upgrade")
            require(not revoked_subjects.intersection((windows_publisher, payload_publisher)),
                    "Windows publisher certificate is revoked")
            qualification = update.get("windowsUpgradeDetection")
            require(qualification is None or (
                qualification["publisherCertificateSHA256"] == windows_publisher
                and qualification.get(WINDOWS_PAYLOAD_PUBLISHER, windows_publisher) == payload_publisher
            ), "Windows publisher certificate differs from the upgrade qualification")
            payload = next(item for item in files if item["target"] == target and item["role"] == "payload")
            for name, approved_digest, publisher_pin in (
                (update["installer"], update["installerSHA256"], windows_publisher),
                (payload["file"], payload["sha256"], payload_publisher),
            ):
                artifact = root / name
                check_windows_publisher(artifact, approved_digest, publisher_pin)
                require(digest(artifact) == approved_digest, "Windows artifact changed during publisher verification")
            update["nativePublisherVerification"] = {
                "publisherCertificateSHA256": windows_publisher, "installerEmbeddedSignatureVerified": True,
                "payloadEmbeddedSignatureVerified": True, "timestampsVerified": True,
            }
            if windows_payload_publisher is not None:
                update["nativePublisherVerification"][WINDOWS_PAYLOAD_PUBLISHER] = payload_publisher
            report["nativePublisherChecksPerformed"] = True
        if macos_publisher is not None:
            update = report["managedUpdate"]
            require(update["updateAvailable"], "Candidate is not an eligible managed upgrade")
            require(not revoked_subjects.intersection((installer_pin, application_pin)),
                    "macOS publisher certificate is revoked")
            package = root / update["installer"]
            architecture = target.split("/")[1]
            check_package_publisher(package, team, installer_pin)
            verify_packaged_deployment(package, team, architecture, application_pin)
            require(digest(package) == update["installerSHA256"], "macOS package changed during publisher verification")
            update["nativePublisherVerification"] = {
                "developerTeamID": team, "installerCertificateSHA256": installer_pin,
                "applicationCertificateSHA256": application_pin, "gatekeeperAccepted": True,
                "packagedInstallationHelperVerified": True, "stapledTicketValidated": True,
            }
            report["nativePublisherChecksPerformed"] = True
        if policy["schemaVersion"] == 2:
            # Candidate authentication and native publisher verification can take time.
            require_current_revocation_policy(policy)
            report["revocationPolicySequence"] = policy["sequence"]
            report["revocationPolicyExpiresAt"] = policy["expiresAt"]
        if stage_directory is not None:
            update = report["managedUpdate"]
            require(update["updateAvailable"], "Candidate is not an eligible managed upgrade")
            installer = next(item for item in files if item["file"] == update["installer"])
            stage_managed_update(root, stage_directory, update, policy,
                                 size=installer["size"], directory_identity=stage_directory_id)
            update["installerStaged"] = True
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
    verify_args.add_argument("--minimum-revocation-sequence", type=int,
                             help="require an active schema 2 policy at or above this independently approved sequence")
    verify_args.add_argument("--openssl", default="openssl", help="trusted OpenSSL executable")
    verify_args.add_argument("--current-version", help="installed version from trusted endpoint inventory")
    verify_args.add_argument("--target", choices=("windows/amd64", "windows/arm64", "darwin/amd64", "darwin/arm64"),
                             help="native managed endpoint target")
    verify_args.add_argument("--current-payload-sha256",
                             help="require signed Windows reboot evidence for this installed payload")
    verify_args.add_argument("--current-payload-sbom-sha256",
                             help="match the installed Windows payload SBOM to signed reboot evidence")
    verify_args.add_argument("--current-payload-publisher-sha256",
                             help="match the installed Windows payload signer certificate to signed reboot evidence")
    verify_args.add_argument("--current-build-info-sha256",
                             help="match the installed Windows build metadata digest to signed reboot evidence")
    verify_args.add_argument("--windows-upgrade-inventory", nargs=2, metavar=("PATH", "SHA256"),
                             help="match an independently pinned Windows detector inventory to signed reboot evidence")
    verify_args.add_argument("--windows-publisher-sha256",
                             help="require native Authenticode and timestamp checks on the Windows setup and payload")
    verify_args.add_argument("--windows-payload-publisher-sha256",
                             help="approved Windows payload leaf SHA-256 when it differs from the setup signer")
    verify_args.add_argument("--macos-publisher", nargs=3, metavar=("TEAM_ID", "INSTALLER_SHA256", "APPLICATION_SHA256"),
                             help="require native macOS package and app publisher checks before staging")
    verify_args.add_argument("--stage-directory", type=Path,
                             help="existing trusted directory for the authenticated eligible installer")
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
            inventory = args.windows_upgrade_inventory
            if inventory is not None:
                inventory = (Path(inventory[0]), inventory[1])
            print(json.dumps(verify(args.directory, args.approval_certificate, args.approval_certificate_sha256,
                                    args.source_commit, args.source_ref, args.openssl,
                                    revocation_list=args.revocation_list,
                                    revocation_list_sha256=args.revocation_list_sha256,
                                    current_version=args.current_version, target=args.target,
                                    stage_directory=args.stage_directory,
                                    current_payload_sha256=args.current_payload_sha256,
                                    current_payload_sbom_sha256=args.current_payload_sbom_sha256,
                                    current_payload_publisher_sha256=args.current_payload_publisher_sha256,
                                    current_build_info_sha256=args.current_build_info_sha256,
                                    minimum_revocation_sequence=args.minimum_revocation_sequence,
                                    windows_upgrade_inventory=inventory, macos_publisher=args.macos_publisher,
                                    windows_publisher=args.windows_publisher_sha256,
                                    windows_payload_publisher=args.windows_payload_publisher_sha256)))
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Signed release inventory, approval or revocation verification failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
