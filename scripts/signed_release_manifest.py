#!/usr/bin/env python3
"""Prepare or authenticate the final publisher-signed Windows and macOS release subjects."""
import argparse
from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
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

from macos_deployment import DETACHED_MANIFEST
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
WINDOWS_DETECTION_FAILURE_REASONS = (
    "approved-installation-not-detected",
    "detector-inspection-failed",
    "detector-result-invalid",
    "detector-timeout",
    "detector-unavailable",
    "revocation-policy-expired",
)
WINDOWS_PAYLOAD_PUBLISHER = "payloadPublisherCertificateSHA256"
WINDOWS_BUILD_INFO = "buildInfoSHA256"
WINDOWS_DETECTOR = "detectorSHA256"
WINDOWS_RESTORATION_JOURNAL = "restorationJournalSHA256"
WINDOWS_LIFECYCLE_SOURCES = {
    WINDOWS_DETECTOR: "scripts/detect-windows-installer.ps1",
    "fixtureSHA256": "scripts/test-windows-installer-reboot.ps1",
    "commonSHA256": "scripts/windows-installer-common.ps1",
    "publisherVerifierSHA256": "scripts/verify-windows-installer-publisher.ps1",
}
WINDOWS_LIFECYCLE_SOURCE_FIELDS = tuple(field for field in WINDOWS_LIFECYCLE_SOURCES if field != WINDOWS_DETECTOR)
WINDOWS_PREVIOUS_BUILD_INFO = "previousBuildInfoSHA256"
WINDOWS_SETUP_BASELINE = "setupUpgradeBaselineVerified"
WINDOWS_SETUP_BASELINE_PREFIX = "/AWUpgradeFrom="
WINDOWS_SETUP_WRONG_BASELINE = "setupWrongBaselineRefusedWithStatePreserved"
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


def macos_deployment_digests(document, identity):
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
    manifest = components.get("detached-file:" + DETACHED_MANIFEST, {})
    hashes = manifest.get("hashes")
    require(manifest.get("type") == "file" and manifest.get("name") == DETACHED_MANIFEST
            and isinstance(hashes, list) and len(hashes) == 1 and isinstance(hashes[0], dict),
            "Invalid macOS deployment manifest digest")
    manifest_pin = hashes[0].get("content")
    require(isinstance(manifest_pin, str) and re.fullmatch(SHA256, manifest_pin)
            and hashes == [{"alg": "SHA-256", "content": manifest_pin}], "Invalid macOS deployment manifest digest")
    payload = components["payload:application"]
    require(payload.get("type") == "application" and payload.get("version") == identity["version"]
            and all(prop_map(payload).get("accessweaver:" + key) == identity[field]
                    for key, field in (("source-commit", "commit"), ("source-state", "sourceState"),
                                       ("target-os", "platform"), ("target-arch", "arch"))),
            "macOS controller build identity differs")
    controller_path = "Contents/MacOS/accessweaver"
    controller = components["bundle-file:" + controller_path]
    payload_hashes = payload.get("hashes")
    require(isinstance(payload_hashes, list) and len(payload_hashes) == 1
            and isinstance(payload_hashes[0], dict), "Invalid macOS controller digest")
    payload_pin = payload_hashes[0].get("content")
    require(isinstance(payload_pin, str) and re.fullmatch(SHA256, payload_pin)
            and payload_hashes == [{"alg": "SHA-256", "content": payload_pin}]
            and controller.get("type") == "file" and controller.get("name") == controller_path
            and controller.get("hashes") == payload_hashes,
            "macOS controller differs from the sealed package executable")
    return pin, manifest_pin, payload_pin


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
                detector_pin, manifest_pin, payload_pin = macos_deployment_digests(document, identity)
                macos_detectors.append({
                    "target": subject["target"], "version": version, "packageSHA256": subject["sha256"],
                    "detectorSHA256": detector_pin, "manifestSHA256": manifest_pin, "payloadSHA256": payload_pin,
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
        require(isinstance(entry, dict) and all(
            value is True if key in (WINDOWS_SETUP_BASELINE, WINDOWS_SETUP_WRONG_BASELINE) else isinstance(value, str)
            for key, value in entry.items()
        ),
                "Malformed Windows detection entry")
        trust_fields = set(WINDOWS_PREVIOUS_TRUST_FIELDS).intersection(entry)
        publisher_fields = {WINDOWS_PAYLOAD_PUBLISHER}.intersection(entry)
        downgrade_fields = set(WINDOWS_DOWNGRADE_FIELDS).intersection(entry)
        build_info_fields = {WINDOWS_BUILD_INFO, WINDOWS_PREVIOUS_BUILD_INFO}.intersection(entry)
        detector_fields = {WINDOWS_DETECTOR}.intersection(entry)
        restoration_fields = {WINDOWS_RESTORATION_JOURNAL}.intersection(entry)
        require(not restoration_fields or detector_fields, "Windows restoration evidence requires a qualified detector")
        source_fields = set(WINDOWS_LIFECYCLE_SOURCE_FIELDS).intersection(entry)
        require(not source_fields or (source_fields == set(WINDOWS_LIFECYCLE_SOURCE_FIELDS) and detector_fields),
                "Malformed Windows lifecycle source bindings")
        require(not detector_fields or WINDOWS_BUILD_INFO in build_info_fields,
                "Windows detector evidence requires installed build metadata")
        if WINDOWS_PREVIOUS_BUILD_INFO in build_info_fields:
            require(WINDOWS_BUILD_INFO in build_info_fields and entry.get("installMode") == "upgrade"
                    and trust_fields == set(WINDOWS_PREVIOUS_TRUST_FIELDS),
                    "Malformed previous Windows build metadata evidence")
        baseline_fields = {WINDOWS_SETUP_BASELINE, WINDOWS_SETUP_WRONG_BASELINE}.intersection(entry)
        require(WINDOWS_SETUP_WRONG_BASELINE not in baseline_fields or WINDOWS_SETUP_BASELINE in baseline_fields,
                "Windows incorrect Setup baseline refusal requires approved baseline enforcement")
        require(not baseline_fields or WINDOWS_PREVIOUS_BUILD_INFO in build_info_fields,
                "Windows Setup baseline evidence requires the approved prior build pins")
        require(entry.keys() == set(WINDOWS_DETECTION_FIELDS) | trust_fields | publisher_fields
                | downgrade_fields | build_info_fields | baseline_fields | detector_fields | source_fields | restoration_fields
                and (not trust_fields or trust_fields == set(WINDOWS_PREVIOUS_TRUST_FIELDS)
                     and entry["installMode"] == "upgrade"), "Malformed Windows detection entry")
        if downgrade_fields:
            require(downgrade_fields == set(WINDOWS_DOWNGRADE_FIELDS) and entry["installMode"] == "upgrade"
                    and all(re.fullmatch(SHA256, entry[field]) for field in downgrade_fields),
                    "Malformed Windows downgrade evidence digests")
        for field in trust_fields | publisher_fields | build_info_fields | detector_fields | source_fields | restoration_fields:
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


def validate_bound_reboot_report(report, mode):
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
    if report["schemaVersion"] >= 12:
        fields.add(WINDOWS_SETUP_BASELINE)
        require(report.get(WINDOWS_SETUP_BASELINE) is (mode == "upgrade"),
                "Windows reboot evidence does not match the Setup baseline requirement")
    if report["schemaVersion"] >= 13:
        fields.add(WINDOWS_SETUP_WRONG_BASELINE)
        require(report.get(WINDOWS_SETUP_WRONG_BASELINE) is (mode == "upgrade"),
                "Windows reboot evidence does not match the incorrect Setup baseline refusal requirement")
    if report["schemaVersion"] >= 14:
        fields.add(WINDOWS_RESTORATION_JOURNAL)
        journal = report.get(WINDOWS_RESTORATION_JOURNAL)
        require(isinstance(journal, str) and re.fullmatch(SHA256, journal),
                "Windows reboot evidence lacks the verified restoration journal digest")
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


def load_detection_evidence(directory, evidence, subjects, version, *, include_lifecycle_sources=False):
    require(len(evidence) <= MAX_REBOOT_EVIDENCE, "Too many Windows reboot reports")
    targets = windows_subjects(subjects)
    payload_sboms = windows_payload_sboms(subjects)
    entries = []
    for path, fingerprint in evidence:
        content = independently_pinned_file(directory, path, fingerprint, maximum=8192)
        report = decode_json(content)
        require(isinstance(report, dict) and type(report.get("schemaVersion")) is int
                and report["schemaVersion"] in (5, 6, 7, 8, 9, 10, 11, 12, 13, 14) and report.get("stage") == "complete"
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
        if report["schemaVersion"] >= 11:
            validate_bound_reboot_report(report, mode)
            entry[WINDOWS_DETECTOR] = report[WINDOWS_DETECTOR]
            if report["schemaVersion"] >= 14:
                entry[WINDOWS_RESTORATION_JOURNAL] = report[WINDOWS_RESTORATION_JOURNAL]
            if include_lifecycle_sources:
                entry.update({field: report[field] for field in WINDOWS_LIFECYCLE_SOURCE_FIELDS})
            prior_build_info = report.get(WINDOWS_PREVIOUS_BUILD_INFO)
            if mode == "upgrade":
                entry[WINDOWS_PREVIOUS_BUILD_INFO] = prior_build_info
                if report["schemaVersion"] >= 12:
                    entry[WINDOWS_SETUP_BASELINE] = True
                if report["schemaVersion"] >= 13:
                    entry[WINDOWS_SETUP_WRONG_BASELINE] = True
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


def windows_lifecycle_sources(commit):
    root = Path(__file__).resolve().parents[1]
    git = ["git", "--no-replace-objects"]
    # Keep object selection rooted in the verifier's checkout.
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    options = {"cwd": root, "env": environment, "timeout": 15,
               "stdin": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    try:
        kind = subprocess.check_output([*git, "cat-file", "-t", commit], **options).strip()
        require(kind == b"commit", "Windows lifecycle qualification requires the approved Git commit")
        sources = {}
        for field, path in WINDOWS_LIFECYCLE_SOURCES.items():
            entry = subprocess.check_output([*git, "ls-tree", commit, "--", path], **options).split(b"\t", 1)
            require(len(entry) == 2 and entry[1].rstrip(b"\r\n") == path.encode("ascii"),
                    "Windows lifecycle source is missing from the approved Git commit")
            mode, kind, object_id = entry[0].split()
            require(mode in (b"100644", b"100755") and kind == b"blob",
                    "Windows lifecycle source must be a committed ordinary file")
            subject = object_id.decode("ascii")
            size = int(subprocess.check_output([*git, "cat-file", "-s", subject], **options))
            require(0 < size <= 1 << 20, "Windows lifecycle source exceeds its size limit")
            content = subprocess.check_output([*git, "cat-file", "blob", subject], **options)
            require(len(content) == size, "Windows lifecycle source size differs from its Git object")
            sources[field] = content
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("Windows lifecycle qualification requires the approved Git commit and its script objects") from error
    return sources


def require_windows_lifecycle_evidence(entries, windows_build_info, commit, *, require_restoration_journals=False):
    required = {"windows/amd64", "windows/arm64"}
    common_fields = {WINDOWS_PAYLOAD_PUBLISHER, WINDOWS_BUILD_INFO, WINDOWS_DETECTOR}
    upgrade_fields = {*WINDOWS_PREVIOUS_TRUST_FIELDS, *WINDOWS_DOWNGRADE_FIELDS,
                      WINDOWS_PREVIOUS_BUILD_INFO, WINDOWS_SETUP_BASELINE, WINDOWS_SETUP_WRONG_BASELINE}
    coverage = set()
    publishers = {}
    for entry in entries:
        target = entry["target"]
        mode = entry["installMode"]
        require(common_fields <= entry.keys()
                and entry[WINDOWS_BUILD_INFO] == windows_build_info.get(target),
                f"Windows lifecycle evidence for {target} {mode} requires the qualified detector, publisher and SBOM build binding")
        if mode == "upgrade":
            require(upgrade_fields <= entry.keys(),
                    f"Windows lifecycle evidence for {target} upgrade requires prior trust, Setup baseline refusal and downgrade refusal")
        signer_pair = (entry["publisherCertificateSHA256"], entry[WINDOWS_PAYLOAD_PUBLISHER])
        require(publishers.setdefault(target, signer_pair) == signer_pair,
                f"Windows lifecycle evidence for {target} disagrees on candidate publisher certificates")
        coverage.add((target, mode))
    missing = sorted((target, mode) for target in required for mode in ("clean", "upgrade")
                     if (target, mode) not in coverage)
    require(not missing, "Missing Windows lifecycle evidence: " + ", ".join(f"{target} {mode}" for target, mode in missing))
    sources = windows_lifecycle_sources(commit)
    expected_sources = {field: hashlib.sha256(content).hexdigest() for field, content in sources.items()}
    for entry in entries:
        require(all(entry.get(field) == pin for field, pin in expected_sources.items()),
                f"Windows lifecycle evidence for {entry['target']} {entry['installMode']} differs from the approved source scripts")
        require(not require_restoration_journals or WINDOWS_RESTORATION_JOURNAL in entry,
                f"Windows lifecycle evidence for {entry['target']} {entry['installMode']} requires a restoration journal digest")
    return sources, publishers


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
    if any(WINDOWS_SETUP_BASELINE in entry for entry in windows_detection):
        schema = 8
    if any(WINDOWS_SETUP_WRONG_BASELINE in entry for entry in windows_detection):
        schema = 9
    if any(WINDOWS_DETECTOR in entry for entry in windows_detection):
        schema = 10
    if any(WINDOWS_LIFECYCLE_SOURCE_FIELDS[0] in entry for entry in windows_detection):
        schema = 11
    if any(WINDOWS_RESTORATION_JOURNAL in entry for entry in windows_detection):
        schema = 12
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
             + (WINDOWS_BUILD_INFO, WINDOWS_PREVIOUS_BUILD_INFO, WINDOWS_SETUP_BASELINE,
                WINDOWS_SETUP_WRONG_BASELINE, WINDOWS_DETECTOR) + WINDOWS_LIFECYCLE_SOURCE_FIELDS
             + (WINDOWS_RESTORATION_JOURNAL,) if field in entry}
            for entry in sorted(windows_detection, key=detection_key)
        ]
    return (json.dumps(manifest, indent=2) + "\n").encode("utf-8")


def prepare(directory, output, commit, ref, *, windows_reboot_evidence=(), require_windows_lifecycle=False):
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
            entries = load_detection_evidence(directory, windows_reboot_evidence, files, version,
                                              include_lifecycle_sources=require_windows_lifecycle)
        _, _, windows_build_info = validate_release_sboms(root, files, commit, version, entries)
        if require_windows_lifecycle:
            require_windows_lifecycle_evidence(entries, windows_build_info, commit, require_restoration_journals=True)
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


def load_windows_upgrade_start_receipt(directory, path, fingerprint):
    receipt = decode_json(independently_pinned_file(directory, path, fingerprint, maximum=4096))
    digests = ("manifestSHA256", "approvalCertificateSHA256", "installerSHA256",
               "rebootEvidenceSHA256", "revocationListSHA256")
    strings = ("attemptID", "sourceCommit", "sourceRef", "target", "windowsSetupBaselineArgument")
    require(isinstance(receipt, dict) and type(receipt.get("schemaVersion")) is int
            and receipt["schemaVersion"] in (1, 2), "Malformed Windows upgrade start receipt")
    fields = {*digests, *strings, "schemaVersion", "revocationPolicySequence"}
    if receipt["schemaVersion"] == 2:
        fields.add("boot")
    require(receipt.keys() == fields
            and type(receipt["revocationPolicySequence"]) is int and receipt["revocationPolicySequence"] > 0
            and all(isinstance(receipt[field], str) and re.fullmatch(SHA256, receipt[field]) for field in digests)
            and all(isinstance(receipt[field], str) for field in strings)
            and re.fullmatch(r"[a-f0-9]{32}", receipt["attemptID"]),
            "Malformed Windows upgrade start receipt")
    if receipt["schemaVersion"] == 2:
        validate_windows_boot(receipt["boot"])
    return receipt


def load_windows_upgrade_result_receipt(directory, path, fingerprint, start_receipt):
    receipt = decode_json(independently_pinned_file(directory, path, fingerprint, maximum=4096))
    require(isinstance(receipt, dict), "Malformed Windows upgrade result receipt")
    fields = {"setupExitCode", "installedDetection"}
    if "installedDetectionReason" in receipt:
        fields.add("installedDetectionReason")
    require(receipt.keys() == start_receipt.keys() | fields
            and all(type(receipt[key]) is type(value) and receipt[key] == value
                    for key, value in start_receipt.items()),
            "Windows upgrade result receipt differs from the saved start receipt")
    code = receipt["setupExitCode"]
    detection = receipt["installedDetection"]
    reason = receipt.get("installedDetectionReason")
    require(type(code) is int and 0 <= code <= 0xFFFFFFFF
            and ((code == 0 and detection in ("detected", "unverified"))
                 or (code == 3010 and detection == "restart-required")
                 or (code not in (0, 3010) and detection == "setup-failed"))
            and ("installedDetectionReason" not in receipt
                 or (code == 0 and detection == "unverified" and reason in WINDOWS_DETECTION_FAILURE_REASONS)),
            "Malformed Windows upgrade result receipt")
    return {field: receipt[field] for field in sorted(fields)}


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


def windows_system_directory():
    system_directory = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(system_directory, len(system_directory))
    require(0 < length < len(system_directory), "Windows system directory could not be resolved")
    return Path(system_directory.value)


def validate_windows_boot(record):
    require(isinstance(record, dict) and record.keys() == {"endpointSHA256", "bootTicks"}
            and isinstance(record["endpointSHA256"], str) and re.fullmatch(SHA256, record["endpointSHA256"])
            and isinstance(record["bootTicks"], str) and re.fullmatch(r"[1-9][0-9]{17}", record["bootTicks"]),
            "Malformed Windows upgrade boot evidence")
    return record


def read_windows_boot(attempt_id):
    require(re.fullmatch(r"[a-f0-9]{32}", attempt_id), "Malformed Windows upgrade attempt ID")
    shell = windows_system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    # The provider UUID stays within PowerShell. The receipt uses a digest
    # scoped to this attempt and omits computer names and hardware details.
    command = r"""
$ErrorActionPreference='Stop'
$os=@(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop)
$system=@(Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop)
$id=[guid]::Empty
if($os.Count -ne 1 -or $os[0].LastBootUpTime -isnot [datetime] -or $system.Count -ne 1 -or
   -not [guid]::TryParseExact([string]$system[0].UUID,'D',[ref]$id) -or
   $id -eq [guid]::Empty -or $id.ToString('D') -ceq 'ffffffff-ffff-ffff-ffff-ffffffffffff'){
    throw 'Cannot establish Windows endpoint and boot identity'
}
$sha=[Security.Cryptography.SHA256]::Create()
try {
    $data=[Text.Encoding]::ASCII.GetBytes('AccessWeaver-Windows-upgrade:'+'ATTEMPT_ID'+':'+$id.ToString('D'))
    $digest=[BitConverter]::ToString($sha.ComputeHash($data)).Replace('-','').ToLowerInvariant()
} finally {$sha.Dispose()}
@{endpointSHA256=$digest;bootTicks=$os[0].LastBootUpTime.ToUniversalTime().Ticks.ToString(
    [Globalization.CultureInfo]::InvariantCulture)} | ConvertTo-Json -Compress
""".replace("ATTEMPT_ID", attempt_id)
    with tempfile.TemporaryFile() as output:
        subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command],
                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, check=True, timeout=30)
        output.seek(0)
        content = output.read(513)
    require(0 < len(content) <= 512, "Windows boot evidence exceeds inspection bounds")
    return validate_windows_boot(decode_json(content))


def check_windows_publisher(artifact, approved_digest, publisher_pin, *, script=None):
    shell = windows_system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if script is None:
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


def verify_windows_lifecycle_publishers(root, files, sources, publishers):
    # These are the identical script bytes approved for the reboot fixture.
    for field in ("commonSHA256", "publisherVerifierSHA256"):
        path = root / Path(WINDOWS_LIFECYCLE_SOURCES[field]).name
        with path.open("xb") as stream:
            stream.write(sources[field])
    script = root / Path(WINDOWS_LIFECYCLE_SOURCES["publisherVerifierSHA256"]).name
    for subject in files:
        target = subject["target"]
        role = subject["role"]
        if target not in publishers or role not in ("installer", "payload"):
            continue
        setup_pin, payload_pin = publishers[target]
        artifact = root / subject["file"]
        check_windows_publisher(artifact, subject["sha256"], setup_pin if role == "installer" else payload_pin,
                                script=script)
        require(digest(artifact) == subject["sha256"], "Windows artifact changed during publisher verification")


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


@contextmanager
def hold_windows_staging_directory(directory):
    if os.name != "nt":
        yield
        return

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_directory = kernel.CreateFileW
    open_directory.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                               wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    open_directory.restype = wintypes.HANDLE
    get_attributes = kernel.GetFileInformationByHandleEx
    get_attributes.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    get_attributes.restype = wintypes.BOOL
    close_handle = kernel.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    class AttributeTag(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    require(".." not in directory.parts, "Managed update staging path includes a parent traversal")
    chain = [*reversed(directory.parents), directory]
    with ExitStack() as handles:
        for component in chain:
            if component == Path(directory.anchor):
                continue
            # FILE_LIST_DIRECTORY, read/write sharing without delete sharing,
            # OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
            handle = open_directory(str(component), 1, 3, None, 3, 0x02200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.callback(close_handle, handle)
            info = AttributeTag()
            if not get_attributes(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):  # FileAttributeTagInfo
                raise ctypes.WinError(ctypes.get_last_error())
            require(info.attributes & stat.FILE_ATTRIBUTE_DIRECTORY
                    and not info.attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT,
                    "Managed update staging path includes a non-directory or reparse point")
        yield


@contextmanager
def hold_windows_setup(path):
    """Keep a Windows executable or script readable while denying writes and deletion."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_file = kernel.CreateFileW
    open_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                          wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    open_file.restype = wintypes.HANDLE
    close_handle = kernel.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT.
    handle = open_file(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        close_handle(handle)


def require_native_windows_setup_host(target, *, elevated=True):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    native_architecture = kernel.IsWow64Process2
    native_architecture.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
    native_architecture.restype = wintypes.BOOL
    process, native = wintypes.USHORT(), wintypes.USHORT()
    require(native_architecture(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native))
            and process.value == 0 and target == {0x8664: "windows/amd64", 0xAA64: "windows/arm64"}.get(native.value),
            "Windows Setup launch requires the matching native architecture")
    if elevated:
        require(ctypes.windll.shell32.IsUserAnAdmin(), "Windows Setup launch requires an already elevated agent")


def write_windows_upgrade_receipt(destination, receipt):
    content = (json.dumps(receipt, sort_keys=True) + "\n").encode("ascii")
    with tempfile.TemporaryDirectory(prefix=".accessweaver-receipt-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "receipt.json"
        with staged.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        publish_staged_installer(staged, destination)
    return hashlib.sha256(content).hexdigest()


class WindowsSetupLaunchError(OSError):
    """Windows did not return a Setup process handle."""


class WindowsSetupWaitError(OSError):
    """Setup was launched but its exit status could not be observed."""


class WindowsSetupDispatchPolicyExpired(ValueError):
    """The policy expired after the start receipt was published."""


def launch_windows_setup(directory, update, policy, *, size, directory_identity, attempt=None, wait_seconds=None):
    setup = directory / update["installer"]
    arguments = [str(setup), "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                 "/RESTARTEXITCODE=3010", "/NOICONS", update["windowsSetupBaselineArgument"]]
    with hold_windows_staging_directory(directory):
        require(staging_directory_identity(directory) == directory_identity,
                "Managed update staging directory changed before launch")
        with hold_windows_setup(setup):
            verify_staged_update(setup, size, update["installerSHA256"])
            working_directory = windows_system_directory()
            require_current_revocation_policy(policy)
            if attempt is not None:
                require(not os.path.lexists(directory / (attempt["attemptID"] + ".result.json")),
                        "Windows upgrade attempt already has a result receipt")
                update["startReceiptSHA256"] = write_windows_upgrade_receipt(
                    directory / (attempt["attemptID"] + ".started.json"), attempt,
                )
                try:
                    require_current_revocation_policy(policy)
                except ValueError as error:
                    raise WindowsSetupDispatchPolicyExpired("Revocation policy expired before Setup dispatch") from error
            # Popen's context manager waits on exit, which would defeat a wait limit.
            try:
                process = subprocess.Popen(arguments, executable=str(setup), cwd=working_directory,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as error:
                raise WindowsSetupLaunchError("Windows Setup could not be launched") from error
            try:
                return process.wait(timeout=wait_seconds)
            except OSError as error:
                raise WindowsSetupWaitError("Windows Setup exit could not be observed") from error


@contextmanager
def hold_qualified_windows_detector(qualification):
    script = Path(__file__).absolute().with_name("detect-windows-installer.ps1")
    expected = qualification.get(WINDOWS_DETECTOR)
    if expected is None:
        yield script
        return
    with hold_windows_staging_directory(script.parent), hold_windows_setup(script):
        info = release_file(script, 1 << 20)
        verify_staged_update(script, info.st_size, expected)
        yield script


@contextmanager
def hold_qualified_windows_publisher(qualification):
    if qualification is None or "publisherVerifierSHA256" not in qualification:
        yield None
        return
    script_directory = Path(__file__).absolute().parent
    with hold_windows_staging_directory(script_directory), ExitStack() as held:
        for field in ("commonSHA256", "publisherVerifierSHA256"):
            path = script_directory / Path(WINDOWS_LIFECYCLE_SOURCES[field]).name
            held.enter_context(hold_windows_setup(path))
            info = release_file(path, 1 << 20)
            verify_staged_update(path, info.st_size, qualification[field])
        yield path


def detect_windows_upgrade(qualification, publisher_pin):
    try:
        shell = windows_system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        with tempfile.TemporaryFile() as output, hold_qualified_windows_detector(qualification) as script:
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-File", script, "-UseRegisteredDirectory",
                 "-Version", qualification["version"], "-Architecture", qualification["target"].split("/")[1],
                 "-PayloadSHA256", qualification["payloadSHA256"], "-PayloadSBOMSHA256", qualification["payloadSBOMSHA256"],
                 "-BuildInfoSHA256", qualification[WINDOWS_BUILD_INFO], "-UninstallerSHA256", qualification["uninstallerSHA256"],
                 "-PayloadPublisherSHA256", publisher_pin],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, timeout=90,
            )
            output.seek(0)
            content = output.read(4097)
    except subprocess.TimeoutExpired:
        return "unverified", "detector-timeout"
    except (ValueError, OSError):
        return "unverified", "detector-unavailable"

    if result.returncode == 0:
        if content in (b"AccessWeaver detected\r\n", b"AccessWeaver detected\n"):
            return "detected", None
        if not content:
            return "unverified", "approved-installation-not-detected"
    if result.returncode == 1 and not content:
        return "unverified", "detector-inspection-failed"
    return "unverified", "detector-result-invalid"


def record_windows_installed_detection(update, publisher_pin, policy):
    def policy_is_current():
        try:
            require_current_revocation_policy(policy)
        except ValueError:
            update["installedDetection"] = "unverified"
            update["installedDetectionReason"] = "revocation-policy-expired"
            return False
        return True

    if not policy_is_current():
        return
    detection, reason = detect_windows_upgrade(update["windowsUpgradeDetection"], publisher_pin)
    if policy_is_current():
        update["installedDetection"] = detection
        if reason is not None:
            update["installedDetectionReason"] = reason


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
    directory = directory.absolute()
    with hold_windows_staging_directory(directory):
        stage_verified_installer(root, directory, update, policy, size, directory_identity)


def stage_verified_installer(root, directory, update, policy, size, directory_identity):
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
           windows_publisher=None, windows_payload_publisher=None, require_windows_setup_baseline=False,
           resume_windows_upgrade_setup_sha256=None, require_windows_setup_wrong_baseline_refusal=False,
           resume_windows_upgrade_baseline_argument=None, launch_staged_windows_setup=False,
           detect_installed_windows_upgrade=False, windows_upgrade_attempt_id=None, windows_upgrade_start_receipt=None,
           windows_setup_wait_seconds=None, windows_upgrade_result_receipt=None, require_windows_lifecycle=False,
           verify_lifecycle_publishers=False):
    if verify_lifecycle_publishers:
        require(sys.platform == "win32", "Windows lifecycle publisher verification requires a Windows host")
        require_windows_lifecycle = True
    if windows_setup_wait_seconds is not None:
        require(launch_staged_windows_setup and type(windows_setup_wait_seconds) is int
                and 1 <= windows_setup_wait_seconds <= 4_294_966,
                "Windows Setup wait limit requires Setup launch and a positive duration within the Windows wait range")
    start_receipt = None
    if windows_upgrade_start_receipt is not None:
        require(detect_installed_windows_upgrade and not launch_staged_windows_setup
                and resume_windows_upgrade_setup_sha256 is None and resume_windows_upgrade_baseline_argument is None,
                "A Windows start receipt is for read-only detection and replaces explicit retry pins")
        path, fingerprint = windows_upgrade_start_receipt
        start_receipt = load_windows_upgrade_start_receipt(directory, path, fingerprint)
        resume_windows_upgrade_setup_sha256 = start_receipt["installerSHA256"]
        resume_windows_upgrade_baseline_argument = start_receipt["windowsSetupBaselineArgument"]
    recorded_result = None
    if windows_upgrade_result_receipt is not None:
        require(start_receipt is not None, "A Windows result receipt requires the saved start receipt")
        path, fingerprint = windows_upgrade_result_receipt
        recorded_result = load_windows_upgrade_result_receipt(directory, path, fingerprint, start_receipt)
    if windows_upgrade_attempt_id is not None:
        require(launch_staged_windows_setup and isinstance(windows_upgrade_attempt_id, str)
                and re.fullmatch(r"[a-f0-9]{32}", windows_upgrade_attempt_id),
                "A Windows upgrade attempt ID requires Setup launch and 32 lowercase hexadecimal characters")
    if windows_setup_wait_seconds is not None:
        require(windows_upgrade_attempt_id is not None, "Windows Setup wait limit requires a Windows upgrade attempt ID")
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
    if resume_windows_upgrade_setup_sha256 is not None:
        require(isinstance(resume_windows_upgrade_setup_sha256, str)
                and re.fullmatch(r"[a-fA-F0-9]{64}", resume_windows_upgrade_setup_sha256),
                "Expected the original approved Windows Setup SHA-256 for retry")
        require_windows_setup_baseline = True
    if resume_windows_upgrade_baseline_argument is not None:
        require(resume_windows_upgrade_setup_sha256 is not None,
                "Retry baseline matching requires the original approved Windows Setup SHA-256")
        require(isinstance(resume_windows_upgrade_baseline_argument, str)
                and resume_windows_upgrade_baseline_argument.startswith(WINDOWS_SETUP_BASELINE_PREFIX),
                "Expected the original Windows Setup baseline argument for retry")
    if launch_staged_windows_setup or detect_installed_windows_upgrade:
        require(os.name == "nt" and windows_publisher is not None
                and type(minimum_revocation_sequence) is int and minimum_revocation_sequence > 0,
                "Managed Windows execution requires native Windows, publisher pins and a revocation sequence")
        require_windows_setup_baseline = True
    if launch_staged_windows_setup:
        require(stage_directory is not None, "Windows Setup launch requires a staging directory")
        if resume_windows_upgrade_setup_sha256 is not None:
            require(resume_windows_upgrade_baseline_argument is not None,
                    "Windows Setup retry launch requires the saved baseline argument")
        require_native_windows_setup_host(target)
    if detect_installed_windows_upgrade:
        require(stage_directory is None and not launch_staged_windows_setup,
                "Installed Windows detection cannot stage or launch Setup")
        require(resume_windows_upgrade_setup_sha256 is not None and resume_windows_upgrade_baseline_argument is not None,
                "Installed Windows detection requires the original approved Setup digest and baseline argument")
        require_native_windows_setup_host(target, elevated=False)
    if require_windows_setup_baseline or require_windows_setup_wrong_baseline_refusal:
        require(target in ("windows/amd64", "windows/arm64") and current_version is not None
                and WINDOWS_PREVIOUS_BUILD_INFO in installed_trust,
                "Required Windows Setup baseline needs a Windows target and complete installed trust pins")
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
        stage_directory = stage_directory.absolute()
        stage_directory_id = staging_directory_identity(stage_directory)
        resolved_staging = stage_directory.resolve(strict=True)
        require(staging_directory_identity(resolved_staging) == stage_directory_id,
                "Managed update staging directory changed during resolution")
        require(not resolved_staging.is_relative_to(directory.resolve()),
                "Stage the installer outside the release input directory")
        # Keep the caller's Windows path so staging can inspect and hold its original ancestors.
        if os.name != "nt":
            stage_directory = resolved_staging
    subjects = release_subjects(commit, ref)
    der = independently_pinned_file(directory, certificate, certificate_sha256)
    certificate_sha256 = certificate_sha256.lower()
    policy = revocations(independently_pinned_file(directory, revocation_list, revocation_list_sha256),
                         minimum_sequence=minimum_revocation_sequence)
    require(commit not in policy["sourceCommits"] and ref not in policy["sourceRefs"]
            and certificate_sha256 not in policy["approvalCertificateSHA256"],
            "Release source or approval signer is revoked")
    with tempfile.TemporaryDirectory(prefix="accessweaver-signed-release-") as temporary, ExitStack() as held:
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
                    + WINDOWS_DOWNGRADE_FIELDS + (WINDOWS_BUILD_INFO, WINDOWS_PREVIOUS_BUILD_INFO, WINDOWS_DETECTOR)
                    + WINDOWS_LIFECYCLE_SOURCE_FIELDS + (WINDOWS_RESTORATION_JOURNAL,) if field in entry
                ) for entry in entries),
                "Release subject or Windows detection evidence is revoked")
        sboms_verified, macos_detectors, windows_build_info = validate_release_sboms(root, files, commit, version, entries)
        require(not revoked_subjects.intersection(windows_build_info.values()),
                "Windows installer SBOM build metadata is revoked")
        require(all(entry["detectorSHA256"] not in revoked_subjects for entry in macos_detectors),
                "macOS detector is revoked")
        require(all(entry["manifestSHA256"] not in revoked_subjects for entry in macos_detectors),
                "macOS deployment manifest is revoked")
        require(all(entry["payloadSHA256"] not in revoked_subjects for entry in macos_detectors),
                "macOS controller is revoked")
        report = {
            "schemaVersion": 1, "scope": "accessweaver-signed-desktop-release",
            "sbomArtifactBindingsVerified": sboms_verified, "macosDetection": macos_detectors,
            "sourceCommit": commit, "sourceRef": ref, "subjectsVerified": len(subjects),
            "organizationApprovalSignatureVerified": True, "approvalCertificateSHA256": certificate_sha256,
            "revocationListSHA256": revocation_list_sha256.lower(), "revocationCheckPassed": True,
            "nativePublisherChecksPerformed": False, "productionQualificationComplete": False,
        }
        if require_windows_lifecycle:
            require_restoration = manifest["schemaVersion"] >= 12
            lifecycle_sources, lifecycle_publishers = require_windows_lifecycle_evidence(
                entries, windows_build_info, commit, require_restoration_journals=require_restoration,
            )
            report["windowsLifecycleEvidenceVerified"] = True
            if require_restoration:
                report["windowsRestorationJournalEvidenceVerified"] = True
            if verify_lifecycle_publishers:
                verify_windows_lifecycle_publishers(root, files, lifecycle_sources, lifecycle_publishers)
                report["windowsLifecyclePublishersVerified"] = True
                report["nativePublisherChecksPerformed"] = True
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
            baseline = select_windows_upgrade(
                report.get("windowsDetection", ()), update, current_payload_sha256, installed_trust
            )
            baseline_verified = baseline.get(WINDOWS_SETUP_BASELINE) is True
            require(not require_windows_setup_baseline or baseline_verified,
                    "The selected Windows upgrade lacks signed Setup baseline enforcement evidence")
            require(not require_windows_setup_wrong_baseline_refusal or baseline.get(WINDOWS_SETUP_WRONG_BASELINE) is True,
                    "The selected Windows upgrade lacks signed incorrect Setup baseline refusal evidence")
            if resume_windows_upgrade_setup_sha256 is not None:
                require(update["installerSHA256"] == resume_windows_upgrade_setup_sha256.lower(),
                        "Signed Windows Setup differs from the original approved upgrade package")
            update["windowsUpgradeDetection"] = baseline
            if baseline_verified:
                values = (baseline["previousVersion"], baseline["previousPayloadSHA256"],
                          baseline["previousPayloadSBOMSHA256"], baseline[WINDOWS_PREVIOUS_BUILD_INFO])
                argument = WINDOWS_SETUP_BASELINE_PREFIX + ",".join(values)
                require(resume_windows_upgrade_baseline_argument is None
                        or argument == resume_windows_upgrade_baseline_argument,
                        "Windows Setup baseline argument differs from the original approved upgrade")
                update["windowsSetupBaselineArgument"] = argument
            if launch_staged_windows_setup:
                try:
                    held.enter_context(hold_qualified_windows_detector(baseline))
                except (OSError, ValueError) as error:
                    raise ValueError("Qualified Windows detector unavailable before Setup launch") from error
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
            with hold_qualified_windows_publisher(qualification) as script:
                for name, approved_digest, publisher_pin in (
                    (update["installer"], update["installerSHA256"], windows_publisher),
                    (payload["file"], payload["sha256"], payload_publisher),
                ):
                    artifact = root / name
                    if script is None:
                        check_windows_publisher(artifact, approved_digest, publisher_pin)
                    else:
                        check_windows_publisher(artifact, approved_digest, publisher_pin, script=script)
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
            detectors = [entry for entry in macos_detectors if entry["target"] == target
                         and entry["packageSHA256"] == update["installerSHA256"]]
            require(len(detectors) == 1, "Managed macOS upgrade requires approved deployment digests")
            approved_package = detectors[0]
            check_package_publisher(package, team, installer_pin)
            verify_packaged_deployment(package, team, architecture, application_pin,
                                       commit=commit, version=approved_package["version"],
                                       helper_sha256=approved_package["detectorSHA256"],
                                       manifest_sha256=approved_package["manifestSHA256"],
                                       payload_sha256=approved_package["payloadSHA256"])
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
        if detect_installed_windows_upgrade:
            update = report["managedUpdate"]
            current_boot = None
            if start_receipt is not None:
                bindings = {
                    "sourceCommit": commit, "sourceRef": ref, "target": update["target"],
                    "manifestSHA256": hashlib.sha256(manifest_bytes).hexdigest(),
                    "approvalCertificateSHA256": certificate_sha256,
                    "rebootEvidenceSHA256": update["windowsUpgradeDetection"]["rebootEvidenceSHA256"],
                }
                require(all(start_receipt[field] == value for field, value in bindings.items()),
                        "Signed Windows upgrade differs from the saved start receipt")
                original_sequence = start_receipt["revocationPolicySequence"]
                require(policy["sequence"] >= original_sequence and (
                    policy["sequence"] != original_sequence
                    or start_receipt["revocationListSHA256"] == report["revocationListSHA256"]
                ), "Windows detection requires the original revocation policy or a newer sequence")
                update["attemptID"] = start_receipt["attemptID"]
                if recorded_result is not None:
                    update["recordedSetupResult"] = recorded_result
                restart_required = recorded_result is not None and recorded_result["setupExitCode"] == 3010
                restart_unconfirmed = recorded_result is None
                if start_receipt["schemaVersion"] == 2:
                    try:
                        current_boot = read_windows_boot(start_receipt["attemptID"])
                    except (ValueError, OSError, subprocess.SubprocessError):
                        update["installedDetection"] = "unverified"
                        update["installedDetectionReason"] = "boot-evidence-unavailable"
                        return report
                    old_boot = start_receipt["boot"]
                    if current_boot["endpointSHA256"] != old_boot["endpointSHA256"]:
                        update["installedDetection"] = "unverified"
                        update["installedDetectionReason"] = "endpoint-mismatch"
                        return report
                    if current_boot["bootTicks"] <= old_boot["bootTicks"] and (restart_required or restart_unconfirmed):
                        update["installedDetection"] = "unverified"
                        update["installedDetectionReason"] = (
                            "restart-required" if restart_required else "restart-status-unverified"
                        )
                        return report
                elif restart_required or restart_unconfirmed:
                    update["installedDetection"] = "unverified"
                    update["installedDetectionReason"] = "boot-evidence-unavailable"
                    return report
            record_windows_installed_detection(update, payload_publisher, policy)
            if current_boot is not None and update["installedDetection"] == "detected":
                try:
                    confirmed_boot = read_windows_boot(start_receipt["attemptID"])
                except (ValueError, OSError, subprocess.SubprocessError):
                    update["installedDetection"] = "unverified"
                    update["installedDetectionReason"] = "boot-evidence-unavailable"
                else:
                    if confirmed_boot != current_boot:
                        update["installedDetection"] = "unverified"
                        update["installedDetectionReason"] = "boot-evidence-changed"
                try:
                    require_current_revocation_policy(policy)
                except ValueError:
                    report["revocationCheckPassed"] = False
                    update["installedDetection"] = "unverified"
                    update["installedDetectionReason"] = "revocation-policy-expired"
        if stage_directory is not None:
            update = report["managedUpdate"]
            require(update["updateAvailable"], "Candidate is not an eligible managed upgrade")
            installer = next(item for item in files if item["file"] == update["installer"])
            stage_managed_update(root, stage_directory, update, policy,
                                 size=installer["size"], directory_identity=stage_directory_id)
            update["installerStaged"] = True
            if launch_staged_windows_setup:
                attempt = None
                if windows_upgrade_attempt_id is not None:
                    attempt = {
                        "schemaVersion": 2, "attemptID": windows_upgrade_attempt_id,
                        "boot": read_windows_boot(windows_upgrade_attempt_id),
                        "sourceCommit": commit, "sourceRef": ref, "target": update["target"],
                        "manifestSHA256": hashlib.sha256(manifest_bytes).hexdigest(),
                        "approvalCertificateSHA256": certificate_sha256,
                        "installerSHA256": update["installerSHA256"],
                        "windowsSetupBaselineArgument": update["windowsSetupBaselineArgument"],
                        "rebootEvidenceSHA256": update["windowsUpgradeDetection"]["rebootEvidenceSHA256"],
                        "revocationListSHA256": report["revocationListSHA256"],
                        "revocationPolicySequence": policy["sequence"],
                    }
                    update["attemptID"] = windows_upgrade_attempt_id
                try:
                    code = launch_windows_setup(stage_directory, update, policy, attempt=attempt,
                                                size=installer["size"], directory_identity=stage_directory_id,
                                                wait_seconds=windows_setup_wait_seconds)
                except (WindowsSetupLaunchError, WindowsSetupWaitError, WindowsSetupDispatchPolicyExpired,
                        subprocess.TimeoutExpired) as error:
                    reasons = {
                        WindowsSetupLaunchError: "setup-launch-failed",
                        WindowsSetupWaitError: "setup-wait-failed",
                        WindowsSetupDispatchPolicyExpired: "revocation-policy-expired",
                        subprocess.TimeoutExpired: "setup-wait-timeout",
                    }
                    update["setupExitCode"] = None
                    update["installedDetection"] = "unverified"
                    update["installedDetectionReason"] = reasons[type(error)]
                    return report
                update["setupExitCode"] = code
                if code == 0:
                    record_windows_installed_detection(update, payload_publisher, policy)
                elif code == 3010:
                    update["installedDetection"] = "restart-required"
                else:
                    update["installedDetection"] = "setup-failed"
                if attempt is not None:
                    result_receipt = {**attempt, "setupExitCode": code,
                                      "installedDetection": update["installedDetection"]}
                    if "installedDetectionReason" in update:
                        result_receipt["installedDetectionReason"] = update["installedDetectionReason"]
                    try:
                        with hold_windows_staging_directory(stage_directory):
                            require(staging_directory_identity(stage_directory) == stage_directory_id,
                                    "Managed update staging directory changed before receipt publication")
                            update["resultReceiptSHA256"] = write_windows_upgrade_receipt(
                                stage_directory / (windows_upgrade_attempt_id + ".result.json"), result_receipt,
                            )
                    except (OSError, ValueError):
                        # Setup has already exited. Keep its outcome available to the agent.
                        update["resultReceiptStatus"] = "unverified"
                    else:
                        update["resultReceiptStatus"] = "published"
                    if update["installedDetection"] == "detected":
                        # Receipt publication can outlast the policy. Keep the historical
                        # observation, but require current policy for the live result.
                        try:
                            require_current_revocation_policy(policy)
                        except ValueError:
                            report["revocationCheckPassed"] = False
                            update["installedDetection"] = "unverified"
                            update["installedDetectionReason"] = "revocation-policy-expired"
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prepare_args = commands.add_parser("prepare")
    prepare_args.add_argument("--output", type=Path, required=True)
    prepare_args.add_argument("--windows-reboot-evidence", nargs=2, metavar=("PATH", "SHA256"),
                              action="append", default=[], help="independently pinned Windows reboot result")
    verify_args = commands.add_parser("verify")
    verify_args.add_argument("--verify-windows-lifecycle-publishers", action="store_true",
                             help="verify Authenticode for both Windows architectures using signed lifecycle publisher pins")
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
    verify_args.add_argument("--require-windows-setup-baseline", action="store_true",
                             help="require signed Setup baseline enforcement for the exact installed Windows build")
    verify_args.add_argument("--require-windows-setup-wrong-baseline-refusal", action="store_true",
                             help="require evidence that Windows Setup refused an incorrect baseline and preserved installed state")
    verify_args.add_argument("--resume-windows-upgrade-setup-sha256",
                             help="reverify an interrupted upgrade using its original approval and exact Setup digest")
    verify_args.add_argument("--resume-windows-upgrade-baseline-argument",
                             help="compare the exact baseline argument saved with the original Windows Setup approval")
    verify_args.add_argument("--windows-publisher-sha256",
                             help="require native Authenticode and timestamp checks on the Windows setup and payload")
    verify_args.add_argument("--windows-payload-publisher-sha256",
                             help="approved Windows payload leaf SHA-256 when it differs from the setup signer")
    verify_args.add_argument("--macos-publisher", nargs=3, metavar=("TEAM_ID", "INSTALLER_SHA256", "APPLICATION_SHA256"),
                             help="require native macOS package and app publisher checks before staging")
    verify_args.add_argument("--stage-directory", type=Path,
                             help="existing trusted directory for the authenticated eligible installer")
    verify_args.add_argument("--windows-upgrade-start-receipt", nargs=2, metavar=("PATH", "SHA256"),
                             help="bind read-only detection to an independently pinned start receipt")
    verify_args.add_argument("--windows-upgrade-result-receipt", nargs=2, metavar=("PATH", "SHA256"),
                             help="verify an independently pinned result receipt against the saved start receipt")
    verify_args.add_argument("--windows-upgrade-attempt-id",
                             help="record an exclusive start and result for this 32-character lowercase hexadecimal ID")
    verify_args.add_argument("--windows-setup-wait-seconds", type=int,
                             help="limit the Setup wait and retain the start receipt for the required upgrade attempt ID")
    execution = verify_args.add_mutually_exclusive_group()
    execution.add_argument("--launch-staged-windows-setup", action="store_true",
                           help="explicitly launch the qualified Windows upgrade after verification and staging")
    execution.add_argument("--detect-installed-windows-upgrade", action="store_true",
                           help="confirm the installed Windows upgrade using the original signed assignment")
    for command in (prepare_args, verify_args):
        command.add_argument("--require-windows-lifecycle", action="store_true",
                             help="require signed clean and upgrade reboot evidence on AMD64 and ARM64, including downgrade refusal")
        command.add_argument("directory", type=Path)
        command.add_argument("--source-commit", required=True)
        command.add_argument("--source-ref", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            prepare(args.directory, args.output, args.source_commit, args.source_ref,
                    windows_reboot_evidence=[(Path(path), pin) for path, pin in args.windows_reboot_evidence],
                    require_windows_lifecycle=args.require_windows_lifecycle)
        else:
            inventory = args.windows_upgrade_inventory
            if inventory is not None:
                inventory = (Path(inventory[0]), inventory[1])
            receipt = args.windows_upgrade_start_receipt
            if receipt is not None:
                receipt = (Path(receipt[0]), receipt[1])
            result_receipt = args.windows_upgrade_result_receipt
            if result_receipt is not None:
                result_receipt = (Path(result_receipt[0]), result_receipt[1])
            report = verify(args.directory, args.approval_certificate, args.approval_certificate_sha256,
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
                                    windows_payload_publisher=args.windows_payload_publisher_sha256,
                                    require_windows_setup_baseline=args.require_windows_setup_baseline,
                                    resume_windows_upgrade_setup_sha256=args.resume_windows_upgrade_setup_sha256,
                                    require_windows_setup_wrong_baseline_refusal=args.require_windows_setup_wrong_baseline_refusal,
                                    resume_windows_upgrade_baseline_argument=args.resume_windows_upgrade_baseline_argument,
                                    launch_staged_windows_setup=args.launch_staged_windows_setup,
                                    detect_installed_windows_upgrade=args.detect_installed_windows_upgrade,
                                    windows_upgrade_attempt_id=args.windows_upgrade_attempt_id,
                                    windows_upgrade_start_receipt=receipt,
                                    windows_setup_wait_seconds=args.windows_setup_wait_seconds,
                                    windows_upgrade_result_receipt=result_receipt,
                                    require_windows_lifecycle=args.require_windows_lifecycle,
                                    verify_lifecycle_publishers=args.verify_windows_lifecycle_publishers)
            print(json.dumps(report))
            if args.launch_staged_windows_setup:
                update = report["managedUpdate"]
                code = update["setupExitCode"]
                if code is None:
                    return 1
                if code == 0 and (update["installedDetection"] == "unverified"
                                  or update.get("resultReceiptStatus") == "unverified"):
                    return 1
                return code
            if args.detect_installed_windows_upgrade:
                return 0 if report["managedUpdate"]["installedDetection"] == "detected" else 1
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Signed release inventory, approval or revocation verification failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
