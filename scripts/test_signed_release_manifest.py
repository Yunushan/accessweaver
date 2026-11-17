from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import signed_release_manifest as release
from sbom import properties


COMMIT = "a" * 40
REF = "refs/tags/v1.2.3-rc.1"
OPENSSL = shutil.which("openssl")
VERSION = REF.removeprefix("refs/tags/v")
DETECTOR_DIGESTS = {"darwin/amd64": "1" * 64, "darwin/arm64": "2" * 64}
DEPLOYMENT_MANIFEST_DIGESTS = {"darwin/amd64": "7" * 64, "darwin/arm64": "8" * 64}
MACOS_PAYLOAD_DIGESTS = {
    target: hashlib.sha256(("fixture controller " + target).encode()).hexdigest()
    for target in DETECTOR_DIGESTS
}


class SignedReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.revocation_list = self.root / "revocations.json"
        self.policy = {"schemaVersion": 1, **{field: [] for field in release.REVOCATION_FIELDS}}
        self.policy_pin = self.write_policy(self.policy)
        self.subjects = release.release_subjects(COMMIT, REF)
        for name, (_, role) in self.subjects.items():
            if role in ("installer", "payload"):
                (self.candidate / name).write_bytes(name.encode())
        self.write_sboms()

    def write_sboms(self):
        payloads = {}
        for name, (target, role) in self.subjects.items():
            if role != "payload":
                continue
            root = self.sbom_root(name, target)
            payloads[target] = {**root, "bom-ref": "payload-application"}
            self.write_sbom(name, root)
        for name, (target, role) in self.subjects.items():
            if role != "installer":
                continue
            root = self.sbom_root(name, target)
            if target.startswith("darwin/"):
                hashes = [{"alg": "SHA-256", "content": DETECTOR_DIGESTS[target]}]
                core_path = "Contents/MacOS/accessweaver"
                core_hashes = [{"alg": "SHA-256", "content": MACOS_PAYLOAD_DIGESTS[target]}]
                components = [
                    {**root, "bom-ref": "helper:application", "hashes": hashes},
                    {**root, "bom-ref": "payload:application", "hashes": core_hashes},
                    {"bom-ref": "bundle-file:" + core_path, "type": "file", "name": core_path, "hashes": core_hashes},
                ]
                components.extend({"bom-ref": "script-file:" + phase, "type": "file",
                                   "name": phase, "hashes": hashes} for phase in ("preinstall", "postinstall"))
                components.append({"bom-ref": "detached-file:" + release.DETACHED_MANIFEST, "type": "file",
                                   "name": release.DETACHED_MANIFEST,
                                   "hashes": [{"alg": "SHA-256", "content": DEPLOYMENT_MANIFEST_DIGESTS[target]}]})
            else:
                components = [payloads[target]]
            self.write_sbom(name, root, components)

    def add_windows_installer_property(self, architecture, name, value):
        sidecar = self.candidate / f"accessweaver-{VERSION}-windows-{architecture}-setup.exe.cdx.json"
        document = json.loads(sidecar.read_bytes())
        document["metadata"]["component"]["properties"].append({"name": name, "value": value})
        sidecar.write_text(json.dumps(document), encoding="utf-8")

    def sbom_root(self, name, target):
        platform, arch = target.split("/")
        return {
            "type": "application", "name": name, "version": VERSION, "bom-ref": "application",
            "hashes": [{"alg": "SHA-256", "content": release.digest(self.candidate / name)}],
            "properties": properties({
                "source-commit": COMMIT, "source-state": "clean", "target-os": platform, "target-arch": arch,
                "license-evidence": json.dumps([{"path": "licenses/LICENSE", "sha256": "a" * 64}]),
            }),
        }

    def write_sbom(self, name, root, components=()):
        references = [entry["bom-ref"] for entry in components]
        document = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": root}, "components": list(components),
            "dependencies": [{"ref": root["bom-ref"], "dependsOn": references}]
                            + [{"ref": ref, "dependsOn": []} for ref in references],
            "compositions": [{"aggregate": "incomplete"}],
        }
        (self.candidate / (name + ".cdx.json")).write_text(json.dumps(document), encoding="utf-8")

    def write_policy(self, policy):
        self.revocation_list.write_text(json.dumps(policy), encoding="utf-8")
        return release.digest(self.revocation_list)

    def verify(self, certificate, certificate_pin, commit=COMMIT, ref=REF, *, policy_pin=None, **update):
        return release.verify(self.candidate, certificate, certificate_pin, commit, ref, OPENSSL,
                              revocation_list=self.revocation_list,
                              revocation_list_sha256=policy_pin or self.policy_pin, **update)

    def write_reboot_report(self, filename, architecture="amd64", **overrides):
        version = REF.removeprefix("refs/tags/v")
        stem = f"accessweaver-{version}-windows-{architecture}"
        report = {
            "schemaVersion": 5, "stage": "complete", "architecture": architecture, "version": version,
            "installMode": "clean", "previousVersion": "", "previousPayloadSHA256": "",
            "setupSHA256": release.digest(self.candidate / (stem + "-setup.exe")),
            "payloadSHA256": release.digest(self.candidate / (stem + ".exe")),
            "publisherSHA256": "b" * 64, "uninstallerSHA256": "c" * 64,
            "passed": True, "guestRebootVerified": True, "installedPayloadVerifiedBeforeRestart": True,
            "installedPayloadVerified": True, "uninstallerIdentityVerified": True,
            "installedTreeVerified": True, "registrationPreserved": True, "registrationRemoved": True,
            "packageFilesRemoved": True, "userProfileVerifiedAfterReboot": True,
            "userProfilePreservedAfterUninstall": True, "userProfilePreservedThroughUpgrade": False,
            "downgradeRequested": False, "downgradeRefused": False, "downgradeStatePreserved": False,
        }
        if overrides.get("schemaVersion", 5) >= 6:
            report.update(
                payloadSBOMSHA256=release.digest(self.candidate / (stem + ".exe.cdx.json")),
                installedPayloadSBOMVerified=True,
                installedPayloadPublisherVerified=True,
            )
        if overrides.get("schemaVersion", 5) >= 7:
            report["userProfileOpenedByInstalledController"] = True
        if overrides.get("schemaVersion", 5) >= 8:
            upgrade = overrides.get("installMode") == "upgrade"
            report.update(
                previousPayloadTrustVerified=upgrade,
                previousPayloadSBOMSHA256="1" * 64 if upgrade else "",
                previousPayloadPublisherSHA256="2" * 64 if upgrade else "",
            )
        if overrides.get("schemaVersion", 5) >= 9:
            report["payloadPublisherSHA256"] = "7" * 64
        if overrides.get("schemaVersion", 5) >= 10:
            report.update(buildInfoSHA256="6" * 64, installedBuildInfoVerified=True)
        if overrides.get("schemaVersion", 5) >= 11:
            report.update(
                runID="a" * 32, detectorSHA256="1" * 64, fixtureSHA256="2" * 64,
                commonSHA256="3" * 64, publisherVerifierSHA256="4" * 64,
                installedTreeSHA256="5" * 64, registrationSHA256="6" * 64,
                setupExitCode=0, setupRequestedRestart=False, previousSetupSHA256="", previousPublisherSHA256="",
            )
            report["previousBuildInfoSHA256"] = "5" * 64 if overrides.get("installMode") == "upgrade" else ""
        if overrides.get("schemaVersion", 5) >= 12:
            report["setupUpgradeBaselineVerified"] = overrides.get("installMode") == "upgrade"
        if overrides.get("schemaVersion", 5) >= 13:
            report["setupWrongBaselineRefusedWithStatePreserved"] = overrides.get("installMode") == "upgrade"
        if overrides.get("schemaVersion", 5) >= 14:
            report[release.WINDOWS_RESTORATION_JOURNAL] = hashlib.sha256(filename.encode()).hexdigest()
        evidence = self.root / filename
        evidence.write_text(json.dumps({**report, **overrides}), encoding="utf-8")
        return evidence, release.digest(evidence)

    def test_legacy_upgrade_uses_the_signed_prior_uninstall_pair_and_exact_endpoint_inventory(self):
        self.add_windows_installer_property("amd64", release.WINDOWS_BUILD_INFO_PROPERTY, "6" * 64)
        self.add_windows_installer_property("amd64", release.WINDOWS_PAYLOAD_FINGERPRINT_PROPERTY, "7" * 64)
        files = release.inventory(self.candidate, self.subjects)
        prior = dict(zip(release.WINDOWS_LEGACY_PRIOR_FIELDS, ("a" * 64, "b" * 64)))
        evidence_fields = dict(
            schemaVersion=15, installMode="upgrade", previousVersion="1.2.2-rc.1",
            previousPayloadSHA256="d" * 64, userProfilePreservedThroughUpgrade=True,
            legacyRegistrationMigrated=True, **prior,
        )
        for wrong in ({"legacyRegistrationMigrated": False}, {release.WINDOWS_LEGACY_PRIOR_FIELDS[1]: None}):
            invalid = self.write_reboot_report("legacy-invalid.json", **{**evidence_fields, **wrong})
            with self.subTest(report=wrong), self.assertRaisesRegex(ValueError, "verified legacy migration"):
                release.load_detection_evidence(self.candidate, [invalid], files, VERSION)
        reboot = self.write_reboot_report("legacy-qualified.json", **evidence_fields)
        entry, = release.load_detection_evidence(self.candidate, [reboot], files, VERSION)
        self.assertIs(entry[release.WINDOWS_LEGACY_MIGRATION], True)
        manifest = release.encode_manifest(COMMIT, REF, files, [entry])
        self.assertEqual(json.loads(manifest)["schemaVersion"], 13)
        self.assertEqual(json.loads(manifest)["windowsDetection"], [entry])
        (self.candidate / release.MANIFEST).write_bytes(manifest)
        (self.candidate / release.SIGNATURE).write_bytes(b"inert authentication fixture")
        certificate = self.root / "legacy-approval.der"
        certificate.write_bytes(b"inert approval certificate")
        inventory = self.root / "prior-inventory.json"
        fields = {
            "schemaVersion": 3, "target": entry["target"], "version": entry["previousVersion"],
            "payloadSHA256": entry["previousPayloadSHA256"], "payloadSBOMSHA256": entry["previousPayloadSBOMSHA256"],
            "payloadPublisherSHA256": entry["previousPayloadPublisherSHA256"],
            "buildInfoSHA256": entry[release.WINDOWS_PREVIOUS_BUILD_INFO],
            "uninstallerSHA256": prior[release.WINDOWS_LEGACY_PRIOR_FIELDS[0]],
            "uninstallDataSHA256": "9" * 64,
        }
        def verify_installed(content, **options):
            inventory.write_text(json.dumps(content), encoding="utf-8")
            return self.verify(certificate, release.digest(certificate),
                               windows_upgrade_inventory=(inventory, release.digest(inventory)), **options)

        with patch.object(release, "authenticate"):
            update = verify_installed(fields)["managedUpdate"]
            approval = ",".join((
                fields["version"], fields["payloadSHA256"], fields["payloadSBOMSHA256"],
                fields["buildInfoSHA256"], fields["uninstallerSHA256"], fields["uninstallDataSHA256"],
            ))
            self.assertEqual(update["windowsSetupBaselineArgument"], "/AWUpgradeFrom=" + approval)
            self.assertEqual(update["windowsPendingApprovalSHA256"],
                             hashlib.sha256((approval + "|amd64|" + "7" * 64).encode("ascii")).hexdigest())
            with self.assertRaisesRegex(ValueError, "requires the qualified Windows uninstaller"):
                verify_installed({**fields, "uninstallerSHA256": "0" * 64})
            old_fields = {field: value for field, value in fields.items()
                          if field not in release.WINDOWS_INSTALLED_UNINSTALL_FIELDS}
            with self.assertRaisesRegex(ValueError, "independently approved endpoint uninstall-data digest"):
                verify_installed({**old_fields, "schemaVersion": 2})
            retry = {
                "resume_windows_upgrade_setup_sha256": update["installerSHA256"],
                "resume_windows_upgrade_baseline_argument": update["windowsSetupBaselineArgument"],
            }
            self.assertEqual(verify_installed(fields, **retry)["managedUpdate"], update)
            with self.assertRaisesRegex(ValueError, "lacks signed retirement evidence"):
                verify_installed(fields, require_windows_legacy_footprint_sha256="9" * 64)
            with self.assertRaisesRegex(ValueError, "differs from the original approved upgrade"):
                verify_installed({**fields, "uninstallDataSHA256": "8" * 64}, **retry)
            for revoked in (prior[release.WINDOWS_LEGACY_PRIOR_FIELDS[1]], fields["uninstallDataSHA256"]):
                with self.subTest(revoked=revoked), self.assertRaisesRegex(ValueError, "revoked"):
                    policy_pin = self.write_policy({**self.policy, "subjectSHA256": [revoked]})
                    verify_installed(fields, policy_pin=policy_pin)

    def test_signed_legacy_footprint_binds_both_inventories_before_staging(self):
        candidate_pin = "7" * 64
        previous_pin = "8" * 64
        self.add_windows_installer_property("amd64", release.WINDOWS_PAYLOAD_FINGERPRINT_PROPERTY, candidate_pin)
        files = release.inventory(self.candidate, self.subjects)
        inputs = dict(
            schemaVersion=16, installMode="upgrade", previousVersion="1.2.2-rc.1",
            previousPayloadSHA256="d" * 64, userProfilePreservedThroughUpgrade=True,
            legacyRegistrationMigrated=True, previousUninstallerSHA256="a" * 64,
            previousUninstallDataSHA256="b" * 64, legacyPackageFootprintVerified=True,
            retiredPackageFileCount=2, previousStagedPayloadSHA256=previous_pin,
            candidateStagedPayloadSHA256=candidate_pin,
        )
        for changed in ({"retiredPackageFileCount": 0}, {"retiredPackageFileCount": True},
                        {"legacyPackageFootprintVerified": False}, {"previousStagedPayloadSHA256": candidate_pin}):
            bad = self.write_reboot_report("footprint-invalid.json", **{**inputs, **changed})
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "verified prior package file retirement"):
                release.load_detection_evidence(self.candidate, [bad], files, VERSION)
        wrong_candidate = self.write_reboot_report("footprint-sbom-mismatch.json",
                                                  **{**inputs, "candidateStagedPayloadSHA256": "9" * 64})
        output = self.root / release.MANIFEST
        with self.assertRaisesRegex(ValueError, "footprint differs from the signed installer SBOM"):
            release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=[wrong_candidate])
        self.assertFalse(output.exists())
        qualified = self.write_reboot_report("footprint-qualified.json", **inputs)
        release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=[qualified])
        manifest = output.read_bytes()
        approval = json.loads(manifest)
        self.assertEqual(approval["schemaVersion"], 14)
        entry, = approval["windowsDetection"]
        self.assertEqual(entry[release.WINDOWS_FOOTPRINT_DIGESTS[0]], previous_pin)
        self.assertEqual(entry[release.WINDOWS_FOOTPRINT_DIGESTS[1]], candidate_pin)
        (self.candidate / release.MANIFEST).write_bytes(manifest)
        (self.candidate / release.SIGNATURE).write_bytes(b"inert authentication fixture")
        certificate = self.root / "legacy-footprint-approval.der"
        certificate.write_bytes(b"inert approval certificate")
        installed = self.root / "legacy-footprint-installed.json"
        installed.write_text(json.dumps({
            "schemaVersion": 3, "target": entry["target"], "version": entry["previousVersion"],
            "payloadSHA256": entry["previousPayloadSHA256"], "payloadSBOMSHA256": entry["previousPayloadSBOMSHA256"],
            "payloadPublisherSHA256": entry["previousPayloadPublisherSHA256"],
            "buildInfoSHA256": entry[release.WINDOWS_PREVIOUS_BUILD_INFO],
            "uninstallerSHA256": entry["previousUninstallerSHA256"], "uninstallDataSHA256": "1" * 64,
        }), encoding="utf-8")
        options = {"windows_upgrade_inventory": (installed, release.digest(installed))}
        with patch.object(release, "authenticate"):
            result = self.verify(certificate, release.digest(certificate),
                                 require_windows_legacy_footprint_sha256=previous_pin, **options)
            self.assertEqual(result["managedUpdate"]["windowsUpgradeDetection"]["legacyPackageFootprintVerified"], True)
            refused_stage = self.root / "refused-footprint-stage"
            refused_stage.mkdir()
            with self.assertRaisesRegex(ValueError, "lacks signed retirement evidence"):
                self.verify(certificate, release.digest(certificate), stage_directory=refused_stage,
                            require_windows_legacy_footprint_sha256="9" * 64, **options)
            self.assertFalse(list(refused_stage.iterdir()))
            for pin in (previous_pin, candidate_pin):
                revoked = self.write_policy({**self.policy, "subjectSHA256": [pin]})
                with self.subTest(revoked=pin), self.assertRaisesRegex(ValueError, "revoked"):
                    self.verify(certificate, release.digest(certificate), policy_pin=revoked, **options)

    def test_setup_baseline_claim_is_required_for_a_current_upgrade_and_rejected_for_clean_install(self):
        files = release.inventory(self.candidate, self.subjects)
        for mode, claim in (("clean", True), ("upgrade", False), ("upgrade", 1), ("upgrade", "true")):
            with self.subTest(mode=mode, claim=claim):
                prior = {} if mode == "clean" else {
                    "previousVersion": "1.2.2-rc.1", "previousPayloadSHA256": "d" * 64,
                    "userProfilePreservedThroughUpgrade": True,
                }
                evidence = self.write_reboot_report(
                    "invalid-baseline-claim.json", schemaVersion=12, installMode=mode,
                    setupUpgradeBaselineVerified=claim, **prior,
                )
                with self.assertRaisesRegex(ValueError, "Setup baseline requirement"):
                    release.load_detection_evidence(self.candidate, [evidence], files, VERSION)
        clean = self.write_reboot_report("clean-no-baseline.json", schemaVersion=12)
        entry, = release.load_detection_evidence(self.candidate, [clean], files, VERSION)
        self.assertNotIn("setupUpgradeBaselineVerified", entry)
        with self.assertRaisesRegex(ValueError, "approved prior build pins"):
            release.validate_detection([{**entry, "setupUpgradeBaselineVerified": True}], files, VERSION)
        for claim in (False, 1, "true"):
            with self.subTest(signed_claim=claim), self.assertRaisesRegex(ValueError, "Malformed"):
                release.validate_detection([{**entry, "setupUpgradeBaselineVerified": claim}], files, VERSION)

    def test_schema_13_binds_the_wrong_baseline_refusal_to_upgrade_evidence(self):
        files = release.inventory(self.candidate, self.subjects)
        field = "setupWrongBaselineRefusedWithStatePreserved"
        upgrade = {
            "installMode": "upgrade", "previousVersion": "1.2.2-rc.1", "previousPayloadSHA256": "d" * 64,
            "userProfilePreservedThroughUpgrade": True,
        }
        for inputs, claim, accepted in (
            ({}, False, True), (upgrade, True, True), ({}, True, False),
            (upgrade, False, False), (upgrade, 1, False), (upgrade, None, False),
        ):
            with self.subTest(mode=inputs.get("installMode", "clean"), claim=claim):
                evidence = self.write_reboot_report(
                    "baseline-refusal.json", schemaVersion=13, **inputs, **{field: claim},
                )
                if accepted:
                    entry, = release.load_detection_evidence(self.candidate, [evidence], files, VERSION)
                    self.assertEqual(entry["rebootEvidenceSHA256"], evidence[1])
                    self.assertEqual(entry.get(field), True if claim else None)
                    manifest = json.loads(release.encode_manifest(COMMIT, REF, files, [entry]))
                    self.assertEqual(manifest["schemaVersion"], 10)
                    self.assertEqual(manifest["windowsDetection"], [entry])
                    if claim:
                        incomplete = {key: value for key, value in entry.items() if key != "setupUpgradeBaselineVerified"}
                        with self.assertRaisesRegex(ValueError, "requires approved baseline enforcement"):
                            release.validate_detection([incomplete], files, VERSION)
                else:
                    with self.assertRaisesRegex(ValueError, "incorrect Setup baseline refusal"):
                        release.load_detection_evidence(self.candidate, [evidence], files, VERSION)

    def test_windows_publisher_requires_exact_bounded_native_report(self):
        artifact = self.root / "inert.exe"
        artifact_pin, publisher_pin = "a" * 64, "b" * 64
        expected = {
            "schemaVersion": 1, "scope": "windows-publisher-signature",
            "artifactSHA256": artifact_pin, "publisherCertificateSHA256": publisher_pin,
            "embeddedSignatureVerified": True, "timestampPresent": True,
        }

        def system_directory(buffer, maximum):
            directory = str(self.root / "System32")
            self.assertGreater(maximum, len(directory))
            buffer.value = directory
            return len(directory)

        def run(arguments, **kwargs):
            shell = self.root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            script = Path(release.__file__).resolve().with_name("verify-windows-installer-publisher.ps1")
            self.assertEqual(arguments, [shell, "-NoProfile", "-NonInteractive", "-File", script,
                                         "-Artifact", artifact, "-ArtifactSHA256", artifact_pin,
                                         "-PublisherCertificateSHA256", publisher_pin])
            self.assertTrue(kwargs["check"])
            self.assertEqual(kwargs["timeout"], 90)
            kwargs["stdout"].write(content)

        with patch.object(release.ctypes, "windll", create=True) as windows, patch.object(release.subprocess, "run", side_effect=run):
            windows.kernel32.GetSystemDirectoryW.side_effect = system_directory
            content = json.dumps(expected).encode()
            release.check_windows_publisher(artifact, artifact_pin, publisher_pin)
            for report in ({**expected, "artifactSHA256": "0" * 64},
                           {**expected, "publisherCertificateSHA256": "0" * 64},
                           {**expected, "embeddedSignatureVerified": 1},
                           {**expected, "schemaVersion": True},
                           {**expected, "timestampPresent": False},
                           {**expected, "extra": "fixture"}):
                content = json.dumps(report).encode()
                with self.assertRaisesRegex(ValueError, "report differs"):
                    release.check_windows_publisher(artifact, artifact_pin, publisher_pin)
            for content in (b"", b" " * 4097, b'{"schemaVersion":1,"schemaVersion":1}'):
                with self.assertRaises(ValueError):
                    release.check_windows_publisher(artifact, artifact_pin, publisher_pin)

    def test_prepare_closes_target_and_subject_inventory(self):
        output = self.root / release.MANIFEST
        self.assertEqual(len(self.subjects), 12)
        self.assertEqual({target for target, _ in self.subjects.values()},
                         {"windows/amd64", "windows/arm64", "darwin/amd64", "darwin/arm64"})
        release.prepare(self.candidate, output, COMMIT, REF)
        original = output.read_bytes()
        with self.assertRaises(FileExistsError):
            release.prepare(self.candidate, output, COMMIT, REF)
        self.assertEqual(output.read_bytes(), original)
        for ref in ("refs/heads/main", "refs/tags/v1.2", "refs/tags/v1.2.3-01"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                release.release_subjects(COMMIT, ref)
        with self.assertRaises(ValueError):
            release.prepare(self.candidate, self.candidate / release.MANIFEST, COMMIT, REF)
        (self.candidate / "extra.exe").write_bytes(b"unexpected")
        with self.assertRaises(ValueError):
            release.prepare(self.candidate, output, COMMIT, REF)

    def windows_lifecycle_reports(self, pins, *, schema=14):
        evidence = {}
        for arch in ("amd64", "arm64"):
            self.add_windows_installer_property(arch, release.WINDOWS_BUILD_INFO_PROPERTY, "6" * 64)
            evidence[arch, "clean"] = self.write_reboot_report(
                f"{arch}-clean.json", architecture=arch, schemaVersion=schema, **pins)
            evidence[arch, "upgrade"] = self.write_reboot_report(
                f"{arch}-upgrade.json", architecture=arch, schemaVersion=schema, installMode="upgrade",
                previousVersion="1.2.2-rc.1", previousPayloadSHA256="d" * 64,
                userProfilePreservedThroughUpgrade=True, downgradeRequested=True,
                downgradeRefused=True, downgradeStatePreserved=True,
                previousSetupSHA256="8" * 64, previousPublisherSHA256="9" * 64, **pins,
            )
        return evidence

    def lifecycle_source_fixture(self):
        top = Path(__file__).resolve().parents[1]
        source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=top, text=True, timeout=15).strip()
        sources = release.windows_lifecycle_sources(source)
        self.assertEqual(sources.keys(), release.WINDOWS_LIFECYCLE_SOURCES.keys())
        pins = {field: hashlib.sha256(content).hexdigest() for field, content in sources.items()}
        for sidecar in self.candidate.glob("*.cdx.json"):
            document = json.loads(sidecar.read_bytes())
            for component in [document["metadata"]["component"], *document["components"]]:
                for prop in component.get("properties", []):
                    if prop["name"] == "accessweaver:source-commit":
                        prop["value"] = source
            sidecar.write_text(json.dumps(document), encoding="utf-8")
        return source, pins

    def test_prepare_can_require_windows_lifecycle_coverage(self):
        output = self.root / release.MANIFEST
        source, pins = self.lifecycle_source_fixture()
        evidence = self.windows_lifecycle_reports(pins)
        for missing in evidence:
            provided = [item for path, item in evidence.items() if path != missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "Missing Windows lifecycle evidence"):
                release.prepare(self.candidate, output, source, REF, windows_reboot_evidence=provided,
                                require_windows_lifecycle=True)
        arm_upgrade, _ = evidence["arm64", "upgrade"]
        incomplete = json.loads(arm_upgrade.read_bytes())
        without_downgrade = {**incomplete, "downgradeRequested": False, "downgradeRefused": False,
                             "downgradeStatePreserved": False, "previousSetupSHA256": "", "previousPublisherSHA256": ""}
        for record, message in (
            (without_downgrade, "downgrade refusal"),
            ({**incomplete, "publisherSHA256": "0" * 64}, "disagrees on candidate publisher certificates"),
            ({**incomplete, "payloadPublisherSHA256": "0" * 64}, "disagrees on candidate publisher certificates"),
            ({key: value for key, value in {**incomplete, "schemaVersion": 12}.items()
              if key not in (release.WINDOWS_SETUP_WRONG_BASELINE, release.WINDOWS_RESTORATION_JOURNAL)}, "Setup baseline refusal"),
            ({key: value for key, value in {**incomplete, "schemaVersion": 13}.items()
              if key != release.WINDOWS_RESTORATION_JOURNAL}, "requires a restoration journal digest"),
            *[({**incomplete, field: "0" * 64}, "differs from the approved source scripts") for field in pins],
        ):
            arm_upgrade.write_text(json.dumps(record), encoding="utf-8")
            provided = {**evidence, ("arm64", "upgrade"): (arm_upgrade, release.digest(arm_upgrade))}
            with self.subTest(record=message), self.assertRaisesRegex(ValueError, message):
                release.prepare(self.candidate, output, source, REF, windows_reboot_evidence=list(provided.values()),
                                require_windows_lifecycle=True)
            self.assertFalse(output.exists())
        arm_upgrade.write_text(json.dumps(incomplete), encoding="utf-8")
        evidence["arm64", "upgrade"] = (arm_upgrade, release.digest(arm_upgrade))
        release.prepare(self.candidate, output, source, REF, windows_reboot_evidence=list(evidence.values()),
                        require_windows_lifecycle=True)
        manifest = json.loads(output.read_bytes())
        self.assertEqual(manifest["schemaVersion"], 12)
        self.assertEqual(len(manifest["windowsDetection"]), 4)
        for entry in manifest["windowsDetection"]:
            self.assertEqual({field: entry[field] for field in pins}, pins)

    def test_prepare_rejects_mismatched_or_malformed_sboms(self):
        output = self.root / release.MANIFEST
        name = f"accessweaver-{VERSION}-windows-amd64-setup.exe.cdx.json"
        sidecar = self.candidate / name
        original = sidecar.read_text(encoding="utf-8")
        for field, value in (("source-commit", "b" * 40), ("source-state", "modified"),
                             ("target-os", "darwin"), ("target-arch", "arm64")):
            document = json.loads(original)
            root = document["metadata"]["component"]
            prop = next(prop for prop in root["properties"] if prop["name"] == "accessweaver:" + field)
            prop["value"] = value
            sidecar.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "SBOM build identity"):
                release.prepare(self.candidate, output, COMMIT, REF)
            self.assertFalse(output.exists())

        for edit, message in (
            (lambda doc: doc["metadata"]["component"].update(version="1.2.3"), "SBOM version"),
            (lambda doc: doc["metadata"]["component"]["hashes"][0].update(content="0" * 64), "artifact bytes"),
            (lambda doc: doc["components"][0]["hashes"][0].update(content="0" * 64), "signed payload SBOM"),
            (lambda doc: doc["dependencies"][0]["dependsOn"].append("missing"), "Dangling SBOM dependency"),
            (lambda doc: doc.update(metadata=None), "Malformed signed release SBOM"),
        ):
            document = json.loads(original)
            edit(document)
            sidecar.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                release.prepare(self.candidate, output, COMMIT, REF)
            self.assertFalse(output.exists())

        sidecar.write_text(original.replace('"bomFormat":', '"bomFormat": "CycloneDX", "bomFormat":', 1),
                           encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            release.prepare(self.candidate, output, COMMIT, REF)
        self.assertFalse(output.exists())

    def test_prepare_rejects_mismatched_macos_controller_digest(self):
        output = self.root / release.MANIFEST
        sidecar = self.candidate / f"accessweaver-{VERSION}-darwin-arm64-deployment-experimental.pkg.cdx.json"
        document = json.loads(sidecar.read_bytes())
        controller = next(entry for entry in document["components"]
                          if entry["bom-ref"] == "bundle-file:Contents/MacOS/accessweaver")
        controller["hashes"][0]["content"] = "0" * 64
        sidecar.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "controller differs from the sealed package executable"):
            release.prepare(self.candidate, output, COMMIT, REF)
        self.assertFalse(output.exists())

    def test_prepare_binds_windows_reboot_build_metadata_to_the_installer_sbom(self):
        output = self.root / release.MANIFEST
        self.add_windows_installer_property("amd64", release.WINDOWS_BUILD_INFO_PROPERTY, "6" * 64)
        for pin in ("a" * 64, "6" * 64):
            evidence = self.write_reboot_report("bound.json", schemaVersion=11, buildInfoSHA256=pin)
            if pin != "6" * 64:
                with self.assertRaisesRegex(ValueError, "differs from the signed installer SBOM"):
                    release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=[evidence])
                self.assertFalse(output.exists())
            else:
                release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=[evidence])
                entry, = json.loads(output.read_bytes())["windowsDetection"]
                self.assertEqual(entry["buildInfoSHA256"], pin)
                self.assertEqual(entry["detectorSHA256"], "1" * 64)

        self.add_windows_installer_property("arm64", release.WINDOWS_BUILD_INFO_PROPERTY, 1)
        with self.assertRaisesRegex(ValueError, "Malformed Windows installer SBOM build metadata"):
            release.prepare(self.candidate, self.root / "unused" / release.MANIFEST, COMMIT, REF)

    def test_prepare_rejects_conflicting_windows_build_metadata_across_install_paths(self):
        output = self.root / release.MANIFEST
        clean = self.write_reboot_report("clean.json", schemaVersion=11, buildInfoSHA256="6" * 64)
        upgrade_args = {
            "schemaVersion": 11, "installMode": "upgrade",
            "previousVersion": "1.2.2-rc.1", "previousPayloadSHA256": "d" * 64,
            "userProfilePreservedThroughUpgrade": True,
        }
        upgrade = self.write_reboot_report("upgrade.json", **upgrade_args, buildInfoSHA256="7" * 64)
        with self.assertRaisesRegex(ValueError, "reboot reports disagree on candidate build metadata"):
            release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=[clean, upgrade])
        self.assertFalse(output.exists())

        upgrade = self.write_reboot_report("upgrade.json", **upgrade_args, buildInfoSHA256="6" * 64)
        release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=[clean, upgrade])
        entries = json.loads(output.read_bytes())["windowsDetection"]
        self.assertEqual([entry["buildInfoSHA256"] for entry in entries], ["6" * 64, "6" * 64])

    def test_prepare_rejects_conflicting_macos_detector_metadata(self):
        output = self.root / release.MANIFEST
        path = self.candidate / f"accessweaver-{VERSION}-darwin-amd64-deployment-experimental.pkg.cdx.json"
        original = path.read_bytes()
        for reference, field, value, message in (
            ("helper:application", "version", "1.2.3", "detector build identity"),
            ("helper:application", "hashes", [{"alg": "SHA-256", "content": "x" * 64}], "detector digest"),
            ("helper:application", "hashes", [{"alg": "SHA-1", "content": "1" * 64}], "detector digest"),
            ("script-file:preinstall", "hashes", [{"alg": "SHA-256", "content": "0" * 64}], "script differs"),
            ("script-file:postinstall", "name", "preinstall", "script differs"),
            ("detached-file:INSTALL-MANIFEST.json", "name", "OTHER.json", "deployment manifest digest"),
            ("detached-file:INSTALL-MANIFEST.json", "hashes", [{"alg": "SHA-1", "content": "1" * 64}], "deployment manifest digest"),
        ):
            document = json.loads(original)
            entry = next(entry for entry in document["components"] if entry["bom-ref"] == reference)
            entry[field] = value
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(reference=reference, field=field), self.assertRaisesRegex(ValueError, message):
                release.prepare(self.candidate, output, COMMIT, REF)
            self.assertFalse(output.exists())

    def test_prepare_rejects_untrusted_or_incomplete_windows_detection_evidence(self):
        output = self.root / release.MANIFEST
        valid = self.write_reboot_report("valid.json")
        tampered = self.write_reboot_report("tampered.json")
        tampered[0].write_bytes(tampered[0].read_bytes() + b" ")
        invalid = [
            (tampered,),
            (valid, valid),
            (self.write_reboot_report("incomplete.json", uninstallerIdentityVerified=1),),
            (self.write_reboot_report("wrong-setup.json", setupSHA256="d" * 64),),
            (self.write_reboot_report("wrong-payload.json", payloadSHA256="d" * 64),),
            (self.write_reboot_report("wrong-version.json", version="1.2.3"),),
            (self.write_reboot_report("bad-baseline.json", previousVersion="1.2.2"),),
            (self.write_reboot_report("bad-digest.json", uninstallerSHA256="c" * 63),),
            (self.write_reboot_report("wrong-sbom.json", schemaVersion=6, payloadSBOMSHA256="d" * 64),),
            (self.write_reboot_report("missing-payload-publisher.json", schemaVersion=9, payloadPublisherSHA256=None),),
            (self.write_reboot_report("invalid-payload-publisher.json", schemaVersion=9, payloadPublisherSHA256="bad"),),
            (self.write_reboot_report("unverified-build-info.json", schemaVersion=10, installedBuildInfoVerified=1),),
            (self.write_reboot_report("missing-build-info.json", schemaVersion=10, buildInfoSHA256=None),),
            (self.write_reboot_report("bad-build-info.json", schemaVersion=10, buildInfoSHA256="bad"),),
            (self.write_reboot_report("sbom-unverified.json", schemaVersion=6, installedPayloadSBOMVerified=1),),
            (self.write_reboot_report("publisher-unverified.json", schemaVersion=6, installedPayloadPublisherVerified=False),),
            (self.write_reboot_report("profile-read-failed.json", schemaVersion=7,
                                      userProfileOpenedByInstalledController=False),),
            (self.write_reboot_report("profile-read-untyped.json", schemaVersion=7,
                                      userProfileOpenedByInstalledController=1),),
            (self.write_reboot_report("partial-upgrade.json", installMode="upgrade",
                                      previousVersion="1.2.2", previousPayloadSHA256="d" * 64),),
            (self.write_reboot_report("prior-trust-on-clean.json", schemaVersion=8,
                                      previousPayloadTrustVerified=True),),
            (self.write_reboot_report("unverified-prior-publisher.json", schemaVersion=8,
                                      installMode="upgrade", previousVersion="1.2.2", previousPayloadSHA256="d" * 64,
                                      userProfilePreservedThroughUpgrade=True, previousPayloadTrustVerified=False),),
            (self.write_reboot_report("missing-prior-sbom.json", schemaVersion=8,
                                      installMode="upgrade", previousVersion="1.2.2", previousPayloadSHA256="d" * 64,
                                      userProfilePreservedThroughUpgrade=True, previousPayloadSBOMSHA256=""),),
            (self.write_reboot_report("missing-prior-publisher.json", schemaVersion=8,
                                      installMode="upgrade", previousVersion="1.2.2", previousPayloadSHA256="d" * 64,
                                      userProfilePreservedThroughUpgrade=True, previousPayloadPublisherSHA256=""),),
            (self.write_reboot_report("newer-baseline.json", schemaVersion=8,
                                      installMode="upgrade", previousVersion="1.2.3", previousPayloadSHA256="d" * 64,
                                      userProfilePreservedThroughUpgrade=True),),
            (self.write_reboot_report("equal-precedence-baseline.json", schemaVersion=8,
                                      installMode="upgrade", previousVersion="1.2.3-rc.1+build", previousPayloadSHA256="d" * 64,
                                      userProfilePreservedThroughUpgrade=True),),
            (self.write_reboot_report("downgrade.json", downgradeRequested=True,
                                      downgradeRefused=True, downgradeStatePreserved=True),),
            (self.write_reboot_report("unused-downgrade.json", previousSetupSHA256="a" * 64),),
        ]
        duplicate = self.root / "duplicate.json"
        duplicate.write_bytes(valid[0].read_bytes().replace(b'"passed": true', b'"passed": false, "passed": true'))
        invalid.append(((duplicate, release.digest(duplicate)),))
        for evidence in invalid:
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=evidence)
            self.assertFalse(output.exists())

    def test_current_windows_reboot_report_requires_complete_consistent_evidence(self):
        path, _ = self.write_reboot_report("current.json", schemaVersion=11)
        report = json.loads(path.read_bytes())
        files = release.inventory(self.candidate, self.subjects)

        def load(record):
            path.write_text(json.dumps(record), encoding="utf-8")
            return release.load_detection_evidence(self.candidate, [(path, release.digest(path))], files, VERSION)

        for code, restart in ((0, False), (3010, True)):
            with self.subTest(code=code):
                entry, = load({**report, "setupExitCode": code, "setupRequestedRestart": restart})
                self.assertEqual(entry["buildInfoSHA256"], report["buildInfoSHA256"])
        for field in (*release.REBOOT_REPORT_DIGESTS, "runID", "setupExitCode", "setupRequestedRestart"):
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, "current report schema"):
                load({name: value for name, value in report.items() if name != field})
        for overrides in (
            {"runID": "invalid"}, {"fixtureSHA256": 123}, {"registrationSHA256": "a" * 63},
            {"setupExitCode": 1641}, {"setupExitCode": False}, {"setupExitCode": 3010},
            {"setupRequestedRestart": 0}, {"userProfilePreservedThroughUpgrade": True},
            {"unexpected": "private baseline field"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                load({**report, **overrides})

    def test_current_windows_reboot_report_binds_restoration_journal(self):
        files = release.inventory(self.candidate, self.subjects)
        field = release.WINDOWS_RESTORATION_JOURNAL
        path, pin = self.write_reboot_report("uninstall-journal.json", schemaVersion=14)
        original = json.loads(path.read_bytes())
        entry, = release.load_detection_evidence(self.candidate, [(path, pin)], files, VERSION)
        self.assertEqual(entry[field], original[field])
        self.assertEqual(json.loads(release.encode_manifest(COMMIT, REF, files, [entry]))["schemaVersion"], 12)
        for invalid in ({key: value for key, value in original.items() if key != field},
                        {**original, field: True}, {**original, field: "0" * 63},
                        {**original, "schemaVersion": 13}):
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.subTest(schema=invalid["schemaVersion"], digest=invalid.get(field)), self.assertRaises(ValueError):
                release.load_detection_evidence(self.candidate, [(path, release.digest(path))], files, VERSION)

    def test_downgrade_refusal_evidence_requires_both_distinct_prior_setup_pins(self):
        files = release.inventory(self.candidate, self.subjects)
        setup = next(item for item in files if item["target"] == "windows/amd64" and item["role"] == "installer")
        upgrade = {
            "schemaVersion": 9, "installMode": "upgrade", "previousVersion": "1.2.2-rc.1",
            "previousPayloadSHA256": "d" * 64, "userProfilePreservedThroughUpgrade": True,
            "downgradeRequested": True, "downgradeRefused": True, "downgradeStatePreserved": True,
            "previousSetupSHA256": "8" * 64, "previousPublisherSHA256": "9" * 64,
        }
        for override in (
            {"previousSetupSHA256": None},
            {"previousPublisherSHA256": None},
            {"previousPublisherSHA256": "Z" * 64},
            {"previousSetupSHA256": setup["sha256"]},
            {"downgradeStatePreserved": False},
        ):
            report = self.write_reboot_report("invalid-downgrade.json", **{**upgrade, **override})
            with self.subTest(override=override), self.assertRaises(ValueError):
                release.load_detection_evidence(self.candidate, [report], files, VERSION)
        report = self.write_reboot_report("downgrade.json", **upgrade)
        entry, = release.load_detection_evidence(self.candidate, [report], files, VERSION)
        for omitted in release.WINDOWS_DOWNGRADE_FIELDS:
            incomplete = {key: value for key, value in entry.items() if key != omitted}
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, "downgrade evidence"):
                release.validate_detection([incomplete], files, VERSION)
        manifest = json.loads(release.encode_manifest(COMMIT, REF, files, [entry]))
        self.assertEqual(manifest["schemaVersion"], 5)
        self.assertEqual(manifest["windowsDetection"], [entry])

    def test_managed_update_orders_versions_and_requires_an_exact_target(self):
        files = release.inventory(self.candidate, self.subjects)
        for current, candidate, decision in (
            ("1.0.0", "2.0.0-rc.1", "channel-mismatch"),
            ("1.0.0-rc.2", "1.0.0-rc.10", "upgrade"),
            ("1.0.0-rc.2", "1.0.0-rc.two", "upgrade"),
            ("1.0.0-rc.2", "1.0.0-rc", "older"),
            ("1.0.0-rc.2", "1.0.0", "upgrade"),
            ("1.2.3+local", "1.2.3+release", "current"),
            ("2.0.0", "1.99.0", "older"),
        ):
            with self.subTest(current=current, candidate=candidate):
                result = release.managed_update(files, "windows/arm64", current, candidate)
                self.assertEqual(result["decision"], decision)
                self.assertIs(result["updateAvailable"], decision == "upgrade")
        for target, version in (("linux/amd64", "1.0.0"), ("darwin/arm64", "01.0.0"),
                                ("darwin/arm64", "1.0.0-01")):
            with self.subTest(target=target, version=version), self.assertRaises(ValueError):
                release.managed_update(files, target, version, VERSION)

    def test_real_cms_windows_lifecycle_gate(self):
        self.assertIsNotNone(OPENSSL, "OpenSSL is required for CMS signing fixtures")

        def openssl(*arguments):
            subprocess.run([OPENSSL, *map(str, arguments)], check=True, timeout=30,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        key = self.root / "lifecycle.key"
        pem = self.root / "lifecycle.pem"
        cert = self.root / "lifecycle.cer"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
                "-subj", "/CN=Disposable Windows lifecycle fixture", "-keyout", key, "-out", pem)
        openssl("x509", "-in", pem, "-outform", "DER", "-out", cert)
        source, pins = self.lifecycle_source_fixture()
        evidence = self.windows_lifecycle_reports(pins)
        prepared = self.root / release.MANIFEST
        manifest = self.candidate / release.MANIFEST
        signature = self.candidate / release.SIGNATURE
        for complete, bind_sources in ((False, False), (True, False), (True, True)):
            if prepared.exists():
                prepared.unlink()
            if manifest.exists():
                manifest.unlink()
                signature.unlink()
            provided = list(evidence.values()) if complete else [evidence["amd64", "clean"]]
            release.prepare(self.candidate, prepared, source, REF, windows_reboot_evidence=provided,
                            require_windows_lifecycle=bind_sources)
            shutil.copyfile(prepared, manifest)
            openssl("cms", "-sign", "-binary", "-md", "sha256", "-in", manifest,
                    "-signer", pem, "-inkey", key, "-outform", "DER", "-out", signature)
            pin = release.digest(cert)
            if bind_sources:
                report = self.verify(cert, pin, source, require_windows_lifecycle=True)
                self.assertIs(report["windowsLifecycleEvidenceVerified"], True)
                self.assertIs(report["productionQualificationComplete"], False)
                self.assertEqual(report["schemaVersion"], 12)
                self.assertIs(report["windowsRestorationJournalEvidenceVerified"], True)
                for arch, mode in (("amd64", "clean"), ("arm64", "upgrade")):
                    evidence_pin = evidence[arch, mode][1]
                    selection, = [entry for entry in report["windowsDetection"]
                                  if entry["target"] == f"windows/{arch}" and entry["rebootEvidenceSHA256"] == evidence_pin]
                    output = self.root / f"intune-{arch}.ps1"
                    arguments = [
                        "signed_release_manifest.py", "verify", str(self.candidate),
                        "--approval-certificate", str(cert), "--approval-certificate-sha256", pin,
                        "--revocation-list", str(self.revocation_list), "--revocation-list-sha256", self.policy_pin,
                        "--source-commit", source, "--source-ref", REF,
                        "--write-intune-detector", arch, evidence_pin, str(output),
                    ]
                    stdout = io.StringIO()
                    with patch.object(sys, "argv", arguments), redirect_stdout(stdout):
                        self.assertEqual(release.main(), 0)
                    assignment = json.loads(stdout.getvalue())["windowsIntuneDetector"]
                    self.assertEqual(assignment, {
                        "target": f"windows/{arch}", "version": VERSION, "file": output.name,
                        "rebootEvidenceSHA256": evidence_pin, "sourceDetectorSHA256": pins["detectorSHA256"],
                        "scriptSHA256": release.digest(output),
                    })
                    approved_template = release.windows_lifecycle_sources(source)[release.WINDOWS_DETECTOR]
                    expected = approved_template.removeprefix(b"\xef\xbb\xbf")
                    for name, value in {
                        "Version": VERSION, "Architecture": arch, "PayloadSHA256": selection["payloadSHA256"],
                        "UninstallerSHA256": selection["uninstallerSHA256"],
                        "PayloadSBOMSHA256": selection["payloadSBOMSHA256"],
                        "PayloadPublisherSHA256": selection["payloadPublisherCertificateSHA256"],
                        "BuildInfoSHA256": selection["buildInfoSHA256"],
                    }.items():
                        expected = expected.replace(f"[string]${name} = ''".encode(),
                                                    f"[string]${name} = '{value}'".encode(), 1)
                    self.assertEqual(output.read_bytes(), b"\xef\xbb\xbf" + expected)
                    with self.assertRaises(FileExistsError):
                        self.verify(cert, pin, source, intune_detection=(arch, evidence_pin, output))
                    self.assertEqual(output.read_bytes(), b"\xef\xbb\xbf" + expected)
                refused = self.root / "refused.ps1"
                amd64_pin = evidence["amd64", "clean"][1]
                detector_directory = self.root / "detector-output"
                detector_directory.mkdir()
                altered = detector_directory / "altered.ps1"
                native_publish = release.publish_staged_installer

                def change_published_detector(staged, destination):
                    if destination == altered:
                        if os.name == "nt":
                            moved = detector_directory.with_name("moved-detector-output")
                            with self.assertRaises(PermissionError):
                                detector_directory.rename(moved)
                        native_publish(staged, destination)
                        valid = destination.read_bytes()
                        destination.write_bytes(b"!" + valid[1:])
                    else:
                        native_publish(staged, destination)

                with patch.object(release, "publish_staged_installer", side_effect=change_published_detector):
                    with self.assertRaisesRegex(ValueError, "Intune detector differs from the approved digest"):
                        self.verify(cert, pin, source, intune_detection=("amd64", amd64_pin, altered))
                with self.assertRaisesRegex(ValueError, "No unique signed Windows detection entry"):
                    self.verify(cert, pin, source, intune_detection=("arm64", amd64_pin, refused))
                with self.assertRaisesRegex(ValueError, "outside the release directory"):
                    self.verify(cert, pin, source, intune_detection=("amd64", amd64_pin, self.candidate / refused.name))
                with patch.object(release, "windows_lifecycle_sources", return_value={release.WINDOWS_DETECTOR: b"other detector"}):
                    with self.assertRaisesRegex(ValueError, "differs from the qualified Git source"):
                        self.verify(cert, pin, source, intune_detection=("amd64", amd64_pin, refused))
                revoked = self.write_policy({**self.policy, "subjectSHA256": [amd64_pin]})
                with self.assertRaisesRegex(ValueError, "revoked"):
                    self.verify(cert, pin, source, policy_pin=revoked, intune_detection=("amd64", amd64_pin, refused))
                self.assertFalse(refused.exists())
                self.write_policy(self.policy)
                journal_field = release.WINDOWS_RESTORATION_JOURNAL
                restoration_pin = report["windowsDetection"][0][journal_field]
                with patch.object(release.sys, "platform", "linux"):
                    with self.assertRaisesRegex(ValueError, "requires a Windows host"):
                        self.verify(cert, pin, source, verify_lifecycle_publishers=True)

                inspected = []

                def native(artifact, artifact_pin, publisher_pin, *, script):
                    self.assertEqual(release.digest(artifact), artifact_pin)
                    self.assertEqual(release.digest(script), pins["publisherVerifierSHA256"])
                    self.assertEqual(release.digest(script.with_name("windows-installer-common.ps1")), pins["commonSHA256"])
                    self.assertNotEqual(artifact.parent, self.candidate)
                    inspected.append((artifact.name, publisher_pin))

                with patch.object(release.sys, "platform", "win32"), patch.object(release, "check_windows_publisher", side_effect=native):
                    native_report = self.verify(cert, pin, source, verify_lifecycle_publishers=True)
                self.assertIs(native_report["windowsLifecycleEvidenceVerified"], True)
                self.assertIs(native_report["windowsLifecyclePublishersVerified"], True)
                self.assertIs(native_report["nativePublisherChecksPerformed"], True)
                self.assertEqual(len(inspected), 4)
                self.assertEqual(set(inspected), {
                    (f"accessweaver-{VERSION}-windows-{arch}{suffix}", signer * 64)
                    for arch in ("amd64", "arm64") for suffix, signer in (("-setup.exe", "b"), (".exe", "7"))
                })
                if os.name == "nt":
                    scripts = self.root / "approved-scripts"
                    scripts.mkdir()
                    approved_sources = release.windows_lifecycle_sources(source)
                    for field, path in release.WINDOWS_LIFECYCLE_SOURCES.items():
                        (scripts / Path(path).name).write_bytes(approved_sources[field])
                    staging = self.root / "managed-windows"
                    staging.mkdir()
                    staged_options = {
                        "target": "windows/arm64", "current_version": "1.2.2-rc.1",
                        "current_payload_sha256": "d" * 64, "current_payload_sbom_sha256": "1" * 64,
                        "current_payload_publisher_sha256": "2" * 64, "current_build_info_sha256": "5" * 64,
                        "windows_publisher": "b" * 64, "windows_payload_publisher": "7" * 64,
                        "stage_directory": staging,
                    }

                    def native_managed(artifact, artifact_pin, publisher_pin, *, script):
                        self.assertEqual(script.parent, scripts)
                        native(artifact, artifact_pin, publisher_pin, script=script)
                        for filename in ("windows-installer-common.ps1", "verify-windows-installer-publisher.ps1"):
                            with self.assertRaises(OSError), (scripts / filename).open("r+b"):
                                self.fail("Approved publisher script could be written during verification")

                    with patch.object(release, "__file__", str(scripts / "signed_release_manifest.py")), \
                            patch.object(release, "check_windows_publisher", side_effect=native_managed) as managed:
                        for field in ("publisherVerifierSHA256", "commonSHA256"):
                            script_path = scripts / Path(release.WINDOWS_LIFECYCLE_SOURCES[field]).name
                            original = script_path.read_bytes()
                            script_path.write_bytes(original + b" changed")
                            try:
                                with self.subTest(field=field), self.assertRaises(ValueError):
                                    self.verify(cert, pin, source, **staged_options)
                                managed.assert_not_called()
                                self.assertEqual(list(staging.iterdir()), [])
                            finally:
                                script_path.write_bytes(original)
                        update = self.verify(cert, pin, source, **staged_options)["managedUpdate"]
                        self.assertTrue(update["installerStaged"])
                        self.assertEqual(managed.call_count, 2)
                        self.assertEqual(release.digest(staging / update["installer"]), update["installerSHA256"])
                for revoked_pin in (evidence["arm64", "upgrade"][1], pins["fixtureSHA256"], "7" * 64, restoration_pin):
                    revoked = self.write_policy({**self.policy, "subjectSHA256": [revoked_pin]})
                    with self.assertRaisesRegex(ValueError, "revoked"):
                        self.verify(cert, pin, source, policy_pin=revoked, require_windows_lifecycle=True)
                self.write_policy(self.policy)
                files = release.inventory(self.candidate, self.subjects)
                entries = json.loads(manifest.read_bytes())["windowsDetection"]
                for legacy in (False, True):
                    partial = [entry.copy() for entry in entries]
                    for entry in partial if legacy else partial[:1]:
                        del entry[journal_field]
                    manifest.write_bytes(release.encode_manifest(source, REF, files, partial))
                    openssl("cms", "-sign", "-binary", "-md", "sha256", "-in", manifest,
                            "-signer", pem, "-inkey", key, "-outform", "DER", "-out", signature)
                    if legacy:
                        legacy_report = self.verify(cert, pin, source, require_windows_lifecycle=True)
                        self.assertEqual(legacy_report["schemaVersion"], 11)
                        self.assertIs(legacy_report["windowsLifecycleEvidenceVerified"], True)
                        self.assertNotIn("windowsRestorationJournalEvidenceVerified", legacy_report)
                    else:
                        with self.assertRaisesRegex(ValueError, "requires a restoration journal digest"):
                            self.verify(cert, pin, source, require_windows_lifecycle=True)
                entries[0]["fixtureSHA256"] = "0" * 64
                manifest.write_bytes(release.encode_manifest(source, REF, files, entries))
                openssl("cms", "-sign", "-binary", "-md", "sha256", "-in", manifest,
                        "-signer", pem, "-inkey", key, "-outform", "DER", "-out", signature)
                with self.assertRaisesRegex(ValueError, "differs from the approved source scripts"):
                    self.verify(cert, pin, source, require_windows_lifecycle=True)
            else:
                message = "differs from the approved source scripts" if complete else "Missing Windows lifecycle evidence"
                with self.assertRaisesRegex(ValueError, message):
                    self.verify(cert, pin, source, require_windows_lifecycle=True)
                with patch.object(release.sys, "platform", "win32"), patch.object(release, "check_windows_publisher") as native:
                    with self.assertRaisesRegex(ValueError, message):
                        self.verify(cert, pin, source, verify_lifecycle_publishers=True)
                    native.assert_not_called()
                self.assertNotIn("windowsLifecycleEvidenceVerified", self.verify(cert, pin, source))

    def test_revoked_approval_cannot_stage_even_after_resigning(self):
        self.assertIsNotNone(OPENSSL, "OpenSSL is required for CMS signing fixtures")

        def openssl(*arguments):
            subprocess.run([OPENSSL, *map(str, arguments)], check=True, timeout=30,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        key, pem, der = (self.root / name for name in ("approval.key", "approval.pem", "approval.cer"))
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
                "-subj", "/CN=Disposable release control", "-keyout", key, "-out", pem)
        openssl("x509", "-in", pem, "-outform", "DER", "-out", der)
        signer_pin = release.digest(der)
        initial = self.root / release.MANIFEST
        reviewed = self.root / "reviewed"
        reviewed.mkdir()
        replacement = reviewed / release.MANIFEST
        evidence = self.write_reboot_report("replacement-reboot.json")
        release.prepare(self.candidate, initial, COMMIT, REF)
        release.prepare(self.candidate, replacement, COMMIT, REF, windows_reboot_evidence=[evidence])
        manifest = self.candidate / release.MANIFEST
        signature = self.candidate / release.SIGNATURE

        def sign(approval, *options):
            shutil.copyfile(approval, manifest)
            openssl("cms", "-sign", "-binary", "-md", "sha256", "-in", manifest, "-signer", pem,
                    "-inkey", key, "-outform", "DER", "-out", signature, *options)

        staging = self.root / "staging"
        staging.mkdir()
        update = {"current_version": "1.2.2-alpha", "target": "windows/amd64", "stage_directory": staging}
        sign(initial)
        original_signature = release.digest(signature)
        accepted = self.verify(der, signer_pin, **update)
        installer = staging / accepted["managedUpdate"]["installer"]
        installer_digest = release.digest(installer)
        rejected_manifest = release.digest(initial)
        now = datetime.now(timezone.utc)
        timestamp = "%Y-%m-%dT%H:%M:%SZ"
        revoked = self.write_policy({
            **self.policy, "schemaVersion": 2, "sequence": 2, "subjectSHA256": [rejected_manifest],
            "issuedAt": (now - timedelta(minutes=1)).strftime(timestamp),
            "expiresAt": (now + timedelta(minutes=5)).strftime(timestamp),
        })
        approved_policy = {"policy_pin": revoked, "minimum_revocation_sequence": 2}
        with self.assertRaisesRegex(ValueError, "Signed release approval manifest is revoked"):
            self.verify(der, signer_pin, **approved_policy, **update)
        sign(initial, "-noattr")
        self.assertNotEqual(release.digest(signature), original_signature)
        with self.assertRaisesRegex(ValueError, "Signed release approval manifest is revoked"):
            self.verify(der, signer_pin, **approved_policy, **update)
        self.assertEqual(list(staging.iterdir()), [installer])
        self.assertEqual(release.digest(installer), installer_digest)

        installer.unlink()
        with self.assertRaisesRegex(ValueError, "Signed release approval manifest is revoked"):
            self.verify(der, signer_pin, **approved_policy, **update)
        self.assertEqual(list(staging.iterdir()), [])

        sign(replacement)
        recovered = self.verify(der, signer_pin, **approved_policy, **update)
        self.assertEqual(accepted["signedReleaseManifestSHA256"], rejected_manifest)
        self.assertEqual(recovered["signedReleaseManifestSHA256"], release.digest(replacement))
        self.assertNotEqual(recovered["signedReleaseManifestSHA256"], rejected_manifest)
        self.assertEqual(recovered["revocationPolicySequence"], 2)
        self.assertTrue(recovered["managedUpdate"]["installerStaged"])
        self.assertEqual(recovered["managedUpdate"]["installerSHA256"], installer_digest)
        self.assertEqual(release.digest(installer), installer_digest)

    def test_real_cms_approval_and_refusals(self):
        self.assertIsNotNone(OPENSSL, "OpenSSL is required for CMS signing fixtures")

        def openssl(*arguments):
            subprocess.run([OPENSSL, *map(str, arguments)], check=True, timeout=30,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def certificate(label):
            key = self.root / (label + ".key")
            pem = self.root / (label + ".pem")
            der = self.root / (label + ".cer")
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
                    "-subj", "/CN=" + label, "-keyout", key, "-out", pem)
            openssl("x509", "-in", pem, "-outform", "DER", "-out", der)
            return key, pem, der

        key, pem, approved = certificate("Disposable approval fixture")
        pin = release.digest(approved)
        _, _, stranger = certificate("Unapproved fixture")
        self.add_windows_installer_property("arm64", release.WINDOWS_BUILD_INFO_PROPERTY, "6" * 64)
        self.add_windows_installer_property("amd64", release.WINDOWS_PAYLOAD_FINGERPRINT_PROPERTY, "7" * 64)
        prepared = self.root / release.MANIFEST
        release.prepare(self.candidate, prepared, COMMIT, REF)
        manifest = self.candidate / release.MANIFEST
        signature = self.candidate / release.SIGNATURE
        def sign_manifest():
            openssl("cms", "-sign", "-binary", "-md", "sha256", "-in", manifest,
                    "-signer", pem, "-inkey", key, "-outform", "DER", "-out", signature)

        shutil.copyfile(prepared, manifest)
        sign_manifest()

        report = self.verify(approved, pin)
        self.assertEqual(report["subjectsVerified"], 12)
        self.assertNotIn("managedUpdate", report)
        self.assertNotIn("windowsDetection", report)
        stem = f"accessweaver-{VERSION}-windows-arm64"
        self.assertEqual(report["windowsBuildMetadata"], [{
            "target": "windows/arm64", "version": VERSION, "buildInfoSHA256": "6" * 64,
            "setupSHA256": release.digest(self.candidate / (stem + "-setup.exe")),
            "payloadSHA256": release.digest(self.candidate / (stem + ".exe")),
            "payloadSBOMSHA256": release.digest(self.candidate / (stem + ".exe.cdx.json")),
        }])
        revoked = self.write_policy({**self.policy, "subjectSHA256": ["6" * 64]})
        with self.assertRaisesRegex(ValueError, "Windows installer SBOM build metadata is revoked"):
            self.verify(approved, pin, policy_pin=revoked)
        self.write_policy(self.policy)
        for arch, name in (
            ("windows/arm64", f"accessweaver-{VERSION}-windows-arm64-setup.exe"),
            ("darwin/amd64", f"accessweaver-{VERSION}-darwin-amd64-deployment-experimental.pkg"),
        ):
            selected = self.verify(approved, pin, current_version="1.2.2-alpha", target=arch)["managedUpdate"]
            self.assertEqual(selected, {
                "target": arch, "currentVersion": "1.2.2-alpha", "candidateVersion": VERSION,
                "decision": "upgrade", "updateAvailable": True, "installer": name,
                "installerSHA256": release.digest(self.candidate / name),
            })
        with self.assertRaisesRegex(ValueError, "installed version and target"):
            self.verify(approved, pin, target="windows/arm64")
        staging = self.root / "staging"
        staging.mkdir()
        update = {"current_version": "1.2.2-alpha", "target": "windows/arm64", "stage_directory": staging}
        installer = f"accessweaver-{VERSION}-windows-arm64-setup.exe"
        input_file = self.candidate / installer
        staged_file = staging / installer
        original_installer = input_file.read_bytes()
        for version in ("1.0.0", VERSION, "2.0.0-rc.1"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "eligible managed upgrade"):
                self.verify(approved, pin, **{**update, "current_version": version})
            self.assertEqual(list(staging.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "outside the release"):
            self.verify(approved, pin, **{**update, "stage_directory": self.candidate})
        with self.assertRaisesRegex(ValueError, "staging requires"):
            self.verify(approved, pin, stage_directory=staging)
        with self.assertRaisesRegex(ValueError, "No approved reboot evidence"):
            self.verify(approved, pin, **update, current_payload_sha256="d" * 64)
        self.assertEqual(list(staging.iterdir()), [])

        windows_staging = self.root / "windows-staging"
        windows_staging.mkdir()
        publisher_pin = "e" * 64
        with patch.object(release.sys, "platform", "win32"), patch.object(release, "check_windows_publisher") as native:
            options = {**update, "stage_directory": windows_staging, "windows_publisher": publisher_pin.upper()}
            revoked_pin = self.write_policy({**self.policy, "subjectSHA256": [publisher_pin]})
            with self.assertRaisesRegex(ValueError, "Windows publisher certificate is revoked"):
                self.verify(approved, pin, policy_pin=revoked_pin, **options)
            native.assert_not_called()
            self.write_policy(self.policy)
            native.side_effect = [None, subprocess.CalledProcessError(1, "powershell")]
            with self.assertRaises(subprocess.CalledProcessError):
                self.verify(approved, pin, **options)
            self.assertEqual(list(windows_staging.iterdir()), [])
            native.side_effect = lambda artifact, *_: artifact.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "changed during publisher verification"):
                self.verify(approved, pin, **options)
            self.assertEqual(list(windows_staging.iterdir()), [])
            native.reset_mock(side_effect=True)
            native_report = self.verify(approved, pin, **options)
            self.assertTrue(native_report["nativePublisherChecksPerformed"])
            self.assertTrue(native_report["managedUpdate"]["installerStaged"])
            self.assertEqual(native_report["managedUpdate"]["nativePublisherVerification"], {
                "publisherCertificateSHA256": publisher_pin, "installerEmbeddedSignatureVerified": True,
                "payloadEmbeddedSignatureVerified": True, "timestampsVerified": True,
            })
            calls = [call.args for call in native.call_args_list]
            payload_name = f"accessweaver-{VERSION}-windows-arm64.exe"
            self.assertEqual([args[0].name for args in calls], [installer, payload_name])
            self.assertTrue(all(args[0].parent not in (self.candidate, windows_staging) for args in calls))
            self.assertEqual([args[1:] for args in calls],
                             [(release.digest(self.candidate / name), publisher_pin)
                              for name in (installer, payload_name)])
            self.assertEqual((windows_staging / installer).read_bytes(), original_installer)

        macos_staging = self.root / "macos-staging"
        macos_staging.mkdir()
        team, installer_pin, application_pin = "A12345BCDE", "3" * 64, "4" * 64
        macos_target = "darwin/arm64"
        macos_options = {
            "current_version": "1.2.2-alpha", "target": macos_target, "stage_directory": macos_staging,
            "macos_publisher": (team, installer_pin.upper(), application_pin.upper()),
        }
        pkg_name = f"accessweaver-{VERSION}-darwin-arm64-deployment-experimental.pkg"
        with patch.object(release.sys, "platform", "win32"), self.assertRaisesRegex(ValueError, "requires macOS"):
            self.verify(approved, pin, **macos_options)
        with patch.object(release.sys, "platform", "darwin"):
            for overrides in ({"target": "windows/arm64"}, {"macos_publisher": (team, installer_pin, "wrong")}):
                with self.assertRaises(ValueError):
                    self.verify(approved, pin, **{**macos_options, **overrides})

            with patch.object(release, "check_package_publisher") as package_check, \
                    patch.object(release, "verify_packaged_deployment") as deployment_check:
                for revoked in (installer_pin, application_pin):
                    revoked_pin = self.write_policy({**self.policy, "subjectSHA256": [revoked]})
                    with self.assertRaisesRegex(ValueError, "publisher certificate is revoked"):
                        self.verify(approved, pin, policy_pin=revoked_pin, **macos_options)
                    package_check.assert_not_called()
                    deployment_check.assert_not_called()
                    self.assertEqual(list(macos_staging.iterdir()), [])
                revoked_pin = self.write_policy({**self.policy, "subjectSHA256": [MACOS_PAYLOAD_DIGESTS[macos_target]]})
                with self.assertRaisesRegex(ValueError, "macOS controller is revoked"):
                    self.verify(approved, pin, policy_pin=revoked_pin, **macos_options)
                package_check.assert_not_called()
                deployment_check.assert_not_called()
                self.assertEqual(list(macos_staging.iterdir()), [])
                self.write_policy(self.policy)

                package_check.side_effect = subprocess.CalledProcessError(1, "spctl")
                with self.assertRaises(subprocess.CalledProcessError):
                    self.verify(approved, pin, **macos_options)
                deployment_check.assert_not_called()
                self.assertEqual(list(macos_staging.iterdir()), [])
                package_check.side_effect = None

                deployment_check.side_effect = subprocess.CalledProcessError(1, "codesign")
                with self.assertRaises(subprocess.CalledProcessError):
                    self.verify(approved, pin, **macos_options)
                self.assertEqual(list(macos_staging.iterdir()), [])
                deployment_check.side_effect = lambda package, *_, **__: package.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "changed during publisher verification"):
                    self.verify(approved, pin, **macos_options)
                self.assertEqual(list(macos_staging.iterdir()), [])
                deployment_check.side_effect = None

                native_report = self.verify(approved, pin, **macos_options)
                native_update = native_report["managedUpdate"]
                self.assertTrue(native_report["nativePublisherChecksPerformed"])
                self.assertTrue(native_update["installerStaged"])
                self.assertEqual(native_update["nativePublisherVerification"], {
                    "developerTeamID": team, "installerCertificateSHA256": installer_pin,
                    "applicationCertificateSHA256": application_pin, "gatekeeperAccepted": True,
                    "packagedInstallationHelperVerified": True, "packagedPayloadSBOMVerified": True,
                    "stapledTicketValidated": True,
                })
                checked_path = package_check.call_args.args[0]
                self.assertEqual(checked_path.name, pkg_name)
                self.assertNotEqual(checked_path.parent, self.candidate)
                self.assertNotEqual(checked_path.parent, macos_staging)
                self.assertEqual(package_check.call_args.args, (checked_path, team, installer_pin))
                self.assertEqual(deployment_check.call_args.args, (checked_path, team, "arm64", application_pin))
                helper_pin, = [entry["detectorSHA256"] for entry in native_report["macosDetection"]
                               if entry["target"] == macos_target]
                self.assertEqual(deployment_check.call_args.kwargs, {
                    "commit": COMMIT, "version": VERSION, "helper_sha256": helper_pin,
                    "manifest_sha256": DEPLOYMENT_MANIFEST_DIGESTS[macos_target],
                    "payload_sha256": MACOS_PAYLOAD_DIGESTS[macos_target],
                })
                self.assertEqual((macos_staging / pkg_name).read_bytes(), (self.candidate / pkg_name).read_bytes())

                output = macos_staging / "accessweaver-installer"
                export = {"macos_publisher": macos_options["macos_publisher"],
                          "macos_detection": ("arm64", output)}
                with patch.object(release, "stage_detector") as stage:
                    with self.assertRaisesRegex(ValueError, "requires an architecture and approved Apple publisher pins"):
                        self.verify(approved, pin, **{**export, "macos_publisher": None})
                    with self.assertRaisesRegex(ValueError, "outside the release input directory"):
                        self.verify(approved, pin, **{**export, "macos_detection": ("arm64", self.candidate / output.name)})
                    revoked_pin = self.write_policy({**self.policy, "subjectSHA256": [helper_pin]})
                    with self.assertRaisesRegex(ValueError, "macOS detector is revoked"):
                        self.verify(approved, pin, policy_pin=revoked_pin, **export)
                    self.write_policy(self.policy)
                    stage.assert_not_called()

                    for arch in ("amd64", "arm64"):
                        stage.reset_mock()
                        output_target = "darwin/" + arch
                        entry, = [record for record in native_report["macosDetection"]
                                  if record["target"] == output_target]
                        arguments = [
                            "signed_release_manifest.py", "verify", str(self.candidate),
                            "--approval-certificate", str(approved), "--approval-certificate-sha256", pin,
                            "--revocation-list", str(self.revocation_list), "--revocation-list-sha256", self.policy_pin,
                            "--source-commit", COMMIT, "--source-ref", REF,
                            "--macos-publisher", *export["macos_publisher"],
                            "--write-macos-detector", arch, str(output),
                        ]
                        deployment_check.side_effect = lambda package, *_, **__: package.parent / "expanded"
                        stdout = io.StringIO()
                        with patch.object(sys, "argv", arguments), redirect_stdout(stdout):
                            self.assertEqual(release.main(), 0)
                        detector_report = json.loads(stdout.getvalue())
                        self.assertNotIn("managedUpdate", detector_report)
                        self.assertTrue(detector_report["nativePublisherChecksPerformed"])
                        self.assertEqual(detector_report["macosManagedDetector"], {
                            **entry, "file": output.name,
                            "nativePublisherVerification": native_update["nativePublisherVerification"],
                        })
                        pkg = deployment_check.call_args.args[0]
                        self.assertEqual(pkg.name, f"accessweaver-{VERSION}-darwin-{arch}-deployment-experimental.pkg")
                        self.assertNotEqual(pkg.parent, self.candidate)
                        self.assertEqual(package_check.call_args.args, (pkg, team, installer_pin))
                        self.assertEqual(deployment_check.call_args.args, (pkg, team, arch, application_pin))
                        stage.assert_called_once()
                        self.assertEqual(stage.call_args.args[:5],
                                         (pkg.parent / "expanded", team, arch, entry["detectorSHA256"], output.resolve()))
                        self.assertEqual(stage.call_args.args[-1], application_pin)
                        with patch.object(release, "require_current_revocation_policy",
                                          side_effect=ValueError("approval expired")):
                            with self.assertRaisesRegex(ValueError, "approval expired"):
                                stage.call_args.kwargs["check_approval"]()


        real_stage = release.stage_managed_update
        def replace_input_after_verification(snapshot, directory, decision, policy, **binding):
            input_file.write_bytes(b"replacement after verification")
            real_stage(snapshot, directory, decision, policy, **binding)

        with patch.object(release, "stage_managed_update", side_effect=replace_input_after_verification):
            staged = self.verify(approved, pin, **update)["managedUpdate"]
        self.assertTrue(staged["installerStaged"])
        input_file.write_bytes(original_installer)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        timestamp = "%Y-%m-%dT%H:%M:%SZ"
        active_policy = {
            **self.policy, "schemaVersion": 2, "sequence": 3,
            "issuedAt": (now - timedelta(minutes=1)).strftime(timestamp),
            "expiresAt": (now + timedelta(minutes=5)).strftime(timestamp),
        }
        active_pin = self.write_policy(active_policy)
        fresh = self.verify(approved, pin, policy_pin=active_pin, minimum_revocation_sequence=3, **update)
        self.assertTrue(fresh["managedUpdate"]["installerStaged"])
        self.assertEqual(fresh["revocationPolicySequence"], 3)
        self.assertEqual(fresh["revocationPolicyExpiresAt"], active_policy["expiresAt"])
        with self.assertRaisesRegex(ValueError, "below the approved minimum"):
            self.verify(approved, pin, policy_pin=active_pin, minimum_revocation_sequence=4, **update)
        readings = iter((now, now + timedelta(minutes=5)))

        class ControlledClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return next(readings)

        with patch.object(release, "datetime", ControlledClock), \
                patch.object(release, "stage_managed_update") as stage, \
                self.assertRaisesRegex(ValueError, "outside its validity window"):
            self.verify(approved, pin, policy_pin=active_pin, minimum_revocation_sequence=3, **update)
        stage.assert_not_called()
        self.write_policy(self.policy)
        with self.assertRaisesRegex(ValueError, "sequenced revocation policy"):
            self.verify(approved, pin, minimum_revocation_sequence=3, **update)
        self.assertEqual(staged["installerSHA256"], release.digest(staged_file))
        self.assertEqual(staged_file.read_bytes(), original_installer)
        self.assertEqual(list(staging.iterdir()), [staged_file])
        input_file.write_bytes(original_installer)

        before = staged_file.stat()
        retry = self.verify(approved, pin, **update)["managedUpdate"]
        self.assertTrue(retry["installerStaged"])
        self.assertEqual(staged_file.stat().st_ino, before.st_ino)
        self.assertEqual(staged_file.stat().st_mtime_ns, before.st_mtime_ns)
        revoked_pin = self.write_policy({**self.policy, "subjectSHA256": [retry["installerSHA256"]]})
        with self.assertRaisesRegex(ValueError, "is revoked"):
            self.verify(approved, pin, policy_pin=revoked_pin, **update)
        self.assertEqual(staged_file.read_bytes(), original_installer)
        self.write_policy(self.policy)

        conflicting = b"x" * len(original_installer)
        staged_file.write_bytes(conflicting)
        with self.assertRaisesRegex(ValueError, "differs from the approved digest"):
            self.verify(approved, pin, **update)
        self.assertEqual(staged_file.read_bytes(), conflicting)
        self.assertEqual(list(staging.iterdir()), [staged_file])
        staged_file.unlink()

        os_link = release.os.link
        alias = self.root / "existing-assignment"
        alias.write_bytes(original_installer)
        os_link(alias, staged_file)
        with self.assertRaisesRegex(ValueError, "bounded ordinary staged installer"):
            self.verify(approved, pin, **update)
        self.assertEqual(alias.read_bytes(), original_installer)
        staged_file.unlink()

        native_publish = release.publish_staged_installer
        for competing_bytes in (original_installer, conflicting):
            def publish_concurrently(source, destination):
                destination.write_bytes(competing_bytes)
                native_publish(source, destination)

            with self.subTest(matching=competing_bytes == original_installer), \
                    patch.object(release, "publish_staged_installer", side_effect=publish_concurrently):
                if competing_bytes == original_installer:
                    self.assertTrue(self.verify(approved, pin, **update)["managedUpdate"]["installerStaged"])
                else:
                    with self.assertRaisesRegex(ValueError, "differs from the approved digest"):
                        self.verify(approved, pin, **update)
            self.assertEqual(staged_file.read_bytes(), competing_bytes)
            self.assertEqual(list(staging.iterdir()), [staged_file])
            staged_file.unlink()

        macos = self.verify(approved, pin, **{**update, "target": "darwin/amd64"})["managedUpdate"]
        macos_file = staging / macos["installer"]
        self.assertEqual(macos_file.suffix, ".pkg")
        self.assertEqual(release.digest(macos_file), macos["installerSHA256"])
        self.assertEqual(list(staging.iterdir()), [macos_file])
        macos_file.unlink()

        def corrupt_copy(source, staged, size):
            staged.write_bytes(b"corrupted copy")

        with patch.object(release, "copy_approved_installer", side_effect=corrupt_copy):
            with self.assertRaisesRegex(ValueError, "bounded ordinary staged installer"):
                self.verify(approved, pin, **update)
        self.assertEqual(list(staging.iterdir()), [])
        self.assertEqual(report["sbomArtifactBindingsVerified"], 6)
        self.assertEqual(report["macosDetection"], [
            {"target": target, "version": VERSION, "detectorSHA256": pin,
             "manifestSHA256": DEPLOYMENT_MANIFEST_DIGESTS[target], "payloadSHA256": MACOS_PAYLOAD_DIGESTS[target],
             "packageSHA256": release.digest(self.candidate /
                 f"accessweaver-{VERSION}-darwin-{target.split('/')[1]}-deployment-experimental.pkg")}
            for target, pin in DETECTOR_DIGESTS.items()
        ])
        for target, detector in DETECTOR_DIGESTS.items():
            current_pin = self.write_policy({**self.policy, "subjectSHA256": [detector]})
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "macOS detector is revoked"):
                self.verify(approved, pin, policy_pin=current_pin)
        for target, manifest_pin in DEPLOYMENT_MANIFEST_DIGESTS.items():
            current_pin = self.write_policy({**self.policy, "subjectSHA256": [manifest_pin]})
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "macOS deployment manifest is revoked"):
                self.verify(approved, pin, policy_pin=current_pin)
        for target, macos_payload_pin in MACOS_PAYLOAD_DIGESTS.items():
            current_pin = self.write_policy({**self.policy, "subjectSHA256": [macos_payload_pin]})
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "macOS controller is revoked"):
                self.verify(approved, pin, policy_pin=current_pin)
        self.write_policy(self.policy)
        self.assertTrue(report["organizationApprovalSignatureVerified"])
        self.assertFalse(report["nativePublisherChecksPerformed"])
        self.assertTrue(report["revocationCheckPassed"])
        self.assertEqual(report["revocationListSHA256"], self.policy_pin)
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify(stranger, release.digest(stranger))
        with self.assertRaises(ValueError):
            self.verify(stranger, pin)
        with self.assertRaises(ValueError):
            self.verify(approved, pin, "b" * 40)

        original = manifest.read_bytes()
        manifest.write_bytes(original + b" ")
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify(approved, pin, **update)
        self.assertEqual(list(staging.iterdir()), [])
        manifest.write_bytes(original)

        subject = self.candidate / next(iter(self.subjects))
        data = subject.read_bytes()
        subject.write_bytes(data + b"changed")
        with self.assertRaises(ValueError):
            self.verify(approved, pin)
        subject.write_bytes(data)

        extra = self.candidate / "extra.exe"
        extra.write_bytes(b"unexpected")
        with self.assertRaises(ValueError):
            self.verify(approved, pin)
        extra.unlink()
        self.assertEqual(self.verify(approved, pin), report)

        # Even a correctly signed inventory cannot approve the wrong SBOM semantics.
        sidecar = self.candidate / f"accessweaver-{VERSION}-darwin-arm64-deployment-experimental.pkg.cdx.json"
        original_sidecar = sidecar.read_bytes()
        document = json.loads(original_sidecar)
        document["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
        sidecar.write_text(json.dumps(document), encoding="utf-8")
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, release.inventory(self.candidate, self.subjects)))
        sign_manifest()
        with self.assertRaisesRegex(ValueError, "SBOM does not match artifact bytes"):
            self.verify(approved, pin)
        sidecar.write_bytes(original_sidecar)
        manifest.write_bytes(original)
        sign_manifest()

        for field, revoked in {
            "sourceCommits": COMMIT,
            "sourceRefs": REF,
            "subjectSHA256": release.digest(subject),
            "approvalCertificateSHA256": pin,
        }.items():
            with self.subTest(field=field):
                current_pin = self.write_policy({**self.policy, field: [revoked]})
                with self.assertRaisesRegex(ValueError, "revoked"):
                    self.verify(approved, pin, policy_pin=current_pin, **update)
                self.assertEqual(list(staging.iterdir()), [])
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    self.verify(approved, pin)

        self.write_policy(self.policy)
        prepared.unlink()
        manifest.unlink()
        signature.unlink()
        clean = self.write_reboot_report("clean.json")
        upgrade = self.write_reboot_report("upgrade.json", schemaVersion=9, installMode="upgrade",
                                           previousVersion="1.2.2-rc.1", previousPayloadSHA256="d" * 64,
                                           userProfilePreservedThroughUpgrade=True, uninstallerSHA256="e" * 64,
                                           downgradeRequested=True, downgradeRefused=True, downgradeStatePreserved=True,
                                           previousSetupSHA256="8" * 64, previousPublisherSHA256="9" * 64)
        arm = self.write_reboot_report("arm.json", architecture="arm64", schemaVersion=10, uninstallerSHA256="f" * 64)
        release.prepare(self.candidate, prepared, COMMIT, REF, windows_reboot_evidence=[arm, upgrade, clean])
        shutil.copyfile(prepared, manifest)
        sign_manifest()
        report = self.verify(approved, pin)
        self.assertEqual(report["schemaVersion"], 6)
        self.assertEqual(report["subjectsVerified"], 12)
        clean_entry, upgrade_entry, arm_entry = report["windowsDetection"]
        self.assertEqual(clean_entry, {
            "target": "windows/amd64", "installMode": "clean", "previousVersion": "",
            "previousPayloadSHA256": "", "uninstallerSHA256": "c" * 64,
            "publisherCertificateSHA256": "b" * 64, "rebootEvidenceSHA256": clean[1],
            "version": "1.2.3-rc.1",
            "setupSHA256": release.digest(self.candidate / "accessweaver-1.2.3-rc.1-windows-amd64-setup.exe"),
            "payloadSHA256": release.digest(self.candidate / "accessweaver-1.2.3-rc.1-windows-amd64.exe"),
            "payloadSBOMSHA256": release.digest(self.candidate / "accessweaver-1.2.3-rc.1-windows-amd64.exe.cdx.json"),
        })
        self.assertEqual(upgrade_entry, {
            **clean_entry, "installMode": "upgrade", "previousVersion": "1.2.2-rc.1",
            "previousPayloadSHA256": "d" * 64, "uninstallerSHA256": "e" * 64, "rebootEvidenceSHA256": upgrade[1],
            "previousPayloadSBOMSHA256": "1" * 64, "previousPayloadPublisherSHA256": "2" * 64,
            "payloadPublisherCertificateSHA256": "7" * 64,
            "previousSetupSHA256": "8" * 64, "previousPublisherSHA256": "9" * 64,
        })
        self.assertEqual(arm_entry["target"], "windows/arm64")
        self.assertEqual(arm_entry["buildInfoSHA256"], "6" * 64)
        self.assertEqual(arm_entry["payloadSBOMSHA256"],
                         release.digest(self.candidate / "accessweaver-1.2.3-rc.1-windows-arm64.exe.cdx.json"))
        self.assertEqual(arm_entry["uninstallerSHA256"], "f" * 64)
        qualified = {"current_version": "1.2.2-rc.1", "target": "windows/amd64",
                     "current_payload_sha256": "D" * 64}
        update_report = self.verify(approved, pin, **qualified)["managedUpdate"]
        self.assertEqual(update_report["windowsUpgradeDetection"], upgrade_entry)
        with patch.object(release.sys, "platform", "win32"), patch.object(release, "check_windows_publisher") as native:
            with self.assertRaisesRegex(ValueError, "differs from the upgrade qualification"):
                self.verify(approved, pin, windows_publisher="0" * 64, stage_directory=staging, **qualified)
            native.assert_not_called()
            with self.assertRaisesRegex(ValueError, "differs from the upgrade qualification"):
                self.verify(approved, pin, windows_publisher="b" * 64, stage_directory=staging, **qualified)
            native.assert_not_called()
            self.assertEqual(list(staging.iterdir()), [])
            distinct_publishers = self.verify(
                approved, pin, windows_publisher="b" * 64, windows_payload_publisher="7" * 64,
                stage_directory=staging, **qualified,
            )["managedUpdate"]
            self.assertTrue(distinct_publishers["installerStaged"])
            self.assertEqual(distinct_publishers["nativePublisherVerification"]["payloadPublisherCertificateSHA256"],
                             "7" * 64)
            self.assertEqual([call.args[2] for call in native.call_args_list], ["b" * 64, "7" * 64])
            (staging / distinct_publishers["installer"]).unlink()
        self.assertEqual(list(staging.iterdir()), [])
        for override, error in (
            ({"current_payload_sha256": "a" * 64}, "No approved reboot evidence"),
            ({"current_version": "1.2.2-rc.1+other"}, "No approved reboot evidence"),
            ({"target": "windows/arm64"}, "No approved reboot evidence"),
            ({"current_version": "1.2.2"}, "not an eligible managed upgrade"),
            ({"target": "darwin/arm64"}, "requires a Windows target"),
            ({"current_payload_sha256": "unverified"}, "installed payload SHA-256"),
        ):
            with self.subTest(override=override), self.assertRaisesRegex(ValueError, error):
                self.verify(approved, pin, stage_directory=staging, **{**qualified, **override})
            self.assertEqual(list(staging.iterdir()), [])
        trusted = {
            **qualified,
            "current_payload_sbom_sha256": upgrade_entry["previousPayloadSBOMSHA256"],
            "current_payload_publisher_sha256": upgrade_entry["previousPayloadPublisherSHA256"],
        }
        for override, error in (
            ({"current_payload_sbom_sha256": "0" * 64}, "matches the installed Windows SBOM and publisher"),
            ({"current_payload_publisher_sha256": "0" * 64}, "matches the installed Windows SBOM and publisher"),
            ({"current_payload_publisher_sha256": None}, "requires the payload, SBOM and publisher"),
            ({"current_payload_sbom_sha256": None}, "requires the payload, SBOM and publisher"),
            ({"current_payload_sbom_sha256": "unverified"}, "requires the payload, SBOM and publisher"),
            ({"current_payload_sha256": None}, "requires the payload, SBOM and publisher"),
        ):
            with self.subTest(installed_trust=override), self.assertRaisesRegex(ValueError, error):
                self.verify(approved, pin, stage_directory=staging, **{**trusted, **override})
            self.assertEqual(list(staging.iterdir()), [])
        qualified_report = self.verify(approved, pin, stage_directory=staging, **trusted)["managedUpdate"]
        self.assertTrue(qualified_report["installerStaged"])
        self.assertEqual(qualified_report["windowsUpgradeDetection"], upgrade_entry)
        (staging / qualified_report["installer"]).unlink()
        command = [
            sys.executable, str(Path(release.__file__).resolve()), "verify", str(self.candidate),
            "--approval-certificate", str(approved), "--approval-certificate-sha256", pin,
            "--revocation-list", str(self.revocation_list), "--revocation-list-sha256", self.policy_pin,
            "--openssl", OPENSSL, "--source-commit", COMMIT, "--source-ref", REF,
            "--current-version", qualified["current_version"], "--target", qualified["target"],
            "--current-payload-sha256", trusted["current_payload_sha256"],
            "--current-payload-sbom-sha256", trusted["current_payload_sbom_sha256"],
            "--current-payload-publisher-sha256", trusted["current_payload_publisher_sha256"],
            "--stage-directory", str(staging),
        ]
        completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        self.assertEqual(json.loads(completed.stdout)["managedUpdate"], qualified_report)
        (staging / qualified_report["installer"]).unlink()
        inventory_path = self.root / "installed-inventory.json"
        inventory_record = {
            "schemaVersion": 1, "target": qualified["target"], "version": qualified["current_version"],
            "payloadSHA256": qualified["current_payload_sha256"].lower(),
            "payloadSBOMSHA256": trusted["current_payload_sbom_sha256"],
            "payloadPublisherSHA256": trusted["current_payload_publisher_sha256"],
        }
        inventory_path.write_text(json.dumps(inventory_record), encoding="utf-8")
        inventory_pin = release.digest(inventory_path)
        inventory_args = (inventory_path, inventory_pin)
        cli = command[:command.index("--current-version")] + [
            "--windows-upgrade-inventory", str(inventory_path), inventory_pin, "--stage-directory", str(staging),
        ]
        completed = subprocess.run(cli, check=True, capture_output=True, text=True, timeout=30)
        self.assertEqual(json.loads(completed.stdout)["managedUpdate"], qualified_report)
        (staging / qualified_report["installer"]).unlink()
        for mixed_args in (
            {"target": qualified["target"]}, {"current_version": qualified["current_version"]},
            {"current_payload_sha256": qualified["current_payload_sha256"]},
            {"current_payload_sbom_sha256": trusted["current_payload_sbom_sha256"]},
            {"current_payload_publisher_sha256": trusted["current_payload_publisher_sha256"]},
        ):
            with self.subTest(mixed_args=mixed_args), self.assertRaisesRegex(ValueError, "cannot be combined"):
                self.verify(approved, pin, windows_upgrade_inventory=inventory_args, **mixed_args)
        for override, error in (
            ({"schemaVersion": True}, "Malformed Windows upgrade inventory"),
            ({"target": "darwin/amd64"}, "Malformed Windows upgrade inventory"),
            ({"target": "windows/arm64"}, "matches the installed Windows payload"),
            ({"payloadSBOMSHA256": "0" * 64}, "matches the installed Windows SBOM and publisher"),
            ({"payloadPublisherSHA256": "0" * 64}, "matches the installed Windows SBOM and publisher"),
            ({"payloadPublisherSHA256": "not-a-digest"}, "Malformed Windows upgrade inventory digest"),
            ({"payloadPublisherSHA256": None}, "Malformed Windows upgrade inventory digest"),
            ({"endpointName": "inert-private-name"}, "Malformed Windows upgrade inventory"),
        ):
            inventory_path.write_text(json.dumps({**inventory_record, **override}), encoding="utf-8")
            with self.subTest(inventory_override=override), self.assertRaisesRegex(ValueError, error):
                self.verify(approved, pin, stage_directory=staging,
                            windows_upgrade_inventory=(inventory_path, release.digest(inventory_path)))
            self.assertEqual(list(staging.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            self.verify(approved, pin, stage_directory=staging, windows_upgrade_inventory=inventory_args)
        self.assertEqual(list(staging.iterdir()), [])
        for invalid in (
            b"",
            b" " * 4097,
            b'{"schemaVersion":1,"schemaVersion":1}',
            b"\xff",
        ):
            inventory_path.write_bytes(invalid)
            with self.subTest(inventory_bytes=len(invalid)), self.assertRaises(ValueError):
                self.verify(approved, pin, stage_directory=staging,
                            windows_upgrade_inventory=(inventory_path, release.digest(inventory_path)))
            self.assertEqual(list(staging.iterdir()), [])
        for revoked in (clean[1], "b" * 64, "d" * 64, "e" * 64,
                        upgrade_entry["previousPayloadSBOMSHA256"], upgrade_entry["previousPayloadPublisherSHA256"],
                        upgrade_entry["payloadPublisherCertificateSHA256"], arm_entry["buildInfoSHA256"],
                        *(upgrade_entry[field] for field in release.WINDOWS_DOWNGRADE_FIELDS)):
            current_pin = self.write_policy({**self.policy, "subjectSHA256": [revoked]})
            with self.subTest(revoked=revoked), self.assertRaisesRegex(ValueError, "revoked"):
                self.verify(approved, pin, policy_pin=current_pin, stage_directory=staging, **qualified)
            self.assertEqual(list(staging.iterdir()), [])
        self.write_policy(self.policy)

        original = manifest.read_bytes()
        data = json.loads(original)
        files = release.inventory(self.candidate, self.subjects)
        upgraded_evidence = self.write_reboot_report(
            "upgrade-build-info.json", schemaVersion=11, installMode="upgrade",
            previousVersion="1.2.2-rc.1", previousPayloadSHA256="d" * 64,
            userProfilePreservedThroughUpgrade=True, uninstallerSHA256="e" * 64,
        )
        new_entry, = release.load_detection_evidence(self.candidate, [upgraded_evidence], files, VERSION)
        self.assertEqual(new_entry["previousBuildInfoSHA256"], "5" * 64)
        entries = [data["windowsDetection"][0], new_entry, data["windowsDetection"][2]]
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, files, entries))
        sign_manifest()
        new_inventory = {**inventory_record, "schemaVersion": 2, "buildInfoSHA256": "5" * 64}
        inventory_path.write_text(json.dumps(new_inventory), encoding="utf-8")
        inventory_options = {"windows_upgrade_inventory": (inventory_path, release.digest(inventory_path))}
        with self.assertRaisesRegex(ValueError, "matches the installed Windows SBOM and publisher"):
            self.verify(approved, pin, stage_directory=staging, **qualified)
        with self.assertRaisesRegex(ValueError, "matches the installed Windows build metadata"):
            self.verify(approved, pin, stage_directory=staging, **trusted)
        self.assertEqual(list(staging.iterdir()), [])
        selected = self.verify(approved, pin, stage_directory=staging, **inventory_options)
        self.assertEqual(selected["schemaVersion"], 10)
        self.assertTrue(selected["managedUpdate"]["installerStaged"])
        self.assertEqual(selected["managedUpdate"]["windowsUpgradeDetection"]["previousBuildInfoSHA256"], "5" * 64)
        self.assertNotIn("windowsSetupBaselineArgument", selected["managedUpdate"])
        (staging / selected["managedUpdate"]["installer"]).unlink()
        with self.assertRaisesRegex(ValueError, "lacks signed Setup baseline enforcement evidence"):
            self.verify(approved, pin, stage_directory=staging, require_windows_setup_baseline=True, **inventory_options)
        original_setup_pin = release.digest(self.candidate / qualified_report["installer"])
        with self.assertRaisesRegex(ValueError, "lacks signed Setup baseline enforcement evidence"):
            self.verify(approved, pin, stage_directory=staging, resume_windows_upgrade_setup_sha256=original_setup_pin,
                        **inventory_options)
        self.assertEqual(list(staging.iterdir()), [])
        for missing_pins in ({}, qualified, trusted, {"current_version": "1.2.2-rc.1", "target": "darwin/arm64"}):
            with self.subTest(baseline_inputs=sorted(missing_pins)), self.assertRaisesRegex(
                ValueError, "complete installed trust pins"
            ):
                self.verify(approved, pin, stage_directory=staging, require_windows_setup_baseline=True, **missing_pins)
        self.assertEqual(list(staging.iterdir()), [])

        launch_detector = self.root / "detect-windows-installer.ps1"
        detector_bytes = b"inert qualified detector"
        launch_detector.write_bytes(detector_bytes)
        evidence = self.write_reboot_report(
            "upgrade-baseline-enforced.json", schemaVersion=12, installMode="upgrade",
            detectorSHA256=release.digest(launch_detector),
            previousVersion="1.2.2-rc.1", previousPayloadSHA256="d" * 64,
            userProfilePreservedThroughUpgrade=True, uninstallerSHA256="e" * 64,
        )
        qualified_entry, = release.load_detection_evidence(self.candidate, [evidence], files, VERSION)
        self.assertIs(qualified_entry["setupUpgradeBaselineVerified"], True)
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, files, [entries[0], qualified_entry, entries[2]]))
        sign_manifest()
        selected = self.verify(approved, pin, stage_directory=staging, require_windows_setup_baseline=True,
                               **inventory_options)
        self.assertEqual(selected["schemaVersion"], 10)
        self.assertTrue(selected["managedUpdate"]["installerStaged"])
        self.assertEqual(selected["managedUpdate"]["windowsSetupBaselineArgument"], "/AWUpgradeFrom=" + ",".join((
            qualified_entry["previousVersion"], qualified_entry["previousPayloadSHA256"],
            qualified_entry["previousPayloadSBOMSHA256"], qualified_entry["previousBuildInfoSHA256"],
        )))
        staged_path = staging / selected["managedUpdate"]["installer"]
        before = staged_path.stat()
        original_baseline = selected["managedUpdate"]["windowsSetupBaselineArgument"]
        approval_material = original_baseline.removeprefix(release.WINDOWS_SETUP_BASELINE_PREFIX) + "|amd64|" + "7" * 64
        expected_approval = hashlib.sha256(approval_material.encode("ascii")).hexdigest()
        self.assertEqual(selected["managedUpdate"]["windowsPendingApprovalSHA256"], expected_approval)
        retry_cli = command[:command.index("--current-version")] + [
            "--windows-upgrade-inventory", str(inventory_path), inventory_options["windows_upgrade_inventory"][1],
            "--stage-directory", str(staging), "--resume-windows-upgrade-setup-sha256", original_setup_pin.upper(),
            "--resume-windows-upgrade-baseline-argument", original_baseline,
        ]
        completed = subprocess.run(retry_cli, check=True, capture_output=True, text=True, timeout=30)
        self.assertEqual(json.loads(completed.stdout)["managedUpdate"], selected["managedUpdate"])
        self.assertEqual(staged_path.stat().st_ino, before.st_ino)
        self.assertEqual(staged_path.stat().st_mtime_ns, before.st_mtime_ns)

        wrong_baseline = original_baseline.rsplit(",", 1)[0] + "," + ("0" * 64)
        with patch.object(release, "stage_managed_update") as stage:
            for retry_setup, retry_baseline, error in (
                (None, original_baseline, "requires the original approved Windows Setup"),
                (original_setup_pin, "", "Expected the original Windows Setup baseline argument"),
                (original_setup_pin, wrong_baseline, "differs from the original approved upgrade"),
                (original_setup_pin, original_baseline.upper(), "Expected the original Windows Setup baseline argument"),
            ):
                with self.subTest(retry_baseline_error=error), self.assertRaisesRegex(ValueError, error):
                    self.verify(approved, pin, stage_directory=staging, **inventory_options,
                                resume_windows_upgrade_setup_sha256=retry_setup,
                                resume_windows_upgrade_baseline_argument=retry_baseline)
            for retry_pin, options, error in (
                ("", inventory_options, "Expected the original approved Windows Setup"),
                ("0" * 64, inventory_options, "differs from the original approved upgrade package"),
                (original_setup_pin, trusted, "complete installed trust pins"),
            ):
                with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                    self.verify(approved, pin, stage_directory=staging,
                                resume_windows_upgrade_setup_sha256=retry_pin, **options)
            revoked = self.write_policy({**self.policy, "subjectSHA256": [original_setup_pin]})
            with self.assertRaisesRegex(ValueError, "is revoked"):
                self.verify(approved, pin, policy_pin=revoked, stage_directory=staging,
                            resume_windows_upgrade_setup_sha256=original_setup_pin, **inventory_options)
            stage.assert_not_called()
        self.write_policy(self.policy)
        self.assertEqual(release.digest(staged_path), original_setup_pin)
        staged_path.unlink()
        bad_retry_cli = [*retry_cli[:-1], wrong_baseline]
        rejected = subprocess.run(bad_retry_cli, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")
        self.assertEqual(list(staging.iterdir()), [])
        verified = self.verify(approved, pin, current_build_info_sha256="5" * 64,
                               require_windows_setup_baseline=True, **trusted)
        self.assertEqual(verified["managedUpdate"]["windowsSetupBaselineArgument"],
                         selected["managedUpdate"]["windowsSetupBaselineArgument"])
        self.assertEqual(list(staging.iterdir()), [])
        if os.name == "nt":
            now = datetime.now(timezone.utc).replace(microsecond=0)
            launch_policy = {**self.policy, "schemaVersion": 2, "sequence": 4,
                             "issuedAt": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
                             "expiresAt": (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")}
            launch_pin = self.write_policy(launch_policy)
            launch_options = {**inventory_options, "stage_directory": staging,
                              "windows_publisher": qualified_entry["publisherCertificateSHA256"],
                              "windows_payload_publisher": qualified_entry[release.WINDOWS_PAYLOAD_PUBLISHER],
                              "minimum_revocation_sequence": 4, "launch_staged_windows_setup": True}
            native_launch = release.launch_windows_setup
            initial_boot = {"endpointSHA256": "f" * 64, "bootTicks": "638900000000000000"}
            with patch.object(release, "read_windows_boot", return_value=initial_boot) as boot, \
                    patch.object(release, "require_native_windows_setup_host") as host, \
                    patch.object(release, "__file__", str(self.root / "signed_release_manifest.py")), \
                    patch.object(release, "check_windows_publisher") as publisher, \
                    patch.object(release, "launch_windows_setup", return_value=3010) as launch, \
                    patch.object(release, "detect_windows_upgrade", return_value=("detected", None)) as detect:
                with self.assertRaisesRegex(ValueError, "revocation sequence"):
                    self.verify(approved, pin, policy_pin=launch_pin,
                                **{**launch_options, "minimum_revocation_sequence": None})
                with self.assertRaisesRegex(ValueError, "requires the saved baseline argument"):
                    self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                resume_windows_upgrade_setup_sha256=original_setup_pin)
                launch.assert_not_called()
                self.assertEqual(list(staging.iterdir()), [])

                for contents in (None, b"different detector"):
                    if contents is None:
                        launch_detector.unlink()
                    else:
                        launch_detector.write_bytes(contents)
                    with self.subTest(detector=contents), self.assertRaisesRegex(ValueError, "unavailable before Setup launch"):
                        self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                    windows_upgrade_attempt_id="a" * 32)
                    launch.assert_not_called()
                    detect.assert_not_called()
                    publisher.assert_not_called()
                    self.assertEqual(list(staging.iterdir()), [])
                launch_detector.write_bytes(detector_bytes)
                host.reset_mock()

                def restart_required(*args, **kwargs):
                    with self.assertRaises(PermissionError):
                        launch_detector.write_bytes(b"changed during Setup")
                    return 3010

                launch.side_effect = restart_required
                result = self.verify(approved, pin, policy_pin=launch_pin, **launch_options)["managedUpdate"]
                launch.side_effect = None
                self.assertEqual(result["setupExitCode"], 3010)
                self.assertEqual(result["installedDetection"], "restart-required")
                detect.assert_not_called()
                self.assertEqual(result["windowsSetupBaselineArgument"], original_baseline)
                self.assertEqual(publisher.call_count, 2)
                host.assert_called_once_with(result["target"])
                launch.assert_called_once()
                self.assertEqual(release.digest(staged_path), original_setup_pin)
                attempt_id = "a" * 32
                launch.reset_mock()
                with self.assertRaisesRegex(ValueError, "wait limit requires a Windows upgrade attempt ID"):
                    self.verify(approved, pin, policy_pin=launch_pin, **launch_options, windows_setup_wait_seconds=60)
                launch.assert_not_called()
                with patch.object(release, "write_windows_upgrade_receipt") as write_result:
                    launch.side_effect = subprocess.TimeoutExpired("setup", 60)
                    try:
                        timed_out = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                                windows_upgrade_attempt_id=attempt_id, windows_setup_wait_seconds=60)
                    finally:
                        launch.side_effect = None
                    self.assertIsNone(timed_out["managedUpdate"]["setupExitCode"])
                    self.assertEqual(timed_out["managedUpdate"]["installedDetection"], "unverified")
                    self.assertEqual(timed_out["managedUpdate"]["installedDetectionReason"], "setup-wait-timeout")
                    self.assertEqual(launch.call_args.kwargs["wait_seconds"], 60)
                    detect.assert_not_called()
                    write_result.assert_not_called()
                for invalid_wait in (True, 0, -1, 4_294_967):
                    with self.subTest(invalid_wait=invalid_wait), self.assertRaisesRegex(ValueError, "wait limit"):
                        self.verify(approved, pin, policy_pin=launch_pin, **launch_options, windows_setup_wait_seconds=invalid_wait)

                failed_start = staging / (attempt_id + ".started.json")
                failed_result = staging / (attempt_id + ".result.json")

                def fail_dispatch(*args, **kwargs):
                    with patch.object(release.subprocess, "Popen", side_effect=PermissionError("private path")):
                        return native_launch(*args, **kwargs)

                launch.side_effect = fail_dispatch
                try:
                    failure = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                          windows_upgrade_attempt_id=attempt_id)
                    update = failure["managedUpdate"]
                    self.assertIsNone(update["setupExitCode"])
                    self.assertEqual(update["installedDetection"], "unverified")
                    self.assertEqual(update["installedDetectionReason"], "setup-launch-failed")
                    self.assertEqual(update["startReceiptSHA256"], release.digest(failed_start))
                    self.assertFalse(failed_result.exists())
                    self.assertNotIn("private path", json.dumps(failure))
                    detect.assert_not_called()
                    with self.assertRaises(FileExistsError):
                        self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                    windows_upgrade_attempt_id=attempt_id)
                finally:
                    launch.side_effect = None
                    failed_start.unlink(missing_ok=True)

                def fail_wait(*args, **kwargs):
                    process = Mock()
                    process.wait.side_effect = OSError("private wait failure")
                    with patch.object(release.subprocess, "Popen", return_value=process) as dispatch:
                        try:
                            return native_launch(*args, **kwargs)
                        finally:
                            dispatch.assert_called_once()
                            process.wait.assert_called_once_with(timeout=None)

                real_policy_check = release.require_current_revocation_policy

                def expire_after_receipt(policy, **kwargs):
                    if failed_start.exists():
                        raise ValueError("Revocation policy is outside its validity window")
                    return real_policy_check(policy, **kwargs)

                def expire_before_dispatch(*args, **kwargs):
                    with patch.object(release, "require_current_revocation_policy",
                                      side_effect=expire_after_receipt), \
                            patch.object(release.subprocess, "Popen") as dispatch:
                        try:
                            return native_launch(*args, **kwargs)
                        finally:
                            dispatch.assert_not_called()

                for reason in ("setup-wait-failed", "revocation-policy-expired"):
                    with self.subTest(reason=reason):
                        launch.side_effect = fail_wait if reason == "setup-wait-failed" else expire_before_dispatch
                        try:
                            report = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                                 windows_upgrade_attempt_id=attempt_id)
                            update = report["managedUpdate"]
                            self.assertEqual(report["revocationCheckPassed"], reason == "setup-wait-failed")
                            self.assertEqual(update["attemptID"], attempt_id)
                            self.assertIsNone(update["setupExitCode"])
                            self.assertEqual(update["installedDetection"], "unverified")
                            self.assertEqual(update["installedDetectionReason"], reason)
                            self.assertEqual(update["startReceiptSHA256"], release.digest(failed_start))
                            if reason == "revocation-policy-expired":
                                self.assertIs(update["setupDispatched"], False)
                                self.assertEqual(update["resultReceiptStatus"], "published")
                                self.assertEqual(update["resultReceiptSHA256"], release.digest(failed_result))
                                saved_start = json.loads(failed_start.read_bytes())
                                self.assertEqual(release.load_windows_upgrade_result_receipt(
                                    approved, failed_result, update["resultReceiptSHA256"], saved_start,
                                ), {"setupExitCode": None, "setupDispatched": False,
                                    "installedDetection": "unverified",
                                    "installedDetectionReason": "revocation-policy-expired"})
                                policy_blocked_result = failed_result.read_bytes()
                            else:
                                self.assertFalse(failed_result.exists())
                                self.assertNotIn("setupDispatched", update)
                            self.assertNotIn("private wait failure", json.dumps(update))
                            detect.assert_not_called()
                        finally:
                            launch.side_effect = None
                            failed_start.unlink(missing_ok=True)
                            failed_result.unlink(missing_ok=True)

                launch.return_value = 0
                result = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                     windows_upgrade_attempt_id=attempt_id)["managedUpdate"]
                attempt = launch.call_args.kwargs["attempt"]
                self.assertEqual(attempt["attemptID"], attempt_id)
                self.assertEqual(attempt["schemaVersion"], 2)
                self.assertEqual(attempt["boot"], initial_boot)
                self.assertEqual(attempt["manifestSHA256"], release.digest(manifest))
                self.assertEqual(attempt["approvalCertificateSHA256"], pin)
                self.assertEqual(attempt["revocationListSHA256"], launch_pin)
                self.assertEqual(attempt["installerSHA256"], original_setup_pin)
                self.assertEqual(attempt["windowsSetupBaselineArgument"], original_baseline)
                completed_receipt = staging / (attempt_id + ".result.json")
                self.assertEqual(json.loads(completed_receipt.read_bytes()),
                                 {**attempt, "setupExitCode": 0, "installedDetection": "detected"})
                self.assertEqual(result["resultReceiptSHA256"], release.digest(completed_receipt))
                completed_receipt.unlink()
                self.assertEqual(result["setupExitCode"], 0)
                self.assertEqual(result["installedDetection"], "detected")
                self.assertEqual(result["resultReceiptStatus"], "published")
                detect.assert_called_once_with(result["windowsUpgradeDetection"], launch_options["windows_payload_publisher"])

                detect.return_value = ("unverified", "detector-timeout")
                result = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                     windows_upgrade_attempt_id=attempt_id)["managedUpdate"]
                detect.return_value = ("detected", None)
                expected = {"setupExitCode": 0, "installedDetection": "unverified",
                            "installedDetectionReason": "detector-timeout"}
                self.assertEqual({field: result[field] for field in expected}, expected)
                historical = release.load_windows_upgrade_result_receipt(
                    approved, completed_receipt, result["resultReceiptSHA256"], attempt)
                self.assertEqual(historical, expected)
                completed_receipt.unlink()

                real_check = release.require_current_revocation_policy
                for when in ("setup", "detection"):
                    with self.subTest(expired_after=when):
                        detect.reset_mock()
                        launch.reset_mock()

                        def check_after_native_call(policy, **kwargs):
                            if detect.called or (when == "setup" and launch.called):
                                raise ValueError("Revocation policy is outside its validity window")
                            return real_check(policy, **kwargs)

                        with patch.object(release, "require_current_revocation_policy", side_effect=check_after_native_call):
                            report = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                                 windows_upgrade_attempt_id=attempt_id)
                        result = report["managedUpdate"]
                        receipt_path = staging / (attempt_id + ".result.json")
                        try:
                            self.assertFalse(report["revocationCheckPassed"])
                            self.assertEqual(result["setupExitCode"], 0)
                            self.assertEqual(result["installedDetection"], "unverified")
                            self.assertEqual(result["installedDetectionReason"], "revocation-policy-expired")
                            self.assertEqual(detect.call_count, int(when == "detection"))
                            receipt = json.loads(receipt_path.read_bytes())
                            self.assertEqual(receipt, {**attempt, "setupExitCode": 0, "installedDetection": "unverified",
                                                       "installedDetectionReason": "revocation-policy-expired"})
                        finally:
                            receipt_path.unlink(missing_ok=True)

                real_write = release.write_windows_upgrade_receipt
                policy_expired = False

                def publish_then_expire(destination, receipt):
                    nonlocal policy_expired
                    fingerprint = real_write(destination, receipt)
                    policy_expired = True
                    return fingerprint

                def check_after_receipt(policy, **kwargs):
                    if policy_expired:
                        raise ValueError("Revocation policy is outside its validity window")
                    return real_check(policy, **kwargs)

                with patch.object(release, "write_windows_upgrade_receipt", side_effect=publish_then_expire), \
                        patch.object(release, "require_current_revocation_policy", side_effect=check_after_receipt):
                    report = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                         windows_upgrade_attempt_id=attempt_id)
                result = report["managedUpdate"]
                self.assertFalse(report["revocationCheckPassed"])
                self.assertEqual(result["setupExitCode"], 0)
                self.assertEqual(result["installedDetection"], "unverified")
                self.assertEqual(result["installedDetectionReason"], "revocation-policy-expired")
                self.assertEqual(result["resultReceiptStatus"], "published")
                self.assertEqual(release.load_windows_upgrade_result_receipt(
                    approved, receipt_path, result["resultReceiptSHA256"], attempt,
                ), {"setupExitCode": 0, "installedDetection": "detected"})
                receipt_path.unlink()

                for setup_code, expected_detection in ((0, "detected"), (3010, "restart-required"), (7, "setup-failed")):
                    with self.subTest(result_receipt_unavailable=setup_code):
                        launch.return_value = setup_code
                        with patch.object(release, "write_windows_upgrade_receipt", side_effect=PermissionError) as write:
                            result = self.verify(approved, pin, policy_pin=launch_pin, **launch_options,
                                                 windows_upgrade_attempt_id=attempt_id)["managedUpdate"]
                        self.assertEqual(result["setupExitCode"], setup_code)
                        self.assertEqual(result["installedDetection"], expected_detection)
                        self.assertEqual(result["resultReceiptStatus"], "unverified")
                        self.assertNotIn("resultReceiptSHA256", result)
                        self.assertEqual(write.call_args.args[0], receipt_path)
                        self.assertFalse(receipt_path.exists())

                def expire_after_setup(policy, **kwargs):
                    if launch.called:
                        raise ValueError("Revocation policy is outside its validity window")
                    return real_check(policy, **kwargs)

                detect.reset_mock()
                for code, status in ((3010, "restart-required"), (7, "setup-failed")):
                    with self.subTest(expired_setup_exit=code):
                        launch.reset_mock()
                        launch.return_value = code
                        with patch.object(release, "require_current_revocation_policy", side_effect=expire_after_setup):
                            report = self.verify(approved, pin, policy_pin=launch_pin, **launch_options)
                        self.assertFalse(report["revocationCheckPassed"])
                        self.assertEqual(report["managedUpdate"]["setupExitCode"], code)
                        self.assertEqual(report["managedUpdate"]["installedDetection"], status)
                        detect.assert_not_called()
                launch.reset_mock()
                detect_options = {**launch_options, "stage_directory": None, "launch_staged_windows_setup": False,
                                  "detect_installed_windows_upgrade": True,
                                  "resume_windows_upgrade_setup_sha256": original_setup_pin,
                                  "resume_windows_upgrade_baseline_argument": original_baseline}
                for changed, message in (
                    ({"stage_directory": staging}, "cannot stage or launch"),
                    ({"resume_windows_upgrade_baseline_argument": None}, "original approved Setup digest and baseline"),
                    ({"resume_windows_upgrade_baseline_argument": wrong_baseline}, "differs from the original approved upgrade"),
                    ({"resume_windows_upgrade_setup_sha256": "0" * 64}, "differs from the original approved upgrade package"),
                ):
                    with self.subTest(post_restart=changed), self.assertRaisesRegex(ValueError, message):
                        self.verify(approved, pin, policy_pin=launch_pin, **{**detect_options, **changed})
                detect.assert_not_called()
                launch.assert_not_called()
                staged_path.unlink()
                observed = self.verify(approved, pin, policy_pin=launch_pin, **detect_options)["managedUpdate"]
                self.assertEqual(observed["installedDetection"], "detected")
                self.assertNotIn("setupExitCode", observed)
                detect.assert_called_once_with(observed["windowsUpgradeDetection"], launch_options["windows_payload_publisher"])
                self.assertEqual(host.call_args.kwargs, {"elevated": False})
                launch.assert_not_called()
                self.assertEqual(list(staging.iterdir()), [])

                start_file = staging / (attempt_id + ".started.json")
                receipt_options = {**detect_options, "resume_windows_upgrade_setup_sha256": None,
                                   "resume_windows_upgrade_baseline_argument": None}
                for change, message in (
                    ({"manifestSHA256": "0" * 64}, "differs from the saved start receipt"),
                    ({"target": "windows/amd64" if observed["target"] == "windows/arm64" else "windows/arm64"},
                     "differs from the saved start receipt"),
                    ({"revocationListSHA256": "0" * 64}, "original revocation policy or a newer sequence"),
                    ({"revocationPolicySequence": True}, "Malformed Windows upgrade start receipt"),
                    ({"boot": {**initial_boot, "bootTicks": 638900000000000000}}, "Malformed Windows upgrade boot evidence"),
                    ({"boot": {**initial_boot, "endpointSHA256": "private host"}}, "Malformed Windows upgrade boot evidence"),
                    ({"revocationPolicySequence": 5}, "original revocation policy or a newer sequence"),
                    ({"setupExitCode": 0}, "Malformed Windows upgrade start receipt"),
                ):
                    start_file.write_text(json.dumps({**attempt, **change}), encoding="utf-8")
                    detect.reset_mock()
                    with self.subTest(start_receipt=change), self.assertRaisesRegex(ValueError, message):
                        self.verify(approved, pin, policy_pin=launch_pin, **receipt_options,
                                    windows_upgrade_start_receipt=(start_file, release.digest(start_file)))
                    detect.assert_not_called()

                start_file.unlink()
                start_digest = release.write_windows_upgrade_receipt(start_file, attempt)
                self.assertEqual(start_digest, release.digest(start_file))
                with self.assertRaisesRegex(ValueError, "independently approved fingerprint"):
                    self.verify(approved, pin, policy_pin=launch_pin, **receipt_options,
                                windows_upgrade_start_receipt=(start_file, "0" * 64))
                newer_policy = {**launch_policy, "sequence": 5}
                newer_pin = self.write_policy(newer_policy)
                receipt = (start_file, start_digest)
                revoked_policy = {**newer_policy, "subjectSHA256": [original_setup_pin]}
                with self.assertRaisesRegex(ValueError, "is revoked"):
                    self.verify(approved, pin, policy_pin=self.write_policy(revoked_policy), **receipt_options,
                                windows_upgrade_start_receipt=receipt)
                self.assertEqual(release.digest(start_file), start_digest)
                detect.assert_not_called()
                launch.assert_not_called()
                self.assertEqual(list(staging.iterdir()), [start_file])
                self.write_policy(newer_policy)
                later_boot = {**initial_boot, "bootTicks": "638900000000000001"}
                boot.side_effect = [initial_boot, later_boot, later_boot]
                pending = self.verify(approved, pin, policy_pin=newer_pin, **receipt_options,
                                      windows_upgrade_start_receipt=receipt)["managedUpdate"]
                self.assertEqual(pending["attemptID"], attempt_id)
                self.assertEqual(pending["installedDetection"], "unverified")
                self.assertEqual(pending["installedDetectionReason"], "restart-status-unverified")
                self.assertNotIn("recordedSetupResult", pending)
                detect.assert_not_called()
                recovered = self.verify(approved, pin, policy_pin=newer_pin, **receipt_options,
                                        windows_upgrade_start_receipt=receipt)["managedUpdate"]
                boot.side_effect = None
                self.assertEqual(recovered["attemptID"], attempt_id)
                self.assertEqual(recovered["installedDetection"], "detected")
                detect.assert_called_once()
                launch.assert_not_called()
                self.assertEqual(list(staging.iterdir()), [start_file])
                self.assertEqual(release.digest(start_file), start_digest)

                historical = {"setupExitCode": 3010, "installedDetection": "restart-required"}
                for overrides, message in (
                    ({"attemptID": "b" * 32}, "differs from the saved start receipt"),
                    ({"revocationPolicySequence": True}, "differs from the saved start receipt"),
                    ({"manifestSHA256": "0" * 64}, "differs from the saved start receipt"),
                    ({"setupExitCode": True}, "Malformed Windows upgrade result receipt"),
                    ({"setupExitCode": 0}, "Malformed Windows upgrade result receipt"),
                    ({"installedDetectionReason": "private exception"}, "Malformed Windows upgrade result receipt"),
                    ({}, "independently approved fingerprint"),
                    ({}, None),
                ):
                    with self.subTest(result_receipt=overrides, message=message):
                        result_bytes = json.dumps({**attempt, **historical, **overrides}).encode("ascii")
                        completed_receipt.write_bytes(result_bytes)
                        result_pin = release.digest(completed_receipt) if message != "independently approved fingerprint" else "0" * 64
                        detect.reset_mock()
                        options = {**receipt_options, "windows_upgrade_start_receipt": receipt,
                                   "windows_upgrade_result_receipt": (completed_receipt, result_pin)}
                        if message is not None:
                            with self.assertRaisesRegex(ValueError, message):
                                self.verify(approved, pin, policy_pin=newer_pin, **options)
                            detect.assert_not_called()
                        else:
                            for observation, reason in (
                                (initial_boot, "restart-required"),
                                ({**initial_boot, "bootTicks": "638899999999999999"}, "restart-required"),
                                ({**initial_boot, "endpointSHA256": "a" * 64}, "endpoint-mismatch"),
                                (OSError("private provider error"), "boot-evidence-unavailable"),
                                ({**initial_boot, "bootTicks": "638900000000000001"}, None),
                            ):
                                with self.subTest(boot=reason):
                                    boot.side_effect = [observation, observation] if reason is None else [observation]
                                    detect.reset_mock()
                                    readback = self.verify(approved, pin, policy_pin=newer_pin, **options)["managedUpdate"]
                                    self.assertEqual(readback["recordedSetupResult"], historical)
                                    self.assertEqual(readback["attemptID"], attempt_id)
                                    self.assertNotIn("setupExitCode", readback)
                                    if reason is None:
                                        self.assertEqual(readback["installedDetection"], "detected")
                                        detect.assert_called_once()
                                    else:
                                        self.assertEqual(readback["installedDetection"], "unverified")
                                        self.assertEqual(readback["installedDetectionReason"], reason)
                                        detect.assert_not_called()
                            boot.side_effect = None
                        launch.assert_not_called()
                        self.assertEqual(completed_receipt.read_bytes(), result_bytes)
                        self.assertEqual(release.digest(start_file), start_digest)
                completed_receipt.unlink()
                legacy_start = staging / "legacy.started.json"
                legacy = {field: value for field, value in attempt.items() if field != "boot"}
                legacy["schemaVersion"] = 1
                legacy_digest = release.write_windows_upgrade_receipt(legacy_start, legacy)
                detect.reset_mock()
                legacy_recovery = self.verify(approved, pin, policy_pin=newer_pin, **receipt_options,
                                              windows_upgrade_start_receipt=(legacy_start, legacy_digest))["managedUpdate"]
                self.assertEqual(legacy_recovery["installedDetectionReason"], "boot-evidence-unavailable")
                detect.assert_not_called()
                legacy_start.unlink()

                completed = {"setupExitCode": 0, "installedDetection": "detected"}
                result_pin = release.write_windows_upgrade_receipt(completed_receipt, {**attempt, **completed})
                confirmed = self.verify(approved, pin, policy_pin=newer_pin, **receipt_options,
                                        windows_upgrade_start_receipt=receipt,
                                        windows_upgrade_result_receipt=(completed_receipt, result_pin))["managedUpdate"]
                self.assertEqual(confirmed["recordedSetupResult"], completed)
                self.assertEqual(confirmed["installedDetection"], "detected")
                detect.assert_called_once()
                for final_boot, reason in (
                    ({**initial_boot, "endpointSHA256": "a" * 64}, "boot-evidence-changed"),
                    (later_boot, "boot-evidence-changed"),
                    (OSError("private provider failure"), "boot-evidence-unavailable"),
                ):
                    with self.subTest(final_boot=reason):
                        boot.side_effect = [initial_boot, final_boot]
                        detect.reset_mock()
                        readback = self.verify(approved, pin, policy_pin=newer_pin, **receipt_options,
                                               windows_upgrade_start_receipt=receipt,
                                               windows_upgrade_result_receipt=(completed_receipt, result_pin))["managedUpdate"]
                        self.assertEqual(readback["installedDetection"], "unverified")
                        self.assertEqual(readback["installedDetectionReason"], reason)
                        self.assertEqual(readback["recordedSetupResult"], completed)
                        self.assertEqual(readback["attemptID"], attempt_id)
                        self.assertNotIn("private provider failure", json.dumps(readback))
                        self.assertEqual(release.digest(completed_receipt), result_pin)
                        detect.assert_called_once()
                        launch.assert_not_called()
                def expire_during_final_boot(policy, **kwargs):
                    if boot.call_count == 2:
                        raise ValueError("Revocation policy is outside its validity window")
                    return real_check(policy, **kwargs)

                boot.reset_mock()
                boot.side_effect = [initial_boot, initial_boot]
                with patch.object(release, "require_current_revocation_policy", side_effect=expire_during_final_boot):
                    report = self.verify(approved, pin, policy_pin=newer_pin, **receipt_options,
                                         windows_upgrade_start_receipt=receipt,
                                         windows_upgrade_result_receipt=(completed_receipt, result_pin))
                self.assertFalse(report["revocationCheckPassed"])
                self.assertEqual(report["managedUpdate"]["installedDetection"], "unverified")
                self.assertEqual(report["managedUpdate"]["installedDetectionReason"], "revocation-policy-expired")
                self.assertEqual(release.digest(completed_receipt), result_pin)
                boot.side_effect = None
                completed_receipt.unlink()
                detect.reset_mock()

                def expire_during_recovery(policy, **kwargs):
                    if detect.called:
                        raise ValueError("Revocation policy is outside its validity window")
                    return real_check(policy, **kwargs)

                with patch.object(release, "require_current_revocation_policy", side_effect=expire_during_recovery):
                    boot.side_effect = [{**initial_boot, "bootTicks": "638900000000000001"}]
                    report = self.verify(approved, pin, policy_pin=newer_pin, **receipt_options,
                                         windows_upgrade_start_receipt=receipt)
                    boot.side_effect = None
                expired = report["managedUpdate"]
                self.assertFalse(report["revocationCheckPassed"])
                self.assertEqual(expired["attemptID"], attempt_id)
                self.assertEqual(expired["installedDetection"], "unverified")
                self.assertEqual(expired["installedDetectionReason"], "revocation-policy-expired")
                self.assertNotIn("setupExitCode", expired)
                detect.assert_called_once()
                launch.assert_not_called()
                self.assertEqual(list(staging.iterdir()), [start_file])
                self.assertEqual(release.digest(start_file), start_digest)

                blocked_receipt = self.root / "policy-blocked.result.json"
                blocked_receipt.write_bytes(policy_blocked_result)
                blocked_digest = release.digest(blocked_receipt)
                blocked = json.loads(policy_blocked_result)
                for changed in ({"setupDispatched": 0}, {"setupDispatched": True}, {"setupExitCode": 1603},
                                {"installedDetectionReason": "setup-launch-failed"},
                                {"installedDetectionReason": "setup-wait-timeout"}):
                    invalid_receipt = self.root / "invalid-dispatch.result.json"
                    invalid_receipt.write_text(json.dumps({**blocked, **changed}), encoding="ascii")
                    with self.subTest(invalid_dispatch=changed), self.assertRaisesRegex(
                            ValueError, "Malformed Windows upgrade result receipt"):
                        release.load_windows_upgrade_result_receipt(
                            approved, invalid_receipt, release.digest(invalid_receipt), attempt,
                        )
                nondispatch_attempt = "c" * 32
                launch.return_value = 0
                boot.side_effect = [initial_boot, {**initial_boot, "endpointSHA256": "c" * 64}]
                try:
                    retried_dispatch = self.verify(
                        approved, pin, policy_pin=newer_pin, **launch_options,
                        windows_upgrade_start_receipt=receipt,
                        windows_upgrade_result_receipt=(blocked_receipt, blocked_digest),
                        windows_upgrade_attempt_id=nondispatch_attempt,
                    )["managedUpdate"]
                finally:
                    boot.side_effect = None
                self.assertEqual(retried_dispatch["previousAttemptID"], attempt_id)
                self.assertEqual(launch.call_args.kwargs["attempt"]["previousResultReceiptSHA256"], blocked_digest)
                self.assertEqual(launch.call_args.kwargs["attempt"]["revocationPolicySequence"], 5)
                self.assertEqual(retried_dispatch["setupExitCode"], 0)
                self.assertEqual(release.digest(blocked_receipt), blocked_digest)
                (staging / (nondispatch_attempt + ".result.json")).unlink()
                staged_path.unlink()
                launch.reset_mock()

                retry_attempt_id = "b" * 32
                retry_from_receipt = {**launch_options, "windows_upgrade_start_receipt": receipt,
                                      "windows_upgrade_attempt_id": retry_attempt_id}
                with patch.object(release, "stage_managed_update") as stage:
                    with self.assertRaisesRegex(ValueError, "saved Setup failure result"):
                        self.verify(approved, pin, policy_pin=newer_pin, **retry_from_receipt)
                    for code, status in ((0, "detected"), (3010, "restart-required")):
                        terminal_pin = release.write_windows_upgrade_receipt(completed_receipt, {
                            **attempt, "setupExitCode": code, "installedDetection": status,
                        })
                        try:
                            with self.assertRaisesRegex(ValueError, "saved Setup failure result"):
                                self.verify(approved, pin, policy_pin=newer_pin, **retry_from_receipt,
                                            windows_upgrade_result_receipt=(completed_receipt, terminal_pin))
                        finally:
                            completed_receipt.unlink()
                    failure_pin = release.write_windows_upgrade_receipt(completed_receipt, {
                        **attempt, "setupExitCode": 1603, "installedDetection": "setup-failed",
                    })
                    retry_from_receipt["windows_upgrade_result_receipt"] = (completed_receipt, failure_pin)
                    for same_or_missing_id in (attempt_id, None):
                        with self.assertRaisesRegex(ValueError, "requires a new attempt ID"):
                            self.verify(approved, pin, policy_pin=newer_pin,
                                        **{**retry_from_receipt, "windows_upgrade_attempt_id": same_or_missing_id})
                    for observed_retry_boot in ({**initial_boot, "endpointSHA256": "5" * 64},
                                                {**initial_boot, "bootTicks": "638899999999999999"}):
                        boot.side_effect = [observed_retry_boot]
                        with self.assertRaisesRegex(ValueError, "original endpoint and a current boot"):
                            self.verify(approved, pin, policy_pin=newer_pin, **retry_from_receipt)
                    boot.side_effect = None
                    stage.assert_not_called()
                launch.assert_not_called()
                self.assertEqual(set(staging.iterdir()), {start_file, completed_receipt})

                retry_boot = {**later_boot, "endpointSHA256": "b" * 64}
                boot.side_effect = [later_boot, {**retry_boot, "bootTicks": initial_boot["bootTicks"]}]
                try:
                    with patch.object(release, "stage_managed_update"), self.assertRaisesRegex(
                            ValueError, "boot evidence changed before dispatch"):
                        self.verify(approved, pin, policy_pin=newer_pin, **retry_from_receipt)
                finally:
                    boot.side_effect = None
                launch.assert_not_called()
                self.assertEqual(set(staging.iterdir()), {start_file, completed_receipt})
                boot.side_effect = [later_boot, retry_boot]
                process = Mock()
                process.wait.return_value = 0

                def dispatch_receipt_bound_retry(*args, **kwargs):
                    with patch.object(release.subprocess, "Popen", return_value=process) as dispatch:
                        result = native_launch(*args, **kwargs)
                        dispatch.assert_called_once()
                        self.assertEqual(dispatch.call_args.args[0][-1], original_baseline)
                        return result

                launch.side_effect = dispatch_receipt_bound_retry
                try:
                    retried = self.verify(approved, pin, policy_pin=newer_pin, **retry_from_receipt)["managedUpdate"]
                finally:
                    launch.side_effect = None
                    boot.side_effect = None
                self.assertEqual(retried["setupExitCode"], 0)
                self.assertEqual(retried["installedDetection"], "detected")
                self.assertEqual(retried["previousAttemptID"], attempt_id)
                self.assertEqual(release.digest(start_file), start_digest)
                self.assertEqual(release.digest(completed_receipt), failure_pin)
                retry_start = staging / (retry_attempt_id + ".started.json")
                retry_result = staging / (retry_attempt_id + ".result.json")
                lineage = release.load_windows_upgrade_start_receipt(approved, retry_start, retried["startReceiptSHA256"])
                self.assertEqual(lineage, {**attempt, "schemaVersion": 3, "attemptID": retry_attempt_id,
                                           "boot": retry_boot, "revocationPolicySequence": 5,
                                           "revocationListSHA256": newer_pin, "previousAttemptID": attempt_id,
                                           "previousStartReceiptSHA256": start_digest,
                                           "previousResultReceiptSHA256": failure_pin})
                self.assertEqual(release.load_windows_upgrade_result_receipt(
                    approved, retry_result, retried["resultReceiptSHA256"], lineage,
                ), {"setupExitCode": 0, "installedDetection": "detected"})
                launch.reset_mock()
                boot.side_effect = [retry_boot, retry_boot]
                try:
                    retried_detection = self.verify(
                        approved, pin, policy_pin=newer_pin, **receipt_options,
                        windows_upgrade_start_receipt=(retry_start, retried["startReceiptSHA256"]),
                        windows_upgrade_result_receipt=(retry_result, retried["resultReceiptSHA256"]),
                    )["managedUpdate"]
                finally:
                    boot.side_effect = None
                self.assertEqual(retried_detection["attemptID"], retry_attempt_id)
                self.assertEqual(retried_detection["installedDetection"], "detected")
                launch.assert_not_called()
                for fixture_path in (retry_start, retry_result, staged_path):
                    fixture_path.unlink()

                reboot_retry_id = "d" * 32
                reboot_retry = {**launch_options, "windows_upgrade_start_receipt": receipt,
                                "windows_upgrade_attempt_id": reboot_retry_id, "retry_windows_upgrade_after_reboot": True}
                boot.side_effect = [later_boot]
                try:
                    with self.assertRaisesRegex(ValueError, "found an existing result receipt"):
                        self.verify(approved, pin, policy_pin=newer_pin, **reboot_retry)
                finally:
                    boot.side_effect = None
                completed_receipt.unlink()
                detect.reset_mock()
                with patch.object(release, "stage_managed_update") as stage:
                    with self.assertRaisesRegex(ValueError, "requires a later boot"):
                        self.verify(approved, pin, policy_pin=newer_pin, **reboot_retry)
                    detect.assert_not_called()
                    for observation in (("detected", None), ("unverified", "detector-inspection-failed"),
                                        ("unverified", "approved-installation-not-detected"),
                                        ("unverified", "installer-recovery-pending")):
                        boot.side_effect = [later_boot]
                        detect.side_effect = [observation]
                        try:
                            with self.subTest(reboot_retry_detection=observation), self.assertRaisesRegex(
                                    ValueError, "requires a verified pending installation marker"):
                                self.verify(approved, pin, policy_pin=newer_pin, **reboot_retry)
                        finally:
                            boot.side_effect = None
                            detect.side_effect = None
                    stage.assert_not_called()
                    self.assertTrue(detect.call_args_list)
                    self.assertTrue(all(call.kwargs.get("pending_approval") == expected_approval for call in detect.call_args_list))
                launch.assert_not_called()

                pending_status = ("unverified", "installer-managed-upgrade-pending")
                reboot_boot = {**later_boot, "endpointSHA256": "d" * 64}
                boot.side_effect = [later_boot, reboot_boot]
                detect.side_effect = [pending_status, ("detected", None)]
                try:
                    with patch.object(release, "stage_managed_update") as stage, self.assertRaisesRegex(
                            ValueError, "requires a verified pending installation marker"):
                        self.verify(approved, pin, policy_pin=newer_pin, **reboot_retry)
                    stage.assert_called_once()
                finally:
                    boot.side_effect = None
                    detect.side_effect = None
                launch.assert_not_called()
                self.assertEqual(list(staging.iterdir()), [start_file])

                def reject_late_dispatch(*args, **kwargs):
                    with patch.object(release.subprocess, "Popen") as dispatch:
                        try:
                            return native_launch(*args, **kwargs)
                        finally:
                            dispatch.assert_not_called()

                reboot_start = staging / (reboot_retry_id + ".started.json")
                reboot_result = staging / (reboot_retry_id + ".result.json")
                arrival = b"retained original result"
                observed = iter((False, True))

                def detect_with_late_result(_qualification, _publisher, *, pending_approval):
                    self.assertEqual(pending_approval, expected_approval)
                    if next(observed):
                        completed_receipt.write_bytes(arrival)
                    return pending_status

                boot.side_effect = [later_boot, reboot_boot]
                detect.side_effect = detect_with_late_result
                launch.side_effect = reject_late_dispatch
                try:
                    stopped = self.verify(approved, pin, policy_pin=newer_pin, **reboot_retry)["managedUpdate"]
                finally:
                    boot.side_effect = None
                    detect.side_effect = None
                    launch.side_effect = None
                self.assertIs(stopped["setupDispatched"], False)
                self.assertEqual(stopped["installedDetectionReason"], release.WINDOWS_PREVIOUS_RESULT_UNVERIFIED)
                self.assertNotIn("startReceiptSHA256", stopped)
                self.assertFalse(reboot_start.exists())
                self.assertFalse(reboot_result.exists())
                self.assertEqual(completed_receipt.read_bytes(), arrival)
                completed_receipt.unlink()

                retained = self.root / "retained-start.json"
                retained.write_bytes(start_file.read_bytes())
                retained_result = retained.parent / completed_receipt.name
                write_receipt = release.write_windows_upgrade_receipt

                def publish_start_with_late_result(path, record):
                    saved = write_receipt(path, record)
                    if path == reboot_start:
                        retained_result.write_bytes(arrival)
                    return saved

                boot.side_effect = [later_boot, reboot_boot]
                detect.side_effect = [pending_status, pending_status]
                launch.side_effect = reject_late_dispatch
                try:
                    with patch.object(release, "write_windows_upgrade_receipt", side_effect=publish_start_with_late_result):
                        stopped = self.verify(approved, pin, policy_pin=newer_pin, **{
                            **reboot_retry, "windows_upgrade_start_receipt": (retained, start_digest),
                        })["managedUpdate"]
                finally:
                    boot.side_effect = None
                    detect.side_effect = None
                    launch.side_effect = None
                self.assertIs(stopped["setupDispatched"], False)
                self.assertIsNone(stopped["setupExitCode"])
                self.assertEqual(stopped["installedDetectionReason"], release.WINDOWS_PREVIOUS_RESULT_UNVERIFIED)
                self.assertEqual(retained_result.read_bytes(), arrival)
                stopped_start = (reboot_start, stopped["startReceiptSHA256"])
                stopped_result = (reboot_result, stopped["resultReceiptSHA256"])
                lineage = release.load_windows_upgrade_start_receipt(approved, *stopped_start)
                self.assertEqual(release.load_windows_upgrade_result_receipt(approved, *stopped_result, lineage), {
                    "setupDispatched": False, "setupExitCode": None, "installedDetection": "unverified",
                    "installedDetectionReason": release.WINDOWS_PREVIOUS_RESULT_UNVERIFIED,
                })
                launch.reset_mock()
                with self.assertRaisesRegex(ValueError, "Verify the original Windows Setup result"):
                    self.verify(approved, pin, policy_pin=newer_pin, **{
                        **launch_options, "windows_upgrade_attempt_id": "e" * 32,
                        "windows_upgrade_start_receipt": stopped_start, "windows_upgrade_result_receipt": stopped_result,
                    })
                launch.assert_not_called()
                for fixture_path in (retained, retained_result, reboot_start, reboot_result):
                    fixture_path.unlink()

                boot.side_effect = [later_boot, reboot_boot]
                detect.side_effect = [pending_status, pending_status, ("detected", None)]
                launch.side_effect = dispatch_receipt_bound_retry
                try:
                    recovery = self.verify(approved, pin, policy_pin=newer_pin, **reboot_retry)["managedUpdate"]
                finally:
                    boot.side_effect = None
                    detect.side_effect = None
                    launch.side_effect = None
                self.assertEqual(recovery["setupExitCode"], 0)
                self.assertEqual(recovery["installedDetection"], "detected")
                reboot_start = staging / (reboot_retry_id + ".started.json")
                reboot_result = staging / (reboot_retry_id + ".result.json")
                reboot_lineage = release.load_windows_upgrade_start_receipt(
                    approved, reboot_start, recovery["startReceiptSHA256"],
                )
                self.assertEqual(reboot_lineage, {
                    **attempt, "schemaVersion": 4, "attemptID": reboot_retry_id, "boot": reboot_boot,
                    "revocationPolicySequence": 5, "revocationListSHA256": newer_pin,
                    "previousAttemptID": attempt_id, "previousStartReceiptSHA256": start_digest,
                    "previousBootTicks": initial_boot["bootTicks"],
                })
                self.assertEqual(release.load_windows_upgrade_result_receipt(
                    approved, reboot_result, recovery["resultReceiptSHA256"], reboot_lineage,
                ), {"setupExitCode": 0, "installedDetection": "detected"})
                self.assertEqual(release.digest(start_file), start_digest)
                launch.reset_mock()
                boot.side_effect = [reboot_boot, reboot_boot]
                try:
                    post_reboot_retry = self.verify(
                        approved, pin, policy_pin=newer_pin, **receipt_options,
                        windows_upgrade_start_receipt=(reboot_start, recovery["startReceiptSHA256"]),
                        windows_upgrade_result_receipt=(reboot_result, recovery["resultReceiptSHA256"]),
                    )["managedUpdate"]
                finally:
                    boot.side_effect = None
                self.assertEqual(post_reboot_retry["installedDetection"], "detected")
                self.assertEqual(post_reboot_retry["attemptID"], reboot_retry_id)
                launch.assert_not_called()
                for fixture_path in (start_file, reboot_start, reboot_result, staged_path):
                    fixture_path.unlink()
            self.write_policy(self.policy)
        strict_args = [*retry_cli, "--require-windows-setup-wrong-baseline-refusal"]
        refused = subprocess.run(strict_args, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(refused.stdout, "")
        with self.assertRaisesRegex(ValueError, "lacks signed incorrect Setup baseline refusal evidence"):
            self.verify(approved, pin, stage_directory=staging, **inventory_options,
                        require_windows_setup_wrong_baseline_refusal=True)
        self.assertEqual(list(staging.iterdir()), [])

        evidence = self.write_reboot_report(
            "upgrade-wrong-baseline-refused.json", schemaVersion=13, installMode="upgrade",
            previousVersion="1.2.2-rc.1", previousPayloadSHA256="d" * 64,
            userProfilePreservedThroughUpgrade=True, uninstallerSHA256="e" * 64,
        )
        latest_entry, = release.load_detection_evidence(self.candidate, [evidence], files, VERSION)
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, files, [entries[0], latest_entry, entries[2]]))
        sign_manifest()
        completed = subprocess.run(strict_args, check=True, capture_output=True, text=True, timeout=30)
        report = json.loads(completed.stdout)
        self.assertEqual(report["schemaVersion"], 10)
        update = report["managedUpdate"]
        self.assertEqual(update["windowsUpgradeDetection"]["detectorSHA256"], "1" * 64)
        self.assertIs(update["windowsUpgradeDetection"]["setupWrongBaselineRefusedWithStatePreserved"], True)
        self.assertEqual(update["windowsSetupBaselineArgument"], selected["managedUpdate"]["windowsSetupBaselineArgument"])
        self.assertTrue(update["installerStaged"])
        staged_path.unlink()
        revoked_detector = self.write_policy({**self.policy, "subjectSHA256": [latest_entry["detectorSHA256"]]})
        with self.assertRaisesRegex(ValueError, "revoked"):
            self.verify(approved, pin, policy_pin=revoked_detector, stage_directory=staging, **inventory_options)
        self.assertEqual(list(staging.iterdir()), [])
        self.write_policy(self.policy)
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, files, entries))
        sign_manifest()
        self.verify(approved, pin, current_build_info_sha256="5" * 64, **trusted)
        for update, error in (
            ({"current_build_info_sha256": "0" * 64}, "matches the installed Windows build metadata"),
            ({"current_build_info_sha256": "invalid"}, "requires all installed trust pins"),
        ):
            with self.subTest(build_info=update), self.assertRaisesRegex(ValueError, error):
                self.verify(approved, pin, stage_directory=staging, **trusted, **update)
        for invalid_inventory, error in (
            (inventory_record, "matches the installed Windows build metadata"),
            ({**new_inventory, "buildInfoSHA256": "0" * 64}, "matches the installed Windows build metadata"),
            ({**new_inventory, "buildInfoSHA256": ""}, "Malformed Windows upgrade inventory digest"),
            ({**new_inventory, "schemaVersion": 1}, "Malformed Windows upgrade inventory"),
        ):
            inventory_path.write_text(json.dumps(invalid_inventory), encoding="utf-8")
            with self.subTest(new_inventory=invalid_inventory), self.assertRaisesRegex(ValueError, error):
                self.verify(approved, pin, stage_directory=staging,
                            windows_upgrade_inventory=(inventory_path, release.digest(inventory_path)))
        inventory_path.write_text(json.dumps(new_inventory), encoding="utf-8")
        revoked_prior = self.write_policy({**self.policy, "subjectSHA256": ["5" * 64]})
        with self.assertRaisesRegex(ValueError, "revoked"):
            self.verify(approved, pin, policy_pin=revoked_prior, stage_directory=staging, **inventory_options)
        self.assertEqual(list(staging.iterdir()), [])
        self.write_policy(self.policy)
        without_build_info = [
            {field: value for field, value in entry.items() if field != release.WINDOWS_BUILD_INFO}
            for entry in data["windowsDetection"]
        ]
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, files, without_build_info))
        sign_manifest()
        self.assertEqual(self.verify(approved, pin, **qualified)["schemaVersion"], 5)
        no_downgrade = [
            {field: value for field, value in entry.items() if field not in release.WINDOWS_DOWNGRADE_FIELDS}
            for entry in without_build_info
        ]
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, files, no_downgrade))
        sign_manifest()
        self.assertEqual(self.verify(approved, pin, **qualified)["schemaVersion"], 4)

        legacy_fields = (*release.WINDOWS_PREVIOUS_TRUST_FIELDS, release.WINDOWS_PAYLOAD_PUBLISHER)
        legacy_entries = [
            {field: value for field, value in entry.items() if field not in legacy_fields}
            for entry in no_downgrade
        ]
        manifest.write_bytes(release.encode_manifest(COMMIT, REF, release.inventory(self.candidate, self.subjects), legacy_entries))
        sign_manifest()
        legacy_report = self.verify(approved, pin, **qualified)
        self.assertEqual(legacy_report["schemaVersion"], 2)
        with self.assertRaisesRegex(ValueError, "matches the installed Windows SBOM and publisher"):
            self.verify(approved, pin, stage_directory=staging, **trusted)
        self.assertEqual(list(staging.iterdir()), [])
        self.assertEqual(legacy_report["managedUpdate"]["windowsUpgradeDetection"],
                         {field: value for field, value in upgrade_entry.items()
                          if field not in legacy_fields + release.WINDOWS_DOWNGRADE_FIELDS})

        for bad_entries in (
            [legacy_entries[0], {**legacy_entries[1], "previousPayloadPublisherSHA256": "2" * 64}],
            [{**legacy_entries[0], "previousPayloadPublisherSHA256": "2" * 64,
              "previousPayloadSBOMSHA256": "1" * 64}],
            [legacy_entries[0], {**legacy_entries[1], "previousPayloadPublisherSHA256": "invalid",
                                 "previousPayloadSBOMSHA256": "1" * 64}],
        ):
            with self.assertRaises(ValueError):
                release.validate_detection(bad_entries, release.inventory(self.candidate, self.subjects), VERSION)

        manifest.write_bytes(original)
        sign_manifest()
        data["windowsDetection"][0]["uninstallerSHA256"] = "a" * 64
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify(approved, pin)
        del data["windowsDetection"][0]["previousPayloadSHA256"]
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        sign_manifest()
        with self.assertRaisesRegex(ValueError, "Malformed Windows detection entry"):
            self.verify(approved, pin)

        self.revocation_list.unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify(approved, pin)

    def test_managed_staging_rechecks_policy_after_copy_and_destination_readback(self):
        now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        expires = now + timedelta(seconds=1)
        policy = {**self.policy, "schemaVersion": 2, "sequence": 9,
                  "issuedAt": "2026-01-01T12:00:00Z", "expiresAt": "2026-01-01T12:00:01Z"}
        update = release.managed_update(release.inventory(self.candidate, self.subjects),
                                        "windows/arm64", "1.2.2-rc.1", VERSION)
        staging = self.root / "deadline-staging"
        staging.mkdir()
        destination = staging / update["installer"]
        original = (self.candidate / update["installer"]).read_bytes()

        for phase, times in (
            ("before publication", (expires,)),
            ("after publication", (now, expires)),
            ("on existing file", (expires,)),
        ):
            with self.subTest(phase=phase):
                readings = iter(times)

                class ControlledClock(datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return next(readings)

                if phase == "on existing file":
                    destination.write_bytes(original)
                with patch.object(release, "datetime", ControlledClock), \
                        self.assertRaisesRegex(ValueError, "outside its validity window"):
                    release.stage_managed_update(self.candidate, staging, update, policy, size=len(original),
                                                 directory_identity=release.staging_directory_identity(staging))
                if phase == "before publication":
                    self.assertEqual(list(staging.iterdir()), [])
                else:
                    self.assertEqual(destination.read_bytes(), original)
                    self.assertEqual(list(staging.iterdir()), [destination])
                    destination.unlink()

    @unittest.skipUnless(sys.platform in ("win32", "darwin", "linux"), "requires native exclusive rename")
    def test_retry_recovers_after_exit_immediately_after_publication(self):
        update = release.managed_update(release.inventory(self.candidate, self.subjects),
                                        "windows/amd64", "1.2.2-rc.1", VERSION)
        source = self.candidate / update["installer"]
        staging = self.root / "interrupted-staging"
        staging.mkdir()
        child = """
import os
from pathlib import Path
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, sys.argv[1])
import signed_release_manifest as release

source, staging = map(Path, sys.argv[2:4])
update = {"installer": source.name, "installerSHA256": release.digest(source)}
publish = release.publish_staged_installer

def publish_then_exit(staged, destination):
    publish(staged, destination)
    os._exit(73)

with patch.object(release, "publish_staged_installer", side_effect=publish_then_exit):
    release.stage_managed_update(source.parent, staging, update, {"schemaVersion": 1},
                                 size=source.stat().st_size,
                                 directory_identity=release.staging_directory_identity(staging))
"""
        process = subprocess.run([sys.executable, "-c", child, str(Path(release.__file__).parent),
                                  str(source), str(staging)], timeout=20, capture_output=True)
        self.assertEqual(process.returncode, 73, process.stderr.decode(errors="replace"))
        destination = staging / source.name
        original = source.read_bytes()
        published = destination.stat()
        self.assertEqual(published.st_nlink, 1)
        abandoned = [path for path in staging.iterdir() if path != destination]
        self.assertEqual(len(abandoned), 1)
        self.assertEqual(list(abandoned[0].iterdir()), [])

        release.stage_managed_update(self.candidate, staging, update, self.policy,
                                     size=len(original), directory_identity=release.staging_directory_identity(staging))
        self.assertTrue(os.path.samestat(published, destination.stat()))
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(list(abandoned[0].iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "requires Windows directory sharing")
    def test_windows_staging_holds_directory_chain_through_publication_and_readback(self):
        update = release.managed_update(release.inventory(self.candidate, self.subjects),
                                        "windows/arm64", "1.2.2-rc.1", VERSION)
        parent = self.root / "protected-staging-parent"
        staging = parent / "staging"
        staging.mkdir(parents=True)
        source = self.candidate / update["installer"]
        destination = staging / source.name
        identity = release.staging_directory_identity(staging)
        publish = release.publish_staged_installer
        verify_file = release.verify_staged_update

        def assert_renames_refused():
            for path in (staging, parent):
                with self.assertRaises(PermissionError) as refused:
                    path.rename(path.with_name("displaced"))
                self.assertEqual(refused.exception.winerror, 32)

        def publish_while_pinned(staged, final):
            assert_renames_refused()
            publish(staged, final)

        def readback_while_pinned(path, size, digest):
            if path == destination:
                assert_renames_refused()
            verify_file(path, size, digest)

        with patch.object(release, "publish_staged_installer", side_effect=publish_while_pinned) as renamed, \
                patch.object(release, "verify_staged_update", side_effect=readback_while_pinned):
            for _ in range(2):
                release.stage_managed_update(self.candidate, staging, update, self.policy,
                                             size=source.stat().st_size, directory_identity=identity)
            renamed.assert_called_once()
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        moved = parent.with_name("released-staging-parent")
        parent.rename(moved)
        self.assertTrue((moved / "staging" / source.name).is_file())

    def test_launch_cli_returns_setup_exit_code(self):
        argv = ["signed_release_manifest.py", "verify", str(self.candidate),
                "--source-commit", COMMIT, "--source-ref", REF, "--approval-certificate", "approval.cer",
                "--approval-certificate-sha256", "b" * 64, "--revocation-list", "revocation.json",
                "--revocation-list-sha256", self.policy_pin, "--launch-staged-windows-setup"]
        cases = (
            (None, "unverified", None, 1),
            (0, "detected", None, 0),
            (0, "detected", "published", 0),
            (0, "unverified", "published", 1),
            (0, "detected", "unverified", 1),
            (7, "setup-failed", "unverified", 7),
            (3010, "restart-required", "unverified", 3010),
        )
        for code, detection, receipt_status, expected in cases:
            update = {"setupExitCode": code, "installedDetection": detection}
            if receipt_status is not None:
                update["resultReceiptStatus"] = receipt_status
            report = {"managedUpdate": update}
            with self.subTest(code=code, detection=detection, receipt_status=receipt_status), patch.object(sys, "argv", argv), \
                    patch.object(release, "verify", return_value=report) as verify, redirect_stdout(io.StringIO()) as output:
                if code is None:
                    sys.argv = argv + ["--windows-setup-wait-seconds", "60"]
                self.assertEqual(release.main(), expected)
                self.assertEqual(json.loads(output.getvalue()), report)
                self.assertIs(verify.call_args.kwargs["launch_staged_windows_setup"], True)
                self.assertEqual(verify.call_args.kwargs["windows_setup_wait_seconds"], 60 if code is None else None)

    def test_installed_detection_cli_returns_confirmation_status(self):
        argv = ["signed_release_manifest.py", "verify", str(self.candidate),
                "--source-commit", COMMIT, "--source-ref", REF, "--approval-certificate", "approval.cer",
                "--approval-certificate-sha256", "b" * 64, "--revocation-list", "revocation.json",
                "--revocation-list-sha256", self.policy_pin, "--detect-installed-windows-upgrade",
                "--windows-upgrade-start-receipt", "start.json", "c" * 64,
                "--windows-upgrade-result-receipt", "result.json", "d" * 64]
        for detection, code in (("detected", 0), ("unverified", 1)):
            report = {"managedUpdate": {"installedDetection": detection}}
            with self.subTest(code=code), patch.object(sys, "argv", argv), \
                    patch.object(release, "verify", return_value=report) as verify, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(release.main(), code)
                self.assertEqual(json.loads(output.getvalue()), report)
                self.assertIs(verify.call_args.kwargs["detect_installed_windows_upgrade"], True)
                self.assertEqual(verify.call_args.kwargs["windows_upgrade_start_receipt"], (Path("start.json"), "c" * 64))
                self.assertEqual(verify.call_args.kwargs["windows_upgrade_result_receipt"], (Path("result.json"), "d" * 64))
                self.assertIs(verify.call_args.kwargs["launch_staged_windows_setup"], False)

    def test_windows_staging_detector_requires_exact_success_and_uses_signed_pins(self):
        qualification = {"target": "windows/arm64", "version": VERSION, "payloadSHA256": "a" * 64,
                         "payloadSBOMSHA256": "b" * 64, "buildInfoSHA256": "c" * 64, "uninstallerSHA256": "d" * 64}
        publisher = "e" * 64
        for code, content, reason in (
            (0, b"AccessWeaver detected\r\n", None),
            (0, b"AccessWeaver detected\n", None),
            (0, b"", "approved-installation-not-detected"),
            (1, b"", "detector-inspection-failed"),
            (1, b"AccessWeaver installation pending\r\n", "installer-recovery-pending"),
            (1, b"AccessWeaver installation pending\n", "installer-recovery-pending"),
            (1, b"AccessWeaver managed upgrade pending\r\n", "installer-managed-upgrade-pending"),
            (1, b"AccessWeaver managed upgrade pending\n", "installer-managed-upgrade-pending"),
            (0, b"AccessWeaver managed upgrade pending\n", "detector-result-invalid"),
            (1, b"AccessWeaver managed upgrade pending\nextra\n", "detector-result-invalid"),
            (0, b"AccessWeaver installation pending\n", "detector-result-invalid"),
            (1, b"AccessWeaver installation pending\nextra\n", "detector-result-invalid"),
            (0, b"AccessWeaver detected\nextra\n", "detector-result-invalid"),
            (0, b"\n" * 4098, "detector-result-invalid"),
            (1, b"AccessWeaver detected\n", "detector-result-invalid"),
            (2, b"", "detector-result-invalid"),
        ):
            def run(argv, *, stdout, **options):
                stdout.write(content)
                return subprocess.CompletedProcess(argv, code)

            with self.subTest(code=code, content=content), patch.object(release.subprocess, "run", side_effect=run) as call, \
                    patch.object(release, "windows_system_directory", return_value=self.root):
                expected = ("unverified", reason) if reason else ("detected", None)
                pending_approval = "f" * 64 if reason == "installer-managed-upgrade-pending" else None
                self.assertEqual(release.detect_windows_upgrade(qualification, publisher, pending_approval=pending_approval), expected)
                arguments = call.call_args.args[0]
                self.assertEqual(arguments[5:], [
                    "-UseRegisteredDirectory", "-Version", VERSION, "-Architecture", "arm64",
                    "-PayloadSHA256", "a" * 64, "-PayloadSBOMSHA256", "b" * 64, "-BuildInfoSHA256",
                    "c" * 64, "-UninstallerSHA256", "d" * 64, "-PayloadPublisherSHA256", publisher,
                ] + (["-PendingApprovalSHA256", pending_approval] if pending_approval else []))
                self.assertEqual(call.call_args.kwargs["timeout"], 90)
                self.assertEqual(call.call_args.kwargs["env"]["ACCESSWEAVER_REPORT_INSTALLER_RECOVERY"], "1")
        with patch.object(release, "windows_system_directory", return_value=self.root), \
                patch.object(release.subprocess, "run", side_effect=lambda argv, *, stdout, **options: (
                    stdout.write(b"AccessWeaver managed upgrade pending\n"), subprocess.CompletedProcess(argv, 1)
                )[1]):
            self.assertEqual(release.detect_windows_upgrade(qualification, publisher), ("unverified", "detector-result-invalid"))
        for error, reason in (
            (subprocess.TimeoutExpired("detector", 90), "detector-timeout"),
            (OSError("detector could not start"), "detector-unavailable"),
        ):
            with self.subTest(reason=reason), patch.object(release.subprocess, "run", side_effect=error), \
                    patch.object(release, "windows_system_directory", return_value=self.root):
                self.assertEqual(release.detect_windows_upgrade(qualification, publisher), ("unverified", reason))

    @unittest.skipUnless(os.name == "nt", "requires native Windows file sharing")
    def test_pending_retry_refuses_release_without_authenticated_payload_fingerprint(self):
        update = {"windowsUpgradeDetection": {release.WINDOWS_DETECTOR: "a" * 64}}
        with patch.object(release, "detect_windows_upgrade") as detect:
            with self.assertRaisesRegex(ValueError, "requires an authenticated staged payload fingerprint"):
                release.require_pending_windows_upgrade(update, "b" * 64, self.policy)
            detect.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "requires native Windows file sharing")
    def test_windows_staging_detector_pins_script_through_execution(self):
        script = self.root / "detect-windows-installer.ps1"
        script.write_bytes(b"inert reviewed detector")
        qualification = {
            "target": "windows/amd64", "version": VERSION, "payloadSHA256": "a" * 64,
            "payloadSBOMSHA256": "b" * 64, "buildInfoSHA256": "c" * 64, "uninstallerSHA256": "d" * 64,
            "detectorSHA256": release.digest(script),
        }

        def run(argv, *, stdout, **options):
            self.assertEqual(argv[4], script)
            with self.assertRaises(PermissionError):
                script.write_bytes(b"different detector")
            stdout.write(b"AccessWeaver detected\r\n")
            return subprocess.CompletedProcess(argv, 0)

        with patch.object(release, "__file__", str(self.root / "signed_release_manifest.py")), \
                patch.object(release, "windows_system_directory", return_value=self.root), \
                patch.object(release.subprocess, "run", side_effect=run) as call:
            self.assertEqual(release.detect_windows_upgrade(qualification, "e" * 64), ("detected", None))
            call.assert_called_once()
            call.reset_mock()
            script.write_bytes(b"different detector")
            self.assertEqual(release.detect_windows_upgrade(qualification, "e" * 64), ("unverified", "detector-unavailable"))
            call.assert_not_called()

    def test_windows_retry_requires_inspectable_previous_results(self):
        directory = self.root / "receipts"
        directory.mkdir()
        result = directory / "previous.result.json"
        release.require_missing_windows_results((result,))
        result.mkdir()
        with self.assertRaisesRegex(release.WindowsSetupPreviousResultUnverified, "found an existing result receipt"):
            release.require_missing_windows_results((result,))
        result.rmdir()
        with patch.object(Path, "lstat", side_effect=PermissionError("synthetic unreadable receipt")):
            with self.assertRaisesRegex(release.WindowsSetupPreviousResultUnverified, "could not verify absence"):
                release.require_missing_windows_results((result,))
        directory.rmdir()
        with self.assertRaisesRegex(release.WindowsSetupPreviousResultUnverified, "could not verify absence"):
            release.require_missing_windows_results((result,))

    @unittest.skipUnless(os.name == "nt", "requires native Windows file sharing")
    def test_windows_staging_holds_approved_setup_and_parents_through_launch(self):
        directory = self.root / "staged"
        directory.mkdir()
        setup = directory / "accessweaver-setup.exe"
        contents = b"inert Setup fixture"
        setup.write_bytes(contents)
        identity = release.staging_directory_identity(directory)
        baseline = "/AWUpgradeFrom=1.2.2-rc.1," + ",".join([("a" * 64)] * 3)
        update = {"installer": setup.name, "installerSHA256": release.digest(setup),
                  "windowsSetupBaselineArgument": baseline}

        def assert_held():
            with self.assertRaises(PermissionError):
                setup.write_bytes(b"unapproved")
            with self.assertRaises(PermissionError):
                setup.rename(directory / "replaced.exe")
            with self.assertRaises(PermissionError):
                directory.rename(self.root / "renamed")

        with patch.object(release.subprocess, "Popen") as launch:
            process = launch.return_value
            def wait(*, timeout):
                assert_held()
                return 3010
            process.wait.side_effect = wait
            launch_options = {"size": len(contents), "directory_identity": identity}
            self.assertEqual(release.launch_windows_setup(directory, update, self.policy, **launch_options), 3010)
            self.assertEqual(launch.call_args.args[0][-1], baseline)
            self.assertIn("/NORESTART", launch.call_args.args[0])
            self.assertEqual(launch.call_args.kwargs["executable"], str(setup))

            launch.reset_mock()
            with patch.object(release, "require_current_revocation_policy", side_effect=ValueError("expired")):
                with self.assertRaisesRegex(ValueError, "expired"):
                    release.launch_windows_setup(directory, update, self.policy, **launch_options)
            setup.write_bytes(b"x" * len(contents))
            with self.assertRaisesRegex(ValueError, "differs from the approved digest"):
                release.launch_windows_setup(directory, update, self.policy, **launch_options)
            launch.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "requires native Windows file sharing")
    def test_windows_setup_wait_timeout_leaves_start_receipt_and_setup_running(self):
        directory = self.root / "staged"
        directory.mkdir()
        setup = directory / "accessweaver-setup.exe"
        setup.write_bytes(b"inert Setup fixture")
        update = {"installer": setup.name, "installerSHA256": release.digest(setup),
                  "windowsSetupBaselineArgument": "/AWUpgradeFrom=approved"}
        attempt = {"attemptID": "a" * 32}
        started = directory / (attempt["attemptID"] + ".started.json")
        with patch.object(release.subprocess, "Popen") as launch:
            process = launch.return_value
            process.wait.side_effect = subprocess.TimeoutExpired("setup", 60)
            with self.assertRaises(subprocess.TimeoutExpired):
                release.launch_windows_setup(directory, update, self.policy, size=setup.stat().st_size,
                                             directory_identity=release.staging_directory_identity(directory),
                                             attempt=attempt, wait_seconds=60)
            process.wait.assert_called_once_with(timeout=60)
            process.kill.assert_not_called()
            process.terminate.assert_not_called()
            process.__exit__.assert_not_called()
        self.assertEqual(json.loads(started.read_bytes()), attempt)
        self.assertEqual(set(directory.iterdir()), {setup, started})

    @unittest.skipUnless(os.name == "nt", "requires native Windows process waiting and file sharing")
    def test_windows_staging_wait_timeout_leaves_real_process_running(self):
        directory = self.root / "staged"
        directory.mkdir()
        setup = directory / "accessweaver-setup.exe"
        setup.write_bytes(b"inert Setup fixture")
        update = {"installer": setup.name, "installerSHA256": release.digest(setup),
                  "windowsSetupBaselineArgument": "/AWUpgradeFrom=approved"}
        attempt = {"attemptID": "a" * 32}
        started = directory / (attempt["attemptID"] + ".started.json")
        real_popen = subprocess.Popen
        process = None

        def start_fixture(arguments, *, executable, cwd, stdin, stdout, stderr):
            nonlocal process
            self.assertEqual(executable, str(setup))
            self.assertEqual(arguments[0], executable)
            self.assertEqual(json.loads(started.read_bytes()), attempt)
            # Use the test runner's Python executable so the wait can be exercised
            # even on hosts that block newly built executable fixtures.
            process = real_popen(
                [sys.executable, "-I", "-S", "-c",
                 "import os, sys, threading; guard = threading.Timer(15, os._exit, args=(43,)); "
                 "guard.daemon = True; guard.start(); sys.stdin.read(); sys.exit(42)"],
                cwd=cwd, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
            )
            return process

        options = {"size": setup.stat().st_size, "directory_identity": release.staging_directory_identity(directory),
                   "attempt": attempt, "wait_seconds": 1}
        try:
            with patch.object(release.subprocess, "Popen", side_effect=start_fixture) as launch:
                with self.assertRaises(subprocess.TimeoutExpired):
                    release.launch_windows_setup(directory, update, self.policy, **options)
                self.assertEqual(update["startReceiptSHA256"], release.digest(started))
                self.assertIsNone(process.poll())
                with self.assertRaises(FileExistsError):
                    release.launch_windows_setup(directory, update, self.policy, **options)
                launch.assert_called_once()
            self.assertIsNone(process.poll())
            self.assertEqual(set(directory.iterdir()), {setup, started})
            # The wait released the staging handles. The child remains live until
            # the harness signals it, so the timeout cannot be a fast child exit.
            setup.rename(directory / "retired.exe")
            process.stdin.close()
            self.assertEqual(process.wait(timeout=10), 42)
        finally:
            if process is not None:
                process.stdin.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)

    @unittest.skipUnless(os.name == "nt", "requires native Windows file sharing")
    def test_windows_staging_reserves_attempt_before_launch_and_refuses_replay(self):
        directory = self.root / "staged"
        directory.mkdir()
        setup = directory / "accessweaver-setup.exe"
        setup.write_bytes(b"inert Setup fixture")
        baseline = "/AWUpgradeFrom=1.2.2-rc.1," + ",".join(["a" * 64] * 3)
        update = {"installer": setup.name, "installerSHA256": release.digest(setup),
                  "windowsSetupBaselineArgument": baseline}
        attempt = {"attemptID": "a" * 32, "installerSHA256": update["installerSHA256"],
                   "windowsSetupBaselineArgument": baseline}
        started = directory / (attempt["attemptID"] + ".started.json")
        options = {"size": setup.stat().st_size, "directory_identity": release.staging_directory_identity(directory),
                   "attempt": attempt}

        def failed_dispatch(*args, **kwargs):
            self.assertEqual(json.loads(started.read_bytes()), attempt)
            raise OSError("synthetic failure during dispatch")

        with patch.object(release.subprocess, "Popen", side_effect=failed_dispatch) as launch:
            with self.assertRaisesRegex(release.WindowsSetupLaunchError, "Windows Setup could not be launched"):
                release.launch_windows_setup(directory, update, self.policy, **options)
            with self.assertRaises(FileExistsError):
                release.launch_windows_setup(directory, update, self.policy, **options)
            launch.assert_called_once()
        self.assertEqual(json.loads(started.read_bytes()), attempt)
        self.assertEqual(set(directory.iterdir()), {setup, started})

    @unittest.skipUnless(os.name == "nt", "requires native Windows process creation")
    def test_windows_staging_launches_inert_fixture_with_fixed_arguments(self):
        directory = self.root / "staged setup fixture"
        directory.mkdir()
        setup = directory / "accessweaver-setup.exe"
        baseline = "/AWUpgradeFrom=1.2.2-rc.1," + ",".join(["a" * 64, "b" * 64, "c" * 64])
        source = directory / "Fixture.cs"
        source.write_text(
            'public static class Fixture {\n'
            '    public static int Main(string[] args) {\n'
            '        string[] expected = {"/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",\n'
            '                             "/RESTARTEXITCODE=3010", "/NOICONS", "' + baseline + '"};\n'
            '        if (args.Length != expected.Length) return 64;\n'
            '        for (int i = 0; i < expected.Length; i++)\n'
            '            if (args[i] != expected[i]) return 65;\n'
            '        return 3010;\n'
            '    }\n'
            '}\n',
            encoding="utf-8",
        )
        shell = release.windows_system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        compile_fixture = (
            "$ErrorActionPreference='Stop'; "
            "Add-Type -LiteralPath $env:AW_TEST_SETUP_SOURCE -OutputAssembly $env:AW_TEST_SETUP_EXE "
            "-OutputType ConsoleApplication"
        )
        subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", compile_fixture],
            check=True, timeout=30, capture_output=True,
            env={**os.environ, "AW_TEST_SETUP_SOURCE": str(source), "AW_TEST_SETUP_EXE": str(setup)},
        )

        update = {"installer": setup.name, "installerSHA256": release.digest(setup),
                  "windowsSetupBaselineArgument": baseline}
        options = {"size": setup.stat().st_size, "directory_identity": release.staging_directory_identity(directory)}
        self.assertEqual(release.launch_windows_setup(directory, update, self.policy, **options), 3010)
        wrong_baseline = {**update, "windowsSetupBaselineArgument": baseline.replace("rc.1", "rc.2")}
        self.assertEqual(release.launch_windows_setup(directory, wrong_baseline, self.policy, **options), 65)
        self.assertEqual(release.digest(setup), update["installerSHA256"])
        setup.rename(directory / "retired.exe")

    @unittest.skipUnless(os.name == "nt", "requires a Windows junction")
    def test_windows_staging_refuses_a_redirected_parent(self):
        update = release.managed_update(release.inventory(self.candidate, self.subjects),
                                        "windows/arm64", "1.2.2-rc.1", VERSION)
        real_parent = self.root / "real-staging-parent"
        staging = real_parent / "staging"
        staging.mkdir(parents=True)
        junction = self.root / "redirected-staging-parent"
        shell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        command = "New-Item -ItemType Junction -Path $env:AW_TEST_JUNCTION -Target $env:AW_TEST_TARGET -ErrorAction Stop | Out-Null"
        subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command], check=True, timeout=15,
                       capture_output=True, env={**os.environ, "AW_TEST_JUNCTION": str(junction),
                                                 "AW_TEST_TARGET": str(real_parent)})
        try:
            with self.assertRaisesRegex(ValueError, "reparse point"):
                release.stage_managed_update(self.candidate, junction / "staging", update, self.policy,
                                             size=(self.candidate / update["installer"]).stat().st_size,
                                             directory_identity=release.staging_directory_identity(staging))
            self.assertEqual(list(staging.iterdir()), [])

            files = release.inventory(self.candidate, self.subjects)
            (self.candidate / release.MANIFEST).write_bytes(release.encode_manifest(COMMIT, REF, files))
            (self.candidate / release.SIGNATURE).write_bytes(b"mocked CMS signature")
            certificate = self.root / "fixture.cer"
            certificate.write_bytes(b"mocked approval certificate")
            with patch.object(release, "authenticate"):
                with self.assertRaisesRegex(ValueError, "reparse point"):
                    self.verify(certificate, release.digest(certificate),
                                current_version="1.2.2-rc.1", target="windows/arm64",
                                stage_directory=junction / "staging")
                self.assertEqual(list(staging.iterdir()), [])
                with self.assertRaisesRegex(ValueError, "parent traversal"):
                    self.verify(certificate, release.digest(certificate),
                                current_version="1.2.2-rc.1", target="windows/arm64",
                                stage_directory=staging / ".." / "staging")
                self.assertEqual(list(staging.iterdir()), [])
                accepted = self.verify(certificate, release.digest(certificate),
                                       current_version="1.2.2-rc.1", target="windows/arm64",
                                       stage_directory=staging)
            self.assertIs(accepted["managedUpdate"]["installerStaged"], True)
            self.assertEqual(release.digest(staging / update["installer"]), update["installerSHA256"])
        finally:
            junction.rmdir()

    def test_staging_refuses_changed_snapshot_size_and_directory(self):
        update = release.managed_update(release.inventory(self.candidate, self.subjects),
                                        "windows/amd64", "1.2.2-rc.1", VERSION)
        source = self.candidate / update["installer"]
        original = source.read_bytes()
        staging = self.root / "bound-staging"
        staging.mkdir()
        identity = release.staging_directory_identity(staging)
        with source.open("ab") as output:
            output.write(b"excess bytes")
        with self.assertRaisesRegex(ValueError, "differs from the approved size"):
            release.stage_managed_update(self.candidate, staging, update, self.policy,
                                         size=len(original), directory_identity=identity)
        self.assertEqual(list(staging.iterdir()), [])
        source.write_bytes(original)

        other = staging.with_name("displaced-staging")
        staging.rename(other)
        staging.mkdir()
        with self.assertRaisesRegex(ValueError, "staging directory changed"):
            release.stage_managed_update(self.candidate, staging, update, self.policy,
                                         size=len(original), directory_identity=identity)
        self.assertEqual(list(staging.iterdir()), [])
        self.assertEqual(list(other.iterdir()), [])

    def test_sequenced_revocation_policy_requires_current_utc_window(self):
        now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        policy = {**self.policy, "schemaVersion": 2, "sequence": 9,
                  "issuedAt": "2026-01-01T12:00:00Z", "expiresAt": "2026-01-01T13:00:00Z"}
        content = json.dumps(policy).encode()
        self.assertEqual(release.revocations(content, minimum_sequence=9, now=now), policy)
        for override, floor in (
            ({"issuedAt": "2026-01-01T12:00:01Z"}, 9),
            ({"expiresAt": "2026-01-01T12:00:00Z"}, 9),
            ({"issuedAt": "2026-02-29T12:00:00Z"}, 9),
            ({"issuedAt": "2026-01-01T12:00:00+00:00"}, 9),
            ({"sequence": True}, 9),
            ({"sequence": 0}, 9),
            ({}, 10),
            ({}, 0),
            ({}, True),
        ):
            with self.subTest(override=override, floor=floor), self.assertRaises(ValueError):
                release.revocations(json.dumps({**policy, **override}).encode(), minimum_sequence=floor, now=now)
        for omitted in ("sequence", "issuedAt", "expiresAt"):
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                release.revocations(json.dumps({key: value for key, value in policy.items() if key != omitted}).encode())

    def test_independently_pinned_input_rejects_replacement_with_identical_bytes(self):
        path = self.revocation_list
        replacement = self.root / "replacement.json"
        replacement.write_bytes(path.read_bytes())
        open_file = os.open

        def open_replacement(name, flags):
            self.assertEqual(name, path)
            self.assertEqual(flags & getattr(os, "O_NONBLOCK", 0), getattr(os, "O_NONBLOCK", 0))
            replacement.replace(path)
            return open_file(name, flags)

        with patch.object(release.os, "open", side_effect=open_replacement):
            with self.assertRaisesRegex(ValueError, "changed before verification"):
                release.independently_pinned_file(self.candidate, path, self.policy_pin)

        replacement.write_bytes(path.read_bytes())
        original_lstat = Path.lstat
        inspections = 0

        def replaced_path_info(name):
            nonlocal inspections
            if name == path:
                inspections += 1
                if inspections > 1:
                    return original_lstat(replacement)
            return original_lstat(name)

        with patch.object(Path, "lstat", replaced_path_info):
            with self.assertRaisesRegex(ValueError, "changed during verification"):
                release.independently_pinned_file(self.candidate, path, self.policy_pin)

    def test_revocation_policy_refuses_malformed_inputs(self):
        self.assertEqual(release.revocations(json.dumps(self.policy).encode()), self.policy)
        invalid = [
            {"schemaVersion": 1},
            {**self.policy, "schemaVersion": True},
            {**self.policy, "unknown": []},
            {**self.policy, "sourceRefs": ["refs/heads/main"]},
            {**self.policy, "sourceCommits": [COMMIT, COMMIT]},
            {**self.policy, "subjectSHA256": ["bad"]},
            {**self.policy, "approvalCertificateSHA256": [False]},
        ]
        for policy in invalid:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                release.revocations(json.dumps(policy).encode())
        with self.assertRaises(ValueError):
            release.revocations(b'{"schemaVersion": 1, "schemaVersion": 1}')
        with self.assertRaises(ValueError):
            release.revocations(b"\xff")


if __name__ == "__main__":
    unittest.main()
