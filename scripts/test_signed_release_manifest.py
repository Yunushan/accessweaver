from datetime import datetime, timedelta, timezone
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import signed_release_manifest as release
from sbom import properties


COMMIT = "a" * 40
REF = "refs/tags/v1.2.3-rc.1"
OPENSSL = shutil.which("openssl")
VERSION = REF.removeprefix("refs/tags/v")
DETECTOR_DIGESTS = {"darwin/amd64": "1" * 64, "darwin/arm64": "2" * 64}


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
                components = [{**root, "bom-ref": "helper:application", "hashes": hashes}]
                components.extend({"bom-ref": "script-file:" + phase, "type": "file",
                                   "name": phase, "hashes": hashes} for phase in ("preinstall", "postinstall"))
            else:
                components = [payloads[target]]
            self.write_sbom(name, root, components)

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
        evidence = self.root / filename
        evidence.write_text(json.dumps({**report, **overrides}), encoding="utf-8")
        return evidence, release.digest(evidence)

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
        ]
        duplicate = self.root / "duplicate.json"
        duplicate.write_bytes(valid[0].read_bytes().replace(b'"passed": true', b'"passed": false, "passed": true'))
        invalid.append(((duplicate, release.digest(duplicate)),))
        for evidence in invalid:
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                release.prepare(self.candidate, output, COMMIT, REF, windows_reboot_evidence=evidence)
            self.assertFalse(output.exists())

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
                    patch.object(release, "verify_packaged_application") as app_check:
                for revoked in (installer_pin, application_pin):
                    revoked_pin = self.write_policy({**self.policy, "subjectSHA256": [revoked]})
                    with self.assertRaisesRegex(ValueError, "publisher certificate is revoked"):
                        self.verify(approved, pin, policy_pin=revoked_pin, **macos_options)
                    package_check.assert_not_called()
                    app_check.assert_not_called()
                    self.assertEqual(list(macos_staging.iterdir()), [])
                self.write_policy(self.policy)

                package_check.side_effect = subprocess.CalledProcessError(1, "spctl")
                with self.assertRaises(subprocess.CalledProcessError):
                    self.verify(approved, pin, **macos_options)
                app_check.assert_not_called()
                self.assertEqual(list(macos_staging.iterdir()), [])
                package_check.side_effect = None

                app_check.side_effect = subprocess.CalledProcessError(1, "codesign")
                with self.assertRaises(subprocess.CalledProcessError):
                    self.verify(approved, pin, **macos_options)
                self.assertEqual(list(macos_staging.iterdir()), [])
                app_check.side_effect = lambda package, *_: package.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "changed during publisher verification"):
                    self.verify(approved, pin, **macos_options)
                self.assertEqual(list(macos_staging.iterdir()), [])
                app_check.side_effect = None

                native_report = self.verify(approved, pin, **macos_options)
                native_update = native_report["managedUpdate"]
                self.assertTrue(native_report["nativePublisherChecksPerformed"])
                self.assertTrue(native_update["installerStaged"])
                self.assertEqual(native_update["nativePublisherVerification"], {
                    "developerTeamID": team, "installerCertificateSHA256": installer_pin,
                    "applicationCertificateSHA256": application_pin, "gatekeeperAccepted": True,
                    "stapledTicketValidated": True,
                })
                checked_path = package_check.call_args.args[0]
                self.assertEqual(checked_path.name, pkg_name)
                self.assertNotEqual(checked_path.parent, self.candidate)
                self.assertNotEqual(checked_path.parent, macos_staging)
                self.assertEqual(package_check.call_args.args, (checked_path, team, installer_pin))
                self.assertEqual(app_check.call_args.args, (checked_path, team, "arm64", application_pin))
                self.assertEqual((macos_staging / pkg_name).read_bytes(), (self.candidate / pkg_name).read_bytes())

        real_stage = release.stage_managed_update
        def replace_input_after_verification(snapshot, directory, decision, policy):
            input_file.write_bytes(b"replacement after verification")
            real_stage(snapshot, directory, decision, policy)

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

        for competing_bytes in (original_installer, conflicting):
            def publish_concurrently(source, destination):
                destination.write_bytes(competing_bytes)
                os_link(source, destination)

            with self.subTest(matching=competing_bytes == original_installer), \
                    patch.object(release.os, "link", side_effect=publish_concurrently):
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

        def corrupt_copy(source, output, length):
            output.write(b"corrupted copy")

        with patch.object(release.shutil, "copyfileobj", side_effect=corrupt_copy):
            with self.assertRaisesRegex(ValueError, "bounded ordinary staged installer"):
                self.verify(approved, pin, **update)
        self.assertEqual(list(staging.iterdir()), [])
        self.assertEqual(report["sbomArtifactBindingsVerified"], 6)
        self.assertEqual(report["macosDetection"], [
            {"target": target, "version": VERSION, "detectorSHA256": pin,
             "packageSHA256": release.digest(self.candidate /
                 f"accessweaver-{VERSION}-darwin-{target.split('/')[1]}-deployment-experimental.pkg")}
            for target, pin in DETECTOR_DIGESTS.items()
        ])
        for target, detector in DETECTOR_DIGESTS.items():
            current_pin = self.write_policy({**self.policy, "subjectSHA256": [detector]})
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "macOS detector is revoked"):
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
        upgrade = self.write_reboot_report("upgrade.json", schemaVersion=8, installMode="upgrade",
                                           previousVersion="1.2.2-rc.1", previousPayloadSHA256="d" * 64,
                                           userProfilePreservedThroughUpgrade=True, uninstallerSHA256="e" * 64)
        arm = self.write_reboot_report("arm.json", architecture="arm64", schemaVersion=7, uninstallerSHA256="f" * 64)
        release.prepare(self.candidate, prepared, COMMIT, REF, windows_reboot_evidence=[arm, upgrade, clean])
        shutil.copyfile(prepared, manifest)
        sign_manifest()
        report = self.verify(approved, pin)
        self.assertEqual(report["schemaVersion"], 3)
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
        })
        self.assertEqual(arm_entry["target"], "windows/arm64")
        self.assertEqual(arm_entry["payloadSBOMSHA256"],
                         release.digest(self.candidate / "accessweaver-1.2.3-rc.1-windows-arm64.exe.cdx.json"))
        self.assertEqual(arm_entry["uninstallerSHA256"], "f" * 64)
        qualified = {"current_version": "1.2.2-rc.1", "target": "windows/amd64",
                     "current_payload_sha256": "D" * 64}
        update_report = self.verify(approved, pin, **qualified)["managedUpdate"]
        self.assertEqual(update_report["windowsUpgradeDetection"], upgrade_entry)
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
                        upgrade_entry["previousPayloadSBOMSHA256"], upgrade_entry["previousPayloadPublisherSHA256"]):
            current_pin = self.write_policy({**self.policy, "subjectSHA256": [revoked]})
            with self.subTest(revoked=revoked), self.assertRaisesRegex(ValueError, "revoked"):
                self.verify(approved, pin, policy_pin=current_pin, stage_directory=staging, **qualified)
            self.assertEqual(list(staging.iterdir()), [])
        self.write_policy(self.policy)

        original = manifest.read_bytes()
        data = json.loads(original)
        legacy_entries = [
            {field: value for field, value in entry.items() if field not in release.WINDOWS_PREVIOUS_TRUST_FIELDS}
            for entry in data["windowsDetection"]
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
                          if field not in release.WINDOWS_PREVIOUS_TRUST_FIELDS})

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
                    release.stage_managed_update(self.candidate, staging, update, policy)
                if phase == "before publication":
                    self.assertEqual(list(staging.iterdir()), [])
                else:
                    self.assertEqual(destination.read_bytes(), original)
                    self.assertEqual(list(staging.iterdir()), [destination])
                    destination.unlink()

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
