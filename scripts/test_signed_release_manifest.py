import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import signed_release_manifest as release
from sbom import properties


COMMIT = "a" * 40
REF = "refs/tags/v1.2.3-rc.1"
OPENSSL = shutil.which("openssl")
VERSION = REF.removeprefix("refs/tags/v")


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
            if role == "installer":
                self.write_sbom(name, self.sbom_root(name, target), payloads.get(target))

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

    def write_sbom(self, name, root, payload=None):
        references = [payload["bom-ref"]] if payload else []
        document = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": root}, "components": [payload] if payload else [],
            "dependencies": [{"ref": root["bom-ref"], "dependsOn": references}]
                            + [{"ref": ref, "dependsOn": []} for ref in references],
            "compositions": [{"aggregate": "incomplete"}],
        }
        (self.candidate / (name + ".cdx.json")).write_text(json.dumps(document), encoding="utf-8")

    def write_policy(self, policy):
        self.revocation_list.write_text(json.dumps(policy), encoding="utf-8")
        return release.digest(self.revocation_list)

    def verify(self, certificate, certificate_pin, commit=COMMIT, ref=REF, *, policy_pin=None):
        return release.verify(self.candidate, certificate, certificate_pin, commit, ref, OPENSSL,
                              revocation_list=self.revocation_list,
                              revocation_list_sha256=policy_pin or self.policy_pin)

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
        if overrides.get("schemaVersion") == 6:
            report.update(
                payloadSBOMSHA256=release.digest(self.candidate / (stem + ".exe.cdx.json")),
                installedPayloadSBOMVerified=True,
                installedPayloadPublisherVerified=True,
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
            (self.write_reboot_report("partial-upgrade.json", installMode="upgrade",
                                      previousVersion="1.2.2", previousPayloadSHA256="d" * 64),),
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
        self.assertEqual(report["sbomArtifactBindingsVerified"], 6)
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
            self.verify(approved, pin)
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
                    self.verify(approved, pin, policy_pin=current_pin)
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    self.verify(approved, pin)

        self.write_policy(self.policy)
        prepared.unlink()
        manifest.unlink()
        signature.unlink()
        clean = self.write_reboot_report("clean.json")
        upgrade = self.write_reboot_report("upgrade.json", installMode="upgrade",
                                           previousVersion="1.2.2", previousPayloadSHA256="d" * 64,
                                           userProfilePreservedThroughUpgrade=True, uninstallerSHA256="e" * 64)
        arm = self.write_reboot_report("arm.json", architecture="arm64", schemaVersion=6, uninstallerSHA256="f" * 64)
        release.prepare(self.candidate, prepared, COMMIT, REF, windows_reboot_evidence=[arm, upgrade, clean])
        shutil.copyfile(prepared, manifest)
        sign_manifest()
        report = self.verify(approved, pin)
        self.assertEqual(report["schemaVersion"], 2)
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
            **clean_entry, "installMode": "upgrade", "previousVersion": "1.2.2",
            "previousPayloadSHA256": "d" * 64, "uninstallerSHA256": "e" * 64, "rebootEvidenceSHA256": upgrade[1],
        })
        self.assertEqual(arm_entry["target"], "windows/arm64")
        self.assertEqual(arm_entry["payloadSBOMSHA256"],
                         release.digest(self.candidate / "accessweaver-1.2.3-rc.1-windows-arm64.exe.cdx.json"))
        self.assertEqual(arm_entry["uninstallerSHA256"], "f" * 64)
        for revoked in (clean[1], "b" * 64, "d" * 64, "e" * 64):
            current_pin = self.write_policy({**self.policy, "subjectSHA256": [revoked]})
            with self.subTest(revoked=revoked), self.assertRaisesRegex(ValueError, "revoked"):
                self.verify(approved, pin, policy_pin=current_pin)
        self.write_policy(self.policy)

        data = json.loads(manifest.read_bytes())
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
