import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import signed_release_manifest as release


COMMIT = "a" * 40
REF = "refs/tags/v1.2.3-rc.1"
OPENSSL = shutil.which("openssl")


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
        for name in self.subjects:
            (self.candidate / name).write_bytes(name.encode())

    def write_policy(self, policy):
        self.revocation_list.write_text(json.dumps(policy), encoding="utf-8")
        return release.digest(self.revocation_list)

    def verify(self, certificate, certificate_pin, commit=COMMIT, ref=REF, *, policy_pin=None):
        return release.verify(self.candidate, certificate, certificate_pin, commit, ref, OPENSSL,
                              revocation_list=self.revocation_list,
                              revocation_list_sha256=policy_pin or self.policy_pin)

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
        shutil.copyfile(prepared, manifest)
        openssl("cms", "-sign", "-binary", "-md", "sha256", "-in", manifest,
                "-signer", pem, "-inkey", key, "-outform", "DER", "-out", signature)

        report = self.verify(approved, pin)
        self.assertEqual(report["subjectsVerified"], 12)
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
