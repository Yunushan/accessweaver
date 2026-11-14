import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import publish_prerelease as publisher


class PrereleasePublicationTests(unittest.TestCase):
    commit = "a" * 40
    tag = "v1.2.3-alpha"
    ref = "refs/tags/" + tag

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.assets = {}
        for index in range(13):
            name = f"fixture-{index:02d}.zip"
            body = name.encode()
            (self.directory / name).write_bytes(body)
            self.assets[name] = {
                "name": name, "state": "uploaded",
                "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            }

    def release(self, draft, count=13, release_id=456):
        return {
            "databaseId": release_id, "tagName": self.tag, "isDraft": draft, "isPrerelease": True,
            "assets": [dict(item) for item in list(self.assets.values())[:count]],
        }

    def run_publisher(self, releases, tags=None, verify_snapshot=None, upload_error=None, promotion_error=None,
                      create_error=None):
        with (
            patch.object(publisher, "verify", side_effect=verify_snapshot) as verify,
            patch.object(publisher, "git_tag_commit", side_effect=tags or [self.commit] * 4),
            patch.object(publisher, "view", side_effect=releases),
            patch.object(publisher, "gh", side_effect=create_error) as gh,
            patch.object(publisher, "upload_asset", side_effect=upload_error) as upload,
            patch.object(publisher, "promote_draft", side_effect=promotion_error) as promote,
        ):
            self.calls = gh
            self.upload = upload
            self.promote = promote
            try:
                publisher.publish(self.directory, self.commit, self.ref)
            finally:
                verify.assert_called_once()
                self.snapshot, commit, ref = verify.call_args.args
                self.assertEqual((commit, ref), (self.commit, self.ref))
                self.assertNotEqual(self.snapshot, self.directory)
                self.assertFalse(self.snapshot.exists())

    def test_publication_requires_the_rebuild_reference_when_supplied(self):
        checksums = self.directory / "SHA256SUMS.txt"
        (self.directory / "fixture-00.zip").rename(checksums)
        expected = hashlib.sha256(checksums.read_bytes()).hexdigest()
        for match in (False, True):
            approved = expected if match else "0" * 64
            with self.subTest(match=match), patch.object(publisher, "verify") as verify, patch.object(
                publisher, "publish_verified",
            ) as publish_verified:
                if match:
                    publisher.publish(self.directory, self.commit, self.ref, rebuild_checksums_sha256=approved)
                    publish_verified.assert_called_once()
                else:
                    with self.assertRaisesRegex(ValueError, "differs from the authenticated rebuild"):
                        publisher.publish(self.directory, self.commit, self.ref, rebuild_checksums_sha256=approved)
                    publish_verified.assert_not_called()
                verify.assert_called_once()

    def test_publication_requires_matching_receipts_for_all_targets(self):
        names = sorted(self.assets)
        manifest = {"artifacts": []}
        manifest_path = self.directory / "BUILD-MANIFEST.json"
        (self.directory / names[11]).rename(manifest_path)
        bundle_path = self.directory / publisher.BUNDLE_NAME
        (self.directory / names[12]).rename(bundle_path)
        with tempfile.TemporaryDirectory() as folder:
            receipts = Path(folder)
            for (system, arch), input_name in zip(sorted(publisher.TARGETS), names):
                suffix = ".zip" if system == "windows" else ".tar.gz"
                name = f"accessweaver-{system}-{arch}{suffix}"
                (self.directory / input_name).rename(self.directory / name)
                manifest["artifacts"].append({"goos": system, "goarch": arch, "file": name})
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            def archived_build(system, arch):
                return {"commit": self.commit, "version": "1.2.3-alpha", "sourceState": "clean",
                        "platform": system, "arch": arch}

            def inspect_archive(path, root, binary_name):
                name = path.name
                system, arch = next((item["goos"], item["goarch"]) for item in manifest["artifacts"]
                                     if item["file"] == name)
                self.assertEqual(root, f"accessweaver-{system}-{arch}")
                self.assertEqual(binary_name, "accessweaver.exe" if system == "windows" else "accessweaver")
                return archived_build(system, arch), path.read_bytes()

            for item in manifest["artifacts"]:
                system, arch, name = item["goos"], item["goarch"], item["file"]
                target = receipts / f"release-qualified-{system}-{arch}"
                target.mkdir()
                receipt = {"schemaVersion": 1, "repository": publisher.REPOSITORY, "workflow": publisher.WORKFLOW,
                           "sourceCommit": self.commit, "sourceRef": self.ref, "target": f"{system}/{arch}",
                           "archive": name, "archiveSha256": publisher.digest(self.directory / name),
                           "manifestSha256": publisher.digest(manifest_path), "bundleSha256": publisher.digest(bundle_path),
                           "provenanceSubjectsVerified": 12, "authenticatedBeforeStaging": True,
                           "binary": "accessweaver.exe" if system == "windows" else "accessweaver",
                           "binarySha256": publisher.digest(self.directory / name),
                           "build": archived_build(system, arch), "publisherSignatureVerified": False,
                           "productionQualificationComplete": False}
                if system in {"freebsd", "openbsd"}:
                    receipt["executionEnvironment"] = f"disposable-{system}-guest"
                (target / "candidate.json").write_text(json.dumps(receipt), encoding="utf-8")
                execution = {"schemaVersion": 2, "updateBuildVerified": True,
                             "sourceCommit": self.commit, "target": receipt["target"],
                             "productionQualificationComplete": False}
                if system in {"freebsd", "openbsd"}:
                    execution.update(
                        packagedCandidate=receipt, executedCLI=receipt["build"], cliSHA256=receipt["binarySha256"],
                        guestExecutionPassed=True, packagedCandidateExecuted=True,
                        allTransportedExecutableHashesVerified=True, ownedCapsuleRemoved=True,
                        packagedBackupChecks={"encryptedBackupCreated": True, "archiveAuthenticated": True,
                                              "restoredProfileMatched": True, "wrongPassphraseRejected": True,
                                              "backupNoPlaintext": True, "offlineOnly": True,
                                              "settingsChanged": False, "productionQualificationComplete": False},
                    )
                    execution["ownedEmulatorStopped" if system == "freebsd" else "ownedEmulatorsStopped"] = True
                else:
                    execution.update(
                        sourceRef=self.ref, archiveSha256=receipt["archiveSha256"],
                        binarySha256=receipt["binarySha256"],
                        build=receipt["build"], authenticatedCandidateExecuted=True,
                        backupAndRecoveryVerified=True,
                        loopbackDiagnosticsVerified=True, unixControllerVerified=system != "windows",
                        windowsDiscoveryVerified=system == "windows", publisherSignatureVerified=False,
                    )
                (target / "execution.json").write_text(json.dumps(execution), encoding="utf-8")
            path = receipts / "release-qualified-windows-arm64" / "candidate.json"
            original = path.read_bytes()
            faults = (None, "missing", "extra", "oversize", "array", "archiveSha256", "manifestSha256",
                      "bundleSha256", "target", "sourceRef", "binary", "binarySha256", "build",
                      "publisherSignatureVerified", "productionQualificationComplete", "executionEnvironment")
            for fault in faults:
                with (self.subTest(fault=fault), patch.object(publisher, "verify"),
                      patch.object(publisher, "inspect_archive", side_effect=inspect_archive),
                      patch.object(publisher, "publish_verified") as publish_verified):
                    if fault is None:
                        with publisher.verified_candidate(self.directory, self.commit, self.ref, None, receipts) as candidate:
                            approved_digest = candidate[2]["qualificationSHA256"]
                        publisher.publish(self.directory, self.commit, self.ref, native_qualification=receipts,
                                          expected_qualification_sha256=approved_digest)
                        publish_verified.assert_called_once()
                        publish_verified.reset_mock()
                        with self.assertRaisesRegex(ValueError, "differ from the read-only verification job"):
                            publisher.publish(self.directory, self.commit, self.ref, native_qualification=receipts,
                                              expected_qualification_sha256="0" * 64)
                        publish_verified.assert_not_called()
                        continue
                    elif fault == "missing":
                        path.unlink()
                    elif fault == "extra":
                        (path.parent / "extra.json").touch()
                    elif fault == "oversize":
                        path.write_bytes(original + b" " * (16 << 10))
                    elif fault == "array":
                        path.write_text("[]", encoding="utf-8")
                    else:
                        path.write_text(json.dumps({**json.loads(original), fault: "different"}), encoding="utf-8")
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            publisher.publish(self.directory, self.commit, self.ref, native_qualification=receipts)
                        publish_verified.assert_not_called()
                    finally:
                        (path.parent / "extra.json").unlink(missing_ok=True)
                        path.write_bytes(original)
            path = receipts / "release-qualified-openbsd-arm64" / "candidate.json"
            receipt = json.loads(path.read_bytes())
            receipt["executionEnvironment"] = "disposable-freebsd-guest"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            with (patch.object(publisher, "verify"),
                  patch.object(publisher, "inspect_archive", side_effect=inspect_archive),
                  patch.object(publisher, "publish_verified") as publish_verified):
                with self.assertRaisesRegex(ValueError, "does not match openbsd/arm64"):
                    publisher.publish(self.directory, self.commit, self.ref, native_qualification=receipts)
                publish_verified.assert_not_called()
            receipt["executionEnvironment"] = "disposable-openbsd-guest"
            path.write_text(json.dumps(receipt), encoding="utf-8")

            for system, faults in (
                ("windows", {"authenticatedCandidateExecuted": False, "binarySha256": "b" * 64,
                             "sourceRef": "refs/heads/other", "windowsDiscoveryVerified": False,
                             "updateBuildVerified": False, "schemaVersion": 1}),
                ("openbsd", {"packagedCandidateExecuted": False, "guestExecutionPassed": False,
                             "ownedEmulatorsStopped": False, "ownedCapsuleRemoved": False,
                             "cliSHA256": "b" * 64, "packagedBackupChecks": {}, "failurePhase": "guest-cli",
                             "updateBuildVerified": 1, "schemaVersion": 1}),
            ):
                result = receipts / f"release-qualified-{system}-arm64" / "execution.json"
                original_result = result.read_bytes()
                for key, value in faults.items():
                    with (self.subTest(system=system, execution=key), patch.object(publisher, "verify"),
                          patch.object(publisher, "inspect_archive", side_effect=inspect_archive),
                          patch.object(publisher, "publish_verified") as publish_verified):
                        result.write_text(json.dumps({**json.loads(original_result), key: value}), encoding="utf-8")
                        try:
                            with self.assertRaisesRegex(ValueError, "execution evidence does not match"):
                                publisher.publish(self.directory, self.commit, self.ref, native_qualification=receipts)
                            publish_verified.assert_not_called()
                        finally:
                            result.write_bytes(original_result)

            windows_receipt = receipts / "release-qualified-windows-arm64" / "candidate.json"
            bsd_execution = receipts / "release-qualified-openbsd-arm64" / "execution.json"
            for path, corrupt, message in (
                (windows_receipt, lambda data: b'{"schemaVersion":2,' + data[1:], "Duplicate native metadata"),
                (bsd_execution, lambda data: data.replace(b'"encryptedBackupCreated": true',
                                                          b'"encryptedBackupCreated": 1'),
                 "execution evidence does not match"),
                (bsd_execution, lambda data: data.replace(b'"encryptedBackupCreated": true',
                                                          b'"encryptedBackupCreated": false, "encryptedBackupCreated": true'),
                 "Duplicate native metadata"),
            ):
                original_data = path.read_bytes()
                changed = corrupt(original_data)
                self.assertNotEqual(changed, original_data)
                try:
                    path.write_bytes(changed)
                    with (patch.object(publisher, "verify"),
                          patch.object(publisher, "inspect_archive", side_effect=inspect_archive),
                          patch.object(publisher, "publish_verified") as publish_verified,
                          self.assertRaisesRegex(ValueError, message)):
                        publisher.publish(self.directory, self.commit, self.ref, native_qualification=receipts)
                    publish_verified.assert_not_called()
                finally:
                    path.write_bytes(original_data)

            preview_ref = "refs/heads/codex/dns-adapter-coverage"
            for receipt_path in receipts.glob("*/candidate.json"):
                receipt = json.loads(receipt_path.read_bytes())
                receipt["sourceRef"] = preview_ref
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                result_path = receipt_path.with_name("execution.json")
                execution = json.loads(result_path.read_bytes())
                if "packagedCandidate" in execution:
                    execution["packagedCandidate"] = receipt
                else:
                    execution["sourceRef"] = preview_ref
                result_path.write_text(json.dumps(execution), encoding="utf-8")
            for folder in receipts.iterdir():
                (folder / publisher.QUALIFICATION_BUNDLE).write_bytes(b"synthetic attestation")
            checksums = self.directory / "SHA256SUMS.txt"
            (self.directory / names[10]).rename(checksums)
            argv = ["publish_prerelease.py", str(self.directory), "--source-commit", self.commit,
                    "--source-ref", preview_ref, "--native-qualification", str(receipts), "--verify-only",
                    "--workflow-run-id", "123456",
                    "--rebuild-checksums-sha256"]
            with (patch.object(publisher, "verify") as verify,
                  patch.object(publisher, "authenticate_qualification") as authenticate,
                  patch.object(publisher, "inspect_archive", side_effect=inspect_archive),
                  patch.object(publisher, "publish_verified") as publish_verified,
                  patch.object(publisher, "git_tag_commit") as tag,
                  patch.object(publisher, "gh") as gh):
                with (patch.object(sys, "argv", [*argv, publisher.digest(checksums)]),
                      contextlib.redirect_stdout(io.StringIO()) as output):
                    self.assertEqual(publisher.main(), 0)
                    preview = json.loads(output.getvalue())
                    preview_digest = preview["qualificationSHA256"]
                    self.assertRegex(preview_digest, r"^[0-9a-f]{64}$")
                    self.assertEqual(preview["sourceCommit"], self.commit)
                    self.assertEqual(preview["sourceRef"], preview_ref)
                    self.assertEqual(preview["workflowRunID"], "123456")
                    self.assertEqual(preview["manifestSHA256"], publisher.digest(manifest_path))
                    self.assertEqual(preview["provenanceBundleSHA256"], publisher.digest(bundle_path))
                    self.assertEqual(preview["rebuildReferenceChecksumsSHA256"], publisher.digest(checksums))
                    expected_reports = {
                        f"{system}/{arch}": {
                            name: publisher.digest(receipts / f"release-qualified-{system}-{arch}" / name)
                            for name in ("candidate.json", "execution.json", publisher.QUALIFICATION_BUNDLE)
                        }
                        for system, arch in publisher.TARGETS
                    }
                    self.assertEqual(preview["targetEvidenceSHA256"], expected_reports)
                    canonical = json.dumps(expected_reports, sort_keys=True, separators=(",", ":")).encode("ascii")
                    self.assertEqual(preview_digest, hashlib.sha256(canonical).hexdigest())
                    self.assertNotIn(str(self.directory), output.getvalue())
                    verify.assert_called_once()
                    self.assertEqual(verify.call_args.kwargs, {"run_id": "123456"})
                    self.assertEqual(authenticate.call_count, 20)
                    self.assertTrue(all(call.args[4] == "123456" for call in authenticate.call_args_list))
                with (patch.object(sys, "argv", [*argv, "0" * 64]),
                      contextlib.redirect_stderr(io.StringIO()) as errors):
                    self.assertEqual(publisher.main(), 1)
                    self.assertIn("candidate verification failed", errors.getvalue())
                result_path = receipts / "release-qualified-windows-arm64" / "execution.json"
                original_result = result_path.read_bytes()
                result_path.write_bytes(original_result + b"\n")
                with (patch.object(sys, "argv", [*argv, publisher.digest(checksums)]),
                      contextlib.redirect_stdout(io.StringIO()) as output):
                    self.assertEqual(publisher.main(), 0)
                    self.assertNotEqual(json.loads(output.getvalue())["qualificationSHA256"], preview_digest)
                result_path.write_bytes(original_result)
                target_bundle = result_path.with_name(publisher.QUALIFICATION_BUNDLE)
                target_bundle.write_bytes(target_bundle.read_bytes() + b"\n")
                with (patch.object(sys, "argv", [*argv, publisher.digest(checksums)]),
                      contextlib.redirect_stdout(io.StringIO()) as output):
                    self.assertEqual(publisher.main(), 0)
                    changed = json.loads(output.getvalue())
                    self.assertNotEqual(changed["qualificationSHA256"], preview_digest)
                    self.assertEqual(changed["targetEvidenceSHA256"]["windows/arm64"][publisher.QUALIFICATION_BUNDLE],
                                     publisher.digest(target_bundle))
                result_path.unlink()
                with (patch.object(sys, "argv", [*argv, publisher.digest(checksums)]),
                      contextlib.redirect_stderr(io.StringIO()) as errors):
                    self.assertEqual(publisher.main(), 1)
                    self.assertIn("candidate verification failed", errors.getvalue())
                tag.assert_not_called()
                gh.assert_not_called()
                publish_verified.assert_not_called()

    def test_attestation_requires_a_repository_signed_run_uri(self):
        path = self.directory / "execution.json"
        bundle = self.directory / publisher.QUALIFICATION_BUNDLE
        base = f"https://github.com/{publisher.REPOSITORY}/actions/runs/"
        for code, stdout, accepted in (
            (0, base + "123456/attempts/2\n", True),
            (0, "null\n" + base + "123456/attempts/1\n", True),
            (0, base + "123457/attempts/2\n", False),
            (0, base + "123456/attempts/0\n", False),
            (0, base + "123456/attempts/2/extra\n", False),
            (0, "null\n", False),
            (1, base + "123456/attempts/2\n", False),
        ):
            result = subprocess.CompletedProcess(["gh"], code, stdout=stdout)
            with self.subTest(code=code, stdout=stdout), patch.object(publisher.subprocess, "run", return_value=result) as run:
                if accepted:
                    publisher.authenticate_qualification(path, bundle, self.commit, self.ref, "123456")
                else:
                    with self.assertRaises(ValueError):
                        publisher.authenticate_qualification(path, bundle, self.commit, self.ref, "123456")
                command = run.call_args.args[0]
                self.assertEqual(command[-2:], ["--jq", ".[] | .verificationResult.signature.certificate.runInvocationURI"])
                self.assertIn("--deny-self-hosted-runners", command)
                self.assertIn("--source-digest", command)
                self.assertIn(publisher.WORKFLOW, command)

    def test_new_draft_uploads_and_verifies_before_publication(self):
        self.run_publisher([None, self.release(True, 0), self.release(True), self.release(False)])
        args = [entry.args for entry in self.calls.call_args_list]
        self.assertEqual([entry[0] for entry in args], ["create"])
        self.assertIn("--draft", args[0])
        self.assertIn("--verify-tag", args[0])
        self.assertEqual(
            [entry.args for entry in self.upload.call_args_list],
            [(456, self.snapshot / name, asset["digest"]) for name, asset in self.assets.items()],
        )
        self.promote.assert_called_once_with(456)

    def test_uncertain_draft_creation_resumes_same_tag_without_repeating_create(self):
        for error in (subprocess.TimeoutExpired(["gh", "release", "create"], 240),
                      ValueError("Concurrent creation")):
            with self.subTest(error=type(error).__name__):
                self.run_publisher(
                    [None, self.release(True, 12), self.release(True), self.release(False)],
                    create_error=error,
                )
                self.calls.assert_called_once()
                self.assertEqual(self.calls.call_args.args[0], "create")
                self.upload.assert_called_once_with(
                    456, self.snapshot / "fixture-12.zip", self.assets["fixture-12.zip"]["digest"],
                )
                self.promote.assert_called_once_with(456)

    def test_uncertain_draft_creation_refuses_missing_published_or_unverified_state(self):
        wrong_tag = self.release(True)
        wrong_tag["tagName"] = "v1.0.0-alpha"
        wrong_asset = self.release(True, 12)
        wrong_asset["assets"][-1]["digest"] = "sha256:" + "0" * 64
        for observed, tags in (
            (None, [self.commit]),
            (self.release(False), [self.commit]),
            (wrong_tag, [self.commit] * 2),
            (wrong_asset, [self.commit] * 2),
            (self.release(True, 12), [self.commit, "b" * 40]),
        ):
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                self.run_publisher(
                    [None, observed], tags=tags,
                    create_error=subprocess.TimeoutExpired(["gh", "release", "create"], 240),
                )
            self.calls.assert_called_once()
            self.upload.assert_not_called()
            self.promote.assert_not_called()

    def test_successful_creation_rechecks_remote_tag_before_upload(self):
        with self.assertRaisesRegex(ValueError, "tag changed during draft creation"):
            self.run_publisher([None, self.release(True, 0)], tags=[self.commit, "b" * 40])
        self.calls.assert_called_once()
        self.upload.assert_not_called()
        self.promote.assert_not_called()

    def test_retry_uploads_only_missing_draft_assets(self):
        self.run_publisher([self.release(True, 12), self.release(True), self.release(False)])
        self.calls.assert_not_called()
        self.upload.assert_called_once_with(456, self.snapshot / "fixture-12.zip",
                                           self.assets["fixture-12.zip"]["digest"])
        self.promote.assert_called_once_with(456)

    def test_publication_uses_the_verified_copy_when_source_changes(self):
        changed = self.directory / "fixture-12.zip"

        def verify_snapshot(frozen, _commit, _ref, **_):
            self.assertEqual((frozen / changed.name).read_bytes(), changed.name.encode())
            changed.write_bytes(b"changed original")

        self.run_publisher([self.release(True, 12), self.release(True), self.release(False)],
                           verify_snapshot=verify_snapshot)
        self.upload.assert_called_once_with(456, self.snapshot / changed.name, self.assets[changed.name]["digest"])
        self.assertEqual(changed.read_bytes(), b"changed original")

    def test_extra_input_cannot_reach_verifier_or_github(self):
        (self.directory / "extra.zip").write_bytes(b"unexpected")
        with patch.object(publisher, "verify") as verify, patch.object(publisher, "gh") as gh:
            with self.assertRaises(ValueError):
                publisher.publish(self.directory, self.commit, self.ref)
        verify.assert_not_called()
        gh.assert_not_called()

    def test_matching_published_release_is_untouched(self):
        self.run_publisher([self.release(False)])
        self.calls.assert_not_called()
        self.upload.assert_not_called()
        self.promote.assert_not_called()

    def test_mismatch_duplicate_and_missing_published_asset_leave_release_untouched(self):
        wrong = self.release(True, 1)
        wrong["assets"][0]["digest"] = "sha256:" + "0" * 64
        duplicate = self.release(True, 1)
        duplicate["assets"] *= 2
        for invalid in (wrong, duplicate, self.release(False, 12)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.run_publisher([invalid])
            self.calls.assert_not_called()
            self.upload.assert_not_called()
            self.promote.assert_not_called()

    def test_incomplete_readback_or_moved_tag_cannot_publish(self):
        for readback, tags in (
            (self.release(True, 12), None),
            (self.release(True), [self.commit, "b" * 40]),
        ):
            with self.subTest(readback=readback, tags=tags), self.assertRaises(ValueError):
                self.run_publisher([self.release(True, 12), readback], tags)
            self.calls.assert_not_called()
            self.assertEqual(self.upload.call_count, 1)
            self.promote.assert_not_called()

    def test_upload_uses_fixed_host_release_id_and_binary_file(self):
        name = "fixture + space.zip"
        path = self.directory / name
        expected = "sha256:" + "a" * 64
        body = json.dumps(dict(name=name, state="uploaded", digest=expected))
        with patch.object(publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, body, "")) as run:
            publisher.upload_asset(456, path, expected)
        run.assert_called_once_with(
            ["gh", "api", "--hostname", "github.com", "--method", "POST",
             f"https://uploads.github.com/repos/{publisher.REPOSITORY}/releases/456/assets?name=fixture+%2B+space.zip",
             "--header", "Content-Type: application/octet-stream", "--input", str(path)],
            capture_output=True, text=True, timeout=240,
        )

    def test_upload_response_must_confirm_the_expected_asset(self):
        asset = self.assets["fixture-12.zip"]
        for override in ({"name": "another.zip"}, {"state": "starter"}, {"digest": "sha256:" + "b" * 64}):
            body = json.dumps({**asset, **override})
            with self.subTest(override=override), patch.object(
                publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, body, "")
            ), self.assertRaisesRegex(ValueError, "asset could not be verified"):
                publisher.upload_asset(456, self.directory / asset["name"], asset["digest"])

    def test_new_draft_uploads_the_provenance_bundle_last(self):
        name = publisher.BUNDLE_NAME
        (self.directory / "fixture-00.zip").rename(self.directory / name)
        self.assets[name] = {**self.assets.pop("fixture-00.zip"), "name": name}
        self.run_publisher([self.release(True, 0), self.release(True), self.release(False)])
        uploaded_names = [call.args[1].name for call in self.upload.call_args_list]
        self.assertEqual(uploaded_names, sorted(self.assets.keys() - {name}) + [name])
        self.promote.assert_called_once_with(456)

    def test_existing_bundle_download_bounds_bytes_and_checks_exit(self):
        for payload, exit_code, expected in (
            (b"abc", 0, b"abc"),
            (b"ab", 0, "length differs"),
            (b"x" * (128 << 10), 0, "length differs"),
            (b"abc", 1, "could not be downloaded"),
        ):
            with self.subTest(length=len(payload), exit_code=exit_code):
                program = f"import sys; sys.stdout.buffer.write({payload[:3]!r} + b'x' * {max(0, len(payload) - 3)}); sys.exit({exit_code})"
                popen = subprocess.Popen
                with patch.object(publisher.subprocess, "Popen", side_effect=lambda _command, **kwargs: popen(
                    [sys.executable, "-c", program], **kwargs
                )) as start:
                    if isinstance(expected, bytes):
                        self.assertEqual(publisher.download_existing_bundle("987", 3), expected)
                    else:
                        with self.assertRaisesRegex(ValueError, expected):
                            publisher.download_existing_bundle("987", 3)
                    self.assertEqual(start.call_args.args[0], [
                        "gh", "api", "--hostname", "github.com", "--method", "GET",
                        f"repos/{publisher.REPOSITORY}/releases/assets/987",
                        "--header", "Accept: application/octet-stream",
                    ])

    def test_existing_bundle_download_stops_a_child_that_never_closes_stdout(self):
        popen = subprocess.Popen
        timer = publisher.Timer
        with (
            patch.object(publisher.subprocess, "Popen", side_effect=lambda _command, **kwargs: popen(
                [sys.executable, "-c", "import time; time.sleep(10)"], **kwargs
            )),
            patch.object(publisher, "Timer", side_effect=lambda _seconds, callback: timer(0.1, callback)),
            self.assertRaisesRegex(ValueError, "length differs"),
        ):
            publisher.download_existing_bundle("987", 3)

    def test_retry_reuses_an_authenticated_existing_bundle(self):
        bundle_name = publisher.BUNDLE_NAME
        new_bundle = b"fresh attestation"
        old_bundle = b"previous attestation"
        (self.directory / "fixture-00.zip").rename(self.directory / bundle_name)
        (self.directory / bundle_name).write_bytes(new_bundle)
        del self.assets["fixture-00.zip"]
        self.assets[bundle_name] = {
            "name": bundle_name, "state": "uploaded",
            "size": len(old_bundle),
            "apiUrl": f"https://api.github.com/repos/{publisher.REPOSITORY}/releases/assets/987",
            "digest": "sha256:" + hashlib.sha256(old_bundle).hexdigest(),
        }
        draft = self.release(True)
        draft["assets"] = [asset for asset in draft["assets"] if asset["name"] != "fixture-12.zip"]
        for published in (False, True):
            with self.subTest(already_published=published):
                existing = self.release(False) if published else draft
                releases = [existing] if published else [existing, self.release(True), self.release(False)]
                seen = []

                def verify(directory, commit, ref, *, run_id=None):
                    self.assertEqual((commit, ref), (self.commit, self.ref))
                    seen.append((directory / bundle_name).read_bytes())
                    self.assertEqual((directory / "fixture-12.zip").read_bytes(), b"fixture-12.zip")

                with (
                    patch.object(publisher, "verify", side_effect=verify),
                    patch.object(publisher, "git_tag_commit", return_value=self.commit),
                    patch.object(publisher, "view", side_effect=releases),
                    patch.object(publisher, "upload_asset") as upload,
                    patch.object(publisher, "promote_draft") as promote,
                    patch.object(publisher, "download_existing_bundle", return_value=old_bundle) as fetch,
                ):
                    publisher.publish(self.directory, self.commit, self.ref)
                self.assertEqual(seen, [new_bundle, old_bundle])
                self.assertEqual((self.directory / bundle_name).read_bytes(), new_bundle)
                fetch.assert_called_once_with("987", len(old_bundle))
                if published:
                    upload.assert_not_called()
                    promote.assert_not_called()
                else:
                    upload.assert_called_once()
                    self.assertEqual(upload.call_args.args[1].name, "fixture-12.zip")
                    promote.assert_called_once_with(456)

    def test_retry_rejects_changed_or_untrusted_existing_bundle_before_any_write(self):
        bundle_name = publisher.BUNDLE_NAME
        (self.directory / "fixture-00.zip").rename(self.directory / bundle_name)
        del self.assets["fixture-00.zip"]
        good = b"prior signed bundle"
        self.assets[bundle_name] = {
            "name": bundle_name, "state": "uploaded",
            "size": len(good), "digest": "sha256:" + hashlib.sha256(good).hexdigest(),
            "apiUrl": f"https://api.github.com/repos/{publisher.REPOSITORY}/releases/assets/987",
        }
        for payload, trusted in ((b"x" * len(good), True), (good, False)):
            with self.subTest(trusted=trusted):
                def verify(directory, _commit, _ref, *, run_id=None):
                    if (directory / bundle_name).read_bytes() == good and not trusted:
                        raise ValueError("Synthetic authentication failure")

                with (
                    patch.object(publisher, "verify", side_effect=verify),
                    patch.object(publisher, "git_tag_commit", return_value=self.commit),
                    patch.object(publisher, "view", return_value=self.release(True)),
                    patch.object(publisher, "upload_asset") as upload,
                    patch.object(publisher, "promote_draft") as promote,
                    patch.object(publisher, "download_existing_bundle", return_value=payload),
                    self.assertRaises(ValueError),
                ):
                    publisher.publish(self.directory, self.commit, self.ref)
                upload.assert_not_called()
                promote.assert_not_called()

    def test_interrupted_upload_does_not_promote_or_continue(self):
        with self.assertRaisesRegex(ValueError, "synthetic upload failure"):
            self.run_publisher([self.release(True, 11), self.release(True, 11)],
                               upload_error=ValueError("synthetic upload failure"))
        self.calls.assert_not_called()
        self.assertEqual(self.upload.call_count, 1)
        self.promote.assert_not_called()

    def test_upload_response_loss_resumes_after_exact_same_draft_readback(self):
        timeout = subprocess.TimeoutExpired(["gh", "api"], 240)
        self.run_publisher(
            [self.release(True, 11), self.release(True, 12), self.release(True), self.release(False)],
            upload_error=[timeout, None],
        )
        self.assertEqual([call.args[1].name for call in self.upload.call_args_list],
                         ["fixture-11.zip", "fixture-12.zip"])
        self.promote.assert_called_once_with(456)

    def test_upload_response_loss_refuses_replaced_or_invalid_draft(self):
        wrong_digest = self.release(True, 12)
        wrong_digest["assets"][-1]["digest"] = "sha256:" + "0" * 64
        starter = self.release(True, 12)
        starter["assets"][-1].update(state="starter", digest=None, size=0)
        for observed in (wrong_digest, starter, self.release(True, 12, release_id=789), self.release(False)):
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                self.run_publisher([self.release(True, 11), observed],
                                   upload_error=ValueError("synthetic upload failure"))
            self.assertEqual(self.upload.call_count, 1)
            self.promote.assert_not_called()

    def test_replaced_draft_is_refused_before_publication(self):
        with self.assertRaisesRegex(ValueError, "draft identity"):
            self.run_publisher([self.release(True), self.release(True, release_id=789)])
        self.calls.assert_not_called()
        self.promote.assert_not_called()

    def test_final_readback_must_be_the_promoted_release(self):
        with self.assertRaisesRegex(ValueError, "could not be verified"):
            self.run_publisher([self.release(True), self.release(True), self.release(False, release_id=789)])
        self.promote.assert_called_once_with(456)

    def test_lost_promotion_response_reconciles_publication_without_retrying_patch(self):
        timeout = subprocess.TimeoutExpired(["gh", "api"], 240)
        self.run_publisher([self.release(True), self.release(True), self.release(False)], promotion_error=timeout)
        self.promote.assert_called_once_with(456)
        self.upload.assert_not_called()

    def test_lost_promotion_response_refuses_unverified_publication(self):
        replaced = self.release(False, release_id=789)
        wrong_digest = self.release(False)
        wrong_digest["assets"][-1]["digest"] = "sha256:" + "0" * 64
        for observed in (None, self.release(True), replaced, wrong_digest, self.release(False, 12)):
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                self.run_publisher(
                    [self.release(True), self.release(True), observed],
                    promotion_error=ValueError("synthetic promotion response loss"),
                )
            self.promote.assert_called_once_with(456)
            self.upload.assert_not_called()

    def test_tag_change_after_promotion_or_during_existing_release_check_is_refused(self):
        for published in (False, True):
            with self.subTest(already_published=published), self.assertRaisesRegex(ValueError, "tag changed during"):
                releases = [self.release(False)] if published else [self.release(True), self.release(True), self.release(False)]
                tags = [self.commit] if published else [self.commit, self.commit]
                self.run_publisher(releases, tags + ["b" * 40])
            self.assertEqual(self.promote.call_count, 0 if published else 1)

    def test_promotion_patches_only_draft_state_by_release_id(self):
        with patch.object(publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            publisher.promote_draft(456)
        run.assert_called_once_with(
            ["gh", "api", "--hostname", "github.com", "--method", "PATCH",
             f"repos/{publisher.REPOSITORY}/releases/456", "--field", "draft=false", "--silent"],
            capture_output=True, text=True, timeout=240,
        )

    def test_view_only_treats_the_cli_not_found_result_as_absent(self):
        with patch.object(publisher, "gh", return_value=subprocess.CompletedProcess([], 1, "", "release not found\n")):
            self.assertIsNone(publisher.view(self.tag))
        with patch.object(publisher, "gh", return_value=subprocess.CompletedProcess([], 1, "", "HTTP 403")):
            with self.assertRaises(ValueError):
                publisher.view(self.tag)

    def test_tag_lookup_rejects_duplicate_and_unexpected_refs(self):
        for contents in (
            f"{self.commit}\t{self.ref}\n{self.commit}\t{self.ref}\n",
            f"{self.commit}\trefs/tags/v-unexpected\n",
            f"invalid\t{self.ref}\n",
        ):
            with self.subTest(contents=contents), patch.object(
                publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, contents, "")
            ), self.assertRaisesRegex(ValueError, "Unexpected remote tag"):
                publisher.git_tag_commit(self.tag)

    def test_tag_lookup_prefers_peeled_annotated_tag(self):
        ref = self.ref
        for contents in (
            f"{self.commit}\t{ref}\n",
            f"{'b' * 40}\t{ref}\n{self.commit}\t{ref}^{{}}\n",
        ):
            with patch.object(publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, contents, "")):
                self.assertEqual(publisher.git_tag_commit(self.tag), self.commit)


if __name__ == "__main__":
    unittest.main()
