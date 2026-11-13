import hashlib
import json
from pathlib import Path
import subprocess
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

    def run_publisher(self, releases, tags=None, verify_snapshot=None, upload_error=None):
        with (
            patch.object(publisher, "verify", side_effect=verify_snapshot) as verify,
            patch.object(publisher, "git_tag_commit", side_effect=tags or [self.commit] * 2),
            patch.object(publisher, "view", side_effect=releases),
            patch.object(publisher, "gh", return_value=subprocess.CompletedProcess([], 0, "", "")) as gh,
            patch.object(publisher, "upload_asset", side_effect=upload_error) as upload,
            patch.object(publisher, "promote_draft") as promote,
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

    def test_retry_uploads_only_missing_draft_assets(self):
        self.run_publisher([self.release(True, 12), self.release(True), self.release(False)])
        self.calls.assert_not_called()
        self.upload.assert_called_once_with(456, self.snapshot / "fixture-12.zip",
                                           self.assets["fixture-12.zip"]["digest"])
        self.promote.assert_called_once_with(456)

    def test_publication_uses_the_verified_copy_when_source_changes(self):
        changed = self.directory / "fixture-12.zip"

        def verify_snapshot(frozen, _commit, _ref):
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

                def verify(directory, commit, ref):
                    self.assertEqual((commit, ref), (self.commit, self.ref))
                    seen.append((directory / bundle_name).read_bytes())
                    self.assertEqual((directory / "fixture-12.zip").read_bytes(), b"fixture-12.zip")

                def download(args, *, stdout, **kwargs):
                    self.assertEqual(args, [
                        "gh", "api", "--hostname", "github.com", "--method", "GET",
                        f"repos/{publisher.REPOSITORY}/releases/assets/987",
                        "--header", "Accept: application/octet-stream",
                    ])
                    stdout.write(old_bundle)
                    return subprocess.CompletedProcess(args, 0)

                with (
                    patch.object(publisher, "verify", side_effect=verify),
                    patch.object(publisher, "git_tag_commit", return_value=self.commit),
                    patch.object(publisher, "view", side_effect=releases),
                    patch.object(publisher, "upload_asset") as upload,
                    patch.object(publisher, "promote_draft") as promote,
                    patch.object(publisher.subprocess, "run", side_effect=download) as fetch,
                ):
                    publisher.publish(self.directory, self.commit, self.ref)
                self.assertEqual(seen, [new_bundle, old_bundle])
                self.assertEqual((self.directory / bundle_name).read_bytes(), new_bundle)
                fetch.assert_called_once()
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
                def download(args, *, stdout, **kwargs):
                    stdout.write(payload)
                    return subprocess.CompletedProcess(args, 0)

                def verify(directory, _commit, _ref):
                    if (directory / bundle_name).read_bytes() == good and not trusted:
                        raise ValueError("Synthetic authentication failure")

                with (
                    patch.object(publisher, "verify", side_effect=verify),
                    patch.object(publisher, "git_tag_commit", return_value=self.commit),
                    patch.object(publisher, "view", return_value=self.release(True)),
                    patch.object(publisher, "upload_asset") as upload,
                    patch.object(publisher, "promote_draft") as promote,
                    patch.object(publisher.subprocess, "run", side_effect=download),
                    self.assertRaises(ValueError),
                ):
                    publisher.publish(self.directory, self.commit, self.ref)
                upload.assert_not_called()
                promote.assert_not_called()

    def test_interrupted_upload_does_not_promote_or_continue(self):
        with self.assertRaisesRegex(ValueError, "synthetic upload failure"):
            self.run_publisher([self.release(True, 11)], upload_error=ValueError("synthetic upload failure"))
        self.calls.assert_not_called()
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
