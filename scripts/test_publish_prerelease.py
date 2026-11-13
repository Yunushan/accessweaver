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
