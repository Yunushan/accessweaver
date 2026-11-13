import hashlib
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

    def release(self, draft, count=13):
        return {
            "tagName": self.tag, "isDraft": draft, "isPrerelease": True,
            "assets": [dict(item) for item in list(self.assets.values())[:count]],
        }

    def run_publisher(self, releases, tags=None, verify_snapshot=None):
        with (
            patch.object(publisher, "verify", side_effect=verify_snapshot) as verify,
            patch.object(publisher, "git_tag_commit", side_effect=tags or [self.commit] * 2),
            patch.object(publisher, "view", side_effect=releases),
            patch.object(publisher, "gh", return_value=subprocess.CompletedProcess([], 0, "", "")) as gh,
        ):
            self.calls = gh
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
        self.assertEqual([entry[0] for entry in args], ["create", "upload", "edit"])
        self.assertIn("--draft", args[0])
        self.assertIn("--verify-tag", args[0])
        self.assertEqual(len(args[1]), 15)
        self.assertNotIn("--clobber", args[1])
        self.assertEqual(args[2], ("edit", self.tag, "--draft=false"))

    def test_retry_uploads_only_missing_draft_assets(self):
        self.run_publisher([self.release(True, 12), self.release(True), self.release(False)])
        self.assertEqual(self.calls.call_args_list[0].args,
                         ("upload", self.tag, str(self.snapshot / "fixture-12.zip")))
        self.assertEqual(self.calls.call_count, 2)

    def test_publication_uses_the_verified_copy_when_source_changes(self):
        changed = self.directory / "fixture-12.zip"

        def verify_snapshot(frozen, _commit, _ref):
            self.assertEqual((frozen / changed.name).read_bytes(), changed.name.encode())
            changed.write_bytes(b"changed original")

        self.run_publisher([self.release(True, 12), self.release(True), self.release(False)],
                           verify_snapshot=verify_snapshot)
        self.assertEqual(self.calls.call_args_list[0].args,
                         ("upload", self.tag, str(self.snapshot / changed.name)))
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

    def test_mismatch_duplicate_and_missing_published_asset_leave_release_untouched(self):
        wrong = self.release(True, 1)
        wrong["assets"][0]["digest"] = "sha256:" + "0" * 64
        duplicate = self.release(True, 1)
        duplicate["assets"] *= 2
        for invalid in (wrong, duplicate, self.release(False, 12)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.run_publisher([invalid])
            self.calls.assert_not_called()

    def test_incomplete_readback_or_moved_tag_cannot_publish(self):
        for readback, tags in (
            (self.release(True, 12), None),
            (self.release(True), [self.commit, "b" * 40]),
        ):
            with self.subTest(readback=readback, tags=tags), self.assertRaises(ValueError):
                self.run_publisher([self.release(True, 12), readback], tags)
            self.assertEqual(self.calls.call_count, 1)
            self.assertEqual(self.calls.call_args.args[0], "upload")

    def test_view_only_treats_the_cli_not_found_result_as_absent(self):
        with patch.object(publisher, "gh", return_value=subprocess.CompletedProcess([], 1, "", "release not found\n")):
            self.assertIsNone(publisher.view(self.tag))
        with patch.object(publisher, "gh", return_value=subprocess.CompletedProcess([], 1, "", "HTTP 403")):
            with self.assertRaises(ValueError):
                publisher.view(self.tag)

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
