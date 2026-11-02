import importlib.util
import json
import lzma
import os
from pathlib import Path
import tempfile
import sys
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bsd_guest", Path(__file__).with_name("test-bsd-guest.py"))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestSafetyTests(unittest.TestCase):
    def test_outside_hosted_context_launches_no_command(self):
        with patch.object(guest, "run") as run:
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
                guest.guard()
            run.assert_not_called()

    def test_missing_opt_in_and_wrong_runner_launch_no_command(self):
        allowed = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        for changes in ({}, {"ACCESSWEAVER_DISPOSABLE_BSD_GUEST_TEST": "1", "RUNNER_ENVIRONMENT": "self-hosted"},
                        {"ACCESSWEAVER_DISPOSABLE_BSD_GUEST_TEST": "1", "RUNNER_OS": "Windows"}):
            with self.subTest(changes=changes), patch.object(guest.platform, "system", return_value="Linux"), patch.dict(os.environ, allowed | changes, clear=True), patch.object(guest, "run") as run:
                with self.assertRaises(RuntimeError):
                    guest.guard()
                run.assert_not_called()

    def test_root_launch_is_refused_before_commands(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "ACCESSWEAVER_DISPOSABLE_BSD_GUEST_TEST": "1"}
        with patch.object(guest.platform, "system", return_value="Linux"), patch.object(os, "geteuid", return_value=0, create=True), patch.dict(os.environ, env, clear=True), patch.object(guest, "run") as run:
            with self.assertRaises(RuntimeError):
                guest.guard()
            run.assert_not_called()

    def test_bootstrap_has_only_explicit_unprivileged_key_user(self):
        config = guest.cloud_config("client-public-fixture", "host-private-fixture", "host-public-fixture")
        self.assertIs(config["ssh_pwauth"], False)
        self.assertEqual([u["name"] for u in config["users"]], ["awtest"])
        self.assertEqual(config["users"][0]["passwd"], "*")
        self.assertNotIn("sudo", config["users"][0])
        self.assertNotIn("doas", config["users"][0])
        self.assertEqual(config["ssh_keys"]["ed25519_public"], "host-public-fixture")
        self.assertEqual(json.loads(json.dumps(config)), config)

    def test_decompression_bound_fails_before_over_limit_write(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-bsd-") as name:
            root = Path(name).resolve()
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
            image = root / "fixture.xz"
            image.write_bytes(lzma.compress(b"a" * 4096))
            with self.assertRaises(ValueError):
                guest.expand_image(image, root / "bounded", maximum=4095)
            self.assertEqual((root / "bounded").stat().st_size, 0)
            self.assertEqual(guest.expand_image(image, root / "exact", maximum=4096), 4096)

    def test_package_paths_cannot_escape_source(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(guest.relative_package(root / "internal" / "api", root), "internal/api")
        for path in (root, root.parent / "outside"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                guest.relative_package(path, root)

    @unittest.skipUnless(os.name == "posix", "host helper pipe tests require POSIX")
    def test_actual_helper_output_is_bounded(self):
        with self.assertRaises(ValueError):
            guest.run([sys.executable, "-c", "import sys;sys.stdout.write('x'*4096)"], limit=4095)

    @unittest.skipUnless(os.name == "posix", "host helper session tests require POSIX")
    def test_actual_hung_helper_has_a_deadline(self):
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            guest.run([sys.executable, "-c", "import time;print('ready',flush=True);time.sleep(30)"], timeout=0.3)
        self.assertLess(time.monotonic() - started, 5)

    def test_large_helper_input_is_refused_before_launch(self):
        with patch.object(guest.subprocess, "Popen") as launch:
            with self.assertRaises(ValueError):
                guest.run(["unused"], data=b"x" * 2049)
            launch.assert_not_called()

    def test_wrong_guest_kernel_architecture_user_or_uid_is_refused(self):
        valid = ["FreeBSD", "15.1-RELEASE", "amd64", "1001", "awtest"]
        self.assertEqual(guest.validate_guest_identity(valid)["uid"], 1001)
        for index, value in [(0, "Linux"), (1, "14.4-RELEASE"), (2, "arm64"), (3, "0"), (3, "invalid"), (4, "root")]:
            with self.subTest(index=index, value=value):
                invalid = list(valid)
                invalid[index] = value
                with self.assertRaises(RuntimeError):
                    guest.validate_guest_identity(invalid)

    @unittest.skipUnless(os.name == "posix", "capsule identity checks require POSIX owners")
    def test_live_or_replaced_capsule_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-bsd-") as name:
            root = Path(name).resolve()
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
            capsule = root / "capsule"
            capsule.mkdir(mode=0o700)
            (capsule / "keep").write_text("retained", encoding="utf-8")
            identity = capsule.stat()
            with self.assertRaises(RuntimeError):
                guest.remove_owned_capsule(capsule, root, identity, False)
            wrong = root / "different"
            wrong.mkdir(mode=0o700)
            with self.assertRaises(RuntimeError):
                guest.remove_owned_capsule(capsule, root, wrong.stat(), True)
            self.assertEqual((capsule / "keep").read_text(encoding="utf-8"), "retained")
            guest.remove_owned_capsule(capsule, root, identity, True)
            self.assertFalse(capsule.exists())
            self.assertTrue(wrong.is_dir())

    def test_concatenated_go_package_metadata_is_not_truncated(self):
        self.assertEqual(guest.decode_objects(b' {"name":"one"}\n {"name":"two"} '), [{"name": "one"}, {"name": "two"}])
        with self.assertRaises(json.JSONDecodeError):
            guest.decode_objects(b'{"name":"one"}\nmalformed')


if __name__ == "__main__":
    unittest.main()
