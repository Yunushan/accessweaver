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

    def test_boot_error_classification_excludes_arbitrary_private_text(self):
        private = b"PRIVATE_SEED_MATERIAL_AND_PATH"
        for message, expected in [(b"Host key verification failed", "host-key-rejected"),
                                  (b"Permission denied (publickey)", "authentication-refused"),
                                  (b"Connection refused", "not-listening"),
                                  (b"Connection timed out", "connect-timeout"),
                                  (b"Connection reset", "connection-reset"),
                                  (b"No route to host", "unreachable")]:
            with self.subTest(expected=expected):
                result = guest.ssh_failure_class(message + private)
                self.assertEqual(result, expected)
                self.assertNotIn("PRIVATE", result)
        self.assertEqual(guest.ssh_failure_class(private), "unclassified")

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


class BootDiskPrivacyTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("bsd_boot", Path(__file__).with_name("bsd_boot_diagnostics.py"))
        self.boot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.boot)

    def test_missing_boot_state_never_becomes_a_successful_boot(self):
        data = self.boot.boot_observations(lambda _: b"", lambda _: False, b"client", b"host")
        self.assertTrue(data.pop("inspectionComplete"))
        self.assertFalse(any(data.values()))

    def test_disk_observations_exclude_contents_and_never_read_cached_keys(self):
        private = b"PRIVATE_KEY_AND_HOSTILE_LOG_CONTENT"
        files = {
            "/etc/rc.conf.d/hostname": b'hostname="awbsd"\n',
            "/etc/passwd": b"awtest:*:1001:1001::/home/awtest:/bin/sh\n",
            "/home/awtest/.ssh/authorized_keys": b"client-public\n",
            "/etc/ssh/ssh_host_ed25519_key.pub": b"host-public\n",
            "/etc/ssh/sshd_config": b"#PasswordAuthentication yes\nPasswordAuthentication no\n",
            "/var/db/dhclient.leases.vtnet0": b"lease { fixed-address 10.0.2.15; }\n",
            "/var/log/nuageinit.log": private + b"\nbad argument\nstack traceback\nerror parsing\n",
            "/var/log/messages": private + b"\nsshd[42]: test\n",
        }
        reads = []
        def read(name):
            reads.append(name)
            return files.get(name, b"")
        data = self.boot.boot_observations(read, lambda _: True, b"client-public", b"host-public")
        for name in ("inspectionComplete", "hostnameConfigured", "nuageCachePresent", "testUserCreated",
                     "clientKeyInstalled", "hostKeyInstalled", "passwordAuthenticationDisabled",
                     "controlAddressDHCPLeasePresent", "sshdPIDFilePresent", "nuageParseErrorObserved",
                     "nuageArgumentErrorObserved", "nuageTracebackObserved", "sshdMessageObserved"):
            self.assertIs(data[name], True)
        self.assertNotIn("/var/cache/nuageinit/user_data", reads)
        self.assertTrue(all(type(value) is bool or value is None for value in data.values()))
        self.assertNotIn("PRIVATE", json.dumps(data))
        self.assertNotIn("public", json.dumps(data))

    def test_root_user_wrong_keys_commented_auth_and_other_lease_are_not_matches(self):
        files = {"/etc/passwd": b"awtest:*:0:0::/:/bin/sh\n",
                 "/home/awtest/.ssh/authorized_keys": b"wrong-client\n",
                 "/etc/ssh/ssh_host_ed25519_key.pub": b"wrong-host\n",
                 "/etc/ssh/sshd_config": b"#PasswordAuthentication no\n",
                 "/var/db/dhclient.leases.vtnet0": b"fixed-address 10.0.2.150;\n"}
        data = self.boot.boot_observations(lambda name: files.get(name, b""), lambda _: False, b"client", b"host")
        for name in ("testUserCreated", "clientKeyInstalled", "hostKeyInstalled",
                     "passwordAuthenticationDisabled", "controlAddressDHCPLeasePresent"):
            self.assertIs(data[name], False)

    def test_later_or_conditional_password_directive_is_not_a_global_disable(self):
        for text in (b"PasswordAuthentication yes\nPasswordAuthentication no\n",
                     b"Match User awtest\nPasswordAuthentication no\n",
                     b"#PasswordAuthentication no\n"):
            with self.subTest(text=text):
                self.assertFalse(self.boot.global_password_auth_disabled(text))
        self.assertTrue(self.boot.global_password_auth_disabled(b" PasswordAuthentication NO # fixture\n"))

    def test_runtime_observations_keep_independent_false_results(self):
        runtime = {"configurationValid": True, "serviceRunning": True,
                   "controlAddressConfigured": False, "ipv4SSHListening": False}
        files = {"/root/accessweaver-boot-state.json": json.dumps(runtime).encode(),
                 "/var/log/accessweaver-sshd.log": b"PRIVATE_CONTENT\nServer listening on 0.0.0.0 port 22.\n",
                 "/var/log/accessweaver-sshd-configtest.log": b"UNPROTECTED PRIVATE KEY FILE: PRIVATE_PATH\n"}
        data = self.boot.boot_observations(lambda name: files.get(name, b""), lambda _: False, b"client", b"host")
        for name in ("runtimeObservationPresent", "sshdConfigCheckPassed", "sshdRuntimeServiceRunningObserved",
                     "sshdListeningLogObserved", "sshdKeyPermissionErrorObserved"):
            self.assertIs(data[name], True)
        for name in ("controlIPv4AddressObserved", "sshdRuntimeIPv4ListenerObserved"):
            self.assertIs(data[name], False)
        self.assertNotIn("PRIVATE", json.dumps(data))

    def test_runtime_observer_rejects_extra_fields_nonbooleans_and_invalid_json(self):
        valid = {"configurationValid": True, "serviceRunning": True,
                 "controlAddressConfigured": True, "ipv4SSHListening": True}
        for invalid in ({**valid, "private": "PRIVATE_SECRET"}, {**valid, "serviceRunning": 1},
                        {"serviceRunning": True}, [], "PRIVATE_SECRET"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.boot.runtime_observations(json.dumps(invalid).encode())
        with self.assertRaises(ValueError):
            self.boot.runtime_observations(b"PRIVATE_INVALID_JSON")
        self.assertEqual(self.boot.runtime_observations(b""), {})
        self.assertEqual(self.boot.runtime_observations(json.dumps(valid).encode()), valid)

    def test_runtime_command_exit_and_empty_stderr_remain_distinct(self):
        runtime = {"configurationValid": False, "serviceRunning": False,
                   "controlAddressConfigured": True, "ipv4SSHListening": False,
                   "configurationExitCode": 132, "configurationLogBytes": 0}
        files = {"/root/accessweaver-boot-state.json": json.dumps(runtime).encode()}
        data = self.boot.boot_observations(lambda name: files.get(name, b""), lambda _: False, b"client", b"host")
        self.assertEqual(data["sshdConfigCheckExitCode"], 132)
        self.assertEqual(data["sshdConfigCheckLogBytes"], 0)
        self.assertIs(data["sshdConfigCheckPassed"], False)
        self.assertNotIn("PRIVATE", json.dumps(data))
        runtime.update(configurationValid=True, configurationExitCode=0, configurationLogBytes=1 << 20)
        self.assertEqual(self.boot.runtime_observations(json.dumps(runtime).encode()), runtime)

    def test_runtime_command_metadata_rejects_unbounded_inconsistent_or_hostile_values(self):
        valid = {"configurationValid": False, "serviceRunning": False,
                 "controlAddressConfigured": True, "ipv4SSHListening": False,
                 "configurationExitCode": 1, "configurationLogBytes": 1}
        invalids = [{**valid, "configurationExitCode": value} for value in (-1, 256, True, 1.5, "PRIVATE")]
        invalids += [{**valid, "configurationLogBytes": value} for value in (-1, (1 << 20) + 1, False, 1.5, "PRIVATE")]
        invalids += [{**valid, "configurationExitCode": 0}, {**valid, "configurationValid": True},
                     {name: value for name, value in valid.items() if name != "configurationLogBytes"}]
        for invalid in invalids:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.boot.runtime_observations(json.dumps(invalid).encode())

    @unittest.skipUnless(os.name == "posix", "guest observer rejection uses a POSIX shell")
    def test_actual_observer_refuses_missing_opt_in_or_non_freebsd_host(self):
        script = str(Path(__file__).with_name("bsd-boot-observer.sh"))
        result = guest.run(["/bin/sh", script], env={}, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        if not sys.platform.startswith("freebsd"):
            result = guest.run(["/bin/sh", script], env={"ACCESSWEAVER_DISPOSABLE_BSD_BOOT_OBSERVER": "1"}, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")

    def test_postmortem_requires_hosted_opt_in_before_disk_reads(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(self.boot, "inspect") as inspect:
            with self.assertRaises(RuntimeError):
                self.boot.main()
            inspect.assert_not_called()

    def test_postmortem_refuses_path_outside_private_capsule_root(self):
        with self.assertRaises(RuntimeError):
            self.boot.inspect(Path(__file__).resolve().parents[1] / "build" / "unrelated")


if __name__ == "__main__":
    unittest.main()
