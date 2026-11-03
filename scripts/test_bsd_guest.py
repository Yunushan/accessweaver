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


class TargetAndFirmwareTests(unittest.TestCase):
    def hosted(self, arch):
        repo = Path(__file__).resolve().parents[1]
        return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                "ACCESSWEAVER_DISPOSABLE_BSD_GUEST_TEST": "1", "ACCESSWEAVER_BSD_ARCH": arch,
                "GITHUB_WORKSPACE": str(repo), "GITHUB_SHA": "a" * 40, "GO_VERSION": "1.27.3"}

    def test_unknown_target_and_cross_host_architecture_launch_no_command(self):
        for arch, machine in (("arm64/../../other", "aarch64"), ("", "x86_64"), ("riscv64", "x86_64"),
                              ("arm64", "x86_64"), ("amd64", "aarch64")):
            with self.subTest(arch=arch, machine=machine), patch.dict(os.environ, self.hosted(arch), clear=True), \
                    patch.object(guest.platform, "system", return_value="Linux"), patch.object(guest.platform, "machine", return_value=machine), \
                    patch.object(guest.os, "geteuid", return_value=1001, create=True), patch.object(guest, "run") as run:
                with self.assertRaises(RuntimeError):
                    guest.guard()
                run.assert_not_called()

    def test_guard_binds_each_target_to_a_native_host_sdk(self):
        for arch, machine in (("amd64", "x86_64"), ("arm64", "aarch64")):
            sdk = {"GOOS": "linux", "GOARCH": arch, "GOHOSTOS": "linux", "GOHOSTARCH": arch,
                   "GOVERSION": "go1.27.3", "GOTOOLCHAIN": "local"}
            for cross_sdk in (False, True):
                reported = dict(sdk, GOHOSTARCH="amd64" if arch == "arm64" else "arm64") if cross_sdk else sdk
                def command(args, **kwargs):
                    data = json.dumps(reported).encode() if args[0] == "go" else (b"a" * 40 if "rev-parse" in args else b"")
                    return guest.subprocess.CompletedProcess(args, 0, data)
                with self.subTest(arch=arch, cross_sdk=cross_sdk), patch.dict(os.environ, self.hosted(arch), clear=True), \
                        patch.object(guest.platform, "system", return_value="Linux"), patch.object(guest.platform, "machine", return_value=machine), \
                        patch.object(guest.os, "geteuid", return_value=1001, create=True), patch.object(guest.shutil, "disk_usage") as space, \
                        patch.object(guest, "run", side_effect=command):
                    space.return_value.free = 20 << 30
                    if cross_sdk:
                        with self.assertRaises(RuntimeError):
                            guest.guard()
                    else:
                        _, source, actual_sdk, target = guest.guard()
                        self.assertEqual(source, "a" * 40)
                        self.assertEqual(actual_sdk, sdk)
                        self.assertEqual(target["arch"], arch)

    def test_payload_keeps_selected_architecture_through_test_and_cli_builds(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory(prefix="accessweaver-payload-") as name:
                root = Path(name).resolve()
                repo, capsule = root / "repo", root / "capsule"
                (repo / "internal" / "profile").mkdir(parents=True)
                capsule.mkdir(mode=0o700)
                compiled = []
                def command(args, *, env=None, **kwargs):
                    result = b""
                    if args[:2] == ["go", "list"]:
                        result = json.dumps({"ImportPath": guest.MODULE + "internal/profile",
                                             "Dir": str(repo / "internal/profile"), "TestGoFiles": ["fixture_test.go"]}).encode()
                    elif args[:2] == ["go", "test"]:
                        self.assertEqual(env["GOOS"], "freebsd")
                        self.assertEqual(env["GOARCH"], arch)
                        output = Path(args[args.index("-o") + 1])
                        output.write_bytes(b"test-for-" + arch.encode())
                        compiled.append(env["GOARCH"])
                    elif args[:2] == ["bash", "scripts/build-all.sh"]:
                        self.assertEqual(args[2], "freebsd/" + arch)
                        output = Path(env["OUTPUT_DIR"])
                        (output / ("accessweaver-freebsd-" + arch)).write_bytes(b"cli-for-" + arch.encode())
                        (output / "BUILD-INFO.json").write_text("{}", encoding="utf-8")
                    elif args[:2] == ["git", "ls-tree"]:
                        result = b"100644 blob " + b"0" * 40 + b" 4\tfixture.txt\n"
                    elif args[:2] == ["git", "archive"]:
                        output = next(value.removeprefix("--output=") for value in args if value.startswith("--output="))
                        Path(output).write_bytes(b"source-fixture")
                    elif args[:2] != ["git", "status"]:
                        self.fail("unexpected build command")
                    return guest.subprocess.CompletedProcess(args, 0, result)
                target = guest.selected_target(arch)
                with patch.object(guest, "run", side_effect=command):
                    manifest, archive = guest.build_payload(repo, capsule, "a" * 40, target)
                self.assertEqual(target["arch"], arch)
                self.assertEqual(compiled, [arch])
                self.assertEqual(manifest["goarch"], arch)
                self.assertEqual(manifest["cli"]["file"], "accessweaver-freebsd-" + arch)
                self.assertEqual(manifest["cli"]["sha256"], guest.digest(capsule / "payload" / manifest["cli"]["file"]))
                self.assertEqual(manifest["sourceArchiveSHA256"], guest.digest(capsule / "payload/source.tar"))
                self.assertEqual(len(manifest["packages"]), 1)
                with guest.tarfile.open(archive) as payload:
                    self.assertIn("accessweaver-freebsd-" + arch, payload.getnames())
                    self.assertNotIn("accessweaver-freebsd-" + ("amd64" if arch == "arm64" else "arm64"), payload.getnames())

    def test_guest_architecture_cannot_be_substituted_between_targets(self):
        for arch, wrong in (("amd64", "arm64"), ("arm64", "amd64")):
            target = guest.selected_target(arch)
            actual = ["FreeBSD", "15.1-RELEASE", arch, "1001", "awtest"]
            self.assertEqual(guest.validate_guest_identity(actual, target)["machine"], arch)
            actual[2] = wrong
            with self.assertRaises(RuntimeError):
                guest.validate_guest_identity(actual, target)

    def test_firmware_failure_report_exposes_only_fixed_codes_and_metadata(self):
        error = guest.FirmwareSnapshotError("ancestor-permissions", {"node": "share", "uid": 0, "mode": 0o777})
        self.assertEqual(guest.firmware_failure_observations(error),
                         {"firmwareFailureCode": "ancestor-permissions",
                          "firmwareFailureMetadata": {"node": "share", "uid": 0, "mode": 0o777}})
        self.assertEqual(guest.firmware_failure_observations(RuntimeError("PRIVATE_PATH_OR_CONTENT")), {})
        for code, metadata in (("PRIVATE", {}), ("source-owner", {"path": "PRIVATE"}),
                               ("source-owner", {"node": "PRIVATE"}), ("source-owner", {"uid": "PRIVATE"}),
                               ("source-owner", {"uid": True}), ("copy-changed", {"mtimeChanged": 1})):
            with self.subTest(code=code, metadata=metadata), self.assertRaises(ValueError):
                guest.FirmwareSnapshotError(code, metadata)

    def test_vm_commands_keep_control_isolated_and_firmware_private(self):
        firmware = {"code": Path("/private/capsule/efi-code.fd"), "variables": Path("/private/capsule/efi-vars.fd")}
        for arch in ("amd64", "arm64"):
            for acceleration in ("tcg", "kvm"):
                target = guest.selected_target(arch)
                command = guest.virtual_machine_command(target, Path("/private/capsule/overlay.qcow2"),
                                                        Path("/private/capsule/seed.iso"), acceleration, firmware)
                self.assertEqual(command[command.index("-m") + 1], "3072")
                self.assertEqual(command[command.index("-smp") + 1], "2")
                self.assertEqual(command[command.index("-monitor") + 1], "none")
                self.assertIn("user,id=n1,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22", command)
                self.assertNotIn("-virtfs", command)
                self.assertNotIn("-fsdev", command)
                if arch == "arm64":
                    self.assertIn("virt,gic-version=3", command)
                    self.assertIn("if=pflash,format=raw,unit=0,file=" + str(firmware["code"]) + ",readonly=on", command)
                    self.assertIn("if=pflash,format=raw,unit=1,file=" + str(firmware["variables"]), command)
                    self.assertIn("scsi-cd,drive=seed,bus=scsi0.0,bootindex=2", command)
                else:
                    self.assertFalse(any("pflash" in value for value in command))
        with self.assertRaises(RuntimeError):
            guest.virtual_machine_command(guest.selected_target("arm64"), Path("/overlay"), Path("/seed"), "tcg")
        with self.assertRaises(RuntimeError):
            guest.virtual_machine_command(guest.selected_target("amd64"), Path("/overlay"), Path("/seed"), "arbitrary")

    @unittest.skipUnless(os.name == "posix", "firmware ownership and no-follow snapshots require POSIX")
    def test_each_guest_gets_private_firmware_snapshots_without_changing_templates(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-firmware-") as name:
            root = Path(name).resolve()
            templates = root / "templates"
            templates.mkdir(mode=0o700)
            code, variables = templates / "AAVMF_CODE.fd", templates / "AAVMF_VARS.fd"
            code.write_bytes(b"public-code-fixture")
            variables.write_bytes(b"public-variables-fixture")
            for source in (code, variables):
                source.chmod(0o600)
            original = guest.copy_firmware
            def copy(source, destination):
                self.assertEqual(source.parent, Path("/usr/share/AAVMF"))
                return original(templates / source.name, destination, owner=os.geteuid())
            prepared = []
            with patch.object(guest, "copy_firmware", side_effect=copy):
                for label in ("one", "two"):
                    capsule = root / label
                    capsule.mkdir(mode=0o700)
                    prepared.append(guest.prepare_arm_firmware(capsule))
            first, second = prepared
            self.assertEqual(first["codeSHA256"], guest.digest(code))
            self.assertEqual(first["initialVariablesSHA256"], guest.digest(variables))
            self.assertEqual(first["code"].stat().st_mode & 0o777, 0o400)
            self.assertEqual(first["variables"].stat().st_mode & 0o777, 0o600)
            first["variables"].write_bytes(b"changed-in-one-guest")
            self.assertEqual(second["variables"].read_bytes(), b"public-variables-fixture")
            self.assertEqual(variables.read_bytes(), b"public-variables-fixture")
            self.assertEqual(code.read_bytes(), b"public-code-fixture")

    @unittest.skipUnless(os.name == "posix", "firmware snapshot ownership requires POSIX")
    def test_firmware_refuses_untrusted_owner_modes_links_and_existing_destinations(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-firmware-") as name:
            root = Path(name).resolve()
            source, destination, retained = root / "template", root / "copy", root / "retained"
            source.write_bytes(b"public-firmware")
            source.chmod(0o600)
            with self.assertRaises(RuntimeError):
                guest.copy_firmware(source, destination, owner=os.geteuid() + 10000)
            self.assertFalse(destination.exists())
            source.chmod(0o666)
            with self.assertRaises(RuntimeError):
                guest.copy_firmware(source, destination, owner=os.geteuid())
            source.chmod(0o600)
            linked = root / "linked"
            os.link(source, linked)
            with self.assertRaises(RuntimeError):
                guest.copy_firmware(source, destination, owner=os.geteuid())
            linked.unlink()
            retained.write_bytes(b"keep")
            destination.symlink_to(retained)
            with self.assertRaises(FileExistsError):
                guest.copy_firmware(source, destination, owner=os.geteuid())
            self.assertEqual(retained.read_bytes(), b"keep")
            destination.unlink()
            destination.write_bytes(b"retain-existing")
            with self.assertRaises(FileExistsError):
                guest.copy_firmware(source, destination, owner=os.geteuid())
            self.assertEqual(destination.read_bytes(), b"retain-existing")

    @unittest.skipUnless(os.name == "posix", "firmware special-file refusal requires POSIX")
    def test_firmware_fifo_is_refused_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-firmware-") as name:
            root = Path(name).resolve()
            source, destination = root / "fifo", root / "copy"
            os.mkfifo(source, 0o600)
            code = (
                "import importlib.util,os,sys;from pathlib import Path;"
                "s=importlib.util.spec_from_file_location('probe',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "\ntry: m.copy_firmware(Path(sys.argv[2]),Path(sys.argv[3]),owner=os.geteuid())"
                "\nexcept RuntimeError: print('refused')"
                "\nelse: raise SystemExit(1)"
            )
            result = guest.run([sys.executable, "-c", code, str(Path(guest.__file__).resolve()),
                                str(source), str(destination)], timeout=3)
            self.assertEqual(result.stdout, b"refused\n")
            self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "posix", "firmware snapshot ownership requires POSIX")
    def test_oversized_firmware_is_rejected_before_creating_destination(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-firmware-") as name:
            root = Path(name).resolve()
            source, destination = root / "template", root / "copy"
            source.write_bytes(b"bounded")
            source.chmod(0o600)
            info = source.stat()
            oversized = type("Oversized", (), {"st_mode": info.st_mode, "st_uid": os.geteuid(),
                                               "st_nlink": 1, "st_size": (64 << 20) + 1})()
            with patch.object(guest.os, "fstat", return_value=oversized), self.assertRaises(RuntimeError):
                guest.copy_firmware(source, destination, owner=os.geteuid())
            self.assertFalse(destination.exists())


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

    def test_guest_report_consumer_preserves_numeric_and_legacy_observations(self):
        absent = self.boot.boot_observations(lambda _: b"", lambda _: False, b"client", b"host")
        self.assertEqual(guest.decode_disk_observations(json.dumps(absent).encode()), absent)
        for code, size in ((132, 0), (1, 200), (0, 0), (255, 1 << 20)):
            runtime = {"configurationValid": code == 0, "serviceRunning": False,
                       "controlAddressConfigured": True, "ipv4SSHListening": False,
                       "configurationExitCode": code, "configurationLogBytes": size}
            files = {"/root/accessweaver-boot-state.json": json.dumps(runtime).encode()}
            actual = self.boot.boot_observations(lambda name: files.get(name, b""), lambda _: False, b"client", b"host")
            decoded = guest.decode_disk_observations(json.dumps(actual).encode())
            self.assertEqual(decoded["sshdConfigCheckExitCode"], code)
            self.assertEqual(decoded["sshdConfigCheckLogBytes"], size)
            self.assertEqual(decoded, actual)

    def test_guest_report_consumer_rejects_private_fields_and_invalid_command_metadata(self):
        base = self.boot.boot_observations(lambda _: b"", lambda _: False, b"client", b"host")
        valid = {**base, "runtimeObservationPresent": True,
                 "sshdConfigCheckExitCode": 132, "sshdConfigCheckLogBytes": 0}
        invalids = [{**valid, "PRIVATE_FIELD": True}, {**valid, "inspectionComplete": "PRIVATE"},
                    {**valid, "sshdConfigCheckExitCode": 0},
                    {**valid, "sshdConfigCheckExitCode": None},
                    {**valid, "sshdConfigCheckLogBytes": None},
                    {**valid, "runtimeObservationPresent": False},
                    {name: value for name, value in valid.items() if name != "sshdPIDFilePresent"},
                    [], "PRIVATE"]
        invalids += [{**valid, "sshdConfigCheckExitCode": value} for value in (-1, 256, True, 1.5, "PRIVATE")]
        invalids += [{**valid, "sshdConfigCheckLogBytes": value} for value in (-1, (1 << 20) + 1, False, 1.5, "PRIVATE")]
        for invalid in invalids:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError) as result:
                guest.decode_disk_observations(json.dumps(invalid).encode())
            self.assertNotIn("PRIVATE", str(result.exception))

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
