import importlib.util
import json
import hashlib
import subprocess

import bsd_packaged_candidate as packaged_candidate
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


class PackagedUpdateBuildTests(unittest.TestCase):
    def test_compares_the_original_guest_executable_without_writing_state(self):
        root = "/home/awtest/test capsule"
        executable = root + "/accessweaver"
        for system in ("freebsd", "openbsd"):
            build = {"version": "0.1.0-alpha", "commit": "a" * 40, "sourceState": "clean",
                     "platform": system, "arch": "arm64", "builtAt": "unknown", "goVersion": "go1.27.4"}
            receipt = {"build": build, "binarySha256": "b" * 64}
            comparison = {"version": "v0.1.0-alpha", "currentVersion": "0.1.0-alpha",
                          "updateAvailable": False, "build": dict(build)}
            with self.subTest(system=system), patch.object(guest, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, json.dumps(comparison).encode())
                guest.verify_packaged_update_build(["ssh"], root, executable, receipt)
                self.assertEqual(run.call_args.args, (["ssh"],))
                self.assertEqual(run.call_args.kwargs["limit"], 4096)
                self.assertEqual(run.call_args.kwargs["timeout"], 30)
                script = run.call_args.kwargs["data"].decode()
                self.assertIn("'"+executable+"' system check-version --build-identity --follow-channel v0.1.0-alpha", script)
                self.assertEqual(script.count("test ! -e"), 2)
                self.assertIn("sha256 -q '" + executable + "'", script)
                self.assertIn(receipt["binarySha256"], script)

            for value in (
                json.dumps({**comparison, "build": {**build, "sourceState": "modified"}}).encode(),
                json.dumps({**comparison, "build": {**build, "platform": "linux"}}).encode(),
                json.dumps({**comparison, "updateAvailable": 0}).encode(),
                json.dumps({**comparison, "currentVersion": "0.0.1"}).encode(),
                json.dumps(comparison).encode()[:-1] + b', "version": "v0.1.0-alpha"}',
            ):
                with self.subTest(system=system), patch.object(guest, "run") as run:
                    run.return_value = subprocess.CompletedProcess([], 0, value)
                    with self.assertRaises((RuntimeError, ValueError)):
                        guest.verify_packaged_update_build(["ssh"], root, executable, receipt)


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

    @unittest.skipUnless(os.name == "posix", "host helper session tests require POSIX")
    def test_output_bound_survives_permission_error_only_when_reaped_group_is_gone(self):
        actual = guest.os.killpg
        signals = []
        def signal_group(pid, sig):
            signals.append(sig)
            if sig == guest.signal.SIGKILL:
                raise PermissionError("simulated unreaped-child signal refusal")
            return actual(pid, sig)
        with patch.object(guest.os, "killpg", side_effect=signal_group):
            with self.assertRaisesRegex(ValueError, "bounded helper output exceeded"):
                guest.run([sys.executable, "-c", "import sys;sys.stdout.write('x'*4096)"], limit=4095)
        self.assertEqual(signals, [guest.signal.SIGKILL, 0])

    @unittest.skipUnless(os.name == "posix", "host helper session tests require POSIX")
    def test_reaped_child_with_unconfirmed_group_cleanup_still_fails(self):
        for result in (None, PermissionError("group still inaccessible")):
            with self.subTest(result=type(result).__name__):
                def signal_group(pid, sig):
                    if sig == guest.signal.SIGKILL:
                        raise PermissionError("signal refused")
                    if result is not None:
                        raise result
                    return result
                with patch.object(guest.os, "killpg", side_effect=signal_group):
                    with self.assertRaises(PermissionError):
                        guest.run([sys.executable, "-c", "import sys;sys.stdout.write('x'*4096)"], limit=4095)

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


@unittest.skipUnless(os.name == "posix", "pipe selector subprocess fixture requires POSIX")
class StructuredCommandTests(unittest.TestCase):
    def test_stderr_diagnostics_do_not_contaminate_discovery_json(self):
        body = "import os;os.write(2,b'go: downloading fixture.invalid/module v1.0.0\\n');os.write(1,b'{\"ImportPath\":\"fixture\"}\\n')"
        result = guest.run([sys.executable, "-c", body], split_stderr=True, timeout=5)
        self.assertEqual(guest.decode_objects(result.stdout), [{"ImportPath": "fixture"}])
        self.assertIn(b"go: downloading", result.stderr)
        merged = guest.run([sys.executable, "-c", body], timeout=5)
        with self.assertRaises(json.JSONDecodeError):guest.decode_objects(merged.stdout)
        self.assertIsNone(merged.stderr)

    def test_split_streams_share_one_bound_and_preserve_nonzero_exit(self):
        body = "import os;os.write(1,b'a'*1024);os.write(2,b'b'*1024)"
        with self.assertRaisesRegex(ValueError, "bounded helper output exceeded"):
            guest.run([sys.executable, "-c", body], split_stderr=True, limit=1500, timeout=5)
        body = "import os;os.write(1,b'{}');os.write(2,b'PRIVATE_FIXTURE');raise SystemExit(7)"
        with self.assertRaises(guest.CommandFailure) as caught:
            guest.run([sys.executable, "-c", body], split_stderr=True, timeout=5)
        self.assertEqual(caught.exception.result.returncode,7)
        self.assertEqual(caught.exception.result.stdout,b'{}')
        self.assertEqual(caught.exception.result.stderr,b'PRIVATE_FIXTURE')
        self.assertNotIn("PRIVATE_FIXTURE",str(caught.exception))


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
        cases = [("freebsd", arch, mode) for arch in ("amd64", "arm64") for mode in (False, True, "changed-cli")]
        cases += [("openbsd", arch, mode) for arch in ("amd64", "arm64") for mode in (False, True, "changed-cli")]
        for goos, arch, packaged in cases:
            with self.subTest(goos=goos, arch=arch, packaged=packaged), tempfile.TemporaryDirectory(prefix="accessweaver-payload-") as name:
                root = Path(name).resolve()
                repo, capsule = root / "repo", root / "capsule"
                (repo / "internal" / "profile").mkdir(parents=True)
                (repo / "internal/profile/fixture_test.go").write_text("package profile\nfunc TestFixture(t *testing.T) {}\n", encoding="utf-8")
                capsule.mkdir(mode=0o700)
                compiled = []
                def command(args, *, env=None, **kwargs):
                    result = b""
                    if args[:2] == ["go", "list"]:
                        self.assertTrue(kwargs.get("split_stderr"), "module-download diagnostics must not contaminate JSON")
                        result = json.dumps({"ImportPath": guest.MODULE + "internal/profile",
                                             "Dir": str(repo / "internal/profile"), "TestGoFiles": ["fixture_test.go"]}).encode()
                    elif args[:2] == ["go", "test"]:
                        self.assertEqual(env["GOOS"], goos)
                        self.assertEqual(env["GOARCH"], arch)
                        output = Path(args[args.index("-o") + 1])
                        output.write_bytes(b"test-for-" + arch.encode())
                        compiled.append(env["GOARCH"])
                    elif args[:2] == ["bash", "scripts/build-all.sh"]:
                        self.assertFalse(packaged, "archived CLI was replaced with a source build")
                        self.assertEqual(args[2], goos + "/" + arch)
                        output = Path(env["OUTPUT_DIR"])
                        (output / ("accessweaver-" + goos + "-" + arch)).write_bytes(b"cli-for-" + arch.encode())
                        (output / "BUILD-INFO.json").write_text("{}", encoding="utf-8")
                    elif args[:2] == ["git", "ls-tree"]:
                        result = b"100644 blob " + b"0" * 40 + b" 4\tfixture.txt\n"
                    elif args[:2] == ["git", "archive"]:
                        output = next(value.removeprefix("--output=") for value in args if value.startswith("--output="))
                        Path(output).write_bytes(b"source-fixture")
                    elif args[:2] != ["git", "status"]:
                        self.fail("unexpected build command")
                    return guest.subprocess.CompletedProcess(args, 0, result, b"go: downloading fixture.invalid/module v1.0.0\n" if args[:2] == ["go", "list"] else None)
                target = dict(guest.selected_target(arch), goos=goos, label=goos + "-" + arch)
                staged = root / "authenticated-stage"
                receipt = {"build": {"arch": arch}, "binarySha256": hashlib.sha256(b"archived-cli-for-" + arch.encode()).hexdigest()}
                def copy(directory, destination, source, actual_arch, ref, *, goos):
                    self.assertEqual((directory, source, actual_arch, ref, goos), (staged, "a" * 40, arch, "refs/heads/main", target["goos"]))
                    destination.write_bytes(b"changed-after-handoff" if packaged == "changed-cli" else b"archived-cli-for-" + arch.encode())
                    return receipt
                with patch.object(guest, "run", side_effect=command), patch.object(guest, "copy_packaged_cli", side_effect=copy) as stage, patch.dict(os.environ, {"GITHUB_REF": "refs/heads/main"}):
                    if packaged == "changed-cli":
                        with self.assertRaisesRegex(RuntimeError, "archived executable changed"):
                            guest.build_payload(repo, capsule, "a" * 40, target, staged)
                        self.assertFalse((capsule / "payload.tar.gz").exists())
                        continue
                    observations = {}
                    manifest, archive = guest.build_payload(repo, capsule, "a" * 40, target, staged if packaged else None, observations)
                    self.assertEqual(observations, {"step": "complete", "plannedPackages": 1, "completedPackages": 1, "currentPackageID": None})
                if packaged:
                    stage.assert_called_once()
                    self.assertEqual(manifest["packagedCandidate"], receipt)
                else:
                    stage.assert_not_called()
                    self.assertNotIn("packagedCandidate", manifest)
                self.assertEqual(target["arch"], arch)
                self.assertEqual(compiled, [arch])
                self.assertEqual(manifest["goarch"], arch)
                self.assertEqual(manifest["goos"], goos)
                self.assertEqual(manifest["cli"]["file"], "accessweaver-" + goos + "-" + arch)
                self.assertEqual(manifest["cli"]["sha256"], guest.digest(capsule / "payload" / manifest["cli"]["file"]))
                self.assertEqual(manifest["sourceArchiveSHA256"], guest.digest(capsule / "payload/source.tar"))
                self.assertEqual(len(manifest["packages"]), 1)
                with guest.tarfile.open(archive) as payload:
                    self.assertIn("accessweaver-" + goos + "-" + arch, payload.getnames())
                    expected_cli = (b"archived-cli-for-" if packaged else b"cli-for-") + arch.encode()
                    self.assertEqual(payload.extractfile("accessweaver-" + goos + "-" + arch).read(), expected_cli)
                    self.assertNotIn("accessweaver-" + goos + "-" + ("amd64" if arch == "arm64" else "arm64"), payload.getnames())

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
                    self.assertIn("virtio-net-pci,netdev=n1,romfile=", command)
                    self.assertNotIn("virtio-net-pci,netdev=n1", command)
                    self.assertIn("virt,gic-version=3", command)
                    self.assertIn("if=pflash,format=raw,unit=0,file=" + str(firmware["code"]) + ",readonly=on", command)
                    self.assertIn("if=pflash,format=raw,unit=1,file=" + str(firmware["variables"]), command)
                    self.assertIn("scsi-cd,drive=seed,bus=scsi0.0,bootindex=2", command)
                else:
                    self.assertIn("virtio-net-pci,netdev=n1", command)
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
            def copy(source, destination, *, expected_sha256):
                self.assertEqual(source.parent, Path("/usr/share/AAVMF"))
                return original(templates / source.name, destination, owner=os.geteuid(), expected_sha256=expected_sha256)
            prepared = []
            with patch.object(guest, "copy_firmware", side_effect=copy), patch.object(guest, "ARM_FIRMWARE_PINS", {"code": guest.digest(code), "variables": guest.digest(variables)}):
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

    @unittest.skipUnless(os.name == "posix", "mutable firmware source directories require POSIX")
    def test_mutable_firmware_ancestor_requires_an_independent_matching_digest(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-firmware-") as name:
            root = Path(name).resolve()
            mutable = root / "mutable"
            mutable.mkdir(mode=0o700)
            mutable.chmod(0o777)
            source = mutable / "template"
            source.write_bytes(b"authenticated-public-firmware")
            source.chmod(0o600)
            expected = guest.digest(source)
            destination = root / "snapshot"
            with self.assertRaises(guest.FirmwareSnapshotError) as failure:
                guest.copy_firmware(source, destination, owner=os.geteuid())
            self.assertEqual(failure.exception.code, "ancestor-permissions")
            self.assertFalse(destination.exists())
            self.assertEqual(guest.copy_firmware(source, destination, owner=os.geteuid(), expected_sha256=expected), expected)
            self.assertEqual(destination.read_bytes(), b"authenticated-public-firmware")
            self.assertEqual(mutable.stat().st_mode & 0o777, 0o777)
            destination.unlink()
            source.write_bytes(b"tampered-public-firmware")
            with self.assertRaises(guest.FirmwareSnapshotError) as failure:
                guest.copy_firmware(source, destination, owner=os.geteuid(), expected_sha256=expected)
            self.assertEqual(failure.exception.code, "source-digest")
            destination.unlink()
            for invalid in ("", "PRIVATE", "0" * 63, "0" * 65, True):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    guest.copy_firmware(source, destination, owner=os.geteuid(), expected_sha256=invalid)
                self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "posix", "firmware special-file refusal requires POSIX")
    def test_firmware_fifo_is_refused_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-firmware-") as name:
            root = Path(name).resolve()
            source, destination = root / "fifo", root / "copy"
            os.mkfifo(source, 0o600)
            code = (
                "import importlib.util,os,sys;from pathlib import Path;"
                "sys.path.insert(0,str(Path(sys.argv[1]).parent));"
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


class PackagedBackupProbeTests(unittest.TestCase):
    def test_failed_or_leaking_backup_response_never_becomes_passing_evidence(self):
        for mode in ("command-failure", "private-output", "wrong-count"):
            with self.subTest(mode=mode):
                responses = iter([guest.subprocess.CompletedProcess([], 0, b""),
                                  guest.subprocess.CompletedProcess([], 1 if mode == "command-failure" else 0,
                                      b"private-fixture-password" if mode == "private-output" else
                                      json.dumps({"profiles": 2 if mode == "wrong-count" else 1, "encrypted": True, "externalFilesIncluded": False}).encode())])
                with patch.object(guest, "run", side_effect=lambda *args, **kwargs: next(responses)), patch.object(guest.secrets, "token_urlsafe", return_value="private-fixture-password"):
                    with self.assertRaises(RuntimeError):
                        guest.packaged_backup_checks(["ssh"], "/home/awtest/fixture", "/home/awtest/fixture/accessweaver")


    def test_wrong_passphrase_acceptance_or_changed_restore_never_passes(self):
        for mode in ("accepted-wrong-passphrase", "changed-restore", "invalid-encrypted-format"):
            with self.subTest(mode=mode):
                fixture = None
                wrong_password = False
                def command(args, *, data, **kwargs):
                    nonlocal fixture, wrong_password
                    script = data.decode()
                    output, status = b"", 0
                    if "mkdir -p" in script:
                        fixture_line = next(line for line in script.splitlines() if "bsd-archive-check.json" in line)
                        fixture = json.loads(guest.shlex.split(fixture_line)[2])
                    elif "wrong-fixture-passphrase" in script:
                        wrong_password = True
                    elif "backup create" in script:
                        output = json.dumps({"profiles": 1, "encrypted": True, "externalFilesIncluded": False}).encode()
                    elif "backup inspect" in script:
                        if wrong_password and mode != "accepted-wrong-passphrase":
                            status, output = 1, b"error: authentication failed"
                        else:
                            output = json.dumps({"authenticated": True, "profiles": 1, "externalFilesIncluded": False}).encode()
                    elif "backup restore" in script:
                        output = json.dumps({"complete": True, "startedEngines": False, "machinePolicyRestored": False}).encode()
                    elif "profiles.awbackup" in script:
                        encrypted = bytearray(80)
                        encrypted[:8] = b"BADMAGIC" if mode == "invalid-encrypted-format" else b"AWBACKUP"
                        encrypted[12:16] = (600000).to_bytes(4, "big")
                        output = bytes(encrypted)
                    elif "bsd-archive-check.json" in script:
                        result = dict(fixture)
                        if mode == "changed-restore":
                            result["name"] = "Changed restored profile"
                        output = json.dumps(result).encode()
                    else:
                        self.fail("unexpected backup probe command")
                    return guest.subprocess.CompletedProcess(args, status, output)
                with patch.object(guest, "run", side_effect=command):
                    with self.assertRaises(RuntimeError):
                        guest.packaged_backup_checks(["ssh"], "/home/awtest/fixture", "/home/awtest/fixture/accessweaver")


@unittest.skipUnless(os.name == "posix", "private descriptor-based guest staging requires POSIX")
class PackagedGuestHandoffTests(unittest.TestCase):
    goos = "freebsd"

    def copy_cli(self, *args):
        return packaged_candidate.copy_packaged_cli(*args, goos=self.goos)

    def fixture(self, root, arch="amd64"):
        stage = root / "stage"
        stage.mkdir(mode=0o700)
        binary = b"exact-authenticated-archived-binary"
        (stage / "accessweaver").write_bytes(binary)
        (stage / "accessweaver").chmod(0o700)
        receipt = {"schemaVersion": 1, "sourceCommit": "a" * 40, "sourceRef": "refs/heads/main",
                   "repository": packaged_candidate.REPOSITORY, "workflow": packaged_candidate.WORKFLOW,
                   "target": self.goos + "/" + arch, "archive": "accessweaver-preview-" + self.goos + "-" + arch + ".tar.gz",
                   "archiveSha256": "1" * 64, "manifestSha256": "2" * 64, "bundleSha256": "3" * 64,
                   "binary": "accessweaver", "binarySha256": hashlib.sha256(binary).hexdigest(),
                   "build": {"version": "0.1.0-alpha", "commit": "a" * 40, "sourceState": "clean",
                             "builtAt": "2026-11-01T00:00:00Z", "goVersion": "go1.27.3", "platform": self.goos, "arch": arch},
                   "provenanceSubjectsVerified": 12, "authenticatedBeforeStaging": True,
                   "publisherSignatureVerified": False, "productionQualificationComplete": False,
                   "executionEnvironment": "disposable-" + self.goos + "-guest"}
        (stage / "candidate.json").write_text(json.dumps(receipt), encoding="utf-8")
        (stage / "candidate.json").chmod(0o600)
        return stage, receipt, binary

    def test_archived_candidate_copy_retains_exact_bytes_and_receipt(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                stage, expected, binary = self.fixture(root, arch)
                destination = root / "payload-cli"
                receipt = self.copy_cli(stage, destination, "a" * 40, arch, "refs/heads/main")
                self.assertEqual(receipt, expected)
                self.assertEqual(destination.read_bytes(), binary)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

    def test_receipt_and_file_substitutions_fail_before_payload_creation(self):
        cases = ("source", "ref", "target", "os", "environment", "platform", "build", "unauthenticated", "subjects", "schema-bool", "unknown", "duplicate",
                 "archive-path", "binary-path", "binary-tamper", "binary-symlink", "receipt-symlink", "hardlink",
                 "file-mode", "directory-mode", "directory-symlink", "oversize-receipt", "oversize-binary", "existing-output")
        for mode in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                stage, receipt, binary = self.fixture(root)
                destination = root / "payload-cli"
                if mode in ("source", "ref", "target", "unauthenticated", "subjects", "schema-bool", "unknown", "archive-path", "binary-path"):
                    key, value = {"source": ("sourceCommit", "b" * 40), "ref": ("sourceRef", "refs/tags/v1"),
                                  "target": ("target", "freebsd/arm64"), "unauthenticated": ("authenticatedBeforeStaging", False),
                                  "subjects": ("provenanceSubjectsVerified", True), "schema-bool": ("schemaVersion", True),
                                  "unknown": ("unreviewed", "private"), "archive-path": ("archive", "../other.tar.gz"),
                                  "binary-path": ("binary", "../other")}[mode]
                    receipt[key] = value
                if mode == "os":
                    receipt["target"] = ("openbsd" if self.goos == "freebsd" else "freebsd") + "/amd64"
                if mode == "environment":
                    receipt["executionEnvironment"] = "disposable-other-guest"
                if mode == "platform":
                    receipt["build"]["platform"] = "openbsd" if self.goos == "freebsd" else "freebsd"
                if mode == "build":
                    receipt["build"]["arch"] = "arm64"
                (stage / "candidate.json").write_text(json.dumps(receipt), encoding="utf-8")
                if mode == "duplicate":
                    (stage / "candidate.json").write_text(json.dumps(receipt)[:-1] + ',"sourceCommit":"' + "a" * 40 + '"}', encoding="utf-8")
                if mode == "binary-tamper":
                    (stage / "accessweaver").write_bytes(b"changed binary")
                if mode in ("binary-symlink", "receipt-symlink"):
                    path = stage / ("accessweaver" if mode == "binary-symlink" else "candidate.json")
                    saved = root / "outside"
                    path.rename(saved)
                    path.symlink_to(saved)
                if mode == "hardlink":
                    os.link(stage / "accessweaver", root / "alias")
                if mode == "file-mode":
                    (stage / "accessweaver").chmod(0o666)
                if mode == "directory-mode":
                    stage.chmod(0o755)
                if mode == "directory-symlink":
                    held = root / "elsewhere"
                    stage.rename(held)
                    stage.symlink_to(held, target_is_directory=True)
                if mode.startswith("oversize-"):
                    with (stage / ("candidate.json" if mode == "oversize-receipt" else "accessweaver")).open("wb") as stream:
                        stream.truncate((16 << 10) + 1 if mode == "oversize-receipt" else (64 << 20) + 1)
                if mode == "existing-output":
                    destination.write_bytes(b"preserve-existing")
                with self.assertRaises((ValueError, OSError)):
                    self.copy_cli(stage, destination, "a" * 40, "amd64", "refs/heads/main")
                if mode == "existing-output":
                    self.assertEqual(destination.read_bytes(), b"preserve-existing")
                else:
                    self.assertFalse(destination.exists())

    def test_handoff_holds_directory_identity_after_staging_name_is_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, receipt, binary = self.fixture(root)
            original = packaged_candidate.read_private
            def read(fd, name, maximum):
                data = original(fd, name, maximum)
                if name == "candidate.json":
                    stage.rename(root / "displaced")
                    stage.mkdir(mode=0o700)
                    (stage / "accessweaver").write_bytes(b"replaced path")
                return data
            destination = root / "payload-cli"
            with patch.object(packaged_candidate, "read_private", side_effect=read):
                actual = self.copy_cli(stage, destination, "a" * 40, "amd64", "refs/heads/main")
            self.assertEqual(actual, receipt)
            self.assertEqual(destination.read_bytes(), binary)

    def test_fifo_candidate_input_is_refused_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, _, _ = self.fixture(root)
            (stage / "accessweaver").unlink()
            os.mkfifo(stage / "accessweaver", 0o600)
            code = "import sys; from pathlib import Path; from bsd_packaged_candidate import copy_packaged_cli; copy_packaged_cli(Path(sys.argv[1]),Path(sys.argv[2]),'a'*40,'amd64','refs/heads/main',goos=sys.argv[3])"
            result = subprocess.run([sys.executable, "-c", code, str(stage), str(root / "payload-cli"), self.goos], cwd=Path(__file__).parent, capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"unsafe or unbounded staged candidate file", result.stderr)
            self.assertFalse((root / "payload-cli").exists())


class OpenBSDPackagedGuestHandoffTests(PackagedGuestHandoffTests):
    goos = "openbsd"


if __name__ == "__main__":
    unittest.main()
