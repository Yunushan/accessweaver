#!/usr/bin/env python3
"""Opt-in, isolated FreeBSD guest core execution on a disposable hosted Linux job.

The host cross-compiles; the guest executes. This is not hardware, routing,
managed BSD policy, installer or complete platform qualification.
"""
import argparse
from bsd_test_observations import source_catalog, observe_output
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import re
import selectors
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

from bsd_packaged_candidate import copy_packaged_cli

TARGETS = {
    "amd64": {
        "arch": "amd64", "machine": "amd64", "hostMachines": ("x86_64", "amd64"),
        "image": "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        "imageDirectory": "amd64",
        "imageSHA256": "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f",
        "qemu": "qemu-system-x86_64", "tcgCPU": "Nehalem-v1",
    },
    "arm64": {
        "arch": "arm64", "machine": "arm64", "hostMachines": ("aarch64", "arm64"),
        "image": "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        "imageDirectory": "aarch64",
        "imageSHA256": "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963",
        "qemu": "qemu-system-aarch64", "tcgCPU": "cortex-a72",
    },
}
# From the official Ubuntu qemu-efi-aarch64 2024.02-2ubuntu0.10 package.
ARM_FIRMWARE_PINS = {
    "code": "545e2eda871a00dba51c0df48a34829fe3b0de6ec10ea760c75f1fc1c6a29dc5",
    "variables": "b3b855c5a80310168051164986855692d1bdb06e67619856177965cd87c6774f",
}

MODULE = "github.com/Yunushan/accessweaver/"
PORT = 2222


def selected_target(name=None):
    name = os.environ.get("ACCESSWEAVER_BSD_ARCH", "amd64") if name is None else name
    if name not in TARGETS:
        raise RuntimeError("unsupported explicit BSD target")
    target = dict(TARGETS[name])
    target["imageURL"] = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/" + target["imageDirectory"] + "/Latest/" + target["image"]
    target["label"] = "freebsd-" + target["arch"]
    return target


class FirmwareSnapshotError(RuntimeError):
    codes = {"ancestor-owner", "ancestor-permissions", "source-type", "source-owner", "source-links",
             "source-permissions", "source-size", "source-digest", "copy-grew", "copy-changed", "capsule-permissions"}
    nodes = {"root", "usr", "share", "firmware", "capsule", "other"}
    numbers = {"uid", "mode", "links", "bytes", "bytesCopied"}
    flags = {"sizeChanged", "mtimeChanged", "ctimeChanged"}

    def __init__(self, code, metadata):
        if code not in self.codes or not isinstance(metadata, dict):
            raise ValueError("unexpected firmware observation")
        for name, value in metadata.items():
            if name == "node":
                valid = value in self.nodes if isinstance(value, str) else False
            elif name in self.numbers:
                valid = type(value) is int and 0 <= value < 1 << 64
            elif name in self.flags:
                valid = type(value) is bool
            else:
                valid = False
            if not valid:
                raise ValueError("unexpected firmware observation field")
        super().__init__(code)
        self.code, self.metadata = code, dict(metadata)


def firmware_failure_observations(error):
    if isinstance(error, FirmwareSnapshotError):
        return {"firmwareFailureCode": error.code, "firmwareFailureMetadata": error.metadata}
    return {}


def copy_firmware(source, destination, *, owner=0, expected_sha256=None):
    """Snapshot an administrator-owned firmware input; fixtures may name their UID."""
    if expected_sha256 is not None and (not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)):
        raise ValueError("firmware digest must be an independently pinned SHA-256")
    resolved = source.resolve(strict=True)
    # The fixed runtime caller uses /usr/share/AAVMF. Root/expected ownership
    # remains mandatory. Mutable ancestors require a separately pinned content
    # digest: trust the copied bytes, never the mutable pathname.
    for parent in resolved.parents:
        info = parent.stat()
        node = {"/": "root", "/usr": "usr", "/usr/share": "share", "/usr/share/AAVMF": "firmware"}.get(str(parent), "other")
        metadata = {"node": node, "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner):
            raise FirmwareSnapshotError("ancestor-owner", metadata)
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX and expected_sha256 is None:
            raise FirmwareSnapshotError("ancestor-permissions", metadata)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        metadata = {"uid": before.st_uid, "mode": stat.S_IMODE(before.st_mode), "links": before.st_nlink, "bytes": before.st_size}
        for valid, code in ((stat.S_ISREG(before.st_mode), "source-type"), (before.st_uid == owner, "source-owner"),
                            (before.st_nlink == 1, "source-links"), (not before.st_mode & 0o022, "source-permissions"),
                            (0 < before.st_size <= 64 << 20, "source-size")):
            if not valid:
                raise FirmwareSnapshotError(code, metadata)
        output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        total = 0
        value = hashlib.sha256()
        with os.fdopen(output_fd, "wb") as output:
            while block := stream.read(1 << 20):
                total += len(block)
                if total > before.st_size:
                    raise FirmwareSnapshotError("copy-grew", {"bytes": before.st_size, "bytesCopied": total})
                output.write(block)
                value.update(block)
        after = os.fstat(stream.fileno())
        if total != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise FirmwareSnapshotError("copy-changed", {"bytesCopied": total, "sizeChanged": before.st_size != after.st_size,
                                                         "mtimeChanged": before.st_mtime_ns != after.st_mtime_ns,
                                                         "ctimeChanged": before.st_ctime_ns != after.st_ctime_ns})
    actual = value.hexdigest()
    if expected_sha256 is not None and actual != expected_sha256:
        raise FirmwareSnapshotError("source-digest", {"bytes": total})
    return actual


def prepare_arm_firmware(capsule):
    owned_directory(capsule)
    if capsule.stat().st_mode & 0o077:
        raise FirmwareSnapshotError("capsule-permissions", {"node": "capsule", "mode": stat.S_IMODE(capsule.stat().st_mode)})
    code, variables = capsule / "efi-code.fd", capsule / "efi-vars.fd"
    # Source paths and expected root ownership are not environment-selectable.
    code_hash = copy_firmware(Path("/usr/share/AAVMF/AAVMF_CODE.fd"), code, expected_sha256=ARM_FIRMWARE_PINS["code"])
    variables_hash = copy_firmware(Path("/usr/share/AAVMF/AAVMF_VARS.fd"), variables, expected_sha256=ARM_FIRMWARE_PINS["variables"])
    code.chmod(0o400)
    return {"code": code, "variables": variables, "codeSHA256": code_hash, "initialVariablesSHA256": variables_hash}


def virtual_machine_command(target, overlay, seed, acceleration, firmware=None):
    if acceleration not in ("kvm", "tcg"):
        raise RuntimeError("unsupported accelerator")
    cpu = "host" if acceleration == "kvm" else target["tcgCPU"]
    command = [target["qemu"], "-accel", acceleration, "-cpu", cpu, "-m", "3072", "-smp", "2",
               "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot"]
    if target["arch"] == "arm64":
        if firmware is None:
            raise RuntimeError("ARM64 requires private firmware snapshots")
        command += ["-machine", "virt,gic-version=3",
                    "-drive", f"if=pflash,format=raw,unit=0,file={firmware['code']},readonly=on",
                    "-drive", f"if=pflash,format=raw,unit=1,file={firmware['variables']}",
                    "-drive", f"file={overlay},if=none,id=osdisk,format=qcow2",
                    "-device", "virtio-blk-pci,drive=osdisk,bootindex=1",
                    "-device", "virtio-scsi-pci,id=scsi0",
                    "-drive", f"file={seed},if=none,id=seed,media=cdrom,format=raw,readonly=on",
                    "-device", "scsi-cd,drive=seed,bus=scsi0.0,bootindex=2"]
    else:
        command += ["-drive", f"file={overlay},if=virtio,format=qcow2",
                    "-drive", f"file={seed},media=cdrom,format=raw,readonly=on"]
    # Boot only the pinned disk/seed, never a NIC option ROM. ARM distribution
    # packages need not ship the optional efi-virtio.rom PXE image.
    network_device = "virtio-net-pci,netdev=n1" + (",romfile=" if target["arch"] == "arm64" else "")
    command += ["-netdev", f"user,id=n1,restrict=on,hostfwd=tcp:127.0.0.1:{PORT}-:22",
                "-device", network_device,
                "-object", "rng-random,id=rng0,filename=/dev/urandom",
                "-device", "virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000"]
    return command



class CommandFailure(RuntimeError):
    def __init__(self, result):
        super().__init__(Path(result.args[0]).name + " returned " + str(result.returncode))
        self.result = result


def run(args, *, env=None, timeout=120, limit=8 << 20, data=None, check=True, split_stderr=False):
    """Use explicit argv and bound output/lifetime; guest targets run via SSH."""
    if data is not None and len(data) > 2048:
        raise ValueError("bounded helper input exceeded")
    proc = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE if split_stderr else subprocess.STDOUT, env=env,
                            start_new_session=True)
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        if data is not None:
            try:
                proc.stdin.write(data)
                proc.stdin.close()
            except BrokenPipeError:
                pass
        selector.register(proc.stdout, selectors.EVENT_READ, output)
        if split_stderr:
            selector.register(proc.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded helper deadline exceeded")
            events = selector.select(min(0.25, remaining))
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(errors) + len(chunk) > limit:
                    raise ValueError("bounded helper output exceeded")
                key.data.extend(chunk)
        code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        result = subprocess.CompletedProcess(args, code, bytes(output), bytes(errors) if split_stderr else None)
        if check and code:
            raise CommandFailure(result)
        return result
    finally:
        try:
            # Until wait() reaps this session leader, its PID cannot be reused.
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # A completed child may still be unreaped when output hits
                    # its bound. Accept cleanup only after reaping and proving
                    # that no process group remains. Never signal a possibly
                    # reused group with SIGKILL after releasing the child PID.
                    proc.wait(timeout=5)
                    try:
                        os.killpg(proc.pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        raise
                proc.wait(timeout=5)
        finally:
            selector.close()
            proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()
            if proc.stdin is not None and not proc.stdin.closed:
                try:
                    proc.stdin.close()
                except BrokenPipeError:
                    pass


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(1 << 20), b""):
            value.update(data)
    return value.hexdigest()


def owned_directory(path):
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise RuntimeError("unsafe owned directory")


def guard():
    if (platform.system() != "Linux" or os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.environ.get("RUNNER_OS") != "Linux" or
            os.environ.get("ACCESSWEAVER_DISPOSABLE_BSD_GUEST_TEST") != "1" or os.geteuid() == 0):
        raise RuntimeError("refusing guest execution outside an ordinary-user opted-in hosted Linux job")
    target = selected_target()
    if platform.machine().lower() not in target["hostMachines"]:
        raise RuntimeError("native host architecture differs from selected BSD target")
    repo = Path(__file__).resolve().parents[1]
    if Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve() != repo or any(c in str(repo) for c in ",\n\r"):
        raise RuntimeError("unexpected hosted workspace")
    source = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[a-f0-9]{40}", source):
        raise RuntimeError("exact source identity required")
    if run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.decode().strip() != source or run(["git", "-C", str(repo), "status", "--porcelain"]).stdout.strip():
        raise RuntimeError("clean exact-source checkout required")
    if shutil.disk_usage(repo).free < 10 << 30:
        raise RuntimeError("insufficient host storage reserve")
    sdk = json.loads(run(["go", "env", "-json", "GOOS", "GOARCH", "GOHOSTOS", "GOHOSTARCH", "GOVERSION", "GOTOOLCHAIN"]).stdout)
    expected = {"GOOS": "linux", "GOARCH": target["arch"], "GOHOSTOS": "linux", "GOHOSTARCH": target["arch"],
                "GOVERSION": "go" + os.environ.get("GO_VERSION", ""), "GOTOOLCHAIN": "local"}
    if sdk != expected or not re.fullmatch(r"go\d+\.\d+\.\d+", sdk["GOVERSION"]):
        raise RuntimeError("unexpected native host SDK")
    return repo, source, sdk, target


def decode_disk_observations(data):
    """Accept only the private helper's fixed, bounded public observation schema."""
    fields = json.loads(data)
    booleans = {
        "inspectionComplete",
        "hostnameConfigured",
        "nuageCachePresent",
        "testUserCreated",
        "clientKeyInstalled",
        "hostKeyInstalled",
        "passwordAuthenticationDisabled",
        "sshdPIDFilePresent",
        "sshdECDSAKeyPresent",
        "sshdEd25519PrivateKeyPresent",
        "virtioEntropyModulePresent",
        "controlAddressDHCPLeasePresent",
        "nuageLogPresent",
        "nuageParseErrorObserved",
        "nuageArgumentErrorObserved",
        "nuageTracebackObserved",
        "nuageOpenErrorObserved",
        "sshdMessageObserved",
        "cloudProviderMissingObserved",
        "runtimeObservationPresent",
        "sshdConfigCheckPassed",
        "sshdRuntimeServiceRunningObserved",
        "controlIPv4AddressObserved",
        "sshdRuntimeIPv4ListenerObserved",
        "sshdListeningLogObserved",
        "sshdNoHostKeysObserved",
        "sshdKeyPermissionErrorObserved",
        "sshdMissingSeparationUserObserved",
        "sshdMissingSeparationDirectoryObserved",
        "sshdBadConfigOptionObserved",
        "sshdSharedLibraryErrorObserved",
        "sshdKeyLoadErrorObserved",
        "sshdKeyFormatErrorObserved",
        "sshdAuthenticationRejectedObserved",
        "sshdKexNegotiationErrorObserved",
        "sshdSessionExecErrorObserved",
        "sshdFatalLogObserved",
    }
    numeric = {"sshdConfigCheckExitCode", "sshdConfigCheckLogBytes"}
    if (not isinstance(fields, dict) or set(fields) != booleans | numeric or
            any(type(fields[name]) is not bool for name in booleans)):
        raise ValueError("unexpected disk observation fields")
    code, size = fields["sshdConfigCheckExitCode"], fields["sshdConfigCheckLogBytes"]
    # Missing numeric observations are explicit for absent/legacy runtime state.
    if code is None and size is None:
        return fields
    if (type(code) is not int or not 0 <= code <= 255 or
            type(size) is not int or not 0 <= size <= 1 << 20 or
            not fields["runtimeObservationPresent"] or
            fields["sshdConfigCheckPassed"] != (code == 0)):
        raise ValueError("unexpected bounded disk command observations")
    return fields


def decode_objects(data):
    text = data.decode("utf-8")
    decoder = json.JSONDecoder()
    result = []
    while text.strip():
        item, end = decoder.raw_decode(text.lstrip())
        result.append(item)
        text = text.lstrip()[end:]
    return result


def relative_package(path, repo):
    relative = Path(path).resolve().relative_to(repo)
    text = relative.as_posix()
    if text == "." or not re.fullmatch(r"[a-zA-Z0-9_/-]+", text):
        raise ValueError("unsupported package path")
    return text


def cloud_config(client_public, host_private, host_public):
    # FreeBSD 15.1 nuageinit's supported cloud-config interface, not a Linux
    # cloud-init package. Explicit users avoid its default password-bearing user.
    return {"hostname": "awbsd", "users": [{"name": "awtest", "homedir": "/home/awtest", "shell": "/bin/sh",
             "passwd": "*", "ssh_authorized_keys": [client_public]}], "ssh_pwauth": False,
            "ssh_keys": {"ed25519_private": host_private, "ed25519_public": host_public},
            "runcmd": ["ACCESSWEAVER_DISPOSABLE_BSD_BOOT_OBSERVER=1 /bin/sh /root/accessweaver-boot-observer.sh </dev/null >/dev/null 2>&1 &"],
            "write_files": [{"path": "/etc/rc.conf.d/firstboot_pkg_upgrade", "permissions": "0600", "owner": "root:wheel",
                             "content": 'firstboot_pkg_upgrade_enable="NO"\n'},
                            {"path": "/etc/rc.conf.d/sshd", "permissions": "0600", "owner": "root:wheel",
                             "content": 'sshd_flags="-E /var/log/accessweaver-sshd.log"\n'},
                            {"path": "/var/log/accessweaver-sshd.log", "permissions": "0600", "owner": "root:wheel",
                             "content": ""},
                            {"path": "/root/accessweaver-boot-observer.sh", "permissions": "0700", "owner": "root:wheel",
                             "content": Path(__file__).with_name("bsd-boot-observer.sh").read_text(encoding="utf-8")} ]}


def expand_image(source, target, maximum=8 << 30):
    total = 0
    with lzma.open(source, "rb") as compressed, target.open("xb") as output:
        while data := compressed.read(1 << 20):
            total += len(data)
            if total > maximum:
                raise ValueError("decompressed image exceeds bound")
            output.write(data)
    return total


def ssh_failure_class(output):
    # Keep arbitrary server/client text and seed material out of boot reports.
    for needle, kind in [(b"REMOTE HOST IDENTIFICATION HAS CHANGED", "host-key-rejected"),
                         (b"Host key verification failed", "host-key-rejected"),
                         (b"Permission denied", "authentication-refused"),
                         (b"Connection refused", "not-listening"),
                         (b"Connection timed out", "connect-timeout"),
                         (b"Connection reset", "connection-reset"),
                         (b"No route to host", "unreachable")]:
        if needle in output:
            return kind
    return "unclassified"


def validate_guest_identity(actual, target=None):
    target = selected_target("amd64") if target is None else target
    if (len(actual) != 5 or actual[0] != "FreeBSD" or not actual[1].startswith("15.1-RELEASE") or
            actual[2] != target["machine"] or not actual[3].isdecimal() or int(actual[3]) == 0 or actual[4] != "awtest"):
        raise RuntimeError("unexpected actual guest identity")
    return {"OS": actual[0], "release": actual[1], "machine": actual[2], "uid": int(actual[3]), "user": actual[4]}


def remove_owned_capsule(capsule, root, identity, emulator_stopped):
    if not emulator_stopped:
        raise RuntimeError("refusing cleanup while emulator remains live")
    owned_directory(capsule)
    current = capsule.stat()
    if capsule.parent != root or current.st_dev != identity.st_dev or current.st_ino != identity.st_ino:
        raise RuntimeError("owned capsule identity changed")
    shutil.rmtree(capsule)


def build_failure_observations(error):
    # Only source-defined codes and bounded integers leave the build runner.
    kind = {CommandFailure: "command-failed", TimeoutError: "helper-timeout",
            ValueError: "invalid-build-input", json.JSONDecodeError: "invalid-discovery-json", RuntimeError: "build-assertion"}.get(type(error), "build-exception")
    cause = {"bounded helper output exceeded": "helper-output-limit",
             "unsupported package path": "unsupported-package-path",
             "unexpected test module": "unexpected-test-module",
             "unexpected unit package set": "unexpected-package-count",
             "source archive exceeds bounds or contains submodules": "source-archive-limit",
             "source changed while building": "source-changed",
             "payload exceeds bound": "payload-limit"}.get(str(error), "unspecified")
    code = error.result.returncode if isinstance(error, CommandFailure) else None
    if type(code) is not int or not -255 <= code <= 255:
        code = None
    return {"failureKind": kind, "failureCause": cause, "failureExitCode": code}


def build_payload(repo, capsule, source, target, packaged=None, observations=None):
    goos = target.get("goos", "freebsd")
    if (goos not in ("freebsd", "openbsd") or target["arch"] not in ("amd64", "arm64") or
            target["label"] != goos + "-" + target["arch"]):
        raise ValueError("unsupported explicit BSD payload target")
    payload = capsule / "payload"
    payload.mkdir(mode=0o700)
    tests = payload / "tests"
    tests.mkdir(mode=0o700)
    env = dict(os.environ, GOOS=goos, GOARCH=target["arch"], CGO_ENABLED="0", GOTOOLCHAIN="local")
    observations = {} if observations is None else observations
    observations.update(step="package-discovery", plannedPackages=0, completedPackages=0, currentPackageID=None)
    packages = decode_objects(run(["go", "list", "-json", "./..."], env=env, split_stderr=True).stdout)
    observations["plannedPackages"] = sum(bool(p.get("TestGoFiles") or p.get("XTestGoFiles")) for p in packages)
    records, catalogs = [], {}
    for package in packages:
        if not package.get("TestGoFiles") and not package.get("XTestGoFiles"):
            continue
        name = package["ImportPath"]
        if not name.startswith(MODULE):
            raise RuntimeError("unexpected test module")
        directory = relative_package(package["Dir"], repo)
        catalogs[name] = source_catalog(repo, directory, package.get("TestGoFiles", []) + package.get("XTestGoFiles", []))
        filename = "tests/" + hashlib.sha256(name.encode()).hexdigest()[:20] + ".test"
        executable = payload / filename
        observations.update(step="package-compile", currentPackageID=len(records))
        run(["go", "test", "-mod=readonly", "-c", "-o", str(executable), name], env=env, timeout=300)
        if not executable.is_file() or executable.stat().st_size > 128 << 20:
            raise RuntimeError("unbounded test binary")
        records.append({"package": name, "directory": directory, "file": filename, "sha256": digest(executable)})
        observations["completedPackages"] = len(records)
    if not records or len(records) > 64:
        raise RuntimeError("unexpected unit package set")
    cli = "accessweaver-" + target["label"]
    receipt = None
    observations.update(step="source-cli-build" if packaged is None else "packaged-cli-copy", currentPackageID=None)
    if packaged is None:
        run(["bash", "scripts/build-all.sh", goos + "/" + target["arch"]],
            env=dict(os.environ, OUTPUT_DIR=str(payload), GOTOOLCHAIN="local"), timeout=300)
    else:
        # The prior credential-scoped step authenticates all twelve subjects.
        # Copy the exact staged archive bytes; never substitute a rebuilt CLI.
        receipt = copy_packaged_cli(packaged, payload / cli, source, target["arch"], os.environ.get("GITHUB_REF", ""), goos=goos)
        (payload / "BUILD-INFO.json").write_text(json.dumps(receipt["build"]) + "\n", encoding="utf-8")
    observations["step"] = "source-archive"
    tree = run(["git", "ls-tree", "-r", "-l", "HEAD"]).stdout.decode("utf-8").splitlines()
    sizes = [line.split("\t", 1)[0].split()[-1] for line in tree]
    if len(tree) > 4096 or any(not value.isdecimal() for value in sizes) or sum(map(int, sizes)) > 64 << 20:
        raise RuntimeError("source archive exceeds bounds or contains submodules")
    run(["git", "archive", "--format=tar", "--output=" + str(payload / "source.tar"), "HEAD"])
    if run(["git", "status", "--porcelain"]).stdout.strip():
        raise RuntimeError("source changed while building")
    manifest = {"sourceCommit": source, "goos": goos, "goarch": target["arch"], "hostCrossCompiled": True, "testCatalogs": catalogs,
                "cli": {"file": cli, "sha256": digest(payload / cli)}, "packages": records,
                "sourceArchiveSHA256": digest(payload / "source.tar")}
    if receipt is not None:
        if manifest["cli"]["sha256"] != receipt["binarySha256"]:
            raise RuntimeError("archived executable changed before payload packaging")
        manifest["packagedCandidate"] = receipt
    (payload / "PROBE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    files = [payload / cli, payload / "BUILD-INFO.json", payload / "PROBE-MANIFEST.json", payload / "source.tar"]
    files += [payload / record["file"] for record in records]
    if sum(path.stat().st_size for path in files) > 1 << 30:
        raise RuntimeError("payload exceeds bound")
    observations["step"] = "transport-archive"
    archive = capsule / "payload.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=1) as tar:
        for path in files:
            tar.add(path, arcname=path.relative_to(payload).as_posix(), recursive=False)
    observations["step"] = "complete"
    return manifest, archive


def packaged_backup_checks(ssh, guest, executable):
    """Exercise the archived CLI offline; export only fixed boolean results."""
    root = guest + "/packaged-backup"
    source, password_file = root + "/source", root + "/passphrase"
    archive, restored = root + "/profiles.awbackup", root + "/restored"
    fixture = {"version": 1, "id": "bsd-archive-check", "name": "Private BSD archive fixture", "engine": "byedpi",
               "args": ["private fixture argument"], "routing": {"includeDomains": [], "excludeDomains": [], "applications": []},
               "probe": {"host": "example.invalid", "port": 443, "tls": True, "timeoutSeconds": 5}, "updatedAt": "2026-11-01T00:00:00Z"}
    password = secrets.token_urlsafe(32)
    setup = ("set -eu\numask 077\nmkdir -p " + shlex.quote(source + "/profiles") +
             "\nprintf '%s\\n' " + shlex.quote(json.dumps(fixture)) + " > " + shlex.quote(source + "/profiles/" + fixture["id"] + ".json") +
             "\nprintf '%s\\n' " + shlex.quote(password) + " > " + shlex.quote(password_file) + "\n")
    run(ssh, data=setup.encode(), limit=16384)

    def invoke(arguments, success=True):
        command = ["env", "-i", "HOME=/home/awtest", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", "LANG=C", "LC_ALL=C", "TZ=UTC",
                   "ACCESSWEAVER_HOME=" + source, executable, "backup", *arguments]
        result = run(ssh, data=("set -eu\n" + shlex.join(command) + "\n").encode(), timeout=150, limit=16384, check=False)
        if any(value.encode() in result.stdout for value in (password, fixture["name"], fixture["args"][0])):
            raise RuntimeError("packaged backup response exposed private fixture data")
        if success:
            if result.returncode != 0:
                raise RuntimeError("packaged backup operation failed")
            return json.loads(result.stdout)
        if result.returncode == 0 or b"authentication failed" not in result.stdout:
            raise RuntimeError("packaged backup accepted the wrong passphrase or failed unexpectedly")
        return None

    created = invoke(["create", "--out", archive, "--passphrase-file", password_file])
    if created.get("profiles") != 1 or created.get("encrypted") is not True or created.get("externalFilesIncluded") is not False:
        raise RuntimeError("unexpected packaged backup creation result")
    encrypted = run(ssh, data=("set -eu\ncat " + shlex.quote(archive) + "\n").encode(), limit=64 << 10).stdout
    if (len(encrypted) <= 60 or encrypted[:8] != b"AWBACKUP" or int.from_bytes(encrypted[12:16], "big") != 600000 or
            any(value.encode() in encrypted for value in (password, fixture["name"], fixture["args"][0]))):
        raise RuntimeError("unexpected packaged encrypted backup format")
    inspected = invoke(["inspect", "--archive", archive, "--passphrase-file", password_file])
    if inspected.get("authenticated") is not True or inspected.get("profiles") != 1 or inspected.get("externalFilesIncluded") is not False:
        raise RuntimeError("packaged backup inspection did not authenticate the archive")
    recovered = invoke(["restore", "--archive", archive, "--passphrase-file", password_file, "--into", restored])
    if recovered.get("complete") is not True or recovered.get("startedEngines") is not False or recovered.get("machinePolicyRestored") is not False:
        raise RuntimeError("packaged backup restore did not complete safely")
    data = run(ssh, data=("set -eu\ntest ! -e " + shlex.quote(restored + "/.restore-incomplete") +
                         "\ncat " + shlex.quote(restored + "/profiles/" + fixture["id"] + ".json") + "\n").encode(), limit=16384).stdout
    if json.loads(data) != fixture:
        raise RuntimeError("packaged backup restore changed the saved profile")
    run(ssh, data=("set -eu\numask 077\nprintf '%s\\n' wrong-fixture-passphrase > " + shlex.quote(password_file) + "\n").encode(), limit=16384)
    invoke(["inspect", "--archive", archive, "--passphrase-file", password_file], success=False)
    return {"encryptedBackupCreated": True, "archiveAuthenticated": True, "restoredProfileMatched": True,
            "wrongPassphraseRejected": True, "backupNoPlaintext": True, "offlineOnly": True,
            "settingsChanged": False, "productionQualificationComplete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packaged-candidate", type=Path, help="Prior authenticated private staging directory; require exact archived CLI execution")
    args = parser.parse_args()
    repo, source, sdk, target = guard()
    os.chdir(repo)
    os.umask(0o077)
    root = repo / "build" / "bsd-capsules"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(root)
    capsule = Path(tempfile.mkdtemp(prefix=target["label"] + "-", dir=root))
    owned_directory(capsule)
    identity = capsule.stat()
    output = repo / "build" / "bsd-native-checks"
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(output)
    report = {"schemaVersion": 1, "sourceCommit": source, "target": "freebsd/" + target["arch"], "hostSDK": sdk,
              "imageURL": target["imageURL"], "imageSHA256": target["imageSHA256"], "packages": [], "publicTestObservations": [], "guestExecutionPassed": False,
              "packagedCandidateExecuted": False,
              "hardwareQualificationComplete": False, "platformQualificationComplete": False,
              "readinessGatesPromoted": 0, "productionQualificationComplete": False}
    vm = None
    serial_tail = bytearray()
    serial_thread = None
    phase = "build"
    failed = True
    try:
        report["buildObservations"] = {}
        manifest, archive = build_payload(repo, capsule, source, target, args.packaged_candidate, report["buildObservations"])
        if args.packaged_candidate is not None:
            report["packagedCandidate"] = manifest["packagedCandidate"]
        report["crossCompiledPackages"] = len(manifest["packages"])
        phase = "image-download"
        compressed = capsule / target["image"]
        value = hashlib.sha256()
        size = 0
        download_deadline = time.monotonic() + 600
        with urllib.request.urlopen(target["imageURL"], timeout=60) as response, compressed.open("xb") as destination:
            if response.geturl().split(":", 1)[0] != "https":
                raise RuntimeError("image download changed transport")
            while data := response.read(1 << 20):
                size += len(data)
                if time.monotonic() > download_deadline:
                    raise TimeoutError("image download deadline exceeded")
                if size > 1 << 30:
                    raise ValueError("compressed image exceeds bound")
                value.update(data)
                destination.write(data)
        if value.hexdigest() != target["imageSHA256"]:
            raise RuntimeError("official image digest mismatch")
        report["imageDigestVerified"] = True
        phase = "image-prepare"
        base = capsule / "base.qcow2"
        report["decompressedImageBytes"] = expand_image(compressed, base)
        info = json.loads(run(["qemu-img", "info", "--output=json", str(base)]).stdout)
        if info.get("format") != "qcow2" or info.get("backing-filename") or not 0 < info["virtual-size"] <= 16 << 30:
            raise RuntimeError("unexpected base image layout")
        report["virtualDiskBytes"] = info["virtual-size"]
        base.chmod(0o400)
        overlay = capsule / "overlay.qcow2"
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay)])
        for name in ("client", "host"):
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "accessweaver-disposable-guest", "-f", str(capsule / name)])
        client_public = (capsule / "client.pub").read_text(encoding="utf-8").strip()
        host_public = (capsule / "host.pub").read_text(encoding="utf-8").strip()
        config = cloud_config(client_public, (capsule / "host").read_text(encoding="utf-8"), host_public)
        (capsule / "user-data").write_text("#cloud-config\n" + json.dumps(config) + "\n", encoding="utf-8")
        (capsule / "meta-data").write_text(json.dumps({"instance-id": "awbsd-" + source, "local-hostname": "awbsd"}) + "\n", encoding="utf-8")
        (capsule / "known_hosts").write_text(f"[127.0.0.1]:{PORT} {host_public}\n", encoding="utf-8")
        seed = capsule / "seed.iso"
        run(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(seed), "-volid", "cidata", "-joliet", "-rock",
             str(capsule / "user-data"), str(capsule / "meta-data")])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", PORT))
        acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        report["hypervisorAcceleration"] = acceleration
        report["CPUEmulated"] = acceleration == "tcg"
        report["cpuModel"] = "host" if acceleration == "kvm" else target["tcgCPU"]
        report["entropyDevice"] = "virtio-rng-pci"
        report["entropyBackend"] = "host-kernel-urandom"
        report["entropyMaximumBytesPerPeriod"] = 1024
        report["entropyPeriodMilliseconds"] = 1000
        report["qemuVersion"] = run([target["qemu"], "--version"]).stdout.decode().splitlines()[0]
        firmware = None
        if target["arch"] == "arm64":
            phase = "firmware-prepare"
            firmware = prepare_arm_firmware(capsule)
            report["bootFirmwareCodeSHA256"] = firmware["codeSHA256"]
            report["bootFirmwareInitialVariablesSHA256"] = firmware["initialVariablesSHA256"]
        vm = subprocess.Popen(virtual_machine_command(target, overlay, seed, acceleration, firmware), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        def drain_serial():
            while chunk := vm.stdout.read(4096):
                serial_tail.extend(chunk)
                if len(serial_tail) > 1 << 20:
                    del serial_tail[:len(serial_tail) - (1 << 20)]
        serial_thread = threading.Thread(target=drain_serial, daemon=True)
        serial_thread.start()
        options = ["-F", "/dev/null", "-i", str(capsule / "client"), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(capsule / "known_hosts"),
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
                   "-o", "ForwardAgent=no", "-o", "ControlMaster=no", "-o", "ConnectTimeout=5",
                   "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"]
        ssh = ["ssh", *options, "-p", str(PORT), "awtest@127.0.0.1", "/bin/sh -s"]
        phase = "guest-boot"
        deadline = time.monotonic() + 480
        while True:
            if vm.poll() is not None:
                raise RuntimeError("owned emulator exited during boot")
            try:
                result = run(ssh, data=b"true\n", timeout=8, check=False)
                report["lastSSHStatus"] = result.returncode
                if result.returncode == 0:
                    break
                report["lastSSHFailureClass"] = ssh_failure_class(result.stdout)
                counts = report.setdefault("sshFailureCounts", {})
                kind = report["lastSSHFailureClass"]
                counts[kind] = counts.get(kind, 0) + 1
                if report["lastSSHFailureClass"] == "host-key-rejected":
                    raise RuntimeError("Pinned guest host key was rejected")
            except (TimeoutError, subprocess.TimeoutExpired):
                report["bootProbeTimeouts"] = report.get("bootProbeTimeouts", 0) + 1
            if time.monotonic() >= deadline:
                raise TimeoutError("pinned guest boot deadline exceeded")
            time.sleep(2)
        phase = "guest-identity"
        actual = run(ssh, data=b"set -eu\nuname -s\nuname -r\nuname -m\nid -u\nid -un\n").stdout.decode().splitlines()
        report["guestIdentity"] = validate_guest_identity(actual, target)
        report["sshHostKeyPinned"] = True
        phase = "payload-transfer"
        guest = "/home/awtest/awprobe-" + capsule.name.split("-")[-1]
        run(ssh, data=f"set -eu\numask 077\nmkdir {shlex.quote(guest)}\n".encode())
        run(["scp", *options, "-P", str(PORT), str(archive), f"awtest@127.0.0.1:{guest}/payload.tar.gz"], timeout=180)
        actual_hash = run(ssh, data=f"sha256 -q {shlex.quote(guest + '/payload.tar.gz')}\n".encode()).stdout.decode().strip()
        if actual_hash != digest(archive):
            raise RuntimeError("transported payload hash mismatch")
        run(ssh, data=f"set -eu\ncd {shlex.quote(guest)}\ntar -xzf payload.tar.gz\nmkdir source\ntar -xf source.tar -C source\n".encode())
        for item in [manifest["cli"], *manifest["packages"]]:
            remote = guest + "/" + item["file"]
            actual_hash = run(ssh, data=f"sha256 -q {shlex.quote(remote)}\n".encode()).stdout.decode().strip()
            if actual_hash != item["sha256"]:
                raise RuntimeError("transported executable hash mismatch")
        report["allTransportedExecutableHashesVerified"] = True
        phase = "guest-cli"
        cli = json.loads(run(ssh, data=f"{shlex.quote(guest + '/' + manifest['cli']['file'])} version --json\n".encode()).stdout)
        if cli.get("commit") != source or cli.get("sourceState") != "clean" or cli.get("platform") != "freebsd" or cli.get("arch") != target["arch"] or cli.get("goVersion") != sdk["GOVERSION"]:
            raise RuntimeError("executed CLI differs from candidate")
        if args.packaged_candidate is not None:
            if cli != manifest["packagedCandidate"]["build"] or manifest["cli"]["sha256"] != manifest["packagedCandidate"]["binarySha256"]:
                raise RuntimeError("executed CLI differs from authenticated archived candidate")
            report["packagedCandidateExecuted"] = True
        report["executedCLI"] = cli
        report["cliSHA256"] = manifest["cli"]["sha256"]
        if args.packaged_candidate is not None:
            phase = "packaged-backup-roundtrip"
            report["packagedBackupChecks"] = packaged_backup_checks(ssh, guest, guest + "/" + manifest["cli"]["file"])
        phase = "guest-unit-tests"
        for index, package in enumerate(manifest["packages"]):
            script = f"set -eu\ncd {shlex.quote(guest + '/source/' + package['directory'])}\nexec env -i HOME=/home/awtest PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin LANG=C LC_ALL=C TZ=UTC {shlex.quote(guest + '/' + package['file'])} -test.timeout=150s -test.count=1 -test.v\n"
            started = time.monotonic()
            result = run(ssh, data=script.encode(), timeout=180, check=False)
            text = result.stdout.decode("utf-8", "replace")
            log = output / f"{target['label']}-unit-{index:02d}.log"
            log.write_bytes(result.stdout)
            record = {**package, "returnCode": result.returncode, "elapsedSeconds": round(time.monotonic() - started, 3),
                      "passedTestInstances": len(re.findall(r"--- PASS:", text)), "skippedTestInstances": len(re.findall(r"--- SKIP:", text)),
                      "logSHA256": digest(log)}
            diagnostic = observe_output(result.stdout, manifest["testCatalogs"][package["package"]], result.returncode)
            report["publicTestObservations"].append({"packageID": index, **diagnostic})
            report["packages"].append(record)
            print(json.dumps({"package": package["package"], "returnCode": result.returncode}), flush=True)
        if any(record["returnCode"] != 0 for record in report["packages"]):
            raise RuntimeError("one or more actual guest unit packages failed")
        report["guestExecutionPassed"] = True
        failed = False
    except Exception as error:
        report.update(firmware_failure_observations(error))
        if phase == "build":
            report.setdefault("buildObservations", {}).update(build_failure_observations(error))
        report["failurePhase"] = phase
        report["failureType"] = type(error).__name__
        print("Guest qualification incomplete: " + phase + "/" + type(error).__name__, flush=True)
    finally:
        emulator_stopped = vm is None
        if vm is not None:
            try:
                if vm.poll() is None:
                    vm.terminate()
                    try:
                        vm.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        vm.kill()
                        vm.wait(timeout=2)
                emulator_stopped = vm.returncode is not None
            except (OSError, subprocess.TimeoutExpired):
                report["cleanupFailed"] = True
                failed = True
        report["ownedEmulatorStopped"] = emulator_stopped
        if serial_thread is not None:
            serial_thread.join(timeout=2)
            if serial_thread.is_alive():
                report["cleanupFailed"] = True
                failed = True
            else:
                vm.stdout.close()
                report["serialTailSHA256"] = hashlib.sha256(serial_tail).hexdigest()
                report["serialTailBytes"] = len(serial_tail)
                report["sshdBootMessageObserved"] = b"Starting sshd" in serial_tail
                report["virtioEntropyAdapterObserved"] = b"VirtIO Entropy Adapter" in serial_tail
                report["nuageinitMessageObserved"] = b"nuageinit" in serial_tail
                report["firstbootPackageMessageObserved"] = b"firstboot_pkg_upgrade" in serial_tail
                report["consoleLoginObserved"] = b"login:" in serial_tail
                report["expectedHostnameConsoleObserved"] = b"awbsd login:" in serial_tail.lower()
                report["defaultHostnameConsoleObserved"] = b"amnesiac" in serial_tail.lower() or b"freebsd login:" in serial_tail.lower()
        if emulator_stopped and vm is not None and phase == "guest-boot":
            # Read only the stopped overlay, in a separate bounded helper. The
            # helper returns a fixed boolean/bounded-numeric schema, never private contents.
            try:
                observed = run([sys.executable, str(repo / "scripts" / "bsd_boot_diagnostics.py"), str(capsule)],
                               env=dict(os.environ, PYTHONPATH=str(repo / "build" / "bsd-inspection-tools")),
                               timeout=60, limit=16384)
                report["bootDiskInspection"] = decode_disk_observations(observed.stdout)
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
                report["bootDiskInspectionFailed"] = True
        # Never publish the seed ISO, per-run credentials, disk image or serial
        # console. The guest has no host filesystem mount or signing secrets.
        try:
            remove_owned_capsule(capsule, root, identity, emulator_stopped)
            report["ownedCapsuleRemoved"] = not capsule.exists()
        except (OSError, RuntimeError):
            report["cleanupFailed"] = True
            failed = True
        (output / (target["label"] + ".json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


def interrupted(*_):
    raise KeyboardInterrupt()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
