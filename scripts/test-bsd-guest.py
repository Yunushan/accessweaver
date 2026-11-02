#!/usr/bin/env python3
"""Opt-in, isolated FreeBSD guest core execution on a disposable hosted Linux job.

The host cross-compiles; the guest executes. This is not hardware, routing,
managed BSD policy, installer or complete platform qualification.
"""
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import re
import selectors
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

IMAGE = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
IMAGE_URL = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/amd64/Latest/" + IMAGE
IMAGE_SHA256 = "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f"
MODULE = "github.com/Yunushan/accessweaver/"
PORT = 2222


class CommandFailure(RuntimeError):
    def __init__(self, result):
        super().__init__(Path(result.args[0]).name + " returned " + str(result.returncode))
        self.result = result


def run(args, *, env=None, timeout=120, limit=8 << 20, data=None, check=True):
    """Use explicit argv and bound output/lifetime; guest targets run via SSH."""
    if data is not None and len(data) > 2048:
        raise ValueError("bounded helper input exceeded")
    proc = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                            start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        if data is not None:
            try:
                proc.stdin.write(data)
                proc.stdin.close()
            except BrokenPipeError:
                pass
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded helper deadline exceeded")
            events = selector.select(min(0.25, remaining))
            if not events:
                continue
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            if len(output) + len(chunk) > limit:
                raise ValueError("bounded helper output exceeded")
            output.extend(chunk)
        code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        result = subprocess.CompletedProcess(args, code, bytes(output), None)
        if check and code:
            raise CommandFailure(result)
        return result
    finally:
        # Until wait() reaps this session leader, its PID cannot be reused.
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
        selector.close()
        proc.stdout.close()


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
    if platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError("first guest probe requires an x86_64 host")
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
    expected = {"GOOS": "linux", "GOARCH": "amd64", "GOHOSTOS": "linux", "GOHOSTARCH": "amd64",
                "GOVERSION": "go" + os.environ.get("GO_VERSION", ""), "GOTOOLCHAIN": "local"}
    if sdk != expected or not re.fullmatch(r"go\d+\.\d+\.\d+", sdk["GOVERSION"]):
        raise RuntimeError("unexpected native host SDK")
    return repo, source, sdk


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
            "write_files": [{"path": "/etc/rc.conf.d/firstboot_pkg_upgrade", "permissions": "0600", "owner": "root:wheel",
                             "content": 'firstboot_pkg_upgrade_enable="NO"\n'}]}


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


def validate_guest_identity(actual):
    if (len(actual) != 5 or actual[0] != "FreeBSD" or not actual[1].startswith("15.1-RELEASE") or
            actual[2] != "amd64" or not actual[3].isdecimal() or int(actual[3]) == 0 or actual[4] != "awtest"):
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


def build_payload(repo, capsule, source):
    payload = capsule / "payload"
    payload.mkdir(mode=0o700)
    tests = payload / "tests"
    tests.mkdir(mode=0o700)
    env = dict(os.environ, GOOS="freebsd", GOARCH="amd64", CGO_ENABLED="0", GOTOOLCHAIN="local")
    packages = decode_objects(run(["go", "list", "-json", "./..."], env=env).stdout)
    records = []
    for package in packages:
        if not package.get("TestGoFiles") and not package.get("XTestGoFiles"):
            continue
        name = package["ImportPath"]
        if not name.startswith(MODULE):
            raise RuntimeError("unexpected test module")
        directory = relative_package(package["Dir"], repo)
        filename = "tests/" + hashlib.sha256(name.encode()).hexdigest()[:20] + ".test"
        target = payload / filename
        run(["go", "test", "-mod=readonly", "-c", "-o", str(target), name], env=env, timeout=300)
        if not target.is_file() or target.stat().st_size > 128 << 20:
            raise RuntimeError("unbounded test binary")
        records.append({"package": name, "directory": directory, "file": filename, "sha256": digest(target)})
    if not records or len(records) > 64:
        raise RuntimeError("unexpected unit package set")
    run(["bash", "scripts/build-all.sh", "freebsd/amd64"],
        env=dict(os.environ, OUTPUT_DIR=str(payload), GOTOOLCHAIN="local"), timeout=300)
    tree = run(["git", "ls-tree", "-r", "-l", "HEAD"]).stdout.decode("utf-8").splitlines()
    sizes = [line.split("\t", 1)[0].split()[-1] for line in tree]
    if len(tree) > 4096 or any(not value.isdecimal() for value in sizes) or sum(map(int, sizes)) > 64 << 20:
        raise RuntimeError("source archive exceeds bounds or contains submodules")
    run(["git", "archive", "--format=tar", "--output=" + str(payload / "source.tar"), "HEAD"])
    if run(["git", "status", "--porcelain"]).stdout.strip():
        raise RuntimeError("source changed while building")
    cli = "accessweaver-freebsd-amd64"
    manifest = {"sourceCommit": source, "goos": "freebsd", "goarch": "amd64", "hostCrossCompiled": True,
                "cli": {"file": cli, "sha256": digest(payload / cli)}, "packages": records,
                "sourceArchiveSHA256": digest(payload / "source.tar")}
    (payload / "PROBE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    files = [payload / cli, payload / "BUILD-INFO.json", payload / "PROBE-MANIFEST.json", payload / "source.tar"]
    files += [payload / record["file"] for record in records]
    if sum(path.stat().st_size for path in files) > 1 << 30:
        raise RuntimeError("payload exceeds bound")
    archive = capsule / "payload.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=1) as tar:
        for path in files:
            tar.add(path, arcname=path.relative_to(payload).as_posix(), recursive=False)
    return manifest, archive


def main():
    repo, source, sdk = guard()
    os.chdir(repo)
    os.umask(0o077)
    root = repo / "build" / "bsd-capsules"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(root)
    capsule = Path(tempfile.mkdtemp(prefix="freebsd-amd64-", dir=root))
    owned_directory(capsule)
    identity = capsule.stat()
    output = repo / "build" / "bsd-native-checks"
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(output)
    report = {"schemaVersion": 1, "sourceCommit": source, "target": "freebsd/amd64", "hostSDK": sdk,
              "imageURL": IMAGE_URL, "imageSHA256": IMAGE_SHA256, "packages": [], "guestExecutionPassed": False,
              "hardwareQualificationComplete": False, "platformQualificationComplete": False,
              "readinessGatesPromoted": 0, "productionQualificationComplete": False}
    vm = None
    serial_tail = bytearray()
    serial_thread = None
    phase = "build"
    failed = True
    try:
        manifest, archive = build_payload(repo, capsule, source)
        report["crossCompiledPackages"] = len(manifest["packages"])
        phase = "image-download"
        compressed = capsule / IMAGE
        value = hashlib.sha256()
        size = 0
        download_deadline = time.monotonic() + 600
        with urllib.request.urlopen(IMAGE_URL, timeout=60) as response, compressed.open("xb") as destination:
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
        if value.hexdigest() != IMAGE_SHA256:
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
        report["qemuVersion"] = run(["qemu-system-x86_64", "--version"]).stdout.decode().splitlines()[0]
        vm = subprocess.Popen(["qemu-system-x86_64", "-accel", acceleration, "-cpu", "host" if acceleration == "kvm" else "max", "-m", "3072", "-smp", "2",
                               "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
                               "-drive", f"file={overlay},if=virtio,format=qcow2",
                               "-drive", f"file={seed},media=cdrom,format=raw,readonly=on",
                               "-netdev", f"user,id=n1,restrict=on,hostfwd=tcp:127.0.0.1:{PORT}-:22",
                               "-device", "virtio-net-pci,netdev=n1"], stdin=subprocess.DEVNULL,
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
                if report["lastSSHFailureClass"] == "host-key-rejected":
                    raise RuntimeError("Pinned guest host key was rejected")
            except (TimeoutError, subprocess.TimeoutExpired):
                report["bootProbeTimeouts"] = report.get("bootProbeTimeouts", 0) + 1
            if time.monotonic() >= deadline:
                raise TimeoutError("pinned guest boot deadline exceeded")
            time.sleep(2)
        phase = "guest-identity"
        actual = run(ssh, data=b"set -eu\nuname -s\nuname -r\nuname -m\nid -u\nid -un\n").stdout.decode().splitlines()
        report["guestIdentity"] = validate_guest_identity(actual)
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
        if cli.get("commit") != source or cli.get("sourceState") != "clean" or cli.get("platform") != "freebsd" or cli.get("arch") != "amd64" or cli.get("goVersion") != sdk["GOVERSION"]:
            raise RuntimeError("executed CLI differs from candidate")
        report["executedCLI"] = cli
        report["cliSHA256"] = manifest["cli"]["sha256"]
        phase = "guest-unit-tests"
        for index, package in enumerate(manifest["packages"]):
            script = f"set -eu\ncd {shlex.quote(guest + '/source/' + package['directory'])}\nexec env -i HOME=/home/awtest PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin LANG=C LC_ALL=C TZ=UTC {shlex.quote(guest + '/' + package['file'])} -test.timeout=150s -test.count=1 -test.v\n"
            started = time.monotonic()
            result = run(ssh, data=script.encode(), timeout=180, check=False)
            text = result.stdout.decode("utf-8", "replace")
            log = output / f"freebsd-amd64-unit-{index:02d}.log"
            log.write_bytes(result.stdout)
            record = {**package, "returnCode": result.returncode, "elapsedSeconds": round(time.monotonic() - started, 3),
                      "passedTestInstances": len(re.findall(r"--- PASS:", text)), "skippedTestInstances": len(re.findall(r"--- SKIP:", text)),
                      "logSHA256": digest(log)}
            report["packages"].append(record)
            print(json.dumps({"package": package["package"], "returnCode": result.returncode}), flush=True)
        if any(record["returnCode"] != 0 for record in report["packages"]):
            raise RuntimeError("one or more actual guest unit packages failed")
        report["guestExecutionPassed"] = True
        failed = False
    except Exception as error:
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
                report["nuageinitMessageObserved"] = b"nuageinit" in serial_tail
                report["firstbootPackageMessageObserved"] = b"firstboot_pkg_upgrade" in serial_tail
                report["consoleLoginObserved"] = b"login:" in serial_tail
                report["expectedHostnameConsoleObserved"] = b"awbsd login:" in serial_tail.lower()
                report["defaultHostnameConsoleObserved"] = b"amnesiac" in serial_tail.lower() or b"freebsd login:" in serial_tail.lower()
        if emulator_stopped and vm is not None and phase == "guest-boot":
            # Read only the stopped overlay, in a separate bounded helper. The
            # helper returns fixed booleans, never logs, keys or cached user data.
            try:
                observed = run([sys.executable, str(repo / "scripts" / "bsd_boot_diagnostics.py"), str(capsule)],
                               env=dict(os.environ, PYTHONPATH=str(repo / "build" / "bsd-inspection-tools")),
                               timeout=60, limit=16384)
                fields = json.loads(observed.stdout)
                if not isinstance(fields, dict) or not fields or any(type(v) is not bool for v in fields.values()):
                    raise ValueError("unexpected disk observation result")
                report["bootDiskInspection"] = fields
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
        (output / "freebsd-amd64.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


def interrupted(*_):
    raise KeyboardInterrupt()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
