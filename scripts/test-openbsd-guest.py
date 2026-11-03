#!/usr/bin/env python3
"""Hosted-only OpenBSD 8.0 installation and ordinary-user core execution.

Never boot locally. Installer media is authenticated before a reviewed ISO
transform. Seed media is removed before target execution; no host mounts exist.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

_spec = importlib.util.spec_from_file_location("_aw_bsd_host", Path(__file__).with_name("test-bsd-guest.py"))
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

PUBLIC_KEY = "RWSMSt0erHTctUxq2JDAgQRo64ztikp8JvQeiSPte3NZ0Geou0TkTEiE"
MEDIA = {
    "amd64": ("bc85d747c6ee4354d14fbfeee38087500386a2e9d86fa7b5ab13d840d902aa33", 832565248),
    "arm64": ("6449a657d021e000cebb50987535b3dec6988edc65908107b42a42c2f95c3f6b", 656941056),
}
PORT = 2222
ARM_BOOTSTRAP_SHA256 = "30e76fa7616c0cda0e3514d341ffa5a21b1b9efb5c71820b53a63b15c305296d"


def guard():
    if os.environ.get("ACCESSWEAVER_DISPOSABLE_OPENBSD_GUEST_TEST") != "1":
        raise RuntimeError("OpenBSD hosted installation requires explicit opt-in")
    repo, source, sdk, base = common.guard()
    target = dict(base, goos="openbsd", label="openbsd-" + base["arch"], machine=base["arch"])
    target.update(imageURL="https://cdn.openbsd.org/pub/OpenBSD/8.0/" + target["arch"] + "/install80.iso",
                  imageSHA256=MEDIA[target["arch"]][0], imageBytes=MEDIA[target["arch"]][1])
    return repo, source, sdk, target


def download(url, destination, maximum, expected=None):
    total, value, deadline = 0, hashlib.sha256(), time.monotonic() + 600
    with urllib.request.urlopen(url, timeout=30) as response, destination.open("xb") as stream:
        if not response.geturl().startswith("https://"):
            raise RuntimeError("installer input changed transport")
        while data := response.read(1 << 20):
            total += len(data)
            if total > maximum or time.monotonic() > deadline:
                raise RuntimeError("installer input exceeded download bounds")
            value.update(data)
            stream.write(data)
    if total == 0 or (expected is not None and value.hexdigest() != expected):
        raise RuntimeError("installer input digest mismatch")
    return total, value.hexdigest()


def verify_manifest(signed, capsule, arch):
    if arch not in MEDIA or not 0 < len(signed) <= 65536:
        raise ValueError("unexpected signed installer manifest")
    parts = signed.split(b"\n", 2)
    if len(parts) != 3 or not parts[0].startswith(b"untrusted comment: ") or len(parts[0]) > 1024:
        raise ValueError("invalid installer signature envelope")
    public = base64.b64decode(PUBLIC_KEY, validate=True)
    signature = base64.b64decode(parts[1], validate=True)
    if len(public) != 42 or public[:2] != b"Ed" or len(signature) != 74 or signature[:10] != public[:10]:
        raise ValueError("installer signer differs from pinned OpenBSD 8.0 key")
    key, sig, message = capsule / "key.der", capsule / "signature.raw", capsule / "SHA256"
    for path, data in ((key, bytes.fromhex("302a300506032b6570032100") + public[10:]), (sig, signature[10:]), (message, parts[2])):
        with path.open("xb") as stream:
            stream.write(data)
    common.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", str(key),
                "-sigfile", str(sig), "-in", str(message)], timeout=20, limit=16384)
    # Only authenticated checksum text may select the reviewed image bytes.
    matches = re.findall(rb"^SHA256 \(install80\.iso\) = ([a-f0-9]{64})$", parts[2], re.M)
    if matches != [MEDIA[arch][0].encode()]:
        raise ValueError("signed installer digest differs from source-controlled media pin")
    if arch == "arm64" and re.findall(rb"^SHA256 \(miniroot80\.img\) = ([a-f0-9]{64})$", parts[2], re.M) != [ARM_BOOTSTRAP_SHA256.encode()]:
        raise ValueError("signed ARM bootstrap disk differs from reviewed pin")
    return {"signedManifestSHA256": hashlib.sha256(signed).hexdigest(), "installerMetadataSignatureVerified": True}


def response_file(arch, client_public):
    if arch not in MEDIA or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]{60,80}( [A-Za-z0-9._-]{1,80})?", client_public):
        raise ValueError("invalid OpenBSD bootstrap target or public key")
    answers = [
        ("System hostname", "awobsd"), ("Terminal type", "vt220"),
        ("Network interface to configure", "vio0"), ("IPv4 address for vio0", "autoconf"),
        ("IPv6 address for vio0", "none"), ("Network interface to configure", "done"),
        ("DNS domain name", "invalid"), ("DNS nameservers", "10.0.2.3"),
        ("Password for root account", "*************"), ("Public ssh key for root account", "none"),
        ("Start sshd(8) by default", "yes"), ("Do you expect to run the X Window System", "no"),
        ("Do you want the X Window System to be started by xenodm(1)", "no"),
        ("Change the default console to com0", "yes"), ("Which speed should com0 use", "115200"),
        ("Setup a user", "awtest"), ("Full name for user awtest", "Disposable core probe"),
        ("Password for user awtest", "*************"), ("Public ssh key for user awtest", client_public),
        ("Allow root ssh login", "no"), ("What timezone are you in", "UTC"),
        ("Which disk is the root disk", "sd0"), ("Encrypt the root disk", "no"),
        ("Use (W)hole disk", "whole"), ("URL to autopartitioning template for disklabel", "none"),
        ("Use (A)uto layout", "a"), ("Which disk do you wish to initialize", "done"),
        ("Location of sets", "cd0"), ("Pathname to the sets", "8.0/" + arch),
        ("Set name(s)", "done"),
    ]
    # The reviewed media gains its official SHA256.sig; no checksum/signature
    # failure or missing-manifest question has a permissive answer here.
    return "".join(question + " = " + answer + "\n" for question, answer in answers)


def bootstrap_script():
    return """#!/bin/ksh
set -eu
trap 'rc=$?; if ((rc != 0)); then print -u2 AW_OPENBSD_BOOTSTRAP_FAILED; fi' EXIT
/install -af /tmp/aw-install.conf </dev/null
test -f /tmp/ai/ai.done
test -d /mnt/etc/ssh
mkdir -p /awseed
(cd /dev && sh MAKEDEV cd1)
mount -t cd9660 -o ro /dev/cd1c /awseed
cp /awseed/host /mnt/etc/ssh/ssh_host_ed25519_key
cp /awseed/host.pub /mnt/etc/ssh/ssh_host_ed25519_key.pub
cp /awseed/sshd_config /mnt/etc/ssh/sshd_config
chmod 600 /mnt/etc/ssh/ssh_host_ed25519_key /mnt/etc/ssh/sshd_config
chmod 644 /mnt/etc/ssh/ssh_host_ed25519_key.pub
chown root:wheel /mnt/etc/ssh/ssh_host_ed25519_key /mnt/etc/ssh/ssh_host_ed25519_key.pub /mnt/etc/ssh/sshd_config
chroot /mnt /usr/sbin/sshd -t
sync
umount -af
printf '\\nAW_OPENBSD_PRIVATE_BOOTSTRAP_COMPLETE\\n'
"""


def bootstrap_command():
    return (b"mkdir -p /awseed /tmp/ai && (cd /dev && sh MAKEDEV cd1) && "
            b"mount -t cd9660 -o ro /dev/cd1c /awseed && cp /awseed/auto_install.conf /tmp/aw-install.conf && "
            b"cp /awseed/guest-setup.sh /tmp/aw-setup.sh && umount /awseed && /bin/ksh /tmp/aw-setup.sh\n")


def iso_primary_bytes(path, components, maximum):
    """Read a small ISO9660 primary-name file, without Rock Ridge aliases."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        def read(offset, length, bound):
            if not 0 <= offset or not 0 < length <= bound or offset + length > size:
                raise ValueError("ISO primary record exceeds bounds")
            stream.seek(offset)
            data = stream.read(length)
            if len(data) != length:
                raise ValueError("truncated ISO primary record")
            return data
        def record(data):
            if len(data) < 34 or data[0] != len(data) or data[32] == 0 or 33 + data[32] > len(data) or data[25] & 128:
                raise ValueError("unsupported ISO primary record")
            offset = int.from_bytes(data[2:6], "little")
            length = int.from_bytes(data[10:14], "little")
            if offset != int.from_bytes(data[6:10], "big") or length != int.from_bytes(data[14:18], "big"):
                raise ValueError("inconsistent ISO primary record")
            return offset * 2048, length, bool(data[25] & 2)
        for sector in range(16, 48):
            pvd = read(sector * 2048, 2048, 2048)
            if pvd[:7] == b"\x01CD001\x01":
                break
        else:
            raise ValueError("missing ISO primary descriptor")
        current = record(pvd[156:190])
        for component in components:
            if not current[2] or not re.fullmatch(r"[A-Za-z0-9._-]+", component):
                raise ValueError("invalid ISO bootstrap path")
            directory = read(current[0], current[1], 1 << 20)
            offset, matches = 0, []
            while offset < len(directory):
                length = directory[offset]
                if length == 0:
                    offset = (offset // 2048 + 1) * 2048
                    continue
                entry = directory[offset:offset + length]
                value = record(entry)
                if entry[33:33 + entry[32]].split(b";", 1)[0].upper() == component.upper().encode():
                    matches.append(value)
                offset += length
            if len(matches) != 1:
                raise ValueError("bootstrap file absent or ambiguous in primary ISO names")
            current = matches[0]
        if current[2]:
            raise ValueError("expected ISO bootstrap file, not directory")
        return read(current[0], current[1], maximum)


def prepare_media(capsule, target, client_public):
    signed = capsule / "SHA256.sig"
    download("https://cdn.openbsd.org/pub/OpenBSD/8.0/" + target["arch"] + "/SHA256.sig", signed, 65536)
    observed = verify_manifest(signed.read_bytes(), capsule, target["arch"])
    original, prepared = capsule / "official.iso", capsule / "installer.iso"
    size, digest = download(target["imageURL"], original, 1 << 30, target["imageSHA256"])
    if size != target["imageBytes"]:
        raise RuntimeError("installer media size differs from reviewed release")
    original.chmod(0o400)
    boot = capsule / "boot.conf"
    boot.write_text(("stty com0 115200\nset tty com0\n" if target["arch"] == "amd64" else "") + "set timeout 1\n", encoding="ascii")
    common.run(["xorriso", "-indev", str(original), "-outdev", str(prepared), "-compliance", "iso_9660_level=2", "-boot_image", "any", "replay",
                "-map", str(boot), "/etc/boot.conf", "-map", str(signed), "/8.0/" + target["arch"] + "/SHA256.sig"], timeout=180)
    if not 0 < prepared.stat().st_size <= 1 << 30 or common.digest(original) != digest:
        raise RuntimeError("installer media preparation violated bounds or changed original")
    prepared.chmod(0o400)
    copied_signature, copied_boot = capsule / "inserted-signature", capsule / "inserted-boot.conf"
    common.run(["xorriso", "-osirrox", "on", "-indev", str(prepared),
                "-extract", "/8.0/" + target["arch"] + "/SHA256.sig", str(copied_signature),
                "-extract", "/etc/boot.conf", str(copied_boot)], timeout=60)
    if (copied_signature.stat().st_size > 65536 or copied_boot.stat().st_size > 1024 or
            copied_signature.read_bytes() != signed.read_bytes() or copied_boot.read_bytes() != boot.read_bytes()):
        raise RuntimeError("prepared installer did not retain exact signature and boot configuration")
    if iso_primary_bytes(prepared, ("etc", "boot.conf"), 1024) != boot.read_bytes():
        raise RuntimeError("boot configuration is not readable through primary ISO names")
    bootstrap = None
    if target["arch"] == "arm64":
        # The ARM full ISO has a legacy BIOS/floppy El Torito entry, not an
        # EFI boot entry. Boot the official signed miniroot disk; use CD0 for
        # the independently authenticated full sets and CD1 for private input.
        bootstrap = capsule / "miniroot.img"
        bootstrap_bytes, _ = download("https://cdn.openbsd.org/pub/OpenBSD/8.0/arm64/miniroot80.img", bootstrap, 128 << 20, ARM_BOOTSTRAP_SHA256)
        bootstrap.chmod(0o400)
        observed.update(bootstrapDiskSHA256=ARM_BOOTSTRAP_SHA256, bootstrapDiskBytes=bootstrap_bytes)
    seed_dir = capsule / "seed"
    seed_dir.mkdir(mode=0o700)
    (seed_dir / "auto_install.conf").write_text(response_file(target["arch"], client_public), encoding="ascii")
    (seed_dir / "guest-setup.sh").write_text(bootstrap_script(), encoding="ascii")
    (seed_dir / "sshd_config").write_text("""HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers awtest
LoginGraceTime 30
MaxAuthTries 3
Subsystem sftp /usr/libexec/sftp-server
""", encoding="ascii")
    for name in ("host", "host.pub"):
        with (seed_dir / name).open("xb") as out:
            out.write((capsule / name).read_bytes())
    seed = capsule / "seed.iso"
    common.run(["xorriso", "-as", "mkisofs", "-quiet", "-R", "-V", "AWSEED", "-o", str(seed), str(seed_dir)])
    if not 0 < seed.stat().st_size <= 8 << 20:
        raise RuntimeError("private seed exceeds bounds")
    return prepared, seed, bootstrap, {**observed, "installerMediaDigestVerified": True, "officialInstallerSHA256": digest,
                            "officialInstallerBytes": size, "preparedInstallerSHA256": common.digest(prepared),
                            "bootConfigurationSHA256": common.digest(boot), "officialSetSignatureInserted": True}


def machine_command(target, disk, acceleration, firmware=None, installer=None, seed=None, bootstrap=None):
    if (acceleration not in ("kvm", "tcg") or (installer is None) != (seed is None) or
            (installer is None and bootstrap is not None) or
            (target["arch"] == "arm64" and installer is not None and bootstrap is None) or
            (target["arch"] != "arm64" and bootstrap is not None)):
        raise ValueError("invalid OpenBSD virtual machine parameters")
    cpu = "host" if acceleration == "kvm" else target["tcgCPU"]
    args = [target["qemu"], "-accel", acceleration, "-cpu", cpu, "-m", "3072", "-smp", "2", "-display", "none",
            "-monitor", "none", "-serial", "stdio", "-no-reboot"]
    if target["arch"] == "arm64":
        if firmware is None:
            raise ValueError("private ARM firmware required")
        args += ["-machine", "virt,gic-version=3", "-drive", f"if=pflash,format=raw,unit=0,file={firmware['code']},readonly=on",
                 "-drive", f"if=pflash,format=raw,unit=1,file={firmware['variables']}"]
    args += ["-drive", f"file={disk},if=none,id=osdisk,format=qcow2", "-device", "virtio-blk-pci,drive=osdisk,bootindex=" + ("2" if installer is not None else "1")]
    if bootstrap is not None:
        args += ["-drive", f"file={bootstrap},if=none,id=bootdisk,format=raw,readonly=on",
                 "-device", "virtio-blk-pci,drive=bootdisk,bootindex=1"]
    if installer is not None:
        if target["arch"] == "amd64":
            # Use the PC's native optical controller for the BIOS/CD loader.
            # The installed root disk remains virtio and is always sd0.
            optical, seed_device = "ide-cd,drive=installer,bus=ide.1,unit=0,bootindex=1", "ide-cd,drive=seed,bus=ide.1,unit=1"
        else:
            args += ["-device", "virtio-scsi-pci,id=scsi0"]
            optical, seed_device = "scsi-cd,drive=installer,bus=scsi0.0", "scsi-cd,drive=seed,bus=scsi0.0"
        args += ["-drive", f"file={installer},if=none,id=installer,media=cdrom,format=raw,readonly=on",
                 "-device", optical,
                 "-drive", f"file={seed},if=none,id=seed,media=cdrom,format=raw,readonly=on",
                 "-device", seed_device]
    args += ["-netdev", f"user,id=n1,restrict=on,hostfwd=tcp:127.0.0.1:{PORT}-:22", "-device", "virtio-net-pci,netdev=n1,romfile=",
             "-object", "rng-random,id=rng0,filename=/dev/urandom", "-device", "virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000"]
    return args


class Console:
    def __init__(self, command):
        self.tail = bytearray()
        self.condition = threading.Condition()
        self.thread = threading.Thread(target=self._drain, daemon=True)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            self.thread.start()
        except BaseException:
            try:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=5)
            finally:
                self.process.stdin.close()
                self.process.stdout.close()
            raise

    def _drain(self):
        try:
            while chunk := os.read(self.process.stdout.fileno(), 4096):
                with self.condition:
                    self.tail.extend(chunk)
                    if len(self.tail) > 1 << 20:
                        del self.tail[:len(self.tail) - (1 << 20)]
                    self.condition.notify_all()
        except OSError:
            pass
        finally:
            with self.condition:
                self.condition.notify_all()

    def wait(self, marker, timeout):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if b"AW_OPENBSD_BOOTSTRAP_FAILED" in self.tail:
                    raise RuntimeError("OpenBSD installer/bootstrap reported failure")
                if marker in self.tail:
                    return
                if self.process.poll() is not None:
                    raise RuntimeError("owned OpenBSD emulator exited before expected stage")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("OpenBSD console stage deadline exceeded")
                self.condition.wait(min(remaining, 0.5))

    def send(self, data):
        if not isinstance(data, bytes) or len(data) > 1024:
            raise ValueError("bounded installer console input exceeded")
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def stop(self):
        proc = self.process
        try:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
            return proc.poll() is not None
        finally:
            proc.stdin.close()
            self.thread.join(timeout=2)
            proc.stdout.close()

    def observations(self):
        with self.condition:
            data = bytes(self.tail)
        unanswered = re.findall(rb'Question has no answer in response file: "([^"\r\n]{1,512})"', data)
        return {"serialTailBytes": len(data), "serialTailSHA256": hashlib.sha256(data).hexdigest(),
                "installerUnansweredPromptSHA256": hashlib.sha256(unanswered[-1]).hexdigest() if unanswered else None,
                "installerQuestionWithoutAnswerObserved": b"Question has no answer" in data,
                "installerSignatureFailureObserved": b"Signature check of SHA256.sig failed" in data,
                "installerCongratulationsObserved": b"CONGRATULATIONS!" in data,
                "privateBootstrapMarkerObserved": b"AW_OPENBSD_PRIVATE_BOOTSTRAP_COMPLETE" in data,
                "privateBootstrapFailureObserved": b"AW_OPENBSD_BOOTSTRAP_FAILED" in data,
                "kernelPanicObserved": b"panic:" in data,
                "openbsdLoaderObserved": b">> OpenBSD/" in data,
                "openbsdLoaderPromptObserved": b"boot>" in data,
                "efiShellObserved": b"UEFI Interactive Shell" in data or b"Shell>" in data,
                "efiBootFailureObserved": b"BdsDxe: failed" in data}


def validate_identity(lines, arch):
    if (arch not in MEDIA or len(lines) != 5 or lines[0] != "OpenBSD" or lines[1] != "8.0" or lines[2] != arch or
            not lines[3].isdecimal() or int(lines[3]) == 0 or lines[4] != "awtest"):
        raise RuntimeError("unexpected actual OpenBSD guest identity")
    return {"OS": lines[0], "release": lines[1], "machine": lines[2], "uid": int(lines[3]), "user": lines[4]}


def wait_for_ssh(ssh, process, report, timeout=600):
    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            raise RuntimeError("installed OpenBSD emulator exited")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("installed OpenBSD SSH boot deadline exceeded")
        try:
            probe = common.run(ssh, data=b"true\n", timeout=min(8, remaining), check=False)
            if probe.returncode == 0:
                return
            kind = common.ssh_failure_class(probe.stdout)
            report["lastSSHFailureClass"] = kind
            if kind == "host-key-rejected":
                raise RuntimeError("pinned OpenBSD host key was rejected")
        except (TimeoutError, subprocess.TimeoutExpired):
            report["bootProbeTimeouts"] = report.get("bootProbeTimeouts", 0) + 1
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def main():
    repo, source, sdk, target = guard()
    os.chdir(repo)
    os.umask(0o077)
    root = repo / "build/bsd-capsules"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    common.owned_directory(root)
    capsule = Path(tempfile.mkdtemp(prefix=target["label"] + "-", dir=root))
    common.owned_directory(capsule)
    identity = capsule.stat()
    output = repo / "build/openbsd-native-checks"
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    common.owned_directory(output)
    report = {"schemaVersion": 1, "sourceCommit": source, "target": "openbsd/" + target["arch"], "hostSDK": sdk,
              "packages": [], "guestExecutionPassed": False, "packagedCandidateExecuted": False,
              "hardwareQualificationComplete": False, "platformQualificationComplete": False,
              "productionQualificationComplete": False, "readinessGatesPromoted": 0}
    installer_vm = runtime_vm = None
    stopped, failed, phase = True, True, "source-build"
    unconfirmed_start = False
    try:
        manifest, payload = common.build_payload(repo, capsule, source, target)
        report["crossCompiledPackages"] = len(manifest["packages"])
        for name in ("client", "host"):
            common.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "aw-disposable-openbsd", "-f", str(capsule / name)])
        client_public = (capsule / "client.pub").read_text(encoding="ascii").strip()
        host_public = (capsule / "host.pub").read_text(encoding="ascii").strip()
        (capsule / "known_hosts").write_text(f"[127.0.0.1]:{PORT} {host_public}\n", encoding="ascii")
        phase = "installer-media"
        installer, seed, bootstrap, observed = prepare_media(capsule, target, client_public)
        report.update(observed)
        disk = capsule / "root.qcow2"
        common.run(["qemu-img", "create", "-f", "qcow2", str(disk), "16G"])
        with socket.socket() as check:
            check.bind(("127.0.0.1", PORT))
        acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        report.update(hypervisorAcceleration=acceleration, CPUEmulated=acceleration == "tcg", cpuModel="host" if acceleration == "kvm" else target["tcgCPU"])
        report["qemuVersion"] = common.run([target["qemu"], "--version"]).stdout.decode().splitlines()[0]
        firmware = common.prepare_arm_firmware(capsule) if target["arch"] == "arm64" else None
        if firmware:
            report.update(bootFirmwareCodeSHA256=firmware["codeSHA256"], bootFirmwareInitialVariablesSHA256=firmware["initialVariablesSHA256"])
        phase = "installer-boot"
        unconfirmed_start = True
        installer_vm = Console(machine_command(target, disk, acceleration, firmware, installer, seed, bootstrap))
        unconfirmed_start = False
        stopped = False
        installer_vm.wait(b"(S)hell?", 480)
        installer_vm.send(b"s\n")
        installer_vm.wait(b"# ", 30)
        # The script and response are copied to RAM before /install unmounts
        # other filesystems. No private key bytes travel through console input.
        installer_vm.send(bootstrap_command())
        phase = "guest-installation"
        installer_vm.wait(b"AW_OPENBSD_PRIVATE_BOOTSTRAP_COMPLETE", 1200)
        report["installerCompleted"] = True
        stopped = installer_vm.stop()
        report["installerVM"] = installer_vm.observations()
        if not stopped:
            raise RuntimeError("installer VM did not stop")
        # Restart with only the installed disk: private-key seed and installer
        # media must not be available to the ordinary target user.
        phase = "installed-guest-boot"
        unconfirmed_start = True
        runtime_vm = Console(machine_command(target, disk, acceleration, firmware))
        unconfirmed_start = False
        stopped = False
        report["seedRemovedBeforeTargetExecution"] = True
        options = ["-F", "/dev/null", "-i", str(capsule / "client"), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(capsule / "known_hosts"),
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ForwardAgent=no",
                   "-o", "ControlMaster=no", "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"]
        ssh = ["ssh", *options, "-p", str(PORT), "awtest@127.0.0.1", "/bin/sh -s"]
        wait_for_ssh(ssh, runtime_vm.process, report)
        phase = "guest-identity"
        actual = common.run(ssh, data=b"set -eu\nuname -s\nuname -r\nuname -m\nid -u\nid -un\n").stdout.decode().splitlines()
        report["guestIdentity"] = validate_identity(actual, target["arch"])
        report["sshHostKeyPinned"] = True
        guest = "/home/awtest/awprobe-" + capsule.name.split("-")[-1]
        common.run(ssh, data=f"set -eu\numask 077\nmkdir {shlex.quote(guest)}\n".encode())
        phase = "payload-transfer"
        common.run(["scp", *options, "-P", str(PORT), str(payload), f"awtest@127.0.0.1:{guest}/payload.tar.gz"], timeout=180)
        actual_hash = common.run(ssh, data=f"sha256 -q {shlex.quote(guest + '/payload.tar.gz')}\n".encode()).stdout.decode().strip()
        if actual_hash != common.digest(payload):
            raise RuntimeError("OpenBSD payload transport digest mismatch")
        common.run(ssh, data=f"set -eu\ncd {shlex.quote(guest)}\ntar -xzf payload.tar.gz\nmkdir source tmp\ntar -xf source.tar -C source\n".encode())
        for item in [manifest["cli"], *manifest["packages"]]:
            actual_hash = common.run(ssh, data=f"sha256 -q {shlex.quote(guest + '/' + item['file'])}\n".encode()).stdout.decode().strip()
            if actual_hash != item["sha256"]:
                raise RuntimeError("OpenBSD executable transport digest mismatch")
        report["allTransportedExecutableHashesVerified"] = True
        phase = "guest-cli"
        cli = json.loads(common.run(ssh, data=f"{shlex.quote(guest + '/' + manifest['cli']['file'])} version --json\n".encode()).stdout)
        for key, expected in {"commit": source, "sourceState": "clean", "platform": "openbsd", "arch": target["arch"], "goVersion": sdk["GOVERSION"]}.items():
            if cli.get(key) != expected:
                raise RuntimeError("executed OpenBSD CLI source/target differs")
        report.update(executedCLI=cli, cliSHA256=manifest["cli"]["sha256"])
        phase = "guest-unit-tests"
        for index, package in enumerate(manifest["packages"]):
            script = f"set -eu\ncd {shlex.quote(guest + '/source/' + package['directory'])}\nexec env -i HOME=/home/awtest TMPDIR={shlex.quote(guest + '/tmp')} PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin LANG=C LC_ALL=C TZ=UTC {shlex.quote(guest + '/' + package['file'])} -test.timeout=150s -test.count=1 -test.v\n"
            started = time.monotonic()
            result = common.run(ssh, data=script.encode(), timeout=180, check=False)
            log = output / f"{target['label']}-unit-{index:02d}.log"
            log.write_bytes(result.stdout)
            report["packages"].append({**package, "returnCode": result.returncode, "elapsedSeconds": round(time.monotonic() - started, 3),
                                      "passedTestInstances": len(re.findall(rb"--- PASS:", result.stdout)),
                                      "skippedTestInstances": len(re.findall(rb"--- SKIP:", result.stdout)), "logSHA256": common.digest(log)})
            print(json.dumps({"package": package["package"], "returnCode": result.returncode}), flush=True)
        if any(p["returnCode"] != 0 for p in report["packages"]):
            raise RuntimeError("OpenBSD target package failed")
        report["guestExecutionPassed"] = True
        failed = False
    except Exception as error:
        report.update(failurePhase=phase, failureType=type(error).__name__)
        print("OpenBSD qualification incomplete: " + phase + "/" + type(error).__name__, file=sys.stderr)
    finally:
        # A failed constructor may leave process ownership uncertain. Preserve
        # its private files rather than deleting storage under a possible VM.
        stopped = not unconfirmed_start
        for label, machine in (("installerVM", installer_vm), ("runtimeVM", runtime_vm)):
            if machine is not None:
                try:
                    stopped = machine.stop() and stopped
                    report[label] = machine.observations()
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    stopped, failed = False, True
        report["ownedEmulatorsStopped"] = stopped
        try:
            common.remove_owned_capsule(capsule, root, identity, stopped)
            report["ownedCapsuleRemoved"] = not capsule.exists()
        except (OSError, RuntimeError):
            report["cleanupFailed"], failed = True, True
        (output / (target["label"] + ".json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, common.interrupted)
    raise SystemExit(main())
