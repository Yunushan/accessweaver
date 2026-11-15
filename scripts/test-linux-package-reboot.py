#!/usr/bin/env python3
"""Verify a real Debian package reboot in an offline disposable Ubuntu QEMU guest."""
import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from verify_release import MAX_FILE, release_file, require

GUEST = Path(__file__).with_name("linux_package_reboot_guest.py")
UNIT = """[Unit]
Description=AccessWeaver disposable package reboot fixture
After=cloud-final.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/accessweaver-reboot-qualification
TimeoutStartSec=180
"""
ENTRY = """#!/bin/sh
set -eu
install -d -m 0755 /run/accessweaver-seed
mount -t iso9660 -o ro,nodev,nosuid,noexec /dev/disk/by-label/cidata /run/accessweaver-seed
exec /usr/bin/python3 -B /run/accessweaver-seed/guest.py
"""
SHA256 = re.compile(r"[a-f0-9]{64}")


def run(*args, timeout=60):
    result = subprocess.run(args, check=False, capture_output=True, timeout=timeout)
    require(result.returncode == 0, f"{Path(args[0]).name} failed: "
            + result.stderr[-2048:].decode("utf-8", "replace").strip())
    return result.stdout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stage(source, target, maximum, pin=None):
    info = release_file(source, maximum)
    with source.open("rb") as stream, target.open("xb") as output:
        total = 0
        sha = hashlib.sha256()
        for block in iter(lambda: stream.read(1 << 20), b""):
            total += len(block)
            require(total <= info.st_size, "Guest input grew while staging")
            output.write(block)
            sha.update(block)
    actual = sha.hexdigest()
    require(total == info.st_size and (pin is None or actual == pin), "Guest input differs from its approved bytes")
    return actual


def package_info(path, expected_arch):
    metadata = run("dpkg-deb", "--field", path, "Package", "Architecture", "Version").decode("ascii")
    fields = dict(line.split(": ", 1) for line in metadata.strip().splitlines())
    require(set(fields) == {"Package", "Architecture", "Version"}
            and fields["Package"] == "accessweaver" and fields["Architecture"] == expected_arch,
            "Expected an approved AccessWeaver package for the guest architecture")
    controls = run("dpkg-deb", "--ctrl-tarfile", path)
    with tarfile.open(fileobj=BytesIO(controls)) as archive:
        require({str(PurePosixPath(item.name)) for item in archive} == {".", "control", "md5sums"},
                "Unexpected native package hooks")
    return fields["Version"]


def seed_guest(seed, packages):
    config = {
        "ssh_pwauth": False, "disable_root": True, "package_update": False, "package_upgrade": False,
        "write_files": [
            {"path": "/etc/systemd/system/accessweaver-reboot-qualification.service",
             "permissions": "0644", "content": UNIT},
            {"path": "/etc/systemd/system/cloud-final.service.d/accessweaver-reboot.conf", "permissions": "0644",
             "content": "[Unit]\nWants=accessweaver-reboot-qualification.service\n"},
            {"path": "/usr/local/libexec/accessweaver-reboot-qualification", "permissions": "0755", "content": ENTRY}],
        "runcmd": [["systemctl", "daemon-reload"],
                   ["systemctl", "--no-block", "start", "accessweaver-reboot-qualification.service"]],
    }
    (seed / "user-data").write_text("#cloud-config\n" + json.dumps(config) + "\n", encoding="ascii")
    (seed / "meta-data").write_text("instance-id: accessweaver-package-reboot\nlocal-hostname: accessweaver-reboot\n",
                                   encoding="ascii")
    network = {"version": 2, "ethernets": {"awfixture0": {
        "match": {"macaddress": "52:54:00:ac:ce:55"}, "set-name": "awfixture0",
        "addresses": ["192.0.2.2/24"], "link-local": [], "dhcp4": False, "dhcp6": False,
    }}}
    (seed / "network-config").write_text(json.dumps(network) + "\n", encoding="ascii")
    (seed / "packages.json").write_text(json.dumps(packages), encoding="ascii")
    shutil.copyfile(GUEST, seed / "guest.py")


def boot(command, temporary, number, timeout):
    serial = temporary / f"result-{number}.json"
    console = temporary / f"console-{number}.log"
    result = subprocess.run([*command, "-serial", f"file:{console}", "-serial", f"file:{serial}"],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    require(result.returncode == 0, "QEMU did not exit cleanly: " + result.stderr[-2048:].decode("utf-8", "replace"))
    require(serial.is_file() and 0 < serial.stat().st_size <= 16384, "Guest did not emit a bounded boot report")
    marker = b"ACCESSWEAVER-BOOT-V1 "
    frames = [line[len(marker):] for line in serial.read_bytes().splitlines() if line.startswith(marker)]
    require(len(frames) == 1, "Expected one guest report frame after firmware output")
    receipt = json.loads(frames[0])
    require(receipt.get("phase") != "failure", f"Guest acceptance failed: {receipt.get('code')}")
    return receipt


def exercise(args, temporary):
    base = temporary / "base.qcow2"
    stage(args.image, base, 8 << 30, args.image_sha256)
    base.chmod(0o444)
    result = json.loads(run(args.qemu_img, "info", "--output=json", base))
    require(result.get("format") == "qcow2" and not result.get("backing-filename")
            and not result.get("format-specific", {}).get("data", {}).get("data-file"),
            "Expected a self-contained approved QCOW2 base image")
    overlay = temporary / "guest.qcow2"
    run(args.qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", base, overlay)
    firmware = temporary / "firmware.fd"
    variables = temporary / "variables.fd"
    template_pins = {"code": stage(args.firmware_code, firmware, 16 << 20),
                     "initialVariables": stage(args.firmware_vars, variables, 16 << 20)}
    firmware.chmod(0o444)

    seed = temporary / "seed"
    seed.mkdir()
    packages = {}
    versions = {}
    for label, source, pin in (("older", args.old, args.old_sha256), ("newer", args.new, args.new_sha256)):
        name = label + ".deb"
        packages[name] = stage(source, seed / name, MAX_FILE, pin)
        versions[label] = package_info(seed / name, "amd64")
    run("dpkg", "--compare-versions", versions["older"], "lt", versions["newer"])
    seed_guest(seed, packages)
    iso = temporary / "seed.iso"
    run(args.genisoimage, "-quiet", "-V", "cidata", "-J", "-r", "-o", iso, seed)
    system = [
        args.qemu, "-nodefaults", "-machine", f"q35,accel={args.accel}", "-smp", "2", "-m", "1536",
        "-cpu", "host" if args.accel == "kvm" else "max", "-monitor", "none",
        "-netdev", "user,id=sealed,restrict=on,ipv6=off",
        "-device", "virtio-net-pci,netdev=sealed,mac=52:54:00:ac:ce:55,romfile=",
        "-display", "none", "-no-reboot", "-smbios", "type=1,manufacturer=QEMU,product=AccessWeaver-Isolated-Guest,serial=ds=nocloud;",
        "-drive", f"if=pflash,format=raw,unit=0,file={firmware},readonly=on",
        "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
        "-drive", f"if=virtio,format=qcow2,file={overlay}",
        "-drive", f"if=virtio,file={iso},format=raw,readonly=on",
    ]
    if args.qemu_data is not None:
        system.extend(["-L", args.qemu_data])
    first, second = (boot(system, temporary, index, args.boot_timeout) for index in (1, 2))
    startup_fields = {"phase", "bootSHA256", "installedVersion", "acceptedRevision", "controllerSHA256"}
    recovery_fields = {"rollbackVersion", "rollbackKeptCurrentPolicy", "replayRefused", "purgePreservedState"}
    require(set(first) == startup_fields and set(second) == startup_fields | recovery_fields
            and first["phase"] == "before-reboot" and second["phase"] == "after-reboot"
            and all(SHA256.fullmatch(receipt["bootSHA256"]) and SHA256.fullmatch(receipt["controllerSHA256"])
                    and receipt["installedVersion"] == versions["newer"] and receipt["acceptedRevision"] == 2
                    for receipt in (first, second))
            and first["bootSHA256"] != second["bootSHA256"]
            and first["controllerSHA256"] == second["controllerSHA256"]
            and second["rollbackVersion"] == versions["older"]
            and all(second[name] is True for name in recovery_fields - {"rollbackVersion"}),
            "Unexpected pre-reboot and reboot evidence")
    require(digest(base) == args.image_sha256, "Approved guest base snapshot changed")
    return {"schemaVersion": 1, "scope": "Offline Ubuntu Linux AMD64 QEMU guest kernel restart and Debian lifecycle",
            "guestArchitecture": "amd64", "emulation": args.accel, "imageSHA256": args.image_sha256,
            "firmwareSHA256": template_pins, "packagesSHA256": packages,
            "driverSHA256": digest(Path(__file__)), "guestProbeSHA256": digest(GUEST),
            "qemuVersion": run(args.qemu, "--version").splitlines()[0].decode("ascii"),
            "guestExternalNetworkDisabled": True, "firstBoot": first, "secondBoot": second,
            "productionQualificationComplete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("image", "old", "new"):
        parser.add_argument(f"--{key}", type=Path, required=True)
        parser.add_argument(f"--{key}-sha256", required=True)
    parser.add_argument("--firmware-code", type=Path, required=True)
    parser.add_argument("--firmware-vars", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--qemu-img", default="qemu-img")
    parser.add_argument("--genisoimage", default="genisoimage")
    parser.add_argument("--qemu-data", type=Path)
    parser.add_argument("--accel", choices=("tcg", "kvm"), default="tcg")
    parser.add_argument("--boot-timeout", type=int, default=240)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.uname().machine == "x86_64", "Expected a Linux AMD64 QEMU host")
    require(30 <= args.boot_timeout <= 600 and all(SHA256.fullmatch(pin) for pin in
            (args.image_sha256, args.old_sha256, args.new_sha256)), "Expected approved SHA-256 pins and a bounded boot time")
    with tempfile.TemporaryDirectory(prefix="accessweaver-package-reboot-") as directory:
        report = exercise(args, Path(directory))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
