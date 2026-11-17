#!/usr/bin/env python3
"""Prepare a private Ubuntu cloud-image clone for slow offline QEMU lifecycle tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from verify_release import publish_staged_file, release_file, require

MAX_DISK = 8 << 30
LINUX_FILESYSTEM = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
UNIT = """[Unit]
Description=AccessWeaver isolated ARM64 reboot fixture
After=local-fs.target systemd-udev-trigger.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/accessweaver-reboot-qualification
TimeoutStartSec=480
StandardError=journal+console

[Install]
WantedBy=multi-user.target
"""
ENTRY = """#!/bin/sh
set -eu
seed=/dev/disk/by-label/cidata
device=
for attempt in $(seq 1 60); do
    for node in /sys/class/net/*; do
        if [ -r "$node/address" ] && read -r address < "$node/address" && [ "$address" = "52:54:00:ac:ce:55" ]; then
            device="${node##*/}"
            break
        fi
    done
    if [ -n "$device" ] && [ -b "$seed" ]; then
        break
    fi
    sleep 2
done
if [ -z "$device" ] || [ ! -b "$seed" ]; then
    echo "The fixture NIC or seed device did not become available" >&2
    exit 1
fi
if [ "$device" != awfixture0 ]; then
    ip link set "$device" down
    ip link set "$device" name awfixture0
fi
ip link set lo up
ip link set awfixture0 up
install -d -m 0755 /run/accessweaver-seed
mount -t iso9660 -o ro,nodev,nosuid,noexec "$seed" /run/accessweaver-seed
exec /usr/bin/python3 -B /run/accessweaver-seed/guest.py
"""


def run(*args):
    result = subprocess.run(args, capture_output=True, check=False, timeout=120)
    require(result.returncode == 0, f"{Path(args[0]).name} failed: " + result.stderr[-2048:].decode("utf-8", "replace").strip())
    return result.stdout.decode("utf-8"), result.stderr.decode("utf-8", "replace")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def root_range(raw):
    table = json.loads(run("sfdisk", "--json", raw)[0])["partitiontable"]
    sector_size = table["sectorsize"]
    roots = [part for part in table["partitions"] if part.get("type") == LINUX_FILESYSTEM]
    require(table["label"] == "gpt" and sector_size in (512, 4096) and len(roots) == 1,
            "Expected a single Linux root partition in the Ubuntu GPT layout")
    offset, length = roots[0]["start"] * sector_size, roots[0]["size"] * sector_size
    require(offset > 0 and length > 0 and offset + length <= raw.stat().st_size, "Invalid root partition bounds")
    return offset, length


def prepare_guest_root(work, partition):
    def readonly(command):
        return run("debugfs", "-R", command, partition)[0]

    require("Type: regular" in readonly("stat /usr/bin/dpkg")
            and "Type: directory" in readonly("stat /etc/cloud")
            and "Type: directory" in readonly("stat /etc/systemd/system")
            and not readonly("stat /etc/accessweaver"), "Expected a fresh Ubuntu Minimal root")
    inputs = {"cloud-init.disabled": "", "fixture.service": UNIT, "fixture-entry": ENTRY}
    for name, data in inputs.items():
        (work / name).write_text(data, encoding="ascii")

    parent = "/etc/systemd/system/multi-user.target.wants"
    entry = "/usr/local/libexec/accessweaver-reboot-qualification"
    operations = [f"mkdir {target}" for target in ("/usr/local/libexec", parent)
                  if "Type: directory" not in readonly("stat " + target)]
    operations.extend((
        f"write {work / 'cloud-init.disabled'} /etc/cloud/cloud-init.disabled",
        f"write {work / 'fixture.service'} /etc/systemd/system/accessweaver-reboot-qualification.service",
        f"write {work / 'fixture-entry'} {entry}",
        f"set_inode_field {entry} mode 0100755",
        f"symlink {parent}/accessweaver-reboot-qualification.service ../accessweaver-reboot-qualification.service",
        "symlink /etc/systemd/system/systemd-networkd-wait-online.service /dev/null",
        "symlink /etc/systemd/system/pollinate.service /dev/null",
    ))
    script = work / "debugfs.commands"
    script.write_text("\n".join(operations) + "\n", encoding="ascii")
    _, diagnostic = run("debugfs", "-w", "-f", script, partition)
    require(not any(error in diagnostic for error in ("File not found", "already exists", "Invalid argument")),
            "Could not prepare the guest bootstrap files")
    require(readonly("cat " + entry) == ENTRY and "Mode:  0755" in readonly("stat " + entry)
            and "Type: symlink" in readonly(f"stat {parent}/accessweaver-reboot-qualification.service"),
            "Prepared guest bootstrap did not match the requested service")


def prepare(image, expected, destination, qemu_img):
    size = release_file(image, MAX_DISK).st_size
    require(not os.path.lexists(destination), "Prepared output already exists")
    with tempfile.TemporaryDirectory(prefix="accessweaver-preseed-", dir="/var/tmp") as temporary:
        work = Path(temporary)
        snapshot = work / "authenticated.qcow2"
        with image.open("rb") as source, snapshot.open("xb") as target:
            total = 0
            for block in iter(lambda: source.read(1 << 20), b""):
                total += len(block)
                require(total <= size, "Image grew during staging")
                target.write(block)
        require(total == size and digest(snapshot) == expected, "Image does not match its authenticated digest")
        snapshot.chmod(0o444)
        metadata = json.loads(run(qemu_img, "info", "--output=json", snapshot)[0])
        require(metadata.get("format") == "qcow2" and 0 < metadata["virtual-size"] <= MAX_DISK
                and not metadata.get("backing-filename")
                and not metadata.get("format-specific", {}).get("data", {}).get("data-file"),
                "Expected a bounded self-contained Ubuntu QCOW2 image")
        raw = work / "base.raw"
        run(qemu_img, "convert", "-f", "qcow2", "-O", "raw", snapshot, raw)
        offset, length = root_range(raw)
        partition = work / "root.ext4"
        run("dd", f"if={raw}", f"of={partition}", f"skip={offset}", f"count={length}", "bs=4M",
            "iflag=skip_bytes,count_bytes", "conv=sparse", "status=none")
        prepare_guest_root(work, partition)
        require(partition.stat().st_size == length, "Guest root partition size changed")
        run("dd", f"if={partition}", f"of={raw}", f"seek={offset}", "bs=4M", "oflag=seek_bytes", "conv=notrunc", "status=none")

        with tempfile.TemporaryDirectory(prefix=".accessweaver-preseed-", dir=destination.parent) as staged:
            candidate = Path(staged) / "prepared.qcow2"
            run(qemu_img, "convert", "-f", "raw", "-O", "qcow2", raw, candidate)
            prepared_sha256 = digest(candidate)
            publish_staged_file(candidate, destination)
    return {"schemaVersion": 1, "authenticatedImageSHA256": expected,
            "preparedImageSHA256": prepared_sha256, "preparationSourceSHA256": digest(Path(__file__))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--image-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--qemu-img", default="qemu-img")
    args = parser.parse_args()
    require(re.fullmatch(r"[a-f0-9]{64}", args.image_sha256), "Expected an authenticated image SHA-256")
    print(json.dumps(prepare(args.image, args.image_sha256, args.output, args.qemu_img), indent=2))


if __name__ == "__main__":
    main()
