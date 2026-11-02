#!/usr/bin/env python3
"""Bounded APFS pressure only on an explicitly opted-in disposable hosted Mac."""
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

DEVICE = re.compile(r"/dev/disk[0-9]+(?:s[0-9]+)?")
BASE_DEVICE = re.compile(r"/dev/disk[0-9]+")
HDIUTIL = "/usr/bin/hdiutil"


def association(info, image, mount):
    """Require one image association and one exact mounted volume, never a guess."""
    images = [i for i in info.get("images", []) if i.get("image-path") == str(image)]
    if len(images) != 1:
        raise RuntimeError("Expected one association for the exclusively created image")
    entities = images[0].get("system-entities", [])
    volumes = [e for e in entities if e.get("mount-point") == str(mount)]
    bases = [e["dev-entry"] for e in entities if BASE_DEVICE.fullmatch(e.get("dev-entry", ""))]
    if len(volumes) != 1 or not bases:
        raise RuntimeError("Expected an exact mounted volume and image base device")
    device = volumes[0].get("dev-entry", "")
    if not DEVICE.fullmatch(device):
        raise RuntimeError("Unexpected image volume device")
    return bases[0], device


def command(args, timeout=90, check=True, env=None):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, env=env)
    if len(result.stdout) + len(result.stderr) > 1 << 20:
        raise RuntimeError("Native tool output exceeds its evidence bound")
    if check and result.returncode:
        raise RuntimeError("Native command failed: " + args[0] + " " + args[1] +
                           ": " + (result.stdout + result.stderr).decode("utf-8", "replace")[:8192])
    return result


def info():
    return plistlib.loads(command([HDIUTIL, "info", "-plist"]).stdout)


def guarded_directory(path, owner):
    entry = path.lstat()
    if path.is_symlink() or not path.is_dir() or entry.st_uid != owner or entry.st_mode & 0o022:
        raise RuntimeError("Unsafe owned test directory")
    return entry


def help_evidence(result, requested_flag):
    body = result.stdout + result.stderr
    if not body or result.returncode < 0:
        raise RuntimeError("Native help failed or was empty")
    return {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
            "statusCode": result.returncode,
            "basicHelpListsRequestedFlag": requested_flag in body}


def main():
    if (os.environ.get("ACCESSWEAVER_DISPOSABLE_DARWIN_STORAGE_TEST") != "1" or
        os.environ.get("GITHUB_ACTIONS") != "true" or
        os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
        os.environ.get("RUNNER_OS") != "macOS" or platform.system() != "Darwin" or os.geteuid() == 0):
        raise RuntimeError("Refusing storage pressure outside an ordinary-user disposable hosted Mac")
    repo = Path(__file__).resolve().parents[1]
    if Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve() != repo:
        raise RuntimeError("Unexpected hosted workspace")
    source = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise RuntimeError("Expected exact source identity")
    actual = command(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.decode().strip()
    if actual != source or command(["git", "-C", str(repo), "status", "--porcelain"]).stdout.strip():
        raise RuntimeError("Expected clean exact-source checkout")
    if shutil.disk_usage(repo).free < 4 << 30:
        raise RuntimeError("Insufficient host reserve for a bounded image")
    sdk = json.loads(command(["go", "env", "-json", "GOARCH", "GOHOSTARCH", "GOOS", "GOHOSTOS", "GOVERSION"]).stdout)
    arch = sdk.get("GOARCH")
    if (arch not in ("amd64", "arm64") or sdk.get("GOHOSTARCH") != arch or
        sdk.get("GOOS") != "darwin" or sdk.get("GOHOSTOS") != "darwin" or
        os.environ.get("ACCESSWEAVER_EXPECT_GOARCH") != arch or
        sdk.get("GOVERSION") != "go" + os.environ.get("GO_VERSION", "")):
        raise RuntimeError("Expected the verified native matrix SDK: " + json.dumps(sdk))
    output = repo / "build" / "darwin-storage-checks"
    output.mkdir(mode=0o755, parents=True, exist_ok=True)
    guarded_directory(output, os.geteuid())
    tools = output / ("native-tools-" + arch + ".json")
    if tools.exists():
        raise RuntimeError("Refusing existing native tool evidence")
    help_hashes = {}
    for verb, required in [("create", b"-fs"), ("attach", b"-owners")]:
        help_hashes[verb] = help_evidence(command([HDIUTIL, verb, "-help"], check=False), required)
    tools.write_text(json.dumps({"schemaVersion": 1, "sourceCommit": source, "arch": arch,
                                "sdk": sdk, "nativeHelp": help_hashes,
                                "productionQualificationComplete": False}, indent=2) + "\n", encoding="utf-8")
    parent = repo / "build" / "storage-capsules"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    guarded_directory(parent, os.geteuid())
    if parent.resolve() != parent or repo not in parent.resolve().parents:
        raise RuntimeError("Capsule parent must remain inside the canonical workspace")
    capsule = Path(tempfile.mkdtemp(prefix="apfs-full-", dir=parent)).resolve()
    identity = guarded_directory(capsule, os.geteuid())
    image = capsule / "pressure.sparseimage"
    mount = capsule / "mount"
    mount.mkdir(mode=0o700)
    report = output / ("apfs-exhaustion-" + arch + ".json")
    lifecycle = output / ("image-lifecycle-" + arch + ".json")
    if report.exists() or lifecycle.exists():
        raise RuntimeError("Refusing existing storage evidence")
    binary = capsule / "managed-storage.test"
    build_env = dict(os.environ, CGO_ENABLED="0")
    command(["go", "test", "-c", "-o", str(binary), "./internal/managed"], timeout=180, env=build_env)
    record = {"schemaVersion": 1, "sourceCommit": source, "arch": arch,
              "imageVirtualBytes": 512 << 20, "nativeToolHelp": help_hashes, "productionQualificationComplete": False,
              "attached": False, "detached": False, "ownedImageRemoved": False,
              "rootMachinePolicyChanged": False, "hostVolumePressureApplied": False}
    failure = None
    attached = False
    image_stat = None
    def interrupted(_number, _frame):
        raise KeyboardInterrupt("Disposable storage test interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    os.chdir(repo)
    try:
        command([HDIUTIL, "create", "-size", "512m", "-type", "SPARSE", "-fs", "APFS",
                 "-volname", "AWStorage-" + capsule.name, str(image)])
        image_stat = image.lstat()
        if not image.is_file() or image.is_symlink() or image_stat.st_uid != os.geteuid():
            raise RuntimeError("Unexpected image identity")
        # The only attach target is the new owned image, never an existing device.
        command([HDIUTIL, "attach", "-plist", "-nobrowse", "-owners", "on",
                 "-mountpoint", str(mount), str(image)])
        attached = True
        base_device, volume_device = association(info(), image, mount)
        record.update(attached=True, imageDevice=base_device, volumeDevice=volume_device)
        mounted = mount.stat()
        volume = os.statvfs(mount)
        if mounted.st_dev == image_stat.st_dev or volume.f_frsize <= 0 or not 0 < volume.f_blocks * volume.f_frsize <= 1 << 30:
            raise RuntimeError("Refusing an unbounded or host mount before root setup")
        command(["/usr/bin/sudo", "-n", "/usr/sbin/chown", "0:0", str(mount)])
        command(["/usr/bin/sudo", "-n", "/bin/chmod", "0755", str(mount)])
        record["onlyOwnedImageRootProtectionSet"] = True
        receipt = {"schemaVersion": 1, "sourceCommit": source, "capsule": str(capsule),
                   "mount": str(mount), "volumeDevice": volume_device,
                   "image": str(image), "imageDev": image_stat.st_dev, "imageIno": image_stat.st_ino,
                   "maximumVolumeBytes": 1 << 30, "report": str(report)}
        receipt_path = capsule / "receipt.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        # Keep native tool evidence from this exact host; do not infer mount flags.
        command(["/usr/bin/sudo", "-n", "env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                 "LANG=C", "LC_ALL=C", "TZ=UTC", "GITHUB_ACTIONS=true",
                 "RUNNER_ENVIRONMENT=github-hosted", "RUNNER_OS=macOS", "GITHUB_SHA=" + source, "GITHUB_WORKSPACE=" + str(repo),
                 "ACCESSWEAVER_DISPOSABLE_DARWIN_STORAGE_TEST=1",
                 "ACCESSWEAVER_DARWIN_STORAGE_RECEIPT=" + str(receipt_path), str(binary),
                 "-test.run=^TestDisposableDarwinAPFSExhaustion$", "-test.timeout=8m", "-test.v"],
                timeout=510)
        if not report.is_file():
            raise RuntimeError("Native test produced no exhaustion evidence")
        result = json.loads(report.read_text(encoding="utf-8"))
        if result.get("sourceCommit") != source or len(result.get("cases", [])) != 8:
            raise RuntimeError("Native evidence identity/count mismatch")
        record["nativeCasesPassed"] = 8
    except BaseException as error:
        failure = error
    finally:
        try:
            associated = image.exists() and any(i.get("image-path") == str(image) for i in info().get("images", []))
            if attached or associated:
                # Rebind the exact device to our image before detaching. Never force
                # eject an unidentified/busy device and never recurse into a mount.
                base_device, _ = association(info(), image, mount)
                command([HDIUTIL, "detach", base_device])
                if any(i.get("image-path") == str(image) for i in info().get("images", [])):
                    raise RuntimeError("Owned image remains attached")
                record["detached"] = True
            if image.exists():
                if image_stat is None:
                    raise RuntimeError("Preserving image without a verified creation identity")
                if any(i.get("image-path") == str(image) for i in info().get("images", [])):
                    raise RuntimeError("Refusing deletion of an associated image")
                if mount.exists() and mount.stat().st_dev != image_stat.st_dev:
                    raise RuntimeError("Refusing image deletion while the mount point is on another device")
                current = image.lstat()
                if image.is_symlink() or not image.is_file() or current.st_dev != image_stat.st_dev or current.st_ino != image_stat.st_ino:
                    raise RuntimeError("Refusing changed image cleanup")
                if attached and not record["detached"]:
                    raise RuntimeError("Refusing mounted image deletion")
                image.unlink()
                record["ownedImageRemoved"] = True
            current = capsule.lstat()
            if capsule.parent != parent.resolve() or current.st_dev != identity.st_dev or current.st_ino != identity.st_ino:
                raise RuntimeError("Owned capsule identity changed")
        except BaseException as cleanup_error:
            record["cleanupFailed"] = True
            if failure is None:
                failure = cleanup_error
            else:
                print("Storage fixture cleanup failed: " + str(cleanup_error), file=sys.stderr)
        lifecycle.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if failure is not None:
        raise failure
    print("Eight native APFS ENOSPC cases passed; exact owned image detached and removed")


if __name__ == "__main__":
    main()
