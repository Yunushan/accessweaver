#!/usr/bin/env python3
"""Exercise the AccessWeaver Debian package in a private dpkg root on Linux AMD64."""
import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import subprocess
import sys
import tarfile
import tempfile

from verify_release import require

BUILDER = Path(__file__).with_name("build-linux-deb.py")
CONTACT = "AccessWeaver Fixture <package-fixture@example.invalid>"
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
AMD64 = "amd64"
ARM64 = "arm64"


def run(*args, **options):
    result = subprocess.run(args, capture_output=True, timeout=180, env=COMMAND_ENV, **options)
    if result.returncode:
        diagnostic = result.stderr[-2048:].decode("utf-8", "replace").strip()
        raise ValueError(f"{Path(args[0]).name} exited {result.returncode}: {diagnostic}")
    return result.stdout


def sha(file):
    with file.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def build(archive, pin, arch, output, rejection=None):
    command = [sys.executable, "-B", BUILDER, archive, "--sha256", pin, "--arch", arch,
               "--maintainer", CONTACT, "--output-directory", output]
    if rejection:
        result = subprocess.run(command, capture_output=True, timeout=180, env=COMMAND_ENV)
        require(result.returncode == 1 and rejection in result.stderr, "Unexpected package builder rejection")
        return
    return Path(os.fsdecode(run(*command).rstrip(b"\n")))


def inspect(package, arch):
    info = {}
    for field in ("Package", "Architecture", "Version"):
        info[field] = run("/usr/bin/dpkg-deb", "--field", package, field).decode("ascii").strip()
    require(info["Package"] == "accessweaver" and info["Architecture"] == arch, "Wrong native package registration")
    controls = run("/usr/bin/dpkg-deb", "--ctrl-tarfile", package)
    with tarfile.open(fileobj=BytesIO(controls)) as archive:
        require({str(PurePosixPath(item.name)) for item in archive} == {".", "control", "md5sums"},
                "Unexpected install hooks or control files")

    recorded = {}
    with subprocess.Popen(["/usr/bin/dpkg-deb", "--fsys-tarfile", package],
                          stdout=subprocess.PIPE, env=COMMAND_ENV) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for item in archive:
                name = PurePosixPath(item.name)
                binary = name == PurePosixPath("usr/bin/accessweaver")
                docs = name.is_relative_to("usr/share/doc/accessweaver")
                parents = {".", "usr", "usr/bin", "usr/share", "usr/share/doc"}
                require(item.uid == item.gid == 0 and not name.is_absolute()
                        and ".." not in name.parts and (binary or docs or str(name) in parents and item.isdir()),
                        "Package payload extends beyond the controller and documentation")
                if item.isdir():
                    require(item.mode == 0o755, "Unexpected package directory mode")
                else:
                    require(item.isfile() and item.mode == (0o755 if binary else 0o644),
                            "Unexpected package file type or mode")
                    require(str(name) not in recorded, "Unexpected duplicate payload path")
                    with archive.extractfile(item) as stream:
                        recorded[str(name)] = hashlib.file_digest(stream, "sha256").hexdigest()
        require(process.wait(timeout=30) == 0, "Failed to inspect native payload")
    expected = {"usr/bin/accessweaver"}
    expected.update("usr/share/doc/accessweaver/" + name for name in (
        "BUILD-INFO.json", "SBOM.cdx.json", "copyright", "THIRD_PARTY.md",
        "SECURITY.md", "licenses/Go-runtime-LICENSE"))
    require(expected <= recorded.keys(), "Package is missing the controller, metadata or notices")
    return info["Version"], recorded


def install_state(root, package_version, payload):
    status = run("/usr/bin/dpkg-query", f"--root={root}", "--showformat=${Status}\t${Version}", "--show", "accessweaver")
    require(status.decode() == f"install ok installed\t{package_version}", "Unexpected installed package status/version")
    installed = root / "usr/bin/accessweaver"
    metadata = root / "usr/share/doc/accessweaver/BUILD-INFO.json"
    actual = run(installed, "version", "--json", user=65534, group=65534, extra_groups=[])
    require(json.loads(actual) == json.loads(metadata.read_bytes()), "Installed ordinary-user CLI reports a different identity")
    for name, digest in payload.items():
        path = root / name
        item = path.lstat()
        mode = 0o755 if path == installed else 0o644
        require(item.st_uid == item.st_gid == 0 and stat.S_ISREG(item.st_mode)
                and stat.S_IMODE(item.st_mode) == mode and sha(path) == digest,
                "Installed file differs from the inspected package payload")


def exercise(work, old, old_pin, new, new_pin, arm, arm_pin):
    builds = work / "packages"
    builds.mkdir()
    build(old, "0" * 64, AMD64, builds, b"Portable archive SHA-256 mismatch")
    require(not list(builds.iterdir()), "Rejected source left package output")
    before = build(old, old_pin, AMD64, builds)
    after = build(new, new_pin, AMD64, builds)
    arm64 = build(arm, arm_pin, ARM64, builds)
    before_version, before_payload = inspect(before, AMD64)
    after_version, after_payload = inspect(after, AMD64)
    arm_version, arm_payload = inspect(arm64, ARM64)
    run("/usr/bin/dpkg", "--compare-versions", before_version, "lt", after_version)
    if "~" in after_version:
        run("/usr/bin/dpkg", "--compare-versions", after_version, "lt", after_version.split("~")[0])
    build(old, old_pin, AMD64, builds, b"File exists")
    other = work / "repeat"
    other.mkdir()
    repeat = build(old, old_pin, AMD64, other)
    require(sha(before) == sha(repeat), "Repeat builds disagree or exclusive publication altered the first package")

    root = work / "root"
    database = root / "var/lib/dpkg"
    database.mkdir(parents=True)
    for name in ("info", "updates"):
        (database / name).mkdir()
    (database / "status").touch()
    preserved = {root / "etc/accessweaver/installation.json": b'{"fixture":"protected-installation"}\n',
                 root / "etc/accessweaver/acceptance.json": b'{"fixture":"protected-acceptance"}\n',
                 root / "home/fixture/.config/accessweaver/profiles/fixture.json": b'{"fixture":"user-profile"}\n'}
    for path, data in preserved.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
        if path.is_relative_to(root / "home"):
            os.chown(path, 65534, 65534)

    def preserved_state():
        return {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode),
                       path.stat().st_uid, path.stat().st_gid, path.stat().st_ino)
                for path in preserved}

    expected = preserved_state()
    dpkg = ("/usr/bin/dpkg", f"--root={root}", f"--admindir={database}")
    for path, version, payload, downgrade in (
            (before, before_version, before_payload, "--refuse-downgrade"),
            (after, after_version, after_payload, "--refuse-downgrade"),
            (after, after_version, after_payload, "--refuse-downgrade"),
            (before, after_version, after_payload, "--refuse-downgrade"),
            (before, before_version, before_payload, "--force-downgrade")):
        run(*dpkg, downgrade, "--install", path)
        install_state(root, version, payload)
        require(not run(*dpkg, "--verify", "accessweaver"), "dpkg failed installed file verification")
        require(preserved_state() == expected, "Install or rollback changed policy or profile state")

    run(*dpkg, "--purge", "accessweaver")
    require(not (root / "usr/bin/accessweaver").exists()
            and not (root / "usr/share/doc/accessweaver").exists()
            and "Package: accessweaver" not in (database / "status").read_text(encoding="utf-8")
            and not run(*dpkg, "--audit"), "Uninstall left package registration, payload or an incomplete transaction")
    require(preserved_state() == expected, "Uninstall changed policy or profile state")
    return {"schemaVersion": 1, "scope": "Isolated unsigned Debian package construction and Linux AMD64 dpkg lifecycle",
            "dpkgVersion": run("/usr/bin/dpkg", "--version").splitlines()[0].decode("ascii"),
            "builderSHA256": sha(BUILDER), "probeSHA256": sha(Path(__file__)),
            "packages": [{"arch": arch, "version": version, "archiveSHA256": pin, "debSHA256": sha(package),
                          "binarySHA256": payload["usr/bin/accessweaver"], "payloadFiles": len(payload)}
                         for arch, version, pin, package, payload in (
                             (AMD64, before_version, old_pin, before, before_payload),
                             (AMD64, after_version, new_pin, after, after_payload),
                             (ARM64, arm_version, arm_pin, arm64, arm_payload))],
            "checks": ["mismatched-source-digest-refused-without-output",
                       "amd64-and-arm64-control-and-payload-inspected",
                       "reproducible-package-and-exclusive-publication",
                       "clean-install-upgrade-and-same-version-reinstall",
                       "ordinary-user-installed-cli-identity-after-each-change",
                       "dpkg-verify-after-each-change",
                       "guarded-downgrade-refusal-and-explicit-rollback",
                       "purge-and-package-registration-removal",
                       "synthetic-policy-and-profile-bytes-owner-mode-and-inode-preserved"],
            "amd64Execution": True, "arm64Execution": False, "productionQualificationComplete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("old", "new", "arm64"):
        parser.add_argument(f"--{name}", required=True, type=Path)
        parser.add_argument(f"--{name}-sha256", required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0 and platform.machine() == "x86_64",
            "Run on a disposable Linux AMD64 system as root")
    with tempfile.TemporaryDirectory(prefix="accessweaver-deb-acceptance-") as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        result = exercise(work, args.old, args.old_sha256, args.new, args.new_sha256, args.arm64, args.arm64_sha256)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
