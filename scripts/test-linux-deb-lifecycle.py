#!/usr/bin/env python3
"""Exercise the AccessWeaver Debian package in a private dpkg root on native Linux."""
import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

from linux_package_managed_fixture import ManagedPackageFixture
import linux_package_traffic_fixture as traffic
from verify_release import require

BUILDER = Path(__file__).with_name("build-linux-deb.py")
CONTACT = "AccessWeaver Fixture <package-fixture@example.invalid>"
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
MACHINE_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}


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


def exercise(work, arch, old, old_pin, new, new_pin, other, other_pin, byedpi=None):
    other_arch = "arm64" if arch == "amd64" else "amd64"
    builds = work / "packages"
    builds.mkdir()
    build(old, "0" * 64, arch, builds, b"Portable archive SHA-256 mismatch")
    require(not list(builds.iterdir()), "Rejected source left package output")
    before = build(old, old_pin, arch, builds)
    after = build(new, new_pin, arch, builds)
    cross_package = build(other, other_pin, other_arch, builds)
    before_version, before_payload = inspect(before, arch)
    after_version, after_payload = inspect(after, arch)
    cross_version, cross_payload = inspect(cross_package, other_arch)
    run("/usr/bin/dpkg", "--compare-versions", before_version, "lt", after_version)
    if "~" in after_version:
        run("/usr/bin/dpkg", "--compare-versions", after_version, "lt", after_version.split("~")[0])
    build(old, old_pin, arch, builds, b"File exists")
    repeat_directory = work / "repeat"
    repeat_directory.mkdir()
    repeat = build(old, old_pin, arch, repeat_directory)
    require(sha(before) == sha(repeat), "Repeat builds disagree or exclusive publication altered the first package")

    root = work / "root"
    database = root / "var/lib/dpkg"
    database.mkdir(parents=True)
    for name in ("info", "updates"):
        (database / name).mkdir()
    (database / "status").touch()
    dpkg = ("/usr/bin/dpkg", f"--root={root}", f"--admindir={database}")

    def install(path, version, payload, downgrade="--refuse-downgrade"):
        run(*dpkg, downgrade, "--install", path)
        install_state(root, version, payload)
        require(not run(*dpkg, "--verify", "accessweaver"), "dpkg failed installed file verification")

    install(before, before_version, before_payload)
    managed = ManagedPackageFixture(root, byedpi)
    managed.verify()
    traffic_stages = []

    def prove_engine(stage):
        if byedpi is not None:
            traffic.roundtrip_and_stop(managed)
            traffic_stages.append(stage)

    prove_engine("before-upgrade")

    def transition(path, version, payload, downgrade="--refuse-downgrade"):
        prior = managed.state()
        install(path, version, payload, downgrade)
        managed.verify()
        require(managed.state() == prior, "Package transition changed enrolled policy or profile")

    transition(after, after_version, after_payload)
    managed.advance()
    managed.verify()
    prove_engine("after-upgrade")
    transition(after, after_version, after_payload)
    transition(before, after_version, after_payload)
    transition(before, before_version, before_payload, "--force-downgrade")
    managed.refuse_replay()
    prove_engine("after-rollback")

    def purge():
        prior = managed.state()
        run(*dpkg, "--purge", "accessweaver")
        require(not (root / "usr/bin/accessweaver").exists()
                and not (root / "usr/share/doc/accessweaver").exists()
                and "Package: accessweaver" not in (database / "status").read_text(encoding="utf-8")
                and not run(*dpkg, "--audit"), "Uninstall left package registration, payload or an incomplete transaction")
        require(managed.state() == prior, "Uninstall changed enrolled policy or profile")

    purge()
    transition(after, after_version, after_payload)
    prove_engine("after-purge-and-reinstall")
    purge()
    report = {"schemaVersion": 1, "scope": "Isolated unsigned Debian package construction and native Linux dpkg lifecycle",
            "endpointArchitecture": arch,
            "dpkgVersion": run("/usr/bin/dpkg", "--version").splitlines()[0].decode("ascii"),
            "builderSHA256": sha(BUILDER), "probeSHA256": sha(Path(__file__)),
            "packages": [{"arch": target, "version": version, "archiveSHA256": pin, "debSHA256": sha(package),
                          "binarySHA256": payload["usr/bin/accessweaver"], "payloadFiles": len(payload)}
                         for target, version, pin, package, payload in (
                             (arch, before_version, old_pin, before, before_payload),
                             (arch, after_version, new_pin, after, after_payload),
                             (other_arch, cross_version, other_pin, cross_package, cross_payload))],
            "managedRevisionsObserved": [1, managed.revision],
            "managedFixtureSHA256": sha(Path(__file__).with_name("linux_package_managed_fixture.py")),
            "checks": ["mismatched-source-digest-refused-without-output",
                       "amd64-and-arm64-control-and-payload-inspected",
                       "reproducible-package-and-exclusive-publication",
                       "clean-install-upgrade-and-same-version-reinstall",
                       "ordinary-user-installed-cli-identity-after-each-change",
                       "dpkg-verify-after-each-change",
                       "guarded-downgrade-refusal-and-explicit-rollback",
                       "purge-and-package-registration-removal",
                       "enrollment-and-profile-created-with-first-installed-controller",
                       "new-controller-advanced-policy-and-older-rollback-refused-replay",
                       "ordinary-mutation-and-engine-launch-denied-through-installed-controllers",
                       "enrolled-policy-and-profile-preserved-through-purge-and-reinstall"],
            "amd64Execution": arch == "amd64", "arm64Execution": arch == "arm64",
            "productionQualificationComplete": False}
    if byedpi is not None:
        report["liveByedpi"] = {
            "engineSHA256": hashlib.sha256(byedpi).hexdigest(),
            "probeSHA256": sha(Path(traffic.__file__)),
            "sharedNetworkProbeSHA256": sha(Path(traffic.__file__).with_name("test-linux-managed-byedpi.py")),
            "socksAndShutdownVerifiedAt": traffic_stages,
            "trafficWasLoopbackOnly": True,
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=sorted(MACHINE_ARCH.values()))
    for name in ("old", "new"):
        parser.add_argument(f"--{name}", required=True, type=Path)
        parser.add_argument(f"--{name}-sha256", required=True)
    parser.add_argument("--other", "--arm64", required=True, type=Path)
    parser.add_argument("--other-sha256", "--arm64-sha256", required=True)
    parser.add_argument("--byedpi", type=Path, help="Approved native static ByeDPI executable")
    parser.add_argument("--byedpi-sha256", help="Approved SHA-256 for --byedpi")
    parser.add_argument("--live-namespaces", nargs=3, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "Run on a disposable Linux system as root")
    arch = MACHINE_ARCH.get(platform.machine())
    require(arch is not None and args.arch in (None, arch)
            and run("/usr/bin/dpkg", "--print-architecture").strip() == arch.encode("ascii"),
            "Kernel and dpkg must match the requested native architecture")
    require((args.byedpi is None) == (args.byedpi_sha256 is None), "Supply both ByeDPI arguments")
    byedpi = None
    if args.byedpi is not None:
        require(re.fullmatch(r"[a-f0-9]{64}", args.byedpi_sha256), "Expected the approved ByeDPI SHA-256")
        if args.live_namespaces is None:
            raise SystemExit(traffic.run_private(Path(__file__).resolve()))
        byedpi = traffic.prepare_byedpi(args.byedpi, args.byedpi_sha256, args.live_namespaces)
    with tempfile.TemporaryDirectory(prefix="accessweaver-deb-acceptance-", dir="/var/tmp") as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        result = exercise(work, arch, args.old, args.old_sha256, args.new, args.new_sha256,
                          args.other, args.other_sha256, byedpi)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
