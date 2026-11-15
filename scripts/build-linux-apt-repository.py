#!/usr/bin/env python3
"""Build and verify a signed APT repository snapshot of approved AccessWeaver packages."""
import argparse
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from verify_release import publish_staged_file, release_file, require, snapshot

PACKAGE_NAME = re.compile(
    r"accessweaver_((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:~(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?)?)_(amd64|arm64)\.deb"
)
FINGERPRINT = re.compile(r"(?:[A-F0-9]{40}|[A-F0-9]{64})")
SHA256 = re.compile(r"[a-f0-9]{64}")
TOOL_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def run(tool, *args, cwd=None):
    result = subprocess.run([f"/usr/bin/{tool}", *args], capture_output=True,
                            timeout=120, env=TOOL_ENV, cwd=cwd)
    require(result.returncode == 0, f"{tool} failed (exit {result.returncode})")
    require(len(result.stdout) <= 2 << 20, f"{tool} output exceeded its limit")
    return result.stdout


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def candidate_indexes(repo, suite, names_and_pins):
    pool = repo / "pool"
    packages = {}
    for name, pin in names_and_pins.items():
        version, arch = PACKAGE_NAME.fullmatch(name).groups()
        package = pool / name
        require(sha256(package) == pin, "Package SHA-256 differs from its approval")
        packages.setdefault(arch, {})[name] = (version, str(package.stat().st_size), pin)

    distribution = repo / "dists" / suite
    checksums = []
    for arch, expected in sorted(packages.items()):
        output = run("dpkg-scanpackages", "--arch", arch, "--multiversion", "--hash",
                     "sha256", "pool", cwd=repo)
        indexed = {}
        for paragraph in output.strip().split(b"\n\n"):
            fields = {}
            for line in paragraph.decode("utf-8").splitlines():
                if not line.startswith((" ", "\t")):
                    key, value = line.split(":", 1)
                    require(key not in fields, "Duplicate field in generated APT index")
                    fields[key] = value.strip()
            name = fields["Filename"].removeprefix("pool/")
            require(name in expected and name not in indexed and fields["Filename"] == f"pool/{name}"
                    and fields["Package"] == "accessweaver" and fields["Architecture"] == arch
                    and (fields["Version"], fields["Size"], fields["SHA256"]) == expected[name],
                    "Generated APT index differs from the approved packages")
            indexed[name] = paragraph
        require(indexed.keys() == expected.keys(), "Generated APT index omitted approved packages")
        index = b"\n\n".join(indexed[name] for name in sorted(indexed)) + b"\n\n"
        directory = distribution / "main" / f"binary-{arch}"
        by_hash = directory / "by-hash" / "SHA256"
        by_hash.mkdir(parents=True)
        for filename, data in (("Packages", index), ("Packages.gz", gzip.compress(index, mtime=0))):
            target = directory / filename
            target.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            (by_hash / digest).write_bytes(data)
            checksums.append(f" {digest} {len(data)} {target.relative_to(distribution).as_posix()}\n")
    return distribution, " ".join(sorted(packages)), checksums


def sign_and_verify(distribution, staging, home, keyring, fingerprint):
    release = distribution / "Release"
    signed = distribution / "InRelease"
    run("gpg", "--homedir", home, "--no-options", "--batch", "--no-tty",
        "--local-user", fingerprint, "--digest-algo", "SHA512",
        "--output", signed, "--clearsign", release)
    verifier = staging / "verify"
    verifier.mkdir(mode=0o700)
    trusted = verifier / "approved.gpg"
    release_file(keyring, 1 << 20)
    shutil.copyfile(keyring, trusted)
    plaintext = verifier / "Release"
    status = run("gpgv", "--homedir", verifier, "--keyring", trusted, "--status-fd", "1",
                 "--output", plaintext, signed)
    records = [line.split(maxsplit=2)[1:] for line in status.decode("utf-8").splitlines()
               if line.startswith("[GNUPG:] ")]
    signatures = [record[1].split() for record in records if record[0] == "VALIDSIG"]
    bad_status = {"BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "ERRSIG", "NO_PUBKEY"}
    require(len(signatures) == 1 and len(signatures[0]) >= 10
            and signatures[0][9] == fingerprint and signatures[0][7] in ("8", "9", "10")
            and not {record[0] for record in records} & bad_status,
            "APT Release signature does not match the approved primary key")
    require(plaintext.read_bytes() == release.read_bytes(), "Signed Release differs from the generated metadata")


def build(source, pins, suite, home, keyring, fingerprint, destination, valid_days):
    require(1 <= len(pins) <= 16 and all(len(name) < 110 and PACKAGE_NAME.fullmatch(name)
                and SHA256.fullmatch(pin) for name, pin in pins.items()),
            "Expected one to sixteen canonical AccessWeaver package names and SHA-256 digests")
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,62}", suite), "Expected a lowercase APT suite name")
    require(FINGERPRINT.fullmatch(fingerprint), "Expected the approved uppercase OpenPGP primary fingerprint")
    require(1 <= valid_days <= 30, "APT metadata validity must be between 1 and 30 days")
    require(home.is_dir() and not home.is_symlink(), "Expected an existing private GnuPG signing home")
    home = home.resolve(strict=True)
    require(destination.name not in ("", "..") and destination.parent.is_dir()
            and not destination.parent.is_symlink(), "Expected a new snapshot in an existing output directory")
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    parent_identity = parent.stat()

    with tempfile.TemporaryDirectory(prefix=".accessweaver-apt-", dir=parent) as temporary:
        staging = Path(temporary)
        repo = staging / "repository"
        pool = repo / "pool"
        pool.mkdir(parents=True)
        require(snapshot(source, pool, len(pins)) == pins.keys(), "Package directory differs from the approval inventory")
        distribution, architectures, checksums = candidate_indexes(repo, suite, pins)
        now = datetime.now(timezone.utc)
        expiration = now + timedelta(days=valid_days)
        release = (f"Origin: AccessWeaver\nLabel: AccessWeaver\nSuite: {suite}\nCodename: {suite}\n"
                   f"Date: {format_datetime(now, usegmt=True)}\n"
                   f"Valid-Until: {format_datetime(expiration, usegmt=True)}\n"
                   f"Architectures: {architectures}\nComponents: main\nAcquire-By-Hash: yes\n"
                   "SHA256:\n" + "".join(checksums))
        (distribution / "Release").write_text(release, encoding="ascii")
        sign_and_verify(distribution, staging, home, keyring, fingerprint)
        repo.chmod(0o755)
        for path in repo.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        current = parent.stat()
        require((current.st_dev, current.st_ino) == (parent_identity.st_dev, parent_identity.st_ino)
                and not parent.is_symlink(), "Output directory changed during repository build")
        publish_staged_file(repo, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--package-sha256", action="append", nargs=2, required=True, metavar=("FILENAME", "SHA256"))
    parser.add_argument("--suite", required=True)
    parser.add_argument("--gnupg-home", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True, help="Independently approved binary public keyring")
    parser.add_argument("--fingerprint", required=True, help="Approved full uppercase primary key fingerprint")
    parser.add_argument("--valid-days", type=int, default=7)
    args = parser.parse_args()
    try:
        pins = dict(args.package_sha256)
        require(len(pins) == len(args.package_sha256), "Duplicate package approval")
        build(args.source_directory, pins, args.suite, args.gnupg_home, args.keyring,
              args.fingerprint, args.destination, args.valid_days)
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"APT repository build failed: {error}\n")
    print(args.destination)


if __name__ == "__main__":
    main()
