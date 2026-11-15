#!/usr/bin/env python3
"""Exercise signed AccessWeaver APT delivery over loopback in private package roots."""
import argparse
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Thread

from verify_release import require

BUILDER = Path(__file__).with_name("build-linux-apt-repository.py")
SUITE = "accessweaver-test"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def command(*argv, env=ENV, expected=None):
    result = subprocess.run(argv, env=env, capture_output=True, timeout=90)
    if expected is None:
        require(result.returncode == 0, f"{Path(argv[0]).name} failed: "
                + result.stderr[-2048:].decode("utf-8", "replace"))
    else:
        require(result.returncode != 0 and expected in result.stderr,
                f"{Path(argv[0]).name} did not reject the fixture as expected")
    return result.stdout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def generate_key(gpg, alias):
    identity = f"AccessWeaver {alias} Fixture <{alias.lower()}@example.invalid>"
    command(*gpg, "--pinentry-mode", "loopback", "--passphrase", "",
            "--quick-generate-key", identity, "ed25519", "cert", "1d")
    listed = command(*gpg, "--with-colons", "--list-keys", identity)
    fingerprint = next(line.split(":")[9] for line in listed.decode().splitlines() if line.startswith("fpr:"))
    command(*gpg, "--pinentry-mode", "loopback", "--passphrase", "",
            "--quick-add-key", fingerprint, "ed25519", "sign", "1d")
    return fingerprint


def publication(path, source, pins, home, keyring, fingerprint, rejection=None):
    approvals = [arg for name, pin in sorted(pins.items()) for arg in ("--package-sha256", name, pin)]
    command(sys.executable, "-B", BUILDER, source, path, "--suite", SUITE,
            "--gnupg-home", home, "--keyring", keyring, "--fingerprint", fingerprint,
            *approvals, expected=rejection)


def apt_client(work, url, keyring, fingerprint):
    root = work / "root"
    config = work / "config"
    database = root / "var/lib/dpkg"
    status = database / "status"
    for directory in (database / "info", database / "updates", work / "state/lists",
                      work / "cache/archives", config / "apt.conf.d", config / "trusted.gpg.d",
                      config / "sources.list.d"):
        directory.mkdir(parents=True)
    status.touch()
    (config / "sources.list.d/accessweaver.sources").write_text(
        f"Types: deb\nURIs: {url}\nSuites: {SUITE}\nComponents: main\nArchitectures: amd64\n"
        f"Signed-By: {keyring} {fingerprint}\n", encoding="ascii")
    options = work / "config.conf"
    options.write_text(
        f'Dir::Etc "{config}";\nDir::State "{work / "state"}";\n'
        f'Dir::State::status "{status}";\nDir::Cache "{work / "cache"}";\n'
        'Dir::Etc::sourcelist "sources.list";\nDir::Etc::sourceparts "sources.list.d";\n'
        'Dir::Etc::main "apt.conf";\nDir::Etc::parts "apt.conf.d";\n'
        'Dir::Etc::trusted "trusted.gpg";\nDir::Etc::trustedparts "trusted.gpg.d";\n'
        'APT::Architecture "amd64";\nAPT::Architectures { "amd64"; };\n'
        'APT::Update::Error-Mode "any";\nAcquire::Languages "none";\n'
        'Acquire::Retries "0";\nAcquire::http::Timeout "10";\nDPkg::Use-Pty "false";\n'
        f'DPkg::Options {{ "--root={root}"; "--admindir={database}"; }};\n',
        encoding="ascii",
    )
    env = dict(ENV, APT_CONFIG=str(options))

    def apt(*args, expected=None):
        return command("/usr/bin/apt-get", *args, env=env, expected=expected)

    return apt, root


def installed_version(root, version):
    query = command("/usr/bin/dpkg-query", f"--root={root}", "-W",
                    "-f=${Status}\t${Version}", "accessweaver")
    require(query.decode() == f"install ok installed\t{version}", "Wrong package version after APT transaction")
    require(not command("/usr/bin/dpkg", f"--root={root}", "--verify", "accessweaver"),
            "APT-installed package failed dpkg verification")
    return digest(root / "usr/bin/accessweaver")


def install_and_upgrade(work, url, keyring, trusted, served, first, upgrade, older, newer):
    apt, root = apt_client(work / "client", url, keyring, trusted)
    policy = root / "etc/accessweaver/installation.json"
    profile = root / "home/fixture/.config/accessweaver/profiles/fixture.json"
    for path, data in ((policy, b'{"fixture":"policy"}\n'), (profile, b'{"fixture":"profile"}\n')):
        path.parent.mkdir(parents=True)
        path.write_bytes(data)
        path.chmod(0o600)
    os.chown(profile, 65534, 65534)

    def state():
        result = []
        for path in (policy, profile):
            info = path.stat()
            result.append((digest(path), info.st_mode, info.st_uid, info.st_gid, info.st_ino))
        return result

    expected = state()
    served[0] = first
    apt("update")
    apt("-y", "install", "accessweaver")
    previous = installed_version(root, older)
    require(state() == expected, "APT installation modified machine policy or user profile")
    served[0] = upgrade
    apt("update")
    apt("-y", "install", "--only-upgrade", "accessweaver")
    current = installed_version(root, newer)
    require(previous != current and state() == expected, "APT upgrade did not preserve policy and profile")
    apt("-y", "purge", "accessweaver")
    require(not (root / "usr/bin/accessweaver").exists() and state() == expected,
            "APT purge did not remove the binary and preserve policy/profile")
    return previous, current


def rejection_cases(work, url, ring, trusted, other, served, valid, gpg, newer):
    # The same keyring contains both test keys. The single scoped fingerprint chooses the authority.
    served[0] = valid
    apt, _ = apt_client(work / "wrong-key", url, ring, other)
    apt("update", expected=b"InRelease")

    damaged = work / "damaged-repository"
    shutil.copytree(valid, damaged)
    signed = damaged / "dists" / SUITE / "InRelease"
    original = signed.read_bytes()
    signed.write_bytes(original.replace(b"Label: AccessWeaver", b"Label: AccessW3aver", 1))
    require(signed.read_bytes() != original, "Failed to alter signed test metadata")
    served[0] = damaged
    apt, _ = apt_client(work / "bad-signature", url, ring, trusted)
    apt("update", expected=b"InRelease")
    signed.write_bytes(original)

    release = signed.with_name("Release")
    previous = datetime.now(timezone.utc) - timedelta(days=2)
    lines = release.read_text(encoding="ascii").splitlines()
    expired = {"Date:": previous, "Valid-Until:": previous + timedelta(days=1)}
    for i, line in enumerate(lines):
        label = line.split(" ", 1)[0]
        if label in expired:
            lines[i] = label + " " + format_datetime(expired[label], usegmt=True)
    release.write_text("\n".join(lines) + "\n", encoding="ascii")
    signed.unlink()
    command(*gpg, "--local-user", trusted, "--digest-algo", "SHA512", "--output", signed, "--clearsign", release)
    apt, _ = apt_client(work / "expired", url, ring, trusted)
    apt("update", expected=b"expired")
    signed.write_bytes(original)

    directory = signed.parent / "main/binary-amd64"
    originals = {}
    for index in (directory / "Packages", directory / "Packages.gz"):
        data = index.read_bytes()
        by_hash = directory / "by-hash/SHA256" / hashlib.sha256(data).hexdigest()
        for entry in (index, by_hash):
            originals[entry] = data
            entry.write_bytes(b"\0" + data[1:])
    apt, _ = apt_client(work / "bad-index", url, ring, trusted)
    apt("update", expected=b"Hash Sum mismatch")
    for entry, data in originals.items():
        entry.write_bytes(data)

    package = damaged / "pool" / f"accessweaver_{newer}_amd64.deb"
    with package.open("r+b") as stream:
        stream.seek(-1, os.SEEK_END)
        byte = stream.read(1)
        stream.seek(-1, os.SEEK_END)
        stream.write(bytes([byte[0] ^ 1]))
    apt, root = apt_client(work / "bad-package", url, ring, trusted)
    apt("update")
    apt("-y", "install", "accessweaver", expected=b"Hash Sum mismatch")
    require(not (root / "usr/bin/accessweaver").exists(), "APT unpacked a modified package")


def exercise(work, packages, pins, older, newer):
    home = work / "gnupg"
    home.mkdir(mode=0o700)
    gpg = ("/usr/bin/gpg", "--homedir", home, "--no-options", "--batch", "--no-tty")
    try:
        trusted = generate_key(gpg, "Approved")
        other = generate_key(gpg, "Unapproved")
        keyring = work / "approved-and-other.gpg"
        keyring.write_bytes(command(*gpg, "--export-options", "export-minimal", "--export", trusted, other))
        keyring.chmod(0o644)
        wrong_keyring = work / "wrong-key.gpg"
        wrong_keyring.write_bytes(command(*gpg, "--export", other))
        old = {name: pin for name, pin in pins.items() if name.startswith(f"accessweaver_{older}_")}
        previous = work / "previous-packages"
        previous.mkdir()
        for name in old:
            shutil.copyfile(packages / name, previous / name)

        first = work / "first"
        current = work / "current"
        failed = work / "must-remain-absent"
        mismatch = dict(pins)
        mismatch[next(iter(mismatch))] = "0" * 64
        publication(failed, packages, mismatch, home, keyring, trusted, b"SHA-256")
        publication(failed, packages, pins, home, wrong_keyring, trusted, b"gpgv failed")
        require(not failed.exists(), "Rejected input published a repository")
        publication(first, previous, old, home, keyring, trusted)
        publication(current, packages, pins, home, keyring, trusted)
        signed = current / "dists" / SUITE / "InRelease"
        first_signed_digest = digest(signed)
        publication(current, packages, pins, home, keyring, trusted, b"File exists")
        require(digest(signed) == first_signed_digest, "Exclusive publication changed the original snapshot")

        served = [first]
        requests = []

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=served[0], **kwargs)

            def send_head(self):
                # Fixture snapshots can be published in the same clock second.
                # Revalidate the mutable pointer by returning its current bytes.
                if self.path.endswith("/InRelease") and "If-Modified-Since" in self.headers:
                    del self.headers["If-Modified-Since"]
                return super().send_head()

            def log_request(self, code="-", size="-"):
                requests.append((getattr(self, "path", ""), code))

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                old_binary, new_binary = install_and_upgrade(
                    work, url, keyring, trusted, served, first, current, older, newer)
                require(any("/by-hash/SHA256/" in path and code == 200 for path, code in requests),
                        "Native APT never fetched an index by its signed hash")
                rejection_cases(work, url, keyring, trusted, other, served, current, gpg, newer)
            finally:
                server.shutdown()
                thread.join()
    finally:
        command("/usr/bin/gpgconf", "--homedir", home, "--kill", "all")
    return {
        "schemaVersion": 1, "scope": "Loopback signed APT publication and isolated Linux AMD64 install lifecycle",
        "builderSHA256": digest(BUILDER), "probeSHA256": digest(Path(__file__)),
        "aptVersion": command("/usr/bin/apt-get", "--version").splitlines()[0].decode("ascii"),
        "packageSHA256": dict(sorted(pins.items())), "olderBinarySHA256": old_binary,
        "newerBinarySHA256": new_binary, "suiteArchitectures": ["amd64", "arm64"],
        "checks": ["approved-signing-subkey-verified-against-primary-fingerprint",
                   "package-pin-and-untrusted-verification-key-rejected-without-publication",
                   "exclusive-publication-preserved-existing-snapshot",
                   "native-apt-fetched-index-by-signed-hash",
                   "signed-install-upgrade-and-purge-preserved-policy-and-profile",
                   "wrong-scoped-key-tampered-signature-and-expired-metadata-rejected",
                   "tampered-index-and-payload-rejected-before-installation"],
        "ephemeralSigningKeys": True, "arm64EndpointExecution": False,
        "productionQualificationComplete": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--older-version", required=True)
    parser.add_argument("--newer-version", required=True)
    parser.add_argument("--package-sha256", action="append", nargs=2, required=True, metavar=("FILENAME", "SHA256"))
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "Run as root on a disposable Linux AMD64 system")
    older, newer = args.older_version, args.newer_version
    require(command("/usr/bin/dpkg", "--print-architecture").strip() == b"amd64", "Expected native Linux AMD64")
    command("/usr/bin/dpkg", "--compare-versions", older, "lt", newer)
    pins = dict(args.package_sha256)
    expected = {f"accessweaver_{version}_{arch}.deb" for version in (older, newer) for arch in ("amd64", "arm64")}
    require(len(args.package_sha256) == 4 and pins.keys() == expected,
            "Supply two approved versions of each architecture")
    with tempfile.TemporaryDirectory(prefix="accessweaver-apt-acceptance-", dir="/var/tmp") as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        result = exercise(work, args.source, pins, older, newer)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
