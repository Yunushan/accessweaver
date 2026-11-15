"""Guest-side installed-package reboot acceptance, launched from the read-only fixture ISO."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

SEED = Path("/run/accessweaver-seed")
WORK = Path("/var/lib/accessweaver-reboot-qualification")
HOME = WORK / "user"
PROFILE_ID = "reboot-package-fixture"
PROFILE = HOME / ".config/AccessWeaver/profiles" / (PROFILE_ID + ".json")
POLICY = Path("/etc/accessweaver")
AUTHORITY = (POLICY / "installation.json", POLICY / "acceptance.json", Path("/etc/.accessweaver-policy.lock"))
CORE = Path("/usr/bin/accessweaver")
DATA = Path("/usr/share/accessweaver")
COPYRIGHT = Path("/usr/share/doc/accessweaver/copyright")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC", "HOME": str(HOME)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def command(*args, ordinary=False, rejection=None):
    credentials = dict(user=65534, group=65534, extra_groups=[]) if ordinary else {}
    result = subprocess.run(args, env=ENV, capture_output=True, timeout=60, **credentials)
    operation = f"{Path(args[0]).name}-{args[1]}" if args[0] == CORE else Path(args[0]).name
    if rejection is None:
        require(result.returncode == 0, f"guest-command-{operation}-failed")
    else:
        require(result.returncode != 0 and rejection in result.stderr,
                f"guest-command-{Path(args[0]).name}-did-not-refuse")
    return result.stdout


def cli(*args, **options):
    return command(CORE, *args, **options)


def fingerprint(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "expected-private-state-file")
    return [digest(path), info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]


def state():
    return [fingerprint(path) for path in (*AUTHORITY, PROFILE)]


def package_version():
    status = command("dpkg-query", "-W", "-f", "${Status}\t${Version}", "accessweaver").decode("ascii")
    fields = status.split("\t")
    require(len(fields) == 2 and fields[0] == "install ok installed", "package-registration-missing")
    verification = command("dpkg", "--verify", "accessweaver")
    filters = [
        line.strip().replace("=", " ", 1)
        for path in Path("/etc/dpkg/dpkg.cfg.d").iterdir() if path.is_file()
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    for line in verification.decode("ascii").splitlines():
        result, name = line.split(maxsplit=1)
        require(result == "missing" and "path-exclude /usr/share/doc/*" in filters
                and name.startswith("/usr/share/doc/accessweaver/") and Path(name) != COPYRIGHT,
                "package-verification-found-unexpected-change")
    runtime = json.loads(cli("version", "--json", ordinary=True))
    metadata = json.loads((DATA / "BUILD-INFO.json").read_bytes())
    sbom = json.loads((DATA / "SBOM.cdx.json").read_bytes())
    require(runtime == metadata and runtime["arch"] == "amd64"
            and sbom["metadata"]["component"]["hashes"] == [{"alg": "SHA-256", "content": digest(CORE)}]
            and (DATA / "THIRD_PARTY.md").is_file() and (DATA / "licenses/Go-runtime-LICENSE").is_file()
            and COPYRIGHT.is_file(), "package-operational-metadata-mismatch")
    return fields[1]


def verify_installed(revision, key_id, profile):
    status = json.loads(cli("managed", "status", ordinary=True))
    require(status["valid"] and status["configured"] and status["storageVersion"] == 2
            and status["revision"] == status["acceptedRevision"] == revision
            and status["keyId"] == key_id and status["enforcement"] == "partial",
            "installed-policy-revision-mismatch")
    require(json.loads(cli("show", PROFILE_ID, ordinary=True)) == profile, "installed-profile-readback-mismatch")
    cli("import", WORK / "refused.json", ordinary=True, rejection=b"profile changes are disabled")


def sign(revision, private):
    now = datetime.now(timezone.utc)
    policy = private / f"policy-{revision}.json"
    policy.write_text(json.dumps({"schemaVersion": 1, "revision": revision,
                                  "issuedAt": (now - timedelta(minutes=1)).isoformat(),
                                  "expiresAt": (now + timedelta(hours=2)).isoformat(),
                                  "allowProfileChanges": False, "allowDownloads": False,
                                  "allowDiagnostics": False, "launches": [], "workflows": []}), encoding="ascii")
    envelope = private / f"envelope-{revision}.json"
    cli("managed", "sign", policy, "--private-key", private / "key.pem", "--out", envelope)
    return envelope


def receipt(phase, **fields):
    with open("/dev/ttyS1", "w", encoding="ascii") as serial:
        serial.write("\nACCESSWEAVER-BOOT-V1 " + json.dumps(dict(phase=phase, **fields),
                                                            separators=(",", ":")) + "\n")


def before_reboot(boot, checkpoint):
    require(not POLICY.exists(), "test-image-already-enrolled")
    command("dpkg", "--install", SEED / "older.deb")
    old = package_version()
    WORK.mkdir(mode=0o755, exist_ok=True)
    private = WORK / "private"
    private.mkdir(mode=0o700)
    HOME.mkdir(mode=0o700)
    os.chown(HOME, 65534, 65534)
    profile_input = WORK / "profile.json"
    profile = {"version": 1, "id": PROFILE_ID, "name": "Package reboot fixture", "engine": "byedpi", "args": [],
               "routing": {"includeDomains": [], "excludeDomains": [], "applications": []},
               "probe": {"host": "127.0.0.1", "port": 1080, "tls": False, "timeoutSeconds": 2}}
    profile_input.write_text(json.dumps(profile), encoding="ascii")
    cli("import", profile_input, ordinary=True)
    saved = json.loads(cli("show", PROFILE_ID, ordinary=True))
    profile["id"] = "reboot-refused-fixture"
    (WORK / "refused.json").write_text(json.dumps(profile), encoding="ascii")

    command("openssl", "genpkey", "-algorithm", "ED25519", "-out", private / "key.pem")
    pin = cli("managed", "public-key", "--private-key", private / "key.pem").decode("ascii").strip()
    envelope = sign(1, private)
    installation = private / "installation.json"
    cli("managed", "prepare", envelope, "--public-key", pin, "--minimum-revision", "0", "--out", installation)
    enrolled = json.loads(cli("managed", "install", installation, "--public-key", pin))
    require(enrolled["committed"] is True, "initial-enrollment-did-not-commit")
    key_id = enrolled["keyId"]
    verify_installed(1, key_id, saved)
    prior = state()
    command("dpkg", "--refuse-downgrade", "--install", SEED / "newer.deb")
    new = package_version()
    command("dpkg", "--compare-versions", old, "lt", new)
    verify_installed(1, key_id, saved)
    require(state() == prior, "upgrade-modified-enrollment-or-profile")
    updated = json.loads(cli("managed", "update", sign(2, private)))
    require(updated["committed"] is True and updated["previousRevision"] == 1 and updated["revision"] == 2,
            "policy-update-did-not-commit")
    verify_installed(2, key_id, saved)
    protected = state()
    require(protected[-1] == prior[-1], "policy-update-modified-profile")
    require([entry[2:] for entry in protected] == [[0, 0, 0o644], [0, 0, 0o644], [0, 0, 0o600], [65534, 65534, 0o600]],
            "persistent-state-permissions-mismatch")
    record = {"boot": boot, "older": old, "newer": new, "keyId": key_id, "profile": saved,
              "state": protected, "controllerSHA256": digest(CORE)}
    with checkpoint.open("x", encoding="ascii") as output:
        json.dump(record, output)
        output.flush()
        os.fsync(output.fileno())
    os.sync()
    receipt("before-reboot", bootSHA256=boot, installedVersion=new, acceptedRevision=2,
            controllerSHA256=record["controllerSHA256"])
    command("systemctl", "--no-block", "reboot")


def after_reboot(boot, checkpoint):
    record = json.loads(checkpoint.read_bytes())
    require(boot != record["boot"], "guest-kernel-did-not-reboot")
    require(package_version() == record["newer"] and digest(CORE) == record["controllerSHA256"],
            "reboot-changed-installed-package")
    verify_installed(2, record["keyId"], record["profile"])
    require(state() == record["state"], "reboot-changed-policy-or-profile")
    command("dpkg", "--force-downgrade", "--install", SEED / "older.deb")
    require(package_version() == record["older"], "rollback-version-mismatch")
    verify_installed(2, record["keyId"], record["profile"])
    cli("managed", "update", WORK / "private/envelope-1.json", rejection=b"newer than the minimum revision")
    require(state() == record["state"], "rollback-or-policy-replay-changed-state")
    command("dpkg", "--purge", "accessweaver")
    require(not CORE.exists() and not DATA.exists()
            and "Package: accessweaver" not in Path("/var/lib/dpkg/status").read_text()
            and state() == record["state"], "purge-left-package-or-changed-state")
    require(not (PROFILE.parent / "reboot-refused-fixture.json").exists(), "refused-profile-was-created")
    receipt("after-reboot", bootSHA256=boot, installedVersion=record["newer"], acceptedRevision=2,
            controllerSHA256=record["controllerSHA256"], rollbackVersion=record["older"],
            rollbackKeptCurrentPolicy=True, replayRefused=True, purgePreservedState=True)
    command("systemctl", "--no-block", "poweroff")


def main():
    require(os.geteuid() == 0 and Path(__file__) == SEED / "guest.py"
            and os.statvfs(SEED).f_flag & os.ST_RDONLY
            and Path("/sys/class/dmi/id/product_name").read_text().strip() == "AccessWeaver-Isolated-Guest"
            and {path.name for path in Path("/sys/class/net").iterdir()} == {"lo", "awfixture0"}
            and Path("/sys/class/net/awfixture0/address").read_text().strip() == "52:54:00:ac:ce:55"
            and not json.loads(command("ip", "-j", "route", "show", "default"))
            and not json.loads(command("ip", "-j", "-6", "route", "show", "default")),
            "refused-non-isolated-guest")
    pins = json.loads((SEED / "packages.json").read_bytes())
    for name in ("older.deb", "newer.deb"):
        require(digest(SEED / name) == pins[name], "guest-package-pin-mismatch")
    boot = digest(Path("/proc/sys/kernel/random/boot_id"))
    checkpoint = WORK / "checkpoint.json"
    if checkpoint.exists():
        after_reboot(boot, checkpoint)
    else:
        before_reboot(boot, checkpoint)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        code = str(error) if type(error) is ValueError else type(error).__name__
        receipt("failure", code=code)
        command("systemctl", "--no-block", "poweroff")
        raise
