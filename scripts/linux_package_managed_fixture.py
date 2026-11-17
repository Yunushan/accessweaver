"""Exercise installed AccessWeaver policy and profile state in a private package root."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from verify_release import require

PROFILE_ID = "managed-package-fixture"
UID = 65534
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC",
       "HOME": "/home/fixture", "XDG_CONFIG_HOME": "/home/fixture/.config"}


def fingerprint(path):
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    metadata = path.lstat()
    return digest, metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)


class ManagedPackageFixture:
    def __init__(self, root, byedpi=None):
        self.root = root.resolve(strict=True)
        require(self.root != Path("/") and self.root.stat().st_uid == 0, "Expected an owned private package root")
        work = root / "managed-fixture"
        work.mkdir(mode=0o755)
        work.chmod(0o755)
        self.private = work / "private"
        self.private.mkdir(mode=0o700)
        self.profile_path = root / f"home/fixture/.config/AccessWeaver/profiles/{PROFILE_ID}.json"
        self.policy_paths = [root / path for path in ("etc/accessweaver/installation.json",
                                                     "etc/accessweaver/acceptance.json",
                                                     "etc/.accessweaver-policy.lock")]
        for directory in (root / "etc", root / "home"):
            directory.mkdir(mode=0o755, exist_ok=True)
            directory.chmod(0o755)
        home = root / "home/fixture"
        home.mkdir(mode=0o700)
        os.chown(home, UID, UID)
        engine = work / "inert-engine"
        if byedpi is not None:
            engine = work / "bin" / "ciadpi"
            for directory in (engine.parent, root / "dev"):
                directory.mkdir(mode=0o755)
                directory.chmod(0o755)
            null = root / "dev/null"
            os.mknod(null, stat.S_IFCHR | 0o666, os.makedev(1, 3))
            null.chmod(0o666)
        engine.write_bytes(byedpi if byedpi is not None else b"Inert managed package acceptance fixture\n")
        engine.chmod(0o755 if byedpi is not None else 0o644)
        self.engine = engine
        profile = {"version": 1, "id": PROFILE_ID, "name": "Managed package fixture", "engine": "byedpi",
                   "binary": f"/{engine.relative_to(root).as_posix()}", "sha256": fingerprint(engine)[0], "args": [],
                   "routing": {"includeDomains": [], "excludeDomains": [], "applications": []},
                   "probe": {"host": "127.0.0.1", "port": 1080, "tls": False, "timeoutSeconds": 2}}
        profile_input = self.profile_input(work, profile)
        self.cli("import", profile_input, ordinary=True)
        self.profile = json.loads(self.cli("show", PROFILE_ID, ordinary=True))
        require(self.profile["id"] == PROFILE_ID and self.profile["sha256"] == profile["sha256"]
                and self.profile_path.is_file(), "Installed command did not create the expected profile")
        self.launches = []
        self.denied_launch = PROFILE_ID
        if byedpi is not None:
            launch = json.loads(self.cli("managed", "digest-profile", profile_input))["inputSHA256"]
            self.launches = [{"engine": "byedpi", "inputSHA256": launch, "binarySHA256": profile["sha256"]}]
            self.denied_launch = "unapproved-live-package-fixture"
            substitute = dict(profile, id=self.denied_launch, args=["--split", "2"])
            self.cli("import", self.profile_input(work, substitute), ordinary=True)
        profile["id"] = "refused-package-fixture"
        self.refused_profile = self.profile_input(work, profile)

        key = self.private / "key.pem"
        subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", key],
                       check=True, capture_output=True, timeout=15, env=ENV)
        key.chmod(0o600)
        self.key = "/managed-fixture/private/key.pem"
        pin = self.cli("managed", "public-key", "--private-key", self.key).decode("ascii").strip()
        self.first = self.sign(1)
        install = "/managed-fixture/private/installation.json"
        self.cli("managed", "prepare", self.first, "--public-key", pin, "--minimum-revision", "0", "--out", install)
        result = json.loads(self.cli("managed", "install", install, "--public-key", pin))
        self.key_id = result["keyId"]
        require(result["committed"] is True and result["previousRevision"] == 0 and result["revision"] == 1,
                "Could not enroll managed policy using the installed package")
        require([fingerprint(path)[3:] for path in self.policy_paths] == [(0, 0, 0o644), (0, 0, 0o644), (0, 0, 0o600)]
                and fingerprint(self.profile_path)[3:] == (UID, UID, 0o600),
                "Installed commands created weak policy or profile permissions")
        self.revision = 1

    def profile_input(self, work, profile):
        path = work / f"{profile['id']}.json"
        path.write_text(json.dumps(profile), encoding="utf-8")
        path.chmod(0o644)
        return f"/managed-fixture/{path.name}"

    def command(self, *args, ordinary=False):
        credentials = ["--userspec=+65534:+65534", "--groups="] if ordinary else []
        return ["chroot", *credentials, self.root, "/usr/bin/accessweaver", *args]

    def cli(self, *args, ordinary=False, rejection=None):
        result = subprocess.run(self.command(*args, ordinary=ordinary),
                                capture_output=True, timeout=30, env=ENV)
        if rejection is None:
            require(result.returncode == 0, f"Installed {args[0]} failed: "
                    + result.stderr[-1024:].decode("utf-8", "replace"))
        else:
            require(result.returncode != 0 and rejection in result.stderr,
                    f"Installed {args[0]} did not enforce the expected {rejection.decode('ascii')} refusal")
        return result.stdout

    def sign(self, revision):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        data = {"schemaVersion": 1, "revision": revision,
                "issuedAt": (now - timedelta(minutes=1)).isoformat(),
                "expiresAt": (now + timedelta(minutes=30)).isoformat(),
                "allowDownloads": False, "allowDiagnostics": False, "allowProfileChanges": False,
                "launches": self.launches, "workflows": []}
        policy = self.private / f"policy-{revision}.json"
        policy.write_text(json.dumps(data), encoding="utf-8")
        envelope = f"/managed-fixture/envelope-{revision}.json"
        self.cli("managed", "sign", f"/managed-fixture/private/{policy.name}",
                 "--private-key", self.key, "--out", envelope)
        (self.root / envelope.lstrip("/")).chmod(0o644)
        return envelope

    def advance(self):
        before = fingerprint(self.profile_path)
        envelope = self.sign(self.revision + 1)
        self.cli("managed", "update", envelope, ordinary=True, rejection=b"separately elevated root CLI")
        result = json.loads(self.cli("managed", "update", envelope))
        require(result["committed"] is True and result["previousRevision"] == self.revision
                and result["revision"] == self.revision + 1 and result["keyId"] == self.key_id
                and fingerprint(self.profile_path) == before, "Installed CLI did not advance the enrolled policy")
        self.revision += 1

    def state(self):
        return tuple(fingerprint(path) for path in (*self.policy_paths, self.profile_path))

    def verify(self):
        prior = self.state()
        result = json.loads(self.cli("managed", "status", ordinary=True))
        require(result["supported"] is True and result["configured"] is True and result["valid"] is True
                and result["storageVersion"] == 2 and result["acceptedRevision"] == result["revision"] == self.revision
                and result["keyId"] == self.key_id and result["enforcement"] == "partial",
                "Ordinary installed CLI did not recognize the protected revision")
        require(json.loads(self.cli("show", PROFILE_ID, ordinary=True)) == self.profile,
                "Ordinary installed CLI did not read the same real user profile")
        self.cli("import", self.refused_profile, ordinary=True, rejection=b"profile changes are disabled")
        self.cli("run", self.denied_launch, ordinary=True, rejection=b"launch inputs are not approved")
        blocked = self.profile_path.with_name("refused-package-fixture.json")
        require(not blocked.exists() and self.state() == prior,
                "Blocked operation changed enrolled policy or the user profile inventory")

    def refuse_replay(self):
        state = self.state()
        self.cli("managed", "update", self.first, rejection=b"newer than the minimum revision")
        require(self.state() == state, "Replayed policy changed the installed policy or profile")
