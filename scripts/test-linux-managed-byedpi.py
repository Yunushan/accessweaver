#!/usr/bin/env python3
"""Qualify Linux managed policy against real loopback ByeDPI traffic.

Run with a separately elevated CLI on a disposable Linux host. The input
directory contains the approved accessweaver and ciadpi binaries and prep.json
with their SHA-256 digests. Only a private child mount, network and PID
namespace receives the synthetic /etc and /opt. The child drops all capabilities
for desktop operations. The result on stdout contains fixed cases and digests.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

PORT = 1080
UID = 65534
BUNDLE = Path("/opt/accessweaver-qualification")
POLICY = Path("/etc/accessweaver")
SOURCE = POLICY / "installation.json"
ACCEPTANCE = POLICY / "acceptance.json"
LOCK = Path("/etc/.accessweaver-policy.lock")
CORE = BUNDLE / "bin/accessweaver"
ENGINE = BUNDLE / "engine/ciadpi"
STATE = BUNDLE / "state"
ORDINARY = ["/usr/bin/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
            "--ambient-caps=-all", "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs"]
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": str(STATE),
       "ACCESSWEAVER_HOME": str(STATE)}


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inode(path):
    info = path.lstat()
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)


def namespace_id(name):
    return os.readlink("/proc/self/ns/" + name)


def auth_cli(*args, ordinary=False, expect_error=None):
    command = [*ORDINARY, CORE, *args] if ordinary else [CORE, *args]
    result = subprocess.run(command, env=ENV, cwd=BUNDLE, capture_output=True, timeout=20)
    if expect_error is None:
        if result.returncode != 0:
            markers = ("managed machine policy is unavailable", "managed operation is blocked",
                       "require", "permission denied", "unknown", "parse", "protected", "ordinary")
            matched = [marker for marker in markers if marker.encode("ascii") in result.stderr.lower()]
            raise RuntimeError("cli-failed-" + str(args[0]) + "-" + ",".join(matched))
        return result.stdout
    require(result.returncode != 0 and expect_error.encode("ascii") in result.stderr,
            "expected-cli-rejection-" + str(args[0]) + "-" + expect_error)
    return result.stdout


def recv_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        portion = stream.recv(count - len(result))
        require(bool(portion), "unexpected-socks-eof")
        result.extend(portion)
    return bytes(result)


def wait_listener(parent):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        require(parent.poll() is None, "approved-cli-exited-before-listener")
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("approved-loopback-listener-unavailable")


def listener_closed():
    try:
        stream = socket.create_connection(("127.0.0.1", PORT), timeout=0.4)
    except ConnectionRefusedError:
        return True
    stream.close()
    return False


def run_engine():
    return subprocess.Popen([*ORDINARY, CORE, "run", "approved-byedpi"], env=ENV, cwd=BUNDLE,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def owned_engine_pidfd(parent):
    for task in (Path("/proc") / str(parent.pid) / "task").iterdir():
        try:
            children = (task / "children").read_text().split()
        except FileNotFoundError:
            continue
        for child in children:
            try:
                # Read the child's executable and credentials under the same
                # ordinary account. The original admin may lack ptrace access.
                inspected = subprocess.run([*ORDINARY, "/usr/bin/readlink", f"/proc/{child}/exe"],
                                           capture_output=True, text=True, timeout=2)
                if inspected.returncode != 0 or inspected.stdout.strip() != str(ENGINE):
                    continue
                fd = os.pidfd_open(int(child))
                return fd
            except ProcessLookupError:
                continue
    raise RuntimeError("approved-vendor-child-not-observed")


def clean_engine(parent, fd):
    if parent.poll() is None:
        parent.terminate()
        try:
            parent.wait(timeout=6)
        except subprocess.TimeoutExpired:
            parent.kill()
            parent.wait(timeout=4)
    if fd is not None:
        if not select.select([fd], [], [], 0)[0]:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        os.close(fd)
    parent.stderr.close()


def socks_roundtrip():
    observed = []
    with socket.socket() as target:
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(5)
        destination = target.getsockname()[1]
        request, reply = b"managed-traffic-stimulus", b"owned-origin-response"

        def origin():
            try:
                child, _ = target.accept()
                with child:
                    child.settimeout(3)
                    observed.append(recv_exact(child, len(request)))
                    child.sendall(reply)
            except (OSError, RuntimeError):
                observed.append(b"")

        worker = threading.Thread(target=origin)
        worker.start()
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=4) as stream:
                stream.sendall(b"\x05\x01\x00")
                require(recv_exact(stream, 2) == b"\x05\x00", "managed-socks-negotiation-failed")
                stream.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", destination))
                header = recv_exact(stream, 4)
                require(header[:3] == b"\x05\x00\x00" and header[3] in (1, 4), "managed-socks-request-failed")
                recv_exact(stream, (4 if header[3] == 1 else 16) + 2)
                stream.sendall(request)
                require(recv_exact(stream, len(reply)) == reply, "managed-socks-response-mismatch")
        finally:
            worker.join(timeout=9)
        require(observed == [request], "managed-traffic-origin-unobserved")


def status(ordinary=True, expect_error=None):
    return json.loads(auth_cli("managed", "status", ordinary=ordinary, expect_error=expect_error))


def approved_revision(revision, expected_key=None):
    state = status()
    require(state["supported"] and state["configured"] and state["valid"]
            and state["storageVersion"] == 2 and state["revision"] == state["acceptedRevision"] == revision
            and (expected_key is None or state["keyId"] == expected_key), "protected-revision-readback-mismatch")
    return state["keyId"]


def committed(operation, revision, previous, *args):
    outcome = json.loads(auth_cli("managed", operation, *args))
    require(outcome["committed"] is True and outcome["operation"] == operation
            and outcome["revision"] == revision and outcome["previousRevision"] == previous,
            "managed-commit-receipt-mismatch-" + operation)
    return outcome["keyId"]


def namespace_test(work, outside_mount, outside_net):
    require(os.getuid() == 0 and os.getpid() == 1 and namespace_id("mnt") != outside_mount
            and namespace_id("net") != outside_net and socket.if_nameindex() == [(1, "lo")],
            "refused-non-isolated-managed-fixture")
    for target in ("/etc", "/opt"):
        source = work / target.lstrip("/")
        require(source.parent == work and source.is_dir() and inode(source)[2:] == (0, 0o755),
                "invalid-private-mount-source")
        subprocess.run(["/usr/bin/mount", "-n", "--bind", source, target], check=True, timeout=6)
        require(inode(Path(target)) == inode(source), "private-mount-readback-mismatch")
    subprocess.run(["/usr/sbin/ip", "link", "set", "dev", "lo", "up"], check=True, timeout=5)
    require(not POLICY.exists() and not LOCK.exists(), "private-policy-path-is-not-fresh")
    checks = ["private-mount-net-and-pid-isolation-verified"]
    verified_ordinary = subprocess.run([*ORDINARY, "/usr/bin/python3", "-I", "-S", "-B", "-c",
        "import os; assert os.getuid()==65534 and os.getgid()==65534 and not os.getgroups(); "
        "s=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line); "
        "assert not any(int(s[k],16) for k in ('CapEff','CapPrm','CapBnd','CapAmb')) and s['NoNewPrivs'].strip()=='1'"],
        check=True, timeout=5, capture_output=True)
    require(verified_ordinary.returncode == 0, "ordinary-worker-credentials-mismatch")

    checks.append("ordinary-uid-gid-and-zero-capabilities-verified")
    prep = json.loads((work / "prep.json").read_bytes())
    require(digest(CORE) == prep["controllerSHA256"] and digest(ENGINE) == prep["engineSHA256"],
            "mounted-subject-digest-mismatch")
    require(status() == {"supported": True, "configured": False, "valid": False, "enforcement": "none"},
            "unexpected-clean-machine-policy-state")
    checks.append("unenrolled-status-verified-without-native-policy")

    profile = {"version": 1, "id": "approved-byedpi", "name": "Approved ByeDPI fixture", "engine": "byedpi",
               "binary": str(ENGINE), "sha256": prep["engineSHA256"], "args": [],
               "routing": {"includeDomains": [], "excludeDomains": [], "applications": []},
               "probe": {"host": "localhost", "port": PORT, "tls": False, "timeoutSeconds": 2}}
    profile_path = BUNDLE / "inputs" / "approved-profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    unapproved = BUNDLE / "inputs" / "unapproved-profile.json"
    profile["id"] = "unapproved-byedpi"
    profile["args"] = ["--split", "2"]
    unapproved.write_text(json.dumps(profile), encoding="utf-8")
    auth_cli("import", profile_path, ordinary=True)
    auth_cli("import", unapproved, ordinary=True)
    launch_digest = json.loads(auth_cli("managed", "digest-profile", profile_path))["inputSHA256"]
    launch_rule = {"engine": "byedpi", "inputSHA256": launch_digest, "binarySHA256": prep["engineSHA256"]}

    signing = work / "signing"
    key1, key2 = (signing / name for name in ("key-one.pem", "key-two.pem"))
    for key in (key1, key2):
        subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", key],
                       check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pins = [auth_cli("managed", "public-key", "--private-key", key).decode("ascii").strip() for key in (key1, key2)]
    require(all(len(base64.b64decode(pin, validate=True)) == 32 for pin in pins) and pins[0] != pins[1],
            "signing-key-generation-failed")

    def envelope(revision, key, allowed, file_label):
        policy_file = signing / (file_label + ".policy.json")
        output = BUNDLE / "inputs" / (file_label + ".envelope.json")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        document = {"schemaVersion": 1, "revision": revision, "allowDownloads": False,
                    "allowDiagnostics": False, "allowProfileChanges": False,
                    "issuedAt": (now - timedelta(minutes=1)).isoformat(),
                    "expiresAt": (now + timedelta(minutes=25)).isoformat(),
                    "launches": [launch_rule] if allowed else [], "workflows": []}
        policy_file.write_text(json.dumps(document), encoding="utf-8")
        auth_cli("managed", "sign", policy_file, "--private-key", key, "--out", output)
        output.chmod(0o644)
        return output

    initial = envelope(1, key1, True, "initial")
    installation = BUNDLE / "inputs" / "installation.json"
    auth_cli("managed", "prepare", initial, "--public-key", pins[0], "--minimum-revision", "0", "--out", installation)
    installation.chmod(0o644)
    auth_cli("managed", "install", installation, "--public-key", pins[0], ordinary=True, expect_error="root")
    auth_cli("managed", "install", installation, "--public-key", pins[1], expect_error="independently supplied public key")
    require(not POLICY.exists(), "refused-install-left-an-enrollment")
    checks.append("ordinary-install-and-wrong-trust-pin-refused")
    enrolled = committed("install", 1, 0, installation, "--public-key", pins[0])
    approved_revision(1, enrolled)
    require(inode(POLICY)[2:] == (0, 0o755) and inode(SOURCE)[2:] == (0, 0o644)
            and inode(ACCEPTANCE)[2:] == (0, 0o644) and inode(LOCK)[2:] == (0, 0o600), "native-policy-ownership-mismatch")
    lock_identity = inode(LOCK)
    checks.append("root-install-and-normal-user-protected-pair-readback")
    write_probe = """import os, sys
for path in sys.argv[1:]:
    try:
        fd = os.open(path, os.O_WRONLY)
    except PermissionError:
        continue
    os.close(fd)
    raise SystemExit(1)
"""
    subprocess.run([*ORDINARY, "/usr/bin/python3", "-I", "-S", "-B", "-c", write_probe,
                    SOURCE, ACCEPTANCE, LOCK, ENGINE], check=True, capture_output=True, timeout=6)
    checks.append("ordinary-user-cannot-open-protected-policy-lock-or-engine-for-write")
    auth_cli("import", unapproved, ordinary=True, expect_error="profile changes are disabled")
    auth_cli("run", "unapproved-byedpi", ordinary=True, expect_error="launch inputs are not approved")
    require(listener_closed(), "a-denied-profile-opened-the-listener")
    checks.append("ordinary-profile-mutation-and-unapproved-launch-refused")

    revoked = envelope(2, key1, False, "revoke")
    auth_cli("managed", "update", revoked, ordinary=True, expect_error="root")
    approved_revision(1, enrolled)
    checks.append("ordinary-update-denied-and-prior-policy-preserved")
    owner = run_engine()
    child = None
    try:
        wait_listener(owner)
        child = owned_engine_pidfd(owner)
        socks_roundtrip()
        checks.append("approved-ordinary-vendor-process-served-real-socks5-traffic")
        committed("update", 2, 1, revoked)
        approved_revision(2, enrolled)
        require(owner.wait(timeout=12) != 0 and b"machine policy changed" in owner.stderr.read(32768)
                and bool(select.select([child], [], [], 3)[0]) and listener_closed(),
                "policy-update-did-not-stop-owned-engine-and-listener")
        checks.append("signed-revocation-stopped-owned-engine-and-closed-listener")
    finally:
        clean_engine(owner, child)
    auth_cli("run", "approved-byedpi", ordinary=True, expect_error="launch inputs are not approved")
    auth_cli("managed", "update", initial, expect_error="revision")
    approved_revision(2, enrolled)
    checks.append("revoked-launch-and-stale-signed-update-refused")

    prior = signing / "previous-installation.json"
    auth_cli("managed", "export-installation", "--out", prior)
    rotation = signing / "rotation.json"
    rotated = envelope(3, key2, False, "rotated")
    auth_cli("managed", "sign-rotation", rotated, "--previous-installation", prior,
             "--next-public-key", pins[1], "--private-key", key1, "--out", rotation)
    auth_cli("managed", "verify-rotation", rotation, "--previous-installation", prior, "--public-key", pins[0])
    active = committed("rotate", 3, 2, rotation)
    require(active != enrolled, "rotation-did-not-change-key")
    approved_revision(3, active)
    retired = envelope(4, key1, True, "retired")
    auth_cli("managed", "update", retired, expect_error="envelope key ID does not match")
    auth_cli("managed", "rotate", rotation, expect_error="rotation")
    approved_revision(3, active)
    checks.append("key-rotation-retired-key-and-replay-refusal-verified")

    damaged = b'{"damaged":"synthetic fixture"}\n'
    acceptance_digest = digest(ACCEPTANCE)
    SOURCE.write_bytes(damaged)
    broken = status(expect_error="managed machine policy is unavailable")
    require(broken.get("configured") and broken.get("enforcement") == "blocked"
            and broken.get("acceptedRevision") == 3 and digest(ACCEPTANCE) == acceptance_digest,
            "damaged-policy-did-not-fail-closed")
    auth_cli("run", "approved-byedpi", ordinary=True, expect_error="managed machine policy is unavailable")
    snapshot = signing / "damaged-source.bin"
    auth_cli("managed", "export-source", "--out", snapshot)
    require(snapshot.read_bytes() == damaged and listener_closed(), "damaged-source-export-mismatch")
    checks.append("damaged-policy-blocked-vendor-and-exported-exact-source")

    recovered = envelope(4, key2, True, "recovered")
    recovery = BUNDLE / "inputs" / "recovery.json"
    auth_cli("managed", "sign-recovery", recovered, "--previous-source", snapshot,
             "--minimum-revision", "3", "--private-key", key2, "--valid-for", "1h", "--out", recovery)
    recovery.chmod(0o644)
    auth_cli("managed", "verify-recovery", recovery, "--previous-source", snapshot,
             "--public-key", pins[1], "--minimum-revision", "3")
    args = [recovery, "--public-key", pins[1], "--minimum-revision", "3"]
    auth_cli("managed", "recover", *args, ordinary=True, expect_error="root")
    require(SOURCE.read_bytes() == damaged and digest(ACCEPTANCE) == acceptance_digest,
            "ordinary-recovery-modified-protected-state")
    outcome = json.loads(auth_cli("managed", "recover", *args))
    require(outcome["operation"] == "recover" and outcome["committed"] and outcome["revision"] == 4
            and outcome["keyId"] == active and outcome["previousSourceSHA256"] == hashlib.sha256(damaged).hexdigest(),
            "native-recovery-receipt-mismatch")
    approved_revision(4, active)
    auth_cli("managed", "recover", *args, expect_error="source")
    approved_revision(4, active)
    checks.append("signed-native-recovery-and-replay-refusal-verified")

    owner = run_engine()
    child = None
    try:
        wait_listener(owner)
        child = owned_engine_pidfd(owner)
        socks_roundtrip()
        owner.terminate()
        require(owner.wait(timeout=8) == 0 and bool(select.select([child], [], [], 3)[0]) and listener_closed(),
                "recovered-vendor-graceful-shutdown-failed")
    finally:
        clean_engine(owner, child)
    concurrent = envelope(5, key2, True, "concurrent")
    writers = []
    read_fd, write_fd = os.pipe()
    release_writer = "import os, sys; os.read(int(sys.argv[1]), 1); os.execv(sys.argv[2], sys.argv[2:])"
    try:
        with os.fdopen(read_fd, "rb") as ready, os.fdopen(write_fd, "wb") as release:
            for _ in range(2):
                command = ["/usr/bin/python3", "-I", "-S", "-B", "-c", release_writer, str(ready.fileno()),
                           CORE, "managed", "update", concurrent]
                writers.append(subprocess.Popen(command, env=ENV, cwd=BUNDLE, pass_fds=(ready.fileno(),),
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            release.write(b"12")
            release.flush()
        results = [writer.communicate(timeout=20) for writer in writers]
    finally:
        for writer in writers:
            if writer.poll() is None:
                writer.kill()
                writer.wait(timeout=4)
            writer.stdout.close()
            writer.stderr.close()
    successful = [json.loads(output) for writer, (output, _) in zip(writers, results) if writer.returncode == 0]
    rejected = [error for writer, (_, error) in zip(writers, results) if writer.returncode != 0]
    require(len(successful) == len(rejected) == 1 and successful[0]["operation"] == "update"
            and successful[0]["committed"] and successful[0]["previousRevision"] == 4
            and successful[0]["revision"] == 5 and b"revision" in rejected[0], "concurrent-updates-did-not-serialize")
    approved_revision(5, active)
    checks.append("concurrent-same-revision-updates-committed-once")

    require(inode(LOCK) == lock_identity and sorted(item.name for item in POLICY.iterdir()) ==
            ["acceptance.json", "installation.json"], "final-policy-or-lock-inventory-mismatch")
    require(not tuple(Path("/etc").glob(".accessweaver-policy-stage-*")), "native-transaction-stage-left-behind")
    checks.append("recovered-approval-served-traffic-and-cleanly-stopped")
    checks.append("persistent-lock-and-final-pair-preserved-without-staging-leaks")
    print(json.dumps({**prep, "checks": checks, "policyRevisionsObserved": [1, 2, 3, 4, 5]}))


def prepare_file(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)
    path.chmod(mode)


def outer(inputs):
    require(sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() == 0,
            "expected-elevated-linux-amd64-fixture-preparation")
    prep_file = inputs / "prep.json"
    require(prep_file.is_file() and 0 < prep_file.stat().st_size <= 16384, "invalid-prep-record")
    prep = json.loads(prep_file.read_bytes())
    hosts = (Path("/etc"), Path("/opt"), POLICY, LOCK)
    baseline = {path: inode(path) if os.path.lexists(path) else None for path in hosts}
    host_resolver = digest(Path("/etc/resolv.conf"))
    with tempfile.TemporaryDirectory(prefix="accessweaver-managed-namespace-", dir="/var/tmp") as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        for path in ("etc", "opt", "opt/accessweaver-qualification", "opt/accessweaver-qualification/bin",
                     "opt/accessweaver-qualification/engine", "opt/accessweaver-qualification/inputs"):
            (work / path).mkdir(mode=0o755)
        (work / "signing").mkdir(mode=0o700)
        home = work / "opt/accessweaver-qualification/state"
        home.mkdir(mode=0o700)
        os.chown(home, UID, UID)
        prepare_file(work / "etc/hosts", b"127.0.0.1 localhost\n::1 localhost\n", 0o644)
        prepare_file(work / "etc/nsswitch.conf", b"hosts: files\npasswd: files\ngroup: files\n", 0o644)
        prepare_file(work / "etc/passwd", b"root:x:0:0:fixture root:/nonexistent:/usr/sbin/nologin\nnobody:x:65534:65534:fixture user:/nonexistent:/usr/sbin/nologin\n", 0o644)
        prepare_file(work / "etc/group", b"root:x:0:\nnogroup:x:65534:\n", 0o644)
        for field, original, target in (("controllerSHA256", "accessweaver", CORE), ("engineSHA256", "ciadpi", ENGINE)):
            path = inputs / original
            require(path.is_file() and 0 < path.stat().st_size <= 128 << 20, "invalid-input-subject")
            with path.open("rb") as stream:
                data = stream.read((128 << 20) + 1)
            require(0 < len(data) <= 128 << 20 and hashlib.sha256(data).hexdigest() == prep[field],
                    "input-subject-digest-mismatch")
            prepare_file(work / target.relative_to("/"), data, 0o755)
        prepare_file(work / "prep.json", json.dumps(prep).encode("utf-8"), 0o600)
        fixture = work / "fixture.py"
        prepare_file(fixture, Path(__file__).read_bytes(), 0o500)
        child = subprocess.run(["/usr/bin/unshare", "--mount", "--propagation", "private", "--net", "--pid",
                                "--fork", "--mount-proc", "--kill-child", "/usr/bin/python3", "-I", "-S", "-B", fixture,
                                "--inside", work, namespace_id("mnt"), namespace_id("net")],
                               capture_output=True, timeout=220)
    require(all((inode(path) if os.path.lexists(path) else None) == baseline[path] for path in hosts)
            and digest(Path("/etc/resolv.conf")) == host_resolver, "host-policy-or-mount-identity-changed")
    if child.returncode != 0:
        sys.stderr.buffer.write(child.stderr)
        return child.returncode
    result = json.loads(child.stdout)
    result.update(schemaVersion=1, scope="Real managed Linux AMD64 CLI policy lifecycle and ByeDPI routing",
                  probeSourceSHA256=digest(Path(__file__)), hostMountAndResolverIdentityPreserved=True,
                  productionQualificationComplete=False)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--inside":
        namespace_test(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 2:
        raise SystemExit(outer(Path(sys.argv[1]).resolve(strict=True)))
    else:
        raise SystemExit("usage: test-linux-managed-byedpi.py PRIVATE_PREPARED_INPUTS")
