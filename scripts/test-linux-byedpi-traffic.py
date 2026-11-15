#!/usr/bin/env python3
"""Exercise an exact AccessWeaver build and a pinned ByeDPI binary on Linux loopback.

The private fixture directory contains accessweaver, ciadpi, and prep.json.
The prep record pins the controller and engine SHA-256 digests and identifies
the source, toolchain and engine release. The runner publishes traffic-report.json
without replacing an existing report. Launch it with an ordinary Linux user and
no capabilities in a disposable network namespace whose only interface is lo.
"""

import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

def require(ok, label):
    if not ok:
        raise RuntimeError(label)


if len(sys.argv) != 2:
    raise SystemExit("usage: test-linux-byedpi-traffic.py PRIVATE_FIXTURE_DIRECTORY")
ROOT = Path(sys.argv[1]).resolve(strict=True)
require(ROOT.is_dir() and ROOT.stat().st_uid == os.geteuid() and ROOT.stat().st_mode & 0o077 == 0,
        "fixture-directory-not-private")
require(sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() != 0
        and socket.if_nameindex() == [(1, "lo")],
        "expected-ordinary-user-in-loopback-only-linux-namespace")
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
require(all(int(status[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapBnd", "CapAmb"))
        and status["NoNewPrivs"].strip() == "1", "expected-no-capabilities-or-privilege-gain")
PREP = json.loads((ROOT / "prep.json").read_bytes())
CORE = ROOT / "accessweaver"
ENGINE = ROOT / "ciadpi"
require(hashlib.sha256(CORE.read_bytes()).hexdigest() == PREP["controllerSHA256"], "controller-digest-mismatch")
require(hashlib.sha256(ENGINE.read_bytes()).hexdigest() == PREP["engineSHA256"], "engine-digest-mismatch")

results = []
port = 0
loopback = "127.0.0.1"


def trial(label, action):
    try:
        action()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        if isinstance(error, RuntimeError):
            failure = str(error)
        else:
            failure = type(error).__name__
        results.append({"name": label, "passed": False, "failure": failure})
    else:
        results.append({"name": label, "passed": True})
    print(json.dumps(results[-1]), flush=True)

def recv_exact(stream, count):
    data = bytearray()
    while len(data) < count:
        part = stream.recv(count - len(data))
        require(bool(part), "unexpected-eof")
        data.extend(part)
    return bytes(data)

def endpoint(host, destination):
    if host == "localhost":
        return b"\x03\x09localhost" + struct.pack("!H", destination)
    address = ipaddress.ip_address(host)
    return (b"\x01" if address.version == 4 else b"\x04") + address.packed + struct.pack("!H", destination)

def read_endpoint(stream, kind):
    if kind in (1, 4):
        host = str(ipaddress.ip_address(recv_exact(stream, 4 if kind == 1 else 16)))
    else:
        require(kind == 3, "unknown-socks-address-kind")
        host = recv_exact(stream, recv_exact(stream, 1)[0]).decode("ascii")
    return host, struct.unpack("!H", recv_exact(stream, 2))[0]

def socks(command, host, destination):
    stream = socket.create_connection((loopback, port), timeout=4)
    try:
        stream.sendall(b"\x05\x01\x00")
        require(recv_exact(stream, 2) == b"\x05\x00", "socks-negotiation-refused")
        stream.sendall(bytes([5, command, 0]) + endpoint(host, destination))
        version, reply, reserved, kind = recv_exact(stream, 4)
        require(version == 5 and reserved == 0, "socks-invalid-response")
        require(reply == 0, "socks-request-refused-" + str(reply))
        return stream, read_endpoint(stream, kind)
    except BaseException:
        stream.close()
        raise

def tcp_tls_roundtrip(destination, use_proxy, server_context, client_context):
    host_names = ("127.0.0.1", "::1") if destination == "localhost" else (destination,)
    listeners = []
    try:
        for name in host_names:
            kind = socket.AF_INET6 if ":" in name else socket.AF_INET
            listener = socket.socket(kind)
            listeners.append(listener)
            if kind == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((name, listeners[0].getsockname()[1]))
            listener.listen(1)
        target = listeners[0].getsockname()[1]
        stimulus = b"controlled-tls-request"
        response = b"independent-tls-response"
        def observe():
            ready, _, _ = select.select(listeners, [], [], 5)
            require(len(ready) == 1, "target-tls-connection-unobserved")
            client, _ = ready[0].accept()
            with client:
                client.settimeout(4)
                with server_context.wrap_socket(client, server_side=True) as tls:
                    measured = recv_exact(tls, len(stimulus))
                    tls.sendall(response)
                    return measured, tls.version()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as task:
            observation = task.submit(observe)
            with (socks(1, destination, target)[0] if use_proxy else socket.create_connection((destination, target), timeout=4)) as stream:
                with client_context.wrap_socket(stream, server_hostname="localhost") as tls:
                    tls.sendall(stimulus)
                    require(recv_exact(tls, len(response)) == response, "client-tls-response-mismatch")
            measured, version = observation.result(timeout=6)
            require(measured == stimulus and version in ("TLSv1.2", "TLSv1.3"), "server-tls-observation-mismatch")
    finally:
        for listener in listeners:
            listener.close()

def normalized(address):
    parsed = ipaddress.ip_address(address)
    return str(getattr(parsed, "ipv4_mapped", None) or parsed)

def udp_roundtrip(host):
    kind = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(kind, socket.SOCK_DGRAM) as target:
        target.bind((host, 0))
        target.settimeout(4)
        destination = target.getsockname()[1]
        stimulus, response = b"independent-udp-stimulus", b"controlled-udp-response"
        def observe():
            received, peer = target.recvfrom(512)
            target.sendto(response, peer)
            return received
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as task:
            observation = task.submit(observe)
            control, relay = socks(3, "0.0.0.0", 0)
            with control:
                relay_host = normalized(relay[0])
                if relay_host in ("0.0.0.0", "::"):
                    relay_host = loopback
                require(ipaddress.ip_address(relay_host).is_loopback and relay[1] > 0, "udp-relay-not-loopback")
                with socket.socket(socket.AF_INET6 if ":" in relay_host else socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(4)
                    client.connect((relay_host, relay[1]))
                    client.send(b"\0\0\0" + endpoint(host, destination) + stimulus)
                    packet = client.recv(512)
                    require(packet[:3] == b"\0\0\0", "invalid-udp-relay-header")
                    require(len(packet) > 4 and packet[3] in (1, 4), "invalid-udp-relay-endpoint")
                    size = 4 if packet[3] == 1 else 16
                    require(len(packet) == 4 + size + 2 + len(response), "invalid-udp-relay-length")
                    sender = normalized(str(ipaddress.ip_address(packet[4:4 + size])))
                    reply_port = struct.unpack_from("!H", packet, 4 + size)[0]
                    require(sender == host and reply_port == destination and packet[6 + size:] == response,
                            "udp-relay-response-mismatch")
            require(observation.result(timeout=6) == stimulus, "server-udp-observation-mismatch")

def open_child(parent):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        require(parent.poll() is None, "foreground-controller-exited-before-engine-observation")
        for task in (Path("/proc") / str(parent.pid) / "task").iterdir():
            try:
                children = (task / "children").read_text().split()
            except FileNotFoundError:
                continue
            for child in children:
                try:
                    child_pid = int(child)
                    child_fd = os.pidfd_open(child_pid)
                except ProcessLookupError:
                    continue
                try:
                    if os.readlink(f"/proc/{child_pid}/exe") == str(ENGINE):
                        return child_fd
                except FileNotFoundError:
                    pass
                os.close(child_fd)
        time.sleep(0.04)
    raise RuntimeError("owned-engine-process-unobserved")

def show_listener():
    for _ in range(45):
        try:
            with socket.create_connection((loopback, port), timeout=0.15):
                return
        except OSError:
            time.sleep(0.08)
    raise RuntimeError("owned-listener-not-ready")

def is_closed():
    try:
        stream = socket.create_connection((loopback, port), timeout=0.8)
    except ConnectionRefusedError:
        return True
    stream.close()
    return False

with tempfile.TemporaryDirectory(prefix="run-", dir=ROOT) as temporary:
    work = Path(temporary)
    home = work / "home"
    home.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(home),
           "ACCESSWEAVER_HOME": str(work / "state")}
    cert, key = work / "local-cert.pem", work / "local-key.pem"
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "ed25519", "-nodes",
                    "-subj", "/CN=localhost", "-days", "1", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", key, "-out", cert], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=10)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=cert)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2

    def cli(*args):
        return subprocess.run([CORE, *args], env=env, cwd=work, capture_output=True, text=True, timeout=12)

    def import_profile(id, fingerprint):
        profile = {"version": 1, "id": id, "name": "Synthetic ByeDPI traffic fixture", "engine": "byedpi",
                   "binary": str(ENGINE), "sha256": fingerprint, "args": ["--ip", loopback, "--port", str(port)],
                   "routing": {"includeDomains": [], "excludeDomains": [], "applications": []},
                   "probe": {"host": "localhost", "port": 443, "tls": True, "timeoutSeconds": 2}}
        source = work / (id + ".json")
        source.write_text(json.dumps(profile), encoding="utf-8")
        require(cli("import", str(source)).returncode == 0, "profile-import-failed")

    def open_run():
        return subprocess.Popen([CORE, "run", "socks-fixture"], env=env, cwd=work, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    def run_checks():
        p = open_run()
        fd = None
        try:
            fd = open_child(p)
            show_listener()
            def duplicate():
                result = cli("run", "socks-fixture")
                require(result.returncode != 0 and "another AccessWeaver controller" in result.stderr
                        and p.poll() is None, "duplicate-controller-not-refused")
            trial("duplicate-foreground-run-refused", duplicate)
            for host, label in (("127.0.0.1", "ipv4"), ("::1", "ipv6"), ("localhost", "localhost-domain")):
                if host != "localhost":
                    trial(f"direct-tls-{label}-control",
                          lambda: tcp_tls_roundtrip(host, False, server_context, client_context))
                trial(f"socks-connect-tls-{label}",
                      lambda: tcp_tls_roundtrip(host, True, server_context, client_context))
            for host, label in (("127.0.0.1", "ipv4"), ("::1", "ipv6")):
                trial(f"socks-udp-associate-{label}", lambda: udp_roundtrip(host))

            def graceful():
                p.send_signal(signal.SIGTERM)
                require(p.wait(timeout=9) == 0, "controller-graceful-returncode")
                require(bool(select.select([fd], [], [], 2)[0]) and is_closed(), "engine-survived-graceful-shutdown")
            trial("sigterm-reaps-engine-and-closes-listener", graceful)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=5)
            if fd is not None:
                if not select.select([fd], [], [], 0)[0]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                os.close(fd)

    def crash_recovery():
        p = open_run()
        fd = None
        try:
            fd = open_child(p)
            show_listener()
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            require(p.wait(timeout=9) != 0 and bool(select.select([fd], [], [], 2)[0]) and is_closed(),
                    "controller-did-not-observe-engine-crash")
            import_profile("crash-lock-check", PREP["engineSHA256"])
        finally:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=5)
            if fd is not None:
                if not select.select([fd], [], [], 0)[0]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                os.close(fd)

    def changed_digest():
        import_profile("wrong-digest", "0" * 64)
        output = cli("run", "wrong-digest")
        require(output.returncode != 0 and "executable SHA-256 mismatch" in output.stderr and is_closed(),
                "changed-engine-digest-not-refused")

    with socket.socket() as allocation:
        allocation.bind((loopback, 0))
        port = allocation.getsockname()[1]
    import_profile("socks-fixture", PREP["engineSHA256"])
    plan = cli("preview", "socks-fixture")
    require(plan.returncode == 0 and json.loads(plan.stdout)["ready"] is True, "normal-preview-not-ready")
    trial("controller-starts-owned-upstream-engine", run_checks)
    trial("engine-crash-observed-and-controller-lock-released", crash_recovery)
    trial("mismatched-engine-digest-refused-without-listener", changed_digest)

report = {**PREP, "schemaVersion": 1, "scope": "Linux AMD64 real ByeDPI local traffic and lifecycle",
          "ordinaryUser": True, "zeroLinuxCapabilities": True,
          "loopbackOnlyNetworkNamespace": True, "tlsTargetLocal": True, "probeClients": "Python sockets",
          "probeSourceSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "tests": results, "allChecksPassed": all(record["passed"] for record in results),
          "productionQualificationComplete": False}
with (ROOT / "traffic-report.json").open("x", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2)
sys.exit(0 if report["allChecksPassed"] else 1)
