#!/usr/bin/env python3
"""Exercise an exact AccessWeaver build and a pinned ByeDPI binary on Linux loopback.

The private fixture directory contains accessweaver, ciadpi, and prep.json.
The prep record pins the controller and engine SHA-256 digests and identifies
the source, toolchain and engine release. The runner publishes traffic-report.json
without replacing an existing report. The optional --dns-rules mode also needs
the documented private resolver setup and writes dns-rule-report.json. The
--browser mode adds the prepared Chrome for Testing binary and writes
browser-report.json. Launch with an ordinary user without capabilities in a
disposable loopback-only network namespace.
"""

import base64
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
import threading
import time

def require(ok, label):
    if not ok:
        raise RuntimeError(label)


if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] not in ("--dns-rules", "--browser")):
    raise SystemExit("usage: test-linux-byedpi-traffic.py PRIVATE_FIXTURE_DIRECTORY [--dns-rules|--browser]")
DNS_RULES = len(sys.argv) == 3
BROWSER = DNS_RULES and sys.argv[2] == "--browser"
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
DNS_SERVER = "127.0.0.53"
RESOLVER_CONFIG = "nameserver 127.0.0.53\noptions timeout:1 attempts:1\n"
INCLUDE = "included.aw-fixture.test"
EXCLUDE = "excluded.included.aw-fixture.test"
UNLISTED = "unlisted.aw-fixture.test"
IPV6 = "v6.included.aw-fixture.test"
DNS_TARGETS = {INCLUDE: loopback, EXCLUDE: loopback, UNLISTED: loopback, IPV6: "::1"}
if DNS_RULES:
    require(Path("/etc/resolv.conf").read_text() == RESOLVER_CONFIG, "expected-private-fixture-resolver")
if BROWSER:
    browser_root = ROOT / "browser"
    browser = browser_root / "chrome-headless-shell-linux64" / "chrome-headless-shell"
    browser_prep = json.loads((browser_root / "browser-prep.json").read_bytes())
    with browser.open("rb") as executable:
        require(hashlib.file_digest(executable, "sha256").hexdigest() == browser_prep["browserExecutableSHA256"],
                "browser-digest-mismatch")


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
    if host == "localhost" or host in DNS_TARGETS:
        name = host.encode("ascii")
        return bytes((3, len(name))) + name + struct.pack("!H", destination)
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


def dns_packet(data):
    """Return the fixture query identity and its authoritative response."""
    if len(data) < 17 or struct.unpack_from("!H", data, 4)[0] != 1:
        return None
    index, labels = 12, []
    while index < len(data) and data[index] != 0:
        size = data[index]
        index += 1
        if size > 63 or index + size >= len(data):
            return None
        labels.append(data[index:index + size])
        index += size
    if index + 5 > len(data):
        return None
    name = b".".join(labels).decode("ascii", errors="replace").lower()
    query_type, query_class = struct.unpack_from("!HH", data, index + 1)
    address = DNS_TARGETS.get(name)
    expected_type = 28 if address == "::1" else 1
    answer = b""
    if address and query_class == 1 and query_type == expected_type:
        wire_address = ipaddress.ip_address(address).packed
        answer = struct.pack("!HHHIH", 0xC00C, query_type, 1, 0, len(wire_address)) + wire_address
    flags = 0x8580 if address else 0x8583
    header = data[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0)
    return name, query_type, bool(answer), header + data[12:index + 5] + answer


def serve_dns(server, stop, observations):
    server.settimeout(0.2)
    while not stop.is_set():
        try:
            data, peer = server.recvfrom(512)
        except TimeoutError:
            continue
        result = dns_packet(data)
        if result is None:
            continue
        name, query_type, answered, response = result
        if answered:
            observations.add((name, query_type))
        server.sendto(response, peer)


def http_header_observed(name, target, *, use_proxy):
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((target, 0))
        listener.listen(1)
        listener.settimeout(5)
        destination = listener.getsockname()[1]
        response = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"

        def observe():
            accepted, _ = listener.accept()
            with accepted:
                accepted.settimeout(4)
                payload = bytearray()
                while b"\r\n\r\n" not in payload and len(payload) < 512:
                    payload.extend(recv_exact(accepted, 1))
                require(b"\r\n\r\n" in payload, "http-request-not-observed")
                accepted.sendall(response)
                return bytes(payload).split(b"\r\n")[1]

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as task:
            observation = task.submit(observe)
            if use_proxy:
                connection, _ = socks(1, name, destination)
            else:
                connection = socket.create_connection((target, destination), timeout=4)
            with connection:
                request = b"GET /fixture HTTP/1.1\r\nHost: " + name.encode("ascii") + b"\r\nConnection: close\r\n\r\n"
                connection.sendall(request)
                require(recv_exact(connection, len(response)) == response, "http-response-not-observed")
            return observation.result(timeout=6)


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
    names = ",".join("DNS:" + name for name in ("localhost", *DNS_TARGETS)) if BROWSER else "DNS:localhost"
    key_options = ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"] if BROWSER else ["ed25519"]
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", *key_options, "-nodes",
                    "-subj", "/CN=localhost", "-days", "1", "-addext", "subjectAltName=" + names,
                    "-keyout", key, "-out", cert], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=10)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=cert)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    if BROWSER:
        public_key = subprocess.check_output(["/usr/bin/openssl", "x509", "-in", cert, "-pubkey", "-noout"], timeout=10)
        spki = subprocess.check_output(["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"],
                                       input=public_key, timeout=10)
        spki_pin = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
        browser_env = {**env, "LD_LIBRARY_PATH": str(browser_root / "dependencies/usr/lib/x86_64-linux-gnu")}

    def cli(*args):
        return subprocess.run([CORE, *args], env=env, cwd=work, capture_output=True, text=True, timeout=12)

    def import_profile(id, fingerprint, *, include=(), exclude=(), extra_args=()):
        profile = {"version": 1, "id": id, "name": "Synthetic ByeDPI traffic fixture", "engine": "byedpi",
                   "binary": str(ENGINE), "sha256": fingerprint, "args": ["--ip", loopback, "--port", str(port), *extra_args],
                   "routing": {"includeDomains": list(include), "excludeDomains": list(exclude), "applications": []},
                   "probe": {"host": "localhost", "port": 443, "tls": True, "timeoutSeconds": 2}}
        source = work / (id + ".json")
        source.write_text(json.dumps(profile), encoding="utf-8")
        require(cli("import", str(source)).returncode == 0, "profile-import-failed")

    def open_run(id="socks-fixture"):
        return subprocess.Popen([CORE, "run", id], env=env, cwd=work, stdin=subprocess.DEVNULL,
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



    def navigate_browser(url, *, proxy, tls):
        with tempfile.TemporaryDirectory(prefix="chrome-profile-", dir=work) as profile:
            args = [str(browser), "--dump-dom", "--disable-gpu", "--disable-dev-shm-usage",
                    "--disable-background-networking", "--disable-component-update", "--no-first-run",
                    "--disable-sync", "--host-resolver-rules=MAP *.aw-fixture.test ~NOTFOUND",
                    "--user-data-dir=" + profile]
            args.append(f"--proxy-server=socks5://127.0.0.1:{port}" if proxy else "--no-proxy-server")
            if tls:
                args.append("--ignore-certificate-errors-spki-list=" + spki_pin)
            result = subprocess.run([*args, url], cwd=work, env=browser_env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=20)
        errors = result.stderr
        require(b"No usable sandbox" not in errors and b"Operation not permitted" not in errors,
                "chromium-sandbox-unavailable")
        return result

    def browser_origin(name, *, proxy, expected_header=None, expected_error=None, tls=False):
        target = DNS_TARGETS.get(name, name)
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.bind((target, 0))
            listener.listen(1)
            listener.settimeout(6)
            destination = listener.getsockname()[1]
            protocol = "https" if tls else "http"
            url = f"{protocol}://{name}:{destination}/fixture"
            marker = b"accessweaver-browser-origin-observed"
            body = b"<!doctype html><html><head><link rel='icon' href='data:,'></head><body>" + marker + b"</body></html>"
            response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: "
                        + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)

            def observe():
                accepted, _ = listener.accept()
                with accepted:
                    accepted.settimeout(4)
                    stream = server_context.wrap_socket(accepted, server_side=True) if tls else accepted
                    with stream:
                        request = bytearray()
                        while b"\r\n\r\n" not in request and len(request) < 16 << 10:
                            request.extend(recv_exact(stream, 1))
                        require(b"\r\n\r\n" in request, "chromium-origin-request-incomplete")
                        stream.sendall(response)
                return bytes(request)

            if expected_error is not None:
                result = navigate_browser(url, proxy=proxy, tls=tls)
                require(not select.select([listener], [], [], 0.2)[0] and marker not in result.stdout,
                        "chromium-unexpected-origin-connection")
                require(expected_error in result.stderr or expected_error in result.stdout, "chromium-expected-error-unobserved")
                return

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as task:
                arrived = task.submit(observe)
                result = navigate_browser(url, proxy=proxy, tls=tls)
                request = arrived.result(timeout=8)
            require(result.returncode == 0 and marker in result.stdout, "chromium-origin-document-unobserved")
            headers = request.split(b"\r\n")
            expected_host = expected_header + f"{name}:{destination}".encode("ascii")
            require(expected_host in headers, "chromium-origin-host-header-mismatch")
            identity = ("HeadlessChrome/" + browser_prep["browserVersion"].split(".")[0]).encode("ascii")
            require(any(line.lower().startswith(b"user-agent:") and identity in line for line in headers),
                    "chromium-origin-user-agent-unobserved")

    def check_browser_paths(observations):
        def inspect(name, header, *, tls=False):
            observations.clear()
            browser_origin(name, proxy=True, expected_header=header, tls=tls)
            query_type = 28 if DNS_TARGETS[name] == "::1" else 1
            require((name, query_type) in observations, "chromium-proxy-dns-query-unobserved")

        def direct_numeric():
            observations.clear()
            browser_origin(loopback, proxy=False, expected_header=b"Host: ")
            require(not observations, "chromium-direct-numeric-unexpected-dns")

        def direct_named():
            observations.clear()
            browser_origin(INCLUDE, proxy=False, expected_error=b"ERR_NAME_NOT_RESOLVED")
            require(not observations, "chromium-direct-blocked-unexpected-dns")

        trial("chromium-direct-numeric-http-control", direct_numeric)
        trial("chromium-direct-name-lookup-blocked", direct_named)
        trial("chromium-proxied-included-http", lambda: inspect(INCLUDE, b"hOsT: "))
        trial("chromium-proxied-nested-exclusion-http", lambda: inspect(EXCLUDE, b"Host: "))
        trial("chromium-proxied-unlisted-http", lambda: inspect(UNLISTED, b"Host: "))
        trial("chromium-proxied-ipv6-https", lambda: inspect(IPV6, b"Host: ", tls=True))

    def check_dns_rules(guided):
        profile = "dns-guided" if guided else "dns-unguided"
        import_profile(profile, PREP["engineSHA256"],
                       include=(INCLUDE,) if guided else (), exclude=(EXCLUDE,) if guided else (),
                       extra_args=("--mod-http=h",))
        preview = cli("preview", profile)
        require(preview.returncode == 0 and json.loads(preview.stdout)["ready"], "dns-rule-preview-not-ready")
        observations = set()
        stop = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
                concurrent.futures.ThreadPoolExecutor(max_workers=1) as task:
            server.bind((DNS_SERVER, 53))
            dns = task.submit(serve_dns, server, stop, observations)
            p, fd = None, None
            try:
                p = open_run(profile)
                fd = open_child(p)
                show_listener()
                def inspect(name, expected_header, *, use_proxy=True):
                    target = DNS_TARGETS[name]
                    observed = http_header_observed(name, target, use_proxy=use_proxy)
                    expected = expected_header + name.encode("ascii")
                    require(observed == expected, "origin-http-host-casing-mismatch")
                    if use_proxy:
                        wanted = 28 if target == "::1" else 1
                        require((name, wanted) in observations, "proxy-dns-query-not-observed")
                    else:
                        require(not observations, "direct-numeric-control-used-dns")

                if guided:
                    trial("direct-http-host-unmodified-without-dns", lambda: inspect(INCLUDE, b"Host: ", use_proxy=False))
                    trial("guided-included-http-host-modified", lambda: inspect(INCLUDE, b"hOsT: "))
                    trial("guided-nested-excluded-http-host-unmodified", lambda: inspect(EXCLUDE, b"Host: "))
                    trial("guided-unlisted-http-host-unmodified", lambda: inspect(UNLISTED, b"Host: "))
                    trial("guided-included-ipv6-http-host-modified", lambda: inspect(IPV6, b"hOsT: "))
                    if BROWSER:
                        check_browser_paths(observations)
                else:
                    inspect(UNLISTED, b"hOsT: ")

                p.send_signal(signal.SIGTERM)
                require(p.wait(timeout=9) == 0 and bool(select.select([fd], [], [], 2)[0]) and is_closed(),
                        "dns-rule-proxy-cleanup-failed")
                if guided and BROWSER:
                    def proxy_loss():
                        observations.clear()
                        browser_origin(INCLUDE, proxy=True, expected_error=b"ERR_PROXY_CONNECTION_FAILED")
                        require(not observations, "chromium-proxy-loss-followed-direct-dns")
                    trial("chromium-proxy-loss-refuses-direct-fallback", proxy_loss)
            finally:
                stop.set()
                if p is not None and p.poll() is None:
                    p.kill()
                    p.wait(timeout=5)
                if fd is not None:
                    if not select.select([fd], [], [], 0)[0]:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    os.close(fd)
            dns.result(timeout=4)


    with socket.socket() as allocation:
        allocation.bind((loopback, 0))
        port = allocation.getsockname()[1]
    import_profile("socks-fixture", PREP["engineSHA256"])
    plan = cli("preview", "socks-fixture")
    require(plan.returncode == 0 and json.loads(plan.stdout)["ready"] is True, "normal-preview-not-ready")
    trial("controller-starts-owned-upstream-engine", run_checks)
    trial("engine-crash-observed-and-controller-lock-released", crash_recovery)
    trial("mismatched-engine-digest-refused-without-listener", changed_digest)
    if DNS_RULES:
        trial("unguided-http-marker-control", lambda: check_dns_rules(False))
        trial("guided-dns-and-http-rules", lambda: check_dns_rules(True))

report = {**PREP, "schemaVersion": 1, "scope": "Linux AMD64 real ByeDPI local traffic and lifecycle",
          "ordinaryUser": True, "zeroLinuxCapabilities": True,
          "loopbackOnlyNetworkNamespace": True, "tlsTargetLocal": True, "probeClients": "Python sockets",
          "probeSourceSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "syntheticDNSRulesRequested": DNS_RULES,
          "tests": results, "allChecksPassed": all(record["passed"] for record in results),
          "productionQualificationComplete": False}
report_name = "browser-report.json" if BROWSER else "dns-rule-report.json" if DNS_RULES else "traffic-report.json"
if BROWSER:
    report["browser"] = browser_prep
    report["browserSandboxDisabled"] = False
    report["browserTLSFixtureSPKIPinned"] = True
    report["browserTLSFixtureKey"] = "ECDSA P-256"
with (ROOT / report_name).open("x", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2)
sys.exit(0 if report["allChecksPassed"] else 1)
