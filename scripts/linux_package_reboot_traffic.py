"""Real isolated ByeDPI sessions used by the disposable Debian reboot guest."""
from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import runpy
import select
import socket
import struct
import subprocess

ENGINE = Path("/opt/accessweaver-qualification/engine/ciadpi")
SHARED_PROBE = "test-linux-managed-byedpi.py"
BEFORE = {"ordinaryControllerAndVendor", "routedBytesVerified", "connectedWhenRebootRequested"}
AFTER = {"oldEngineAndListenerAbsent", "restoredApprovalRoutedBytes", "ownedEngineAndClientStopped"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ordinary(pid):
    fields = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    return (all(fields[key].split() == ["65534"] * 4 for key in ("Uid", "Gid"))
            and not fields["Groups"].strip()
            and all(int(fields[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapBnd", "CapAmb"))
            and fields["NoNewPrivs"].strip() == "1")


def assert_restart_idle(seed):
    probe = runpy.run_path(str(seed / SHARED_PROBE))
    require(probe["listener_closed"](), "stale-socks-listener-after-reboot")
    for executable in Path("/proc").glob("[0-9]*/exe"):
        try:
            actual = executable.readlink()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        require(actual != ENGINE, "stale-byedpi-process-after-reboot")


@contextmanager
def routed_session(seed, controller, profile, env):
    probe = runpy.run_path(str(seed / SHARED_PROBE))
    require(probe["ENGINE"] == ENGINE and probe["listener_closed"](), "unexpected-byedpi-path-or-listener")
    proc = subprocess.Popen([*probe["ORDINARY"], controller, "run", profile], env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    descriptor = None
    try:
        probe["wait_listener"](proc)
        try:
            descriptor = probe["owned_engine_pidfd"](proc)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("guest-engine-ownership-inspection-timed-out") from error
        pid = int(next(line.split()[1] for line in Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines()
                       if line.startswith("Pid:")))
        require(ordinary(proc.pid) and ordinary(pid), "controller-or-vendor-ran-with-privilege")
        with ExitStack() as resources:
            origin = resources.enter_context(socket.socket())
            origin.bind(("127.0.0.1", 0))
            origin.listen(1)
            origin.settimeout(4)
            client = resources.enter_context(socket.create_connection(("127.0.0.1", probe["PORT"]), timeout=4))
            exact = probe["recv_exact"]
            client.sendall(b"\x05\x01\x00")
            require(exact(client, 2) == b"\x05\x00", "guest-socks-negotiation-failed")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", origin.getsockname()[1]))
            header = exact(client, 4)
            require(header[:3] == b"\x05\x00\x00" and header[3] in (1, 4), "guest-socks-connect-failed")
            exact(client, (4 if header[3] == 1 else 16) + 2)
            peer = resources.enter_context(origin.accept()[0])
            peer.settimeout(4)
            request, response = b"reboot-fixture-request", b"reboot-fixture-response"
            client.sendall(request)
            require(exact(peer, len(request)) == request, "guest-origin-did-not-receive-proxied-request")
            peer.sendall(response)
            require(exact(client, len(response)) == response, "guest-socks-did-not-return-origin-response")
            yield proc, descriptor, client, probe
    finally:
        try:
            probe["clean_engine"](proc, descriptor)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("guest-engine-cleanup-timed-out") from error


def prove_connected(session):
    proc, descriptor, client, _ = session
    require(proc.poll() is None and not select.select([descriptor, client], [], [], 0)[0],
            "vendor-or-socks-client-ended-before-reboot")


def stop_and_verify(session):
    proc, descriptor, client, probe = session
    proc.terminate()
    try:
        status = proc.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("guest-controller-stop-timed-out") from error
    require(status == 0 and bool(select.select([descriptor], [], [], 3)[0])
            and probe["listener_closed"](), "recovered-controller-did-not-stop-its-vendor")
    try:
        data = client.recv(1)
    except ConnectionResetError:
        data = b""
    require(data == b"", "recovered-socks-client-remained-connected")
