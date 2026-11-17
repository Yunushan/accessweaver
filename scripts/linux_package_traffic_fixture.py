"""Live engine checks for the optional Debian package maintenance probe."""
import hashlib
import os
from pathlib import Path
import runpy
import select
import socket
import subprocess
import sys

from linux_package_managed_fixture import ENV, PROFILE_ID, UID
from verify_release import release_file, require

NAMESPACE_PATH = Path("/proc/self/ns")


def namespaces():
    return tuple(os.readlink(NAMESPACE_PATH / name) for name in ("mnt", "net", "pid"))


def run_private(script):
    """Re-execute the normal CLI with a private loopback network and process table."""
    result = subprocess.run(["unshare", "--mount", "--propagation", "private", "--net",
                             "--pid", "--fork", "--mount-proc", "--kill-child",
                             sys.executable, "-B", script, *sys.argv[1:],
                             "--live-namespaces", *namespaces()], timeout=600)
    return result.returncode


def prepare_byedpi(executable, expected_sha, outside):
    require(os.getpid() == 1 and all(a != b for a, b in zip(namespaces(), outside, strict=True))
            and socket.if_nameindex() == [(1, "lo")],
            "The live package fixture requires isolated mount, network and PID namespaces")
    limit = 16 << 20
    release_file(executable, limit)
    with executable.open("rb") as stream:
        engine = stream.read(limit + 1)
    require(0 < len(engine) <= limit and hashlib.sha256(engine).hexdigest() == expected_sha,
            "ByeDPI executable does not match its pinned digest")
    subprocess.run(["ip", "link", "set", "dev", "lo", "up"], check=True, timeout=10)
    return engine


def executable_is(pid, path):
    result = subprocess.run(["setpriv", f"--reuid={UID}", f"--regid={UID}", "--clear-groups",
                             "readlink", f"/proc/{pid}/exe"],
                            env=ENV, capture_output=True, text=True, timeout=5)
    return result.returncode == 0 and result.stdout.rstrip("\n") == str(path)


def ordinary_process(pid):
    fields = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    return (all(fields[key].split() == [str(UID)] * 4 for key in ("Uid", "Gid"))
            and not fields["Groups"].strip()
            and all(int(fields[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapAmb"))
            and fields["NoNewPrivs"].strip() == "1")


def owned_engine(controller, engine):
    for task in Path(f"/proc/{controller.pid}/task").iterdir():
        try:
            children = (task / "children").read_text().split()
        except FileNotFoundError:
            continue
        for child in map(int, children):
            try:
                descriptor = os.pidfd_open(child)
            except ProcessLookupError:
                continue
            if executable_is(child, engine):
                return child, descriptor
            os.close(descriptor)
    raise ValueError("Expected child from the pinned ByeDPI executable")


def roundtrip_and_stop(managed):
    # The existing managed-engine acceptance script defines the loopback SOCKS5
    # exchange and cleanup helpers without starting its standalone probe on import.
    probe = runpy.run_path(str(Path(__file__).with_name("test-linux-managed-byedpi.py")))
    require(probe["listener_closed"](), "Loopback listener already in use")
    prior = managed.state()
    controller = subprocess.Popen(
        ["setpriv", "--no-new-privs", *managed.command("run", PROFILE_ID, ordinary=True)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=ENV)
    descriptor = None
    try:
        try:
            probe["wait_listener"](controller)
        except RuntimeError as error:
            if controller.poll() is not None:
                reason = controller.stderr.read(1024).decode("utf-8", "replace")
                raise ValueError("Installed controller could not start ByeDPI: " + reason.strip()) from error
            raise
        require(executable_is(controller.pid, managed.root / "usr/bin/accessweaver")
                and ordinary_process(controller.pid),
                "Expected the installed controller process with ordinary credentials")
        pid, descriptor = owned_engine(controller, managed.engine)
        require(ordinary_process(pid), "Expected ordinary ByeDPI process credentials")
        probe["socks_roundtrip"]()
        with socket.create_connection(("127.0.0.1", probe["PORT"]), timeout=4) as connected:
            connected.sendall(b"\x05\x01\x00")
            require(probe["recv_exact"](connected, 2) == b"\x05\x00", "Live SOCKS client did not negotiate")
            controller.terminate()
            require(controller.wait(timeout=10) == 0 and bool(select.select([descriptor], [], [], 3)[0])
                    and probe["listener_closed"](), "Controller shutdown did not release the owned engine and listener")
            try:
                after_stop = connected.recv(1)
            except ConnectionResetError:
                after_stop = b""
            require(after_stop == b"", "Live SOCKS client remained attached after controller shutdown")
        require(managed.state() == prior, "Engine shutdown changed enrolled policy or saved profiles")
    finally:
        probe["clean_engine"](controller, descriptor)
