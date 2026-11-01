#!/usr/bin/env python3
"""Exercise an isolated foreground controller without starting an engine.

Run as a normal Unix desktop user. Temporary profile/cache/log fixtures are
retained for diagnosis; the application must remove its private launch credential
on graceful shutdown. No account, service, driver or network setting is changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import url2pathname

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("--report", type=Path)
args = parser.parse_args()
if os.name != "posix" or os.geteuid() == 0:
    raise SystemExit("Run this test as a normal Unix user")
binary = args.binary.resolve(strict=True)
fixture = Path(tempfile.mkdtemp(prefix="accessweaver-controller-"))
state = fixture / "state"
server_log = fixture / "server.log"
env = dict(os.environ, ACCESSWEAVER_HOME=str(state),
           XDG_CACHE_HOME=str(fixture / "cache"), ACCESSWEAVER_NO_BROWSER="1")
result = {"passed": False, "platform": platform.system(), "checks": [],
          "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
process = None

def require(condition, description):
    if not condition:
        raise RuntimeError(description)
    result["checks"].append(description)

def cli(*arguments):
    return subprocess.run([str(binary), *arguments], env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=15)

try:
    with server_log.open("w", encoding="utf-8") as log:
        process = subprocess.Popen([str(binary), "ui"], env=env, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 15
        while "Open this private launch file in your browser: " not in server_log.read_text():
            if process.poll() is not None:
                raise RuntimeError("Isolated controller exited before creating its private launcher")
            if time.monotonic() > deadline:
                raise RuntimeError("Isolated controller did not become ready")
            time.sleep(0.05)
        lines = server_log.read_text().splitlines()
        launcher_url = next(line.removeprefix("Open this private launch file in your browser: ")
                            for line in lines if line.startswith("Open this private launch file in your browser: "))
        launcher = Path(url2pathname(urlsplit(launcher_url).path))
        duplicate = cli("ui")
        require(duplicate.returncode != 0 and "another AccessWeaver controller" in duplicate.stderr,
                "duplicate UI rejected while the first controller remains active")
        require(process.poll() is None, "first controller survives duplicate launch")
        profile = {"version": 1, "id": "controller-smoke", "name": "Isolated controller fixture",
                   "engine": "byedpi", "args": [], "routing": {"includeDomains": [], "excludeDomains": [], "applications": []},
                   "probe": {"host": "example.invalid", "port": 443, "tls": True, "timeoutSeconds": 1}}
        source = fixture / "import.json"
        source.write_text(json.dumps(profile), encoding="utf-8")
        blocked = cli("import", str(source))
        require(blocked.returncode != 0 and "another AccessWeaver controller" in blocked.stderr,
                "CLI import rejected while UI owns the root")
        require(not (state / "profiles" / "controller-smoke.json").exists(),
                "rejected import preserves saved profiles")
        require(cli("profiles").returncode == 0, "read-only CLI remains available")
        # An intentionally unusable proxy proves the private bootstrap bypasses
        # ambient proxy settings instead of forwarding its session credential.
        probe_env = dict(env, HTTP_PROXY="http://127.0.0.1:0", http_proxy="http://127.0.0.1:0",
                         HTTPS_PROXY="http://127.0.0.1:0", https_proxy="http://127.0.0.1:0",
                         NO_PROXY="", no_proxy="")
        probe = subprocess.run([sys.executable, str(Path(__file__).with_name("test-linux-session.py")),
                                "--mode", "owner", "--server-log", str(server_log)],
                               env=probe_env, capture_output=True, text=True, timeout=15)
        require(probe.returncode == 0 and json.loads(probe.stdout)["passed"],
                "private owner bootstrap bypasses proxies without disclosing a credential")
        process.send_signal(signal.SIGTERM)
        require(process.wait(timeout=15) == 0, "controller shuts down gracefully")
        require(not launcher.exists(), "shutdown removes the private launch credential")
        imported = cli("import", str(source))
        require(imported.returncode == 0, "CLI import succeeds after controller shutdown")
        saved = json.loads((state / "profiles" / "controller-smoke.json").read_text())
        require(saved["name"] == profile["name"], "post-shutdown import preserves profile contents")
        require((state / ".controller.lock").is_file(), "released coordination file remains in place")
    result["passed"] = True
except Exception as error:
    result["error"] = str(error)
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
sys.exit(0 if result["passed"] else 1)
