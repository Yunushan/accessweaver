#!/usr/bin/env python3
"""Guest-only WireGuard fixture qualification; publish fixed, source-bound data."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time

CRYPTO = "v0.58.1-0.20261009181718-2f1f834330b2"
CRYPTO_SUM = "h1:zGDaB+/Mus2mScKvZ23k+W9NAUbP56sNM9SptgvWI5A="
SOURCES = [".github/workflows/ci.yml", "scripts/fixture_qualification.py",
           "scripts/test_fixture_qualification.py", "scripts/check-vulnerability-report.py",
           "scripts/fixtures/wgpeer/main.go", "scripts/fixtures/wgpeer/cmd/probe/main.go",
           "scripts/fixtures/wgpeer/go.mod", "scripts/fixtures/wgpeer/go.sum",
           "scripts/security-tools/go.mod", "scripts/security-tools/go.sum"]
STAGES = ["source", "modules", "normal-build", "normal-self-test", "race-build",
          "race-self-test", "windows", "advisories", "complete"]

class Failure(Exception):
    def __init__(self, kind, code=None):
        super().__init__("Fixture qualification failed")
        self.kind, self.code = kind, code

def hosted_guest(environment, system, machine, uid):
    assert environment.get("GITHUB_ACTIONS") == "true"
    assert environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert environment.get("RUNNER_OS") == "Linux" and environment.get("RUNNER_ARCH") == "X64"
    assert system == "linux" and machine in ("x86_64", "AMD64") and uid > 0

def command(arguments, cwd, environment, limit=1 << 20, seconds=180):
    """Bound both output memory and the owned process group; never echo stderr."""
    child = subprocess.Popen(arguments, cwd=cwd, env=environment, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    chunks, size, failure = [], 0, None
    until = time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= until:
                    failure = "timeout"
                    break
                for key, _ in selector.select(min(1, max(0, until - time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(data)
                    if size > limit:
                        failure = "output-budget"
                        break
                    chunks.append(data)
                if failure:
                    break
        if failure:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
            raise Failure(failure)
        code = child.wait(timeout=30)
        if code:
            raise Failure("tool", code if 0 <= code <= 255 else None)
        return b"".join(chunks)
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
        child.stdout.close()

def identity(root, environment):
    source = command(["git", "rev-parse", "HEAD"], root, environment).decode().strip()
    tree = command(["git", "rev-parse", "HEAD^{tree}"], root, environment).decode().strip()
    assert re.fullmatch("[0-9a-f]{40}", source) and re.fullmatch("[0-9a-f]{40}", tree)
    assert not command(["git", "status", "--porcelain=v1"], root, environment)
    return source, tree

def hashes(root):
    result = {}
    for name in SOURCES:
        data = (root / name).read_bytes()
        assert 0 < len(data) <= 2 << 20
        result[name] = hashlib.sha256(data).hexdigest()
    return result

def decode_build_info(raw, target, race, source, role):
    lines = raw.decode("utf-8").splitlines()
    assert lines and lines[0].endswith(": go1.27.3")
    settings, dependencies, main, package = {}, {}, None, None
    for line in lines[1:]:
        fields = line.strip().split("\t")
        if fields[0] == "path":
            package = fields[1]
        elif fields[0] == "mod":
            main = fields[1]
        elif fields[0] == "dep":
            dependencies[fields[1]] = fields[2:]
        elif fields[0] == "build":
            key, value = fields[1].split("=", 1)
            settings[key] = value
    assert main == "accessweaver.test/wgpeer"
    assert package == "accessweaver.test/wgpeer" + ("/cmd/probe" if role == "probe" else "")
    assert settings.get("GOOS") == target.split("/")[0]
    assert settings.get("GOARCH") == target.split("/")[1]
    assert settings.get("CGO_ENABLED") == ("1" if race else "0")
    assert (settings.get("-race") == "true") is race
    if source is not None:
        assert settings.get("vcs.revision") == source and settings.get("vcs.modified") == "false"
    if role == "peer":
        assert dependencies.get("golang.org/x/crypto") == [CRYPTO, CRYPTO_SUM]
    else:
        assert "golang.org/x/crypto" not in dependencies
    return {"target": target, "race": race, "go": "go1.27.3", "role": role}

def inspect_binary(root, file, environment, target, race, source, role):
    before = file.read_bytes()
    assert 0 < len(before) <= 128 << 20
    if target.startswith("linux/"):
        assert before[:6] == b"\x7fELF\x02\x01" and int.from_bytes(before[18:20], "little") == 62
        kind = "elf"
    else:
        assert before[:2] == b"MZ"
        offset = int.from_bytes(before[60:64], "little")
        assert offset + 26 <= len(before) and before[offset:offset+4] == b"PE\x00\x00"
        assert int.from_bytes(before[offset+4:offset+6], "little") == 0x8664
        kind = "pe"
    info = decode_build_info(command(["go", "version", "-m", str(file)], root, environment),
                             target, race, source, role)
    assert file.read_bytes() == before
    return {**info, "format": kind, "binarySHA256": hashlib.sha256(before).hexdigest()}

def peer_result(value, now):
    assert type(value) is dict and set(value) == {"passed", "tcpIPv4", "udpIPv4", "tcpIPv6", "udpIPv6", "peer"}
    assert all(value[key] is True for key in ["passed", "tcpIPv4", "udpIPv4", "tcpIPv6", "udpIPv6"])
    peer = value["peer"]
    assert type(peer) is dict and set(peer) == {"last_handshake_time_sec", "rx_bytes", "tx_bytes"}
    assert all(type(v) is str and re.fullmatch("[0-9]{1,16}", v) for v in peer.values())
    numbers = {key: int(v) for key, v in peer.items()}
    assert now - 180 <= numbers["last_handshake_time_sec"] <= now + 5
    assert 0 < numbers["rx_bytes"] <= 1 << 40 and 0 < numbers["tx_bytes"] <= 1 << 40
    return {"tcpIPv4": True, "udpIPv4": True, "tcpIPv6": True, "udpIPv6": True,
            "freshHandshake": True, "rxBytes": numbers["rx_bytes"], "txBytes": numbers["tx_bytes"]}

def read_peer(path):
    named = path.lstat()
    assert stat.S_ISREG(named.st_mode) and 0 < named.st_size <= 4096 and named.st_mode & 0o077 == 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        data = os.read(fd, 4097)
        after = os.fstat(fd)
        assert (before.st_dev, before.st_ino) == (named.st_dev, named.st_ino)
        assert before.st_size == after.st_size == len(data) and before.st_mtime_ns == after.st_mtime_ns
    finally:
        os.close(fd)
    return peer_result(json.loads(data), int(time.time()))

def public_report(data):
    assert set(data) == {"schemaVersion", "sourceCommit", "sourceTree", "sourceSHA256", "hostedGuestVerified", "go", "cryptoVersion", "cryptoSum", "openpgpExcluded", "modes", "windows", "advisories", "sourceStable", "stage", "exitCode", "failureKind", "outcome", "productionQualificationComplete"}
    assert type(data["schemaVersion"]) is int and data["schemaVersion"] == 1 and data["hostedGuestVerified"] is True
    assert re.fullmatch("[0-9a-f]{40}", data["sourceCommit"]) and re.fullmatch("[0-9a-f]{40}", data["sourceTree"])
    assert set(data["sourceSHA256"]) == set(SOURCES) and all(re.fullmatch("[0-9a-f]{64}", h) for h in data["sourceSHA256"].values())
    assert data["go"] == "go1.27.3" and data["cryptoVersion"] == CRYPTO and data["cryptoSum"] == CRYPTO_SUM
    assert type(data["openpgpExcluded"]) is bool and type(data["sourceStable"]) is bool
    assert data["stage"] in STAGES and data["failureKind"] in ["none", "contract", "tool", "timeout", "output-budget", "io", "other"]
    assert data["exitCode"] is None or type(data["exitCode"]) is int and 0 <= data["exitCode"] <= 255
    assert data["productionQualificationComplete"] is False and data["outcome"] in ["passed", "failed"]
    for mode in data["modes"]:
        assert set(mode) == {"mode", "binary", "checks"} and mode["mode"] in ["normal", "race"]
        binary = mode["binary"]
        assert set(binary) == {"target", "race", "go", "role", "format", "binarySHA256"}
        assert binary["target"] == "linux/amd64" and binary["race"] is (mode["mode"] == "race") and binary["go"] == "go1.27.3" and binary["role"] == "peer" and binary["format"] == "elf" and re.fullmatch("[0-9a-f]{64}", binary["binarySHA256"])
        checks = mode["checks"]
        assert set(checks) == {"tcpIPv4", "udpIPv4", "tcpIPv6", "udpIPv6", "freshHandshake", "rxBytes", "txBytes"}
        assert all(checks[k] is True for k in ["tcpIPv4", "udpIPv4", "tcpIPv6", "udpIPv6", "freshHandshake"])
        assert all(type(checks[k]) is int and 0 < checks[k] <= 1 << 40 for k in ["rxBytes", "txBytes"])
    for binary in data["windows"]:
        assert set(binary) == {"target", "race", "go", "role", "format", "binarySHA256"}
        assert binary["target"] == "windows/amd64" and binary["race"] is False and binary["go"] == "go1.27.3" and binary["role"] in ["peer", "probe"] and binary["format"] == "pe" and re.fullmatch("[0-9a-f]{64}", binary["binarySHA256"])
    for advisory in data["advisories"]:
        assert set(advisory) == {"target", "scanner", "go", "databaseModifiedAt", "affected", "moduleOnly", "reportSHA256"}
        assert advisory["target"] in ["linux/amd64", "windows/amd64"] and advisory["scanner"] == "v1.9.0" and advisory["go"] == "go1.27.3"
        assert advisory["affected"] == 0 and advisory["moduleOnly"] == 0 and type(advisory["affected"]) is int and type(advisory["moduleOnly"]) is int and re.fullmatch("[0-9a-f]{64}", advisory["reportSHA256"])
        assert re.fullmatch("[0-9TZ:.+-]{20,40}", advisory["databaseModifiedAt"])
    passed = (data["stage"] == "complete" and data["failureKind"] == "none" and data["exitCode"] == 0 and data["sourceStable"] and data["openpgpExcluded"] and [m["mode"] for m in data["modes"]] == ["normal", "race"] and len(data["windows"]) == 2 and {b["role"] for b in data["windows"]} == {"peer", "probe"} and len(data["advisories"]) == 2 and {a["target"] for a in data["advisories"]} == {"linux/amd64", "windows/amd64"})
    assert (data["outcome"] == "passed") == passed
    encoded = json.dumps(data, separators=(",", ":")) + "\n"
    assert len(encoded.encode()) <= 32768
    return encoded

def main():
    hosted_guest(os.environ, os.sys.platform, platform.machine(), getattr(os, "geteuid", lambda: 0)())
    root = Path(__file__).resolve().parent.parent
    environment = dict(os.environ, GOTOOLCHAIN="local", GOMAXPROCS="2")
    source, tree = identity(root, environment)
    assert source == os.environ["GITHUB_SHA"]
    source_hashes = hashes(root)
    data = {"schemaVersion": 1, "sourceCommit": source, "sourceTree": tree, "sourceSHA256": source_hashes,
            "hostedGuestVerified": True, "go": "go1.27.3", "cryptoVersion": CRYPTO, "cryptoSum": CRYPTO_SUM,
            "openpgpExcluded": False, "modes": [], "windows": [], "advisories": [], "sourceStable": False,
            "stage": "source", "exitCode": None, "failureKind": "none", "outcome": "failed", "productionQualificationComplete": False}
    output = root / "build/fixture-qualification"
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    module = root / "scripts/fixtures/wgpeer"
    try:
        assert command(["go", "env", "GOHOSTOS", "GOHOSTARCH", "GOVERSION"], root, environment).decode().split() == ["linux", "amd64", "go1.27.3"]
        data["stage"] = "modules"
        command(["go", "mod", "verify"], module, environment)
        info = json.loads(command(["go", "list", "-m", "-json", "golang.org/x/crypto"], module, environment))
        assert info["Version"] == CRYPTO and info["Sum"] == CRYPTO_SUM
        cache = Path(command(["go", "env", "GOMODCACHE"], module, environment).decode().strip()).resolve()
        assert Path(info["Dir"]).resolve() == (cache / ("golang.org/x/crypto@" + CRYPTO)).resolve()
        assert not (Path(info["Dir"]) / "openpgp").exists()
        data["openpgpExcluded"] = True
        for mode in ["normal", "race"]:
            race = mode == "race"
            native = dict(environment, CGO_ENABLED="1" if race else "0")
            binary = output / ("wgpeer-" + mode)
            data["stage"] = mode + "-build"
            command(["go", "build", "-p=2", "-buildvcs=true", "-trimpath", *(["-race"] if race else []), "-o", str(binary), "."], module, native, seconds=300)
            binary_info = inspect_binary(root, binary, native, "linux/amd64", race, source, "peer")
            data["stage"] = mode + "-self-test"
            scratch = Path(tempfile.mkdtemp(prefix="accessweaver-fixture-", dir=os.environ["RUNNER_TEMP"]))
            try:
                command([str(binary), "self-test", str(scratch)], module, dict(native, ACCESSWEAVER_TEST_VM="1"), seconds=90)
                assert sorted(p.name for p in scratch.iterdir()) == ["self-test.json"]
                checks = read_peer(scratch / "self-test.json")
                assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_info["binarySHA256"]
                data["modes"].append({"mode": mode, "binary": binary_info, "checks": checks})
            finally:
                assert scratch.parent.resolve() == Path(os.environ["RUNNER_TEMP"]).resolve() and scratch.name.startswith("accessweaver-fixture-") and not scratch.is_symlink()
                shutil.rmtree(scratch)
        data["stage"] = "windows"
        for role, name in [("peer", "wgpeer.exe"), ("probe", "probe.exe")]:
            data["windows"].append(inspect_binary(root, Path(os.environ["RUNNER_TEMP"]) / name, environment, "windows/amd64", False, None, role))
        data["stage"] = "advisories"
        scanner = str(Path(os.environ["GOBIN"]) / "govulncheck")
        tool = command(["go", "version", "-m", scanner], root, environment).decode().splitlines()
        assert any(line.split()[:3] == ["mod", "golang.org/x/vuln", "v1.9.0"] for line in tool)
        spec = importlib.util.spec_from_file_location("advisory_contract", root / "scripts/check-vulnerability-report.py")
        contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contract)
        for target in ["linux/amd64", "windows/amd64"]:
            system, arch = target.split("/")
            raw = command([scanner, "-db", "https://vuln.go.dev", "-json", "./..."], module, dict(environment, GOOS=system, GOARCH=arch, CGO_ENABLED="0"), limit=32 << 20, seconds=300)
            result = contract.analyze(raw.decode("utf-8"), "accessweaver.test/wgpeer", "v1.9.0", "go1.27.3")
            assert result["passed"] and result["affectedCount"] == result["moduleOnlyCount"] == 0
            data["advisories"].append({"target": target, "scanner": "v1.9.0", "go": "go1.27.3", "databaseModifiedAt": result["databaseModifiedAt"], "affected": 0, "moduleOnly": 0, "reportSHA256": hashlib.sha256(raw).hexdigest()})
        data["stage"] = "source"
        assert identity(root, environment) == (source, tree) and hashes(root) == source_hashes
        data.update(sourceStable=True, stage="complete", exitCode=0, outcome="passed")
    except Failure as error:
        data.update(failureKind=error.kind, exitCode=error.code)
    except AssertionError:
        data["failureKind"] = "contract"
    except OSError:
        data["failureKind"] = "io"
    except Exception:
        data["failureKind"] = "other"
    encoded = public_report(data)
    fd = os.open(output / "status.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
        file.write(encoded)
    print(json.dumps({"stage": data["stage"], "outcome": data["outcome"], "failureKind": data["failureKind"]}))
    return 0 if data["outcome"] == "passed" else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, Failure):
        print("Guest fixture qualification refused")
        raise SystemExit(1)
