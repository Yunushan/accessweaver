#!/usr/bin/env python3
"""Probe an isolated test dashboard as its owner or a different local OS user.

No credential is printed and mutation probes deliberately contain invalid inputs,
so a broken authorization guard cannot launch an engine or change valid profiles.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--mode", choices=("owner", "foreign"), required=True)
parser.add_argument("--server-log", type=Path, required=True)
args = parser.parse_args()
lines = args.server_log.read_text(encoding="utf-8").splitlines()
address = next(line.removeprefix("AccessWeaver is running at ") for line in lines if line.startswith("AccessWeaver is running at "))
launcher_url = next(line.removeprefix("Open this private launch file in your browser: ") for line in lines if line.startswith("Open this private launch file in your browser: "))
if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", address):
    raise SystemExit("Test listener must be IPv4 loopback")
parsed = urlsplit(launcher_url)
if parsed.scheme != "file" or parsed.netloc:
    raise SystemExit("Expected a local private launcher")
launcher = Path(unquote(parsed.path))
credential = None
try:
    page = launcher.read_text(encoding="utf-8")
    readable = True
    if args.mode == "owner":
        credential = re.search(r"accessweaver-session=([A-Za-z0-9_-]{43})", page).group(1)
except PermissionError:
    readable = False

# Private loopback credentials must never traverse environment/system proxies.
loopback = build_opener(ProxyHandler({}))

def probe(method, path, payload=None):
    headers = {"Content-Type": "application/json"}
    if credential:
        headers["X-AccessWeaver-Token"] = credential
    data = None if payload is None else json.dumps(payload).encode()
    try:
        with loopback.open(Request(address + path, data=data, method=method, headers=headers), timeout=5) as response:
            return response.status, json.loads(response.read((1 << 20) + 1))
    except HTTPError as error:
        return error.code, None

status, bootstrap = probe("GET", "/api/bootstrap")
result = {"mode": args.mode, "uid": os.geteuid(), "launcherReadable": readable, "statuses": {"bootstrap": status}}
if args.mode == "owner":
    result["credentialReturned"] = bool(bootstrap and "token" in bootstrap)
    result["passed"] = readable and status == 200 and not result["credentialReturned"]
else:
    for name, method, path, payload in (
        ("profiles", "GET", "/api/v1/profiles", None),
        ("history", "GET", "/api/v1/system/history", None),
        ("save", "PUT", "/api/v1/profiles/invalid-probe", {}),
        ("start", "POST", "/api/v1/start", {"id": "missing-probe", "confirm": True, "expectedUpdatedAt": "invalid"}),
        ("systemStart", "POST", "/api/v1/system/start", {"planId": "invalid", "confirm": True}),
    ):
        result["statuses"][name] = probe(method, path, payload)[0]
    result["passed"] = not readable and all(value == 403 for value in result["statuses"].values())
print(json.dumps(result))
sys.exit(0 if result["passed"] else 1)
