"""Numeric diagnostics derived only from target-selected, immutable test source.

The lexical declaration inventory is a diagnostic allowlist, not an execution
coverage catalogue. Guest exit status remains the acceptance result.
"""
import hashlib
import json
from pathlib import Path
import re
import stat

MAX_SOURCE = 2 << 20
MAX_OUTPUT = 8 << 20
MAX_ITEMS = 32


def digest_catalog(catalog):
    return hashlib.sha256(json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_catalog(repo, directory, filenames):
    repo = Path(repo).resolve()
    folder = repo / directory
    if (folder.resolve() != folder or not folder.is_dir() or
            not folder.is_relative_to(repo) or len(filenames) > 512 or len(set(filenames)) != len(filenames)):
        raise ValueError("test source selection differs")
    files, roots = [], set()
    for name in sorted(filenames):
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_.-]+_test\.go", name) is None:
            raise ValueError("test source filename differs")
        path = folder / name
        before = path.lstat()
        if path.resolve() != path or not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= MAX_SOURCE:
            raise ValueError("test source identity differs")
        raw = path.read_bytes()
        after = path.lstat()
        if len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("test source changed")
        files.append({"name": name, "sha256": hashlib.sha256(raw).hexdigest(), "lineCount": raw.count(b"\n") + 1})
        for match in re.finditer(rb"^func ((?:Test|Fuzz)(?:[A-Z0-9_][A-Za-z0-9_]*)?)\s*\(", raw, re.MULTILINE):
            name = match.group(1).decode("ascii")
            if name != "TestMain":
                roots.add(name)
    if len(roots) > 4096:
        raise ValueError("test declaration budget differs")
    return {"schemaVersion": 1, "files": files, "roots": sorted(roots)}


def observe_output(raw, catalog, exit_code):
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        raise ValueError("test observation byte budget differs")
    roots = {name: i for i, name in enumerate(catalog["roots"])}
    files = {row["name"]: (i, row["lineCount"]) for i, row in enumerate(catalog["files"])}
    failed, locations, unknown = set(), set(), 0
    if exit_code != 0:
        for line in raw.splitlines():
            match = re.fullmatch(rb"--- FAIL: ([A-Za-z0-9_]{1,256}) \([0-9.]+s\)", line)
            if match:
                name = match.group(1).decode("ascii")
                if name in roots:
                    failed.add(roots[name])
                else:
                    unknown += 1
            match = re.match(rb"^[ \t]+([A-Za-z0-9_.-]+_test\.go):([1-9][0-9]{0,6}):", line)
            if match:
                name, number = match.group(1).decode("ascii"), int(match.group(2))
                if name in files and number <= files[name][1]:
                    locations.add((files[name][0], number))
    result = {"catalogSHA256": digest_catalog(catalog), "rootCount": len(roots), "fileCount": len(files),
              "failedRootIDs": sorted(failed)[:MAX_ITEMS],
              "assertionLocations": [{"fileID": f, "line": n} for f, n in sorted(locations)[:MAX_ITEMS]],
              "unknownFailureNames": unknown, "truncated": len(failed) > MAX_ITEMS or len(locations) > MAX_ITEMS}
    validate_observation(result)
    return result


def integer(value, maximum, minimum=0):
    return type(value) is int and minimum <= value <= maximum


def validate_observation(data):
    keys = {"catalogSHA256", "rootCount", "fileCount", "failedRootIDs", "assertionLocations", "unknownFailureNames", "truncated"}
    if (not isinstance(data, dict) or set(data) != keys or
            not isinstance(data["catalogSHA256"], str) or re.fullmatch(r"[a-f0-9]{64}", data["catalogSHA256"]) is None or
            not integer(data["rootCount"], 4096) or not integer(data["fileCount"], 512) or
            not integer(data["unknownFailureNames"], 1_000_000) or type(data["truncated"]) is not bool):
        raise ValueError("test observation schema differs")
    failed, locations = data["failedRootIDs"], data["assertionLocations"]
    if (not isinstance(failed, list) or len(failed) > MAX_ITEMS or
            any(not integer(n, data["rootCount"] - 1) for n in failed) or failed != sorted(set(failed)) or
            not isinstance(locations, list) or len(locations) > MAX_ITEMS):
        raise ValueError("test observation IDs differ")
    rows = []
    for row in locations:
        if (not isinstance(row, dict) or set(row) != {"fileID", "line"} or
                not integer(row["fileID"], data["fileCount"] - 1) or not integer(row["line"], MAX_SOURCE + 1, 1)):
            raise ValueError("test observation location differs")
        rows.append((row["fileID"], row["line"]))
    if rows != sorted(set(rows)):
        raise ValueError("test observation location order differs")
    return data
