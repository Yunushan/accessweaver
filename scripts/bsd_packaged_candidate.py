"""Copy an already authenticated BSD candidate into a private guest payload.

Authentication is performed by the prior credential-scoped staging step. This
consumer pins its independently supplied source/ref/target, holds the private
staging directory, bounds reads and checks the executable digest again. It never
executes a downloaded binary or authenticates a receipt by its own assertions.
"""
import hashlib
import json
import os
import re
import stat

from verify_release_provenance import REPOSITORY, WORKFLOW, validate_identity


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate packaged candidate field")
        result[key] = value
    return result


def read_private(directory_fd, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_nlink != 1 or before.st_mode & 0o022 or not 0 < before.st_size <= maximum):
            raise ValueError("unsafe or unbounded staged candidate file")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or len(data) > maximum or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("staged candidate file changed while reading")
        return data


def copy_packaged_cli(directory, destination, source, arch, ref, *, goos="freebsd"):
    validate_identity(source, ref)
    if goos not in ("freebsd", "openbsd") or arch not in ("amd64", "arm64"):
        raise ValueError("unsupported packaged BSD target")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        # Open every source relative to this held directory, even after rename.
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("packaged staging directory must be owned and private")
        receipt = json.loads(read_private(fd, "candidate.json", 16 << 10), object_pairs_hook=unique_object)
        fields = {"schemaVersion", "sourceCommit", "sourceRef", "repository", "workflow", "target", "archive",
                  "archiveSha256", "manifestSha256", "bundleSha256", "binary", "binarySha256", "build",
                  "provenanceSubjectsVerified", "authenticatedBeforeStaging", "publisherSignatureVerified",
                  "productionQualificationComplete", "executionEnvironment"}
        if (not isinstance(receipt, dict) or set(receipt) != fields or type(receipt["schemaVersion"]) is not int or
                receipt["schemaVersion"] != 1 or type(receipt["provenanceSubjectsVerified"]) is not int or
                receipt["provenanceSubjectsVerified"] != 12 or receipt["authenticatedBeforeStaging"] is not True or
                receipt["publisherSignatureVerified"] is not False or receipt["productionQualificationComplete"] is not False):
            raise ValueError("unexpected packaged candidate receipt schema")
        for key, expected in {"sourceCommit": source, "sourceRef": ref, "repository": REPOSITORY, "workflow": WORKFLOW,
                              "target": goos + "/" + arch, "binary": "accessweaver",
                              "executionEnvironment": "disposable-" + goos + "-guest"}.items():
            if receipt[key] != expected:
                raise ValueError("packaged candidate identity mismatch: " + key)
        for key in ("archiveSha256", "manifestSha256", "bundleSha256", "binarySha256"):
            if not isinstance(receipt[key], str) or not re.fullmatch(r"[a-f0-9]{64}", receipt[key]):
                raise ValueError("invalid packaged candidate digest")
        if not isinstance(receipt["archive"], str) or not re.fullmatch(r"accessweaver-[A-Za-z0-9._-]+-" + goos + "-" + arch + r"\.tar\.gz", receipt["archive"]):
            raise ValueError("invalid packaged candidate archive")
        build = receipt["build"]
        if (not isinstance(build, dict) or set(build) != {"version", "commit", "sourceState", "builtAt", "goVersion", "platform", "arch"} or
                any(not isinstance(value, str) or not 0 < len(value) <= 256 for value in build.values())):
            raise ValueError("invalid packaged build identity")
        for key, expected in {"commit": source, "sourceState": "clean", "platform": goos, "arch": arch}.items():
            if build[key] != expected:
                raise ValueError("packaged build identity mismatch: " + key)
        binary = read_private(fd, "accessweaver", 64 << 20)
        if hashlib.sha256(binary).hexdigest() != receipt["binarySha256"]:
            raise ValueError("staged packaged executable digest mismatch")
    finally:
        os.close(fd)
    with destination.open("xb") as stream:
        stream.write(binary)
    destination.chmod(0o700)
    return receipt
