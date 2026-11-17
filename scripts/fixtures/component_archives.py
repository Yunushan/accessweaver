#!/usr/bin/env python3
"""Create small inert ZIP fixtures for the native Windows extraction contracts."""
import io
import json
from pathlib import Path
import stat
import struct
import sys
import warnings
import zipfile


def create(root):
    root.mkdir(parents=True, exist_ok=False)
    records = []

    def archive(name, members, *, expected="reject", zip64=False):
        path = root / (name + ".zip")
        old_size, old_count = zipfile.ZIP64_LIMIT, zipfile.ZIP_FILECOUNT_LIMIT
        try:
            if zip64:
                zipfile.ZIP64_LIMIT = 0
                zipfile.ZIP_FILECOUNT_LIMIT = 0
            with warnings.catch_warnings(), zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as target:
                warnings.simplefilter("ignore", UserWarning)
                for member, content in members:
                    target.writestr(member, content)
        finally:
            zipfile.ZIP64_LIMIT, zipfile.ZIP_FILECOUNT_LIMIT = old_size, old_count
        records.append(dict(name=path.name, expected=expected))
        return path

    def patch(name, members, edit):
        path = archive(name, members)
        data = bytearray(path.read_bytes())
        end = data.rfind(b"PK\x05\x06")
        central = struct.unpack_from("<I", data, end + 16)[0]
        edit(data, end, central)
        path.write_bytes(data)
        return path

    archive("valid", [("folder/", b""), ("folder/file.txt", b"payload"), ("empty.txt", b""), ("root.txt", b"replacement")], expected="valid")
    z64 = archive("valid-zip64", [("root.txt", b"replacement")], expected="valid", zip64=True)
    # Independently validate the CPython-produced small ZIP64 archive.
    with zipfile.ZipFile(z64) as check:
        assert check.read("root.txt") == b"replacement" and check.testzip() is None
    data = bytearray(z64.read_bytes());end = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HHII", data, end + 8, 65535, 65535, 0xffffffff, 0xffffffff)
    (root / "valid-zip64-sentinel.zip").write_bytes(data)
    records.append(dict(name="valid-zip64-sentinel.zip", expected="valid"))
    with zipfile.ZipFile(root / "valid-zip64-sentinel.zip") as check:
        assert check.read("root.txt") == b"replacement" and check.testzip() is None

    # Force streaming headers and an independent descriptor, with both forms
    # of the optional signature and both size widths.
    class NonSeekable(io.BytesIO):
        def seek(self, *args):
            raise io.UnsupportedOperation("streaming archive")

    for zip64 in (False, True):
        stream = NonSeekable()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as target:
            with target.open("root.txt", "w", force_zip64=zip64) as member:
                member.write(b"replacement")
        streamed = bytearray(stream.getvalue())
        end = streamed.rfind(b"PK\x05\x06")
        central = struct.unpack_from("<I", streamed, end + 16)[0]
        descriptor = central - (24 if zip64 else 16)
        assert streamed[descriptor:descriptor + 4] == b"PK\x07\x08"
        for signed in (True, False):
            data = bytearray(streamed)
            if not signed:
                del data[descriptor:descriptor + 4]
                struct.pack_into("<I", data, end - 4 + 16, central - 4)
            suffix = f"{'zip64' if zip64 else 'zip32'}-{'signed' if signed else 'unsigned'}"
            name = f"valid-descriptor-{suffix}.zip"
            (root / name).write_bytes(data)
            records.append(dict(name=name, expected="valid"))
            with zipfile.ZipFile(root / name) as check:
                assert check.read("root.txt") == b"replacement" and check.testzip() is None
            size_offset = descriptor + (4 if signed else 0) + (12 if zip64 else 8)
            struct.pack_into("<Q" if zip64 else "<I", data, size_offset, 1)
            name = f"invalid-descriptor-{suffix}.zip"
            (root / name).write_bytes(data)
            records.append(dict(name=name, expected="reject"))

    archive("empty", [])
    archive("too-many", [(f"item-{i:04d}.txt", b"") for i in range(4097)])
    bad_paths = {
        "traversal": "../outside.txt", "backslash-traversal": "..\\outside.txt",
        "absolute": "/outside.txt", "drive": "C:/outside.txt", "unc": "\\\\server\\share\\file",
        "ads": "root.txt:payload", "reserved": "NUL.txt", "reserved-child": "folder/COM1.log",
        "reserved-space": "con .txt", "trailing-dot": "file.", "trailing-space": "file ",
        "empty-segment": "folder//file", "control": "a\x01.txt", "wildcard": "file*.txt",
    }
    for name, bad_path in bad_paths.items():
        # Valid first entry proves whole-archive path validation precedes writes.
        archive(name, [("root.txt", b"replacement"), (bad_path, b"invalid")])
    archive("duplicate", [("root.txt", b"first"), ("root.txt", b"second")])
    archive("case-collision", [("root.txt", b"first"), ("ROOT.TXT", b"second")])
    archive("separator-collision", [("folder/file.txt", b"first"), ("folder\\file.txt", b"second")])
    archive("file-directory", [("folder", b"file"), ("folder/child.txt", b"child")])
    link = zipfile.ZipInfo("link");link.create_system = 3;link.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive("symlink", [("root.txt", b"replacement"), (link, b"root.txt")])

    patch("lying-count", [("root.txt", b"one"), ("other.txt", b"two")], lambda d, e, c: struct.pack_into("<HH", d, e + 8, 1, 1))
    patch("metadata-budget", [("root.txt", b"x")], lambda d, e, c: struct.pack_into("<I", d, e + 12, (16 << 20) + 1))
    patch("central-offset", [("root.txt", b"x")], lambda d, e, c: struct.pack_into("<I", d, e + 16, 0xffffffff))
    patch("underreported-metadata", [("root.txt", b"x"), ("other.txt", b"y")], lambda d, e, c: struct.pack_into("<HHI", d, e + 8, 1, 1, 54))
    patch("central-header", [("root.txt", b"x")], lambda d, e, c: d.__setitem__(c, 0))
    patch("central-member-bounds", [("root.txt", b"x")], lambda d, e, c: struct.pack_into("<H", d, c + 28, 65535))
    patch("end-comment", [("root.txt", b"x")], lambda d, e, c: struct.pack_into("<H", d, e + 20, 1))
    patch("multi-volume", [("root.txt", b"x")], lambda d, e, c: struct.pack_into("<H", d, e + 4, 1))
    patch("declared-budget", [("root.txt", b"x")], lambda d, e, c: struct.pack_into("<I", d, c + 24, (2 << 30) + 1))
    patch("underreported-stream", [("root.txt", b"actual-stream-data")], lambda d, e, c: struct.pack_into("<I", d, c + 24, 1))
    patch("overreported-stream", [("root.txt", b"actual-stream-data")], lambda d, e, c: struct.pack_into("<I", d, c + 24, 100))
    patch("different-local-name", [("root.txt", b"replacement")], lambda d, e, c: d.__setitem__(30, ord("x")))
    patch("different-local-crc", [("root.txt", b"replacement")], lambda d, e, c: d.__setitem__(14, d[14] ^ 1))
    patch("local-offset-in-directory", [("root.txt", b"replacement")], lambda d, e, c: struct.pack_into("<I", d, c + 42, c))
    patch("unsupported-compression", [("root.txt", b"actual-stream-data")], lambda d, e, c: struct.pack_into("<H", d, c + 10, 99))
    (root / "cases.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"Created {len(records)} inert archive cases")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Provide one new owned fixture directory")
    create(Path(sys.argv[1]))
