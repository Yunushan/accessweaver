"""Metadata-only handle census for an owned Windows test child.

Capture flags exclude object names, virtual memory, stacks and thread contexts.
Only aggregate object type names/counts leave this module. No handle values,
process IDs, access masks, object pointers, object names or paths are exported.
"""
from collections import Counter
import ctypes
import os
from ctypes import wintypes as w
import re
import subprocess


class TypeData(ctypes.Union):
    # Max member is the 48-byte x64/arm64 thread-specific structure. We never
    # request or read it, but preserve the documented union's size/alignment.
    _fields_ = [("alignment", ctypes.c_uint64), ("reserved", ctypes.c_byte * 48)]


class Entry(ctypes.Structure):
    _fields_ = [("handle", w.HANDLE), ("flags", w.DWORD), ("object_type", w.DWORD),
                ("capture_time", w.FILETIME), ("attributes", w.DWORD), ("granted_access", w.DWORD),
                ("handle_count", w.DWORD), ("pointer_count", w.DWORD), ("paged", w.DWORD),
                ("nonpaged", w.DWORD), ("creation_time", w.FILETIME), ("type_name_bytes", w.WORD),
                ("type_name", ctypes.c_void_p), ("object_name_bytes", w.WORD),
                ("object_name", ctypes.c_void_p), ("type_data", TypeData)]


def type_label(entry):
    """Read only the bounded kernel type label; never dereference ObjectName."""
    if not entry.type_name or not entry.type_name_bytes:
        return "UnavailableType"
    if entry.type_name_bytes % 2 or entry.type_name_bytes > 128:
        raise ValueError("Unexpected object type label length")
    label = ctypes.string_at(entry.type_name, entry.type_name_bytes).decode("utf-16-le")
    # Observed PSS buffers may include one terminating UTF-16 NUL in Length.
    if label.endswith(chr(0)):
        label = label[:-1]
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,63}", label):
        raise ValueError("Unexpected object type label")
    return label


class HandleCensus:
    def __init__(self, process):
        if os.name != "nt":
            raise ValueError("Windows process snapshot APIs are required")
        if ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(Entry) != 136:
            raise ValueError("Handle census requires the verified 64-bit Windows ABI")
        if not isinstance(process, subprocess.Popen) or process.poll() is not None:
            raise ValueError("Census requires a live child created by this observer")
        self.process = process
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        declarations = {
            "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "GetCurrentProcess": ([], w.HANDLE),
            "PssCaptureSnapshot": ([w.HANDLE, w.DWORD, w.DWORD, ctypes.POINTER(w.HANDLE)], w.DWORD),
            "PssWalkMarkerCreate": ([ctypes.c_void_p, ctypes.POINTER(w.HANDLE)], w.DWORD),
            "PssWalkSnapshot": ([w.HANDLE, w.DWORD, w.HANDLE, ctypes.c_void_p, w.DWORD], w.DWORD),
            "PssWalkMarkerFree": ([w.HANDLE], w.DWORD),
            "PssFreeSnapshot": ([w.HANDLE, w.HANDLE], w.DWORD),
        }
        for name, (arguments, result) in declarations.items():
            method = getattr(self.kernel, name)
            method.argtypes, method.restype = arguments, result
        # QUERY_INFORMATION | VM_READ | DUP_HANDLE; no write/operation/debug right.
        self.handle = self.kernel.OpenProcess(0x400 | 0x10 | 0x40, False, process.pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    @staticmethod
    def check(code):
        if code:
            raise ctypes.WinError(code)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.handle:
            if not self.kernel.CloseHandle(self.handle):
                raise ctypes.WinError(ctypes.get_last_error())
            self.handle = None

    def sample(self):
        if not self.handle or self.process.poll() is not None:
            raise RuntimeError("Census is closed or child has exited")
        snapshot, marker = w.HANDLE(), w.HANDLE()
        counts = Counter()
        try:
            # HANDLES | BASIC_INFORMATION. Deliberately no NAME_INFORMATION,
            # TYPE_SPECIFIC_INFORMATION, VA clone, contexts or trace collection.
            self.check(self.kernel.PssCaptureSnapshot(self.handle, 0x4 | 0x10, 0, ctypes.byref(snapshot)))
            self.check(self.kernel.PssWalkMarkerCreate(None, ctypes.byref(marker)))
            while True:
                entry = Entry()
                code = self.kernel.PssWalkSnapshot(snapshot, 2, marker, ctypes.byref(entry), ctypes.sizeof(entry))
                if code == 259:  # ERROR_NO_MORE_ITEMS
                    break
                self.check(code)
                if sum(counts.values()) >= 4096:
                    raise ValueError("Census exceeds bounded test-process handle limit")
                if entry.flags & 2 or entry.object_name_bytes:
                    raise ValueError("Unexpected object name capture")
                label = type_label(entry)
                counts[label] += 1
        finally:
            try:
                if marker.value:
                    self.check(self.kernel.PssWalkMarkerFree(marker))
            finally:
                if snapshot.value:
                    self.check(self.kernel.PssFreeSnapshot(self.kernel.GetCurrentProcess(), snapshot))
        if self.process.poll() is not None or not counts:
            raise RuntimeError("Incomplete or exited census child")
        return {"source": "Windows-PSS-handles-and-basic-information", "captureFlags": 20,
                "counts": dict(sorted(counts.items())), "total": sum(counts.values()),
                "objectNamesCaptured": False, "memoryCaptured": False}
