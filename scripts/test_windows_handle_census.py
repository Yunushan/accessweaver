import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import unittest
import uuid

from windows_handle_census import Entry, HandleCensus, type_label


class Labels(unittest.TestCase):
    def test_bounded_type_labels_do_not_accept_paths_or_control_data(self):
        self.assertEqual(type_label(Entry()), "UnavailableType")
        for text, valid in (("Event", True), ("ALPC Port", True), ("File\0", True),
                            ("private/path", False), ("private\\path", False), ("Token\nValue", False)):
            with self.subTest(valid=valid):
                buffer = ctypes.create_string_buffer(text.encode("utf-16-le"))
                entry = Entry(type_name=ctypes.cast(buffer, ctypes.c_void_p), type_name_bytes=len(text)*2)
                if valid:
                    self.assertEqual(type_label(entry), text.rstrip("\0"))
                else:
                    with self.assertRaises(ValueError):type_label(entry)
        with self.assertRaises(ValueError):type_label(Entry(type_name=1, type_name_bytes=3))
        with self.assertRaises(ValueError):type_label(Entry(type_name=1, type_name_bytes=130))

    @unittest.skipIf(os.name == "nt", "non-Windows rejection")
    def test_unsupported_platform_does_not_attempt_snapshot(self):
        with self.assertRaisesRegex(ValueError, "Windows"):
            HandleCensus(None)


@unittest.skipUnless(os.name == "nt", "requires Windows")
class NativeCensus(unittest.TestCase):
    def setUp(self):
        self.assertEqual(ctypes.sizeof(ctypes.c_void_p),8,"native census verification requires a 64-bit interpreter")
        self.marker = "AccessWeaver_PRIVATE_CENSUS_" + uuid.uuid4().hex
        code = "import ctypes,time,sys; k=ctypes.WinDLL('kernel32'); k.CreateEventW.restype=ctypes.c_void_p; h=k.CreateEventW(None,False,False,sys.argv[1]); assert h; print('ready',flush=True); time.sleep(30)"
        self.child = subprocess.Popen([sys.executable, "-c", code, self.marker], stdout=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_child)
        ready = queue.Queue(1)
        reader = threading.Thread(target=lambda:ready.put(self.child.stdout.readline()), daemon=True)
        reader.start()
        self.assertEqual(ready.get(timeout=5).strip(), "ready")
        reader.join(timeout=1)
        self.census = HandleCensus(self.child)
        self.addCleanup(self.census.close)
        from ctypes import wintypes as w
        self.w = w
        self.count = self.census.kernel.GetProcessHandleCount
        self.count.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.count.restype = w.BOOL

    def stop_child(self):
        if self.child.poll() is None:self.child.terminate()
        self.child.wait(timeout=5)
        self.child.stdout.close()

    def handles(self, process=None):
        value = self.w.DWORD()
        self.assertTrue(self.count(process or self.census.kernel.GetCurrentProcess(),ctypes.byref(value)))
        return value.value

    def test_native_type_counts_privacy_and_observer_cleanup(self):
        self.assertEqual(ctypes.sizeof(Entry),136)
        before = self.handles()
        samples = [self.census.sample() for _ in range(10)]
        after = self.handles()
        self.assertLessEqual(after,before)
        for sample in samples:
            self.assertEqual(sample['captureFlags'],20)
            self.assertFalse(sample['objectNamesCaptured'])
            self.assertFalse(sample['memoryCaptured'])
            self.assertEqual(sample['total'],sum(sample['counts'].values()))
            self.assertGreater(sample['counts'].get('Event',0),0)
            self.assertNotIn(self.marker,json.dumps(sample))
        # Counts may move during child startup. A stable child must agree with
        # the independent process-handle counter, including untyped entries.
        before_child = self.handles(self.census.handle)
        sample = self.census.sample()
        after_child = self.handles(self.census.handle)
        self.assertGreaterEqual(sample['total'],min(before_child,after_child))
        self.assertLessEqual(sample['total'],max(before_child,after_child))

    def test_unrequested_object_name_is_rejected_without_dereference(self):
        original = self.census.kernel.PssWalkSnapshot
        before = self.handles()
        def unexpected_name(snapshot, kind, marker, output, size):
            entry = ctypes.cast(output, ctypes.POINTER(Entry)).contents
            entry.flags = 2
            entry.object_name_bytes = 2
            entry.object_name = 1  # Invalid pointer must never be dereferenced.
            return 0
        self.census.kernel.PssWalkSnapshot = unexpected_name
        try:
            with self.assertRaisesRegex(ValueError, "Unexpected object name"):
                self.census.sample()
        finally:
            self.census.kernel.PssWalkSnapshot = original
        self.assertLessEqual(self.handles(), before)

    def test_closed_observer_rejects_sampling(self):
        self.census.close()
        self.census.close()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            self.census.sample()

    def test_walk_failure_releases_snapshot_and_marker(self):
        original = self.census.kernel.PssWalkSnapshot
        before = self.handles()
        self.census.kernel.PssWalkSnapshot = lambda *args:31
        try:
            with self.assertRaises(OSError):self.census.sample()
        finally:
            self.census.kernel.PssWalkSnapshot = original
        self.assertLessEqual(self.handles(),before)


if __name__ == "__main__":unittest.main()
