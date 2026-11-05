"""Exercise the Darwin capture wrapper without launching any process."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("test-darwin-audit-commands.sh")
SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def embedded_program(script: str) -> str:
    marker = "<<'PY'\n"
    if script.count(marker) != 1:
        raise ValueError("expected one embedded capture program")
    return script.split(marker, 1)[1].split("\nPY\n", 1)[0]


def run_capture(program: str, arch: str, raw: bytes = b"", status: int = 0):
    """Run real wrapper composition/filtering against an inert Popen stub."""
    process = mock.Mock()
    process.stdout = io.BytesIO(raw)
    process.wait.return_value = status
    output = io.StringIO()
    environment = {"RUNNER_ARCH": {"arm64": "ARM64", "amd64": "X64"}[arch], "GO_VERSION": "1.27.3"}
    with mock.patch.object(sys, "argv", ["capture", SOURCE_COMMIT, arch]), \
            mock.patch.dict(os.environ, environment, clear=True), \
            mock.patch.object(subprocess, "Popen", return_value=process) as popen, \
            contextlib.redirect_stdout(output):
        try:
            exec(compile(program, str(SCRIPT), "exec"), {"__name__": "__main__"})
        except SystemExit as result:
            code = result.code
        else:
            raise AssertionError("capture program did not report an exit status")
    popen.assert_called_once()
    process.wait.assert_called_once_with()
    command = popen.call_args.args[0]
    if popen.call_args.kwargs != {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT}:
        raise AssertionError("unexpected process capture contract")
    return code, output.getvalue(), command


class DarwinAuditCommandCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = embedded_program(SCRIPT.read_text(encoding="utf-8"))

    def test_source_binding_survives_all_diagnostic_label_generation(self):
        for arch, runner_arch in (("arm64", "ARM64"), ("amd64", "X64")):
            with self.subTest(arch=arch):
                code, output, command = run_capture(self.program, arch)
                self.assertEqual(code, 0)
                self.assertEqual(output, "Ordinary Darwin audit source commands PASS\n")
                self.assertEqual(command[:4], ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i"])
                source_bindings = [value for value in command if value.startswith("GITHUB_SHA=")]
                self.assertEqual(source_bindings, ["GITHUB_SHA=" + SOURCE_COMMIT])
                self.assertIn("RUNNER_ARCH=" + runner_arch, command)
                self.assertIn("ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST=1", command)
                self.assertIn("ACCESSWEAVER_DISPOSABLE_DARWIN_AUDIT_COMMANDS_TEST=1", command)
                self.assertIn("-test.run=^TestDisposableDarwinAuditCommands$", command)

    def test_private_output_is_discarded_and_closed_failure_label_survives(self):
        label = "ordinary Darwin audit alias case: run-policy-document-direct-output"
        raw = ("PRIVATE_RAW_FIXTURE_VALUE\nsource_test.go:12: " + label + "\n").encode()
        code, output, _ = run_capture(self.program, "arm64", raw, 1)
        self.assertEqual(code, 1)
        self.assertEqual(output, label + "\nOrdinary Darwin audit source commands FAIL\n")
        self.assertNotIn("PRIVATE_RAW_FIXTURE_VALUE", output)

    def test_overlong_child_line_fails_closed_without_echo(self):
        code, output, _ = run_capture(self.program, "amd64", b"x" * 1025 + b"\n")
        self.assertEqual(code, 1)
        self.assertEqual(output, "Ordinary Darwin audit source commands FAIL\n")


if __name__ == "__main__":
    unittest.main()
