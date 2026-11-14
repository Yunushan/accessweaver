from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch

import check_readiness_evidence as readiness
from check_readiness_evidence import summarize


class ReadinessRegisterTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.evidence = "receipt.json"
        self.receipt = b'{"install":"passed","recovery":"passed"}'
        (self.root / self.evidence).write_bytes(self.receipt)
        path = Path(__file__).resolve().parents[1] / "docs" / "readiness-gates.json"
        self.register = json.loads(path.read_bytes())
        self.gates = [gate for area in self.register["areas"] for gate in area["gates"]]
        for gate in self.gates:
            gate.update(status="partial", evidence=[self.evidence])
            gate.pop("qualification", None)
        self.gates[0]["status"] = "passed"
        self.gates[2]["status"] = "failed"
        self.commit = "a" * 40
        self.qualification = {
            "sourceCommit": self.commit, "environment": "disposable desktop",
            "procedure": "install and recover", "result": "verified installed and original state",
            "evidenceSHA256": {self.evidence: hashlib.sha256(self.receipt).hexdigest()},
        }
        self.gates[0]["qualification"] = self.qualification
        self.register.update(assessmentState="in-progress", candidateCommit=self.commit)

    def summary(self):
        return summarize(self.register, self.root, {self.evidence})

    def test_only_passed_gates_earn_points(self):
        self.assertEqual(self.summary(), {
            "assessmentState": "in-progress", "candidateCommit": self.commit, "score": 2, "total": 100,
            "counts": {"passed": 1, "partial": 48, "failed": 1},
            "failedGates": ["functional.dns"],
        })

    def test_completion_requires_all_gates(self):
        self.register["assessmentState"] = "complete"
        with self.assertRaisesRegex(ValueError, "assessment state"):
            self.summary()
        for gate in self.gates:
            gate["status"] = "passed"
            gate["qualification"] = self.qualification
        self.assertEqual(self.summary()["score"], 100)
        self.register["assessmentState"] = "in-progress"
        with self.assertRaisesRegex(ValueError, "assessment state"):
            self.summary()

    def test_passing_gate_requires_complete_candidate_specific_evidence(self):
        for override, message in (
            (None, "needs a qualification record"),
            ({"sourceCommit": "b" * 40}, "differs from the assessed candidate"),
            ({"procedure": " "}, "environment, procedure and result"),
            ({"evidenceSHA256": {}}, "pin one or more cited evidence files"),
            ({"evidenceSHA256": {"other.json": "c" * 64}}, "pin one or more cited evidence files"),
            ({"evidenceSHA256": {self.evidence: "bad"}}, "invalid qualification evidence pin"),
        ):
            with self.subTest(override=override), self.assertRaisesRegex(ValueError, message):
                self.gates[0]["qualification"] = None if override is None else {**self.qualification, **override}
                self.summary()

    def test_changed_evidence_cannot_keep_a_pass(self):
        (self.root / self.evidence).write_text('{"changed":true}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "evidence digest differs"):
            self.summary()

    def test_qualification_requires_a_repository_relative_evidence_path(self):
        path = str(self.root / self.evidence)
        self.gates[0]["evidence"] = [path]
        self.qualification["evidenceSHA256"] = {path: hashlib.sha256(self.receipt).hexdigest()}
        with self.assertRaisesRegex(ValueError, "invalid qualification evidence pin"):
            summarize(self.register, self.root, {self.evidence, path})

    def test_caller_can_require_one_exact_candidate(self):
        self.assertEqual(summarize(self.register, self.root, {self.evidence},
                                   candidate_commit=self.commit)["score"], 2)
        for commit in ("b" * 40, "abc", "A" * 40):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "candidate"):
                summarize(self.register, self.root, {self.evidence}, candidate_commit=commit)
        del self.register["candidateCommit"]
        with self.assertRaisesRegex(ValueError, "differs from the assessed candidate"):
            self.summary()

    def test_register_rejects_duplicate_fields_at_any_depth(self):
        for data in (b'{"candidateCommit":null,"candidateCommit":null}',
                     b'{"areas":[{"status":"failed","status":"passed"}]}'):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                readiness.load_register(data)

    def test_production_check_requires_an_independently_supplied_candidate(self):
        with patch.object(sys, "argv", ["check_readiness_evidence.py", "--require-complete"]), \
                redirect_stderr(io.StringIO()) as messages, self.assertRaises(SystemExit) as failure:
            readiness.main()
        self.assertEqual(failure.exception.code, 2)
        self.assertIn("--require-complete requires --candidate-commit", messages.getvalue())

    def test_production_check_reports_exact_candidate_and_refuses_partial_readiness(self):
        docs = self.root / "docs"
        docs.mkdir()
        register = docs / "readiness-gates.json"
        def git(*arguments):
            return subprocess.check_output(["git", *arguments], cwd=self.root, timeout=30).decode("ascii").strip()

        git("init", "-q")
        git("add", self.evidence)
        git("-c", "user.name=Readiness Test", "-c", "user.email=test@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "Build candidate source")
        self.commit = git("rev-parse", "HEAD")
        self.register["candidateCommit"] = self.qualification["sourceCommit"] = self.commit
        argv = ["check_readiness_evidence.py", "--candidate-commit", self.commit, "--require-complete", "--json"]
        for complete in (False, True):
            if complete:
                self.register["assessmentState"] = "complete"
                for gate in self.gates:
                    gate.update(status="passed", qualification=self.qualification)
            register.write_text(json.dumps(self.register), encoding="utf-8")
            git("add", self.evidence, "docs/readiness-gates.json")
            git("-c", "user.name=Readiness Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "-qm", "Assess candidate")
            assessment = git("rev-parse", "HEAD")
            if not complete:
                earlier_assessment = assessment
            register.write_text("uncommitted change", encoding="utf-8")
            (self.root / self.evidence).unlink()
            with self.subTest(complete=complete), patch.object(sys, "argv", argv), \
                    patch.object(readiness, "__file__", str(self.root / "scripts" / "check_readiness_evidence.py")), \
                    redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as messages:
                self.assertEqual(readiness.main(), 0 if complete else 1)
                report = json.loads(output.getvalue())
                self.assertEqual(report["candidateCommit"], self.commit)
                self.assertEqual(report["assessmentCommit"], assessment)
                self.assertEqual(report["score"], 100 if complete else 2)
                self.assertEqual(bool(messages.getvalue()), not complete)
            (self.root / self.evidence).write_bytes(self.receipt)

        with patch.object(sys, "argv", [*argv, "--assessment-commit", earlier_assessment]), \
                patch.object(readiness, "__file__", str(self.root / "scripts" / "check_readiness_evidence.py")), \
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
            self.assertEqual(readiness.main(), 1)
            self.assertEqual(json.loads(output.getvalue())["assessmentCommit"], earlier_assessment)

        for identity, error in ((git("rev-parse", f"HEAD:{self.evidence}"), "Git commit"),
                                ("b" * len(self.commit), "unavailable")):
            self.register["candidateCommit"] = self.qualification["sourceCommit"] = identity
            register.write_text(json.dumps(self.register), encoding="utf-8")
            git("add", self.evidence, "docs/readiness-gates.json")
            git("-c", "user.name=Readiness Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "-qm", "Assess invalid candidate")
            invalid = ["check_readiness_evidence.py", "--candidate-commit", identity, "--require-complete"]
            with self.subTest(identity=identity), patch.object(sys, "argv", invalid), \
                    patch.object(readiness, "__file__", str(self.root / "scripts" / "check_readiness_evidence.py")), \
                    redirect_stdout(io.StringIO()) as output, self.assertRaisesRegex(ValueError, error):
                readiness.main()
            self.assertEqual(output.getvalue(), "")

    def test_invalid_status_cannot_be_counted(self):
        for status in ("pass", "Passed", "", False, None):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "invalid readiness status"):
                self.gates[0]["status"] = status
                self.summary()

    def test_float_and_incorrect_weights_are_rejected(self):
        for weight in (2.0, True, 4, -2):
            with self.subTest(weight=weight), self.assertRaisesRegex(ValueError, "weights"):
                self.register["scoring"]["gateWeight"] = weight
                self.summary()

    def test_scope_requires_every_original_acceptance_requirement(self):
        self.register["assessmentState"] = "complete"
        for gate in self.gates:
            gate.update(status="passed", qualification=self.qualification)
        self.assertEqual(self.summary()["score"], 100)
        area = self.register["areas"][0]
        removed = area["gates"].pop()
        with self.assertRaisesRegex(ValueError, "Readiness scope differs"):
            self.summary()
        area["gates"].append({**removed, "id": "functional.substitute"})
        with self.assertRaisesRegex(ValueError, "Readiness scope differs"):
            self.summary()
        area["gates"][-1] = {**removed, "acceptance": "Compilation passed."}
        with self.assertRaisesRegex(ValueError, "Readiness scope differs"):
            self.summary()
        area["gates"][-1] = removed
        area["gates"].reverse()
        self.register["areas"].reverse()
        self.assertEqual(self.summary()["score"], 100)

    def test_passed_gate_cannot_earn_points_with_missing_evidence(self):
        with self.assertRaisesRegex(ValueError, "missing from the checkout"):
            summarize(self.register, self.root, set())
        (self.root / self.evidence).unlink()
        with self.assertRaisesRegex(ValueError, "missing from the checkout"):
            self.summary()


if __name__ == "__main__":
    unittest.main()
