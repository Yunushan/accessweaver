import hashlib
import tempfile
import unittest
from pathlib import Path

from check_readiness_evidence import summarize


class ReadinessRegisterTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.evidence = "receipt.json"
        self.receipt = b'{"install":"passed","recovery":"passed"}'
        (self.root / self.evidence).write_bytes(self.receipt)
        self.gates = [
            {"id": "functional.first", "status": "passed", "evidence": [self.evidence]},
            {"id": "functional.second", "status": "partial", "evidence": [self.evidence]},
            {"id": "reliability.third", "status": "failed", "evidence": [self.evidence]},
            {"id": "reliability.fourth", "status": "partial", "evidence": [self.evidence]},
        ]
        self.commit = "a" * 40
        self.qualification = {
            "sourceCommit": self.commit, "environment": "disposable desktop",
            "procedure": "install and recover", "result": "verified installed and original state",
            "evidenceSHA256": {self.evidence: hashlib.sha256(self.receipt).hexdigest()},
        }
        self.gates[0]["qualification"] = self.qualification
        self.register = {
            "assessmentState": "in-progress", "candidateCommit": self.commit,
            "scoring": {"total": 100, "gateWeight": 25},
            "areas": [{"gates": self.gates[:2]}, {"gates": self.gates[2:]}],
        }

    def summary(self):
        return summarize(self.register, self.root, {self.evidence})

    def test_only_passed_gates_earn_points(self):
        self.assertEqual(self.summary(), {
            "assessmentState": "in-progress", "candidateCommit": self.commit, "score": 25, "total": 100,
            "counts": {"passed": 1, "partial": 2, "failed": 1},
            "failedGates": ["reliability.third"],
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
                                   candidate_commit=self.commit)["score"], 25)
        for commit in ("b" * 40, "abc", "A" * 40):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "candidate"):
                summarize(self.register, self.root, {self.evidence}, candidate_commit=commit)
        del self.register["candidateCommit"]
        with self.assertRaisesRegex(ValueError, "differs from the assessed candidate"):
            self.summary()

    def test_invalid_status_cannot_be_counted(self):
        for status in ("pass", "Passed", "", False, None):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "invalid readiness status"):
                self.gates[0]["status"] = status
                self.summary()

    def test_float_and_incorrect_weights_are_rejected(self):
        for weight in (25.0, True, 24, -25):
            with self.subTest(weight=weight), self.assertRaisesRegex(ValueError, "weights"):
                self.register["scoring"]["gateWeight"] = weight
                self.summary()

    def test_passed_gate_cannot_earn_points_with_missing_evidence(self):
        with self.assertRaisesRegex(ValueError, "missing from the checkout"):
            summarize(self.register, self.root, set())
        (self.root / self.evidence).unlink()
        with self.assertRaisesRegex(ValueError, "missing from the checkout"):
            self.summary()


if __name__ == "__main__":
    unittest.main()
