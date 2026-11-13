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
        (self.root / self.evidence).write_text("{}", encoding="utf-8")
        self.gates = [
            {"id": "functional.first", "status": "passed", "evidence": [self.evidence]},
            {"id": "functional.second", "status": "partial", "evidence": [self.evidence]},
            {"id": "reliability.third", "status": "failed", "evidence": [self.evidence]},
            {"id": "reliability.fourth", "status": "partial", "evidence": [self.evidence]},
        ]
        self.register = {
            "assessmentState": "in-progress",
            "scoring": {"total": 100, "gateWeight": 25},
            "areas": [{"gates": self.gates[:2]}, {"gates": self.gates[2:]}],
        }

    def summary(self):
        return summarize(self.register, self.root, {self.evidence})

    def test_only_passed_gates_earn_points(self):
        self.assertEqual(self.summary(), {
            "assessmentState": "in-progress", "score": 25, "total": 100,
            "counts": {"passed": 1, "partial": 2, "failed": 1},
            "failedGates": ["reliability.third"],
        })

    def test_completion_requires_all_gates(self):
        self.register["assessmentState"] = "complete"
        with self.assertRaisesRegex(ValueError, "assessment state"):
            self.summary()
        for gate in self.gates:
            gate["status"] = "passed"
        self.assertEqual(self.summary()["score"], 100)
        self.register["assessmentState"] = "in-progress"
        with self.assertRaisesRegex(ValueError, "assessment state"):
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
