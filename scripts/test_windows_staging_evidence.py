import json
import sys
import unittest

import windows_staging_evidence as evidence


class WindowsStagingEvidenceTests(unittest.TestCase):
    def fixture(self, method):
        class Fixture(unittest.TestCase):
            def runTest(self):
                pass
        test = Fixture()
        test._testMethodName = method
        return test

    def failure(self):
        try:
            raise OSError(13, "PRIVATE_ACCOUNT_AND_PATH", "PRIVATE_CREDENTIAL")
        except OSError:
            return sys.exc_info()

    def test_subtest_and_error_details_cannot_enter_public_report(self):
        result = evidence.FixedResult()
        test = self.fixture(next(iter(evidence.TESTS)))
        result.addSubTest(test, {"PRIVATE_PROFILE": "PRIVATE_SECRET"}, self.failure())
        text = json.dumps(evidence.summarize(result))
        self.assertNotIn("PRIVATE", text)
        self.assertEqual(result.fixed[0]["test"], test._testMethodName)
        self.assertEqual(result.fixed[0]["errno"], 13)
        self.assertEqual(result.fixed[0]["frames"], [])
        self.assertEqual(len(result.errors), 1)
        self.assertFalse(result.wasSuccessful())

    def test_unselected_names_and_exception_classes_are_closed(self):
        class PRIVATE_EXCEPTION(Exception):
            pass
        try:
            raise PRIVATE_EXCEPTION("PRIVATE")
        except PRIVATE_EXCEPTION:
            error = sys.exc_info()
        result = evidence.FixedResult()
        result.addError(self.fixture("PRIVATE_NAME"), error)
        row, = result.fixed
        self.assertEqual(row["test"], "unselected-test")
        self.assertEqual(row["exception"], "other")
        self.assertNotIn("PRIVATE", json.dumps(evidence.summarize(result)))

    def test_skips_and_expected_failures_cannot_satisfy_native_gate(self):
        for mode in ("missing", "skip", "expected"):
            result = evidence.FixedResult()
            result.testsRun = len(evidence.TESTS)
            test = self.fixture(next(iter(evidence.TESTS)))
            if mode == "missing":
                result.testsRun -= 1
            elif mode == "skip":
                result.addSkip(test, "PRIVATE_SKIP_REASON")
            else:
                result.addExpectedFailure(test, self.failure())
            report = evidence.summarize(result)
            self.assertEqual(report["outcome"], "failed")
            self.assertNotIn("PRIVATE", json.dumps(report))

    def test_complete_suite_is_required_and_output_is_bounded(self):
        result = evidence.FixedResult()
        result.testsRun = len(evidence.TESTS)
        self.assertEqual(evidence.summarize(result)["outcome"], "passed")
        output = evidence.DiscardOutput()
        output.write("PRIVATE")
        self.assertFalse(hasattr(output, "buffer"))
        with self.assertRaises(RuntimeError):
            output.write("x" * (2 << 20))


if __name__ == "__main__":
    unittest.main()
