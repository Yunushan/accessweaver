import importlib.util
from pathlib import Path
import unittest


driver_path = Path(__file__).with_name("test-linux-package-reboot.py")
spec = importlib.util.spec_from_file_location("linux_package_reboot_driver", driver_path)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class BootEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.versions = {"older": "0.1.0~alpha.2", "newer": "0.1.0~alpha.3"}
        self.controllers = {"older.deb": "a" * 64, "newer.deb": "b" * 64}
        self.first = {
            "phase": "before-reboot",
            "guestArchitecture": "amd64",
            "bootSHA256": "c" * 64,
            "installedVersion": self.versions["newer"],
            "acceptedRevision": 2,
            "controllerSHA256": self.controllers["newer.deb"],
            "initialControllerSHA256": self.controllers["older.deb"],
        }
        self.second = {
            **self.first,
            "phase": "after-reboot",
            "bootSHA256": "d" * 64,
            "rollbackVersion": self.versions["older"],
            "rollbackControllerSHA256": self.controllers["older.deb"],
            "rollbackKeptCurrentPolicy": True,
            "replayRefused": True,
            "purgePreservedState": True,
        }
        del self.second["initialControllerSHA256"]

    def verify(self):
        driver.verify_boots(self.first, self.second, "amd64", self.versions, self.controllers, False)

    def test_accepts_both_matching_package_payloads(self):
        self.verify()

    def test_rejects_same_wrong_executable_on_both_boots(self):
        self.first["controllerSHA256"] = self.second["controllerSHA256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "match the approved package payloads"):
            self.verify()

    def test_rejects_wrong_initial_or_rollback_executable(self):
        for report, key in (
            (self.first, "initialControllerSHA256"), (self.second, "rollbackControllerSHA256"),
        ):
            with self.subTest(key=key):
                original = report[key]
                report[key] = self.controllers["newer.deb"]
                try:
                    with self.assertRaisesRegex(ValueError, "match the approved package payloads"):
                        self.verify()
                finally:
                    report[key] = original

    def test_rejects_missing_rollback_executable_observation(self):
        del self.second["rollbackControllerSHA256"]
        with self.assertRaisesRegex(ValueError, "match the approved package payloads"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
