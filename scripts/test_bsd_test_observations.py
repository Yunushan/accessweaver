import copy
import json
from pathlib import Path
import tempfile
import unittest
import bsd_test_observations as observations

class TestObservations(unittest.TestCase):
    def test_source_allowlist_discards_paths_accounts_values_and_unknown_names(self):
        with tempfile.TemporaryDirectory(prefix="accessweaver-bsd-observations-") as name:
            root = Path(name).resolve()
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
            self.assertTrue(root.name.startswith("accessweaver-bsd-observations-"))
            folder = root / "internal" / "fixture";folder.mkdir(parents=True)
            (folder / "fixture_test.go").write_text("package fixture\nfunc TestPublic(t *testing.T) {}\nfunc TestMain(m *testing.M) {}\n",encoding="utf-8")
            catalog = observations.source_catalog(root,"internal/fixture",["fixture_test.go"])
            self.assertEqual(catalog["roots"],["TestPublic"])
            raw = b"    fixture_test.go:2: PRIVATE_ACCOUNT_PATH_VALUE\n--- FAIL: TestPublic (0.01s)\n--- FAIL: PRIVATE_ACCOUNT_PATH_VALUE (0.00s)\n    private_test.go:1: PRIVATE_ACCOUNT_PATH_VALUE\n    fixture_test.go:999: PRIVATE_ACCOUNT_PATH_VALUE\n"
            data = observations.observe_output(raw,catalog,1)
            self.assertEqual(data["failedRootIDs"],[0])
            self.assertEqual(data["assertionLocations"],[{"fileID":0,"line":2}])
            self.assertEqual(data["unknownFailureNames"],1)
            self.assertNotIn("PRIVATE_ACCOUNT_PATH_VALUE",json.dumps(data))
            self.assertNotIn("fixture_test.go",json.dumps(data))
            clean = observations.observe_output(raw,catalog,0)
            self.assertEqual(clean["failedRootIDs"],[]);self.assertEqual(clean["assertionLocations"],[])
            for filenames in (["../private_test.go"],["fixture_test.go","fixture_test.go"]):
                with self.assertRaises(ValueError):observations.source_catalog(root,"internal/fixture",filenames)
            with self.assertRaises(ValueError):observations.source_catalog(root,"../private",[])
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())

    def test_ids_schema_duplicates_and_combined_limits_are_closed(self):
        catalog={"schemaVersion":1,"files":[{"name":"fixture_test.go","sha256":"a"*64,"lineCount":100}],"roots":["Test"+str(i) for i in range(40)]}
        raw=b"".join(("--- FAIL: Test%d (0.00s)\n    fixture_test.go:%d: PRIVATE\n"%(i,i+1)).encode() for i in range(40))
        data=observations.observe_output(raw,catalog,1)
        self.assertTrue(data["truncated"]);self.assertEqual(len(data["failedRootIDs"]),32);self.assertEqual(len(data["assertionLocations"]),32)
        for mutation in (lambda d:d.update(private="PRIVATE"),lambda d:d.update(rootCount=True),lambda d:d.update(failedRootIDs=[True]),lambda d:d.update(failedRootIDs=[1,1]),lambda d:d.update(failedRootIDs=[40]),lambda d:d.update(assertionLocations=[{"fileID":1,"line":1}])):
            changed=copy.deepcopy(data);mutation(changed)
            with self.assertRaises(ValueError):observations.validate_observation(changed)
        with self.assertRaises(ValueError):observations.observe_output(b"x"*(observations.MAX_OUTPUT+1),catalog,1)

if __name__ == "__main__":unittest.main()
