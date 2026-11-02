import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("darwin_storage",Path(__file__).with_name("test-darwin-storage.py"))
storage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)

class ImageAssociationTests(unittest.TestCase):
    def setUp(self):
        self.image=Path("/owned/pressure.sparseimage")
        self.mount=Path("/owned/mount")
        self.entities=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1","mount-point":str(self.mount)}]
    def info(self,entities=None):
        return {"images":[{"image-path":str(self.image),"system-entities":self.entities if entities is None else entities}]}
    def test_exact_owned_image_and_mount_select_their_associated_devices(self):
        self.assertEqual(storage.association(self.info(),self.image,self.mount),("/dev/disk20","/dev/disk21s1"))
    def test_other_images_and_missing_or_duplicate_associations_are_refused(self):
        for data in ({"images":[]},{"images":[{"image-path":"other","system-entities":self.entities}]},{"images":self.info()["images"]*2}):
            with self.subTest(data=data),self.assertRaises(RuntimeError):
                storage.association(data,self.image,self.mount)
    def test_wrong_or_ambiguous_mounts_and_invalid_devices_are_refused(self):
        for entities in ([{"dev-entry":"/dev/disk20"}],self.entities+[self.entities[1]],
                         [{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1;other","mount-point":str(self.mount)}],
                         [{"dev-entry":"/dev/disk21s1","mount-point":str(self.mount)}]):
            with self.subTest(entities=entities),self.assertRaises(RuntimeError):
                storage.association(self.info(entities),self.image,self.mount)

class NativeHelpEvidenceTests(unittest.TestCase):
    def test_minimal_help_retains_missing_flag_as_information(self):
        from subprocess import CompletedProcess
        result=storage.help_evidence(CompletedProcess([],1,b"Usage: hdiutil attach image",b""),b"-owners")
        self.assertFalse(result["basicHelpListsRequestedFlag"])
        self.assertEqual(result["statusCode"],1)
        self.assertEqual(result["bytes"],len(b"Usage: hdiutil attach image"))
        self.assertEqual(len(result["sha256"]),64)
    def test_empty_or_signalled_help_is_refused(self):
        from subprocess import CompletedProcess
        for result in [CompletedProcess([],0,b"",b""),CompletedProcess([],-9,b"partial",b"")]:
            with self.assertRaises(RuntimeError):storage.help_evidence(result,b"-owners")

class HostedGuardTests(unittest.TestCase):
    def test_nonhosted_wrong_os_root_or_missing_optin_never_launches_a_command(self):
        valid={"ACCESSWEAVER_DISPOSABLE_DARWIN_STORAGE_TEST":"1","GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted","RUNNER_OS":"macOS"}
        cases=[({},"Darwin",501),(dict(valid,RUNNER_ENVIRONMENT="self-hosted"),"Darwin",501),
               (valid,"Windows",501),(valid,"Darwin",0)]
        for environment,system,uid in cases:
            with self.subTest(system=system,uid=uid),patch.dict(os.environ,environment,clear=True),patch.object(storage.platform,"system",return_value=system),patch.object(storage.os,"geteuid",return_value=uid,create=True),patch.object(storage,"command") as command:
                with self.assertRaises(RuntimeError):storage.main()
                command.assert_not_called()

if __name__=="__main__":unittest.main()
