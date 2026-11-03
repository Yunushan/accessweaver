import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("darwin_storage",Path(__file__).with_name("test-darwin-storage.py"))
storage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)

class ImageFixture:
    def setUp(self):
        self.image=Path("/owned/pressure.sparseimage")
        self.mount=Path("/owned/mount")
        self.entities=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1","mount-point":str(self.mount)}]
    def info(self,entities=None):
        return {"images":[{"image-path":str(self.image),"system-entities":self.entities if entities is None else entities}]}

class ImageAssociationTests(ImageFixture,unittest.TestCase):
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

class NormalDetachTests(ImageFixture,unittest.TestCase):
    def test_busy_then_success_rebinds_and_never_forces(self):
        from subprocess import CompletedProcess
        busy=CompletedProcess([],16,b"",b"hdiutil: Resource busy")
        done=CompletedProcess([],0,b"",b"")
        with patch.object(storage,"info",side_effect=[self.info(),self.info(),{"images":[]}]),patch.object(storage,"command",side_effect=[busy,done]) as command,patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1"),2)
            self.assertEqual(command.call_count,2)
            for call in command.call_args_list:
                self.assertEqual(call.args[0],[storage.HDIUTIL,"detach","/dev/disk20"])
                self.assertLessEqual(call.kwargs["timeout"],30)
                self.assertGreater(call.kwargs["timeout"],0)

    def test_accepted_detach_waits_for_exact_association_to_disappear_without_redetaching(self):
        from subprocess import CompletedProcess
        partial=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage,"info",side_effect=[self.info(),self.info(),self.info(partial),{"images":[]}]),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command,patch.object(storage.time,"sleep") as sleep:
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1"),1)
            self.assertEqual(command.call_count,1);self.assertEqual(sleep.call_count,2)
            self.assertEqual(command.call_args.args[0],[storage.HDIUTIL,"detach","/dev/disk20"])

    def test_accepted_detach_never_resets_deadline_or_launches_another_detach(self):
        from subprocess import CompletedProcess
        with patch.object(storage.time,"monotonic",side_effect=[0,0,0,0,1,30]),patch.object(storage,"info",return_value=self.info()),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command,patch.object(storage.time,"sleep"):
            with self.assertRaisesRegex(RuntimeError,"associated after detach deadline"):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1")
            self.assertEqual(command.call_count,1)

    def test_accepted_detach_refuses_reassigned_devices_ambiguous_images_and_other_mounts(self):
        from subprocess import CompletedProcess
        changed=[{"dev-entry":"/dev/disk30"},self.entities[1]]
        relocated=[self.entities[0],dict(self.entities[1],**{"mount-point":"/other"})]
        for observed in (self.info(changed),{"images":self.info()["images"]*2},self.info(relocated)):
            with self.subTest(observed=observed),patch.object(storage,"info",side_effect=[self.info(),observed]),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command:
                with self.assertRaisesRegex(RuntimeError,"mapping changed after accepted detach"):
                    storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1")
                self.assertEqual(command.call_count,1)

    def test_clock_rounding_never_extends_detach_timeout_past_total_budget(self):
        from subprocess import CompletedProcess
        # (2.02 + 30) - 2.02 rounds above 30 on binary floating-point clocks.
        with patch.object(storage.time,"monotonic",return_value=2.02),patch.object(storage,"info",side_effect=[self.info(),{"images":[]}]),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command:
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1"),1)
            self.assertLessEqual(command.call_args.kwargs["timeout"],30)
            self.assertGreater(command.call_args.kwargs["timeout"],0)

    def test_changed_device_after_busy_is_not_detached(self):
        from subprocess import CompletedProcess
        changed=[{"dev-entry":"/dev/disk30"},self.entities[1]]
        with patch.object(storage,"info",side_effect=[self.info(),self.info(changed)]),patch.object(storage,"command",return_value=CompletedProcess([],16,b"",b"Resource busy")) as command,patch.object(storage.time,"sleep"):
            with self.assertRaisesRegex(RuntimeError,"mapping changed"):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1")
            self.assertEqual(command.call_count,1)

    def test_other_failure_is_not_retried(self):
        from subprocess import CompletedProcess
        with patch.object(storage,"info",return_value=self.info()),patch.object(storage,"command",return_value=CompletedProcess([],1,b"",b"unrelated failure")) as command:
            with self.assertRaisesRegex(RuntimeError,"normal detach failed"):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1")
            self.assertEqual(command.call_count,1)

    def test_busy_deadline_does_not_launch_another_detach(self):
        from subprocess import CompletedProcess
        with patch.object(storage.time,"monotonic",side_effect=[0,0,0,31]),patch.object(storage,"info",return_value=self.info()),patch.object(storage,"command",return_value=CompletedProcess([],16,b"",b"Resource busy")) as command:
            with self.assertRaisesRegex(RuntimeError,"detach deadline"):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1")
            self.assertEqual(command.call_count,1)

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
