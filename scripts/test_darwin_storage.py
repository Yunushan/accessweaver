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

class PartialDetachObservationTests(ImageFixture,unittest.TestCase):
    def test_partial_original_binding_only_observes_disappearance(self):
        partial=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}];observations=[]
        with patch.object(storage,"info",side_effect=[self.info(partial),{"images":[]}]),patch.object(storage,"command") as command,patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",
                known_devices={"/dev/disk20","/dev/disk21s1"},observations=observations),0)
            command.assert_not_called()
        self.assertEqual(observations[0]["exactMountCount"],0)
        self.assertTrue(observations[0]["safeKnownMapping"])
        self.assertEqual(observations[-1]["ownedImageCount"],0)

    def test_busy_then_partial_never_issues_another_detach_without_full_binding(self):
        from subprocess import CompletedProcess
        partial=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage,"info",side_effect=[self.info(),self.info(partial),{"images":[]}]),patch.object(storage,"command",return_value=CompletedProcess([],16,b"",b"Resource busy")) as command,patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1"),1)
            self.assertEqual(command.call_count,1)

    def test_busy_partial_then_restored_full_binding_permits_normal_retry(self):
        from subprocess import CompletedProcess
        partial=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}];observations=[]
        def command(*args,**kwargs):
            self.assertEqual(observations[-1]["exactMountCount"],1)
            self.assertTrue(observations[-1]["basePresent"])
            return CompletedProcess([],16,b"",b"Resource busy") if len(calls)==0 else CompletedProcess([],0,b"",b"")
        calls=[]
        def invoke(*args,**kwargs):
            result=command(*args,**kwargs);calls.append(args);return result
        with patch.object(storage,"info",side_effect=[self.info(),self.info(partial),self.info(),{"images":[]}]),patch.object(storage,"command",side_effect=invoke),patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",observations=observations),2)
        self.assertEqual(len(calls),2)

    def test_partial_mapping_does_not_extend_original_deadline(self):
        partial=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage.time,"monotonic",side_effect=[0,0,0,30]),patch.object(storage,"info",return_value=self.info(partial)),patch.object(storage,"command") as command,patch.object(storage.time,"sleep"):
            with self.assertRaisesRegex(RuntimeError,"detach deadline"):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk21s1"})
            command.assert_not_called()

    def test_unknown_devices_mounts_duplicate_or_conflicting_ownership_refuse(self):
        wrong=[{"dev-entry":"/dev/disk30"},{"dev-entry":"/dev/disk21s1"}]
        relocated=[self.entities[0],dict(self.entities[1],**{"mount-point":"/private/unknown-secret"})]
        collision=self.info();collision["images"].append({"image-path":"/private/other-secret","system-entities":[{"dev-entry":"/dev/disk20"}]})
        malformed=[{"dev-entry":[]}]
        for snapshot in (self.info(wrong),self.info(relocated),{"images":self.info()["images"]*2},collision,self.info(malformed)):
            observations=[]
            with self.subTest(snapshot=snapshot),patch.object(storage,"info",return_value=snapshot),patch.object(storage,"command") as command:
                with self.assertRaises(RuntimeError):
                    storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk21s1"},observations=observations)
                command.assert_not_called()
                import json
                self.assertNotIn("secret",json.dumps(observations))
                self.assertNotIn(str(self.image),json.dumps(observations))

    def test_observations_retain_only_last_eight_bounded_frames(self):
        partial=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}];observations=[]
        with patch.object(storage,"info",side_effect=[self.info(partial)]*12+[{"images":[]}]),patch.object(storage,"command") as command,patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk21s1"},observations=observations),0)
            command.assert_not_called()
        self.assertEqual(len(observations),8)
        self.assertTrue(all(set(frame)=={"phase","ownedImageCount","deviceLabels","basePresent","volumePresent","exactMountCount","unexpectedMountCount","conflictingDeviceAssociation","safeKnownMapping"} for frame in observations))

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



class UnmountedOriginalBindingTests(ImageFixture,unittest.TestCase):
    def test_complete_unmounted_binding_requires_original_filesystem_identities(self):
        from subprocess import CompletedProcess
        unmounted=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        observations=[];diagnostics={};original=("image","mount","capsule")
        with patch.object(storage,"info",side_effect=[self.info(unmounted),{"images":[]}]),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command,patch.object(storage,"check_owned_cleanup_identity") as check:
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk21s1"},observations=observations,owned_identity=original,diagnostics=diagnostics),1)
            self.assertEqual(command.call_args.args[0],[storage.HDIUTIL,"detach","/dev/disk20"])
            self.assertTrue(all(call.kwargs["unmounted"] is True for call in check.call_args_list))
            self.assertEqual(check.call_count,2)
        self.assertEqual(diagnostics["normalDetachAttempts"],1)
        self.assertEqual(diagnostics["unmountedOriginalBindingDetachAttempts"],1)
        self.assertTrue(diagnostics["normalDetachAccepted"])
        self.assertEqual(diagnostics["normalDetachObservations"][0]["outcome"],"accepted")

    def test_busy_mounted_then_complete_unmounted_binding_permits_identity_checked_normal_retry(self):
        from subprocess import CompletedProcess
        unmounted=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        diagnostics={}
        with patch.object(storage,"info",side_effect=[self.info(),self.info(unmounted),{"images":[]}]),patch.object(storage,"command",side_effect=[CompletedProcess([],16,b"",b"Resource busy"),CompletedProcess([],0,b"",b"")]) as command,patch.object(storage,"check_owned_cleanup_identity"),patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",owned_identity=("image","mount","capsule"),diagnostics=diagnostics),2)
        self.assertEqual(command.call_count,2)
        self.assertEqual([case["outcome"] for case in diagnostics["normalDetachObservations"]],["busy","accepted"])
        self.assertEqual([case["unmountedOriginalBinding"] for case in diagnostics["normalDetachObservations"]],[False,True])

    def test_subset_of_original_devices_stays_observe_only_even_with_identity(self):
        partial=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage,"info",side_effect=[self.info(partial),{"images":[]}]),patch.object(storage,"command") as command,patch.object(storage,"check_owned_cleanup_identity") as check,patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk20s1","/dev/disk21","/dev/disk21s1"},owned_identity=("image","mount","capsule")),0)
            command.assert_not_called();check.assert_not_called()

    def test_changed_owned_identity_refuses_unmounted_detach(self):
        unmounted=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage,"info",return_value=self.info(unmounted)),patch.object(storage,"command") as command,patch.object(storage,"check_owned_cleanup_identity",side_effect=RuntimeError("identity changed")):
            with self.assertRaisesRegex(RuntimeError,"identity changed"):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk21s1"},owned_identity=("image","mount","capsule"))
            command.assert_not_called()

    def test_accepted_unmounted_detach_only_observes_until_disappearance(self):
        from subprocess import CompletedProcess
        unmounted=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage,"info",side_effect=[self.info(unmounted),self.info(unmounted),{"images":[]}]),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command,patch.object(storage,"check_owned_cleanup_identity"),patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk21s1"},owned_identity=("image","mount","capsule")),1)
            self.assertEqual(command.call_count,1)

    def test_failed_detach_retains_attempt_count_and_bounded_nonsecret_result(self):
        from subprocess import CompletedProcess
        diagnostics={}
        with patch.object(storage,"info",return_value=self.info()),patch.object(storage,"command",return_value=CompletedProcess([],1,b"",b"failure /private/owned-secret")):
            with self.assertRaises(RuntimeError):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",diagnostics=diagnostics)
        self.assertEqual(diagnostics["normalDetachAttempts"],1)
        self.assertFalse(diagnostics["normalDetachAccepted"])
        self.assertEqual(diagnostics["normalDetachObservations"][0]["exitCode"],1)
        import json
        self.assertNotIn("secret",json.dumps(diagnostics))


    def test_detach_failure_diagnostics_keep_only_last_eight_results(self):
        from subprocess import CompletedProcess
        diagnostics={}
        with patch.object(storage,"info",side_effect=[self.info()]*20+[{"images":[]}]),patch.object(storage,"command",return_value=CompletedProcess([],16,b"",b"Resource busy")),patch.object(storage.time,"sleep"):
            self.assertEqual(storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",diagnostics=diagnostics),20)
        self.assertEqual(diagnostics["normalDetachAttempts"],20)
        self.assertEqual(len(diagnostics["normalDetachObservations"]),8)
        self.assertEqual([case["attempt"] for case in diagnostics["normalDetachObservations"]],list(range(13,21)))

    def test_timed_out_normal_command_retains_started_attempt(self):
        from subprocess import TimeoutExpired
        diagnostics={}
        with patch.object(storage,"info",return_value=self.info()),patch.object(storage,"command",side_effect=TimeoutExpired("hdiutil",1)):
            with self.assertRaises(TimeoutExpired):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",diagnostics=diagnostics)
        self.assertEqual(diagnostics["normalDetachAttempts"],1)
        self.assertEqual(diagnostics["normalDetachObservations"][0]["outcome"],"timeout")
        self.assertFalse(diagnostics["normalDetachAccepted"])

    def test_identity_revalidation_never_extends_original_deadline(self):
        unmounted=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage.time,"monotonic",side_effect=[0,0,0,30]),patch.object(storage,"info",return_value=self.info(unmounted)),patch.object(storage,"check_owned_cleanup_identity"),patch.object(storage,"command") as command:
            with self.assertRaisesRegex(RuntimeError,"detach deadline"):
                storage.detach_owned(self.image,self.mount,"/dev/disk20","/dev/disk21s1",known_devices={"/dev/disk20","/dev/disk21s1"},owned_identity=("image","mount","capsule"))
            command.assert_not_called()

class OwnedCleanupIdentityTests(ImageFixture,unittest.TestCase):
    def original(self):
        from types import SimpleNamespace
        import stat
        return (SimpleNamespace(st_dev=1,st_ino=20,st_uid=501,st_mode=stat.S_IFREG|0o600,st_nlink=1),
                SimpleNamespace(st_dev=1,st_ino=21,st_uid=501,st_mode=stat.S_IFDIR|0o700,st_nlink=2),
                SimpleNamespace(st_dev=1,st_ino=22,st_uid=501,st_mode=stat.S_IFDIR|0o700,st_nlink=2))
    def test_exact_original_regular_image_capsule_and_unmounted_host_directory(self):
        original=self.original();actual={self.image:original[0],self.mount:original[1],self.image.parent:original[2]}
        with patch.object(Path,"lstat",lambda path:actual[path]),patch.object(storage.os,"geteuid",return_value=501,create=True):
            storage.check_owned_cleanup_identity(self.image,self.mount,original,unmounted=True)
    def test_replaced_linked_foreign_writable_or_symlink_objects_are_refused(self):
        from types import SimpleNamespace
        import stat
        for index,field,value in [(0,"st_ino",99),(0,"st_nlink",2),(0,"st_uid",502),(0,"st_mode",stat.S_IFREG|0o666),
                                  (1,"st_ino",99),(1,"st_dev",2),(1,"st_mode",stat.S_IFLNK|0o777),
                                  (2,"st_ino",99),(2,"st_mode",stat.S_IFDIR|0o777)]:
            original=self.original();changed=list(original);fields=dict(vars(changed[index]));fields[field]=value;changed[index]=SimpleNamespace(**fields)
            actual={self.image:changed[0],self.mount:changed[1],self.image.parent:changed[2]}
            with self.subTest(index=index,field=field),patch.object(Path,"lstat",lambda path:actual[path]),patch.object(storage.os,"geteuid",return_value=501,create=True):
                with self.assertRaises(RuntimeError):storage.check_owned_cleanup_identity(self.image,self.mount,original,unmounted=True)



class ControlledUnmountProtocolTests(ImageFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.original=("image","mount","capsule")
        self.known={"/dev/disk20","/dev/disk21s1"}
    def invoke(self,record):
        return storage.unmount_owned_volume(self.image,self.mount,"/dev/disk20","/dev/disk21s1",self.known,self.original,record)
    def test_normal_unmount_uses_only_verified_volume_then_checks_original_unmounted_binding(self):
        from subprocess import CompletedProcess
        after=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}];record={}
        with patch.object(storage,"require_disposable_host"),patch.object(storage,"info",side_effect=[self.info(),self.info(after)]),patch.object(storage,"check_owned_cleanup_identity") as identity,patch.object(storage,"command",return_value=CompletedProcess([],0,b"unmounted",b"")) as command:
            self.invoke(record)
            self.assertEqual(command.call_count,1)
            self.assertEqual(command.call_args.args[0],[storage.HDIUTIL,"unmount","/dev/disk21s1"])
            self.assertEqual(command.call_args.kwargs["timeout"],30)
            self.assertEqual([call.kwargs["unmounted"] for call in identity.call_args_list],[False,True])
        self.assertTrue(record["originalUnmountedBindingVerified"])
        self.assertEqual(record["normalUnmountExitCode"],0)

    def test_missing_host_optin_never_queries_or_launches_native_commands(self):
        with patch.dict(os.environ,{},clear=True),patch.object(storage,"info") as info,patch.object(storage,"command") as command,patch.object(storage.tempfile,"mkdtemp") as create:
            with self.assertRaises(RuntimeError):self.invoke({})
            with self.assertRaises(RuntimeError):storage.controlled_unmounted_image(Path("/owned"),"a"*40,"amd64",{})
            info.assert_not_called();command.assert_not_called();create.assert_not_called()


    def test_controlled_case_refuses_foreign_parent_source_and_target_before_creating_anything(self):
        source="a"*40;workspace=Path("owned-test-workspace").resolve()
        valid={"GITHUB_WORKSPACE":str(workspace),"GITHUB_SHA":source,"ACCESSWEAVER_EXPECT_GOARCH":"amd64"}
        for parent,commit,arch in ((workspace/"outside",source,"amd64"),(workspace/"build"/"storage-capsules","b"*40,"amd64"),(workspace/"build"/"storage-capsules",source,"arm64")):
            with self.subTest(parent=parent,commit=commit,arch=arch),patch.dict(os.environ,valid,clear=True),patch.object(storage,"require_disposable_host"),patch.object(storage,"guarded_directory") as guard,patch.object(storage.tempfile,"mkdtemp") as create,patch.object(storage,"command") as command:
                with self.assertRaisesRegex(RuntimeError,"source, target or parent"):storage.controlled_unmounted_image(parent,commit,arch,{})
                guard.assert_not_called();create.assert_not_called();command.assert_not_called()

    def test_controlled_evidence_cannot_reuse_a_previous_result(self):
        with patch.object(storage,"require_disposable_host"),patch.object(storage.tempfile,"mkdtemp") as create,patch.object(storage,"command") as command:
            with self.assertRaisesRegex(RuntimeError,"evidence must be new"):
                storage.controlled_unmounted_image(Path("/owned"),"a"*40,"amd64",{"passed":True})
            create.assert_not_called();command.assert_not_called()

    def test_changed_initial_device_mapping_or_filesystem_identity_never_unmounts(self):
        wrong=self.info([{"dev-entry":"/dev/disk30"},self.entities[1]])
        for changed in (True,False):
            with self.subTest(changed_mapping=changed),patch.object(storage,"require_disposable_host"),patch.object(storage,"info",return_value=wrong if changed else self.info()),patch.object(storage,"check_owned_cleanup_identity",side_effect=RuntimeError("changed")) as check,patch.object(storage,"command") as command:
                with self.assertRaises(RuntimeError):self.invoke({})
                command.assert_not_called()

    def test_failed_normal_unmount_is_not_retried_or_forced(self):
        from subprocess import CompletedProcess
        record={}
        with patch.object(storage,"require_disposable_host"),patch.object(storage,"info",return_value=self.info()),patch.object(storage,"check_owned_cleanup_identity"),patch.object(storage,"command",return_value=CompletedProcess([],16,b"",b"busy /private/secret")) as command:
            with self.assertRaisesRegex(RuntimeError,"normal unmount did not succeed"):self.invoke(record)
            self.assertEqual(command.call_count,1)
        self.assertEqual(record["normalUnmountExitCode"],16)
        self.assertNotIn("originalUnmountedBindingVerified",record)
        import json
        self.assertNotIn("secret",json.dumps(record))

    def test_disappeared_reassigned_or_foreign_mounted_association_cannot_qualify_the_path(self):
        from subprocess import CompletedProcess
        wrong=self.info([{"dev-entry":"/dev/disk30"},{"dev-entry":"/dev/disk21s1"}])
        foreign=self.info([self.entities[0],dict(self.entities[1],**{"mount-point":"/other"})])
        for after in ({"images":[]},wrong,foreign):
            record={}
            with self.subTest(after=after),patch.object(storage,"require_disposable_host"),patch.object(storage,"info",side_effect=[self.info(),after]),patch.object(storage,"check_owned_cleanup_identity"),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command:
                with self.assertRaises(RuntimeError):self.invoke(record)
                self.assertEqual(command.call_count,1)
            self.assertNotIn("originalUnmountedBindingVerified",record)

    def test_changed_host_mount_vnode_after_unmount_refuses_qualification(self):
        from subprocess import CompletedProcess
        after=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}];record={}
        with patch.object(storage,"require_disposable_host"),patch.object(storage,"info",side_effect=[self.info(),self.info(after)]),patch.object(storage,"check_owned_cleanup_identity",side_effect=[None,RuntimeError("changed host mount")]),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")):
            with self.assertRaisesRegex(RuntimeError,"changed host mount"):self.invoke(record)
        self.assertNotIn("originalUnmountedBindingVerified",record)

    def test_stale_mounted_observation_waits_without_launching_another_unmount(self):
        from subprocess import CompletedProcess
        after=[{"dev-entry":"/dev/disk20"},{"dev-entry":"/dev/disk21s1"}]
        with patch.object(storage,"require_disposable_host"),patch.object(storage,"info",side_effect=[self.info(),self.info(),self.info(after)]),patch.object(storage,"check_owned_cleanup_identity"),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command,patch.object(storage.time,"sleep") as sleep:
            self.invoke({})
            self.assertEqual(command.call_count,1);self.assertEqual(sleep.call_count,1)

    def test_observation_deadline_is_not_extended_and_partial_state_is_not_qualified(self):
        from subprocess import CompletedProcess
        record={}
        with patch.object(storage,"require_disposable_host"),patch.object(storage.time,"monotonic",side_effect=[0,30]),patch.object(storage,"info",return_value=self.info()),patch.object(storage,"check_owned_cleanup_identity"),patch.object(storage,"command",return_value=CompletedProcess([],0,b"",b"")) as command:
            with self.assertRaisesRegex(RuntimeError,"observation deadline"):self.invoke(record)
            self.assertEqual(command.call_count,1)
        self.assertNotIn("originalUnmountedBindingVerified",record)

if __name__=="__main__":unittest.main()
