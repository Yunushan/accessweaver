import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from verify_macos_installer_provenance import BUNDLE_NAME,WORKFLOW,check_rejections,subject_names,verification_command,verify,validate_deployment_transactions,validate_fixed_deployment_helper,validate_preparation_sigkill
COMMIT='a'*40
REF='refs/heads/main'
VERSION='0.1.0-alpha'

def preparation_kill_fixture():
    phases=["removal-preparation-created","removal-state-durable","removal-plan-durable","removal-marker-durable","removal-directory-durable","removal-preparation-durable","removal-record-reserved","removal-reservation-parent-durable","removal-published","removal-parent-durable"]
    cases=[]
    for index,phase in enumerate(phases):
        outside=index<6;published=index>=8
        cases.append({"phase":phase,"signal":9,"elapsedMilliseconds":123,"timedOut":False,"stateAtTermination":"external-preparation" if outside else "published-intent" if published else "reserved-preparation","stageFileCountAtTermination":min(index,3),"intentPublishedAtTermination":published,"freshRetryPublished":outside,"reservedRecoveryPublished":not outside and not published,"publishedIntentReopened":published,"bothLeasesReacquired":True,"completedIntentReopenVerified":True,"activePreimageRetained":True,"preparationEvidencePreserved":True,"payloadObjectsRemoved":0,"retainedDataPreserved":True,"passed":True})
    return {"schemaVersion":1,"caseCount":10,"cases":cases,"copiedCodeExecuted":False,"packageScriptsIntegrated":False,"productionQualificationComplete":False,"testExecutableSHA256":"c"*64,"elapsedMilliseconds":123,"installedObjectsAndReceiptsPreserved":True,"fixtureParent":"private-exclusive-temporary-directory","invocationScope":"file-directory-quarantine-app-and-preparation-kills"}


class NativePackageProvenanceTests(unittest.TestCase):
    def fixture(self,root):
        package,names=subject_names(VERSION,'amd64')
        for name in names|{BUNDLE_NAME}:(root/name).write_bytes(b'not parsed before real authentication')
        return package,names
    def test_independently_pins_native_workflow_and_source(self):
        command=verification_command(Path('artifact.pkg'),Path('bundle'),COMMIT,REF,'trusted-gh')
        for flag,value in {'--signer-workflow':WORKFLOW,'--repo':'Yunushan/accessweaver','--hostname':'github.com','--source-digest':COMMIT,'--signer-digest':COMMIT,'--source-ref':REF,'--cert-oidc-issuer':'https://token.actions.githubusercontent.com','--predicate-type':'https://slsa.dev/provenance/v1'}.items():self.assertEqual(command[command.index(flag)+1],value)
        self.assertEqual(command[0],'trusted-gh');self.assertIn('--deny-self-hosted-runners',command)
        for commit,ref in (('a'*7,REF),(COMMIT,'main')):
            with self.assertRaises(ValueError):verification_command(Path('x'),Path('y'),commit,ref)
        for version,arch in (('../escape','amd64'),(VERSION,'x86'),('v1.2.3','arm64')):
            with self.assertRaises(ValueError):subject_names(version,arch)
    def test_all_snapshot_subjects_authenticate_before_parsing(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);package,names=self.fixture(root);authenticated=[]
            def auth(path,bundle,commit,ref,gh):
                self.assertNotEqual(path.parent,root);self.assertEqual(bundle.parent,path.parent)
                self.assertEqual((commit,ref,gh),(COMMIT,REF,'trusted-gh'));authenticated.append(path.name)
            def parse(snapshot,*args):
                self.assertEqual(set(authenticated),names)
                self.assertEqual((snapshot/package).read_bytes(),(root/package).read_bytes())
                (root/package).write_bytes(b'changed outside private snapshot')
                self.assertNotEqual((snapshot/package).read_bytes(),(root/package).read_bytes())
                return {'mocked':True}
            with patch('verify_macos_installer_provenance.authenticate',side_effect=auth),patch('verify_macos_installer_provenance.validate_contents',side_effect=parse):report=verify(root,COMMIT,REF,VERSION,'amd64','trusted-gh')
            self.assertEqual(report['subjectsVerified'],7);self.assertEqual({v['file'] for v in report['subjects']},names)
            self.assertFalse(report['publisherSignatureVerified']);self.assertFalse(report['localTargetExecution'])
    def test_signature_failures_stop_before_parsing_without_fallback(self):
        for failed_call in (1,7):
            with self.subTest(failed_call=failed_call),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);self.fixture(root);calls=[]
                def run(*args,**kwargs):
                    calls.append(args[0])
                    if len(calls)==failed_call:raise subprocess.CalledProcessError(1,args[0],stderr=b'private child response')
                    return subprocess.CompletedProcess(args[0],0)
                with patch('verify_macos_installer_provenance.subprocess.run',side_effect=run),patch('verify_macos_installer_provenance.validate_contents') as contents:
                    with self.assertRaisesRegex(ValueError,'cryptographic') as error:verify(root,COMMIT,REF,VERSION,'amd64')
                    metadata=json.loads(str(error.exception).split(": ",1)[1])
                    self.assertEqual(metadata['phase'],'subject-authentication')
                    self.assertEqual(metadata['returncode'],1)
                    self.assertEqual(metadata['stderrSHA256'],hashlib.sha256(b'private child response').hexdigest())
                    self.assertNotIn('private child response',str(error.exception))
                    contents.assert_not_called();self.assertEqual(len(calls),failed_call)
    def test_bad_inventory_and_wrong_target_fail_before_authentication(self):
        for kind in ('extra','missing','hardlink','wrong-target'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);package,names=self.fixture(root)
                if kind=='extra':(root/'extra.pkg').write_bytes(b'extra')
                if kind=='missing':(root/BUNDLE_NAME).unlink()
                if kind=='hardlink':
                    (root/'BUILD-INFO.json').unlink();os.link(root/package,root/'BUILD-INFO.json')
                with patch('verify_macos_installer_provenance.authenticate') as auth:
                    with self.assertRaises(ValueError):verify(root,COMMIT,REF,VERSION,'arm64' if kind=='wrong-target' else 'amd64')
                    auth.assert_not_called()
    def test_negative_probes_recheck_correct_subject_and_preserve_other_constraints(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);package,_=self.fixture(root);calls=[]
            def run(command,**kwargs):
                calls.append(command)
                if len(calls)==6:self.assertEqual(Path(command[3]).read_bytes(),(root/package).read_bytes()+b'changed')
                return subprocess.CompletedProcess(command,0 if len(calls) in (1,7) else 1)
            with patch('verify_macos_installer_provenance.subprocess.run',side_effect=run):result=check_rejections(root/package,root/BUNDLE_NAME,COMMIT,REF,'trusted-gh')
            self.assertEqual(calls[0],calls[-1]);self.assertEqual(len(result['rejected']),5)
            self.assertTrue(result['realBundleVerifiedBeforeAndAfter']);self.assertTrue(all('--deny-self-hosted-runners' in c for c in calls))

    def test_probe_failures_identify_phase_without_output_or_retries(self):
        secret=b"private child response token=secret /private/path"
        for failed_call,phase,expected in ((1,"positive-control-before",True),(3,"--source-ref",False),(7,"positive-control-after",True)):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);package,_=self.fixture(root);calls=[]
                def run(command,**kwargs):
                    calls.append(command)
                    normal=0 if len(calls) in (1,7) else 1
                    return subprocess.CompletedProcess(command,1-normal if len(calls)==failed_call else normal,stdout=secret,stderr=secret)
                with patch('verify_macos_installer_provenance.subprocess.run',side_effect=run):
                    with self.assertRaises(ValueError) as error:check_rejections(root/package,root/BUNDLE_NAME,COMMIT,REF,'trusted-gh')
                prefix,metadata=str(error.exception).split(": ",1)
                value=json.loads(metadata)
                self.assertIn("cryptographic",prefix)
                self.assertEqual(value,{"phase":phase,"expectedSuccess":expected,"returncode":1 if expected else 0,"stdoutBytes":len(secret),"stderrBytes":len(secret),"stdoutSHA256":hashlib.sha256(secret).hexdigest(),"stderrSHA256":hashlib.sha256(secret).hexdigest()})
                self.assertEqual(len(calls),failed_call);self.assertNotIn(secret.decode(),str(error.exception))

    def test_preparation_sigkill_requires_exact_phases_signal_routes_and_preservation(self):
        value=preparation_kill_fixture()
        validate=lambda v:validate_preparation_sigkill(v,"c"*64)
        validate(value)
        for key in value:
            changed=dict(value);del changed[key]
            with self.subTest(missing=key):
                with self.assertRaises(ValueError):validate(changed)
        for key,bad in (("schemaVersion",True),("caseCount",True),("caseCount",9),("copiedCodeExecuted",True),("packageScriptsIntegrated",True),("productionQualificationComplete",True),("testExecutableSHA256","d"*64),("installedObjectsAndReceiptsPreserved",False),("fixtureParent","/Applications"),("invocationScope","preparation-only"),("elapsedMilliseconds",True),("elapsedMilliseconds",150001),("cases",None),("cases",value["cases"][:9]),("cases",list(reversed(value["cases"])))):
            changed=dict(value);changed[key]=bad
            with self.subTest(key=key):
                with self.assertRaises(ValueError):validate(changed)
        for index,case in enumerate(value["cases"]):
            for key in case:
                changed=dict(value);changed["cases"]=[dict(c) for c in value["cases"]];del changed["cases"][index][key]
                with self.subTest(index=index,missing=key):
                    with self.assertRaises(ValueError):validate(changed)
            corrupt=[("phase","unknown"),("signal",True),("signal",15),("timedOut",True),("stateAtTermination","unknown"),("stageFileCountAtTermination",True),("stageFileCountAtTermination",-1),("payloadObjectsRemoved",True),("payloadObjectsRemoved",1),("elapsedMilliseconds",True),("elapsedMilliseconds",20001)]
            corrupt += [(key,not case[key]) for key in ("intentPublishedAtTermination","freshRetryPublished","reservedRecoveryPublished","publishedIntentReopened","bothLeasesReacquired","completedIntentReopenVerified","activePreimageRetained","preparationEvidencePreserved","retainedDataPreserved","passed")]
            for key,bad in corrupt:
                changed=dict(value);changed["cases"]=[dict(c) for c in value["cases"]];changed["cases"][index][key]=bad
                with self.subTest(index=index,key=key):
                    with self.assertRaises(ValueError):validate(changed)
        with self.assertRaises(ValueError):validate(None)

    def test_deployment_report_is_bound_to_copied_subjects_and_fixed_scope(self):
        value={"schemaVersion":1,"manifestSHA256":"a"*64,"payloadSHA256":"b"*64,"version":VERSION,"finalGeneration":4,"testExecutableSHA256":"c"*64,"detachedPayloadSBOMManifestSHA256":"d"*64,"detachedPayloadSBOMSHA256":"e"*64,"elapsedMilliseconds":123,"rootFixtureElapsedMilliseconds":123,"removalPreparationRecoveryCaseCount":28,"intactTargetCaseCount":16,"protectedFileJournalCaseCount":18,"protectedFileSIGKILLCaseCount":4,"publicAppQuarantineSIGKILLCaseCount":4,"quarantinedAppSIGKILLCaseCount":12,"quarantinedAppRemovalCaseCount":32,"publicAppQuarantineCaseCount":28,"protectedDirectoryJournalCaseCount":25,"protectedDirectorySIGKILLCaseCount":8,"fixtureParent":"private-exclusive-temporary-directory","copiedCodeExecuted":False,"packageScriptsIntegrated":False,"productionQualificationComplete":False}
        checks=("fixedProtectedParentVerified","partialCopyPreservedAndRefused","completeCopyRecovered","concurrentPreparationFenced","postPublicationRemovalRecovered","oldCompleteSlotFencedAfterRemoval","restoredRetryVerified","payloadIsIndependentCopy","detachedManifestPartialCopyPreservedAndRefused","detachedManifestCompleteCopyRecovered","detachedPayloadSBOMPartialCopyPreservedAndRefused","legacyToSchema2BridgeVerified","removalPreparationRecoveryVerified","intactRemovalTargetsVerified","ownedTargetRefusalsPreserved","protectedFileJournalVerified","protectedFileSIGKILLVerified","publicAppQuarantineSIGKILLVerified","quarantinedAppSIGKILLVerified","quarantinedAppRemovalVerified","publicAppQuarantineVerified","protectedDirectoryJournalVerified","protectedDirectorySIGKILLVerified","installedObjectsAndReceiptsPreserved")
        value.update({key:True for key in checks})
        value["removalPreparationSIGKILL"]=preparation_kill_fixture()
        phases=["removal-file-intent-durable","removal-file-unlinked","removal-file-parent-durable","removal-file-done-durable"]
        value["protectedFileSIGKILLCases"]=[{"phase":phase,"signal":9,"elapsedMilliseconds":123,"timedOut":False,"journalSHA256AtTermination":"f"*64,"completedActionsAtTermination":int(i==3),"pendingAtTermination":i!=3,"filePresentAtTermination":i==0,"completedFilesAfterRetry":2,"bothLeasesReacquired":True,"completedRetryIdempotent":True,"retainedDataPreserved":True,"passed":True} for i,phase in enumerate(phases)]


        directory_phases=["removal-directory-intent-durable","removal-directory-unlinked","removal-directory-parent-durable","removal-directory-done-durable"]
        value["protectedDirectorySIGKILLCases"]=[{"target":target,"phase":phase,"signal":9,"elapsedMilliseconds":123,"timedOut":False,"journalSHA256AtTermination":"f"*64,"completedActionsAtTermination":base+int(i==3),"pendingAtTermination":i!=3,"directoryPresentAtTermination":i==0,"completedObjectsAfterRetry":6,"bothLeasesReacquired":True,"completedRetryIdempotent":True,"retainedDataPreserved":True,"passed":True} for target,base in (("nested-directory",2),("protected-root",3)) for i,phase in enumerate(directory_phases)]
        quarantine_phases=["removal-quarantine-intent-durable","removal-quarantine-renamed","removal-quarantine-parents-durable","removal-quarantine-done-durable"]
        value["publicAppQuarantineSIGKILLCases"]=[{"phase":phase,"signal":9,"elapsedMilliseconds":123,"timedOut":False,"journalSHA256AtTermination":"f"*64,"completedQuarantineActionsAtTermination":int(i==3),"pendingAtTermination":i!=3,"publicAppPresentAtTermination":i==0,"quarantinedAppPresentAtTermination":i!=0,"protectedObjectsRemovedAtTermination":0,"completedProtectedObjectsAfterRetry":6,"bothLeasesReacquired":True,"completedRetryIdempotent":True,"retainedDataPreserved":True,"passed":True} for i,phase in enumerate(quarantine_phases)]
        app_file_phases=["removal-app-file-intent-durable","removal-app-file-unlinked","removal-app-file-parent-durable","removal-app-file-done-durable"]
        app_directory_phases=["removal-app-directory-intent-durable","removal-app-directory-unlinked","removal-app-directory-parent-durable","removal-app-directory-done-durable"]
        value["quarantinedAppSIGKILLCases"]=[{"target":target,"phase":phase,"signal":9,"elapsedMilliseconds":123,"timedOut":False,"journalSHA256AtTermination":"f"*64,"completedActionsAtTermination":base+int(i==3),"pendingAtTermination":i!=3,"objectPresentAtTermination":i==0,"completedObjectsAfterRetry":9,"bothLeasesReacquired":True,"completedRetryIdempotent":True,"retainedDataPreserved":True,"passed":True} for target,base,phases in (("file",6,app_file_phases),("nested-directory",7,app_directory_phases),("quarantined-root",8,app_directory_phases)) for i,phase in enumerate(phases)]
        def validate(record):validate_deployment_transactions(record,"a"*64,"b"*64,VERSION)
        validate(value)
        for key,bad in [(key,False) for key in checks]+[("schemaVersion",True),("manifestSHA256","0"*64),("payloadSHA256","0"*64),("version","0.1.1-alpha"),("finalGeneration",5),("testExecutableSHA256","unknown"),("copiedCodeExecuted",True),("packageScriptsIntegrated",True),("productionQualificationComplete",True),("fixtureParent","/Applications"),("elapsedMilliseconds",True),("elapsedMilliseconds",-1),("elapsedMilliseconds",150001),("elapsedMilliseconds",122),("rootFixtureElapsedMilliseconds",True),("rootFixtureElapsedMilliseconds",-1),("rootFixtureElapsedMilliseconds",124),("rootFixtureElapsedMilliseconds",150001),("removalPreparationRecoveryCaseCount",True),("removalPreparationRecoveryCaseCount",27),("intactTargetCaseCount",True),("intactTargetCaseCount",15),("protectedFileJournalCaseCount",True),("protectedFileJournalCaseCount",17),("protectedFileSIGKILLCaseCount",True),("protectedFileSIGKILLCaseCount",3),("publicAppQuarantineSIGKILLCaseCount",True),("publicAppQuarantineSIGKILLCaseCount",3),("quarantinedAppSIGKILLCaseCount",True),("quarantinedAppSIGKILLCaseCount",11),("quarantinedAppRemovalCaseCount",True),("quarantinedAppRemovalCaseCount",31),("publicAppQuarantineCaseCount",True),("publicAppQuarantineCaseCount",27),("protectedDirectoryJournalCaseCount",True),("protectedDirectoryJournalCaseCount",24),("protectedDirectorySIGKILLCaseCount",True),("protectedDirectorySIGKILLCaseCount",7)]:
            with self.subTest(key=key):
                changed=dict(value);changed[key]=bad
                with self.assertRaises(ValueError):validate(changed)

        for key,bad in [("signal",True),("signal",15),("timedOut",True),("phase","unknown"),("completedActionsAtTermination",True),("completedActionsAtTermination",1),("pendingAtTermination",False),("filePresentAtTermination",False),("completedFilesAfterRetry",True),("completedFilesAfterRetry",1),("bothLeasesReacquired",False),("completedRetryIdempotent",False),("retainedDataPreserved",False),("passed",False),("elapsedMilliseconds",True),("elapsedMilliseconds",20001),("journalSHA256AtTermination","bad")]:
            changed=dict(value);changed["protectedFileSIGKILLCases"]=[dict(case) for case in value["protectedFileSIGKILLCases"]];changed["protectedFileSIGKILLCases"][0][key]=bad
            with self.subTest(killed_child_key=key):
                with self.assertRaises(ValueError):validate(changed)
        for bad in ([],value["protectedFileSIGKILLCases"][:3],list(reversed(value["protectedFileSIGKILLCases"]))):
            changed=dict(value);changed["protectedFileSIGKILLCases"]=bad
            with self.assertRaises(ValueError):validate(changed)

        for index in range(8):
            case=value["protectedDirectorySIGKILLCases"][index]
            corrupt=[("target","unknown"),("phase","unknown"),("signal",True),("signal",15),("timedOut",True),("completedActionsAtTermination",True),("completedActionsAtTermination",-1),("pendingAtTermination",not case["pendingAtTermination"]),("directoryPresentAtTermination",not case["directoryPresentAtTermination"]),("completedObjectsAfterRetry",True),("completedObjectsAfterRetry",5),("bothLeasesReacquired",False),("completedRetryIdempotent",False),("retainedDataPreserved",False),("passed",False),("elapsedMilliseconds",True),("elapsedMilliseconds",20001),("journalSHA256AtTermination","bad")]
            for key,bad in corrupt:
                changed=dict(value);changed["protectedDirectorySIGKILLCases"]=[dict(c) for c in value["protectedDirectorySIGKILLCases"]];changed["protectedDirectorySIGKILLCases"][index][key]=bad
                with self.subTest(directory_index=index,directory_key=key):
                    with self.assertRaises(ValueError):validate(changed)
        for bad in ([],value["protectedDirectorySIGKILLCases"][:7],list(reversed(value["protectedDirectorySIGKILLCases"]))):
            changed=dict(value);changed["protectedDirectorySIGKILLCases"]=bad
            with self.assertRaises(ValueError):validate(changed)
        for index in range(4):
            case=value["publicAppQuarantineSIGKILLCases"][index]
            corrupt=[("phase","unknown"),("signal",True),("signal",15),("timedOut",True),("elapsedMilliseconds",True),("elapsedMilliseconds",20001),("journalSHA256AtTermination","bad"),("completedQuarantineActionsAtTermination",True),("completedQuarantineActionsAtTermination",-1),("pendingAtTermination",not case["pendingAtTermination"]),("publicAppPresentAtTermination",not case["publicAppPresentAtTermination"]),("quarantinedAppPresentAtTermination",not case["quarantinedAppPresentAtTermination"]),("protectedObjectsRemovedAtTermination",True),("protectedObjectsRemovedAtTermination",1),("completedProtectedObjectsAfterRetry",True),("completedProtectedObjectsAfterRetry",5),("bothLeasesReacquired",False),("completedRetryIdempotent",False),("retainedDataPreserved",False),("passed",False)]
            for key,bad in corrupt:
                changed=dict(value);changed["publicAppQuarantineSIGKILLCases"]=[dict(c) for c in value["publicAppQuarantineSIGKILLCases"]];changed["publicAppQuarantineSIGKILLCases"][index][key]=bad
                with self.subTest(quarantine_index=index,quarantine_key=key):
                    with self.assertRaises(ValueError):validate(changed)
        for bad in (None,[],value["publicAppQuarantineSIGKILLCases"][:3],list(reversed(value["publicAppQuarantineSIGKILLCases"]))):
            changed=dict(value);changed["publicAppQuarantineSIGKILLCases"]=bad
            with self.assertRaises(ValueError):validate(changed)
        for index in range(12):
            case=value["quarantinedAppSIGKILLCases"][index]
            corrupt=[("target","unknown"),("phase","unknown"),("signal",True),("signal",15),("timedOut",True),("completedActionsAtTermination",True),("completedActionsAtTermination",-1),("pendingAtTermination",not case["pendingAtTermination"]),("objectPresentAtTermination",not case["objectPresentAtTermination"]),("completedObjectsAfterRetry",True),("completedObjectsAfterRetry",8),("bothLeasesReacquired",False),("completedRetryIdempotent",False),("retainedDataPreserved",False),("passed",False),("elapsedMilliseconds",True),("elapsedMilliseconds",20001),("journalSHA256AtTermination","bad")]
            for key,bad in corrupt:
                changed=dict(value);changed["quarantinedAppSIGKILLCases"]=[dict(c) for c in value["quarantinedAppSIGKILLCases"]];changed["quarantinedAppSIGKILLCases"][index][key]=bad
                with self.subTest(app_index=index,app_key=key):
                    with self.assertRaises(ValueError):validate(changed)
        for bad in (None,[],value["quarantinedAppSIGKILLCases"][:11],list(reversed(value["quarantinedAppSIGKILLCases"]))):
            changed=dict(value);changed["quarantinedAppSIGKILLCases"]=bad
            with self.assertRaises(ValueError):validate(changed)
        for key in value:
            changed=dict(value);del changed[key]
            with self.assertRaises(ValueError):validate(changed)
        with self.assertRaises(ValueError):validate(None)

    def test_fixed_helper_report_requires_the_complete_fenced_protocol(self):
        import copy
        identity={"version":VERSION,"commit":COMMIT,"sourceState":"clean","builtAt":"2026-11-03T00:00:00Z","goVersion":"go1.27.3","platform":"darwin","arch":"amd64"}
        value={"schemaVersion":1,"build":identity,"helperSHA256":"c"*64,"manifestSHA256":"a"*64,"payloadSHA256":"b"*64,"rootAndLegacyRefusalsPreservedAbsentAuthority":True,"ordinaryUserActiveRuntimeVerified":True,"stagingRemovalPreservedActiveCopy":True,"detachedManifestBridgeVerified":True,"ownedFixedFixtureCleanupVerified":True,"installedCodeExecutedAsRoot":False,"actualApplePackageUpgradeExecuted":False,"packageScriptsIntegrated":False,"productionQualificationComplete":False,"cases":[]}
        sequence=[
            ("activation-without-authority-refused","activate-deployment",None,0),
            ("unsealed-helper-refused","prepare-deployment",None,0),
            ("prepared","prepare-deployment",(0,"prepared",True),1),
            ("prepare-retry-idempotent","prepare-deployment",(0,"prepared",False),1),
            ("changed-incoming-refused","activate-deployment",None,0),
            ("activated","activate-deployment",(1,"active",True),1),
            ("activation-retry-idempotent","activate-deployment",(1,"active",False),1),
            ("active-survives-staging-removal","activate-deployment",(1,"active",False),1),
            ("reinstall-prepared","prepare-deployment",(1,"prepared",True),2),
            ("missing-incoming-refused","activate-deployment",None,0),
            ("deactivated-with-pending","deactivate-deployment",(2,"inactive",True),1),
            ("stale-activation-fenced","activate-deployment",None,0),
            ("stale-prepare-fenced","prepare-deployment",None,0),
            ("stale-preparation-abandoned","abandon-deployment",(2,"abandoned",True),2),
            ("abandon-retry-refused","abandon-deployment",None,0),
            ("restored-retry-prepared","prepare-deployment",(2,"prepared",True),3),
            ("restored-retry-activated","activate-deployment",(3,"active",True),3),
            ("restored-activation-idempotent","activate-deployment",(3,"active",False),3),
            ("final-deactivation","deactivate-deployment",(4,"inactive",True),3),
        ]
        for name,op,transition,slot in sequence:
            result=None
            if transition:
                generation,state,published=transition
                result={"schemaVersion":1,"operation":op,"generation":generation,"version":VERSION,"manifestSHA256":"a"*64,"payloadSHA256":"b"*64,"slotID":f"{slot:032x}","state":state,"operationRecordPublished":published,"publisherSignatureVerified":False,"productionQualificationComplete":False}
            value["cases"].append({"name":name,"operation":op,"exitCode":0 if transition else 1,"elapsedMilliseconds":5,"passed":True,"result":result,"recordPreserved":transition is None or not transition[2]})
        validate=lambda v:validate_fixed_deployment_helper(v,identity,"a"*64,"b"*64)
        validate(value)
        mutations=[lambda v:v.update(detachedManifestBridgeVerified=False),lambda v:v.update(payloadSHA256="0"*64),lambda v:v.update(helperSHA256="unmeasured"),lambda v:v.update(installedCodeExecutedAsRoot=True),lambda v:v.update(packageScriptsIntegrated=True),lambda v:v.update(ownedFixedFixtureCleanupVerified=False),lambda v:v["cases"].pop(),lambda v:v["cases"][0].update(exitCode=0),lambda v:v["cases"][0].update(recordPreserved=False),lambda v:v["cases"][3]["result"].update(slotID=f"{4:032x}"),lambda v:v["cases"][5]["result"].update(generation=2),lambda v:v["cases"][6]["result"].update(operationRecordPublished=True),lambda v:v["cases"][17]["result"].update(slotID=f"{2:032x}")]
        for change in mutations:
            changed=copy.deepcopy(value);change(changed)
            with self.assertRaises(ValueError):validate(changed)
        with self.assertRaises(ValueError):validate(None)

if __name__=='__main__':unittest.main()
