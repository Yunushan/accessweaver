import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import macos_product_recovery as recovery
from macos_installer import digest
from verify_macos_desktop_provenance import validate_product_recovery,VERSIONS


@unittest.skipUnless(os.name=="posix","Physical prefix/ownership checks require POSIX")
class PartialCopyObservation(unittest.TestCase):
    def fixture(self,root):
        root.mkdir(mode=0o700);(root/"App").mkdir(mode=0o700)
        (root/"manifest").write_bytes(b"sealed manifest");(root/"manifest").chmod(0o644)
        (root/"App/core").write_bytes(b"known");(root/"App/core").chmod(0o600)
        return {"":{"directory":True,"mode":0o755},"App":{"directory":True,"mode":0o755},"manifest":{"directory":False,"mode":0o644,"data":b"sealed manifest"},"App/core":{"directory":False,"mode":0o755,"data":b"known binary content"}}
    def inspect(self,root,expected):
        return recovery.partial_inventory(root,expected,os.getuid(),os.getgid())
    def test_complete_metadata_and_partial_known_binary_are_exactly_fingerprinted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()/"partial";expected=self.fixture(root);before=self.inspect(root,expected)
            self.assertEqual(before["partialFiles"],["App/core"]);self.assertTrue(before["allKnownSourcePrefixesVerified"])
            self.assertEqual(before,self.inspect(root,expected))
            self.assertFalse(next(r for r in before["entries"] if r["path"]=="App/core")["complete"])
    def test_unknown_wrong_prefix_overlong_alias_hardlink_and_writable_objects_refuse(self):
        for kind in ("extra","wrong-prefix","overlong","symlink","hardlink","file-mode","directory-mode"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                root=Path(folder).resolve()/"partial";expected=self.fixture(root);file=root/"App/core"
                if kind=="extra":(root/"unrelated").write_bytes(b"private")
                elif kind=="wrong-prefix":file.write_bytes(b"other")
                elif kind=="overlong":file.write_bytes(expected["App/core"]["data"]+b"x")
                elif kind in ("symlink","hardlink"):
                    other=Path(folder).resolve()/"outside";other.write_bytes(file.read_bytes());other.chmod(0o600);file.unlink()
                    if kind=="symlink":file.symlink_to(other)
                    else:file.hardlink_to(other)
                elif kind=="file-mode":file.chmod(0o777)
                else:(root/"App").chmod(0o777)
                with self.assertRaises(ValueError):self.inspect(root,expected)
    def test_symlinked_parent_is_refused_even_with_exact_known_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder).resolve();root=base/"partial";expected=self.fixture(root)
            alias=base/"alias";alias.symlink_to(base,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,"refuses aliases"):self.inspect(alias/"partial",expected)
    def test_file_identity_or_content_change_during_read_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()/"partial";expected=self.fixture(root);real=recovery.os.fstat;changed=False
            def observe(fd):
                nonlocal changed
                info=real(fd)
                if not changed:
                    changed=True;(root/"App/core").write_bytes(b"changed")
                return info
            with patch.object(recovery.os,"fstat",side_effect=observe):
                with self.assertRaises(ValueError):self.inspect(root,expected)


class RecoveryRootGuard(unittest.TestCase):
    def test_root_observer_and_executor_refuse_nonhosted_or_non_native_state(self):
        for system,euid,environment in (("Windows",0,{}),("Darwin",501,{}),("Darwin",0,{})):
            with self.subTest(system=system,euid=euid),patch.object(recovery.platform,"system",return_value=system),patch.object(recovery.os,"geteuid",return_value=euid,create=True),patch.dict(os.environ,environment,clear=True),patch.object(Path,"read_bytes") as read:
                with self.assertRaises(ValueError):recovery.inspect_root_slot({})
                with self.assertRaises(ValueError):recovery.limited_exec(Path("not-a-helper"),4096)
                read.assert_not_called()

class RecoveryArtifactContracts(unittest.TestCase):
    def fixture(self):
        commit="a"*40;arch="amd64";version=VERSIONS[-1];core={"packageSHA256":"b"*64,"helperSHA256":"c"*64,"manifestSHA256":"d"*64,"payloadSHA256":"e"*64};product="f"*64
        payload={"":{"directory":True,"mode":0o755},"AccessWeaver.app":{"directory":True,"mode":0o755},"AccessWeaver.app/Contents":{"directory":True,"mode":0o755},"AccessWeaver.app/Contents/MacOS":{"directory":True,"mode":0o755},"INSTALL-MANIFEST.json":{"directory":False,"mode":0o644,"data":b"M"*5000},"AccessWeaver.app/Contents/MacOS/accessweaver":{"directory":False,"mode":0o755,"data":b"C"*((1<<20)+20)}}
        value={"schemaVersion":1,"sourceCommit":commit,"target":"darwin/"+arch,"runID":"7","version":version,"stage":"deactivation-and-owned-cleanup","failureType":None,"failureSourceLine":None,"corePackageSHA256":core["packageSHA256"],"productPackageSHA256":product,"helperSHA256":core["helperSHA256"],"cases":[]}
        for key in ("passed","actualPackageHelperWriteFaultsVerified","explicitAbandonmentAndWholeProductRetryVerified","retainedPartialCopiesPreservedUntilOwnedCleanup","ownedFixturesRemoved"):value[key]=True
        for key in ("installedProductCodeExecutedAsRoot","hostFilesystemPressureApplied","actualInstallerProcessTerminated","actualPowerLossTested","productUninstallQualified","wholeProductInterruptionRecoveryQualified","productionQualificationComplete"):value[key]=False
        for index,(kind,limit,path) in enumerate((("metadata",4096,"INSTALL-MANIFEST.json"),("controller",1<<20,"AccessWeaver.app/Contents/MacOS/accessweaver"))):
            generation=4+index;slot={"id":str(index+1)*32,"device":3,"inode":10+index,"identity":{"version":version,"manifestSHA256":core["manifestSHA256"],"payloadSHA256":core["payloadSHA256"]}}
            rows=[]
            names=["","AccessWeaver.app"] if index==0 else ["","AccessWeaver.app","AccessWeaver.app/Contents","AccessWeaver.app/Contents/MacOS"]
            for name in names:
                rows.append({"path":name,"kind":"directory","mode":"0700","uid":0,"gid":0,"device":3,"inode":slot["inode"] if not name else 20+len(rows),"links":1,"mtimeNs":1,"ctimeNs":2})
            rows.append({"path":path,"kind":"file","mode":"0600","uid":0,"gid":0,"device":3,"inode":50,"links":1,"mtimeNs":1,"ctimeNs":2,"bytes":limit,"expectedBytes":len(payload[path]["data"]),"sha256":digest(payload[path]["data"][:limit]),"complete":False});rows.sort(key=lambda r:r["path"])
            inventory={"entries":rows,"partialFiles":[path],"allKnownSourcePrefixesVerified":True,"bytes":limit};fingerprint=digest(json.dumps(inventory,sort_keys=True,separators=(",",":")).encode())
            case={"name":kind,"limitBytes":limit,"baseGeneration":generation,"recoveredGeneration":generation+1,"helperSHA256":core["helperSHA256"],"partialSlot":slot,"oldActiveSlotID":"9"*32 if index==0 else "7"*32,"recoveredSlotID":str(7+index)*32,"partialInventory":inventory,"operations":[]}
            for key in ("partialFingerprintSHA256","refusedRetryPreservedFingerprintSHA256","abandonmentPreservedFingerprintSHA256","recoveryPreservedFingerprintSHA256"):case[key]=fingerprint
            for key in ("oldActiveCorePreservedDuringFault","publicAppRegistrationsAndReceiptsPreservedDuringFault","privateProfileAndContainerPreserved","wholeProductRetryVerified","passed"):case[key]=True
            for name,command,state,code,published in (("prepare","prepare-deployment","prepared",0,True),("partial-retry-refused","activate-deployment","refused",1,False),("explicit-abandon","abandon-deployment","abandoned",0,True)):
                result={"schemaVersion":1,"operation":command,"state":state,"generation":generation,"version":version,"manifestSHA256":core["manifestSHA256"],"payloadSHA256":core["payloadSHA256"],"slotID":slot["id"],"operationRecordPublished":published,"publisherSignatureVerified":False,"productionQualificationComplete":False}
                case["operations"].append({"name":name,"exitCode":code,"elapsedMilliseconds":1,"result":result})
            case["operations"].insert(1,{"name":"limited-activate","exitCode":1,"elapsedMilliseconds":1,"fileSizeSignalObserved":False,"appliedLimit":{"schemaVersion":1,"euid":0,"softFileSizeBytes":limit,"hardFileSizeBytes":limit,"coreDumpLimitBytes":0,"scope":"owned-helper-process"},"stdoutSHA256":"a"*64,"stderrSHA256":"b"*64})
            value["cases"].append(case)
        value["lastHelper"]=copy.deepcopy(value["cases"][-1]["operations"][-1])
        return value,(commit,arch,core,product,payload,"7")
    def test_actual_prefixes_helper_protocol_and_narrow_recovery_scope_bind(self):
        value,args=self.fixture();result=validate_product_recovery(value,*args)
        self.assertEqual(result["actualPackageHelperWriteFaultCases"],2);self.assertEqual(result["actualRootHelperCommands"],8)
        self.assertFalse(result["wholeProductInterruptionRecoveryQualified"])
    def test_missing_reordered_forged_prefix_or_unpreserved_recovery_fails(self):
        for kind in ("missing","order","source","run","helper","prefix","unknown","owner","links","limit","fingerprint","abandon-generation","reused-slot","profile","power-loss"):
            with self.subTest(kind=kind):
                value,args=self.fixture();case=value["cases"][0]
                if kind=="missing":value["cases"].pop()
                elif kind=="order":case["operations"][0],case["operations"][1]=case["operations"][1],case["operations"][0]
                elif kind=="source":value["sourceCommit"]="0"*40
                elif kind=="run":value["runID"]="8"
                elif kind=="helper":value["helperSHA256"]="0"*64
                elif kind=="prefix":case["partialInventory"]["entries"][-1]["sha256"]="0"*64
                elif kind=="unknown":case["partialInventory"]["entries"][-1]["path"]="unknown"
                elif kind=="owner":case["partialInventory"]["entries"][-1]["uid"]=501
                elif kind=="links":case["partialInventory"]["entries"][-1]["links"]=2
                elif kind=="limit":case["operations"][1]["appliedLimit"]["coreDumpLimitBytes"]=1000
                elif kind=="fingerprint":case["recoveryPreservedFingerprintSHA256"]="0"*64
                elif kind=="abandon-generation":case["operations"][-1]["result"]["generation"]+=1
                elif kind=="reused-slot":case["recoveredSlotID"]=case["partialSlot"]["id"]
                elif kind=="profile":case["privateProfileAndContainerPreserved"]=False
                else:value["actualPowerLossTested"]=True
                with self.assertRaises(ValueError):validate_product_recovery(value,*args)
