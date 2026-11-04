import copy
from verify_windows_installer_provenance import PHASES,validate_state_observations,validate_firewall_origin_diagnostics
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from verify_windows_installer_provenance import BUNDLE_NAME,DEFAULT_VERSIONS,WORKFLOW,check_rejections,stage,subject_names,validate_build,verification_command,verify

COMMIT='a'*40
REF='refs/heads/main'
class WindowsInstallerProvenanceTests(unittest.TestCase):
    def fixture(self,root):
        names=subject_names('amd64',DEFAULT_VERSIONS)
        for name in names|{BUNDLE_NAME}:(root/name).write_bytes(b'fixture, not a signed artifact')
        return names
    def test_source_workflow_and_trusted_version_selection_are_pinned(self):
        command=verification_command(Path('candidate'),Path('bundle'),COMMIT,REF,'trusted-gh')
        for flag,value in {'--repo':'Yunushan/accessweaver','--signer-workflow':WORKFLOW,'--source-digest':COMMIT,'--signer-digest':COMMIT,'--source-ref':REF,'--hostname':'github.com','--cert-oidc-issuer':'https://token.actions.githubusercontent.com','--predicate-type':'https://slsa.dev/provenance/v1'}.items():self.assertEqual(command[command.index(flag)+1],value)
        self.assertIn('--deny-self-hosted-runners',command);self.assertEqual(command[0],'trusted-gh')
        for versions in (('v0.1.0','0.1.1'),('0.1.0-alpha.01','0.1.1'),('0.1.0','0.1.0'),('../outside','0.1.1')):
            with self.assertRaises(ValueError):subject_names('amd64',versions)
        self.assertEqual(len(subject_names('arm64',('999999999999999999999.0.0','1.2.3+build.001'))),5)
    def test_complete_build_identity_and_real_calendar_timestamp_are_required(self):
        identity={"version":"0.1.0-alpha","commit":COMMIT,"sourceState":"clean","builtAt":"2026-11-03T00:00:00Z","goVersion":"go1.27.3","platform":"windows","arch":"amd64"}
        validate_build(identity,COMMIT,"amd64","0.1.0-alpha")
        for key,value in (("builtAt","unknown"),("builtAt","2026-02-30T00:00:00Z"),("sourceState","modified"),("arch","arm64")):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):validate_build(dict(identity,**{key:value}),COMMIT,"amd64","0.1.0-alpha")
        del identity["builtAt"]
        with self.assertRaises(ValueError):validate_build(identity,COMMIT,"amd64","0.1.0-alpha")
    def test_all_five_private_snapshot_subjects_authenticate_before_any_parse(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);names=self.fixture(root);seen=[]
            def authenticate(path,bundle,commit,ref,gh):
                self.assertNotEqual(path.parent,root);self.assertEqual(bundle.parent,path.parent)
                self.assertEqual((commit,ref,gh),(COMMIT,REF,'trusted-gh'));seen.append(path.name)
            def contents(private,*args):
                self.assertEqual(set(seen),names);(root/'amd64.json').write_bytes(b'changed original input')
                self.assertNotEqual((private/'amd64.json').read_bytes(),(root/'amd64.json').read_bytes());return {'mocked':True}
            with patch('verify_windows_installer_provenance.authenticate',side_effect=authenticate),patch('verify_windows_installer_provenance.validate_contents',side_effect=contents):result=verify(root,COMMIT,REF,'amd64',gh='trusted-gh')
            self.assertEqual(result['subjectsVerified'],5);self.assertFalse(result['publisherSignatureVerified']);self.assertFalse(result['targetExecutionPerformedByVerifier'])
    def test_any_signature_failure_blocks_parsing_without_fallback(self):
        for at in (1,5):
            with self.subTest(at=at),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);self.fixture(root);calls=[]
                def run(command,**kwargs):
                    calls.append(command)
                    if len(calls)==at:raise subprocess.CalledProcessError(1,command,stderr=b'private response')
                    return subprocess.CompletedProcess(command,0)
                with patch('verify_windows_installer_provenance.subprocess.run',side_effect=run),patch('verify_windows_installer_provenance.validate_contents') as contents:
                    with self.assertRaisesRegex(ValueError,'cryptographic'):verify(root,COMMIT,REF,'amd64')
                    self.assertEqual(len(calls),at);contents.assert_not_called()
    def test_bad_input_set_and_wrong_target_fail_before_authentication(self):
        for kind in ('extra','missing','hardlink','target'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);self.fixture(root)
                if kind=='extra':(root/'unexpected.exe').write_bytes(b'extra')
                if kind=='missing':(root/BUNDLE_NAME).unlink()
                if kind=='hardlink':
                    (root/'amd64.json').unlink();os.link(root/BUNDLE_NAME,root/'amd64.json')
                with patch('verify_windows_installer_provenance.authenticate') as auth:
                    with self.assertRaises(ValueError):verify(root,COMMIT,REF,'arm64' if kind=='target' else 'amd64')
                    auth.assert_not_called()
    def test_producer_does_not_replace_existing_staging_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with self.assertRaises(ValueError):stage(root,root,COMMIT,REF,'amd64',DEFAULT_VERSIONS)
    def test_real_negative_protocol_rechecks_correct_subject_after_all_probes(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root);calls=[]
            def run(command,**kwargs):
                calls.append(command)
                if len(calls)==6:self.assertEqual(Path(command[3]).read_bytes(),(root/'amd64.json').read_bytes()+b'changed')
                return subprocess.CompletedProcess(command,0 if len(calls) in (1,7) else 1)
            with patch('verify_windows_installer_provenance.subprocess.run',side_effect=run):result=check_rejections(root/'amd64.json',root/BUNDLE_NAME,COMMIT,REF,'trusted-gh')
            self.assertEqual(calls[0],calls[-1]);self.assertEqual(len(result['rejected']),5);self.assertTrue(result['realBundleVerifiedBeforeAndAfter'])



class WindowsStateObservationContracts(unittest.TestCase):
    def fixture(self):
        comparison={"exactMatch":True,"beforeSHA256":"a"*64,"afterSHA256":"a"*64,"domains":{}}
        for name in ("services","firewall","dns"):
            comparison["domains"][name]={"beforeSHA256":"b"*64,"afterSHA256":"b"*64,"serializedEqual":True,"beforeRows":1,"afterRows":1,"added":0,"removed":0,"changed":0,"rowSerializationChanges":0,"recordOrderingChanged":False,"changes":[],"changesTruncated":False}
        return [{"phase":phase,"comparison":copy.deepcopy(comparison),"transition":copy.deepcopy(comparison)} for phase in PHASES]

    def test_all_fifteen_original_baseline_and_transition_comparisons_are_required(self):
        self.assertEqual(len(PHASES),15)
        self.assertIn("after-restoration-launch-failures",PHASES)
        result=validate_state_observations(self.fixture())
        self.assertEqual(result,{"nativeStateCheckpointsVerified":15,"nativeStateComparisonsVerified":30})

    def test_missing_reordered_rebased_transient_private_or_incomplete_observations_refuse(self):
        for kind in ("missing","reordered","missing-transition","null","prior-drift","transient-restored","rebased","row-count-bool","counter-bool","changed-rule","raw-private-field","changed-hash","missing-domain","unknown-envelope"):
            observations=self.fixture();item=observations[8]
            if kind=="missing":observations.pop(8)
            elif kind=="reordered":observations[8],observations[9]=observations[9],observations[8]
            elif kind=="missing-transition":item.pop("transition")
            elif kind=="null":item["comparison"]=None
            elif kind=="prior-drift":item["comparison"]["exactMatch"]=False
            elif kind=="transient-restored":item["transition"]["exactMatch"]=False
            elif kind=="rebased":item["comparison"]["beforeSHA256"]=item["comparison"]["afterSHA256"]="c"*64
            elif kind=="row-count-bool":item["transition"]["domains"]["firewall"]["beforeRows"]=True
            elif kind=="counter-bool":item["transition"]["domains"]["firewall"]["added"]=False
            elif kind=="changed-rule":item["transition"]["domains"]["firewall"]["added"]=1
            elif kind=="raw-private-field":item["comparison"]["domains"]["firewall"]["privateRuleName"]="private"
            elif kind=="changed-hash":item["transition"]["domains"]["firewall"]["afterSHA256"]="c"*64
            elif kind=="missing-domain":item["transition"]["domains"].pop("dns")
            elif kind=="unknown-envelope":item["privatePath"]="/private"
            with self.subTest(kind=kind),self.assertRaises(ValueError):validate_state_observations(observations)


class CapturedFirewallOriginContracts(unittest.TestCase):
    def fixture(self):
        return {"schemaVersion":1,"source":"captured-rule-properties","maxRecords":16,"maxPropertyBytes":4096,"records":[],"truncated":False,"unavailable":False,"extraNativeQueriesPerformed":False,"processOriginEstablished":False}

    def test_qualified_unchanged_state_requires_complete_empty_bounded_metadata(self):
        self.assertEqual(validate_firewall_origin_diagnostics(self.fixture()),{"nativeFirewallOriginRecordsVerified":0})

    def test_missing_private_unbounded_incomplete_or_mutating_metadata_refuses(self):
        invalid=[None,{},dict(self.fixture(),privateRuleName="private")]
        for key,value in (("schemaVersion",True),("schemaVersion",2),("source","native-query"),("maxRecords",17),("maxPropertyBytes",4097),("records",[{}]),("records",{}),("truncated",True),("unavailable",True),("extraNativeQueriesPerformed",True),("processOriginEstablished",True)):
            invalid.append(dict(self.fixture(),**{key:value}))
        for value in invalid:
            with self.subTest(value=value),self.assertRaises(ValueError):validate_firewall_origin_diagnostics(value)


if __name__=='__main__':unittest.main()
