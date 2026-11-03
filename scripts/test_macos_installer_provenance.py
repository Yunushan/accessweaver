import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from verify_macos_installer_provenance import BUNDLE_NAME,WORKFLOW,check_rejections,subject_names,verification_command,verify
COMMIT='a'*40
REF='refs/heads/main'
VERSION='0.1.0-alpha'

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
                    with self.assertRaisesRegex(ValueError,'cryptographic'):verify(root,COMMIT,REF,VERSION,'amd64')
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

if __name__=='__main__':unittest.main()
