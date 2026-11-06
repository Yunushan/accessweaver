"""Ordinary local fixture tests only; never executes the native/root entry point."""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('native_runtime_read_driver',Path(__file__).with_name('test-darwin-runtime-read-completion.py'))
DRIVER=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(DRIVER)

class NativeRuntimeReadCaptureTests(unittest.TestCase):
 def valid(self):
  return {'schemaVersion':1,'sourceCommit':'a'*40,'goos':'darwin','goarch':'arm64','goVersion':'go1.27.3','outcome':'passed','cases':[{'name':name,'passed':True,'checks':1,'code':'none','sites':0} for name in DRIVER.CASES],'nativeRootFixture':True,'nativeInstalledQualified':False}

 def test_fixed_protocol_and_qualification_refusal(self):
  value=self.valid();self.assertEqual(DRIVER.validate_native(value,'a'*40,'arm64'),value)
  for change in ({'nativeInstalledQualified':True},{'nativeRootFixture':False},{'goarch':'amd64'},{'goVersion':'go1.27.2'},{'sourceCommit':'b'*40},{'privatePath':'fixed synthetic private value'}):
   malformed={**value,**change}
   with self.assertRaises(DRIVER.Refused):DRIVER.validate_native(malformed,'a'*40,'arm64')

 def test_unknown_and_malformed_case_metadata_refused(self):
  for operation in (
   lambda v:v['cases'][0].update(code='/fixed/private/fixture'),
   lambda v:v['cases'][0].update(code='PRIVATE_SYNTHETIC_VALUE'),
   lambda v:v['cases'][0].update(checks=True),
   lambda v:v['cases'][0].update(checks=0),
   lambda v:v['cases'][0].update(sites=129),
   lambda v:v['cases'][0].update(name='unrecognized-case'),
   lambda v:v['cases'].append(v['cases'][0]),
   lambda v:v['cases'].__setitem__(0,None),
  ):
   value=copy.deepcopy(self.valid());operation(value)
   with self.assertRaises(DRIVER.Refused):DRIVER.validate_native(value,'a'*40,'arm64')

 def test_failed_case_cannot_claim_passed_outcome(self):
  value=self.valid();value['cases'][0].update(passed=False,code='fixed-test-code')
  with self.assertRaises(DRIVER.Refused):DRIVER.validate_native(value,'a'*40)
  value['outcome']='failed';self.assertEqual(DRIVER.validate_native(value,'a'*40),value)

 def test_deployment_profile_cannot_accept_runtime_cases(self):
  value=self.valid()
  with self.assertRaises(DRIVER.Refused):DRIVER.validate_native(value,'a'*40,'arm64','deployment-completion')
  value['cases']=[{'name':name,'passed':True,'checks':1,'code':'none','sites':0} for name in DRIVER.DEPLOYMENT_CASES]
  self.assertEqual(DRIVER.validate_native(value,'a'*40,'arm64','deployment-completion'),value)
  with self.assertRaises(DRIVER.Refused):DRIVER.validate_native(value,'a'*40,'arm64','runtime-read')
  profile=DRIVER.PROFILES['deployment-completion']
  self.assertNotEqual(profile['guard'],DRIVER.PROFILES['runtime-read']['guard'])
  self.assertEqual(profile['test'],'TestDarwinDeploymentCompletionContracts')
  self.assertEqual(profile['filename'],'darwin-deployment-completion.json')

 def test_duplicate_json_keys_refused(self):
  with self.assertRaises(DRIVER.Refused):DRIVER.load_json('{"schemaVersion":1,"schemaVersion":2}')

 def test_capture_success_and_exit_status(self):
  code,data=DRIVER.capture_owned([sys.executable,'-c','import os; os.write(1,b"fixed output"); raise SystemExit(7)'],os.environ,Path.cwd(),5,1024)
  self.assertEqual((code,data),(7,b'fixed output'))

 def captured_failure(self,program,timeout,limit,expected):
  real=subprocess.Popen;created=[]
  def start(*args,**kwargs):
   child=real(*args,**kwargs);created.append(child);return child
  with patch.object(DRIVER.subprocess,'Popen',side_effect=start):
   with self.assertRaises(DRIVER.Refused) as result:DRIVER.capture_owned([sys.executable,'-c',program],os.environ,Path.cwd(),timeout,limit)
  self.assertEqual(result.exception.code,expected)
  self.assertEqual(len(created),1)
  self.assertIsNotNone(created[0].poll(),'owned process remained live after failure')

 @unittest.skipIf(os.name=='nt','POSIX owned process groups only')
 def test_output_overflow_kills_and_reaps_owned_process(self):
  self.captured_failure('import os\nwhile True: os.write(1,b"x"*65536)',5,1024,'native-output-limit')

 @unittest.skipIf(os.name=='nt','POSIX owned process groups only')
 def test_pipe_eof_does_not_complete_a_live_process(self):
  self.captured_failure('import os,time; os.close(1); os.close(2); time.sleep(30)',.3,1024,'native-timeout')

 def test_report_creation_is_exclusive_and_aliases_refused(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve();parent=root/'report';parent.mkdir()
   DRIVER.write_report(parent,{'fixed':'public fixture'})
   before=(parent/'darwin-runtime-read.json').read_bytes()
   with self.assertRaises(DRIVER.Refused):DRIVER.write_report(parent,{'changed':True})
   self.assertEqual((parent/'darwin-runtime-read.json').read_bytes(),before)
   if os.name!='nt':
    alias=root/'alias';alias.symlink_to(parent,target_is_directory=True)
    with self.assertRaises(DRIVER.Refused):DRIVER.write_report(alias,{'changed':True})

 def test_binary_hash_refuses_aliases_and_hard_links(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);binary=root/'normal.test';binary.write_bytes(b'fixed binary fixture')
   self.assertEqual(len(DRIVER.file_hash(binary)),64)
   if os.name!='nt':
    alias=root/'alias';alias.symlink_to(binary)
    with self.assertRaises(DRIVER.Refused):DRIVER.file_hash(alias)
    os.link(binary,root/'linked')
    with self.assertRaises(DRIVER.Refused):DRIVER.file_hash(binary)

if __name__=='__main__':unittest.main()
