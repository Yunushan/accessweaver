#!/usr/bin/env python3
"""Disposable hosted Mac root fixtures; only fixed source-owned reports survive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

REPO=Path(__file__).resolve().parent.parent
LIMIT=2<<20
SOURCES=tuple('internal/packageupgrade/'+name for name in (
 'runtime_darwin.go','runtime_read_darwin.go','preflight_darwin.go','deployment_darwin.go',
 'deployment_payload_darwin.go','launcher_darwin.go','desktop_darwin.go','runtime_read_completion_darwin_test.go'))+('scripts/test-darwin-runtime-read-completion.py',)
CASES=('active-runtime','read-close-sites','missing-cofailure','bounded-cofailure','successor-cofailure','seal-refusal','scope-transfer','scope-close-sites','scope-cofailure','scope-blocked','scope-panic','inherited-transfer','inherited-cofailure','foreign-descriptor','parse-and-busy','authority-and-identity')
DEPLOYMENT_CASES=('prepare-close-sites','payload-close-sites','partial-copy-preserved','complete-copy-reconcile','source-postpublication','record-postpublication','phase-postpublication','partial-source-owner','store-close-sites','store-lock-lifetime','store-multiple-causes','creation-cofailure','idempotent-activation','reconcile-publication','source-factory','input-preflight')
PROFILES={
 'runtime-read':{'cases':CASES,'sources':SOURCES,'fixture':'internal/packageupgrade/runtime_read_completion_darwin_test.go','guard':'ACCESSWEAVER_DISPOSABLE_DARWIN_RUNTIME_READ_TEST','evidence':'ACCESSWEAVER_DARWIN_RUNTIME_READ_EVIDENCE','test':'TestDarwinRuntimeReadCompletionContracts','prefix':b'RUNTIME-READ-RESULT ','filename':'darwin-runtime-read.json','label':'Native runtime read'},
 'deployment-completion':{'cases':DEPLOYMENT_CASES,'sources':tuple('internal/packageupgrade/'+name for name in ('deployment_completion_darwin.go','deployment_darwin.go','deployment_payload_darwin.go','deployment_command_darwin.go','package_phase_darwin.go','deployment_completion_darwin_test.go','runtime_read_completion_darwin_test.go','runtime_read_darwin.go','preflight_darwin.go','contract.go'))+('internal/darwintrust/files_darwin.go','scripts/test-darwin-runtime-read-completion.py'),'fixture':'internal/packageupgrade/deployment_completion_darwin_test.go','guard':'ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_COMPLETION_TEST','evidence':'ACCESSWEAVER_DARWIN_DEPLOYMENT_COMPLETION_EVIDENCE','test':'TestDarwinDeploymentCompletionContracts','prefix':b'DEPLOYMENT-COMPLETION-RESULT ','filename':'darwin-deployment-completion.json','label':'Native deployment completion'},
 'desktop-read':{'cases': ('registration-close-sites', 'registration-missing', 'registration-body-cofailure', 'application-close-sites', 'compatible-close-sites', 'application-body-cofailure', 'applications-acquisition', 'receipt-absence-completion', 'result-completion-scope', 'result-blocked-scope', 'result-panic-scope', 'native-policy-refusal'), 'sources': ('internal/packageupgrade/desktop_darwin.go', 'internal/packageupgrade/desktop_read_darwin.go', 'internal/packageupgrade/desktop_read_completion_darwin_test.go', 'internal/packageupgrade/desktop.go', 'internal/packageupgrade/desktop_test.go', 'internal/packageupgrade/contract.go', 'internal/packageupgrade/contract_test.go', 'internal/packageupgrade/runtime_read_completion_darwin_test.go', 'internal/packageupgrade/runtime_read_darwin.go', 'internal/packageupgrade/preflight_darwin.go', 'internal/packageupgrade/deployment_darwin.go', 'internal/darwintrust/files_darwin.go', 'scripts/test-darwin-runtime-read-completion.py'), 'fixture': 'internal/packageupgrade/desktop_read_completion_darwin_test.go', 'guard': 'ACCESSWEAVER_DISPOSABLE_DARWIN_DESKTOP_READ_TEST', 'evidence': 'ACCESSWEAVER_DARWIN_DESKTOP_READ_EVIDENCE', 'test': 'TestDarwinDesktopReadCompletionContracts', 'prefix': b'DESKTOP-READ-RESULT ', 'filename': 'darwin-desktop-read.json', 'label': 'Native desktop read'},
}

FAILURES={'native-output-limit','native-timeout','native-child-reap-uncertain','native-report-unavailable','native-report-invalid','native-binary-changed','native-compile-failed','native-root-driver-failed','native-driver-refused'}

class Refused(Exception):
 def __init__(self,code):
  self.code=code if code in FAILURES else 'native-driver-refused'
  super().__init__(self.code)

def require(ok,code='native-driver-refused'):
 if not ok:raise Refused(code)

def load_json(data):
 def unique(pairs):
  result={}
  for key,value in pairs:
   if key in result:raise Refused('native-report-invalid')
   result[key]=value
  return result
 return json.loads(data,object_pairs_hook=unique)

def capture_owned(argv,env,cwd,timeout=210,limit=LIMIT):
 """Bound memory before retention; kill/join only our own new process group."""
 process=subprocess.Popen([str(x) for x in argv],cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
 selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
 os.set_blocking(process.stdout.fileno(),False)
 collected=bytearray();deadline=time.monotonic()+timeout;failure=None
 try:
  while selector.get_map() or process.poll() is None:
   if time.monotonic()>=deadline:
    failure='native-timeout';break
   for key,_ in selector.select(min(.25,max(0,deadline-time.monotonic()))):
    chunk=os.read(key.fd,65536)
    if not chunk:selector.unregister(key.fileobj);continue
    if len(collected)+len(chunk)>limit:
     failure='native-output-limit';break
    collected.extend(chunk)
   if failure:break
  if failure:
   # process remains our unreaped child, so its PID cannot be recycled here.
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  try:code=process.wait(timeout=10)
  except subprocess.TimeoutExpired:raise Refused('native-child-reap-uncertain') from None
  if failure:raise Refused(failure)
  return code,bytes(collected)
 finally:
  selector.close();process.stdout.close()
  if process.poll() is None:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:raise Refused('native-child-reap-uncertain') from None

def source_hashes(suite='runtime-read'):
 result={}
 for name in PROFILES[suite]['sources']:
  path=REPO/name;info=path.lstat()
  require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=65536)
  with path.open('rb') as file:data=file.read(65537)
  require(len(data)<=65536)
  result[name]=hashlib.sha256(data).hexdigest()
 return result

def file_hash(path):
 info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink() and 0<info.st_size<=128<<20)
 digest=hashlib.sha256()
 with path.open('rb') as file:
  size=0
  for chunk in iter(lambda:file.read(65536),b''):
   size+=len(chunk);require(size<=128<<20);digest.update(chunk)
 after=path.lstat();require((info.st_dev,info.st_ino,info.st_size)==(after.st_dev,after.st_ino,after.st_size))
 return digest.hexdigest()

def validate_native(value,source,arch=None,suite='runtime-read'):
 require(type(value) is dict and set(value)=={'schemaVersion','sourceCommit','goos','goarch','goVersion','outcome','cases','nativeRootFixture','nativeInstalledQualified'},'native-report-invalid')
 require(type(value['schemaVersion']) is int and value['schemaVersion']==1 and value['sourceCommit']==source,'native-report-invalid')
 require(value['goos']=='darwin' and value['goarch'] in ('amd64','arm64') and (arch is None or value['goarch']==arch) and value['goVersion']=='go1.27.3','native-report-invalid')
 require(value['nativeRootFixture'] is True and value['nativeInstalledQualified'] is False and value['outcome'] in ('passed','failed'),'native-report-invalid')
 require(type(value['cases']) is list and len(value['cases'])==len(PROFILES[suite]['cases']) and all(type(case) is dict for case in value['cases']) and [case.get('name') for case in value['cases']]==list(PROFILES[suite]['cases']),'native-report-invalid')
 for case in value['cases']:
  require(set(case)=={'name','passed','checks','code','sites'} and type(case['passed']) is bool and type(case['checks']) is int and 0<=case['checks']<=65536 and type(case['sites']) is int and 0<=case['sites']<=128 and type(case['code']) is str and re.fullmatch('[a-z][a-z0-9-]{1,80}',case['code']) is not None,'native-report-invalid')
  require(not case['passed'] or (case['checks']>0 and case['code']=='none'),'native-report-invalid')
 require((value['outcome']=='passed')==all(c['passed'] for c in value['cases']),'native-report-invalid')
 return value

def root_child(args):
 profile=PROFILES[args.suite]
 require(sys.platform=='darwin' and os.getuid()==0 and os.geteuid()==0 and os.getgid()==0 and os.getegid()==0)
 require(os.environ.get(profile['guard'])=='1' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='macOS')
 require(re.fullmatch('[0-9a-f]{40}',args.source) is not None and re.fullmatch('[0-9a-f]{64}',args.digest) is not None)
 binary=Path(args.binary);require(binary.is_absolute() and binary.name in ('normal.test','race.test') and binary.parent.name.startswith('accessweaver-runtime-read-') and binary.resolve()==binary)
 require(file_hash(binary)==args.digest,'native-binary-changed')
 # No workflow credentials or caller paths/configuration enter the root test.
 environment={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C','TZ':'UTC','TMPDIR':'/private/tmp','GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'macOS','GITHUB_SHA':args.source,profile['guard']:'1'}
 code,output=capture_owned([binary,'-test.run=^'+profile['test']+'$','-test.v','-test.timeout=3m'],environment,'/',210)
 require(file_hash(binary)==args.digest,'native-binary-changed')
 prefix=profile['prefix']
 lines=[line[len(prefix):] for line in output.splitlines() if line.startswith(prefix)]
 require(len(lines)==1 and len(lines[0])<=16384,'native-report-unavailable')
 value=validate_native(load_json(lines[0]),args.source,suite=args.suite)
 require(code in (0,1) and (code==0)==(value['outcome']=='passed'),'native-report-invalid')
 # Re-serialize only the validated protocol; raw test output is never retained.
 print(json.dumps({'kind':'native-cases','exitCode':code,'native':value},separators=(',',':')))


def write_report(parent,value,filename='darwin-runtime-read.json'):
 require(parent.is_absolute() and parent.resolve()==parent)
 before=parent.lstat();require(stat.S_ISDIR(before.st_mode) and not parent.is_symlink() and not list(parent.iterdir()))
 encoded=(json.dumps(value,separators=(',',':'))+'\n').encode('utf-8');require(len(encoded)<=32768)
 after=parent.lstat();require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino))
 with (parent/filename).open('xb') as report:
  require(report.write(encoded)==len(encoded));report.flush()


def ordinary(suite):
 profile=PROFILES[suite]
 require(sys.platform=='darwin' and os.getuid()!=0 and os.geteuid()!=0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='macOS' and os.environ.get(profile['guard'])=='1' and os.environ.get('GOTOOLCHAIN')=='local')
 source=os.environ.get('GITHUB_SHA','');require(re.fullmatch('[0-9a-f]{40}',source) is not None)
 code,head=capture_owned(['git','rev-parse','HEAD'],os.environ,REPO,30,4096);require(code==0 and head.decode().strip()==source)
 code,identity=capture_owned(['go','env','-json','GOHOSTOS','GOHOSTARCH','GOOS','GOARCH','GOVERSION','GOTOOLCHAIN'],os.environ,REPO,30,8192)
 native=load_json(identity);arch=native['GOARCH'];require(code==0 and native['GOOS']==native['GOHOSTOS']=='darwin' and arch==native['GOHOSTARCH'] and arch in ('amd64','arm64') and native['GOVERSION']=='go1.27.3' and native['GOTOOLCHAIN']=='local')
 evidence=Path(os.environ.get(profile['evidence'],''));require(evidence.is_absolute() and evidence.resolve()==evidence and evidence.is_dir())
 runner_temp=Path(os.environ.get('RUNNER_TEMP',''));require(runner_temp.is_absolute());runner_temp=runner_temp.resolve();require(runner_temp.is_dir())
 capsule=Path(tempfile.mkdtemp(prefix='accessweaver-runtime-read-',dir=runner_temp)).resolve()
 initial=capsule.lstat();bindings=source_hashes(suite);failed=False
 try:
  for mode in ('normal','race'):
   report_parent=evidence/mode;binary=capsule/(mode+'.test');binary_sha=None
   try:
    command=['go','test','-c','-p=2','-mod=readonly','-trimpath','-buildvcs=false']
    if mode=='race':command.append('-race')
    command+=['-o',binary,'./internal/packageupgrade']
    code,_=capture_owned(command,os.environ,REPO,300)
    require(code==0,'native-compile-failed');require(source_hashes(suite)==bindings)
    binary_sha=file_hash(binary)
    command=['/usr/bin/sudo','-n','/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','LANG=C','LC_ALL=C','TZ=UTC','GITHUB_ACTIONS=true','RUNNER_ENVIRONMENT=github-hosted','RUNNER_OS=macOS',profile['guard']+'=1','/usr/bin/python3','-I',str(Path(__file__).resolve()),'--root-child','--suite',suite,'--source',source,'--binary',str(binary),'--digest',binary_sha]
    code,output=capture_owned(command,os.environ,REPO,240,65536)
    require(code==0 and len(output)<=32768,'native-root-driver-failed')
    observed=load_json(output)
    require(set(observed)=={'kind','exitCode','native'} and observed['kind']=='native-cases' and type(observed['exitCode']) is int and observed['exitCode'] in (0,1),'native-report-invalid')
    value=validate_native(observed['native'],source,arch,suite)
    fixture=''.join((REPO/name).read_text(encoding='utf-8') for name in profile['sources'] if name.endswith('_test.go'))
    codes=set(re.findall(r'"([a-z][a-z0-9-]{1,80})"',fixture))
    require(all(c['code'] in codes for c in value['cases']),'native-report-invalid')
    require(file_hash(binary)==binary_sha and source_hashes(suite)==bindings,'native-binary-changed')
    report={'schemaVersion':1,'kind':'native-cases','sourceCommit':source,'sourceSHA256':bindings,'testBinarySHA256':binary_sha,'mode':mode,'exitCode':observed['exitCode'],'native':value}
    write_report(report_parent,report,profile['filename'])
    print(profile['label']+' '+arch+'/'+mode+' '+('PASS' if value['outcome']=='passed' else 'FAIL'),flush=True)
    failed=failed or value['outcome']!='passed'
   except Exception as error:
    code=error.code if isinstance(error,Refused) else 'native-driver-refused'
    write_report(report_parent,{'schemaVersion':1,'kind':'driver-failure','sourceCommit':source,'sourceSHA256':bindings,'mode':mode,'code':code,'nativeInstalledQualified':False},profile['filename'])
    print(profile['label']+' '+arch+'/'+mode+' FAIL '+code,flush=True);failed=True
 finally:
  # Delete only the two exact binaries we created, after checking our capsule.
  current=capsule.lstat();require(current.st_dev==initial.st_dev and current.st_ino==initial.st_ino and stat.S_ISDIR(current.st_mode) and not capsule.is_symlink() and capsule.parent==runner_temp and capsule.name.startswith('accessweaver-runtime-read-'))
  for name in ('normal.test','race.test'):
   path=capsule/name
   if path.exists():require(path.is_file() and not path.is_symlink());path.unlink()
  capsule.rmdir()
 require(not failed,'native-root-driver-failed')


def main():
 parser=argparse.ArgumentParser();parser.add_argument('--root-child',action='store_true');parser.add_argument('--suite',choices=tuple(PROFILES),default='runtime-read');parser.add_argument('--source');parser.add_argument('--binary');parser.add_argument('--digest');args=parser.parse_args()
 if args.root_child:root_child(args)
 else:ordinary(args.suite)

if __name__=='__main__':
 try:main()
 except BaseException as error:
  code=error.code if isinstance(error,Refused) else 'native-driver-refused'
  print('Native runtime read driver stopped: '+code,flush=True);sys.exit(1)
