'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {matchReceipt,validateRecoveryEvidence}=require('./check-packaged-evidence.cjs');
test('runtime evidence must match authenticated metadata and binary bytes',()=>{
 const expected={goos:'windows',goarch:'arm64',goVersion:'1.27.3',commit:'a'.repeat(40),ref:'refs/heads/main'};
 const build={version:'0.1.0-alpha',commit:expected.commit,sourceState:'clean',builtAt:'2026-11-02T00:00:00Z',goVersion:'go1.27.3',platform:'windows',arch:'arm64'};
 const receipt={schemaVersion:1,sourceCommit:expected.commit,sourceRef:expected.ref,target:'windows/arm64',authenticatedBeforeStaging:true,provenanceSubjectsVerified:12,binarySha256:'b'.repeat(64),build};
 const report={sourceCommit:expected.commit,binarySha256:receipt.binarySha256,build};
 matchReceipt(receipt,report,expected);
 for(const key of Object.keys(build))assert.throws(()=>matchReceipt(receipt,{...report,build:{...build,[key]:'different'}},expected),key);
 assert.throws(()=>matchReceipt(receipt,{...report,binarySha256:'c'.repeat(64)},expected));
 assert.throws(()=>matchReceipt(receipt,{...report,sourceCommit:'c'.repeat(40)},expected));
 for(const [key,value] of Object.entries({sourceCommit:'c'.repeat(40),sourceRef:'refs/tags/v0.1',target:'windows/amd64',authenticatedBeforeStaging:false,provenanceSubjectsVerified:11}))assert.throws(()=>matchReceipt({...receipt,[key]:value},report,expected),key);
});

test('packaged recovery evidence requires empty-source and missing-file checks',()=>{
 const previous={goToWebCrypto:true,webCryptoToGo:true,replacementPolicySignatureVerified:true,binarySourceBytesPreserved:true,wrongKeyAndFloorRejected:true,changedSourceRejected:true,expiryRejected:true,crossProtocolSignatureRejected:true,changedSignatureRejected:true,validReviewBeforeAndAfterRejections:true,machinePolicyMutationAttempted:false};
 assert.throws(()=>validateRecoveryEvidence(previous),'historical incomplete coverage accepted');
 const complete={...previous,emptySourceGoToWebCrypto:true,emptySourceWebCryptoToGo:true,missingSnapshotRejected:true};
 validateRecoveryEvidence(complete);
 for(const name of ['emptySourceGoToWebCrypto','emptySourceWebCryptoToGo','missingSnapshotRejected']){
  const missing={...complete};delete missing[name];assert.throws(()=>validateRecoveryEvidence(missing),name);
  assert.throws(()=>validateRecoveryEvidence({...complete,[name]:false}),name);
 }
 assert.throws(()=>validateRecoveryEvidence({...complete,machinePolicyMutationAttempted:true}));
});


test('archived Windows discovery requires complete source-bound successful inspection and owned cleanup',()=>{
 const {validateWindowsDiscoveryEvidence}=require('./check-packaged-evidence.cjs');
 const report={schemaVersion:1,deadlineMilliseconds:45000,probeElapsedMilliseconds:8100,originalArchiveExecuted:true,readOnlyActionVerified:true,fullDiscoveryShapeVerified:true,ownedProcessStopped:true,ownedCapsuleRemoved:true,serviceInspectionSucceeded:true,taskInspectionSucceeded:true,settingsChanged:false,productionQualificationComplete:false,phases:['Workflow timing ms: shell-dispatch 1000','Discovery timing ms: complete 1200','Workflow timing ms: child-exited 8000']};
 validateWindowsDiscoveryEvidence(report);
 for(const key of ['originalArchiveExecuted','readOnlyActionVerified','fullDiscoveryShapeVerified','ownedProcessStopped','ownedCapsuleRemoved','serviceInspectionSucceeded','taskInspectionSucceeded']){
  const missing={...report};delete missing[key];assert.throws(()=>validateWindowsDiscoveryEvidence(missing),key);
  assert.throws(()=>validateWindowsDiscoveryEvidence({...report,[key]:false}),key);
 }
 for(const elapsed of [-1,45001,1.1,NaN,'8100'])assert.throws(()=>validateWindowsDiscoveryEvidence({...report,probeElapsedMilliseconds:elapsed}));
 for(const change of [{settingsChanged:true},{productionQualificationComplete:true},{deadlineMilliseconds:60000},{phases:[]},{phases:['PRIVATE']},{phases:[...report.phases,'Workflow timing ms: private-name 5']},{phases:Array(129).fill(report.phases[0])},{phases:report.phases.slice(1)}])assert.throws(()=>validateWindowsDiscoveryEvidence({...report,...change}));
});

const {validateUnixControllerEvidence}=require('./check-packaged-evidence.cjs');
function unixControllerSuccess(platform='Linux'){
 return {passed:true,platform,binarySha256:'b'.repeat(64),checks:[
  'duplicate UI rejected while the first controller remains active',
  'first controller survives duplicate launch',
  'CLI import rejected while UI owns the root',
  'rejected import preserves saved profiles',
  'read-only CLI remains available',
  'private owner bootstrap bypasses proxies without disclosing a credential',
  'controller shuts down gracefully',
  'shutdown removes the private launch credential',
  'CLI import succeeds after controller shutdown',
  'post-shutdown import preserves profile contents',
  'released coordination file remains in place',
 ]};
}

test('existing Linux and Darwin controller successes bind all fixed cases to the archive binary',()=>{
 for(const [goos,platform] of [['linux','Linux'],['darwin','Darwin']]){
  const report=JSON.parse(JSON.stringify(unixControllerSuccess(platform)));
  validateUnixControllerEvidence(report,goos,report.binarySha256);
  assert.throws(()=>validateUnixControllerEvidence(report,goos,'c'.repeat(64)),'different archive binary');
  assert.throws(()=>validateUnixControllerEvidence(report,goos==='linux'?'darwin':'linux',report.binarySha256),'different native platform');
 }
 assert.throws(()=>validateUnixControllerEvidence(unixControllerSuccess(),'freebsd','b'.repeat(64)),'unsupported target');
});

test('controller success requires the exact producer schema and typed native identity',()=>{
 const report=unixControllerSuccess(),validate=value=>validateUnixControllerEvidence(value,'linux',report.binarySha256);
 for(const value of [null,[],true,'success'])assert.throws(()=>validate(value));
 for(const key of Object.keys(report)){
  const missing={...report};delete missing[key];assert.throws(()=>validate(missing),key);
 }
 for(const change of [{error:'failed check'},{extra:true},{passed:false},{passed:'true'},{platform:'linux'},{platform:'Windows'},{platform:null}])assert.throws(()=>validate({...report,...change}));
 for(const hash of ['',null,123,'b'.repeat(63),'b'.repeat(65),'B'.repeat(64),'g'.repeat(64)])assert.throws(()=>validate({...report,binarySha256:hash}));
});

test('controller case counts cannot substitute for the required successful behaviors',()=>{
 const report=unixControllerSuccess(),validate=checks=>validateUnixControllerEvidence({...report,checks},'linux',report.binarySha256);
 for(const checks of ['x'.repeat(11),{length:11},null,Array(11).fill(report.checks[0]),report.checks.concat('unexpected behavior'),[...report.checks].reverse()])assert.throws(()=>validate(checks));
 for(let index=0;index<report.checks.length;index++){
  assert.throws(()=>validate(report.checks.filter((_,at)=>at!==index)),'missing case '+index);
  for(const replacement of [report.checks[(index+1)%report.checks.length],'unknown behavior',true,{passed:true}]){
   const changed=report.checks.slice();changed[index]=replacement;assert.throws(()=>validate(changed),'changed case '+index);
  }
 }
});

const {validateDiagnosticsEvidence}=require('./check-packaged-evidence.cjs');
function diagnosticsSuccess(goos='linux',goarch='amd64'){
 const commit='a'.repeat(40),binarySha256='b'.repeat(64);
 const build={version:'0.1.0-alpha',commit,sourceState:'clean',builtAt:'2026-11-02T00:00:00Z',goVersion:'go1.27.3',platform:goos,arch:goarch};
 return {sourceCommit:commit,platform:{windows:'win32',linux:'linux',darwin:'darwin'}[goos],arch:goarch,build,binarySha256,loopbackOnly:true,settingsChanged:false,productionQualificationComplete:false,checks:[
  {name:'direct loopback TCP',passed:true,path:'direct',transport:'tcp'},
  {name:'untrusted TLS certificate',passed:true,path:'direct',transport:'tcp'},
  {name:'socks5 tunnel',passed:true,path:'socks5',transport:'tcp'},
  {name:'http-connect tunnel',passed:true,path:'http-connect',transport:'tcp'},
  {name:'HTTP proxy refusal',passed:true,path:'http-connect',transport:'tcp'},
  {name:'direct UDP/STUN',passed:true,path:'direct',transport:'stun'},
  {name:'mismatched STUN transaction',passed:true,path:'direct',transport:'stun'},
  {name:'bounded UDP timeout',passed:true,path:'direct',transport:'stun'},
  {name:'SOCKS5 UDP association',passed:true,path:'socks5',transport:'stun'},
 ]};
}

test('existing packaged diagnostics bind all nine wire cases on every hosted target',()=>{
 for(const goos of ['windows','linux','darwin'])for(const goarch of ['amd64','arm64']){
  const report=JSON.parse(JSON.stringify(diagnosticsSuccess(goos,goarch)));
  const expected={goos,goarch,goVersion:'1.27.3',commit:report.sourceCommit,ref:'refs/heads/main'};
  const receipt={schemaVersion:1,sourceCommit:expected.commit,sourceRef:expected.ref,target:goos+'/'+goarch,authenticatedBeforeStaging:true,provenanceSubjectsVerified:12,binarySha256:report.binarySha256,build:report.build};
  matchReceipt(receipt,report,expected);validateDiagnosticsEvidence(report,expected);
  assert.throws(()=>validateDiagnosticsEvidence({...report,platform:'wrong'},expected));
  assert.throws(()=>validateDiagnosticsEvidence({...report,arch:goarch==='amd64'?'arm64':'amd64'},expected));
  assert.throws(()=>matchReceipt(receipt,{...report,build:{...report.build,commit:'c'.repeat(40)}},expected));
  assert.throws(()=>matchReceipt(receipt,{...report,binarySha256:'c'.repeat(64)},expected));
 }
});

test('diagnostics require the exact success envelope and bounded binary identity',()=>{
 const report=diagnosticsSuccess(),expected={goos:'linux',goarch:'amd64',commit:report.sourceCommit},validate=value=>validateDiagnosticsEvidence(value,expected);
 for(const value of [null,[],true,'success'])assert.throws(()=>validate(value));
 for(const key of Object.keys(report)){
  const missing={...report};delete missing[key];assert.throws(()=>validate(missing),key);
 }
 for(const change of [{extra:true},{error:'failed probe'},{sourceCommit:'c'.repeat(40)},{loopbackOnly:false},{loopbackOnly:'true'},{settingsChanged:true},{settingsChanged:0},{productionQualificationComplete:true},{productionQualificationComplete:null}])assert.throws(()=>validate({...report,...change}));
 for(const hash of ['',null,123,'b'.repeat(63),'b'.repeat(65),'B'.repeat(64),'g'.repeat(64)])assert.throws(()=>validate({...report,binarySha256:hash}));
 assert.throws(()=>validateDiagnosticsEvidence(report,{...expected,goos:'freebsd'}));
});

test('diagnostics reject duplicate counts and altered, missing or extra check tuple fields',()=>{
 const report=diagnosticsSuccess(),expected={goos:'linux',goarch:'amd64',commit:report.sourceCommit},validate=checks=>validateDiagnosticsEvidence({...report,checks},expected);
 for(const checks of ['x'.repeat(9),{length:9},null,Array(9).fill(report.checks[0]),report.checks.concat(report.checks[0]),[...report.checks].reverse()])assert.throws(()=>validate(checks));
 for(let index=0;index<report.checks.length;index++){
  assert.throws(()=>validate(report.checks.filter((_,at)=>at!==index)),'missing case '+index);
  const replaced=report.checks.slice();replaced[index]=report.checks[(index+1)%report.checks.length];assert.throws(()=>validate(replaced),'duplicate case '+index);
  for(const change of [{name:'unknown behavior'},{path:'unknown path'},{transport:'udp'},{passed:false},{passed:'true'},{extra:true}]){
   const changed=report.checks.slice();changed[index]={...changed[index],...change};assert.throws(()=>validate(changed),'changed tuple '+index);
  }
  for(const key of Object.keys(report.checks[index])){
   const changed=report.checks.slice();changed[index]={...changed[index]};delete changed[index][key];assert.throws(()=>validate(changed),'missing tuple field '+key);
  }
 }
});
