#!/usr/bin/env node
'use strict';
// Bind runtime results to the authenticated archive, not just the checkout SHA.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {validateBuild}=require('./check-native-environment.cjs');
const identityKeys=['version','commit','sourceState','builtAt','goVersion','platform','arch'];
function matchReceipt(receipt,report,expected){
 assert.equal(receipt.schemaVersion,1);assert.equal(receipt.sourceCommit,expected.commit);assert.equal(receipt.sourceRef,expected.ref);
 assert.equal(receipt.target,expected.goos+'/'+expected.goarch);assert.equal(receipt.authenticatedBeforeStaging,true);assert.equal(receipt.provenanceSubjectsVerified,12);
 assert.equal(report.sourceCommit,expected.commit);assert.equal(report.binarySha256,receipt.binarySha256,'tested binary differs from authenticated archive');
 validateBuild(report.build,expected);
 for(const key of identityKeys)assert.equal(report.build[key],receipt.build[key],'runtime differs from authenticated BUILD-INFO: '+key);
}
function validateRecoveryEvidence(recovery){
 for(const key of ['goToWebCrypto','webCryptoToGo','emptySourceGoToWebCrypto','emptySourceWebCryptoToGo','missingSnapshotRejected','replacementPolicySignatureVerified','binarySourceBytesPreserved','wrongKeyAndFloorRejected','changedSourceRejected','expiryRejected','crossProtocolSignatureRejected','changedSignatureRejected','validReviewBeforeAndAfterRejections'])assert.equal(recovery[key],true);
 assert.equal(recovery.machinePolicyMutationAttempted,false);
}
function validateWindowsDiscoveryEvidence(report){
 assert.equal(report.schemaVersion,1);assert.equal(report.deadlineMilliseconds,45000);
 assert(Number.isSafeInteger(report.probeElapsedMilliseconds)&&report.probeElapsedMilliseconds>=0&&report.probeElapsedMilliseconds<=45000,'discovery exceeded its unchanged deadline');
 for(const key of ['originalArchiveExecuted','readOnlyActionVerified','fullDiscoveryShapeVerified','ownedProcessStopped','ownedCapsuleRemoved','serviceInspectionSucceeded','taskInspectionSucceeded'])assert.equal(report[key],true,key);
 assert.equal(report.settingsChanged,false);assert.equal(report.productionQualificationComplete,false);
 assert(Array.isArray(report.phases)&&report.phases.length>0&&report.phases.length<=128);
 const names={Workflow:'storage-ready script-ready request-ready environment-ready launch first-output child-exited shell-input shell-parse shell-initialize shell-utility-ready shell-management-ready shell-request-decoded shell-network-ready shell-root-ready shell-state-ready shell-catalog-ready shell-dispatch'.split(' '),Discovery:'services components applications conflicts refresh-task final-paths complete'.split(' '),'Task query':'start started capture-ready exited timed-out drained cleanup tree-helper-returned disposed'.split(' ')};
 for(const line of report.phases){
  const match=typeof line==='string'&&line.match(/^(Workflow|Discovery|Task query) timing ms: ([a-z-]+) ([0-9]{1,12})$/);
  assert(match&&names[match[1]].includes(match[2]),'invalid public discovery timing');
 }
 for(const marker of ['Workflow timing ms: shell-dispatch ','Workflow timing ms: child-exited ','Discovery timing ms: complete '])assert(report.phases.some(line=>line.startsWith(marker)),'missing discovery completion timing');
}
function read(file){const st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<=1<<20,'evidence must be a bounded regular file');return JSON.parse(fs.readFileSync(file,'utf8'));}
function main(){
 const [phase,folder]=process.argv.slice(2);assert(['identity','complete'].includes(phase)&&folder,'usage: check-packaged-evidence.cjs identity|complete STAGED_DIRECTORY');
 const expected={goos:process.env.ACCESSWEAVER_EXPECT_GOOS,goarch:process.env.ACCESSWEAVER_EXPECT_GOARCH,goVersion:process.env.GO_VERSION,commit:process.env.GITHUB_SHA,ref:process.env.GITHUB_REF};
 assert.match(expected.commit||'',/^[0-9a-f]{40,64}$/);assert.match(expected.ref||'',/^refs\/(heads|tags)\/.+/);
 const receipt=read(path.join(folder,'candidate.json'));
 assert.equal(receipt.binary,expected.goos==='windows'?'accessweaver.exe':'accessweaver');
 const executable=path.join(folder,receipt.binary),st=fs.lstatSync(executable);assert(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<=64<<20);
 assert.equal(createHash('sha256').update(fs.readFileSync(executable)).digest('hex'),receipt.binarySha256);
 const identity=read('build/native-checks/binary-'+expected.goos+'-'+expected.goarch+'.json');matchReceipt(receipt,identity,expected);assert.equal(identity.executedTargetVerified,true);
 if(phase==='identity')return;
 const nodePlatform={windows:'win32',linux:'linux',darwin:'darwin'}[expected.goos];
 const backup=read('build/backup-checks/interop-'+nodePlatform+'.json');matchReceipt(receipt,backup,expected);
 for(const key of ['goToWebCrypto','webCryptoToGo','restoredRevisionPreserved','tamperRejected','wrongPassphraseRejected'])assert.equal(backup[key],true);
 const recovery=read('build/managed-policy-checks/recovery-interop-'+nodePlatform+'.json');matchReceipt(receipt,recovery,expected);
 validateRecoveryEvidence(recovery);
 const diagnostics=read('build/packaged-native-checks/diagnostics-'+expected.goos+'-'+expected.goarch+'.json');matchReceipt(receipt,diagnostics,expected);
 assert.equal(diagnostics.loopbackOnly,true);assert.equal(diagnostics.settingsChanged,false);assert.equal(diagnostics.checks.length,9);assert(diagnostics.checks.every(c=>c.passed===true));
 if(expected.goos==='windows'){
  const discovery=read('build/packaged-native-checks/discovery-windows-'+expected.goarch+'.json');matchReceipt(receipt,discovery,expected);
  for(const key of ['archiveSha256','manifestSha256','bundleSha256'])assert.equal(discovery[key],receipt[key]);
  validateWindowsDiscoveryEvidence(discovery);
 }
 if(expected.goos!=='windows'){
  const controller=read('build/packaged-native-checks/controller.json');assert.equal(controller.binarySha256,receipt.binarySha256);assert.equal(controller.passed,true);assert(controller.checks.length>=11);
 }
 const result={schemaVersion:1,sourceCommit:expected.commit,sourceRef:expected.ref,target:receipt.target,binarySha256:receipt.binarySha256,archiveSha256:receipt.archiveSha256,build:receipt.build,authenticatedCandidateExecuted:true,backupAndRecoveryVerified:true,loopbackDiagnosticsVerified:true,unixControllerVerified:expected.goos!=='windows',windowsDiscoveryVerified:expected.goos==='windows',publisherSignatureVerified:false,productionQualificationComplete:false};
 fs.writeFileSync('build/packaged-native-checks/acceptance.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
module.exports={matchReceipt,validateRecoveryEvidence,validateWindowsDiscoveryEvidence};
if(require.main===module){try{main()}catch(error){console.error(error.message);process.exitCode=1;}}
