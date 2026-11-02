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
