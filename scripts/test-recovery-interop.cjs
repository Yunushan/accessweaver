#!/usr/bin/env node
'use strict';
// Offline native CLI/Web Crypto signature interoperability. No policy enrollment.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {createHash, webcrypto} = require('node:crypto');
const {spawnSync} = require('node:child_process');
const {validateBuild}=require('./check-native-environment.cjs');
const executable = path.resolve(process.argv[2] || (process.platform === 'win32' ? 'accessweaver.exe' : 'accessweaver'));
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'accessweaver-recovery-check-'));
const userState = path.join(workspace, 'must-not-create-state');
const policyDomain = Buffer.from('AccessWeaver managed policy v1\0');
const recoveryDomain = Buffer.from('AccessWeaver managed machine recovery v1\0');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
let privatePEM = '';
function cli(args, success=true) {
 const child=spawnSync(executable,args,{env:{...process.env,ACCESSWEAVER_HOME:userState},encoding:'utf8',timeout:30000,windowsHide:true});
 if(child.error)throw child.error;
 assert(!privatePEM || (!child.stdout.includes(privatePEM) && !child.stderr.includes(privatePEM)));
 if(success){assert.equal(child.status,0,child.stderr);return child.stdout.trim()?JSON.parse(child.stdout):null;}
 assert.notEqual(child.status,0,'unapproved recovery unexpectedly accepted');
 assert.equal(child.stdout.trim(),'','failed offline review returned a successful report');
 return child;
}
(async()=>{
 try {
  const build=cli(['version','--json']);
  if(process.env.GITHUB_ACTIONS==='true'){
   assert.match(process.env.GITHUB_SHA||'',/^[0-9a-f]{40,64}$/);
   assert.equal(build.commit,process.env.GITHUB_SHA,'native CLI does not identify the expected source commit');
   assert.equal(build.sourceState,'clean','native CLI was built from a modified source tree');
  }
  if(process.env.ACCESSWEAVER_EXPECT_GOOS || process.env.ACCESSWEAVER_EXPECT_GOARCH)validateBuild(build,{goos:process.env.ACCESSWEAVER_EXPECT_GOOS,goarch:process.env.ACCESSWEAVER_EXPECT_GOARCH,goVersion:process.env.GO_VERSION,commit:process.env.GITHUB_SHA||''});
  const keys=await webcrypto.subtle.generateKey('Ed25519',true,['sign','verify']);
  const publicBytes=Buffer.from(await webcrypto.subtle.exportKey('raw',keys.publicKey));
  const publicKey=publicBytes.toString('base64'),keyID=sha(publicBytes);
  const keyDER=Buffer.from(await webcrypto.subtle.exportKey('pkcs8',keys.privateKey));
  privatePEM='-----BEGIN PRIVATE KEY-----\n'+keyDER.toString('base64').match(/.{1,64}/g).join('\n')+'\n-----END PRIVATE KEY-----\n';
  const keyFile=path.join(workspace,'private.pem');fs.writeFileSync(keyFile,privatePEM,{mode:0o600});
  const source=Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from('damaged source\r\n'),Buffer.from([0xff])]);
  const sourceFile=path.join(workspace,'source.bin');fs.writeFileSync(sourceFile,source,{mode:0o600});
  const now=Date.now();
  const policy={schemaVersion:1,revision:8,issuedAt:new Date(now-60000).toISOString(),expiresAt:new Date(now+3600000).toISOString(),allowDiagnostics:false,allowProfileChanges:false,launches:[],workflows:[]};
  const policyFile=path.join(workspace,'policy.json');fs.writeFileSync(policyFile,JSON.stringify(policy),{mode:0o600});
  const nextFile=path.join(workspace,'next.json');cli(['managed','sign',policyFile,'--private-key',keyFile,'--out',nextFile]);
  const goFile=path.join(workspace,'go-recovery.json');
  cli(['managed','sign-recovery',nextFile,'--previous-source',sourceFile,'--minimum-revision','7','--private-key',keyFile,'--valid-for','1h','--out',goFile]);
  const signed=JSON.parse(fs.readFileSync(goFile,'utf8')),payload=Buffer.from(signed.payload,'base64');
  assert.equal(signed.keyId,keyID);
  assert(await webcrypto.subtle.verify('Ed25519',keys.publicKey,Buffer.from(signed.signature,'base64'),Buffer.concat([recoveryDomain,payload])));
  assert.equal(await webcrypto.subtle.verify('Ed25519',keys.publicKey,Buffer.from(signed.signature,'base64'),Buffer.concat([policyDomain,payload])),false);
  const request=JSON.parse(payload.toString('utf8'));
  assert.equal(request.previousSourceSHA256,sha(source));assert.equal(request.minimumRevision,7);
  assert(await webcrypto.subtle.verify('Ed25519',keys.publicKey,Buffer.from(request.nextEnvelope.signature,'base64'),Buffer.concat([policyDomain,Buffer.from(request.nextEnvelope.payload,'base64')])));
  async function envelope(value,domain){const bytes=Buffer.from(JSON.stringify(value));return {schemaVersion:1,keyId:keyID,payload:bytes.toString('base64'),signature:Buffer.from(await webcrypto.subtle.sign('Ed25519',keys.privateKey,Buffer.concat([domain,bytes]))).toString('base64')};}
  const foreignRequest={schemaVersion:1,previousSourceSHA256:sha(source),minimumRevision:7,issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+1800000).toISOString(),nextEnvelope:await envelope({...policy,revision:9},policyDomain)};
  const foreign=path.join(workspace,'webcrypto-recovery.json');
  const verify=(success=true,key=publicKey,floor='7')=>cli(['managed','verify-recovery',foreign,'--previous-source',sourceFile,'--public-key',key,'--minimum-revision',floor],success);
  const writeForeign=async(value=foreignRequest,domain=recoveryDomain)=>fs.writeFileSync(foreign,JSON.stringify(await envelope(value,domain)),{mode:0o600});
  await writeForeign();const accepted=verify();assert.equal(accepted.signatureValid,true);assert.equal(accepted.runtimeEnforced,false);assert.equal(accepted.next.policy.revision,9);assert.equal(accepted.previousAuthenticated,false);
  verify(false,publicKey,'6');
  const other=await webcrypto.subtle.generateKey('Ed25519',true,['sign','verify']);verify(false,Buffer.from(await webcrypto.subtle.exportKey('raw',other.publicKey)).toString('base64'));
  fs.writeFileSync(sourceFile,source.subarray(3));verify(false);fs.writeFileSync(sourceFile,source);
  await writeForeign({...foreignRequest,previousSourceSHA256:'0'.repeat(64)});verify(false);
  await writeForeign({...foreignRequest,issuedAt:new Date(now-120000).toISOString(),expiresAt:new Date(now-60000).toISOString()});verify(false);
  await writeForeign(foreignRequest,policyDomain);verify(false);
  await writeForeign();const damaged=JSON.parse(fs.readFileSync(foreign,'utf8'));const sig=Buffer.from(damaged.signature,'base64');sig[0]^=1;damaged.signature=sig.toString('base64');fs.writeFileSync(foreign,JSON.stringify(damaged));verify(false);
  await writeForeign();assert.equal(verify().next.policy.revision,9);
  const emptySource=path.join(workspace,'empty-source.bin');fs.writeFileSync(emptySource,Buffer.alloc(0),{mode:0o600});
  const emptyGo=path.join(workspace,'empty-go-recovery.json');
  cli(['managed','sign-recovery',nextFile,'--previous-source',emptySource,'--minimum-revision','7','--private-key',keyFile,'--valid-for','1h','--out',emptyGo]);
  const emptySigned=JSON.parse(fs.readFileSync(emptyGo,'utf8')),emptyPayload=Buffer.from(emptySigned.payload,'base64');
  assert.equal(JSON.parse(emptyPayload.toString('utf8')).previousSourceSHA256,sha(Buffer.alloc(0)));
  assert(await webcrypto.subtle.verify('Ed25519',keys.publicKey,Buffer.from(emptySigned.signature,'base64'),Buffer.concat([recoveryDomain,emptyPayload])));
  const emptyForeign=path.join(workspace,'empty-foreign.json');
  fs.writeFileSync(emptyForeign,JSON.stringify(await envelope({...foreignRequest,previousSourceSHA256:sha(Buffer.alloc(0))},recoveryDomain)),{mode:0o600});
  const verifyEmpty=(success=true,sourcePath=emptySource)=>cli(['managed','verify-recovery',emptyForeign,'--previous-source',sourcePath,'--public-key',publicKey,'--minimum-revision','7'],success);
  assert.equal(verifyEmpty().next.policy.revision,9);assert.equal(verifyEmpty().previousAuthenticated,false);
  verifyEmpty(false,sourceFile);
  fs.unlinkSync(emptySource);verifyEmpty(false);fs.writeFileSync(emptySource,Buffer.alloc(0),{mode:0o600});
  assert.equal(verifyEmpty().signatureValid,true);
  assert(!fs.existsSync(userState),'offline commands unexpectedly created user state');
  const evidence={sourceCommit:process.env.GITHUB_SHA||'unknown',platform:process.platform,arch:process.arch,nodeVersion:process.version,binarySha256:sha(fs.readFileSync(executable)),build,goToWebCrypto:true,webCryptoToGo:true,emptySourceGoToWebCrypto:true,emptySourceWebCryptoToGo:true,missingSnapshotRejected:true,replacementPolicySignatureVerified:true,binarySourceBytesPreserved:true,wrongKeyAndFloorRejected:true,changedSourceRejected:true,expiryRejected:true,crossProtocolSignatureRejected:true,changedSignatureRejected:true,validReviewBeforeAndAfterRejections:true,machinePolicyMutationAttempted:false,productionQualificationComplete:false};
  const directory=path.resolve('build','managed-policy-checks');fs.mkdirSync(directory,{recursive:true});fs.writeFileSync(path.join(directory,'recovery-interop-'+process.platform+'.json'),JSON.stringify(evidence,null,2)+'\n');
  console.log(JSON.stringify(evidence));
 } finally {
  const absolute=path.resolve(workspace);
  assert.equal(path.dirname(absolute),path.resolve(os.tmpdir()));assert(path.basename(absolute).startsWith('accessweaver-recovery-check-'));assert(!fs.lstatSync(absolute).isSymbolicLink());
  fs.rmSync(absolute,{recursive:true,force:true});
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
