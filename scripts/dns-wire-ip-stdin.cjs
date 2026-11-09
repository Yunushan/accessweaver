'use strict';
// Separate hosted-only binary stdin entry. No arbitrary paths, network or files.
const os=require('node:os');
const {inspectConfiguredIPDoHWire,WireError,LIMITS}=require('./dns-wire-evidence.cjs');
const {assertIPBinding,declaredIPBinding,POLICY_SHA256,PREREQUISITE_SHA256}=require('./dns-wire-ip-policy.cjs');
const {protocolExitCode}=require('./dns-wire-stdin.cjs');
function decodeConfiguredIPBytes(bytes,binding){
 let projected=null;
 try{assertIPBinding(binding);projected=declaredIPBinding(binding.sourceCommit);}catch{return {schemaVersion:1,outcome:'refused',code:'identity-binding',evidence:null,identityBinding:null};}
 try{return {schemaVersion:1,outcome:'decoded',code:'none',evidence:inspectConfiguredIPDoHWire(bytes,projected),identityBinding:projected};}
 catch(e){return {schemaVersion:1,outcome:'refused',code:e instanceof WireError&&/^[a-z0-9-]{1,48}$/.test(e.code)?e.code:'decoder-failed',evidence:null,identityBinding:projected};}
}
function hostedGuard(context){
 if(context===null||typeof context!=='object'||context.env===null||typeof context.env!=='object'||Array.isArray(context.env))return false;
 const {platform,version,arch,machine,env,argv}=context;
 const native={x64:'amd64',arm64:'arm64'}[arch],host={x86_64:'amd64',amd64:'amd64',aarch64:'arm64',arm64:'arm64'}[typeof machine==='string'?machine.toLowerCase():''];
 return platform==='win32'&&version==='v26.8.2'&&env.GITHUB_ACTIONS==='true'&&env.RUNNER_ENVIRONMENT==='github-hosted'&&env.RUNNER_OS==='Windows'&&typeof env.GITHUB_SHA==='string'&&/^[a-f0-9]{40}$/.test(env.GITHUB_SHA)&&env.ACCESSWEAVER_EXPECT_GOOS==='windows'&&Boolean(native)&&native===host&&native===env.ACCESSWEAVER_EXPECT_GOARCH&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(env,k))&&Array.isArray(argv)&&argv.length===6&&argv[2]==='--configured-ip-authority'&&argv[3]===env.GITHUB_SHA&&argv[4]===POLICY_SHA256&&argv[5]===PREREQUISITE_SHA256;
}
module.exports={decodeConfiguredIPBytes,hostedGuard};
if(require.main===module){
 let done=false,total=0;const chunks=[];
 const finish=(report,handled=false)=>{if(done)return;done=true;process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=protocolExitCode(report,handled);};
 const refuse=code=>({schemaVersion:1,outcome:'refused',code,evidence:null,identityBinding:null});
 if(!hostedGuard({platform:process.platform,version:process.version,arch:process.arch,machine:os.machine(),env:process.env,argv:process.argv})){finish(refuse('environment'));process.stdin.destroy();}
 else{
  const binding=declaredIPBinding(process.env.GITHUB_SHA);
  process.stdin.on('data',chunk=>{total+=chunk.length;if(total>LIMITS.bytes||chunks.length>=8192){finish(refuse('input-bound'));process.stdin.destroy();return;}chunks.push(chunk);});
  process.stdin.on('end',()=>finish(decodeConfiguredIPBytes(Buffer.concat(chunks,total),binding),true));
  process.stdin.on('error',()=>finish(refuse('input-read')));
  process.stdin.on('close',()=>{if(!done)finish(refuse('input-incomplete'));});
 }
}
