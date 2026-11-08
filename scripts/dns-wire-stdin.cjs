'use strict';
// Guarded hosted-only binary stdin adapter. It never opens a capture path.
const os=require('node:os');
const {inspectDoHWire,WireError,LIMITS}=require('./dns-wire-evidence.cjs');
function decodeBytes(bytes){
 try{return {schemaVersion:1,outcome:'decoded',code:'none',evidence:inspectDoHWire(bytes)};}
 catch(e){return {schemaVersion:1,outcome:'refused',code:e instanceof WireError&&/^[a-z0-9-]{1,48}$/.test(e.code)?e.code:'decoder-failed',evidence:null};}
}
module.exports={decodeBytes};
if(require.main===module){
 let done=false,total=0;const chunks=[];
 const finish=report=>{if(done)return;done=true;process.stdout.write(JSON.stringify(report)+'\n');if(report.outcome!=='decoded')process.exitCode=1;};
 const arch={x64:'amd64',arm64:'arm64'}[process.arch],machine=os.machine().toLowerCase();
 const host=machine==='x86_64'||machine==='amd64'?'amd64':machine==='arm64'||machine==='aarch64'?'arm64':'unknown';
 const guarded=process.platform==='win32'&&process.version==='v26.8.2'&&process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||'')&&process.env.ACCESSWEAVER_EXPECT_GOOS==='windows'&&arch===host&&arch===process.env.ACCESSWEAVER_EXPECT_GOARCH&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(process.env,k));
 if(!guarded){finish({schemaVersion:1,outcome:'refused',code:'environment',evidence:null});process.stdin.destroy();}
 else {
  process.stdin.on('data',chunk=>{
   total+=chunk.length;
   if(total>LIMITS.bytes||chunks.length>=8192){finish({schemaVersion:1,outcome:'refused',code:'input-bound',evidence:null});process.stdin.destroy();return;}
   chunks.push(chunk);
  });
  process.stdin.on('end',()=>finish(decodeBytes(Buffer.concat(chunks,total))));
  process.stdin.on('error',()=>finish({schemaVersion:1,outcome:'refused',code:'input-read',evidence:null}));
  process.stdin.on('close',()=>{if(!done)finish({schemaVersion:1,outcome:'refused',code:'input-incomplete',evidence:null});});
 }
}
