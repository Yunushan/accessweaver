"use strict";
// Pure phase/count join plus a guarded private-file entry. No frame is removed.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {convertNdisFrames}=require('./ndis-frame-converter.cjs');
const {decodePrivateFrames,privateCapturePaths}=require('./ndis-private-convert.cjs');
const NUMBERS=['records','frames','before','at','after','tcpBefore','tcpAt','tcpAfter','udpBefore','udpAt','udpAfter','sentBefore','sentAt','sentAfter','receivedBefore','receivedAt','receivedAfter'];
class PhaseError extends Error{constructor(code){super(code);this.code=code;}}
function need(ok,code){if(!ok)throw new PhaseError(code);}
function closed(value,keys){return value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));}
function joinFramePhases(records,document,sourceDigest){
 need(Array.isArray(records)&&records.length>0&&records.length<=4096,'phase-count');
 need(closed(document,['schemaVersion','records','sourceFramesSHA256','phases'])&&document.schemaVersion===1&&Number.isSafeInteger(document.records)&&document.records>=records.length&&document.records<=4096,'phase-document');
 need(typeof document.sourceFramesSHA256==='string'&&/^[a-f0-9]{64}$/.test(document.sourceFramesSHA256)&&document.sourceFramesSHA256===sourceDigest,'phase-source');
 need(Array.isArray(document.phases)&&document.phases.length===records.length&&document.phases.every(p=>Number.isSafeInteger(p)&&p>=0&&p<=2),'phase-count');
 const result={schemaVersion:1,outcome:'complete',code:'none',nativeFrameDataRead:true,sourceBound:true,productionQualificationComplete:false};for(const k of NUMBERS)result[k]=0;result.records=document.records;
 for(let i=0;i<records.length;i++){
  const {summary:q}=convertNdisFrames([records[i]]),bucket=['Before','At','After'][document.phases[i]];
  need(q.frames===1&&q.tcp+q.udp===1&&q.sent+q.received===1,'conversion');
  result.frames++;result[bucket.toLowerCase()]++;result[(q.tcp?'tcp':'udp')+bucket]++;result[(q.sent?'sent':'received')+bucket]++;
 }
 return Object.freeze(result);
}
function ordinary(file){let p=file;while(p){need(!fs.lstatSync(p).isSymbolicLink(),'private-path');const next=path.dirname(p);if(next===p)break;p=next;}}
function boundedRead(file,limit){ordinary(file);let fd=null;try{fd=fs.openSync(file,'r');const before=fs.fstatSync(fd);need(before.isFile()&&before.nlink===1&&before.size>0&&before.size<=limit,'private-file');const raw=Buffer.alloc(before.size);let at=0;while(at<raw.length){const n=fs.readSync(fd,raw,at,raw.length-at,null);need(n>0,'private-file');at+=n;}const after=fs.fstatSync(fd);need(fs.readSync(fd,Buffer.alloc(1),0,1,null)===0&&before.size===after.size&&before.mtimeMs===after.mtimeMs,'private-file');return raw;}finally{if(fd!==null)fs.closeSync(fd);}}
function privatePhases(root){
 let read=false;try{
  const files=privateCapturePaths(root,process.env.LOCALAPPDATA);ordinary(root);need(fs.statSync(root).isDirectory(),'private-path');
  const raw=boundedRead(files.input,16777216),map=boundedRead(path.win32.join(root,'frame-phases.json'),65536);read=true;let document,frames;
  try{const decoder=new TextDecoder('utf-8',{fatal:true});document=JSON.parse(decoder.decode(map));frames=JSON.parse(decoder.decode(raw));}catch{throw new PhaseError('private-document');}
  return joinFramePhases(decodePrivateFrames(frames),document,crypto.createHash('sha256').update(raw).digest('hex'));
 }catch(e){const allowed=new Set(['private-path','private-file','private-document','phase-document','phase-source','phase-count','conversion']);const r={schemaVersion:1,outcome:'refused',code:e instanceof PhaseError&&allowed.has(e.code)?e.code:'conversion',nativeFrameDataRead:read,sourceBound:false,productionQualificationComplete:false};for(const k of NUMBERS)r[k]=0;return r;}
}
module.exports={joinFramePhases,NUMBERS,PhaseError};
if(require.main===module){
 const arch={x64:'amd64',arm64:'arm64'}[process.arch],host={x86_64:'amd64',amd64:'amd64',arm64:'arm64',aarch64:'arm64'}[os.machine().toLowerCase()];
 const guarded=process.platform==='win32'&&process.version==='v26.8.2'&&process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&process.env.RUNNER_OS==='Windows'&&/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||'')&&arch===host&&process.env.ACCESSWEAVER_EXPECT_GOOS==='windows'&&arch===process.env.ACCESSWEAVER_EXPECT_GOARCH&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(process.env,k))&&process.argv.length===3;
 if(!guarded){const r={schemaVersion:1,outcome:'refused',code:'environment',nativeFrameDataRead:false,sourceBound:false,productionQualificationComplete:false};for(const k of NUMBERS)r[k]=0;process.stdout.write(JSON.stringify(r)+'\n');}
 else process.stdout.write(JSON.stringify(privatePhases(process.argv[2]))+'\n');
}
