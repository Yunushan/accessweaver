'use strict';
// Native hosted CLI only; pure decoding helpers below perform no I/O.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {convertNdisFrames,FrameConversionError,LIMITS}=require('./ndis-frame-converter.cjs');
function need(ok,code){if(!ok)throw new FrameConversionError(code);}
function decimal(value,signed){
 need(typeof value==='string'&&/^-?(0|[1-9][0-9]{0,19})$/.test(value),'private-encoding');
 const n=BigInt(value);need(n.toString()===value&&(signed?n>=-(1n<<63n)&&n<(1n<<63n):n>=0n&&n<(1n<<64n)),'private-encoding');return n;
}
function decodePrivateFrames(document){
 need(document!==null&&typeof document==='object'&&!Array.isArray(document)&&Object.keys(document).length===2&&document.schemaVersion===1&&Array.isArray(document.records)&&document.records.length>0&&document.records.length<=LIMITS.frames,'private-document');
 return document.records.map(record=>{
  need(record!==null&&typeof record==='object'&&!Array.isArray(record),'private-record');
  const keys=Object.keys(record),base=['provider','id','version','keywords','fragmentSize','fragment'],modern=keys.length===8,expected=modern?[...base,'gftFlowEntryId','gftOffloadInformation']:base;
  need((keys.length===6||modern)&&keys.every(k=>expected.includes(k))&&expected.every(k=>Object.hasOwn(record,k)),'private-record');
  const text=record.fragment;need(typeof text==='string'&&text.length>=20&&text.length<=87380&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text),'private-encoding');
  const fragment=Buffer.from(text,'base64');need(fragment.toString('base64')===text,'private-encoding');
  const out={provider:record.provider,id:record.id,version:record.version,keywords:decimal(record.keywords,true),fragmentSize:record.fragmentSize,fragment};
  if(modern){out.gftFlowEntryId=decimal(record.gftFlowEntryId,false);out.gftOffloadInformation=decimal(record.gftOffloadInformation,false);}return out;
 });
}
function privateCapturePaths(root,local){
 need(typeof root==='string'&&typeof local==='string'&&path.win32.isAbsolute(root)&&path.win32.isAbsolute(local)&&path.win32.resolve(root)===root&&path.win32.dirname(root).toLowerCase()===path.win32.resolve(local).toLowerCase()&&/^AccessWeaver-NetEventControl-[a-f0-9]{32}$/.test(path.win32.basename(root)),'private-path');
 return {root,input:path.win32.join(root,'frames.json'),output:path.win32.join(root,'capture.pcapng')};
}
function ordinaryAncestors(file){let current=file;while(current){need(!fs.lstatSync(current).isSymbolicLink(),'private-path');const parent=path.dirname(current);if(parent===current)break;current=parent;}}
const CODES=new Set(['environment','private-path','private-file','private-document','private-record','private-encoding','record-shape','fragment-identity','fragment-keywords','fragment-boundaries','fragment-media','fragment-direction','fragment-offload-type','fragment-offload','fragment-length','ethernet-vlan','ethernet-type','ipv4-header','ipv4-length','ipv4-header-length','ipv4-zero-length','ipv4-short-length','ipv4-truncated','ipv6-header','ipv6-length','ip-fragment','frame-length','ipv6-extension','tcp-header','udp-length','transport-type','record-bound','capture-bound']);
function runPrivateConversion(root){
 let read=false,input=null,output=null;
 try{
  const files=privateCapturePaths(root,process.env.LOCALAPPDATA);ordinaryAncestors(files.input);need(fs.lstatSync(files.root).isDirectory(),'private-path');
  input=fs.openSync(files.input,'r');const before=fs.fstatSync(input);need(before.isFile()&&before.nlink===1&&before.size>0&&before.size<=LIMITS.bytes,'private-file');
  const bytes=Buffer.alloc(before.size);let offset=0;while(offset<bytes.length){const n=fs.readSync(input,bytes,offset,bytes.length-offset,null);need(n>0,'private-file');offset+=n;}read=true;
  const extra=Buffer.alloc(1),after=fs.fstatSync(input);need(fs.readSync(input,extra,0,1,null)===0&&after.size===before.size&&after.mtimeMs===before.mtimeMs,'private-file');fs.closeSync(input);input=null;
  let document;try{document=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new FrameConversionError('private-document');}
  const converted=convertNdisFrames(decodePrivateFrames(document));ordinaryAncestors(files.root);
  output=fs.openSync(files.output,'wx',0o600);let written=0;while(written<converted.capture.length){const n=fs.writeSync(output,converted.capture,written,converted.capture.length-written,null);need(n>0,'private-file');written+=n;}fs.fsyncSync(output);fs.closeSync(output);output=null;
  ordinaryAncestors(files.output);const stat=fs.statSync(files.output);need(stat.isFile()&&stat.nlink===1&&stat.size===converted.summary.captureBytes,'private-file');
  return {schemaVersion:1,outcome:'converted',code:'none',nativeFrameDataRead:true,summary:converted.summary};
 }catch(e){return {schemaVersion:1,outcome:'refused',code:e instanceof FrameConversionError&&CODES.has(e.code)?e.code:'conversion-unavailable',nativeFrameDataRead:read,summary:null};}
 finally{for(const fd of [input,output])if(fd!==null)try{fs.closeSync(fd);}catch{}}
}
module.exports={decodePrivateFrames,privateCapturePaths};
if(require.main===module){
 const arch={x64:'amd64',arm64:'arm64'}[process.arch],host={x86_64:'amd64',amd64:'amd64',arm64:'arm64',aarch64:'arm64'}[os.machine().toLowerCase()];
 const guarded=process.platform==='win32'&&process.version==='v26.8.2'&&process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||'')&&process.env.ACCESSWEAVER_EXPECT_GOOS==='windows'&&arch===host&&arch===process.env.ACCESSWEAVER_EXPECT_GOARCH&&process.argv.length===3&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(process.env,k));
 const report=guarded?runPrivateConversion(process.argv[2]):{schemaVersion:1,outcome:'refused',code:'environment',nativeFrameDataRead:false,summary:null};process.stdout.write(JSON.stringify(report)+'\n');
}
