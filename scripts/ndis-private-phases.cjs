"use strict";
// Pure phase/count join plus a guarded private-file entry. No frame is removed.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {convertNdisFrames}=require('./ndis-frame-converter.cjs');
const {decodePrivateFrames,privateCapturePaths}=require('./ndis-private-convert.cjs');
const NUMBERS=['records','frames','before','at','after','tcpBefore','tcpAt','tcpAfter','udpBefore','udpAt','udpAfter','sentBefore','sentAt','sentAfter','receivedBefore','receivedAt','receivedAfter','udp53Before','udp53At','udp53After','udp443Before','udp443At','udp443After','udpOtherBefore','udpOtherAt','udpOtherAfter'];
const DNS_KEYS=['queries','responses','productProbe','positiveProbe','negativeProbe','providerBootstrap','otherName','a','aaaa','otherType','unclassified','googleV4','quad9V4','googleV6','quad9V6'];
function dnsCounters(){return Object.fromEntries(DNS_KEYS.map(k=>[k,0]));}
const UDP_PROVIDERS=Object.freeze({'08080808':'googleV4','09090909':'quad9V4','20014860486000000000000000008888':'googleV6','262000fe0000000000000000000000fe':'quad9V6'});
function udpTuple(frame){
  need(Buffer.isBuffer(frame)&&frame.length>=42,'dns');let n=14,ether=frame.readUInt16BE(12),vlan=0;
  while(ether===0x8100||ether===0x88a8){need(++vlan<=2&&n+4<=frame.length,'dns');ether=frame.readUInt16BE(n+2);n+=4;}
  let t,source,destination;
  if(ether===0x0800){need(n+20<=frame.length&&(frame[n]>>>4)===4&&frame[n+9]===17,'dns');t=n+(frame[n]&15)*4;source=frame.subarray(n+12,n+16).toString('hex');destination=frame.subarray(n+16,n+20).toString('hex');}
  else if(ether===0x86dd){need(n+40<=frame.length&&(frame[n]>>>4)===6,'dns');t=n+40;let next=frame[n+6],extensions=0;while([0,43,60,51].includes(next)){need(++extensions<=8&&t+2<=frame.length,'dns');const size=next===51?(frame[t+1]+2)*4:(frame[t+1]+1)*8;next=frame[t];t+=size;need(t<=frame.length,'dns');}need(next===17,'dns');source=frame.subarray(n+8,n+24).toString('hex');destination=frame.subarray(n+24,n+40).toString('hex');}
  else throw new PhaseError('dns');
  need(t+8<=frame.length,'dns');const sp=frame.readUInt16BE(t),dp=frame.readUInt16BE(t+2),size=frame.readUInt16BE(t+4);
  need(size>=8&&t+size<=frame.length,'dns');return {source,destination,sp,dp,data:frame.subarray(t+8,t+size)};
}
function classifyUDPPort(frame){
 try{const {source,destination,sp,dp}=udpTuple(frame),from=Object.hasOwn(UDP_PROVIDERS,source),to=Object.hasOwn(UDP_PROVIDERS,destination);need(from!==to,'dns');const port=from?sp:dp;return port===53?'53':port===443?'443':'Other';}catch{return 'Other';}
}
function classifyUDP(frame){
 const bad=dnsCounters();bad.unclassified=1;
 try{
  const {source,destination,sp,dp,data}=udpTuple(frame),providers=UDP_PROVIDERS;
  const from=sp===53&&Object.hasOwn(providers,source),to=dp===53&&Object.hasOwn(providers,destination);need(Boolean(from)!==Boolean(to),'dns');
  need(data.length>=12&&data.readUInt16BE(4)===1,'dns');let at=12,end=null,steps=0,expanded=0;const labels=[],visited=new Set();
  while(true){need(++steps<=128&&at<data.length&&!visited.has(at),'dns');visited.add(at);const count=data[at];
   if((count&0xc0)===0xc0){need(at+1<data.length,'dns');if(end===null)end=at+2;at=((count&63)<<8)|data[at+1];continue;}
   need((count&0xc0)===0&&count<=63&&at+1+count<=data.length,'dns');at++;if(count===0){if(end===null)end=at;break;}
   expanded+=count+1;need(expanded<=254,'dns');const label=data.subarray(at,at+count);need(label.every(b=>b>=33&&b<=126&&b!==46),'dns');labels.push(label.toString('ascii'));at+=count;
  }
  need(end+4<=data.length&&data.readUInt16BE(end+2)===1,'dns');const name=labels.join('.').toLowerCase(),type=data.readUInt16BE(end),r=dnsCounters();
  r[(data.readUInt16BE(2)&0x8000)?'responses':'queries']=1;
  r[name==='example.com'?'productProbe':name==='example.net'?'positiveProbe':name==='example.org'?'negativeProbe':name==='dns.google'||name==='dns.quad9.net'?'providerBootstrap':'otherName']=1;
  r[type===1?'a':type===28?'aaaa':'otherType']=1;r[providers[from?source:destination]]=1;return r;
 }catch{return bad;}
}
class PhaseError extends Error{constructor(code){super(code);this.code=code;}}
function need(ok,code){if(!ok)throw new PhaseError(code);}
function closed(value,keys){return value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));}
function joinFramePhases(records,document,sourceDigest){
 need(Array.isArray(records)&&records.length>0&&records.length<=4096,'phase-count');
 need(closed(document,['schemaVersion','records','sourceFramesSHA256','phases'])&&document.schemaVersion===1&&Number.isSafeInteger(document.records)&&document.records>=records.length&&document.records<=4096,'phase-document');
 need(typeof document.sourceFramesSHA256==='string'&&/^[a-f0-9]{64}$/.test(document.sourceFramesSHA256)&&document.sourceFramesSHA256===sourceDigest,'phase-source');
 need(Array.isArray(document.phases)&&document.phases.length===records.length&&document.phases.every(p=>Number.isSafeInteger(p)&&p>=0&&p<=2),'phase-count');
 const result={schemaVersion:1,outcome:'complete',code:'none',nativeFrameDataRead:true,sourceBound:true,productionQualificationComplete:false};for(const k of NUMBERS)result[k]=0;for(const bucket of ['Before','At','After'])result['dns'+bucket]=dnsCounters();result.records=document.records;
 for(let i=0;i<records.length;i++){
  const {summary:q,capture}=convertNdisFrames([records[i]]),bucket=['Before','At','After'][document.phases[i]];
  need(q.frames===1&&q.tcp+q.udp===1&&q.sent+q.received===1,'conversion');
  result.frames++;result[bucket.toLowerCase()]++;result[(q.tcp?'tcp':'udp')+bucket]++;result[(q.sent?'sent':'received')+bucket]++;if(q.udp){const frame=capture.subarray(76,76+records[i].fragmentSize),counters=classifyUDP(frame);result['udp'+classifyUDPPort(frame)+bucket]++;for(const key of DNS_KEYS)result['dns'+bucket][key]+=counters[key];}
 }
 for(const bucket of ['Before','At','After'])Object.freeze(result['dns'+bucket]);return Object.freeze(result);
}
function ordinary(file){let p=file;while(p){need(!fs.lstatSync(p).isSymbolicLink(),'private-path');const next=path.dirname(p);if(next===p)break;p=next;}}
function boundedRead(file,limit){ordinary(file);let fd=null;try{fd=fs.openSync(file,'r');const before=fs.fstatSync(fd);need(before.isFile()&&before.nlink===1&&before.size>0&&before.size<=limit,'private-file');const raw=Buffer.alloc(before.size);let at=0;while(at<raw.length){const n=fs.readSync(fd,raw,at,raw.length-at,null);need(n>0,'private-file');at+=n;}const after=fs.fstatSync(fd);need(fs.readSync(fd,Buffer.alloc(1),0,1,null)===0&&before.size===after.size&&before.mtimeMs===after.mtimeMs,'private-file');return raw;}finally{if(fd!==null)fs.closeSync(fd);}}
function privatePhases(root){
 let read=false;try{
  const files=privateCapturePaths(root,process.env.LOCALAPPDATA);ordinary(root);need(fs.statSync(root).isDirectory(),'private-path');
  const raw=boundedRead(files.input,16777216),map=boundedRead(path.win32.join(root,'frame-phases.json'),65536);read=true;let document,frames;
  try{const decoder=new TextDecoder('utf-8',{fatal:true});document=JSON.parse(decoder.decode(map));frames=JSON.parse(decoder.decode(raw));}catch{throw new PhaseError('private-document');}
  return joinFramePhases(decodePrivateFrames(frames),document,crypto.createHash('sha256').update(raw).digest('hex'));
 }catch(e){const allowed=new Set(['private-path','private-file','private-document','phase-document','phase-source','phase-count','conversion']);const r={schemaVersion:1,outcome:'refused',code:e instanceof PhaseError&&allowed.has(e.code)?e.code:'conversion',nativeFrameDataRead:read,sourceBound:false,productionQualificationComplete:false};for(const k of NUMBERS)r[k]=0;for(const bucket of ['Before','At','After'])r['dns'+bucket]=dnsCounters();return r;}
}
module.exports={joinFramePhases,NUMBERS,DNS_KEYS,PhaseError};
if(require.main===module){
 const arch={x64:'amd64',arm64:'arm64'}[process.arch],host={x86_64:'amd64',amd64:'amd64',arm64:'arm64',aarch64:'arm64'}[os.machine().toLowerCase()];
 const guarded=process.platform==='win32'&&process.version==='v26.8.2'&&process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&process.env.RUNNER_OS==='Windows'&&/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||'')&&arch===host&&process.env.ACCESSWEAVER_EXPECT_GOOS==='windows'&&arch===process.env.ACCESSWEAVER_EXPECT_GOARCH&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(process.env,k))&&process.argv.length===3;
 if(!guarded){const r={schemaVersion:1,outcome:'refused',code:'environment',nativeFrameDataRead:false,sourceBound:false,productionQualificationComplete:false};for(const k of NUMBERS)r[k]=0;for(const bucket of ['Before','At','After'])r['dns'+bucket]=dnsCounters();process.stdout.write(JSON.stringify(r)+'\n');}
 else process.stdout.write(JSON.stringify(privatePhases(process.argv[2]))+'\n');
}
