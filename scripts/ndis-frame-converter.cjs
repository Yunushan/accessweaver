'use strict';
// Pure private-frame conversion. No files, network, native APIs or CLI paths.
// Catalog, loss, ownership and recovery qualification belong to the hosted driver.
const LIMITS=Object.freeze({bytes:16*1024*1024,frames:4096,frameBytes:65535});
const PROVIDER='2ed6006e-4729-4609-b423-3ee7bcd678ef';
class FrameConversionError extends Error {constructor(code){super(code);this.name='FrameConversionError';this.code=code;}}
function need(ok,code){if(!ok)throw new FrameConversionError(code);}
function wholeIP(frame){
 let at=14,type=frame.readUInt16BE(12),tags=0;
 while(type===0x8100||type===0x88a8){need(++tags<=2&&at+4<=frame.length,'ethernet-vlan');type=frame.readUInt16BE(at+2);at+=4;}
 const networkOffset=at;let end,protocol,family;
 if(type===0x0800){
  family=4;need(at+20<=frame.length&&(frame[at]>>>4)===4,'ipv4-header');
  const header=(frame[at]&15)*4,size=frame.readUInt16BE(at+2);
  need(header>=20,'ipv4-header-length');need(size!==0,'ipv4-zero-length');need(size>=header,'ipv4-short-length');need(at+size<=frame.length,'ipv4-truncated');
  need((frame.readUInt16BE(at+6)&0xbfff)===0,'ip-fragment');
  end=at+size;protocol=frame[at+9];at+=header;
 }else if(type===0x86dd){
  family=6;need(at+40<=frame.length&&(frame[at]>>>4)===6,'ipv6-header');
  const size=frame.readUInt16BE(at+4);need(size>0&&at+40+size<=frame.length,'ipv6-length');
  end=at+40+size;protocol=frame[at+6];at+=40;let extensions=0;
  while([0,43,60].includes(protocol)){
   need(++extensions<=8&&at+8<=end,'ipv6-extension');const size=(frame[at+1]+1)*8;
   need(at+size<=end,'ipv6-extension');protocol=frame[at];at+=size;
  }
  need(protocol!==44,'ip-fragment');
 }else need(false,'ethernet-type');
 // Only complete IP bytes plus optional zero-filled minimum Ethernet padding.
 need(frame.length===end||(end<60&&frame.length===60&&frame.subarray(end).every(x=>x===0)),'frame-length');
 if(protocol===6){need(at+20<=end,'tcp-header');const header=(frame[at+12]>>>4)*4;need(header>=20&&at+header<=end,'tcp-header');}
 else if(protocol===17){need(at+8<=end&&frame.readUInt16BE(at+4)===end-at,'udp-length');}
 else need(false,'transport-type');
 return {family,protocol,networkOffset,transportOffset:at,transportEnd:end};
}
function readRecord(record){
 need(record!==null&&typeof record==='object'&&(Object.getPrototypeOf(record)===Object.prototype||Object.getPrototypeOf(record)===null),'record-shape');
 const own=Object.getOwnPropertyDescriptors(record),keys=Reflect.ownKeys(own),base=['provider','id','version','keywords','fragmentSize','fragment'];
 const modern=keys.length===8;need(keys.length===6||modern,'record-shape');
 const expected=modern?[...base,'gftFlowEntryId','gftOffloadInformation']:base;
 need(keys.every(k=>typeof k==='string'&&expected.includes(k)&&Object.hasOwn(own[k],'value'))&&expected.every(k=>Object.hasOwn(own,k)),'record-shape');
 const r=Object.fromEntries(keys.map(k=>[k,own[k].value]));
 need(r.provider===PROVIDER&&r.id===1001&&r.version===0,'fragment-identity');
 need(typeof r.keywords==='bigint'&&r.keywords>=-(1n<<63n)&&r.keywords<(1n<<63n),'fragment-keywords');
 const bits=BigInt.asUintN(64,r.keywords);need((bits&0xc0000000n)===0xc0000000n,'fragment-boundaries');
 need((bits&0x10200n)===0n,'fragment-media');const direction=bits&0x300000000n;
 need(direction===0x100000000n||direction===0x200000000n,'fragment-direction');
 if(modern){for(const key of ['gftFlowEntryId','gftOffloadInformation'])need(typeof r[key]==='bigint'&&r[key]>=0n&&r[key]<(1n<<64n),'fragment-offload-type');need(r.gftFlowEntryId===0n&&r.gftOffloadInformation===0n,'fragment-offload');}
 need(Number.isSafeInteger(r.fragmentSize)&&r.fragmentSize>=14&&r.fragmentSize<=LIMITS.frameBytes&&Buffer.isBuffer(r.fragment)&&r.fragment.length===r.fragmentSize,'fragment-length');
 const frame=Buffer.from(r.fragment),ip=wholeIP(frame);return {frame,...ip,sent:direction===0x100000000n};
}
function convertNdisFrames(records){
 need(Array.isArray(records)&&records.length>0&&records.length<=LIMITS.frames,'record-bound');
 const frames=[],flowStates=new Map();let bytes=48;
 const closure={schemaVersion:1,flows:0,sentFin:0,receivedFin:0,sentReset:0,receivedReset:0,beforeFin:0,afterSentFin:0,afterReceivedFin:0,afterBothFin:0,resetFlows:0,resetFlowsWithPayloadBoth:0,productionQualificationComplete:false};
 const summary={schemaVersion:1,frames:0,ipv4:0,ipv6:0,tcp:0,udp:0,sent:0,received:0,captureBytes:0,productionQualificationComplete:false,tcpClosure:closure};
 for(const record of records){const r=readRecord(record);bytes+=32+Math.ceil(r.frame.length/4)*4;need(bytes<=LIMITS.bytes,'capture-bound');frames.push(r.frame);summary.frames++;summary[r.family===4?'ipv4':'ipv6']++;summary[r.protocol===6?'tcp':'udp']++;summary[r.sent?'sent':'received']++;
  if(r.protocol===6){
   const n=r.networkOffset,t=r.transportOffset,src=r.frame.subarray(n+(r.family===4?12:8),n+(r.family===4?16:24)).toString('hex'),dst=r.frame.subarray(n+(r.family===4?16:24),n+(r.family===4?20:40)).toString('hex'),sp=r.frame.readUInt16BE(t),dp=r.frame.readUInt16BE(t+2);
   const key=r.family+':'+(r.sent?src+':'+sp+'>'+dst+':'+dp:dst+':'+dp+'>'+src+':'+sp);let state=flowStates.get(key);if(!state){state={sentFin:false,receivedFin:false,sentData:false,receivedData:false,reset:false};flowStates.set(key,state);}
   const flags=r.frame[t+13],payload=r.transportEnd-t-(r.frame[t+12]>>>4)*4;
   if(flags&4){closure[r.sent?'sentReset':'receivedReset']++;closure[state.sentFin?(state.receivedFin?'afterBothFin':'afterSentFin'):(state.receivedFin?'afterReceivedFin':'beforeFin')]++;state.reset=true;}
   if(flags&1){closure[r.sent?'sentFin':'receivedFin']++;state[r.sent?'sentFin':'receivedFin']=true;}
   if(payload>0)state[r.sent?'sentData':'receivedData']=true;
  }
 }
 closure.flows=flowStates.size;for(const state of flowStates.values())if(state.reset){closure.resetFlows++;if(state.sentData&&state.receivedData)closure.resetFlowsWithPayloadBoth++;}Object.freeze(closure);
 const capture=Buffer.alloc(bytes);capture.writeUInt32LE(0x0a0d0d0a,0);capture.writeUInt32LE(28,4);capture.writeUInt32LE(0x1a2b3c4d,8);capture.writeUInt16LE(1,12);capture.writeBigInt64LE(-1n,16);capture.writeUInt32LE(28,24);
 capture.writeUInt32LE(1,28);capture.writeUInt32LE(20,32);capture.writeUInt16LE(1,36);capture.writeUInt32LE(65535,40);capture.writeUInt32LE(20,44);
 let at=48;for(const frame of frames){const size=32+Math.ceil(frame.length/4)*4;capture.writeUInt32LE(6,at);capture.writeUInt32LE(size,at+4);capture.writeUInt32LE(frame.length,at+20);capture.writeUInt32LE(frame.length,at+24);frame.copy(capture,at+28);capture.writeUInt32LE(size,at+size-4);at+=size;}
 summary.captureBytes=bytes;return {capture,summary:Object.freeze(summary)};
}
module.exports={convertNdisFrames,FrameConversionError,LIMITS};
