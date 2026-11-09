'use strict';
// Pure, bounded decoder for a future fixed-provider hosted DoH wire check.
// No packet bytes, addresses, names, timestamps or arbitrary errors leave this API.
const {assertIPBinding}=require('./dns-wire-ip-policy.cjs');
const LIMITS=Object.freeze({bytes:16*1024*1024,blocks:65536,interfaces:32,packets:16384,flows:32,stream:512*1024,segments:8192});
const PROVIDERS=Object.freeze([
 {id:'google-v4',hex:'08080808',sni:'dns.google'},
 {id:'quad9-v4',hex:'09090909',sni:'dns.quad9.net'},
 {id:'google-v6',hex:'20014860486000000000000000008888',sni:'dns.google'},
 {id:'quad9-v6',hex:'262000fe0000000000000000000000fe',sni:'dns.quad9.net'}
]);
class WireError extends Error { constructor(code){super(code);this.name='WireError';this.code=code;} }
function fail(code){throw new WireError(code);}
function need(ok,code){if(!ok)fail(code);}
function validateDropOptions(input,p,end,u16,dropCodes){
 while(p<end){
  need(p+4<=end,'capture-options');const code=u16(p),n=u16(p+2);p+=4;
  need(p+Math.ceil(n/4)*4<=end,'capture-options');
  if(code===0){need(n===0&&input.subarray(p,end).every(v=>v===0),'capture-options');break;}
  if(dropCodes.includes(code))need(n===8&&input.subarray(p,p+8).every(v=>v===0),'capture-drops');
  p+=Math.ceil(n/4)*4;
 }
}
function parseCapture(input){
 need(Buffer.isBuffer(input)&&input.length>=28&&input.length<=LIMITS.bytes,'capture-bound');
 const interfaces=[],packets=[];let offset=0,blocks=0,order=null,sections=0;
 let u16,u32;
 while(offset<input.length){
  need(++blocks<=LIMITS.blocks&&offset+12<=input.length,'block-bound');
  const section=input.readUInt32LE(offset)===0x0a0d0d0a;
  if(section){
   need(++sections===1&&offset+28<=input.length,'section-shape');
   const magic=input.readUInt32LE(offset+8);
   need(magic===0x1a2b3c4d||magic===0x4d3c2b1a,'section-magic');
   order=magic===0x1a2b3c4d?'LE':'BE';
   u16=p=>input['readUInt16'+order](p);u32=p=>input['readUInt32'+order](p);
  }
  need(order!==null,'section-required');
  const type=u32(offset),size=u32(offset+4),end=offset+size;
  need(size>=12&&size%4===0&&end<=input.length&&u32(end-4)===size,'block-shape');
  if(section){
   need(size>=28&&u16(offset+12)===1&&u16(offset+14)===0,'section-version');
   const declared=input['readBigInt64'+order](offset+16);need(declared===-1n||declared===BigInt(input.length-size),'section-length');
  }else if(type===1){
   need(size>=20&&interfaces.length<LIMITS.interfaces,'interface-bound');
   need(u16(offset+8)===1&&u16(offset+10)===0,'interface-link');
   const snap=u32(offset+12);need(snap===0||(snap>=65535&&snap<=LIMITS.bytes),'interface-snaplen');
   interfaces.push(snap);
  }else if(type===6){
   need(size>=32&&packets.length<LIMITS.packets,'packet-bound');
   const id=u32(offset+8),captured=u32(offset+20),original=u32(offset+24);
   need(id<interfaces.length&&captured===original&&captured>=14&&captured<=65575,'packet-shape');
   need(28+Math.ceil(captured/4)*4<=size-4,'packet-truncated');
   need(interfaces[id]===0||captured<=interfaces[id],'packet-snaplen');
   validateDropOptions(input,offset+28+Math.ceil(captured/4)*4,end-4,u16,[4]);
   packets.push(input.subarray(offset+28,offset+28+captured));
  }else if(type===2||type===3){fail('packet-kind');}
  else if(type===5){
   // Drop statistics cannot be silently discarded when claiming observation.
   need(size>=24&&u32(offset+8)<interfaces.length,'statistics-shape');
   validateDropOptions(input,offset+20,end-4,u16,[5,7]);
  }
  // Other blocks/options are opaque metadata; never interpreted or exported.
  offset=end;
 }
 need(sections===1&&interfaces.length>0&&packets.length>0,'capture-empty');
 return packets;
}
function decodeFrame(frame){
 let at=14,type=frame.readUInt16BE(12),tags=0;
 while(type===0x8100||type===0x88a8){need(++tags<=2&&at+4<=frame.length,'ethernet-shape');type=frame.readUInt16BE(at+2);at+=4;}
 let source,destination,protocol,end;
 if(type===0x0800){
  need(at+20<=frame.length&&(frame[at]>>>4)===4,'ipv4-shape');
  const header=(frame[at]&15)*4,size=frame.readUInt16BE(at+2);
  need(header>=20&&size>=header&&at+size<=frame.length,'ipv4-bound');
  need((frame.readUInt16BE(at+6)&0x3fff)===0,'ip-fragment');
  source=frame.subarray(at+12,at+16).toString('hex');destination=frame.subarray(at+16,at+20).toString('hex');
  protocol=frame[at+9];end=at+size;at+=header;
 }else if(type===0x86dd){
  need(at+40<=frame.length&&(frame[at]>>>4)===6,'ipv6-shape');
  const size=frame.readUInt16BE(at+4);need(size>0&&at+40+size<=frame.length,'ipv6-bound');
  source=frame.subarray(at+8,at+24).toString('hex');destination=frame.subarray(at+24,at+40).toString('hex');
  protocol=frame[at+6];end=at+40+size;at+=40;let extensions=0;
  while([0,43,60].includes(protocol)){
   need(++extensions<=8&&at+8<=end,'ipv6-extension');
   const n=(frame[at+1]+1)*8;need(at+n<=end,'ipv6-extension');protocol=frame[at];at+=n;
  }
  need(protocol!==44,'ip-fragment');
 }else fail('ethernet-protocol');
 const from=PROVIDERS.find(p=>p.hex===source),to=PROVIDERS.find(p=>p.hex===destination);
 need(Boolean(from)!==Boolean(to),'provider-scope');
 need([6,17].includes(protocol)&&at+8<=end,'transport-shape');
 const sp=frame.readUInt16BE(at),dp=frame.readUInt16BE(at+2),provider=from||to,direction=to?'out':'in';
 const port=to?dp:sp,local=to?source:destination,localPort=to?sp:dp;
 need(port===53||(protocol===6&&port===443),'provider-port');
 if(protocol===17){need(port===53&&frame.readUInt16BE(at+4)===end-at,'udp-shape');return {plain:true};}
 need(at+20<=end,'tcp-shape');const header=(frame[at+12]>>>4)*4;
 need(header>=20&&at+header<=end,'tcp-bound');
 return {plain:port===53,provider,direction,key:provider.id+'/'+local+'/'+localPort,seq:frame.readUInt32BE(at+4),flags:frame[at+13],payload:frame.subarray(at+header,end)};
}
function clientHello(body,expected,allowAbsent){
 need(body.length>=38&&body.readUInt16BE(0)===0x0303,'client-hello');
 let p=34;const session=body[p++];need(session<=32&&p+session+2<=body.length,'client-hello');p+=session;
 const ciphers=body.readUInt16BE(p);p+=2;need(ciphers>=2&&ciphers%2===0&&p+ciphers+1<=body.length,'client-hello');p+=ciphers;
 const compression=body[p++];need(compression>=1&&p+compression+2<=body.length,'client-hello');p+=compression;
 const ext=body.readUInt16BE(p);p+=2;need(p+ext===body.length,'client-hello');
 let sni=false;const seen=new Set();
 while(p<body.length){
  need(p+4<=body.length,'client-hello');const kind=body.readUInt16BE(p),size=body.readUInt16BE(p+2);p+=4;
  need(p+size<=body.length&&!seen.has(kind),'client-hello');seen.add(kind);
  if(kind===0){
   need(size>5&&body.readUInt16BE(p)===size-2&&body[p+2]===0&&body.readUInt16BE(p+3)===size-5,'client-sni');
   need(body.subarray(p+5,p+size).equals(Buffer.from(expected,'ascii')),'client-sni-mismatch');sni=true;
  }
  p+=size;
 }
 need(sni||allowAbsent,'client-sni-absent');
}
function serverHello(body){
 need(body.length>=40&&body.readUInt16BE(0)===0x0303,'server-hello');
 const session=body[34],p=35+session;
 need(session<=32&&p+5<=body.length&&body.readUInt16BE(p)!==0&&body[p+2]===0&&p+5+body.readUInt16BE(p+3)===body.length,'server-hello');
}
function streamBytes(state){
 need(state.base!==null,'tcp-syn-required');
 state.segments.sort((a,b)=>a.at-b.at);let length=0;
 const out=Buffer.alloc(LIMITS.stream);
 for(const s of state.segments){
  need(s.at<=length,'tcp-gap');
  const overlap=Math.min(Math.max(0,length-s.at),s.bytes.length);
  need(out.subarray(s.at,s.at+overlap).equals(s.bytes.subarray(0,overlap)),'tcp-overlap');
  s.bytes.copy(out,s.at);length=Math.max(length,s.at+s.bytes.length);
 }
 return out.subarray(0,length);
}
function tlsRecords(bytes,direction,expected,allowAbsent){
 let p=0,handshake=Buffer.alloc(0),hello=false,cipher=false,application=0,records=0;
 while(p<bytes.length){
  need(p+5<=bytes.length,'tls-truncated');const kind=bytes[p],version=bytes.readUInt16BE(p+1),size=bytes.readUInt16BE(p+3);p+=5;
  need([20,21,22,23].includes(kind)&&version>=0x0301&&version<=0x0303&&size>0&&size<=18432,'tls-record');
  need(p+size<=bytes.length,'tls-truncated');const body=bytes.subarray(p,p+size);p+=size;records++;
  if(kind===20){need(size===1&&body[0]===1,'tls-change-cipher');cipher=true;}
  if(kind===23){need(hello,'tls-hello-required');application++;}
  if(kind===22&&!cipher){
   handshake=Buffer.concat([handshake,body]);need(handshake.length<=LIMITS.stream,'tls-handshake-bound');
   while(handshake.length>=4){
    const type=handshake[0],n=handshake.readUIntBE(1,3);
    need(n<=LIMITS.stream-4,'tls-handshake-bound');if(n+4>handshake.length)break;
    if(!hello){
     need(type===(direction==='out'?1:2),'tls-hello-required');
     if(direction==='out')clientHello(handshake.subarray(4,n+4),expected,allowAbsent);else serverHello(handshake.subarray(4,n+4));hello=true;
    }
    handshake=handshake.subarray(n+4);
   }
  }
 }
 need(hello&&handshake.length===0,'tls-hello-required');
 return {application,records};
}
function inspectWire(input,allowAbsent){
 const frames=parseCapture(input),flows=new Map();let plaintextPackets=0,segments=0;
 for(const frame of frames){
  const p=decodeFrame(frame);if(p.plain){plaintextPackets++;continue;}
  if(!flows.has(p.key)){need(flows.size<LIMITS.flows,'flow-bound');flows.set(p.key,{provider:p.provider,out:{base:null,segments:[]},in:{base:null,segments:[]}});}
  const state=flows.get(p.key)[p.direction],syn=Boolean(p.flags&2);
  need(!(p.flags&4),'tcp-reset');
  if(syn){need(p.direction==='in'?Boolean(p.flags&16):!(p.flags&16),'tcp-syn-shape');const base=(p.seq+1)>>>0;need(state.base===null||state.base===base,'tcp-reuse');state.base=base;}
  if(p.payload.length){
   need(state.base!==null&&++segments<=LIMITS.segments,'tcp-segment-bound');
   const at=((p.seq+(syn?1:0))-state.base)>>>0;need(at+p.payload.length<=LIMITS.stream,'tcp-stream-bound');
   state.segments.push({at,bytes:p.payload});
  }
 }
 const results=[];
 for(const flow of flows.values()){
  // SYN-only connection attempts must not become positive TLS evidence.
  if(!flow.out.segments.length&&!flow.in.segments.length)continue;
  const out=tlsRecords(streamBytes(flow.out),'out',flow.provider.sni,allowAbsent),incoming=tlsRecords(streamBytes(flow.in),'in',flow.provider.sni);
  results.push({provider:flow.provider.id,clientHello:true,serverHello:true,outboundEncryptedRecords:out.application,inboundEncryptedRecords:incoming.application,records:out.records+incoming.records});
 }
 const observed=plaintextPackets===0&&results.some(r=>r.outboundEncryptedRecords>0&&r.inboundEncryptedRecords>0);
 return {schemaVersion:1,observation:observed?'tls-observed':'insufficient',packets:frames.length,plaintextPackets,flows:results,
  dnsPayloadDecrypted:false,ordinaryResolverBound:false,negativeControlPassed:false,productionQualificationComplete:false};
}
function inspectDoHWire(input){return inspectWire(input,false);}
function inspectConfiguredIPDoHWire(input,binding){
 try{assertIPBinding(binding);}catch{fail('identity-binding');}
 return inspectWire(input,true);
}
module.exports={inspectDoHWire,inspectConfiguredIPDoHWire,WireError,LIMITS};
// No CLI accepting arbitrary capture paths: only an explicitly authorized hosted
// driver may supply private bytes in memory and publish this fixed projection.
