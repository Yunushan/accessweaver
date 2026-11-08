'use strict';
// Synthetic protocol contracts only: no network, capture utility or product runs.
const assert=require('node:assert/strict');
const {inspectDoHWire,WireError,LIMITS}=require('./dns-wire-evidence.cjs');
const b16=n=>{const b=Buffer.alloc(2);b.writeUInt16BE(n);return b;};
const b24=n=>{const b=Buffer.alloc(3);b.writeUIntBE(n,0,3);return b;};
function record(kind,body){return Buffer.concat([Buffer.from([kind,3,3]),b16(body.length),body]);}
function handshake(kind,body){return Buffer.concat([Buffer.from([kind]),b24(body.length),body]);}
function client(name='dns.google'){
 const host=Buffer.from(name,'ascii'),entry=Buffer.concat([Buffer.from([0]),b16(host.length),host]);
 const sni=Buffer.concat([b16(entry.length),entry]),ext=Buffer.concat([b16(0),b16(sni.length),sni]);
 return handshake(1,Buffer.concat([b16(0x0303),Buffer.alloc(32,7),Buffer.from([0]),b16(2),b16(0x1301),Buffer.from([1,0]),b16(ext.length),ext]));
}
function server(){return handshake(2,Buffer.concat([b16(0x0303),Buffer.alloc(32,9),Buffer.from([0]),b16(0x1301),Buffer.from([0]),b16(6),b16(43),b16(2),b16(0x0304)]));}
function tcp(payload,{incoming=false,seq=101,flags=0x18,port=443,localPort=50123}={}){
 const h=Buffer.alloc(20);h.writeUInt16BE(incoming?port:localPort,0);h.writeUInt16BE(incoming?localPort:port,2);h.writeUInt32BE(seq>>>0,4);h[12]=0x50;h[13]=flags;return Buffer.concat([h,payload]);
}
function frame(payload,options={}){
 const {incoming=false,v6=false,provider='google',fragment=false,port=443,udp=false}=options;
 const ethernet=Buffer.alloc(14);ethernet.writeUInt16BE(v6?0x86dd:0x0800,12);
 const local=Buffer.from(v6?'20010db8000000000000000000000001':'c0000201','hex');
 const remote=Buffer.from(v6?(provider==='google'?'20014860486000000000000000008888':'262000fe0000000000000000000000fe'):(provider==='google'?'08080808':'09090909'),'hex');
 let transport;
 if(udp){transport=Buffer.alloc(8+payload.length);transport.writeUInt16BE(incoming?port:50123,0);transport.writeUInt16BE(incoming?50123:port,2);transport.writeUInt16BE(transport.length,4);payload.copy(transport,8);}
 else transport=tcp(payload,options);
 const ip=Buffer.alloc(v6?40:20);
 if(v6){ip[0]=0x60;ip.writeUInt16BE(transport.length,4);ip[6]=udp?17:6;ip[7]=64;(incoming?remote:local).copy(ip,8);(incoming?local:remote).copy(ip,24);}
 else {ip[0]=0x45;ip.writeUInt16BE(20+transport.length,2);ip.writeUInt16BE(fragment?0x2000:0,6);ip[8]=64;ip[9]=udp?17:6;(incoming?remote:local).copy(ip,12);(incoming?local:remote).copy(ip,16);}
 return Buffer.concat([ethernet,ip,transport]);
}
function block(kind,body,be=false){
 const b=Buffer.alloc(12+Math.ceil(body.length/4)*4),write=(p,n)=>b[be?'writeUInt32BE':'writeUInt32LE'](n,p);
 write(0,kind);write(4,b.length);body.copy(b,8);write(b.length-4,b.length);return b;
}
function capture(frames,{be=false,link=1,snap=0}={}){
 const sh=Buffer.alloc(16),id=Buffer.alloc(8),u16=(b,p,n)=>b[be?'writeUInt16BE':'writeUInt16LE'](n,p),u32=(b,p,n)=>b[be?'writeUInt32BE':'writeUInt32LE'](n,p);
 u32(sh,0,0x1a2b3c4d);u16(sh,4,1);sh.fill(255,8);
 u16(id,0,link);u32(id,4,snap);
 return Buffer.concat([block(0x0a0d0d0a,sh,be),block(1,id,be),...frames.map(f=>{const e=Buffer.alloc(20);u32(e,12,f.length);u32(e,16,f.length);return block(6,Buffer.concat([e,f]),be);})]);
}
function conversation({v6=false,provider='google',name,segment=false,sequence=100,localPort=50123}={}){
 const o={v6,provider,localPort},hello=record(22,client(name||(provider==='google'?'dns.google':'dns.quad9.net'))),response=record(22,server());
 const outbound=Buffer.concat([hello,record(23,Buffer.alloc(41,0x71))]),inbound=Buffer.concat([response,record(23,Buffer.alloc(57,0x91))]);
 const frames=[frame(Buffer.alloc(0),{...o,seq:sequence,flags:2}),frame(Buffer.alloc(0),{...o,incoming:true,seq:200,flags:0x12})];
 if(segment){frames.push(frame(outbound.subarray(8),{...o,seq:(sequence+9)>>>0}),frame(outbound.subarray(0,8),{...o,seq:(sequence+1)>>>0}));}
 else frames.push(frame(outbound,{...o,seq:(sequence+1)>>>0}));
 frames.push(frame(inbound,{...o,incoming:true,seq:201}));return frames;
}
function refusal(data,code){
 assert.throws(()=>inspectDoHWire(data),e=>e instanceof WireError&&(!code||e.code===code)&&/^[a-z0-9-]+$/.test(e.message));
}
const cases=[];
function check(name,fn){cases.push([name,fn]);}
check('four-fixed-providers-two-byte-orders',()=>{
 for(const v6 of [false,true])for(const provider of ['google','quad9'])for(const be of [false,true]){
  const r=inspectDoHWire(capture(conversation({v6,provider}),{be}));
  assert.equal(r.observation,'tls-observed');assert.equal(r.flows.length,1);assert.equal(r.flows[0].provider,provider+(v6?'-v6':'-v4'));
  assert.equal(r.flows[0].outboundEncryptedRecords,1);assert.equal(r.flows[0].inboundEncryptedRecords,1);
  assert.equal(r.ordinaryResolverBound,false);assert.equal(r.negativeControlPassed,false);assert.equal(r.dnsPayloadDecrypted,false);assert.equal(r.productionQualificationComplete,false);
 }
});
check('split-reordered-tcp-and-sequence-wrap',()=>{
 for(const sequence of [100,0xfffffffc])assert.equal(inspectDoHWire(capture(conversation({segment:true,sequence}))).observation,'tls-observed');
});
check('consistent-duplicate-retransmission',()=>{
 const f=conversation();f.splice(3,0,Buffer.from(f[2]));assert.equal(inspectDoHWire(capture(f)).observation,'tls-observed');
});
check('conflicting-retransmission-refused',()=>{
 const f=conversation(),duplicate=Buffer.from(f[2]);duplicate[duplicate.length-1]^=1;f.splice(3,0,duplicate);refusal(capture(f),'tcp-overlap');
});
check('missing-tcp-bytes-refused',()=>{
 const f=conversation({segment:true});f.splice(3,1);refusal(capture(f),'tcp-gap');
});
check('unrelated-sni-refused',()=>refusal(capture(conversation({name:'private.invalid'})),'client-sni'));
check('provider-name-mismatch-refused',()=>refusal(capture(conversation({provider:'quad9',name:'dns.google'})),'client-sni'));
check('syn-only-is-insufficient',()=>assert.equal(inspectDoHWire(capture(conversation().slice(0,2))).observation,'insufficient'));
check('server-missing-refused',()=>refusal(capture(conversation().slice(0,3)),'tls-hello-required'));
check('missing-initial-syn-refused',()=>refusal(capture(conversation().slice(1)),'tcp-segment-bound'));
check('handshake-only-is-insufficient',()=>{
 const f=conversation();f[2]=frame(record(22,client()),{seq:101});f[3]=frame(record(22,server()),{incoming:true,seq:201});
 assert.equal(inspectDoHWire(capture(f)).observation,'insufficient');
});
check('one-direction-encrypted-data-is-insufficient',()=>{
 const f=conversation();f[3]=frame(record(22,server()),{incoming:true,seq:201});assert.equal(inspectDoHWire(capture(f)).observation,'insufficient');
});
check('different-flows-cannot-combine-evidence',()=>{
 const f=conversation();f[3]=frame(Buffer.concat([record(22,server()),record(23,Buffer.alloc(20,8))]),{incoming:true,seq:201,localPort:50124});
 refusal(capture(f));
});
check('plaintext-udp-prevents-positive-evidence',()=>{
 const r=inspectDoHWire(capture([...conversation(),frame(Buffer.from('PRIVATE-SYNTHETIC'),{udp:true,port:53})]));
 assert.equal(r.observation,'insufficient');assert.equal(r.plaintextPackets,1);assert(!JSON.stringify(r).includes('PRIVATE'));
});
check('plaintext-tcp-prevents-positive-evidence',()=>{
 const r=inspectDoHWire(capture([...conversation(),frame(Buffer.from('PRIVATE-SYNTHETIC'),{port:53})]));
 assert.equal(r.observation,'insufficient');assert.equal(r.plaintextPackets,1);
});
check('unrelated-endpoint-refused',()=>{
 const f=conversation();f[0].fill(10,30,34);refusal(capture(f),'provider-scope');
});
check('unsupported-port-refused',()=>refusal(capture([frame(Buffer.alloc(0),{port:853,flags:2})]),'provider-port'));
check('fragmented-ipv4-refused',()=>refusal(capture([frame(Buffer.alloc(0),{fragment:true,flags:2})]),'ip-fragment'));
check('ip-length-truncation-refused',()=>{
 for(const v6 of [false,true]){const f=conversation({v6});f[2]=f[2].subarray(0,f[2].length-1);refusal(capture(f));}
});
check('tcp-offset-and-reset-refused',()=>{
 const f=conversation();f[2][46]=0x10;refusal(capture(f),'tcp-bound');
 const g=conversation();g[2][47]|=4;refusal(capture(g),'tcp-reset');
});
check('tls-truncated-or-unknown-record-refused',()=>{
 const f=conversation();f[2]=frame(Buffer.from([23,3,3,0,8,1]),{seq:101});refusal(capture(f),'tls-truncated');
 const g=conversation();g[2]=frame(Buffer.from([99,3,3,0,1,1]),{seq:101});refusal(capture(g),'tls-record');
});
check('encrypted-record-before-hello-refused',()=>{
 const f=conversation();f[2]=frame(record(23,Buffer.alloc(20,1)),{seq:101});refusal(capture(f),'tls-hello-required');
});
check('malformed-handshake-length-refused',()=>{
 const f=conversation(),bad=client();bad[1]=255;f[2]=frame(record(22,bad),{seq:101});refusal(capture(f),'tls-handshake-bound');
});
check('capture-size-bound',()=>{refusal(Buffer.alloc(0),'capture-bound');refusal(Buffer.alloc(LIMITS.bytes+1),'capture-bound');});
check('every-prefix-fails-or-remains-insufficient',()=>{
 const data=capture(conversation());
 for(let n=0;n<data.length;n++){
  try{assert.equal(inspectDoHWire(data.subarray(0,n)).observation,'insufficient');}
  catch(e){assert(e instanceof WireError);}
 }
});
check('invalid-section-magic-version-and-multiple-sections',()=>{
 const data=capture(conversation()),bad=Buffer.from(data);bad[8]=0;refusal(bad,'section-magic');
 const version=Buffer.from(data);version[12]=2;refusal(version,'section-version');
 refusal(Buffer.concat([data,data]),'section-shape');
});
check('block-length-and-trailer-refused',()=>{
 const data=capture(conversation());for(const at of [4,24,32]){const bad=Buffer.from(data);bad.writeUInt32LE(13,at);refusal(bad,'block-shape');}
});
check('interface-and-captured-length-refused',()=>{
 refusal(capture(conversation(),{link:101}),'interface-link');refusal(capture(conversation(),{snap:128}),'interface-snaplen');
 const bad=capture(conversation());bad.writeUInt32LE(7,56);refusal(bad,'packet-shape');
 const cut=capture(conversation());cut.writeUInt32LE(65536,68);refusal(cut,'packet-shape');
});
check('obsolete-packet-blocks-refused',()=>{
 for(const kind of [2,3]){const d=capture(conversation());d.writeUInt32LE(kind,48);refusal(d,'packet-kind');}
});
check('nonzero-capture-drop-statistics-refused',()=>{
 const data=capture(conversation()),s=Buffer.alloc(24);s.writeUInt16LE(5,12);s.writeUInt16LE(8,14);s[16]=1;
 refusal(Buffer.concat([data,block(5,s)]),'capture-drops');
});
check('stream-and-flow-bounds',()=>{
 const f=conversation();f[2].writeUInt32BE(101+LIMITS.stream,38);refusal(capture(f),'tcp-stream-bound');
 const frames=[];for(let n=0;n<LIMITS.flows+1;n++)frames.push(frame(Buffer.alloc(0),{seq:100,flags:2,localPort:40000+n}));
 refusal(capture(frames),'flow-bound');
});
check('opaque-metadata-is-not-exported',()=>{
 const data=capture(conversation()),metadata=block(0x00000bad,Buffer.from('PRIVATE-SYNTHETIC-METADATA'));
 const r=inspectDoHWire(Buffer.concat([data,metadata]));
 assert.equal(r.observation,'tls-observed');assert(!JSON.stringify(r).includes('PRIVATE'));
 assert.deepEqual(Object.keys(r).sort(),['schemaVersion','observation','packets','plaintextPackets','flows','dnsPayloadDecrypted','ordinaryResolverBound','negativeControlPassed','productionQualificationComplete'].sort());
});
check('bounded-deterministic-malformed-mutation-sweep',()=>{
 const data=capture(conversation());let seed=0x1d5c3a77;
 for(let n=0;n<4096;n++){
  seed=(Math.imul(seed,1664525)+1013904223)>>>0;const at=seed%data.length,mutated=Buffer.from(data);mutated[at]^=1<<(n%8);
  try{const r=inspectDoHWire(mutated);assert.equal(r.productionQualificationComplete,false);assert.equal(r.ordinaryResolverBound,false);}
  catch(e){assert(e instanceof WireError);assert(/^[a-z0-9-]+$/.test(e.message));}
 }
});
check('read-only-capability-classifiers-fail-closed',()=>{
 const {classifyStatus,classifyFilters}=require('./dns-wire-contract-report.cjs');
 assert.equal(classifyStatus('Packet Monitor is not running.'),'stopped');
 assert.equal(classifyStatus('Packet Monitor is running.'),'running');
 for(const text of ['PRIVATE-SYNTHETIC\nPacket Monitor is not running.','not running',''])assert.equal(classifyStatus(text),'unrecognized');
 for(const text of ['No filters.','Packet Filters:\nNone','No packet filters configured'])assert.equal(classifyFilters(text),'empty');
 assert.equal(classifyFilters('None\n 1 existing-filter'),'rows-present');
 for(const text of ['Unknown output','No filters.\nPRIVATE-SYNTHETIC',''])assert.equal(classifyFilters(text),'unrecognized');
});
check('packet-drop-options-and-section-length-are-not-ignored',()=>{
 const f=frame(Buffer.alloc(0),{seq:100,flags:2}),e=Buffer.alloc(20);e.writeUInt32LE(f.length,12);e.writeUInt32LE(f.length,16);
 const option=Buffer.alloc(12);option.writeUInt16LE(4,0);option.writeUInt16LE(8,2);option[4]=1;
 const initial=capture(conversation()).subarray(0,48);
 refusal(Buffer.concat([initial,block(6,Buffer.concat([e,f,Buffer.alloc((4-f.length%4)%4),option]))]),'capture-drops');
 const d=capture(conversation());d.writeBigInt64LE(99n,16);refusal(d,'section-length');
});
check('server-syn-must-acknowledge-client-open',()=>{
 const f=conversation();f[1][47]=2;refusal(capture(f),'tcp-syn-shape');
 const g=conversation();g[0][47]=0x12;refusal(capture(g),'tcp-syn-shape');
});
function runContracts(){
 const results=cases.map(([name,fn])=>{try{fn();return {name,passed:true};}catch{return {name,passed:false};}});
 return {schemaVersion:1,scope:'synthetic-doh-wire-decoder',cases:results,passed:results.every(r=>r.passed),nativeCapturePerformed:false,encryptedTrafficObserved:false,productionQualificationComplete:false};
}
module.exports={runContracts};
if(require.main===module){const report=runContracts();process.stdout.write(JSON.stringify(report)+'\n');if(!report.passed)process.exitCode=1;}
