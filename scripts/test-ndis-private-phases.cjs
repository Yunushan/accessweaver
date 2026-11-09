"use strict";
const assert=require('node:assert/strict');const {joinFramePhases,NUMBERS,DNS_KEYS}=require('./ndis-private-phases.cjs');
const digest='a'.repeat(64),provider='2ed6006e-4729-4609-b423-3ee7bcd678ef';
function frame(sent=true,tcp=false){const n=tcp?20:8,b=Buffer.alloc(14+20+n);b.writeUInt16BE(0x0800,12);b[14]=0x45;b.writeUInt16BE(20+n,16);b[22]=64;b[23]=tcp?6:17;b.set([10,0,0,2],26);b.set([8,8,8,8],30);b.writeUInt16BE(40000,34);b.writeUInt16BE(tcp?443:53,36);if(tcp){b[46]=0x50;b[47]=2;}else b.writeUInt16BE(8,38);return {provider,id:1001,version:0,keywords:sent?0x1c0000000n:0x2c0000000n,fragmentSize:b.length,fragment:b};}
function doc(phases,records=phases.length,starts=phases.map(()=>2)){return {schemaVersion:2,records,sourceFramesSHA256:digest,phases,starts};}
let passed=0;function test(name,body){body();passed++;process.stdout.write(JSON.stringify({name,passed:true})+'\n');}
test('phase-before-boundary-udp-sent-counts',()=>{const r=joinFramePhases([frame()],doc([0],4),digest);assert.equal(r.before,1);assert.equal(r.udpBefore,1);assert.equal(r.sentBefore,1);assert.equal(r.records,4);});
test('phase-exact-boundary-is-explicit',()=>{const r=joinFramePhases([frame(false)],doc([1]),digest);assert.equal(r.at,1);assert.equal(r.receivedAt,1);assert.equal(r.udpAt,1);});
test('phase-after-boundary-tcp-counts',()=>{const r=joinFramePhases([frame(true,true)],doc([2]),digest);assert.equal(r.tcpAfter,1);assert.equal(r.after,1);});
test('phase-full-ordered-frame-set-is-retained',()=>{const r=joinFramePhases([frame(),frame(false),frame(true,true)],doc([0,1,2],9),digest);assert.equal(r.frames,3);assert.equal(r.before+r.at+r.after,3);assert.equal(r.tcpAfter+r.udpBefore+r.udpAt,3);});
test('phase-mismatched-source-digest-refused',()=>assert.throws(()=>joinFramePhases([frame()],doc([0]),'b'.repeat(64)),/phase-source/));
test('phase-missing-or-extra-ordinal-refused',()=>{for(const phases of [[],[0,1]])assert.throws(()=>joinFramePhases([frame()],doc(phases,2),digest),/phase-count/);});
test('phase-coerced-or-unknown-classification-refused',()=>{for(const v of ['0',true,-1,3,null,0.5])assert.throws(()=>joinFramePhases([frame()],doc([v]),digest),/phase-count/);});
test('phase-private-or-unknown-document-field-refused',()=>assert.throws(()=>joinFramePhases([frame()],{...doc([0]),ticks:1},digest),/phase-document/));
test('phase-incomplete-or-excessive-header-count-refused',()=>{for(const count of [0,4097,1.5])assert.throws(()=>joinFramePhases([frame()],doc([0],count),digest),/phase-document/);});
test('phase-empty-and-excessive-record-sets-refused',()=>{for(const frames of [[],Array(4097).fill(frame())])assert.throws(()=>joinFramePhases(frames,doc([0]),digest),/phase-count/);});
test('phase-incomplete-frame-not-repaired-or-dropped',()=>{const f=frame();f.fragment=f.fragment.subarray(0,20);assert.throws(()=>joinFramePhases([f],doc([0]),digest));});
test('phase-public-projection-excludes-private-source-and-vectors',()=>{const r=joinFramePhases([frame()],doc([0]),digest);assert.equal(Object.keys(r).length,NUMBERS.length+12);assert.equal(r.productionQualificationComplete,false);const text=JSON.stringify(r);for(const forbidden of ['sourceFramesSHA256','phases','ticks',digest,'fragment','"provider":'])assert(!text.includes(forbidden));assert(Object.isFrozen(r));});
function dnsFrame(name,type=1,response=false,v6=false,quad=false){
 const parts=name.split('.'),question=Buffer.concat(parts.flatMap(label=>[Buffer.from([label.length]),Buffer.from(label)]).concat([Buffer.from([0])])),data=Buffer.alloc(12+question.length+4);data.writeUInt16BE(response?0x8180:0x0100,2);data.writeUInt16BE(1,4);question.copy(data,12);data.writeUInt16BE(type,12+question.length);data.writeUInt16BE(1,14+question.length);
 const n=v6?40:20,b=Buffer.alloc(14+n+8+data.length);b.writeUInt16BE(v6?0x86dd:0x0800,12);
 if(v6){b[14]=0x60;b.writeUInt16BE(8+data.length,18);b[20]=17;b[21]=64;const client=Buffer.from('fd000000000000000000000000000002','hex'),server=Buffer.from(quad?'262000fe0000000000000000000000fe':'20014860486000000000000000008888','hex');(response?server:client).copy(b,22);(response?client:server).copy(b,38);}
 else{b[14]=0x45;b.writeUInt16BE(n+8+data.length,16);b[22]=64;b[23]=17;const client=Buffer.from([10,0,0,2]),server=Buffer.from(quad?[9,9,9,9]:[8,8,8,8]);(response?server:client).copy(b,26);(response?client:server).copy(b,30);}
 const t=14+n;b.writeUInt16BE(response?53:40000,t);b.writeUInt16BE(response?40000:53,t+2);b.writeUInt16BE(8+data.length,t+4);data.copy(b,t+8);return {...frame(!response),fragmentSize:b.length,fragment:b};
}
function dnsResult(record){return joinFramePhases([record],doc([0]),digest).dnsBefore;}
test('dns-product-probe-request-and-response-classified',()=>{for(const response of [false,true]){const r=dnsResult(dnsFrame('Example.COM',1,response));assert.equal(r.productProbe,1);assert.equal(r[response?'responses':'queries'],1);assert.equal(r.a,1);assert.equal(r.googleV4,1);assert.equal(r.unclassified,0);}});
test('dns-positive-and-negative-fixture-roles-closed',()=>{assert.equal(dnsResult(dnsFrame('example.net')).positiveProbe,1);assert.equal(dnsResult(dnsFrame('example.org')).negativeProbe,1);});
test('dns-provider-bootstrap-roles-are-source-known-only',()=>{for(const [name,key,other] of [['dns.google','googleBootstrap','quad9Bootstrap'],['dns.quad9.net','quad9Bootstrap','googleBootstrap']])for(const response of [false,true]){const d=dnsResult(dnsFrame(name,1,response));assert.equal(d.providerBootstrap,1);assert.equal(d[key],1);assert.equal(d[other],0);}for(const name of ['example.com','private.synthetic.test']){const d=dnsResult(dnsFrame(name));assert.equal(d.googleBootstrap+d.quad9Bootstrap,0);}});
test('dns-unknown-name-is-counted-without-publication',()=>{const r=dnsResult(dnsFrame('private.synthetic.test'));assert.equal(r.otherName,1);assert(!JSON.stringify(r).includes('private.synthetic'));assert.deepEqual(Object.keys(r),DNS_KEYS);});
test('dns-aaaa-and-other-question-types-counted',()=>{assert.equal(dnsResult(dnsFrame('example.com',28)).aaaa,1);assert.equal(dnsResult(dnsFrame('example.com',65)).otherType,1);});
test('dns-malformed-question-and-pointer-cycle-unclassified',()=>{const zero=dnsFrame('example.com');zero.fragment.writeUInt16BE(0,46);assert.equal(dnsResult(zero).unclassified,1);const loop=dnsFrame('example.com');loop.fragment[54]=0xc0;loop.fragment[55]=12;assert.equal(dnsResult(loop).unclassified,1);assert.equal(dnsResult(frame()).unclassified,1);const dot=dnsFrame('example.com');dot.fragment[54]=11;dot.fragment[62]=46;assert.equal(dnsResult(dot).unclassified,1);});
test('dns-all-fixed-provider-slots-include-ipv6',()=>{assert.equal(dnsResult(dnsFrame('example.com',1,false,false,true)).quad9V4,1);assert.equal(dnsResult(dnsFrame('example.com',1,false,true,false)).googleV6,1);assert.equal(dnsResult(dnsFrame('example.com',1,true,true,true)).quad9V6,1);});
test('dns-phase-partitions-preserve-all-udp-frames',()=>{const r=joinFramePhases([dnsFrame('example.com'),dnsFrame('example.net'),dnsFrame('dns.google')],doc([0,1,2]),digest);assert.equal(r.dnsBefore.productProbe,1);assert.equal(r.dnsAt.positiveProbe,1);assert.equal(r.dnsAfter.providerBootstrap,1);for(const bucket of ['Before','At','After']){const d=r['dns'+bucket];assert.equal(d.queries+d.responses+d.unclassified,r['udp'+bucket]);assert(Object.isFrozen(d));}});

function withPort(record,port,response=false){const b=Buffer.from(record.fragment),t=b.readUInt16BE(12)===0x86dd?54:34;b.writeUInt16BE(port,t+(response?0:2));return {...record,fragment:b};}
test('udp-port-partitions-cover-all-fixed-providers-both-directions',()=>{
 for(const v6 of [false,true])for(const quad of [false,true])for(const response of [false,true])for(const port of [53,443,853]){
  const r=joinFramePhases([withPort(dnsFrame('example.com',1,response,v6,quad),port,response)],doc([0]),digest);
  assert.equal(r.udpBefore,1);assert.equal(r.udp53Before+r.udp443Before+r.udpOtherBefore,1);assert.equal(r['udp'+(port===53?'53':port===443?'443':'Other')+'Before'],1);
  if(port!==53){assert.equal(r.dnsBefore.unclassified,1);assert.equal(r.dnsBefore.productProbe,0);}
 }
});
test('udp-ports-close-at-every-phase-without-discarding-tcp',()=>{
 const rows=[withPort(frame(),53),withPort(frame(),443),withPort(frame(),853),frame(true,true)];
 for(const phase of [0,1,2]){const r=joinFramePhases(rows,doc(rows.map(()=>phase)),digest),bucket=['Before','At','After'][phase];assert.equal(r.frames,4);assert.equal(r['udp'+bucket],3);for(const port of ['53','443','Other'])assert.equal(r['udp'+port+bucket],1);assert.equal(r['tcp'+bucket],1);}
});
test('google-ipv6-role-matches-independent-network-byte-literal',()=>{
 const row=dnsFrame('example.com',1,false,true,false),b=Buffer.from(row.fragment);
 b.set([0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88],38);
 assert.equal(dnsResult({...row,fragment:b}).googleV6,1);
 b.set([0x20,0x01,0x48,0x60,0,0,0,0,0,0,0,0,0,0,0x88,0x88],38);
 const r=joinFramePhases([{...row,fragment:b}],doc([0]),digest);assert.equal(r.dnsBefore.unclassified,1);assert.equal(r.udpOtherBefore,1);assert.equal(r.dnsBefore.googleV6,0);
});
test('udp-port-publication-contains-only-bounded-counts',()=>{
 const r=joinFramePhases([withPort(dnsFrame('private.synthetic.test'),443)],doc([0]),digest);assert.equal(r.udp443Before,1);assert.equal(r.dnsBefore.unclassified,1);assert(!JSON.stringify(r).includes('private.synthetic'));for(const key of NUMBERS)assert(Number.isSafeInteger(r[key])&&r[key]>=0&&r[key]<=4096);
});

test('start-partitions-distinguish-before-exact-and-during-dispatch',()=>{
 const r=joinFramePhases([dnsFrame('dns.google'),dnsFrame('example.net'),dnsFrame('example.com')],doc([0,0,0],3,[0,1,2]),digest);assert.equal(r.preStart,1);assert.equal(r.startAt,1);assert.equal(r.during,1);assert.equal(r.before,3);assert.equal(r.dnsPreStart.providerBootstrap,1);assert.equal(r.dnsStartAt.positiveProbe,1);assert.equal(r.dnsDuring.productProbe,1);assert.equal(r.udp53PreStart+r.udp53StartAt+r.udp53During,r.udp53Before);
});
test('start-partitions-preserve-every-original-protocol-direction-and-role',()=>{
 const rows=[dnsFrame('dns.google'),withPort(dnsFrame('example.net'),443),frame(false,true),dnsFrame('example.com'),frame(true,true)],r=joinFramePhases(rows,doc([0,0,0,1,2],5,[0,1,2,2,2]),digest);assert.equal(r.frames,5);assert.equal(r.before,3);assert.equal(r.at,1);assert.equal(r.after,1);
 for(const prefix of ['tcp','udp','sent','received','udp53','udp443','udpOther'])assert.equal(r[prefix+'PreStart']+r[prefix+'StartAt']+r[prefix+'During'],r[prefix+'Before']);for(const key of DNS_KEYS)assert.equal(r.dnsPreStart[key]+r.dnsStartAt[key]+r.dnsDuring[key],r.dnsBefore[key]);
});
test('start-and-return-boundaries-refuse-impossible-private-classifications',()=>{
 for(const returned of [1,2])for(const started of [0,1])assert.throws(()=>joinFramePhases([frame()],doc([returned],1,[started]),digest),/phase-boundaries/);
});
test('start-map-missing-extra-coerced-and-legacy-documents-refused',()=>{
 for(const starts of [[],[0,1],['0'],[true],[-1],[3],[0.5]])assert.throws(()=>joinFramePhases([frame()],doc([0],2,starts),digest));const missing=doc([0]);delete missing.starts;assert.throws(()=>joinFramePhases([frame()],missing,digest),/phase-document/);assert.throws(()=>joinFramePhases([frame()],{...doc([0]),schemaVersion:1},digest),/phase-document/);
});
test('start-count-publication-never-leaks-vectors-timestamps-or-names',()=>{
 const r=joinFramePhases([dnsFrame('private.synthetic.test')],doc([0],1,[0]),digest),text=JSON.stringify(r);assert.equal(r.schemaVersion,4);assert.equal(r.dnsPreStart.otherName,1);assert(Object.isFrozen(r.dnsPreStart));for(const privateValue of ['private.synthetic','"starts"','"phases"','UtcTicks','sourceFramesSHA256',digest])assert(!text.includes(privateValue));
});
test('start-count-closed-schema-stays-within-existing-public-report-bound',()=>{
 const r=JSON.parse(JSON.stringify(joinFramePhases([frame()],doc([0]),digest)));for(const key of NUMBERS)r[key]=4096;for(const bucket of ['Before','At','After','PreStart','StartAt','During'])for(const key of DNS_KEYS)r['dns'+bucket][key]=4096;assert(Buffer.byteLength(JSON.stringify(r))<=4096);assert.equal(Object.keys(r).length,NUMBERS.length+12);
});
function resetFrame(sent=true){const r=frame(sent,true);r.fragment[47]=0x14;return r;}
test('reset-flags-have-exact-start-and-return-phase-counts',()=>{
 const rows=[resetFrame(),resetFrame(false),resetFrame(),resetFrame(false),resetFrame()],r=joinFramePhases(rows,doc([0,0,0,1,2],5,[0,1,2,2,2]),digest);
 assert.equal(r.tcpResetBefore,3);assert.equal(r.tcpResetPreStart,1);assert.equal(r.tcpResetStartAt,1);assert.equal(r.tcpResetDuring,1);assert.equal(r.tcpResetAt,1);assert.equal(r.tcpResetAfter,1);assert.equal(r.frames,5);
});
test('reset-counts-do-not-reclassify-normal-tcp-udp-or-fin',()=>{
 const fin=frame(true,true);fin.fragment[47]=0x11;const r=joinFramePhases([frame(),frame(false,true),fin,resetFrame()],doc([0,0,0,0]),digest);
 assert.equal(r.frames,4);assert.equal(r.tcpBefore,3);assert.equal(r.udpBefore,1);assert.equal(r.tcpResetBefore,1);assert.equal(r.tcpResetDuring,1);
});
test('reset-phase-partitions-close-for-both-directions',()=>{
 for(const sent of [true,false]){const r=joinFramePhases([resetFrame(sent),resetFrame(sent),resetFrame(sent)],doc([0,1,2]),digest);assert.equal(r.tcpResetBefore+r.tcpResetAt+r.tcpResetAfter,3);assert.equal(r.tcpResetPreStart+r.tcpResetStartAt+r.tcpResetDuring,r.tcpResetBefore);assert.equal(r[sent?'sentBefore':'receivedBefore'],1);}
});
test('reset-counts-include-ipv6-and-vlan-frames-without-private-fields',()=>{
 const a=resetFrame(),b=Buffer.alloc(14+40+20);b.writeUInt16BE(0x86dd,12);b[14]=0x60;b.writeUInt16BE(20,18);b[20]=6;b[21]=64;b.set(Buffer.from('fd000000000000000000000000000002','hex'),22);b.set(Buffer.from('20014860486000000000000000008888','hex'),38);a.fragment.copy(b,54,34);const v6={...a,fragment:b,fragmentSize:b.length};
 const tagged=Buffer.concat([a.fragment.subarray(0,12),Buffer.from([0x81,0,0,1]),a.fragment.subarray(12)]),vlan={...a,fragment:tagged,fragmentSize:tagged.length};const r=joinFramePhases([v6,vlan],doc([0,2]),digest);assert.equal(r.tcpResetBefore,1);assert.equal(r.tcpResetAfter,1);assert.equal(r.frames,2);assert(!JSON.stringify(r).includes('fd0000'));
});
test('reset-counts-remain-bounded-frozen-and-closed',()=>{
 const r=joinFramePhases([resetFrame()],doc([0]),digest);assert(Object.isFrozen(r));assert.equal(Object.keys(r).length,NUMBERS.length+12);for(const key of NUMBERS)assert(Number.isSafeInteger(r[key])&&r[key]>=0&&r[key]<=4096);for(const secret of ['fragment','phases','starts','sourceFramesSHA256',digest])assert(!JSON.stringify(r).includes(secret));
});
test('reset-bearing-malformed-frame-is-refused-without-count-repair',()=>{
 const r=resetFrame();r.fragment=Buffer.from(r.fragment);r.fragment[46]=0xf0;assert.throws(()=>joinFramePhases([r],doc([0]),digest));
});
assert.equal(passed,36);
