"use strict";
const assert=require('node:assert/strict');const {joinFramePhases,NUMBERS}=require('./ndis-private-phases.cjs');
const digest='a'.repeat(64),provider='2ed6006e-4729-4609-b423-3ee7bcd678ef';
function frame(sent=true,tcp=false){const n=tcp?20:8,b=Buffer.alloc(14+20+n);b.writeUInt16BE(0x0800,12);b[14]=0x45;b.writeUInt16BE(20+n,16);b[22]=64;b[23]=tcp?6:17;b.set([10,0,0,2],26);b.set([8,8,8,8],30);b.writeUInt16BE(40000,34);b.writeUInt16BE(tcp?443:53,36);if(tcp){b[46]=0x50;b[47]=2;}else b.writeUInt16BE(8,38);return {provider,id:1001,version:0,keywords:sent?0x1c0000000n:0x2c0000000n,fragmentSize:b.length,fragment:b};}
function doc(phases,records=phases.length){return {schemaVersion:1,records,sourceFramesSHA256:digest,phases};}
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
test('phase-public-projection-excludes-private-source-and-vectors',()=>{const r=joinFramePhases([frame()],doc([0]),digest);assert.equal(Object.keys(r).length,NUMBERS.length+6);assert.equal(r.productionQualificationComplete,false);const text=JSON.stringify(r);for(const forbidden of ['sourceFramesSHA256','phases','ticks',digest,'fragment','provider'])assert(!text.includes(forbidden));assert(Object.isFrozen(r));});
assert.equal(passed,12);
