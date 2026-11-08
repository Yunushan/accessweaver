'use strict';
// Synthetic bytes only; no capture reader, DNS, product or native execution.
const assert=require('node:assert/strict');
const {convertNdisFrames,FrameConversionError,LIMITS}=require('./ndis-frame-converter.cjs');
const {inspectDoHWire}=require('./dns-wire-evidence.cjs');
const cases=[];
function test(name,fn){let passed=false;try{fn();passed=true;}catch{}cases.push({name,passed});}
function frame({v6=false,udp=false,payload=0,incoming=false}={}){
 const h=Buffer.alloc(14),ip=Buffer.alloc(v6?40:20),transport=Buffer.alloc((udp?8:20)+payload);h.writeUInt16BE(v6?0x86dd:0x0800,12);
 transport.writeUInt16BE(incoming?443:50123,0);transport.writeUInt16BE(incoming?50123:443,2);
 if(udp)transport.writeUInt16BE(transport.length,4);else{transport[12]=0x50;transport[13]=incoming?0x12:2;transport.writeUInt32BE(incoming?200:100,4);}
 const local=Buffer.from(v6?'20010db8000000000000000000000001':'c0000201','hex'),remote=Buffer.from(v6?'20014860486000000000000000008888':'08080808','hex');
 if(v6){ip[0]=0x60;ip.writeUInt16BE(transport.length,4);ip[6]=udp?17:6;(incoming?remote:local).copy(ip,8);(incoming?local:remote).copy(ip,24);}
 else{ip[0]=0x45;ip.writeUInt16BE(ip.length+transport.length,2);ip[9]=udp?17:6;(incoming?remote:local).copy(ip,12);(incoming?local:remote).copy(ip,16);}
 return Buffer.concat([h,ip,transport]);
}
function record(bytes=frame(),incoming=false){return {provider:'2ed6006e-4729-4609-b423-3ee7bcd678ef',id:1001,version:0,keywords:incoming?0x2c0000000n:0x1c0000000n,fragmentSize:bytes.length,fragment:bytes};}
function reject(r,code){assert.throws(()=>convertNdisFrames([r]),e=>e instanceof FrameConversionError&&(!code||e.code===code));}
function vlan(bytes){const h=Buffer.alloc(4);h.writeUInt16BE(bytes.readUInt16BE(12),2);const out=Buffer.concat([bytes.subarray(0,12),Buffer.from([0x81,0]),h,bytes.subarray(14)]);return out;}
test('complete-ipv4-tcp-capture-retains-exact-private-bytes',()=>{const bytes=frame(),r=convertNdisFrames([record(bytes)]);assert.equal(r.summary.frames,1);assert.equal(r.summary.ipv4,1);assert.deepEqual(r.capture.subarray(76,76+bytes.length),bytes);assert.equal(r.capture.readUInt32LE(68),bytes.length);assert.equal(r.capture.readUInt32LE(72),bytes.length);});
test('ipv6-and-udp-are-validated-without-tls-claims',()=>{const r=convertNdisFrames([record(frame({v6:true})),record(frame({udp:true})),record(frame({v6:true,udp:true}),true)]);assert.equal(r.summary.ipv6,2);assert.equal(r.summary.udp,2);assert.equal(r.summary.received,1);assert.equal(r.summary.productionQualificationComplete,false);});
test('existing-strict-decoder-parses-positive-format-without-inventing-tls',()=>{const r=convertNdisFrames([record(),record(frame({incoming:true}),true)]),e=inspectDoHWire(r.capture);assert.equal(e.packets,2);assert.equal(e.observation,'insufficient');});
test('modern-zero-offload-and-signed-keywords-are-supported',()=>{const r=record();r.keywords=BigInt.asIntN(64,r.keywords|(1n<<63n));r.gftFlowEntryId=0n;r.gftOffloadInformation=0n;assert.equal(convertNdisFrames([r]).summary.frames,1);});
test('nonzero-flow-id-or-offload-information-is-refused',()=>{for(const key of ['gftFlowEntryId','gftOffloadInformation']){const r={...record(),gftFlowEntryId:0n,gftOffloadInformation:0n};r[key]=1n;reject(r,'fragment-offload');}});
test('offload-values-must-be-exact-unsigned-bigints',()=>{for(const value of [0,false,'0',-1n,1n<<64n])reject({...record(),gftFlowEntryId:0n,gftOffloadInformation:value},'fragment-offload-type');});
test('partial-or-extra-record-fields-are-refused',()=>{reject({...record(),gftFlowEntryId:0n},'record-shape');reject({...record(),private:'PRIVATE-SYNTHETIC'},'record-shape');});
test('record-accessors-are-not-evaluated',()=>{let touched=false;const r=record();Object.defineProperty(r,'keywords',{get(){touched=true;return 0n;},enumerable:true});reject(r,'record-shape');assert.equal(touched,false);});
test('wrong-provider-event-or-version-is-refused',()=>{for(const [key,value] of [['provider','PRIVATE-SYNTHETIC'],['id',1002],['version',1]])reject({...record(),[key]:value},'fragment-identity');});
test('keywords-require-exact-signed-bigint-range',()=>{for(const value of [1,false,'7516192768',-(1n<<63n)-1n,1n<<63n])reject({...record(),keywords:value},'fragment-keywords');});
test('single-event-start-and-end-bits-are-required',()=>{for(const value of [0x140000000n,0x180000000n,0x100000000n])reject({...record(),keywords:value},'fragment-boundaries');});
test('wireless-and-wan-media-are-refused',()=>{for(const mask of [0x200n,0x10000n,0x10200n])reject({...record(),keywords:record().keywords|mask},'fragment-media');});
test('missing-or-ambiguous-direction-is-refused',()=>{for(const value of [0xc0000000n,0x3c0000000n])reject({...record(),keywords:value},'fragment-direction');});
test('fragment-size-is-exact-and-cannot-be-coerced',()=>{for(const value of [false,'54',13,65536,53,55,54.5])reject({...record(),fragmentSize:value},'fragment-length');});
test('non-buffer-fragments-are-refused',()=>reject({...record(),fragment:new Uint8Array(54)},'fragment-length'));
test('truncated-ipv4-and-inconsistent-total-length-are-refused',()=>{const b=frame();reject(record(b.subarray(0,-1)),'ipv4-truncated');const c=Buffer.from(b);c.writeUInt16BE(0,16);reject(record(c),'ipv4-zero-length');});
test('ipv4-version-and-header-length-are-checked',()=>{for(const value of [0x65,0x44,0x4f]){const b=frame();b[14]=value;reject(record(b));}});
test('ipv4-fragments-are-refused-even-if-byte-lengths-match',()=>{for(const flags of [0x2000,1,0x8000]){const b=frame();b.writeUInt16BE(flags,20);reject(record(b),'ip-fragment');}});
test('ethernet-ip-length-trailing-bytes-are-not-silently-ignored',()=>reject(record(Buffer.concat([frame({payload:10}),Buffer.from([1])])),'frame-length'));
test('zero-minimum-ethernet-padding-is-supported',()=>{const b=Buffer.concat([frame(),Buffer.alloc(6)]);assert.equal(convertNdisFrames([record(b)]).summary.frames,1);});
test('nonzero-or-oversized-padding-is-refused',()=>{reject(record(Buffer.concat([frame(),Buffer.alloc(6,1)])),'frame-length');reject(record(Buffer.concat([frame(),Buffer.alloc(7)])),'frame-length');});
test('ipv6-zero-jumbo-or-truncated-length-is-refused',()=>{const b=frame({v6:true});const c=Buffer.from(b);c.writeUInt16BE(0,18);reject(record(c),'ipv6-length');reject(record(b.subarray(0,-1)),'ipv6-length');});
test('ipv6-fragment-and-unsupported-next-headers-are-refused',()=>{for(const protocol of [44,50,51,58]){const b=frame({v6:true});b[20]=protocol;reject(record(b));}});
test('bounded-ipv6-extension-header-is-accepted',()=>{const b=frame({v6:true}),ext=Buffer.alloc(8);ext[0]=6;const out=Buffer.concat([b.subarray(0,54),ext,b.subarray(54)]);out[20]=0;out.writeUInt16BE(28,18);assert.equal(convertNdisFrames([record(out)]).summary.ipv6,1);});
test('oversized-ipv6-extension-header-is-refused',()=>{const b=frame({v6:true});b[20]=0;b[55]=255;reject(record(b),'ipv6-extension');});
test('tcp-header-length-must-fit-the-complete-ip-payload',()=>{for(const value of [0x40,0xf0]){const b=frame();b[46]=value;reject(record(b),'tcp-header');}});
test('udp-length-must-match-the-complete-ip-payload',()=>{for(const value of [0,7,9]){const b=frame({udp:true});b.writeUInt16BE(value,38);reject(record(b),'udp-length');}});
test('unsupported-ethernet-types-are-not-discarded',()=>{const b=frame();b.writeUInt16BE(0x0806,12);reject(record(b),'ethernet-type');});
test('one-or-two-vlan-tags-are-supported-and-third-refused',()=>{assert.equal(convertNdisFrames([record(vlan(frame()))]).summary.frames,1);assert.equal(convertNdisFrames([record(vlan(vlan(frame())))]).summary.frames,1);reject(record(vlan(vlan(vlan(frame())))),'ethernet-vlan');});
test('empty-nonarray-or-too-many-records-are-refused',()=>{for(const input of [[],null,{},Array(LIMITS.frames+1).fill(record())])assert.throws(()=>convertNdisFrames(input),e=>e.code==='record-bound');});
test('pcapng-total-byte-bound-includes-all-block-overhead',()=>{const b=frame({payload:65000}),r=record(b);assert.throws(()=>convertNdisFrames(Array(260).fill(r)),e=>e.code==='capture-bound');});
test('output-is-independent-of-later-input-buffer-mutation',()=>{const b=frame(),r=convertNdisFrames([record(b)]),copy=Buffer.from(r.capture);b.fill(0);assert.deepEqual(r.capture,copy);});
test('fixed-error-messages-and-summary-exclude-synthetic-private-data',()=>{try{convertNdisFrames([{private:'PRIVATE-SYNTHETIC'}]);}catch(e){assert.equal(e.message,'record-shape');}assert.equal(JSON.stringify(convertNdisFrames([record()]).summary).includes('PRIVATE-SYNTHETIC'),false);});

const {decodePrivateFrames,privateCapturePaths}=require('./ndis-private-convert.cjs');
function privateDocument(modern=false){const r=record();r.keywords=r.keywords.toString();r.fragment=r.fragment.toString('base64');if(modern){r.gftFlowEntryId='0';r.gftOffloadInformation='0';}return {schemaVersion:1,records:[r]};}
function rejectDocument(document,code){assert.throws(()=>decodePrivateFrames(document),e=>e instanceof FrameConversionError&&e.code===code);}
test('private-transport-preserves-typed-binary-and-modern-zero-fields',()=>{for(const modern of [false,true]){const records=decodePrivateFrames(privateDocument(modern));assert.equal(typeof records[0].keywords,'bigint');assert.deepEqual(records[0].fragment,frame());assert.equal(convertNdisFrames(records).summary.frames,1);}});
test('private-transport-refuses-extra-root-or-record-fields',()=>{rejectDocument({...privateDocument(),private:'PRIVATE-SYNTHETIC'},'private-document');const d=privateDocument();d.records[0].private='PRIVATE-SYNTHETIC';rejectDocument(d,'private-record');});
test('private-keywords-must-be-canonical-signed-decimal-strings',()=>{for(const value of [7516192768,'07516192768','-0','9223372036854775808','PRIVATE-SYNTHETIC']){const d=privateDocument();d.records[0].keywords=value;rejectDocument(d,'private-encoding');}});
test('private-offload-values-cannot-lose-integer-precision',()=>{for(const value of [0,'-1','18446744073709551616','00']){const d=privateDocument(true);d.records[0].gftOffloadInformation=value;rejectDocument(d,'private-encoding');}});
test('private-base64-must-be-canonical-and-bounded',()=>{for(const value of ['','PRIVATE-SYNTHETIC','A'.repeat(87384),frame().toString('base64')+'\n']){const d=privateDocument();d.records[0].fragment=value;rejectDocument(d,'private-encoding');}});
test('private-paths-are-fixed-under-the-exact-owned-local-root',()=>{const path=require('node:path').win32,local=path.join('C:','Users','Synthetic','AppData','Local'),root=path.join(local,'AccessWeaver-NetEventControl-'+'a'.repeat(32));const result=privateCapturePaths(root,local);assert.equal(result.input,path.join(root,'frames.json'));assert.equal(result.output,path.join(root,'capture.pcapng'));});
test('private-paths-refuse-other-roots-traversal-and-owner-patterns',()=>{const path=require('node:path').win32,local=path.join('C:','Users','Synthetic','AppData','Local'),owned=path.join(local,'AccessWeaver-NetEventControl-'+'a'.repeat(32));for(const root of [path.join('D:','AccessWeaver-NetEventControl-'+'a'.repeat(32)),path.join(local,'Other'),owned+path.sep+'..'+path.sep+'Other','relative'])assert.throws(()=>privateCapturePaths(root,local),e=>e.code==='private-path');});
test('private-bridge-import-does-not-consume-a-native-capture',()=>{const d=privateDocument();d.records=[];rejectDocument(d,'private-document');assert.equal(typeof privateCapturePaths,'function');});


const {fixedDohQuery,requestOptions,validateDohResponse,beginDohClose,fixedHttpDohRequest,readHttpDohReply}=require('./ndis-tls-control.cjs');
function dohReply(){const header=Buffer.alloc(12);header.writeUInt16BE(0x8180,2);header.writeUInt16BE(1,4);header.writeUInt16BE(1,6);const answer=Buffer.from('c00c000100010000012c0004c0000202','hex');return Buffer.concat([header,fixedDohQuery().subarray(12),answer]);}
const dohHeaders={'content-type':'application/dns-message'};
test('tls-stimulus-uses-fixed-endpoint-authenticated-tls-and-no-system-dns',()=>{const q=requestOptions();assert.equal(q.hostname,'8.8.8.8');assert.equal(q.servername,'dns.google');assert.equal(q.rejectUnauthorized,true);assert.equal(q.minVersion,'TLSv1.3');assert.equal(q.maxVersion,'TLSv1.3');assert.equal(q.path,'/dns-query');assert.equal(q.agent,false);assert.ok(q.ca.length>0);});
test('fixed-query-is-an-independent-bounded-synthetic-dns-message',()=>{const q=fixedDohQuery();assert.equal(q.length,29);assert.equal(q.readUInt16BE(4),1);q.fill(255);assert.equal(fixedDohQuery().readUInt16BE(0),0);});
test('authenticated-http-dns-response-requires-complete-positive-a-answer',()=>assert.equal(validateDohResponse(200,dohHeaders,dohReply()),true));
test('http-status-and-dns-media-type-errors-are-refused',()=>{assert.equal(validateDohResponse(302,dohHeaders,dohReply()),false);assert.equal(validateDohResponse(200,{'content-type':'text/html'},dohReply()),false);});
test('dns-response-id-question-and-error-flags-must-match',()=>{for(const offset of [0,3,4,13]){const b=dohReply();b[offset]^=1;assert.equal(validateDohResponse(200,dohHeaders,b),false);}const b=dohReply();b.writeUInt16BE(0x8182,2);assert.equal(validateDohResponse(200,dohHeaders,b),false);});
test('dns-response-truncation-trailing-data-or-missing-answer-is-refused',()=>{const b=dohReply();assert.equal(validateDohResponse(200,dohHeaders,b.subarray(0,-1)),false);assert.equal(validateDohResponse(200,dohHeaders,Buffer.concat([b,Buffer.from([0])])),false);b.writeUInt16BE(0,6);assert.equal(validateDohResponse(200,dohHeaders,b),false);});
test('dns-name-compression-loops-and-out-of-range-offsets-are-refused',()=>{for(const pointer of [0xc01d,0xffff]){const b=dohReply();b.writeUInt16BE(pointer,29);assert.equal(validateDohResponse(200,dohHeaders,b),false);}});
test('dns-response-size-and-record-count-are-bounded',()=>{assert.equal(validateDohResponse(200,dohHeaders,Buffer.alloc(4097)),false);const b=dohReply();b.writeUInt16BE(65,10);assert.equal(validateDohResponse(200,dohHeaders,b),false);});

test('tls-response-close-uses-graceful-end-without-forced-destroy',()=>{let ends=0,destroys=0;const socket={destroyed:false,writable:true,writableEnded:false,end(){ends++;this.writableEnded=true;},destroy(){destroys++;}};assert.equal(requestOptions().headers.Connection,'close');assert.equal(beginDohClose(socket),true);assert.equal(beginDohClose(socket),false);assert.equal(ends,1);assert.equal(destroys,0);assert.equal(beginDohClose({...socket,writableEnded:false,destroyed:true}),false);assert.equal(beginDohClose(null),false);});

function httpReply(body=dohReply(),extra=''){return Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: '+body.length+'\r\n'+extra+'\r\n','ascii'),body]);}
test('direct-tls-http-request-retains-exact-fixed-dns-body',()=>{const bytes=fixedHttpDohRequest(),cut=bytes.indexOf('\r\n\r\n');assert.ok(cut>0);assert.deepEqual(bytes.subarray(cut+4),fixedDohQuery());assert.ok(bytes.toString('ascii',0,cut).includes('Content-Length: 29'));assert.ok(bytes.toString('ascii',0,cut).startsWith('POST /dns-query HTTP/1.1\r\nHost: dns.google'));});
test('direct-tls-http-content-length-waits-for-complete-body',()=>{const bytes=httpReply();for(let at=0;at<bytes.length;at++)assert.equal(readHttpDohReply(bytes.subarray(0,at)),null);const r=readHttpDohReply(bytes);assert.equal(validateDohResponse(r.status,r.headers,r.body),true);assert.throws(()=>readHttpDohReply(bytes.subarray(0,-1),true));});
test('direct-tls-http-chunked-framing-is-complete-and-bounded',()=>{const body=dohReply(),bytes=Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n'+body.length.toString(16)+'\r\n'),body,Buffer.from('\r\n0\r\n\r\n')]);assert.deepEqual(readHttpDohReply(bytes).body,body);assert.equal(readHttpDohReply(bytes.subarray(0,-1)),null);assert.throws(()=>readHttpDohReply(bytes.subarray(0,-1),true));});
test('direct-tls-http-rejects-ambiguous-lengths-and-trailing-data',()=>{for(const bytes of [httpReply(dohReply(),'Content-Length: 45\r\n'),httpReply(dohReply(),'Transfer-Encoding: chunked\r\n'),Buffer.concat([httpReply(),Buffer.from([0])])])assert.throws(()=>readHttpDohReply(bytes));});
test('direct-tls-http-rejects-invalid-status-header-and-bounds',()=>{for(const bytes of [Buffer.from('HTTP/1.1 302 Found\r\n\r\n'),Buffer.from('HTTP/1.1 200 OK\r\n bad: x\r\n\r\n'),Buffer.alloc(16385),Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n')])assert.throws(()=>readHttpDohReply(bytes));assert.throws(()=>readHttpDohReply(Buffer.from('HTTP/1.1 200'),true));});
test('direct-tls-http-chunk-errors-never-become-complete-dns',()=>{for(const suffix of ['z\r\n','1001\r\n','1\r\nxXX','0\r\nX\r\n'])assert.throws(()=>readHttpDohReply(Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'+suffix),true));});
test('direct-tls-http-close-framing-requires-peer-end',()=>{const body=dohReply(),bytes=Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n'),body]);assert.equal(readHttpDohReply(bytes),null);const r=readHttpDohReply(bytes,true);assert.equal(validateDohResponse(r.status,r.headers,r.body),true);});

process.stdout.write(JSON.stringify({schemaVersion:1,scope:'pure-ndis-frame-converter',cases,passed:cases.every(c=>c.passed),nativeCaptureRead:false,productionQualificationComplete:false})+'\n');
if(cases.some(c=>!c.passed))process.exitCode=1;
