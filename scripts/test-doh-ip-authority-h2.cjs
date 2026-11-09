"use strict";
// Pure fake resources: never connect to a network or query a certificate store.
const assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {runH2Endpoint,emptyH2Result,requestHeaders,sessionOptions,headerBudget}=require('./doh-ip-authority-h2.cjs');
const {specFor}=require('./doh-ip-authority-control.cjs');const {fixedDohQuery}=require('./ndis-tls-control.cjs');
function dnsResponse(){const b=Buffer.concat([fixedDohQuery(),Buffer.from('c00c000100010000003c0004c0000201','hex')]);b.writeUInt16BE(0x8180,2);b.writeUInt16BE(1,6);return b;}
function fake(ordinal=0,fault=''){
 const spec=specFor(ordinal),hooks={timer:null,requests:0,tlsOptions:null,sessionOptions:null,headers:null,clearCount:0,releaseAll:null,releaseSocket:null,releaseSession:null,releaseStream:null};let socket=null,session=null,stream=null,aborting=false;
 const closeStream=()=>{if(stream&&!stream.closed){stream.closed=true;stream.emit('close');}};
 const closeSocket=graceful=>{if(socket&&!socket.closed){if(graceful&&fault!=='no-peer-end')socket.emit('end');socket.closed=true;socket.emit('close',!graceful);}};
 const closeSession=()=>{if(session&&!session.closedEvent){session.closedEvent=true;session.emit('close');}};
 const closeAll=graceful=>{closeStream();closeSocket(graceful);closeSession();};
 const abort=()=>{if(aborting)return;aborting=true;if(fault==='defer-timeout'){hooks.releaseAll=()=>closeAll(false);return;}queueMicrotask(()=>closeAll(false));};
 const dependencies={roots:['synthetic-root'],setTimer:(fn,ms)=>{assert.equal(ms,8000);hooks.timer=fn;return 1;},clearTimer:()=>hooks.clearCount++,checkIdentity:ip=>{assert.equal(ip,spec.address);return fault==='identity'?new Error('PRIVATE-IDENTITY'):undefined;},certificate:()=>({checkIP:ip=>fault==='ip-san'?undefined:ip===spec.address||fault!=='no-ipv6'&&ip===spec.peerIPv6?ip:undefined}),connect:options=>{
  hooks.tlsOptions=options;if(fault==='socket-start')throw new Error('PRIVATE-PATH');socket=new EventEmitter();Object.assign(socket,{closed:false,authorized:fault!=='tls',alpnProtocol:fault==='alpn'?'http/1.1':'h2',getProtocol:()=>fault==='version'?'TLSv1.2':'TLSv1.3',getPeerCertificate:()=>({raw:Buffer.alloc(1)}),destroy:abort});return socket;
 },session:(authority,options)=>{
  assert.equal(authority,'https://'+spec.address);hooks.sessionOptions=options;if(fault==='session-start')throw new Error('PRIVATE-PATH');socket=options.createConnection();session=new EventEmitter();Object.assign(session,{closedEvent:false,alpnProtocol:'h2',destroy:abort});
  session.close=()=>{if(fault==='defer-success'){hooks.releaseSocket=()=>closeSocket(true);hooks.releaseSession=closeSession;hooks.releaseStream=closeStream;hooks.releaseAll=()=>closeAll(true);return;}queueMicrotask(()=>closeAll(true));};
  session.request=headers=>{
   hooks.requests++;assert.equal(hooks.requests,1);hooks.headers=headers;stream=new EventEmitter();Object.assign(stream,{closed:false,rstCode:0,destroy:abort});
   stream.end=body=>{assert(body.equals(fixedDohQuery()));queueMicrotask(()=>{
    if(aborting)return;if(fault==='stream-error'){stream.emit('error',new Error('PRIVATE'));return;}if(fault==='push'){const pushed=new EventEmitter();pushed.destroy=()=>{};session.emit('stream',pushed);return;}if(fault==='goaway'){session.emit('goaway',1);return;}
    const data=dnsResponse(),response={':status':fault==='redirect'?301:200,'content-type':fault==='mime'?'text/plain':'application/dns-message','content-length':String(fault==='length'?data.length+1:data.length)};
    if(fault==='headers-bound')response['x-padding']='x'.repeat(8193);stream.emit('response',response);if(aborting)return;
    if(fault==='body-bound')stream.emit('data',Buffer.alloc(4097));else if(fault==='chunks'){for(let i=0;i<129;i++)stream.emit('data',Buffer.alloc(0));}else stream.emit('data',fault==='dns'?Buffer.alloc(data.length):data);
    if(!aborting){if(fault==='trailers')stream.emit('trailers',{'x-fixed':'private-value'});stream.emit('end');}
   });};return stream;
  };
  if(!['timeout','defer-timeout'].includes(fault))queueMicrotask(()=>{options.createConnection=()=>{throw new Error('extra');};if(fault==='connect-first')session.emit('connect');hooks.tlsOptions.checkServerIdentity(spec.address,socket.getPeerCertificate());socket.emit('secureConnect');if(fault!=='connect-first'&&!aborting)session.emit('connect');});
  return session;
 }};return {dependencies,hooks};
}
const cases=[];async function test(name,body){let passed=true;try{await body();}catch{passed=false;}cases.push({name,passed});}
async function scenario(fault='',ordinal=0){const f=fake(ordinal,fault);return {r:await runH2Endpoint(ordinal,f.dependencies),...f};}
async function ready(f){for(let i=0;i<8&&!f.hooks.releaseAll;i++)await Promise.resolve();assert(f.hooks.releaseAll);}
(async()=>{
await test('h2-request-is-fixed-literal-authority-and-dns-message',()=>{for(const i of [0,1]){const h=requestHeaders(i);assert.equal(h[':authority'],specFor(i).address);assert.equal(h[':method'],'POST');assert.equal(h[':path'],'/dns-query');assert.equal(h['content-length'],String(fixedDohQuery().length));}});
await test('h2-session-limits-disable-push-and-bound-headers',()=>{const o=sessionOptions(()=>{});assert.equal(o.settings.enablePush,false);assert.equal(o.settings.maxHeaderListSize,8192);assert.equal(o.maxSessionMemory,1);assert.equal(o.maxHeaderListPairs,64);assert.equal(o.settings.maxConcurrentStreams,1);});
await test('h2-google-completes-authenticated-dns-and-all-resource-joins',async()=>{const {r,hooks}=await scenario();assert.equal(r.outcome,'passed');assert.equal(r.certificateMask,5);assert.equal(r.transport,'h2');assert(r.socketJoined&&r.sessionJoined&&r.streamJoined&&r.closed&&r.peerEnded&&r.sessionClosed&&r.streamClosed);assert.equal(hooks.clearCount,1);assert.equal(hooks.requests,1);});
await test('h2-quad9-retains-distinct-ip-certificate-coverage',async()=>{const {r}=await scenario('',1);assert.equal(r.outcome,'passed');assert.equal(r.certificateMask,10);});
await test('h2-custom-tls-retains-ca-ip-checks-and-no-sni-or-dns',async()=>{const {hooks}=await scenario();const o=hooks.tlsOptions;assert.equal(o.host,'8.8.8.8');assert.equal(o.servername,'');assert.equal(o.rejectUnauthorized,true);assert.deepEqual(o.ALPNProtocols,['h2']);assert.equal(o.minVersion,'TLSv1.3');assert.equal(o.maxVersion,'TLSv1.3');let refused;o.lookup('forbidden',{},e=>refused=e);assert(refused);});
await test('h2-session-connect-before-tls-cannot-bypass-identity-gating',async()=>{const {r,hooks}=await scenario('connect-first');assert.equal(r.outcome,'passed');assert.equal(hooks.requests,1);});
await test('h2-untrusted-tls-never-creates-request',async()=>{const {r,hooks}=await scenario('tls');assert.equal(r.code,'tls');assert.equal(hooks.requests,0);});
await test('h2-alpn-and-version-downgrades-refused',async()=>{for(const fault of ['alpn','version']){const {r,hooks}=await scenario(fault);assert.equal(r.code,'tls');assert.equal(hooks.requests,0);}});
await test('h2-ip-callback-and-san-mismatch-refused',async()=>{for(const fault of ['identity','ip-san']){const {r,hooks}=await scenario(fault);assert.equal(r.code,'identity');assert.equal(hooks.requests,0);}});
await test('h2-missing-ipv6-san-does-not-claim-full-certificate-coverage',async()=>{const {r}=await scenario('no-ipv6');assert.equal(r.outcome,'passed');assert.equal(r.certificateMask,1);});
await test('h2-redirect-is-not-followed',async()=>{const {r,hooks}=await scenario('redirect');assert.equal(r.code,'http');assert.equal(r.httpStatus,301);assert.equal(hooks.requests,1);assert(!r.responseValidated);});
await test('h2-invalid-content-type-and-dns-reply-refused',async()=>{for(const f of ['mime','dns']){const {r}=await scenario(f);assert.equal(r.code,'response');}});
await test('h2-declared-length-mismatch-refused',async()=>{const {r}=await scenario('length');assert.equal(r.code,'http');assert.equal(r.httpStage,'length');});
await test('h2-header-body-and-chunk-bounds-abort-and-join',async()=>{for(const f of ['headers-bound','body-bound','chunks']){const {r}=await scenario(f);assert.equal(r.code,'bound');assert(r.socketJoined&&r.sessionJoined&&r.streamJoined);}});
await test('h2-server-push-and-error-goaway-refused',async()=>{for(const f of ['push','goaway']){const {r}=await scenario(f);assert.equal(r.outcome,'failed');assert(r.socketJoined&&r.sessionJoined&&r.streamJoined);}});
await test('h2-stream-error-is-fixed-and-private-text-absent',async()=>{const {r}=await scenario('stream-error');assert.equal(r.code,'http');assert(!JSON.stringify(r).includes('PRIVATE'));});
await test('h2-deadline-destroys-and-joins-session-and-socket',async()=>{const f=fake(0,'timeout');const p=runH2Endpoint(0,f.dependencies);f.hooks.timer();const r=await p;assert.equal(r.code,'timeout');assert(r.socketJoined&&r.sessionJoined&&!r.streamStarted&&r.streamJoined);});
await test('h2-deadline-cannot-report-joined-before-close-events',async()=>{const f=fake(0,'defer-timeout');let settled=false;const p=runH2Endpoint(0,f.dependencies).then(r=>{settled=true;return r;});f.hooks.timer();await Promise.resolve();assert(!settled);f.hooks.releaseAll();const r=await p;assert(r.socketJoined&&r.sessionJoined);});
await test('h2-success-waits-for-main-stream-close-after-other-closes',async()=>{const f=fake(0,'defer-success');let settled=false;const p=runH2Endpoint(0,f.dependencies).then(r=>{settled=true;return r;});await ready(f);f.hooks.releaseSocket();f.hooks.releaseSession();await Promise.resolve();assert(!settled);f.hooks.releaseStream();assert.equal((await p).outcome,'passed');});
await test('h2-success-waits-for-session-close-after-other-closes',async()=>{const f=fake(0,'defer-success');let settled=false;const p=runH2Endpoint(0,f.dependencies).then(r=>{settled=true;return r;});await ready(f);f.hooks.releaseStream();f.hooks.releaseSocket();await Promise.resolve();assert(!settled);f.hooks.releaseSession();assert.equal((await p).outcome,'passed');});
await test('h2-peer-tcp-end-is-required-for-success',async()=>{const {r}=await scenario('no-peer-end');assert.equal(r.code,'close');assert(!r.peerEnded);});
await test('h2-start-failures-have-no-unjoined-resources',async()=>{for(const f of ['session-start','socket-start']){const {r}=await scenario(f);assert.equal(r.outcome,'failed');assert(r.socketJoined&&r.sessionJoined&&r.streamJoined);assert(!JSON.stringify(r).includes('PRIVATE'));}});
await test('h2-bounded-trailers-do-not-replace-response-metadata',async()=>{const {r}=await scenario('trailers');assert.equal(r.outcome,'passed');assert(!JSON.stringify(r).includes('private-value'));assert.throws(()=>headerBudget({':status':200},false));});
await test('h2-public-report-closes-resource-fields-without-private-data',async()=>{const {r}=await scenario();assert.equal(Object.keys(r).length,22);assert.equal(Object.keys(r).length,Object.keys(emptyH2Result(0)).length);assert.equal(r.productionQualificationComplete,false);for(const k of ['headers','certificate','address','path','error','body'])assert(!Object.hasOwn(r,k));assert(Object.isFrozen(r));});
await test('h2-header-budget-counts-repeated-fields-and-rfc-overhead',()=>{assert.throws(()=>headerBudget({':status':200,'set-cookie':Array(64).fill('x')}),/bound/);assert.throws(()=>headerBudget({'set-cookie':Array(64).fill('x'),':status':200}),/bound/);const r=headerBudget({':status':200,'x-fixed':['a','b']});assert.equal(r.count,3);assert(r.bytes>=96);});
const passed=cases.length===25&&cases.every(c=>c.passed);process.stdout.write(JSON.stringify({schemaVersion:1,scope:'pure-h2-ip-authority-contracts',cases,passed,nativeNetworkUsed:false,productionQualificationComplete:false})+'\n');if(!passed)process.exitCode=1;
})();
