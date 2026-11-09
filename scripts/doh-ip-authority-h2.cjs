"use strict";
// Fixed-IP HTTP/2 prerequisite. Every started transport resource must close.
const tls=require('node:tls'),http2=require('node:http2'),os=require('node:os'),{X509Certificate}=require('node:crypto');
const {specFor,endpointOptions,emptyResult,hostedGuard,socketFailure}=require('./doh-ip-authority-control.cjs');
const {fixedDohQuery,validateDohResponse}=require('./ndis-tls-control.cjs');
const STATUSES=[200,301,302,303,307,308,400,401,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,421,425,426,429,431,451,500,501,502,503,504,505];
function emptyH2Result(ordinal,code='environment'){return {...emptyResult(ordinal,code),transport:'h2',sessionStarted:false,sessionClosed:false,sessionJoined:true,streamStarted:false,streamClosed:false,streamJoined:true};}
function requestHeaders(ordinal){return {':method':'POST',':scheme':'https',':authority':specFor(ordinal).address,':path':'/dns-query','accept':'application/dns-message','content-type':'application/dns-message','content-length':String(fixedDohQuery().length)};}
function sessionOptions(createConnection){return {createConnection,maxDeflateDynamicTableSize:0,maxSessionMemory:1,maxHeaderListPairs:64,maxOutstandingPings:1,maxSettings:16,settings:{enablePush:false,headerTableSize:0,initialWindowSize:16384,maxConcurrentStreams:1,maxHeaderListSize:8192}};}
function headerBudget(headers,allowStatus=true){
 if(headers===null||typeof headers!=='object'||Array.isArray(headers))throw new Error('headers');const keys=Object.keys(headers);if(keys.length>64)throw new Error('bound');let bytes=0,count=0;
 for(const key of keys){if(key.startsWith(':')){if(!allowStatus||key!==':status'||!Number.isInteger(headers[key]))throw new Error('headers');bytes+=key.length+3+32;count++;continue;}
  if(!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(key))throw new Error('headers');const values=Array.isArray(headers[key])?headers[key]:[headers[key]];if(values.length>64)throw new Error('bound');count+=values.length;if(count>64)throw new Error('bound');bytes+=(Buffer.byteLength(key)+32)*values.length;for(const value of values){if(typeof value!=='string')throw new Error('headers');bytes+=Buffer.byteLength(value);if(bytes>8192)throw new Error('bound');}
 }if(bytes>8192||count>64)throw new Error('bound');return {bytes,count};
}
const LIVE={connect:o=>tls.connect(o),session:(authority,o)=>http2.connect(authority,o),setTimer:(f,ms)=>setTimeout(f,ms),clearTimer:t=>clearTimeout(t),checkIdentity:(ip,c)=>tls.checkServerIdentity(ip,c),certificate:raw=>new X509Certificate(raw),roots:tls.rootCertificates};
async function runH2Endpoint(ordinal,dependencies=LIVE){
 const spec=specFor(ordinal),r=emptyH2Result(ordinal,'network');
 return await new Promise(resolve=>{
  let socket=null,session=null,stream=null,done=false,failure=null,identityChecked=false,sessionReady=false,deadline=null,responseHeaders=null,declaredLength=null,total=0,headerBytes=0,headerCount=0;const chunks=[];
  const finish=()=>{
   if(done)return;r.socketJoined=!r.socketStarted||r.closed;r.sessionJoined=!r.sessionStarted||r.sessionClosed;r.streamJoined=!r.streamStarted||r.streamClosed;
   if(!r.socketJoined||!r.sessionJoined||!r.streamJoined)return;done=true;if(deadline!==null)dependencies.clearTimer(deadline);
   const good=failure===null&&r.tlsAuthorized&&r.ipIdentityVerified&&r.responseValidated&&r.socketStarted&&r.closed&&r.peerEnded&&r.sessionStarted&&r.sessionClosed&&r.streamStarted&&r.streamClosed;r.outcome=good?'passed':'failed';r.code=good?'none':failure||'close';resolve(Object.freeze(r));
  };
  const stop=code=>{if(done)return;if(failure===null)failure=code;try{if(stream&&!r.streamClosed)stream.destroy();}catch{}try{if(session&&!r.sessionClosed)session.destroy();}catch{}try{if(socket&&!r.closed)socket.destroy();}catch{}finish();};
  const budget=(headers,allowStatus=true)=>{if(done||failure!==null)return false;try{const b=headerBudget(headers,allowStatus);headerBytes+=b.bytes;headerCount+=b.count;if(headerBytes>8192||headerCount>64)throw new Error('bound');return true;}catch(e){r.httpStage=e.message==='bound'?'header-bound':'headers';stop(e.message==='bound'?'bound':'http');return false;}};
  const beginRequest=()=>{
   if(done||failure!==null||!sessionReady||!r.tlsAuthorized||!r.ipIdentityVerified||r.streamStarted)return;
   try{
    stream=session.request(requestHeaders(ordinal),{endStream:false});r.streamStarted=true;
    stream.on('headers',headers=>{budget(headers);});
    stream.on('response',headers=>{
     if(done||failure!==null)return;     if(responseHeaders!==null){stop('http');return;}const status=headers&&headers[':status'];r.httpStatus=STATUSES.includes(status)?status:-1;r.httpStage=status===200?'headers':'status';
     if(!budget(headers))return;if(status!==200){stop('http');return;}
     const type=headers['content-type'],length=headers['content-length'];if(typeof type!=='string'||type.split(';')[0].trim().toLowerCase()!=='application/dns-message'){stop('response');return;}
     if(length!==undefined){if(typeof length!=='string'||!/^(0|[1-9][0-9]{0,3})$/.test(length)||Number(length)>4096){r.httpStage='length';stop('http');return;}declaredLength=Number(length);}
     responseHeaders={'content-type':type};r.httpStage='body';
    });
    stream.on('trailers',headers=>{budget(headers,false);});
    stream.on('data',chunk=>{if(done||failure!==null)return;total+=chunk.length;if(total>4096||chunks.length>=128){stop('bound');return;}chunks.push(chunk);});
    stream.on('end',()=>{
     if(done||failure!==null)return;if(responseHeaders===null||declaredLength!==null&&declaredLength!==total){r.httpStage='length';stop('http');return;}
     r.responseValidated=validateDohResponse(200,responseHeaders,Buffer.concat(chunks,total));if(!r.responseValidated){stop('response');return;}r.httpStage='complete';session.close();
    });
    stream.on('close',()=>{if(done)return;r.streamClosed=true;if(stream.rstCode!==0&&failure===null)stop('http');finish();});
    stream.on('error',()=>stop('http'));stream.on('aborted',()=>stop('http'));stream.on('frameError',()=>stop('http'));
    stream.end(fixedDohQuery());
   }catch{stop('http');}
  };
  const createConnection=()=>{
   if(socket!==null)throw new Error('extra-connection');const check=(_host,peer)=>{try{const error=dependencies.checkIdentity(spec.address,peer);identityChecked=error===undefined;return error;}catch{return new Error('identity-refused');}};
   socket=dependencies.connect({...endpointOptions(ordinal,check,dependencies.roots),ALPNProtocols:['h2']});r.socketStarted=true;
   socket.on('secureConnect',()=>{
    if(done||failure!==null)return;    r.tlsAuthorized=socket.authorized===true&&socket.getProtocol()==='TLSv1.3'&&socket.alpnProtocol==='h2';if(!r.tlsAuthorized){stop('tls');return;}
    try{const peer=socket.getPeerCertificate();if(!identityChecked||!Buffer.isBuffer(peer.raw)||peer.raw.length===0||peer.raw.length>32768){stop('identity');return;}const cert=dependencies.certificate(peer.raw);if(!cert.checkIP(spec.address)){stop('identity');return;}r.ipIdentityVerified=true;r.certificateMask=spec.mask;if(cert.checkIP(spec.peerIPv6))r.certificateMask|=spec.ipv6Mask;}catch{stop('identity');return;}beginRequest();
   });
   socket.on('end',()=>{if(done)return;r.peerEnded=true;});socket.on('close',hadError=>{if(done)return;r.closed=true;if(hadError&&failure===null)failure='network';finish();});socket.on('error',e=>stop(socketFailure(e)));return socket;
  };
  deadline=dependencies.setTimer(()=>stop('timeout'),8000);
  try{
   session=dependencies.session('https://'+spec.address,sessionOptions(createConnection));r.sessionStarted=true;
   session.on('connect',()=>{if(done||failure!==null)return;if(session.alpnProtocol!=='h2'){stop('tls');return;}sessionReady=true;beginRequest();});
   session.on('close',()=>{if(done)return;r.sessionClosed=true;finish();});session.on('error',()=>stop('http'));session.on('frameError',()=>stop('http'));
   session.on('goaway',code=>{if(code!==0)stop('http');});session.on('stream',pushed=>{pushed.on('error',()=>{});pushed.destroy();stop('bound');});
  }catch{stop('network');}
 });
}
module.exports={emptyH2Result,requestHeaders,sessionOptions,headerBudget,runH2Endpoint};
if(require.main===module){const ordinal=/^[01]$/.test(process.argv[2]||'')?Number(process.argv[2]):0;if(!hostedGuard(process.env,process.platform,os.machine(),process.version,process.arch,process.argv))process.stdout.write(JSON.stringify(emptyH2Result(ordinal))+'\n');else runH2Endpoint(ordinal).then(r=>process.stdout.write(JSON.stringify(r)+'\n'));}
