"use strict";
// Independent authenticated IP-authority prerequisite. Fixed targets only.
const tls=require('node:tls'),os=require('node:os'),{X509Certificate}=require('node:crypto');
const {fixedDohQuery,validateDohResponse,readHttpDohReply,beginDohClose}=require('./ndis-tls-control.cjs');
const SPECS=Object.freeze([
 Object.freeze({address:'8.8.8.8',peerIPv6:'2001:4860:4860::8888',mask:1,ipv6Mask:4}),
 Object.freeze({address:'9.9.9.9',peerIPv6:'2620:fe::fe',mask:2,ipv6Mask:8})
]);
function specFor(ordinal){if(!Number.isInteger(ordinal)||ordinal<0||ordinal>=SPECS.length)throw new Error('endpoint');return SPECS[ordinal];}
function requestBytes(ordinal){const s=specFor(ordinal),body=fixedDohQuery();return Buffer.concat([Buffer.from('POST /dns-query HTTP/1.1\r\nHost: '+s.address+'\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: '+body.length+'\r\nConnection: keep-alive\r\n\r\n','ascii'),body]);}
function noLookup(_name,_options,callback){callback(new Error('lookup-refused'));}
function endpointOptions(ordinal,checker,roots=tls.rootCertificates){const s=specFor(ordinal);return {host:s.address,port:443,family:4,servername:'',rejectUnauthorized:true,ca:roots,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['http/1.1'],allowHalfOpen:true,lookup:noLookup,checkServerIdentity:checker};}
function emptyResult(ordinal,code='environment'){const s=specFor(ordinal);return {schemaVersion:1,endpointMask:s.mask,outcome:'failed',code,tlsAuthorized:false,ipIdentityVerified:false,certificateMask:0,responseValidated:false,socketStarted:false,closed:false,peerEnded:false,socketJoined:true,productionQualificationComplete:false};}
function socketFailure(error){const code=error&&error.code;if(code==='ERR_TLS_CERT_ALTNAME_INVALID')return 'identity';if(['CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','UNABLE_TO_GET_ISSUER_CERT','ERR_TLS_CERT_SIGNATURE_ALGORITHM_UNSUPPORTED','ERR_TLS_INVALID_PROTOCOL_VERSION','ERR_SSL_WRONG_VERSION_NUMBER','ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION','ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE'].includes(code))return 'tls';return 'network';}
const LIVE={connect:options=>tls.connect(options),setTimer:(fn,ms)=>setTimeout(fn,ms),clearTimer:t=>clearTimeout(t),checkIdentity:(ip,peer)=>tls.checkServerIdentity(ip,peer),certificate:raw=>new X509Certificate(raw),roots:tls.rootCertificates};
async function runEndpoint(ordinal,dependencies=LIVE){
 const spec=specFor(ordinal),r=emptyResult(ordinal,'network');
 return await new Promise(resolve=>{
  let socket=null,done=false,failure=null,identityCallbackPassed=false,deadline=null,total=0;const chunks=[];
  const finish=()=>{if(done)return;done=true;if(deadline!==null)dependencies.clearTimer(deadline);r.socketJoined=!r.socketStarted||r.closed;const good=failure===null&&r.tlsAuthorized&&r.ipIdentityVerified&&r.responseValidated&&r.closed&&r.peerEnded;r.outcome=good?'passed':'failed';r.code=good?'none':failure||'close';resolve(Object.freeze(r));};
  const stop=code=>{if(failure===null)failure=code;if(socket)socket.destroy();else finish();};
  const inspect=ended=>{let reply;try{reply=readHttpDohReply(Buffer.concat(chunks,total),ended);}catch{stop('http');return;}if(!reply)return;r.responseValidated=validateDohResponse(reply.status,reply.headers,reply.body);if(!r.responseValidated){stop('response');return;}if(!socket.writableEnded&&!beginDohClose(socket,true))stop('close');};
  const check=(_hostname,peer)=>{try{const error=dependencies.checkIdentity(spec.address,peer);identityCallbackPassed=error===undefined;return error;}catch{return new Error('identity-refused');}};
  deadline=dependencies.setTimer(()=>stop('timeout'),8000);
  try{
   socket=dependencies.connect(endpointOptions(ordinal,check,dependencies.roots));r.socketStarted=true;
   socket.on('secureConnect',()=>{
    r.tlsAuthorized=socket.authorized===true&&socket.getProtocol()==='TLSv1.3'&&socket.alpnProtocol==='http/1.1';if(!r.tlsAuthorized){stop('tls');return;}
    try{const peer=socket.getPeerCertificate();if(!identityCallbackPassed||!Buffer.isBuffer(peer.raw)||peer.raw.length===0||peer.raw.length>32768){stop('identity');return;}const cert=dependencies.certificate(peer.raw);if(!cert.checkIP(spec.address)){stop('identity');return;}r.ipIdentityVerified=true;r.certificateMask=spec.mask;if(cert.checkIP(spec.peerIPv6))r.certificateMask|=spec.ipv6Mask;}
    catch{stop('identity');return;}
    socket.write(requestBytes(ordinal),error=>{if(error)stop('network');});
   });
   socket.on('data',chunk=>{total+=chunk.length;if(total>16384||chunks.length>=128){stop('bound');return;}chunks.push(chunk);inspect(false);});
   socket.on('end',()=>{r.peerEnded=true;inspect(true);});
   socket.on('close',hadError=>{r.closed=true;if(hadError&&failure===null)failure='network';finish();});
   socket.on('error',error=>stop(socketFailure(error)));
  }catch{stop('network');}
 });
}
function hostedGuard(environment,platform,machine,version,architecture,argv){const host={x86_64:'amd64',amd64:'amd64',arm64:'arm64',aarch64:'arm64'}[machine.toLowerCase()],arch={x64:'amd64',arm64:'arm64'}[architecture];return platform==='win32'&&version==='v26.8.2'&&environment.GITHUB_ACTIONS==='true'&&environment.RUNNER_ENVIRONMENT==='github-hosted'&&environment.RUNNER_OS==='Windows'&&/^[a-f0-9]{40}$/.test(environment.GITHUB_SHA||'')&&environment.ACCESSWEAVER_EXPECT_GOOS==='windows'&&arch===host&&arch===environment.ACCESSWEAVER_EXPECT_GOARCH&&argv.length===3&&/^[01]$/.test(argv[2])&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(environment,k));}
module.exports={specFor,requestBytes,endpointOptions,emptyResult,runEndpoint,hostedGuard,socketFailure};
if(require.main===module){const ordinal=/^[01]$/.test(process.argv[2]||'')?Number(process.argv[2]):0;if(!hostedGuard(process.env,process.platform,os.machine(),process.version,process.arch,process.argv))process.stdout.write(JSON.stringify(emptyResult(ordinal))+'\n');else runEndpoint(ordinal).then(r=>process.stdout.write(JSON.stringify(r)+'\n'));}
