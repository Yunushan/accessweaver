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
const HTTP_STATUSES=Object.freeze([200,301,302,303,307,308,400,401,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,421,425,426,429,431,451,500,501,502,503,504,505]);
function httpDiagnostic(bytes){
 const r={status:0,stage:'incomplete'};if(!Buffer.isBuffer(bytes)||bytes.length>16384)return {status:0,stage:'body'};const cut=bytes.indexOf('\r\n\r\n');if(cut<0)return bytes.length>8192?{status:0,stage:'header-bound'}:r;if(cut>8192)return {status:0,stage:'header-bound'};
 const head=bytes.subarray(0,cut);if(head.some(c=>c>126||(c<32&&![9,10,13].includes(c))))return {status:0,stage:'headers'};const lines=head.toString('ascii').split('\r\n'),match=/^HTTP\/1\.[01] ([1-5][0-9]{2})(?: [ -~]*)?$/.exec(lines[0]);if(!match)return {status:0,stage:'headers'};const status=Number(match[1]);r.status=HTTP_STATUSES.includes(status)?status:-1;if(status!==200){r.stage='status';return r;}if(lines.length>65){r.stage='header-bound';return r;}
 const headers=Object.create(null);for(const line of lines.slice(1)){const colon=line.indexOf(':');if(colon<=0){r.stage='headers';return r;}const key=line.slice(0,colon).toLowerCase();if(!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(key)){r.stage='headers';return r;}if(Object.hasOwn(headers,key)){r.stage='duplicate-header';return r;}headers[key]=line.slice(colon+1).trim();}
 const length=headers['content-length'],transfer=headers['transfer-encoding'];r.stage=length!==undefined&&transfer!==undefined?'framing':length!==undefined&&!/^(0|[1-9][0-9]{0,3})$/.test(length)?'length':transfer!==undefined&&transfer.toLowerCase()!=='chunked'?'transfer':'body';return r;
}
function emptyResult(ordinal,code='environment'){const s=specFor(ordinal);return {schemaVersion:1,endpointMask:s.mask,outcome:'failed',code,httpStatus:0,httpStage:'not-inspected',tlsAuthorized:false,ipIdentityVerified:false,certificateMask:0,responseValidated:false,socketStarted:false,closed:false,peerEnded:false,socketJoined:true,productionQualificationComplete:false};}
function socketFailure(error){const code=error&&error.code;if(code==='ERR_TLS_CERT_ALTNAME_INVALID')return 'identity';if(['CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','UNABLE_TO_GET_ISSUER_CERT','ERR_TLS_CERT_SIGNATURE_ALGORITHM_UNSUPPORTED','ERR_TLS_INVALID_PROTOCOL_VERSION','ERR_SSL_WRONG_VERSION_NUMBER','ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION','ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE'].includes(code))return 'tls';return 'network';}
const LIVE={connect:options=>tls.connect(options),setTimer:(fn,ms)=>setTimeout(fn,ms),clearTimer:t=>clearTimeout(t),checkIdentity:(ip,peer)=>tls.checkServerIdentity(ip,peer),certificate:raw=>new X509Certificate(raw),roots:tls.rootCertificates};
async function runEndpoint(ordinal,dependencies=LIVE){
 const spec=specFor(ordinal),r=emptyResult(ordinal,'network');
 return await new Promise(resolve=>{
  let socket=null,done=false,failure=null,identityCallbackPassed=false,deadline=null,total=0;const chunks=[];
  const finish=()=>{if(done)return;done=true;if(deadline!==null)dependencies.clearTimer(deadline);r.socketJoined=!r.socketStarted||r.closed;const good=failure===null&&r.tlsAuthorized&&r.ipIdentityVerified&&r.responseValidated&&r.closed&&r.peerEnded;r.outcome=good?'passed':'failed';r.code=good?'none':failure||'close';resolve(Object.freeze(r));};
  const stop=code=>{if(failure===null)failure=code;if(socket)socket.destroy();else finish();};
  const inspect=ended=>{let reply;const bytes=Buffer.concat(chunks,total),diagnostic=httpDiagnostic(bytes);r.httpStatus=diagnostic.status;r.httpStage=diagnostic.stage;try{reply=readHttpDohReply(bytes,ended);}catch{stop('http');return;}if(!reply)return;r.httpStage='complete';r.responseValidated=validateDohResponse(reply.status,reply.headers,reply.body);if(!r.responseValidated){stop('response');return;}if(!socket.writableEnded&&!beginDohClose(socket,true))stop('close');};
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
module.exports={specFor,requestBytes,endpointOptions,emptyResult,runEndpoint,hostedGuard,socketFailure,httpDiagnostic};
if(require.main===module){const ordinal=/^[01]$/.test(process.argv[2]||'')?Number(process.argv[2]):0;if(!hostedGuard(process.env,process.platform,os.machine(),process.version,process.arch,process.argv))process.stdout.write(JSON.stringify(emptyResult(ordinal))+'\n');else runEndpoint(ordinal).then(r=>process.stdout.write(JSON.stringify(r)+'\n'));}
