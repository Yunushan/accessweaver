'use strict';
// One fixed public synthetic DoH request. No configurable endpoint or credentials.
const tls=require('node:tls'),os=require('node:os');
const QUERY='000001000001000000000000076578616d706c6503636f6d0000010001';
function fixedDohQuery(){return Buffer.from(QUERY,'hex');}
function requestOptions(){return {hostname:'8.8.8.8',port:443,family:4,servername:'dns.google',rejectUnauthorized:true,ca:tls.rootCertificates,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['http/1.1'],method:'POST',path:'/dns-query',agent:false,headers:{Host:'dns.google',Accept:'application/dns-message','Content-Type':'application/dns-message','Content-Length':fixedDohQuery().length,Connection:'keep-alive'}};}
function dnsName(bytes,start){
 let at=start,next=null,jumps=0;const labels=[],seen=new Set();
 while(true){
  if(at>=bytes.length||seen.has(at)||++jumps>128)return null;seen.add(at);const size=bytes[at];
  if((size&0xc0)===0xc0){if(at+2>bytes.length)return null;const target=((size&63)<<8)|bytes[at+1];if(target<12||target>=at)return null;if(next===null)next=at+2;at=target;continue;}
  if(size&0xc0||size>63||at+1+size>bytes.length)return null;at++;if(size===0)return {next:next===null?at:next,name:labels.join('.').toLowerCase()};
  const label=bytes.subarray(at,at+size);if(label.some(c=>c<33||c>126))return null;labels.push(label.toString('ascii'));at+=size;
 }
}
function validateDohResponse(status,headers,body){
 if(status!==200||headers===null||typeof headers!=='object'||typeof headers['content-type']!=='string'||headers['content-type'].split(';')[0].trim().toLowerCase()!=='application/dns-message'||!Buffer.isBuffer(body)||body.length>4096||body.length<fixedDohQuery().length)return false;
 const query=fixedDohQuery(),flags=body.readUInt16BE(2),answers=body.readUInt16BE(6),authority=body.readUInt16BE(8),additional=body.readUInt16BE(10);
 if(body.readUInt16BE(0)!==0||(flags&0xf800)!==0x8000||(flags&0x024f)!==0||body.readUInt16BE(4)!==1||answers<1||answers>16||answers+authority+additional>64||!body.subarray(12,query.length).equals(query.subarray(12)))return false;
 let at=query.length,found=false;
 for(let i=0;i<answers+authority+additional;i++){
  const name=dnsName(body,at);if(!name)return false;at=name.next;if(at+10>body.length)return false;
  const type=body.readUInt16BE(at),klass=body.readUInt16BE(at+2),size=body.readUInt16BE(at+8);at+=10;if(at+size>body.length)return false;
  if(i<answers&&type===1&&klass===1&&size===4&&name.name==='example.com')found=true;at+=size;
 }
 return found&&at===body.length;
}
function beginDohClose(socket,responseComplete=false){if(!responseComplete||!socket||socket.destroyed||!socket.writable||socket.writableEnded)return false;socket.end();return true;}

function fixedHttpDohRequest(){const q=requestOptions();return Buffer.concat([Buffer.from(q.method+' '+q.path+' HTTP/1.1\r\n'+Object.entries(q.headers).map(([k,v])=>k+': '+v+'\r\n').join('')+'\r\n','ascii'),fixedDohQuery()]);}
function readHttpDohReply(bytes,ended=false){
 const need=ok=>{if(!ok)throw new Error('http-response');};need(Buffer.isBuffer(bytes)&&bytes.length<=16384);
 const cut=bytes.indexOf('\r\n\r\n');if(cut<0){need(bytes.length<=8192&&!ended);return null;}need(cut<=8192);
 const headerBytes=bytes.subarray(0,cut);need(!headerBytes.some(c=>c>126||(c<32&&![9,10,13].includes(c))));const lines=headerBytes.toString('ascii').split('\r\n');need(lines.length<=65&&/^HTTP\/1\.[01] 200(?: [ -~]*)?$/.test(lines[0]));const headers=Object.create(null);
 for(const line of lines.slice(1)){const colon=line.indexOf(':');need(colon>0);const key=line.slice(0,colon).toLowerCase(),value=line.slice(colon+1).trim();need(/^[!#$%&'*+.^_\x60|~0-9a-z-]+$/.test(key)&&!Object.hasOwn(headers,key));headers[key]=value;}
 const start=cut+4,length=headers['content-length'],transfer=headers['transfer-encoding'];need(length===undefined||transfer===undefined);
 if(length!==undefined){need(/^(0|[1-9][0-9]{0,3})$/.test(length));const size=Number(length);need(size<=4096&&bytes.length-start<=size);if(bytes.length-start<size){need(!ended);return null;}return {status:200,headers,body:bytes.subarray(start)};}
 if(transfer!==undefined){
  need(transfer.toLowerCase()==='chunked');let at=start,total=0;const chunks=[];
  for(let count=0;count<128;count++){
   const lineEnd=bytes.indexOf('\r\n',at);if(lineEnd<0){need(!ended&&bytes.length-at<=16);return null;}need(lineEnd-at<=4&&/^[0-9a-fA-F]{1,4}$/.test(bytes.toString('ascii',at,lineEnd)));const size=Number.parseInt(bytes.toString('ascii',at,lineEnd),16);at=lineEnd+2;need(size<=4096-total);
   if(bytes.length-at<size+2){need(!ended);return null;}need(bytes[at+size]===13&&bytes[at+size+1]===10);
   if(size===0){need(at+2===bytes.length);return {status:200,headers,body:Buffer.concat(chunks,total)};}
   chunks.push(bytes.subarray(at,at+size));total+=size;at+=size+2;
  };need(false);
 }
 need(bytes.length-start<=4096);if(!ended)return null;return {status:200,headers,body:bytes.subarray(start)};
}
async function runFixedDohStimulus(){
 return await new Promise(resolve=>{
  let socket=null,done=false,authorized=false,validated=false,closed=false,peerEnded=false,failure=null,total=0;const chunks=[];
  const finish=()=>{if(done)return;done=true;clearTimeout(deadline);const good=failure===null&&authorized&&validated&&closed&&peerEnded;resolve({schemaVersion:1,outcome:good?'passed':'failed',code:good?'none':failure||'close',tlsAuthorized:authorized,responseValidated:validated,closed,productionQualificationComplete:false});};
  const stop=code=>{if(failure===null)failure=code;if(socket)socket.destroy();else finish();};
  const inspect=ended=>{try{const r=readHttpDohReply(Buffer.concat(chunks,total),ended);if(!r)return;validated=validateDohResponse(r.status,r.headers,r.body);if(!validated)stop('response');else if(!socket.writableEnded&&!beginDohClose(socket,validated))stop('close');}catch{stop('response');}};
  const deadline=setTimeout(()=>{stop('timeout');finish();},8000);
  try{
   const q=requestOptions();socket=tls.connect({host:q.hostname,port:q.port,family:q.family,servername:q.servername,rejectUnauthorized:q.rejectUnauthorized,ca:q.ca,minVersion:q.minVersion,maxVersion:q.maxVersion,ALPNProtocols:q.ALPNProtocols,allowHalfOpen:true});
   socket.on('secureConnect',()=>{authorized=socket.authorized===true&&socket.getProtocol()==='TLSv1.3'&&socket.alpnProtocol==='http/1.1';if(!authorized)stop('tls');else socket.write(fixedHttpDohRequest());});
   socket.on('data',chunk=>{total+=chunk.length;if(total>16384||chunks.length>=128){stop('bound');return;}chunks.push(chunk);inspect(false);});
   socket.on('end',()=>{peerEnded=true;inspect(true);});
   socket.on('close',hadError=>{closed=true;if(hadError&&failure===null)failure='network';finish();});
   socket.on('error',()=>stop('network'));
  }catch{stop('network');}
 });
}
module.exports={fixedDohQuery,requestOptions,validateDohResponse,beginDohClose,fixedHttpDohRequest,readHttpDohReply};

if(require.main===module){
 const arch={x64:'amd64',arm64:'arm64'}[process.arch],host={x86_64:'amd64',amd64:'amd64',arm64:'arm64',aarch64:'arm64'}[os.machine().toLowerCase()];
 const guarded=process.platform==='win32'&&process.version==='v26.8.2'&&process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||'')&&process.env.ACCESSWEAVER_EXPECT_GOOS==='windows'&&arch===host&&arch===process.env.ACCESSWEAVER_EXPECT_GOARCH&&process.argv.length===2&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(process.env,k));
 if(!guarded)process.stdout.write(JSON.stringify({schemaVersion:1,outcome:'failed',code:'environment',tlsAuthorized:false,responseValidated:false,closed:false,productionQualificationComplete:false})+'\n');
 else runFixedDohStimulus().then(r=>process.stdout.write(JSON.stringify(r)+'\n'));
}
