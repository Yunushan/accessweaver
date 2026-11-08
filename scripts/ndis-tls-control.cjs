'use strict';
// One fixed public synthetic DoH request. No configurable endpoint or credentials.
const https=require('node:https'),tls=require('node:tls'),os=require('node:os');
const QUERY='000001000001000000000000076578616d706c6503636f6d0000010001';
function fixedDohQuery(){return Buffer.from(QUERY,'hex');}
function requestOptions(){return {hostname:'8.8.8.8',port:443,family:4,servername:'dns.google',rejectUnauthorized:true,ca:tls.rootCertificates,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['http/1.1'],method:'POST',path:'/dns-query',agent:false,headers:{Host:'dns.google',Accept:'application/dns-message','Content-Type':'application/dns-message','Content-Length':fixedDohQuery().length,Connection:'close'}};}
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
async function runFixedDohStimulus(){
 return await new Promise(resolve=>{
  let request=null,socket=null,response=null,done=false,authorized=false,validated=false,closed=false,failure=null,total=0;const chunks=[];
  const finish=()=>{if(done)return;done=true;clearTimeout(deadline);const good=failure===null&&authorized&&validated&&closed;resolve({schemaVersion:1,outcome:good?'passed':'failed',code:good?'none':failure||'close',tlsAuthorized:authorized,responseValidated:validated,closed,productionQualificationComplete:false});};
  const stop=code=>{if(failure===null)failure=code;if(response)response.destroy();if(request)request.destroy();if(socket)socket.destroy();if(!socket)finish();};
  const deadline=setTimeout(()=>{stop('timeout');finish();},8000);
  try{
   request=https.request(requestOptions(),res=>{
    response=res;
    res.on('data',chunk=>{total+=chunk.length;if(total>4096||chunks.length>=128){stop('bound');return;}chunks.push(chunk);});
    res.on('end',()=>{validated=validateDohResponse(res.statusCode,res.headers,Buffer.concat(chunks,total));if(!validated)stop('response');else if(closed)finish();});
    res.on('error',()=>stop('network'));
   });
   request.on('socket',s=>{socket=s;s.on('secureConnect',()=>{authorized=s.authorized===true&&s.getProtocol()==='TLSv1.3';if(!authorized)stop('tls');});s.on('close',()=>{closed=true;finish();});s.on('error',()=>{if(failure===null)failure='network';});});
   request.on('error',()=>stop('network'));request.end(fixedDohQuery());
  }catch{stop('network');}
 });
}
module.exports={fixedDohQuery,requestOptions,validateDohResponse};
if(require.main===module){
 const arch={x64:'amd64',arm64:'arm64'}[process.arch],host={x86_64:'amd64',amd64:'amd64',arm64:'arm64',aarch64:'arm64'}[os.machine().toLowerCase()];
 const guarded=process.platform==='win32'&&process.version==='v26.8.2'&&process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||'')&&process.env.ACCESSWEAVER_EXPECT_GOOS==='windows'&&arch===host&&arch===process.env.ACCESSWEAVER_EXPECT_GOARCH&&process.argv.length===2&&['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'].every(k=>!Object.hasOwn(process.env,k));
 if(!guarded)process.stdout.write(JSON.stringify({schemaVersion:1,outcome:'failed',code:'environment',tlsAuthorized:false,responseValidated:false,closed:false,productionQualificationComplete:false})+'\n');
 else runFixedDohStimulus().then(r=>process.stdout.write(JSON.stringify(r)+'\n'));
}
