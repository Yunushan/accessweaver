#!/usr/bin/env node
'use strict';
// Independent loopback wire fixtures for the actual authenticated portable CLI.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const net=require('node:net');
const tls=require('node:tls');
const dgram=require('node:dgram');
const {createHash}=require('node:crypto');
const {spawn}=require('node:child_process');
const {validateBuild}=require('./check-native-environment.cjs');
const executable=path.resolve(process.argv[2]);
const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'accessweaver-packaged-diagnostics-'));
const userState=path.join(workspace,'must-not-create-state');
const fixtureErrors=[],cleanups=[],checks=[];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
class Wire {
 constructor(socket){this.socket=socket;this.buffer=Buffer.alloc(0);this.iterator=socket[Symbol.asyncIterator]();}
 async bytes(n){while(this.buffer.length<n){const next=await this.iterator.next();assert(!next.done,'truncated client protocol');this.buffer=Buffer.concat([this.buffer,next.value]);assert(this.buffer.length<=16384,'excessive client fixture data');}const result=this.buffer.subarray(0,n);this.buffer=this.buffer.subarray(n);return result;}
 async address(){const type=(await this.bytes(1))[0];let host;if(type===1)host=[...await this.bytes(4)].join('.');else if(type===3){const size=(await this.bytes(1))[0];host=(await this.bytes(size)).toString('ascii');}else throw Error('unsupported fixture destination type');return {host,port:(await this.bytes(2)).readUInt16BE()};}
}
async function tcpServer(handler,options){
 const sockets=new Set();
 const accept=socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));socket.setTimeout(7000,()=>socket.destroy());Promise.resolve(handler(socket)).catch(error=>{fixtureErrors.push(error.message);socket.destroy();});};
 const server=options?tls.createServer(options,accept):net.createServer(accept);
 if(options)server.on('tlsClientError',()=>{});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 cleanups.push(async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));});
 return server.address().port;
}
async function udpServer(handler){
 const socket=dgram.createSocket('udp4');socket.on('error',error=>fixtureErrors.push(error.message));
 socket.on('message',(message,peer)=>{try{assert.equal(peer.address,'127.0.0.1');handler(message,reply=>socket.send(reply,peer.port,peer.address));}catch(error){fixtureErrors.push(error.message);}});
 await new Promise((resolve,reject)=>{socket.once('error',reject);socket.bind(0,'127.0.0.1',resolve);});
 cleanups.push(()=>new Promise(resolve=>socket.close(resolve)));return socket.address().port;
}
function bindingReply(request){
 assert.equal(request.length,20);assert.equal(request.readUInt16BE(0),1);assert.equal(request.readUInt16BE(2),0);assert.equal(request.readUInt32BE(4),0x2112a442);
 const reply=Buffer.alloc(32);reply.writeUInt16BE(0x0101,0);reply.writeUInt16BE(12,2);reply.writeUInt32BE(0x2112a442,4);request.copy(reply,8,8,20);
 reply.writeUInt16BE(0x0020,20);reply.writeUInt16BE(8,22);reply[25]=1;reply.writeUInt16BE(49152^0x2112,26);
 for(let i=0;i<4;i++)reply[28+i]=[203,0,113,7][i]^[0x21,0x12,0xa4,0x42][i];return reply;
}
async function cli(args,success){
 const env={...process.env,ACCESSWEAVER_HOME:userState};delete env.GH_TOKEN;delete env.GITHUB_TOKEN;
 const child=spawn(executable,args,{env,windowsHide:true,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
 const collect=(key,data)=>{if(key==='out')stdout+=data;else stderr+=data;if(stdout.length+stderr.length>1<<20)child.kill();};
 child.stdout.on('data',data=>collect('out',data));child.stderr.on('data',data=>collect('err',data));
 const timer=setTimeout(()=>child.kill(),12000);
 const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);}).finally(()=>clearTimeout(timer));
 if(success)assert.equal(code,0,stderr);else assert.notEqual(code,0,'failed probe returned success');
 assert(stdout.length+stderr.length<=1<<20,'excessive CLI output');
 return JSON.parse(stdout);
}
async function probe(name,args,success,expectedPath,transport='tcp'){
 const report=await cli(['doctor',...args],success);
 assert.equal(report.path,expectedPath);assert.equal(report.transport,transport);assert(report.checks.length>0);
 assert.equal(report.checks.every(c=>c.status==='ok'),success);assert.deepEqual(fixtureErrors,[]);
 checks.push({name,passed:true,path:report.path,transport:report.transport});return report;
}
(async()=>{
 try {
  const hash=sha(fs.readFileSync(executable)),build=await cli(['version','--json'],true);
  validateBuild(build,{goos:process.env.ACCESSWEAVER_EXPECT_GOOS,goarch:process.env.ACCESSWEAVER_EXPECT_GOARCH,goVersion:process.env.GO_VERSION,commit:process.env.GITHUB_SHA||''});
  let targetConnections=0;
  const target=await tcpServer(()=>{targetConnections++;});
  await probe('direct loopback TCP',['--tls=false','--port',String(target),'127.0.0.1'],true,'direct');
  const tlsPort=await tcpServer(()=>{}, {key:fs.readFileSync(path.join(__dirname,'fixtures/diagnostic-tls/server-key.pem')),cert:fs.readFileSync(path.join(__dirname,'fixtures/diagnostic-tls/server-cert.pem'))});
  const rejected=await probe('untrusted TLS certificate',['--port',String(tlsPort),'127.0.0.1'],false,'direct');
  assert.equal(rejected.checks.at(-1).name,'TLS');
  for(const mode of ['socks5','http-connect']){
   const proxy=await tcpServer(async socket=>{
    const wire=new Wire(socket);
    if(mode==='socks5'){
     assert.deepEqual([...await wire.bytes(3)],[5,1,0]);socket.write(Buffer.from([5,0]));assert.deepEqual([...await wire.bytes(3)],[5,1,0]);
     assert.deepEqual(await wire.address(),{host:'target.invalid',port:target});
    }else{
     let header='';while(!header.endsWith('\r\n\r\n')){header+=(await wire.bytes(1)).toString('ascii');assert(header.length<=16384);}
     assert.equal(header.split('\r\n')[0],`CONNECT target.invalid:${target} HTTP/1.1`);
    }
    const remote=net.connect({host:'127.0.0.1',port:target});remote.on('error',error=>fixtureErrors.push(error.message));socket.on('close',()=>remote.destroy());
    await new Promise(resolve=>remote.once('connect',resolve));
    socket.write(mode==='socks5'?Buffer.from([5,0,0,1,127,0,0,1,0,1]):'HTTP/1.1 200 Connection Established\r\n\r\n');
    await new Promise(resolve=>socket.once('end',resolve));remote.destroy();
   });
   await probe(mode+' tunnel',['--tls=false','--path',mode,'--proxy','127.0.0.1:'+proxy,'--port',String(target),'target.invalid'],true,mode);
  }
  assert.equal(targetConnections,3,'selected proxy paths did not reach the controlled target');
  const denied=await tcpServer(async socket=>{const wire=new Wire(socket);let header='';while(!header.endsWith('\r\n\r\n')){header+=(await wire.bytes(1)).toString('ascii');assert(header.length<=16384);}socket.write('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');});
  const failed=await probe('HTTP proxy refusal',['--tls=false','--path','http-connect','--proxy','127.0.0.1:'+denied,'target.invalid'],false,'http-connect');assert.equal(failed.checks.at(-1).name,'Proxy');
  const stun=await udpServer((request,send)=>send(bindingReply(request)));
  await probe('direct UDP/STUN',['--transport','stun','--port',String(stun),'127.0.0.1'],true,'direct','stun');
  const invalid=await udpServer((request,send)=>{const reply=bindingReply(request);reply[8]^=1;send(reply);});
  await probe('mismatched STUN transaction',['--transport','stun','--port',String(invalid),'127.0.0.1'],false,'direct','stun');
  const silent=await udpServer(()=>{});
  await probe('bounded UDP timeout',['--transport','stun','--timeout','1','--port',String(silent),'127.0.0.1'],false,'direct','stun');
  const udpProxy=await udpServer((packet,send)=>{
   assert.deepEqual([...packet.subarray(0,4)],[0,0,0,3]);const length=packet[4],host=packet.subarray(5,5+length).toString('ascii'),port=packet.readUInt16BE(5+length);
   assert.equal(host,'stun.target.invalid');assert.equal(port,3478);
   const reply=bindingReply(packet.subarray(7+length));send(Buffer.concat([packet.subarray(0,7+length),reply]));
  });
  const association=await tcpServer(async socket=>{const wire=new Wire(socket);assert.deepEqual([...await wire.bytes(3)],[5,1,0]);socket.write(Buffer.from([5,0]));assert.deepEqual([...await wire.bytes(3)],[5,3,0]);assert.deepEqual(await wire.address(),{host:'0.0.0.0',port:0});socket.write(Buffer.from([5,0,0,1,127,0,0,1,udpProxy>>8,udpProxy&255]));await new Promise(resolve=>socket.once('end',resolve));});
  await probe('SOCKS5 UDP association',['--transport','stun','--path','socks5','--proxy','127.0.0.1:'+association,'stun.target.invalid'],true,'socks5','stun');
  assert(!fs.existsSync(userState),'diagnostics created profile state');assert.equal(sha(fs.readFileSync(executable)),hash,'candidate changed during diagnostics');assert.deepEqual(fixtureErrors,[]);
  const evidence={sourceCommit:process.env.GITHUB_SHA||'unknown',platform:process.platform,arch:build.arch,build,binarySha256:hash,checks,loopbackOnly:true,settingsChanged:false,productionQualificationComplete:false};
  const directory=path.resolve('build','packaged-native-checks');fs.mkdirSync(directory,{recursive:true});fs.writeFileSync(path.join(directory,'diagnostics-'+build.platform+'-'+build.arch+'.json'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify(evidence));
 }finally{
  for(const cleanup of cleanups.reverse())await cleanup();
  const absolute=path.resolve(workspace);assert.equal(path.dirname(absolute),path.resolve(os.tmpdir()));assert(path.basename(absolute).startsWith('accessweaver-packaged-diagnostics-'));assert(!fs.lstatSync(absolute).isSymbolicLink());fs.rmSync(absolute,{recursive:true,force:true});
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
