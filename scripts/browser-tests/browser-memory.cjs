// Fixed numeric diagnostics only. Never retain proc headers, addresses or PIDs.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto');
const phases=['dashboard','reload','navigation','editor','burst','load','cooldown'];
const mappedFields=['mappedRssBytes','pssBytes','privateBytes','sharedBytes','anonymousBytes','swapBytes','pssAnonBytes','pssFileBytes','pssShmemBytes'];
const groupFields=['processes','statRssBytes','largestProcessRssBytes','readable','denied','unavailable',...mappedFields];
const sources=['scripts/browser-tests/browser-memory.cjs','scripts/browser-tests/browser-resources.cjs','scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/performance-budgets.json','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/package-lock.json','web/app.js','web/app.css','web/index.html','.github/workflows/browser.yml'];
function emptyGroup(){return Object.fromEntries(groupFields.map(k=>[k,0]))}
function parseSmaps(raw){
 assert.ok(typeof raw==='string'&&Buffer.byteLength(raw)<=16384,'Owned memory input budget differs');
 const keys=['Rss','Pss','Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Anonymous','Swap','Pss_Anon','Pss_File','Pss_Shmem'],values={};
 for(const line of raw.split('\n')){
  const name=line.match(/^([A-Za-z_]+):/)?.[1];if(!keys.includes(name))continue;
  const match=line.match(/^([A-Za-z_]+):\s+([0-9]+) kB\s*$/);assert.ok(match&&!Object.hasOwn(values,name),'Owned memory counter shape differs');
  const n=Number(match[2])*1024;assert.ok(Number.isSafeInteger(n)&&n>=0,'Owned memory counter range differs');values[name]=n;
 }
 assert.deepEqual(Object.keys(values).sort(),[...keys].sort(),'Owned memory counter set differs');
 const result={mappedRssBytes:values.Rss,pssBytes:values.Pss,privateBytes:values.Private_Clean+values.Private_Dirty,sharedBytes:values.Shared_Clean+values.Shared_Dirty,anonymousBytes:values.Anonymous,swapBytes:values.Swap,pssAnonBytes:values.Pss_Anon,pssFileBytes:values.Pss_File,pssShmemBytes:values.Pss_Shmem};
 assert.ok(Object.values(result).every(Number.isSafeInteger),'Owned memory aggregate range differs');return result;
}
function validatePoints(points){
 assert.ok(Array.isArray(points)&&points.length<=phases.length,'Owned memory phase budget differs');
 for(let i=0;i<points.length;i++){
  const point=points[i];assert.deepEqual(Object.keys(point).sort(),['phase','root','descendants'].sort());assert.equal(point.phase,phases[i],'Owned memory phase order differs');
  for(const role of ['root','descendants']){
   const group=point[role];assert.deepEqual(Object.keys(group).sort(),[...groupFields].sort());assert.ok(Object.values(group).every(n=>Number.isSafeInteger(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER),'Owned memory numeric schema differs');
   assert.ok(group.processes<=(role==='root'?1:63)&&group.readable+group.denied+group.unavailable===group.processes,'Owned memory coverage differs');
   assert.ok(group.largestProcessRssBytes<=group.statRssBytes,'Owned memory largest-process counter differs');
   if(!group.readable)assert.ok(mappedFields.every(k=>group[k]===0),'Unread mapping totals must be empty');
  }
 }
}
async function hash(file,maximum){
 const fd=await fs.open(file,'r');try{const before=await fd.stat();assert.ok(before.isFile()&&before.size>0&&before.size<=maximum,'Memory evidence input differs');const buffer=Buffer.alloc(65536),digest=createHash('sha256');let total=0;
 for(;;){const {bytesRead}=await fd.read(buffer,0,Math.min(buffer.length,maximum-total+1),null);if(!bytesRead)break;total+=bytesRead;assert.ok(total<=maximum,'Memory evidence input grew');digest.update(buffer.subarray(0,bytesRead))}
 const after=await fd.stat();assert.ok(total===before.size&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs,'Memory evidence input changed');return digest.digest('hex')}finally{await fd.close()}
}
async function writeMemoryReport(repo,source,binaryHash,project,architecture,points){
 assert.ok(/^[0-9a-f]{40}$/.test(source)&&/^[0-9a-f]{64}$/.test(binaryHash)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture),'Owned memory identity differs');validatePoints(points);
 const snapshot=points.map(p=>({phase:p.phase,root:{...p.root},descendants:{...p.descendants}})),sourceSHA256={};for(const name of sources)sourceSHA256[name]=await hash(path.join(repo,name),1<<20);
 assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binaryHash,'Memory controller binary changed');
 const data={schemaVersion:1,sourceCommit:source,sourceSHA256,binarySHA256:binaryHash,project,architecture,mode:'diagnostic-only',complete:snapshot.length===phases.length,points:snapshot,productionQualificationComplete:false};
 const encoded=JSON.stringify(data)+'\n';assert.ok(Buffer.byteLength(encoded)<=32768,'Memory report budget differs');
 const parent=path.join(repo,'build/browser-memory');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),resolved=await fs.realpath(parent),build=await fs.realpath(path.join(repo,'build'));assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(resolved)===build,'Memory report parent differs');
 const file=await fs.open(path.join(resolved,'status.json'),'wx',0o600);try{await file.writeFile(encoded,'utf8')}finally{await file.close()}
}
module.exports={phases,mappedFields,groupFields,sources,emptyGroup,parseSmaps,validatePoints,writeMemoryReport};
