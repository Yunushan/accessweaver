// Fixed numeric phase attribution for disposable browser fixtures only.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto');
const phases=['navigationMs','applicationMs','paintMs'];
const editorFields=['actionMs','visibilityMs','paintMs','totalMs'];
const stages=['environment','startup','dashboard','reload','navigation','editor','burst','load','cooldown','resources','job-cpu','complete'];
const failures=['none','Error','TypeError','ReferenceError','TimeoutError','AssertionError','AbortError','Other'];
const sources=['scripts/browser-tests/browser-timing.cjs','scripts/browser-tests/browser-timing.test.cjs','scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/soak.config.cjs','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/package-lock.json','internal/uiaccess/launcher.go','internal/api/server.go','web/app.js','web/system.js','web/locales.js','web/index.html','web/app.css','.github/workflows/browser-soak.yml'];
const startupLabels=['bootstrap','engines','profiles','runtime','appScript','systemScript','localesScript','stylesheet'];
function empty(){return {dashboard:Object.fromEntries(phases.map(k=>[k,null])),editor:[],startup:null}}
// Serialized into the isolated page. Return only this closed numeric projection;
// names, origins, fragments, headers and response bodies never cross back.
function captureStartup(){
 const routes={'/api/bootstrap':'bootstrap','/api/v1/engines':'engines','/api/v1/profiles':'profiles','/api/v1/runtime':'runtime','/app.js':'appScript','/system.js':'systemScript','/locales.js':'localesScript','/app.css':'stylesheet'};
 const all=performance.getEntriesByType('resource'),nav=performance.getEntriesByType('navigation')[0],observedMs=performance.now(),resources=Object.fromEntries(Object.values(routes).map(label=>[label,null]));let invalidRecords=0;
 for(const entry of all.slice(0,512)){
  if(typeof entry.name!=='string'||entry.name.length>2048)continue;let url;try{url=new URL(entry.name)}catch{continue}
  if(url.origin!==location.origin||url.username||url.password||url.search||url.hash||!Object.hasOwn(routes,url.pathname))continue;
  const row={startMs:entry.startTime,firstByteMs:entry.responseStart,endMs:entry.responseEnd};
  if(!Object.values(row).every(n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=observedMs)||row.firstByteMs<row.startMs||row.endMs<row.firstByteMs){invalidRecords++;continue}
  const label=routes[url.pathname];if(resources[label]===null||row.startMs<resources[label].startMs)resources[label]=row;
 }
 return {observedMs,domContentLoadedMs:nav?.domContentLoadedEventEnd??null,resourceOverflow:all.length>512,invalidRecords,resources};
}
function startupComplete(value){return value!==null&&!value.resourceOverflow&&value.invalidRecords===0&&value.domContentLoadedMs!==null&&value.domContentLoadedMs>0&&Object.values(value.resources).every(row=>row!==null)}
function validate(value){
 assert.deepEqual(Object.keys(value).sort(),['dashboard','editor','startup']);assert.deepEqual(Object.keys(value.dashboard).sort(),[...phases].sort());
 const numeric=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER;
 assert.ok(Object.values(value.dashboard).every(n=>n===null||numeric(n)));assert.ok(Array.isArray(value.editor)&&value.editor.length<=10);
 for(const row of value.editor){assert.deepEqual(Object.keys(row).sort(),[...editorFields].sort());assert.ok(Object.values(row).every(numeric));assert.ok(Math.abs(row.totalMs-row.actionMs-row.visibilityMs-row.paintMs)<1e-6)}
 if(value.startup!==null){const v=value.startup;assert.deepEqual(Object.keys(v).sort(),['domContentLoadedMs','invalidRecords','observedMs','resourceOverflow','resources']);assert.ok(numeric(v.observedMs)&&(v.domContentLoadedMs===null||numeric(v.domContentLoadedMs)&&v.domContentLoadedMs<=v.observedMs)&&typeof v.resourceOverflow==='boolean'&&Number.isSafeInteger(v.invalidRecords)&&v.invalidRecords>=0&&v.invalidRecords<=512);assert.deepEqual(Object.keys(v.resources).sort(),[...startupLabels].sort());for(const row of Object.values(v.resources)){if(row===null)continue;assert.deepEqual(Object.keys(row).sort(),['endMs','firstByteMs','startMs']);assert.ok(Object.values(row).every(numeric)&&row.startMs<=row.firstByteMs&&row.firstByteMs<=row.endMs&&row.endMs<=v.observedMs)}}
}
async function hash(file,maximum){const fd=await fs.open(file,'r');try{const before=await fd.stat();assert.ok(before.isFile()&&before.size>0&&before.size<=maximum);const h=createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;for(;;){const {bytesRead}=await fd.read(buffer,0,Math.min(buffer.length,maximum-total+1),null);if(!bytesRead)break;total+=bytesRead;assert.ok(total<=maximum);h.update(buffer.subarray(0,bytesRead))}const after=await fd.stat();assert.ok(total===before.size&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs);return h.digest('hex')}finally{await fd.close()}}
async function writeReport(repo,source,binarySHA256,project,architecture,stage,failureKind,value){
 validate(value);assert.ok(/^[a-f0-9]{40}$/.test(source)&&/^[a-f0-9]{64}$/.test(binarySHA256)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture)&&stages.includes(stage)&&failures.includes(failureKind));
 const snapshot={dashboard:{...value.dashboard},editor:value.editor.map(row=>({...row})),startup:value.startup===null?null:{...value.startup,resources:Object.fromEntries(Object.entries(value.startup.resources).map(([key,row])=>[key,row===null?null:{...row}]))}},sourceSHA256={};for(const name of sources)sourceSHA256[name]=await hash(path.join(repo,name),1<<20);assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binarySHA256);
 const data={schemaVersion:2,sourceCommit:source,sourceSHA256,binarySHA256,project,architecture,mode:'diagnostic-only',stage,failureKind,...snapshot,complete:Object.values(snapshot.dashboard).every(n=>n!==null)&&snapshot.editor.length===10&&startupComplete(snapshot.startup),productionQualificationComplete:false};const encoded=JSON.stringify(data)+'\n';assert.ok(Buffer.byteLength(encoded)<=16384);
 const parent=path.join(repo,'build/browser-timing');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),real=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===await fs.realpath(path.join(repo,'build')));const fd=await fs.open(path.join(real,'status.json'),'wx',0o600);try{await fd.writeFile(encoded,'utf8')}finally{await fd.close()}
}
module.exports={phases,editorFields,stages,failures,sources,empty,validate,writeReport,captureStartup,startupComplete,startupLabels};
