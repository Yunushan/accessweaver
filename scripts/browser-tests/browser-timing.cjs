// Fixed numeric phase attribution for disposable browser fixtures only.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto');
const {usageBetween}=require('./job-cpu.cjs');
const phases=['navigationMs','applicationMs','paintMs'];
const editorFields=['actionMs','visibilityMs','paintMs','totalMs'];
const stages=['environment','startup','dashboard','reload','navigation','editor','burst','load','cooldown','resources','job-cpu','complete'];
const failures=['none','Error','TypeError','ReferenceError','TimeoutError','AssertionError','AbortError','Other'];
const sources=['scripts/browser-tests/job-cpu.cjs','scripts/browser-tests/job-cpu.test.cjs','scripts/browser-tests/browser-timing.cjs','scripts/browser-tests/browser-timing.test.cjs','scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/soak.config.cjs','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/package-lock.json','internal/uiaccess/launcher.go','internal/api/server.go','web/app.js','web/system.js','web/locales.js','web/index.html','web/app.css','.github/workflows/browser-soak.yml'];
const startupLabels=['bootstrap','engines','profiles','runtime','appScript','systemScript','localesScript','stylesheet'];
function empty(){return {dashboard:Object.fromEntries(phases.map(k=>[k,null])),editor:[],startup:null,startupJobCpu:null}}
// Serialized into the isolated page. Return only this closed numeric projection;
// names, origins, fragments, headers and response bodies never cross back.
// Installed before navigation in the selected disposable fixture. The exact
// production readiness predicate is supplied as source by the harness. No state,
// DOM nodes or mutation records leave this observer; only bounded clock values.
function installStartupClock(predicate,count){
 function context(){
  let visibility='unknown',focused=null;
  try{const value=document.visibilityState;if(['visible','hidden','prerender'].includes(value))visibility=value}catch{}
  try{if(typeof document.hasFocus==='function'){const value=document.hasFocus();if(typeof value==='boolean')focused=value}}catch{}
  return {visibility,focused};
 }
 const value={clock:'performance-now-callback-delivery',status:'pending',firstReadyMs:null,readyPaintMs:null,framesAfterReady:0,firstFrameMs:null,lastFrameMs:null,frameCount:0,maxFrameGapMs:0,callbacks:0,stoppedMs:null,context:{start:context(),ready:null,stop:null}};
 let observer=null,frame=null,timer=null,stopped=false;
 function finish(){
  if(!stopped){stopped=true;observer?.disconnect();observer=null;if(frame!==null)cancelAnimationFrame(frame);frame=null;if(timer!==null)clearTimeout(timer);timer=null;value.context.stop=context();value.stoppedMs=performance.now()}
  return {...value,context:{start:{...value.context.start},ready:value.context.ready===null?null:{...value.context.ready},stop:value.context.stop===null?null:{...value.context.stop}}};
 }
 Object.defineProperty(globalThis,'__accessweaverStartupClock',{value:Object.freeze({finish}),configurable:false});
 if(typeof MutationObserver!=='function'||typeof requestAnimationFrame!=='function'||typeof cancelAnimationFrame!=='function'){value.status='unavailable';finish();return}
 function check(){
  if(stopped||value.status==='ready')return;
  if(value.callbacks===4096){value.status='overflow';finish();return}value.callbacks++;
  // A global lexical state can be in its temporal dead zone while the app
  // script is being initialized. No exception text crosses this boundary.
  let ready=false;try{ready=predicate(count)===true}catch{}
  if(ready){value.firstReadyMs=performance.now();value.context.ready=context();value.status='ready';observer?.disconnect();observer=null}
 }
 function tick(){
  if(stopped)return;
  // Animation timestamps and performance.now can use different rounding. All
  // diagnostic delivery/readiness samples use performance.now consistently.
  const at=performance.now();
  if(typeof at!=='number'||!Number.isFinite(at)||at<0||(value.lastFrameMs!==null&&at<value.lastFrameMs)){value.status='invalid';finish();return}
  if(value.frameCount===4096){value.status='overflow';finish();return}
  const gap=value.lastFrameMs===null?at:at-value.lastFrameMs;value.maxFrameGapMs=Math.max(value.maxFrameGapMs,gap);if(value.firstFrameMs===null)value.firstFrameMs=at;value.lastFrameMs=at;value.frameCount++;if(value.firstReadyMs!==null&&at>=value.firstReadyMs){value.framesAfterReady++;if(value.framesAfterReady===2){value.readyPaintMs=at;finish();return}}frame=requestAnimationFrame(tick);
 }
 observer=new MutationObserver(check);observer.observe(document,{subtree:true,childList:true,characterData:true});
 frame=requestAnimationFrame(tick);timer=setTimeout(()=>{if(value.status==='pending')value.status='timeout';finish()},10000);check();
}
function captureStartup(){
 const routes={'/api/bootstrap':'bootstrap','/api/v1/engines':'engines','/api/v1/profiles':'profiles','/api/v1/runtime':'runtime','/app.js':'appScript','/system.js':'systemScript','/locales.js':'localesScript','/app.css':'stylesheet'};
 const readyObservation=typeof globalThis.__accessweaverStartupClock?.finish==='function'?globalThis.__accessweaverStartupClock.finish():null;
 const all=performance.getEntriesByType('resource'),nav=performance.getEntriesByType('navigation')[0],observedMs=performance.now(),resources=Object.fromEntries(Object.values(routes).map(label=>[label,null]));let invalidRecords=0;
 for(const entry of all.slice(0,512)){
  if(typeof entry.name!=='string'||entry.name.length>2048)continue;let url;try{url=new URL(entry.name)}catch{continue}
  if(url.origin!==location.origin||url.username||url.password||url.search||url.hash||!Object.hasOwn(routes,url.pathname))continue;
  const row={startMs:entry.startTime,firstByteMs:entry.responseStart,endMs:entry.responseEnd};
  if(!Object.values(row).every(n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=observedMs)||row.firstByteMs<row.startMs||row.endMs<row.firstByteMs){invalidRecords++;continue}
  const label=routes[url.pathname];if(resources[label]===null||row.startMs<resources[label].startMs)resources[label]=row;
 }
 return {observedMs,domContentLoadedMs:nav?.domContentLoadedEventEnd??null,resourceOverflow:all.length>512,invalidRecords,resources,readyObservation};
}
function startupComplete(value){return value!==null&&!value.resourceOverflow&&value.invalidRecords===0&&value.domContentLoadedMs!==null&&value.domContentLoadedMs>0&&Object.values(value.resources).every(row=>row!==null)&&value.readyObservation!==null&&value.readyObservation.status==='ready'&&value.readyObservation.firstReadyMs!==null&&value.readyObservation.frameCount>=2&&value.readyObservation.readyPaintMs!==null&&value.readyObservation.framesAfterReady===2&&Object.values(value.readyObservation.context).every(c=>c!==null&&c.visibility!=='unknown'&&typeof c.focused==='boolean')}
function startupCpuInterval(before,after){
 const left={},right={};for(const key of ['usageUsec','userUsec','systemUsec']){assert.ok(Number.isSafeInteger(before[key])&&before[key]>=0&&Number.isSafeInteger(after[key])&&after[key]>=before[key]);left[key]=before[key];right[key]=after[key]}
 left.finishedMilliseconds=before.finishedMilliseconds;right.startedMilliseconds=after.startedMilliseconds;
 const usage=usageBetween(left,right);return {scope:'isolated-job-cgroup-v2',intervalMilliseconds:usage.milliseconds,cpuMicroseconds:right.usageUsec-left.usageUsec,userMicroseconds:right.userUsec-left.userUsec,systemMicroseconds:right.systemUsec-left.systemUsec,percentOneCore:usage.percentOneCore};
}
function validate(value){
 assert.deepEqual(Object.keys(value).sort(),['dashboard','editor','startup','startupJobCpu']);assert.deepEqual(Object.keys(value.dashboard).sort(),[...phases].sort());
 const numeric=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER;
 assert.ok(Object.values(value.dashboard).every(n=>n===null||numeric(n)));assert.ok(Array.isArray(value.editor)&&value.editor.length<=10);
 for(const row of value.editor){assert.deepEqual(Object.keys(row).sort(),[...editorFields].sort());assert.ok(Object.values(row).every(numeric));assert.ok(Math.abs(row.totalMs-row.actionMs-row.visibilityMs-row.paintMs)<1e-6)}
 if(value.startup!==null){const v=value.startup;assert.deepEqual(Object.keys(v).sort(),['domContentLoadedMs','invalidRecords','observedMs','readyObservation','resourceOverflow','resources']);assert.ok(numeric(v.observedMs)&&(v.domContentLoadedMs===null||numeric(v.domContentLoadedMs)&&v.domContentLoadedMs<=v.observedMs)&&typeof v.resourceOverflow==='boolean'&&Number.isSafeInteger(v.invalidRecords)&&v.invalidRecords>=0&&v.invalidRecords<=512);assert.deepEqual(Object.keys(v.resources).sort(),[...startupLabels].sort());for(const row of Object.values(v.resources)){if(row===null)continue;assert.deepEqual(Object.keys(row).sort(),['endMs','firstByteMs','startMs']);assert.ok(Object.values(row).every(numeric)&&row.startMs<=row.firstByteMs&&row.firstByteMs<=row.endMs&&row.endMs<=v.observedMs)}
  if(v.readyObservation!==null){const r=v.readyObservation;assert.deepEqual(Object.keys(r).sort(),['callbacks','clock','context','firstFrameMs','firstReadyMs','frameCount','framesAfterReady','lastFrameMs','maxFrameGapMs','readyPaintMs','status','stoppedMs']);assert.equal(r.clock,'performance-now-callback-delivery');assert.ok(['pending','ready','timeout','overflow','invalid','unavailable'].includes(r.status));for(const key of ['firstReadyMs','readyPaintMs','firstFrameMs','lastFrameMs'])assert.ok(r[key]===null||numeric(r[key])&&r[key]<=r.stoppedMs);assert.ok(numeric(r.stoppedMs)&&r.stoppedMs<=v.observedMs&&numeric(r.maxFrameGapMs)&&r.maxFrameGapMs<=r.stoppedMs);for(const key of ['callbacks','frameCount'])assert.ok(Number.isSafeInteger(r[key])&&r[key]>=0&&r[key]<=4096);assert.ok((r.frameCount===0)===(r.firstFrameMs===null&&r.lastFrameMs===null));if(r.frameCount>0)assert.ok(r.firstFrameMs!==null&&r.lastFrameMs!==null&&r.firstFrameMs<=r.lastFrameMs);if(r.status==='ready')assert.ok(r.firstReadyMs!==null);assert.ok(Number.isSafeInteger(r.framesAfterReady)&&r.framesAfterReady>=0&&r.framesAfterReady<=2&&r.framesAfterReady<=r.frameCount);assert.equal(r.readyPaintMs!==null,r.framesAfterReady===2);if(r.readyPaintMs!==null)assert.ok(r.status==='ready'&&r.firstReadyMs!==null&&r.readyPaintMs>=r.firstReadyMs&&r.readyPaintMs===r.lastFrameMs);if(r.firstReadyMs===null)assert.equal(r.framesAfterReady,0);assert.deepEqual(Object.keys(r.context).sort(),['ready','start','stop']);for(const key of ['start','ready','stop']){const c=r.context[key];if(key==='ready'&&c===null)continue;assert.ok(c!==null);assert.deepEqual(Object.keys(c).sort(),['focused','visibility']);assert.ok(['visible','hidden','prerender','unknown'].includes(c.visibility)&&(c.focused===null||typeof c.focused==='boolean'))}assert.equal(r.context.ready!==null,r.firstReadyMs!==null)}
 }

 if(value.startupJobCpu!==null){const c=value.startupJobCpu;assert.deepEqual(Object.keys(c).sort(),['cpuMicroseconds','intervalMilliseconds','percentOneCore','scope','systemMicroseconds','userMicroseconds']);assert.equal(c.scope,'isolated-job-cgroup-v2');assert.ok(numeric(c.intervalMilliseconds)&&c.intervalMilliseconds>0&&numeric(c.percentOneCore));for(const key of ['cpuMicroseconds','userMicroseconds','systemMicroseconds'])assert.ok(Number.isSafeInteger(c[key])&&c[key]>=0&&c[key]<=Number.MAX_SAFE_INTEGER);assert.ok(Math.abs(c.percentOneCore-c.cpuMicroseconds/1000/c.intervalMilliseconds*100)<1e-6)}
}
async function hash(file,maximum){const fd=await fs.open(file,'r');try{const before=await fd.stat();assert.ok(before.isFile()&&before.size>0&&before.size<=maximum);const h=createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;for(;;){const {bytesRead}=await fd.read(buffer,0,Math.min(buffer.length,maximum-total+1),null);if(!bytesRead)break;total+=bytesRead;assert.ok(total<=maximum);h.update(buffer.subarray(0,bytesRead))}const after=await fd.stat();assert.ok(total===before.size&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs);return h.digest('hex')}finally{await fd.close()}}
async function writeReport(repo,source,binarySHA256,project,architecture,stage,failureKind,value){
 validate(value);assert.ok(/^[a-f0-9]{40}$/.test(source)&&/^[a-f0-9]{64}$/.test(binarySHA256)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture)&&stages.includes(stage)&&failures.includes(failureKind));
 const snapshot={startupJobCpu:value.startupJobCpu===null?null:{...value.startupJobCpu},dashboard:{...value.dashboard},editor:value.editor.map(row=>({...row})),startup:value.startup===null?null:{...value.startup,readyObservation:value.startup.readyObservation===null?null:{...value.startup.readyObservation,context:{start:{...value.startup.readyObservation.context.start},ready:value.startup.readyObservation.context.ready===null?null:{...value.startup.readyObservation.context.ready},stop:{...value.startup.readyObservation.context.stop}}},resources:Object.fromEntries(Object.entries(value.startup.resources).map(([key,row])=>[key,row===null?null:{...row}]))}},sourceSHA256={};for(const name of sources)sourceSHA256[name]=await hash(path.join(repo,name),1<<20);assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binarySHA256);
 const data={schemaVersion:5,sourceCommit:source,sourceSHA256,binarySHA256,project,architecture,mode:'diagnostic-only',stage,failureKind,...snapshot,complete:Object.values(snapshot.dashboard).every(n=>n!==null)&&snapshot.editor.length===10&&startupComplete(snapshot.startup)&&snapshot.startupJobCpu!==null,productionQualificationComplete:false};const encoded=JSON.stringify(data)+'\n';assert.ok(Buffer.byteLength(encoded)<=16384);
 const parent=path.join(repo,'build/browser-timing');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),real=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===await fs.realpath(path.join(repo,'build')));const fd=await fs.open(path.join(real,'status.json'),'wx',0o600);try{await fd.writeFile(encoded,'utf8')}finally{await fd.close()}
}
module.exports={phases,editorFields,stages,failures,sources,empty,validate,writeReport,captureStartup,startupComplete,startupLabels,installStartupClock,startupCpuInterval};
