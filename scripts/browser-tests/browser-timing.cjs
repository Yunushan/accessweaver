// Fixed numeric phase attribution for disposable browser fixtures only.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto');
const phases=['navigationMs','applicationMs','paintMs'];
const editorFields=['actionMs','visibilityMs','paintMs','totalMs'];
const stages=['environment','startup','dashboard','reload','navigation','editor','burst','load','cooldown','resources','job-cpu','complete'];
const failures=['none','Error','TypeError','ReferenceError','TimeoutError','AssertionError','AbortError','Other'];
const sources=['scripts/browser-tests/browser-timing.cjs','scripts/browser-tests/browser-timing.test.cjs','scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/soak.config.cjs','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/package-lock.json','internal/uiaccess/launcher.go','internal/api/server.go','web/app.js','web/system.js','web/locales.js','web/index.html','web/app.css','.github/workflows/browser-soak.yml'];
function empty(){return {dashboard:Object.fromEntries(phases.map(k=>[k,null])),editor:[]}}
function validate(value){
 assert.deepEqual(Object.keys(value).sort(),['dashboard','editor']);assert.deepEqual(Object.keys(value.dashboard).sort(),[...phases].sort());
 const numeric=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER;
 assert.ok(Object.values(value.dashboard).every(n=>n===null||numeric(n)));assert.ok(Array.isArray(value.editor)&&value.editor.length<=10);
 for(const row of value.editor){assert.deepEqual(Object.keys(row).sort(),[...editorFields].sort());assert.ok(Object.values(row).every(numeric));assert.ok(Math.abs(row.totalMs-row.actionMs-row.visibilityMs-row.paintMs)<1e-6)}
}
async function hash(file,maximum){const fd=await fs.open(file,'r');try{const before=await fd.stat();assert.ok(before.isFile()&&before.size>0&&before.size<=maximum);const h=createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;for(;;){const {bytesRead}=await fd.read(buffer,0,Math.min(buffer.length,maximum-total+1),null);if(!bytesRead)break;total+=bytesRead;assert.ok(total<=maximum);h.update(buffer.subarray(0,bytesRead))}const after=await fd.stat();assert.ok(total===before.size&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs);return h.digest('hex')}finally{await fd.close()}}
async function writeReport(repo,source,binarySHA256,project,architecture,stage,failureKind,value){
 validate(value);assert.ok(/^[a-f0-9]{40}$/.test(source)&&/^[a-f0-9]{64}$/.test(binarySHA256)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture)&&stages.includes(stage)&&failures.includes(failureKind));
 const snapshot={dashboard:{...value.dashboard},editor:value.editor.map(row=>({...row}))},sourceSHA256={};for(const name of sources)sourceSHA256[name]=await hash(path.join(repo,name),1<<20);assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binarySHA256);
 const data={schemaVersion:1,sourceCommit:source,sourceSHA256,binarySHA256,project,architecture,mode:'diagnostic-only',stage,failureKind,...snapshot,complete:Object.values(snapshot.dashboard).every(n=>n!==null)&&snapshot.editor.length===10,productionQualificationComplete:false};const encoded=JSON.stringify(data)+'\n';assert.ok(Buffer.byteLength(encoded)<=16384);
 const parent=path.join(repo,'build/browser-timing');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),real=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===await fs.realpath(path.join(repo,'build')));const fd=await fs.open(path.join(real,'status.json'),'wx',0o600);try{await fd.writeFile(encoded,'utf8')}finally{await fd.close()}
}
module.exports={phases,editorFields,stages,failures,sources,empty,validate,writeReport};
