// Closed numeric diagnostics for canonical, owned SVG fixtures only.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto');
const sizes=[15,18,33],themes=['dark','light'];
const sources=['scripts/browser-tests/svg-geometry.cjs','scripts/browser-tests/svg-geometry.test.cjs','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/suite-status-reporter.cjs','scripts/browser-tests/package-lock.json','web/index.html','web/app.js','web/app.css','.github/workflows/browser.yml'];
const fields=['glyph','theme','size','shapeCount','hasUse','styleMask','direct','reference','directFill','referenceFill','directStroke','referenceStroke'];
function validate(value){
 assert.deepEqual(Object.keys(value).sort(),['glyphCount','rows']);assert.ok(Number.isSafeInteger(value.glyphCount)&&value.glyphCount>=0&&value.glyphCount<=64);assert.ok(Array.isArray(value.rows)&&value.rows.length<=value.glyphCount*6);
 for(let i=0;i<value.rows.length;i++){
  const r=value.rows[i];assert.deepEqual(Object.keys(r).sort(),[...fields].sort());assert.equal(r.glyph,Math.floor(i/3)%value.glyphCount);assert.equal(r.theme,themes[Math.floor(i/(value.glyphCount*3))]);assert.equal(r.size,sizes[i%3]);
  assert.ok(Number.isSafeInteger(r.shapeCount)&&r.shapeCount>=0&&r.shapeCount<=64&&typeof r.hasUse==='boolean'&&Number.isSafeInteger(r.styleMask)&&r.styleMask>=0&&r.styleMask<=1023);
  for(const key of ['direct','reference','directFill','referenceFill','directStroke','referenceStroke'])assert.ok(Array.isArray(r[key])&&r[key].length===4&&r[key].every(n=>n===null||typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=65536));
 }
}
async function hash(file,maximum){const fd=await fs.open(file,'r');try{const before=await fd.stat();assert.ok(before.isFile()&&before.size>0&&before.size<=maximum);const h=createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;for(;;){const {bytesRead}=await fd.read(buffer,0,Math.min(buffer.length,maximum-total+1),null);if(!bytesRead)break;total+=bytesRead;assert.ok(total<=maximum);h.update(buffer.subarray(0,bytesRead))}const after=await fd.stat();assert.ok(total===before.size&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs);return h.digest('hex')}finally{await fd.close()}}
async function boundedHTML(file){const fd=await fs.open(file,'r');try{const maximum=1<<20,buffer=Buffer.alloc(maximum+1);let total=0;for(;;){const {bytesRead}=await fd.read(buffer,total,buffer.length-total,null);if(!bytesRead)break;total+=bytesRead;assert.ok(total<=maximum)}return buffer.subarray(0,total)}finally{await fd.close()}}
async function writeReport(repo,source,binarySHA256,project,architecture,value){
 validate(value);assert.ok(/^[a-f0-9]{40}$/.test(source)&&/^[a-f0-9]{64}$/.test(binarySHA256)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture));
 const data={glyphCount:value.glyphCount,rows:value.rows.map(r=>({...r,direct:[...r.direct],reference:[...r.reference],directFill:[...r.directFill],referenceFill:[...r.referenceFill],directStroke:[...r.directStroke],referenceStroke:[...r.referenceStroke]}))},sourceSHA256={};for(const name of sources)sourceSHA256[name]=await hash(path.join(repo,name),1<<20);assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binarySHA256);
 const bytes=await boundedHTML(path.join(repo,'web/index.html'));assert.equal(createHash('sha256').update(bytes).digest('hex'),sourceSHA256['web/index.html']);const expectedGlyphCount=[...bytes.toString('utf8').matchAll(/<symbol\b[^>]*\bid="i-[^"]+"/g)].length;assert.ok(expectedGlyphCount>0&&expectedGlyphCount<=64);
 const report={schemaVersion:1,sourceCommit:source,sourceSHA256,binarySHA256,project,architecture,scope:'owned-source-svg-geometry',expectedGlyphCount,data,complete:data.glyphCount===expectedGlyphCount&&data.rows.length===expectedGlyphCount*6,productionQualificationComplete:false};const encoded=JSON.stringify(report)+'\n';assert.ok(Buffer.byteLength(encoded)<=131072);
 const parent=path.join(repo,'build/svg-geometry');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),real=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===await fs.realpath(path.join(repo,'build')));const fd=await fs.open(path.join(real,'status.json'),'wx',0o600);try{await fd.writeFile(encoded,'utf8')}finally{await fd.close()}
 return {expectedGlyphCount,complete:report.complete};
}
module.exports={sizes,themes,sources,fields,validate,writeReport};
