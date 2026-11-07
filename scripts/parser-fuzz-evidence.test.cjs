// Pure synthetic projection/writer checks. Importing the producer never runs Go.
'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {manifest,validateManifest,Tracker,passed,validateReport,writeReport,commonSources}=require('./parser-fuzz-evidence.cjs');
const target=manifest.targets[0],pkg='github.com/Yunushan/accessweaver/'+target.package;
function tracker(){const t=new Tracker(target);t.event({Action:'start',Package:pkg});t.event({Action:'output',Package:pkg,Output:'fuzz: elapsed: 0s, gathering baseline coverage: 3/3 completed, now fuzzing with 2 workers\n'});t.event({Action:'output',Package:pkg,Output:'fuzz: elapsed: 30s, execs: 1000 (33/sec), new interesting: 4 (total: 7)\n'});t.event({Action:'pass',Package:pkg});return t}
function report(t=tracker()){return {schemaVersion:1,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),sourceSHA256:Object.fromEntries([...commonSources,target.source].map(p=>[p,'c'.repeat(64)])),platform:'linux',architecture:'amd64',go:'go1.27.3',node:'v26.8.2',target:target.id,stage:'complete',exitCode:0,sourceStable:true,streamValid:t.valid,...t.value(),inputBytes:1024,outcome:'passed',productionQualificationComplete:false}}
test('registry covers every source fuzz root once with fixed budgets',async()=>{
 validateManifest(manifest);const found=[];
 for(const folder of ['audit','diagnostics','jsoninput','managed','profile','workflow']){
  const base=path.join(__dirname,'../internal',folder);
  for(const name of await fs.readdir(base))if(name.endsWith('_test.go')){
   const text=await fs.readFile(path.join(base,name),'utf8');
   for(const match of text.matchAll(/^func (Fuzz[A-Za-z0-9_]+)\(f \*testing\.F\)/gm))found.push({package:'internal/'+folder,root:match[1],source:'internal/'+folder+'/'+name});
  }
 }
 assert.equal(found.length,14);assert.deepEqual(manifest.targets.map(t=>({package:t.package,root:t.root,source:t.source})).sort((a,b)=>a.root.localeCompare(b.root)),found.sort((a,b)=>a.root.localeCompare(b.root)));
 for(const change of [x=>x.seconds=0,x=>x.workers=0,x=>x.targets[0].package='../private',x=>x.targets[0].source='internal/jsoninput/../../private_test.go',x=>x.targets[1].id=x.targets[0].id]){const changed=structuredClone(manifest);change(changed);assert.throws(()=>validateManifest(changed))}
});
test('instrumented mutation progress requires completed seeds, new executions, duration and package pass',()=>{
 const t=tracker(),v=report(t);assert.equal(passed(v),true);validateReport(v);
 for(const change of [x=>x.baselineInputs=0,x=>x.executions=x.baselineInputs,x=>x.elapsedSeconds=29,x=>x.instrumented=false,x=>x.packagePassed=false,x=>x.sourceStable=false,x=>x.streamValid=false,x=>x.exitCode=1]){const changed=structuredClone(v);change(changed);assert.equal(passed(changed),false);assert.throws(()=>validateReport(changed));changed.outcome='failed';validateReport(changed)}
 const unknown=new Tracker(target);unknown.event({Action:'output',Package:pkg,Output:'fuzz: elapsed: 30s, execs: 1000 (33/sec)\n'});unknown.event({Action:'pass',Package:pkg});assert.equal(passed({...report(unknown),outcome:'failed'}),false);
});
test('numeric projection discards private text, dynamic labels and unrelated objects',()=>{
 const t=tracker(),secret='PRIVATE_SYNTHETIC_CORPUS_AND_PATH';
 t.event({Action:'output',Package:pkg,Test:target.root+'/'+secret,Output:secret,error:{get stack(){throw new Error(secret)}}});
 t.event({Action:'output',Package:pkg,Output:secret.repeat(1000)});
 assert.equal(t.executions,1000);assert.ok(!JSON.stringify(t.value()).includes(secret));assert.ok(!Object.hasOwn(t.value(),'Output'));
 const wrong=new Tracker(target);wrong.event({Action:'pass',Package:'PRIVATE_UNRECOGNIZED_PACKAGE'});assert.equal(wrong.valid,false);assert.ok(!JSON.stringify(wrong.value()).includes('PRIVATE'));
});
test('malformed, regressing and wrong-worker progress cannot qualify',()=>{
 for(const output of ['fuzz: elapsed: 30s, gathering baseline coverage: 3/3 completed, now fuzzing with 9 workers\n','fuzz: elapsed: 29s, execs: 10 (1/sec), new interesting: 0 (total: 3)\n','fuzz: elapsed: 30s, execs: 99999999999999999 (1/sec), new interesting: 0 (total: 3)\n']){
  const t=tracker();t.event({Action:'output',Package:pkg,Output:output});assert.equal(t.valid,false);
 }
 const skipped=tracker();skipped.event({Action:'skip',Package:pkg,Test:target.root});assert.equal(skipped.valid,false);
 const failed=tracker();failed.event({Action:'build-fail'});assert.equal(failed.valid,false);
 const v=report();v.executions=null;assert.throws(()=>validateReport(v));
});
test('fixed schema writer refuses private fields, overwrite and link redirection',async()=>{
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-parser-fuzz-'));
 try{
  const v=report();v.private='PRIVATE_SYNTHETIC_VALUE';await assert.rejects(writeReport(temporary,v));delete v.private;
  await writeReport(temporary,v);const file=path.join(temporary,'build/parser-fuzz-evidence',target.id+'.json'),raw=await fs.readFile(file,'utf8');assert.deepEqual(JSON.parse(raw),v);assert.ok(!raw.includes(temporary));await assert.rejects(writeReport(temporary,v),{code:'EEXIST'});
  const other=path.join(temporary,'linked');await fs.mkdir(other);await fs.symlink(path.join(temporary,'build'),path.join(other,'build'),process.platform==='win32'?'junction':'dir');await assert.rejects(writeReport(other,v));
 }finally{const real=await fs.realpath(temporary),parent=await fs.realpath(os.tmpdir());assert.ok(path.dirname(real)===parent&&path.basename(real).startsWith('accessweaver-parser-fuzz-'));await fs.rm(real,{recursive:true,force:true})}
});
