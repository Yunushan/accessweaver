const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const C=require('./core-test-evidence.cjs'),MODULE='github.com/Yunushan/accessweaver';
function plan(){return {schemaVersion:1,module:MODULE,packages:[{path:MODULE+'/internal/example',tests:['TestKnown']} ]}}
function completed(){const t=new C.Tracker(plan()),pkg=MODULE+'/internal/example';for(const e of [{Action:'start',Package:pkg},{Action:'run',Package:pkg,Test:'TestKnown'},{Action:'pass',Package:pkg,Test:'TestKnown',Elapsed:.01},{Action:'pass',Package:pkg,Elapsed:.1}])t.event(e);return t}
async function temporary(t){const root=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-core-evidence-'));t.after(async()=>{const info=await fs.lstat(root),resolved=await fs.realpath(root),parent=await fs.realpath(os.tmpdir());assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(resolved)===parent&&path.basename(resolved).startsWith('accessweaver-core-evidence-'));await fs.rm(resolved,{recursive:true,force:true})});return root}
test('core projection never reads raw output and drops private dynamic subtest labels',()=>{
 const t=new C.Tracker(plan()),pkg=MODULE+'/internal/example';t.event({Action:'output',get Output(){throw new Error('PRIVATE_SYNTHETIC')},get Test(){throw new Error('PRIVATE_SYNTHETIC')}});t.event({Action:'start',Package:pkg});t.event({Action:'run',Package:pkg,Test:'TestKnown'});t.event({Action:'pass',Package:pkg,Test:'TestKnown/PRIVATE_SYNTHETIC_ACCOUNT_PATH',Output:'PRIVATE_SYNTHETIC_TOKEN'});t.event({Action:'pass',Package:pkg,Test:'TestKnown'});t.event({Action:'pass',Package:pkg});const v=t.value('unit',0);assert.equal(v.outcome,'passed');assert.equal(v.discardedOutputEvents,1);assert.equal(v.packages[0].tests[0].childPassed,1);assert.ok(!JSON.stringify(v).includes('PRIVATE_SYNTHETIC'));
});
test('core projection fails missing roots, duplicate attempts, unknown labels and build failures without retaining them',()=>{
 const pkg=MODULE+'/internal/example',missing=new C.Tracker(plan());missing.event({Action:'pass',Package:pkg});assert.equal(missing.value('unit',0).outcome,'failed');
 for(const event of [{Action:'run',Package:pkg,Test:'TestPRIVATE_SYNTHETIC'},{Action:'run',Package:'PRIVATE_SYNTHETIC',Test:'TestKnown'},{Action:'build-fail',ImportPath:'PRIVATE_SYNTHETIC'},{Action:'PRIVATE_SYNTHETIC'}]){const t=completed();t.event(event);const v=t.value('unit',0);assert.equal(v.outcome,'failed');assert.ok(!JSON.stringify(v).includes('PRIVATE_SYNTHETIC'))}
 const twice=completed();twice.event({Action:'run',Package:pkg,Test:'TestKnown'});assert.equal(twice.value('unit',0).outcome,'failed');assert.equal(completed().value('race',1).outcome,'failed');
});
test('vet success does not pretend to execute root tests and catalog refuses runtime label fields',()=>{
 const t=new C.Tracker(plan()),v=t.value('vet',0);assert.equal(v.outcome,'passed');assert.equal(v.packages[0].status,'vet-passed');assert.equal(v.packages[0].tests[0].status,'not-run');assert.equal(v.packages[0].tests[0].attempts,0);
 for(const mutate of [p=>p.private='PRIVATE_SYNTHETIC',p=>p.packages[0].path='PRIVATE_SYNTHETIC',p=>p.packages[0].tests=['TestKnown/private/runtime'],p=>p.packages[0].private='PRIVATE_SYNTHETIC']){const p=plan();mutate(p);assert.throws(()=>C.planValue(p))}
});
test('core reports require consistent outcomes, snapshot closed data and preserve exclusive owned output',async t=>{
 const root=await temporary(t),sourceSHA256={};for(const name of C.sources){const f=path.join(root,name);await fs.mkdir(path.dirname(f),{recursive:true});await fs.writeFile(f,'synthetic fixed source');sourceSHA256[name]=createHash('sha256').update('synthetic fixed source').digest('hex')}
 const data={schemaVersion:1,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),sourceSHA256,platform:'linux',architecture:'amd64',go:'go1.27.3',mode:'unit',stage:'complete',exitCode:0,streamValid:true,sourceStable:true,inputBytes:100,...completed().value('unit',0),productionQualificationComplete:false};data.raw='PRIVATE_SYNTHETIC';await assert.rejects(C.writeReport(root,data));delete data.raw;data.exitCode=1;await assert.rejects(C.writeReport(root,data));data.exitCode=0;
 const writing=C.writeReport(root,data);data.packages[0].tests[0].private='PRIVATE_SYNTHETIC';await writing;delete data.packages[0].tests[0].private;const file=path.join(root,'build/native-core-evidence/status.json'),raw=await fs.readFile(file,'utf8');assert.equal(JSON.parse(raw).outcome,'passed');assert.ok(!raw.includes(root)&&!raw.includes('PRIVATE_SYNTHETIC'));await assert.rejects(C.writeReport(root,data),{code:'EEXIST'});assert.equal(await fs.readFile(file,'utf8'),raw);
});

test('failure annotations use only catalogue root labels and cap output',()=>{
 const p=plan(),pkg=p.packages[0].path,data={get Output(){throw new Error('PRIVATE_SYNTHETIC')},packages:[{path:pkg,status:'failed',tests:[{name:'TestKnown',status:'failed',get Output(){throw new Error('PRIVATE_SYNTHETIC')}},{name:'TestKnown/PRIVATE_SYNTHETIC_PATH',status:'failed'},{name:'TestPRIVATE_SYNTHETIC',status:'failed'}]},{path:'PRIVATE_SYNTHETIC',status:'failed',tests:[]}]};
 assert.deepEqual(C.failureAnnotations(p,data),[pkg+'#TestKnown']);assert.ok(!JSON.stringify(C.failureAnnotations(p,data)).includes('PRIVATE_SYNTHETIC'));
 const many=plan();many.packages[0].tests=Array.from({length:20},(_,n)=>'TestKnown'+n);assert.equal(C.failureAnnotations(many,{packages:[{path:pkg,status:'failed',tests:many.packages[0].tests.map(name=>({name,status:'failed'}))}]}).length,10);
 assert.deepEqual(C.failureAnnotations(p,{packages:[{path:pkg,status:'failed',tests:[]}]}),[pkg]);
});
test('Windows cancellation uses only the owned child object with no PID fallback',()=>{
 const calls=[];let pidReads=0,fallbacks=0;const child={get pid(){pidReads++;return 123},kill(signal){calls.push(signal);throw new Error('owned child already closed')}};
 C.signalOwnedChild(child,'win32','SIGTERM',()=>{fallbacks++});assert.deepEqual(calls,['SIGTERM']);assert.equal(pidReads,0);assert.equal(fallbacks,0);
 const groups=[];C.signalOwnedChild({pid:123},'linux','SIGTERM',(pid,signal)=>groups.push([pid,signal]));assert.deepEqual(groups,[[-123,'SIGTERM']]);
});
test('preview reporting keeps full root scope, default concurrency and existing six-minute timeout',()=>{
 assert.deepEqual(C.testArguments('unit',true),['test','-json','-count=1','-timeout=6m','./...']);
 assert.deepEqual(C.testArguments('race',true),['test','-json','-count=1','-timeout=6m','-race','./...']);
 assert.deepEqual(C.testArguments('unit'),['test','-json','-count=1','-p=2','./...']);assert.deepEqual(C.testArguments('vet',true),['vet','./...']);
 assert.deepEqual(C.testArguments('unit',false,true),['test','-json','-count=1','./...']);
 assert.throws(()=>C.testArguments('race',false,true));
 assert.throws(()=>C.testArguments('unit',true,true));
});
test('Windows unit reports support distinct exclusive names and reject unsafe output names or unsupported modes',async t=>{
 const root=await temporary(t),sourceSHA256=Object.fromEntries(C.sources.map(name=>[name,'c'.repeat(64)]));
 const data={schemaVersion:1,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),sourceSHA256,platform:'windows',architecture:'arm64',go:'go1.27.3',mode:'unit',stage:'complete',exitCode:0,streamValid:true,sourceStable:true,inputBytes:100,...completed().value('unit',0),productionQualificationComplete:false};
 await assert.rejects(C.writeReport(root,data,'../PRIVATE_SYNTHETIC'));await C.writeReport(root,data,'status-unit.json');const written=JSON.parse(await fs.readFile(path.join(root,'build/native-core-evidence/status-unit.json'),'utf8'));assert.equal(written.platform,'windows');assert.equal(written.outcome,'passed');
 await assert.rejects(C.writeReport(root,data,'status-unit.json'),{code:'EEXIST'});await assert.rejects(C.writeReport(root,{...data,mode:'race'},'status-race.json'));
});


test('closed-pipe annotations retain only exact fixed public cases/phases and never inspect output',()=>{
 const pkg=MODULE+'/cmd/accessweaver',root='TestRecordedEngineClosedStdoutAndStderrReapBeforeScopeRestoration',repeat='TestRecordedEngineClosedStandardPipeRepeated';
 const p={schemaVersion:1,module:MODULE,packages:[{path:pkg,tests:[root,repeat]},{path:MODULE+'/internal/other',tests:[root]}]},t=new C.Tracker(p);
 const output={get Output(){throw new Error('PRIVATE_SYNTHETIC')}};
 t.event({Action:'output',get Test(){throw new Error('PRIVATE_SYNTHETIC')},get Output(){throw new Error('PRIVATE_SYNTHETIC')}});
 for(const label of [root+'/accepted/scope-cleanup',repeat+'/attempt-20/notice/sigpipe-restoration'])t.event(Object.assign(Object.create(output),{Action:'fail',Package:pkg,Test:label}));
 assert.deepEqual(C.closedPipeFailureAnnotations(t),[pkg+'#'+root+'/accepted/scope-cleanup',pkg+'#'+repeat+'/attempt-20/notice/sigpipe-restoration']);
 for(const label of [root+'/PRIVATE_SYNTHETIC',root+'/intent/intent-checkpoint',root+'/accepted/scope-cleanup/PRIVATE_SYNTHETIC',repeat+'/attempt-21/notice/sigpipe-restoration'])t.event(Object.assign(Object.create(output),{Action:'fail',Package:pkg,Test:label}));
 t.event({Action:'fail',Package:MODULE+'/internal/other',Test:root+'/accepted/scope-cleanup'});t.event({Action:'pass',Package:pkg,Test:root+'/notice/worker-completion'});
 assert.equal(C.closedPipeFailureAnnotations(t).length,2);assert.ok(!JSON.stringify(C.closedPipeFailureAnnotations(t)).includes('PRIVATE_SYNTHETIC'));assert.ok(!JSON.stringify(t.value('unit',1)).includes('scope-cleanup'));
});

test('fixed closed-pipe diagnostics cap labels and preserve ordinary root failure counts',()=>{
 const pkg=MODULE+'/cmd/accessweaver',root='TestRecordedEngineClosedStandardPipeRepeated',p={schemaVersion:1,module:MODULE,packages:[{path:pkg,tests:[root]}]},t=new C.Tracker(p);
 t.event({Action:'start',Package:pkg});t.event({Action:'run',Package:pkg,Test:root});
 for(let n=1;n<=20;n++)t.event({Action:'fail',Package:pkg,Test:root+'/attempt-'+n+'/notice/scope-cleanup'});
 t.event({Action:'fail',Package:pkg,Test:root});t.event({Action:'fail',Package:pkg});const v=t.value('unit',1);assert.equal(v.outcome,'failed');assert.equal(v.packages[0].tests[0].childFailed,20);assert.equal(C.closedPipeFailureAnnotations(t).length,10);assert.deepEqual(C.failureAnnotations(p,v),[pkg+'#'+root]);
});


test('fixed worker stage projection retains no file contents or arbitrary suffixes',()=>{
 const pkg=MODULE+'/cmd/accessweaver',root='TestRecordedEngineClosedStandardPipeRepeated',p={schemaVersion:1,module:MODULE,packages:[{path:pkg,tests:[root]}]},t=new C.Tracker(p),base=root+'/attempt-20/accepted/scope-cleanup/';
 t.event({Action:'fail',Package:pkg,Test:base+'worker-reaped',get Output(){throw new Error('PRIVATE_SYNTHETIC')}});t.event({Action:'fail',Package:pkg,Test:base+'PRIVATE_SYNTHETIC'});t.event({Action:'fail',Package:pkg,Test:base+'worker-reaped/PRIVATE_SYNTHETIC'});assert.deepEqual(C.closedPipeFailureAnnotations(t),[pkg+'#'+base+'worker-reaped']);assert.ok(!JSON.stringify(t.value('race',1)).includes('worker-reaped'));
});


test('worker annotation allowlist matches all fixed public fixture stage codes',async()=>{
 const source=await fs.readFile(path.join(__dirname,'../cmd/accessweaver/audit_run_pipe_linux_test.go'),'utf8'),block=source.match(/var recordedEnginePipeStages = map\[string\]string\{([^}]+)\}/)[1],labels=[...block.matchAll(/"([0-9]{2})":\s*"(worker-[a-z-]+)"/g)];assert.equal(labels.length,15);assert.equal(new Set(labels.map(m=>m[1])).size,15);
 const pkg=MODULE+'/cmd/accessweaver',root='TestRecordedEngineClosedStandardPipeRepeated',p={schemaVersion:1,module:MODULE,packages:[{path:pkg,tests:[root]}]};for(const stage of [...labels.map(m=>m[2]),'worker-unavailable']){const t=new C.Tracker(p),label=root+'/attempt-20/accepted/scope-cleanup/'+stage;t.event({Action:'fail',Package:pkg,Test:label});assert.deepEqual(C.closedPipeFailureAnnotations(t),[pkg+'#'+label])}
});

test('macOS unit report binds the release workflow and excludes private data',async t=>{
 const root=await temporary(t);
 const sourceSHA256=Object.fromEntries(C.sources.map(name=>[name,'c'.repeat(64)]));
 const data={schemaVersion:1,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),sourceSHA256,platform:'darwin',architecture:'arm64',go:'go1.27.3',mode:'unit',stage:'complete',exitCode:0,streamValid:true,sourceStable:true,inputBytes:100,...completed().value('unit',0),productionQualificationComplete:false};
 await assert.rejects(C.writeReport(root,data));
 sourceSHA256['.github/workflows/release.yml']='d'.repeat(64);
 await assert.rejects(C.writeReport(root,{...data,mode:'race'}));
 await C.writeReport(root,data);
 const report=JSON.parse(await fs.readFile(path.join(root,'build/native-core-evidence/status.json'),'utf8'));
 assert.equal(report.platform,'darwin');
 assert.equal(report.sourceSHA256['.github/workflows/release.yml'],'d'.repeat(64));
 assert.equal(report.outcome,'passed');
});
