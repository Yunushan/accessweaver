const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const S=require('./browser-soak.cjs'),P=require('./desktop-performance.cjs');
function valid(){const v=S.empty(true);v.stage='complete';for(const k of Object.keys(S.limits))v.metrics[k]=S.limits[k]/2;Object.assign(v.counts,{seconds:900,requests:3600,navigation:180,editor:30,samples:901,elapsedMilliseconds:900000});v.editorTimings=Array.from({length:30},()=>({actionMs:150,visibilityMs:10,paintMs:90,totalMs:250,finiteAnimations:0,animationWaitMs:2,firstFrameWaitMs:52,secondFrameWaitMs:20}));for(let i=0;i<=9;i++)v.checkpoints.push({second:i*100,browserRssBytes:100,controllerRssBytes:10,browserDescriptors:20,controllerDescriptors:5,browserThreads:20,controllerThreads:5,browserProcesses:3});setRssPeak(v);return v}
function setRssPeak(v){const n=v.metrics.browserPeakRssBytes;v.browserRssPeak=n===null?null:{phase:'workload',second:100,rssBytes:n,rootBytes:Math.floor(n/2),descendantBytes:n-Math.floor(n/2),largestDescendantBytes:n-Math.floor(n/2),descendantProcesses:1}}
async function temporary(t){const folder=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-soak-unit-'));t.after(async()=>{const info=await fs.lstat(folder),real=await fs.realpath(folder),parent=await fs.realpath(os.tmpdir());assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===parent&&path.basename(real).startsWith('accessweaver-soak-unit-'));await fs.rm(real,{recursive:true,force:true})});return folder}
test('soak refuses missing hosted guards and never treats a single opt-in as authorization',()=>{const env={GITHUB_ACTIONS:'true',CI:'true',ACCESSWEAVER_BROWSER_SOAK:'1',ACCESSWEAVER_JOB_CPU_ACCOUNTING:'required'};assert.equal(S.allowed(env,'linux'),true);for(const key of Object.keys(env))assert.equal(S.allowed({...env,[key]:undefined},'linux'),false);for(const platform of ['win32','darwin','freebsd'])assert.equal(S.allowed(env,platform),false)});
test('sustained limits preserve the original absolute and growth budgets',()=>{for(const [newName,old] of Object.entries({browserPeakRssBytes:'browserSampledPeakRssBytes',controllerPeakRssBytes:'sampledPeakRssBytes',browserPeakDescriptors:'browserSampledPeakDescriptors',browserPeakThreads:'browserSampledPeakThreads',browserPeakProcesses:'browserSampledPeakProcesses',controllerPeakDescriptors:'sampledPeakDescriptors',controllerPeakThreads:'sampledPeakThreads',browserRssGrowthBytes:'browserCooldownRssGrowthBytes',controllerRssGrowthBytes:'cooldownRssGrowthBytes',browserDescriptorGrowth:'browserCooldownDescriptorGrowth',browserThreadGrowth:'browserCooldownThreadGrowth',browserProcessGrowth:'browserCooldownProcessGrowth',controllerDescriptorGrowth:'cooldownDescriptorGrowth',controllerThreadGrowth:'cooldownThreadGrowth',navigationP95Ms:'navigationP95Ms',editorP95Ms:'editorP95Ms',apiP95Ms:'apiP95Ms',browserCpuPercentOneCore:'browserObservedLoadCpuPercentOneCore',controllerCpuPercentOneCore:'loadCpuPercentOneCore',jobCpuPercentOneCore:'jobLoadCpuPercentOneCore'}))assert.equal(S.limits[newName],P.budgets.limits[old].max)});
test('all limit violations and incomplete long-session workloads prevent qualification',()=>{assert.deepEqual(S.violations(valid()),[]);for(const key of Object.keys(S.limits)){const v=valid();v.metrics[key]=S.limits[key]+1;if(key==='browserPeakRssBytes')setRssPeak(v);if(key==='editorP95Ms')for(const row of v.editorTimings){row.paintMs=v.metrics[key]-row.actionMs-row.visibilityMs;row.totalMs=v.metrics[key]}assert.ok(S.violations(v).includes(key));v.metrics[key]=null;if(key==='browserPeakRssBytes')setRssPeak(v);assert.ok(S.violations(v).includes(key))}for(const key of ['seconds','requests','navigation','editor','samples','elapsedMilliseconds']){const v=valid();v.counts[key]--;if(key==='editor')v.editorTimings.pop();assert.ok(S.violations(v).includes('workload'))}const slow=valid();slow.counts.elapsedMilliseconds=1000000;assert.ok(S.violations(slow).includes('workload'));const truncated=valid();truncated.checkpoints.pop();assert.ok(S.violations(truncated).includes('workload'));assert.throws(()=>S.median([1,2]));assert.equal(S.median(Array(300).fill(40)),40)});
test('fixed schema rejects private metadata, unknown fields, malformed checkpoints and nonfinite counters',()=>{for(const change of [v=>v.path='PRIVATE_SYNTHETIC',v=>v.metrics.private='PRIVATE_SYNTHETIC',v=>v.metrics.browserPeakRssBytes=Infinity,v=>v.counts.samples=true,v=>v.checkpoints[0].pid=42,v=>v.checkpoints[1].second=101,v=>v.checkpoints[0].browserRssBytes=-1,v=>v.failureKind='PRIVATE_SYNTHETIC']){const v=valid();change(v);assert.throws(()=>S.validate(v))}S.validate(S.empty())});
test('sustained editor timings cover every recorded open and prove the reported p95',()=>{
 const missing=valid();missing.editorTimings.pop();assert.throws(()=>S.validate(missing));
 const privateField=valid();privateField.editorTimings[0].path='PRIVATE_SYNTHETIC';assert.throws(()=>S.validate(privateField));
 const badSum=valid();badSum.editorTimings[0].paintMs+=1;assert.throws(()=>S.validate(badSum));
 const badPercentile=valid();badPercentile.metrics.editorP95Ms+=1;assert.throws(()=>S.validate(badPercentile));
 const partial=S.empty();partial.counts.editor=1;partial.editorTimings.push(valid().editorTimings[0]);
 S.validate(partial);assert.ok(S.violations(partial).includes('editorP95Ms'));
});
test('soak reports snapshot only numeric contracts and bind exact source/binary without replacing output',async t=>{const root=await temporary(t);for(const name of [...S.sources,'build/browser-tests/accessweaver']){const p=path.join(root,name);await fs.mkdir(path.dirname(p),{recursive:true});await fs.writeFile(p,'fixed synthetic source')};const binary=createHash('sha256').update('fixed synthetic source').digest('hex'),v=valid(),writing=S.writeReport(root,'a'.repeat(40),binary,'firefox','amd64',v);v.metrics.private='PRIVATE_SYNTHETIC';assert.equal(await writing,'passed');delete v.metrics.private;const file=path.join(root,'build/browser-soak/status.json'),raw=await fs.readFile(file,'utf8'),report=JSON.parse(raw);assert.equal(report.schemaVersion,5);assert.equal(report.baselinePassed,true);assert.equal(report.editorTimings.length,30);assert.equal(report.workingDaySoakQualified,false);assert.equal(report.nativeInstalledQualified,false);assert.equal(report.productionQualificationComplete,false);assert.equal(report.counts.seconds,900);assert.equal(Object.keys(report.sourceSHA256).length,S.sources.length);assert.ok(!raw.includes('PRIVATE_SYNTHETIC')&&!raw.includes(root));await assert.rejects(S.writeReport(root,'a'.repeat(40),binary,'firefox','amd64',v),{code:'EEXIST'});assert.equal(await fs.readFile(file,'utf8'),raw);const other=await temporary(t);for(const name of [...S.sources,'build/browser-tests/accessweaver']){const p=path.join(other,name);await fs.mkdir(path.dirname(p),{recursive:true});await fs.writeFile(p,'fixed synthetic source')};v.baselinePassed=false;assert.equal(await S.writeReport(other,'a'.repeat(40),binary,'firefox','amd64',v),'failed');const afterMiss=JSON.parse(await fs.readFile(path.join(other,'build/browser-soak/status.json'),'utf8'));assert.equal(afterMiss.stage,'complete');assert.equal(afterMiss.baselinePassed,false);assert.deepEqual(afterMiss.violations,[]);
 const interrupted=await temporary(t);
 for(const name of [...S.sources,'build/browser-tests/accessweaver']){
  const filename=path.join(interrupted,name);await fs.mkdir(path.dirname(filename),{recursive:true});await fs.writeFile(filename,'fixed synthetic source');
 }
 v.baselinePassed=true;v.stage='workload';v.failureKind='AssertionError';
 assert.equal(await S.writeReport(interrupted,'a'.repeat(40),binary,'firefox','amd64',v),'failed');});

test('sustained scheduler completes all monotonic slots and joins the other operation before propagating failure',async()=>{
 const waits=[],reads=[],actions=[],completions=[];await S.driveWorkload({start:23,waitUntil:async n=>waits.push(n),requests:async()=>{reads.push(1);return [1,2,3,4]},interact:async i=>actions.push(i),complete:async(i,values)=>completions.push([i,...values])});assert.equal(reads.length,900);assert.deepEqual(actions,Array.from({length:900},(_,i)=>i));assert.equal(waits.length,1800);assert.equal(waits[0],23);assert.equal(waits.at(-1),900023);assert.equal(completions.length,900);assert.deepEqual(completions.at(-1),[900,1,2,3,4]);
 for(const failing of ['request','interaction']){let release,settled=false,completed=false;const waiting=new Promise(resolve=>{release=resolve}),failure=new Error('fixed synthetic failure');const work=S.driveWorkload({start:0,waitUntil:async()=>{},requests:async()=>{if(failing==='request')throw failure;await waiting;settled=true;return []},interact:async()=>{if(failing==='interaction')throw failure;await waiting;settled=true},complete:async()=>{completed=true}});await Promise.resolve();await Promise.resolve();assert.equal(settled,false);release();await assert.rejects(work,e=>e===failure);assert.equal(settled,true);assert.equal(completed,false)}
});


test('peak RSS attribution uses the same aggregate maximum, retains the first tie and includes cooldown',()=>{
 const v=S.empty(true);
 const sample=(root,descendant,largest=descendant)=>({rssBytes:root+descendant,processes:2,rssRoles:{rootBytes:root,descendantBytes:descendant,largestDescendantBytes:largest,descendantProcesses:1},pid:12345,path:'PRIVATE_SYNTHETIC'});
 S.observeRssPeak(v,sample(4,6),'initial',0);
 const first=v.browserRssPeak;
 S.observeRssPeak(v,sample(2,5),'workload',1);assert.equal(v.browserRssPeak,first);
 S.observeRssPeak(v,sample(2,8),'workload',2);assert.equal(v.browserRssPeak,first);
 S.observeRssPeak(v,sample(9,5),'workload',899);assert.equal(v.browserRssPeak.rssBytes,14);
 S.observeRssPeak(v,sample(10,6),'cooldown',900);
 assert.deepEqual(v.browserRssPeak,{phase:'cooldown',second:900,rssBytes:16,rootBytes:10,descendantBytes:6,largestDescendantBytes:6,descendantProcesses:1});
 v.metrics.browserPeakRssBytes=16;v.metrics.browserPeakProcesses=2;v.counts.samples=901;S.validate(v);
 assert.ok(!JSON.stringify(v.browserRssPeak).includes('PRIVATE_SYNTHETIC')&&!Object.hasOwn(v.browserRssPeak,'pid'));
 const over=valid();over.metrics.browserPeakRssBytes=S.limits.browserPeakRssBytes+1;setRssPeak(over);
 assert.ok(S.violations(over).includes('browserPeakRssBytes'));
});

test('peak RSS records reject missing, private, inconsistent and unbounded role data',()=>{
 for(const mutate of [
  v=>v.browserRssPeak=null,
  v=>v.browserRssPeak.pid=12345,
  v=>v.browserRssPeak.path='PRIVATE_SYNTHETIC',
  v=>v.browserRssPeak.phase='PRIVATE_SYNTHETIC',
  v=>v.browserRssPeak.second=901,
  v=>v.browserRssPeak.second=-1,
  v=>v.browserRssPeak.rootBytes=Infinity,
  v=>v.browserRssPeak.descendantBytes++,
  v=>v.browserRssPeak.largestDescendantBytes=v.browserRssPeak.descendantBytes+1,
  v=>v.browserRssPeak.descendantProcesses=64,
  v=>v.browserRssPeak.descendantProcesses=0,
  v=>v.browserRssPeak.rssBytes++,
  v=>{v.browserRssPeak.phase='initial';v.browserRssPeak.second=1},
  v=>{v.browserRssPeak.phase='cooldown';v.browserRssPeak.second=899}
 ]){const v=valid();mutate(v);assert.throws(()=>S.validate(v))}
 const good={rssBytes:10,processes:2,rssRoles:{rootBytes:4,descendantBytes:6,largestDescendantBytes:6,descendantProcesses:1}};
 for(const mutate of [
  s=>s.rssRoles.pid=12345,
  s=>s.rssRoles.rootBytes=-1,
  s=>s.rssRoles.descendantBytes=Number.MAX_SAFE_INTEGER+1,
  s=>s.rssRoles.descendantProcesses=0,
  s=>s.rssRoles.largestDescendantBytes=7,
  s=>s.rssBytes=11,
  s=>s.processes=3
 ]){const v=S.empty(),sample=structuredClone(good);mutate(sample);assert.throws(()=>S.observeRssPeak(v,sample,'initial',0));assert.equal(v.browserRssPeak,null)}
 const rootOnly=S.empty();S.observeRssPeak(rootOnly,{rssBytes:5,processes:1,rssRoles:{rootBytes:5,descendantBytes:0,largestDescendantBytes:0,descendantProcesses:0}},'initial',0);assert.equal(rootOnly.browserRssPeak.descendantProcesses,0);
});
