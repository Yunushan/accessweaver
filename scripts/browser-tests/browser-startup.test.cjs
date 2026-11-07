const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const D=require('./browser-startup.cjs'),T=require('./browser-timing.cjs');
function harness(overrides={},clock){let tick=0;const context=vm.createContext({performance:{now:clock||(()=>++tick)},...Object.fromEntries(D.functionNames.map(name=>[name,()=>undefined])),...overrides});vm.runInContext(D.instrumentation(),context,{timeout:1000});return {context,capture:()=>JSON.parse(JSON.stringify(context.__accessweaverScriptCosts.capture()))}}
const syntheticSource=()=>D.functionNames.map(name=>(D.asyncNames.includes(name)?'async ':'')+`function ${name}(){return 1}`).join('\n')+'\nbindEvents();initialize();';
function valid(){
 const v=D.empty();v.stage='complete';v.interceptedScripts=1;v.scriptSHA256='a'.repeat(64);v.instrumentedScriptSHA256='b'.repeat(64);v.profilesRendered=256;
 v.timing={startupJobCpu:{scope:'isolated-job-cgroup-v2',intervalMilliseconds:1000,cpuMicroseconds:500000,userMicroseconds:400000,systemMicroseconds:100000,percentOneCore:50},dashboard:{navigationMs:30,applicationMs:20,paintMs:10},editor:Array.from({length:10},()=>({actionMs:30,visibilityMs:10,paintMs:20,totalMs:60})),startup:{observedMs:100,domContentLoadedMs:10,resourceOverflow:false,invalidRecords:0,readyObservation:{clock:'performance-now-callback-delivery',status:'ready',firstReadyMs:30,readyPaintMs:80,framesAfterReady:2,firstFrameMs:10,lastFrameMs:80,frameCount:4,maxFrameGapMs:30,callbacks:3,stoppedMs:90,context:{start:{visibility:'visible',focused:true},ready:{visibility:'visible',focused:true},stop:{visibility:'visible',focused:true}}},resources:Object.fromEntries(T.startupLabels.map(label=>[label,{startMs:10,firstByteMs:20,endMs:30}]))}};
 v.scriptCosts=harness().capture();v.scriptCosts.phase=2;
 for(const name of ['initialize','readCore'])Object.assign(v.scriptCosts.records[0][D.functionNames.indexOf(name)],{calls:1,asyncSettled:1});
 v.scriptCosts.records[2][D.functionNames.indexOf('showEditor')].calls=10;
 Object.assign(v.scriptCosts.records[0][D.functionNames.indexOf('apiRequest')],{calls:4,asyncSettled:4});v.scriptCosts.records[0][D.functionNames.indexOf('renderAll')].calls=1;v.scriptCosts.records[1][D.functionNames.indexOf('renderProfiles')].calls=1;
 for(const object of [v.browserChecks,v.jobCpuChecks,v.cleanup])for(const key of Object.keys(object))object[key]=true;return v;
}
async function temporary(t){const p=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-startup-unit-'));t.after(async()=>{const info=await fs.lstat(p),real=await fs.realpath(p),base=await fs.realpath(os.tmpdir());assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===base&&path.basename(real).startsWith('accessweaver-startup-unit-'));await fs.rm(real,{recursive:true,force:true})});return p}
async function fixture(t){const root=await temporary(t);for(const name of D.sources){const p=path.join(root,name);await fs.mkdir(path.dirname(p),{recursive:true});await fs.writeFile(p,'fixed synthetic public source')};return root}
const env={platform:'linux',architecture:'arm64',node:'v26.8.2',playwright:require('./package-lock.json').packages[''].devDependencies['@playwright/test']};
test('startup attribution requires all hosted opt-ins and refuses local execution before inspecting fixtures',async()=>{
 const env={GITHUB_ACTIONS:'true',CI:'true',ACCESSWEAVER_BROWSER_STARTUP:'1',ACCESSWEAVER_JOB_CPU_ACCOUNTING:'required'};assert.equal(D.allowed(env,'linux'),true);for(const key of Object.keys(env))assert.equal(D.allowed({...env,[key]:undefined},'linux'),false);for(const platform of ['win32','darwin','freebsd','openbsd'])assert.equal(D.allowed(env,platform),false);await assert.rejects(D.run(),/Explicit hosted Linux/);
});
test('instrumentation requires exact source-owned declarations and preserves all original application bytes',async()=>{
 const source=await fs.readFile(path.join(__dirname,'../../web/app.js'),'utf8'),result=D.instrument(source);assert.equal(result.replace(D.instrumentation()+'\n',''),source);assert.equal(result.split(D.instrumentation()).length,2);
 for(const changed of [source.replace('bindEvents();initialize();','initialize();'),source+'\nbindEvents();initialize();',source.replace('function renderHero(','function otherHero('),source.replace('async function readCore(','function readCore(')])assert.throws(()=>D.instrument(changed));
 const synthetic=syntheticSource();assert.ok(D.instrument(synthetic).includes(D.instrumentation()));
});
test('script interception permits only the exact loopback application script',()=>{
 assert.equal(D.appPattern.test('http://127.0.0.1:1234/app.js'),true);for(const value of ['http://127.0.0.1:1234/app.js?private','http://127.0.0.1:1234/app.js#private','http://127.0.0.1:1234/api/v1/profiles','http://private@127.0.0.1:1234/app.js','https://127.0.0.1:1234/app.js','http://example.com/app.js'])assert.equal(D.appPattern.test(value),false);
});
test('wrapping preserves receiver, arguments, exact return identity and synchronous thrown errors without retaining values',()=>{
 const value={private:'SYNTHETIC_PRIVATE_CANARY'},error=new Error('SYNTHETIC_PRIVATE_CANARY');let received;
 const h=harness({renderHero:function(a,b){received=[this,a,b];return value},renderProfiles:()=>{throw error}}),receiver={private:'SYNTHETIC_PRIVATE_CANARY'};
 assert.equal(h.context.renderHero.call(receiver,value,error),value);assert.deepEqual(received,[receiver,value,error]);assert.throws(()=>h.context.renderProfiles(),e=>e===error);
 const costs=h.capture();assert.equal(costs.records[0][D.functionNames.indexOf('renderHero')].calls,1);assert.equal(costs.records[0][D.functionNames.indexOf('renderProfiles')].failures,1);D.validateCosts(costs);assert.ok(!JSON.stringify(costs).includes('SYNTHETIC_PRIVATE_CANARY'));
});
test('async observation preserves exact promise identity and records settlement without swallowing rejection',async()=>{
 let resolve,reject;const resolved=new Promise(r=>resolve=r),rejected=new Promise((_,r)=>reject=r),error=new Error('SYNTHETIC_PRIVATE_CANARY');const h=harness({initialize:()=>resolved,readCore:()=>rejected});
 assert.equal(h.context.initialize(),resolved);assert.equal(h.context.readCore(),rejected);let c=h.capture();assert.equal(c.records[0][D.functionNames.indexOf('initialize')].pending,1);resolve(12);reject(error);assert.equal(await resolved,12);await assert.rejects(rejected,e=>e===error);
 c=h.capture();for(const name of ['initialize','readCore']){const row=c.records[0][D.functionNames.indexOf(name)];assert.equal(row.pending,0);assert.equal(row.asyncSettled,1);assert.ok(row.asyncWallTotalMs>=row.syncTotalMs)}assert.equal(c.records[0][D.functionNames.indexOf('readCore')].failures,1);D.validateCosts(c);assert.ok(!JSON.stringify(c).includes('SYNTHETIC_PRIVATE_CANARY'));
});
test('phase transitions retain pending calls in their original phase and return detached numeric snapshots',async()=>{
 let resolve;const promise=new Promise(r=>resolve=r),h=harness({initialize:()=>promise});h.context.initialize();h.context.__accessweaverScriptCosts.markPhase(1);h.context.renderProfiles();h.context.__accessweaverScriptCosts.markPhase(2);h.context.showEditor();resolve();await promise;
 const c=h.capture();assert.equal(c.records[0][D.functionNames.indexOf('initialize')].asyncSettled,1);assert.equal(c.records[1][D.functionNames.indexOf('renderProfiles')].calls,1);assert.equal(c.records[2][D.functionNames.indexOf('showEditor')].calls,1);c.records[0][0].calls=123;assert.equal(h.capture().records[0][0].calls,0);for(const phase of [-1,0,1,3,'2'])assert.throws(()=>h.context.__accessweaverScriptCosts.markPhase(phase));D.validateCosts(h.capture());
});
test('overflow and backward or invalid clocks stay explicit and cannot create trusted costs',()=>{
 const h=harness();for(let i=0;i<16385;i++)h.context.icon();let c=h.capture();assert.equal(c.overflow,true);assert.equal(c.records[0][D.functionNames.indexOf('icon')].calls,16384);D.validateCosts(c);
 for(const clock of [()=>NaN,(()=>{let n=20;return ()=>n--})()]){const x=harness({},clock);x.context.icon();c=x.capture();assert.equal(c.invalidClock,true);D.validateCosts(c)}
});
test('fixed cost schema rejects private fields, impossible counts, nonfinite times and forged async records',()=>{
 D.validateCosts(harness().capture());for(const mutate of [v=>v.private='SYNTHETIC_PRIVATE_CANARY',v=>v.records[0][0].private='SYNTHETIC_PRIVATE_CANARY',v=>v.records[0][0].calls=16385,v=>v.records[0][0].syncTotalMs=Infinity,v=>v.records[0][0].syncMaxMs=1,v=>v.records[0][0].pending=1,v=>v.records[0][0].asyncSettled=1,v=>v.records[0].pop(),v=>v.records.push([])]){const v=harness().capture();mutate(v);assert.throws(()=>D.validateCosts(v))}
});
test('diagnostic completion requires actual startup, full profile DOM, ten editor opens, settled observations and all guards',()=>{
 const v=valid();D.validate(v);assert.equal(D.complete(v),true);assert.equal(D.complete(D.empty()),false);
 for(const mutate of [v=>v.profilesRendered=255,v=>v.interceptedScripts=0,v=>v.scriptSHA256=null,v=>v.scriptCosts=null,v=>v.scriptCosts.overflow=true,v=>v.scriptCosts.invalidClock=true,v=>v.scriptCosts.records[0][D.functionNames.indexOf('initialize')].asyncSettled=0,v=>v.scriptCosts.records[2][D.functionNames.indexOf('showEditor')].calls=9,v=>v.timing.editor.pop(),v=>v.timing.startup.resources.profiles=null,v=>v.timing.startupJobCpu=null,v=>v.browserChecks.afterEditor=false,v=>v.jobCpuFailureStage=1,v=>v.browserFailureStage=1,v=>v.cleanup.fixtureRemoved=false]){const value=valid();mutate(value);assert.equal(D.complete(value),false)}
});
test('partial source-bound report exposes no source bodies, paths or qualification and refuses replacement',async t=>{
 const root=await fixture(t),v=D.empty(),writing=D.writeReport(root,'a'.repeat(40),null,'webkit','arm64',v,env);v.private='SYNTHETIC_PRIVATE_CANARY';assert.equal(await writing,false);const file=path.join(root,'build/browser-startup/status.json'),raw=await fs.readFile(file,'utf8'),report=JSON.parse(raw);
 assert.equal(report.complete,false);for(const k of ['qualificationCredit','workingDaySoakQualified','nativeInstalledQualified','productionQualificationComplete'])assert.equal(report[k],false);assert.equal(report.scope,'owned-application-script-costs');assert.equal(report.driver,'playwright-test');assert.equal(Object.keys(report.sourceSHA256).length,D.sources.length);assert.ok(!raw.includes(root)&&!raw.includes('SYNTHETIC_PRIVATE_CANARY')&&!raw.includes('fixed synthetic public source'));
 await assert.rejects(D.writeReport(root,'a'.repeat(40),null,'webkit','arm64',D.empty(),env),{code:'EEXIST'});assert.equal(await fs.readFile(file,'utf8'),raw);
});
test('report refuses mismatched source reconstruction, executable identity and output symlinks',async t=>{
 const root=await fixture(t),v=D.empty();v.scriptSHA256='a'.repeat(64);v.instrumentedScriptSHA256='b'.repeat(64);await assert.rejects(D.writeReport(root,'a'.repeat(40),null,'webkit','arm64',v,env));
 const binary=path.join(root,'build/browser-tests/accessweaver');await fs.mkdir(path.dirname(binary),{recursive:true});await fs.writeFile(binary,'synthetic executable bytes never executed');await assert.rejects(D.writeReport(root,'a'.repeat(40),'b'.repeat(64),'webkit','arm64',D.empty(),env));
 const target=path.join(root,'redirect');await fs.mkdir(target);await fs.symlink(target,path.join(root,'build/browser-startup'),process.platform==='win32'?'junction':'dir');await assert.rejects(D.writeReport(root,'a'.repeat(40),null,'webkit','arm64',D.empty(),env));assert.deepEqual(await fs.readdir(target),[]);
});

test('complete synthetic publication binds transformed source and binary bytes while remaining diagnostic only',async t=>{
 const root=await fixture(t),body=syntheticSource()+'\n// SYNTHETIC_PRIVATE_CANARY',v=valid(),digest=value=>createHash('sha256').update(value).digest('hex');await fs.writeFile(path.join(root,'web/app.js'),body);const binary=path.join(root,'build/browser-tests/accessweaver');await fs.mkdir(path.dirname(binary),{recursive:true});await fs.writeFile(binary,'synthetic binary bytes never executed');v.scriptSHA256=digest(body);v.instrumentedScriptSHA256=digest(D.instrument(body));
 assert.equal(await D.writeReport(root,'a'.repeat(40),digest('synthetic binary bytes never executed'),'webkit','arm64',v,env),true);const raw=await fs.readFile(path.join(root,'build/browser-startup/status.json'),'utf8'),report=JSON.parse(raw);assert.equal(report.complete,true);assert.equal(report.qualificationCredit,false);assert.equal(report.productionQualificationComplete,false);assert.equal(report.sourceSHA256['web/app.js'],digest(body));assert.equal(report.instrumentedScriptSHA256,digest(D.instrument(body)));assert.equal(report.timingSemantics.nested,'overlap-do-not-sum');assert.ok(Buffer.byteLength(raw)<=65536&&!raw.includes('SYNTHETIC_PRIVATE_CANARY')&&!raw.includes(root));
});
