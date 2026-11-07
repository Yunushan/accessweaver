// Fixed script-cost attribution for an owned disposable full-application fixture.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{spawn,execFileSync}=require('node:child_process'),{createHash}=require('node:crypto'),{performance}=require('node:perf_hooks');
const P=require('./desktop-performance.cjs'),T=require('./browser-timing.cjs'),C=require('./browser-control.cjs'),{BrowserResources}=require('./browser-resources.cjs'),{JobCpu,emptyChecks,checkNames,failureStage}=require('./job-cpu.cjs');
const functionNames=['bindEvents','initialize','readSession','setTheme','updateTranslations','navigate','apiRequest','readCore','renderAll','renderHero','renderProfiles','renderEngines','profileCard','icon','renderMarkup','setText','setHidden','setDisabled','updateProbeAvailability','updateSupportAvailability','newProfile','showEditor','fillSimple','updateEditorGuidance','setModal','switchEditor','closeEditor'];
const asyncNames=['initialize','apiRequest','readCore'];
const phaseNames=['startup','profile-navigation','editor'];
const recordFields=['calls','syncTotalMs','syncMaxMs','asyncSettled','asyncWallTotalMs','asyncWallMaxMs','pending','failures'];
const stages=['environment','controller','browser','startup','profiles','editor','close','complete'];
const cleanupNames=['contextClosed','browserStopped','controllerStopped','fixtureRemoved'];
const sources=['scripts/browser-tests/browser-startup.cjs','scripts/browser-tests/browser-startup.test.cjs','scripts/browser-tests/browser-startup.spec.cjs','scripts/browser-tests/startup.config.cjs','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/browser-control.cjs','scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/browser-timing.cjs','scripts/browser-tests/browser-resources.cjs','scripts/browser-tests/browser-memory.cjs','scripts/browser-tests/job-cpu.cjs','scripts/browser-tests/browser-native-binary.cjs','scripts/browser-tests/check-image-environment.cjs','scripts/browser-tests/performance-budgets.json','scripts/browser-tests/package-lock.json','scripts/check-native-environment.cjs','.github/workflows/browser-startup.yml','internal/api/server.go','internal/profile/store.go','web/app.js','web/app.css','web/index.html','web/locales.js','web/system.js','go.mod','go.sum'];
const appPattern=/^http:\/\/127\.0\.0\.1:[0-9]+\/app\.js$/;
const marker='bindEvents();initialize();';
// A source string is intentional: test-runner formatting must not affect the
// generated application bytes, unlike serializing a transformed function.
const profilerSource=String.raw`(()=>{
 const names=FUNCTION_NAMES, asynchronous=ASYNC_NAMES;
 let phase=0,overflow=false,invalidClock=false;
 const records=Array.from({length:3},()=>names.map(()=>({calls:0,syncTotalMs:0,syncMaxMs:0,asyncSettled:0,asyncWallTotalMs:0,asyncWallMaxMs:0,pending:0,failures:0})));
 const now=()=>{const n=performance.now();if(typeof n!=='number'||!Number.isFinite(n)||n<0){invalidClock=true;return 0}return n};
 const elapsed=start=>{const delta=now()-start;if(delta<0){invalidClock=true;return 0}return delta};
 const wrap=(fn,index)=>function(...args){
  const row=records[phase][index];if(row.calls===16384){overflow=true;return Reflect.apply(fn,this,args)}row.calls++;
  const start=now();let result;
  try{result=Reflect.apply(fn,this,args)}catch(error){const delta=elapsed(start);row.syncTotalMs+=delta;row.syncMaxMs=Math.max(row.syncMaxMs,delta);row.failures++;throw error}
  const delta=elapsed(start);row.syncTotalMs+=delta;row.syncMaxMs=Math.max(row.syncMaxMs,delta);
  if(asynchronous.includes(names[index])){
   if(!result||typeof result.then!=='function'){invalidClock=true;return result}row.pending++;
   const finish=failed=>{const wall=elapsed(start);row.pending--;row.asyncSettled++;row.asyncWallTotalMs+=wall;row.asyncWallMaxMs=Math.max(row.asyncWallMaxMs,wall);if(failed)row.failures++};
   result.then(()=>finish(false),()=>finish(true));
  }
  return result;
 };
 Object.defineProperty(globalThis,'__accessweaverScriptCosts',{configurable:false,value:Object.freeze({
  markPhase(next){if(!Number.isInteger(next)||next!==phase+1||next>2)throw new Error('Diagnostic phase differs');phase=next},
  capture(){return {phase,overflow,invalidClock,records:records.map(rows=>rows.map(row=>({...row})))}}
 })});
 WRAP_FUNCTIONS
})();`;
function instrumentation(){return profilerSource.replace('FUNCTION_NAMES',JSON.stringify(functionNames)).replace('ASYNC_NAMES',JSON.stringify(asyncNames)).replace('WRAP_FUNCTIONS',functionNames.map((name,index)=>`${name}=wrap(${name},${index});`).join('\n '))}
function instrument(source){
 assert.ok(typeof source==='string'&&Buffer.byteLength(source)>0&&Buffer.byteLength(source)<=1048576);
 assert.equal(source.split(marker).length,2,'Exactly one public startup marker required');
 for(const name of functionNames)assert.equal((source.match(new RegExp('^(?:async )?function '+name+'\\(','gm'))||[]).length,1,'Source-known function declaration required');
 for(const name of asyncNames)assert.ok(new RegExp('^async function '+name+'\\(','m').test(source),'Source-known async declaration required');
 return source.replace(marker,instrumentation()+'\n'+marker);
}
function allowed(env=process.env,platform=process.platform){return platform==='linux'&&env.GITHUB_ACTIONS==='true'&&env.CI==='true'&&env.ACCESSWEAVER_BROWSER_STARTUP==='1'&&env.ACCESSWEAVER_JOB_CPU_ACCOUNTING==='required'}
function empty(){return {stage:'environment',failureKind:'none',interceptedScripts:0,scriptSHA256:null,instrumentedScriptSHA256:null,profilesRendered:0,timing:T.empty(),scriptCosts:null,browserChecks:{beforeStartup:false,afterEditor:false},jobCpuChecks:emptyChecks(),jobCpuFailureStage:0,browserFailureStage:0,cleanup:Object.fromEntries(cleanupNames.map(k=>[k,false]))}}
function keys(v,names){assert.ok(v&&typeof v==='object');assert.deepEqual(Object.keys(v).sort(),[...names].sort())}
const numeric=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER;
const sha=n=>typeof n==='string'&&/^[a-f0-9]{64}$/.test(n);
function validateCosts(v){
 keys(v,['phase','overflow','invalidClock','records']);assert.ok(Number.isInteger(v.phase)&&v.phase>=0&&v.phase<=2&&typeof v.overflow==='boolean'&&typeof v.invalidClock==='boolean');assert.ok(Array.isArray(v.records)&&v.records.length===3);
 for(const rows of v.records){assert.ok(Array.isArray(rows)&&rows.length===functionNames.length);for(let index=0;index<rows.length;index++){
  const row=rows[index];keys(row,recordFields);for(const k of ['calls','asyncSettled','pending','failures'])assert.ok(Number.isInteger(row[k])&&row[k]>=0&&row[k]<=16384);
  for(const k of ['syncTotalMs','syncMaxMs','asyncWallTotalMs','asyncWallMaxMs'])assert.ok(numeric(row[k]));
  assert.ok(row.syncMaxMs<=row.syncTotalMs&&row.asyncWallMaxMs<=row.asyncWallTotalMs&&row.asyncSettled+row.pending<=row.calls&&row.failures<=row.calls);
  if(row.calls===0)assert.ok(Object.values(row).every(n=>n===0));
  if(!asyncNames.includes(functionNames[index]))assert.ok(row.asyncSettled===0&&row.pending===0&&row.asyncWallTotalMs===0&&row.asyncWallMaxMs===0);
 }}
}
function validate(v){
 keys(v,['stage','failureKind','interceptedScripts','scriptSHA256','instrumentedScriptSHA256','profilesRendered','timing','scriptCosts','browserChecks','jobCpuChecks','jobCpuFailureStage','browserFailureStage','cleanup']);
 assert.ok(stages.includes(v.stage)&&P.failureKinds.includes(v.failureKind));assert.ok(Number.isInteger(v.interceptedScripts)&&v.interceptedScripts>=0&&v.interceptedScripts<=2&&Number.isInteger(v.profilesRendered)&&v.profilesRendered>=0&&v.profilesRendered<=256);
 for(const k of ['scriptSHA256','instrumentedScriptSHA256'])assert.ok(v[k]===null||sha(v[k]));T.validate(v.timing);if(v.scriptCosts!==null)validateCosts(v.scriptCosts);
 for(const [k,names] of [['browserChecks',['beforeStartup','afterEditor']],['jobCpuChecks',checkNames],['cleanup',cleanupNames]]){keys(v[k],names);assert.ok(Object.values(v[k]).every(n=>typeof n==='boolean'))}
 for(const k of ['jobCpuFailureStage','browserFailureStage'])assert.ok(Number.isInteger(v[k])&&v[k]>=0&&v[k]<=9);
}
function complete(v){
 validate(v);return v.stage==='complete'&&v.failureKind==='none'&&v.interceptedScripts===1&&sha(v.scriptSHA256)&&sha(v.instrumentedScriptSHA256)&&v.profilesRendered===256&&T.startupComplete(v.timing.startup)&&v.timing.startupJobCpu!==null&&Object.values(v.timing.dashboard).every(numeric)&&v.timing.editor.length===10&&v.scriptCosts!==null&&v.scriptCosts.phase===2&&!v.scriptCosts.overflow&&!v.scriptCosts.invalidClock&&v.scriptCosts.records.every(rows=>rows.every((r,i)=>r.pending===0&&r.failures===0&&(!asyncNames.includes(functionNames[i])||r.asyncSettled===r.calls)))&&v.scriptCosts.records[0][functionNames.indexOf('initialize')].asyncSettled===1&&v.scriptCosts.records[0][functionNames.indexOf('readCore')].asyncSettled===1&&v.scriptCosts.records[0][functionNames.indexOf('apiRequest')].asyncSettled>=4&&v.scriptCosts.records[0][functionNames.indexOf('renderAll')].calls===1&&v.scriptCosts.records[1][functionNames.indexOf('renderProfiles')].calls>=1&&v.scriptCosts.records[2][functionNames.indexOf('showEditor')].calls===10&&Object.values(v.browserChecks).every(Boolean)&&Object.values(v.jobCpuChecks).every(Boolean)&&!v.jobCpuFailureStage&&!v.browserFailureStage&&Object.values(v.cleanup).every(Boolean);
}
async function hash(file,cap){const fd=await fs.open(file,'r');try{const a=await fd.stat();assert.ok(a.isFile()&&a.size>0&&a.size<=cap);const h=createHash('sha256'),buffer=Buffer.alloc(65536);let size=0;for(;;){const n=await fd.read(buffer,0,Math.min(buffer.length,cap-size+1),null);if(!n.bytesRead)break;size+=n.bytesRead;assert.ok(size<=cap);h.update(buffer.subarray(0,n.bytesRead))}const b=await fd.stat();assert.ok(size===a.size&&a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs);return h.digest('hex')}finally{await fd.close()}}
async function writeReport(repo,source,binarySHA256,project,architecture,value,environment){
 validate(value);assert.ok(/^[a-f0-9]{40}$/.test(source)&&(binarySHA256===null||sha(binarySHA256))&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture));
 keys(environment,['platform','architecture','node','playwright']);assert.deepEqual(environment,{platform:'linux',architecture:architecture==='amd64'?'x64':'arm64',node:'v26.8.2',playwright:require('./package-lock.json').packages[''].devDependencies['@playwright/test']});
 const snapshot=JSON.parse(JSON.stringify(value)),sourceSHA256={};for(const file of sources)sourceSHA256[file]=await hash(path.join(repo,file),1<<20);if(binarySHA256!==null)assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binarySHA256);
 if(snapshot.scriptSHA256!==null){assert.equal(snapshot.scriptSHA256,sourceSHA256['web/app.js']);const body=await fs.readFile(path.join(repo,'web/app.js'),'utf8');assert.equal(snapshot.instrumentedScriptSHA256,createHash('sha256').update(instrument(body)).digest('hex'))}
 const done=binarySHA256!==null&&complete(snapshot);const report={schemaVersion:1,sourceCommit:source,sourceSHA256,binarySHA256,project,architecture,environment:{...environment},scope:'owned-application-script-costs',driver:'playwright-test',mode:'diagnostic-only',functionNames:[...functionNames],asyncNames:[...asyncNames],phaseNames:[...phaseNames],timingSemantics:{synchronous:'entry-to-return-inclusive',asynchronous:'entry-to-promise-settlement-inclusive',nested:'overlap-do-not-sum',asyncContinuations:'not-isolated'},...snapshot,complete:done,qualificationCredit:false,workingDaySoakQualified:false,nativeInstalledQualified:false,productionQualificationComplete:false};
 const raw=JSON.stringify(report)+'\n';assert.ok(Buffer.byteLength(raw)<=65536);const parent=path.join(repo,'build/browser-startup');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),real=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===await fs.realpath(path.join(repo,'build')));const fd=await fs.open(path.join(real,'status.json'),'wx',0o600);try{await fd.writeFile(raw,'utf8')}finally{await fd.close()}return done;
}
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function run({referenceBrowser,launchOptions={},headless=true,channel,contextOptions={},viewport={width:1280,height:900}}={}){
 assert.ok(allowed(),'Explicit hosted Linux startup diagnostic required');assert.ok(referenceBrowser&&referenceBrowser.isConnected(),'Test-runner browser fixture required');assert.equal(headless,true);assert.ok(!channel);assert.deepEqual(viewport,{width:1280,height:900});
 const repo=path.resolve(__dirname,'../..'),source=process.env.GITHUB_SHA,project=process.env.BROWSER,arch=process.env.ACCESSWEAVER_EXPECT_GOARCH,v=empty();assert.ok(/^[a-f0-9]{40}$/.test(source)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(arch));assert.equal(process.getuid(),1001);assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:repo,encoding:'utf8'}).trim(),source);assert.equal(execFileSync('git',['status','--porcelain=v1'],{cwd:repo,encoding:'utf8'}).trim(),'');
 const binary=path.join(repo,'build/browser-tests/accessweaver'),parent=path.join(repo,'build/browser-startup-state');let binarySHA256=null,home,child,server,browserChild,context,job,observer;let output='',startFailed=false;
 try{
  v.stage='controller';binarySHA256=await hash(binary,128<<20);const build=JSON.parse(execFileSync(binary,['version','--json'],{encoding:'utf8',timeout:10000,maxBuffer:16384}));assert.ok(build.commit===source&&build.sourceState==='clean'&&build.platform==='linux'&&build.arch===arch&&build.goVersion==='go1.27.3');
  await fs.mkdir(parent,{recursive:true,mode:0o700});home=await fs.mkdtemp(path.join(parent,'case-'));await fs.mkdir(path.join(home,'cache'),{mode:0o700});await P.seedPerformanceProfiles(home);
  child=spawn(binary,['ui'],{stdio:['ignore','pipe','pipe'],env:{...process.env,ACCESSWEAVER_HOME:path.join(home,'state'),ACCESSWEAVER_NO_BROWSER:'1',XDG_CACHE_HOME:path.join(home,'cache'),LOCALAPPDATA:path.join(home,'cache')}});child.once('error',()=>{startFailed=true});for(const stream of [child.stdout,child.stderr])stream?.on('data',data=>{output=(output+data.toString()).slice(-65536)});
  const deadline=performance.now()+15000;let launcher;while(!(launcher=output.match(/Open this private launch file in your browser: (file:[^\r\n]+)/)?.[1])){assert.ok(!startFailed&&child.exitCode===null&&child.signalCode===null&&performance.now()<deadline,'Owned controller startup failed');await pause(25)}
  v.stage='browser';const playwright=require('@playwright/test');server=await playwright[project].launchServer({...launchOptions,headless,channel,host:'127.0.0.1',timeout:30000});browserChild=server.process();const browser=await playwright[project].connect(server.wsEndpoint(),{timeout:30000});context=await browser.newContext({...contextOptions,viewport});
  const body=await fs.readFile(path.join(repo,'web/app.js'),'utf8'),instrumented=instrument(body);v.scriptSHA256=createHash('sha256').update(body).digest('hex');v.instrumentedScriptSHA256=createHash('sha256').update(instrumented).digest('hex');
  await context.route(appPattern,async route=>{assert.equal(route.request().method(),'GET');v.interceptedScripts++;assert.equal(v.interceptedScripts,1);await route.fulfill({status:200,contentType:'application/javascript',body:instrumented})});const page=await context.newPage();
  await page.addInitScript({content:'('+T.installStartupClock.toString()+')('+P.dashboardReady.toString()+',256)'});
  const pageBytes=Number(execFileSync('/usr/bin/getconf',['PAGESIZE'],{encoding:'utf8',timeout:2000,maxBuffer:128}).trim());assert.ok(Number.isSafeInteger(pageBytes)&&pageBytes>0);job=await JobCpu.open({children:[child,browserChild],checks:v.jobCpuChecks});observer=new BrowserResources(browserChild,pageBytes,P.parseStat);await observer.snapshot();v.browserChecks.beforeStartup=true;
  v.stage='startup';const before=await job.sample(),started=performance.now();await page.goto(launcher);const navigated=performance.now();await page.waitForFunction(P.dashboardReady,256,{timeout:10000});const ready=performance.now();await P.paint(page);const painted=performance.now();v.timing.dashboard={navigationMs:navigated-started,applicationMs:ready-navigated,paintMs:painted-ready};v.timing.startupJobCpu=T.startupCpuInterval(before,await job.sample());v.timing.startup=await page.evaluate(T.captureStartup);
  await page.evaluate(()=>globalThis.__accessweaverScriptCosts.markPhase(1));v.stage='profiles';await page.locator('.nav-item[data-view="profiles"]').click();await P.paint(page);v.profilesRendered=await page.locator('#all-profiles .profile-card').count();assert.equal(v.profilesRendered,256);
  await page.evaluate(()=>globalThis.__accessweaverScriptCosts.markPhase(2));v.stage='editor';for(let i=0;i<10;i++){const start=performance.now();await page.locator('#new-profile').click();const acted=performance.now();await page.locator('#editor-modal').waitFor({state:'visible'});const visible=performance.now();await P.paint(page);const done=performance.now();v.timing.editor.push({actionMs:acted-start,visibilityMs:visible-acted,paintMs:done-visible,totalMs:done-start});await page.locator('#close-editor').click();await page.locator('#editor-modal').waitFor({state:'hidden'})}
  await page.waitForFunction(()=>globalThis.__accessweaverScriptCosts.capture().records.every(rows=>rows.every(row=>row.pending===0)),null,{timeout:2000});v.scriptCosts=await page.evaluate(()=>globalThis.__accessweaverScriptCosts.capture());await observer.snapshot();v.browserChecks.afterEditor=true;await job.sample();v.stage='close';
 }catch(error){v.failureKind=P.classifyFailure(error);if(error?.jobCpuStage)v.jobCpuFailureStage=failureStage(error);v.browserFailureStage=observer?.failureStage||0}
 finally{
  if(job)try{await job.close()}catch(error){v.failureKind=P.classifyFailure(error);v.jobCpuFailureStage=failureStage(error)}
  try{if(context){await context.close();v.cleanup.contextClosed=true}}catch(error){v.failureKind=P.classifyFailure(error)}
  try{if(server)await server.close()}catch(error){v.failureKind=P.classifyFailure(error)}
  try{v.cleanup.browserStopped=await C.stopChild(browserChild)}catch(error){v.failureKind=P.classifyFailure(error)}
  try{v.cleanup.controllerStopped=await C.stopChild(child)}catch(error){v.failureKind=P.classifyFailure(error)}
  try{if(home){assert.ok(v.cleanup.controllerStopped);const info=await fs.lstat(home),real=await fs.realpath(home),base=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===base&&path.basename(real).startsWith('case-'));await fs.rm(real,{recursive:true,force:true})}v.cleanup.fixtureRemoved=true}catch(error){v.failureKind=P.classifyFailure(error)}
 }
 if(v.failureKind==='none'&&Object.values(v.cleanup).every(Boolean))v.stage='complete';
 const done=await writeReport(repo,source,binarySHA256,project,arch,v,{platform:process.platform,architecture:process.arch,node:process.version,playwright:require('@playwright/test/package.json').version});assert.ok(done,'Startup script diagnostic incomplete');
}
module.exports={allowed,empty,validate,validateCosts,complete,instrument,instrumentation,profilerSource,functionNames,asyncNames,phaseNames,recordFields,stages,cleanupNames,sources,appPattern,writeReport,run};
