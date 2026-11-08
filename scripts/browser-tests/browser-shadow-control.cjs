// One-property rendering control on a complete owned application fixture.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{spawn,execFileSync}=require('node:child_process'),{createHash}=require('node:crypto'),{performance}=require('node:perf_hooks');
const P=require('./desktop-performance.cjs'),T=require('./browser-timing.cjs'),C=require('./browser-control.cjs'),{BrowserResources}=require('./browser-resources.cjs'),{JobCpu,emptyChecks,checkNames,failureStage}=require('./job-cpu.cjs');
const variants=['original','without-box-shadow'];
const stages=['environment','controller','browser','startup','profiles','editor','close','complete'];
const cleanupNames=['contextClosed','browserStopped','controllerStopped','fixtureRemoved'];
const styleFields=['installed','attached','textMatches','observerStopped','timerStopped','failed','attempts'];
const sources=['scripts/browser-tests/browser-shadow-control.cjs','scripts/browser-tests/browser-shadow-control.test.cjs','scripts/browser-tests/browser-shadow-control.spec.cjs','scripts/browser-tests/shadow.config.cjs','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/browser-control.cjs','scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/browser-timing.cjs','scripts/browser-tests/browser-resources.cjs','scripts/browser-tests/browser-memory.cjs','scripts/browser-tests/job-cpu.cjs','scripts/browser-tests/browser-native-binary.cjs','scripts/browser-tests/check-image-environment.cjs','scripts/browser-tests/performance-budgets.json','scripts/browser-tests/package-lock.json','scripts/check-native-environment.cjs','.github/workflows/browser-shadow.yml','internal/api/server.go','internal/profile/store.go','web/app.js','web/app.css','web/index.html','web/locales.js','web/system.js','go.mod','go.sum'];
const styles={original:'/* owned box-shadow control: original */','without-box-shadow':'*,*::before,*::after{box-shadow:none!important}'};
// Literal source remains byte-identical when the runner transforms this module.
// Both arms install one owned style node before the application starts. No
// script, stylesheet or API request is intercepted in either arm.
const installer=String.raw`(()=>{
 const css=STYLE_LITERAL;
 let style=null,observer=null,timer=null,attempts=0,failed=false,stopped=false;
 const stop=()=>{if(observer!==null){observer.disconnect();observer=null}if(timer!==null){clearTimeout(timer);timer=null}stopped=true};
 const capture=()=>{stop();let attached=false,textMatches=false;try{attached=style!==null&&style.parentNode===document.head;textMatches=style!==null&&style.textContent===css}catch{failed=true}return {installed:style!==null,attached,textMatches,observerStopped:observer===null,timerStopped:timer===null,failed,attempts}};
 Object.defineProperty(globalThis,'__accessweaverShadowControl',{configurable:false,value:Object.freeze({capture})});
 const mount=()=>{if(stopped)return;if(attempts===128){failed=true;stop();return}attempts++;
  try{const head=document.head;if(!head)return;const node=document.createElement('style');node.setAttribute('data-accessweaver-shadow-control','');node.textContent=css;head.appendChild(node);style=node;stop()}catch{failed=true;stop()}
 };
 mount();if(stopped)return;
 if(typeof MutationObserver!=='function'){failed=true;stop();return}
 observer=new MutationObserver(mount);observer.observe(document,{childList:true,subtree:true});timer=setTimeout(()=>{failed=true;stop()},5000);
})();`;
function injectionSource(variant){assert.ok(variants.includes(variant),'Fixed shadow variant required');return installer.replace('STYLE_LITERAL',JSON.stringify(styles[variant]))}
function shadowProjection({variant,phase}){
 if(!['original','without-box-shadow'].includes(variant)||!['startup','editor'].includes(phase))return [];
 const none=variant==='without-box-shadow',selectors=phase==='startup'?['.core-symbol','.brand-mark','.btn-primary']:['#editor-modal .modal-card'];return selectors.map(selector=>{const node=document.querySelector(selector);return !!node&&(getComputedStyle(node).boxShadow==='none')===none});
}
function allowed(env=process.env,platform=process.platform){return platform==='linux'&&env.GITHUB_ACTIONS==='true'&&env.CI==='true'&&env.ACCESSWEAVER_BROWSER_SHADOW==='1'&&env.ACCESSWEAVER_JOB_CPU_ACCOUNTING==='required'}
function empty(){return {stage:'environment',failureKind:'none',profilesRendered:0,timing:T.empty(),styleState:null,shadowChecks:{startup:[false,false,false],editor:[false]},browserChecks:{beforeStartup:false,afterEditor:false},jobCpuChecks:emptyChecks(),jobCpuFailureStage:0,browserFailureStage:0,cleanup:Object.fromEntries(cleanupNames.map(k=>[k,false]))}}
function keys(v,names){assert.ok(v&&typeof v==='object');assert.deepEqual(Object.keys(v).sort(),[...names].sort())}
const numeric=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER;
const sha=n=>typeof n==='string'&&/^[a-f0-9]{64}$/.test(n);
function validate(v){
 keys(v,['stage','failureKind','profilesRendered','timing','styleState','shadowChecks','browserChecks','jobCpuChecks','jobCpuFailureStage','browserFailureStage','cleanup']);assert.ok(stages.includes(v.stage)&&P.failureKinds.includes(v.failureKind)&&Number.isInteger(v.profilesRendered)&&v.profilesRendered>=0&&v.profilesRendered<=256);T.validate(v.timing);
 if(v.styleState!==null){keys(v.styleState,styleFields);for(const k of styleFields.filter(k=>k!=='attempts'))assert.ok(typeof v.styleState[k]==='boolean');assert.ok(Number.isInteger(v.styleState.attempts)&&v.styleState.attempts>=0&&v.styleState.attempts<=128)}
 keys(v.shadowChecks,['startup','editor']);for(const [phase,rows] of Object.entries(v.shadowChecks))assert.ok(Array.isArray(rows)&&rows.length===(phase==='startup'?3:1)&&rows.every(n=>typeof n==='boolean'));
 for(const [k,names] of [['browserChecks',['beforeStartup','afterEditor']],['jobCpuChecks',checkNames],['cleanup',cleanupNames]]){keys(v[k],names);assert.ok(Object.values(v[k]).every(n=>typeof n==='boolean'))}
 for(const k of ['jobCpuFailureStage','browserFailureStage'])assert.ok(Number.isInteger(v[k])&&v[k]>=0&&v[k]<=9);
}
function complete(v){
 validate(v);const s=v.styleState;return v.stage==='complete'&&v.failureKind==='none'&&v.profilesRendered===256&&T.startupComplete(v.timing.startup)&&v.timing.startupJobCpu!==null&&Object.values(v.timing.dashboard).every(numeric)&&v.timing.editor.length===10&&s!==null&&s.installed&&s.attached&&s.textMatches&&s.observerStopped&&s.timerStopped&&!s.failed&&s.attempts>0&&Object.values(v.shadowChecks).every(rows=>rows.every(Boolean))&&Object.values(v.browserChecks).every(Boolean)&&Object.values(v.jobCpuChecks).every(Boolean)&&!v.jobCpuFailureStage&&!v.browserFailureStage&&Object.values(v.cleanup).every(Boolean);
}
async function hash(file,cap){const fd=await fs.open(file,'r');try{const a=await fd.stat();assert.ok(a.isFile()&&a.size>0&&a.size<=cap);const h=createHash('sha256'),buffer=Buffer.alloc(65536);let size=0;for(;;){const n=await fd.read(buffer,0,Math.min(buffer.length,cap-size+1),null);if(!n.bytesRead)break;size+=n.bytesRead;assert.ok(size<=cap);h.update(buffer.subarray(0,n.bytesRead))}const b=await fd.stat();assert.ok(size===a.size&&a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs);return h.digest('hex')}finally{await fd.close()}}
async function writeReport(repo,source,binarySHA256,project,architecture,variant,value,environment){
 validate(value);assert.ok(/^[a-f0-9]{40}$/.test(source)&&(binarySHA256===null||sha(binarySHA256))&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture)&&variants.includes(variant));keys(environment,['platform','architecture','node','playwright']);assert.deepEqual(environment,{platform:'linux',architecture:architecture==='amd64'?'x64':'arm64',node:'v26.8.2',playwright:require('./package-lock.json').packages[''].devDependencies['@playwright/test']});
 const snapshot=JSON.parse(JSON.stringify(value)),sourceSHA256={};for(const file of sources)sourceSHA256[file]=await hash(path.join(repo,file),1<<20);if(binarySHA256!==null)assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binarySHA256);
 const done=binarySHA256!==null&&complete(snapshot),report={schemaVersion:1,sourceCommit:source,sourceSHA256,binarySHA256,project,architecture,variant,environment:{...environment},scope:'owned-box-shadow-control',driver:'playwright-test',mode:'diagnostic-only',overrideSHA256:createHash('sha256').update(styles[variant]).digest('hex'),injectionSHA256:createHash('sha256').update(injectionSource(variant)).digest('hex'),applicationScriptIntercepted:false,applicationStylesheetIntercepted:false,apiIntercepted:false,...snapshot,complete:done,qualificationCredit:false,workingDaySoakQualified:false,nativeInstalledQualified:false,productionQualificationComplete:false};
 const raw=JSON.stringify(report)+'\n';assert.ok(Buffer.byteLength(raw)<=32768);const parent=path.join(repo,'build/browser-shadow');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),real=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===await fs.realpath(path.join(repo,'build')));const fd=await fs.open(path.join(real,'status.json'),'wx',0o600);try{await fd.writeFile(raw,'utf8')}finally{await fd.close()}return done;
}
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function run({variant=process.env.SHADOW_VARIANT,referenceBrowser,launchOptions={},headless=true,channel,contextOptions={},viewport={width:1280,height:900}}={}){
 assert.ok(allowed(),'Explicit hosted Linux shadow diagnostic required');assert.ok(referenceBrowser&&referenceBrowser.isConnected(),'Test-runner browser fixture required');assert.ok(variants.includes(variant),'Fixed shadow variant required');assert.equal(headless,true);assert.ok(!channel);assert.deepEqual(viewport,{width:1280,height:900});
 const repo=path.resolve(__dirname,'../..'),source=process.env.GITHUB_SHA,project=process.env.BROWSER,arch=process.env.ACCESSWEAVER_EXPECT_GOARCH,v=empty();assert.ok(/^[a-f0-9]{40}$/.test(source)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(arch));assert.equal(process.getuid(),1001);assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:repo,encoding:'utf8'}).trim(),source);assert.equal(execFileSync('git',['status','--porcelain=v1'],{cwd:repo,encoding:'utf8'}).trim(),'');
 const binary=path.join(repo,'build/browser-tests/accessweaver'),parent=path.join(repo,'build/browser-shadow-state');let binarySHA256=null,home,child,server,browserChild,context,job,observer;let output='',startFailed=false;
 try{
  v.stage='controller';binarySHA256=await hash(binary,128<<20);const build=JSON.parse(execFileSync(binary,['version','--json'],{encoding:'utf8',timeout:10000,maxBuffer:16384}));assert.ok(build.commit===source&&build.sourceState==='clean'&&build.platform==='linux'&&build.arch===arch&&build.goVersion==='go1.27.3');
  await fs.mkdir(parent,{recursive:true,mode:0o700});home=await fs.mkdtemp(path.join(parent,'case-'));await fs.mkdir(path.join(home,'cache'),{mode:0o700});await P.seedPerformanceProfiles(home);
  child=spawn(binary,['ui'],{stdio:['ignore','pipe','pipe'],env:{...process.env,ACCESSWEAVER_HOME:path.join(home,'state'),ACCESSWEAVER_NO_BROWSER:'1',XDG_CACHE_HOME:path.join(home,'cache'),LOCALAPPDATA:path.join(home,'cache')}});child.once('error',()=>{startFailed=true});for(const stream of [child.stdout,child.stderr])stream?.on('data',data=>{output=(output+data.toString()).slice(-65536)});
  const deadline=performance.now()+15000;let launcher;while(!(launcher=output.match(/Open this private launch file in your browser: (file:[^\r\n]+)/)?.[1])){assert.ok(!startFailed&&child.exitCode===null&&child.signalCode===null&&performance.now()<deadline,'Owned controller startup failed');await pause(25)}
  v.stage='browser';const playwright=require('@playwright/test');server=await playwright[project].launchServer({...launchOptions,headless,channel,host:'127.0.0.1',timeout:30000});browserChild=server.process();const browser=await playwright[project].connect(server.wsEndpoint(),{timeout:30000});context=await browser.newContext({...contextOptions,viewport});
  const page=await context.newPage();await page.addInitScript({content:injectionSource(variant)});
  await page.addInitScript({content:'('+T.installStartupClock.toString()+')('+P.dashboardReady.toString()+',256)'});
  const pageBytes=Number(execFileSync('/usr/bin/getconf',['PAGESIZE'],{encoding:'utf8',timeout:2000,maxBuffer:128}).trim());assert.ok(Number.isSafeInteger(pageBytes)&&pageBytes>0);job=await JobCpu.open({children:[child,browserChild],checks:v.jobCpuChecks});observer=new BrowserResources(browserChild,pageBytes,P.parseStat);await observer.snapshot();v.browserChecks.beforeStartup=true;
  v.stage='startup';const before=await job.sample(),started=performance.now();await page.goto(launcher);const navigated=performance.now();await page.waitForFunction(P.dashboardReady,256,{timeout:10000});const ready=performance.now();await P.paint(page);const painted=performance.now();v.timing.dashboard={navigationMs:navigated-started,applicationMs:ready-navigated,paintMs:painted-ready};v.timing.startupJobCpu=T.startupCpuInterval(before,await job.sample());v.timing.startup=await page.evaluate(T.captureStartup);v.styleState=await page.evaluate(()=>globalThis.__accessweaverShadowControl.capture());v.shadowChecks.startup=await page.evaluate(shadowProjection,{variant,phase:'startup'});
  v.stage='profiles';await page.locator('.nav-item[data-view="profiles"]').click();await P.paint(page);v.profilesRendered=await page.locator('#all-profiles .profile-card').count();assert.equal(v.profilesRendered,256);
  v.stage='editor';for(let i=0;i<10;i++){const start=performance.now();await page.locator('#new-profile').click();const acted=performance.now();await page.locator('#editor-modal').waitFor({state:'visible'});const visible=performance.now();await P.paint(page);const done=performance.now();v.timing.editor.push({actionMs:acted-start,visibilityMs:visible-acted,paintMs:done-visible,totalMs:done-start});if(i===9)v.shadowChecks.editor=await page.evaluate(shadowProjection,{variant,phase:'editor'});await page.locator('#close-editor').click();await page.locator('#editor-modal').waitFor({state:'hidden'})}
  v.styleState=await page.evaluate(()=>globalThis.__accessweaverShadowControl.capture());await observer.snapshot();v.browserChecks.afterEditor=true;await job.sample();v.stage='close';
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
 const done=await writeReport(repo,source,binarySHA256,project,arch,variant,v,{platform:process.platform,architecture:process.arch,node:process.version,playwright:require('@playwright/test/package.json').version});assert.ok(done,'Shadow control observation incomplete');
}
module.exports={allowed,empty,validate,complete,injectionSource,installer,shadowProjection,styles,variants,styleFields,stages,cleanupNames,sources,writeReport,run};
