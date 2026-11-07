// Hosted, owned loopback workload only. Evidence is fixed numeric fields/hashes.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto'),{execFileSync}=require('node:child_process'),{performance}=require('node:perf_hooks');
const P=require('./desktop-performance.cjs'),{BrowserResources}=require('./browser-resources.cjs'),{JobCpu,usageBetween}=require('./job-cpu.cjs');
const seconds=900,requestsPerSecond=4,checkpointSeconds=100;
const stages=['environment','baseline','workload','cooldown','close','complete'];
const counts=['seconds','requests','navigation','editor','samples','elapsedMilliseconds'];
const limits={browserPeakRssBytes:1073741824,controllerPeakRssBytes:201326592,browserPeakDescriptors:1024,browserPeakThreads:512,browserPeakProcesses:64,controllerPeakDescriptors:128,controllerPeakThreads:128,browserRssGrowthBytes:268435456,controllerRssGrowthBytes:67108864,browserDescriptorGrowth:64,browserThreadGrowth:64,browserProcessGrowth:4,controllerDescriptorGrowth:2,controllerThreadGrowth:8,navigationP95Ms:500,editorP95Ms:500,apiP95Ms:250,browserCpuPercentOneCore:300,controllerCpuPercentOneCore:50,jobCpuPercentOneCore:100,maximumSampleGapMs:5000,lateMedianRssGrowthBytes:67108864};
const sources=['scripts/browser-tests/browser-soak.cjs','scripts/browser-tests/browser-soak.test.cjs','scripts/browser-tests/soak.config.cjs','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/browser-resources.cjs','scripts/browser-tests/browser-memory.cjs','scripts/browser-tests/job-cpu.cjs','scripts/browser-tests/performance-budgets.json','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/package-lock.json','scripts/check-native-environment.cjs','scripts/browser-tests/check-image-environment.cjs','web/app.js','web/system.js','web/locales.js','web/app.css','web/index.html','.github/workflows/browser-soak.yml'];
function allowed(env=process.env,platform=process.platform){return platform==='linux'&&env.GITHUB_ACTIONS==='true'&&env.CI==='true'&&env.ACCESSWEAVER_BROWSER_SOAK==='1'&&env.ACCESSWEAVER_JOB_CPU_ACCOUNTING==='required'}
function empty(){return {stage:'environment',failureKind:'none',counts:Object.fromEntries(counts.map(n=>[n,0])),metrics:Object.fromEntries(Object.keys(limits).map(n=>[n,null])),checkpoints:[]}}
function validate(v){
 assert.deepEqual(Object.keys(v).sort(),['stage','failureKind','counts','metrics','checkpoints'].sort());assert.ok(stages.includes(v.stage)&&P.failureKinds.includes(v.failureKind));
 assert.deepEqual(Object.keys(v.counts).sort(),[...counts].sort());assert.ok(Object.values(v.counts).every(n=>Number.isSafeInteger(n)&&n>=0&&n<=10000000));
 assert.deepEqual(Object.keys(v.metrics).sort(),Object.keys(limits).sort());assert.ok(Object.values(v.metrics).every(n=>n===null||typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=Number.MAX_SAFE_INTEGER));
 assert.ok(Array.isArray(v.checkpoints)&&v.checkpoints.length<=10);
 for(let i=0;i<v.checkpoints.length;i++){const p=v.checkpoints[i];assert.deepEqual(Object.keys(p).sort(),['second','browserRssBytes','controllerRssBytes','browserDescriptors','controllerDescriptors','browserThreads','controllerThreads','browserProcesses'].sort());assert.equal(p.second,i*checkpointSeconds);assert.ok(Object.values(p).every(n=>Number.isSafeInteger(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER))}
}
function violations(v){validate(v);const bad=Object.keys(limits).filter(k=>v.metrics[k]===null||v.metrics[k]>limits[k]);const c=v.counts;if(c.seconds!==seconds||c.requests!==seconds*requestsPerSecond||c.navigation!==seconds/5||c.editor!==seconds/30||c.samples!==seconds+1||c.elapsedMilliseconds<seconds*1000||c.requests/(c.elapsedMilliseconds/1000)<3.8||v.checkpoints.length!==10)bad.push('workload');return bad}
function median(rows){assert.ok(rows.length===300&&rows.every(n=>Number.isFinite(n)&&n>=0));return P.percentile(rows,.5)}
async function hash(file,cap){const fd=await fs.open(file,'r');try{const a=await fd.stat();assert.ok(a.isFile()&&a.size>0&&a.size<=cap);const h=createHash('sha256'),buffer=Buffer.alloc(65536);let n=0;for(;;){const r=await fd.read(buffer,0,Math.min(buffer.length,cap-n+1),null);if(!r.bytesRead)break;n+=r.bytesRead;assert.ok(n<=cap);h.update(buffer.subarray(0,r.bytesRead))}const b=await fd.stat();assert.ok(n===a.size&&a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs);return h.digest('hex')}finally{await fd.close()}}
async function writeReport(repo,source,binarySHA256,project,architecture,value){
 validate(value);assert.ok(/^[a-f0-9]{40}$/.test(source)&&/^[a-f0-9]{64}$/.test(binarySHA256)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(architecture));
 const snapshot=JSON.parse(JSON.stringify(value)),failed=violations(snapshot),sourceSHA256={};for(const file of sources)sourceSHA256[file]=await hash(path.join(repo,file),1<<20);assert.equal(await hash(path.join(repo,'build/browser-tests/accessweaver'),128<<20),binarySHA256);
 const report={schemaVersion:1,sourceCommit:source,sourceSHA256,binarySHA256,project,architecture,scope:'owned-linux-browser-15-minute-soak',...snapshot,violations:failed,outcome:snapshot.stage==='complete'&&snapshot.failureKind==='none'&&!failed.length?'passed':'failed',workingDaySoakQualified:false,nativeInstalledQualified:false,productionQualificationComplete:false};
 const encoded=JSON.stringify(report)+'\n';assert.ok(Buffer.byteLength(encoded)<=16384);const parent=path.join(repo,'build/browser-soak');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),real=await fs.realpath(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(real)===await fs.realpath(path.join(repo,'build')));const fd=await fs.open(path.join(real,'status.json'),'wx',0o600);try{await fd.writeFile(encoded,'utf8')}finally{await fd.close()}return report.outcome;
}
async function driveWorkload({start,waitUntil,requests,interact,complete}){
 for(let i=0;i<seconds;i++){
  await waitUntil(start+i*1000);
  // Both owned operations settle before any failure propagates to cleanup.
  const results=await Promise.allSettled([requests(),interact(i)]);
  for(const r of results)if(r.status==='rejected')throw r.reason;
  await waitUntil(start+(i+1)*1000);await complete(i+1,results[0].value);
 }
}
async function runSoak(page,core,testInfo,browserChild){
 assert.ok(allowed(),'Soak requires the explicit disposable hosted Linux environment');
 const v=empty(),m=v.metrics,c=v.counts,browserRss=[],api=[],nav=[],editor=[];let job,observer,identity=null,lastSample,first,previous,jobBefore,beforeTime,hz,pageBytes;
 const sample=async second=>{
  const a=await P.sampleController(core.controller,identity,pageBytes);identity=a.startTicks;const b=await observer.snapshot();const now=performance.now();
  if(lastSample!==undefined)m.maximumSampleGapMs=Math.max(m.maximumSampleGapMs||0,now-lastSample);lastSample=now;c.samples++;
  for(const [name,n] of Object.entries({browserPeakRssBytes:b.rssBytes,controllerPeakRssBytes:a.rssBytes,browserPeakDescriptors:b.descriptors,browserPeakThreads:b.threads,browserPeakProcesses:b.processes,controllerPeakDescriptors:a.descriptors,controllerPeakThreads:a.threads}))m[name]=Math.max(m[name]||0,n);
  if(second%checkpointSeconds===0)v.checkpoints.push({second,browserRssBytes:b.rssBytes,controllerRssBytes:a.rssBytes,browserDescriptors:b.descriptors,controllerDescriptors:a.descriptors,browserThreads:b.threads,controllerThreads:a.threads,browserProcesses:b.processes});
  if(second>0)browserRss.push(b.rssBytes);return {a,b};
 };
 try{
  pageBytes=Number(execFileSync('/usr/bin/getconf',['PAGESIZE'],{encoding:'utf8',timeout:2000,maxBuffer:128}).trim());hz=Number(execFileSync('/usr/bin/getconf',['CLK_TCK'],{encoding:'utf8',timeout:2000,maxBuffer:128}).trim());assert.ok(Number.isSafeInteger(pageBytes)&&pageBytes>0&&Number.isSafeInteger(hz)&&hz>0);
  observer=new BrowserResources(browserChild,pageBytes,P.parseStat);job=await JobCpu.open({children:[core.controller,browserChild]});v.stage='baseline';await page.waitForFunction(P.dashboardReady,P.budgets.profiles,{timeout:10000});first=await sample(0);jobBefore=await job.sample();beforeTime=performance.now();const views=['dashboard','profiles','engines','diagnostics','settings','system'];v.stage='workload';
  const interaction=async i=>{
    if(i%5===0){const view=views[(i/5)%views.length],started=performance.now();await page.locator('.nav-item[data-view="'+view+'"]').click();await page.locator('#view-'+view+'.active').waitFor({state:'visible'});await P.paint(page);if(view==='profiles')assert.equal(await page.locator('#all-profiles .profile-card').count(),P.budgets.profiles);nav.push(performance.now()-started);c.navigation++}
    if(i%30===0){await page.locator('.nav-item[data-view="profiles"]').click();await P.paint(page);const started=performance.now();await page.locator('#new-profile').click();await page.locator('#editor-modal').waitFor({state:'visible'});await P.paint(page);editor.push(performance.now()-started);c.editor++;await page.locator('#close-editor').click();await page.locator('#editor-modal').waitFor({state:'hidden'})}
  };
  await driveWorkload({start:beforeTime,waitUntil:P.waitUntil,requests:()=>P.requestBatch(page,requestsPerSecond),interact:interaction,complete:async(i,latencies)=>{api.push(...latencies);c.requests+=requestsPerSecond;previous=await sample(i);c.seconds++}});
  c.elapsedMilliseconds=Math.floor(performance.now()-beforeTime);const jobAfter=await job.sample();m.jobCpuPercentOneCore=usageBetween(jobBefore,jobAfter).percentOneCore;m.controllerCpuPercentOneCore=P.cpuPercent(first.a,previous.a,hz,c.elapsedMilliseconds);m.browserCpuPercentOneCore=(previous.b.cpuTicks-first.b.cpuTicks)/hz/(c.elapsedMilliseconds/1000)*100;
  m.navigationP95Ms=P.percentile(nav);m.editorP95Ms=P.percentile(editor);m.apiP95Ms=P.percentile(api);m.lateMedianRssGrowthBytes=median(browserRss.slice(600,900))-median(browserRss.slice(300,600));
  v.stage='cooldown';await P.waitUntil(performance.now()+5000);const a=await P.sampleController(core.controller,identity,pageBytes),b=await observer.snapshot();
  // Cooldown observations remain included in all absolute peak caps.
  for(const [name,n] of Object.entries({browserPeakRssBytes:b.rssBytes,controllerPeakRssBytes:a.rssBytes,browserPeakDescriptors:b.descriptors,browserPeakThreads:b.threads,browserPeakProcesses:b.processes,controllerPeakDescriptors:a.descriptors,controllerPeakThreads:a.threads}))m[name]=Math.max(m[name],n);
  Object.assign(m,{browserRssGrowthBytes:b.rssBytes-first.b.rssBytes,controllerRssGrowthBytes:a.rssBytes-first.a.rssBytes,browserDescriptorGrowth:b.descriptors-first.b.descriptors,browserThreadGrowth:b.threads-first.b.threads,browserProcessGrowth:b.processes-first.b.processes,controllerDescriptorGrowth:a.descriptors-first.a.descriptors,controllerThreadGrowth:a.threads-first.a.threads});v.stage='complete';
 }catch(error){v.failureKind=P.classifyFailure(error)}finally{if(job)try{await job.close()}catch(error){v.stage='close';v.failureKind=P.classifyFailure(error)}}
 const outcome=await writeReport(path.resolve(__dirname,'../..'),core.build.commit,core.binarySha256,testInfo.project.name,process.env.ACCESSWEAVER_EXPECT_GOARCH,v);assert.equal(outcome,'passed','Browser soak contract failed at '+v.stage);
}
module.exports={seconds,requestsPerSecond,checkpointSeconds,counts,limits,sources,stages,allowed,empty,validate,violations,median,writeReport,driveWorkload,runSoak};
