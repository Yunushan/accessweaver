// Source-known root test labels/statuses only. Raw Go output and dynamic
// subtest names remain in bounded memory and are never written or echoed.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto'),{spawn,execFileSync}=require('node:child_process');
const MODULE='github.com/Yunushan/accessweaver',modes=['unit','race','vet'],stages=['identity','catalog','execute','source','complete'];
const sources=['.github/workflows/native-core.yml','scripts/core-test-evidence.cjs','scripts/core-test-catalog/main.go','scripts/core-test-catalog/main_test.go','go.mod','go.sum'];
function reportSources(platform){return platform==='darwin'?[...sources,'.github/workflows/release.yml']:sources}
// Only these public, fixed CLI cases/phases may appear in supplemental
// annotations. Dynamic test labels and Output payloads are never retained.
const closedPipePackage=MODULE+'/cmd/accessweaver',closedPipeRoot='TestRecordedEngineClosedStdoutAndStderrReapBeforeScopeRestoration',closedPipeRepeat='TestRecordedEngineClosedStandardPipeRepeated';
const closedPipePhases=['intent-checkpoint','worker-completion','scope-cleanup','sigpipe-restoration','journal-integrity'];
const closedPipeCases=['intent','accepted','notice'];
const closedPipeWorkerStages=['worker-initialized','worker-command','worker-outcome','worker-notice','worker-dispatch','worker-pid-read','worker-pid-parse','worker-reaped','worker-inventory','worker-journal-open','worker-journal-lock','worker-controller-open','worker-controller-lock','worker-proof','worker-restoration','worker-unavailable'];
const closedPipeLabels=new Set();
for(const root of [closedPipeRoot,...Array.from({length:20},(_,i)=>closedPipeRepeat+'/attempt-'+(i+1))])for(const mode of closedPipeCases){closedPipeLabels.add(root+'/'+mode);for(const phase of closedPipePhases)if(phase!=='intent-checkpoint'||mode==='accepted')closedPipeLabels.add(root+'/'+mode+'/'+phase)}
for(const label of [...closedPipeLabels])if(label.endsWith('/scope-cleanup'))for(const stage of closedPipeWorkerStages)closedPipeLabels.add(label+'/'+stage);
function exact(value,keys){assert.deepEqual(Object.keys(value).sort(),[...keys].sort(),'Core evidence schema differs')}
function planValue(plan){exact(plan,['schemaVersion','module','packages']);assert.ok(plan.schemaVersion===1&&plan.module===MODULE&&Array.isArray(plan.packages)&&plan.packages.length>0&&plan.packages.length<=128);let roots=0;const packages=new Set();for(const p of plan.packages){exact(p,['path','tests']);assert.ok(typeof p.path==='string'&&(p.path===MODULE||p.path.startsWith(MODULE+'/'))&&/^[A-Za-z0-9_./-]+$/.test(p.path)&&p.path.length<=256&&!packages.has(p.path));packages.add(p.path);assert.ok(Array.isArray(p.tests)&&new Set(p.tests).size===p.tests.length);for(const name of p.tests)assert.ok(typeof name==='string'&&/^(Test|Fuzz|Example)[\p{L}\p{N}_]*$/u.test(name)&&name.length<=256);roots+=p.tests.length}assert.ok(roots<=20000)}
class Tracker{
 constructor(plan){planValue(plan);this.closedPipeFailures=new Set();this.unknown=0;this.overflow=false;this.discardedOutputEvents=0;this.buildFailures=0;this.packages=plan.packages.map(p=>({path:p.path,status:'not-run',elapsedMilliseconds:0,tests:p.tests.map(name=>({name,status:'not-run',attempts:0,elapsedMilliseconds:0,childPassed:0,childFailed:0,childSkipped:0}))}));}
 increment(key){if(this[key]>=10000000)this.overflow=true;else this[key]++}
 event(event){
  const action=event?.Action;if(action==='output'||action==='build-output'){this.increment('discardedOutputEvents');return}if(action==='build-start')return;if(action==='build-fail'){this.increment('buildFailures');return}
  if(!['start','run','pause','cont','pass','fail','skip','bench'].includes(action)){this.increment('unknown');return}
  const p=this.packages.find(p=>p.path===event.Package);if(!p){this.increment('unknown');return}
  if(event.Test!==undefined&&event.Test!==''){
   if(typeof event.Test!=='string'||event.Test.length>65536){this.increment('unknown');return}const slash=event.Test.indexOf('/'),root=slash<0?event.Test:event.Test.slice(0,slash),t=p.tests.find(t=>t.name===root);if(!t){this.increment('unknown');return}
   if(slash>=0){if(action==='fail'&&p.path===closedPipePackage&&closedPipeLabels.has(event.Test)&&this.closedPipeFailures.size<10)this.closedPipeFailures.add(event.Test);if(['pass','fail','skip'].includes(action)){const key={pass:'childPassed',fail:'childFailed',skip:'childSkipped'}[action];if(t[key]>=10000000)this.overflow=true;else t[key]++}return}
   if(action==='run'){if(t.attempts>=16){this.overflow=true;return}t.attempts++;t.status='running'}
   if(['pass','fail','skip'].includes(action)){if(['passed','failed','skipped'].includes(t.status)){this.increment('unknown');return}t.status={pass:'passed',fail:'failed',skip:'skipped'}[action];t.elapsedMilliseconds=elapsed(event.Elapsed)}
  }else{
   if(action==='start')p.status='running';else if(['pass','fail','skip'].includes(action)){if(['passed','failed','skipped'].includes(p.status)){this.increment('unknown');return}p.status={pass:'passed',fail:'failed',skip:'skipped'}[action];p.elapsedMilliseconds=elapsed(event.Elapsed)}
  }
 }
 value(mode,exitCode){assert.ok(modes.includes(mode));const packages=this.packages.map(p=>({...p,tests:p.tests.map(t=>({...t}))}));if(mode==='vet'&&exitCode===0)for(const p of packages)p.status='vet-passed';const roots=packages.flatMap(p=>p.tests),passed=exitCode===0&&!this.unknown&&!this.overflow&&!this.buildFailures&&packages.every(p=>mode==='vet'?p.status==='vet-passed':['passed','skipped'].includes(p.status))&&(mode==='vet'||roots.every(t=>['passed','skipped'].includes(t.status)&&t.attempts===1&&t.childFailed===0));return {unknownEvents:this.unknown,overflow:this.overflow,discardedOutputEvents:this.discardedOutputEvents,buildFailures:this.buildFailures,packages,outcome:passed?'passed':'failed'};}
}
function elapsed(value){return value===undefined?0:Number.isFinite(value)&&value>=0&&value<=86400?Math.round(value*1000):0}
function command(repo,args){return execFileSync(args[0],args.slice(1),{cwd:repo,encoding:'utf8',maxBuffer:8<<20,stdio:['pipe','pipe','ignore'],timeout:180000})}
function identity(repo){const source=command(repo,['git','rev-parse','HEAD']).trim(),tree=command(repo,['git','rev-parse','HEAD^{tree}']).trim();assert.ok(/^[0-9a-f]{40}$/.test(source)&&/^[0-9a-f]{40}$/.test(tree));assert.equal(command(repo,['git','status','--porcelain=v1']),'','Core source must be clean');return {source,tree}}
function testArguments(mode,previewRoot=false,releaseDarwin=false){
 assert.ok(modes.includes(mode)&&(!releaseDarwin||(mode==='unit'&&!previewRoot)));
 if(mode==='vet')return ['vet','./...'];
 const scheduling=releaseDarwin?[]:previewRoot?['-timeout=6m']:['-p=2'];
 return ['test','-json','-count=1',...scheduling,...(mode==='race'?['-race']:[]),'./...'];
}
// Windows ChildProcess.kill uses libuv's retained process handle, not uv_kill's
// numeric-PID reopen. This owns only the root, not an arbitrary descendant tree.
// https://raw.githubusercontent.com/nodejs/node/v26.8.2/deps/uv/src/win/process.c
function signalOwnedChild(child,platform,signal,groupKill=process.kill){assert.ok(['linux','win32','darwin'].includes(platform));try{if(platform==='win32')child.kill(signal);else groupKill(-child.pid,signal)}catch{}}
function failureAnnotations(plan,projected){
 planValue(plan);const labels=[];
 for(const p of plan.packages){const actual=projected.packages.find(value=>value.path===p.path);if(!actual)continue;let failed=false;
  for(const name of p.tests){if(actual.tests.some(t=>t.name===name&&t.status==='failed')){labels.push(p.path+'#'+name);failed=true;if(labels.length===10)return labels}}
  if(!failed&&actual.status==='failed'){labels.push(p.path);if(labels.length===10)return labels}
 }
 return labels;
}
function closedPipeFailureAnnotations(tracker){return [...tracker.closedPipeFailures].filter(label=>closedPipeLabels.has(label)).map(label=>closedPipePackage+'#'+label)}
async function run(repo,mode,tracker){
 const args=testArguments(mode,process.env.CORE_PREVIEW_ROOT_LAYOUT==='1',process.platform==='darwin'),windows=process.platform==='win32';
 return new Promise(resolve=>{const child=spawn('go',args,{cwd:repo,env:{...process.env,GOTOOLCHAIN:'local'},stdio:['ignore',mode==='vet'?'ignore':'pipe','ignore'],detached:!windows,windowsHide:true});let pending=Buffer.alloc(0),bytes=0,failed=false,forced=false,closed=false,killTimer;
 const stop=()=>{if(forced||closed)return;forced=true;signalOwnedChild(child,process.platform,'SIGTERM');killTimer=setTimeout(()=>{signalOwnedChild(child,process.platform,'SIGKILL')},5000)};
 const timer=setTimeout(()=>{failed=true;stop()},12*60000);
 const line=raw=>{if(!raw.length)return;try{tracker.event(JSON.parse(raw.toString('utf8')))}catch{failed=true;stop()}};
 child.stdout?.on('data',chunk=>{if(failed)return;bytes+=chunk.length;if(bytes>128<<20){failed=true;stop();return}pending=Buffer.concat([pending,chunk]);for(;;){const end=pending.indexOf(10);if(end<0)break;if(end>1<<20){failed=true;stop();return}line(pending.subarray(0,end));pending=pending.subarray(end+1)}if(pending.length>1<<20){failed=true;stop()}});
 child.once('error',()=>{failed=true});child.once('close',code=>{closed=true;clearTimeout(timer);clearTimeout(killTimer);if(!failed&&pending.length)line(pending);resolve({exitCode:Number.isInteger(code)&&code>=0&&code<=255?code:null,streamValid:!failed,bytes})});
 });
}
async function boundedHash(file){const fd=await fs.open(file,'r');try{const a=await fd.stat();assert.ok(a.isFile()&&a.size>0&&a.size<=2<<20);const hash=createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;for(;;){const {bytesRead}=await fd.read(buffer,0,Math.min(buffer.length,(2<<20)-total+1),null);if(!bytesRead)break;total+=bytesRead;assert.ok(total<=2<<20);hash.update(buffer.subarray(0,bytesRead))}const b=await fd.stat();assert.ok(total===a.size&&a.size===b.size&&a.dev===b.dev&&a.ino===b.ino&&a.mtimeMs===b.mtimeMs);return hash.digest('hex')}finally{await fd.close()}}
async function writeReport(repo,data,filename='status.json'){
 assert.ok(['status.json',...modes.map(mode=>'status-'+mode+'.json')].includes(filename),'Unsupported core report name');
 exact(data,['schemaVersion','sourceCommit','sourceTree','sourceSHA256','platform','architecture','go','mode','stage','exitCode','streamValid','sourceStable','inputBytes','unknownEvents','overflow','discardedOutputEvents','buildFailures','packages','outcome','productionQualificationComplete']);assert.ok(data.schemaVersion===1&&/^[0-9a-f]{40}$/.test(data.sourceCommit)&&/^[0-9a-f]{40}$/.test(data.sourceTree)&&['linux','windows','darwin'].includes(data.platform)&&(data.platform==='linux'||data.mode==='unit')&&['amd64','arm64'].includes(data.architecture)&&data.go==='go1.27.3'&&modes.includes(data.mode)&&stages.includes(data.stage)&&[null,...Array.from({length:256},(_,i)=>i)].includes(data.exitCode)&&typeof data.streamValid==='boolean'&&typeof data.sourceStable==='boolean'&&typeof data.overflow==='boolean'&&data.productionQualificationComplete===false&&['passed','failed'].includes(data.outcome));
 for(const k of ['inputBytes','unknownEvents','discardedOutputEvents','buildFailures'])assert.ok(Number.isSafeInteger(data[k])&&data[k]>=0&&data[k]<=134217728);exact(data.sourceSHA256,reportSources(data.platform));assert.ok(Object.values(data.sourceSHA256).every(v=>/^[0-9a-f]{64}$/.test(v)));assert.ok(Array.isArray(data.packages)&&data.packages.length<=128);
 for(const p of data.packages){exact(p,['path','status','elapsedMilliseconds','tests']);assert.ok(p.path===MODULE||p.path.startsWith(MODULE+'/'));assert.ok(['not-run','running','passed','failed','skipped','vet-passed'].includes(p.status));assert.ok(Number.isSafeInteger(p.elapsedMilliseconds)&&p.elapsedMilliseconds>=0&&p.elapsedMilliseconds<=86400000);for(const t of p.tests){exact(t,['name','status','attempts','elapsedMilliseconds','childPassed','childFailed','childSkipped']);assert.ok(/^(Test|Fuzz|Example)[\p{L}\p{N}_]*$/u.test(t.name)&&t.name.length<=256&&['not-run','running','passed','failed','skipped'].includes(t.status));for(const k of ['attempts','elapsedMilliseconds','childPassed','childFailed','childSkipped'])assert.ok(Number.isSafeInteger(t[k])&&t[k]>=0&&t[k]<=86400000)}}
 const roots=data.packages.flatMap(p=>p.tests);const passed=data.stage==='complete'&&data.exitCode===0&&data.streamValid&&data.sourceStable&&!data.unknownEvents&&!data.overflow&&!data.buildFailures&&data.packages.length>0&&data.packages.every(p=>data.mode==='vet'?p.status==='vet-passed':['passed','skipped'].includes(p.status))&&(data.mode==='vet'||roots.every(t=>['passed','skipped'].includes(t.status)&&t.attempts===1&&t.childFailed===0));assert.equal(data.outcome==='passed',passed,'Core evidence outcome differs');
 const encoded=JSON.stringify(data)+'\n';assert.ok(Buffer.byteLength(encoded)<=8<<20);const folder=path.join(repo,'build/native-core-evidence');await fs.mkdir(folder,{recursive:true,mode:0o700});const info=await fs.lstat(folder),resolved=await fs.realpath(folder),build=await fs.realpath(path.join(repo,'build'));assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(resolved)===build);const fd=await fs.open(path.join(resolved,filename),'wx',0o600);try{await fd.writeFile(encoded,'utf8')}finally{await fd.close()}
}
async function main(){
 const mode=process.argv[2],repo=path.resolve(__dirname,'..');
 const platform={linux:'linux',win32:'windows',darwin:'darwin'}[process.platform];
 assert.ok(platform&&process.env.GITHUB_ACTIONS==='true'&&modes.includes(mode)&&(platform==='linux'||mode==='unit'));
 if(platform!=='linux'){
  const runnerOS={windows:'Windows',darwin:'macOS'}[platform];
  assert.ok(process.env.RUNNER_ENVIRONMENT==='github-hosted'&&process.env.RUNNER_OS===runnerOS);
 }
 for(const key of ['CORE_PREVIEW_ROOT_LAYOUT','CORE_MODE_REPORTS','CORE_FAILURE_ANNOTATIONS'])assert.ok(process.env[key]===undefined||['0','1'].includes(process.env[key]));
 const arch={x64:'amd64',arm64:'arm64'}[process.arch];
 assert.equal(platform,process.env.ACCESSWEAVER_EXPECT_GOOS);
 assert.equal(arch,process.env.ACCESSWEAVER_EXPECT_GOARCH);
 const before=identity(repo);
 assert.equal(before.source,process.env.GITHUB_SHA);
 assert.equal(command(repo,['go','version']).trim(),'go version go1.27.3 '+platform+'/'+arch);
 let stage='catalog',tracker=null,plan=null,execution={exitCode:null,streamValid:false,bytes:0},stable=false;
 try{const listed=command(repo,['go','list',...(mode==='race'?['-race']:[]),'-json','./...']);plan=JSON.parse(execFileSync('go',['run','./scripts/core-test-catalog','-root',repo],{cwd:repo,input:listed,encoding:'utf8',maxBuffer:8<<20,stdio:['pipe','pipe','ignore'],timeout:180000}));tracker=new Tracker(plan);stage='execute';execution=await run(repo,mode,tracker);stage='source';const after=identity(repo);stable=before.source===after.source&&before.tree===after.tree;assert.ok(stable);stage='complete'}catch{}
 const projected=tracker?tracker.value(mode,execution.exitCode):{unknownEvents:0,overflow:false,discardedOutputEvents:0,buildFailures:0,packages:[],outcome:'failed'},sourceSHA256={};for(const name of reportSources(platform))sourceSHA256[name]=await boundedHash(path.join(repo,name));const outcome=stage==='complete'&&stable&&execution.streamValid&&projected.outcome==='passed'?'passed':'failed';
 const data={schemaVersion:1,sourceCommit:before.source,sourceTree:before.tree,sourceSHA256,platform,architecture:arch,go:'go1.27.3',mode,stage,exitCode:execution.exitCode,streamValid:execution.streamValid,sourceStable:stable,inputBytes:execution.bytes,...projected,outcome,productionQualificationComplete:false};await writeReport(repo,data,process.env.CORE_MODE_REPORTS==='1'?'status-'+mode+'.json':'status.json');console.log(JSON.stringify({mode,stage,outcome,packages:data.packages.length,unknownEvents:data.unknownEvents}));if(outcome!=='passed'){if(process.env.CORE_FAILURE_ANNOTATIONS==='1'&&plan&&stable){for(const label of failureAnnotations(plan,projected))console.log('::error title=Source-known root failure::'+label);for(const label of closedPipeFailureAnnotations(tracker))console.log('::error title=Source-known closed-pipe failure::'+label)}process.exitCode=1;}
}
module.exports={Tracker,planValue,writeReport,sources,modes,stages,testArguments,signalOwnedChild,failureAnnotations,closedPipeFailureAnnotations};if(require.main===module)main().catch(()=>{console.error('Core qualification evidence failed');process.exitCode=1});
