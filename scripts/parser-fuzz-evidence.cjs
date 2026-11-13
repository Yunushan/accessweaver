// Fixed target IDs and numeric native Go mutation counters only. No raw test
// output, corpus inputs, errors, paths or signing material are retained.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const {spawn,execFileSync}=require('node:child_process'),{createHash}=require('node:crypto');
const {signalOwnedChild}=require('./core-test-evidence.cjs');
const manifest=require('./parser-fuzz-targets.json');
const commonSources=['internal/jsoninput/time_spelling_test.go','internal/profile/testdata/timestamps.json','internal/profile/strict_input_test.go','scripts/parser-fuzz-targets.json','scripts/parser-fuzz-evidence.cjs','scripts/parser-fuzz-evidence.test.cjs','.github/workflows/parser-fuzz.yml','.github/workflows/release.yml','internal/managed/fuzz_contract_test.go','internal/managed/policy.go','internal/jsoninput/time.go','go.mod','go.sum'];
const keys=['schemaVersion','sourceCommit','sourceTree','sourceSHA256','platform','architecture','go','node','target','stage','exitCode','sourceStable','streamValid','baselineInputs','workers','executions','newInteresting','elapsedSeconds','packagePassed','instrumented','discardedOutputEvents','inputBytes','outcome','productionQualificationComplete'];
function exact(value,names){assert.deepEqual(Object.keys(value).sort(),[...names].sort(),'Fuzz evidence schema differs')}
function validateManifest(value){
 exact(value,['schemaVersion','seconds','workers','targets']);assert.ok(value.schemaVersion===1&&value.seconds===30&&value.workers===2&&value.targets.length===14);
 const ids=new Set(),roots=new Set();
 for(const t of value.targets){exact(t,['id','package','root','source']);assert.ok(/^[a-z][a-z-]{1,40}$/.test(t.id)&&!ids.has(t.id));ids.add(t.id);assert.ok(/^internal\/[a-z]+$/.test(t.package)&&/^Fuzz[A-Za-z0-9_]+$/.test(t.root)&&!roots.has(t.root));roots.add(t.root);assert.ok(t.source.startsWith(t.package+'/')&&/^[a-z0-9_]+_test\.go$/.test(t.source.slice(t.package.length+1)))}
}
validateManifest(manifest);
function elapsed(text){const m=/^(?:(\d+)m)?(\d+)s$/.exec(text);if(!m)return null;const n=Number(m[1]||0)*60+Number(m[2]);return Number.isSafeInteger(n)&&n<=360?n:null}
function integer(value){const n=Number(value);return Number.isSafeInteger(n)&&n>=0&&n<=1e12?n:null}
class Tracker{
 constructor(target){this.target=target;this.baselineInputs=0;this.workers=0;this.executions=0;this.newInteresting=0;this.elapsedSeconds=0;this.packagePassed=false;this.instrumented=false;this.discardedOutputEvents=0;this.valid=true;}
 event(event){
  const pkg='github.com/Yunushan/accessweaver/'+this.target.package;
  if(event.Action==='build-fail'){this.valid=false;return}
  if(event.Action==='build-start'||event.Action==='build-output')return;
  if(event.Package!==pkg){this.valid=false;return}
  if(event.Action==='pass'&&!event.Test)this.packagePassed=true;
  if(event.Action==='fail'||event.Action==='skip'&&(!event.Test||event.Test===this.target.root))this.valid=false;
  if(event.Action!=='output')return;
  this.discardedOutputEvents++;if(this.discardedOutputEvents>1000000){this.valid=false;return}
  if(typeof event.Output!=='string'||event.Output.length>4096)return;
  const baseline=/^fuzz: elapsed: ([0-9ms]+), gathering baseline coverage: (\d+)\/(\d+) completed, now fuzzing with (\d+) workers\r?\n?$/.exec(event.Output);
  if(baseline){const done=integer(baseline[2]),total=integer(baseline[3]),workers=integer(baseline[4]);if(done===null||total===null||done!==total||total<1||workers!==manifest.workers){this.valid=false;return}this.baselineInputs=total;this.workers=workers;return}
  const progress=/^fuzz: elapsed: ([0-9ms]+), execs: (\d+) \(\d+\/sec\), new interesting: (\d+) \(total: (\d+)\)\r?\n?$/.exec(event.Output);
  if(progress){const seconds=elapsed(progress[1]),execs=integer(progress[2]),interesting=integer(progress[3]),total=integer(progress[4]);if(seconds===null||execs===null||interesting===null||total===null||seconds<this.elapsedSeconds||execs<this.executions||interesting>total||interesting>execs){this.valid=false;return}this.elapsedSeconds=seconds;this.executions=execs;this.newInteresting=interesting;this.instrumented=true;}
 }
 value(){return {baselineInputs:this.baselineInputs,workers:this.workers,executions:this.executions,newInteresting:this.newInteresting,elapsedSeconds:this.elapsedSeconds,packagePassed:this.packagePassed,instrumented:this.instrumented,discardedOutputEvents:this.discardedOutputEvents}}
}
function passed(v){return v.stage==='complete'&&v.exitCode===0&&v.sourceStable&&v.streamValid&&v.baselineInputs>0&&v.workers===manifest.workers&&v.executions>v.baselineInputs&&v.elapsedSeconds>=manifest.seconds&&v.packagePassed&&v.instrumented}
function validateReport(v){
 exact(v,keys);const target=manifest.targets.find(t=>t.id===v.target);assert.ok(target&&v.schemaVersion===1&&/^[a-f0-9]{40}$/.test(v.sourceCommit)&&/^[a-f0-9]{40}$/.test(v.sourceTree)&&['linux','windows'].includes(v.platform)&&['amd64','arm64'].includes(v.architecture)&&v.go==='go1.27.4'&&v.node==='v26.8.2'&&['identity','execute','source','complete'].includes(v.stage));
 exact(v.sourceSHA256,[...new Set([...commonSources,target.source])]);assert.ok(Object.values(v.sourceSHA256).every(x=>/^[a-f0-9]{64}$/.test(x)));
 for(const k of ['baselineInputs','workers','executions','newInteresting','elapsedSeconds','discardedOutputEvents','inputBytes'])assert.ok(typeof v[k]==='number'&&integer(v[k])!==null);
 for(const k of ['sourceStable','streamValid','packagePassed','instrumented'])assert.equal(typeof v[k],'boolean');assert.ok(v.exitCode===null||Number.isInteger(v.exitCode)&&v.exitCode>=0&&v.exitCode<=255);assert.ok(['passed','failed'].includes(v.outcome)&&v.productionQualificationComplete===false);assert.equal(v.outcome==='passed',passed(v));
}
function command(repo,args){return execFileSync(args[0],args.slice(1),{cwd:repo,encoding:'utf8',stdio:['ignore','pipe','ignore'],maxBuffer:2<<20,timeout:180000})}
function identity(repo){const source=command(repo,['git','rev-parse','HEAD']).trim(),tree=command(repo,['git','rev-parse','HEAD^{tree}']).trim();assert.match(source,/^[a-f0-9]{40}$/);assert.match(tree,/^[a-f0-9]{40}$/);assert.equal(command(repo,['git','status','--porcelain=v1']),'');return {source,tree}}
async function hash(file){const data=await fs.readFile(file);assert.ok(data.length>0&&data.length<=2<<20);return createHash('sha256').update(data).digest('hex')}
async function writeReport(repo,data){
 validateReport(data);const encoded=JSON.stringify(data)+'\n';assert.ok(Buffer.byteLength(encoded)<=16384);
 const realRepo=await fs.realpath(repo),build=path.join(realRepo,'build'),folder=path.join(build,'parser-fuzz-evidence');await fs.mkdir(build,{recursive:true});const b=await fs.lstat(build);assert.ok(b.isDirectory()&&!b.isSymbolicLink()&&await fs.realpath(build)===build);await fs.mkdir(folder,{recursive:true});const f=await fs.lstat(folder);assert.ok(f.isDirectory()&&!f.isSymbolicLink()&&await fs.realpath(folder)===folder);
 const handle=await fs.open(path.join(folder,data.target+'.json'),'wx',0o600);try{await handle.writeFile(encoded,'utf8')}finally{await handle.close()}
}
async function execute(repo,target,tracker){
 return new Promise(resolve=>{
  const args=['test','-json','-count=1','-run=^$','-fuzz=^'+target.root+'$','-fuzztime='+manifest.seconds+'s','-parallel='+manifest.workers,'-timeout=3m','./'+target.package];
  const child=spawn('go',args,{cwd:repo,env:{...process.env,GOTOOLCHAIN:'local',CGO_ENABLED:'0'},stdio:['ignore','pipe','ignore'],detached:process.platform==='linux',windowsHide:true});let pending=Buffer.alloc(0),bytes=0,valid=true,stopped=false,closed=false,killTimer;
  const stop=()=>{if(stopped||closed)return;stopped=true;signalOwnedChild(child,process.platform,'SIGTERM');killTimer=setTimeout(()=>signalOwnedChild(child,process.platform,'SIGKILL'),5000)};
  const timer=setTimeout(()=>{valid=false;stop()},6*60000);
  const line=raw=>{if(!raw.length)return;try{tracker.event(JSON.parse(raw.toString('utf8')))}catch{valid=false;stop()}};
  child.stdout.on('data',chunk=>{if(!valid)return;bytes+=chunk.length;if(bytes>32<<20){valid=false;stop();return}pending=Buffer.concat([pending,chunk]);for(;;){const end=pending.indexOf(10);if(end<0)break;if(end>1<<20){valid=false;stop();return}line(pending.subarray(0,end));pending=pending.subarray(end+1)}if(pending.length>1<<20){valid=false;stop()}});
  child.once('error',()=>{valid=false});child.once('close',code=>{closed=true;clearTimeout(timer);clearTimeout(killTimer);if(valid&&pending.length)line(pending);resolve({exitCode:Number.isInteger(code)&&code>=0&&code<=255?code:null,streamValid:valid&&tracker.valid,inputBytes:bytes})});
 });
}
async function main(){
 const target=manifest.targets.find(t=>t.id===process.argv[2]),repo=path.resolve(__dirname,'..');assert.ok(target&&process.argv.length===3);assert.ok(process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted');assert.equal(process.version,'v26.8.2');
 const platform={linux:'linux',win32:'windows'}[process.platform],architecture={x64:'amd64',arm64:'arm64'}[process.arch];assert.ok(platform&&architecture);assert.equal(platform,process.env.ACCESSWEAVER_EXPECT_GOOS);assert.equal(architecture,process.env.ACCESSWEAVER_EXPECT_GOARCH);assert.equal(command(repo,['go','version']).trim(),'go version go1.27.4 '+platform+'/'+architecture);
 const before=identity(repo);assert.equal(before.source,process.env.GITHUB_SHA);const tracker=new Tracker(target);let stage='execute',execution={exitCode:null,streamValid:false,inputBytes:0},stable=false;
 try{execution=await execute(repo,target,tracker);stage='source';const after=identity(repo);stable=before.source===after.source&&before.tree===after.tree;assert.ok(stable);stage='complete'}catch{}
 const sourceSHA256={};for(const name of new Set([...commonSources,target.source]))sourceSHA256[name]=await hash(path.join(repo,name));
 const data={schemaVersion:1,sourceCommit:before.source,sourceTree:before.tree,sourceSHA256,platform,architecture,go:'go1.27.4',node:process.version,target:target.id,stage,...execution,sourceStable:stable,...tracker.value(),outcome:'failed',productionQualificationComplete:false};data.outcome=passed(data)?'passed':'failed';await writeReport(repo,data);console.log(JSON.stringify({target:target.id,outcome:data.outcome,executions:data.executions,baselineInputs:data.baselineInputs,elapsedSeconds:data.elapsedSeconds}));if(data.outcome!=='passed'){console.log('::error title=Source-known parser fuzz failure::'+target.id);process.exitCode=1}
}
module.exports={manifest,validateManifest,Tracker,passed,validateReport,writeReport,commonSources};if(require.main===module)main().catch(()=>{console.error('Parser fuzz evidence failed');process.exitCode=1});
