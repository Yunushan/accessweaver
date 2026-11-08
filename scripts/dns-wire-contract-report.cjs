'use strict';
// Hosted source qualification and READ-ONLY packet-tool capability inspection.
// Never starts/stops capture, edits filters or firewall/DNS state, or launches the product.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),os=require('node:os');
const {spawnSync}=require('node:child_process');
const SOURCES=Object.freeze(['scripts/dns-wire-evidence.cjs','scripts/dns-wire-evidence.test.cjs','scripts/dns-wire-contract-report.cjs','.github/workflows/dns-wire-contracts.yml','scripts/dns-wire-stdin.cjs','scripts/native-dns-wire.ps1','scripts/test-dns-wire-native-contracts.ps1','.github/workflows/native-doh-wire.yml','scripts/test-native-doh.ps1','scripts/dns-acceptance-state.ps1','scripts/native-doh-scenario.ps1']);
function classifyStatus(text){
 const s=text.trim();
 if(/^(?:Packet Monitor|Packet monitoring|Logger) is not (?:currently )?(?:running|active)\.?$/i.test(s))return 'stopped';
 if(/^(?:Packet Monitor|Packet monitoring|Logger) is (?:currently )?(?:running|active)\.?$/i.test(s))return 'running';
 return 'unrecognized';
}
function classifyFilters(text){
 const s=text.trim();
 if(/^(?:Packet Filters:\s*)?(?:No (?:packet )?filters(?: configured)?\.?|None)$/i.test(s))return 'empty';
 // Do not infer emptiness merely from the absence of recognizable numeric rows.
 if(/(?:^|\n)\s*\d+\s+\S/.test(s))return 'rows-present';
 return 'unrecognized';
}
function query(tool,args){
 const r=spawnSync(tool,args,{encoding:null,timeout:10000,maxBuffer:65536,windowsHide:true});
 const out=Buffer.isBuffer(r.stdout)?r.stdout:Buffer.alloc(0),err=Buffer.isBuffer(r.stderr)?r.stderr:Buffer.alloc(0);
 if(out.length+err.length>65536||r.error?.code==='ENOBUFS')return {code:'overflow',text:''};
 if(r.error)return {code:r.error.code==='ETIMEDOUT'?'timeout':'unavailable',text:''};
 return {code:r.status===0?'complete':'exit',text:Buffer.concat([out,err]).toString('utf8')};
}
function inspectCapabilities(){
 const none={applicable:process.platform==='win32',toolAvailable:false,start:false,fixedEndpointFilter:false,pcapConversion:false,session:'not-inspected',filters:'not-inspected',queryCodes:[]};
 if(process.platform!=='win32')return none;
 const system=process.env.SystemRoot;
 if(!system||!path.win32.isAbsolute(system))return none;
 const tool=path.join(system,'System32','pktmon.exe');
 try{const s=fs.lstatSync(tool);if(!s.isFile()||s.isSymbolicLink()||s.size<=0||s.size>64*1024*1024)return none;}catch{return none;}
 const start=query(tool,['start','help']),filter=query(tool,['filter','add','help']),convert=query(tool,['etl2pcap','help']),status=query(tool,['status']),filters=query(tool,['filter','list']);
 return {applicable:true,toolAvailable:true,
  start:['--capture','--comp','--pkt-size','--file-size','--log-mode'].every(s=>start.text.includes(s)),
  fixedEndpointFilter:filter.text.includes('--ip')&&filter.text.includes('--port')&&filter.text.includes('TCP')&&filter.text.includes('UDP'),
  pcapConversion:convert.text.includes('--out')&&convert.text.toLowerCase().includes('pcap'),
  session:status.code==='complete'?classifyStatus(status.text):'unrecognized',
  filters:filters.code==='complete'?classifyFilters(filters.text):'unrecognized',
  queryCodes:[start.code,filter.code,convert.code,status.code,filters.code]};
}
function sourceHashes(){
 const root=path.resolve(__dirname,'..'),hashes={};
 for(const file of SOURCES){const bytes=fs.readFileSync(path.join(root,file));if(bytes.length>256*1024)throw new Error('source-bound');hashes[file]=crypto.createHash('sha256').update(bytes).digest('hex');}
 return hashes;
}
function wireSourceContracts(){
 const script=path.join(__dirname,'test-dns-wire-native-contracts.ps1');
 const names=[...fs.readFileSync(script,'utf8').matchAll(/^    Case-Wire '([a-z0-9-]+)'/gm)].map(m=>m[1]);
 if(names.length!==16||new Set(names).size!==16)throw new Error('wire-source-catalog');
 const jobs=[['core','pwsh',[]]];
 if(process.platform==='win32')jobs.push(['desktop',path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe'),['-RequireWindowsPowerShell']]);
 return jobs.map(([edition,program,flags])=>{
  const result=spawnSync(program,['-NoProfile','-NonInteractive','-File',script,...flags],{encoding:null,timeout:60000,maxBuffer:16384,windowsHide:true});
  let report=null;try{
   if(result.error||!Buffer.isBuffer(result.stdout)||result.stdout.length>16384)throw new Error('source-process');
   const value=JSON.parse(result.stdout.toString('utf8'));
   const keys=['schemaVersion','scope','cases','passed','realDnsChanged','packetCaptureStarted','nativeWireQualified'];
   if(Object.keys(value).length!==keys.length||!keys.every(k=>Object.hasOwn(value,k))||value.schemaVersion!==1||value.scope!=='actual-native-wire-source'||value.realDnsChanged!==false||value.packetCaptureStarted!==false||value.nativeWireQualified!==false||typeof value.passed!=='boolean'||!Array.isArray(value.cases)||value.cases.length!==names.length)throw new Error('source-shape');
   for(let i=0;i<names.length;i++)if(Object.keys(value.cases[i]).length!==2||value.cases[i].name!==names[i]||typeof value.cases[i].passed!=='boolean')throw new Error('source-case');
   if(value.passed!==value.cases.every(c=>c.passed))throw new Error('source-outcome');report=value;
  }catch{}
  return {edition,code:report?(result.stderr?.length?'source-stderr':result.status===0&&report.passed?'complete':'contracts-failed'):'process-failed',report,stderrPresent:Boolean(result.stderr?.length),stdoutPresent:Boolean(result.stdout?.length),timedOut:result.error?.code==='ETIMEDOUT',overflow:result.error?.code==='ENOBUFS'};
 });
}
function main(){
 let report={schemaVersion:1,scope:'synthetic-doh-wire-decoder',outcome:'failed',code:'environment',sourceCommit:'',sourceSHA256:{},
  platform:'unknown',architecture:'unknown',node:'unknown',contracts:null,wireSourceReports:[],capabilities:null,nativeCapturePerformed:false,encryptedTrafficObserved:false,productionQualificationComplete:false};
 try{
  const platform={win32:'windows',linux:'linux',darwin:'darwin'}[process.platform],architecture={x64:'amd64',arm64:'arm64'}[process.arch];
  const machine=os.machine().toLowerCase(),host=machine==='x86_64'||machine==='amd64'?'amd64':machine==='arm64'||machine==='aarch64'?'arm64':'unknown';
  if(process.env.GITHUB_ACTIONS!=='true'||process.env.RUNNER_ENVIRONMENT!=='github-hosted'||!/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||'')||process.version!=='v26.8.2'||platform!==process.env.ACCESSWEAVER_EXPECT_GOOS||architecture!==process.env.ACCESSWEAVER_EXPECT_GOARCH||host!==architecture)throw new Error('environment');
  for(const name of ['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'])if(Object.hasOwn(process.env,name))throw new Error('environment');
  report.sourceCommit=process.env.GITHUB_SHA;report.platform=platform;report.architecture=architecture;report.node=process.version;
  report.code='source';report.sourceSHA256=sourceHashes();report.code='contracts';report.contracts=require('./dns-wire-evidence.test.cjs').runContracts();
  if(!report.contracts.passed)throw new Error('contracts');
  report.code='wire-source';report.wireSourceReports=wireSourceContracts();if(report.wireSourceReports.some(r=>r.code!=='complete'))throw new Error('wire-source');
  report.code='capabilities';report.capabilities=inspectCapabilities();report.code='source-stability';
  if(JSON.stringify(report.sourceSHA256)!==JSON.stringify(sourceHashes()))throw new Error('source-stability');
  // Capability observations do not mean a capture or native DNS operation passed.
  report.code='none';report.outcome='passed';
 }catch{}
 const output=JSON.stringify(report);if(Buffer.byteLength(output)>16384){process.stdout.write('{"schemaVersion":1,"outcome":"failed","code":"report-bound"}\n');process.exitCode=1;return;}
 process.stdout.write(output+'\n');if(report.outcome!=='passed')process.exitCode=1;
}
module.exports={classifyStatus,classifyFilters};
if(require.main===module)main();
