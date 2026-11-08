'use strict';
// Hosted read-only capability probe. No capture/session mutator is invoked.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const FILES=Object.freeze(['scripts/trace-capture-capabilities.cjs','scripts/test-trace-capture-capabilities.cjs','scripts/read-native-trace-capabilities.ps1','.github/workflows/trace-capture-capabilities.yml']);
const REQUESTS=Object.freeze([
 ['before',['trace','show','status']],['startHelp',['trace','start','/?']],
 ['filterHelp',['trace','show','capturefilterhelp']],['after',['trace','show','status']]
].map(([key,args])=>Object.freeze([key,Object.freeze(args)])));
function status(text){
 if(typeof text!=='string'||text.length>65536)return 'unknown';
 const s=text.trim();
 if(/^(?:There is no tracing session currently in progress\.?|No trace session is currently running\.?)$/i.test(s))return 'stopped';
 // Private rows may follow. No path or session identity is returned.
 const rows=[...s.matchAll(/^[ \t]*Status[ \t]*:[ \t]*(Running|Stopped)[ \t]*\r?$/gim)];
 if(rows.length===1)return rows[0][1].toLowerCase();
 return 'unknown';
}
function option(text,name){const escaped=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');return new RegExp('\\b'+escaped+'\\b','i').test(text);}
function values(text,name){
 const match=text.match(new RegExp('\\b'+name+'\\s*=\\s*\\]?\\s*([a-z]+(?:[ \\t]*\\|[ \\t]*[a-z]+)+)','i'));
 return match?match[1].toLowerCase().split(/[ \t]*\|[ \t]*/):[];
}
function summarizeNetsh(rows){
 const text=key=>rows[key]?.code==='complete'&&typeof rows[key].text==='string'&&rows[key].text.length<=65536?rows[key].text:'';
 const start=text('startHelp'),filter=text('filterHelp'),file=values(start,'filemode'),report=values(start,'report');
 return {statusBefore:rows.before?.code==='complete'?status(text('before')):'unknown',statusAfter:rows.after?.code==='complete'?status(text('after')):'unknown',
  captureOptionListed:option(start,'capture'),captureTypeOptionListed:option(start,'capturetype'),sessionNameOptionListed:option(start,'sessionname'),
  privateFileOptionListed:option(start,'tracefile'),fileBoundOptionListed:option(start,'maxsize'),circularSyntaxListed:file.includes('circular'),
  reportDisableSyntaxListed:report.includes('disabled'),correlationOptionListed:option(start,'correlation'),nonpersistentSyntaxListed:values(start,'persistent').includes('no'),overwriteOptionListed:option(start,'overwrite'),
  ipv4FilterListed:option(filter,'IPv4.Address'),ipv6FilterListed:option(filter,'IPv6.Address'),tcpPortFilterListed:option(filter,'TCP.Port'),truncationOptionListed:option(filter,'PacketTruncateBytes')};
}
function emptyNetEvent(code='not-inspected'){
 return {code,stockShell:false,sessionCommandsListed:false,providerCommandsListed:false,privateFileParametersListed:false,packetFilterParametersListed:false,sessionReadbackParametersListed:false,providerReadbackParametersListed:false,sessionInventory:'not-inspected',providerInventory:'not-inspected'};
}
function reduceNetEvent(text){
 const invalid=emptyNetEvent('invalid-report');if(typeof text!=='string'||text.length>4096)return invalid;
 let r;try{r=JSON.parse(text);}catch{return invalid;}
 const keys=Object.keys(invalid);
 if(!r||Array.isArray(r)||typeof r!=='object'||Object.keys(r).length!==keys.length||!keys.every(k=>Object.hasOwn(r,k))||!['complete','unavailable'].includes(r.code))return invalid;
 if(!keys.filter(k=>typeof invalid[k]==='boolean').every(k=>typeof r[k]==='boolean'))return invalid;
 if(!['sessionInventory','providerInventory'].every(k=>['not-inspected','empty','present','bound','unknown'].includes(r[k])))return invalid;
 // Construct a new closed object; never forward private or unknown input fields.
 return Object.fromEntries(keys.map(k=>[k,r[k]]));
}
function query(program,args){
 const r=spawnSync(program,args,{encoding:null,timeout:10000,maxBuffer:32768,windowsHide:true});
 const out=Buffer.isBuffer(r.stdout)?r.stdout:Buffer.alloc(0),err=Buffer.isBuffer(r.stderr)?r.stderr:Buffer.alloc(0);
 if(out.length+err.length>65536||r.error?.code==='ENOBUFS')return {code:'overflow',text:''};
 if(r.error)return {code:r.error.code==='ETIMEDOUT'?'timeout':'unavailable',text:''};
 if(r.status!==0)return {code:'exit',text:''};if(err.length)return {code:'stderr',text:''};
 try{
  const bom=out.length>=2&&out[0]===255&&out[1]===254;
  return {code:'complete',text:new TextDecoder(bom?'utf-16le':'utf-8',{fatal:true}).decode(bom?out.subarray(2):out)};
 }catch{return {code:'encoding',text:''};}
}
function collect(run){
 const rows={};for(const [key,args] of REQUESTS)rows[key]=run('netsh',args);
 rows.netEvent=run('stock',['-NoProfile','-NonInteractive','-File','scripts/read-native-trace-capabilities.ps1']);
 return {netsh:summarizeNetsh(rows),netEvent:rows.netEvent.code==='complete'?reduceNetEvent(rows.netEvent.text):emptyNetEvent('process-failed'),queryCodes:[...REQUESTS.map(([key])=>rows[key].code),rows.netEvent.code]};
}
function hashes(){
 return Object.fromEntries(FILES.map(file=>{const raw=fs.readFileSync(path.resolve(__dirname,'..',file));if(raw.length>262144)throw new Error('source-bound');return [file,crypto.createHash('sha256').update(raw).digest('hex')];}));
}
function main(){
 const report={schemaVersion:1,scope:'read-only-windows-capture-capabilities',sourceCommit:process.env.GITHUB_SHA||'',sourceSHA256:{},platform:'windows',architecture:process.env.ACCESSWEAVER_EXPECT_GOARCH||'unknown',node:process.version,hostVerified:false,outcome:'failed',code:'environment',contracts:null,netsh:null,netEvent:null,queryCodes:[],captureStarted:false,sessionChanged:false,dnsSettingsChangesAttempted:false,productInvoked:false,rawOutputPublished:false,productionQualificationComplete:false};
 try{
  const arch={x64:'amd64',arm64:'arm64'}[process.arch],host={amd64:'amd64',x86_64:'amd64',arm64:'arm64',aarch64:'arm64'}[os.machine().toLowerCase()];
  if(process.env.GITHUB_ACTIONS!=='true'||process.env.RUNNER_ENVIRONMENT!=='github-hosted'||process.env.RUNNER_OS!=='Windows'||process.platform!=='win32'||process.version!=='v26.8.2'||arch!==host||arch!==report.architecture||!/^[a-f0-9]{40}$/.test(report.sourceCommit))throw new Error('environment');
  for(const key of ['ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP'])if(Object.hasOwn(process.env,key))throw new Error('environment');
  report.hostVerified=true;report.code='source';report.sourceSHA256=hashes();report.code='contracts';report.contracts=require('./test-trace-capture-capabilities.cjs').runContracts();if(!report.contracts.passed)throw new Error('contracts');
  report.code='capabilities';const root=process.env.SystemRoot;if(!root||!path.win32.isAbsolute(root))throw new Error('tool');
  const programs={netsh:path.join(root,'System32','netsh.exe'),stock:path.join(root,'System32','WindowsPowerShell','v1.0','powershell.exe')};
  for(const name of Object.values(programs)){const s=fs.lstatSync(name);if(!s.isFile()||s.isSymbolicLink()||s.size<=0||s.size>67108864)throw new Error('tool');}
  const evidence=collect((tool,args)=>query(programs[tool],tool==='stock'?[...args.slice(0,-1),path.resolve(__dirname,'read-native-trace-capabilities.ps1')]:args));Object.assign(report,evidence);
  report.code='source-stability';if(JSON.stringify(report.sourceSHA256)!==JSON.stringify(hashes()))throw new Error('source-stability');
  if(report.queryCodes.some(x=>x!=='complete')||report.netEvent.code==='invalid-report'||report.netEvent.code==='process-failed'||!report.netEvent.stockShell){report.code='queries';throw new Error('queries');}
  report.outcome='observed';report.code='none';
 }catch{}
 const result=JSON.stringify(report);if(Buffer.byteLength(result)>16384)throw new Error('report-bound');process.stdout.write(result+'\n');if(report.outcome!=='observed')process.exitCode=1;
}
module.exports={status,values,summarizeNetsh,emptyNetEvent,reduceNetEvent,collect,REQUESTS};
if(require.main===module)main();
