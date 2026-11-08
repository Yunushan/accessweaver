'use strict';
// Pure synthetic contracts. Never invokes the native query implementation.
const assert=require('node:assert/strict'),p=require('./trace-capture-capabilities.cjs');
function runContracts(){
 const cases=[];function check(name,body){let passed=true;try{body();}catch{passed=false;}cases.push({name,passed});}
 const complete=text=>({code:'complete',text});
 const start='Usage: trace start [capture=]yes|no [capturetype=]physical|vmswitch|both [sessionname=]<name> [tracefile=]<path> [maxsize=]<size>\n[filemode=]single|circular|append [report=]yes|no|disabled [correlation=]yes|no|disabled [persistent=]yes|no [overwrite=]yes|no';
 const filter='IPv4.Address IPv6.Address TCP.Port PacketTruncateBytes';
 const rows=()=>({before:complete('There is no tracing session currently in progress.'),after:complete('There is no tracing session currently in progress.'),startHelp:complete(start),filterHelp:complete(filter)});
 const metadata=()=>({...p.emptyNetEvent('complete'),stockShell:true,sessionCommandsListed:true,providerCommandsListed:true,privateFileParametersListed:true,packetFilterParametersListed:true,sessionReadbackParametersListed:true,providerReadbackParametersListed:true,sessionInventory:'empty',providerInventory:'empty'});
 check('exact-inactive-status-is-recognized',()=>{assert.equal(p.status('There is no tracing session currently in progress.'),'stopped');assert.equal(p.status(' No trace session is currently running.\r\n'),'stopped');});
 check('active-status-discards-private-path-and-session',()=>{assert.equal(p.status('Trace configuration:\nStatus: Running\nTrace File: PRIVATE-SYNTHETIC\nSession: PRIVATE-SYNTHETIC'),'running');});
 check('inactive-snippets-never-imply-stopped',()=>{for(const s of ['PRIVATE-SYNTHETIC There is no tracing session currently in progress.','not running','Status: Unknown',''])assert.equal(p.status(s),'unknown');});
 check('multiple-status-rows-retain-uncertainty',()=>{assert.equal(p.status('Status: Running\nStatus: Stopped'),'unknown');assert.equal(p.status('Status: Running\nStatus: Running'),'unknown');});
 check('listed-syntax-is-reduced-without-help-text',()=>{const r=p.summarizeNetsh(rows());assert.equal(r.statusBefore,'stopped');for(const [k,v]of Object.entries(r))if(typeof v==='boolean')assert.equal(v,true,k);assert.equal(JSON.stringify(r).includes('Usage'),false);});
 check('dotted-filter-names-are-literal',()=>{const r=rows();r.filterHelp=complete('IPv4xAddress IPv6xAddress TCPxPort PacketTruncateBytes');const v=p.summarizeNetsh(r);assert.equal(v.ipv4FilterListed,false);assert.equal(v.ipv6FilterListed,false);assert.equal(v.tcpPortFilterListed,false);});
 check('missing-or-failed-help-does-not-list-options',()=>{const r=rows();r.startHelp={code:'exit',text:start};r.filterHelp={code:'timeout',text:filter};const v=p.summarizeNetsh(r);for(const x of Object.values(v))if(typeof x==='boolean')assert.equal(x,false);});
 check('oversized-help-is-not-consumed',()=>{const r=rows();r.startHelp=complete(start+' '.repeat(65536));assert.equal(p.summarizeNetsh(r).captureOptionListed,false);assert.equal(p.status(' '.repeat(65537)),'unknown');});
 check('disabled-and-circular-values-require-option-syntax',()=>{const r=rows();r.startHelp=complete('capture tracefile maxsize disabled circular report filemode persistent overwrite');const v=p.summarizeNetsh(r);assert.equal(v.reportDisableSyntaxListed,false);assert.equal(v.circularSyntaxListed,false);assert.equal(v.nonpersistentSyntaxListed,false);});
 check('typed-complete-metadata-remains-closed',()=>{const r=metadata();assert.deepEqual(p.reduceNetEvent(JSON.stringify(r)),r);assert.notEqual(p.reduceNetEvent(JSON.stringify(r)),r);});
 check('metadata-extra-fields-never-leak',()=>{const r={...metadata(),private:'PRIVATE-SYNTHETIC'};const v=p.reduceNetEvent(JSON.stringify(r));assert.equal(v.code,'invalid-report');assert.equal(JSON.stringify(v).includes('PRIVATE-SYNTHETIC'),false);});
 check('metadata-booleans-and-inventories-are-strict',()=>{for(const change of [{stockShell:1},{sessionInventory:'PRIVATE-SYNTHETIC'},{code:'passed'}])assert.equal(p.reduceNetEvent(JSON.stringify({...metadata(),...change})).code,'invalid-report');});
 check('unknown-inventory-does-not-become-empty',()=>{const r={...metadata(),sessionInventory:'unknown',providerInventory:'unknown'};const v=p.reduceNetEvent(JSON.stringify(r));assert.equal(v.sessionInventory,'unknown');assert.equal(v.providerInventory,'unknown');});
 check('invalid-and-oversized-metadata-is-refused',()=>{for(const s of ['null','[]','false','{',' '.repeat(4097)])assert.equal(p.reduceNetEvent(s).code,'invalid-report');});
 check('only-read-only-native-requests-are-built',()=>{const calls=[];const r=p.collect((tool,args)=>{calls.push([tool,[...args]]);if(tool==='stock')return complete(JSON.stringify(metadata()));if(args[1]==='start')return complete(start);if(args[2]==='capturefilterhelp')return complete(filter);return complete('There is no tracing session currently in progress.');});assert.deepEqual(calls,[['netsh',['trace','show','status']],['netsh',['trace','start','/?']],['netsh',['trace','show','capturefilterhelp']],['netsh',['trace','show','status']],['stock',['-NoProfile','-NonInteractive','-File','scripts/read-native-trace-capabilities.ps1']]]);assert.equal(r.queryCodes.length,5);assert.ok(r.queryCodes.every(x=>x==='complete'));});
 check('private-process-output-never-enters-aggregate',()=>{const r=p.collect(()=>({code:'timeout',text:'PRIVATE-SYNTHETIC'}));assert.equal(JSON.stringify(r).includes('PRIVATE-SYNTHETIC'),false);assert.equal(r.netEvent.code,'process-failed');assert.equal(r.netsh.statusBefore,'unknown');});
 return {schemaVersion:1,scope:'pure-read-only-capture-capabilities',cases,passed:cases.every(c=>c.passed),nativeExecution:false,networkRequests:0};
}
module.exports={runContracts};
if(require.main===module){const r=runContracts();process.stdout.write(JSON.stringify(r)+'\n');if(!r.passed)process.exitCode=1;}
