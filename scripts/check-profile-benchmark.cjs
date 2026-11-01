#!/usr/bin/env node
'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {validateEnvironment}=require('./check-native-environment.cjs');
function parseBenchmark(output,expected){
 assert(Buffer.byteLength(output)<=1<<20,'benchmark output exceeds limit');
 for(const [key,value] of Object.entries({goos:expected.goos,goarch:expected.goarch}))assert.equal(output.split(/\r?\n/).filter(line=>line.startsWith(key+': ')).join(''),key+': '+value,'benchmark target differs from native host');
 assert(output.split(/\r?\n/).includes('PASS'),'benchmark did not report success');
 const rows={};
 for(const line of output.split(/\r?\n/)){
  if(!line.startsWith('BenchmarkList256/'))continue;
  const fields=line.trim().split(/\s+/),match=/^BenchmarkList256\/(serial|four_readers)-[0-9]+$/.exec(fields[0]);
  assert(match&&!rows[match[1]],'unexpected or duplicated benchmark case');
  assert(/^[1-9][0-9]*$/.test(fields[1])&&Number.isSafeInteger(Number(fields[1])),'invalid benchmark iterations');
  const metrics={};assert(fields.length>=8&&fields.length%2===0,'incomplete benchmark metrics');
  for(let i=2;i<fields.length;i+=2){
   const number=Number(fields[i]),unit=fields[i+1];
   assert(/^(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:e[+-]?[0-9]+)?$/i.test(fields[i])&&Number.isFinite(number)&&number>=0&&!Object.hasOwn(metrics,unit),'invalid or duplicate benchmark metric');
   metrics[unit]=number;
  }
  const units=match[1]==='serial'?['B/op','allocs/op','ns/op']:['B/op','allocs/op','ns/op','readers'];
  assert.deepEqual(Object.keys(metrics).sort(),units.sort(),'missing or unexpected benchmark metric');
  assert(metrics['ns/op']>0,'missing elapsed benchmark time');if(match[1]==='four_readers')assert.equal(metrics.readers,4);
  rows[match[1]]={iterations:Number(fields[1]),nanosecondsPerOperation:metrics['ns/op'],bytesPerOperation:metrics['B/op'],allocationsPerOperation:metrics['allocs/op'],readers:match[1]==='serial'?1:4};
 }
 assert.deepEqual(Object.keys(rows).sort(),['four_readers','serial'],'both serial and concurrent measurements are required');return rows;
}
function execute(command,args,timeout=120000){
 const result=spawnSync(command,args,{encoding:'utf8',windowsHide:true,maxBuffer:1<<20,timeout});
 if(result.error)throw result.error;assert.equal(result.status,0,'native benchmark command failed: '+command);return result.stdout;
}
function main(){
 const expected={goos:process.env.ACCESSWEAVER_EXPECT_GOOS,goarch:process.env.ACCESSWEAVER_EXPECT_GOARCH,goVersion:process.env.GO_VERSION,commit:process.env.GITHUB_SHA,hosted:process.env.GITHUB_ACTIONS==='true'};
 assert.match(expected.commit||'',/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/,'expected source commit is required');
 const actual={platform:process.platform,machine:os.machine(),runnerArch:process.env.RUNNER_ARCH,runnerEnvironment:process.env.RUNNER_ENVIRONMENT,go:JSON.parse(execute('go',['env','-json','GOOS','GOARCH','GOHOSTOS','GOHOSTARCH','GOVERSION','GOTOOLCHAIN','CGO_ENABLED']))};
 validateEnvironment(actual,expected);
 const source=()=>{assert.equal(execute('git',['rev-parse','HEAD']).trim(),expected.commit,'benchmark source mismatch');assert(!execute('git',['status','--porcelain','--untracked-files=normal']).trim(),'benchmarks require clean source');};
 source();const startedAt=new Date().toISOString();
 const output=execute('go',['test','./internal/profile','-run=^$','-bench=^BenchmarkList256$','-benchtime=1s','-benchmem','-count=1']);
 const measurements=parseBenchmark(output,expected);source();
 const report={schemaVersion:1,sourceCommit:expected.commit,sourceState:'clean',target:expected.goos+'/'+expected.goarch,scope:'synthetic-source-store-benchmark',timingSemantics:'aggregate-wall-time-divided-by-completed-operations',startedAt,finishedAt:new Date().toISOString(),machine:actual.machine,osRelease:os.release(),runnerArch:actual.runnerArch||'',runnerEnvironment:actual.runnerEnvironment||'',imageOS:process.env.ImageOS||'',imageVersion:process.env.ImageVersion||'',go:actual.go,fixtureProfiles:256,measurements,serialToConcurrentRatio:measurements.serial.nanosecondsPerOperation/measurements.four_readers.nanosecondsPerOperation,packagedCandidateMeasured:false,desktopPerformanceBudgetsVerified:false,productionQualificationComplete:false};
 const folder=path.resolve('build','profile-benchmarks');fs.mkdirSync(folder,{recursive:true});fs.writeFileSync(path.join(folder,expected.goos+'-'+expected.goarch+'.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}
module.exports={parseBenchmark};
if(require.main===module){try{main()}catch(error){console.error(error.message);process.exitCode=1;}}
