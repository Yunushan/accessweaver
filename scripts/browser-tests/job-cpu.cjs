// Read-only cgroup-v2 CPU accounting for this explicitly isolated CI job.
// No host census, process arguments, namespace IDs or cgroup paths are retained.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises');
const {ChildProcess}=require('node:child_process'),{performance}=require('node:perf_hooks');
const ROOT='/sys/fs/cgroup',CGROUP2_MAGIC=0x63677270;
const checkNames=['privateMembership','mountUnique','mountRoot','mountReadOnly','mountCgroupV2','rootDirectory','filesystemCgroupV2','controlsReadOnly','counterRegular','counterStable','counterRead','closeConfirmed'];
const emptyChecks=()=>Object.fromEntries(checkNames.map(k=>[k,false]));
class JobCpuError extends Error{constructor(stage,cause){super('Private job CPU verification failed',{cause});this.jobCpuStage=stage}}
function failureStage(error){let n;try{n=error?.jobCpuStage}catch{return 1}return Number.isInteger(n)&&n>=1&&n<=9?n:1}
function membership(raw){assert.equal(raw,'0::/\n','Private job cgroup membership differs')}
function mount(raw,checks=emptyChecks()){
 assert.ok(typeof raw==='string'&&Buffer.byteLength(raw)<=131072,'Job mount input budget differs');let found=0;
 for(const line of raw.split('\n')){const parts=line.split(' - ');if(parts.length!==2)continue;const before=parts[0].split(' '),after=parts[1].split(' ');if(before[4]!==ROOT)continue;found++;checks.mountRoot=before[3]==='/';checks.mountReadOnly=before[5].split(',').includes('ro');checks.mountCgroupV2=after[0]==='cgroup2'}
 checks.mountUnique=found===1;assert.ok(checks.mountUnique&&checks.mountRoot&&checks.mountReadOnly&&checks.mountCgroupV2,'Private job cgroup mount differs');return checks;
}
function parseCpuStat(raw){
 assert.ok(typeof raw==='string'&&Buffer.byteLength(raw)<=4096,'Job CPU counter budget differs');const values={};
 for(const line of raw.trim().split('\n')){const parts=line.trim().split(/\s+/);if(!['usage_usec','user_usec','system_usec'].includes(parts[0]))continue;assert.ok(parts.length===2&&/^[0-9]+$/.test(parts[1])&&!Object.hasOwn(values,parts[0]),'Job CPU counter shape differs');const n=Number(parts[1]);assert.ok(Number.isSafeInteger(n)&&n>=0,'Job CPU counter range differs');values[parts[0]]=n}
 assert.deepEqual(Object.keys(values).sort(),['system_usec','usage_usec','user_usec']);return {usageUsec:values.usage_usec,userUsec:values.user_usec,systemUsec:values.system_usec};
}
async function boundedRead(file,maximum){const fd=await fs.open(file,'r');try{const buffer=Buffer.alloc(maximum+1);let total=0;while(total<buffer.length){const {bytesRead}=await fd.read(buffer,total,buffer.length-total,null);if(!bytesRead)break;total+=bytesRead}assert.ok(total<=maximum,'Private job input budget differs');return buffer.subarray(0,total).toString('utf8')}finally{await fd.close()}}
const systemIO={
 readMembership:pid=>boundedRead('/proc/'+pid+'/cgroup',4096),
 async guardMount(checks){mount(await boundedRead('/proc/self/mountinfo',131072),checks);const info=await fs.lstat(ROOT),resolved=await fs.realpath(ROOT),type=await fs.statfs(ROOT);checks.rootDirectory=info.isDirectory()&&!info.isSymbolicLink()&&info.uid===0&&resolved===ROOT;checks.filesystemCgroupV2=type.type===CGROUP2_MAGIC;assert.ok(checks.rootDirectory&&checks.filesystemCgroupV2,'Private cgroup filesystem differs');let denied=false;try{await fs.access(ROOT+'/cgroup.procs',fs.constants.W_OK)}catch(error){if(['EACCES','EROFS','EPERM'].includes(error?.code))denied=true;else throw error}checks.controlsReadOnly=denied;assert.ok(denied,'Private cgroup controls must not be writable')},
 open:()=>fs.open(ROOT+'/cpu.stat','r')
};
function owned(child){assert.ok(child instanceof ChildProcess&&Number.isSafeInteger(child.pid)&&child.pid>0&&child.exitCode===null&&child.signalCode===null&&!child.killed,'Owned live job child required')}
class JobCpu {
 constructor(fd,info,children,io,clock,checks){this.checks=checks;this.fd=fd;this.info=info;this.children=children;this.io=io;this.clock=clock;this.busy=false;this.closed=false;this.previous=null;this.closePromise=null}
 static async open({children=[],io=systemIO,clock=()=>performance.now(),environment=process.env,platform=process.platform,checks=emptyChecks()}={}){
  try{assert.ok(platform==='linux'&&environment.GITHUB_ACTIONS==='true'&&environment.ACCESSWEAVER_JOB_CPU_ACCOUNTING==='required','Private job CPU requires explicit CI isolation');assert.ok(Array.isArray(children)&&children.length<=2);for(const child of children)owned(child)}catch(error){throw new JobCpuError(1,error)}
  try{membership(await io.readMembership(process.pid));for(const child of children)membership(await io.readMembership(child.pid));checks.privateMembership=true;}catch(error){throw new JobCpuError(2,error)}
  try{await io.guardMount(checks)}catch(error){throw new JobCpuError(3,error)}
  let fd;
  try{fd=await io.open();const info=await fd.stat();checks.counterRegular=info.isFile();assert.ok(checks.counterRegular,'Job CPU counter must be a regular interface');return new JobCpu(fd,info,[...children],io,clock,checks)}catch(error){if(fd)try{await fd.close()}catch(closeError){throw new JobCpuError(8,new AggregateError([error,closeError],'Job CPU acquisition cleanup failed'))}throw new JobCpuError(4,error)}
 }
 async sample(){
  if(this.closed||this.busy)throw new JobCpuError(5);this.busy=true;
  try{
   try{membership(await this.io.readMembership(process.pid));for(const child of this.children){owned(child);membership(await this.io.readMembership(child.pid))}}catch(error){throw new JobCpuError(2,error)}
   let before,after,raw,startedMilliseconds,finishedMilliseconds;
   try{before=await this.fd.stat();const buffer=Buffer.alloc(4097);startedMilliseconds=this.clock();const {bytesRead}=await this.fd.read(buffer,0,buffer.length,0);finishedMilliseconds=this.clock();assert.ok(bytesRead>0&&bytesRead<=4096,'Job CPU read budget differs');raw=buffer.subarray(0,bytesRead).toString('utf8');after=await this.fd.stat()}catch(error){throw new JobCpuError(5,error)}
   try{this.checks.counterStable=before.isFile()&&after.isFile()&&before.dev===this.info.dev&&before.ino===this.info.ino&&after.dev===this.info.dev&&after.ino===this.info.ino;assert.ok(this.checks.counterStable,'Private job counter identity changed')}catch(error){throw new JobCpuError(6,error)}
   let counters;try{counters=parseCpuStat(raw);if(this.previous)for(const k of ['usageUsec','userUsec','systemUsec'])assert.ok(counters[k]>=this.previous[k],'Job CPU counters regressed');assert.ok(Number.isFinite(startedMilliseconds)&&Number.isFinite(finishedMilliseconds)&&finishedMilliseconds>=startedMilliseconds&&(!this.previous||startedMilliseconds>=this.previous.finishedMilliseconds),'Job CPU clock regressed')}catch(error){throw new JobCpuError(7,error)}
   this.checks.counterRead=true;const value={...counters,startedMilliseconds,finishedMilliseconds};this.previous=value;return {...value};
  }finally{this.busy=false}
 }
 close(){if(!this.closePromise){this.closed=true;this.closePromise=this.fd.close().then(()=>{this.checks.closeConfirmed=true},error=>{throw new JobCpuError(8,error)})}return this.closePromise}
}
function usageBetween(before,after){
 try{const milliseconds=after.startedMilliseconds-before.finishedMilliseconds;assert.ok(Number.isFinite(milliseconds)&&milliseconds>0&&after.usageUsec>=before.usageUsec,'Job CPU observation window differs');return {milliseconds,percentOneCore:(after.usageUsec-before.usageUsec)/1000/milliseconds*100}}catch(error){throw new JobCpuError(9,error)}
}
module.exports={emptyChecks,checkNames,JobCpu,JobCpuError,failureStage,membership,mount,parseCpuStat,usageBetween,owned};
