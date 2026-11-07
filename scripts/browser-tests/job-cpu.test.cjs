const test=require('node:test'),assert=require('node:assert/strict'),{spawn}=require('node:child_process');
const J=require('./job-cpu.cjs');
const goodMount='20 1 0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n';
function fixture(){let usage=100000,clock=0,closes=0,ino=10;const checks=J.emptyChecks(),fd={async stat(){return {isFile:()=>true,dev:2,ino}},async read(buffer){const raw='usage_usec '+usage+'\nuser_usec '+Math.floor(usage*.6)+'\nsystem_usec '+Math.floor(usage*.4)+'\nnr_throttled 0\n';buffer.write(raw);return {bytesRead:Buffer.byteLength(raw)}},async close(){closes++}},io={async readMembership(){return '0::/\n'},async guardMount(c){for(const k of J.checkNames.slice(1,8))c[k]=true},async open(){return fd}};return {io,fd,checks,options:{io,checks,clock:()=>++clock,platform:'linux',environment:{GITHUB_ACTIONS:'true',ACCESSWEAVER_JOB_CPU_ACCOUNTING:'required'}},get closes(){return closes},set usage(v){usage=v},set ino(v){ino=v}}}
test('private CPU parser and membership/mount checks reject malformed or host scope without retaining values',()=>{
 assert.deepEqual(J.parseCpuStat('usage_usec 100\nuser_usec 60\nsystem_usec 40\nPRIVATE_SYNTHETIC 5\n'),{usageUsec:100,userUsec:60,systemUsec:40});J.membership('0::/\n');assert.ok(J.mount(goodMount).mountReadOnly);
 for(const v of ['0::/PRIVATE_SYNTHETIC\n','1:cpu:/\n','0::/'])assert.throws(()=>J.membership(v));
 for(const v of [goodMount.replace(' / /sys',' /PRIVATE_SYNTHETIC /sys'),goodMount.replace(' ro,',' rw,'),goodMount.replace('- cgroup2','- cgroup'),goodMount+goodMount,''])assert.throws(()=>J.mount(v));
 for(const v of ['usage_usec 1\n','usage_usec 1\nusage_usec 2\nuser_usec 1\nsystem_usec 0', 'usage_usec PRIVATE_SYNTHETIC\nuser_usec 1\nsystem_usec 0','x'.repeat(4097)])assert.throws(()=>J.parseCpuStat(v));
});
test('job CPU tracks identity and monotonic counters, caches checked close, and excludes raw data',async()=>{
 const f=fixture(),counter=await J.JobCpu.open(f.options),a=await counter.sample();f.usage=300000;const b=await counter.sample();assert.deepEqual(Object.keys(a).sort(),['usageUsec','userUsec','systemUsec','startedMilliseconds','finishedMilliseconds'].sort());assert.ok(!JSON.stringify(a).includes('PRIVATE_SYNTHETIC'));assert.ok(J.usageBetween(a,b).percentOneCore>0);await Promise.all([counter.close(),counter.close()]);assert.equal(f.closes,1);assert.equal(f.checks.closeConfirmed,true);await assert.rejects(counter.sample(),e=>J.failureStage(e)===5);
});
test('job CPU refuses unexpected membership, mount, identity, regression and close failures',async()=>{
 const env=fixture();env.options.environment={};await assert.rejects(J.JobCpu.open(env.options),e=>J.failureStage(e)===1);
 const member=fixture();member.io.readMembership=async()=> '0::/PRIVATE_SYNTHETIC\n';await assert.rejects(J.JobCpu.open(member.options),e=>J.failureStage(e)===2);
 const mounted=fixture();mounted.io.guardMount=async()=>{throw new Error('PRIVATE_SYNTHETIC')};await assert.rejects(J.JobCpu.open(mounted.options),e=>J.failureStage(e)===3);
 const f=fixture(),counter=await J.JobCpu.open(f.options);await counter.sample();f.usage=10;await assert.rejects(counter.sample(),e=>J.failureStage(e)===7);f.usage=200000;f.ino=11;await assert.rejects(counter.sample(),e=>J.failureStage(e)===6);let calls=0;f.fd.close=async()=>{calls++;throw new Error('PRIVATE_SYNTHETIC')};await assert.rejects(counter.close(),e=>J.failureStage(e)===8);await assert.rejects(counter.close(),e=>J.failureStage(e)===8);assert.equal(calls,1);
});
test('job CPU uses the inner monotonic window and rejects inconsistent elapsed time',()=>{
 assert.deepEqual(J.usageBetween({usageUsec:100,finishedMilliseconds:10},{usageUsec:100100,startedMilliseconds:110}),{milliseconds:100,percentOneCore:100});assert.throws(()=>J.usageBetween({usageUsec:100,finishedMilliseconds:10},{usageUsec:1,startedMilliseconds:110}));assert.throws(()=>J.usageBetween({usageUsec:0,finishedMilliseconds:10},{usageUsec:1,startedMilliseconds:10}));assert.equal(J.failureStage({jobCpuStage:'PRIVATE_SYNTHETIC'}),1);assert.equal(J.failureStage({get jobCpuStage(){throw new Error('PRIVATE_SYNTHETIC')}}),1);
});
test('private cgroup counter retains CPU from an exited owned helper',{skip:process.platform!=='linux'||process.env.ACCESSWEAVER_JOB_CPU_ACCOUNTING!=='required'},async()=>{
 const counter=await J.JobCpu.open(),before=await counter.sample();let child,timer;
 try{
  const script="const fs=require('node:fs');process.stdin.once('data',()=>{const begin=process.cpuUsage();for(;;){const now=process.cpuUsage(begin);if(now.user+now.system>=200000)break}process.exit(0)});process.stdout.write('ready');";
  child=spawn(process.execPath,['-e',script],{stdio:['pipe','pipe','ignore']});await Promise.race([new Promise(resolve=>child.stdout.once('data',resolve)),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Owned helper ready deadline')),5000)})]);clearTimeout(timer);J.owned(child);const fs=require('node:fs/promises');J.membership(await fs.readFile('/proc/'+child.pid+'/cgroup','utf8'));
  const done=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>code===0?resolve():reject(new Error('Owned helper refused')))});child.stdin.end('go');await Promise.race([done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Owned helper exit deadline')),5000)})]);clearTimeout(timer);assert.notEqual(child.exitCode,null);const after=await counter.sample();assert.ok(after.usageUsec-before.usageUsec>=150000,'Exited helper CPU must remain in the job counter');
 }finally{clearTimeout(timer);if(child&&child.exitCode===null){const exited=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGKILL');await Promise.race([exited,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Owned helper cleanup deadline')),5000)})]);clearTimeout(timer)}await counter.close()}
});
