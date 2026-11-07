const test=require('node:test'),assert=require('node:assert/strict');
const {ChildProcess,spawn}=require('node:child_process');
const {BrowserResources,ids,live}=require('./browser-resources.cjs');
const {parseStat}=require('./desktop-performance.cjs');
function processRow(pid,parent,overrides={}){return {pid,parent,ticks:10,start:pid*10,rss:4,threads:2,tasks:[pid],children:{[pid]:[]},fds:['0','1'],state:'S',...overrides}}
function raw(row){const f=Array(50).fill('0');Object.assign(f,{0:row.state,1:String(row.parent),11:String(row.ticks),12:'0',17:String(row.threads),19:String(row.start),21:String(row.rss)});return row.pid+' (PRIVATE_SYNTHETIC_NAME ) name) '+f.join(' ')}
function fixture(rows){const child=new ChildProcess();child.pid=100;const graph=new Map(rows.map(r=>[r.pid,r])),reads=[];const source={async read(file){reads.push(file);const pid=Number(file.split('/')[2]),r=graph.get(pid);if(!r)throw Object.assign(new Error('PRIVATE_SYNTHETIC_ERROR'),{code:'ENOENT'});if(file.endsWith('/stat'))return raw(r);return (r.children[Number(file.split('/')[4])]||[]).join(' ')},async entries(file){const r=graph.get(Number(file.split('/')[2]));if(!r)throw Object.assign(new Error('PRIVATE_SYNTHETIC_ERROR'),{code:'ENOENT'});return file.endsWith('/task')?r.tasks.map(String):r.fds}};return {child,graph,reads,source,observer:new BrowserResources(child,4096,parseStat,source)}}
test('browser ownership requires an actual live spawned-process handle and bounded numeric identifiers',()=>{
 assert.throws(()=>live({pid:100,exitCode:null,signalCode:null}));for(const value of ['1 PRIVATE_SYNTHETIC','0','-1','1 1','9007199254740992','1'.repeat(65537)])assert.throws(()=>ids(value,64));assert.deepEqual(ids(' 2 3\n',64),[2,3]);assert.deepEqual(ids('',64),[]);assert.throws(()=>ids('1 2',1));
});
test('browser census discovers descendants forked by non-leader threads and retains only aggregates',async()=>{
 const f=fixture([processRow(100,process.pid,{tasks:[100,101],children:{100:[],101:[200]}}),processRow(200,100,{children:{200:[300]}}),processRow(300,200)]);const v=await f.observer.snapshot();assert.deepEqual(v,{cpuTicks:30,rssBytes:49152,descriptors:6,threads:6,processes:3,samples:1,observedExits:0});assert.ok(f.reads.includes('/proc/100/task/101/children'));assert.ok(f.reads.every(p=>/^\/proc\/(100|200|300)\//.test(p)));assert.ok(!JSON.stringify(v).includes('PRIVATE_SYNTHETIC'));
});
test('browser census rejects foreign parentage, PID reuse and counter regression',async()=>{
 const f=fixture([processRow(100,process.pid,{children:{100:[200]}}),processRow(200,999)]);await assert.rejects(f.observer.snapshot());f.graph.get(200).parent=100;await f.observer.snapshot();f.graph.get(200).start++;await assert.rejects(f.observer.snapshot());f.graph.get(200).start--;f.graph.get(200).ticks--;await assert.rejects(f.observer.snapshot());
});
test('known descendants remain measured after reparenting and exited children do not break a sample',async()=>{
 const f=fixture([processRow(100,process.pid,{children:{100:[200]}}),processRow(200,100)]);await f.observer.snapshot();f.graph.get(100).children={100:[]};f.graph.get(200).parent=1;f.graph.get(200).ticks=20;const alive=await f.observer.snapshot();assert.equal(alive.processes,2);assert.equal(alive.cpuTicks,30);f.graph.get(200).state='Z';const dead=await f.observer.snapshot();assert.equal(dead.processes,1);assert.equal(dead.observedExits,1);f.graph.delete(200);assert.equal((await f.observer.snapshot()).observedExits,1);
});
test('browser samples are serialized and a disappeared root fails ownership',async()=>{
 const f=fixture([processRow(100,process.pid)]);const pending=f.observer.snapshot();await assert.rejects(f.observer.snapshot());await pending;f.graph.delete(100);await assert.rejects(f.observer.snapshot());
});
test('browser census fails closed on oversized lists, ancestry cycles and read/close refusal',async()=>{
 const f=fixture([processRow(100,process.pid,{tasks:Array.from({length:513},(_,i)=>100+i)})]);await assert.rejects(f.observer.snapshot());f.graph.get(100).tasks=[100];f.graph.get(100).children={100:[100]};await assert.rejects(f.observer.snapshot());f.graph.get(100).children={100:[]};f.source.entries=async()=>{throw new Error('PRIVATE_SYNTHETIC_CLOSE_FAILURE')};await assert.rejects(f.observer.snapshot());
});
test('real Linux census includes an owned Node grandchild without inspecting other processes',{skip:process.platform!=='linux'},async()=>{
 const child=spawn(process.execPath,['-e',"const {spawn}=require('node:child_process');const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});process.stdout.write('ready\\n');process.on('SIGTERM',()=>{c.kill('SIGTERM');c.on('exit',()=>process.exit(0))});setInterval(()=>{},1000)"],{stdio:['ignore','pipe','ignore']});
 let timer;
 try{await Promise.race([new Promise(resolve=>child.stdout.once('data',resolve)),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Synthetic child deadline')),5000)})]);clearTimeout(timer);const observer=new BrowserResources(child,4096,parseStat);const value=await observer.snapshot();assert.equal(value.processes,2);assert.ok(value.threads>=2&&value.rssBytes>0&&value.descriptors>=2);assert.deepEqual(Object.keys(value).sort(),['cpuTicks','rssBytes','descriptors','threads','processes','samples','observedExits'].sort());const memory=(await observer.snapshot(true)).memory;assert.equal(memory.root.readable,1);assert.equal(memory.descendants.readable,1);assert.ok(memory.root.pssBytes>0&&memory.descendants.pssBytes>0)}
 finally{clearTimeout(timer);const done=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGTERM');await Promise.race([done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Synthetic child cleanup deadline')),5000)})]);clearTimeout(timer)}
});


test('owned memory collection reports root/descendant totals and permission coverage without exposing identities',async()=>{
 const M=require('./browser-memory.cjs'),f=fixture([processRow(100,process.pid,{children:{100:[200]}}),processRow(200,100)]),read=f.source.read;
 const text=['Rss','Pss','Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Anonymous','Swap','Pss_Anon','Pss_File','Pss_Shmem'].map(k=>k+': 1 kB').join('\n');
 f.source.read=async file=>{if(file.endsWith('/smaps_rollup')){if(file.startsWith('/proc/200/'))throw Object.assign(new Error('PRIVATE_SYNTHETIC_DENIAL'),{code:'EACCES'});return text}return read(file)};
 const sample=await f.observer.snapshot(true);assert.equal(sample.memory.root.readable,1);assert.equal(sample.memory.root.pssBytes,1024);assert.equal(sample.memory.descendants.denied,1);assert.equal(sample.memory.descendants.pssBytes,0);assert.equal(sample.memory.root.statRssBytes+sample.memory.descendants.statRssBytes,sample.rssBytes);M.validatePoints([{phase:'dashboard',...sample.memory}]);assert.ok(!JSON.stringify(sample).includes('PRIVATE_SYNTHETIC'));
});
test('owned memory read is rechecked against the original start time before aggregation',async()=>{
 const f=fixture([processRow(100,process.pid)]),read=f.source.read;f.source.read=async file=>{if(file.endsWith('/smaps_rollup')){f.graph.get(100).start++;return ['Rss','Pss','Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Anonymous','Swap','Pss_Anon','Pss_File','Pss_Shmem'].map(k=>k+': 0 kB').join('\n')}return read(file)};await assert.rejects(f.observer.snapshot(true));assert.equal(f.observer.failureStage,6);
});
