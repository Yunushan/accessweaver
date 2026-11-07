const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const M=require('./browser-memory.cjs');
function rollup(){return '0001-ffff ---p 0000 00:00 0 PRIVATE_SYNTHETIC_HEADER\n'+Object.entries({Rss:100,Pss:70,Private_Clean:10,Private_Dirty:30,Shared_Clean:50,Shared_Dirty:10,Anonymous:35,Swap:0,Pss_Anon:30,Pss_File:35,Pss_Shmem:5}).map(([k,v])=>k+': '+v+' kB').join('\n')+'\nUnknown_PRIVATE_FIELD: PRIVATE_SYNTHETIC_VALUE\n'}
function points(){const root={...M.emptyGroup(),processes:1,statRssBytes:102400,largestProcessRssBytes:102400,readable:1,...M.parseSmaps(rollup())};return M.phases.map(phase=>({phase,root:{...root},descendants:M.emptyGroup()}))}
async function temporary(t){const root=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-browser-memory-'));t.after(async()=>{const info=await fs.lstat(root),resolved=await fs.realpath(root),parent=await fs.realpath(os.tmpdir());assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(resolved)===parent&&path.basename(resolved).startsWith('accessweaver-browser-memory-'));await fs.rm(resolved,{recursive:true,force:true})});return root}
test('smaps parser retains only fixed numeric totals and rejects missing, duplicate, malformed or oversized counters',()=>{
 const v=M.parseSmaps(rollup());assert.equal(v.mappedRssBytes,102400);assert.equal(v.privateBytes,40960);assert.equal(v.sharedBytes,61440);assert.equal(v.pssBytes,71680);assert.ok(!JSON.stringify(v).includes('PRIVATE_SYNTHETIC'));
 for(const text of [rollup().replace('Pss: 70 kB','Pss: PRIVATE_SYNTHETIC kB'),rollup()+'Pss: 70 kB\n',rollup().replace('Pss: 70 kB',''),rollup().replace('Rss: 100 kB','Rss: 9007199254740992 kB'),'x'.repeat(16385)])assert.throws(()=>M.parseSmaps(text));
});
test('memory diagnostic schema rejects private fields, missing coverage and incorrect phase order',()=>{
 M.validatePoints(points());for(const mutate of [p=>p[0].path='PRIVATE_SYNTHETIC',p=>p[0].root.pid=123,p=>p[0].root.readable=0,p=>p[0].root.pssBytes=Infinity,p=>p.reverse()]){const p=points();mutate(p);assert.throws(()=>M.validatePoints(p))}M.validatePoints([]);
});
test('memory report snapshots numeric fields, binds source/binary identity and refuses output replacement',async t=>{
 const root=await temporary(t);for(const n of [...M.sources,'build/browser-tests/accessweaver']){const file=path.join(root,n);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,'synthetic fixed source')}
 const binary=createHash('sha256').update('synthetic fixed source').digest('hex'),value=points(),writing=M.writeMemoryReport(root,'a'.repeat(40),binary,'firefox','arm64',value);value[0].root.private='PRIVATE_SYNTHETIC';await writing;delete value[0].root.private;
 const file=path.join(root,'build/browser-memory/status.json'),bytes=await fs.readFile(file,'utf8'),report=JSON.parse(bytes);assert.equal(report.mode,'diagnostic-only');assert.equal(report.complete,true);assert.equal(report.productionQualificationComplete,false);assert.equal(report.points.length,7);assert.ok(!bytes.includes('PRIVATE_SYNTHETIC')&&!bytes.includes(root));await assert.rejects(M.writeMemoryReport(root,'a'.repeat(40),binary,'firefox','arm64',value),{code:'EEXIST'});assert.equal(await fs.readFile(file,'utf8'),bytes);
});
