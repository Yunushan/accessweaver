const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {contract,names,sources,writeEvidence,validKeyboard}=require('./modal-keyboard.cjs');

test('keyboard evidence checks retain only ordered static state and never callback errors',async()=>{
 const result=contract(),secret='PRIVATE_SYNTHETIC_ERROR';await result.check(names[0],async()=>{});
 await assert.rejects(result.check(names[1],async()=>{throw new Error(secret)}));
 assert.equal(result.outcome,'failed');assert.equal(result.code,names[1]);assert.equal(result.checks[0].status,'passed');assert.equal(result.checks[1].status,'failed');assert.equal(result.checks[2].status,'not-run');assert.ok(!JSON.stringify(result.checks).includes(secret));
});
test('keyboard evidence cannot reorder or omit the required browser checks',async()=>{
 const result=contract();await assert.rejects(result.check(names[1],async()=>{}));assert.ok(result.checks.every(c=>c.status==='not-run'));
 for(const name of names)await result.check(name,async()=>{});assert.equal(result.outcome,'passed');assert.equal(result.code,'none');
});
test('keyboard evidence is source-bound, closed-schema and exclusive without retaining private error fields',async()=>{
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-modal-contract-'));
 const prior={GITHUB_ACTIONS:process.env.GITHUB_ACTIONS,GITHUB_SHA:process.env.GITHUB_SHA};const source='a'.repeat(40);
 process.env.GITHUB_ACTIONS='true';process.env.GITHUB_SHA=source;
 try{
  for(const name of sources){const file=path.join(temporary,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,'fixed source fixture bytes')}
  const core={build:{commit:source,sourceState:'clean',platform:'linux'},binarySha256:'b'.repeat(64)},info={project:{name:'chromium'}},result=contract();for(const name of names)await result.check(name,async()=>{});
  result.checks[0].privateError='PRIVATE_SYNTHETIC_ERROR';await assert.rejects(writeEvidence(temporary,core,info,'json-success',result),/Malformed keyboard checks/);delete result.checks[0].privateError;
  await writeEvidence(temporary,core,info,'json-success',result);const file=path.join(temporary,'build/modal-keyboard-evidence/json-success.json'),raw=await fs.readFile(file,'utf8'),report=JSON.parse(raw);
  assert.equal(report.outcome,'passed');assert.equal(report.productionQualificationComplete,false);assert.deepEqual(report.checks,result.checks);assert.equal(Object.keys(report.sourceSHA256).length,7);assert.ok(!raw.includes(temporary));assert.ok(!raw.includes('PRIVATE_SYNTHETIC_ERROR'));
  await assert.rejects(writeEvidence(temporary,core,info,'json-success',result),{code:'EEXIST'});assert.equal(await fs.readFile(file,'utf8'),raw);
 }finally{
  for(const [key,value] of Object.entries(prior)){if(value===undefined)delete process.env[key];else process.env[key]=value}
  const info=await fs.lstat(temporary),resolved=await fs.realpath(temporary),parent=await fs.realpath(os.tmpdir());
  assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(resolved)===parent&&path.basename(resolved).startsWith('accessweaver-modal-contract-'),'Unsafe keyboard evidence fixture cleanup');
  await fs.rm(resolved,{recursive:true,force:true});
 }
});

test('keyboard focus trace accepts only fixed categories, booleans and bounded source line numbers',()=>{
 const trace={before:'feedback',after:'dialog',prevented:true,feedbackTabIndex:0,feedbackRendered:true,feedbackBlocked:false,candidates:['feedback'],candidateLimited:false,candidateScanOK:true,errorKind:'none',errorLine:0};
 assert.equal(validKeyboard(trace),true);assert.equal(validKeyboard(null),true);assert.equal(validKeyboard({...trace,after:'scroll',candidates:['scroll','feedback']}),true);
 for(const mutation of [{after:'PRIVATE_SYNTHETIC_TARGET'},{candidates:['/private/fixture']},{errorKind:'PRIVATE_SYNTHETIC_ERROR'},{errorLine:5001},{message:'PRIVATE_SYNTHETIC_ERROR'},{candidates:Array(65).fill('feedback')}])assert.equal(validKeyboard({...trace,...mutation}),false);
});
