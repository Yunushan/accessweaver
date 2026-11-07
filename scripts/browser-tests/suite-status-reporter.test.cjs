const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),vm=require('node:vm');
const Reporter=require('./suite-status-reporter.cjs'),manifest=require('./suite-contracts.json');

test('browser case registry exactly matches all53source-registered contracts',async()=>{
 const names=[],register=title=>names.push(title),base={test:{extend:()=>register},expect:()=>{}};
 vm.runInNewContext(await fs.readFile(path.join(__dirname,'desktop.spec.cjs'),'utf8'),{__dirname,process:{env:{},platform:'linux',arch:'x64',version:process.version},setTimeout,clearTimeout,require(name){if(name==='@playwright/test')return base;if(name==='./accessibility.cjs')return {};return require(name)}},{timeout:2000});
 assert.equal(names.length,53);assert.deepEqual(manifest.cases,names.map((name,i)=>({id:i+1,name})));
});
test('browser status projection drops errors, attachments, private titles and unknown status strings',()=>{
 const reporter=new Reporter();reporter.onBegin({}, {allTests:()=>Array(53)});
 const secret='PRIVATE_SYNTHETIC_VALUE';reporter.onTestEnd({title:manifest.cases[0].name,annotations:[{type:'aw-a11y-rule',description:'landmark-unique'},{type:'aw-a11y-rule',description:secret},{type:'PRIVATE_SYNTHETIC_TYPE',description:secret}]},{status:'failed',retry:0,error:{message:secret},attachments:[{path:secret}],stdout:[secret]});
 reporter.onTestEnd({title:secret},{status:secret,retry:0});reporter.onTestEnd({title:manifest.cases[1].name},{status:secret,retry:0});
 const data=reporter.value('failed');assert.equal(data.cases[0].status,'failed');assert.deepEqual(data.cases[0].a11yRules,['landmark-unique']);assert.equal(data.cases[1].status,'unknown');assert.equal(data.unrecognized,1);assert.ok(!JSON.stringify(data).includes(secret));assert.equal(data.outcome,'failed');
});
test('browser status evidence requires every case exactly once and preserves exclusive owned output',async()=>{
 const reporter=new Reporter();reporter.onBegin({}, {allTests:()=>Array(53)});for(const c of manifest.cases)reporter.onTestEnd({title:c.name},{status:'passed',retry:0});assert.equal(reporter.value('passed').outcome,'passed');
 reporter.onTestEnd({title:manifest.cases[0].name},{status:'passed',retry:1});assert.equal(reporter.value('passed').outcome,'failed');
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-suite-contract-'));
 try{
  for(const name of [...Reporter.sources,'build/browser-tests/accessweaver']){const file=path.join(temporary,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,'fixed public fixture bytes')}
  const value=reporter.value('failed');value.cases[0].message='PRIVATE_SYNTHETIC_VALUE';await assert.rejects(Reporter.writeReport(temporary,'chromium','a'.repeat(40),value),/Browser case evidence differs/);delete value.cases[0].message;
  const writing=Reporter.writeReport(temporary,'chromium','a'.repeat(40),value);value.cases[0].message='PRIVATE_SYNTHETIC_VALUE';value.cases[0].a11yRules.push('PRIVATE_SYNTHETIC_VALUE');await writing;delete value.cases[0].message;value.cases[0].a11yRules.pop();const file=path.join(temporary,'build/browser-contract-evidence/status.json'),raw=await fs.readFile(file,'utf8');assert.ok(!raw.includes(temporary));assert.ok(!raw.includes('PRIVATE_SYNTHETIC_VALUE'));assert.equal(JSON.parse(raw).productionQualificationComplete,false);assert.equal(JSON.parse(raw).schemaVersion,2);assert.equal(JSON.parse(raw).cases.length,53);
  await assert.rejects(Reporter.writeReport(temporary,'chromium','a'.repeat(40),value),{code:'EEXIST'});assert.equal(await fs.readFile(file,'utf8'),raw);
 }finally{const info=await fs.lstat(temporary),resolved=await fs.realpath(temporary),parent=await fs.realpath(os.tmpdir());assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(resolved)===parent&&path.basename(resolved).startsWith('accessweaver-suite-contract-'));await fs.rm(resolved,{recursive:true,force:true})}
});

test('browser source locations discard private path prefixes and never read error text; evidence failure only fails the runner',async()=>{
 const secret='PRIVATE_SYNTHETIC_VALUE';const error={get message(){throw new Error(secret)},get stack(){throw new Error(secret)},location:{file:path.join(os.tmpdir(),secret,'desktop.spec.cjs'),line:42,column:3}};
 assert.deepEqual(Reporter.sourceLocation(error),{sourceRole:'desktop',sourceLine:42,sourceColumn:3});assert.ok(!JSON.stringify(Reporter.sourceLocation(error)).includes(secret));
 assert.deepEqual(Reporter.sourceLocation({location:{file:path.join(os.tmpdir(),secret),line:42,column:3}}),{sourceRole:'other',sourceLine:0,sourceColumn:0});
 const previous={GITHUB_ACTIONS:process.env.GITHUB_ACTIONS,BROWSER:process.env.BROWSER,GITHUB_SHA:process.env.GITHUB_SHA};process.env.GITHUB_ACTIONS='true';process.env.BROWSER='invalid';process.env.GITHUB_SHA='a'.repeat(40);
 try{const reporter=new Reporter();reporter.onBegin({}, {allTests:()=>Array(53)});for(const c of manifest.cases)reporter.onTestEnd({title:c.name},{status:'passed',retry:0});assert.deepEqual(await reporter.onEnd({status:'passed'}),{status:'failed'});assert.deepEqual(await reporter.onEnd({status:'failed'}),{status:'failed'})}finally{for(const [key,value]of Object.entries(previous)){if(value===undefined)delete process.env[key];else process.env[key]=value}}
});
