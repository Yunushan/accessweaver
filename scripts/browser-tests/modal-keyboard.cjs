// Source-owned fixed-schema keyboard evidence; never DOM, URLs or errors.
const fs=require('node:fs/promises');
const path=require('node:path');
const {createHash}=require('node:crypto');
const scenarios=['guided-success','json-success','guided-failure','json-failure'];
const names=['editor-open','save-request','busy-focus','forward-tab','reverse-tab','busy-shortcuts','disclosure-or-json','release-reply','save-outcome','draft-or-saved-preserved','close-or-return','single-save'];
const sources=['web/app.js','web/index.html','web/app.css','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/modal-keyboard.cjs','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/package-lock.json'];
function contract(){
 const checks=names.map(name=>({name,status:'not-run'}));let current=0;
 return {checks,async check(name,action){if(name!==names[current])throw new Error('Keyboard contract order differs');const item=checks[current++];try{await action();item.status='passed'}catch(error){item.status='failed';throw error}},get outcome(){return checks.every(c=>c.status==='passed')?'passed':'failed'},get code(){return checks.find(c=>c.status!=='passed')?.name||'none'}};
}
async function writeEvidence(repo,core,testInfo,scenario,result){
 if(process.env.GITHUB_ACTIONS!=='true')return;
 if(!scenarios.includes(scenario)||!['chromium','firefox','webkit'].includes(testInfo.project.name))throw new Error('Unknown keyboard fixture');
 const source=core.build.commit;
 if(!/^[a-f0-9]{40}$/.test(source)||core.build.sourceState!=='clean'||source!==process.env.GITHUB_SHA||process.env.GITHUB_ACTIONS!=='true'||core.build.platform!=='linux'||!/^[a-f0-9]{64}$/.test(core.binarySha256))throw new Error('Keyboard fixture source binding differs');
 if(!Array.isArray(result.checks)||result.checks.length!==names.length||result.checks.some((c,i)=>!c||Object.keys(c).sort().join(',')!=='name,status'||c.name!==names[i]||!['passed','failed','not-run'].includes(c.status)))throw new Error('Malformed keyboard checks');
 const checks=result.checks.map(c=>({name:c.name,status:c.status}));
 const outcome=checks.every(c=>c.status==='passed')?'passed':'failed',code=checks.find(c=>c.status!=='passed')?.name||'none';
 const hashes={};for(const name of sources){const bytes=await fs.readFile(path.join(repo,name));if(bytes.length>1<<20)throw new Error('Keyboard source budget exceeded');hashes[name]=createHash('sha256').update(bytes).digest('hex')}
 const value={schemaVersion:1,sourceCommit:source,sourceSHA256:hashes,binarySHA256:core.binarySha256,project:testInfo.project.name,scenario,outcome,code,checks,productionQualificationComplete:false};
 const encoded=JSON.stringify(value)+'\n';if(Buffer.byteLength(encoded)>16384)throw new Error('Keyboard report budget exceeded');
 const parent=path.join(repo,'build/modal-keyboard-evidence');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),actual=await fs.realpath(parent),build=await fs.realpath(path.join(repo,'build'));
 if(!info.isDirectory()||info.isSymbolicLink()||path.dirname(actual)!==build)throw new Error('Keyboard evidence parent differs');
 const file=await fs.open(path.join(actual,scenario+'.json'),'wx',0o600);try{await file.writeFile(encoded,'utf8')}finally{await file.close()}
}
module.exports={scenarios,names,sources,contract,writeEvidence};
