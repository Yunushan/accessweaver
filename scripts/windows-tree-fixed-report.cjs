'use strict';
// Public projection of a single inert owned-process-tree test. Raw Go events,
// output, process IDs and native error text are never printed or retained.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const target='TestNativeWindowsTerminationKillsOwnedTree';
const stages=Object.freeze(['parent-create','parent-bind','parent-start-tree','tree-inventory','unrelated-create','unrelated-bind','tree-cancel','parent-wait','owner-close','tree-empty','unrelated-alive','closed-protocol','fixture-cleanup']);
function project(text,exitCode,expected){
 if(typeof text!=='string'||Buffer.byteLength(text)>4*1024*1024||!Number.isInteger(expected)||expected<1||expected>20)return {outcome:'refused',code:'bound',attempts:0,passed:0,failed:0,stages:{}};
 let attempts=0,passed=0,failed=0,open=false,marker=null,invalid=false;const counts=Object.fromEntries(stages.map(x=>[x,0]));
 for(const line of text.split('\n')){if(!line)continue;let event;try{event=JSON.parse(line)}catch{invalid=true;break}
  if(event.Test!==target)continue;
  if(event.Action==='run'){if(open||++attempts>expected){invalid=true;break}open=true;marker=null}
  else if(event.Action==='output'&&typeof event.Output==='string'){
   const m=event.Output.match(/ACCESSWEAVER_TREE_STAGE=([a-z-]+)/g)||[];
   for(const raw of m){const value=raw.slice('ACCESSWEAVER_TREE_STAGE='.length);if(!open||marker!==null||!stages.includes(value)){invalid=true;break}marker=value}
  }else if(event.Action==='pass'||event.Action==='fail'){
   if(!open){invalid=true;break}open=false;
   if(event.Action==='pass'){if(marker!==null){invalid=true;break}passed++}
   else{failed++;if(marker===null){invalid=true;break}counts[marker]++}
  }
  if(invalid)break;
 }
 if(invalid||open||attempts!==expected||passed+failed!==expected||!Number.isInteger(exitCode)||(exitCode===0)!==(failed===0))return {outcome:'refused',code:'protocol',attempts,passed,failed,stages:counts};
 return {outcome:failed?'failed':'passed',code:failed?'test-failed':'none',attempts,passed,failed,stages:counts};
}
module.exports={project,stages,target};
if(require.main===module){
 const arch={x64:'amd64',arm64:'arm64'}[process.arch],host={AMD64:'amd64',ARM64:'arm64'}[(process.env.PROCESSOR_ARCHITECTURE||'').toUpperCase()];
 if(process.platform!=='win32'||process.version!=='v26.8.2'||process.env.GITHUB_ACTIONS!=='true'||process.env.RUNNER_ENVIRONMENT!=='github-hosted'||arch!==host||arch!==process.env.ACCESSWEAVER_EXPECT_GOARCH||!/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||''))throw Error('Hosted native identity refused');
 const root=path.resolve(process.env.GITHUB_WORKSPACE||''),dir=path.resolve(process.env.ACCESSWEAVER_TREE_REPORT_DIR||''),temp=path.resolve(process.env.RUNNER_TEMP||'');
 if(!dir.startsWith(temp+path.sep)||fs.readdirSync(dir).length!==0||fs.lstatSync(dir).isSymbolicLink())throw Error('Report directory refused');
 const files=['internal/nativeprocess/terminate_windows_test.go','internal/nativeprocess/terminate_windows.go','scripts/windows-tree-fixed-report.cjs','scripts/test-windows-tree-fixed-report.cjs','.github/workflows/windows-tree-regression.yml','go.mod','go.sum'];
 const hashes=Object.fromEntries(files.map(file=>[file,crypto.createHash('sha256').update(fs.readFileSync(path.join(root,file))).digest('hex')]));
 const result=spawnSync('go',['test','-json','-count=10','-timeout=4m','-run','^'+target+'$','./internal/nativeprocess'],{cwd:root,encoding:'utf8',maxBuffer:4*1024*1024,timeout:360000,windowsHide:true,env:{...process.env,GOTOOLCHAIN:'local'}});
 const value=project(result.stdout||'',result.status,10),after=Object.fromEntries(files.map(file=>[file,crypto.createHash('sha256').update(fs.readFileSync(path.join(root,file))).digest('hex')]));
 const stable=files.every(file=>hashes[file]===after[file]);if(!stable){value.outcome='refused';value.code='source-changed'}
 const report={schemaVersion:1,sourceCommit:process.env.GITHUB_SHA,architecture:arch,sourceSHA256:hashes,sourceStable:stable,...value,rawOutputPublished:false,productionQualificationComplete:false};
 fs.writeFileSync(path.join(dir,'status.json'),JSON.stringify(report)+'\n',{flag:'wx'});
 if(value.outcome!=='passed')process.exitCode=1;
}
