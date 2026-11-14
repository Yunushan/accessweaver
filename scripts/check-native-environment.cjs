#!/usr/bin/env node
'use strict';
// Native test identity checks, not a claim of vendor/deployment qualification.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {spawnSync}=require('node:child_process');
function architecture(value){
 const result={x64:'amd64',amd64:'amd64',x86_64:'amd64',arm64:'arm64',aarch64:'arm64'}[String(value).toLowerCase()];
 assert(result,'unsupported or missing native architecture');return result;
}
function validateEnvironment(actual,expected){
 assert(['windows','linux','darwin'].includes(expected.goos),'explicit expected platform is required');
 assert(['amd64','arm64'].includes(expected.goarch),'explicit expected Go architecture is required');
 assert(/^\d+\.\d+\.\d+$/.test(expected.goVersion||''),'explicit pinned Go version is required');
 assert.equal({win32:'windows',linux:'linux',darwin:'darwin'}[actual.platform],expected.goos,'host OS differs from native test target');
 assert.equal(architecture(actual.machine),expected.goarch,'host machine differs from native test target');
 if(actual.runnerArch)assert.equal(architecture(actual.runnerArch),expected.goarch,'runner architecture differs from native test target');
 for(const [key,value] of Object.entries({GOHOSTOS:expected.goos,GOHOSTARCH:expected.goarch,GOOS:expected.goos,GOARCH:expected.goarch,GOVERSION:'go'+expected.goVersion,GOTOOLCHAIN:'local'}))assert.equal(actual.go[key],value,'unexpected native Go SDK/target: '+key);
 if(expected.hosted){assert.equal(actual.runnerEnvironment,'github-hosted','native acceptance requires a hosted runner');assert.match(expected.commit||'',/^[0-9a-f]{40,64}$/,'native acceptance requires an expected source commit');}
}
function validateBuild(build,expected){
 assert.equal(build.platform,expected.goos,'executed CLI platform differs from native target');
 assert.equal(build.arch,expected.goarch,'executed CLI architecture differs from native target');
 assert.equal(build.goVersion,'go'+expected.goVersion,'executed CLI compiler differs from pinned SDK');
 if(expected.commit){assert.equal(build.commit,expected.commit,'executed CLI source commit differs from expectation');assert.equal(build.sourceState,'clean','executed CLI was built from modified source');}
}
function validateUpdateBuild(comparison,build){
 const tag='v'+build.version;
 assert.deepEqual(comparison,{version:tag,currentVersion:build.version,updateAvailable:false,build},'native update comparison differs from the executed build');
}
function execute(command,args){
 const result=spawnSync(command,args,{encoding:'utf8',timeout:30000,windowsHide:true,maxBuffer:1<<20});
 if(result.error)throw result.error;
 assert.equal(result.status,0,'native identity command failed: '+result.stderr);
 return JSON.parse(result.stdout);
}
function main(){
 const args=process.argv.slice(2);
 const checkUpdate=args.length===3&&args[2]==='--check-update-build';
 assert(args.length===0 || (args.length===2 || checkUpdate) && args[0]==='--binary','usage: check-native-environment.cjs [--binary PATH [--check-update-build]]');
 const expected={goos:process.env.ACCESSWEAVER_EXPECT_GOOS,goarch:process.env.ACCESSWEAVER_EXPECT_GOARCH,goVersion:process.env.GO_VERSION,commit:process.env.GITHUB_SHA||'',hosted:process.env.GITHUB_ACTIONS==='true'};
 const actual={platform:process.platform,machine:os.machine(),nodeProcessArch:process.arch,runnerArch:process.env.RUNNER_ARCH||'',runnerEnvironment:process.env.RUNNER_ENVIRONMENT||'',go:execute('go',['env','-json','GOOS','GOARCH','GOHOSTOS','GOHOSTARCH','GOVERSION','GOTOOLCHAIN','CGO_ENABLED'])};
 validateEnvironment(actual,expected);
 const report={schemaVersion:1,sourceCommit:expected.commit||'unknown',target:expected.goos+'/'+expected.goarch,platform:actual.platform,machine:actual.machine,nodeProcessArch:actual.nodeProcessArch,nodeVersion:process.version,runnerArch:actual.runnerArch,runnerEnvironment:actual.runnerEnvironment,imageOS:process.env.ImageOS||'',imageVersion:process.env.ImageVersion||'',osRelease:os.release(),go:actual.go,environmentVerified:true,productionQualificationComplete:false};
 let phase='environment';
 if(args.length){
  const binary=path.resolve(args[1]),info=fs.lstatSync(binary);assert(info.isFile()&&!info.isSymbolicLink()&&info.size>0&&info.size<=128<<20,'native CLI must be a bounded regular file');
  const before=fs.readFileSync(binary),build=execute(binary,['version','--json']);
  validateBuild(build,expected);
  if(checkUpdate){
   validateUpdateBuild(execute(binary,['system','check-version','--build-identity','--follow-channel','v'+build.version]),build);
   report.updateBuildVerified=true;
  }
  const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
  const hash=digest(before);assert.equal(digest(fs.readFileSync(binary)),hash,'native CLI changed during identity check');
  Object.assign(report,{build,binarySha256:hash,executedTargetVerified:true});phase='binary';
 }
 const folder=path.resolve('build','native-checks');fs.mkdirSync(folder,{recursive:true});
 fs.writeFileSync(path.join(folder,phase+'-'+expected.goos+'-'+expected.goarch+'.json'),JSON.stringify(report,null,2)+'\n');
 console.log(JSON.stringify(report));
}
module.exports={architecture,validateEnvironment,validateBuild,validateUpdateBuild};
if(require.main===module){try{main()}catch(error){console.error(error.message);process.exitCode=1;}}
