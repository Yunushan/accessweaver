#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {architecture}=require('../check-native-environment.cjs');
const {verifyBrowserCache,validateNativeInvocation}=require('./browser-native-binary.cjs');

const expectedVersion = '1.64.1';
const expectedCache = '/ms-playwright';


const crypto=require('node:crypto');
const sources=['scripts/check-native-environment.cjs','scripts/browser-tests/check-image-environment.cjs','scripts/browser-tests/browser-native-binary.cjs','scripts/browser-tests/package-lock.json','.github/workflows/browser.yml'];
const roles=['chromium','firefox','webkit-gtk','webkit-wpe','chromium-headless-shell'];
const stages=['environment','packages','cache','browser-isa','complete'];
function validValue(value){
 assert.deepEqual(Object.keys(value).sort(),['stage','failureKind','outcome','observations'].sort());
 assert.ok(stages.includes(value.stage)&&['none','AssertionError','Error','TypeError','Other'].includes(value.failureKind)&&['passed','failed'].includes(value.outcome));
 assert.equal(value.outcome==='passed',value.stage==='complete'&&value.failureKind==='none');
 assert.ok(Array.isArray(value.observations)&&value.observations.length<=8);
 for(const item of value.observations){assert.deepEqual(Object.keys(item).sort(),['role','format','machine'].sort());assert.ok(roles.includes(item.role)&&['unread','elf','script','other'].includes(item.format)&&['unknown','amd64','arm64','other'].includes(item.machine));assert.ok(item.format==='elf'||item.machine==='unknown')}
 if(value.outcome==='passed'){assert.ok(['chromium','firefox','webkit-gtk','chromium-headless-shell'].every(role=>value.observations.some(item=>item.role===role)));assert.ok(value.observations.every(item=>item.format==='elf'))}
}
function hash(file){const fd=fs.openSync(file,'r');try{const before=fs.fstatSync(fd);assert.ok(before.isFile()&&before.size>0&&before.size<=1<<20);const buffer=Buffer.alloc(before.size+1);let total=0;while(total<buffer.length){const n=fs.readSync(fd,buffer,total,buffer.length-total,null);if(!n)break;total+=n}const bytes=buffer.subarray(0,total);const after=fs.fstatSync(fd);assert.ok(bytes.length===before.size&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs);return crypto.createHash('sha256').update(bytes).digest('hex')}finally{fs.closeSync(fd)}}
function writeReport(repo,source,project,arch,value){
 assert.ok(/^[0-9a-f]{40}$/.test(source)&&['chromium','firefox','webkit'].includes(project)&&['amd64','arm64'].includes(arch));validValue(value);
 if(value.outcome==='passed')assert.ok(value.observations.every(item=>item.machine===arch));
 const sourceSHA256=Object.fromEntries(sources.map(name=>[name,hash(path.join(repo,name))]));
 const data={schemaVersion:1,sourceCommit:source,sourceSHA256,project,architecture:arch,...value,productionQualificationComplete:false};
 const encoded=JSON.stringify(data)+'\n';assert.ok(Buffer.byteLength(encoded)<=8192);
 const parent=path.join(repo,'build/browser-image-evidence');fs.mkdirSync(parent,{recursive:true,mode:0o700});const info=fs.lstatSync(parent),resolved=fs.realpathSync(parent),build=fs.realpathSync(path.join(repo,'build'));assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&path.dirname(resolved)===build);
 const fd=fs.openSync(path.join(resolved,'status.json'),'wx',0o600);try{fs.writeFileSync(fd,encoded,'utf8')}finally{fs.closeSync(fd)}return data;
}
function main(){let stage='environment',failureKind='none';const observations=[];let failed=false;
 try{
assert.equal(process.platform, 'linux', 'Browser image verification requires Linux');
validateNativeInvocation(process.env);
assert.equal(process.getuid(), 1001, 'Browser acceptance requires UID 1001');
assert.ok(['amd64','arm64'].includes(process.env.ACCESSWEAVER_EXPECT_GOARCH),'Explicit native browser architecture is required');
assert.equal(architecture(process.arch),process.env.ACCESSWEAVER_EXPECT_GOARCH,'Node observer architecture differs from native target');
assert.equal(process.env.PLAYWRIGHT_BROWSERS_PATH, expectedCache, 'Keep the image browser cache selected');

stage='packages';
const lock = JSON.parse(fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8'));
assert.equal(lock.packages[''].devDependencies['@playwright/test'], expectedVersion, 'Lockfile test dependency differs');
for (const name of ['@playwright/test', 'playwright', 'playwright-core']) {
  assert.equal(lock.packages['node_modules/' + name].version, expectedVersion, 'Lockfile version differs for ' + name);
  const installed = JSON.parse(fs.readFileSync(require.resolve(name + '/package.json'), 'utf8'));
  assert.equal(installed.version, expectedVersion, 'Installed version differs for ' + name);
}

stage='cache';
const cache = fs.realpathSync(expectedCache);
assert.equal(cache, expectedCache, 'Image browser cache must retain its expected path');
assert.ok(fs.statSync(cache).isDirectory(), 'Image browser cache must be a directory');

const playwright = require('@playwright/test');
const executables={};
for (const name of ['chromium', 'firefox', 'webkit']) {
  const executable = playwright[name].executablePath();executables[name]=executable;
  assert.ok(path.isAbsolute(executable), 'Browser executable path must be absolute for ' + name);
  const resolved = fs.realpathSync(executable);
  const relative = path.relative(cache, resolved);
  assert.ok(relative && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative),
    'Browser executable must remain inside the image cache for ' + name);
  assert.ok(fs.statSync(resolved).isFile(), 'Browser executable must be a regular file for ' + name);
  fs.accessSync(resolved, fs.constants.X_OK);

}

stage='browser-isa';
const native=verifyBrowserCache(cache,executables,process.env.ACCESSWEAVER_EXPECT_GOARCH,record=>{const last=observations.at(-1);if(last&&last.role===record.role&&last.format==='unread')observations[observations.length-1]=record;else observations.push(record)});
console.log('Verified native browser ELF architecture '+process.env.ACCESSWEAVER_EXPECT_GOARCH+' for '+native.length+' entry points.');
// Header checks do not prove shared-library compatibility or actual browser launch.
// The unchanged real-controller suite must establish those runtime outcomes.
console.log('Verified locked Playwright ' + expectedVersion + ' and preinstalled browser executable paths.');

stage='complete';
 }catch(error){failed=true;failureKind=['AssertionError','Error','TypeError'].includes(error?.name)?error.name:'Other'}
 const value={stage,failureKind,outcome:failed?'failed':'passed',observations};
 if(process.env.GITHUB_ACTIONS==='true')writeReport(path.resolve(__dirname,'../..'),process.env.GITHUB_SHA,process.env.BROWSER,process.env.ACCESSWEAVER_EXPECT_GOARCH,value);
 console.log(JSON.stringify({stage,failureKind,outcome:value.outcome,observations}));if(failed)process.exitCode=1;
}
module.exports={sources,roles,stages,validValue,writeReport};if(require.main===module)main();
