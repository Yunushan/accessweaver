#!/usr/bin/env node
'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const vm=require('node:vm');
const {EventEmitter}=require('node:events');

// Register the real Playwright core fixture without registering/running browser
// cases. Process creation is inert; allocation and cleanup use the real isolated
// filesystem, with one cache-creation failure injected below.
async function coreFixture(t,spawn,filesystem={}){
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'accessweaver-browser-start-'));
 t.after(async()=>{
  const info=await fs.lstat(root),resolved=await fs.realpath(root),parent=await fs.realpath(os.tmpdir());
  assert.ok(info.isDirectory()&&!info.isSymbolicLink());assert.equal(path.dirname(resolved),parent);assert.ok(path.basename(resolved).startsWith('accessweaver-browser-start-'));
  await fs.rm(resolved,{recursive:true,force:true});
 });
 let fixture;
 const sandbox={__dirname:path.join(root,'scripts/browser-tests'),process:{env:{},platform:process.platform,arch:process.arch,version:process.version},setTimeout,clearTimeout,
  require(name){
   if(name==='@playwright/test')return {test:{extend(definition){fixture=definition.core;return ()=>{}}}};
   if(name==='./accessibility.cjs')return {};
   if(['./desktop-performance.cjs','./svg-geometry.cjs','../../internal/profile/testdata/timestamps.json','node:perf_hooks'].includes(name))return require(name);
   if(name==='node:child_process')return {spawn,execFileSync(){throw new Error('version execution must not occur after failed spawn')}};
   if(name==='node:fs/promises')return {...fs,...filesystem};
   if(['node:fs/promises','node:path','node:events','node:crypto'].includes(name))return require(name);
   throw new Error('Unexpected fixture dependency: '+name);
  }};
 vm.runInNewContext(await fs.readFile(path.join(__dirname,'desktop.spec.cjs'),'utf8'),sandbox,{filename:'desktop.spec.cjs'});
 assert.equal(typeof fixture,'function');return {fixture,parent:path.join(root,'build/browser-state')};
}

for(const mode of ['synchronous','asynchronous'])test('failed '+mode+' process startup removes the owned browser fixture',async t=>{
 const failure=new Error('synthetic process start denied');let attempts=0,used=false;
 const {fixture,parent}=await coreFixture(t,()=>{
  attempts++;
  if(mode==='synchronous')throw failure;
  const child=new EventEmitter();Object.assign(child,{exitCode:null,signalCode:null,stdout:new EventEmitter(),stderr:new EventEmitter(),kill(){throw new Error('unstarted child must not be killed')}});
  queueMicrotask(()=>child.emit('error',failure));return child;
 });
 await assert.rejects(fixture({browser:{}},async()=>{used=true},{}),error=>error===failure);
 assert.equal(attempts,1);assert.equal(used,false);assert.deepEqual(await fs.readdir(parent),[],'failed startup retained a private fixture directory');
});


test('cache initialization failure removes the already allocated private fixture',async t=>{
 const failure=new Error('synthetic cache initialization failed');let attempts=0;
 const {fixture,parent}=await coreFixture(t,()=>{attempts++;throw new Error('process must not be started')},{async mkdir(directory,options){if(path.basename(directory)==='cache')throw failure;return fs.mkdir(directory,options)}});
 await assert.rejects(fixture({browser:{}},async()=>{throw new Error('fixture must not be used')},{}),error=>error===failure);
 assert.equal(attempts,0);assert.deepEqual(await fs.readdir(parent),[]);
});
