'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {project,target}=require('./windows-tree-fixed-report.cjs');
const event=(Action,extra={})=>JSON.stringify({Action,Test:target,...extra});
test('projects repeated successful source test runs',()=>{
 const s=[event('run'),event('pass'),event('run'),event('pass')].join('\n');
 const r=project(s,0,2);assert.equal(r.outcome,'passed');assert.equal(r.attempts,2);assert.equal(r.failed,0);
});
test('retains only a fixed stage for an actual failure',()=>{
 const s=[event('run'),event('output',{Output:'private path ACCESSWEAVER_TREE_STAGE=tree-cancel\n'}),event('fail')].join('\n');
 const r=project(s,1,1);assert.equal(r.outcome,'failed');assert.equal(r.stages['tree-cancel'],1);assert(!JSON.stringify(r).includes('private path'));
});
test('refuses missing, private, duplicate and inconsistent failure stages',()=>{
 for(const lines of [
  [event('run'),event('fail')],
  [event('run'),event('output',{Output:'ACCESSWEAVER_TREE_STAGE=private-data'}),event('fail')],
  [event('run'),event('output',{Output:'ACCESSWEAVER_TREE_STAGE=tree-cancel ACCESSWEAVER_TREE_STAGE=tree-empty'}),event('fail')],
  [event('run'),event('output',{Output:'ACCESSWEAVER_TREE_STAGE=tree-cancel'}),event('pass')],
 ])assert.equal(project(lines.join('\n'),1,1).outcome,'refused');
 assert.equal(project([event('run'),event('pass')].join('\n'),1,1).outcome,'refused');
 assert.equal(project('x'.repeat(4*1024*1024+1),0,1).code,'bound');
});
