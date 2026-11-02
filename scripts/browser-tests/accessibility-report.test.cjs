#!/usr/bin/env node
'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {summarize}=require('./accessibility-report.cjs');
function rule(any=[],all=[],none=[]){return {id:'color-contrast',impact:'serious',nodes:[{
 target:['#fixture'],any,all,none,
 html:'PRIVATE_DOM_CONTENT',failureSummary:'PRIVATE_TEXT',
}]};}
test('incomplete contrast evidence retains fixed reasons and all check IDs',()=>{
 const result=summarize([rule(
  [{id:'color-contrast',data:{messageKey:'bgGradient'}}],
  [{id:'color-contrast',data:{messageKey:'bgOverlap'}}],
  [{id:'another-check',data:{messageKey:'PRIVATE_REASON'}}],
 )],true);
 assert.deepEqual(result,[{id:'color-contrast',impact:'serious',nodes:[{
  target:['#fixture'],checks:['color-contrast','color-contrast','another-check'],
  reviewReasons:[{check:'color-contrast',reason:'bgGradient'},{check:'color-contrast',reason:'bgOverlap'}],
 }]}]);
});
test('unknown, missing and malformed contrast reasons remain visibly unclassified',()=>{
 for(const data of [undefined,null,{}, {messageKey:'PRIVATE_REASON'}, {messageKey:['bgGradient']}, {messageKey:{toString(){throw new Error('must not coerce reason')}}}]){
  const result=summarize([rule([{id:'color-contrast',data}])],true);
  assert.deepEqual(result[0].nodes[0].reviewReasons,[{check:'color-contrast',reason:'unclassified'}]);
 }
});
test('review evidence omits private messages, arbitrary data and related nodes',()=>{
 const input=rule([{id:'color-contrast',message:'PRIVATE_MESSAGE',data:{messageKey:'bgImage',colorParse:'PRIVATE_COLOR',image:'https://PRIVATE_URL',text:'PRIVATE_DATA'},relatedNodes:[{html:'PRIVATE_RELATED'}]}]);
 const before=JSON.stringify(input);
 const result=summarize([input],true);
 assert.equal(JSON.stringify(input),before,'source report changed');
 assert.equal(JSON.stringify(result).includes('PRIVATE_'),false);
 assert.deepEqual(result[0].nodes[0].reviewReasons,[{check:'color-contrast',reason:'bgImage'}]);
});
test('violation summaries preserve the existing compact contract',()=>{
 assert.deepEqual(summarize([rule([{id:'color-contrast',data:{messageKey:'bgGradient'}}])]),[
  {id:'color-contrast',impact:'serious',nodes:[{target:['#fixture'],checks:['color-contrast']}]},
 ]);
 assert.deepEqual(summarize([],true),[]);
});
