#!/usr/bin/env node
'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const {architecture,validateEnvironment,validateBuild}=require('./check-native-environment.cjs');
const commit='a'.repeat(40);
function fixture(goos,goarch){
 const expected={goos,goarch,goVersion:'1.27.3',commit,hosted:true};
 const actual={platform:{windows:'win32',linux:'linux',darwin:'darwin'}[goos],machine:goarch==='amd64'?'x86_64':'aarch64',runnerArch:goarch==='amd64'?'X64':'ARM64',runnerEnvironment:'github-hosted',go:{GOOS:goos,GOARCH:goarch,GOHOSTOS:goos,GOHOSTARCH:goarch,GOVERSION:'go1.27.3',GOTOOLCHAIN:'local'}};
 const build={platform:goos,arch:goarch,goVersion:'go1.27.3',commit,sourceState:'clean'};return {expected,actual,build};
}
test('all six native platform/architecture combinations require the intended host, SDK and executed CLI',()=>{
 for(const goos of ['windows','linux','darwin'])for(const goarch of ['amd64','arm64']){const {expected,actual,build}=fixture(goos,goarch);validateEnvironment(actual,expected);validateBuild(build,expected);}
});
test('cross SDK, cross target, wrong host and wrong version cannot count as native execution',()=>{
 for(const mutate of [a=>{a.platform='win32'},a=>{a.machine='x86_64'},a=>{a.runnerArch='X64'},a=>{a.go.GOHOSTARCH='amd64'},a=>{a.go.GOARCH='amd64'},a=>{a.go.GOHOSTOS='windows'},a=>{a.go.GOOS='windows'},a=>{a.go.GOVERSION='go1.27.2'},a=>{a.go.GOTOOLCHAIN='auto'},a=>{a.runnerEnvironment='self-hosted'}]){
  const {expected,actual}=fixture('linux','arm64');mutate(actual);assert.throws(()=>validateEnvironment(actual,expected));
 }
});
test('unrecognized native target and absent hosted source expectations fail closed',()=>{
 for(const mutate of [e=>{e.goos='freebsd'},e=>{e.goarch='386'},e=>{e.goVersion='latest'},e=>{e.commit=''},e=>{e.commit='bad'}]){const {expected,actual}=fixture('linux','arm64');mutate(expected);assert.throws(()=>validateEnvironment(actual,expected));}
 for(const alias of ['ARM64','aarch64','arm64'])assert.equal(architecture(alias),'arm64');
 for(const alias of ['x64','x86_64','amd64','X64'])assert.equal(architecture(alias),'amd64');
 assert.throws(()=>architecture('unknown'));
});
test('stale, dirty, differently compiled or emulated-target CLIs do not pass the intended native identity',()=>{
 for(const mutate of [b=>{b.commit='b'.repeat(40)},b=>{b.sourceState='modified'},b=>{b.arch='amd64'},b=>{b.platform='windows'},b=>{b.goVersion='go1.26.0'}]){const {expected,build}=fixture('linux','arm64');mutate(build);assert.throws(()=>validateBuild(build,expected));}
});
