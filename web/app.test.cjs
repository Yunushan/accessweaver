#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const sourcePath = require('node:path').join(__dirname, 'app.js');
const htmlPath = sourcePath.replace(/app\.js$/, 'index.html');
const source = fs.readFileSync(sourcePath, 'utf8').replace(/\bbindEvents\(\);\s*initialize\(\);\s*$/, '');
const localeSource = fs.readFileSync(require('node:path').join(__dirname,'locales.js'),'utf8');
const systemSource = fs.readFileSync(require('node:path').join(__dirname,'system.js'),'utf8').split('const systemNavigation')[0];
const html = fs.readFileSync(htmlPath, 'utf8');
const plain = value => JSON.parse(JSON.stringify(value));
const baseProfile = () => ({version:1,id:'test-profile',name:'Original name',description:'',category:'Custom',engine:'byedpi',binary:'',sha256:'',args:[],routing:{includeDomains:[],excludeDomains:[],applications:[]},probe:{host:'discord.com',port:443,tls:true,timeoutSeconds:5},notes:''});
function environment() {
  const nodes = new Map();
  const data = new Map();
  let failStorage = false;
  let context;
  class Element {
    constructor(id='') { this.id=id;this._value='';this.textContent='';this.innerHTML='';this.hidden=false;this.disabled=false;this.checked=false;this.dataset={};this.style={};this.className='';this.children=[];this.attributes={};this.tagName='DIV';this.classList={add(){},remove(){},toggle(){},contains(){return false}}; }
    get value() {return this._value;}
    set value(value) {this._value=String(value);}
    setAttribute(k,v) {this.attributes[k]=String(v);}
    getAttribute(k) {return this.attributes[k]??null;}
    removeAttribute(k) {delete this.attributes[k];}
    toggleAttribute(k,force) {if(force)this.setAttribute(k,'');else this.removeAttribute(k);}
    focus() {context.document.activeElement=this;}
    blur() {}
    addEventListener() {}
    removeEventListener() {}
    querySelectorAll() {return [];}
    querySelector() {return null;}
    closest() {return null;}
    contains(target) {return target===this;}
    checkValidity() {return true;}
    reportValidity() {return true;}
    appendChild(el) {this.children.push(el);return el;}
    append(...els) {this.children.push(...els);}
    remove() {}
    click() {}
    scrollIntoView() {}
  }
  const get = id => {if(!nodes.has(id))nodes.set(id,new Element(id));return nodes.get(id)};
  for(const match of html.matchAll(/<([a-z]+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
    const el=get(match[3]);el.tagName=match[1].toUpperCase();
    const value=/\bvalue="([^"]*)"/.exec(match[2]);if(value)el.value=value[1];
    el.checked=/\bchecked\b/.test(match[2]);el.hidden=/\bhidden\b/.test(match[2]);
  }
  get('profile-filter').value='all';
  context={console,URL,URLSearchParams,Blob,TextEncoder,TextDecoder,AbortController,DOMException,structuredClone,performance,Date,Intl,Math,JSON,Number,String,Boolean,Array,Object,Set,Map,Error,TypeError,Promise,
    sessionStorage:{getItem(k){return data.get('session:'+k)??null},setItem(k,v){data.set('session:'+k,String(v))}},
    localStorage:{getItem(k){return data.get(k)??null},setItem(k,v){if(failStorage)throw new Error('quota exceeded');data.set(k,String(v));},removeItem(k){if(failStorage)throw new Error('quota exceeded');data.delete(k);}},
    document:{getElementById:get,querySelectorAll:()=>[],querySelector:selector=>selector==='.app-shell'?get('app-shell'):null,createElement:()=>new Element(),addEventListener(){},documentElement:new Element(),body:new Element(),activeElement:new Element()},
    navigator:{userAgent:'test',clipboard:{writeText:async()=>{}}},location:{hash:'',origin:'http://localhost'},history:{replaceState(){},pushState(){}},
    window:{scrollTo(){},addEventListener(){},matchMedia(){return {matches:false,addEventListener(){}}}},
    fetch:async()=>{throw new Error('Unexpected network call in isolated test');},
    confirm:()=>false,setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},requestAnimationFrame:cb=>cb(),cancelAnimationFrame(){},
  };
  context.window.document=context.document;context.window.location=context.location;
  vm.createContext(context);vm.runInContext(localeSource,context);vm.runInContext(source,context,{filename:sourcePath});
  vm.runInContext('state.engines = exampleEngines; state.offline = true; renderAll = () => {}; toast = () => {};',context);
  return {context,get,data,setStorageFailure(v){failStorage=v},run(code){return vm.runInContext(code,context)},put(name,value){context[name]=plain(value)}};
}
const test = require('node:test');
test('connected UI displays the core build version without interpreting HTML',async()=>{
  const env=environment();
  env.run('state.token="fixture"');
  const versionNodes=[env.get('sidebar-version'),env.get('footer-version')];
  env.context.document.querySelectorAll=selector=>selector==='[data-app-version]'?versionNodes:[];
  env.context.fetch=async path=>({ok:true,json:async()=>path==='/api/bootstrap'?{token:'fixture',platform:'windows',version:'2.3.4-rc.1 <source>'}:path==='/api/v1/runtime'?{state:'stopped'}:[]});
  await env.run('readCore()');
  for(const node of versionNodes){assert.equal(node.textContent,'2.3.4-rc.1 <source>');assert.equal(node.innerHTML,'');}
});
function valid(env,profile=baseProfile()) {env.put('fixture',profile);return env.run('validateProfile(fixture)');}
test('private launcher session is consumed without retaining it in the address',()=>{
  const env=environment(),credential='s'.repeat(43);let cleanAddress;
  env.context.location.hash='#accessweaver-session='+credential;
  env.context.history.replaceState=(_state,_title,address)=>{cleanAddress=address};
  env.run('readSession()');
  assert.equal(env.run('state.token'),credential);assert.equal(cleanAddress,'/#dashboard');
  assert.equal(env.data.get('session:aw.session'),credential);assert.equal(env.data.get('aw.session'),undefined);
});
test('browser cannot obtain a session credential from public bootstrap',async()=>{
  const env=environment();let called=false;env.context.fetch=async()=>{called=true;throw new Error('unexpected')};
  await assert.rejects(env.run('readCore()'));assert.equal(called,false);
});
function rejectsProfile(profile) {const env=environment();assert.throws(()=>valid(env,profile));}
test('valid version-1 profile is accepted',()=>{valid(environment());});
test('unknown top-level fields are rejected',()=>{rejectsProfile({...baseProfile(),surprise:true});});
test('unsupported schema version is rejected',()=>{rejectsProfile({...baseProfile(),version:2});});
test('invalid ID is rejected',()=>{rejectsProfile({...baseProfile(),id:'../escape'});});
test('non-string arguments are rejected',()=>{rejectsProfile({...baseProfile(),args:[42]});});
test('invalid SHA-256 is rejected',()=>{rejectsProfile({...baseProfile(),sha256:'bad'});});
test('invalid probe timeout is rejected',()=>{const p=baseProfile();p.probe.timeoutSeconds=61;rejectsProfile(p);});
test('case-insensitive duplicate domains are rejected',()=>{const p=baseProfile();p.engine='zapret2';p.routing.includeDomains=['discord.com','Discord.com'];rejectsProfile(p);});
test('include/exclude conflict is rejected',()=>{const p=baseProfile();p.engine='zapret2';p.routing.includeDomains=['discord.com'];p.routing.excludeDomains=['DISCORD.COM'];rejectsProfile(p);});
test('URLs cannot be entered as domains',()=>{const p=baseProfile();p.engine='zapret2';p.routing.includeDomains=['https://discord.com'];rejectsProfile(p);});
test('offline save persists a new profile exactly once',async()=>{const env=environment();env.put('fixture',baseProfile());await env.run('persist(fixture)');assert.equal(env.run('state.profiles.length'),1);assert.deepEqual(JSON.parse(env.data.get('aw.profiles')),plain(env.run('state.profiles')));});
test('offline storage failure rejects without changing in-memory profiles',async()=>{const env=environment();const original=baseProfile();env.put('fixture',original);env.run('state.profiles = [fixture]');env.data.set('aw.profiles',JSON.stringify([original]));env.setStorageFailure(true);env.put('replacement',{...original,name:'Changed'});await assert.rejects(env.run('persist(replacement)'));assert.deepEqual(plain(env.run('state.profiles')),[original]);assert.deepEqual(JSON.parse(env.data.get('aw.profiles')),[original]);});
test('new-profile save cannot overwrite an existing ID',async()=>{const env=environment();const original=baseProfile();env.put('fixture',original);env.run('state.profiles = [fixture]; showEditor({...fixture,name:"Collision"}, true); switchEditor("advanced");');await env.run('saveEditor()');assert.deepEqual(plain(env.run('state.profiles')),[original]);assert.equal(env.run('state.editing !== null'),true);});
test('JSON to guided transfer preserves timeout',()=>{const env=environment();env.put('fixture',baseProfile());env.run('showEditor(fixture); switchEditor("advanced"); const edited = JSON.parse($("p-json").value); edited.probe.timeoutSeconds=42; $("p-json").value=JSON.stringify(edited); switchEditor("simple");');assert.equal(env.run('fromSimple().probe.timeoutSeconds'),42);});
test('JSON to guided transfer preserves spaced and empty arguments',()=>{const env=environment();const p=baseProfile();p.args=[' value ',''];env.put('fixture',p);env.run('showEditor(fixture); switchEditor("advanced"); switchEditor("simple");');const result=env.run('state.editorTab === "advanced" ? JSON.parse($("p-json").value).args : fromSimple().args');assert.deepEqual(plain(result),p.args);});
test('failed editor persistence keeps unsaved changes available',async()=>{const env=environment();env.put('fixture',baseProfile());env.run('showEditor(fixture, true)');env.setStorageFailure(true);await env.run('saveEditor()');assert.equal(env.run('state.editing !== null'),true);assert.equal(env.run('state.profiles.length'),0);});
test('a stale connected save preserves the draft and its original revision',async()=>{const env=environment();env.put('fixture',{...baseProfile(),updatedAt:'2026-11-01T10:00:00.123456789Z'});env.run('state.offline=false;state.loading=false;state.profiles=[fixture];showEditor(fixture);$("p-name").value="Unsaved work";markDirty();apiRequest=async(path,method,payload)=>{globalThis.saveAttempt=payload;throw new Error("profile changed; reload before retrying")}');await env.run('saveEditor()');assert.equal(env.context.saveAttempt.updatedAt,'2026-11-01T10:00:00.123456789Z');assert.equal(env.run('state.editing.dirty'),true);assert.equal(env.get('p-name').value,'Unsaved work');assert.equal(env.run('state.profiles[0].name'),'Original name');assert.match(env.get('editor-feedback').textContent,/profile changed/);});
test('a stale connected deletion sends its reviewed revision and preserves the cached profile',async()=>{const env=environment();env.put('fixture',{...baseProfile(),updatedAt:'2026-11-01T10:00:00.123456789Z'});env.run('state.offline=false;state.loading=false;state.profiles=[fixture];confirm=()=>true;apiRequest=async(path,method,payload)=>{globalThis.deleteAttempt={method,payload};throw new Error("profile changed")}');await env.run('handleProfileAction("delete",fixture.id)');assert.deepEqual(plain(env.context.deleteAttempt),{method:'DELETE',payload:{expectedUpdatedAt:'2026-11-01T10:00:00.123456789Z'}});assert.equal(env.run('state.profiles.length'),1);assert.equal(env.run('state.busy'),false);});
test('null profile arrays remain editable and renderable',()=>{const env=environment();const p=baseProfile();p.args=null;p.routing={includeDomains:null,excludeDomains:null,applications:null};valid(env,p);env.put('fixture',p);env.run('showEditor(fixture); fromSimple(); profileCard(fixture,true);');});
test('unknown nested routing fields are rejected',()=>{const p=baseProfile();p.routing.unknown=true;rejectsProfile(p);});
test('unknown nested probe fields are rejected',()=>{const p=baseProfile();p.probe.unknown=true;rejectsProfile(p);});
test('import collision opens renamed draft without replacing stored profile',async()=>{const env=environment();const original=baseProfile();env.put('fixture',original);env.run('state.profiles = [fixture]');const imported={...original,name:'Imported'};env.context.fileFixture={size:100,text:async()=>JSON.stringify(imported)};await env.run('importProfile(fileFixture)');assert.deepEqual(plain(env.run('state.profiles')),[original]);assert.notEqual(env.run('state.editing.profile.id'),original.id);assert.equal(env.run('state.editing.isNew'),true);assert.equal(env.data.has('aw.profiles'),false);});
test('disconnected core blocks writes without changing cached profiles',async()=>{const env=environment();env.put('fixture',baseProfile());env.run('state.disconnected=true');await assert.rejects(env.run('persist(fixture)'));assert.equal(env.run('state.profiles.length'),0);});
test('failed poll marks connection unknown without falsely stopping cached process',async()=>{const env=environment();env.run('state.loading=false;state.offline=false;state.runtime={state:"running",profileId:"test-profile",pid:123};apiRequest=async()=>{throw new Error("network down")};');await env.run('pollStatus()');assert.equal(env.run('state.disconnected'),true);assert.equal(env.run('state.runtime.state'),'running');assert.equal(env.run('coreAvailable()'),false);});
test('process exit refreshes profile actions',async()=>{const env=environment();env.context.profileRenderCalls=0;env.run('state.loading=false;state.offline=false;state.runtime={state:"running",profileId:"test-profile",pid:123};renderProfiles=()=>{profileRenderCalls++};apiRequest=async()=>({state:"exited",profileId:"test-profile"});');await env.run('pollStatus()');assert.equal(env.context.profileRenderCalls,1);});
test('all HTML translation keys exist in both languages',()=>{const env=environment();const keys=[...html.matchAll(/data-i18n(?:-aria)?="([^"]+)"/g)].map(m=>m[1]);env.context.translationKeys=keys;assert.deepEqual(plain(env.run('translationKeys.filter(key=>!en[key]||!tr[key])')),[]);});
test('Russian and Spanish cover every UI translation key',()=>{const env=environment();assert.deepEqual(plain(env.run('Object.keys(en).filter(key=>!extraLocales.ru[key]||!extraLocales.es[key])')),[]);});
test('all four languages can be selected and persisted',()=>{const env=environment();for(const lang of ['en','tr','ru','es']){env.context.languageFixture=lang;env.run('changeLanguage(languageFixture)');assert.equal(env.run('state.lang'),lang);assert.equal(env.data.get('aw.lang'),lang);}});
test('system operation consent is invalidated by input changes',()=>{const env=environment();env.run(systemSource);env.run('systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true;invalidateSystemPlan()');assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-apply').disabled,true);assert.equal(env.get('system-consent').checked,false);});

test('switching operations excludes hidden stale system fields',()=>{const env=environment();env.run(systemSource);env.get('system-action').value='dns-restore';env.get('system-engine').value='byedpi';env.get('system-args').value='stale argument';env.get('system-config').value='C:\\stale.conf';env.get('system-cloudflare-terms').checked=true;assert.deepEqual(plain(env.run('systemRequest()')),{action:'dns-restore'});});
test('system operations expose only compatible component choices',()=>{const env=environment();env.run(systemSource);assert.deepEqual(plain(env.run('systemEnginesFor("scan")')),['zapret','zapret2']);assert.deepEqual(plain(env.run('systemEnginesFor("app-install")')),['discord','discord-ptb','splitcord']);assert.equal(env.run('systemEnginesFor("install").includes("discord")'),false);});
test('user application operations exclude stale machine DNS and bundle inputs',()=>{const env=environment();env.run(systemSource);env.get('system-engine').value='discord';env.get('system-dns').value='doh';env.get('system-bundle').value='C:\\machine-components';for(const action of ['app-install','app-remove','app-start']){env.get('system-action').value=action;const request=plain(env.run('systemRequest()'));assert.equal(request.dns,undefined);assert.equal(request.bundlePath,undefined);}});
test('every system operation label has all four languages',()=>{const env=environment();const labels=plain(env.run('systemOperationText'));assert.equal(Object.keys(labels).length,22);for(const row of Object.values(labels))for(const lang of ['en','tr','ru','es'])assert.ok(row[lang]);});
test('new-release notification is shown once for a completed update check',()=>{const env=environment();env.run(systemSource);env.run('toast=message=>{globalThis.updateNotice=message;globalThis.noticeCount=(globalThis.noticeCount||0)+1};const updateFixture={id:"update-1",action:"updates",state:"succeeded",result:{data:{version:"v1.0.0",updateAvailable:true}}};notifySystemUpdate(updateFixture);notifySystemUpdate(updateFixture)');assert.equal(env.context.noticeCount,1);assert.match(env.context.updateNotice,/v1\.0\.0/);});
test('a late system preview cannot restore a plan invalidated during the request',async()=>{const env=environment();env.run(systemSource);env.run('state.offline=false;state.loading=false;apiRequest=()=>new Promise(resolve=>{globalThis.resolvePlan=resolve})');const pending=env.run('previewSystem({action:"discover"})');env.run('invalidateSystemPlan()');env.context.resolvePlan({id:'stale',ready:true});await pending;assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-consent').disabled,true);assert.equal(env.get('system-export').disabled,true);});
test('applying a system operation submits only the reviewed plan ID',async()=>{const env=environment();env.run(systemSource);env.run('systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true;apiRequest=async(path,method,payload)=>{globalThis.submittedSystem=payload;return {id:"reviewed",state:"succeeded"}};pollSystemJob=()=>{}');await env.run('applySystem()');assert.deepEqual(plain(env.context.submittedSystem),{planId:'reviewed',confirm:true});assert.equal(env.run('systemUI.plan'),null);});

test('invalid browser entries survive unrelated offline saves',async()=>{const env=environment();env.put('fixture',baseProfile());env.put('invalid',{id:'broken-profile',custom:'keep this data'});env.run('state.preservedProfiles=[invalid]');await env.run('persist(fixture)');assert.deepEqual(JSON.parse(env.data.get('aw.profiles')),[baseProfile(),{id:'broken-profile',custom:'keep this data'}]);});
test('unreadable browser storage cannot be replaced by a new save',async()=>{const env=environment();env.put('fixture',baseProfile());env.data.set('aw.profiles','broken JSON');env.run('state.storageBlocked=true');await assert.rejects(env.run('persist(fixture)'));assert.equal(env.data.get('aw.profiles'),'broken JSON');assert.equal(env.run('state.profiles.length'),0);});
test('exporting while another action runs cannot release its busy state',async()=>{const env=environment();env.put('fixture',baseProfile());env.run('state.profiles=[fixture];state.busy=true;downloadFile=()=>{}');await env.run('handleProfileAction("export",fixture.id)');assert.equal(env.run('state.busy'),true);});
test('IPv6 probe hosts are accepted and hostlist prefixes are rejected',()=>{const p=baseProfile();p.probe.host='2001:db8::1';valid(environment(),p);p.probe.host='^discord.com';rejectsProfile(p);p.probe.host='1:::2';rejectsProfile(p);});
test('launch submits the exact revision reviewed by the user',async()=>{const env=environment();env.put('fixture',{...baseProfile(),updatedAt:'2026-10-31T12:00:00.123456789Z'});env.run('state.offline=false;state.loading=false;state.launch={profile:fixture,ready:true};apiRequest=async(path,method,payload)=>{globalThis.launchRequest=payload;return {state:"running",profileId:fixture.id}}');await env.run('confirmLaunch()');assert.equal(env.context.launchRequest.expectedUpdatedAt,'2026-10-31T12:00:00.123456789Z');assert.equal(env.context.launchRequest.confirm,true);});
test('launch review refreshes a profile before checking its plan',async()=>{const env=environment();env.put('fixture',baseProfile());env.put('fresh',{...baseProfile(),updatedAt:'2026-10-31T12:00:00Z',args:['latest']});env.run('state.offline=false;state.loading=false;apiRequest=async(path,method,payload)=>{if(path.startsWith("/api/v1/profiles/"))return fresh;globalThis.previewed=payload;return {ready:true,args:[],warnings:[],issues:[]}}');await env.run('reviewLaunch(fixture)');assert.deepEqual(plain(env.context.previewed.args),['latest']);assert.equal(env.run('state.launch.profile.updatedAt'),'2026-10-31T12:00:00Z');});

test('machine requests can be exported without exporting a plan credential or applying them',async()=>{
  const env=environment();env.run(systemSource);
  env.put('reviewed',{id:'private-plan-id',ready:false,requiresAdministrator:true,request:{action:'dns',dns:'doh'},issues:['administrator CLI required'],steps:[],warnings:[]});
  let download;
  env.context.downloadFile=(data,name)=>{download={data,name}};
  env.run('systemUI.plan=reviewed;exportSystemRequest()');
  assert.deepEqual(JSON.parse(download.data),{action:'dns',dns:'doh'});
  assert.equal(download.name,'accessweaver-dns-request.json');
  assert.equal(download.data.includes('private-plan-id'),false);
  assert.equal(env.run('systemUI.plan.id'),'private-plan-id');
  env.run('invalidateSystemPlan()');
  assert.equal(env.get('system-export').disabled,true);
  download=null;env.run('exportSystemRequest()');assert.equal(download,null);
});

test('a blocked machine preview enables only request export',async()=>{
  const env=environment();env.run(systemSource);
  env.run('state.offline=false;state.loading=false;state.disconnected=false');
  env.put('reviewed',{id:'private-plan-id',ready:false,requiresAdministrator:true,request:{action:'dns',dns:'doh'},issues:['administrator CLI required'],steps:[],warnings:[]});
  env.run('apiRequest=async()=>reviewed');
  await env.run('previewSystem({action:"dns",dns:"doh"})');
  assert.equal(env.get('system-export').disabled,false);
  assert.equal(env.get('system-consent').disabled,true);
  assert.equal(env.get('system-apply').disabled,true);
  env.run('invalidateSystemPlan()');assert.equal(env.get('system-export').disabled,true);
});

test('support export uses the authenticated core summary without changing another busy action',async()=>{
  const env=environment();env.run('state.offline=false;state.loading=false;state.disconnected=false;state.busy=true;state.coreAuthenticated=true;state.token="fixture"');
  const report={schemaVersion:1,scope:'metadata-only',profiles:{total:2},runtime:{state:'stopped'}};
  env.put('supportFixture',report);env.run('apiRequest=async(path)=>{if(path!=="/api/v1/support")throw new Error("wrong summary route");return supportFixture}');
  let download;env.context.downloadFile=(data,name)=>{download={data,name}};
  await env.run('exportSupportSummary()');
  assert.deepEqual(JSON.parse(download.data),report);assert.equal(download.name,'accessweaver-support-summary.json');
  assert.equal(env.run('state.busy'),true);assert.equal(env.get('export-support').disabled,false);
});

test('failed or offline support export never downloads a partial report',async()=>{
  const env=environment();let downloads=0;env.context.downloadFile=()=>downloads++;
  env.run('apiRequest=async()=>{throw new Error("fixture core unavailable")}');
  await env.run('exportSupportSummary()');assert.equal(downloads,0);
  env.run('state.offline=false;state.loading=false;state.disconnected=false;state.coreAuthenticated=true;state.token="fixture"');
  await env.run('exportSupportSummary()');assert.equal(downloads,0);assert.equal(env.run('state.supportExporting'),false);
});

test('support metadata stays accessible when authenticated profile loading fails',async()=>{
  const env=environment();env.run('state.token="fixture"');
  env.context.fetch=async path=>path==='/api/bootstrap'?{ok:true,json:async()=>({platform:'windows'})}:{ok:false,status:500,json:async()=>({error:'private store failure'})};
  await assert.rejects(env.run('readCore()'));
  env.run('state.loading=false;state.offline=true');
  assert.equal(env.run('supportAvailable()'),true);assert.equal(env.run('coreAvailable()'),false);
});
