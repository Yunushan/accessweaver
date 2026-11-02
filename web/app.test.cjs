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


test('diagnostic modes require an explicit STUN target and isolate proxy fields',()=>{
 const env=environment();env.get('probe-path').value='socks5';env.get('probe-transport').value='stun';env.get('probe-proxy').value='127.0.0.1:1080';
 env.run('updateProbeMode(true)');
 assert.equal(env.get('probe-host').value,'');assert.equal(env.get('probe-port').value,'3478');assert.equal(env.get('probe-tls').disabled,true);assert.equal(env.get('probe-tls').checked,false);
 assert.equal(env.get('probe-proxy-field').hidden,false);assert.equal(env.get('probe-proxy').required,true);assert.equal(env.get('probe-http-option').disabled,true);
 env.get('probe-host').value='stun.example.com';assert.deepEqual(plain(env.run('probeRequest()')),{host:'stun.example.com',port:3478,timeoutSeconds:5,tls:false,path:'socks5',transport:'stun',proxy:'127.0.0.1:1080'});
 env.get('probe-path').value='direct';env.run('updateProbeMode()');assert.equal(env.get('probe-proxy').disabled,true);assert.equal('proxy' in env.run('probeRequest()'),false);
 env.get('probe-transport').value='tcp';env.run('updateProbeMode(true)');assert.equal(env.get('probe-host').value,'discord.com');assert.equal(env.get('probe-tls').checked,true);
});
test('diagnostic report identifies and escapes the tested path and endpoint',()=>{
 const env=environment();env.put('report',{host:'example.com',port:443,path:'socks5',transport:'tcp',proxy:'<img src=x onerror=alert(1)>',checks:[{name:'Proxy',status:'failed',detail:'refused'}],at:new Date().toISOString()});env.run('renderProbe(report)');
 assert.match(env.get('diagnostic-meta').innerHTML,/socks5 \/ tcp/);assert.match(env.get('diagnostic-meta').innerHTML,/&lt;img/);assert.doesNotMatch(env.get('diagnostic-meta').innerHTML,/<img/);assert.match(env.get('diagnostic-meta').innerHTML,/One or more checks failed/);
});

test('a rejected diagnostic clears the previous report and export instead of showing stale success',async()=>{
 const env=environment();env.run('state.offline=false;state.loading=false;state.token="fixture";state.lastProbe={checks:[{status:"ok"}]}');
 env.get('probe-path').value='direct';env.get('probe-transport').value='tcp';env.context.fetch=async()=>({ok:false,status:403,json:async()=>({error:'policy denied'})});
 await env.run('runProbe()');assert.equal(env.run('state.lastProbe'),null);assert.equal(env.get('export-report').hidden,true);assert.equal(env.get('diagnostic-meta').hidden,true);assert.match(env.get('diagnostic-results').textContent,/Test failed: policy denied/);
});


test('ordinary JSON previews preserve formatting, values and source data',()=>{
 const env=environment(),fixture=JSON.parse('{"__proto__":{"safe":true},"array":[null,true,2,"<script>\\n界"],"empty":{}}');
 const original=JSON.stringify(fixture);env.context.previewFixture=fixture;
 const preview=env.run('formatJSONPreview(previewFixture)');assert.equal(preview.text,JSON.stringify(fixture,null,2));assert.equal(preview.limited,false);assert.equal(JSON.stringify(fixture),original);
});

test('deep and cyclic JSON previews stay bounded without recursive stringify',()=>{
 const env=environment();let deep=0;for(let i=0;i<6000;i++)deep=[deep];env.context.previewFixture=deep;
 const preview=env.run('formatJSONPreview(previewFixture)');assert.equal(preview.limited,true);assert.ok(preview.text.length<128*1024);assert.match(preview.text,/…/);
 let remaining=deep;for(let i=0;i<6000;i++)remaining=remaining[0];assert.equal(remaining,0);
 const cycle={};cycle.self=cycle;env.context.previewFixture=cycle;assert.equal(env.run('formatJSONPreview(previewFixture).limited'),true);assert.equal(cycle.self,cycle);
});

test('wide, long-key and escaped-text previews enforce their display budget',()=>{
 const env=environment();
 for(const fixture of [Array.from({length:100000},(_,i)=>i),{['k'.repeat(200000)]:'value'},Array(10000).fill('\u0001'.repeat(4096)),{unicode:'😀'.repeat(10000)}]){
  env.context.previewFixture=fixture;const result=env.run('formatJSONPreview(previewFixture)');assert.equal(result.limited,true);assert.ok(result.text.length<=128*1024);assert.ok(result.text.isWellFormed());
 }
});

test('string preview caps include their omission marker without splitting Unicode',()=>{
 const env=environment();env.context.previewFixture={text:'😀'.repeat(10000)};
 const result=env.run('formatJSONPreview(previewFixture)');const rendered=JSON.parse(result.text);assert.ok(rendered.text.length<=4096);assert.ok(rendered.text.isWellFormed());assert.equal(result.limited,true);
});

test('shortened system output is labelled and ordinary output clears its notice',()=>{
 const env=environment();env.run('showSystemOutput({message:"x".repeat(10000)})');
 assert.equal(env.get('system-output-limited').hidden,false);assert.equal(env.get('system-output').getAttribute('aria-describedby'),'system-output-limited');assert.equal(env.get('system-output').innerHTML,'');
 env.run('showSystemOutput({ok:true})');assert.equal(env.get('system-output-limited').hidden,true);assert.equal(env.get('system-output').getAttribute('aria-describedby'),null);
 env.run('showSystemOutput({message:"x".repeat(10000)});setTextOutput("system-output","failed")');assert.equal(env.get('system-output-limited').hidden,true);
});

function onlineSystemExport(){const env=environment();env.run(systemSource);env.run('state.offline=false;state.loading=false;state.disconnected=false;state.coreAuthenticated=true;state.token="export-fixture";state.busy=true');return env;}

test('system exports preserve raw response bytes and send credentials only to fixed local routes',async()=>{
 const env=onlineSystemExport(),bytes='[ { "escaped": "\\u2028", "private": "FULL_EXPORT_FIXTURE" } ]\n';let downloaded,options,route;
 env.context.fetch=async(path,input)=>{route=path;options=input;const response=new Response(bytes,{headers:{'Content-Type':'application/json; charset=utf-8'}});response.json=()=>{throw new Error('export parsed JSON')};return response;};
 env.context.downloadFile=(data,name)=>{downloaded={data,name}};
 await env.run('exportSystemReport("history")');assert.equal(route,'/api/v1/system/history');assert.equal(options.headers['X-AccessWeaver-Token'],'export-fixture');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');assert.equal(options.credentials,'same-origin');assert.equal(options.signal.aborted,true);
 assert.equal(downloaded.name,'accessweaver-workflow-history.json');assert.equal(await downloaded.data.text(),bytes);assert.equal(env.run('state.busy'),true);assert.equal(env.run('systemUI.exporting'),false);
 await env.run('exportSystemReport("status")');assert.equal(route,'/api/v1/system');assert.equal(downloaded.name,'accessweaver-system-status.json');
});

test('offline, unrecognized, HTTP and non-JSON exports never download a report',async()=>{
 const env=onlineSystemExport();let calls=0,downloads=0,lastSignal;
 env.context.downloadFile=()=>downloads++;env.context.fetch=async(path,input)=>{calls++;lastSignal=input.signal;return new Response('private failure',{status:500,headers:{'Content-Type':'application/json'}})};
 for(const kind of ['__proto__','https://untrusted.example/'])await assert.rejects(env.run('exportSystemReport('+JSON.stringify(kind)+')'));
 assert.equal(calls,0);env.run('state.offline=true;state.coreAuthenticated=false');await env.run('exportSystemReport("history")');assert.equal(calls,0);
 env.run('state.offline=false;state.coreAuthenticated=true');await env.run('exportSystemReport("history")');assert.equal(lastSignal.aborted,true);
 env.context.fetch=async(path,input)=>{lastSignal=input.signal;return new Response('<html>private failure</html>',{headers:{'Content-Type':'text/html'}})};
 await env.run('exportSystemReport("status")');assert.equal(lastSignal.aborted,true);assert.equal(downloads,0);assert.equal(env.run('systemUI.exporting'),false);
});

test('streamed report limits are exact and cancel oversized or failed bodies',async()=>{
 const env=environment();env.run(systemSource);
 for(const total of [16,17]){
  let reads=0,cancelled=false,released=false;
  env.context.streamResponse={body:{getReader:()=>({read:async()=>{reads++;return reads===1?{value:new Uint8Array(total),done:false}:{done:true}},cancel:async()=>{cancelled=true},releaseLock:()=>{released=true}})}};
  if(total===16){const blob=await env.run('readSystemDownload(streamResponse,16)');assert.equal(blob.size,16);assert.equal(cancelled,false);}
  else{await assert.rejects(env.run('readSystemDownload(streamResponse,16)'));assert.equal(cancelled,true);}
  assert.equal(released,true);
 }
 let cancelled=false,released=false;env.context.streamResponse={body:{getReader:()=>({read:async()=>{throw new Error('interrupted')},cancel:async()=>{cancelled=true},releaseLock:()=>{released=true}})}};
 await assert.rejects(env.run('readSystemDownload(streamResponse,16)'));assert.equal(cancelled,true);assert.equal(released,true);
});

test('concurrent report exports keep one transfer and release their own busy state',async()=>{
 const env=onlineSystemExport();let controller,calls=0,downloads=0;
 env.context.fetch=async()=>{calls++;return new Response(new ReadableStream({start(value){controller=value}}),{headers:{'Content-Type':'application/json'}})};
 env.context.downloadFile=()=>downloads++;
 const pending=env.run('exportSystemReport("history")');await Promise.resolve();
 assert.equal(env.get('system-export-status').disabled,true);assert.equal(env.get('system-export-history').disabled,true);
 await env.run('exportSystemReport("status")');assert.equal(calls,1);controller.enqueue(new TextEncoder().encode('[]'));controller.close();await pending;
 assert.equal(downloads,1);assert.equal(env.get('system-export-status').disabled,false);assert.equal(env.get('system-export-history').disabled,false);assert.equal(env.run('state.busy'),true);
});


test('authenticated system reports remain available after profile loading fails',async()=>{
 const env=environment();env.run(systemSource);env.run('state.token="fixture"');
 env.context.fetch=async path=>path==='/api/bootstrap'?{ok:true,json:async()=>({platform:'windows'})}:{ok:false,status:500,json:async()=>({error:'private profile failure'})};
 await assert.rejects(env.run('readCore()'));env.run('state.loading=false;state.offline=true;updateSystemExportButtons()');
 assert.equal(env.get('system-export-history').disabled,false);assert.equal(env.get('system-export-status').disabled,false);
 let download;env.context.downloadFile=(data,name)=>{download={data,name}};env.context.fetch=async()=>new Response('[]\n',{headers:{'Content-Type':'application/json'}});
 await env.run('exportSystemReport("history")');assert.equal(await download.data.text(),'[]\n');assert.equal(download.name,'accessweaver-workflow-history.json');
});


test('API errors retain their HTTP status for read-only report backpressure',async()=>{
 const env=environment();env.context.fetch=async()=>({ok:false,status:503,json:async()=>({error:'report busy'})});
 await assert.rejects(env.run('apiRequest("/api/v1/system")'),error=>error.status===503&&error.message==='report busy');
});

test('status backpressure retries only reads and observes the terminal job',async()=>{
 const env=environment();env.run(systemSource);env.run('state.offline=false;state.loading=false;systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true;const actualPoll=pollSystemJob;pollSystemJob=()=>{globalThis.pollPromise=actualPoll()}');
 let starts=0,reads=0,retries=0;
 env.context.setTimeout=(callback,ms)=>{if(ms===1000){retries++;queueMicrotask(callback)}return 1};
 env.context.apiRequest=async(path)=>{if(path==='/api/v1/system/start'){starts++;return {id:'owned-job',state:'running'}};if(path==='/api/v1/system'){reads++;if(reads<=2)throw Object.assign(new Error('busy'),{status:503});return {job:{id:'owned-job',state:'succeeded'}}}throw new Error('unexpected report route')};
 await env.run('applySystem()');await env.context.pollPromise;
 assert.equal(starts,1);assert.equal(reads,3);assert.equal(retries,2);assert.equal(env.run('systemUI.polling'),false);assert.equal(env.get('system-cancel').disabled,true);assert.match(env.get('system-output').textContent,/succeeded/);
});

test('a busy mutation is not replayed and other status failures are returned',async()=>{
 const env=environment();env.run(systemSource);env.run('systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true');let calls=0;
 env.context.apiRequest=async()=>{calls++;throw Object.assign(new Error('busy'),{status:503})};await env.run('applySystem()');assert.equal(calls,1);assert.equal(env.run('systemUI.polling'),false);
 env.context.apiRequest=async()=>{throw Object.assign(new Error('denied'),{status:403})};await assert.rejects(env.run('readSystemStatus()'),error=>error.status===403);
});
