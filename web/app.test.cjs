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
    replaceChildren(...els) {this.children=[...els];}
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
  // Preserve the canonical owned symbol definitions used by the real DOM.
  for(const match of html.matchAll(/<symbol\b([^>]*\bid="([^"]+)"[^>]*)>([\s\S]*?)<\/symbol>/g)) {
    const node=get(match[2]);node.innerHTML=match[3];
    const viewBox=/\bviewBox="([^"]*)"/.exec(match[1]);if(viewBox)node.setAttribute('viewBox',viewBox[1]);
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
test('background engine changes announce localized states once without moving focus', async () => {
  assert.match(html, /id="runtime-announcement"[^>]+role="status"[^>]+aria-atomic="true"/);
  const env=environment(), region=env.get('runtime-announcement'), writes=[];
  let message='';
  Object.defineProperty(region,'textContent',{get:()=>message,set:value=>{message=value;writes.push(value)}});
  env.run('state.offline=false; state.loading=false; state.lang="tr"; state.runtime={state:"running"}; renderHero=()=>{}; renderProfiles=()=>{}; renderLogs=()=>{};');
  env.run('apiRequest=async()=>fixtureRuntime');
  env.get('theme-toggle').focus();
  for (const runtime of [
    {state:'running',pid:42},
    {state:'failed',pid:42,log:['PRIVATE_FIXTURE_LOG']},
    {state:'exited',pid:0},
    {state:'running',lifecyclePending:true},
    {state:'stopping'},
    {state:'stopped'},
  ]) {
    env.put('fixtureRuntime',runtime);
    await env.run('pollStatus()');
  }
  assert.deepEqual(writes,['failedState','shutdownPending',null,'stopped'].map(key=>key ? env.run('t('+JSON.stringify(key)+')') : ''));
  assert.equal(env.context.document.activeElement,env.get('theme-toggle'));
});
test('changing language clears the previous runtime announcement and localizes the next change', async () => {
  const env=environment(), region=env.get('runtime-announcement'), language=env.get('settings-language');
  env.run('state.offline=false; state.loading=false; state.runtime={state:"running"}; renderHero=()=>{}; renderProfiles=()=>{}; renderLogs=()=>{}; apiRequest=async()=>fixtureRuntime;');
  language.focus();
  env.put('fixtureRuntime',{state:'failed'});
  await env.run('pollStatus()');
  assert.equal(region.textContent,env.run('t("failedState")'));
  env.run('changeLanguage("en")');
  assert.equal(region.textContent,env.run('t("failedState")'));
  env.run('changeLanguage("es")');
  assert.equal(region.textContent,'');
  env.put('fixtureRuntime',{state:'exited'});
  await env.run('pollStatus()');
  assert.equal(region.textContent,'');
  env.put('fixtureRuntime',{state:'stopped'});
  await env.run('pollStatus()');
  assert.equal(region.textContent,'Motor detenido');
  assert.equal(env.context.document.activeElement,language);
});
test('a superseded runtime poll cannot overwrite or announce a newer state', async () => {
  for (const reject of [false,true]) {
    const env=environment(), response=Promise.withResolvers();
    env.context.runtimeResponse=response.promise;
    env.run('state.offline=false; state.loading=false; apiRequest=()=>runtimeResponse;');
    const poll=env.run('pollStatus()');
    env.run('state.runtime={state:"running",pid:123}');
    if (reject) response.reject(new Error('fixture request failed'));
    else response.resolve({state:'failed'});
    await poll;
    assert.equal(env.run('state.runtime.pid'),123);
    assert.equal(env.run('state.disconnected'),false);
    assert.equal(env.get('runtime-announcement').textContent,'');
  }
});
test('connected UI displays the core build version without interpreting HTML',async()=>{
  const env=environment();
  env.run('state.token="fixture"');
  const versionNodes=[env.get('sidebar-version'),env.get('footer-version')];
  env.context.document.querySelectorAll=selector=>selector==='[data-app-version]'?versionNodes:[];
  env.context.fetch=async path=>({ok:true,json:async()=>path==='/api/bootstrap'?{token:'fixture',platform:'windows',version:'2.3.4-rc.1 <source>'}:path==='/api/v1/runtime'?{state:'stopped'}:[]});
  await env.run('readCore()');
  for(const node of versionNodes){assert.equal(node.textContent,'2.3.4-rc.1 <source>');assert.equal(node.innerHTML,'');}
});
test('shared API rejects nonlocal and normalized outside-API paths before issuing a request',async()=>{
 const env=environment();env.run('state.token="SYNTHETIC_PRIVATE_SESSION"');let calls=0;
 env.context.fetch=async()=>{calls++;throw new Error('Unexpected request')};
 const invalid=['https://outside.invalid/api/v1/runtime','//outside.invalid/api/v1/runtime','api/v1/runtime','/api/%2e%2e/outside','/api/../outside','/api/v1/runtime#fragment','/api/v1/ru\\ntime','/api/v1/runtime\n','/api/v1/runtime ',null,{},42];
 for(const target of invalid){env.put('requestTarget',target);await assert.rejects(env.run('apiRequest(requestTarget)'));}
 assert.equal(calls,0);
});
test('shared API refuses redirects without replaying its private mutation',async()=>{
 const env=environment();env.run('state.token="SYNTHETIC_PRIVATE_SESSION"');let initial=0,forwarded=0;
 env.context.fetch=async(path,options)=>{
  assert.equal(path,'/api/v1/synthetic-redirect');initial++;
  // This fixture models a redirecting response; a real-browser control verifies
  // that ordinary follow mode can replay the body to another local API route.
  if(options.redirect==='error')throw new TypeError('Synthetic redirect refused');
  forwarded++;return {ok:true,json:async()=>({accepted:true})};
 };
 await assert.rejects(env.run('apiRequest("/api/v1/synthetic-redirect","POST",{scope:"synthetic-private-body"})'));
 assert.equal(initial,1);assert.equal(forwarded,0);assert.equal(env.run('state.token'),'SYNTHETIC_PRIVATE_SESSION');
});
test('shared API preserves valid bootstrap and query requests with same-origin transport',async()=>{
 const env=environment(),seen=[];env.run('state.token="SYNTHETIC_PRIVATE_SESSION"');
 env.context.fetch=async(path,options)=>{seen.push({path,options});return {ok:true,json:async()=>({accepted:true})};};
 await env.run('apiRequest("/api/bootstrap")');
 await env.run('apiRequest("/api/v1/profiles/synthetic?revision=abc","PUT",{name:"synthetic"})');
 assert.equal(seen.length,2);assert.equal(seen[1].options.body,'{"name":"synthetic"}');
 for(const {options}of seen){assert.equal(options.credentials===undefined?'same-origin':options.credentials,'same-origin');assert.equal(options.mode===undefined?'cors':options.mode,'cors');assert.equal(options.cache,'no-store');assert.equal(options.headers['X-AccessWeaver-Token'],'SYNTHETIC_PRIVATE_SESSION');}
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
test('reconnect keeps the trigger focused while pending and moves focus when it disappears',async()=>{
  const env=environment(),button=env.get('reconnect-button');
  let complete,calls=0;
  env.context.readCore=()=>{calls++;return new Promise(resolve=>{complete=resolve})};
  button.focus();
  const pending=env.run('reconnect()');
  assert.equal(button.getAttribute('aria-disabled'),'true');
  assert.equal(env.context.document.activeElement,button);
  await env.run('reconnect()');
  assert.equal(calls,1);
  complete({profiles:[],engines:[]});
  await pending;
  assert.equal(button.getAttribute('aria-disabled'),null);
  assert.equal(env.context.document.activeElement,env.get('content'));
});
test('reconnect preserves moved focus and leaves a failed request retryable',async()=>{
  const env=environment(),button=env.get('reconnect-button'),other=env.get('profile-search');
  let complete;
  env.context.readCore=()=>new Promise(resolve=>{complete=resolve});
  button.focus();
  const pending=env.run('reconnect()');
  other.focus();
  complete({profiles:[],engines:[]});
  await pending;
  assert.equal(env.context.document.activeElement,other);
  button.focus();
  env.context.readCore=async()=>{throw new Error('Synthetic connection failure')};
  await env.run('reconnect()');
  assert.equal(env.context.document.activeElement,button);
  assert.equal(button.getAttribute('aria-disabled'),null);
  assert.equal(env.run('state.reconnecting'),false);
});
function rejectsProfile(profile) {const env=environment();assert.throws(()=>valid(env,profile));}
test('valid version-1 profile is accepted',()=>{valid(environment());});
const timestampTable = require('../internal/profile/testdata/timestamps.json');
test('shared timestamp conformance preserves optional values and original text',()=>{
 assert.equal(timestampTable.schemaVersion,1);assert.equal(timestampTable.cases.length,65);
 for(const c of timestampTable.cases){
  const env=environment(),p=baseProfile();if(c.present)p.updatedAt=c.value;
  if(c.accepted){assert.deepEqual(plain(valid(env,p)),p,c.id);assert.deepEqual(plain(env.run('parseProfileJSON(JSON.stringify(fixture))')),p,c.id)}
  else{env.put('fixture',p);assert.throws(()=>env.run('validateProfile(fixture)'),undefined,c.id);assert.throws(()=>env.run('parseProfileJSON(JSON.stringify(fixture))'),undefined,c.id)}
 }
});
test('invalid timestamps cannot publish an offline profile or replace stored data',async()=>{
 const env=environment(),original=baseProfile();env.put('original',original);env.run('state.profiles=[original]');env.data.set('aw.profiles',JSON.stringify([original]));
 for(const c of timestampTable.cases.filter(c=>!c.accepted)){
  env.put('fixture',{...original,updatedAt:c.value});await assert.rejects(env.run('persist(fixture)'),undefined,c.id);
  assert.deepEqual(plain(env.run('state.profiles')),[original],c.id);assert.deepEqual(JSON.parse(env.data.get('aw.profiles')),[original],c.id);
 }
});
test('valid timestamps retain null, offsets and fractional precision through editor modes',()=>{
 for(const c of timestampTable.cases.filter(c=>c.accepted)){
  const env=environment(),p=baseProfile();if(c.present)p.updatedAt=c.value;env.put('fixture',p);
  env.run('showEditor(fixture,true);switchEditor("advanced");switchEditor("simple");');
  assert.equal(env.run('state.editorTab'),'simple',c.id);const got=plain(env.run('fromSimple()'));
  assert.equal(Object.hasOwn(got,'updatedAt'),c.present,c.id);if(c.present)assert.deepEqual(got.updatedAt,c.value,c.id);
 }
});
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
test('import collision opens renamed draft without replacing stored profile',async()=>{const env=environment();const original=baseProfile();env.put('fixture',original);env.run('state.profiles = [fixture]');const imported={...original,name:'Imported'};env.context.fileFixture=new Blob([JSON.stringify(imported)]);await env.run('importProfile(fileFixture)');assert.deepEqual(plain(env.run('state.profiles')),[original]);assert.notEqual(env.run('state.editing.profile.id'),original.id);assert.equal(env.run('state.editing.isNew'),true);assert.equal(env.data.has('aw.profiles'),false);});
test('disconnected core blocks writes without changing cached profiles',async()=>{const env=environment();env.put('fixture',baseProfile());env.run('state.disconnected=true');await assert.rejects(env.run('persist(fixture)'));assert.equal(env.run('state.profiles.length'),0);});
test('failed poll marks connection unknown without falsely stopping cached process',async()=>{const env=environment();env.run('state.loading=false;state.offline=false;state.runtime={state:"running",profileId:"test-profile",pid:123};apiRequest=async()=>{throw new Error("network down")};');await env.run('pollStatus()');assert.equal(env.run('state.disconnected'),true);assert.equal(env.run('state.runtime.state'),'running');assert.equal(env.run('coreAvailable()'),false);});
test('history navigation moves focus only when leaving the focused view',()=>{
  const env=environment(),search=env.get('profile-search'),sidebar=env.get('sidebar');
  env.get('view-profiles').contains=node=>node===search;
  env.run('state.view="profiles";state.profileGridRendered=true');
  search.focus();
  env.context.location.hash='#profiles';
  env.run('navigateFromHistory()');
  assert.equal(env.context.document.activeElement,search);
  env.context.location.hash='#dashboard';
  env.run('navigateFromHistory()');
  assert.equal(env.run('state.view'),'dashboard');
  assert.equal(env.context.document.activeElement,env.get('content'));
  sidebar.focus();
  env.context.location.hash='#profiles';
  env.run('navigateFromHistory()');
  assert.equal(env.context.document.activeElement,sidebar);
  assert.equal(env.run('state.view'),'profiles');
});
test('process exit refreshes profile actions',async()=>{const env=environment();env.context.profileRenderCalls=0;env.run('state.loading=false;state.offline=false;state.runtime={state:"running",profileId:"test-profile",pid:123};renderProfiles=()=>{profileRenderCalls++};apiRequest=async()=>({state:"exited",profileId:"test-profile"});');await env.run('pollStatus()');assert.equal(env.context.profileRenderCalls,1);});
test('all HTML translation keys exist in both languages',()=>{const env=environment();const keys=[...html.matchAll(/data-i18n(?:-aria)?="([^"]+)"/g)].map(m=>m[1]);env.context.translationKeys=keys;assert.deepEqual(plain(env.run('translationKeys.filter(key=>!en[key]||!tr[key])')),[]);});
test('Russian and Spanish cover every UI translation key',()=>{const env=environment();assert.deepEqual(plain(env.run('Object.keys(en).filter(key=>!extraLocales.ru[key]||!extraLocales.es[key])')),[]);});
test('all four languages can be selected and persisted',()=>{const env=environment();for(const lang of ['en','tr','ru','es']){env.context.languageFixture=lang;env.run('changeLanguage(languageFixture)');assert.equal(env.run('state.lang'),lang);assert.equal(env.data.get('aw.lang'),lang);}});
test('system operation consent is invalidated by input changes',()=>{const env=environment();env.run(systemSource);env.run('systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true;invalidateSystemPlan()');assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-apply').disabled,true);assert.equal(env.get('system-consent').checked,false);});

test('switching operations excludes hidden stale system fields',()=>{const env=environment();env.run(systemSource);env.get('system-action').value='dns-restore';env.get('system-engine').value='byedpi';env.get('system-args').value='stale argument';env.get('system-config').value='C:\\stale.conf';env.get('system-cloudflare-terms').checked=true;assert.deepEqual(plain(env.run('systemRequest()')),{action:'dns-restore'});});
test('system operations expose only compatible component choices',()=>{const env=environment();env.run(systemSource);assert.deepEqual(plain(env.run('systemEnginesFor("scan")')),['zapret','zapret2']);assert.deepEqual(plain(env.run('systemEnginesFor("app-install")')),['discord','discord-ptb','splitcord']);assert.equal(env.run('systemEnginesFor("install").includes("discord")'),false);});
test('user application operations exclude stale machine DNS and bundle inputs',()=>{const env=environment();env.run(systemSource);env.get('system-engine').value='discord';env.get('system-dns').value='doh';env.get('system-bundle').value='C:\\machine-components';for(const action of ['app-install','app-remove','app-start','app-reinstall']){env.get('system-action').value=action;const request=plain(env.run('systemRequest()'));assert.equal(request.dns,undefined);assert.equal(request.bundlePath,undefined);if(action==='app-reinstall')assert.deepEqual(request,{action,engine:'discord'});}});
test('every system operation label has all four languages',()=>{const env=environment();const labels=plain(env.run('systemOperationText'));assert.equal(Object.keys(labels).length,23);for(const row of Object.values(labels))for(const lang of ['en','tr','ru','es'])assert.ok(row[lang]);});
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

function supportFixture(){return {schemaVersion:1,scope:'metadata-only',generatedAt:'2026-11-01T00:00:00Z',build:{version:'source-fixture',commit:'a'.repeat(40),sourceState:'clean',builtAt:'unknown',goVersion:'go1.27.3',platform:'linux',arch:'amd64'},profiles:{status:'available',total:2,byEngine:{byedpi:2}},runtime:{state:'stopped',errorPresent:false,logLines:0},workflow:{state:'idle',errorPresent:false,resultPresent:false}};}
function supportReady(env){env.run('state.view="settings";state.offline=false;state.loading=false;state.disconnected=false;state.coreAuthenticated=true;state.token="fixture";updateSupportAvailability()');}
function supportResponse(report=supportFixture(),options={}){
 const bytes=options.bytes??new TextEncoder().encode(JSON.stringify(report));let read=false,canceled=false,released=false;
 return {ok:options.ok??true,headers:{get:name=>name==='Content-Type'?(options.contentType??'application/json; charset=utf-8'):name==='Content-Length'?(options.length??null):null},body:{getReader:()=>({async read(){if(read)return {done:true};read=true;return {done:false,value:bytes}},async cancel(){canceled=true},releaseLock(){released=true}})},get canceled(){return canceled},get released(){return released}};
}
function supportDeferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return {promise,resolve,reject};}
test('support export uses the bounded authenticated metadata summary without changing another busy action',async()=>{
 const env=environment();supportReady(env);env.run('state.busy=true');const report=supportFixture();
 let request,download;env.context.fetch=async(path,options)=>{request={path,options};return supportResponse(report)};env.context.downloadFile=(data,name)=>{download={data,name}};
 await env.run('exportSupportSummary()');
 assert.equal(request.path,'/api/v1/support');assert.equal(request.options.method,'GET');assert.equal(request.options.headers['X-AccessWeaver-Token'],'fixture');assert.equal(request.options.redirect,'error');assert.equal(request.options.cache,'no-store');
 assert.deepEqual(JSON.parse(download.data),report);assert.equal(download.name,'accessweaver-support-summary.json');assert.equal(env.run('state.busy'),true);assert.equal(env.get('export-support').disabled,false);assert.equal(env.run('state.supportExporting'),false);
});
test('support export failures discard private error bodies and never download partial metadata',async()=>{
 for(const response of [supportResponse(undefined,{ok:false}),supportResponse(undefined,{contentType:'text/plain'}),supportResponse(undefined,{length:'16385'}),supportResponse(undefined,{bytes:new Uint8Array(16385)}),supportResponse(undefined,{bytes:Uint8Array.from([0xff])}),supportResponse({...supportFixture(),privateDetails:'PRIVATE_SUPPORT_BODY'}),supportResponse({...supportFixture(),schemaVersion:2})]){
  const env=environment();supportReady(env);let downloads=0;const messages=[];env.context.fetch=async()=>response;env.context.downloadFile=()=>downloads++;env.context.toast=message=>messages.push(message);
  await env.run('exportSupportSummary()');assert.equal(downloads,0);assert.deepEqual(messages,[env.run('t("disconnectedDesc")')]);assert.equal(env.run('state.supportExporting'),false);assert.equal(env.get('export-support').disabled,false);
 }
 const env=environment();supportReady(env);let downloads=0;const messages=[];env.context.fetch=async()=>{throw new Error('PRIVATE_SUPPORT_TRANSPORT')};env.context.downloadFile=()=>downloads++;env.context.toast=message=>messages.push(message);await env.run('exportSupportSummary()');assert.equal(downloads,0);assert.deepEqual(messages,[env.run('t("disconnectedDesc")')]);
});
test('support export context and navigation changes abort and suppress late success or feedback',async()=>{
 for(const change of ['state.token="next-session";updateSupportAvailability()','state.profileEditingOnly=true;updateSupportAvailability()','state.coreAuthenticated=false;updateSupportAvailability()','state.loading=true;updateSupportAvailability()','state.offline=true;updateSupportAvailability()','state.disconnected=true;updateSupportAvailability()','navigate("profiles")','invalidateSupportExport();updateSupportAvailability()']){
  const env=environment();supportReady(env);const held=supportDeferred();let signal,downloads=0;const messages=[];env.context.fetch=(path,options)=>{signal=options.signal;return held.promise};env.context.downloadFile=()=>downloads++;env.context.toast=message=>messages.push(message);
  const exporting=env.run('exportSupportSummary()');env.run(change);assert.equal(signal.aborted,true,change);held.resolve(supportResponse());await exporting;assert.equal(downloads,0,change);assert.deepEqual(messages,[],change);assert.equal(env.run('state.supportExporting'),false,change);
 }
});
test('old support success and failure cannot release or overwrite a newer explicit export',async()=>{
 for(const lateFailure of [false,true]){
  const env=environment();supportReady(env);const first=supportDeferred(),second=supportDeferred();let calls=0,downloads=0;const messages=[];env.context.fetch=()=>++calls===1?first.promise:second.promise;env.context.downloadFile=()=>downloads++;env.context.toast=message=>messages.push(message);
  const old=env.run('exportSupportSummary()');env.run('navigate("profiles");navigate("settings")');const current=env.run('exportSupportSummary()');assert.equal(calls,2);
  if(lateFailure)first.reject(new Error('PRIVATE_OLD_SUPPORT_ERROR'));else first.resolve(supportResponse());await old;
  assert.equal(env.run('state.supportExporting'),true);assert.equal(env.get('export-support').disabled,true);assert.equal(downloads,0);assert.deepEqual(messages,[]);
  second.resolve(supportResponse());await current;assert.equal(downloads,1);assert.equal(env.run('state.supportExporting'),false);assert.equal(env.get('export-support').disabled,false);assert.deepEqual(messages,[]);
 }
});
test('support export bounds streamed bytes before parsing and cancels an over-limit stream',async()=>{
 const env=environment();supportReady(env);let reads=0,canceled=0,released=0,downloads=0;
 env.context.fetch=async()=>({ok:true,headers:{get:name=>name==='Content-Type'?'application/json':null},body:{getReader:()=>({async read(){reads++;return {done:false,value:new Uint8Array(reads===1?16384:1)}},async cancel(){canceled++},releaseLock(){released++}})}});env.context.downloadFile=()=>downloads++;
 await env.run('exportSupportSummary()');assert.equal(reads,2);assert.equal(canceled,1);assert.equal(released,1);assert.equal(downloads,0);
});
test('support body timeout cannot adopt a late body even when the mocked transport ignores abort',async()=>{
 const env=environment();supportReady(env);const body=supportDeferred(),started=supportDeferred();let timeout,reads=0,canceled=0,downloads=0;const messages=[];env.context.setTimeout=(callback,milliseconds)=>{assert.equal(milliseconds,12000);timeout=callback;return 1};env.context.fetch=async()=>({ok:true,headers:{get:name=>name==='Content-Type'?'application/json':null},body:{getReader:()=>({read(){reads++;started.resolve();return body.promise},async cancel(){canceled++},releaseLock(){}})}});env.context.downloadFile=()=>downloads++;env.context.toast=message=>messages.push(message);
 const exporting=env.run('exportSupportSummary()');await started.promise;assert.equal(reads,1);timeout();body.resolve({done:false,value:new TextEncoder().encode(JSON.stringify(supportFixture()))});await exporting;assert.equal(downloads,0);assert.equal(canceled,1);assert.deepEqual(messages,[env.run('t("disconnectedDesc")')]);assert.equal(env.run('state.supportExporting'),false);
});
test('the actual session loader invalidates a held support export before adopting a new credential',async()=>{
 const env=environment();supportReady(env);const held=supportDeferred();let signal,downloads=0;env.context.fetch=(path,options)=>{signal=options.signal;return held.promise};env.context.downloadFile=()=>downloads++;
 const exporting=env.run('exportSupportSummary()');env.context.location.hash='#accessweaver-session='+'z'.repeat(43);env.run('readSession()');assert.equal(signal.aborted,true);held.resolve(supportResponse());await exporting;assert.equal(downloads,0);assert.equal(env.run('state.token'),'z'.repeat(43));assert.equal(env.run('state.supportExporting'),false);
});
test('the bound pagehide handler cancels support ownership and keeps export usable on a cached authenticated offline view',async()=>{
 const env=environment();supportReady(env);env.run('state.offline=true');const handlers=new Map();env.context.window.addEventListener=(name,callback)=>handlers.set(name,callback);env.run('bindEvents()');
 const first=supportDeferred(),second=supportDeferred();let calls=0,downloads=0;env.context.fetch=()=>++calls===1?first.promise:second.promise;env.context.downloadFile=()=>downloads++;
 const old=env.run('exportSupportSummary()');assert.equal(env.get('export-support').disabled,true);handlers.get('pagehide')();assert.equal(env.run('state.supportExporting'),false);assert.equal(env.get('export-support').disabled,false);
 const current=env.run('exportSupportSummary()');first.resolve(supportResponse());await old;assert.equal(downloads,0);assert.equal(env.run('state.supportExporting'),true);assert.equal(env.get('export-support').disabled,true);second.resolve(supportResponse());await current;assert.equal(downloads,1);assert.equal(env.get('export-support').disabled,false);
});
test('support export stays available after authenticated profile loading fails but profile-audited mode denies it',async()=>{
 const env=environment();env.run('state.token="fixture"');env.context.fetch=async path=>path==='/api/bootstrap'?{ok:true,json:async()=>({platform:'windows'})}:{ok:false,status:500,json:async()=>({error:'private store failure'})};
 await assert.rejects(env.run('readCore()'));env.run('state.loading=false;state.offline=true;state.view="settings"');assert.equal(env.run('supportAvailable()'),true);assert.equal(env.run('coreAvailable()'),false);
 const report=supportFixture();report.profiles={status:'unavailable',total:null};let downloads=0,calls=0;env.context.fetch=async()=>{calls++;return supportResponse(report)};env.context.downloadFile=()=>downloads++;await env.run('exportSupportSummary()');assert.equal(downloads,1);assert.equal(calls,1);
 env.run('state.profileEditingOnly=true');await env.run('exportSupportSummary()');assert.equal(calls,1);assert.equal(downloads,1);assert.equal(env.get('export-support').disabled,true);
 const offline=environment();let requests=0;offline.context.fetch=async()=>{requests++;throw new Error('Unexpected request')};await offline.run('exportSupportSummary()');assert.equal(requests,0);
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
 const env=environment();env.run('state.view="diagnostics";state.offline=false;state.loading=false;state.token="fixture";state.lastProbe={checks:[{status:"ok"}]}');
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


test('optional workflow metadata cannot interrupt job rendering',()=>{
 for(const journal of [null,false,true,0,7,[],{},['unexpected'],{split:'not a function'},'', '   ', 'C:/journals/']){
  const env=environment();env.run(systemSource);env.get('system-journal').value='reviewed.json';
  const job={id:'raw-result',action:'discover',state:'failed',result:{journal,private:'RAW_RESULT_RETAINED'}};env.put('jobFixture',job);
  assert.doesNotThrow(()=>env.run('renderSystemJob(jobFixture)'));
  assert.equal(env.get('system-journal').value,'reviewed.json');assert.equal(env.get('system-cancel').disabled,true);
  assert.match(env.get('system-output').textContent,/RAW_RESULT_RETAINED/);assert.deepEqual(plain(env.run('jobFixture')),job);
 }
 const env=environment();env.run(systemSource);const protectedName='workflow-'+'a'.repeat(32)+'.json';
 env.put('jobFixture',{id:'recovery',action:'install',state:'failed',result:{journal:'C:\\private\\journals\\'+protectedName}});
 env.run('renderSystemJob(jobFixture)');assert.equal(env.get('system-journal').value,protectedName);
});

test('application failure exposes vendor uncertainty and preserves the protected recovery selection',()=>{
 const env=environment();env.run(systemSource);
 const journal=env.get('system-journal'),notice=env.get('system-application-recovery'),output=env.get('system-output');
 const protectedName='workflow-'+'a'.repeat(32)+'.json';
 journal.value=protectedName;
 env.get('system-action').value='recover';env.get('system-consent').checked=true;
 env.run('systemUI.plan={id:"reviewed",ready:true}');
 const render=(action,state,result)=>{env.put('jobFixture',{id:'job',action,state,result});env.run('renderSystemJob(jobFixture)');};
 render('app-reinstall','failed',{journal:'C:\\private\\application.json',externalEffectsPending:true,payload:'x'.repeat(10000)});
 assert.equal(notice.hidden,false);
 assert.equal(output.getAttribute('aria-describedby'),'system-application-recovery system-output-limited');
 assert.equal(journal.value,protectedName);
 assert.equal(env.run('systemUI.plan.id'),'reviewed');
 assert.equal(env.get('system-consent').checked,true);
 for(const [action,state,flag] of [['app-install','failed','true'],['app-remove','succeeded',true],['app-start','running',true],['install','failed',true]]){
  render(action,state,{journal:'application.json',externalEffectsPending:flag});
  assert.equal(notice.hidden,true);assert.equal(output.getAttribute('aria-describedby'),null);assert.equal(journal.value,protectedName);
 }
 render('app-remove','failed',{journal:'workflow-'+'b'.repeat(32)+'.json',externalEffectsPending:true});
 assert.equal(notice.hidden,false);assert.equal(journal.value,protectedName);
 render('install','failed',{journal:'workflow-'+'b'.repeat(32)+'.json\n'});
 assert.equal(notice.hidden,true);assert.equal(journal.value,protectedName);
 const messages=['en','tr','ru','es'].map(lang=>{
  env.put('fixtureLanguage',lang);env.run('state.lang=fixtureLanguage');
  return env.run('t("applicationRecoveryNotice")');
 });
 assert.equal(new Set(messages).size,4);
 assert.ok(messages.every(message=>message!=='applicationRecoveryNotice'));
});

test('only a successful owned folder choice can change the application list',()=>{
 const cases=[
  ...[null,false,true,9,[],{},['C:\\invalid'],''].map(folder=>({folder,state:'succeeded',action:'choose-folder',id:'chooser'})),
  {folder:'C:\\failed',state:'failed',action:'choose-folder',id:'chooser'},
  {folder:'C:\\different-action',state:'succeeded',action:'discover',id:'chooser'},
  {folder:'C:\\different-job',state:'succeeded',action:'choose-folder',id:'another'},
  {folder:'C:\\pending',state:'running',action:'choose-folder',id:'chooser'},
 ];
 for(const row of cases){
  const env=environment();env.run(systemSource);env.get('system-applications').value='C:\\existing';env.get('system-consent').checked=true;
  env.run('systemUI.folderJob="chooser";systemUI.plan={id:"reviewed",ready:true}');
  env.put('jobFixture',{id:row.id,action:row.action,state:row.state,result:{data:{folder:row.folder}}});env.run('renderSystemJob(jobFixture)');
  assert.equal(env.get('system-applications').value,'C:\\existing',JSON.stringify(row));assert.equal(env.run('systemUI.plan.id'),'reviewed');assert.equal(env.get('system-consent').checked,true);
 }
});

test('a successful folder choice is added once and invalidates its old review',()=>{
 const env=environment();env.run(systemSource);env.get('system-applications').value='C:\\existing';env.get('system-consent').checked=true;
 env.run('systemUI.folderJob="chooser";systemUI.plan={id:"reviewed",ready:true}');env.put('jobFixture',{id:'chooser',action:'choose-folder',state:'succeeded',result:{data:{folder:'C:\\selected'}}});
 env.run('renderSystemJob(jobFixture);renderSystemJob(jobFixture)');assert.equal(env.get('system-applications').value,'C:\\existing\nC:\\selected');assert.equal(env.run('systemUI.folderJob'),null);assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-consent').checked,false);assert.equal(env.get('system-apply').disabled,true);
});

test('a duplicate folder choice preserves the current reviewed request',()=>{
 const env=environment();env.run(systemSource);env.get('system-applications').value='C:\\existing';env.get('system-consent').checked=true;
 env.run('systemUI.folderJob="chooser";systemUI.plan={id:"reviewed",ready:true}');env.put('jobFixture',{id:'chooser',action:'choose-folder',state:'succeeded',result:{data:{folder:'C:\\existing'}}});
 env.run('renderSystemJob(jobFixture)');assert.equal(env.run('systemUI.folderJob'),null);assert.equal(env.get('system-applications').value,'C:\\existing');assert.equal(env.run('systemUI.plan.id'),'reviewed');assert.equal(env.get('system-consent').checked,true);
});

test('invalid update metadata cannot show or consume a release notification',()=>{
 for(const data of [null,{},[],{updateAvailable:'true',version:'v2'},{updateAvailable:true},{updateAvailable:true,version:{}},{updateAvailable:true,version:7},{updateAvailable:true,version:''}]){
  const env=environment();env.run(systemSource);env.run('toast=message=>{globalThis.notices=(globalThis.notices||[]).concat(message)}');
  env.put('jobFixture',{id:'updates',action:'updates',state:'succeeded',result:{data}});env.run('notifySystemUpdate(jobFixture)');assert.equal(env.context.notices,undefined);assert.equal(env.run('systemUI.lastUpdate'),undefined);
  env.put('jobFixture',{id:'updates',action:'updates',state:'succeeded',result:{data:{updateAvailable:true,version:'v2.0.0'}}});env.run('notifySystemUpdate(jobFixture);notifySystemUpdate(jobFixture)');assert.equal(env.context.notices.length,1);assert.match(env.context.notices[0],/v2.0.0/);
 }
});

test('workflow polling survives untyped optional metadata until the terminal report',async()=>{
 const env=environment();env.run(systemSource);env.get('system-journal').value='reviewed.json';let reads=0,pauses=0;
 env.context.setTimeout=(callback,ms)=>{assert.equal(ms,1500);pauses++;queueMicrotask(callback);return 1};
 env.context.apiRequest=async path=>{assert.equal(path,'/api/v1/system');reads++;return {job:{id:'polling',action:'discover',state:reads===1?'running':'failed',result:{journal:{legacy:'RAW_OPTIONAL_METADATA'},data:{folder:{invalid:true}}}}}};
 await env.run('pollSystemJob()');assert.equal(reads,2);assert.equal(pauses,1);assert.equal(env.run('systemUI.polling'),false);assert.equal(env.get('system-cancel').disabled,true);assert.equal(env.get('system-journal').value,'reviewed.json');assert.match(env.get('system-output').textContent,/RAW_OPTIONAL_METADATA/);assert.match(env.get('system-output').textContent,/failed/);
});


test('journal hints invalidate a changed recovery review and preserve an unchanged one',()=>{
 const env=environment();env.run(systemSource);
 const reviewed='workflow-'+'a'.repeat(32)+'.json',replacement='workflow-'+'b'.repeat(32)+'.json';
 env.get('system-action').value='recover';env.get('system-journal').value=reviewed;env.get('system-consent').checked=true;env.get('system-apply').disabled=false;
 env.run('systemUI.plan={id:"reviewed",ready:true}');env.put('jobFixture',{id:'completed',action:'install',state:'failed',result:{journal:'C:\\journals\\'+reviewed}});
 env.run('renderSystemJob(jobFixture)');assert.equal(env.run('systemUI.plan.id'),'reviewed');assert.equal(env.get('system-consent').checked,true);
 env.put('jobFixture',{id:'completed',action:'install',state:'failed',result:{journal:'C:\\journals\\'+replacement}});env.run('renderSystemJob(jobFixture)');
 assert.equal(env.get('system-journal').value,replacement);assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-consent').checked,false);assert.equal(env.get('system-apply').disabled,true);
});


test('audited profile desktop displays limits and disables execution while preserving editing',async()=>{
 const env=environment();env.run('state.token="fixture";state.offline=false;state.loading=false');
 env.context.fetch=async path=>({ok:true,json:async()=>path==='/api/bootstrap'?{platform:'linux',profileEditingOnly:true}:path==='/api/v1/runtime'?{state:'stopped'}:[]});
 const core=await env.run('readCore()');env.put('coreFixture',core);env.run('Object.assign(state,coreFixture);renderHero()');
 assert.equal(env.run('state.profileEditingOnly'),true);
 assert.equal(env.get('profile-audit-notice').hidden,false);
 assert.match(env.get('profile-audit-notice').textContent,/saves and deletes require audit/);
 assert.equal(env.get('probe-submit').disabled,true);assert.equal(env.get('launch-confirm').disabled,true);assert.equal(env.get('export-support').disabled,true);
 env.run('navigate("system")');assert.equal(env.run('state.view'),'profiles');
 env.put('fixture',baseProfile());const card=env.run('profileCard(fixture,true)');
 assert.match(card,/data-profile-action="run"[^>]*disabled/);
 assert.doesNotMatch(card,/data-profile-action="edit"[^>]*disabled/);
});
test('audited desktop never saves profiles to browser fallback after partial connection',async()=>{
 const env=environment();env.run('state.profileEditingOnly=true');env.put('fixture',baseProfile());
 await assert.rejects(env.run('persist(fixture)'));assert.equal(env.data.get('aw.profiles'),undefined);
});

test('pending engine shutdown is localized and preserves editing, logs and support',()=>{
  const titles={en:'Shutdown unconfirmed',tr:'Kapanış doğrulanmadı',ru:'Завершение не подтверждено',es:'Cierre sin confirmar'};
  for(const lang of Object.keys(titles)){
    const env=environment();env.put('fixture',baseProfile());env.put('languageFixture',lang);
    env.run('state.lang=languageFixture;state.offline=false;state.loading=false;state.coreAuthenticated=true;state.token="fixture";state.platform="linux";state.profiles=[fixture];state.runtime={state:"running",profileId:fixture.id,engine:"byedpi",pid:321,lifecyclePending:true,lastError:"PRIVATE_NATIVE_FAULT"};renderHero()');
    assert.equal(env.get('hero-status').textContent,titles[lang]);
    assert.equal(env.get('status-badge').textContent,env.run('t("shutdownPendingBadge")'));
    assert.equal(env.get('running-engine').textContent,'—');
    assert.equal(env.get('hero-primary').disabled,true);
    assert.equal(env.get('show-logs').disabled,false);assert.equal(env.get('export-support').disabled,false);
    assert.doesNotMatch(env.get('hero-description').textContent,/PRIVATE|321/);
    const card=env.run('profileCard(fixture,true)');
    assert.match(card.match(/<button[^>]*data-profile-action="run"[^>]*>/)[0],/\bdisabled\b/);
    for(const control of card.matchAll(/<button[^>]*data-profile-action="edit"[^>]*>/g))assert.doesNotMatch(control[0],/\bdisabled\b/);
    env.run('showEditor(fixture)');assert.equal(env.run('state.editing.profile.id'),baseProfile().id);
  }
});

test('pending lifecycle invalidates an open launch review and blocks direct launch handlers',async()=>{
  const env=environment();env.put('fixture',baseProfile());
  env.run('state.offline=false;state.loading=false;state.launch={profile:fixture,ready:true};state.runtime={state:"error",lifecyclePending:true};apiRequest=async()=>{throw new Error("unexpected launch API")};renderHero()');
  assert.equal(env.run('state.launch.ready'),false);assert.equal(env.get('launch-confirm').disabled,true);
  assert.equal(env.get('launch-plan').textContent,env.run('t("shutdownPendingDesc")'));
  await assert.rejects(env.run('reviewLaunch(fixture)'),/Starting another engine is blocked/);
  await env.run('confirmLaunch()');
  assert.equal(env.run('state.busy'),false);
});

test('a late launch preview cannot reenable launch during pending cleanup',async()=>{
  const env=environment();env.put('fixture',baseProfile());
  env.run('state.offline=false;state.loading=false;apiRequest=async path=>path.startsWith("/api/v1/profiles/")?fixture:new Promise(resolve=>{globalThis.finishPreview=resolve})');
  const review=env.run('reviewLaunch(fixture)');await Promise.resolve();
  assert.equal(typeof env.context.finishPreview,'function');
  env.run('state.runtime={state:"error",lifecyclePending:true};renderHero()');
  env.context.finishPreview({ready:true,args:[],warnings:[],issues:[]});await review;
  assert.equal(env.run('state.launch.ready'),false);assert.equal(env.get('launch-confirm').disabled,true);
  assert.equal(env.get('launch-plan').textContent,env.run('t("shutdownPendingDesc")'));
});

test('a pending-lifecycle change refreshes profile controls even when status and PID stay unchanged',async()=>{
  const env=environment();env.run('state.offline=false;state.loading=false;state.runtime={state:"error",profileId:"test-profile",pid:0,lifecyclePending:false};globalThis.profileUpdates=0;renderProfiles=()=>{profileUpdates++};apiRequest=async()=>({state:"error",profileId:"test-profile",pid:0,lifecyclePending:true})');
  await env.run('pollStatus()');assert.equal(env.context.profileUpdates,1);assert.equal(env.get('hero-primary').disabled,true);
  env.run('apiRequest=async()=>({state:"error",profileId:"test-profile",pid:0,lifecyclePending:false})');
  await env.run('pollStatus()');assert.equal(env.context.profileUpdates,2);assert.equal(env.get('hero-primary').disabled,false);
});

// Source-only history contracts: synthetic API replies; no product or native worker.
function historyFixtureRecord(overrides={}){return {recordRef:'record_A',revision:'c'.repeat(64),id:'d'.repeat(48),action:'discover',state:'failed',startedAt:'2026-11-01T00:00:00Z',finishedAt:'2026-11-01T00:01:00Z',size:128,classification:'canonical',protection:'retirement-unavailable',errorPresent:true,resultPresent:true,rawAvailable:true,...overrides};}
function historyFixtureInventory(){return {snapshot:'a'.repeat(48),storeRevision:'b'.repeat(48),createdAt:'2026-11-01T00:02:00Z',count:2,totalBytes:256};}
function historyFixtureResponse(value,status=200){return new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});}
function onlineHistory(){const env=environment();env.run(systemSource);env.run('state.view="system";state.loading=false;state.coreAuthenticated=true;state.token="history-session";state.offline=false;updateHistoryAvailability();historyUI.open=true');return env;}

test('history capture is explicit and metadata paging preserves the legacy export route',async()=>{
 const env=onlineHistory(),inventory=historyFixtureInventory(),record=historyFixtureRecord(),requests=[];
 env.context.fetch=async(path,options)=>{requests.push({path,options});if(path==='/api/v1/system/history/inventory')return historyFixtureResponse(inventory);if(path.startsWith('/api/v1/system/history/page'))return requests.filter(item=>item.path.startsWith('/api/v1/system/history/page')).length===1?historyFixtureResponse({},409):historyFixtureResponse({inventory,items:[record],nextCursor:''});throw Error('unexpected history route');};
 await env.run('openHistory()');assert.equal(requests.length,1);assert.equal(requests[0].options.method,'GET');assert.equal(env.run('historyUI.inventory'),null);assert.match(env.get('history-status').textContent,/new capture/);
 await env.run('captureHistory()');assert.equal(requests.filter(item=>item.options.method==='POST').length,1);
 const capture=requests.find(item=>item.options.method==='POST');assert.equal(capture.path,'/api/v1/system/history/inventory');assert.equal(capture.options.body,'{}');assert.equal(capture.options.headers['X-AccessWeaver-Token'],'history-session');assert.equal(capture.options.redirect,'error');
 assert.equal(env.run('historyUI.items.length'),1);assert.equal(env.run('historyUI.inventory.snapshot'),inventory.snapshot);assert.equal(new URL(requests.at(-1).path,'http://localhost').searchParams.get('limit'),'64');assert.equal(env.get('history-capture').disabled,false);
 assert.match(env.get('history-detail-summary').textContent,/^$/);assert.match(env.get('history-status').textContent,/Showing 1/);
});

test('history follows opaque cursors and previous-page navigation without changing operation review',async()=>{
 const env=onlineHistory(),inventory=historyFixtureInventory(),first=historyFixtureRecord(),second=historyFixtureRecord({recordRef:'record_B',revision:'e'.repeat(64)}),routes=[];
 env.run('systemUI.plan={id:"reviewed-operation",ready:true};$("system-consent").checked=true');
 env.context.fetch=async path=>{routes.push(path);const cursor=new URL(path,'http://localhost').searchParams.get('cursor');return historyFixtureResponse({inventory,items:[cursor?second:first],nextCursor:cursor?'':'next_cursor'});};
 await env.run('loadHistoryPage()');await env.run('historyNextPage()');await new Promise(resolve=>setImmediate(resolve));
 assert.equal(env.run('historyUI.cursor'),'next_cursor');assert.equal(env.run('historyUI.items[0].recordRef'),'record_B');assert.equal(env.get('history-previous').disabled,false);
 await env.run('historyPreviousPage()');await new Promise(resolve=>setImmediate(resolve));assert.equal(env.run('historyUI.items[0].recordRef'),'record_A');assert.equal(env.run('systemUI.plan.id'),'reviewed-operation');assert.equal(env.get('system-consent').checked,true);assert.equal(routes.length,3);
});

test('late history page replies cannot replace a newer page even when fetch ignores abort',async()=>{
 const env=onlineHistory(),inventory=historyFixtureInventory();let resolveFirst,resolveSecond,firstSignal;
 env.context.fetch=(path,options)=>new Promise(resolve=>{if(path.includes('cursor=first')){resolveFirst=resolve;firstSignal=options.signal;}else resolveSecond=resolve;});
 const first=env.run('loadHistoryPage("first")'),second=env.run('loadHistoryPage("second")');
 resolveSecond(historyFixtureResponse({inventory,items:[historyFixtureRecord({recordRef:'record_B'})],nextCursor:''}));await second;
 resolveFirst(historyFixtureResponse({inventory,items:[historyFixtureRecord()],nextCursor:''}));await first;
 assert.equal(firstSignal.aborted,true);assert.equal(env.run('historyUI.items[0].recordRef'),'record_B');
});

test('exact history detail is independent from current status and rejects stale selected records',async()=>{
 const env=onlineHistory(),a=historyFixtureRecord(),b=historyFixtureRecord({recordRef:'record_B',revision:'e'.repeat(64)});env.put('historyRows',[a,b]);env.run('historyUI.items=historyRows;systemUI.plan={id:"reviewed-operation",ready:true};$("system-consent").checked=true;$("system-journal").value="reviewed.json";$("system-cancel").disabled=false');
 let resolveA,resolveB;
 env.context.fetch=path=>new Promise(resolve=>{if(path.includes('/record_A?'))resolveA=resolve;else resolveB=resolve;});
 const pendingA=env.run('selectHistoryRecord("record_A")'),pendingB=env.run('selectHistoryRecord("record_B")');
 const job={id:'historical',state:'failed',result:{journal:'PRIVATE_OLD_JOURNAL',payload:'<img src=x onerror=alert(1)>'}};
 resolveB(historyFixtureResponse({record:b,job,rawAvailable:true}));await pendingB;
 resolveA(historyFixtureResponse({record:a,job:{id:'stale-private'},rawAvailable:true}));await pendingA;
 assert.equal(env.run('historyUI.selected.recordRef'),'record_B');assert.equal(env.run('historyUI.job.id'),'historical');assert.equal(env.get('history-detail').innerHTML,'');assert.match(env.get('history-detail').textContent,/<img/);
 assert.equal(env.get('system-journal').value,'reviewed.json');assert.equal(env.get('system-cancel').disabled,false);assert.equal(env.run('systemUI.plan.id'),'reviewed-operation');assert.equal(env.get('system-consent').checked,true);
});

test('unreadable captured records use explicit empty revision detail and cannot be exported',async()=>{
 const env=onlineHistory(),record=historyFixtureRecord({classification:'special',state:'unknown',rawAvailable:false,revision:'',id:''});env.put('historyRows',[record]);env.run('historyUI.items=historyRows');
 let route;env.context.fetch=async path=>{route=path;return historyFixtureResponse({record,rawAvailable:false});};
 await env.run('selectHistoryRecord("record_A")');assert.equal(route,'/api/v1/system/history/records/record_A?revision=');assert.equal(env.get('history-export-record').disabled,true);assert.match(env.get('history-detail').textContent,/cannot be safely read/);
});

test('selected raw history export preserves binary bytes and requires both exact revision echoes',async()=>{
 const env=onlineHistory(),record=historyFixtureRecord({size:6}),bytes=new Uint8Array([0xff,0,13,10,60,38]);env.put('selectedHistory',record);env.run('historyUI.selected=selectedHistory;historyUI.detailReady=true;historyUI.rawAvailable=true');
 let download,request,route;env.context.downloadFile=(data,name,mime)=>{download={data,name,mime}};
 env.context.fetch=async(path,options)=>{route=path;request=options;return new Response(bytes,{headers:{'Content-Type':'application/octet-stream','ETag':'"'+record.revision+'"','X-AccessWeaver-Revision':record.revision}});};
 await env.run('exportHistoryRecord()');assert.deepEqual(new Uint8Array(await download.data.arrayBuffer()),bytes);assert.equal(download.name,'accessweaver-workflow-record.bin');assert.equal(download.mime,'application/octet-stream');assert.equal(request.headers['X-AccessWeaver-Token'],'history-session');assert.equal(request.redirect,'error');assert.match(route,/record_A\/export\?revision=/);
 download=null;env.context.fetch=async()=>new Response(bytes,{headers:{'Content-Type':'application/octet-stream','ETag':'"wrong"','X-AccessWeaver-Revision':record.revision}});
 await env.run('exportHistoryRecord()');assert.equal(download,null);assert.match(env.get('history-status').textContent,/could not be verified/);assert.equal(env.run('historyUI.exporting'),false);
 env.context.fetch=async()=>new Response(bytes.slice(0,3),{headers:{'Content-Type':'application/octet-stream','ETag':'"'+record.revision+'"','X-AccessWeaver-Revision':record.revision}});await env.run('exportHistoryRecord()');assert.equal(download,null);assert.match(env.get('history-status').textContent,/could not be verified/);
});

test('raw history export refuses a stream beyond64MiB without downloading a partial record',async()=>{
 const env=onlineHistory(),record=historyFixtureRecord();env.put('selectedHistory',record);env.run('historyUI.selected=selectedHistory;historyUI.detailReady=true;historyUI.rawAvailable=true');
 let downloads=0,canceled=false,part=0;env.context.downloadFile=()=>downloads++;
 const response={ok:true,headers:new Headers({'Content-Type':'application/octet-stream','ETag':'"'+record.revision+'"','X-AccessWeaver-Revision':record.revision}),body:{getReader(){return {async read(){return {done:false,value:new Uint8Array(++part===1?64*1024*1024:1)}},async cancel(){canceled=true},releaseLock(){}}}}};
 env.context.fetch=async()=>response;await env.run('exportHistoryRecord()');assert.equal(downloads,0);assert.equal(canceled,true);assert.equal(env.run('historyUI.exporting'),false);
});

test('stale inventory clears selection and does not automatically create a new capture',async()=>{
 const env=onlineHistory(),record=historyFixtureRecord();env.put('selectedHistory',record);env.run('historyUI.items=[selectedHistory];historyUI.selected=selectedHistory;historyUI.detailReady=true;historyUI.rawAvailable=true');
 let requests=0;env.context.fetch=async()=>{requests++;return historyFixtureResponse({},409)};
 await env.run('loadHistoryPage()');assert.equal(requests,1);assert.equal(env.run('historyUI.selected'),null);assert.equal(env.run('historyUI.inventory'),null);assert.equal(env.get('history-detail-panel').hidden,true);assert.equal(env.get('history-capture').disabled,false);assert.match(env.get('history-status').textContent,/new capture/);
});

test('history recovery reads survive profile loading failure and session or audited-mode changes clear private state',async()=>{
 const env=onlineHistory(),inventory=historyFixtureInventory(),record=historyFixtureRecord();env.run('state.offline=true;state.disconnected=true');
 env.context.fetch=async()=>historyFixtureResponse({inventory,items:[record],nextCursor:''});await env.run('loadHistoryPage()');assert.equal(env.run('historyUI.items.length'),1);
 env.run('historyUI.selected=historyUI.items[0];historyUI.job={private:"OLD_SESSION_PAYLOAD"};historyUI.detailReady=true;state.token="new-session";updateHistoryAvailability()');
 assert.equal(env.run('historyUI.items.length'),0);assert.equal(env.run('historyUI.selected'),null);assert.equal(env.get('history-panel').hidden,true);assert.equal(env.get('history-detail-panel').hidden,true);
 env.run('state.profileEditingOnly=true;updateHistoryAvailability()');assert.equal(env.get('system-history').disabled,true);assert.equal(env.get('history-capture').disabled,true);
});

test('history rejects response paths, unknown protection and mismatched detail revisions',async()=>{
 const inventory=historyFixtureInventory();
 for(const change of [{recordRef:'../private'},{protection:'deletion-allowed'},{revision:'PRIVATE_REVISION'}]){
  const env=onlineHistory();env.context.fetch=async()=>historyFixtureResponse({inventory,items:[historyFixtureRecord(change)],nextCursor:''});
  await env.run('loadHistoryPage()');assert.equal(env.run('historyUI.items.length'),0);assert.match(env.get('history-status').textContent,/could not be verified/);
 }
 const env=onlineHistory(),record=historyFixtureRecord();env.put('historyRows',[record]);env.run('historyUI.items=historyRows');
 env.context.fetch=async()=>historyFixtureResponse({record:{...record,revision:'e'.repeat(64)},job:{private:'WRONG_RECORD'},rawAvailable:true});await env.run('selectHistoryRecord("record_A")');
 assert.equal(env.run('historyUI.job'),null);assert.equal(env.get('history-export-record').disabled,true);assert.doesNotMatch(env.get('history-detail').textContent,/WRONG_RECORD/);
});

test('all four languages label history classifications and protection without exposing protocol names',()=>{
 const env=onlineHistory();env.put('historyRows',[historyFixtureRecord()]);env.run('historyUI.items=historyRows');
 for(const language of ['en','tr','ru','es']){env.put('historyLanguage',language);env.run('state.lang=historyLanguage;refreshHistoryLanguage()');assert.equal(env.run('t("historyProtected")').includes('retirement-unavailable'),false);for(const classification of ['canonical','legacy','malformed','oversized','special','unreadable']){env.put('historyClassification',classification);assert.notEqual(env.run('t("historyClass_"+historyClassification)'),'historyClass_'+classification);}}
});


test('canceling only the history capture refuses its late response without canceling a workflow',async()=>{
 const env=onlineHistory(),inventory=historyFixtureInventory();let resolveCapture,signal;const requests=[];
 env.context.fetch=(path,options)=>new Promise(resolve=>{requests.push(path);resolveCapture=resolve;signal=options.signal;});env.run('systemUI.plan={id:"reviewed-operation",ready:true};$("system-cancel").disabled=false');
 const capture=env.run('captureHistory()');assert.equal(env.get('history-cancel-capture').disabled,false);
 env.run('cancelHistoryCapture()');assert.equal(signal.aborted,true);assert.equal(env.get('history-cancel-capture').disabled,true);assert.match(env.get('history-status').textContent,/request canceled/);
 resolveCapture(historyFixtureResponse(inventory));await capture;assert.equal(env.run('historyUI.inventory'),null);assert.deepEqual(requests,['/api/v1/system/history/inventory']);assert.equal(env.run('systemUI.plan.id'),'reviewed-operation');assert.equal(env.get('system-cancel').disabled,false);assert.equal(env.run('historyUI.capturing'),false);
});


test('legacy history labels distinguish canonical opaque refs and oversized logical files remain visible',async()=>{
 const env=onlineHistory(),inventory={...historyFixtureInventory(),totalBytes:0};
 const refs=[0,1].map(slot=>Buffer.from(JSON.stringify({v:1,snapshot:'a'.repeat(48),slot})).toString('base64url'));
 env.put('legacyNameRows',refs.map(recordRef=>historyFixtureRecord({recordRef,id:'',classification:'legacy'})));
 const names=plain(env.run('legacyNameRows.map(historyRecordName)'));assert.notEqual(names[0],names[1]);assert.ok(names.every(name=>name.length<=80));
 const oversized=historyFixtureRecord({recordRef:refs[1],id:'',classification:'oversized',state:'unknown',size:20*1024*1024*1024,rawAvailable:false,revision:''});
 env.context.fetch=async()=>historyFixtureResponse({inventory,items:[oversized],nextCursor:''});await env.run('loadHistoryPage()');
 assert.equal(env.run('historyUI.items[0].size'),20*1024*1024*1024);assert.equal(env.run('historyUI.items[0].rawAvailable'),false);assert.match(env.get('history-status').textContent,/Showing 1/);
 const invalid=historyFixtureRecord({size:64*1024*1024+1});env.context.fetch=async()=>historyFixtureResponse({inventory,items:[invalid],nextCursor:''});await env.run('loadHistoryPage()');assert.match(env.get('history-status').textContent,/could not be verified/);
});


test('large history entries skip JSON detail parsing and keep exact private raw export available',async()=>{
 const env=onlineHistory(),record=historyFixtureRecord({size:3*1024*1024});env.put('historyRows',[record]);env.run('historyUI.items=historyRows');
 const routes=[];let downloaded;
 env.context.fetch=async path=>{routes.push(path);return new Response(new Uint8Array(record.size),{headers:{'Content-Type':'application/octet-stream','ETag':'"'+record.revision+'"','X-AccessWeaver-Revision':record.revision}})};
 env.context.downloadFile=data=>downloaded=data;
 await env.run('selectHistoryRecord("record_A")');assert.equal(routes.length,0);assert.equal(env.get('history-export-record').disabled,false);assert.match(env.get('history-detail').textContent,/too large for the desktop preview/);
 await env.run('exportHistoryRecord()');assert.equal(routes.length,1);assert.match(routes[0],/\/record_A\/export\?/);assert.equal(downloaded.size,record.size);
});

test('detail JSON overflow cancels preview and offers raw export only for the still-selected record',async()=>{
 const env=onlineHistory(),a=historyFixtureRecord(),b=historyFixtureRecord({recordRef:'record_B',revision:'e'.repeat(64)});env.put('historyRows',[a,b]);env.run('historyUI.items=historyRows');
 let canceled=false,reads=0;
 const oversized={ok:true,headers:new Headers({'Content-Type':'application/json'}),body:{getReader(){return {async read(){return {done:false,value:new Uint8Array(++reads===1?4*1024*1024:1)}},async cancel(){canceled=true},releaseLock(){}}}}};
 env.context.fetch=async()=>oversized;await env.run('selectHistoryRecord("record_A")');assert.equal(canceled,true);assert.equal(env.run('historyUI.job'),null);assert.equal(env.get('history-export-record').disabled,false);assert.match(env.get('history-detail').textContent,/too large/);
 let releaseA;env.context.fetch=path=>path.includes('/record_A?')?new Promise(resolve=>releaseA=resolve):Promise.resolve(historyFixtureResponse({record:b,job:{id:'current-B'},rawAvailable:true}));
 const pendingA=env.run('selectHistoryRecord("record_A")');await env.run('selectHistoryRecord("record_B")');reads=0;releaseA(oversized);await pendingA;assert.equal(env.run('historyUI.selected.recordRef'),'record_B');assert.equal(env.run('historyUI.job.id'),'current-B');assert.equal(env.run('historyUI.largePreview'),false);
});


test('history accepts an omitted final cursor but rejects non-string cursor values',async()=>{
 const env=onlineHistory(),inventory={...historyFixtureInventory(),count:0,totalBytes:0};env.context.fetch=async()=>historyFixtureResponse({inventory,items:[]});
 await env.run('loadHistoryPage()');assert.equal(env.run('historyUI.nextCursor'),'');assert.equal(env.run('historyUI.inventory.count'),0);assert.match(env.get('history-status').textContent,/Showing 0/);
 env.context.fetch=async()=>historyFixtureResponse({inventory,items:[],nextCursor:null});await env.run('loadHistoryPage()');assert.match(env.get('history-status').textContent,/could not be verified/);
});


test('history row buttons keep full48hex identity accessible while shortening visible labels',()=>{
 const env=onlineHistory(),record=historyFixtureRecord();env.put('historyRows',[record]);env.run('historyUI.items=historyRows;renderHistoryRows()');
 const button=env.get('history-rows').children[0].children[0].children[0];assert.equal(button.textContent,record.id.slice(0,8)+'…'+record.id.slice(-6));assert.equal(button.getAttribute('title'),record.id);assert.equal(button.getAttribute('aria-label'),button.textContent+': '+record.id);
 env.run('historyUI.selected=historyUI.items[0];renderHistoryDetail()');assert.match(env.get('history-detail-title').textContent,new RegExp(record.id));
});


test('actual Go history wire fixtures satisfy desktop paging, detail and exact raw export',{skip:!process.env.ACCESSWEAVER_HISTORY_INTEROP},async()=>{
 const path=require('node:path'),crypto=require('node:crypto');
 const sources=['go.mod','go.sum','internal/fileinput/fileinput.go','internal/fileinput/native_unix.go','internal/fileinput/native_windows.go','internal/api/history_lifecycle.go','internal/api/history.go','internal/api/history_browser.go','internal/api/history_browser_test.go','internal/api/history_staging_test.go','internal/api/history_browser_interop_test.go','internal/api/server.go','internal/api/workflow_json.go','internal/api/workflows.go','internal/api/audit.go','internal/api/mutations.go','internal/workflow/lifecycle.go','internal/workflow/lifecycle_manifest.go','internal/workflow/history.go','internal/workflow/history_capture.go','internal/workflow/history_staging.go','internal/workflow/history_index.go','internal/workflow/history_inventory.go','internal/workflow/history_record.go','internal/workflow/history_replace_unix.go','internal/workflow/history_replace_windows.go','internal/workflow/manager.go','internal/workflow/outcome.go','internal/workflow/persistence_observation.go','internal/workflow/output.go','internal/workflow/result.go','internal/workflow/store.go','web/system.js','web/app.js','web/locales.js','web/index.html','web/app.css','web/app.test.cjs'];
 const payloadNames=['lifecycle-none.json','inventory.json','page-first.json','page-last.json','detail.json','raw.bin','pending-error.json'],names=[...payloadNames,'manifest.json'];
 const directory=path.resolve(process.env.ACCESSWEAVER_HISTORY_INTEROP),repo=path.resolve(__dirname,'..'),hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
 const keys=(value,expected)=>assert.deepEqual(Object.keys(value).sort(),[...expected].sort(),'Source interop schema contains unexpected fields');
 const same=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
 function readChecked(root,name,maximum){
  let fd;
  try{
   const target=path.join(root,name),before=fs.lstatSync(target,{bigint:true});
   assert.ok(before.isFile()&&!before.isSymbolicLink()&&before.size>=0n&&before.size<=BigInt(maximum),'Source interop file is not a bounded regular file');
   fd=fs.openSync(target,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const opened=fs.fstatSync(fd,{bigint:true});assert.ok(same(before,opened),'Source interop file changed while opening');
   const chunks=[];let total=0;
   for(;;){const buffer=Buffer.alloc(Math.min(32*1024,maximum+1-total)),n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;total+=n;assert.ok(total<=maximum,'Source interop file exceeded its bound');chunks.push(buffer.subarray(0,n));}
   const after=fs.fstatSync(fd,{bigint:true});assert.ok(same(opened,after)&&opened.size===after.size&&BigInt(total)===opened.size,'Source interop file changed while reading');
   return Buffer.concat(chunks,total);
  }catch(error){if(error?.code)assert.fail('Source interop file is unavailable');throw error;}
  finally{if(fd!==undefined){try{fs.closeSync(fd)}catch{assert.fail('Source interop file did not close')}}}
 }
 let identity;
 try{identity=fs.lstatSync(directory,{bigint:true});assert.ok(identity.isDirectory()&&!identity.isSymbolicLink(),'Source interop root is not an ordinary directory');assert.deepEqual(fs.readdirSync(directory).sort(),[...names].sort(),'Source interop directory contains unexpected files');}catch(error){if(error?.code)assert.fail('Source interop root is unavailable');throw error;}
 const parse=bytes=>JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 const manifest=parse(readChecked(directory,'manifest.json',128*1024));keys(manifest,['schemaVersion','sources','files','expected']);assert.equal(manifest.schemaVersion,1);
 assert.ok(Array.isArray(manifest.sources)&&manifest.sources.length===sources.length);assert.deepEqual(manifest.sources.map(item=>item.name).sort(),[...sources].sort());
 for(const entry of manifest.sources){keys(entry,['name','sha256']);assert.ok(sources.includes(entry.name)&&/^[a-f0-9]{64}$/.test(entry.sha256));assert.equal(hash(readChecked(repo,entry.name,8*1024*1024)),entry.sha256,'Source interop does not match this checkout');}
 assert.ok(Array.isArray(manifest.files)&&manifest.files.length===payloadNames.length);assert.deepEqual(manifest.files.map(item=>item.name).sort(),[...payloadNames].sort());
 const bytes={},metadata={};
 for(const entry of manifest.files){
  assert.ok(payloadNames.includes(entry.name),'Source interop filename is not allowed');keys(entry,entry.name==='raw.bin'?['name','size','sha256','contentType','status','etag','xAccessWeaverRevision']:['name','size','sha256','contentType','status']);
  assert.ok(Number.isSafeInteger(entry.size)&&entry.size>=0&&/^[a-f0-9]{64}$/.test(entry.sha256));assert.equal(entry.status,entry.name==='pending-error.json'?409:200);bytes[entry.name]=readChecked(directory,entry.name,entry.name==='raw.bin'?64*1024*1024:entry.name==='pending-error.json'?4096:4*1024*1024);assert.equal(bytes[entry.name].length,entry.size);assert.equal(hash(bytes[entry.name]),entry.sha256);
  assert.ok(entry.name==='raw.bin'?entry.contentType==='application/octet-stream':/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(entry.contentType));metadata[entry.name]=entry;
 }
 keys(manifest.expected,['snapshot','canonicalRef','canonicalRevision','canonicalID','rawRef','rawRevision']);const expected=manifest.expected;
 assert.match(expected.snapshot,/^[a-f0-9]{48}$/);assert.equal(expected.canonicalID,'a'.repeat(48));assert.match(expected.canonicalRevision,/^[a-f0-9]{64}$/);assert.match(expected.rawRevision,/^[a-f0-9]{64}$/);
 for(const ref of [expected.canonicalRef,expected.rawRef])assert.match(ref,/^[A-Za-z0-9_-]{1,256}$/);assert.notEqual(expected.canonicalRef,expected.rawRef);
 assert.deepEqual(bytes['raw.bin'],Buffer.from([0xff,0x7b,0,0x58]));assert.equal(expected.rawRevision,hash(bytes['raw.bin']));assert.equal(metadata['raw.bin'].etag,'"'+expected.rawRevision+'"');assert.equal(metadata['raw.bin'].xAccessWeaverRevision,expected.rawRevision);
 const inventory=parse(bytes['inventory.json']),first=parse(bytes['page-first.json']),last=parse(bytes['page-last.json']),detail=parse(bytes['detail.json']);
 assert.equal(inventory.snapshot,expected.snapshot);assert.equal(inventory.count,2);assert.equal(first.items.length,1);assert.equal(last.items.length,1);assert.ok(first.nextCursor);assert.equal(Object.hasOwn(last,'nextCursor'),false);
 const records=[...first.items,...last.items],canonical=records.find(item=>item.recordRef===expected.canonicalRef),raw=records.find(item=>item.recordRef===expected.rawRef);
 assert.ok(canonical&&raw);assert.equal(canonical.id,expected.canonicalID);assert.equal(canonical.revision,expected.canonicalRevision);assert.equal(raw.revision,expected.rawRevision);assert.equal(raw.size,bytes['raw.bin'].length);assert.equal(detail.record.recordRef,expected.canonicalRef);assert.equal(detail.job.id,expected.canonicalID);
 const pendingError=parse(bytes['pending-error.json']);keys(pendingError,['error','code']);assert.equal(pendingError.code,'history-staging-pending');assert.ok(typeof pendingError.error==='string'&&pendingError.error.length>0&&pendingError.error.length<=256);
 const env=onlineHistory();let downloaded,capturePosts=0,recordExports=0;
 env.context.downloadFile=(data,name,mime)=>downloaded={data,name,mime};
 env.context.fetch=async(target,options)=>{
  const url=new URL(target,'http://localhost');
  if(url.pathname==='/api/v1/system/history/lifecycle')return new Response(bytes['lifecycle-none.json'],{headers:{'Content-Type':metadata['lifecycle-none.json'].contentType}});
  if(url.pathname==='/api/v1/system/history/inventory'){assert.equal(options.method,'POST');assert.equal(options.body,'{}');capturePosts++;assert.ok(capturePosts<=2);const name=capturePosts===1?'inventory.json':'pending-error.json';return new Response(bytes[name],{status:metadata[name].status,headers:{'Content-Type':metadata[name].contentType}});}
  if(url.pathname==='/api/v1/system/history/page'){const name=url.searchParams.has('cursor')?'page-last.json':'page-first.json';return new Response(bytes[name],{headers:{'Content-Type':metadata[name].contentType}});}
  if(url.pathname==='/api/v1/system/history/records/'+expected.canonicalRef){assert.equal(url.searchParams.get('revision'),expected.canonicalRevision);return new Response(bytes['detail.json'],{headers:{'Content-Type':metadata['detail.json'].contentType}});}
  // The six-payload producer carries canonical detail. This metadata-only reply
  // composes its actual malformed row with the already tested raw-only UI state.
  if(url.pathname==='/api/v1/system/history/records/'+expected.rawRef){assert.equal(url.searchParams.get('revision'),expected.rawRevision);return historyFixtureResponse({record:raw,rawAvailable:true});}
  recordExports++;assert.equal(url.pathname,'/api/v1/system/history/records/'+expected.rawRef+'/export');assert.equal(url.searchParams.get('revision'),expected.rawRevision);
  return new Response(bytes['raw.bin'],{headers:{'Content-Type':metadata['raw.bin'].contentType,'ETag':metadata['raw.bin'].etag,'X-AccessWeaver-Revision':metadata['raw.bin'].xAccessWeaverRevision}});
 };
 await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleUI.status.state'),'none');assert.equal(env.run('workflowLifecycleUI.status.admissionBlocked'),false);
 await env.run('captureHistory()');assert.equal(env.run('historyUI.inventory.snapshot'),expected.snapshot);
 await env.run('historyNextPage()');assert.equal(env.run('historyUI.nextCursor'),'');assert.equal(env.get('history-next').disabled,true);
 const canonicalFirst=first.items[0].recordRef===expected.canonicalRef;if(canonicalFirst)await env.run('historyPreviousPage()');
 env.put('interopCanonicalRef',expected.canonicalRef);await env.run('selectHistoryRecord(interopCanonicalRef)');assert.deepEqual(plain(env.run('historyUI.job')),detail.job);
 if(canonicalFirst)await env.run('historyNextPage()');else await env.run('historyPreviousPage()');
 env.put('interopRawRef',expected.rawRef);await env.run('selectHistoryRecord(interopRawRef)');await env.run('exportHistoryRecord()');
 assert.ok(downloaded);assert.equal(downloaded.name,'accessweaver-workflow-record.bin');assert.equal(downloaded.mime,'application/octet-stream');assert.deepEqual(Buffer.from(await downloaded.data.arrayBuffer()),bytes['raw.bin']);
 // The pending proof uses the actual canonical page/detail, never the explicit
 // malformed-row detail composition above. Revalidation is GET-only.
 if(canonicalFirst)await env.run('historyPreviousPage()');else await env.run('historyNextPage()');
 await env.run('selectHistoryRecord(interopCanonicalRef)');const exportsBeforePending=recordExports;
 await env.run('captureHistory()');assert.equal(capturePosts,2);assert.equal(recordExports,exportsBeforePending);assert.equal(env.run('historyUI.inventory.snapshot'),expected.snapshot);assert.equal(env.run('historyUI.selected.recordRef'),expected.canonicalRef);assert.equal(env.run('historyUI.selected.revision'),expected.canonicalRevision);assert.deepEqual(plain(env.run('historyUI.job')),detail.job);assert.equal(env.run('historyUI.message'),'historyStagingPending');assert.equal(env.get('history-export-record').disabled,false);
 const after=fs.lstatSync(directory,{bigint:true});assert.ok(same(identity,after),'Source interop root changed');assert.deepEqual(fs.readdirSync(directory).sort(),[...names].sort());
});

// Local completion metadata source contracts; no workflow/native child runs.
function lifecycleFixture(state='none'){return {state,admissionBlocked:['intent','sealed','blocked'].includes(state),protection:'retirement-unavailable',...(['intent','sealed','released'].includes(state)?{jobId:'a'.repeat(48)}:{})};}
test('completion tracking is read-only, localized and independent of profile loading and current-job controls',async()=>{
 const env=onlineHistory(),requests=[];env.run('state.offline=true;state.profiles=[];systemUI.plan={id:"kept",ready:true};$("system-consent").checked=true;$("system-cancel").disabled=false');
 assert.equal(env.run('coreAvailable()'),false);env.run('updateHistoryAvailability()');assert.equal(env.get('history-lifecycle-refresh').disabled,false);assert.equal(requests.length,0);
 env.context.fetch=async(path,options)=>{requests.push({path,options});return historyFixtureResponse(lifecycleFixture('released'))};
 await env.run('refreshWorkflowLifecycle()');assert.equal(requests.length,1);assert.equal(requests[0].path,'/api/v1/system/history/lifecycle');assert.equal(requests[0].options.method,'GET');assert.equal(requests[0].options.headers['X-AccessWeaver-Token'],'history-session');assert.equal(requests[0].options.redirect,'error');
 assert.equal(env.run('systemUI.plan.id'),'kept');assert.equal(env.get('system-consent').checked,true);assert.equal(env.get('system-cancel').disabled,false);assert.match(env.get('history-lifecycle-status').textContent,/Vendor cleanup.*not certified/);
 for(const lang of ['en','tr','ru','es']){env.put('lifecycleLanguage',lang);env.run('state.lang=lifecycleLanguage');for(const state of ['none','intent','sealed','released','blocked']){env.put('projection',lifecycleFixture(state));env.run('workflowLifecycleUI.status=lifecycleProjection(projection);renderWorkflowLifecycle()');assert.notEqual(env.get('history-lifecycle-status').textContent,'lifecycleState_'+state);assert.ok(env.get('history-lifecycle-status').textContent.length>30);}}
});
test('completion status refuses contradictory or oversized replies and never keeps an old clean projection after failure',async()=>{
 const env=onlineHistory();env.context.fetch=async()=>historyFixtureResponse(lifecycleFixture('released'));await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleUI.status.state'),'released');
 for(const response of [{...lifecycleFixture('released'),admissionBlocked:true},{...lifecycleFixture('none'),jobId:'a'.repeat(48)},{...lifecycleFixture('intent'),jobId:'private/path'}, {...lifecycleFixture(),state:'vendor-clean'}]){env.context.fetch=async()=>historyFixtureResponse(response);await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleUI.status'),null);assert.match(env.get('history-lifecycle-status').textContent,/could not be verified/);}
 env.context.fetch=async()=>historyFixtureResponse({private:'PRIVATE_RAW_ERROR'},503);await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleUI.status'),null);assert.doesNotMatch(env.get('history-lifecycle-status').textContent,/PRIVATE_RAW_ERROR/);assert.match(env.get('history-lifecycle-status').textContent,/busy or unavailable/);
 env.context.fetch=async()=>historyFixtureResponse({private:'x'.repeat(5000)});await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleUI.status'),null);assert.equal(env.get('system-cancel').disabled,false);
});
test('late completion responses cannot cross navigation, session or audited mode generations',async()=>{
 for(const change of ['state.token="new-session";updateHistoryAvailability()','state.profileEditingOnly=true;updateHistoryAvailability()','state.view="profiles";historyNavigationChanged("profiles")']){
  const env=onlineHistory();let finish,signal;env.context.fetch=(_path,options)=>{signal=options.signal;return new Promise(resolve=>finish=resolve)};
  const request=env.run('refreshWorkflowLifecycle()');assert.equal(env.get('history-lifecycle-refresh').disabled,true);env.run(change);assert.equal(signal.aborted,true);assert.match(env.get('history-lifecycle-status').textContent,/has not been read/);finish(historyFixtureResponse(lifecycleFixture('released')));await request;assert.equal(env.run('workflowLifecycleUI.status'),null);assert.doesNotMatch(env.get('history-lifecycle-job').textContent,/[a-f0-9]{48}/);
 }
 const env=onlineHistory();let finish;env.context.fetch=()=>new Promise(resolve=>finish=resolve);const old=env.run('refreshWorkflowLifecycle()');env.run('resetWorkflowLifecycle()');env.context.fetch=async()=>historyFixtureResponse(lifecycleFixture('sealed'));await env.run('refreshWorkflowLifecycle()');finish(historyFixtureResponse(lifecycleFixture('released')));await old;assert.equal(env.run('workflowLifecycleUI.status.state'),'sealed');assert.equal(env.get('system-apply').disabled,true);
});
test('pending workflow admission preserves inputs, clears consent and exposes inspection without replaying mutations',async()=>{
 const env=onlineHistory(),calls=[];env.run('systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true;$("system-applications").value="private existing folder";$("system-journal").value="recovery.json";$("system-cancel").disabled=false');
 env.context.fetch=async(path,options)=>{calls.push({path,options});return historyFixtureResponse({error:'PRIVATE_OS_ERROR',code:'workflow-lifecycle-pending'},409)};
 await env.run('applySystem()');assert.equal(calls.length,1);assert.equal(calls[0].path,'/api/v1/system/start');assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-consent').checked,false);assert.equal(env.get('system-applications').value,'private existing folder');assert.equal(env.get('system-journal').value,'recovery.json');assert.equal(env.get('system-cancel').disabled,false);assert.equal(env.run('historyUI.open'),true);assert.equal(env.run('workflowLifecycleUI.status.state'),'blocked');assert.equal(env.get('system-apply').disabled,true);assert.doesNotMatch(env.get('system-output').textContent,/PRIVATE_OS_ERROR/);assert.match(env.get('system-output').textContent,/Nothing is retried automatically/);
 await env.run('applySystem()');assert.equal(calls.length,1);env.run('state.view="settings";historyNavigationChanged("settings");state.view="system";updateHistoryAvailability()');assert.equal(env.run('workflowLifecycleBlocked()'),true);env.context.fetch=async()=>historyFixtureResponse(lifecycleFixture('released'));await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleUI.status.state'),'released');assert.equal(env.run('workflowLifecycleBlocked()'),true);assert.equal(env.get('history-lifecycle-blocked').hidden,false);env.context.fetch=async()=>historyFixtureResponse({},503);await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleBlocked()'),true);assert.equal(env.get('system-apply').disabled,true);env.context.fetch=async()=>historyFixtureResponse({},409);await env.run('refreshWorkflowLifecycle()');assert.equal(env.run('workflowLifecycleUI.status.state'),'blocked');
});
test('pending start response from an expired session cannot expose private completion state',async()=>{
 const env=onlineHistory();env.run('systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true');let finish;
 env.context.fetch=()=>new Promise(resolve=>finish=resolve);const request=env.run('applySystem()');env.run('state.token="new-session";updateHistoryAvailability()');finish(historyFixtureResponse({error:'private',code:'workflow-lifecycle-pending'},409));await request;assert.equal(env.run('workflowLifecycleUI.status'),null);assert.equal(env.run('historyUI.open'),false);assert.doesNotMatch(env.get('system-output').textContent,/private/);
});

test('an earlier completion read cannot clear a later unresolved admission refusal',async()=>{
 const env=onlineHistory();let finish;env.run('systemUI.plan={id:"reviewed",ready:true};$("system-consent").checked=true');
 env.context.fetch=path=>path.endsWith('/lifecycle')?new Promise(resolve=>finish=resolve):Promise.resolve(historyFixtureResponse({code:'workflow-lifecycle-pending',error:'fixed'},409));
 const read=env.run('refreshWorkflowLifecycle()');await env.run('applySystem()');assert.equal(env.run('workflowLifecycleBlocked()'),true);finish(historyFixtureResponse(lifecycleFixture('released')));await read;
 assert.equal(env.run('workflowLifecycleUI.status.state'),'blocked');assert.equal(env.run('workflowLifecycleUI.loading'),false);assert.equal(env.get('system-apply').disabled,true);
});

// Diagnostic lifecycle fixtures use deferred source replies. They deliberately
// ignore fetch abort to prove stale callbacks cannot publish or release owners.
function onlineProbe(){const env=environment();env.run('state.view="diagnostics";state.loading=false;state.offline=false;state.disconnected=false;state.coreAuthenticated=true;state.token="diagnostic-session";updateProbeAvailability()');return env;}
function probeFixtureReport(host='discord.com',overrides={}){return {host,port:443,path:'direct',transport:'tcp',at:'2026-11-01T00:00:00Z',checks:[{name:'TCP',status:'ok',durationMs:1,detail:'Source-only fixture'}],...overrides};}
function diagnosticResponse(report,status=200){return {ok:status>=200&&status<300,status,json:async()=>report};}

test('external API abort signals are isolated and listeners plus timers close on every terminal path',async()=>{
 const {getEventListeners}=require('node:events'),env=environment(),first=new AbortController(),second=new AbortController(),pending=[],timers=new Set();let timer=0;
 env.context.firstSignal=first.signal;env.context.secondSignal=second.signal;
 env.context.setTimeout=()=>{const id=++timer;timers.add(id);return id};env.context.clearTimeout=id=>timers.delete(id);
 env.context.fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({path,signal:options.signal,resolve,reject}));
 const a=env.run('apiRequest("/api/v1/synthetic-first","GET",undefined,1000,firstSignal)'),b=env.run('apiRequest("/api/v1/synthetic-second","GET",undefined,1000,secondSignal)');
 assert.equal(getEventListeners(first.signal,'abort').length,1);assert.equal(getEventListeners(second.signal,'abort').length,1);first.abort();assert.equal(pending[0].signal.aborted,true);assert.equal(pending[1].signal.aborted,false);
 pending[0].reject(new DOMException('source cancellation','AbortError'));pending[1].resolve(diagnosticResponse({ok:true}));await assert.rejects(a,{name:'AbortError'});assert.deepEqual(plain(await b),{ok:true});assert.equal(timers.size,0);assert.equal(getEventListeners(first.signal,'abort').length,0);assert.equal(getEventListeners(second.signal,'abort').length,0);
 const ended=new AbortController();ended.abort();env.context.endedSignal=ended.signal;let sends=0;env.context.fetch=async()=>{sends++;return diagnosticResponse({})};await assert.rejects(env.run('apiRequest("/api/v1/synthetic-ended","GET",undefined,1000,endedSignal)'),{name:'AbortError'});assert.equal(sends,0);assert.equal(timers.size,0);
 const fault=new AbortController();env.context.faultSignal=fault.signal;env.context.fetch=async()=>({ok:true,json:async()=>{throw Error('source decode fault')}});await assert.rejects(env.run('apiRequest("/api/v1/synthetic-parse","GET",undefined,1000,faultSignal)'));assert.equal(getEventListeners(fault.signal,'abort').length,0);assert.equal(timers.size,0);
});

test('explicit diagnostic cancellation preserves inputs and other operations while discarding late success',async()=>{
 const env=onlineProbe();let resolve,signal;const requests=[];env.get('probe-host').value='private-target.example';env.get('probe-path').value='socks5';env.get('probe-proxy').value='127.0.0.1:1080';env.run('state.busy=true;state.supportExporting=true');
 env.context.fetch=(path,options)=>{requests.push({path,options});signal=options.signal;return new Promise(done=>resolve=done)};
 const running=env.run('runProbe()');assert.equal(env.get('probe-cancel').disabled,false);assert.equal(env.get('probe-submit').disabled,true);assert.equal(requests.length,1);assert.equal(JSON.parse(requests[0].options.body).proxy,'127.0.0.1:1080');
 env.run('cancelProbe()');assert.equal(signal.aborted,true);assert.equal(env.run('state.probing'),false);assert.equal(env.run('state.busy'),true);assert.equal(env.run('state.supportExporting'),true);assert.equal(env.get('probe-host').value,'private-target.example');assert.equal(env.get('probe-proxy').value,'127.0.0.1:1080');assert.equal(env.get('probe-cancel').disabled,true);assert.match(env.get('diagnostic-results').textContent,/Cancellation requested/);
 resolve(diagnosticResponse(probeFixtureReport('LATE_PRIVATE_TARGET')));await running;assert.equal(env.run('state.lastProbe'),null);assert.equal(env.get('export-report').hidden,true);assert.equal(env.get('diagnostic-meta').hidden,true);assert.doesNotMatch(env.get('diagnostic-results').textContent,/LATE_PRIVATE_TARGET/);assert.equal(requests.length,1);
});

test('late canceled diagnostic success and error cannot finish or overwrite a newer diagnostic',async()=>{
 for(const oldError of [false,true]){
  const env=onlineProbe(),pending=[];env.context.fetch=(_path,options)=>new Promise((resolve,reject)=>pending.push({resolve,reject,signal:options.signal}));
  const old=env.run('runProbe()');env.run('cancelProbe()');env.get('probe-host').value='new.example';const current=env.run('runProbe()');
  if(oldError)pending[0].reject(Error('LATE_PRIVATE_ERROR'));else pending[0].resolve(diagnosticResponse(probeFixtureReport('old.example')));await old;
  assert.equal(env.run('state.probing'),true);assert.equal(env.get('probe-submit').disabled,true);assert.equal(env.get('probe-cancel').disabled,false);assert.equal(pending[1].signal.aborted,false);assert.equal(env.run('state.lastProbe'),null);assert.doesNotMatch(env.get('diagnostic-results').textContent,/LATE_PRIVATE_ERROR|old.example/);
  pending[1].resolve(diagnosticResponse(probeFixtureReport('new.example')));await current;assert.equal(env.run('state.lastProbe.host'),'new.example');assert.equal(env.get('probe-submit').disabled,false);assert.equal(env.get('probe-cancel').disabled,true);assert.equal(env.get('export-report').hidden,false);
 }
});

test('diagnostic navigation, inputs, session, mode and connection resets abort and clear private results',async()=>{
 for(const change of ['navigate("settings")','$("probe-host").value="changed.example";probeInputsChanged()','state.token="replacement-session";updateProbeAvailability()','state.profileEditingOnly=true;updateProbeAvailability()','state.offline=true;updateProbeAvailability()','state.disconnected=true;updateProbeAvailability()','state.loading=true;updateProbeAvailability()','state.coreAuthenticated=false;updateProbeAvailability()']){
  const env=onlineProbe();let resolve,signal;env.context.fetch=(_path,options)=>{signal=options.signal;return new Promise(done=>resolve=done)};
  const running=env.run('runProbe()');env.run(change);assert.equal(signal.aborted,true);resolve(diagnosticResponse(probeFixtureReport('LATE_PRIVATE_RESULT')));await running;
  assert.equal(env.run('state.lastProbe'),null);assert.equal(env.run('probeUI.completed'),null);assert.equal(env.run('state.probing'),false);assert.equal(env.get('export-report').hidden,true);assert.equal(env.get('diagnostic-meta').hidden,true);assert.doesNotMatch(env.get('diagnostic-results').textContent,/LATE_PRIVATE_RESULT/);
 }
});

test('a profile-only bootstrap clears an in-flight diagnostic before a later profile read fails',async()=>{
 const env=onlineProbe();let resolve,signal;env.context.fetch=(path,options)=>path==='/api/v1/diagnose'?(signal=options.signal,new Promise(done=>resolve=done)):Promise.resolve(path==='/api/bootstrap'?diagnosticResponse({platform:'linux',profileEditingOnly:true}):path==='/api/v1/profiles'?diagnosticResponse({error:'private profile failure'},500):diagnosticResponse([]));
 const running=env.run('runProbe()');await assert.rejects(env.run('readCore()'));assert.equal(signal.aborted,true);assert.equal(env.get('probe-submit').disabled,true);resolve(diagnosticResponse(probeFixtureReport('OLD_SESSION_TARGET')));await running;assert.equal(env.run('state.lastProbe'),null);assert.equal(env.get('export-report').hidden,true);
});

test('diagnostic export belongs only to the completed unchanged request and current session',async()=>{
 const env=onlineProbe(),downloads=[];env.context.downloadFile=(data,name)=>downloads.push({data,name});env.context.fetch=async()=>diagnosticResponse(probeFixtureReport());
 await env.run('runProbe()');env.run('exportProbeReport()');assert.equal(downloads.length,1);assert.equal(JSON.parse(downloads[0].data).host,'discord.com');
 env.get('probe-host').value='changed-without-event.example';env.run('exportProbeReport()');assert.equal(downloads.length,1);assert.equal(env.run('state.lastProbe'),null);assert.equal(env.get('export-report').hidden,true);
 await env.run('runProbe()');env.run('state.token="new-session";exportProbeReport()');assert.equal(downloads.length,1);assert.equal(env.run('state.lastProbe'),null);
 const noSend=onlineProbe();let sends=0;noSend.context.fetch=async()=>{sends++;return diagnosticResponse(probeFixtureReport())};noSend.run('state.profileEditingOnly=true');await noSend.run('runProbe()');assert.equal(sends,0);
});

test('diagnostic busy feedback is localized without replay and preserves the reviewed test inputs',async()=>{
 for(const lang of ['en','tr','ru','es']){
  const env=onlineProbe();env.context.langFixture=lang;env.run('state.lang=langFixture');env.get('probe-host').value='chosen.example';let sends=0;
  env.context.fetch=async()=>{sends++;return diagnosticResponse({error:'PRIVATE_BUSY_CAUSE',code:'diagnostic-busy'},503)};await env.run('runProbe()');assert.equal(sends,1);assert.equal(env.get('probe-host').value,'chosen.example');assert.equal(env.get('export-report').hidden,true);assert.equal(env.get('probe-submit').disabled,false);assert.equal(env.get('probe-cancel').disabled,true);assert.equal(env.get('diagnostic-results').textContent,env.run('t("probeBusy")'));assert.doesNotMatch(env.get('diagnostic-results').textContent,/PRIVATE_BUSY_CAUSE|diagnostic-busy/);
  for(const key of ['probeCancel','probeCanceled','probeInputsCleared','probeContextCleared','probeViewCleared','probeBusy','probeRequestEnded']){env.context.copyKey=key;assert.notEqual(env.run('t(copyKey)'),key);}
  env.context.fetch=async()=>{sends++;return diagnosticResponse(probeFixtureReport('chosen.example'))};await env.run('runProbe()');assert.equal(sends,2);assert.equal(env.run('state.lastProbe.host'),'chosen.example');
 }
});

test('diagnostic timeouts during fetch and JSON body consumption cannot publish a late success',async()=>{
 for(const phase of ['fetch','body']){
  const env=onlineProbe();let timeout,finish,signal,bodyEntered=false;env.context.setTimeout=callback=>{timeout=callback;return 1};env.context.clearTimeout=()=>{};
  env.context.fetch=(_path,options)=>{signal=options.signal;return phase==='fetch'?new Promise(resolve=>finish=resolve):Promise.resolve({ok:true,json:()=>{bodyEntered=true;return new Promise(resolve=>finish=resolve)}})};
  const running=env.run('runProbe()');if(phase==='body'){for(let i=0;i<4&&!bodyEntered;i++)await Promise.resolve();assert.equal(bodyEntered,true);}
  timeout();assert.equal(signal.aborted,true);if(phase==='fetch')finish(diagnosticResponse(probeFixtureReport('LATE_TIMEOUT_RESULT')));else finish(probeFixtureReport('LATE_TIMEOUT_RESULT'));await running;
  assert.equal(env.run('state.lastProbe'),null);assert.equal(env.get('export-report').hidden,true);assert.equal(env.get('probe-submit').disabled,false);assert.match(env.get('diagnostic-results').textContent,/ended before completion/);assert.doesNotMatch(env.get('diagnostic-results').textContent,/LATE_TIMEOUT_RESULT/);
 }
 const env=onlineProbe();let fail;env.context.fetch=async()=>({ok:true,json:()=>new Promise((_resolve,reject)=>fail=reject)});const request=env.run('apiRequest("/api/v1/synthetic-body")');for(let i=0;i<4&&!fail;i++)await Promise.resolve();fail(new DOMException('source body aborted','AbortError'));await assert.rejects(request,{name:'AbortError'});
});

// Reviewed reconciliation source contracts. No filesystem, owner, worker or
// managed-policy authority is simulated by these browser-state fixtures.
const reconciliationBaseFixture='/api/v1/system/history/reconciliation';
function reconciliationPlanFixture(overrides={}){return {id:'1'.repeat(48),reviewRevision:'2'.repeat(64),operationId:'3'.repeat(48),generation:'4'.repeat(48),action:'retry-local-release-ack',expiresAt:new Date(Date.now()+60000).toISOString(),intentSHA256:'5'.repeat(64),sealSHA256:'6'.repeat(64),objects:[{ref:'7'.repeat(64),role:'closed-ack-stage',size:42,sha256:'8'.repeat(64)}],resume:false,scope:'original-local-owners-only',protection:'retirement-unavailable',...overrides};}
function reconciliationReceiptFixture(plan=reconciliationPlanFixture(),overrides={}){return {operationId:plan.operationId,generation:plan.generation,state:'completed',action:plan.action,intentSHA256:plan.intentSHA256,sealSHA256:plan.sealSHA256,ackSHA256:'9'.repeat(64),quarantined:plan.objects,completedAt:new Date().toISOString(),scope:plan.scope,protection:plan.protection,...overrides};}
function reconciliationStatusFixture(state='available',overrides={}){return {state,canPreview:state==='available',resumeAvailable:false,scope:'original-local-owners-only',protection:'retirement-unavailable',...(['available','pending','completed'].includes(state)?{generation:'4'.repeat(48)}:{}),...(['pending','completed'].includes(state)?{operationId:'3'.repeat(48)}:{}),...overrides};}
function reconciliationTimers(env){let serial=0;const timers=new Map();env.context.setTimeout=(fn,ms)=>{const id=++serial;timers.set(id,{fn,ms});return id;};env.context.clearTimeout=id=>timers.delete(id);return {timers,async fire(ms){const found=[...timers].find(([,timer])=>timer.ms===ms);assert.ok(found,'Expected controlled timer '+ms);timers.delete(found[0]);await found[1].fn();}};}
test('reconciliation requires separate explicit review and consent; own exact receipt preserves original job and refreshes local tracking',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture(),calls=[];env.put('originalJob',{id:'failed-original',state:'failed',error:'Original failure retained'});env.run('systemUI.job=originalJob;$("system-output").textContent="Original failure retained";$("system-applications").value="kept inputs";$("system-journal").value="kept recovery";$("system-cancel").disabled=false;workflowLifecycleUI.admissionRefused=true;globalThis.realTrackingReads=0;refreshWorkflowLifecycle=async()=>{realTrackingReads++}');
 env.context.fetch=async(path,options)=>{calls.push({path,options});return historyFixtureResponse(path.endsWith('/preview')?plan:reconciliationReceiptFixture(plan));};
 await env.run('applyReconciliation()');assert.equal(calls.length,0);await env.run('previewReconciliation()');assert.deepEqual(JSON.parse(calls[0].options.body),{});assert.equal(env.get('reconcile-apply').disabled,true);assert.equal(env.get('reconcile-consent').checked,false);assert.equal(env.context.document.activeElement.id,'reconcile-review-title');assert.equal(env.get('reconcile-operation').value,plan.operationId);
 await env.run('applyReconciliation()');assert.equal(calls.length,1);env.get('reconcile-consent').checked=true;await env.run('applyReconciliation()');assert.deepEqual(JSON.parse(calls[1].options.body),{planId:plan.id,confirm:true});assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.run('reconciliationUI.receipt.state'),'completed');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),false);assert.equal(env.context.realTrackingReads,1);assert.equal(env.get('reconcile-consent').checked,false);await env.run('applyReconciliation()');assert.equal(calls.length,2);
 assert.deepEqual(plain(env.run('systemUI.job')),{id:'failed-original',state:'failed',error:'Original failure retained'});assert.equal(env.get('system-output').textContent,'Original failure retained');assert.equal(env.get('system-applications').value,'kept inputs');assert.equal(env.get('system-journal').value,'kept recovery');assert.equal(env.get('system-cancel').disabled,false);assert.equal(env.run('systemUI.busy'),false);assert.equal(env.run('reconciliationUI.message'),'reconcileCompleted');
});
test('reconciliation schema rejects contradictory status, missing review binding and unbounded or mismatched object metadata',()=>{
 const env=onlineHistory();for(const value of [reconciliationStatusFixture('none',{generation:'4'.repeat(48)}),reconciliationStatusFixture('available',{canPreview:false}),reconciliationStatusFixture('pending',{canPreview:true}),reconciliationStatusFixture('completed',{resumeAvailable:true}),reconciliationStatusFixture('unavailable',{operationId:'3'.repeat(48)}),reconciliationStatusFixture('vendor-clean'),reconciliationStatusFixture('available',{generation:'private/path'})]){env.put('badProjection',value);assert.throws(()=>env.run('reconciliationStatus(badProjection)'));}
 const base=reconciliationPlanFixture();for(const change of [{reviewRevision:''},{reviewRevision:'A'.repeat(64)},{scope:'all-processes'},{objects:undefined},{objects:Array(9).fill(base.objects[0])},{objects:[{...base.objects[0],size:65537}]},{objects:[{...base.objects[0],role:'working-directory'}]},{objects:[base.objects[0],base.objects[0]]},{resume:true},{expiresAt:'invalid'}]){env.put('badPlan',{...base,...change});assert.throws(()=>env.run('reconciliationPlan(badPlan,{})'));}
 env.put('emptyPlan',{...base,objects:null});assert.deepEqual(plain(env.run('reconciliationPlan(emptyPlan,{}).objects')),[]);env.put('expiredPlan',{...base,expiresAt:'2000-01-01T00:00:00Z'});assert.throws(()=>env.run('reconciliationPlan(expiredPlan,{})'),error=>error.code==='reconciliation-expired');env.put('selectedPlan',base);assert.throws(()=>env.run('reconciliationPlan(selectedPlan,{generation:"a".repeat(48)})'));
 env.put('badReceipt',{...reconciliationReceiptFixture(base),state:'pending'});assert.throws(()=>env.run('reconciliationReceipt(badReceipt)'));env.put('badReceipt',{...reconciliationReceiptFixture(base),quarantined:undefined});assert.throws(()=>env.run('reconciliationReceipt(badReceipt)'));
});
test('completed receipt must match every reviewed identity, digest and preserved object before clearing own refusal',async()=>{
 const plan=reconciliationPlanFixture();for(const change of [{operationId:'a'.repeat(48)},{generation:'a'.repeat(48)},{intentSHA256:'a'.repeat(64)},{sealSHA256:'a'.repeat(64)},{quarantined:[]},{quarantined:[{...plan.objects[0],sha256:'a'.repeat(64)}]},{quarantined:[{...plan.objects[0],size:43}]}]){const env=onlineHistory();env.run('workflowLifecycleUI.admissionRefused=true');env.context.fetch=async path=>historyFixtureResponse(path.endsWith('/preview')?plan:reconciliationReceiptFixture(plan,change));await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;await env.run('applyReconciliation()');assert.equal(env.run('reconciliationUI.receipt'),null);assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.match(env.get('reconcile-message').textContent,/could not be verified/);assert.equal(env.get('reconcile-operation').value,plan.operationId);}
 const env=onlineHistory(),second={...plan.objects[0],ref:'a'.repeat(64)};env.put('matchPlan',{...plan,objects:[...plan.objects,second]});env.put('matchReceipt',reconciliationReceiptFixture({...plan,objects:[second,...plan.objects]}));assert.equal(env.run('reconciliationReceiptMatches(reconciliationReceipt(matchReceipt),reconciliationPlan(matchPlan,{}))'),true);
});
test('generic reconciliation status and foreign/manual receipt inspection never authorize new workflow admission',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture();env.run('workflowLifecycleUI.admissionRefused=true');env.context.fetch=async path=>historyFixtureResponse(path===reconciliationBaseFixture?reconciliationStatusFixture('completed'):reconciliationReceiptFixture(plan));await env.run('refreshReconciliationStatus()');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);env.get('reconcile-operation').value=plan.operationId;await env.run('readReconciliationReceipt()');assert.equal(env.run('reconciliationUI.receipt.state'),'completed');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);
 env.run('reconciliationUI.attempt={...reconciliationPlan('+JSON.stringify(plan)+',{}),context:"other-session"}');await env.run('readReconciliationReceipt()');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);
});
test('lost Apply response retains known operation across navigation and uses only explicit GET receipt recovery',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture(),requests=[];env.run('workflowLifecycleUI.admissionRefused=true;refreshWorkflowLifecycle=async()=>{}');env.context.fetch=async(path,options)=>{requests.push({path,options});if(path.endsWith('/preview'))return historyFixtureResponse(plan);if(path.endsWith('/apply'))throw new Error('PRIVATE_NETWORK_DETAIL');return historyFixtureResponse(reconciliationReceiptFixture(plan));};await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;await env.run('applyReconciliation()');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.match(env.get('reconcile-message').textContent,/Read its receipt/);assert.doesNotMatch(env.get('reconcile-message').textContent,/PRIVATE_NETWORK_DETAIL/);env.run('state.view="settings";historyNavigationChanged("settings");state.view="system";updateHistoryAvailability()');assert.equal(env.get('reconcile-operation').value,plan.operationId);assert.equal(env.run('reconciliationUI.attempt.operationId'),plan.operationId);assert.equal(env.get('reconcile-receipt').disabled,false);assert.equal(env.get('reconcile-consent').checked,false);await env.run('applyReconciliation()');assert.equal(requests.length,2);await env.run('readReconciliationReceipt()');assert.equal(requests[2].options.method,'GET');assert.equal(requests[2].path,reconciliationBaseFixture+'/receipts/'+plan.operationId);assert.equal(env.run('workflowLifecycleUI.admissionRefused'),false);assert.equal(requests.filter(item=>item.path.endsWith('/apply')).length,1);
});
test('pending receipt polling is bounded GET-only, stoppable and never repeats a mutation or busy response',async()=>{
 const env=onlineHistory(),clock=reconciliationTimers(env),methods=[];env.get('reconcile-operation').value='3'.repeat(48);env.context.fetch=async(_path,options)=>{methods.push(options.method);return historyFixtureResponse({code:'reconciliation-pending',error:'PRIVATE'},409)};await env.run('readReconciliationReceipt()');assert.equal(env.run('reconciliationUI.watching'),true);for(let i=1;i<20;i++)await clock.fire(1500);assert.equal(methods.length,20);assert.ok(methods.every(method=>method==='GET'));assert.equal(env.run('reconciliationUI.watching'),false);assert.equal([...clock.timers.values()].some(timer=>timer.ms===1500),false);assert.equal(env.run('reconciliationUI.message'),'reconcileStillPending');
 await env.run('readReconciliationReceipt()');await env.run('readReconciliationReceipt()');assert.equal(env.run('reconciliationUI.watching'),false);assert.equal([...clock.timers.values()].some(timer=>timer.ms===1500),false);assert.equal(methods.length,21);
 env.context.fetch=async()=>historyFixtureResponse({code:'reconciliation-busy',error:'PRIVATE_BUSY'},503);await env.run('readReconciliationReceipt()');assert.equal(env.run('reconciliationUI.watching'),false);assert.equal([...clock.timers.values()].some(timer=>timer.ms===1500),false);assert.doesNotMatch(env.get('reconcile-message').textContent,/PRIVATE_BUSY/);
});
test('explicit pending resume gets a fresh plan and never carries consent into the new review',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture({resume:true}),requests=[];env.get('reconcile-operation').value=plan.operationId;env.get('reconcile-consent').checked=true;env.context.fetch=async(path,options)=>{requests.push({path,body:options.body});return historyFixtureResponse(plan)};await env.run('previewReconciliation(true)');assert.deepEqual(JSON.parse(requests[0].body),{operationId:plan.operationId});assert.equal(env.get('reconcile-consent').checked,false);assert.equal(env.get('reconcile-apply').disabled,true);assert.equal(env.run('reconciliationUI.plan.resume'),true);assert.equal(requests.length,1);
 env.get('reconcile-generation').value='private/path';await env.run('previewReconciliation()');assert.equal(requests.length,1);
});
test('review expiry and edited identifiers invalidate consent without changing current-job controls or input evidence',async()=>{
 const env=onlineHistory(),clock=reconciliationTimers(env),now=Date.now(),plan=reconciliationPlanFixture({expiresAt:new Date(now+1000).toISOString()});class ControlledDate extends Date{static now(){return ControlledDate.clock}}ControlledDate.clock=now;env.context.Date=ControlledDate;env.context.fetch=async()=>historyFixtureResponse(plan);await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;ControlledDate.clock=now+1001;const expiry=[...clock.timers].find(([,timer])=>timer.ms===1000);assert.ok(expiry);clock.timers.delete(expiry[0]);expiry[1].fn();assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.get('reconcile-consent').checked,false);assert.equal(env.get('reconcile-apply').disabled,true);
 ControlledDate.clock=now;await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;env.get('reconcile-generation').value='a'.repeat(48);env.run('reconciliationInputsChanged()');assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.get('reconcile-consent').checked,false);assert.equal(env.get('reconcile-generation').value,'a'.repeat(48));
});
test('late review/status/receipt replies and finalizers cannot cross changed input, session, navigation or audited mode',async()=>{
 const plan=reconciliationPlanFixture();for(const change of ['$("reconcile-generation").value="a".repeat(48);reconciliationInputsChanged()','state.token="new-session";updateHistoryAvailability()','state.view="profiles";historyNavigationChanged("profiles")','state.profileEditingOnly=true;updateHistoryAvailability()']){const env=onlineHistory();let finish,signal;env.context.fetch=(_path,options)=>{signal=options.signal;return new Promise(resolve=>finish=resolve)};const pending=env.run('previewReconciliation()');env.run(change);assert.equal(signal.aborted,true);finish(historyFixtureResponse(plan));await pending;assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.run('reconciliationUI.reviewing'),false);assert.equal(env.get('reconcile-consent').checked,false);}
 for(const method of ['refreshReconciliationStatus()','readReconciliationReceipt()']){const env=onlineHistory();env.get('reconcile-operation').value=plan.operationId;let finish;env.context.fetch=()=>new Promise(resolve=>finish=resolve);const old=env.run(method);env.run('state.token="replacement";updateHistoryAvailability()');finish(historyFixtureResponse(method.startsWith('refresh')?reconciliationStatusFixture('available'):reconciliationReceiptFixture(plan)));await old;assert.equal(env.run('reconciliationUI.status'),null);assert.equal(env.run('reconciliationUI.receipt'),null);assert.equal(env.get('reconcile-operation').value,'');}
});
test('old Apply success/error/finally never overwrites a new-context operation or clears its refusal',async()=>{
 for(const rejected of [false,true]){const env=onlineHistory(),oldPlan=reconciliationPlanFixture(),newPlan=reconciliationPlanFixture({id:'a'.repeat(48),operationId:'b'.repeat(48)});let finish,rejectOld;env.run('workflowLifecycleUI.admissionRefused=true');env.context.fetch=async path=>path.endsWith('/preview')?historyFixtureResponse(oldPlan):new Promise((resolve,reject)=>{finish=resolve;rejectOld=reject});await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;const old=env.run('applyReconciliation()');env.run('state.token="new-session";updateHistoryAvailability();workflowLifecycleUI.admissionRefused=true');env.context.fetch=async()=>historyFixtureResponse(newPlan);await env.run('previewReconciliation()');if(rejected)rejectOld(new Error('PRIVATE_OLD'));else finish(historyFixtureResponse(reconciliationReceiptFixture(oldPlan)));await old;assert.equal(env.run('reconciliationUI.plan.operationId'),newPlan.operationId);assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.equal(env.run('reconciliationUI.receipt'),null);assert.equal(env.get('reconcile-apply').disabled,true);assert.doesNotMatch(env.get('reconcile-message').textContent,/PRIVATE_OLD/);}
});
test('status remains independent and cannot replace an active review or receipt message with late generic status',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture();let finish;env.context.fetch=()=>new Promise(resolve=>finish=resolve);const status=env.run('refreshReconciliationStatus()');env.context.fetch=async()=>historyFixtureResponse(plan);await env.run('previewReconciliation()');finish(historyFixtureResponse(reconciliationStatusFixture('pending')));await status;assert.equal(env.run('reconciliationUI.plan.id'),plan.id);assert.equal(env.run('reconciliationUI.message'),'reconcileReviewReady');assert.equal(env.run('reconciliationUI.status'),null);
 env.context.fetch=async()=>historyFixtureResponse(reconciliationStatusFixture('available'));await env.run('refreshReconciliationStatus()');assert.equal(env.run('reconciliationUI.message'),'reconcileReviewReady');assert.equal(env.run('reconciliationUI.status.state'),'available');
});
test('reconciliation refuses oversized/error/UTF8 responses, checks abort after body and never displays raw private errors',async()=>{
 const env=onlineHistory();for(const response of [historyFixtureResponse({private:'x'.repeat(5000)}),new Response(new Uint8Array([0xff]),{headers:{'Content-Type':'application/json'}}),new Response('{}',{headers:{'Content-Type':'text/html'}})]){env.context.fetch=async()=>response;await env.run('refreshReconciliationStatus()');assert.equal(env.run('reconciliationUI.status'),null);assert.equal(env.run('reconciliationUI.statusError'),'reconcileInvalidResponse');}
 env.context.fetch=async()=>historyFixtureResponse({private:'x'.repeat(65536)});await env.run('previewReconciliation()');assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.run('reconciliationUI.message'),'reconcileInvalidResponse');
 for(const code of ['reconciliation-denied','reconciliation-policy-unavailable','reconciliation-store-unavailable','unlisted-private-code']){env.context.fetch=async()=>historyFixtureResponse({code,error:'PRIVATE_FILESYSTEM_PATH'},503);await env.run('refreshReconciliationStatus()');assert.doesNotMatch(env.get('reconcile-message').textContent,/PRIVATE_FILESYSTEM_PATH|unlisted-private-code/);assert.equal(env.run('reconciliationUI.status'),null);}
 const controller=new AbortController();env.context.fixtureController=controller;env.context.fetch=async()=>{controller.abort();return historyFixtureResponse(reconciliationStatusFixture())};await assert.rejects(env.run('reconciliationRequest(reconciliationBase,fixtureController)'),{name:'AbortError'});
});
test('reconciliation remains available after profile failure; immediate audited bootstrap change clears private review and prevents direct requests',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture();env.run('state.offline=true;state.profiles=[]');env.context.fetch=async()=>historyFixtureResponse(plan);await env.run('previewReconciliation()');assert.equal(env.run('reconciliationUI.plan.id'),plan.id);env.run('apiRequest=async path=>{if(path==="/api/bootstrap")return {platform:"windows",profileEditingOnly:true};throw new Error("profile failure") }');await assert.rejects(env.run('readCore()'));assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.get('reconcile-operation').value,'');assert.equal(env.get('history-reconciliation-card').hidden,true);let requests=0;env.context.fetch=async()=>{requests++;throw new Error('no audited request')};await env.run('previewReconciliation()');await env.run('applyReconciliation()');await env.run('readReconciliationReceipt()');await env.run('refreshReconciliationStatus()');assert.equal(requests,0);
});
test('all reconciliation controls, closed states and private errors are translated in four languages',()=>{
 const env=onlineHistory(),keys=plain(env.run('Object.keys(en).filter(key=>key.startsWith("reconcile"))'));assert.ok(keys.length>45);for(const language of ['en','tr','ru','es']){env.put('reconcileLanguage',language);env.run('state.lang=reconcileLanguage');for(const key of keys){env.put('reconcileKey',key);assert.notEqual(env.run('t(reconcileKey)'),key);assert.ok(env.run('t(reconcileKey)').length>0);}for(const state of ['none','available','pending','completed','unavailable']){env.put('projection',reconciliationStatusFixture(state));env.run('reconciliationUI.status=reconciliationStatus(projection);renderReconciliation()');assert.notEqual(env.get('reconcile-status').textContent,'reconcileState_'+state);}}
});

test('a timed-out reconciliation body cannot publish late status even when the source fetch ignores abort',async()=>{
 const env=onlineHistory(),clock=reconciliationTimers(env);let body,signal;env.context.fetch=async(_path,options)=>{signal=options.signal;return new Response(new ReadableStream({start(controller){body=controller}}),{headers:{'Content-Type':'application/json'}})};const pending=env.run('refreshReconciliationStatus()');while(!body)await Promise.resolve();await clock.fire(15000);assert.equal(signal.aborted,true);body.enqueue(new TextEncoder().encode(JSON.stringify(reconciliationStatusFixture('available'))));body.close();await pending;assert.equal(env.run('reconciliationUI.status'),null);assert.equal(env.run('reconciliationUI.statusError'),'reconcileEnded');assert.equal(env.get('reconcile-refresh').disabled,false);
});
test('oversized reconciliation metadata cancels its response reader and cannot leak private payload text',async()=>{
 const env=onlineHistory();let canceled=0;env.context.fetch=async()=>new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode(JSON.stringify({private:'PRIVATE_PAYLOAD'.repeat(500)})))},cancel(){canceled++}}),{headers:{'Content-Type':'application/json'}});await env.run('refreshReconciliationStatus()');assert.equal(canceled,1);assert.equal(env.run('reconciliationUI.status'),null);assert.equal(env.run('reconciliationUI.statusError'),'reconcileInvalidResponse');assert.doesNotMatch(env.get('reconcile-message').textContent,/PRIVATE_PAYLOAD/);
});

test('re-reading an old own completed receipt cannot clear a later workflow admission refusal',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture();env.run('globalThis.reconcileTrackingReads=0;refreshWorkflowLifecycle=async()=>{reconcileTrackingReads++};handleWorkflowLifecycleAdmission({status:409,code:"workflow-lifecycle-pending"})');env.context.fetch=async path=>historyFixtureResponse(path.endsWith('/preview')?plan:reconciliationReceiptFixture(plan));await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;await env.run('applyReconciliation()');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),false);assert.equal(env.run('reconciliationUI.attempt.receiptAccepted'),true);assert.equal(env.context.reconcileTrackingReads,1);
 env.run('handleWorkflowLifecycleAdmission({status:409,code:"workflow-lifecycle-pending"})');const epoch=env.run('workflowLifecycleUI.refusalEpoch');await env.run('readReconciliationReceipt()');assert.equal(env.run('reconciliationUI.receipt.state'),'completed');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.equal(env.run('workflowLifecycleUI.refusalEpoch'),epoch);assert.equal(env.get('history-lifecycle-blocked').hidden,false);assert.equal(env.context.reconcileTrackingReads,1);
});
test('the first exact old receipt received after a newer refusal remains inspectable but cannot clear it',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture();let finish;env.run('globalThis.reconcileTrackingReads=0;refreshWorkflowLifecycle=async()=>{reconcileTrackingReads++};handleWorkflowLifecycleAdmission({status:409,code:"workflow-lifecycle-pending"})');env.context.fetch=async path=>path.endsWith('/preview')?historyFixtureResponse(plan):new Promise(resolve=>finish=resolve);await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;const apply=env.run('applyReconciliation()');env.run('handleWorkflowLifecycleAdmission({status:409,code:"workflow-lifecycle-pending"})');finish(historyFixtureResponse(reconciliationReceiptFixture(plan)));await apply;assert.equal(env.run('reconciliationUI.receipt.state'),'completed');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.equal(env.context.reconcileTrackingReads,0);assert.equal(env.run('reconciliationUI.attempt.receiptAccepted'),true);env.context.fetch=async()=>historyFixtureResponse(reconciliationReceiptFixture(plan));await env.run('readReconciliationReceipt()');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.equal(env.context.reconcileTrackingReads,0);
});
test('a later pending admission invalidates an in-flight or previously consented local review without submitting Apply',async()=>{
 for(const phase of ['during-review','after-review']){const env=onlineHistory(),plan=reconciliationPlanFixture();let finish;const requests=[];env.context.fetch=(path,options)=>{requests.push({path,options});return new Promise(resolve=>finish=resolve)};const preview=env.run('previewReconciliation()');if(phase==='after-review'){finish(historyFixtureResponse(plan));await preview;env.get('reconcile-consent').checked=true;}env.run('handleWorkflowLifecycleAdmission({status:409,code:"workflow-lifecycle-pending"})');if(phase==='during-review'){finish(historyFixtureResponse(plan));await preview;}await env.run('applyReconciliation()');assert.equal(requests.length,1);assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.get('reconcile-consent').checked,false);assert.equal(env.run('reconciliationUI.message'),'reconcileConflict');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);}
});

test('actual Go reconciliation wire supports explicit reviewed local release and durable resume',{skip:!process.env.ACCESSWEAVER_RECONCILIATION_INTEROP},async()=>{
 const path=require('node:path'),crypto=require('node:crypto');
 const directory=path.resolve(process.env.ACCESSWEAVER_RECONCILIATION_INTEROP),repo=path.resolve(__dirname,'..');
 const payloadNames=['available.json','live-plan.json','completed.json','completed-status.json','lifecycle-released.json','unavailable.json','pending-status.json','resume-plan.json','resumed.json','resume-lifecycle-released.json'];
 const names=[...payloadNames,'manifest.json'].sort(),sourceDirectories=['internal/api','internal/workflow','internal/managed','internal/fileidentity','internal/fileinput','internal/privatefile','internal/filelock','internal/nativeprocess','internal/nativepath'];
 const fixedSources=['go.mod','go.sum','internal/workflow/windows.ps1','internal/workflow/reconciliation_test.go','internal/workflow/lifecycle_test.go','internal/workflow/shutdown_test.go','internal/workflow/reconciliation_export_test.go','internal/workflow/reconciliation_http_interop_test.go','internal/workflow/reconciliation_wire_interop_test.go','web/system.js','web/app.js','web/index.html','web/app.css','web/locales.js','web/app.test.cjs'];
 const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex'),same=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
 const closed=(value,fields)=>{assert.ok(value&&typeof value==='object'&&!Array.isArray(value),'Wire object required');assert.ok(JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort()),'Unexpected wire fields');};
 function ordinaryDirectory(target){const state=fs.lstatSync(target,{bigint:true});assert.ok(state.isDirectory()&&!state.isSymbolicLink(),'Wire directory must be ordinary');return state;}
 function readChecked(root,name,maximum){
  let fd;
  try{
   let parent=root;ordinaryDirectory(parent);const parts=name.split('/');
   assert.ok(parts.length>0&&parts.every(part=>part&&part!=='.'&&part!=='..'&&!part.includes('\\')),'Fixed source component required');
   for(const part of parts.slice(0,-1)){parent=path.join(parent,part);ordinaryDirectory(parent);}
   const target=path.join(parent,parts.at(-1)),before=fs.lstatSync(target,{bigint:true});
   assert.ok(before.isFile()&&!before.isSymbolicLink()&&before.size>=0n&&before.size<=BigInt(maximum),'Wire source must be a bounded ordinary file');
   fd=fs.openSync(target,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const opened=fs.fstatSync(fd,{bigint:true});assert.ok(same(before,opened),'Wire source changed while opening');
   const chunks=[];let total=0;
   for(;;){const buffer=Buffer.alloc(Math.min(32768,maximum+1-total)),n=fs.readSync(fd,buffer,0,buffer.length,null);if(n===0)break;total+=n;assert.ok(total<=maximum,'Wire source grew beyond its bound');chunks.push(buffer.subarray(0,n));}
   const after=fs.fstatSync(fd,{bigint:true}),named=fs.lstatSync(target,{bigint:true});
   assert.ok(named.isFile()&&!named.isSymbolicLink()&&same(opened,after)&&same(after,named)&&opened.size===after.size&&after.size===named.size&&opened.mtimeNs===after.mtimeNs&&after.mtimeNs===named.mtimeNs&&BigInt(total)===after.size,'Wire source changed during read');
   return Buffer.concat(chunks,total);
  }catch(error){if(error?.code)assert.fail('Wire source is unavailable');throw error;}
  finally{if(fd!==undefined){try{fs.closeSync(fd)}catch{assert.fail('Wire source Close failed')}}}
 }
 // JSON.parse alone accepts duplicate object keys. Scan the already validated
 // bounded JSON too, rejecting decoded duplicates at every nesting depth.
 function parseStrict(bytes){
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=JSON.parse(text);let at=0;
  const space=()=>{while(/[ \t\r\n]/.test(text[at]||''))at++;};
  function string(){const start=at++;for(;;){const c=text[at++];if(c==='"')return JSON.parse(text.slice(start,at));if(c==='\\')at++;}}
  function scan(depth){assert.ok(depth<=64,'Wire JSON depth exceeded');space();const c=text[at];
   if(c==='{'){at++;space();const seen=new Set();if(text[at]==='}'){at++;return;}for(;;){const key=string();assert.equal(seen.has(key),false,'Duplicate wire JSON key');seen.add(key);space();assert.equal(text[at++],':');scan(depth+1);space();if(text[at++]==='}')return;space();}}
   else if(c==='['){at++;space();if(text[at]===']'){at++;return;}for(;;){scan(depth+1);space();if(text[at++]===']')return;space();}}
   else if(c==='"')string();else{const match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));assert.ok(match,'Invalid wire JSON value');at+=match[0].length;}
  }
  scan(0);space();assert.equal(at,text.length,'Trailing wire JSON');return value;
 }
 const identity=ordinaryDirectory(directory);assert.ok(JSON.stringify(fs.readdirSync(directory).sort())===JSON.stringify(names),'Unexpected wire files');
 const sources=[...fixedSources];
 for(const name of sourceDirectories){ordinaryDirectory(path.join(repo,name));for(const entry of fs.readdirSync(path.join(repo,name),{withFileTypes:true})){if(!entry.name.endsWith('.go')||entry.name.endsWith('_test.go'))continue;assert.ok(entry.isFile()&&!entry.isSymbolicLink(),'Go source must be an ordinary flat file');sources.push(name+'/'+entry.name);}}
 sources.sort();assert.ok(sources.length<=256&&new Set(sources).size===sources.length,'Source allowlist exceeds its bound');
 const manifestBytes=readChecked(directory,'manifest.json',128*1024),manifest=parseStrict(manifestBytes);closed(manifest,['schemaVersion','sources','files','expected']);assert.equal(manifest.schemaVersion,1);
 assert.ok(Array.isArray(manifest.sources)&&manifest.sources.length===sources.length,'Unexpected source count');assert.ok(JSON.stringify(manifest.sources.map(entry=>entry?.name))===JSON.stringify(sources),'Source list differs from independent checkout enumeration');
 for(const entry of manifest.sources){closed(entry,['name','sha256']);assert.match(entry.sha256,/^[a-f0-9]{64}$/);assert.equal(hash(readChecked(repo,entry.name,8*1024*1024)),entry.sha256,'Wire fixture does not match current sources');}
 assert.ok(Array.isArray(manifest.files)&&manifest.files.length===payloadNames.length,'Unexpected payload count');assert.ok(JSON.stringify(manifest.files.map(entry=>entry?.name).sort())===JSON.stringify([...payloadNames].sort()),'Unexpected payload names or duplicate payload');
 const bytes={},metadata={},payloads={};
 const statusFiles=new Set(['available.json','completed-status.json','lifecycle-released.json','pending-status.json','resume-lifecycle-released.json']);
 for(const entry of manifest.files){
  closed(entry,['name','size','sha256','status','contentType']);assert.ok(payloadNames.includes(entry.name),'Payload name is outside fixed allowlist');
  const maximum=statusFiles.has(entry.name)?4096:64*1024;
  assert.ok(Number.isSafeInteger(entry.size)&&entry.size>=0&&entry.size<=maximum,'Payload size exceeds its contract');assert.match(entry.sha256,/^[a-f0-9]{64}$/);assert.equal(entry.status,entry.name==='unavailable.json'?409:200);assert.match(entry.contentType,/^application\/json(?:;\s*charset=utf-8)?$/i);
  bytes[entry.name]=readChecked(directory,entry.name,maximum);assert.equal(bytes[entry.name].length,entry.size);assert.equal(hash(bytes[entry.name]),entry.sha256,'Payload digest mismatch');metadata[entry.name]=entry;payloads[entry.name]=parseStrict(bytes[entry.name]);
 }
 closed(manifest.expected,['generation','operationId','resumeGeneration','resumeOperationId']);const expected=manifest.expected;
 for(const value of Object.values(expected))assert.match(value,/^[a-f0-9]{48}$/);assert.notEqual(expected.generation,expected.resumeGeneration);assert.notEqual(expected.operationId,expected.resumeOperationId);
 const planKeys=['id','reviewRevision','operationId','generation','action','expiresAt','intentSHA256','sealSHA256','objects','resume','scope','protection'],receiptKeys=['operationId','generation','state','action','intentSHA256','sealSHA256','ackSHA256','quarantined','completedAt','scope','protection'];
 for(const name of ['live-plan.json','resume-plan.json']){closed(payloads[name],planKeys);assert.match(payloads[name].reviewRevision,/^[a-f0-9]{64}$/);assert.ok(Array.isArray(payloads[name].objects)&&payloads[name].objects.length<=8);for(const object of payloads[name].objects)closed(object,['ref','role','size','sha256']);}
 for(const name of ['completed.json','resumed.json']){closed(payloads[name],receiptKeys);assert.ok(Array.isArray(payloads[name].quarantined));for(const object of payloads[name].quarantined)closed(object,['ref','role','size','sha256']);}
 closed(payloads['available.json'],['state','generation','canPreview','resumeAvailable','scope','protection']);
 for(const name of ['completed-status.json','pending-status.json'])closed(payloads[name],['state','generation','operationId','canPreview','resumeAvailable','scope','protection']);
 for(const name of ['lifecycle-released.json','resume-lifecycle-released.json'])closed(payloads[name],['state','jobId','admissionBlocked','protection']);assert.equal(payloads['lifecycle-released.json'].jobId,expected.generation);assert.equal(payloads['resume-lifecycle-released.json'].jobId,expected.resumeGeneration);closed(payloads['unavailable.json'],['error','code']);assert.equal(payloads['unavailable.json'].code,'reconciliation-unavailable');assert.equal(payloads['unavailable.json'].error,'positive local ownership proof is unavailable');
 assert.equal(payloads['available.json'].generation,expected.generation);assert.equal(payloads['completed-status.json'].operationId,expected.operationId);assert.equal(payloads['completed-status.json'].generation,expected.generation);assert.equal(payloads['pending-status.json'].operationId,expected.resumeOperationId);assert.equal(payloads['pending-status.json'].generation,expected.resumeGeneration);assert.equal(payloads['pending-status.json'].resumeAvailable,true);
 const respond=name=>new Response(bytes[name],{status:metadata[name].status,headers:{'Content-Type':metadata[name].contentType}});
 function bindOriginal(env){env.put('wireOriginalJob',{id:'source-original-failed',state:'failed',error:'Original outcome preserved'});env.run('systemUI.job=wireOriginalJob;$("system-output").textContent="Original outcome preserved";$("system-journal").value="retained-source-recovery";handleWorkflowLifecycleAdmission({status:409,code:"workflow-lifecycle-pending"});const originalWireLifecycleRead=refreshWorkflowLifecycle;refreshWorkflowLifecycle=()=>{globalThis.lastWireLifecycleRead=originalWireLifecycleRead();return lastWireLifecycleRead}');}
 function assertOriginal(env){assert.deepEqual(plain(env.run('systemUI.job')),{id:'source-original-failed',state:'failed',error:'Original outcome preserved'});assert.equal(env.get('system-journal').value,'retained-source-recovery');assert.equal(env.run('systemUI.busy'),false);}
 const env=onlineHistory(),calls=[];bindOriginal(env);let unavailable=false;
 env.context.fetch=async(target,options)=>{calls.push({target,method:options.method,body:options.body});assert.equal(options.headers['X-AccessWeaver-Token'],'history-session');assert.equal(options.redirect,'error');
  if(target===reconciliationBaseFixture){assert.equal(options.method,'GET');return respond('available.json');}
  if(target===reconciliationBaseFixture+'/preview'){assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),unavailable?{}:{generation:expected.generation});return respond(unavailable?'unavailable.json':'live-plan.json');}
  if(target===reconciliationBaseFixture+'/apply'){assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{planId:payloads['live-plan.json'].id,confirm:true});return respond('completed.json');}
  if(target===reconciliationBaseFixture+'/receipts/'+expected.operationId){assert.equal(options.method,'GET');return respond('completed.json');}
  assert.equal(target,'/api/v1/system/history/lifecycle');assert.equal(options.method,'GET');return respond('lifecycle-released.json');
 };
 env.put('wireLive',payloads['live-plan.json']);env.put('wireComplete',payloads['completed.json']);env.put('wireCompletedStatus',payloads['completed-status.json']);assert.equal(env.run('reconciliationReceiptMatches(reconciliationReceipt(wireComplete),reconciliationPlan(wireLive,{generation:wireLive.generation}))'),true);assert.equal(env.run('reconciliationStatus(wireCompletedStatus).state'),'completed');
 await env.run('refreshReconciliationStatus()');assert.equal(env.run('reconciliationUI.status.state'),'available');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);
 env.get('reconcile-generation').value=expected.generation;env.run('reconciliationInputsChanged()');await env.run('previewReconciliation()');assert.equal(env.run('reconciliationUI.plan.operationId'),expected.operationId);assert.equal(env.run('reconciliationUI.plan.generation'),expected.generation);assert.equal(env.run('reconciliationUI.plan.reviewRevision'),payloads['live-plan.json'].reviewRevision);assert.deepEqual(plain(env.run('reconciliationUI.plan.objects')),payloads['live-plan.json'].objects);assert.equal(env.get('reconcile-consent').checked,false);assert.equal(env.get('reconcile-apply').disabled,true);
 await env.run('applyReconciliation()');assert.equal(calls.filter(call=>call.method==='POST'&&call.target.endsWith('/apply')).length,0);env.get('reconcile-consent').checked=true;await env.run('applyReconciliation()');await env.context.lastWireLifecycleRead;
 assert.equal(env.run('workflowLifecycleUI.admissionRefused'),false);assert.equal(env.run('workflowLifecycleUI.status.state'),'released');assert.deepEqual(plain(env.run('workflowLifecycleUI.status')),payloads['lifecycle-released.json']);assert.deepEqual(plain(env.run('reconciliationUI.receipt')),payloads['completed.json']);assertOriginal(env);
 env.run('handleWorkflowLifecycleAdmission({status:409,code:"workflow-lifecycle-pending"})');await env.run('readReconciliationReceipt()');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.deepEqual(plain(env.run('reconciliationUI.receipt.quarantined')),payloads['live-plan.json'].objects);
 unavailable=true;env.get('reconcile-generation').value='';env.run('reconciliationInputsChanged()');await env.run('previewReconciliation()');assert.equal(env.run('reconciliationUI.plan'),null);assert.equal(env.run('reconciliationUI.message'),'reconcileUnavailable');assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.equal(calls.filter(call=>call.method==='POST'&&call.target.endsWith('/apply')).length,1);assertOriginal(env);
 const resumed=onlineHistory(),resumeCalls=[];bindOriginal(resumed);
 resumed.context.fetch=async(target,options)=>{resumeCalls.push({target,method:options.method,body:options.body});
  if(target===reconciliationBaseFixture){assert.equal(options.method,'GET');return respond('pending-status.json');}
  if(target===reconciliationBaseFixture+'/preview'){assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{operationId:expected.resumeOperationId});return respond('resume-plan.json');}
  if(target===reconciliationBaseFixture+'/apply'){assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{planId:payloads['resume-plan.json'].id,confirm:true});return respond('resumed.json');}
  // The actual fresh resume root supplies its own released projection.
  assert.equal(target,'/api/v1/system/history/lifecycle');assert.equal(options.method,'GET');return respond('resume-lifecycle-released.json');
 };
 resumed.put('wireResumePlan',payloads['resume-plan.json']);resumed.put('wireResumedReceipt',payloads['resumed.json']);assert.equal(resumed.run('reconciliationReceiptMatches(reconciliationReceipt(wireResumedReceipt),reconciliationPlan(wireResumePlan,{operationId:wireResumePlan.operationId}))'),true);
 await resumed.run('refreshReconciliationStatus()');assert.equal(resumed.run('reconciliationUI.status.state'),'pending');assert.equal(resumed.get('reconcile-operation').value,expected.resumeOperationId);assert.equal(resumed.run('workflowLifecycleUI.admissionRefused'),true);
 await resumed.run('previewReconciliation(true)');assert.equal(resumed.run('reconciliationUI.plan.resume'),true);assert.equal(resumed.run('reconciliationUI.plan.generation'),expected.resumeGeneration);assert.equal(resumed.run('reconciliationUI.plan.reviewRevision'),payloads['resume-plan.json'].reviewRevision);assert.deepEqual(plain(resumed.run('reconciliationUI.plan.objects')),payloads['resume-plan.json'].objects);assert.equal(resumed.get('reconcile-consent').checked,false);resumed.get('reconcile-consent').checked=true;await resumed.run('applyReconciliation()');await resumed.context.lastWireLifecycleRead;assert.equal(resumed.run('workflowLifecycleUI.admissionRefused'),false);assert.deepEqual(plain(resumed.run('workflowLifecycleUI.status')),payloads['resume-lifecycle-released.json']);assert.deepEqual(plain(resumed.run('reconciliationUI.receipt')),payloads['resumed.json']);assertOriginal(resumed);assert.equal(resumeCalls.filter(call=>call.target.endsWith('/apply')).length,1);
 for(const entry of manifest.files)assert.equal(hash(readChecked(directory,entry.name,64*1024)),entry.sha256,'Desktop consumer changed a wire payload');assert.equal(hash(readChecked(directory,'manifest.json',128*1024)),hash(manifestBytes));assert.ok(same(identity,ordinaryDirectory(directory)),'Wire directory identity changed');assert.ok(JSON.stringify(fs.readdirSync(directory).sort())===JSON.stringify(names),'Wire directory changed');
});

// A retained capture stage is not a snapshot freshness proof. These source
// fixtures require separate current-page and exact selected-revision reads.
function historyStagingSeed(env){env.put('stagingInventory',historyFixtureInventory());env.put('stagingRow',historyFixtureRecord());env.run('historyUI.inventory=historyInventory(stagingInventory);historyUI.items=[historyRecord(stagingRow)];historyUI.selected=historyRecord(stagingRow);historyUI.job={id:"old-preview",private:"OLD_DETAIL_MUST_NOT_RETURN"};historyUI.detailReady=true;historyUI.rawAvailable=true;renderHistoryRows();renderHistoryDetail();updateHistoryAvailability()');}
function historyPendingResponse(){return historyFixtureResponse({code:'history-staging-pending',error:'PRIVATE_STORAGE_CAUSE_MUST_NOT_RENDER'},409);}
test('retained capture staging restores only a freshly revalidated page and selected revision without mutation retry or download',async()=>{
 const env=onlineHistory(),inventory=historyFixtureInventory(),record=historyFixtureRecord(),calls=[];historyStagingSeed(env);env.run('systemUI.plan={id:"kept-review",ready:true};$("system-consent").checked=true;$("system-cancel").disabled=false');let finishDetail;env.context.downloadFile=()=>assert.fail('Pending capture downloaded record automatically');env.context.fetch=async(path,options)=>{calls.push({path,options});if(options.method==='POST')return historyPendingResponse();if(path.startsWith('/api/v1/system/history/page?')){const query=new URL(path,'http://localhost').searchParams;assert.equal(query.get('snapshot'),inventory.snapshot);assert.equal(query.get('limit'),'64');return historyFixtureResponse({inventory,items:[record]});}assert.equal(path,'/api/v1/system/history/records/'+record.recordRef+'?revision='+record.revision);return new Promise(resolve=>finishDetail=resolve);};const capture=env.run('captureHistory()');for(let turns=0;turns<50&&!finishDetail;turns++)await new Promise(resolve=>setImmediate(resolve));assert.equal(typeof finishDetail,'function','Selected revalidation did not start');assert.equal(env.run('historyUI.selected'),null);assert.equal(env.run('historyUI.job'),null);assert.equal(env.get('history-export-record').disabled,true);assert.equal(env.get('system-cancel').disabled,false);finishDetail(historyFixtureResponse({record,job:{id:'fresh-checked-detail',state:'failed'},rawAvailable:true}));await capture;
 assert.equal(env.run('historyUI.inventory.snapshot'),inventory.snapshot);assert.equal(env.run('historyUI.selected.recordRef'),record.recordRef);assert.equal(env.run('historyUI.job.id'),'fresh-checked-detail');assert.equal(env.get('history-export-record').disabled,false);assert.equal(env.run('historyUI.message'),'historyStagingPending');assert.doesNotMatch(env.get('history-status').textContent,/PRIVATE_STORAGE|OLD_DETAIL/);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(calls.length,3);assert.equal(env.run('systemUI.plan.id'),'kept-review');assert.equal(env.get('system-consent').checked,true);assert.equal(env.run('historyUI.capturing'),false);
});
test('retained capture staging never restores old selection when its actual revision changed, disappeared or exceeded desktop detail budget',async()=>{
 for(const failure of ['changed','missing','oversized']){const env=onlineHistory(),inventory=historyFixtureInventory(),record=historyFixtureRecord();historyStagingSeed(env);env.context.fetch=async(path,options)=>{if(options.method==='POST')return historyPendingResponse();if(path.startsWith('/api/v1/system/history/page?'))return historyFixtureResponse({inventory,items:[record]});if(failure==='oversized')return historyFixtureResponse({record,job:{private:'x'.repeat(4*1024*1024)},rawAvailable:true});return historyFixtureResponse({error:'PRIVATE_CHANGED_RECORD'},failure==='changed'?409:404);};await env.run('captureHistory()');assert.equal(env.run('historyUI.inventory.snapshot'),inventory.snapshot);assert.equal(env.run('historyUI.items.length'),1);assert.equal(env.run('historyUI.selected'),null);assert.equal(env.run('historyUI.job'),null);assert.equal(env.get('history-export-record').disabled,true);assert.equal(env.run('historyUI.message'),'historyStagingPending');assert.doesNotMatch(env.get('history-status').textContent,/PRIVATE_CHANGED|OLD_DETAIL/);}
});
test('retained staging refusal cannot restore a stale, substituted or unavailable page as current',async()=>{
 for(const failure of ['stale','wrong-snapshot','wrong-inventory','unavailable']){const env=onlineHistory(),inventory=historyFixtureInventory(),record=historyFixtureRecord();let reads=0;historyStagingSeed(env);env.context.fetch=async(_path,options)=>{if(options.method==='POST')return historyPendingResponse();reads++;if(failure==='stale'||failure==='unavailable')return historyFixtureResponse({error:'PRIVATE_REVALIDATION'},failure==='stale'?409:503);return historyFixtureResponse({inventory:{...inventory,...(failure==='wrong-snapshot'?{snapshot:'e'.repeat(48)}:{totalBytes:257})},items:[record]});};await env.run('captureHistory()');assert.equal(env.run('historyUI.inventory'),null);assert.equal(env.run('historyUI.items.length'),0);assert.equal(env.run('historyUI.selected'),null);assert.equal(env.get('history-export-record').disabled,true);assert.equal(reads,1);assert.equal(env.run('historyUI.message'),'historyStagingPending');}
});
test('only a bounded fixed staging code on capture409 can retain an old view; malformed/private or unrelated responses clear it safely',async()=>{
 for(const failure of ['oversized','invalid','unknown-code','wrong-type','wrong-status']){const env=onlineHistory();historyStagingSeed(env);let reads=0;env.context.fetch=async(_path,options)=>{if(options.method!=='POST'){reads++;throw Error('Unexpected revalidation');}if(failure==='oversized')return historyFixtureResponse({code:'history-staging-pending',error:'PRIVATE'.repeat(1000)},409);if(failure==='invalid')return new Response('PRIVATE_INVALID_JSON',{status:409,headers:{'Content-Type':'application/json'}});if(failure==='wrong-type')return new Response('{"code":"history-staging-pending"}',{status:409,headers:{'Content-Type':'text/plain'}});return historyFixtureResponse({code:failure==='unknown-code'?'unrecognized-private-code':'history-staging-pending',error:'PRIVATE_FAILURE'},failure==='wrong-status'?503:409);};await env.run('captureHistory()');assert.equal(env.run('historyUI.inventory'),null);assert.equal(env.run('historyUI.selected'),null);assert.equal(env.get('history-export-record').disabled,true);assert.equal(reads,0);assert.doesNotMatch(env.get('history-status').textContent,/PRIVATE|unrecognized/);assert.notEqual(env.run('historyUI.message'),'historyStagingPending');}
});
test('retained view revalidation cannot cross navigation, session, audited mode or explicit capture cancellation',async()=>{
 for(const phase of ['page','detail'])for(const change of ['state.view="profiles";historyNavigationChanged("profiles")','state.token="new-session";updateHistoryAvailability()','state.profileEditingOnly=true;updateHistoryAvailability()','cancelHistoryCapture()']){const env=onlineHistory(),inventory=historyFixtureInventory(),record=historyFixtureRecord();historyStagingSeed(env);let finish,signal;env.context.fetch=async(path,options)=>{if(options.method==='POST')return historyPendingResponse();if(phase==='detail'&&path.startsWith('/api/v1/system/history/page?'))return historyFixtureResponse({inventory,items:[record]});signal=options.signal;return new Promise(resolve=>finish=resolve);};const capture=env.run('captureHistory()');for(let turns=0;turns<50&&!finish;turns++)await new Promise(resolve=>setImmediate(resolve));assert.equal(typeof finish,'function','Revalidation did not start');env.run(change);assert.equal(signal.aborted,true);finish(historyFixtureResponse(phase==='page'?{inventory,items:[record]}:{record,job:{private:'STALE_RESTORED_DETAIL'},rawAvailable:true}));await capture;assert.equal(env.run('historyUI.selected'),null);assert.equal(env.run('historyUI.job'),null);assert.equal(env.get('history-export-record').disabled,true);assert.equal(env.run('historyUI.capturing'),false);if(change.startsWith('state.token')||change.startsWith('state.profile'))assert.equal(env.run('historyUI.inventory'),null);}
});
test('retained staging feedback is translated in four languages without asserting cleanup or enabling repair',()=>{
 const env=onlineHistory();for(const language of ['en','tr','ru','es']){env.put('stagingLanguage',language);env.run('state.lang=stagingLanguage;setHistoryMessage("historyStagingPending",{},true)');assert.notEqual(env.get('history-status').textContent,'historyStagingPending');assert.ok(env.get('history-status').textContent.length>100);}assert.equal(env.get('history-export-record').disabled,true);assert.equal(env.run('reconciliationUI.plan'),null);
});

test('a newer explicit page read owns history while older retained-stage recovery is still awaiting data',async()=>{
 for(const phase of ['page','detail']){const env=onlineHistory(),inventory=historyFixtureInventory(),record=historyFixtureRecord(),newInventory={...inventory,snapshot:'e'.repeat(48)},newRecord=historyFixtureRecord({recordRef:'new_record',revision:'f'.repeat(64)});historyStagingSeed(env);let finish;env.context.fetch=async(path,options)=>{if(options.method==='POST')return historyPendingResponse();if(new URL(path,'http://localhost').searchParams.get('snapshot')===newInventory.snapshot)return historyFixtureResponse({inventory:newInventory,items:[newRecord]});if(phase==='detail'&&path.startsWith('/api/v1/system/history/page?'))return historyFixtureResponse({inventory,items:[record]});return new Promise(resolve=>finish=resolve);};const capture=env.run('captureHistory()');for(let turns=0;turns<50&&!finish;turns++)await new Promise(resolve=>setImmediate(resolve));assert.equal(typeof finish,'function');env.put('newHistorySnapshot',newInventory.snapshot);await env.run('loadHistoryPage("",newHistorySnapshot,[])');finish(historyFixtureResponse(phase==='page'?{inventory,items:[record]}:{record,job:{private:'OLD_SELECTION'},rawAvailable:true}));await capture;assert.equal(env.run('historyUI.inventory.snapshot'),newInventory.snapshot);assert.equal(env.run('historyUI.items[0].recordRef'),newRecord.recordRef);assert.equal(env.run('historyUI.message'),'historyPageSummary');assert.equal(env.run('historyUI.bad'),false);assert.equal(env.run('historyUI.selected'),null);assert.equal(env.run('historyUI.job'),null);assert.equal(env.get('history-export-record').disabled,true);}
});

test('late capture refusal cannot clear or replace the data and feedback of a newer explicit history read',async()=>{
 for(const pending of [false,true]){const env=onlineHistory(),inventory={...historyFixtureInventory(),snapshot:'f'.repeat(48)},record=historyFixtureRecord({recordRef:'newer_visible_record'});historyStagingSeed(env);let finishPost;env.context.fetch=async(path,options)=>{if(options.method==='POST')return new Promise(resolve=>finishPost=resolve);assert.ok(path.startsWith('/api/v1/system/history/page?'));return historyFixtureResponse({inventory,items:[record]});};const capture=env.run('captureHistory()');assert.equal(typeof finishPost,'function');env.put('newerCaptureSnapshot',inventory.snapshot);await env.run('loadHistoryPage("",newerCaptureSnapshot,[])');finishPost(pending?historyPendingResponse():historyFixtureResponse({error:'PRIVATE_STALE_CAPTURE'},409));await capture;assert.equal(env.run('historyUI.inventory.snapshot'),inventory.snapshot);assert.equal(env.run('historyUI.items[0].recordRef'),record.recordRef);assert.equal(env.run('historyUI.message'),'historyPageSummary');assert.equal(env.run('historyUI.bad'),false);assert.equal(env.run('historyUI.capturing'),false);assert.doesNotMatch(env.get('history-status').textContent,/PRIVATE|incomplete inventory/);}
});

// Rendering-only polish: empty and duplicate status text must not crowd the
// aria-live action feedback; distinct real state and action messages coexist.
test('initial reconciliation feedback has one localized action message and no fabricated status in every language',()=>{
 const env=onlineHistory();let requests=0;env.context.fetch=async()=>{requests++;throw Error('Presentation must not request authority')};env.run('workflowLifecycleUI.admissionRefused=true');
 for(const language of ['en','tr','ru','es']){env.put('renderLanguage',language);env.run('state.lang=renderLanguage;renderReconciliation()');assert.equal(env.get('reconcile-status').hidden,true);assert.equal(env.get('reconcile-status').textContent,'');assert.equal(env.get('reconcile-message').textContent,env.run('t("reconcileNotLoaded")'));assert.equal(env.get('reconcile-message').hidden,false);assert.equal(env.run('reconciliationUI.status'),null);assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.equal(env.run('reconciliationUI.plan'),null);}
 assert.equal(requests,0);
});
test('reconciliation presentation retains distinct real status/loading/errors beside review and expiry, deduplicating only identical text',()=>{
 const env=onlineHistory();env.put('presentationProjection',reconciliationStatusFixture());env.run('workflowLifecycleUI.admissionRefused=true');
 for(const language of ['en','tr','ru','es']){env.put('renderLanguage',language);env.run('state.lang=renderLanguage');for(const row of [
  {status:true,loading:false,error:'',message:'reconcileReviewReady',key:'reconcileState_available',hidden:false},
  {status:true,loading:false,error:'',message:'reconcileState_available',key:'reconcileState_available',hidden:true},
  {status:false,loading:true,error:'',message:'reconcileReviewing',key:'reconcileReadingStatus',hidden:false},
  {status:false,loading:true,error:'',message:'reconcileReadingStatus',key:'reconcileReadingStatus',hidden:true},
  {status:false,loading:false,error:'reconcileDenied',message:'reconcileExpired',key:'reconcileDenied',hidden:false},
  {status:false,loading:false,error:'reconcileDenied',message:'reconcileDenied',key:'reconcileDenied',hidden:true}
 ]){env.put('presentationRow',row);env.run('reconciliationUI.status=presentationRow.status?reconciliationStatus(presentationProjection):null;reconciliationUI.statusLoading=presentationRow.loading;reconciliationUI.statusError=presentationRow.error;reconciliationUI.message=presentationRow.message;reconciliationUI.bad=!!presentationRow.error;renderReconciliation()');assert.equal(env.get('reconcile-status').hidden,row.hidden);assert.equal(env.get('reconcile-status').textContent,env.run('t(presentationRow.key)'));assert.equal(env.get('reconcile-message').textContent,env.run('t(presentationRow.message)'));assert.equal(env.get('reconcile-message').hidden,false);assert.equal(env.run('workflowLifecycleUI.admissionRefused'),true);assert.equal(env.run('reconciliationUI.attempt'),null);assert.equal(env.get('reconcile-message').className,row.error?'hint error':'hint');}}
});

// Controller accounting is a source protocol, never a physical usage/space
// estimate or permission to admit another native operation.
function controllerStorageFixture(state='tracked',overrides={}){const empty=state==='uninitialized';return {state,scope:'tracked-controller-evidence-only',...(!empty?{generation:'a'.repeat(48),action:'discover'}:{}),generationsTracked:empty?0:1,reservedBytes:state==='tracked'?65536:0,retainedChargeBytes:empty?0:4096,uncertainBytes:state==='pending'?65536:0,finalizationReservedBytes:state==='tracked'?16384:0,legacyAccounting:'not-included',aggregateQuotaEnforced:false,physicalCapacityGuaranteed:false,nativeWritersContained:false,workerJournalBounded:false,...overrides};}
test('controller storage observation is GET-only, bounded and independent of profile loading, history work and current Cancel',async()=>{
 const env=onlineHistory(),calls=[];env.run('state.offline=true;historyUI.exporting=true;systemUI.busy=true;$("system-cancel").disabled=false');assert.equal(env.run('coreAvailable()'),false);assert.equal(env.get('controller-storage-refresh').disabled,false);env.context.fetch=async(path,options)=>{calls.push({path,options});return historyFixtureResponse(controllerStorageFixture())};await env.run('refreshControllerStorage()');assert.equal(calls.length,1);assert.equal(calls[0].path,'/api/v1/system/storage');assert.equal(calls[0].options.method,'GET');assert.equal(calls[0].options.body,undefined);assert.equal(calls[0].options.headers['X-AccessWeaver-Token'],'history-session');assert.equal(calls[0].options.credentials,'same-origin');assert.equal(calls[0].options.redirect,'error');assert.equal(calls[0].options.cache,'no-store');assert.equal(env.run('controllerStorageUI.status.state'),'tracked');assert.equal(env.get('controller-storage-values').hidden,false);assert.match(env.get('controller-storage-reserved').textContent,/65,536/);assert.equal(env.get('system-cancel').disabled,false);assert.equal(env.run('historyUI.exporting'),true);assert.equal(env.run('systemUI.busy'),true);assert.equal(env.get('controller-storage-refresh').disabled,false);
});
test('uninitialized controller tracking never displays zero disk usage or treats legacy evidence as empty',async()=>{
 const env=onlineHistory();env.context.fetch=async()=>historyFixtureResponse(controllerStorageFixture('uninitialized'));await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.status.state'),'uninitialized');assert.equal(env.get('controller-storage-values').hidden,true);assert.match(env.get('controller-storage-status').textContent,/does not mean the disk is empty/);assert.equal(env.get('controller-storage-generation').textContent,'');assert.equal(env.get('controller-storage-action').textContent,'');assert.equal(env.run('systemUI.plan'),null);
 env.context.fetch=async()=>historyFixtureResponse(controllerStorageFixture('pending'));await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.status.reservedBytes'),0);assert.equal(env.run('controllerStorageUI.status.uncertainBytes'),65536);assert.equal(env.get('controller-storage-values').hidden,false);assert.match(env.get('controller-storage-status').textContent,/not assumed complete/);
});
test('controller storage schema refuses missing/unknown fields, unsafe numbers, unknown actions and any unsupported quota guarantee',()=>{
 const env=onlineHistory(),base=controllerStorageFixture();for(const change of [{scope:'total-volume'},{legacyAccounting:'included'},{state:'clean'},{generation:'private/path'},{action:'private/path'},{action:'future-unknown-action'},{generationsTracked:1.5},{reservedBytes:-1},{retainedChargeBytes:Number.MAX_SAFE_INTEGER+1},{uncertainBytes:NaN},{finalizationReservedBytes:65537},{aggregateQuotaEnforced:true},{physicalCapacityGuaranteed:true},{nativeWritersContained:true},{workerJournalBounded:true},{reservedBytes:undefined},{futurePrivateField:'PRIVATE'}]){env.put('storageBad',{...base,...change});assert.throws(()=>env.run('controllerStorageProjection(storageBad)'));}
 for(const value of [controllerStorageFixture('uninitialized',{generation:'a'.repeat(48)}),controllerStorageFixture('uninitialized',{retainedChargeBytes:1}),controllerStorageFixture('pending',{reservedBytes:1}),controllerStorageFixture('pending',{finalizationReservedBytes:1}),controllerStorageFixture('tracked',{uncertainBytes:1})]){env.put('storageBad',value);assert.throws(()=>env.run('controllerStorageProjection(storageBad)'));}
 for(const action of [...plain(env.run('Object.keys(systemOperationText)')),'choose-folder']){env.put('storageAction',{...base,action});assert.equal(env.run('controllerStorageProjection(storageAction).action'),action);}
});
test('controller storage status failures are fixed/private, cancel oversized readers and never retain a prior clean value',async()=>{
 const env=onlineHistory();env.context.fetch=async()=>historyFixtureResponse(controllerStorageFixture());await env.run('refreshControllerStorage()');assert.ok(env.run('controllerStorageUI.status'));
 for(const code of ['workflow-storage-invalid','workflow-storage-denied','workflow-storage-policy-unavailable','workflow-storage-busy','workflow-storage-request-ended','workflow-storage-pending','workflow-storage-capacity','workflow-storage-unavailable','PRIVATE_UNKNOWN_CODE']){env.context.fetch=async()=>historyFixtureResponse({code,error:'PRIVATE_OS_PATH_OR_PROFILE'},code==='workflow-storage-capacity'?409:503);await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.status'),null);assert.equal(env.get('controller-storage-values').hidden,true);assert.doesNotMatch(env.get('controller-storage-status').textContent,/PRIVATE_|OS_PATH/);}
 let canceled=0;env.context.fetch=async()=>new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode(JSON.stringify({private:'PRIVATE'.repeat(1000)})))},cancel(){canceled++}}),{headers:{'Content-Type':'application/json'}});await env.run('refreshControllerStorage()');assert.equal(canceled,1);assert.equal(env.run('controllerStorageUI.message'),'controllerStorageInvalidResponse');assert.equal(env.run('controllerStorageUI.status'),null);
 for(const response of [new Response(new Uint8Array([255]),{headers:{'Content-Type':'application/json'}}),new Response('{}',{headers:{'Content-Type':'text/html'}})]){env.context.fetch=async()=>response;await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.message'),'controllerStorageInvalidResponse');}
});
test('controller storage late replies and finalizers cannot cross session, mode, navigation or a newer read',async()=>{
 for(const change of ['state.token="new-session";updateHistoryAvailability()','state.profileEditingOnly=true;updateHistoryAvailability()','state.view="profiles";historyNavigationChanged("profiles")']){const env=onlineHistory();let finish,signal;env.context.fetch=(_path,options)=>{signal=options.signal;return new Promise(resolve=>finish=resolve)};const request=env.run('refreshControllerStorage()');env.run(change);assert.equal(signal.aborted,true);finish(historyFixtureResponse(controllerStorageFixture()));await request;assert.equal(env.run('controllerStorageUI.status'),null);assert.equal(env.get('controller-storage-generation').textContent,'');assert.equal(env.run('controllerStorageUI.loading'),false);}
 const env=onlineHistory();let finish;env.context.fetch=()=>new Promise(resolve=>finish=resolve);const old=env.run('refreshControllerStorage()');env.run('resetControllerStorage(false)');env.context.fetch=async()=>historyFixtureResponse(controllerStorageFixture('pending'));await env.run('refreshControllerStorage()');finish(historyFixtureResponse(controllerStorageFixture()));await old;assert.equal(env.run('controllerStorageUI.status.state'),'pending');assert.equal(env.run('controllerStorageUI.loading'),false);
});
test('controller storage timeout cannot publish a late body from an abort-ignoring source',async()=>{
 const env=onlineHistory(),clock=reconciliationTimers(env);let body;env.context.fetch=async()=>new Response(new ReadableStream({start(controller){body=controller}}),{headers:{'Content-Type':'application/json'}});const request=env.run('refreshControllerStorage()');for(let turns=0;turns<50&&!body;turns++)await Promise.resolve();assert.ok(body);await clock.fire(12000);body.enqueue(new TextEncoder().encode(JSON.stringify(controllerStorageFixture())));body.close();await request;assert.equal(env.run('controllerStorageUI.status'),null);assert.equal(env.run('controllerStorageUI.message'),'controllerStorageEnded');assert.equal(env.get('controller-storage-refresh').disabled,false);
});
test('typed storage Start and folder refusal preserve inputs/current output, clear only review consent and invalidate older receipt eligibility',async()=>{
 for(const operation of ['applySystem()','chooseSystemFolder()'])for(const code of ['workflow-storage-capacity','workflow-storage-pending']){const env=onlineHistory(),calls=[];env.run('systemUI.plan={id:"reviewed-source",ready:true};$("system-consent").checked=true;$("system-applications").value="Retained app input";$("system-journal").value="retained-recovery.json";$("system-output").textContent="Original failed outcome";$("system-cancel").disabled=false');const epoch=env.run('workflowLifecycleUI.refusalEpoch');env.context.fetch=async(path,options)=>{calls.push({path,options});return historyFixtureResponse({code,error:'PRIVATE_STORAGE_CAUSE'},409)};await env.run(operation);assert.equal(calls.length,1);assert.equal(calls[0].path,operation.startsWith('apply')?'/api/v1/system/start':'/api/v1/system/folder');assert.equal(calls[0].options.method,'POST');assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-consent').checked,false);assert.equal(env.get('system-applications').value,'Retained app input');assert.equal(env.get('system-journal').value,'retained-recovery.json');assert.equal(env.get('system-output').textContent,'Original failed outcome');assert.equal(env.get('system-cancel').disabled,false);assert.equal(env.run('controllerStorageUI.refusal'),code);assert.equal(env.run('workflowLifecycleUI.refusalEpoch'),epoch+1);assert.equal(env.run('workflowLifecycleUI.admissionRefused'),false);assert.equal(env.context.document.activeElement.id,'controller-storage-title');assert.doesNotMatch(env.get('controller-storage-refusal').textContent,/PRIVATE_STORAGE/);}
});
test('generic storage reads and an older reconciliation receipt cannot erase a storage refusal; only a new adopted explicit review clears its hint',async()=>{
 const env=onlineHistory(),plan=reconciliationPlanFixture();let finishReceipt;env.context.fetch=async path=>path.endsWith('/preview')?historyFixtureResponse(plan):new Promise(resolve=>finishReceipt=resolve);await env.run('previewReconciliation()');env.get('reconcile-consent').checked=true;const oldApply=env.run('applyReconciliation()');env.run('handleControllerStorageAdmission({status:409,code:"workflow-storage-capacity"})');const epoch=env.run('workflowLifecycleUI.refusalEpoch');finishReceipt(historyFixtureResponse(reconciliationReceiptFixture(plan)));await oldApply;assert.equal(env.run('controllerStorageUI.refusal'),'workflow-storage-capacity');assert.equal(env.run('workflowLifecycleUI.refusalEpoch'),epoch);
 env.context.fetch=async()=>historyFixtureResponse(controllerStorageFixture());await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.refusal'),'workflow-storage-capacity');env.run('state.view="settings";historyNavigationChanged("settings");state.view="system";updateHistoryAvailability()');assert.equal(env.run('controllerStorageUI.refusal'),'workflow-storage-capacity');assert.equal(env.run('controllerStorageUI.status'),null);
 env.context.fetch=async(path,options)=>{assert.equal(path,'/api/v1/system/preview');assert.equal(options.method,'POST');return historyFixtureResponse({id:'new-reviewed-source',ready:true,request:{action:'discover'},steps:[],warnings:[],issues:[]})};await env.run('previewSystem({action:"discover"})');assert.equal(env.run('controllerStorageUI.refusal'),'');assert.equal(env.run('systemUI.plan.id'),'new-reviewed-source');assert.equal(env.get('system-consent').checked,false);assert.equal(env.run('workflowLifecycleUI.refusalEpoch'),epoch);
});
test('audited mode and changed sessions clear controller metadata and refuse direct status calls without affecting current Cancel',async()=>{
 const env=onlineHistory();env.context.fetch=async()=>historyFixtureResponse(controllerStorageFixture());await env.run('refreshControllerStorage()');env.run('handleControllerStorageAdmission({status:409,code:"workflow-storage-pending"});state.profileEditingOnly=true;updateHistoryAvailability()');assert.equal(env.run('controllerStorageUI.status'),null);assert.equal(env.run('controllerStorageUI.refusal'),'');assert.equal(env.get('controller-storage-card').hidden,true);let requests=0;env.context.fetch=async()=>{requests++;throw Error('Audited request must not be sent')};await env.run('refreshControllerStorage()');assert.equal(requests,0);
});
test('controller storage status, limits, counters and fixed errors are localized in all four languages',()=>{
 const env=onlineHistory(),keys=plain(env.run('Object.keys(en).filter(key=>key.startsWith("controllerStorage"))'));assert.ok(keys.length>20);for(const language of ['en','tr','ru','es']){env.put('storageLanguage',language);env.run('state.lang=storageLanguage');for(const key of keys){env.put('storageKey',key);assert.notEqual(env.run('t(storageKey)'),key);}env.put('localizedStorage',controllerStorageFixture('tracked',{action:'choose-folder'}));env.run('controllerStorageUI.status=controllerStorageProjection(localizedStorage);renderControllerStorage()');assert.notEqual(env.get('controller-storage-action').textContent,'choose-folder');assert.ok(env.get('controller-storage-action').textContent.length>10);}
});

test('actual Go controller storage wire remains logical, bounded and observation-only',{skip:!process.env.ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP},async()=>{
 const path=require('node:path'),crypto=require('node:crypto'),repo=path.resolve(__dirname,'..'),directory=path.resolve(process.env.ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP);
 const payloadNames=['uninitialized.json','pending.json','tracked.json'],names=[...payloadNames,'manifest.json'].sort();
 const dirs=['internal/api','internal/workflow','internal/managed','internal/fileidentity','internal/fileinput','internal/privatefile','internal/filelock','internal/nativeprocess','internal/nativepath','internal/logfile','internal/profile'];
 const fixed=['go.mod','go.sum','internal/workflow/windows.ps1','internal/workflow/reconciliation_test.go','internal/workflow/lifecycle_test.go','internal/workflow/shutdown_test.go','internal/workflow/reconciliation_export_test.go','internal/workflow/reconciliation_http_interop_test.go','internal/workflow/reconciliation_wire_interop_test.go','internal/workflow/controller_storage_wire_interop_test.go','internal/api/controller_storage_test.go','cmd/accessweaver/system_storage.go','cmd/accessweaver/system_storage_test.go','cmd/accessweaver/system.go','web/system.js','web/app.js','web/index.html','web/app.css','web/locales.js','web/app.test.cjs'];
 const hash=data=>crypto.createHash('sha256').update(data).digest('hex'),same=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
 const closed=(value,keys)=>{assert.ok(value&&typeof value==='object'&&!Array.isArray(value),'Wire object required');assert.ok(JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort()),'Unexpected storage wire schema');};
 function ordinary(target){const info=fs.lstatSync(target,{bigint:true});assert.ok(info.isDirectory()&&!info.isSymbolicLink(),'Ordinary storage wire directory required');return info;}
 function read(root,name,maximum){let fd;try{
  const parts=name.split('/');assert.ok(parts.every(part=>part&&part!=='.'&&part!=='..'&&!part.includes('\\')),'Fixed source components required');let parent=root;ordinary(parent);for(const part of parts.slice(0,-1)){parent=path.join(parent,part);ordinary(parent);}const target=path.join(parent,parts.at(-1)),named=fs.lstatSync(target,{bigint:true});assert.ok(named.isFile()&&!named.isSymbolicLink()&&named.size>=0n&&named.size<=BigInt(maximum),'Bounded ordinary storage wire file required');
  fd=fs.openSync(target,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const opened=fs.fstatSync(fd,{bigint:true});assert.ok(same(named,opened),'Storage wire changed while opening');let total=0;const chunks=[];
  for(;;){const buffer=Buffer.alloc(Math.min(32768,maximum+1-total)),n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;total+=n;assert.ok(total<=maximum,'Storage wire exceeded its read bound');chunks.push(buffer.subarray(0,n));}
  const after=fs.fstatSync(fd,{bigint:true}),current=fs.lstatSync(target,{bigint:true});assert.ok(current.isFile()&&!current.isSymbolicLink()&&same(opened,after)&&same(after,current)&&opened.size===after.size&&after.size===current.size&&opened.mtimeNs===after.mtimeNs&&after.mtimeNs===current.mtimeNs&&BigInt(total)===after.size,'Storage wire changed while reading');return Buffer.concat(chunks,total);
 }catch(error){if(error?.code)assert.fail('Storage wire source unavailable');throw error;}finally{if(fd!==undefined){try{fs.closeSync(fd)}catch{assert.fail('Storage wire Close failed')}}}}
 function parse(bytes){const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=JSON.parse(text);let at=0;const space=()=>{while(/[ \t\r\n]/.test(text[at]||''))at++;};function string(){const start=at++;for(;;){const c=text[at++];if(c==='"')return JSON.parse(text.slice(start,at));if(c==='\\')at++;}}
  function scan(depth){assert.ok(depth<=64,'Storage wire depth exceeded');space();const c=text[at];if(c==='{'){at++;space();const seen=new Set();if(text[at]==='}'){at++;return;}for(;;){const key=string();assert.equal(seen.has(key),false,'Duplicate storage wire JSON key');seen.add(key);space();assert.equal(text[at++],':');scan(depth+1);space();if(text[at++]==='}')return;space();}}else if(c==='['){at++;space();if(text[at]===']'){at++;return;}for(;;){scan(depth+1);space();if(text[at++]===']')return;space();}}else if(c==='"')string();else{const match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));assert.ok(match,'Invalid storage wire value');at+=match[0].length;}}
  scan(0);space();assert.equal(at,text.length,'Trailing storage wire JSON');return value;
 }
 const rootIdentity=ordinary(directory);assert.ok(JSON.stringify(fs.readdirSync(directory).sort())===JSON.stringify(names),'Unexpected storage wire files');
 const sources=[...fixed];for(const name of dirs){ordinary(path.join(repo,name));for(const entry of fs.readdirSync(path.join(repo,name),{withFileTypes:true})){if(!entry.name.endsWith('.go')||entry.name.endsWith('_test.go'))continue;assert.ok(entry.isFile()&&!entry.isSymbolicLink(),'Ordinary flat Go source required');sources.push(name+'/'+entry.name);}}sources.sort();assert.ok(sources.length<=256&&sources.length===new Set(sources).size,'Storage source list exceeded its closed bound');
 const manifestBytes=read(directory,'manifest.json',128*1024),manifest=parse(manifestBytes);closed(manifest,['schemaVersion','sources','files','expected']);assert.equal(manifest.schemaVersion,1);assert.ok(Array.isArray(manifest.sources)&&manifest.sources.length===sources.length,'Storage source count mismatch');assert.ok(JSON.stringify(manifest.sources.map(entry=>entry?.name))===JSON.stringify(sources),'Storage source enumeration mismatch');
 for(const entry of manifest.sources){closed(entry,['name','sha256']);assert.match(entry.sha256,/^[a-f0-9]{64}$/);assert.equal(hash(read(repo,entry.name,8*1024*1024)),entry.sha256,'Storage wire does not match current source');}
 closed(manifest.expected,['generation']);assert.match(manifest.expected.generation,/^[a-f0-9]{48}$/);assert.ok(Array.isArray(manifest.files)&&manifest.files.length===3,'Storage wire payload count mismatch');assert.ok(JSON.stringify(manifest.files.map(entry=>entry?.name).sort())===JSON.stringify([...payloadNames].sort()),'Unexpected or duplicated storage payload');
 const bytes={},metadata={},values={};for(const entry of manifest.files){closed(entry,['name','size','sha256','status','contentType']);assert.ok(payloadNames.includes(entry.name));assert.ok(Number.isSafeInteger(entry.size)&&entry.size>0&&entry.size<=4096);assert.match(entry.sha256,/^[a-f0-9]{64}$/);assert.equal(entry.status,200);assert.match(entry.contentType,/^application\/json(?:;\s*charset=utf-8)?$/i);bytes[entry.name]=read(directory,entry.name,4096);assert.equal(bytes[entry.name].length,entry.size);assert.equal(hash(bytes[entry.name]),entry.sha256);metadata[entry.name]=entry;values[entry.name]=parse(bytes[entry.name]);}
 const env=onlineHistory(),calls=[];let selected='uninitialized.json';env.run('systemUI.plan={id:"independent-reviewed-source",ready:true};$("system-consent").checked=true;$("system-applications").value="Retained source input";$("system-journal").value="source-recovery.json";$("system-output").textContent="Original outcome retained";$("system-cancel").disabled=false');
 env.context.fetch=async(target,options)=>{calls.push({target,options});assert.equal(target,'/api/v1/system/storage');assert.equal(options.method,'GET');assert.equal(options.body,undefined);assert.equal(options.headers['X-AccessWeaver-Token'],'history-session');assert.equal(options.redirect,'error');return new Response(bytes[selected],{status:metadata[selected].status,headers:{'Content-Type':metadata[selected].contentType}});};
 for(const name of payloadNames){env.put('actualStorage',values[name]);const projection=plain(env.run('controllerStorageProjection(actualStorage)'));assert.deepEqual(projection,values[name]);assert.equal(projection.scope,'tracked-controller-evidence-only');assert.equal(projection.legacyAccounting,'not-included');for(const field of ['aggregateQuotaEnforced','physicalCapacityGuaranteed','nativeWritersContained','workerJournalBounded'])assert.equal(projection[field],false);}
 await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.status.state'),'uninitialized');assert.equal(env.get('controller-storage-values').hidden,true);assert.equal(env.run('systemUI.plan.id'),'independent-reviewed-source');assert.equal(env.get('system-consent').checked,true);
 // This seeds only the actual frontend refusal handler. The three producer
 // files prove real API status, not an actual CLI/Start/native admission call.
 env.run('handleControllerStorageAdmission({status:409,code:"workflow-storage-pending"})');const refusalEpoch=env.run('workflowLifecycleUI.refusalEpoch');assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-consent').checked,false);
 selected='pending.json';await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.status.state'),'pending');assert.equal(env.run('controllerStorageUI.status.generation'),manifest.expected.generation);assert.ok(env.run('controllerStorageUI.status.uncertainBytes')>0);assert.equal(env.run('controllerStorageUI.status.reservedBytes'),0);assert.equal(env.run('controllerStorageUI.status.finalizationReservedBytes'),0);assert.equal(env.run('controllerStorageUI.refusal'),'workflow-storage-pending');
 selected='tracked.json';await env.run('refreshControllerStorage()');assert.equal(env.run('controllerStorageUI.status.state'),'tracked');assert.equal(env.run('controllerStorageUI.status.generation'),manifest.expected.generation);assert.equal(env.run('controllerStorageUI.status.reservedBytes'),0);assert.equal(env.run('controllerStorageUI.status.uncertainBytes'),0);assert.equal(env.run('controllerStorageUI.status.finalizationReservedBytes'),0);assert.ok(env.run('controllerStorageUI.status.retainedChargeBytes')>0);assert.equal(env.run('controllerStorageUI.refusal'),'workflow-storage-pending');assert.equal(env.run('workflowLifecycleUI.refusalEpoch'),refusalEpoch);assert.equal(env.run('systemUI.plan'),null);assert.equal(env.get('system-consent').checked,false);assert.equal(env.get('system-applications').value,'Retained source input');assert.equal(env.get('system-journal').value,'source-recovery.json');assert.equal(env.get('system-output').textContent,'Original outcome retained');assert.equal(env.get('system-cancel').disabled,false);assert.equal(calls.length,3);
 for(const entry of manifest.files)assert.equal(hash(read(directory,entry.name,4096)),entry.sha256,'Desktop changed actual storage wire bytes');assert.equal(hash(read(directory,'manifest.json',128*1024)),hash(manifestBytes));assert.ok(same(rootIdentity,ordinary(directory)));assert.ok(JSON.stringify(fs.readdirSync(directory).sort())===JSON.stringify(names));
});

// Optional actual Go HTTP responses. Default source runs never invent wire evidence.
test('actual Go support API wire validates and downloads only the current metadata summary',{skip:!process.env.ACCESSWEAVER_SUPPORT_INTEROP},async()=>{
 const path=require('node:path'),crypto=require('node:crypto'),repo=path.resolve(__dirname,'..'),directory=path.resolve(process.env.ACCESSWEAVER_SUPPORT_INTEROP);
 const payloadNames=['available.json','unavailable.json'],names=[...payloadNames,'manifest.json'].sort();
 const dirs=['internal/api','internal/audit','internal/buildinfo','internal/engine','internal/fileidentity','internal/fileinput','internal/filelock','internal/logfile','internal/managed','internal/nativepath','internal/nativeprocess','internal/privatefile','internal/profile','internal/workflow'];
 const fixed=['go.mod','go.sum','internal/workflow/windows.ps1','internal/api/server_test.go','internal/api/support_test.go','internal/api/support_wire_interop_test.go','web/app.js','web/system.js','web/locales.js','web/index.html','web/app.css','web/app.test.cjs'];
 const hash=data=>crypto.createHash('sha256').update(data).digest('hex'),same=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
 const closed=(value,keys)=>{assert.ok(value&&typeof value==='object'&&!Array.isArray(value),'Wire object required');assert.ok(JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort()),'Unexpected support wire schema');};
 function ordinary(target){const info=fs.lstatSync(target,{bigint:true});assert.ok(info.isDirectory()&&!info.isSymbolicLink(),'Ordinary support wire directory required');return info;}
 function read(root,name,maximum){let fd;try{
  const parts=name.split('/');assert.ok(parts.every(part=>part&&part!=='.'&&part!=='..'&&!part.includes('\\')),'Fixed source components required');let parent=root;ordinary(parent);for(const part of parts.slice(0,-1)){parent=path.join(parent,part);ordinary(parent);}const target=path.join(parent,parts.at(-1)),named=fs.lstatSync(target,{bigint:true});assert.ok(named.isFile()&&!named.isSymbolicLink()&&named.size>=0n&&named.size<=BigInt(maximum),'Bounded ordinary support wire file required');
  fd=fs.openSync(target,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const opened=fs.fstatSync(fd,{bigint:true});assert.ok(same(named,opened),'Support wire changed while opening');let total=0;const chunks=[];
  for(;;){const buffer=Buffer.alloc(Math.min(32768,maximum+1-total)),n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;total+=n;assert.ok(total<=maximum,'Support wire exceeded its read bound');chunks.push(buffer.subarray(0,n));}
  const after=fs.fstatSync(fd,{bigint:true}),current=fs.lstatSync(target,{bigint:true});assert.ok(current.isFile()&&!current.isSymbolicLink()&&same(opened,after)&&same(after,current)&&opened.size===after.size&&after.size===current.size&&opened.mtimeNs===after.mtimeNs&&after.mtimeNs===current.mtimeNs&&BigInt(total)===after.size,'Support wire changed while reading');return Buffer.concat(chunks,total);
 }catch(error){if(error?.code)assert.fail('Support wire source unavailable');throw error;}finally{if(fd!==undefined){try{fs.closeSync(fd)}catch{assert.fail('Support wire Close failed')}}}}
 function parse(bytes){const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=JSON.parse(text);let at=0;const space=()=>{while(/[ \t\r\n]/.test(text[at]||''))at++;};function string(){const start=at++;for(;;){const c=text[at++];if(c==='"')return JSON.parse(text.slice(start,at));if(c==='\\')at++;}}
  function scan(depth){assert.ok(depth<=64,'Support wire depth exceeded');space();const c=text[at];if(c==='{'){at++;space();const seen=new Set();if(text[at]==='}'){at++;return;}for(;;){const key=string();assert.equal(seen.has(key),false,'Duplicate support wire JSON key');seen.add(key);space();assert.equal(text[at++],':');scan(depth+1);space();if(text[at++]==='}')return;space();}}else if(c==='['){at++;space();if(text[at]===']'){at++;return;}for(;;){scan(depth+1);space();if(text[at++]===']')return;space();}}else if(c==='"')string();else{const match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));assert.ok(match,'Invalid support wire value');at+=match[0].length;}}
  scan(0);space();assert.equal(at,text.length,'Trailing support wire JSON');return value;
 }
 const rootIdentity=ordinary(directory);assert.deepEqual(fs.readdirSync(directory).sort(),names,'Unexpected support wire files');
 const sources=[...fixed];for(const name of dirs){ordinary(path.join(repo,name));for(const entry of fs.readdirSync(path.join(repo,name),{withFileTypes:true})){if(!entry.name.endsWith('.go')||entry.name.endsWith('_test.go'))continue;assert.ok(entry.isFile()&&!entry.isSymbolicLink(),'Ordinary flat Go source required');sources.push(name+'/'+entry.name);}}sources.sort();assert.ok(sources.length<=512&&sources.length===new Set(sources).size,'Support source list exceeded its closed bound');
 const manifestBytes=read(directory,'manifest.json',128*1024),manifest=parse(manifestBytes);closed(manifest,['schemaVersion','sources','files','expected']);assert.equal(manifest.schemaVersion,1);assert.ok(Array.isArray(manifest.sources)&&manifest.sources.length===sources.length);assert.deepEqual(manifest.sources.map(entry=>entry.name),sources,'Exact independently collected support sources required');closed(manifest.expected,['availableTotal','availableEngine']);assert.equal(manifest.expected.availableTotal,1);assert.equal(manifest.expected.availableEngine,'byedpi');
 for(const entry of manifest.sources){closed(entry,['name','sha256']);assert.match(entry.sha256,/^[a-f0-9]{64}$/);assert.equal(hash(read(repo,entry.name,8*1024*1024)),entry.sha256,'Support source binding mismatch');}
 assert.ok(Array.isArray(manifest.files)&&manifest.files.length===payloadNames.length);assert.deepEqual(manifest.files.map(entry=>entry.name).sort(),[...payloadNames].sort());
 const bytes={},metadata={},values={};for(const entry of manifest.files){closed(entry,['name','size','sha256','status','contentType']);assert.ok(payloadNames.includes(entry.name));assert.ok(Number.isSafeInteger(entry.size)&&entry.size>0&&entry.size<=16*1024);assert.match(entry.sha256,/^[a-f0-9]{64}$/);assert.equal(entry.status,200);assert.match(entry.contentType,/^application\/json(?:;\s*charset=utf-8)?$/i);bytes[entry.name]=read(directory,entry.name,16*1024);assert.equal(bytes[entry.name].length,entry.size);assert.equal(hash(bytes[entry.name]),entry.sha256);metadata[entry.name]=entry;values[entry.name]=parse(bytes[entry.name]);}
 const env=environment();supportReady(env);const calls=[],downloads=[];let selected=payloadNames[0];env.context.fetch=async(target,options)=>{calls.push({target,options});assert.equal(target,'/api/v1/support');assert.equal(options.method,'GET');assert.equal(options.body,undefined);assert.equal(options.headers['X-AccessWeaver-Token'],'fixture');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');return new Response(bytes[selected],{status:metadata[selected].status,headers:{'Content-Type':metadata[selected].contentType}})};env.context.downloadFile=(data,name)=>downloads.push({data,name});
 for(const name of payloadNames){env.put('actualSupport',values[name]);assert.deepEqual(plain(env.run('supportMetadataReport(actualSupport)')),values[name]);selected=name;await env.run('exportSupportSummary()');assert.equal(downloads.length,calls.length);assert.deepEqual(JSON.parse(downloads.at(-1).data),values[name]);assert.equal(downloads.at(-1).name,'accessweaver-support-summary.json');assert.equal(env.run('state.supportExporting'),false);assert.equal(env.get('export-support').disabled,false);}
 assert.equal(values['available.json'].profiles.status,'available');assert.equal(values['available.json'].profiles.total,manifest.expected.availableTotal);assert.equal(values['available.json'].profiles.byEngine[manifest.expected.availableEngine],manifest.expected.availableTotal);assert.equal(values['unavailable.json'].profiles.status,'unavailable');assert.equal(values['unavailable.json'].profiles.total,null);assert.equal(calls.length,2);
 for(const entry of manifest.files)assert.equal(hash(read(directory,entry.name,16*1024)),entry.sha256,'Desktop changed actual support wire bytes');assert.equal(hash(read(directory,'manifest.json',128*1024)),hash(manifestBytes));assert.ok(same(rootIdentity,ordinary(directory)));assert.deepEqual(fs.readdirSync(directory).sort(),names);
});

function modalKeyboardFixture(candidates=[]) {
 const env=environment(),modal=env.get('editor-modal'),dialog=env.get('modal-keyboard-dialog');
 modal.hidden=false;dialog.tabIndex=-1;
 env.context.document.querySelectorAll=selector=>selector==='.modal-backdrop'?[modal]:[];
 modal.querySelector=selector=>selector==='[role="dialog"]'?dialog:null;
 modal.querySelectorAll=selector=>candidates.filter(el=>el.tagName!=='SUMMARY'||selector.includes('summary'));
 modal.contains=element=>element===dialog||element===modal||candidates.includes(element);
 env.context.getComputedStyle=element=>({visibility:element.visibility||'visible'});
 for(const element of candidates){element.tabIndex??=0;element.getClientRects??=()=>[{}];element.matches??=()=>false;element.focus=()=>{env.context.document.activeElement=element};}
 const press=shiftKey=>{let prevented=0;env.context.keyboardEvent={key:'Tab',shiftKey,preventDefault(){prevented++}};env.run('trapModalKeys(keyboardEvent)');return prevented;};
 return {...env,modal,dialog,press};
}
test('modal keyboard keeps Tab and Shift+Tab inside a dialog without sequential controls',()=>{
 const env=modalKeyboardFixture();
 for(const shift of [false,true]){env.context.document.activeElement=env.context.document.body;assert.equal(env.press(shift),1);assert.equal(env.context.document.activeElement,env.dialog);}
});
test('modal keyboard includes the native summary when all form buttons are disabled',()=>{
 const env=environment(),summary=env.get('modal-keyboard-summary');summary.tagName='SUMMARY';
 const modal=modalKeyboardFixture([summary]);modal.context.document.activeElement=summary;
 for(const shift of [false,true]){assert.equal(modal.press(shift),1);assert.equal(modal.context.document.activeElement,summary);}
});
test('modal keyboard ignores unrendered and invisible controls when wrapping',()=>{
 const env=environment(),first=env.get('modal-keyboard-first'),closed=env.get('modal-keyboard-closed'),invisible=env.get('modal-keyboard-invisible');
 closed.getClientRects=()=>[];invisible.visibility='hidden';
 const modal=modalKeyboardFixture([first,closed,invisible]);modal.context.document.activeElement=first;
 assert.equal(modal.press(true),1);assert.equal(modal.context.document.activeElement,first);
});

test('runtime polling cannot re-enable Preview while an editor save is pending',()=>{
 const env=environment();env.run('state.offline=false;state.loading=false;state.disconnected=false;state.coreAuthenticated=true;state.token="fixture";state.editing={saving:true};renderHero()');
 assert.equal(env.get('preview-profile').disabled,true);
 env.run('state.editing.saving=false;renderHero()');assert.equal(env.get('preview-profile').disabled,false);
});


test('dashboard defers the full256profile DOM until entry and keeps the visited collection current',()=>{
 const env=environment(),profiles=Array.from({length:256},(_,i)=>({...baseProfile(),id:'large-'+i,name:'Large profile '+i}));env.put('collection',profiles);env.run('state.loading=false;state.profiles=collection;renderProfiles()');
 const cards=element=>(element.innerHTML.match(/<article class="profile-card/g)||[]).length;
 assert.equal(cards(env.get('quick-profiles')),3);assert.equal(env.get('all-profiles').innerHTML,'');env.run('navigate("profiles")');assert.equal(cards(env.get('all-profiles')),256);assert.ok(env.get('profile-result-count').textContent.startsWith('256 / 256'));
 env.run('navigate("dashboard");state.profiles[0].name="Updated after visit";renderProfiles()');assert.ok(env.get('all-profiles').innerHTML.includes('Updated after visit'));assert.equal(cards(env.get('all-profiles')),256);env.run('navigate("profiles")');assert.equal(cards(env.get('all-profiles')),256);
});
test('first profile-view render honors search, engine filter and direct navigation without dropping stored profiles',()=>{
 const env=environment(),profiles=Array.from({length:256},(_,i)=>({...baseProfile(),id:'large-'+i,name:'Large profile '+i}));env.put('collection',profiles);env.run('state.loading=false;state.profiles=collection;state.view="profiles";$("profile-search").value="Large profile 255";renderProfiles()');assert.equal((env.get('all-profiles').innerHTML.match(/<article class="profile-card/g)||[]).length,1);assert.ok(env.get('all-profiles').innerHTML.includes('Large profile 255'));assert.ok(env.get('profile-result-count').textContent.startsWith('1 / 256'));env.run('$("profile-filter").value="wiresock";renderProfiles()');assert.ok(env.get('all-profiles').innerHTML.includes('empty-card'));assert.equal(env.run('state.profiles.length'),256);
});

test('raw profile JSON rejects duplicate and escaped keys before object conversion',()=>{
  const env=environment(),source=JSON.stringify(baseProfile());
  for(const text of [source.replace('"id":','"id":"test-profile","id":'),source.replace('"name":','"\\u006eame":"PRIVATE_DUPLICATE_VALUE","name":'),source.replace('"tls":','"tls":false,"tls":'),source.replace('"includeDomains":','"includeDomains":[],"includeDomains":')]){
    env.context.rawJSON=text;
    assert.throws(()=>env.run('parseProfileJSON(rawJSON)'),/Use each JSON field name only once/);
    assert.equal(env.run('state.editing'),null);assert.equal(env.data.has('aw.profiles'),false);
  }
  env.context.rawJSON=JSON.stringify({...baseProfile(),notes:'escaped "quote", slash \\ and true null [ ] { }'});
  assert.equal(plain(env.run('parseProfileJSON(rawJSON)')).notes,JSON.parse(env.context.rawJSON).notes);
  env.context.rawJSON=JSON.stringify(baseProfile(),null,2);
  assert.deepEqual(plain(env.run('parseProfileJSON(rawJSON)')),baseProfile());
});
test('invalid raw advanced JSON preserves editor mode, draft and saved profiles',async()=>{
  const env=environment();env.put('fixture',baseProfile());env.run('state.profiles=[fixture];showEditor(fixture);switchEditor("advanced");');
  const raw=JSON.stringify(baseProfile()).replace('"name":','"name":"PRIVATE_DRAFT","name":');env.get('p-json').value=raw;
  env.run('markDirty();switchEditor("simple")');
  assert.equal(env.run('state.editorTab'),'advanced');assert.equal(env.get('p-json').value,raw);
  await env.run('saveEditor()');
  assert.equal(env.run('state.editing.dirty'),true);assert.equal(env.get('p-json').value,raw);
  assert.deepEqual(plain(env.run('state.profiles')),[baseProfile()]);assert.equal(env.data.has('aw.profiles'),false);
  assert.match(env.get('editor-feedback').textContent,/Use each JSON field name only once/);
});
test('profile file import rejects ambiguous or malformed bytes without replacing a draft',async()=>{
  const env=environment();env.put('fixture',baseProfile());env.run('showEditor(fixture);markDirty()');
  const draft=plain(env.run('state.editing'));
  const valid=JSON.stringify(baseProfile());
  for(const bytes of [valid.replace('"id":','"id":"test-profile","id":'),new Uint8Array([0xff]),'\ufeff'+valid]){
    env.context.fileFixture=new Blob([bytes]);await env.run('importProfile(fileFixture)');
    assert.deepEqual(plain(env.run('state.editing')),draft);assert.equal(env.data.has('aw.profiles'),false);
  }
});
test('raw profile JSON enforces byte and nesting budgets',()=>{
  const env=environment();env.context.rawJSON=JSON.stringify({...baseProfile(),notes:'x'.repeat(1<<20)});
  assert.throws(()=>env.run('parseProfileJSON(rawJSON)'));
  env.context.rawJSON='{"x":'+'['.repeat(17)+'0'+']'.repeat(17)+'}';
  assert.throws(()=>env.run('parseProfileJSON(rawJSON)'));
});

test('raw JSON scanner preserves escaped and multilingual values from canonical profiles',()=>{
  const env=environment();
  for(let index=0;index<100;index++){
    const profile={...baseProfile(),name:'Fixture '+index,notes:('quote " slash \\ braces {} [] true null Türkçe Русский Español\n').repeat(index%5+1),args:['',String(index),'value with "quote" and \\ slash','line\nbreak']};
    env.context.rawJSON=JSON.stringify(profile,null,index%4);
    assert.deepEqual(plain(env.run('parseProfileJSON(rawJSON)')),profile);
  }
});

test('profile grids retain unchanged markup across navigation and still reflect every changed input',()=>{
  const env=environment(),writes={all:0,quick:0};let all='',quick='';
  Object.defineProperty(env.get('all-profiles'),'innerHTML',{get:()=>all,set:value=>{writes.all++;all=value},configurable:true});
  Object.defineProperty(env.get('quick-profiles'),'innerHTML',{get:()=>quick,set:value=>{writes.quick++;quick=value},configurable:true});
  env.put('fixture',baseProfile());env.run('state.view="profiles";state.profiles=[fixture];renderProfiles()');
  assert.deepEqual(writes,{all:1,quick:1});
  env.run('state.view="dashboard";renderProfiles();state.view="profiles";renderProfiles()');
  assert.deepEqual(writes,{all:1,quick:1});
  env.run('state.profiles[0].name="Changed name";renderProfiles()');
  assert.deepEqual(writes,{all:2,quick:2});assert.match(all,/Changed name/);
  env.get('profile-search').value='no match';env.run('renderProfiles()');assert.equal(writes.all,3);assert.equal(writes.quick,2);
  env.get('profile-search').value='';env.run('renderProfiles()');assert.equal(writes.all,4);
  env.run('state.lang="tr";renderProfiles()');assert.equal(writes.all,5);assert.equal(writes.quick,3);
  env.run('state.busy=true;renderProfiles()');assert.equal(writes.all,6);assert.equal(writes.quick,4);
  env.run('state.profiles=[];renderProfiles()');assert.equal(writes.all,7);assert.equal(writes.quick,5);
});


test('unchanged dashboard polling preserves status text, control nodes and focused action',async()=>{
 const env=environment();env.run('state.loading=false;state.offline=false;state.coreAuthenticated=true;state.token="fixture";state.platform="linux";state.runtime={state:"stopped"};renderHero()');let writes=0;
 for(const [id,keys] of [['hero-status',['textContent']],['status-badge',['textContent','className']],['stats-profiles',['textContent']],['hero-primary',['innerHTML','disabled']],['connection-notice',['hidden']]])for(const key of keys){const node=env.get(id);let value=node[key];Object.defineProperty(node,key,{get(){return value},set(next){writes++;value=next},configurable:true})}
 env.get('hero-primary').focus();env.run('apiRequest=async()=>({state:"stopped"});');await env.run('pollStatus()');env.run('renderHero();renderHero()');assert.equal(writes,0);assert.equal(env.context.document.activeElement,env.get('hero-primary'));
 env.run('state.runtime={state:"running",engine:"byedpi",profileId:"fixture",pid:321};renderHero()');assert.equal(env.get('hero-status').textContent,env.run('t("running")'));assert.match(env.get('running-engine').textContent,/321/);assert.ok(env.get('hero-primary').innerHTML.includes(env.run('icon("stop")')));assert.ok(writes>0);
 env.run('state.busy=true;renderHero()');assert.equal(env.get('hero-primary').disabled,true);env.run('state.busy=false;state.runtime.lifecyclePending=true;renderHero()');assert.ok(env.get('hero-primary').innerHTML.includes(env.run('icon("alert")')));assert.equal(env.get('hero-primary').disabled,true);env.run('state.runtime={state:"stopped"};state.lang="es";renderHero()');assert.equal(env.get('hero-status').textContent,env.run('t("ready")'));assert.equal(env.get('hero-primary').disabled,false);assert.ok(env.get('hero-primary').innerHTML.includes(env.run('t("selectProfile")')));
});


test('engine library retains unchanged controls and reflects platform, catalog and language changes',()=>{
 const env=environment(),writes={engines:0,platforms:0};let engines='',platforms='';
 Object.defineProperty(env.get('engines-grid'),'innerHTML',{get:()=>engines,set:value=>{writes.engines++;engines=value},configurable:true});
 Object.defineProperty(env.get('platform-matrix'),'innerHTML',{get:()=>platforms,set:value=>{writes.platforms++;platforms=value},configurable:true});
 env.run('state.engines=[{...exampleEngines[0],platforms:["linux"],integration:"managed"}];state.loading=false;state.offline=false;state.platform="linux";renderEngines()');
 assert.deepEqual(writes,{engines:1,platforms:1});
 env.run('state.profiles=[];renderEngines();renderEngines()');assert.deepEqual(writes,{engines:1,platforms:1});
 env.run('state.engines[0].name="Changed engine label";renderEngines()');assert.deepEqual(writes,{engines:2,platforms:1});assert.match(engines,/Changed engine label/);
 env.run('state.platform="windows";renderEngines()');assert.deepEqual(writes,{engines:3,platforms:1});assert.ok(engines.includes(env.run('t("engineUnsupported")')));assert.doesNotMatch(engines,/class="current-platform"/);
 env.run('state.offline=true;renderEngines()');assert.equal(writes.engines,4);assert.ok(engines.includes(env.run('t("platformUnknown")')));
 env.run('state.lang="tr";renderEngines()');assert.deepEqual(writes,{engines:5,platforms:2});assert.ok(platforms.includes(env.run('t("windowsSupport")')));
 env.run('state.engines=[];renderEngines()');assert.deepEqual(writes,{engines:6,platforms:2});assert.equal(engines,'');
 env.run('renderEngines()');assert.deepEqual(writes,{engines:6,platforms:2});
});


test('dynamic icons preserve canonical symbol geometry without use instance trees',()=>{
 const env=environment();let count=0;
 for(const match of html.matchAll(/<symbol\b([^>]*\bid="i-([^"]+)"[^>]*)>([\s\S]*?)<\/symbol>/g)){
  const viewBox=/\bviewBox="([^"]*)"/.exec(match[1])[1];env.context.glyphName=match[2];const markup=env.run('icon(glyphName)');
  assert.match(markup,/<svg\b[^>]*aria-hidden="true"/);assert.ok(markup.includes('viewBox="'+viewBox+'"'));
  assert.equal(markup.replace(/^<svg\b[^>]*>/,'').replace(/<\/svg>$/,''),match[3]);assert.doesNotMatch(markup,/<use\b/);count++;
 }
 assert.ok(count>20);
 for(const name of ['unknown','<img src=x>','constructor','__proto__']){env.context.glyphName=name;const markup=env.run('icon(glyphName)');assert.match(markup,/<svg\b[^>]*aria-hidden="true"/);assert.doesNotMatch(markup,/<use\b|<img\b|constructor|__proto__/);}
});

test('editor input retains unchanged engine guidance while domain counts stay live',()=>{
 const env=environment(),writes={guidance:0,capability:0,counts:0};
 for(const [id,key,field] of [['engine-guidance','innerHTML','guidance'],['rule-capability','textContent','capability'],['domain-count','textContent','counts']]){
  const node=env.get(id);let value=node[key];Object.defineProperty(node,key,{get:()=>value,set:next=>{writes[field]++;value=next},configurable:true});
 }
 env.put('fixture',baseProfile());env.run('showEditor(fixture)');assert.deepEqual(writes,{guidance:1,capability:1,counts:1});
 const initial=env.get('engine-guidance').innerHTML;
 for(let i=0;i<20;i++){env.get('p-name').value='Draft '+i;env.run('markDirty()');}
 assert.deepEqual(writes,{guidance:1,capability:1,counts:1});assert.equal(env.get('engine-guidance').innerHTML,initial);assert.equal(env.run('state.editing.dirty'),true);
 env.get('p-includes').value='one.example\ntwo.example';env.get('p-excludes').value='excluded.example';env.run('markDirty()');
 assert.deepEqual(writes,{guidance:1,capability:1,counts:2});assert.equal(env.get('domain-count').textContent,env.run('"2 "+t("includeCount")+" \u00b7 1 "+t("excludeCount")'));
 assert.equal(env.get('p-includes').getAttribute('aria-describedby'),'rule-capability');assert.equal(env.get('p-excludes').getAttribute('aria-describedby'),'rule-capability');
 env.run('closeEditor(true);showEditor(fixture)');assert.equal(writes.guidance,1);assert.equal(env.get('p-name').value,baseProfile().name);
});

test('editor guidance updates for engine, catalog and language changes without caching draft inputs',()=>{
 const env=environment();env.put('fixture',baseProfile());env.run('showEditor(fixture)');const initial=env.get('engine-guidance').innerHTML;
 env.get('p-engine').value='wiresock';env.get('p-binary').value='private-draft-binary';env.run('updateEditorGuidance()');
 assert.notEqual(env.get('engine-guidance').innerHTML,initial);assert.ok(env.get('engine-guidance').innerHTML.includes('WireSock'));assert.equal(env.get('p-binary').placeholder,'wiresock-client.exe');assert.equal(env.get('p-binary').value,'private-draft-binary');
 assert.equal(env.get('rule-capability').textContent,env.run('t("unsupportedIncludes")+" "+t("unsupportedExcludes")'));
 env.run('state.engines=state.engines.map(e=>e.id==="wiresock"?{...e,name:"Changed <engine>",source:"https://docs.example/engine?a=1&b=2",executables:["changed-engine"]}:e);updateEditorGuidance()');
 assert.match(env.get('engine-guidance').innerHTML,/Changed &lt;engine&gt;/);assert.match(env.get('engine-guidance').innerHTML,/href="https:\/\/docs.example\/engine\?a=1&amp;b=2"/);assert.equal(env.get('p-binary').placeholder,'changed-engine');
 for(const language of ['tr','ru','es','en']){env.context.fixtureLanguage=language;env.run('state.lang=fixtureLanguage;updateEditorGuidance()');assert.ok(env.get('engine-guidance').innerHTML.includes(env.run('escapeHTML(t("engineDocs"))')));assert.ok(env.get('engine-guidance').innerHTML.includes(env.run('escapeHTML(engineGuide("wiresock"))')));assert.equal(env.get('rule-capability').textContent,env.run('t("unsupportedIncludes")+" "+t("unsupportedExcludes")'));assert.equal(env.get('p-binary').value,'private-draft-binary');}
 env.run('state.engines=state.engines.map(e=>e.id==="wiresock"?{...e,source:"javascript:untrusted"}:e);updateEditorGuidance()');assert.match(env.get('engine-guidance').innerHTML,/href="#"/);assert.doesNotMatch(env.get('engine-guidance').innerHTML,/javascript:/);
});


test('inactive feedback cleanup cancels only owned background CSS transitions',()=>{
 const env=environment(),shell=env.get('app-shell'),owned=new Set(),cancelled=[];shell.inert=true;shell.contains=node=>owned.has(node);
 const target=(kind,inside=true)=>{const node={matches(selector){assert.equal(selector,'.btn,.nav-item,.profile-card');return ['button','navigation','card'].includes(kind)}};if(inside)owned.add(node);return node};
 const transition=(name,node)=>({transitionProperty:'transform',effect:{target:node},cancel(){cancelled.push(name)}});
 const button=target('button'),navigation=target('navigation'),card=target('card'),dialog=target('button',false),other=target('other');
 const rows=[transition('button',button),transition('navigation',navigation),transition('card',card),transition('dialog',dialog),transition('other',other),transition('detached',null),{animationName:'feedback',effect:{target:button},cancel(){cancelled.push('css-animation')}},{effect:{target:button},cancel(){cancelled.push('web-animation')}}];
 let scans=0;env.context.document.getAnimations=()=>{scans++;return rows};env.run('settleInactiveFeedback(document.querySelector(".app-shell"))');assert.deepEqual(cancelled,['button','navigation','card']);assert.equal(scans,1);
 shell.inert=false;env.run('settleInactiveFeedback(document.querySelector(".app-shell"))');env.run('settleInactiveFeedback(null)');assert.equal(scans,1);
});

test('feedback cleanup tolerates unavailable animation APIs and individual failures without exposing errors',()=>{
 const env=environment(),shell=env.get('app-shell');shell.inert=true;shell.contains=()=>true;env.run('settleInactiveFeedback(document.querySelector(".app-shell"))');
 env.context.document.getAnimations=()=>{throw Error('SYNTHETIC_PRIVATE_ANIMATION_CANARY')};assert.doesNotThrow(()=>env.run('settleInactiveFeedback(document.querySelector(".app-shell"))'));
 let cancelled=0;const node={matches(){return true}},brokenName={get transitionProperty(){throw Error('SYNTHETIC_PRIVATE_ANIMATION_CANARY')}},brokenTarget={get effect(){throw Error('SYNTHETIC_PRIVATE_ANIMATION_CANARY')}},brokenCancel={transitionProperty:'transform',effect:{target:node},cancel(){throw Error('SYNTHETIC_PRIVATE_ANIMATION_CANARY')}};
 env.context.document.getAnimations=()=>[brokenName,brokenTarget,brokenCancel,{transitionProperty:'transform',effect:{target:node},cancel(){cancelled++}}];assert.doesNotThrow(()=>env.run('settleInactiveFeedback(document.querySelector(".app-shell"))'));assert.equal(cancelled,1);
});

test('modal activation marks its shell inert before feedback cleanup and close restores input',()=>{
 const env=environment(),shell=env.get('app-shell'),modal=env.get('editor-modal'),states=[];shell.contains=node=>node.id==='owned-feedback';
 env.context.document.querySelectorAll=selector=>selector==='.modal-backdrop'?[modal]:[];
 env.context.document.body.classList.toggle=(name,active)=>{assert.equal(name,'modal-open');states.push(active)};
 let cancelled=0;env.context.document.getAnimations=()=>[{transitionProperty:'transform',effect:{target:{id:'owned-feedback',matches(){return true}}},cancel(){assert.equal(shell.inert,true);cancelled++}}];
 env.run('setModal("editor-modal",true)');assert.equal(modal.hidden,false);assert.equal(shell.inert,true);assert.equal(cancelled,1);
 env.run('setModal("editor-modal",false)');assert.equal(modal.hidden,true);assert.equal(shell.inert,false);assert.equal(cancelled,1);assert.deepEqual(states,[true,false]);
});
