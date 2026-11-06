const base = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { createHash } = require('node:crypto');
const { expect } = base;
const {settleAnimations,scanAccessibility,assertControlContrast}=require('./accessibility.cjs');
const repo = path.resolve(__dirname, '../..');
const binary = path.resolve(process.env.ACCESSWEAVER_BINARY || path.join(repo, 'build/browser-tests', process.platform === 'win32' ? 'accessweaver.exe' : 'accessweaver'));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const test = base.test.extend({
  core: async ({browser}, use, testInfo) => {
    const parent = path.join(repo, 'build/browser-state');
    await fs.mkdir(parent, {recursive:true, mode:0o700});
    const home = await fs.mkdtemp(path.join(parent, 'case-'));
    const cache = path.join(home, 'cache');
    let child, output = '', startError;
    const exited = () => !child || child.exitCode!==null || child.signalCode!==null;
    try {
      await fs.mkdir(cache, {mode:0o700});
      child = spawn(binary, ['ui'], {windowsHide:true, stdio:['ignore','pipe','pipe'], env:{...process.env,
        ACCESSWEAVER_HOME:path.join(home,'state'), ACCESSWEAVER_NO_BROWSER:'1', XDG_CACHE_HOME:cache, LOCALAPPDATA:cache}});
      child.once('error', error => {startError=error;});
      child.stdout?.on('data', data => {output=(output+data.toString()).slice(-65536);});
      child.stderr?.on('data', data => {output=(output+data.toString()).slice(-65536);});
      const deadline=Date.now()+15_000;
      let launcher;
      while(!(launcher=output.match(/Open this private launch file in your browser: (file:[^\r\n]+)/)?.[1])) {
        if(startError) throw startError;
        if(exited()) throw new Error('Controller exited before its launcher was ready: '+output);
        if(Date.now()>deadline) throw new Error('Controller did not produce a private launcher');
        await delay(25);
      }
      const binarySha256=createHash('sha256').update(await fs.readFile(binary)).digest('hex');
      const build=JSON.parse(execFileSync(binary,['version','--json'],{windowsHide:true,encoding:'utf8'}));
      if(process.env.GITHUB_ACTIONS==='true'){
        expect(build.commit).toBe(process.env.GITHUB_SHA);
        expect(build.sourceState).toBe('clean');
      }
      await testInfo.attach('candidate.json', {body:JSON.stringify({
        binarySha256,
        platform:process.platform, architecture:process.arch, node:process.version,
        browser:browser.version(), project:testInfo.project.name,
        playwright:require('@playwright/test/package.json').version,
        build,
      }), contentType:'application/json'});
      await use({launcher, home, build, binarySha256, profilePath:id=>path.join(home,'state','profiles',id+'.json')});
    } finally {
      if(!exited() && child.pid) {
        const exitEvent=once(child,'exit');
        child.kill('SIGTERM');
        await Promise.race([exitEvent,delay(5000)]);
        if(!exited()) {child.kill('SIGKILL');await Promise.race([exitEvent,delay(5000)]);}
        if(!exited()) throw new Error('Isolated test controller did not stop');
      }
      // Delete only the verified owned fixture after its process stops. Private
      // launchers, state and caches are never retained with public test evidence.
      const info=await fs.lstat(home),resolved=await fs.realpath(home),intended=await fs.realpath(parent);
      if(!info.isDirectory()||info.isSymbolicLink()||path.dirname(resolved)!==intended||!path.basename(resolved).startsWith('case-'))throw new Error('Unsafe browser fixture cleanup target');
      await fs.rm(resolved,{recursive:true,force:true});
    }
  },
});
async function open(page, core) {
  await page.goto(core.launcher);
  await expect(page.locator('#connection-notice')).toBeHidden();
  await expect(page.locator('#stats-platform')).not.toHaveText('Checking platform...');
  await expect(page.locator('#hero-status')).toHaveText('Ready when you are');
}
async function profiles(page) {
  await page.locator('.nav-item[data-view="profiles"]').click();
}
async function create(page, id='browser-fixture') {
  await profiles(page);
  await page.locator('#new-profile').click();
  await page.locator('#p-id').fill(id);
  await page.locator('#p-name').fill('Browser fixture');
  // A deliberately absent executable makes this suite independent of engines.
  await page.locator('#p-binary').fill(path.join(repo,'build','absent-browser-fixture-engine'));
  await page.locator('#save-profile').click();
  await expect(page.locator('#editor-modal')).toBeHidden();
}
function action(page, name, id='browser-fixture') {
  return page.locator(`#all-profiles [data-profile-id="${id}"][data-profile-action="${name}"]`).first();
}

test('private launcher authenticates the UI and removes the credential from its address', async ({page, core}) => {
  await open(page, core);
  expect(new URL(page.url()).hash).toBe('#dashboard');
  expect(page.url()).not.toContain('accessweaver-session');
  const unauthenticated=await page.request.get(new URL('/api/bootstrap',page.url()).href);
  expect(unauthenticated.status()).toBe(403);
  await expect(page.locator('#status-badge')).toHaveText('NOT RUNNING');
});

test('create, reload, export and collision import preserve the saved profile', async ({page,core}) => {
  await open(page,core);await create(page);
  const original=JSON.parse(await fs.readFile(core.profilePath('browser-fixture'),'utf8'));
  expect(original.name).toBe('Browser fixture');
  await page.reload();await expect(page.locator('#connection-notice')).toBeHidden();await profiles(page);
  await expect(action(page,'edit')).toBeVisible();
  const downloaded=page.waitForEvent('download');await action(page,'export').click();
  const download=await downloaded;
  const exported=JSON.parse(await fs.readFile(await download.path(),'utf8'));
  expect(exported).toEqual(original);
  await page.locator('#import-file').setInputFiles({name:'fixture.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(exported))});
  await expect(page.locator('#editor-modal')).toBeVisible();
  await expect(page.locator('#p-id')).not.toHaveValue('browser-fixture');
  expect(JSON.parse(await fs.readFile(core.profilePath('browser-fixture'),'utf8'))).toEqual(original);
});

test('a stale tab preserves its draft and cannot overwrite a newer save', async ({page,context,core}) => {
  await open(page,core);await create(page);
  const other=await context.newPage();await open(other,core);await profiles(other);
  await action(page,'edit').click();await action(other,'edit').click();
  await page.locator('#p-name').fill('First tab winner');await page.locator('#save-profile').click();
  await expect(page.locator('#editor-modal')).toBeHidden();
  await other.locator('#p-name').fill('Stale tab draft');await other.locator('#save-profile').click();
  await expect(other.locator('#editor-feedback')).toHaveClass('error');
  await expect(other.locator('#editor-modal')).toBeVisible();
  await expect(other.locator('#p-name')).toHaveValue('Stale tab draft');
  expect(JSON.parse(await fs.readFile(core.profilePath('browser-fixture'),'utf8')).name).toBe('First tab winner');
});

test('invalid JSON stays editable and an unavailable engine cannot be launched', async ({page,core}) => {
  await open(page,core);await create(page);await action(page,'edit').click();
  await page.locator('#tab-advanced').click();await page.locator('#p-json').fill('{broken');
  await page.locator('#save-profile').click();
  await expect(page.locator('#editor-feedback')).toHaveClass('error');
  await expect(page.locator('#p-json')).toHaveValue('{broken');
  page.once('dialog',dialog=>dialog.accept());await page.locator('#cancel-editor').click();
  await action(page,'run').click();await expect(page.locator('#launch-modal')).toBeVisible();
  await expect(page.locator('#launch-confirm')).toBeDisabled();
  expect(JSON.parse(await fs.readFile(core.profilePath('browser-fixture'),'utf8')).name).toBe('Browser fixture');
});

test('modal keyboard focus and persisted preferences work in the real DOM', async ({page,core}) => {
  await open(page,core);await profiles(page);await page.locator('#new-profile').click();
  await expect(page.locator('#p-name')).toBeFocused();
  await page.locator('#close-editor').focus();await page.keyboard.press('Shift+Tab');
  await expect(page.locator('#save-profile')).toBeFocused();await page.keyboard.press('Tab');
  await expect(page.locator('#close-editor')).toBeFocused();await page.keyboard.press('Escape');
  await expect(page.locator('#new-profile')).toBeFocused();
  await page.locator('.nav-item[data-view="settings"]').click();
  for(const language of ['tr','ru','es','en']) {
    await page.locator('#settings-language').selectOption(language);
    await expect(page.locator('html')).toHaveAttribute('lang',language);
  }
  await page.locator('#settings-theme').selectOption('light');await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme','light');
});

// Keep locale navigation independently bounded: one combined flow previously
// exhausted WebKit's test budget despite no failed individual assertion.
for(const language of ['en','tr','ru','es']) {
  test(`narrow navigation preserves layout and drawer state in ${language}`, async ({page,core}) => {
    await open(page,core);
    await page.locator('.nav-item[data-view="settings"]').click();
    await page.setViewportSize({width:390,height:844});
    await page.locator('#settings-language').selectOption(language);
    await expect(page.locator('html')).toHaveAttribute('lang',language);
    await page.locator('#settings-theme').selectOption('light');
    for(const view of ['dashboard','profiles','engines','diagnostics','settings','system']) {
      await page.locator('#menu-toggle').click();await page.locator(`.nav-item[data-view="${view}"]`).click();
      await expect(page.locator('#view-'+view)).toBeVisible();
      await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded','false');
      const layout=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,
        overflow:Array.from(document.querySelectorAll('body *')).filter(el=>el.getBoundingClientRect().right>innerWidth+1).slice(0,15).map(el=>({tag:el.tagName,id:el.id,class:el.className,right:el.getBoundingClientRect().right}))}));
      expect(layout.scroll,language+'/'+view+': '+JSON.stringify(layout)).toBeLessThanOrEqual(layout.width+1);
    }
  });
}

test('machine review exports the exact request while unavailable apply stays disabled',async({page,core})=>{
  await open(page,core);
  await page.locator('.nav-item[data-view="system"]').click();
  await page.locator('#system-action').selectOption('dns');
  await page.locator('#system-dns').selectOption('doh');
  await page.locator('#system-preview').click();
  await expect(page.locator('#system-export')).toBeEnabled();
  await expect(page.locator('#system-consent')).toBeDisabled();
  await expect(page.locator('#system-apply')).toBeDisabled();
  const reviewed=JSON.parse(await page.locator('#system-plan').textContent());
  expect(reviewed.requiresAdministrator).toBe(true);
  if(process.platform==='win32')expect(reviewed.issues.join(' ')).toContain('separately elevated');
  const downloading=page.waitForEvent('download');await page.locator('#system-export').click();
  const download=await downloading;
  expect(download.suggestedFilename()).toBe('accessweaver-dns-request.json');
  expect(JSON.parse(await fs.readFile(await download.path(),'utf8'))).toEqual(reviewed.operation);
  await expect(fs.stat(path.join(core.home,'state','workflows'))).rejects.toMatchObject({code:'ENOENT'});
  await page.locator('#system-dns').selectOption('dnscrypt');
  await expect(page.locator('#system-export')).toBeDisabled();
});

test('support export excludes private profile contents and leaves the runtime stopped',async({page,core})=>{
  await open(page,core);await create(page,'private-support-profile');
  await page.locator('.nav-item[data-view="settings"]').click();
  await expect(page.locator('#export-support')).toBeEnabled();
  const downloading=page.waitForEvent('download');await page.locator('#export-support').click();
  const download=await downloading;
  expect(download.suggestedFilename()).toBe('accessweaver-support-summary.json');
  const text=await fs.readFile(await download.path(),'utf8'),report=JSON.parse(text);
  expect(report.scope).toBe('metadata-only');expect(report.runtime.state).toBe('stopped');
  expect(report.profiles.total).toBeGreaterThan(0);expect(report.build.platform).toBeTruthy();
  expect(text).not.toContain('private-support-profile');expect(text).not.toContain('Browser fixture');
  expect(text).not.toContain('absent-browser-fixture-engine');expect(text).not.toContain(core.home);
  await fs.writeFile(core.profilePath('private-support-profile'),'{private-corrupt-fixture');
  await page.reload();
  await expect(page.locator('#connection-notice')).toBeVisible();
  await expect(page.locator('#export-support')).toBeEnabled();
  const recovering=page.waitForEvent('download');await page.locator('#export-support').click();
  const recovery=await recovering,recoveryText=await fs.readFile(await recovery.path(),'utf8');
  const unavailable=JSON.parse(recoveryText);
  expect(unavailable.profiles.status).toBe('unavailable');expect(unavailable.profiles.total).toBeNull();
  expect(recoveryText).not.toContain('private-support-profile');expect(recoveryText).not.toContain('private-corrupt-fixture');

});


test('diagnostics selects an explicit proxy path and STUN target without sending probe traffic',async({page,core})=>{
 await open(page,core);await page.locator('.nav-item[data-view="diagnostics"]').click();
 await page.locator('#probe-path').selectOption('socks5');await expect(page.locator('#probe-proxy')).toBeVisible();
 await page.locator('#probe-proxy').fill('127.0.0.1:1080');await page.locator('#probe-transport').selectOption('stun');
 await expect(page.locator('#probe-host')).toHaveValue('');await expect(page.locator('#probe-port')).toHaveValue('3478');await expect(page.locator('#probe-tls')).toBeDisabled();
 await page.locator('#probe-host').fill('stun.example.com');let submitted;
 await page.route('**/api/v1/diagnose',async route=>{
  submitted=route.request().postDataJSON();await route.fulfill({json:{host:submitted.host,port:submitted.port,path:submitted.path,transport:submitted.transport,proxy:submitted.proxy,at:new Date().toISOString(),checks:[{name:'UDP/STUN',status:'failed',durationMs:1,detail:'Controlled browser fixture: no probe traffic sent'}]}});
 });
 await page.locator('#probe-submit').click();await expect(page.locator('#diagnostic-meta')).toContainText('One or more checks failed');
 expect(submitted).toEqual({host:'stun.example.com',port:3478,timeoutSeconds:5,tls:false,path:'socks5',transport:'stun',proxy:'127.0.0.1:1080'});
 await expect(page.locator('#diagnostic-meta')).toContainText('socks5 / stun / 127.0.0.1:1080');
 await page.locator('#probe-path').selectOption('direct');await expect(page.locator('#probe-proxy-field')).toBeHidden();
});

// Each locale/theme gets bounded view and modal cases so browser slowness cannot
// silently skip later screens. No exclusions, disabled rules or violation baselines.
for(const language of ['en','tr','ru','es'])for(const theme of ['dark','light']){
 test(`accessibility views in ${language}/${theme}`,async({page,core},testInfo)=>{
  await open(page,core);
  await page.locator('.nav-item[data-view="settings"]').click();
  await page.locator('#settings-language').selectOption(language);await page.locator('#settings-theme').selectOption(theme);
  await expect(page.locator('#lang-toggle')).toHaveAccessibleName(new RegExp(language.toUpperCase()));
  let controls=0;
  for(const view of ['dashboard','profiles','engines','diagnostics','settings','system']){
   await page.locator(`.nav-item[data-view="${view}"]`).click();await expect(page.locator('#view-'+view)).toBeVisible();
   if(view==='system')await expect(page.locator('#system-action option')).not.toHaveCount(0);
   await scanAccessibility(page,core,testInfo,view);
   controls+=await assertControlContrast(page,core,testInfo,view);
  }
  expect(controls).toBeGreaterThan(0);
 });
 test(`accessibility dialogs in ${language}/${theme}`,async({page,core},testInfo)=>{
  await open(page,core);
  await page.locator('.nav-item[data-view="settings"]').click();
  await page.locator('#settings-language').selectOption(language);await page.locator('#settings-theme').selectOption(theme);
  await profiles(page);await page.locator('#new-profile').click();
  await expect(page.locator('#editor-modal [role="dialog"]')).toHaveAccessibleName(await page.locator('#editor-title').textContent());
  expect(await page.locator('.skip-link').evaluate(el=>!!el.closest('[inert]'))).toBe(true);
  await scanAccessibility(page,core,testInfo,'editor-guided');await assertControlContrast(page,core,testInfo,'editor-guided');
  await page.locator('#editor-simple .advanced-details summary').click();
  await scanAccessibility(page,core,testInfo,'editor-expanded');await assertControlContrast(page,core,testInfo,'editor-expanded');
  await page.locator('#preview-profile').click();await expect(page.locator('#editor-preview .plan-status')).toBeVisible();
  await scanAccessibility(page,core,testInfo,'editor-preview');
  await page.locator('#tab-advanced').click();await scanAccessibility(page,core,testInfo,'editor-json');
  await page.locator('#p-json').fill('{broken');await page.locator('#save-profile').click();
  await expect(page.locator('#editor-feedback')).toHaveClass('error');await scanAccessibility(page,core,testInfo,'editor-error');
  page.once('dialog',dialog=>dialog.accept());await page.locator('#cancel-editor').click();
  await page.locator('#all-profiles [data-profile-action="run"]').first().click();
  await expect(page.locator('#launch-plan .plan-status')).toBeVisible();
  await scanAccessibility(page,core,testInfo,'launch-review');
  await page.keyboard.press('Escape');
  await page.locator('.nav-item[data-view="settings"]').click();await page.locator('#show-logs').click();
  await expect(page.locator('#logs-modal [role="dialog"]')).toHaveAccessibleName(await page.locator('#logs-title').textContent());
  await scanAccessibility(page,core,testInfo,'logs');await page.keyboard.press('Escape');
  expect(await page.locator('.skip-link').evaluate(el=>!!el.closest('[inert]'))).toBe(false);
 });
}

test('keyboard users can skip navigation and scroll launch review with visible focus',async({page,core},testInfo)=>{
 await open(page,core);await page.keyboard.press('Tab');await expect(page.locator('.skip-link')).toBeFocused();
 await assertControlContrast(page,core,testInfo,'focused-skip-link');
 await page.keyboard.press('Enter');await expect(page.locator('#content')).toBeFocused();
 await profiles(page);await page.setViewportSize({width:1000,height:500});
 const run=page.locator('#all-profiles [data-profile-action="run"]').first();await run.click();
 await expect(page.locator('#launch-plan .plan-status')).toBeVisible();await settleAnimations(page);
 await expect(page.locator('#close-launch')).toBeFocused();await page.keyboard.press('Tab');
 const region=page.locator('#launch-scroll');await expect(region).toBeFocused();
 await expect.poll(()=>region.evaluate(el=>el.scrollHeight-el.clientHeight)).toBeGreaterThan(0);
 await page.keyboard.press('PageDown');await expect.poll(()=>region.evaluate(el=>el.scrollTop)).toBeGreaterThan(0);
 const focus=await region.evaluate(el=>({style:getComputedStyle(el).outlineStyle,width:parseFloat(getComputedStyle(el).outlineWidth)}));
 expect(focus.style).toBe('solid');expect(focus.width).toBeGreaterThanOrEqual(2);
 await page.keyboard.press('Escape');await expect(run).toBeFocused();
 await page.locator('#new-profile').click();await expect(page.locator('#p-name')).toBeFocused();
 const field=await page.locator('#p-name').evaluate(el=>({style:getComputedStyle(el).outlineStyle,width:parseFloat(getComputedStyle(el).outlineWidth)}));
 expect(field.style).toBe('solid');expect(field.width).toBeGreaterThanOrEqual(2);
});


test('keyboard users can read maintenance review and retained history without applying operations',async({page,core})=>{
 await open(page,core);await page.setViewportSize({width:1000,height:500});
 await page.locator('.nav-item[data-view="system"]').click();await page.locator('#system-action').selectOption('dns');
 await expect(page.locator('#system-plan')).toHaveAttribute('tabindex','-1');
 await page.locator('#system-dns').selectOption('doh');await page.locator('#system-preview').click();
 await expect(page.locator('#system-export')).toBeEnabled();
 await expect(page.locator('#system-plan')).toHaveAttribute('tabindex','0');
 async function tabTo(id){for(let n=0;n<40;n++){await page.keyboard.press('Tab');if(await page.locator('#'+id).evaluate(el=>el===document.activeElement))return}throw new Error('Keyboard could not reach '+id)}
 await tabTo('system-plan');await page.keyboard.press('PageDown');
 await expect.poll(()=>page.locator('#system-plan').evaluate(el=>el.scrollTop)).toBeGreaterThan(0);
 await page.locator('#system-dns').selectOption('dnscrypt');
 await expect(page.locator('#system-plan')).toHaveAttribute('tabindex','-1');
 // Retained synthetic data exercises the real history API; it is never a job.
 const folder=path.join(core.home,'state','workflows');await fs.mkdir(folder,{recursive:true});
 const original=JSON.stringify({id:'keyboard-fixture',action:'discover',state:'failed',startedAt:'2026-11-02T00:00:00Z',result:{rows:Array.from({length:100},(_,i)=>({index:i,value:'Synthetic history fixture'}))}});
 const record=path.join(folder,'keyboard-fixture.json');await fs.writeFile(record,original);
 await page.locator('#system-history').click();await page.locator('#history-capture').click();await page.locator('#history-rows button').first().click();await expect(page.locator('#history-detail')).toContainText('keyboard-fixture');
 await tabTo('history-detail');await page.keyboard.press('PageDown');
 await expect.poll(()=>page.locator('#history-detail').evaluate(el=>el.scrollTop)).toBeGreaterThan(0);
 expect(await fs.readFile(record,'utf8')).toBe(original);
});

test('reduced motion applies to navigation and explicit editor preview scrolling',async({page,core})=>{
 await page.emulateMedia({reducedMotion:'reduce'});await open(page,core);await profiles(page);
 const durations=await page.locator('#view-profiles').evaluate(el=>({animation:getComputedStyle(el).animationDuration,transition:getComputedStyle(el).transitionDuration}));
 const ms=value=>value.split(',').map(s=>parseFloat(s)*(s.trim().endsWith('ms')?1:1000));
 expect(Math.max(...ms(durations.animation))).toBeLessThanOrEqual(.011);
 expect(Math.max(...ms(durations.transition))).toBeLessThanOrEqual(.011);
 await page.evaluate(()=>{window.a11yScrollCalls=[];const original=Element.prototype.scrollIntoView;Element.prototype.scrollIntoView=function(options){window.a11yScrollCalls.push(options?.behavior);return original.call(this,options)}});
 await page.locator('#new-profile').click();await page.locator('#preview-profile').click();
 await expect(page.locator('#editor-preview .plan-status')).toBeVisible();
 expect(await page.evaluate(()=>window.a11yScrollCalls.at(-1))).toBe('auto');
});

for(const language of ['en','tr','ru','es'])test(`320 CSS pixel reflow includes modal controls in ${language}`,async({page,core})=>{
 await open(page,core);await page.locator('.nav-item[data-view="settings"]').click();
 await page.locator('#settings-language').selectOption(language);await page.setViewportSize({width:320,height:720});
 async function fits(name){
  await settleAnimations(page);
  const overflow=await page.evaluate(()=>({viewport:innerWidth,scroll:document.documentElement.scrollWidth,
   elements:Array.from(document.querySelectorAll('body *')).filter(el=>el.getClientRects().length&&getComputedStyle(el).visibility==='visible'&&el.getBoundingClientRect().right>innerWidth+1).slice(0,10).map(el=>({tag:el.tagName,id:el.id,class:typeof el.className==='string'?el.className:'svg',right:el.getBoundingClientRect().right}))}));
  expect(overflow.scroll,name+': '+JSON.stringify(overflow)).toBeLessThanOrEqual(overflow.viewport+1);
  expect(overflow.elements,name+' element overflow').toEqual([]);
 }
 for(const view of ['dashboard','profiles','engines','diagnostics','settings','system']){
  await page.locator('#menu-toggle').click();await page.locator(`.nav-item[data-view="${view}"]`).click();await fits(view);
 }
 await page.locator('#menu-toggle').click();await page.locator('.nav-item[data-view="profiles"]').click();
 await page.locator('#new-profile').click();await fits('editor');await page.locator('#tab-advanced').click();await fits('JSON editor');await page.keyboard.press('Escape');
 await page.locator('#all-profiles [data-profile-action="run"]').first().click();await expect(page.locator('#launch-plan .plan-status')).toBeVisible();await fits('launch review');await page.keyboard.press('Escape');
 await page.locator('#menu-toggle').click();await page.locator('.nav-item[data-view="settings"]').click();await page.locator('#show-logs').click();await fits('logs');
});


test('keyboard focus returns to the same card control after saves and engine creation',async({page,core})=>{
 await open(page,core);await create(page,'keyboard-save');
 const edit=page.locator('#all-profiles .profile-card-actions [data-profile-action="edit"][data-profile-id="keyboard-save"]');
 await edit.click();await page.locator('#p-name').fill('Saved keyboard fixture');await page.locator('#save-profile').click();
 await expect(page.locator('#editor-modal')).toBeHidden();await expect(edit).toBeFocused();
 await page.locator('.nav-item[data-view="engines"]').click();
 const createForEngine=page.locator('#engines-grid [data-engine-create="byedpi"]');await createForEngine.click();
 await page.locator('#save-profile').click();await expect(page.locator('#editor-modal')).toBeHidden();
 await expect(createForEngine).toBeFocused();
});


test('narrow navigation excludes closed links and supports keyboard opening and Escape',async({page,core})=>{
 await open(page,core);await page.setViewportSize({width:390,height:844});
 await expect(page.locator('#sidebar')).toHaveJSProperty('inert',true);
 await page.keyboard.press('Tab');await expect(page.locator('.skip-link')).toBeFocused();
 await page.keyboard.press('Tab');await expect(page.locator('#menu-toggle')).toBeFocused();
 await page.keyboard.press('Enter');await expect(page.locator('#sidebar')).toHaveJSProperty('inert',false);
 await expect(page.locator('#sidebar .nav-item.active')).toBeFocused();
 await page.keyboard.press('Escape');await expect(page.locator('#menu-toggle')).toBeFocused();
 await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded','false');
 await expect(page.locator('#sidebar')).toHaveJSProperty('inert',true);
 await page.keyboard.press('Enter');await page.keyboard.press('Tab');
 await expect(page.locator('#sidebar .nav-item[data-view="profiles"]')).toBeFocused();
 await page.keyboard.press('Enter');await expect(page.locator('#content')).toBeFocused();
 await expect(page.locator('#sidebar')).toHaveJSProperty('inert',true);
 await page.setViewportSize({width:1280,height:900});await expect(page.locator('#sidebar')).toHaveJSProperty('inert',false);
 await page.locator('#sidebar .nav-item[data-view="profiles"]').focus();await page.setViewportSize({width:390,height:844});
 await expect(page.locator('#menu-toggle')).toBeFocused();await expect(page.locator('#sidebar')).toHaveJSProperty('inert',true);
});


test('large retained history has a bounded preview and complete private exports',async({page,core},testInfo)=>{
 await open(page,core);await create(page,'export-recovery-fixture');await page.locator('.nav-item[data-view="system"]').click();
 await expect(page.locator('#system-export-history')).toBeEnabled();
 const folder=path.join(core.home,'state','workflows');await fs.mkdir(folder,{recursive:true});
 const privateText='<img src=x onerror="globalThis.workflowPayloadExecuted=true">'+'x'.repeat(300000);
 const privateError='<img src=x onerror="globalThis.workflowMetadataExecuted=true">'+String.fromCodePoint(0x2028,0x2029).repeat(32768)+'<>&'.repeat(32768);
 const original='{"id":"display-fixture","action":"discover","state":"failed","startedAt":"2026-11-02T00:00:00Z","error":'+JSON.stringify(privateError)+',"result":{"nested":'+'['.repeat(6000)+'0'+']'.repeat(6000)+',"text":'+JSON.stringify(privateText)+',"private":"PRIVATE_FULL_HISTORY_FIXTURE"}}';
 const record=path.join(folder,'display-fixture.json');await fs.writeFile(record,original);
 await page.locator('#system-history').click();await page.locator('#history-capture').click();await page.locator('#history-rows button').first().click();
 await expect(page.locator('#history-detail')).toContainText('display-fixture');
 await expect(page.locator('#history-detail-limited')).toBeVisible();
 await expect(page.locator('#history-detail img')).toHaveCount(0);expect(await page.evaluate(()=>globalThis.workflowPayloadExecuted)).toBeUndefined();expect(await page.evaluate(()=>globalThis.workflowMetadataExecuted)).toBeUndefined();
 await expect(page.locator('#history-detail')).toHaveAttribute('aria-describedby','history-detail-limited');
 expect((await page.locator('#history-detail').textContent()).length).toBeLessThanOrEqual(128*1024);
 await scanAccessibility(page,core,testInfo,'limited-history-preview');await assertControlContrast(page,core,testInfo,'limited-history-preview');
 const pending=page.waitForEvent('download');await page.locator('#system-export-history').click();
 const download=await pending;expect(download.suggestedFilename()).toBe('accessweaver-workflow-history.json');
 const full=await fs.readFile(await download.path(),'utf8');const rows=JSON.parse(full);expect(rows).toHaveLength(1);
 expect(rows[0].id).toBe('display-fixture');expect(rows[0].error).toBe(privateError);expect(rows[0].result.text).toBe(privateText);expect(rows[0].result.private).toBe('PRIVATE_FULL_HISTORY_FIXTURE');
 let value=rows[0].result.nested;for(let depth=0;depth<6000;depth++){expect(Array.isArray(value)).toBe(true);value=value[0];}expect(value).toBe(0);
 expect(await fs.readFile(record,'utf8')).toBe(original);
 const current=page.waitForEvent('download');await page.locator('#system-export-status').click();
 const statusDownload=await current;expect(statusDownload.suggestedFilename()).toBe('accessweaver-system-status.json');
 const status=JSON.parse(await fs.readFile(await statusDownload.path(),'utf8'));expect(status.operations.length).toBeGreaterThan(0);expect(status.job.state).not.toBe('running');
 // A full, explicitly selected history export and the metadata-only support
 // summary have different disclosure scopes; history must not enter support.
 await page.locator('.nav-item[data-view="settings"]').click();const supportPending=page.waitForEvent('download');await page.locator('#export-support').click();
 const support=await supportPending;const supportText=await fs.readFile(await support.path(),'utf8');expect(supportText).not.toContain('PRIVATE_FULL_HISTORY_FIXTURE');expect(supportText).not.toContain('workflowMetadataExecuted');
 expect(await fs.readFile(record,'utf8')).toBe(original);
 await fs.writeFile(core.profilePath('export-recovery-fixture'),'{broken profile fixture');await page.reload();
 await expect(page.locator('#connection-notice')).toBeVisible();await page.locator('.nav-item[data-view="system"]').click();
 await expect(page.locator('#system-export-history')).toBeEnabled();const recovering=page.waitForEvent('download');await page.locator('#system-export-history').click();
 const recovered=await recovering;expect(await fs.readFile(await recovered.path(),'utf8')).toBe(full);
 expect(await fs.readFile(core.profilePath('export-recovery-fixture'),'utf8')).toBe('{broken profile fixture');
 expect(await fs.readFile(record,'utf8')).toBe(original);
});


test('optional workflow metadata cannot stop polling or replace reviewed inputs',async({page,core})=>{
 await open(page,core);await page.locator('.nav-item[data-view="system"]').click();
 await page.locator('#system-action').selectOption('recover');
 await page.locator('#system-form details > summary').click();await expect(page.locator('#system-journal')).toBeVisible();await page.locator('#system-journal').fill('reviewed.json');
 await page.locator('#system-action').selectOption('config');await page.locator('#system-applications').fill('C:\\existing');
 const errors=[];page.on('pageerror',error=>errors.push(error.message));let choices=0,reports=0,journal='chosen.json';
 await page.route('**/api/v1/system/folder',async route=>{
  expect(route.request().method()).toBe('POST');choices++;
  // Controlled UI response: never open the host's native folder dialog.
  await route.fulfill({json:{id:'chooser-'+choices,action:'choose-folder',state:'running'}});
 });
 await page.route('**/api/v1/system',async route=>{
  expect(route.request().method()).toBe('GET');const response=await route.fetch();const info=await response.json();reports++;
  const state=choices===1?(reports===1?'running':'failed'):'succeeded';
  const result=choices===1?{journal:{legacy:'RAW_OPTIONAL_METADATA'},data:{folder:'C:\\failed-choice'}}:{journal:'C:\\journals\\'+journal,data:{folder:'C:\\selected'}};
  await route.fulfill({response,json:{...info,job:{id:'chooser-'+choices,action:'choose-folder',state,result}}});
 });
 await page.locator('#system-folder').click();await expect(page.locator('#system-cancel')).toBeEnabled();
 await expect(page.locator('#system-output')).toContainText('RAW_OPTIONAL_METADATA');
 await expect(page.locator('#system-cancel')).toBeDisabled();await expect(page.locator('#system-output')).toContainText('failed');
 expect(reports).toBe(2);expect(choices).toBe(1);await expect(page.locator('#system-applications')).toHaveValue('C:\\existing');await expect(page.locator('#system-journal')).toHaveValue('reviewed.json');
 await page.locator('#system-folder').click();await expect(page.locator('#system-applications')).toHaveValue('C:\\existing\nC:\\selected');
 await expect(page.locator('#system-journal')).toHaveValue('chosen.json');await expect(page.locator('#system-cancel')).toBeDisabled();
 expect(choices).toBe(2);expect(reports).toBe(3);
 // Review a controlled recovery request without invoking any native worker.
 await page.route('**/api/v1/system/preview',async route=>{await route.fulfill({json:{id:'reviewed-recovery',ready:true,request:route.request().postDataJSON(),steps:[],issues:[],warnings:[]}})});
 await page.locator('#system-action').selectOption('recover');await page.locator('#system-form button[type="submit"]').click();
 await expect(page.locator('#system-consent')).toBeEnabled();await page.locator('#system-consent').check();await expect(page.locator('#system-apply')).toBeEnabled();
 journal='replacement.json';await page.locator('.nav-item[data-view="dashboard"]').click();await page.locator('.nav-item[data-view="system"]').click();
 await expect(page.locator('#system-journal')).toHaveValue('replacement.json');await expect(page.locator('#system-consent')).not.toBeChecked();await expect(page.locator('#system-apply')).toBeDisabled();expect(errors).toEqual([]);
});

// Only static application assets and synthetic API replies are used here. The
// core fixture is deliberately absent, so this case starts no native product.
test('pending lifecycle blocks launch while retaining profile editing and local inspection',async({page})=>{
  const origin='http://127.0.0.1:43101';
  const profile={version:1,id:'pending-fixture',name:'Pending fixture',description:'',category:'Custom',engine:'byedpi',binary:'',sha256:'',args:[],routing:{includeDomains:[],excludeDomains:[],applications:[]},probe:{host:'example.com',port:443,tls:true,timeoutSeconds:5},notes:'',updatedAt:'2026-11-01T00:00:00Z'};
  const engine={id:'byedpi',name:'ByeDPI',kind:'proxy',platforms:['linux'],includes:true,excludes:true,integration:'managed',source:'https://example.invalid',notes:'Synthetic UI fixture'};
  const assets=new Map();
  for(const [route,file,type] of [['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/locales.js','locales.js','text/javascript'],['/system.js','system.js','text/javascript'],['/app.css','app.css','text/css']])assets.set(route,{body:await fs.readFile(path.join(repo,'web',file)),contentType:type});
  let pending=false,starts=0;
  await page.route('**/*',async route=>{
    const target=new URL(route.request().url());
    if(target.origin!==origin){await route.abort();return;}
    const asset=assets.get(target.pathname);if(asset){await route.fulfill(asset);return;}
    let json;
    if(target.pathname==='/api/bootstrap')json={platform:'linux',version:'synthetic-ui-fixture'};
    else if(target.pathname==='/api/v1/engines')json=[engine];
    else if(target.pathname==='/api/v1/profiles')json=[profile];
    else if(target.pathname==='/api/v1/profiles/'+profile.id)json=profile;
    else if(target.pathname==='/api/v1/runtime')json={state:pending?'error':'stopped',profileId:profile.id,engine:'byedpi',pid:0,lifecyclePending:pending,log:[]};
    else if(target.pathname==='/api/v1/preview')json={ready:true,args:[],issues:[],warnings:[]};
    else if(target.pathname==='/api/v1/start'){starts++;await route.fulfill({status:500,json:{error:'unexpected synthetic launch'}});return;}
    else {await route.fulfill({status:404,json:{error:'synthetic route unavailable'}});return;}
    await route.fulfill({json});
  });
  await page.goto(origin+'/#accessweaver-session='+'a'.repeat(43));
  await expect(page.locator('#hero-status')).toHaveText('Ready when you are');
  await profiles(page);await action(page,'run',profile.id).click();
  await expect(page.locator('#launch-confirm')).toBeEnabled();
  pending=true;await page.evaluate(()=>pollStatus());
  await expect(page.locator('#launch-confirm')).toBeDisabled();
  await expect(page.locator('#launch-plan')).toContainText('Starting another engine is blocked');
  await expect(page.locator('#hero-status')).toHaveText('Shutdown unconfirmed');
  await expect(page.locator('#status-badge')).toHaveText('SHUTDOWN UNCONFIRMED');
  await expect(page.locator('#running-engine')).toHaveText('—');
  await expect(page.locator('#hero-primary')).toBeDisabled();
  await page.locator('#launch-edit').click();await expect(page.locator('#editor-modal')).toBeVisible();
  await expect(page.locator('#p-name')).toHaveValue(profile.name);
  await page.locator('#close-editor').click();
  await expect(action(page,'run',profile.id)).toBeDisabled();
  await expect(action(page,'edit',profile.id)).toBeEnabled();
  await page.locator('.nav-item[data-view="settings"]').click();
  await expect(page.locator('#export-support')).toBeEnabled();
  await expect(page.locator('#show-logs')).toBeEnabled();await page.locator('#show-logs').click();
  await expect(page.locator('#logs-modal')).toBeVisible();await page.locator('#close-logs').click();
  expect(starts).toBe(0);
});

// Only static assets and synthetic API replies. Deliberately no core fixture:
// this case launches no product/native worker and proves UI behavior only.
test('history fixture: explicit capture, paging, exact detail and private raw export',async({page},testInfo)=>{
 const origin='http://127.0.0.1:43102',session='a'.repeat(43),revisionA='c'.repeat(64),revisionB='e'.repeat(64);
 const refA=Buffer.from('source-history-record-A').toString('base64url'),refB=Buffer.from('source-history-record-B').toString('base64url'),refC=Buffer.from('source-history-record-C').toString('base64url'),cursor=Buffer.from('source-history-next-page').toString('base64url');
 const a={recordRef:refA,revision:revisionA,id:'1'.repeat(48),action:'discover',state:'failed',startedAt:'2026-11-01T00:00:00Z',finishedAt:'2026-11-01T00:01:00Z',size:128,classification:'canonical',protection:'retirement-unavailable',errorPresent:true,resultPresent:true,rawAvailable:true};
 const b={...a,recordRef:refB,revision:revisionB,id:'2'.repeat(48),classification:'malformed',size:3*1024*1024};
 const c={...a,recordRef:refC,revision:'',id:'',state:'unknown',classification:'special',rawAvailable:false};
 const d={...c,recordRef:Buffer.from('source-history-record-D').toString('base64url'),classification:'oversized',size:20*1024*1024*1024};
 const raw=Buffer.alloc(b.size);raw.set([0xff,0,13,10,60,38,65]);const assets=new Map();
 for(const [route,file,type] of [['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/locales.js','locales.js','text/javascript'],['/system.js','system.js','text/javascript'],['/app.css','app.css','text/css']])assets.set(route,{body:await fs.readFile(path.join(repo,'web',file)),contentType:type});
 let captures=0,stale=false,restricted=false,historyReads=0,firstA=true,releaseA,enteredA,releaseCapture,enteredCapture;
 const heldA=new Promise(resolve=>releaseA=resolve),readyA=new Promise(resolve=>enteredA=resolve),heldCapture=new Promise(resolve=>releaseCapture=resolve),readyCapture=new Promise(resolve=>enteredCapture=resolve);
 const inventory=()=>({snapshot:(captures>1?'f':'a').repeat(48),storeRevision:'b'.repeat(48),createdAt:'2026-11-01T00:02:00Z',count:4,totalBytes:b.size+384});
 const requests=[];
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());if(url.origin!==origin){await route.abort();return;}
  const asset=assets.get(url.pathname);if(asset){await route.fulfill(asset);return;}
  expect(route.request().headers()['x-accessweaver-token']).toBe(session);
  if(url.pathname==='/api/bootstrap'){await route.fulfill({json:{platform:'windows',version:'source-only-history-ui',profileEditingOnly:restricted}});return;}
  if(url.pathname==='/api/v1/profiles'){await route.fulfill({status:500,json:{error:'Synthetic profile loading failure'}});return;}
  if(url.pathname==='/api/v1/engines'){await route.fulfill({json:[]});return;}
  if(url.pathname==='/api/v1/runtime'){await route.fulfill({json:{state:'stopped',log:[]}});return;}
  if(url.pathname.startsWith('/api/v1/system/history')){
   historyReads++;requests.push({path:url.pathname,search:url.search,method:route.request().method()});
   if(url.pathname==='/api/v1/system/history/inventory'){
    expect(route.request().method()).toBe('POST');expect(route.request().postDataJSON()).toEqual({});captures++;stale=false;if(captures===2){enteredCapture();await heldCapture;await route.fulfill({json:inventory()}).catch(()=>{});return;}await route.fulfill({json:inventory()});return;
   }
   if(url.pathname==='/api/v1/system/history/page'){
    expect(url.searchParams.get('limit')).toBe('64');
    if(!captures||stale){await route.fulfill({status:409,json:{error:'History inventory is unavailable'}});return;}
    await route.fulfill({json:{inventory:inventory(),items:url.searchParams.get('cursor')?[c,d]:[a,b],nextCursor:url.searchParams.get('cursor')?'':cursor}});return;
   }
   if(url.pathname==='/api/v1/system/history/records/'+refA){
    expect(url.searchParams.get('revision')).toBe(revisionA);
    if(firstA){firstA=false;enteredA();await heldA;await route.fulfill({json:{record:a,job:{id:'STALE_HISTORY_DETAIL'},rawAvailable:true}}).catch(()=>{});return;}
    await route.fulfill({json:{record:a,job:{id:a.id,state:'failed',result:{text:'<img src=x onerror="globalThis.historyPayloadExecuted=true">'+'x'.repeat(200000)}},rawAvailable:true}});return;
   }
   if(url.pathname==='/api/v1/system/history/records/'+refB){expect(url.searchParams.get('revision')).toBe(revisionB);await route.fulfill({json:{record:b,rawAvailable:true}});return;}
   if(url.pathname==='/api/v1/system/history/records/'+d.recordRef){expect(url.searchParams.has('revision')).toBe(true);expect(url.searchParams.get('revision')).toBe('');await route.fulfill({json:{record:d,rawAvailable:false}});return;}
   if(url.pathname==='/api/v1/system/history/records/'+refC){expect(url.searchParams.has('revision')).toBe(true);expect(url.searchParams.get('revision')).toBe('');await route.fulfill({json:{record:c,rawAvailable:false}});return;}
   if(url.pathname==='/api/v1/system/history/records/'+refB+'/export'){
    expect(url.searchParams.get('revision')).toBe(revisionB);await route.fulfill({body:raw,headers:{'Content-Type':'application/octet-stream','ETag':'"'+revisionB+'"','X-AccessWeaver-Revision':revisionB}});return;
   }
  }
  await route.fulfill({status:404,json:{error:'Synthetic route unavailable'}});
 });
 const navigateHistoryFixture=async view=>{const toggle=page.locator('#menu-toggle');if(await toggle.isVisible())await toggle.click();await page.locator('.nav-item[data-view="'+view+'"]').click();};
 try{
  await page.goto(origin+'/#accessweaver-session='+session);
  await expect(page.locator('#connection-notice')).toBeVisible();
  await navigateHistoryFixture('system');
  await expect(page.locator('#system-history')).toBeEnabled();await page.locator('#system-history').click();
  await expect(page.locator('#history-status')).toContainText('new capture');expect(captures).toBe(0);
  await page.locator('#history-capture').focus();await page.keyboard.press('Enter');
  await expect(page.locator('#history-rows button')).toHaveCount(2);expect(captures).toBe(1);
  await expect(page.locator('#history-rows')).toContainText('Recovery evidence is protected');
  await page.getByTitle(a.id,{exact:true}).click();await readyA;
  await page.getByTitle(b.id,{exact:true}).click();await expect(page.locator('#history-detail-title')).toContainText(b.id);
  releaseA();await expect(page.locator('#history-detail')).not.toContainText('STALE_HISTORY_DETAIL');await expect(page.locator('#history-detail')).toContainText('too large for the desktop preview');expect(requests.some(item=>item.path==='/api/v1/system/history/records/'+refB)).toBe(false);
  await page.getByTitle(a.id,{exact:true}).click();await expect(page.locator('#history-detail-limited')).toBeVisible();
  expect((await page.locator('#history-detail').textContent()).length).toBeLessThanOrEqual(128*1024);await expect(page.locator('#history-detail img')).toHaveCount(0);expect(await page.evaluate(()=>globalThis.historyPayloadExecuted)).toBeUndefined();
  await page.getByTitle(b.id,{exact:true}).click();await expect(page.locator('#history-export-record')).toBeEnabled();
  const pendingDownload=page.waitForEvent('download');await page.locator('#history-export-record').click();const download=await pendingDownload;
  expect(download.suggestedFilename()).toBe('accessweaver-workflow-record.bin');expect(await fs.readFile(await download.path())).toEqual(raw);
  await page.locator('#history-next').focus();await page.keyboard.press('Enter');await expect(page.locator('#history-rows button')).toHaveCount(2);await expect(page.locator('#history-detail-panel')).toBeHidden();
  expect(new Set(await page.locator('#history-rows button').allTextContents()).size).toBe(2);await expect(page.locator('#history-rows')).toContainText('Above inspection limit');
  await page.locator('#history-rows button').first().click();await expect(page.locator('#history-detail')).toContainText('cannot be safely read');await expect(page.locator('#history-export-record')).toBeDisabled();
  await page.locator('#history-panel').screenshot({path:testInfo.outputPath('history-fixture-source-only-oversized.png')});
  await page.locator('#history-previous').click();await expect(page.locator('#history-rows button')).toHaveCount(2);
  stale=true;await page.locator('#history-refresh').click();await expect(page.locator('#history-status')).toContainText('new capture');expect(captures).toBe(1);
  await page.locator('#history-capture').click();await readyCapture;await expect(page.locator('#history-cancel-capture')).toBeEnabled();await page.locator('#history-cancel-capture').click();releaseCapture();await expect(page.locator('#history-status')).toContainText('request canceled');await expect(page.locator('#history-rows button')).toHaveCount(0);
  await page.locator('#history-capture').click();await expect(page.locator('#history-rows button')).toHaveCount(2);expect(captures).toBe(3);
  await page.locator('#history-panel').screenshot({path:testInfo.outputPath('history-fixture-source-only-wide.png')});
  await page.setViewportSize({width:390,height:844});
  const headings={en:'Workflow history',tr:'İşlem geçmişi',ru:'История операций',es:'Historial de operaciones'};
  for(const [language,title] of Object.entries(headings)){
   await navigateHistoryFixture('settings');await page.locator('#settings-language').selectOption(language);
   await navigateHistoryFixture('system');await page.locator('#system-history').click();await expect(page.locator('#history-title')).toHaveText(title);await expect(page.locator('#history-rows button')).toHaveCount(2);
  }
  await page.locator('#history-panel').screenshot({path:testInfo.outputPath('history-fixture-source-only-narrow.png')});
  const AxeBuilder=require('@axe-core/playwright').default;await settleAnimations(page);const accessibility=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(accessibility.violations.map(item=>item.id)).toEqual([]);
  expect(requests.every(item=>item.method==='GET'||item.path==='/api/v1/system/history/inventory'&&item.method==='POST')).toBe(true);
  const beforeRestricted=historyReads;restricted=true;await page.reload();await expect(page.locator('.nav-item[data-view="system"]')).toBeDisabled();await expect(page.locator('#history-panel')).toBeHidden();expect(historyReads).toBe(beforeRestricted);
 }finally{releaseA();releaseCapture();}
});

// Static assets + synthetic API only. No core fixture or native worker.
test('lifecycle fixture: protected completion tracking and pending admission preserve inspection',async({page},testInfo)=>{
 const origin='http://127.0.0.1:43103',session='b'.repeat(43),assets=new Map();
 for(const [route,file,type] of [['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/locales.js','locales.js','text/javascript'],['/system.js','system.js','text/javascript'],['/app.css','app.css','text/css']])assets.set(route,{body:await fs.readFile(path.join(repo,'web',file)),contentType:type});
 let status='none',starts=0,reads=0,restricted=false,releaseRead,enteredRead;
 const heldRead=new Promise(resolve=>releaseRead=resolve),readEntered=new Promise(resolve=>enteredRead=resolve);
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());if(url.origin!==origin){await route.abort();return;}
  const asset=assets.get(url.pathname);if(asset){await route.fulfill(asset);return;}
  expect(route.request().headers()['x-accessweaver-token']).toBe(session);
  if(url.pathname==='/api/bootstrap'){await route.fulfill({json:{platform:'windows',version:'synthetic-lifecycle-ui',profileEditingOnly:restricted}});return;}
  if(url.pathname==='/api/v1/profiles'){await route.fulfill({status:500,json:{error:'Synthetic profile loading failure'}});return;}
  if(url.pathname==='/api/v1/engines'){await route.fulfill({json:[]});return;}
  if(url.pathname==='/api/v1/runtime'){await route.fulfill({json:{state:'stopped',log:[]}});return;}
  if(url.pathname==='/api/v1/system/history/lifecycle'){
   reads++;expect(route.request().method()).toBe('GET');expect(url.search).toBe('');
   if(status==='held'){enteredRead();await heldRead;await route.fulfill({json:{state:'released',jobId:'a'.repeat(48),admissionBlocked:false,protection:'retirement-unavailable'}}).catch(()=>{});return;}
   if(status==='unavailable'){await route.fulfill({status:503,json:{error:'PRIVATE_SYNTHETIC_DETAIL'}});return;}
   await route.fulfill({json:{state:status,...(status!=='none'?{jobId:'a'.repeat(48)}:{}),admissionBlocked:['intent','sealed','blocked'].includes(status),protection:'retirement-unavailable'}});return;
  }
  if(url.pathname==='/api/v1/system/start'){starts++;expect(route.request().postDataJSON()).toEqual({planId:'synthetic-reviewed-plan',confirm:true});await route.fulfill({status:409,json:{error:'PRIVATE_SYNTHETIC_DETAIL',code:'workflow-lifecycle-pending'}});return;}
  if(url.pathname==='/api/v1/system/history/page'){await route.fulfill({status:409,json:{error:'Capture required'}});return;}
  await route.fulfill({status:404,json:{error:'Synthetic route unavailable'}});
 });
 const nav=async view=>{const toggle=page.locator('#menu-toggle');if(await toggle.isVisible())await toggle.click();await page.locator('.nav-item[data-view="'+view+'"]').click();};
 try{
  await page.goto(origin+'/#accessweaver-session='+session);await expect(page.locator('#connection-notice')).toBeVisible();await nav('system');
  await expect(page.locator('#history-lifecycle-refresh')).toBeEnabled();expect(reads).toBe(0);
  await page.locator('#history-lifecycle-refresh').click();await expect(page.locator('#history-lifecycle-status')).toContainText('Legacy evidence remains protected');
  status='released';await page.locator('#history-lifecycle-refresh').click();await expect(page.locator('#history-lifecycle-status')).toContainText('Vendor cleanup and evidence retirement are not certified');
  status='unavailable';await page.locator('#history-lifecycle-refresh').click();await expect(page.locator('#history-lifecycle-status')).toContainText('busy or unavailable');await expect(page.locator('#history-lifecycle-job')).toBeEmpty();await expect(page.locator('#history-lifecycle-card')).not.toContainText('PRIVATE_SYNTHETIC_DETAIL');
  // Explicit synthetic review state exercises the actual click/error path while
  // profile loading remains failed; no product preview or worker is claimed.
  await page.evaluate(()=>{$('system-action').value='config';refreshSystemFields();$('system-applications').value='Synthetic retained application';$('system-journal').value='synthetic-recovery.json';systemUI.plan={id:'synthetic-reviewed-plan',ready:true};$('system-consent').checked=true;$('system-consent').disabled=false;$('system-apply').disabled=false;});
  await page.locator('#system-apply').click();await expect(page.locator('#system-output')).toContainText('Nothing is retried automatically');expect(starts).toBe(1);
  await expect(page.locator('#system-consent')).not.toBeChecked();await expect(page.locator('#system-applications')).toHaveValue('Synthetic retained application');await expect(page.locator('#system-journal')).toHaveValue('synthetic-recovery.json');await expect(page.locator('#system-apply')).toBeDisabled();await expect(page.locator('#history-panel')).toBeVisible();await expect(page.locator('#system-output')).not.toContainText('PRIVATE_SYNTHETIC_DETAIL');
  const titles={en:'Completion tracking',tr:'Tamamlanma takibi',ru:'Контроль завершения',es:'Seguimiento de finalización'};
  for(const [language,title] of Object.entries(titles)){await nav('settings');await page.locator('#settings-language').selectOption(language);await nav('system');await expect(page.locator('#history-lifecycle-title')).toHaveText(title);}
  await nav('settings');await page.locator('#settings-language').selectOption('en');await nav('system');status='sealed';await page.locator('#history-lifecycle-refresh').click();await expect(page.locator('#history-lifecycle-status')).toContainText('owner release is unconfirmed');
  await page.locator('#history-lifecycle-card').screenshot({path:testInfo.outputPath('lifecycle-fixture-source-only.png')});
  status='held';await page.locator('#history-lifecycle-refresh').click();await readEntered;await nav('settings');releaseRead();await nav('system');await expect(page.locator('#history-lifecycle-status')).toContainText('has not been read');await expect(page.locator('#history-lifecycle-job')).toBeEmpty();expect(starts).toBe(1);
  const before=reads;restricted=true;await page.reload();await expect(page.locator('.nav-item[data-view="system"]')).toBeDisabled();await expect(page.locator('#history-lifecycle-card')).toBeHidden();expect(reads).toBe(before);
 }finally{releaseRead();}
});

// No core fixture: all assets and API replies are synthetic. This exercises the
// browser operation lifecycle only; no diagnostic sockets or native worker run.
test('diagnostic fixture: cancellation, busy admission and late replies preserve the current request',async({page},testInfo)=>{
 const origin='http://127.0.0.1:43104',session='c'.repeat(43),assets=new Map(),requests=[],held=[];let profileOnly=false;
 for(const [route,file,type] of [['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/locales.js','locales.js','text/javascript'],['/system.js','system.js','text/javascript'],['/app.css','app.css','text/css']])assets.set(route,{body:await fs.readFile(path.join(repo,'web',file)),contentType:type});
 const report=request=>({host:request.host,port:request.port,path:request.path,transport:request.transport,...(request.proxy?{proxy:request.proxy}:{}),at:'2026-11-01T00:00:00Z',checks:[{name:'Source fixture',status:'ok',durationMs:1,detail:'No diagnostic traffic sent'}]});
 const barrier=()=>{let release,complete;const wait=new Promise(resolve=>release=resolve),done=new Promise(resolve=>complete=resolve),value={release,complete,wait,done};held.push(value);return value};
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());if(url.origin!==origin){await route.abort();return;}
  const asset=assets.get(url.pathname);if(asset){await route.fulfill(asset);return;}
  expect(route.request().headers()['x-accessweaver-token']).toBe(session);
  if(url.pathname==='/api/bootstrap'){await route.fulfill({json:{platform:'linux',version:'source-only-diagnostic-fixture',profileEditingOnly:profileOnly}});return;}
  if(url.pathname==='/api/v1/engines'||url.pathname==='/api/v1/profiles'){await route.fulfill({json:[]});return;}
  if(url.pathname==='/api/v1/runtime'){await route.fulfill({json:{state:'stopped',log:[]}});return;}
  if(url.pathname==='/api/v1/diagnose'){
   expect(route.request().method()).toBe('POST');const request=route.request().postDataJSON();requests.push(request);const ordinal=requests.length;
   if(ordinal===2){await route.fulfill({status:503,headers:{'Retry-After':'1'},json:{code:'diagnostic-busy',error:'PRIVATE_SYNTHETIC_BUSY_DETAIL'}});return;}
   if(ordinal===4){await route.fulfill({json:report(request)});return;}
   const gate=barrier();await gate.wait;try{await route.fulfill({json:report(request)})}catch{}finally{gate.complete()}return;
  }
  await route.fulfill({status:404,json:{error:'Synthetic route unavailable'}});
 });
 const nav=async view=>{const toggle=page.locator('#menu-toggle');if(await toggle.isVisible())await toggle.click();await page.locator('.nav-item[data-view="'+view+'"]').click();};
 try{
  await page.goto(origin+'/#accessweaver-session='+session);await nav('diagnostics');await page.locator('#probe-path').selectOption('socks5');await page.locator('#probe-proxy').fill('127.0.0.1:1080');await page.locator('#probe-host').fill('first.synthetic.example');await page.locator('#probe-timeout').fill('60');
  await expect(page.locator('#probe-submit')).toBeEnabled();expect(await page.locator('#diagnostic-form').evaluate(form=>form.checkValidity())).toBe(true);await page.locator('#probe-submit').click();await expect.poll(()=>requests.length).toBe(1);await expect(page.locator('#probe-cancel')).toBeEnabled();await page.locator('#probe-cancel').focus();await page.keyboard.press('Enter');
  await expect(page.locator('#diagnostic-results')).toContainText('Cancellation requested');await expect(page.locator('#probe-host')).toHaveValue('first.synthetic.example');await expect(page.locator('#probe-proxy')).toHaveValue('127.0.0.1:1080');await expect(page.locator('#export-report')).toBeHidden();await expect(page.locator('#probe-submit')).toBeFocused();
  await page.locator('#probe-submit').click();await expect(page.locator('#diagnostic-results')).toContainText('active or still finishing');expect(requests).toHaveLength(2);await expect(page.locator('#diagnostic-results')).not.toContainText('PRIVATE_SYNTHETIC_BUSY_DETAIL');await expect(page.locator('#probe-submit')).toBeEnabled();held[0].release();await held[0].done;await expect(page.locator('#diagnostic-meta')).toBeHidden();
  await page.locator('#probe-host').fill('second.synthetic.example');await page.locator('#probe-submit').click();await expect.poll(()=>requests.length).toBe(3);await page.locator('#probe-host').fill('current.synthetic.example');await expect(page.locator('#probe-cancel')).toBeDisabled();await expect(page.locator('#diagnostic-results')).toContainText('Inputs changed');await page.locator('#probe-submit').click();await expect(page.locator('#diagnostic-meta')).toContainText('current.synthetic.example');
  held[1].release();await held[1].done;await expect(page.locator('#diagnostic-meta')).not.toContainText('second.synthetic.example');
  const downloadReady=page.waitForEvent('download');await page.locator('#export-report').click();const download=await downloadReady;const exported=JSON.parse(await fs.readFile(await download.path(),'utf8'));expect(exported.host).toBe('current.synthetic.example');expect(exported.path).toBe('socks5');expect(exported.proxy).toBe('127.0.0.1:1080');
  await nav('settings');await nav('diagnostics');await expect(page.locator('#export-report')).toBeHidden();await expect(page.locator('#diagnostic-meta')).toBeHidden();await expect(page.locator('#probe-host')).toHaveValue('current.synthetic.example');
  const labels={en:'Cancel test',tr:'Testi iptal et',ru:'Отменить тест',es:'Cancelar prueba'};
  for(const [language,label] of Object.entries(labels)){
   await nav('settings');await page.locator('#settings-language').selectOption(language);await nav('diagnostics');await page.locator('#probe-host').fill('locale-'+language+'.synthetic.example');const count=requests.length;await page.locator('#probe-submit').click();await expect.poll(()=>requests.length).toBe(count+1);await expect(page.locator('#probe-cancel')).toHaveText(label);await page.locator('#probe-cancel').focus();await page.keyboard.press('Enter');await expect(page.locator('#probe-cancel')).toBeDisabled();await expect(page.locator('#export-report')).toBeHidden();await expect(page.locator('#diagnostic-results')).not.toContainText('probeCanceled');held.at(-1).release();await held.at(-1).done;
  }
  await page.locator('#lang-toggle').click();await expect(page.locator('html')).toHaveAttribute('lang','en');await expect(page.locator('#diagnostic-results')).toContainText('Cancellation requested');await expect(page.locator('#toast')).not.toContainText('Test completed');await page.setViewportSize({width:390,height:844});await settleAnimations(page);await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded','false');expect(await page.locator('#sidebar').evaluate(sidebar=>sidebar.inert)).toBe(true);expect(await page.evaluate(()=>!$('sidebar').contains(document.activeElement))).toBe(true);await expect.poll(()=>page.locator('#sidebar').evaluate(sidebar=>sidebar.getBoundingClientRect().right)).toBeLessThanOrEqual(0.5);await page.screenshot({path:testInfo.outputPath('diagnostic-fixture-source-only-canceled.png'),fullPage:true});
  await page.locator('#probe-submit').click();await expect(page.locator('#probe-cancel')).toBeEnabled();await expect.poll(()=>held.length).toBe(7);profileOnly=true;await page.evaluate(async()=>{await readCore();renderAll()});await expect(page.locator('.nav-item[data-view="diagnostics"]')).toBeDisabled();await expect(page.locator('#export-report')).toBeHidden();expect(await page.evaluate(()=>state.lastProbe)).toBeNull();held.at(-1).release();await held.at(-1).done;
  expect(requests.every(request=>request.path==='socks5'&&request.proxy==='127.0.0.1:1080')).toBe(true);
 }finally{for(const gate of held)gate.release();await Promise.allSettled(held.map(gate=>gate.done));}
});

// Static assets and synthetic API replies only; deliberately no core fixture,
// workflow worker, authority installation or native resource-release claim.
test('reconciliation fixture: explicit review, uncertain apply and known receipt retain original evidence',async({page},testInfo)=>{
 const origin='http://127.0.0.1:43105',session='d'.repeat(43),assets=new Map(),requests=[];
 const generation='4'.repeat(48),operationId='3'.repeat(48),object={ref:'7'.repeat(64),role:'closed-ack-stage',size:42,sha256:'8'.repeat(64)};
 let restricted=false,status='available',previewCount=0,applyCount=0,receiptCount=0,completed=false,holdReview=false,reviewEntered,releaseReview,applyEntered,releaseApply;
 const reviewStarted=new Promise(resolve=>reviewEntered=resolve),reviewGate=new Promise(resolve=>releaseReview=resolve),applyStarted=new Promise(resolve=>applyEntered=resolve),applyGate=new Promise(resolve=>releaseApply=resolve);
 const plan=resume=>({id:(resume?'a':'1').repeat(48),reviewRevision:'2'.repeat(64),operationId,generation,action:'retry-local-release-ack',expiresAt:new Date(Date.now()+120000).toISOString(),intentSHA256:'5'.repeat(64),sealSHA256:'6'.repeat(64),objects:[object],resume,scope:'original-local-owners-only',protection:'retirement-unavailable'});
 const receipt={operationId,generation,state:'completed',action:'retry-local-release-ack',intentSHA256:'5'.repeat(64),sealSHA256:'6'.repeat(64),ackSHA256:'9'.repeat(64),quarantined:[object],completedAt:'2026-11-01T00:00:00Z',scope:'original-local-owners-only',protection:'retirement-unavailable'};
 for(const [route,file,type] of [['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/locales.js','locales.js','text/javascript'],['/system.js','system.js','text/javascript'],['/app.css','app.css','text/css']])assets.set(route,{body:await fs.readFile(path.join(repo,'web',file)),contentType:type});
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());if(url.origin!==origin){await route.abort();return;}const asset=assets.get(url.pathname);if(asset){await route.fulfill(asset);return;}
  expect(route.request().headers()['x-accessweaver-token']).toBe(session);
  if(url.pathname==='/api/bootstrap'){await route.fulfill({json:{platform:'windows',version:'source-only-reconciliation',profileEditingOnly:restricted}});return;}
  if(url.pathname==='/api/v1/profiles'){await route.fulfill({status:500,json:{error:'Synthetic profile loading failure'}});return;}
  if(url.pathname==='/api/v1/engines'){await route.fulfill({json:[]});return;}
  if(url.pathname==='/api/v1/runtime'){await route.fulfill({json:{state:'stopped',log:[]}});return;}
  if(url.pathname.startsWith('/api/v1/system/history/reconciliation')){
   const method=route.request().method(),body=route.request().postDataJSON();requests.push({path:url.pathname,method,body});
   if(url.pathname.endsWith('/preview')){previewCount++;expect(method).toBe('POST');if(holdReview){reviewEntered();await reviewGate;}const resume=!!body.operationId;expect(body).toEqual(resume?{operationId}:{});await route.fulfill({json:plan(resume)}).catch(()=>{});return;}
   if(url.pathname.endsWith('/apply')){applyCount++;expect(method).toBe('POST');expect(body).toEqual({planId:(applyCount===1?'1':'a').repeat(48),confirm:true});if(applyCount===1){await route.abort('connectionreset');return;}applyEntered();await applyGate;completed=true;await route.fulfill({json:receipt}).catch(()=>{});return;}
   if(url.pathname.endsWith('/receipts/'+operationId)){receiptCount++;expect(method).toBe('GET');await route.fulfill(completed?{json:receipt}:{status:409,json:{code:'reconciliation-pending',error:'PRIVATE_SYNTHETIC_PENDING'}});return;}
   expect(method).toBe('GET');await route.fulfill({json:{state:status,generation,...(status==='pending'||status==='completed'?{operationId}:{}),canPreview:status==='available',resumeAvailable:status==='pending',scope:'original-local-owners-only',protection:'retirement-unavailable'}});return;
  }
  if(url.pathname==='/api/v1/system/history/lifecycle'){await route.fulfill({json:{state:'released',jobId:generation,admissionBlocked:false,protection:'retirement-unavailable'}});return;}
  if(url.pathname==='/api/v1/system/history/page'){await route.fulfill({status:409,json:{error:'Synthetic capture needed'}});return;}
  await route.fulfill({status:404,json:{error:'Synthetic route unavailable'}});
 });
 const nav=async view=>{const toggle=page.locator('#menu-toggle');if(await toggle.isVisible())await toggle.click();await page.locator('.nav-item[data-view="'+view+'"]').click();};
 try{
  await page.goto(origin+'/#accessweaver-session='+session);await expect(page.locator('#connection-notice')).toBeVisible();await nav('system');await expect(page.locator('#reconcile-status')).toBeHidden();await expect(page.locator('#reconcile-message')).toContainText('No reconciliation review is loaded');
  await page.evaluate(()=>{workflowLifecycleUI.admissionRefused=true;systemUI.job={id:'original-failed',state:'failed'};$('system-output').textContent='Original failed outcome retained';$('system-applications').value='Synthetic preserved input';$('system-journal').value='synthetic-recovery.json';$('system-cancel').disabled=false;updateHistoryAvailability()});
  await expect(page.locator('#reconcile-refresh')).toBeEnabled();expect(requests).toHaveLength(0);await page.locator('#reconcile-refresh').click();await expect(page.locator('#reconcile-status')).toContainText('not an automatic release');expect(await page.evaluate(()=>workflowLifecycleUI.admissionRefused)).toBe(true);
  await page.locator('#reconcile-preview').focus();await page.keyboard.press('Enter');await expect(page.locator('#reconcile-review')).toBeVisible();await expect(page.locator('#reconcile-review-title')).toBeFocused();await expect(page.locator('#reconcile-status')).toBeVisible();await expect(page.locator('#reconcile-apply')).toBeDisabled();await expect(page.locator('#reconcile-consent')).not.toBeChecked();await expect(page.locator('#reconcile-review-summary')).toContainText(operationId);await expect(page.locator('#reconcile-review-objects tr')).toHaveCount(1);
  await page.locator('#reconcile-consent').focus();await page.keyboard.press('Space');await page.locator('#reconcile-apply').focus();await page.keyboard.press('Enter');await expect(page.locator('#reconcile-message')).toContainText('Read its receipt');expect(applyCount).toBe(1);await expect(page.locator('#reconcile-operation')).toHaveValue(operationId);await expect(page.locator('#reconcile-consent')).not.toBeChecked();await expect(page.locator('#reconcile-review')).toBeHidden();await expect(page.locator('#system-output')).toHaveText('Original failed outcome retained');await expect(page.locator('#system-applications')).toHaveValue('Synthetic preserved input');expect(await page.evaluate(()=>workflowLifecycleUI.admissionRefused)).toBe(true);
  await page.locator('#reconcile-receipt').click();await expect(page.locator('#reconcile-message')).toContainText('read-only');await expect(page.locator('#reconcile-receipt')).toHaveText('Stop checking receipt');await page.locator('#reconcile-receipt').click();await expect(page.locator('#reconcile-message')).toContainText('Receipt checks stopped');expect(receiptCount).toBe(1);expect(applyCount).toBe(1);
  status='pending';await page.locator('#reconcile-refresh').click();await expect(page.locator('#reconcile-resume')).toBeEnabled();await page.locator('#reconcile-resume').click();await expect(page.locator('#reconcile-review')).toBeVisible();await expect(page.locator('#reconcile-consent')).not.toBeChecked();await page.locator('#reconcile-consent').check();await page.locator('#reconcile-apply').click();await applyStarted;await expect(page.locator('#system-history')).toBeEnabled();await expect(page.locator('#system-cancel')).toBeEnabled();await page.locator('#system-history').click();await expect(page.locator('#history-status')).toContainText('new capture');await expect(page.locator('#reconcile-message')).toContainText('Applying');
  await nav('settings');releaseApply();await nav('system');await expect(page.locator('#reconcile-operation')).toHaveValue(operationId);await expect(page.locator('#reconcile-receipt-panel')).toBeHidden();await expect(page.locator('#reconcile-consent')).not.toBeChecked();expect(applyCount).toBe(2);expect(await page.evaluate(()=>workflowLifecycleUI.admissionRefused)).toBe(true);
  await page.locator('#reconcile-receipt').click();await expect(page.locator('#reconcile-receipt-panel')).toBeVisible();await expect(page.locator('#reconcile-message')).toContainText('Reviewed local closure');await expect(page.locator('#reconcile-status')).toBeHidden();expect(await page.evaluate(()=>workflowLifecycleUI.admissionRefused)).toBe(false);await expect(page.locator('#system-output')).toHaveText('Original failed outcome retained');expect(await page.evaluate(()=>systemUI.job.state)).toBe('failed');await expect(page.locator('#system-journal')).toHaveValue('synthetic-recovery.json');
  // Start an explicitly requested new review, then invalidate it by navigating.
  status='available';await page.locator('#reconcile-refresh').click();holdReview=true;await page.locator('#reconcile-preview').click();await reviewStarted;await nav('settings');releaseReview();await nav('system');await expect(page.locator('#reconcile-review')).toBeHidden();await expect(page.locator('#reconcile-consent')).not.toBeChecked();expect(applyCount).toBe(2);
  const titles={en:'Review local closure',tr:'Yerel kapanışı incele',ru:'Проверка локального закрытия',es:'Revisar cierre local'};
  for(const [language,title] of Object.entries(titles)){await nav('settings');await page.locator('#settings-language').selectOption(language);await nav('system');await expect(page.locator('#reconcile-title')).toHaveText(title);await expect(page.locator('#reconcile-operation')).toHaveValue(operationId);}
  await nav('settings');await page.locator('#settings-language').selectOption('en');await nav('system');await page.locator('#reconcile-receipt').click();await expect(page.locator('#reconcile-receipt-panel')).toBeVisible();await page.setViewportSize({width:390,height:844});await settleAnimations(page);await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded','false');expect(await page.locator('#sidebar').evaluate(sidebar=>sidebar.inert)).toBe(true);await expect.poll(()=>page.locator('#sidebar').evaluate(sidebar=>sidebar.getBoundingClientRect().right)).toBeLessThanOrEqual(0.5);await page.locator('#reconcile-title').focus();await expect(page.locator('#reconcile-title')).toBeFocused();await page.evaluate(()=>window.scrollTo(0,0));await expect.poll(()=>page.locator('.skip-link').evaluate(link=>link.getBoundingClientRect().bottom)).toBeLessThanOrEqual(0);await page.screenshot({path:testInfo.outputPath('reconciliation-fixture-source-only-completed.png'),fullPage:true});
  const AxeBuilder=require('@axe-core/playwright').default;const accessibility=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(accessibility.violations.map(item=>item.id)).toEqual([]);
  restricted=true;await page.evaluate(async()=>{try{await readCore()}catch{}renderAll()});await expect(page.locator('.nav-item[data-view="system"]')).toBeDisabled();await expect(page.locator('#history-reconciliation-card')).toBeHidden();expect(await page.evaluate(()=>reconciliationUI.attempt)).toBeNull();expect(await page.locator('#reconcile-operation').inputValue()).toBe('');expect(applyCount).toBe(2);expect(previewCount).toBe(3);expect(requests.filter(item=>item.path.endsWith('/apply'))).toHaveLength(2);
 }finally{releaseApply();releaseReview();}
});

// Static assets and synthetic HTTP only. No core fixture, native workflow,
// source staging file or actual retained-owner cleanup is created here.
test('history staging fixture: retained capture keeps only freshly checked selection and explicit export',async({page},testInfo)=>{
 const origin='http://127.0.0.1:43106',session='e'.repeat(43),assets=new Map(),id='a'.repeat(48),ref='source_record_stage';
 const job={id,state:'failed',error:'Original source-only failure retained'},raw=Buffer.from(JSON.stringify(job)),revision=createHash('sha256').update(raw).digest('hex');
 const inventory={snapshot:'b'.repeat(48),storeRevision:'c'.repeat(48),createdAt:'2026-11-01T00:00:00Z',count:1,totalBytes:raw.length};
 const record={recordRef:ref,revision,id,action:'discover',state:'failed',finishedAt:'2026-11-01T00:00:00Z',size:raw.length,classification:'canonical',protection:'retirement-unavailable',errorPresent:true,resultPresent:false,rawAvailable:true};
 let captures=0,details=0,exports=0,releaseDetail,detailEntered;
 const detailGate=new Promise(resolve=>releaseDetail=resolve),detailStarted=new Promise(resolve=>detailEntered=resolve);
 for(const [route,file,type] of [['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/locales.js','locales.js','text/javascript'],['/system.js','system.js','text/javascript'],['/app.css','app.css','text/css']])assets.set(route,{body:await fs.readFile(path.join(repo,'web',file)),contentType:type});
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());if(url.origin!==origin){await route.abort();return;}const asset=assets.get(url.pathname);if(asset){await route.fulfill(asset);return;}
  expect(route.request().headers()['x-accessweaver-token']).toBe(session);
  if(url.pathname==='/api/bootstrap'){await route.fulfill({json:{platform:'windows',version:'source-only-history-staging',profileEditingOnly:false}});return;}
  if(url.pathname==='/api/v1/profiles'){await route.fulfill({status:500,json:{error:'Synthetic profile read failure'}});return;}
  if(url.pathname==='/api/v1/engines'){await route.fulfill({json:[]});return;}
  if(url.pathname==='/api/v1/runtime'){await route.fulfill({json:{state:'stopped',log:[]}});return;}
  if(url.pathname==='/api/v1/system/history/inventory'){
   expect(route.request().method()).toBe('POST');expect(route.request().postDataJSON()).toEqual({});captures++;expect(captures).toBeLessThanOrEqual(2);await route.fulfill(captures===1?{json:inventory}:{status:409,json:{code:'history-staging-pending',error:'PRIVATE_SYNTHETIC_STAGING_CAUSE'}});return;
  }
  if(url.pathname==='/api/v1/system/history/page'){
   expect(route.request().method()).toBe('GET');if(!captures){await route.fulfill({status:409,json:{error:'Synthetic capture needed'}});return;}
   if(captures===2)expect(url.searchParams.get('snapshot')).toBe(inventory.snapshot);await route.fulfill({json:{inventory,items:[record]}});return;
  }
  if(url.pathname==='/api/v1/system/history/records/'+ref){details++;expect(route.request().method()).toBe('GET');expect(url.searchParams.get('revision')).toBe(revision);if(details===2){detailEntered();await detailGate;}await route.fulfill({json:{record,job,rawAvailable:true}});return;}
  if(url.pathname==='/api/v1/system/history/records/'+ref+'/export'){exports++;expect(route.request().method()).toBe('GET');expect(url.searchParams.get('revision')).toBe(revision);await route.fulfill({body:raw,headers:{'Content-Type':'application/octet-stream','ETag':'"'+revision+'"','X-AccessWeaver-Revision':revision}});return;}
  await route.fulfill({status:404,json:{error:'Synthetic route unavailable'}});
 });
 const nav=async view=>{const toggle=page.locator('#menu-toggle');if(await toggle.isVisible())await toggle.click();await page.locator('.nav-item[data-view="'+view+'"]').click();};
 try{
  await page.goto(origin+'/#accessweaver-session='+session);await expect(page.locator('#connection-notice')).toBeVisible();await nav('system');await page.locator('#system-history').click();await page.locator('#history-capture').click();await page.getByTitle(id,{exact:true}).click();await expect(page.locator('#history-detail')).toContainText(job.error);await expect(page.locator('#history-export-record')).toBeEnabled();
  await page.evaluate(()=>{systemUI.plan={id:'source-review-kept',ready:true};$('system-consent').checked=true;$('system-cancel').disabled=false});
  await page.locator('#history-capture').focus();await page.keyboard.press('Enter');await detailStarted;await expect(page.locator('#history-export-record')).toBeDisabled();await expect(page.locator('#history-detail-panel')).toBeHidden();await expect(page.locator('#system-cancel')).toBeEnabled();expect(exports).toBe(0);releaseDetail();
  await expect(page.locator('#history-status')).toContainText('incomplete inventory capture');await expect(page.locator('#history-status')).not.toContainText('PRIVATE_SYNTHETIC');await expect(page.locator('#history-detail')).toContainText(job.error);await expect(page.locator('#history-export-record')).toBeEnabled();expect(captures).toBe(2);expect(details).toBe(2);expect(exports).toBe(0);expect(await page.evaluate(()=>systemUI.plan.id)).toBe('source-review-kept');await expect(page.locator('#system-consent')).toBeChecked();
  const downloading=page.waitForEvent('download');await page.locator('#history-export-record').click();const download=await downloading;expect(await fs.readFile(await download.path())).toEqual(raw);expect(exports).toBe(1);expect(captures).toBe(2);
  await page.setViewportSize({width:390,height:844});await settleAnimations(page);await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded','false');expect(await page.locator('#sidebar').evaluate(sidebar=>sidebar.inert)).toBe(true);await expect.poll(()=>page.locator('#sidebar').evaluate(sidebar=>sidebar.getBoundingClientRect().right)).toBeLessThanOrEqual(0.5);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);await expect(page.locator('#history-detail-title')).toContainText(id);await page.locator('#history-title').focus();await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:testInfo.outputPath('history-staging-source-only-preserved.png'),fullPage:true});
  const AxeBuilder=require('@axe-core/playwright').default;const accessibility=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(accessibility.violations.map(item=>item.id)).toEqual([]);
 }finally{releaseDetail();}
});

// Static assets + synthetic API only. No core fixture or native storage charge.
test('controller storage fixture: logical observation and refused admission preserve explicit review and controls',async({page},testInfo)=>{
 const origin='http://127.0.0.1:43107',session='f'.repeat(43),assets=new Map(),calls=[];let projection='uninitialized',refusal='workflow-storage-capacity',held=false,releaseRead,readEntered;
 const readGate=new Promise(resolve=>releaseRead=resolve),readStarted=new Promise(resolve=>readEntered=resolve);
 const status=state=>({state,scope:'tracked-controller-evidence-only',...(state!=='uninitialized'?{generation:'a'.repeat(48),action:'discover'}:{}),generationsTracked:state==='uninitialized'?0:2,reservedBytes:state==='tracked'?65536:0,retainedChargeBytes:state==='uninitialized'?0:32768,uncertainBytes:state==='pending'?65536:0,finalizationReservedBytes:state==='tracked'?16384:0,legacyAccounting:'not-included',aggregateQuotaEnforced:false,physicalCapacityGuaranteed:false,nativeWritersContained:false,workerJournalBounded:false});
 for(const [route,file,type] of [['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/locales.js','locales.js','text/javascript'],['/system.js','system.js','text/javascript'],['/app.css','app.css','text/css']])assets.set(route,{body:await fs.readFile(path.join(repo,'web',file)),contentType:type});
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());if(url.origin!==origin){await route.abort();return;}const asset=assets.get(url.pathname);if(asset){await route.fulfill(asset);return;}expect(route.request().headers()['x-accessweaver-token']).toBe(session);
  if(url.pathname==='/api/bootstrap'){await route.fulfill({json:{platform:'windows',version:'source-only-controller-storage',profileEditingOnly:false}});return;}
  if(url.pathname==='/api/v1/profiles'){await route.fulfill({status:500,json:{error:'Synthetic profile loading failure'}});return;}
  if(url.pathname==='/api/v1/engines'){await route.fulfill({json:[]});return;}
  if(url.pathname==='/api/v1/runtime'){await route.fulfill({json:{state:'stopped',log:[]}});return;}
  calls.push({path:url.pathname,method:route.request().method()});
  if(url.pathname==='/api/v1/system/storage'){expect(route.request().method()).toBe('GET');expect(url.search).toBe('');if(held){readEntered();await readGate;}await route.fulfill({json:status(projection)}).catch(()=>{});return;}
  if(url.pathname==='/api/v1/system/start'){expect(route.request().postDataJSON()).toEqual({planId:'source-reviewed-storage',confirm:true});await route.fulfill({status:409,json:{code:refusal,error:'PRIVATE_SYNTHETIC_STORAGE_PATH'}});return;}
  if(url.pathname==='/api/v1/system/folder'){expect(route.request().postDataJSON()).toEqual({});await route.fulfill({status:409,json:{code:'workflow-storage-pending',error:'PRIVATE_SYNTHETIC_FOLDER_PATH'}});return;}
  if(url.pathname==='/api/v1/system/history/page'){await route.fulfill({status:409,json:{error:'Synthetic capture needed'}});return;}
  await route.fulfill({status:404,json:{error:'Synthetic route unavailable'}});
 });
 const nav=async view=>{const toggle=page.locator('#menu-toggle');if(await toggle.isVisible())await toggle.click();await page.locator('.nav-item[data-view="'+view+'"]').click();};
 try{
  await page.goto(origin+'/#accessweaver-session='+session);await expect(page.locator('#connection-notice')).toBeVisible();await nav('system');await expect(page.locator('#controller-storage-refresh')).toBeEnabled();expect(calls.filter(call=>call.path==='/api/v1/system/storage')).toHaveLength(0);
  await page.locator('#controller-storage-refresh').focus();await page.keyboard.press('Enter');await expect(page.locator('#controller-storage-status')).toContainText('does not mean the disk is empty');await expect(page.locator('#controller-storage-values')).toBeHidden();
  projection='tracked';await page.locator('#controller-storage-refresh').click();await expect(page.locator('#controller-storage-values')).toBeVisible();await expect(page.locator('#controller-storage-reserved')).toContainText('65,536');await expect(page.locator('#controller-storage-card')).toContainText('does not enforce an aggregate quota');
  await page.evaluate(()=>{systemUI.plan={id:'source-reviewed-storage',ready:true};$('system-consent').checked=true;$('system-consent').disabled=false;$('system-apply').disabled=false;$('system-applications').value='Source preserved input';$('system-journal').value='source-recovery.json';$('system-output').textContent='Original outcome preserved';$('system-cancel').disabled=false});
  await page.locator('#system-apply').click();await expect(page.locator('#controller-storage-refusal')).toContainText('limits refused');await expect(page.locator('#controller-storage-refusal')).not.toContainText('PRIVATE_SYNTHETIC');await expect(page.locator('#controller-storage-title')).toBeFocused();await expect(page.locator('#system-applications')).toHaveValue('Source preserved input');await expect(page.locator('#system-journal')).toHaveValue('source-recovery.json');await expect(page.locator('#system-output')).toHaveText('Original outcome preserved');await expect(page.locator('#system-consent')).not.toBeChecked();await expect(page.locator('#system-apply')).toBeDisabled();await expect(page.locator('#system-cancel')).toBeEnabled();expect(calls.filter(call=>call.path==='/api/v1/system/start')).toHaveLength(1);
  await page.locator('#controller-storage-refresh').click();await expect(page.locator('#controller-storage-status')).toContainText('does not authorize');await expect(page.locator('#controller-storage-refusal')).toBeVisible();expect(await page.evaluate(()=>systemUI.plan)).toBeNull();
  held=true;await page.locator('#controller-storage-refresh').click();await readStarted;await page.locator('#system-history').click();await expect(page.locator('#history-status')).toContainText('new capture');await expect(page.locator('#system-cancel')).toBeEnabled();await nav('settings');releaseRead();await nav('system');await expect(page.locator('#controller-storage-generation')).toBeEmpty();await expect(page.locator('#controller-storage-refusal')).toBeVisible();held=false;
  projection='pending';await page.locator('#controller-storage-refresh').click();await expect(page.locator('#controller-storage-status')).toContainText('not assumed complete');await expect(page.locator('#controller-storage-reserved')).toContainText('0');await expect(page.locator('#controller-storage-uncertain')).toContainText('65,536');await page.locator('#system-folder').click();await expect(page.locator('#controller-storage-refusal')).toContainText('explicit review');await expect(page.locator('#system-output')).toHaveText('Original outcome preserved');await expect(page.locator('#system-cancel')).toBeEnabled();expect(calls.filter(call=>call.path==='/api/v1/system/folder')).toHaveLength(1);
  const titles={en:'Controller evidence storage',tr:'Denetleyici kanıt depolaması',ru:'Хранилище данных контроллера',es:'Almacenamiento del controlador'};
  for(const [language,title]of Object.entries(titles)){await nav('settings');await page.locator('#settings-language').selectOption(language);await nav('system');await expect(page.locator('#controller-storage-title')).toHaveText(title);await expect(page.locator('#controller-storage-refusal')).toBeVisible();expect(await page.locator('#controller-storage-refusal').textContent()).not.toContain('controllerStorage');}
  await nav('settings');await page.locator('#settings-language').selectOption('en');await nav('system');await page.locator('#controller-storage-refresh').click();await expect(page.locator('#controller-storage-status')).toContainText('not assumed complete');await page.setViewportSize({width:390,height:844});await settleAnimations(page);await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded','false');expect(await page.locator('#sidebar').evaluate(sidebar=>sidebar.inert)).toBe(true);await expect.poll(()=>page.locator('#sidebar').evaluate(sidebar=>sidebar.getBoundingClientRect().right)).toBeLessThanOrEqual(0.5);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);await expect(page.locator('#toast')).toHaveAttribute('class','');await settleAnimations(page);await page.locator('#controller-storage-title').focus();await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:testInfo.outputPath('controller-storage-source-only-pending.png'),fullPage:true});
  const AxeBuilder=require('@axe-core/playwright').default;const accessibility=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(accessibility.violations.map(item=>item.id)).toEqual([]);
  expect(calls.filter(call=>call.method==='POST')).toEqual([{path:'/api/v1/system/start',method:'POST'},{path:'/api/v1/system/folder',method:'POST'}]);
 }finally{releaseRead();}
});
