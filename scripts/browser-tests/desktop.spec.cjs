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
 await page.locator('#system-history').click();await expect(page.locator('#system-output')).toContainText('keyboard-fixture');
 await tabTo('system-output');await page.keyboard.press('PageDown');
 await expect.poll(()=>page.locator('#system-output').evaluate(el=>el.scrollTop)).toBeGreaterThan(0);
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
 await page.locator('#system-history').click();
 await expect(page.locator('#system-output')).toContainText('display-fixture');
 await expect(page.locator('#system-output-limited')).toBeVisible();
 await expect(page.locator('#system-output img')).toHaveCount(0);expect(await page.evaluate(()=>globalThis.workflowPayloadExecuted)).toBeUndefined();expect(await page.evaluate(()=>globalThis.workflowMetadataExecuted)).toBeUndefined();
 await expect(page.locator('#system-output')).toHaveAttribute('aria-describedby','system-output-limited');
 expect((await page.locator('#system-output').textContent()).length).toBeLessThanOrEqual(128*1024);
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
 await page.locator('#system-action').selectOption('recover');await page.locator('#system-journal').fill('reviewed.json');
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
