const base = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { createHash } = require('node:crypto');
const { expect } = base;
const repo = path.resolve(__dirname, '../..');
const binary = path.resolve(process.env.ACCESSWEAVER_BINARY || path.join(repo, 'build/browser-tests', process.platform === 'win32' ? 'accessweaver.exe' : 'accessweaver'));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const test = base.test.extend({
  core: async ({browser}, use, testInfo) => {
    const parent = path.join(repo, 'build/browser-state');
    await fs.mkdir(parent, {recursive:true, mode:0o700});
    const home = await fs.mkdtemp(path.join(parent, 'case-'));
    const cache = path.join(home, 'cache');
    await fs.mkdir(cache, {mode:0o700});
    let output = '', startError;
    const child = spawn(binary, ['ui'], {windowsHide:true, stdio:['ignore','pipe','pipe'], env:{...process.env,
      ACCESSWEAVER_HOME:path.join(home,'state'), ACCESSWEAVER_NO_BROWSER:'1', XDG_CACHE_HOME:cache, LOCALAPPDATA:cache}});
    const exited = () => child.exitCode!==null || child.signalCode!==null;
    child.once('error', error => {startError=error;});
    child.stdout.on('data', data => {output=(output+data.toString()).slice(-65536);});
    child.stderr.on('data', data => {output=(output+data.toString()).slice(-65536);});
    try {
      const deadline=Date.now()+15_000;
      let launcher;
      while(!(launcher=output.match(/Open this private launch file in your browser: (file:[^\r\n]+)/)?.[1])) {
        if(startError) throw startError;
        if(exited()) throw new Error('Controller exited before its launcher was ready: '+output);
        if(Date.now()>deadline) throw new Error('Controller did not produce a private launcher');
        await delay(25);
      }
      await testInfo.attach('candidate.json', {body:JSON.stringify({
        binarySha256:createHash('sha256').update(await fs.readFile(binary)).digest('hex'),
        platform:process.platform, architecture:process.arch, node:process.version,
        browser:browser.version(), project:testInfo.project.name,
        playwright:require('@playwright/test/package.json').version,
        build:JSON.parse(execFileSync(binary,['version','--json'],{windowsHide:true,encoding:'utf8'})),
      }), contentType:'application/json'});
      await use({launcher, home, profilePath:id=>path.join(home,'state','profiles',id+'.json')});
    } finally {
      if(!exited() && child.pid) {
        const exitEvent=once(child,'exit');
        child.kill('SIGTERM');
        await Promise.race([exitEvent,delay(5000)]);
        if(!exited()) {child.kill('SIGKILL');await Promise.race([exitEvent,delay(5000)]);}
        if(!exited()) throw new Error('Isolated test controller did not stop');
      }
      // The private launcher lives only in this ignored test fixture. Do not
      // upload state/cache: they contain session credentials and profile data.
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

test('modal keyboard focus, preferences and narrow navigation work in the real DOM', async ({page,core}) => {
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
  await page.setViewportSize({width:390,height:844});
  for(const language of ['en','tr','ru','es']) {
    await page.locator('#menu-toggle').click();await page.locator('.nav-item[data-view="settings"]').click();
    await page.locator('#settings-language').selectOption(language);
    for(const view of ['dashboard','profiles','engines','diagnostics','settings','system']) {
      await page.locator('#menu-toggle').click();await page.locator(`.nav-item[data-view="${view}"]`).click();
      await expect(page.locator('#view-'+view)).toBeVisible();
      await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded','false');
      const layout=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,
        overflow:Array.from(document.querySelectorAll('body *')).filter(el=>el.getBoundingClientRect().right>innerWidth+1).slice(0,15).map(el=>({tag:el.tagName,id:el.id,class:el.className,right:el.getBoundingClientRect().right}))}));
      expect(layout.scroll,language+'/'+view+': '+JSON.stringify(layout)).toBeLessThanOrEqual(layout.width+1);
    }
  }
});
