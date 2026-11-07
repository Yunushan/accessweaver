#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {architecture}=require('../check-native-environment.cjs');
const {verifyBrowserCache,validateNativeInvocation}=require('./browser-native-binary.cjs');

const expectedVersion = '1.64.1';
const expectedCache = '/ms-playwright';

assert.equal(process.platform, 'linux', 'Browser image verification requires Linux');
validateNativeInvocation(process.env);
assert.equal(process.getuid(), 1001, 'Browser acceptance requires UID 1001');
assert.ok(['amd64','arm64'].includes(process.env.ACCESSWEAVER_EXPECT_GOARCH),'Explicit native browser architecture is required');
assert.equal(architecture(process.arch),process.env.ACCESSWEAVER_EXPECT_GOARCH,'Node observer architecture differs from native target');
assert.equal(process.env.PLAYWRIGHT_BROWSERS_PATH, expectedCache, 'Keep the image browser cache selected');

const lock = JSON.parse(fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8'));
assert.equal(lock.packages[''].devDependencies['@playwright/test'], expectedVersion, 'Lockfile test dependency differs');
for (const name of ['@playwright/test', 'playwright', 'playwright-core']) {
  assert.equal(lock.packages['node_modules/' + name].version, expectedVersion, 'Lockfile version differs for ' + name);
  const installed = JSON.parse(fs.readFileSync(require.resolve(name + '/package.json'), 'utf8'));
  assert.equal(installed.version, expectedVersion, 'Installed version differs for ' + name);
}

const cache = fs.realpathSync(expectedCache);
assert.equal(cache, expectedCache, 'Image browser cache must retain its expected path');
assert.ok(fs.statSync(cache).isDirectory(), 'Image browser cache must be a directory');

const playwright = require('@playwright/test');
const executables={};
for (const name of ['chromium', 'firefox', 'webkit']) {
  const executable = playwright[name].executablePath();executables[name]=executable;
  assert.ok(path.isAbsolute(executable), 'Browser executable path must be absolute for ' + name);
  const resolved = fs.realpathSync(executable);
  const relative = path.relative(cache, resolved);
  assert.ok(relative && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative),
    'Browser executable must remain inside the image cache for ' + name);
  assert.ok(fs.statSync(resolved).isFile(), 'Browser executable must be a regular file for ' + name);
  fs.accessSync(resolved, fs.constants.X_OK);
  console.log(name + ': ' + resolved);
}

const native=verifyBrowserCache(cache,executables,process.env.ACCESSWEAVER_EXPECT_GOARCH);
console.log('Verified native browser ELF architecture '+process.env.ACCESSWEAVER_EXPECT_GOARCH+' for '+native.length+' entry points.');
// Header checks do not prove shared-library compatibility or actual browser launch.
// The unchanged real-controller suite must establish those runtime outcomes.
console.log('Verified locked Playwright ' + expectedVersion + ' and preinstalled browser executable paths.');
