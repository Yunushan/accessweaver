#!/usr/bin/env node
'use strict';
// Offline native CLI/Web Crypto interoperability; no network or OS mutations.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash, randomBytes, webcrypto } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const {validateBuild}=require('./check-native-environment.cjs');

const executable = path.resolve(process.argv[2] || (process.platform === 'win32' ? 'accessweaver.exe' : 'accessweaver'));
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'accessweaver-backup-check-'));
const source = path.join(workspace, 'source');
const password = 'independent Web Crypto test passphrase';
const passwordFile = path.join(workspace, 'passphrase.txt');
const archive = path.join(workspace, 'profiles.awbackup');
const fixture = { version: 1, id: 'interop-profile', name: 'Private interoperability profile', engine: 'byedpi',
  args: ['private literal argument'], routing: { includeDomains: [], excludeDomains: [], applications: [] },
  probe: { host: 'example.org', port: 443, tls: true, timeoutSeconds: 5 }, updatedAt: '2026-11-01T00:00:00Z' };
function cli(args, success = true) {
  const child = spawnSync(executable, args, { env: { ...process.env, ACCESSWEAVER_HOME: source }, encoding: 'utf8', timeout: 30000, windowsHide: true });
  if (child.error) throw child.error;
  for (const privateText of [password, fixture.name, fixture.args[0]]) { assert(!child.stdout.includes(privateText)); assert(!child.stderr.includes(privateText)); }
  if (success) { assert.equal(child.status, 0, child.stderr); return JSON.parse(child.stdout); }
  assert.notEqual(child.status, 0, 'invalid archive unexpectedly accepted');
  assert(!child.stderr.includes(password));
  return child;
}
async function derive(salt, usages) {
  const material = await webcrypto.subtle.importKey('raw', Buffer.from(password, 'utf8'), 'PBKDF2', false, ['deriveKey']);
  return webcrypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, material,
    { name: 'AES-GCM', length: 256 }, false, usages);
}
(async () => {
  try {
    const build=cli(['version','--json']);
    if(process.env.ACCESSWEAVER_EXPECT_GOOS || process.env.ACCESSWEAVER_EXPECT_GOARCH)validateBuild(build,{goos:process.env.ACCESSWEAVER_EXPECT_GOOS,goarch:process.env.ACCESSWEAVER_EXPECT_GOARCH,goVersion:process.env.GO_VERSION,commit:process.env.GITHUB_SHA||''});
    fs.mkdirSync(path.join(source, 'profiles'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(source, 'profiles', fixture.id + '.json'), JSON.stringify(fixture), { mode: 0o600 });
    fs.writeFileSync(passwordFile, password + '\n', { mode: 0o600 });
    const created = cli(['backup', 'create', '--out', archive, '--passphrase-file', passwordFile]);
    assert.equal(created.profiles, 1);
    const data = fs.readFileSync(archive);
    assert.equal(data.subarray(0, 8).toString(), 'AWBACKUP');
    assert.equal(data.readUInt32BE(12), 600000);
    assert(!data.includes(Buffer.from(fixture.name)));
    const decoded = JSON.parse(Buffer.from(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(32, 44),
      additionalData: data.subarray(0, 44), tagLength: 128 }, await derive(data.subarray(16, 32), ['decrypt']), data.subarray(44))).toString('utf8'));
    assert.deepEqual(decoded.profiles, [fixture]);
    const header = Buffer.alloc(44);
    header.write('AWBACKUP'); header[8] = header[9] = header[10] = 1; header.writeUInt32BE(600000, 12);
    randomBytes(28).copy(header, 16);
    const payload = Buffer.from(JSON.stringify({ schemaVersion: 1, createdAt: '2026-11-01T01:02:03Z', profiles: [fixture] }));
    const encrypted = Buffer.from(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: header.subarray(32, 44),
      additionalData: header, tagLength: 128 }, await derive(header.subarray(16, 32), ['encrypt']), payload));
    const foreign = path.join(workspace, 'webcrypto.awbackup');
    fs.writeFileSync(foreign, Buffer.concat([header, encrypted]), { mode: 0o600 });
    assert.equal(cli(['backup', 'inspect', '--archive', foreign, '--passphrase-file', passwordFile]).authenticated, true);
    const restored = path.join(workspace, 'restored');
    assert.equal(cli(['backup', 'restore', '--archive', foreign, '--passphrase-file', passwordFile, '--into', restored]).complete, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(restored, 'profiles', fixture.id + '.json'), 'utf8')), fixture);
    assert(!fs.existsSync(path.join(restored, '.restore-incomplete')));
    const damaged = fs.readFileSync(foreign); damaged[damaged.length - 1] ^= 1;
    fs.writeFileSync(foreign, damaged);
    assert.match(cli(['backup', 'inspect', '--archive', foreign, '--passphrase-file', passwordFile], false).stderr, /authentication failed/);
    fs.writeFileSync(passwordFile, 'a wrong independent passphrase');
    assert.match(cli(['backup', 'inspect', '--archive', archive, '--passphrase-file', passwordFile], false).stderr, /authentication failed/);
    const evidence = { sourceCommit: process.env.GITHUB_SHA || 'unknown', platform: process.platform, arch: process.arch,
      nodeVersion: process.version, build, binarySha256: createHash('sha256').update(fs.readFileSync(executable)).digest('hex'),
      goToWebCrypto: true, webCryptoToGo: true, restoredRevisionPreserved: true,
      tamperRejected: true, wrongPassphraseRejected: true, productionQualificationComplete: false };
    const evidenceDir = path.resolve('build', 'backup-checks');
    fs.mkdirSync(evidenceDir, { recursive: true });
    fs.writeFileSync(path.join(evidenceDir, 'interop-' + process.platform + '.json'), JSON.stringify(evidence, null, 2) + '\n');
    console.log(JSON.stringify(evidence));
  } finally {
    const absolute = path.resolve(workspace);
    assert.equal(path.dirname(absolute), path.resolve(os.tmpdir()));
    assert(path.basename(absolute).startsWith('accessweaver-backup-check-'));
    assert(!fs.lstatSync(absolute).isSymbolicLink());
    fs.rmSync(absolute, { recursive: true, force: true });
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
