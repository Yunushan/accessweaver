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
let workspace,workspaceIdentity,source,passwordFile,archive;
let preserveWorkspace=false;
let phase='fixture-setup',failedPhase='',cleanupFailed=false;
const password = '  independent \u00e9 \ud83d\udd12 Web Crypto test passphrase  ';
const fixture = { version: 1, id: 'interop-profile', name: 'Private interoperability profile', engine: 'byedpi',
  args: ['private literal argument'], routing: { includeDomains: [], excludeDomains: [], applications: [] },
  probe: { host: 'example.org', port: 443, tls: true, timeoutSeconds: 5 }, updatedAt: '2026-11-01T00:00:00Z' };
function cli(args, success = true, home=source) {
  const child = spawnSync(executable, args, { env: { ...process.env, ACCESSWEAVER_HOME: home }, encoding: 'utf8', timeout: 30000, maxBuffer:64*1024, windowsHide: true });
  const reaped=Number.isInteger(child.status)||(typeof child.signal==='string'&&child.signal.length>0);
  if(child.pid>0&&!reaped)preserveWorkspace=true;
  if(child.error||!reaped)throw new Error('Backup fixture child did not complete safely');
  for(const privateText of [password,password.trim(),'a wrong independent passphrase',fixture.name,fixture.args[0],workspace,JSON.stringify(workspace).slice(1,-1)]){
    assert(!child.stdout.includes(privateText),'Backup fixture output disclosed private input');assert(!child.stderr.includes(privateText),'Backup fixture error disclosed private input');
  }
  if(success){assert.equal(child.status,0,'Backup fixture command failed');return JSON.parse(child.stdout);}
  assert.notEqual(child.status,0,'Invalid backup operation unexpectedly accepted');
  assert.equal(child.stdout,'','Failed backup operation emitted success metadata');
  return child;
}
function unchanged(file,bytes){assert(fs.readFileSync(file).equals(bytes),'Backup refusal changed existing fixture bytes');}
function absent(file){assert(!fs.existsSync(file),'Refused backup operation created a destination');}
async function derive(salt, usages) {
  const material = await webcrypto.subtle.importKey('raw', Buffer.from(password, 'utf8'), 'PBKDF2', false, ['deriveKey']);
  return webcrypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, material,
    { name: 'AES-GCM', length: 256 }, false, usages);
}
(async () => {
  let evidence;
  try {
    workspace=fs.mkdtempSync(path.join(os.tmpdir(),'accessweaver-backup-check-'));workspaceIdentity=fs.lstatSync(workspace,{bigint:true});
    source=path.join(workspace,'source');passwordFile=path.join(workspace,'passphrase.txt');archive=path.join(workspace,'profiles.awbackup');
    phase='native-build';
    const build=cli(['version','--json']);
    if(process.env.ACCESSWEAVER_EXPECT_GOOS || process.env.ACCESSWEAVER_EXPECT_GOARCH)validateBuild(build,{goos:process.env.ACCESSWEAVER_EXPECT_GOOS,goarch:process.env.ACCESSWEAVER_EXPECT_GOARCH,goVersion:process.env.GO_VERSION,commit:process.env.GITHUB_SHA||''});
    fs.mkdirSync(path.join(source, 'profiles'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(source, 'profiles', fixture.id + '.json'), JSON.stringify(fixture), { mode: 0o600 });
    fs.writeFileSync(passwordFile, password + '\r\n', { mode: 0o600 });
    phase='go-create-webcrypto-decrypt';
    const created = cli(['backup', 'create', '--out', archive, '--passphrase-file', passwordFile]);
    assert.equal(created.profiles, 1);
    const data = fs.readFileSync(archive);
    assert.equal(data.subarray(0, 8).toString(), 'AWBACKUP');
    assert.equal(data.readUInt32BE(12), 600000);
    assert(!data.includes(Buffer.from(fixture.name)));
    const decoded = JSON.parse(Buffer.from(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(32, 44),
      additionalData: data.subarray(0, 44), tagLength: 128 }, await derive(data.subarray(16, 32), ['decrypt']), data.subarray(44))).toString('utf8'));
    assert.deepEqual(decoded.profiles, [fixture]);
    phase='output-preservation';
    const savedProfile=path.join(source,'profiles',fixture.id+'.json'),savedBytes=fs.readFileSync(savedProfile),passphraseBytes=fs.readFileSync(passwordFile);
    cli(['backup','create','--out',archive,'--passphrase-file',passwordFile],false);unchanged(archive,data);unchanged(savedProfile,savedBytes);unchanged(passwordFile,passphraseBytes);
    cli(['backup','create','--out',passwordFile,'--passphrase-file',passwordFile],false);unchanged(passwordFile,passphraseBytes);unchanged(savedProfile,savedBytes);
    const inside=path.join(source,'profiles','refused-output.awbackup');cli(['backup','create','--out',inside,'--passphrase-file',passwordFile],false);absent(inside);unchanged(savedProfile,savedBytes);
    // The KDF gets exactly the original UTF-8 bytes: preserve spaces/Unicode,
    // remove at most one conventional line ending and never normalize text.
    phase='passphrase-exactness';
    for(const suffix of ['\n','']){fs.writeFileSync(passwordFile,password+suffix);assert.equal(cli(['backup','inspect','--archive',archive,'--passphrase-file',passwordFile]).authenticated,true);}
    for(const changed of [password+'\n\n',password.trim()+'\n']){fs.writeFileSync(passwordFile,changed);assert.match(cli(['backup','inspect','--archive',archive,'--passphrase-file',passwordFile],false).stderr,/authentication failed/);}
    fs.writeFileSync(passwordFile,passphraseBytes);
    phase='bad-input-refusal';
    const missingSource=path.join(workspace,'missing-source'),missingOut=path.join(workspace,'missing-source.awbackup');cli(['backup','create','--out',missingOut,'--passphrase-file',passwordFile],false,missingSource);absent(missingSource);absent(missingOut);
    const oversized=path.join(workspace,'oversized.awbackup');const overFD=fs.openSync(oversized,'wx',0o600);try{fs.ftruncateSync(overFD,(8<<20)+44+16+1)}finally{fs.closeSync(overFD)}
    for(const bad of [path.join(workspace,'absent.awbackup'),workspace,oversized]){const destination=path.join(workspace,'refused-restore-'+path.basename(bad));cli(['backup','restore','--archive',bad,'--passphrase-file',passwordFile,'--into',destination],false);absent(destination);unchanged(savedProfile,savedBytes);}
    const invalidPassphrase=path.join(workspace,'invalid-passphrase.txt');fs.writeFileSync(invalidPassphrase,Buffer.from([0xff]),{mode:0o600});const invalidOut=path.join(workspace,'invalid-password-output.awbackup');cli(['backup','create','--out',invalidOut,'--passphrase-file',invalidPassphrase],false);absent(invalidOut);

    phase='webcrypto-encrypt-go-inspect';
    const header = Buffer.alloc(44);
    header.write('AWBACKUP'); header[8] = header[9] = header[10] = 1; header.writeUInt32BE(600000, 12);
    randomBytes(28).copy(header, 16);
    const payload = Buffer.from(JSON.stringify({ schemaVersion: 1, createdAt: '2026-11-01T01:02:03Z', profiles: [fixture] }));
    const encrypted = Buffer.from(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: header.subarray(32, 44),
      additionalData: header, tagLength: 128 }, await derive(header.subarray(16, 32), ['encrypt']), payload));
    const foreign = path.join(workspace, 'webcrypto.awbackup');
    fs.writeFileSync(foreign, Buffer.concat([header, encrypted]), { mode: 0o600 });
    assert.equal(cli(['backup', 'inspect', '--archive', foreign, '--passphrase-file', passwordFile]).authenticated, true);
    phase='restore-preservation';
    const restored = path.join(workspace, 'restored');
    assert.equal(cli(['backup', 'restore', '--archive', foreign, '--passphrase-file', passwordFile, '--into', restored]).complete, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(restored, 'profiles', fixture.id + '.json'), 'utf8')), fixture);
    assert(!fs.existsSync(path.join(restored, '.restore-incomplete')));
    const restoredProfile=path.join(restored,'profiles',fixture.id+'.json'),restoredBytes=fs.readFileSync(restoredProfile);
    cli(['backup','restore','--archive',foreign,'--passphrase-file',passwordFile,'--into',restored],false);unchanged(restoredProfile,restoredBytes);

    phase='tamper-refusal';
    const damaged = fs.readFileSync(foreign); damaged[damaged.length - 1] ^= 1;
    fs.writeFileSync(foreign, damaged);
    assert.match(cli(['backup', 'inspect', '--archive', foreign, '--passphrase-file', passwordFile], false).stderr, /authentication failed/);
    const tamperedDestination=path.join(workspace,'tampered-restore');cli(['backup','restore','--archive',foreign,'--passphrase-file',passwordFile,'--into',tamperedDestination],false);absent(tamperedDestination);

    phase='wrong-passphrase-refusal';
    fs.writeFileSync(passwordFile, 'a wrong independent passphrase');
    assert.match(cli(['backup', 'inspect', '--archive', archive, '--passphrase-file', passwordFile], false).stderr, /authentication failed/);
    const wrongDestination=path.join(workspace,'wrong-passphrase-restore');cli(['backup','restore','--archive',archive,'--passphrase-file',passwordFile,'--into',wrongDestination],false);absent(wrongDestination);unchanged(archive,data);unchanged(savedProfile,savedBytes);unchanged(restoredProfile,restoredBytes);

    evidence = { sourceCommit: process.env.GITHUB_SHA || 'unknown', platform: process.platform, arch: process.arch,
      nodeVersion: process.version, build, binarySha256: createHash('sha256').update(fs.readFileSync(executable)).digest('hex'),
      goToWebCrypto: true, webCryptoToGo: true, restoredRevisionPreserved: true,
      tamperRejected: true, wrongPassphraseRejected: true, existingOutputPreserved:true, passphraseOutputPreserved:true, sourceOutputRefused:true, passphraseUnicodeAndSpacesPreserved:true, passphraseLineEndingsExact:true, invalidInputsRefused:true, unauthenticatedRestoreCreatesNoDestination:true, existingRestorePreserved:true, productionQualificationComplete: false };
  } catch(error) { failedPhase=phase;throw error;
  } finally {
    phase='owned-cleanup';
    try {
    if(workspace!==undefined){
    if(preserveWorkspace||!workspaceIdentity)throw new Error('Unconfirmed backup fixture retained');
    const absolute = path.resolve(workspace);
    assert.equal(path.dirname(absolute), path.resolve(os.tmpdir()));
    assert(path.basename(absolute).startsWith('accessweaver-backup-check-'));
    const current=fs.lstatSync(absolute,{bigint:true});assert(current.isDirectory()&&!current.isSymbolicLink(),'Changed backup fixture retained');
    assert(current.dev===workspaceIdentity.dev&&current.ino===workspaceIdentity.ino&&current.birthtimeNs===workspaceIdentity.birthtimeNs,'Replaced backup fixture retained');
    fs.rmSync(absolute, { recursive: true });
    }
    } catch(error) {cleanupFailed=true;throw error;}
  }
  phase='public-evidence';
  const evidenceDir=path.resolve('build','backup-checks');fs.mkdirSync(evidenceDir,{recursive:true});
  fs.writeFileSync(path.join(evidenceDir,'interop-'+process.platform+'.json'),JSON.stringify({...evidence,fixtureCleanupComplete:true},null,2)+'\n');
  console.log(JSON.stringify({...evidence,fixtureCleanupComplete:true}));
})().catch(() => { console.error('Backup interoperability fixture failed: '+(failedPhase||phase)+(cleanupFailed?'; owned cleanup unconfirmed':'')); process.exitCode = 1; });
