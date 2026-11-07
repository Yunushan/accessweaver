// Architecture checks for the pinned image's public browser launchers only.
// Read at most one ELF header; never execute a probe or inspect process arguments.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
function validateNativeInvocation(environment){for(const name of ['PW_BROWSER_CHANNEL','PW_TEST_CONNECT_WS_ENDPOINT','ACCESSWEAVER_BINARY'])assert.ok(!environment[name],'Native image acceptance target override is not allowed: '+name)}
function validateELF64(header,architecture){
 assert.ok(['amd64','arm64'].includes(architecture),'expected native browser architecture differs');
 assert.ok(Buffer.isBuffer(header)&&header.length>=64,'native browser ELF header is incomplete');
 assert.ok(header[0]===0x7f&&header[1]===0x45&&header[2]===0x4c&&header[3]===0x46,'native browser executable is not ELF');
 assert.ok(header[4]===2&&header[5]===1&&header[6]===1,'native browser requires little-endian ELF64');
 assert.ok([2,3].includes(header.readUInt16LE(16))&&header.readUInt32LE(20)===1&&header.readUInt16LE(52)===64,'native browser ELF executable format differs');
 assert.equal(header.readUInt16LE(18),architecture==='amd64'?62:183,'native browser ELF instruction set differs');
 return architecture;
}
function insideCache(cache,file){
 const root=fs.realpathSync(cache),resolved=fs.realpathSync(file),relative=path.relative(root,resolved);
 assert.ok(relative&&relative!=='..'&&!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative),'native browser must remain inside the pinned cache');
 const info=fs.statSync(resolved);assert.ok(info.isFile()&&info.size>0,'native browser must be a regular file');fs.accessSync(resolved,fs.constants.X_OK);return resolved;
}
function verifyELFFile(cache,file,architecture,role,observe=()=>{}){
 observe({role,format:"unread",machine:"unknown"});
 const resolved=insideCache(cache,file),fd=fs.openSync(resolved,'r');
 try{
  const before=fs.fstatSync(fd);assert.ok(before.isFile()&&before.size>=64,'native browser executable is incomplete');
  const header=Buffer.alloc(64);let offset=0;while(offset<64){const read=fs.readSync(fd,header,offset,64-offset,offset);assert.ok(read>0,'native browser header ended early');offset+=read}
  const format=header[0]===0x7f&&header[1]===0x45&&header[2]===0x4c&&header[3]===0x46?"elf":header[0]===35&&header[1]===33?"script":"other";
  observe({role,format,machine:format==="elf"?(header.readUInt16LE(18)===62?"amd64":header.readUInt16LE(18)===183?"arm64":"other"):"unknown"});
  validateELF64(header,architecture);const after=fs.fstatSync(fd);assert.ok(before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs,'native browser changed during architecture inspection');
 }finally{fs.closeSync(fd)}
}
function verifyBrowserCache(cache,executables,architecture,observe=()=>{}){
 assert.deepEqual(Object.keys(executables).sort(),['chromium','firefox','webkit'],'native browser launcher set differs');
 const checked=[];
 for(const name of ['chromium','firefox']){verifyELFFile(cache,executables[name],architecture,name,observe);checked.push(name)}
 const webkit=insideCache(cache,executables.webkit),webkitRoot=path.dirname(webkit);
 // The pinned upstream pw_run.sh selects minibrowser-gtk by default. Inspect
 // WPE too when packaged; never select a different executable as a fallback.
 verifyELFFile(cache,path.join(webkitRoot,'minibrowser-gtk','MiniBrowser'),architecture,'webkit-gtk',observe);checked.push('webkit-gtk');
 const wpe=path.join(webkitRoot,'minibrowser-wpe','MiniBrowser');if(fs.existsSync(wpe)){verifyELFFile(cache,wpe,architecture,'webkit-wpe',observe);checked.push('webkit-wpe')}
 const entries=fs.readdirSync(cache);assert.ok(entries.length<=64,'native browser cache entry budget differs');
 const shells=entries.filter(name=>/^chromium_headless_shell-[0-9]+$/.test(name));assert.ok(shells.length>=1&&shells.length<=4,'native Chromium headless shell is missing or ambiguous');
 for(const folder of shells){verifyELFFile(cache,path.join(cache,folder,architecture==='amd64'?'chrome-headless-shell-linux64':'chrome-headless-shell-linux-arm64','chrome-headless-shell'),architecture,'chromium-headless-shell',observe);checked.push('chromium-headless-shell')}
 return checked;
}
module.exports={validateNativeInvocation,validateELF64,verifyELFFile,verifyBrowserCache};
