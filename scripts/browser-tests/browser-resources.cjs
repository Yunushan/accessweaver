// Linux-only observations of a ChildProcess launched by this worker and its
// verified descendants. Process IDs and raw proc bytes never leave this module.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const {ChildProcess} = require('node:child_process');
const {parseSmaps,emptyGroup,mappedFields}=require('./browser-memory.cjs');
const MAX_PROCESSES = 64, MAX_THREADS = 512, MAX_IDENTITIES = 2048;
function live(child) {
  assert.ok(child instanceof ChildProcess && Number.isSafeInteger(child.pid) && child.pid > 0 && child.exitCode === null && child.signalCode === null && !child.killed, 'Owned live browser required');
}
function ids(raw, maximum, allowZero=false) {
  assert.ok(typeof raw === 'string' && Buffer.byteLength(raw) <= 65536, 'Owned child list budget differs');
  const values = raw.trim() ? raw.trim().split(/\s+/) : [];
  assert.ok(values.length <= maximum && values.every(n => (allowZero?/^(0|[1-9][0-9]*)$/:/^[1-9][0-9]*$/).test(n) && Number.isSafeInteger(Number(n))), 'Owned child list differs');
  assert.equal(new Set(values).size, values.length, 'Owned child list repeats an identity');
  return values.map(Number);
}
async function read(file, maximum) {
  const fd = await fs.open(file, 'r');
  try {
    const buffer = Buffer.alloc(maximum + 1); let total = 0;
    while (total < buffer.length) { const {bytesRead} = await fd.read(buffer, total, buffer.length - total, null); if (!bytesRead) break; total += bytesRead; }
    assert.ok(total <= maximum, 'Owned process input budget differs');
    return buffer.subarray(0, total).toString('utf8');
  } finally { await fd.close(); }
}
async function entries(folder, maximum) {
  const directory = await fs.opendir(folder); const values = [];
  try { for (;;) { const item = await directory.read(); if (!item) break; assert.ok(values.length < maximum, 'Owned process directory budget differs'); values.push(item.name); } }
  finally { await directory.close(); }
  return values;
}
const io = {read, entries};
function parent(raw) {
  const end = raw.lastIndexOf(') '); assert.ok(end > 0, 'Owned process shape differs');
  const fields = raw.slice(end + 2).trim().split(/\s+/); assert.ok(/^[0-9]+$/.test(fields[1]), 'Owned parent shape differs');
  const value = Number(fields[1]); assert.ok(Number.isSafeInteger(value) && value > 0, 'Owned parent differs'); return value;
}
class BrowserResources {
  constructor(child, pageBytes, parseStat, source = io) {
    live(child); this.child = child; this.pageBytes = pageBytes; this.parseStat = parseStat; this.io = source;
    this.known = new Map(); this.cpuTicks = 0; this.exits = 0; this.samples = 0; this.busy = false; this.failureStage = 0; this.phase = 0;
  }
  async counters(pid, expectedParent, previous) {
    let raw;
    try { raw = await this.io.read('/proc/' + pid + '/stat', 16384); }
    catch (error) { if (error?.code === 'ENOENT' && pid !== this.child.pid) return null; throw error; }
    const ppid = parent(raw);
    if (expectedParent !== null) assert.equal(ppid, expectedParent, 'New process is not an owned descendant');
    const stat = this.parseStat(raw, pid, ppid, this.pageBytes, true);
    if (previous) { assert.equal(stat.startTicks, previous.startTicks, 'Owned browser identity changed'); assert.ok(stat.cpuTicks >= previous.cpuTicks, 'Owned browser counters regressed'); }
    if(stat.dead){assert.notEqual(pid,this.child.pid,'Owned browser root exited');return null;}
    return stat;
  }
  async snapshot(withMemory=false) {
    assert.equal(typeof withMemory,'boolean','Owned memory selection differs');
    this.phase=1; live(this.child); assert.ok(!this.busy, 'Browser resource samples must be serialized'); this.busy = true;
    try {
      const pending = [{pid:this.child.pid, parent:process.pid}], visited = new Set();
      // Previously proven descendants remain owned if reparented after an exit.
      for (const pid of this.known.keys()) if (pid !== this.child.pid) pending.push({pid, parent:null});
      let rssBytes=0, descriptors=0, threads=0, processes=0, taskReads=0;const memory=withMemory?{root:emptyGroup(),descendants:emptyGroup()}:null;
      while (pending.length) {
        const item=pending.shift(), pid=item.pid; if (visited.has(pid)) continue; visited.add(pid);
        assert.ok(visited.size <= MAX_IDENTITIES, 'Browser identity census budget differs');
        this.phase=2; const previous=this.known.get(pid); const before=await this.counters(pid,item.parent,previous);
        if (!before) { if (previous && !previous.gone) { previous.gone=true; this.exits++; } continue; }
        assert.ok(++processes <= MAX_PROCESSES, 'Owned browser process budget differs');
        let taskNames, fdNames;
        try {
          this.phase=3; taskNames=await this.io.entries('/proc/'+pid+'/task',MAX_THREADS);
          this.phase=4; fdNames=await this.io.entries('/proc/'+pid+'/fd',4096);
        } catch(error) { if (error?.code==='ENOENT' && pid!==this.child.pid) { processes--; if(previous&&!previous.gone){previous.gone=true;this.exits++;} continue; } throw error; }
        const tids=ids(taskNames.join(' '),MAX_THREADS); ids(fdNames.join(' '),4096,true);
        const children=new Set();
        for (const tid of tids) {
          assert.ok(++taskReads<=4096,'Owned thread read budget differs');
          this.phase=5; let raw;
          try { raw=await this.io.read('/proc/'+pid+'/task/'+tid+'/children',65536); }
          catch(error) { if(error?.code==='ENOENT')continue; throw error; }
          for(const child of ids(raw,MAX_PROCESSES)) { assert.ok(child!==pid && child!==this.child.pid, 'Owned browser ancestry cycles'); children.add(child); assert.ok(children.size<=MAX_PROCESSES,'Owned descendant budget differs'); }
        }
        let mapping=null,availability='readable';
        if(withMemory){
          this.phase=8;
          try{mapping=parseSmaps(await this.io.read('/proc/'+pid+'/smaps_rollup',16384));}
          catch(error){if(['EACCES','EPERM'].includes(error?.code))availability='denied';else if(['ENOENT','ESRCH','ENOSYS'].includes(error?.code))availability='unavailable';else throw error;}
        }
        this.phase=6; const after=await this.counters(pid,item.parent,before);
        if (!after) { processes--; if(previous&&!previous.gone){previous.gone=true;this.exits++;} continue; }
        assert.ok(!previous || !previous.gone, 'Retired owned identity unexpectedly returned');
        this.phase=7; this.cpuTicks+=after.cpuTicks-(previous?previous.cpuTicks:0); assert.ok(Number.isSafeInteger(this.cpuTicks),'Owned CPU aggregate differs');
        this.known.set(pid,{startTicks:after.startTicks,cpuTicks:after.cpuTicks,gone:false}); assert.ok(this.known.size<=MAX_IDENTITIES,'Owned identity history budget differs');
        if(withMemory){const group=memory[pid===this.child.pid?'root':'descendants'];group.processes++;group.statRssBytes+=after.rssBytes;group.largestProcessRssBytes=Math.max(group.largestProcessRssBytes,after.rssBytes);group[availability]++;if(mapping)for(const k of mappedFields)group[k]+=mapping[k];}
        rssBytes+=after.rssBytes; descriptors+=fdNames.length; threads+=after.threads;
        for(const child of children) if(!visited.has(child)) pending.push({pid:child,parent:pid});
      }
      live(this.child); this.samples++;
      return {cpuTicks:this.cpuTicks,rssBytes,descriptors,threads,processes,samples:this.samples,observedExits:this.exits,...(withMemory?{memory}:{})};
    } catch(error) { this.failureStage=this.phase; throw error; } finally { this.busy=false; }
  }
}
module.exports={BrowserResources,ids,live,MAX_PROCESSES,MAX_THREADS,MAX_IDENTITIES};
