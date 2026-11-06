// Fixed source-known case IDs, statuses and public source locations only.
// Never read error messages/snippets/stacks, attachments, steps or output streams.
const fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto');
const manifest=require('./suite-contracts.json');
const cases=manifest.cases;
const sources=['scripts/browser-tests/desktop-performance.cjs','scripts/browser-tests/performance-budgets.json','web/app.js','web/index.html','web/app.css','scripts/browser-tests/desktop.spec.cjs','scripts/browser-tests/modal-keyboard.cjs','scripts/browser-tests/accessibility.cjs','scripts/browser-tests/playwright.config.cjs','scripts/browser-tests/package-lock.json','scripts/browser-tests/suite-contracts.json','scripts/browser-tests/suite-status-reporter.cjs','.github/workflows/browser.yml'];
const a11yRules=['landmark-unique','color-contrast','scrollable-region-focusable','region','heading-order','nested-interactive','aria-hidden-focus','aria-allowed-attr','aria-valid-attr-value','aria-required-attr','aria-required-children','label','button-name','link-name','duplicate-id-aria','other'];
const statuses=['passed','failed','timedOut','skipped','interrupted','not-run','unknown'];
const sourceRoles=['none','desktop','accessibility','keyboard','suite','other'];
function sourceLocation(error){
 const location=error?.location;if(!location||typeof location.file!=='string'||location.file.length>4096)return {sourceRole:'none',sourceLine:0,sourceColumn:0};
 const roles={'desktop.spec.cjs':'desktop','accessibility.cjs':'accessibility','modal-keyboard.cjs':'keyboard','suite-status-reporter.cjs':'suite'},name=path.basename(location.file);
 const role=Object.hasOwn(roles,name)?roles[name]:'other';if(role==='other'||!Number.isInteger(location.line)||location.line<1||location.line>10000||!Number.isInteger(location.column)||location.column<1||location.column>1000)return {sourceRole:'other',sourceLine:0,sourceColumn:0};
 return {sourceRole:role,sourceLine:location.line,sourceColumn:location.column};
}
const finals=['passed','failed','timedout','interrupted','unknown'];
class SuiteStatusReporter{
 constructor(){this.records=cases.map(c=>({id:c.id,status:'not-run',attempts:0,retry:null,sourceRole:'none',sourceLine:0,sourceColumn:0,a11yRules:[]}));this.registered=0;this.unrecognized=0;this.overflow=false}
 printsToStdio(){return false}
 onBegin(_config,suite){const count=suite.allTests().length;this.registered=Number.isInteger(count)&&count>=0?Math.min(count,1000):0;this.overflow=count>1000}
 onTestEnd(test,result){
  const index=cases.findIndex(c=>c.name===test.title);
  if(index<0){this.unrecognized=Math.min(this.unrecognized+1,1000);return}
  const record=this.records[index];if(record.attempts>=16){this.overflow=true;return}record.attempts++;
  record.status=statuses.includes(result.status)&&!['not-run','unknown'].includes(result.status)?result.status:'unknown';
  record.retry=Number.isInteger(result.retry)&&result.retry>=0&&result.retry<=16?result.retry:null;
  Object.assign(record,record.status==='passed'?{sourceRole:'none',sourceLine:0,sourceColumn:0}:sourceLocation(result.error));
  record.a11yRules=Array.isArray(test.annotations)?[...new Set(test.annotations.filter(a=>a?.type==='aw-a11y-rule'&&a11yRules.includes(a.description)).map(a=>a.description))].sort():[];
 }
 value(finalStatus){
  const final=finals.includes(finalStatus)?finalStatus:'unknown';
  const passed=final==='passed'&&this.registered===cases.length&&this.unrecognized===0&&!this.overflow&&this.records.every(c=>c.status==='passed'&&c.attempts===1&&c.retry===0);
  return {registered:this.registered,unrecognized:this.unrecognized,overflow:this.overflow,finalStatus:final,outcome:passed?'passed':'failed',cases:this.records.map(c=>({...c,a11yRules:[...c.a11yRules]}))};
 }
 async onEnd(result){
  if(process.env.GITHUB_ACTIONS!=='true')return;
  const value=this.value(result.status);
  try{await writeReport(path.resolve(__dirname,'../..'),process.env.BROWSER,process.env.GITHUB_SHA,value)}catch{return {status:'failed'}}
  if(value.outcome!=='passed')return {status:'failed'};
 }
}
async function boundedHash(file,maximum){
 const handle=await fs.open(file,'r');try{const initial=await handle.stat();if(!initial.isFile()||initial.size<1||initial.size>maximum)throw new Error('Browser evidence input budget differs');const hash=createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;for(;;){const {bytesRead}=await handle.read(buffer,0,Math.min(buffer.length,maximum-total+1),null);if(!bytesRead)break;total+=bytesRead;if(total>maximum)throw new Error('Browser evidence input grew');hash.update(buffer.subarray(0,bytesRead))}const final=await handle.stat();if(total!==initial.size||initial.dev!==final.dev||initial.ino!==final.ino||initial.size!==final.size)throw new Error('Browser evidence input changed');return hash.digest('hex')}finally{await handle.close()}
}
async function writeReport(repo,project,source,value){
 if(!['chromium','firefox','webkit'].includes(project)||!/^[0-9a-f]{40}$/.test(source))throw new Error('Browser evidence identity differs');
 if(Object.keys(value).sort().join(',')!==['registered','unrecognized','overflow','finalStatus','outcome','cases'].sort().join(',')||!Number.isInteger(value.registered)||value.registered<0||value.registered>1000||!Number.isInteger(value.unrecognized)||value.unrecognized<0||value.unrecognized>1000||typeof value.overflow!=='boolean'||!finals.includes(value.finalStatus)||!['passed','failed'].includes(value.outcome)||!Array.isArray(value.cases)||value.cases.length!==cases.length)throw new Error('Browser evidence schema differs');
 for(let i=0;i<value.cases.length;i++){const c=value.cases[i];if(Object.keys(c).sort().join(',')!==['id','status','attempts','retry','sourceRole','sourceLine','sourceColumn','a11yRules'].sort().join(',')||c.id!==cases[i].id||!statuses.includes(c.status)||!Number.isInteger(c.attempts)||c.attempts<0||c.attempts>16||!(c.retry===null||Number.isInteger(c.retry)&&c.retry>=0&&c.retry<=16)||!sourceRoles.includes(c.sourceRole)||!Number.isInteger(c.sourceLine)||c.sourceLine<0||c.sourceLine>10000||!Number.isInteger(c.sourceColumn)||c.sourceColumn<0||c.sourceColumn>1000||(['none','other'].includes(c.sourceRole)&&(c.sourceLine!==0||c.sourceColumn!==0))||!Array.isArray(c.a11yRules)||c.a11yRules.length>a11yRules.length||new Set(c.a11yRules).size!==c.a11yRules.length||c.a11yRules.some(code=>!a11yRules.includes(code)))throw new Error('Browser case evidence differs')}
 const snapshot={registered:value.registered,unrecognized:value.unrecognized,overflow:value.overflow,finalStatus:value.finalStatus,outcome:value.outcome,cases:value.cases.map(c=>({...c,a11yRules:[...c.a11yRules]}))};
 const passed=snapshot.finalStatus==='passed'&&snapshot.registered===cases.length&&snapshot.unrecognized===0&&!snapshot.overflow&&snapshot.cases.every(c=>c.status==='passed'&&c.attempts===1&&c.retry===0);
 if((snapshot.outcome==='passed')!==passed)throw new Error('Browser evidence outcome differs');
 const sourceSHA256={};for(const name of sources)sourceSHA256[name]=await boundedHash(path.join(repo,name),1<<20);
 const binarySHA256=await boundedHash(path.join(repo,'build/browser-tests/accessweaver'),128<<20);
 const data={schemaVersion:2,sourceCommit:source,sourceSHA256,binarySHA256,project,...snapshot,productionQualificationComplete:false};
 const encoded=JSON.stringify(data)+'\n';if(Buffer.byteLength(encoded)>32768)throw new Error('Browser status report budget exceeded');
 const parent=path.join(repo,'build/browser-contract-evidence');await fs.mkdir(parent,{recursive:true,mode:0o700});const info=await fs.lstat(parent),resolved=await fs.realpath(parent),build=await fs.realpath(path.join(repo,'build'));
 if(!info.isDirectory()||info.isSymbolicLink()||path.dirname(resolved)!==build)throw new Error('Browser status parent differs');
 const file=await fs.open(path.join(resolved,'status.json'),'wx',0o600);try{await file.writeFile(encoded,'utf8')}finally{await file.close()}
}
module.exports=SuiteStatusReporter;module.exports.sources=sources;module.exports.statuses=statuses;module.exports.finals=finals;module.exports.writeReport=writeReport;module.exports.sourceRoles=sourceRoles;module.exports.sourceLocation=sourceLocation;module.exports.a11yRules=a11yRules;
