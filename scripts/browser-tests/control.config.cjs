require('node:assert/strict').ok(require('./browser-control.cjs').allowed(),'Disposable hosted Linux control required');
const base=require('./playwright.config.cjs');
module.exports={...base,testMatch:'browser-control.spec.cjs',timeout:20*60_000,globalTimeout:22*60_000,reporter:[['line']],use:{...base.use,trace:'off',screenshot:'off',video:'off'},outputDir:require('node:path').resolve(__dirname,'../../build/browser-control-private-results')};
