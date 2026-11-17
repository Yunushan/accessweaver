require('node:assert/strict').ok(require('./browser-startup.cjs').allowed(),'Disposable hosted Linux startup diagnostic required');
const base=require('./playwright.config.cjs');
module.exports={...base,testMatch:'browser-startup.spec.cjs',timeout:120_000,globalTimeout:180_000,reporter:[['line']],use:{...base.use,trace:'off',screenshot:'off',video:'off'},outputDir:require('node:path').resolve(__dirname,'../../build/browser-startup-private-results')};
