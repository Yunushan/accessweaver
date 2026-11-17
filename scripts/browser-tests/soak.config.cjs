require('node:assert/strict').ok(require('./browser-soak.cjs').allowed(),'Disposable hosted Linux soak required');
const base=require('./playwright.config.cjs');
const {performanceCaseName}=require('./desktop-performance.cjs');
module.exports={...base,globalTimeout:20*60_000,grep:new RegExp(performanceCaseName),reporter:[['line']],use:{...base.use,trace:'off',screenshot:'off',video:'off'},outputDir:require('node:path').resolve(__dirname,'../../build/browser-soak-private-results')};
