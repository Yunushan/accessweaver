require('node:assert/strict').ok(require('./public-shadow-pixels.cjs').allowed(),'Disposable hosted public pixel fixture required');
const base=require('./playwright.config.cjs');
module.exports={...base,testMatch:'public-shadow-pixels.spec.cjs',timeout:150_000,globalTimeout:210_000,reporter:[['line']],use:{...base.use,trace:'off',screenshot:'off',video:'off'},outputDir:require('node:path').resolve(__dirname,'../../build/public-shadow-pixels-private-results')};
