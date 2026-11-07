const {test}=require('@playwright/test');
const {run}=require('./browser-startup.cjs');
test('owned full-application script costs',async({browser,launchOptions,headless,channel,contextOptions,viewport})=>{
 await run({referenceBrowser:browser,launchOptions,headless,channel,contextOptions,viewport});
});
