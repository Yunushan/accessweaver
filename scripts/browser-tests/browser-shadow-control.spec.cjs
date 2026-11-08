const {test}=require('@playwright/test');
const {run}=require('./browser-shadow-control.cjs');
test('owned box-shadow rendering control',async({browser,launchOptions,headless,channel,contextOptions,viewport})=>{
 await run({referenceBrowser:browser,launchOptions,headless,channel,contextOptions,viewport});
});
