const {test}=require('@playwright/test');
const {run}=require('./browser-control.cjs');
// Keep the same idle worker-browser dependency and launch/context defaults as
// the ordinary performance fixture; the owned measured browser stays separate.
test('owned minimal rendering control',async({browser,launchOptions,headless,channel,contextOptions,viewport})=>{
 await run({referenceBrowser:browser,launchOptions,headless,channel,contextOptions,viewport});
});
