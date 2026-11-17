const {test}=require('@playwright/test');
const {run}=require('./public-shadow-pixels.cjs');
test('public fixed shadow raster appearance',async({launchOptions,headless,channel})=>{await run({launchOptions,headless,channel})});
