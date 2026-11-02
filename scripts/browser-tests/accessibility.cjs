// Development-only checks. Retain metadata and selectors, never raw DOM/URLs.
const {expect}=require('@playwright/test');
const AxeBuilder=require('@axe-core/playwright').default;
const tags=['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice'];
async function settleAnimations(page){
 await page.evaluate(async()=>{await Promise.all(document.getAnimations()
  .filter(animation=>animation.effect?.getComputedTiming().iterations!==Infinity)
  .map(animation=>animation.finished.catch(()=>{})))});
}
function identity(core){return {sourceCommit:core.build.commit,binarySha256:core.binarySha256,build:core.build,productionQualificationComplete:false}}
function summarize(rules){return rules.map(rule=>({id:rule.id,impact:rule.impact,nodes:rule.nodes.map(node=>({
 target:node.target,checks:[...node.any,...node.all,...node.none].map(check=>check.id),
}))}))}
async function scanAccessibility(page,core,testInfo,name){
 await settleAnimations(page);
 const result=await new AxeBuilder({page}).withTags(tags).analyze();
 const report={schemaVersion:1,...identity(core),scope:'automated-accessibility',name,project:testInfo.project.name,
  engine:result.testEngine,tags,violations:summarize(result.violations),incomplete:summarize(result.incomplete),
  passedRules:result.passes.length,inapplicableRules:result.inapplicable.length};
 await testInfo.attach('accessibility-'+name+'.json',{body:JSON.stringify(report,null,2)+'\n',contentType:'application/json'});
 expect(report.violations,name+' accessibility violations').toEqual([]);
}
function rgb(value){
 const match=/^rgba?\(([^)]+)\)$/.exec(value);
 expect(match,'supported computed RGB color: '+value).not.toBeNull();
 const values=match[1].split(/,\s*/).map(Number);
 expect(values.length===3 || values.length===4).toBe(true);
 expect(values.every(Number.isFinite)).toBe(true);
 return {rgb:values.slice(0,3),alpha:values[3]??1};
}
function contrast(first,second){
 const luminance=color=>color.map(n=>{const value=n/255;return value<=.04045?value/12.92:((value+.055)/1.055)**2.4})
  .reduce((sum,n,i)=>sum+n*[.2126,.7152,.0722][i],0);
 const values=[luminance(first),luminance(second)].sort((a,b)=>b-a);
 return (values[0]+.05)/(values[1]+.05);
}
async function assertControlContrast(page,core,testInfo,name){
 const samples=await page.evaluate(()=>{
  const visible=el=>el.getClientRects().length&&!el.closest('[inert]')&&getComputedStyle(el).visibility==='visible';
  const background=el=>{
   for(let current=el;current;current=current.parentElement){
    const color=getComputedStyle(current).backgroundColor;
    if(color.replace(/\s/g,'')!=='rgba(0,0,0,0)'&&color!=='transparent')return color;
   }
   return getComputedStyle(document.documentElement).backgroundColor;
  };
  const result=[];
  for(const el of document.querySelectorAll('button.btn-primary:not(:disabled),.skip-link')){
   if(!visible(el))continue;
   const style=getComputedStyle(el);
   const stops=style.backgroundImage==='none'?[background(el)]:style.backgroundImage.match(/rgba?\([^)]+\)/g);
   result.push({kind:'action-text',target:el.id?'#'+el.id:'.skip-link',foreground:style.color,backgrounds:stops});
  }
  for(const el of document.querySelectorAll('input:not([type="checkbox"]):not(:disabled),textarea:not(:disabled),select:not(:disabled),.search-wrap')){
   if(!visible(el))continue;
   const style=getComputedStyle(el);
   if(parseFloat(style.borderTopWidth)===0||style.borderTopStyle==='none')continue;
   result.push({kind:'control-border',target:el.id?'#'+el.id:'.search-wrap',foreground:style.borderTopColor,backgrounds:[background(el),background(el.parentElement)]});
  }
  return result;
 });
 const checks=samples.map(sample=>{
  expect(sample.backgrounds?.length,'known solid colors/gradient stops').toBeGreaterThan(0);
  const foreground=rgb(sample.foreground);expect(foreground.alpha).toBe(1);
  const ratios=sample.backgrounds.map(value=>{const background=rgb(value);expect(background.alpha).toBe(1);return contrast(foreground.rgb,background.rgb)});
  return {...sample,minimumRatio:Math.min(...ratios),requiredRatio:sample.kind==='action-text'?4.5:3};
 });
 await testInfo.attach('control-contrast-'+name+'.json',{body:JSON.stringify({schemaVersion:1,...identity(core),scope:'explicit-control-contrast',name,checks},null,2)+'\n',contentType:'application/json'});
 for(const check of checks)expect(check.minimumRatio,check.target+' '+check.kind).toBeGreaterThanOrEqual(check.requiredRatio);
 return checks.length;
}
module.exports={settleAnimations,scanAccessibility,assertControlContrast};
