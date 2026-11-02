// Public test evidence keeps selectors and fixed diagnostic codes, never DOM,
// arbitrary axe data/messages, CSS image URLs or application text.
'use strict';
const contrastReasons=new Set([
 'bgImage','bgGradient','imgNode','bgOverlap','fgAlpha',
 'elmPartiallyObscured','elmPartiallyObscuring','outsideViewport',
 'equalRatio','shortTextContent','emptyValue','nonBmp','pseudoContent',
 'colorParse','complexTextShadows',
]);
function summarize(rules,includeReviewReasons=false){
 return rules.map(rule=>({id:rule.id,impact:rule.impact,nodes:rule.nodes.map(node=>{
  const checks=[...node.any,...node.all,...node.none];
  const result={target:node.target,checks:checks.map(check=>check.id)};
  if(includeReviewReasons){
   result.reviewReasons=checks.filter(check=>check.id==='color-contrast').map(check=>({
    check:'color-contrast',
    reason:contrastReasons.has(check.data?.messageKey)?check.data.messageKey:'unclassified',
   }));
  }
  return result;
 })}));
}
module.exports={summarize};
