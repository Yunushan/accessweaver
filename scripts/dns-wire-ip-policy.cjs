'use strict';
// Explicit evidence binding, not a credential or an authentication token. The
// hosted collector must independently verify current DNS policy before use.
const crypto=require('node:crypto');
const ENTRIES=Object.freeze([["8.8.8.8", "https://8.8.8.8/dns-query"], ["9.9.9.9", "https://9.9.9.9/dns-query"], ["2001:4860:4860::8888", "https://[2001:4860:4860::8888]/dns-query"], ["2620:fe::fe", "https://[2620:fe::fe]/dns-query"]].map(([address,template])=>Object.freeze({address,template,fallback:false,upgrade:true})));
const POLICY_SHA256=crypto.createHash('sha256').update(ENTRIES.map(e=>e.address+'|'+e.template+'|0|1\n').join(''),'utf8').digest('hex');
const PREREQUISITE_SHA256="f283959a6b8267a5a576e2d0b1725728d9647276db8421242c3f3b54716c703c";
const PREREQUISITE_RECEIPT="docs/qualification/3e2314a8de82-ip-authority-http2.json";
const BINDING_KEYS=Object.freeze(['schemaVersion','mode','sourceCommit','policySHA256','prerequisiteSHA256','providerMask','readbackVerified']);
function assertIPBinding(value,sourceCommit){
 if(value===null||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==BINDING_KEYS.length||!BINDING_KEYS.every(k=>Object.hasOwn(value,k))||value.schemaVersion!==1||value.mode!=='configured-ip-authority'||typeof value.sourceCommit!=='string'||!/^[a-f0-9]{40}$/.test(value.sourceCommit)||(sourceCommit!==undefined&&sourceCommit!==value.sourceCommit)||value.policySHA256!==POLICY_SHA256||value.prerequisiteSHA256!==PREREQUISITE_SHA256||value.providerMask!==15||value.readbackVerified!==true)throw new Error('identity-binding');
 return value;
}
function declaredIPBinding(sourceCommit){
 const value={schemaVersion:1,mode:'configured-ip-authority',sourceCommit,policySHA256:POLICY_SHA256,prerequisiteSHA256:PREREQUISITE_SHA256,providerMask:15,readbackVerified:true};assertIPBinding(value);return Object.freeze(value);
}
module.exports={ENTRIES,POLICY_SHA256,PREREQUISITE_SHA256,PREREQUISITE_RECEIPT,BINDING_KEYS,assertIPBinding,declaredIPBinding};
