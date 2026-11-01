'use strict';
const systemUI={plan:null,presets:[],polling:false,busy:false,revision:0,loading:false,folderJob:null};
function notifySystemUpdate(job){if(job?.action==='updates'&&job.state==='succeeded'&&job.result?.data?.updateAvailable&&systemUI.lastUpdate!==job.id){systemUI.lastUpdate=job.id;toast(t('updateAvailable')+': '+job.result.data.version)}}
function systemRequest(){
  const action=$('system-action').value,engine=$('system-engine').value,fields=systemFieldsFor(action,engine),request={action};
  const names={mode:'mode',profile:'profileId',config:'configPath',bundle:'bundlePath',applications:'applications',browsers:'browsers',refresh:'refresh',dns:'dns',scan:'scan',targets:'targets',journal:'journalId',domains:'domains',enabled:'enabled',clean:'clean',args:'args',url:'downloadUrl',sha:'sha256','cloudflare-terms':'acceptCloudflareTerms'};
  if(fields['system-engine'])request.engine=engine;
  for(const [id,key]of Object.entries(names)){
    if(!fields['system-'+id])continue;
    const node=$('system-'+id);
    request[key]=['browsers','refresh','enabled','clean','cloudflare-terms'].includes(id)?node.checked:['applications','targets','domains'].includes(id)?splitLines(node.value):id==='args'?(node.value?node.value.replace(/\r\n/g,'\n').split('\n'):[]):node.value.trim();
  }
  if(action==='app-repair')request.engine='discord';
  return request;
}
function systemEnginesFor(action){
  if(action==='vendor-uninstall')return ['wiresock'];
  if(action.startsWith('app-'))return ['discord','discord-ptb','splitcord'];
  if(action==='scan'||action==='auto-install')return ['zapret','zapret2'];
  if(action==='hostlist')return ['zapret','zapret2','goodbyedpi'];
  if(action==='install')return ['wiresock','byedpi','zapret','zapret2','goodbyedpi','dnscrypt','ndisapi','vcredist'];
  if(action==='remove')return ['wiresock','byedpi','zapret','zapret2','goodbyedpi','dnscrypt','proxifyre','drover','windivert'];
  return ['wiresock','byedpi','zapret','zapret2','goodbyedpi','dnscrypt','proxifyre','drover','wgcf','ndisapi','vcredist'];
}
function invalidateSystemPlan(){systemUI.revision++;systemUI.plan=null;$('system-consent').checked=false;$('system-consent').disabled=true;$('system-apply').disabled=true;$('system-export').disabled=true;$('system-plan').textContent='';}
async function loadSystemTools(){
  if(systemUI.loading)return;
  if(!coreAvailable())throw new Error(t('coreRequired'));
  systemUI.loading=true;
  try{
  const [info,presets]=await Promise.all([apiRequest('/api/v1/system'),apiRequest('/api/v1/system/presets')]);
  systemUI.presets=presets;
  const selected=$('system-action').value;
  $('system-action').replaceChildren(...info.operations.filter(op=>op.id!=='choose-folder').map(op=>{const option=document.createElement('option');option.value=op.id;option.dataset.fallback=op.label;option.textContent=systemOperationText[op.id]?.[state.lang]||op.label;return option}));
  if(selected)$('system-action').value=selected;
  renderSystemPresets();refreshSystemFields();if(!info.job?.id)$('system-output').textContent='';renderSystemJob(info.job);
  if(info.job?.state==='running')pollSystemJob();
  }finally{systemUI.loading=false}
}
function systemFieldsFor(action,engine){
  const install=action==='install',scan=action==='scan'||action==='auto-install',packet=['zapret','zapret2','goodbyedpi'].includes(engine),tunnel=engine==='wiresock',apps=(install&&['wiresock','byedpi'].includes(engine))||action==='config';
  return {'system-engine':!['discover','updates','remove-all','uninstall','dns','dns-restore','config','connect','disconnect','refresh','recover','app-repair'].includes(action),'system-mode':install&&['wiresock','byedpi','zapret','zapret2','goodbyedpi'].includes(engine),'system-preset':install&&packet,'system-args':install&&['byedpi','zapret','zapret2','goodbyedpi'].includes(engine),'system-applications':apps,'system-browsers':apps,'system-cloudflare-terms':action==='config'||install&&tunnel,'system-refresh':install&&tunnel,'system-dns':action==='dns'||install&&engine!=='dnscrypt'||scan,'system-scan':scan,'system-targets':scan,'system-domains':action==='hostlist'||(install||action==='auto-install')&&packet,'system-enabled':action==='hostlist'||action==='refresh'||(install||action==='auto-install')&&packet,'system-clean':action==='app-install'&&engine==='discord-ptb','system-bundle':install||scan||action==='config','system-config':action==='config'||action==='connect'||install&&tunnel,'system-profile':action==='config'||action==='connect'||install&&tunnel,'system-url':action==='download','system-sha':action==='download','system-journal':action==='recover'};
}
function refreshSystemFields(){
  const action=$('system-action').value,engines=systemEnginesFor(action);
  for(const option of $('system-engine').options){option.hidden=!engines.includes(option.value);option.disabled=option.hidden}
  if(!engines.includes($('system-engine').value))$('system-engine').value=engines[0];
  const engine=$('system-engine').value;
  for(const [id,show]of Object.entries(systemFieldsFor(action,engine))){const label=$(id).closest('label');if(label)label.hidden=!show}
  $('system-folder-actions').hidden=!systemFieldsFor(action,engine)['system-applications'];
  const modes=engine==='wiresock'?['alternative','standard','custom']:engine==='byedpi'?['split','dll','service','once']:['service','once'];
  for(const option of $('system-mode').options){option.hidden=!modes.includes(option.value);option.disabled=option.hidden}
  if(!modes.includes($('system-mode').value))$('system-mode').value=modes[0];
  const paths=$('system-bundle').closest('details'),fields=systemFieldsFor(action,engine);
  if(paths)paths.hidden=!['bundle','config','profile','url','sha','journal'].some(id=>fields['system-'+id]);
  renderSystemPresets();
}
function refreshSystemLanguage(){for(const option of $('system-action').options){option.textContent=systemOperationText[option.value]?.[state.lang]||option.dataset.fallback}renderSystemPresets();refreshSystemFields()}
function renderSystemPresets(){const previous=$('system-preset').value;$('system-preset').replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent=t('customArguments');$('system-preset').appendChild(empty);systemUI.presets.forEach((p,i)=>{if(p.engine!==$('system-engine').value)return;const option=document.createElement('option');option.value=String(i);option.textContent=p.name;$('system-preset').appendChild(option)});$('system-preset').value=previous;}
async function previewSystem(request=systemRequest()){
  if(systemUI.busy)return;
  invalidateSystemPlan();systemUI.busy=true;const revision=systemUI.revision;
  try {if(!coreAvailable())throw new Error(t('coreRequired'));const plan=await apiRequest('/api/v1/system/preview','POST',request);if(revision!==systemUI.revision)return;systemUI.plan=plan;$('system-plan').textContent=JSON.stringify({operation:plan.request,requiresAdministrator:plan.requiresAdministrator,steps:plan.steps,issues:plan.issues,warnings:plan.warnings,expiresAt:plan.expiresAt},null,2);$('system-consent').disabled=!plan.ready;$('system-export').disabled=false;}
  catch(error){$('system-plan').textContent=error.message;toast(error.message,true)}finally{systemUI.busy=false}
}
function exportSystemRequest(){
  if(!systemUI.plan?.request)return;
  const request=systemUI.plan.request;
  downloadFile(JSON.stringify(request,null,2)+'\n','accessweaver-'+request.action+'-request.json');
}
async function applySystem(){
  if(systemUI.busy||!systemUI.plan?.ready||!$('system-consent').checked)return;
  systemUI.busy=true;const id=systemUI.plan.id;invalidateSystemPlan();
  try {const job=await apiRequest('/api/v1/system/start','POST',{planId:id,confirm:true});renderSystemJob(job);pollSystemJob();}
  catch(error){$('system-output').textContent=error.message;toast(error.message,true)}finally{systemUI.busy=false}
}
function renderSystemJob(job){if(!job?.id)return;notifySystemUpdate(job);$('system-output').textContent=JSON.stringify(job,null,2);$('system-cancel').disabled=job.state!=='running';if(job.id===systemUI.folderJob&&job.state!=='running'){systemUI.folderJob=null;const folder=job.result?.data?.folder;if(folder){const paths=splitLines($('system-applications').value);if(!paths.includes(folder))paths.push(folder);$('system-applications').value=paths.join('\n');invalidateSystemPlan()}}if(job.result?.journal)$('system-journal').value=job.result.journal.split(/[\\/]/).pop();}
async function pollSystemJob(){if(systemUI.polling)return;systemUI.polling=true;try{for(;;){const info=await apiRequest('/api/v1/system');renderSystemJob(info.job);if(info.job.state!=='running')break;await new Promise(resolve=>setTimeout(resolve,1500));}}catch(error){$('system-output').textContent=error.message;}finally{systemUI.polling=false}}

const systemNavigation=document.createElement('button');systemNavigation.type='button';systemNavigation.className='nav-item';systemNavigation.dataset.view='system';systemNavigation.dataset.i18n='systemTools';systemNavigation.textContent=t('systemTools');systemNavigation.addEventListener('click',()=>navigate('system',true));document.querySelector('.main-nav').appendChild(systemNavigation);
$('system-form').addEventListener('submit',event=>{event.preventDefault();previewSystem()});
$('system-form').addEventListener('input',invalidateSystemPlan);$('system-form').addEventListener('change',invalidateSystemPlan);
$('system-engine').addEventListener('change',()=>{renderSystemPresets();refreshSystemFields()});
$('system-action').addEventListener('change',()=>{refreshSystemFields()});
$('system-folder').addEventListener('click',async()=>{try{const job=await apiRequest('/api/v1/system/folder','POST',{});systemUI.folderJob=job.id;renderSystemJob(job);pollSystemJob()}catch(e){toast(e.message,true)}});
$('system-clear-apps').addEventListener('click',()=>{$('system-applications').value='';invalidateSystemPlan()});
$('system-preset').addEventListener('change',()=>{const p=systemUI.presets[Number($('system-preset').value)];if($('system-preset').value!==''&&p){$('system-args').value=p.args.join('\n');invalidateSystemPlan()}});
$('system-consent').addEventListener('change',()=>{$('system-apply').disabled=!systemUI.plan?.ready||!$('system-consent').checked});
$('system-apply').addEventListener('click',applySystem);
$('system-export').addEventListener('click',exportSystemRequest);
$('system-inspect').addEventListener('click',()=>previewSystem({action:'discover'}));
$('system-cancel').addEventListener('click',async()=>{try{renderSystemJob(await apiRequest('/api/v1/system/cancel','POST',{}))}catch(e){toast(e.message,true)}});
$('system-history').addEventListener('click',async()=>{try{$('system-output').textContent=JSON.stringify(await apiRequest('/api/v1/system/history'),null,2)}catch(e){toast(e.message,true)}});
if(state.view==='system')loadSystemTools().catch(e=>{$('system-output').textContent=e.message});
updateTranslations();
