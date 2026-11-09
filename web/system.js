'use strict';
const systemUI={plan:null,presets:[],polling:false,busy:false,revision:0,loading:false,folderJob:null,exporting:false};
function notifySystemUpdate(job){
 const data=job?.result?.data;
 if(job?.action==='updates'&&job.state==='succeeded'&&data?.updateAvailable===true&&typeof data.version==='string'&&data.version.trim()&&systemUI.lastUpdate!==job.id){
  systemUI.lastUpdate=job.id;toast(t('updateAvailable')+': '+data.version);
 }
}
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
function invalidateSystemPlan(){systemUI.revision++;systemUI.plan=null;$('system-consent').checked=false;$('system-consent').disabled=true;$('system-apply').disabled=true;$('system-export').disabled=true;setTextOutput('system-plan','');}
// Retry only this read-only report when the server explicitly signals busy.
// Confirmed starts, cancellation and other mutations are never replayed.
async function readSystemStatus(){
 for(;;){try{return await apiRequest('/api/v1/system');}
  catch(error){if(error.status!==503)throw error;await new Promise(resolve=>setTimeout(resolve,1000));}
 }
}
async function loadSystemTools(){
  if(systemUI.loading)return;
  if(!coreAvailable())throw new Error(t('coreRequired'));
  systemUI.loading=true;
  try{
  const [info,presets]=await Promise.all([readSystemStatus(),apiRequest('/api/v1/system/presets')]);
  systemUI.presets=presets;
  const selected=$('system-action').value;
  $('system-action').replaceChildren(...info.operations.filter(op=>op.id!=='choose-folder').map(op=>{const option=document.createElement('option');option.value=op.id;option.dataset.fallback=op.label;option.textContent=systemOperationText[op.id]?.[state.lang]||op.label;return option}));
  if(selected)$('system-action').value=selected;
  renderSystemPresets();refreshSystemFields();if(!info.job?.id)setTextOutput('system-output','');renderSystemJob(info.job);
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
  $('system-doh-notice').hidden=!systemFieldsFor(action,engine)['system-dns']||$('system-dns').value!=='doh';
  $('system-folder-actions').hidden=!systemFieldsFor(action,engine)['system-applications'];
  const modes=engine==='wiresock'?['alternative','standard','custom']:engine==='byedpi'?['split','dll','service','once']:['service','once'];
  for(const option of $('system-mode').options){option.hidden=!modes.includes(option.value);option.disabled=option.hidden}
  if(!modes.includes($('system-mode').value))$('system-mode').value=modes[0];
  const paths=$('system-bundle').closest('details'),fields=systemFieldsFor(action,engine);
  if(paths)paths.hidden=!['bundle','config','profile','url','sha','journal'].some(id=>fields['system-'+id]);
  renderSystemPresets();
}
function refreshSystemLanguage(){for(const option of $('system-action').options){option.textContent=systemOperationText[option.value]?.[state.lang]||option.dataset.fallback}renderSystemPresets();refreshSystemFields();if(typeof refreshHistoryLanguage==='function')refreshHistoryLanguage()}
function renderSystemPresets(){const previous=$('system-preset').value;$('system-preset').replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent=t('customArguments');$('system-preset').appendChild(empty);systemUI.presets.forEach((p,i)=>{if(p.engine!==$('system-engine').value)return;const option=document.createElement('option');option.value=String(i);option.textContent=p.name;$('system-preset').appendChild(option)});$('system-preset').value=previous;}
async function previewSystem(request=systemRequest()){
  if(systemUI.busy)return;
  invalidateSystemPlan();systemUI.busy=true;const revision=systemUI.revision,reviewContext=historyContext();
  try {if(!coreAvailable())throw new Error(t('coreRequired'));const plan=await apiRequest('/api/v1/system/preview','POST',request);if(revision!==systemUI.revision)return;systemUI.plan=plan;if(reviewContext===historyContext()&&state.view==='system')clearControllerStorageRefusal();setTextOutput('system-plan',JSON.stringify({operation:plan.request,requiresAdministrator:plan.requiresAdministrator,steps:plan.steps,issues:plan.issues,warnings:plan.warnings,expiresAt:plan.expiresAt},null,2));$('system-consent').disabled=!plan.ready;$('system-export').disabled=false;}
  catch(error){setTextOutput('system-plan',error.message);toast(error.message,true)}finally{systemUI.busy=false}
}
function exportSystemRequest(){
  if(!systemUI.plan?.request)return;
  const request=systemUI.plan.request;
  downloadFile(JSON.stringify(request,null,2)+'\n','accessweaver-'+request.action+'-request.json');
}
async function applySystem(){
  if(systemUI.busy||workflowLifecycleBlocked()||!systemUI.plan?.ready||!$('system-consent').checked)return;
  systemUI.busy=true;const id=systemUI.plan.id,context=historyContext();invalidateSystemPlan();
  try {const job=await apiRequest('/api/v1/system/start','POST',{planId:id,confirm:true});renderSystemJob(job);pollSystemJob();}
  catch(error){if(context!==historyContext()||state.view!=='system')return;if(!handleWorkflowLifecycleAdmission(error)&&!handleControllerStorageAdmission(error)){setTextOutput('system-output',error.message);toast(error.message,true)}}finally{systemUI.busy=false}
}
function renderSystemJob(job){
 if(!job?.id)return;
 notifySystemUpdate(job);showSystemOutput(job);$('system-cancel').disabled=job.state!=='running';
 // Optional worker metadata may have any JSON shape. Keep the raw report, but
 // only use typed fields to change the request being reviewed.
 if(job.id===systemUI.folderJob&&job.state!=='running'){
  systemUI.folderJob=null;
  const folder=job.result?.data?.folder;
  if(job.action==='choose-folder'&&job.state==='succeeded'&&typeof folder==='string'&&folder.trim()){
   const paths=splitLines($('system-applications').value);
   if(!paths.includes(folder)){paths.push(folder);$('system-applications').value=paths.join('\n');invalidateSystemPlan();}
  }
 }
 const journal=job.result?.journal;
 if(typeof journal==='string'&&journal){
  const name=journal.split(/[\\/]/).pop();
  if(name.trim()&&name!==$('system-journal').value){
   $('system-journal').value=name;
   if($('system-action').value==='recover')invalidateSystemPlan();
  }
 }
}
async function pollSystemJob(){if(systemUI.polling)return;systemUI.polling=true;try{for(;;){const info=await readSystemStatus();renderSystemJob(info.job);if(info.job.state!=='running')break;await new Promise(resolve=>setTimeout(resolve,1500));}}catch(error){setTextOutput('system-output',error.message);}finally{systemUI.polling=false}}

function updateSystemExportButtons(){
  for(const id of ['system-export-status','system-export-history'])$(id).disabled=!supportAvailable()||systemUI.exporting;
  if(typeof updateHistoryAvailability==='function')updateHistoryAvailability();
}
// Preserve response bytes without parsing/stringifying an unbounded JSON tree.
// The ceiling covers the existing 64 MiB history read cap even after escaping.
async function readSystemDownload(response,maxBytes=512*1024*1024){
  const reader=response.body.getReader(),chunks=[];let size=0,complete=false;
  try{
    for(;;){const {done,value}=await reader.read();if(done){complete=true;break;}
      size+=value.byteLength;if(size>maxBytes)throw Object.assign(new Error(t('systemExportTooLarge')),{reportTooLarge:true});chunks.push(value);
    }
    return new Blob(chunks,{type:'application/json'});
  }finally{if(!complete)await reader.cancel().catch(()=>{});reader.releaseLock();}
}
async function exportSystemReport(kind){
  const options={status:{path:'/api/v1/system',name:'accessweaver-system-status.json'},history:{path:'/api/v1/system/history',name:'accessweaver-workflow-history.json'}};
  if(!Object.prototype.hasOwnProperty.call(options,kind))throw new Error(t('systemExportFailed'));
  if(systemUI.exporting)return;
  if(!supportAvailable()){toast(t('coreRequired'),true);return;}
  systemUI.exporting=true;updateSystemExportButtons();
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
  try{
    const response=await fetch(options[kind].path,{method:'GET',headers:{'X-AccessWeaver-Token':state.token},credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal});
    if(!response.ok)throw new Error(t('systemExportFailed')+' (HTTP '+response.status+')');
    if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type')||''))throw new Error(t('systemExportFailed'));
    downloadFile(await readSystemDownload(response),options[kind].name);
  }catch(error){toast(error.name==='AbortError'?t('systemExportFailed'):error.message,true);}
  finally{controller.abort();clearTimeout(timer);systemUI.exporting=false;updateSystemExportButtons();}
}



// Completion tracking is independent of captured pages, current jobs and profile
// loading. Each response is bound to its session, mode and navigation generation.
const workflowLifecycleUI={context:'',generation:0,controller:null,loading:false,status:null,admissionBlocked:false,admissionRefused:false,refusalEpoch:0,message:'lifecycleNotLoaded',bad:false};
function workflowLifecycleBlocked(){return workflowLifecycleUI.admissionBlocked===true||workflowLifecycleUI.admissionRefused===true;}
function lifecycleProjection(value){
 if(!value||!['none','intent','sealed','released','blocked'].includes(value.state)||typeof value.admissionBlocked!=='boolean'||value.protection!=='retirement-unavailable'||(value.jobId!==undefined&&(typeof value.jobId!=='string'||!/^[a-f0-9]{48}$/.test(value.jobId)))||value.admissionBlocked!==['intent','sealed','blocked'].includes(value.state)||(value.state==='none'&&value.jobId!==undefined)||(['intent','sealed','released'].includes(value.state)&&value.jobId===undefined))throw new Error('historyInvalidResponse');
 return {state:value.state,admissionBlocked:value.admissionBlocked,protection:value.protection,...(value.jobId?{jobId:value.jobId}:{})};
}
function resetWorkflowLifecycle(clearAdmissionRefusal=true){workflowLifecycleUI.controller?.abort();workflowLifecycleUI.controller=null;workflowLifecycleUI.generation++;workflowLifecycleUI.loading=false;workflowLifecycleUI.status=null;workflowLifecycleUI.admissionBlocked=false;if(clearAdmissionRefusal)workflowLifecycleUI.admissionRefused=false;workflowLifecycleUI.message='lifecycleNotLoaded';workflowLifecycleUI.bad=false;renderWorkflowLifecycle();}
function updateWorkflowLifecycleAvailability(){
 const context=historyContext();if(context!==workflowLifecycleUI.context){resetWorkflowLifecycle();workflowLifecycleUI.context=context;renderWorkflowLifecycle();}
 $('history-lifecycle-card').hidden=state.profileEditingOnly;
 $('history-lifecycle-refresh').disabled=!supportAvailable()||workflowLifecycleUI.loading;
 $('history-lifecycle-card').setAttribute('aria-busy',String(workflowLifecycleUI.loading));
 if(workflowLifecycleBlocked())$('system-apply').disabled=true;
}
function renderWorkflowLifecycle(){
 const status=workflowLifecycleUI.status;
 $('history-lifecycle-status').textContent=t(workflowLifecycleUI.loading?'lifecycleLoading':status?'lifecycleState_'+status.state:workflowLifecycleUI.message);
 $('history-lifecycle-status').className=workflowLifecycleUI.bad?'hint error':'hint';
 $('history-lifecycle-job').textContent=status?.jobId?t('lifecycleGeneration')+': '+status.jobId:'';
 $('history-lifecycle-blocked').hidden=!workflowLifecycleBlocked();
}
async function refreshWorkflowLifecycle(){
 updateWorkflowLifecycleAvailability();if(!supportAvailable()||workflowLifecycleUI.loading)return;
 const context=historyContext(),generation=++workflowLifecycleUI.generation,controller=new AbortController();workflowLifecycleUI.controller=controller;workflowLifecycleUI.loading=true;renderWorkflowLifecycle();updateWorkflowLifecycleAvailability();
 const current=()=>context===historyContext()&&generation===workflowLifecycleUI.generation&&state.view==='system'&&supportAvailable();
 try{const status=lifecycleProjection(await historyRequest('/api/v1/system/history/lifecycle',controller,{maxBytes:4096}));if(!current())return;workflowLifecycleUI.status=status;workflowLifecycleUI.admissionBlocked=status.admissionBlocked;workflowLifecycleUI.bad=false;}
 catch(error){if(!current())return;workflowLifecycleUI.status=error?.status===409?{state:'blocked',admissionBlocked:true,protection:'retirement-unavailable'}:null;if(error?.status===409)workflowLifecycleUI.admissionBlocked=true;workflowLifecycleUI.message=error?.status===503?'lifecycleBusy':error?.status===408||error?.name==='AbortError'?'lifecycleEnded':'lifecycleUnavailable';workflowLifecycleUI.bad=true;}
 finally{controller.abort();if(current()){workflowLifecycleUI.loading=false;workflowLifecycleUI.controller=null;renderWorkflowLifecycle();updateWorkflowLifecycleAvailability();}}
}
function handleWorkflowLifecycleAdmission(error){
 if(error?.status!==409||error?.code!=='workflow-lifecycle-pending')return false;
 invalidateSystemPlan();workflowLifecycleUI.controller?.abort();workflowLifecycleUI.controller=null;workflowLifecycleUI.generation++;workflowLifecycleUI.loading=false;workflowLifecycleUI.refusalEpoch++;workflowLifecycleUI.admissionRefused=true;workflowLifecycleUI.admissionBlocked=true;workflowLifecycleUI.status={state:'blocked',admissionBlocked:true,protection:'retirement-unavailable'};workflowLifecycleUI.bad=true;historyUI.open=true;updateHistoryAvailability();renderWorkflowLifecycle();
 setTextOutput('system-output',t('lifecycleAdmissionBlocked'));toast(t('lifecycleAdmissionBlocked'),true);$('history-lifecycle-title').focus();return true;
}

const historyUI={open:false,context:'',generation:0,listGeneration:0,detailGeneration:0,inventory:null,items:[],cursor:'',nextCursor:'',trail:[],selected:null,job:null,largePreview:false,detailReady:false,rawAvailable:false,message:'historyNoCapture',messageValues:{},bad:false,capturing:false,listing:false,detailing:false,exporting:false,captureController:null,listController:null,detailController:null,exportController:null};
const historyClassifications=new Set(['canonical','legacy','malformed','oversized','special','unreadable']);
const historyStates=new Set(['running','succeeded','failed','interrupted','unknown']);
function historyContext(){return JSON.stringify([state.token,!!state.coreAuthenticated,!!state.profileEditingOnly]);}
function historyCurrent(context,generation){return historyUI.context===context&&historyContext()===context&&historyUI.generation===generation&&supportAvailable()&&state.view==='system'&&historyUI.open;}
function historyOpaque(value){return typeof value==='string'&&/^[A-Za-z0-9_-]{1,256}$/.test(value);}
function historyInventory(value){
 if(!value||!/^[a-f0-9]{48}$/.test(value.snapshot)||!/^[a-f0-9]{48}$/.test(value.storeRevision)||!Number.isSafeInteger(value.count)||value.count<0||value.count>65536||!Number.isSafeInteger(value.totalBytes)||value.totalBytes<0||value.totalBytes>8*1024*1024*1024||typeof value.createdAt!=='string'||value.createdAt.length>64)throw new Error('historyInvalidResponse');
 return {snapshot:value.snapshot,storeRevision:value.storeRevision,createdAt:value.createdAt,count:value.count,totalBytes:value.totalBytes};
}
function historyRecord(value){
 if(!value||!historyOpaque(value.recordRef)||typeof value.rawAvailable!=='boolean'||(value.rawAvailable?!/^[a-f0-9]{64}$/.test(value.revision):value.revision!=='')||!historyClassifications.has(value.classification)||!historyStates.has(value.state)||value.protection!=='retirement-unavailable'||!Number.isSafeInteger(value.size)||value.size<0||value.rawAvailable&&value.size>64*1024*1024)throw new Error('historyInvalidResponse');
 for(const key of ['startedAt','finishedAt'])if(value[key]!=null&&(typeof value[key]!=='string'||value[key].length>64))throw new Error('historyInvalidResponse');
 if(value.id!=null&&value.id!==''&&!/^[a-f0-9]{48}$/.test(value.id))throw new Error('historyInvalidResponse');
 return {recordRef:value.recordRef,revision:value.revision,id:value.id||'',action:typeof value.action==='string'?value.action:'',state:value.state,startedAt:value.startedAt||'',finishedAt:value.finishedAt||'',size:value.size,classification:value.classification,protection:value.protection,errorPresent:value.errorPresent===true,resultPresent:value.resultPresent===true,rawAvailable:value.rawAvailable};
}
function historyText(key,values={}){return t(key).replace(/\{(\w+)\}/g,(_match,name)=>String(values[name]??''));}
function historyDate(value){const date=new Date(value);return value&&Number.isFinite(date.getTime())?new Intl.DateTimeFormat(state.lang,{dateStyle:'medium',timeStyle:'short'}).format(date):t('historyUnknown');}
function historySize(value){return new Intl.NumberFormat(state.lang).format(value)+' '+t('historyBytes');}
function historyRecordName(record){return record.id||t('historyLegacyRecord')+' '+record.recordRef.slice(-24);}
function historyOperation(record){return systemOperationText[record.action]?.[state.lang]||t('historyUnknownOperation');}
function historyStopRequests(){
 for(const name of ['captureController','listController','detailController','exportController']){historyUI[name]?.abort();historyUI[name]=null;}
 historyUI.generation++;historyUI.listGeneration++;historyUI.detailGeneration++;
 historyUI.capturing=false;historyUI.listing=false;historyUI.detailing=false;historyUI.exporting=false;
}
function historyClearDetail(){historyUI.detailController?.abort();historyUI.exportController?.abort();historyUI.detailGeneration++;historyUI.detailing=false;historyUI.exporting=false;historyUI.selected=null;historyUI.job=null;historyUI.largePreview=false;historyUI.detailReady=false;historyUI.rawAvailable=false;}
function historyReset(){
 historyStopRequests();historyUI.inventory=null;historyUI.items=[];historyUI.cursor='';historyUI.nextCursor='';historyUI.trail=[];historyClearDetail();historyUI.message='historyNoCapture';historyUI.messageValues={};historyUI.bad=false;
}
function historyNavigationChanged(view){if(view!=='system'){historyStopRequests();historyUI.open=false;resetWorkflowLifecycle(false);resetReconciliation(false);updateReconciliationAvailability();resetControllerStorage(false);updateControllerStorageAvailability();}}
function updateHistoryAvailability(){
 updateControllerStorageAvailability();
 updateWorkflowLifecycleAvailability();
 updateReconciliationAvailability();
 const context=historyContext();if(historyUI.context!==context){historyReset();historyUI.context=context;historyUI.open=false;renderHistoryMessage();renderHistoryRows();renderHistoryDetail();}
 $('history-panel').hidden=!historyUI.open||state.profileEditingOnly;
 const available=supportAvailable(),busy=historyUI.capturing||historyUI.listing;
 $('system-history').disabled=!available;
 $('history-capture').disabled=!available||busy;
 $('history-cancel-capture').disabled=!available||!historyUI.capturing;
 $('history-refresh').disabled=!available||busy;
 $('history-previous').disabled=!available||busy||historyUI.trail.length===0;
 $('history-next').disabled=!available||busy||!historyUI.nextCursor||historyUI.trail.length>=2048;
 $('history-export-record').disabled=!available||historyUI.detailing||historyUI.exporting||!historyUI.detailReady||!historyUI.rawAvailable;
 $('history-panel').setAttribute('aria-busy',String(busy||historyUI.detailing));
}
function setHistoryMessage(key,values={},bad=false){historyUI.message=key;historyUI.messageValues=values;historyUI.bad=bad;renderHistoryMessage();}
function renderHistoryMessage(){
 $('history-status').textContent=historyText(historyUI.message,historyUI.messageValues);$('history-status').className=historyUI.bad?'hint error':'hint';
 const inventory=historyUI.inventory;
 $('history-inventory').textContent=inventory?historyText('historyInventorySummary',{count:new Intl.NumberFormat(state.lang).format(inventory.count),size:historySize(inventory.totalBytes),at:historyDate(inventory.createdAt)}):'';
}
function historyCell(row,text){const cell=document.createElement('td');cell.textContent=text;row.appendChild(cell);return cell;}
function renderHistoryRows(){
 const rows=[];
 for(const record of historyUI.items){
  const row=document.createElement('tr'),cell=document.createElement('td'),button=document.createElement('button');
  button.disabled=historyUI.capturing||historyUI.listing;button.type='button';button.className='history-record-button';button.textContent=record.id?record.id.slice(0,8)+'…'+record.id.slice(-6):historyRecordName(record);button.setAttribute('title',historyRecordName(record));button.setAttribute('aria-label',record.id?button.textContent+': '+historyRecordName(record):historyRecordName(record));button.dataset.historyRef=record.recordRef;
  button.setAttribute('aria-pressed',String(historyUI.selected?.recordRef===record.recordRef));button.addEventListener('click',()=>selectHistoryRecord(record.recordRef));
  cell.appendChild(button);row.appendChild(cell);historyCell(row,historyOperation(record));historyCell(row,t('historyState_'+record.state));historyCell(row,historyDate(record.finishedAt||record.startedAt));historyCell(row,historySize(record.size));historyCell(row,t('historyClass_'+record.classification));historyCell(row,t('historyProtected'));
  rows.push(row);
 }
 if(!rows.length){const row=document.createElement('tr'),cell=historyCell(row,t(historyUI.inventory?'historyEmpty':'historyNoCapture'));cell.colSpan=7;rows.push(row);}
 $('history-rows').replaceChildren(...rows);
}
function renderHistoryDetail(){
 const record=historyUI.selected;$('history-detail-panel').hidden=!record;
 if(!record)return;
 $('history-detail-title').textContent=historyText('historyDetailTitle',{record:historyRecordName(record)});
 $('history-detail-summary').textContent=[historyOperation(record),t('historyState_'+record.state),t('historyClass_'+record.classification),historySize(record.size),t('historyProtected')].join(' · ');
 let text=t(historyUI.detailing?'historyDetailLoading':!record.rawAvailable?'historyRawUnavailable':'historyDetailUnavailable'),limited=false;
 if(historyUI.detailReady&&historyUI.largePreview)text=t('historyLargePreview');
 if(historyUI.detailReady&&historyUI.job!==null){const preview=formatJSONPreview(historyUI.job);text=preview.text;limited=preview.limited;}
 setTextOutput('history-detail',text);$('history-detail-limited').hidden=!limited;
 if(limited)$('history-detail').setAttribute('aria-describedby','history-detail-limited');else $('history-detail').removeAttribute('aria-describedby');
}
function refreshHistoryLanguage(){renderControllerStorage();renderReconciliation();renderWorkflowLifecycle();renderHistoryMessage();renderHistoryRows();renderHistoryDetail();updateHistoryAvailability();}
function historyError(error){
 if(error?.status===409&&error?.code==='history-staging-pending')return 'historyStagingPending';
 if(error?.reportTooLarge)return 'historyCapacity';
 if(error?.status===409){historyUI.inventory=null;historyUI.items=[];historyUI.cursor='';historyUI.nextCursor='';historyUI.trail=[];historyClearDetail();return 'historyCaptureNeeded';}
 return ({400:'historyInvalidResponse',404:'historyRecordUnavailable',408:'historyRequestEnded',413:'historyCapacity',503:'historyBusy'})[error?.status]||(error?.name==='AbortError'?'historyRequestEnded':error?.message==='historyInvalidResponse'?'historyInvalidResponse':'historyFailed');
}
async function historyRequest(path,controller,{method='GET',body,maxBytes=2*1024*1024,timeout=12000}={}){
 const timer=setTimeout(()=>controller.abort(),timeout),token=state.token;
 const active=()=>{if(controller.signal.aborted)throw new DOMException('Request canceled','AbortError');};
 try{
  active();const response=await fetch(path,{method,headers:{'X-AccessWeaver-Token':token,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal});active();
  if(!response.ok){
   let code;
   if(response.status===409&&method==='POST'&&path==='/api/v1/system/history/inventory'&&/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type')||'')){
    try{const blob=await readSystemDownload(response,4096);active();const bytes=await blob.arrayBuffer();active();const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));if(value?.code==='history-staging-pending')code=value.code;}catch{active();}
   }
   throw Object.assign(new Error('historyRequestFailed'),{status:response.status,...(code?{code}:{})});
  }
  if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type')||''))throw new Error('historyInvalidResponse');
  const blob=await readSystemDownload(response,maxBytes);active();const bytes=await blob.arrayBuffer();active();
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new Error('historyInvalidResponse');}
 }finally{clearTimeout(timer);controller.abort();}
}
async function openHistory(){
 updateHistoryAvailability();if(!supportAvailable()){toast(t('coreRequired'),true);return;}
 historyUI.open=true;updateHistoryAvailability();$('history-title').focus();
 await loadHistoryPage('',null,[]);
}
function cancelHistoryCapture(){
 if(!historyUI.capturing)return;historyStopRequests();historyClearDetail();setHistoryMessage('historyCaptureCanceled');renderHistoryRows();renderHistoryDetail();updateHistoryAvailability();
}
async function captureHistory(){
 updateHistoryAvailability();if(!supportAvailable()||historyUI.capturing)return;
 const previous=historyUI.inventory?{inventory:historyUI.inventory,cursor:historyUI.cursor,trail:historyUI.trail.slice(),selected:historyUI.selected?{recordRef:historyUI.selected.recordRef,revision:historyUI.selected.revision}:null}:null;
 historyReset();historyUI.context=historyContext();historyUI.open=true;historyUI.capturing=true;
 const context=historyUI.context,generation=historyUI.generation,listGeneration=historyUI.listGeneration,detailGeneration=historyUI.detailGeneration,controller=new AbortController();historyUI.captureController=controller;
 setHistoryMessage('historyCapturing');renderHistoryRows();renderHistoryDetail();updateHistoryAvailability();
 try{
  const inventory=historyInventory(await historyRequest('/api/v1/system/history/inventory',controller,{method:'POST',body:{},timeout:5*60*1000}));
  if(!historyCurrent(context,generation))return;
  historyUI.inventory=inventory;await loadHistoryPage('',inventory.snapshot,[]);
 }catch(error){if(historyCurrent(context,generation)&&error?.status===409&&error?.code==='history-staging-pending')await restoreHistoryAfterStagingPending(previous,context,generation,listGeneration,detailGeneration);if(historyCurrent(context,generation)&&listGeneration===historyUI.listGeneration&&detailGeneration===historyUI.detailGeneration){setHistoryMessage(historyError(error),{},true);renderHistoryRows();renderHistoryDetail();}}
 finally{if(historyCurrent(context,generation)){historyUI.capturing=false;historyUI.captureController=null;renderHistoryRows();updateHistoryAvailability();}}
}
// Retain only bounded capture coordinates, never an old result payload. A
// staging refusal proves no snapshot freshness; both page and selected detail
// must be read again before they can be restored to the current generation.
function historyPage(value,cursor,snapshot,trail){
 const inventory=historyInventory(value.inventory),nextCursor=value.nextCursor===undefined?'':value.nextCursor;
 if(snapshot&&inventory.snapshot!==snapshot||!Array.isArray(value.items)||value.items.length>64||typeof nextCursor!=='string'||nextCursor&&(!historyOpaque(nextCursor)||[cursor,...trail].includes(nextCursor)))throw new Error('historyInvalidResponse');
 const items=value.items.map(historyRecord);if(new Set(items.map(record=>record.recordRef)).size!==items.length)throw new Error('historyInvalidResponse');
 return {inventory,items,nextCursor};
}
async function restoreHistoryAfterStagingPending(previous,context,generation,listGeneration,detailGeneration){
 const current=()=>historyCurrent(context,generation)&&listGeneration===historyUI.listGeneration&&detailGeneration===historyUI.detailGeneration;if(!previous||!current())return;
 const read=async(path,maxBytes)=>{const controller=new AbortController();historyUI.captureController=controller;return historyRequest(path,controller,{maxBytes});};
 try{
  const query=new URLSearchParams({limit:'64',snapshot:previous.inventory.snapshot});if(previous.cursor)query.set('cursor',previous.cursor);
  const page=historyPage(await read('/api/v1/system/history/page?'+query,2*1024*1024),previous.cursor,previous.inventory.snapshot,previous.trail);if(!current())return;
  if(['snapshot','storeRevision','createdAt','count','totalBytes'].some(key=>page.inventory[key]!==previous.inventory[key]))return;
  historyUI.inventory=page.inventory;historyUI.items=page.items;historyUI.cursor=previous.cursor;historyUI.nextCursor=page.nextCursor;historyUI.trail=previous.trail;
  const record=previous.selected&&page.items.find(item=>item.recordRef===previous.selected.recordRef&&item.revision===previous.selected.revision);if(!record)return;
  const detail=await read('/api/v1/system/history/records/'+encodeURIComponent(record.recordRef)+'?revision='+record.revision,4*1024*1024);if(!current())return;
  const observed=historyRecord(detail.record);
  if(observed.recordRef!==record.recordRef||observed.revision!==record.revision||typeof detail.rawAvailable!=='boolean'||detail.rawAvailable!==observed.rawAvailable||detail.job!=null&&(typeof detail.job!=='object'||Array.isArray(detail.job)))return;
  historyUI.selected=observed;historyUI.job=detail.job??null;historyUI.rawAvailable=detail.rawAvailable;historyUI.detailReady=true;
 }catch{/* Unknown or changed evidence never restores the old detail/export. */}
}
async function loadHistoryPage(cursor='',snapshot=null,trail=[]){
 updateHistoryAvailability();if(!supportAvailable())return;
 if(cursor&&!historyOpaque(cursor))return;
 historyUI.listController?.abort();historyClearDetail();historyUI.listing=true;
 const context=historyUI.context,generation=historyUI.generation,listGeneration=++historyUI.listGeneration,controller=new AbortController();historyUI.listController=controller;
 setHistoryMessage('historyLoading');renderHistoryRows();renderHistoryDetail();updateHistoryAvailability();
 const query=new URLSearchParams({limit:'64'});if(cursor)query.set('cursor',cursor);if(snapshot)query.set('snapshot',snapshot);
 try{
  const page=await historyRequest('/api/v1/system/history/page?'+query,controller);
  if(!historyCurrent(context,generation)||listGeneration!==historyUI.listGeneration)return;
  const {inventory,items,nextCursor}=historyPage(page,cursor,snapshot,trail);
  historyUI.inventory=inventory;historyUI.items=items;historyUI.cursor=cursor;historyUI.nextCursor=nextCursor;historyUI.trail=trail;
  setHistoryMessage('historyPageSummary',{count:new Intl.NumberFormat(state.lang).format(items.length)});
  renderHistoryRows();
 }catch(error){if(historyCurrent(context,generation)&&listGeneration===historyUI.listGeneration){setHistoryMessage(historyError(error),{},true);renderHistoryRows();renderHistoryDetail();}}
 finally{if(historyCurrent(context,generation)&&listGeneration===historyUI.listGeneration){historyUI.listing=false;renderHistoryRows();updateHistoryAvailability();}}
}
function historyNextPage(){if(historyUI.nextCursor&&historyUI.trail.length<2048)return loadHistoryPage(historyUI.nextCursor,historyUI.inventory.snapshot,[...historyUI.trail,historyUI.cursor]);}
function historyPreviousPage(){if(historyUI.trail.length){const trail=historyUI.trail.slice(0,-1);return loadHistoryPage(historyUI.trail[historyUI.trail.length-1],historyUI.inventory.snapshot,trail);}}
async function selectHistoryRecord(recordRef){
 updateHistoryAvailability();if(!supportAvailable()||historyUI.listing||historyUI.capturing)return;
 const record=historyUI.items.find(item=>item.recordRef===recordRef);if(!record)return;
 historyClearDetail();historyUI.selected=record;renderHistoryRows();
 if(record.rawAvailable&&record.size>2*1024*1024){historyUI.detailReady=true;historyUI.rawAvailable=true;historyUI.largePreview=true;renderHistoryDetail();updateHistoryAvailability();return;}
  historyUI.detailing=true;
 const context=historyUI.context,generation=historyUI.generation,detailGeneration=historyUI.detailGeneration,controller=new AbortController();historyUI.detailController=controller;
 renderHistoryDetail();updateHistoryAvailability();
 try{
  const detail=await historyRequest('/api/v1/system/history/records/'+encodeURIComponent(record.recordRef)+'?revision='+record.revision,controller,{maxBytes:4*1024*1024});
  if(!historyCurrent(context,generation)||detailGeneration!==historyUI.detailGeneration)return;
  const observed=historyRecord(detail.record);
  if(observed.recordRef!==record.recordRef||observed.revision!==record.revision||typeof detail.rawAvailable!=='boolean'||detail.rawAvailable!==observed.rawAvailable||detail.job!=null&&(typeof detail.job!=='object'||Array.isArray(detail.job)))throw new Error('historyInvalidResponse');
  historyUI.selected=observed;historyUI.job=detail.job??null;historyUI.rawAvailable=detail.rawAvailable;historyUI.detailReady=true;
 }catch(error){if(historyCurrent(context,generation)&&detailGeneration===historyUI.detailGeneration){if(error?.reportTooLarge){historyUI.detailReady=true;historyUI.rawAvailable=record.rawAvailable;historyUI.largePreview=true;}else setHistoryMessage(historyError(error),{},true);renderHistoryRows();renderHistoryDetail();updateHistoryAvailability();}}
 finally{if(historyCurrent(context,generation)&&detailGeneration===historyUI.detailGeneration){historyUI.detailing=false;renderHistoryDetail();updateHistoryAvailability();}}
}
async function exportHistoryRecord(){
 updateHistoryAvailability();const record=historyUI.selected;
 if(!supportAvailable()||!record||!historyUI.detailReady||!historyUI.rawAvailable||historyUI.exporting)return;
 const context=historyUI.context,generation=historyUI.generation,detailGeneration=historyUI.detailGeneration,controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
 historyUI.exportController=controller;historyUI.exporting=true;updateHistoryAvailability();
 try{
  const response=await fetch('/api/v1/system/history/records/'+encodeURIComponent(record.recordRef)+'/export?revision='+record.revision,{method:'GET',headers:{'X-AccessWeaver-Token':state.token},credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal});
  if(!response.ok)throw Object.assign(new Error('historyRequestFailed'),{status:response.status});
  if(!/^application\/octet-stream(?:\s*;|$)/i.test(response.headers.get('Content-Type')||'')||response.headers.get('ETag')!=='"'+record.revision+'"'||response.headers.get('X-AccessWeaver-Revision')!==record.revision)throw new Error('historyInvalidResponse');
  const blob=await readSystemDownload(response,64*1024*1024);
  if(!historyCurrent(context,generation)||detailGeneration!==historyUI.detailGeneration)return;
  if(blob.size!==record.size)throw new Error('historyInvalidResponse');
  downloadFile(blob,'accessweaver-workflow-record.bin','application/octet-stream');
 }catch(error){if(historyCurrent(context,generation)&&detailGeneration===historyUI.detailGeneration)setHistoryMessage(historyError(error),{},true);}
 finally{clearTimeout(timer);controller.abort();if(historyCurrent(context,generation)&&detailGeneration===historyUI.detailGeneration){historyUI.exporting=false;updateHistoryAvailability();}}
}


// Reconciliation owns a separate review and read lifecycle. Only our own
// explicitly applied, matching completed receipt can clear a Start refusal.
const reconciliationUI={context:'',generation:0,statusGeneration:0,reviewGeneration:0,receiptGeneration:0,status:null,plan:null,attempt:null,receipt:null,knownOperation:'',statusError:'',statusLoading:false,reviewing:false,applying:false,reading:false,watching:false,watchRemaining:0,statusController:null,reviewController:null,applyController:null,receiptController:null,planTimer:null,receiptTimer:null,message:'reconcileNotLoaded',detail:'',bad:false};
const reconciliationBase='/api/v1/system/history/reconciliation';
const reconciliationCodes=new Set(['reconciliation-invalid','reconciliation-unavailable','reconciliation-conflict','reconciliation-expired','reconciliation-pending','reconciliation-denied','reconciliation-policy-unavailable','reconciliation-request-ended','reconciliation-busy','reconciliation-store-unavailable']);
function reconciliationHex(value,size=48){return typeof value==='string'&&new RegExp('^[a-f0-9]{'+size+'}$').test(value);}
function reconciliationInvalid(){return new Error('reconcileInvalidResponse');}
function reconciliationTime(value){if(typeof value!=='string'||value.length>64||!Number.isFinite(Date.parse(value)))throw reconciliationInvalid();return value;}
function reconciliationScope(value){if(value?.scope!=='original-local-owners-only'||value?.protection!=='retirement-unavailable')throw reconciliationInvalid();}
function reconciliationObjects(value){
 const items=value===null?[]:value;if(!Array.isArray(items)||items.length>8)throw reconciliationInvalid();const refs=new Set();
 return items.map(item=>{if(!item||!reconciliationHex(item.ref,64)||refs.has(item.ref)||item.role!=='closed-ack-stage'||!Number.isSafeInteger(item.size)||item.size<0||item.size>65536||!reconciliationHex(item.sha256,64))throw reconciliationInvalid();refs.add(item.ref);return {ref:item.ref,role:item.role,size:item.size,sha256:item.sha256};});
}
function reconciliationStatus(value){
 reconciliationScope(value);if(!['none','available','pending','completed','unavailable'].includes(value.state)||typeof value.canPreview!=='boolean'||typeof value.resumeAvailable!=='boolean'||value.generation!==undefined&&!reconciliationHex(value.generation)||value.operationId!==undefined&&!reconciliationHex(value.operationId))throw reconciliationInvalid();
 const generation=value.generation||'',operationId=value.operationId||'';
 if(value.state==='none'&&(generation||operationId||value.canPreview||value.resumeAvailable)||value.state==='available'&&(!generation||operationId||!value.canPreview||value.resumeAvailable)||value.state==='pending'&&(!generation||!operationId||value.canPreview)||value.state==='completed'&&(!generation||!operationId||value.canPreview||value.resumeAvailable)||value.state==='unavailable'&&(operationId||value.canPreview||value.resumeAvailable))throw reconciliationInvalid();
 return {state:value.state,generation,operationId,canPreview:value.canPreview,resumeAvailable:value.resumeAvailable,scope:value.scope,protection:value.protection};
}
function reconciliationPlan(value,request){
 reconciliationScope(value);if(!reconciliationHex(value.id)||!reconciliationHex(value.operationId)||!reconciliationHex(value.generation)||value.action!=='retry-local-release-ack'||!reconciliationHex(value.reviewRevision,64)||!reconciliationHex(value.intentSHA256,64)||!reconciliationHex(value.sealSHA256,64)||typeof value.resume!=='boolean')throw reconciliationInvalid();
 const expiresAt=reconciliationTime(value.expiresAt),objects=reconciliationObjects(value.objects);
 if(value.resume!==!!request.operationId||request.operationId&&value.operationId!==request.operationId||request.generation&&value.generation!==request.generation)throw reconciliationInvalid();
 if(Date.parse(expiresAt)<=Date.now())throw Object.assign(new Error('expired'),{code:'reconciliation-expired'});
 return {id:value.id,operationId:value.operationId,generation:value.generation,action:value.action,expiresAt,reviewRevision:value.reviewRevision,intentSHA256:value.intentSHA256,sealSHA256:value.sealSHA256,objects,resume:value.resume,scope:value.scope,protection:value.protection};
}
function reconciliationReceipt(value){
 reconciliationScope(value);if(!reconciliationHex(value.operationId)||!reconciliationHex(value.generation)||value.state!=='completed'||value.action!=='retry-local-release-ack'||!reconciliationHex(value.intentSHA256,64)||!reconciliationHex(value.sealSHA256,64)||!reconciliationHex(value.ackSHA256,64))throw reconciliationInvalid();
 return {operationId:value.operationId,generation:value.generation,state:value.state,action:value.action,intentSHA256:value.intentSHA256,sealSHA256:value.sealSHA256,ackSHA256:value.ackSHA256,quarantined:reconciliationObjects(value.quarantined),completedAt:reconciliationTime(value.completedAt),scope:value.scope,protection:value.protection};
}
function reconciliationReceiptMatches(receipt,plan){
 if(receipt.operationId!==plan.operationId||receipt.generation!==plan.generation||receipt.action!==plan.action||receipt.intentSHA256!==plan.intentSHA256||receipt.sealSHA256!==plan.sealSHA256||receipt.quarantined.length!==plan.objects.length)return false;
 const objects=new Map(receipt.quarantined.map(object=>[object.ref,object]));
 return plan.objects.every(object=>{const current=objects.get(object.ref);return current&&current.role===object.role&&current.size===object.size&&current.sha256===object.sha256;});
}
function reconciliationActionIdle(){return !reconciliationUI.applying&&!reconciliationUI.reviewing&&!reconciliationUI.reading&&!reconciliationUI.watching&&!reconciliationUI.plan&&!reconciliationUI.receipt;}
function reconciliationCurrent(context,generation){return context===historyContext()&&context===reconciliationUI.context&&generation===reconciliationUI.generation&&supportAvailable()&&state.view==='system';}
function reconciliationError(error){
 if(error?.message==='reconcileInvalidResponse'||error?.reportTooLarge)return 'reconcileInvalidResponse';
 const code={ 'reconciliation-invalid':'reconcileInvalid','reconciliation-unavailable':'reconcileUnavailable','reconciliation-conflict':'reconcileConflict','reconciliation-expired':'reconcileExpired','reconciliation-pending':'reconcilePending','reconciliation-denied':'reconcileDenied','reconciliation-policy-unavailable':'reconcilePolicyUnavailable','reconciliation-request-ended':'reconcileEnded','reconciliation-busy':'reconcileBusy','reconciliation-store-unavailable':'reconcileStoreUnavailable'}[error?.code];
 return code||({400:'reconcileInvalid',403:'reconcileDenied',408:'reconcileEnded',409:'reconcileConflict',503:'reconcileBusy'})[error?.status]||(error?.name==='AbortError'?'reconcileEnded':'reconcileUnavailable');
}
async function reconciliationRequest(path,controller,{method='GET',body,maxBytes=65536}={}){
 const timer=setTimeout(()=>controller.abort(),15000),token=state.token;
 const active=()=>{if(controller.signal.aborted)throw new DOMException('Request canceled','AbortError');};
 try{
  active();const response=await fetch(path,{method,headers:{'X-AccessWeaver-Token':token,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal});active();
  if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type')||''))throw reconciliationInvalid();
  const blob=await readSystemDownload(response,response.ok?maxBytes:4096);active();const bytes=await blob.arrayBuffer();active();let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw reconciliationInvalid();}
  if(!response.ok)throw Object.assign(new Error('reconciliation request failed'),{status:response.status,...(reconciliationCodes.has(value?.code)?{code:value.code}:{})});
  return value;
 }finally{clearTimeout(timer);controller.abort();}
}
function clearReconciliationPlan(){clearTimeout(reconciliationUI.planTimer);reconciliationUI.planTimer=null;reconciliationUI.plan=null;$('reconcile-consent').checked=false;}
function stopReconciliationWatch(){reconciliationUI.receiptGeneration++;clearTimeout(reconciliationUI.receiptTimer);reconciliationUI.receiptTimer=null;reconciliationUI.receiptController?.abort();reconciliationUI.receiptController=null;reconciliationUI.reading=false;reconciliationUI.watching=false;}
function resetReconciliation(contextChanged=true){
 const controllers=['statusController','reviewController','applyController','receiptController'].map(key=>reconciliationUI[key]);
 reconciliationUI.generation++;reconciliationUI.statusGeneration++;reconciliationUI.reviewGeneration++;reconciliationUI.receiptGeneration++;
 clearReconciliationPlan();clearTimeout(reconciliationUI.receiptTimer);reconciliationUI.receiptTimer=null;
 for(const key of ['statusController','reviewController','applyController','receiptController'])reconciliationUI[key]=null;
 reconciliationUI.status=null;reconciliationUI.statusError='';reconciliationUI.receipt=null;reconciliationUI.statusLoading=false;reconciliationUI.reviewing=false;reconciliationUI.applying=false;reconciliationUI.reading=false;reconciliationUI.watching=false;reconciliationUI.detail='';reconciliationUI.bad=false;
 if(contextChanged){reconciliationUI.attempt=null;reconciliationUI.knownOperation='';$('reconcile-generation').value='';$('reconcile-operation').value='';}
 reconciliationUI.message=reconciliationUI.attempt?'reconcileReceiptNeeded':'reconcileNotLoaded';
 for(const controller of controllers)controller?.abort();renderReconciliation();
}
function updateReconciliationAvailability(){
 const context=historyContext();if(context!==reconciliationUI.context){resetReconciliation();reconciliationUI.context=context;}
 const available=supportAvailable(),busy=reconciliationUI.applying||reconciliationUI.reviewing;
 $('history-reconciliation-card').hidden=state.profileEditingOnly;$('reconcile-refresh').disabled=!available||reconciliationUI.statusLoading;
 $('reconcile-preview').disabled=!available||busy||!$('reconcile-generation').value.trim()&&reconciliationUI.status?.canPreview===false;
 const operationId=$('reconcile-operation').value.trim(),known=reconciliationUI.status?.operationId===operationId;
 $('reconcile-resume').disabled=!available||busy||!reconciliationHex(operationId)||known&&!reconciliationUI.status.resumeAvailable;
 $('reconcile-receipt').disabled=!available||reconciliationUI.applying||!reconciliationHex(operationId);
 $('reconcile-receipt').textContent=t(reconciliationUI.watching?'reconcileStopReceipt':'reconcileReadReceipt');
 $('reconcile-consent').disabled=!available||!reconciliationUI.plan||Date.parse(reconciliationUI.plan.expiresAt)<=Date.now()||reconciliationUI.applying;
 $('reconcile-apply').disabled=$('reconcile-consent').disabled||!$('reconcile-consent').checked;
 $('reconcile-generation').disabled=reconciliationUI.applying;$('reconcile-operation').disabled=reconciliationUI.applying;
}
function reconciliationInputsChanged(){clearReconciliationPlan();reconciliationUI.reviewGeneration++;reconciliationUI.reviewController?.abort();reconciliationUI.reviewController=null;reconciliationUI.reviewing=false;stopReconciliationWatch();reconciliationUI.receipt=null;reconciliationUI.message=reconciliationUI.attempt?'reconcileReceiptNeeded':'reconcileNotLoaded';reconciliationUI.detail='';renderReconciliation();updateReconciliationAvailability();}
function setReconciliationMessage(message,bad=false,detail=''){reconciliationUI.message=message;reconciliationUI.detail=detail;reconciliationUI.bad=bad;renderReconciliation();}
function renderReconciliationObjects(target,objects){
 const rows=objects.map(item=>{const row=document.createElement('tr');historyCell(row,t('reconcileRole'));const ref=historyCell(row,item.ref.slice(0,12)+'…'+item.ref.slice(-8));ref.setAttribute('title',item.ref);historyCell(row,historySize(item.size));const digest=historyCell(row,item.sha256.slice(0,12)+'…'+item.sha256.slice(-8));digest.setAttribute('title',item.sha256);return row;});$(target).replaceChildren(...rows);
}
function renderReconciliation(){
 const status=reconciliationUI.status,plan=reconciliationUI.plan,receipt=reconciliationUI.receipt;
 const statusKey=reconciliationUI.statusLoading?'reconcileReadingStatus':reconciliationUI.statusError||(status?'reconcileState_'+status.state:'');
 const statusText=statusKey?t(statusKey):'',messageText=t(reconciliationUI.message)+(reconciliationUI.detail?' '+t(reconciliationUI.detail):'');
 $('reconcile-status').textContent=statusText;$('reconcile-status').hidden=!statusText||statusText===messageText;
 $('reconcile-message').textContent=messageText;$('reconcile-message').className=reconciliationUI.bad?'hint error':'hint';
 $('reconcile-known-operation').textContent=reconciliationUI.knownOperation?t('reconcileOperation')+': '+reconciliationUI.knownOperation:'';
 $('reconcile-review').hidden=!plan;
 if(plan){$('reconcile-review-summary').textContent=[t('reconcileGeneration')+': '+plan.generation,t('reconcileOperation')+': '+plan.operationId,t('reconcileExpires')+': '+historyDate(plan.expiresAt),t('reconcileRevision')+': '+plan.reviewRevision,t('reconcileIntentDigest')+': '+plan.intentSHA256,t('reconcileSealDigest')+': '+plan.sealSHA256].join('\n');renderReconciliationObjects('reconcile-review-objects',plan.objects);}
 $('reconcile-receipt-panel').hidden=!receipt;
 if(receipt){$('reconcile-receipt-summary').textContent=[t('reconcileOperation')+': '+receipt.operationId,t('reconcileGeneration')+': '+receipt.generation,t('reconcileCompletedAt')+': '+historyDate(receipt.completedAt),t('reconcileIntentDigest')+': '+receipt.intentSHA256,t('reconcileSealDigest')+': '+receipt.sealSHA256,t('reconcileAckDigest')+': '+receipt.ackSHA256].join('\n');renderReconciliationObjects('reconcile-receipt-objects',receipt.quarantined);}
}
function scheduleReconciliationExpiry(plan){
 clearTimeout(reconciliationUI.planTimer);reconciliationUI.planTimer=setTimeout(()=>{if(reconciliationUI.plan!==plan)return;if(Date.parse(plan.expiresAt)>Date.now()){scheduleReconciliationExpiry(plan);return;}clearReconciliationPlan();setReconciliationMessage('reconcileExpired',true);updateReconciliationAvailability();},Math.max(1,Math.min(2147483647,Date.parse(plan.expiresAt)-Date.now())));
}
async function refreshReconciliationStatus(){
 updateReconciliationAvailability();if(!supportAvailable()||reconciliationUI.statusLoading)return;
 const context=reconciliationUI.context,generation=reconciliationUI.generation,readGeneration=++reconciliationUI.statusGeneration,controller=new AbortController();reconciliationUI.statusController=controller;reconciliationUI.statusLoading=true;reconciliationUI.statusError='';if(reconciliationActionIdle())setReconciliationMessage('reconcileReadingStatus');updateReconciliationAvailability();
 const current=()=>reconciliationCurrent(context,generation)&&readGeneration===reconciliationUI.statusGeneration;
 try{const status=reconciliationStatus(await reconciliationRequest(reconciliationBase,controller,{maxBytes:4096}));if(!current())return;reconciliationUI.status=status;if(status.operationId&&!$('reconcile-operation').value.trim()){$('reconcile-operation').value=status.operationId;reconciliationUI.knownOperation=status.operationId;}if(reconciliationActionIdle())setReconciliationMessage('reconcileState_'+status.state);}
 catch(error){if(current()){reconciliationUI.status=null;reconciliationUI.statusError=reconciliationError(error);if(reconciliationActionIdle())setReconciliationMessage(reconciliationUI.statusError,true);}}
 finally{if(current()){reconciliationUI.statusLoading=false;reconciliationUI.statusController=null;renderReconciliation();updateReconciliationAvailability();}}
}
async function previewReconciliation(resume=false){
 updateReconciliationAvailability();if(!supportAvailable()||reconciliationUI.applying)return;
 const generationInput=$('reconcile-generation').value.trim(),operationId=$('reconcile-operation').value.trim();
 if(resume?!reconciliationHex(operationId):generationInput&&!reconciliationHex(generationInput)){setReconciliationMessage('reconcileInvalid',true);return;}
 const request=resume?{operationId}:generationInput?{generation:generationInput}:{};
 clearReconciliationPlan();stopReconciliationWatch();reconciliationUI.receipt=null;reconciliationUI.statusGeneration++;reconciliationUI.statusController?.abort();reconciliationUI.statusController=null;reconciliationUI.statusLoading=false;reconciliationUI.reviewController?.abort();const context=reconciliationUI.context,generation=reconciliationUI.generation,reviewGeneration=++reconciliationUI.reviewGeneration,refusalEpoch=workflowLifecycleUI.refusalEpoch,controller=new AbortController();reconciliationUI.reviewController=controller;reconciliationUI.reviewing=true;setReconciliationMessage('reconcileReviewing');updateReconciliationAvailability();
 const current=()=>reconciliationCurrent(context,generation)&&reviewGeneration===reconciliationUI.reviewGeneration;
 try{const plan=reconciliationPlan(await reconciliationRequest(reconciliationBase+'/preview',controller,{method:'POST',body:request}),request);if(!current())return;if(refusalEpoch!==workflowLifecycleUI.refusalEpoch)throw Object.assign(new Error('changed'),{code:'reconciliation-conflict'});plan.refusalEpoch=refusalEpoch;reconciliationUI.plan=plan;reconciliationUI.knownOperation=plan.operationId;$('reconcile-operation').value=plan.operationId;scheduleReconciliationExpiry(plan);setReconciliationMessage('reconcileReviewReady');$('reconcile-review-title').focus();}
 catch(error){if(current())setReconciliationMessage(reconciliationError(error),true);}
 finally{if(current()){reconciliationUI.reviewing=false;reconciliationUI.reviewController=null;renderReconciliation();updateReconciliationAvailability();}}
}
function acceptReconciliationReceipt(receipt){
 reconciliationUI.statusGeneration++;reconciliationUI.statusController?.abort();reconciliationUI.statusController=null;reconciliationUI.statusLoading=false;reconciliationUI.status=null;reconciliationUI.statusError='';reconciliationUI.receipt=receipt;reconciliationUI.knownOperation=receipt.operationId;setReconciliationMessage('reconcileCompleted');
 const attempt=reconciliationUI.attempt;
 if(attempt&&attempt.context===historyContext()&&reconciliationReceiptMatches(receipt,attempt)){const mayClear=!attempt.receiptAccepted&&attempt.refusalEpoch===workflowLifecycleUI.refusalEpoch;attempt.receiptAccepted=true;if(mayClear){workflowLifecycleUI.generation++;workflowLifecycleUI.controller?.abort();workflowLifecycleUI.controller=null;workflowLifecycleUI.loading=false;workflowLifecycleUI.admissionRefused=false;refreshWorkflowLifecycle();}}
}
async function applyReconciliation(){
 updateReconciliationAvailability();const plan=reconciliationUI.plan;if(!supportAvailable()||reconciliationUI.applying||!plan||!$('reconcile-consent').checked)return;
 if(plan.refusalEpoch!==workflowLifecycleUI.refusalEpoch){clearReconciliationPlan();setReconciliationMessage('reconcileConflict',true);updateReconciliationAvailability();return;}
 if(Date.parse(plan.expiresAt)<=Date.now()){clearReconciliationPlan();setReconciliationMessage('reconcileExpired',true);updateReconciliationAvailability();return;}
 const context=reconciliationUI.context,generation=reconciliationUI.generation,controller=new AbortController();
 reconciliationUI.attempt={...plan,context};reconciliationUI.knownOperation=plan.operationId;reconciliationUI.applyController=controller;reconciliationUI.applying=true;clearReconciliationPlan();stopReconciliationWatch();reconciliationUI.statusGeneration++;reconciliationUI.statusController?.abort();reconciliationUI.statusController=null;reconciliationUI.statusLoading=false;setReconciliationMessage('reconcileApplying');updateReconciliationAvailability();
 const current=()=>reconciliationCurrent(context,generation)&&reconciliationUI.applyController===controller;
 try{const receipt=reconciliationReceipt(await reconciliationRequest(reconciliationBase+'/apply',controller,{method:'POST',body:{planId:plan.id,confirm:true}}));if(!current())return;if(!reconciliationReceiptMatches(receipt,plan))throw reconciliationInvalid();acceptReconciliationReceipt(receipt);}
 catch(error){if(current())setReconciliationMessage('reconcileReceiptNeeded',true,reconciliationError(error));}
 finally{if(current()){reconciliationUI.applying=false;reconciliationUI.applyController=null;renderReconciliation();updateReconciliationAvailability();}}
}
async function readReconciliationReceipt(){
 updateReconciliationAvailability();if(!supportAvailable()||reconciliationUI.applying)return;
 if(reconciliationUI.watching){stopReconciliationWatch();setReconciliationMessage('reconcileWatchStopped');updateReconciliationAvailability();return;}
 const operationId=$('reconcile-operation').value.trim();if(!reconciliationHex(operationId)){setReconciliationMessage('reconcileInvalid',true);return;}
 clearReconciliationPlan();reconciliationUI.reviewGeneration++;reconciliationUI.reviewController?.abort();reconciliationUI.reviewController=null;reconciliationUI.reviewing=false;stopReconciliationWatch();reconciliationUI.watching=true;reconciliationUI.watchRemaining=20;reconciliationUI.receipt=null;reconciliationUI.knownOperation=operationId;
 const context=reconciliationUI.context,generation=reconciliationUI.generation,readGeneration=reconciliationUI.receiptGeneration;
 const current=()=>reconciliationCurrent(context,generation)&&readGeneration===reconciliationUI.receiptGeneration&&reconciliationUI.watching;
 const read=async()=>{
  if(!current())return;const controller=new AbortController();reconciliationUI.receiptController=controller;reconciliationUI.reading=true;setReconciliationMessage('reconcileReadingReceipt');updateReconciliationAvailability();
  try{const receipt=reconciliationReceipt(await reconciliationRequest(reconciliationBase+'/receipts/'+operationId,controller));if(!current())return;if(receipt.operationId!==operationId||reconciliationUI.attempt?.context===context&&reconciliationUI.attempt.operationId===operationId&&!reconciliationReceiptMatches(receipt,reconciliationUI.attempt))throw reconciliationInvalid();reconciliationUI.watching=false;reconciliationUI.reading=false;reconciliationUI.receiptController=null;acceptReconciliationReceipt(receipt);updateReconciliationAvailability();}
  catch(error){if(!current())return;reconciliationUI.reading=false;reconciliationUI.receiptController=null;if(error.code==='reconciliation-pending'&&--reconciliationUI.watchRemaining>0){setReconciliationMessage('reconcileReceiptPending');reconciliationUI.receiptTimer=setTimeout(read,1500);}else{reconciliationUI.watching=false;setReconciliationMessage(error.code==='reconciliation-pending'?'reconcileStillPending':reconciliationError(error),true);}updateReconciliationAvailability();}
 };
 await read();
}

// Observation only: source reservations are not disk usage, physical space,
// aggregate quota, native-writer containment or permission to start work.
const controllerStorageUI={context:'',generation:0,controller:null,loading:false,status:null,message:'controllerStorageNotLoaded',bad:false,refusal:''};
const controllerStorageCodes=new Set(['workflow-storage-invalid','workflow-storage-denied','workflow-storage-policy-unavailable','workflow-storage-busy','workflow-storage-request-ended','workflow-storage-pending','workflow-storage-capacity','workflow-storage-unavailable']);
function controllerStorageProjection(value){
 const numeric=['generationsTracked','reservedBytes','retainedChargeBytes','uncertainBytes','finalizationReservedBytes'],flags=['aggregateQuotaEnforced','physicalCapacityGuaranteed','nativeWritersContained','workerJournalBounded'];
 const required=['state','scope',...numeric,'legacyAccounting',...flags],allowed=new Set([...required,'generation','action']);
 if(!value||typeof value!=='object'||Array.isArray(value)||required.some(key=>!Object.hasOwn(value,key))||Object.keys(value).some(key=>!allowed.has(key))||!['uninitialized','tracked','pending'].includes(value.state)||value.scope!=='tracked-controller-evidence-only'||value.legacyAccounting!=='not-included'||numeric.some(key=>!Number.isSafeInteger(value[key])||value[key]<0)||flags.some(key=>value[key]!==false))throw new Error('controllerStorageInvalidResponse');
 if(value.generation!==undefined&&!reconciliationHex(value.generation)||value.action!==undefined&&!(typeof value.action==='string'&&(Object.hasOwn(systemOperationText,value.action)||value.action==='choose-folder')))throw new Error('controllerStorageInvalidResponse');
 if(value.state==='uninitialized'&&(value.generation!==undefined||value.action!==undefined||numeric.some(key=>value[key]!==0)))throw new Error('controllerStorageInvalidResponse');
 if(value.finalizationReservedBytes>value.reservedBytes||value.state==='tracked'&&value.uncertainBytes!==0||value.state==='pending'&&(value.reservedBytes!==0||value.finalizationReservedBytes!==0))throw new Error('controllerStorageInvalidResponse');
 return Object.fromEntries([...required,...['generation','action'].filter(key=>Object.hasOwn(value,key))].map(key=>[key,value[key]]));
}
function resetControllerStorage(clearRefusal=true){const controller=controllerStorageUI.controller;controllerStorageUI.generation++;controllerStorageUI.controller=null;controllerStorageUI.loading=false;controllerStorageUI.status=null;controllerStorageUI.message='controllerStorageNotLoaded';controllerStorageUI.bad=false;if(clearRefusal)controllerStorageUI.refusal='';controller?.abort();renderControllerStorage();}
function updateControllerStorageAvailability(){const context=historyContext();if(controllerStorageUI.context!==context){resetControllerStorage();controllerStorageUI.context=context;}$('controller-storage-card').hidden=state.profileEditingOnly;$('controller-storage-refresh').disabled=!supportAvailable()||controllerStorageUI.loading;$('controller-storage-card').setAttribute('aria-busy',String(controllerStorageUI.loading));}
function renderControllerStorage(){
 const status=controllerStorageUI.status;$('controller-storage-status').textContent=t(controllerStorageUI.loading?'controllerStorageLoading':status?'controllerStorageState_'+status.state:controllerStorageUI.message);$('controller-storage-status').className=controllerStorageUI.bad?'hint error':'hint';
 const refusal=controllerStorageUI.refusal;$('controller-storage-refusal').hidden=!refusal;$('controller-storage-refusal').textContent=refusal?t(refusal==='workflow-storage-capacity'?'controllerStorageAdmissionCapacity':'controllerStorageAdmissionPending'):'';
 $('controller-storage-values').hidden=!status||status.state==='uninitialized';
 for(const [key,id]of [['generationsTracked','generations'],['reservedBytes','reserved'],['retainedChargeBytes','retained'],['uncertainBytes','uncertain'],['finalizationReservedBytes','finalization']])$('controller-storage-'+id).textContent=status?(key==='generationsTracked'?new Intl.NumberFormat(state.lang).format(status[key]):historySize(status[key])):'';
 $('controller-storage-generation').textContent=status?.generation?t('controllerStorageGeneration')+': '+status.generation:'';
 $('controller-storage-action').textContent=status?.action?t('operation')+': '+(status.action==='choose-folder'?t('controllerStorageFolderAction'):systemOperationText[status.action][state.lang]):'';
}
function controllerStorageError(error){if(error?.reportTooLarge||error?.message==='controllerStorageInvalidResponse')return 'controllerStorageInvalidResponse';return ({'workflow-storage-invalid':'controllerStorageInvalidResponse','workflow-storage-denied':'controllerStorageDenied','workflow-storage-policy-unavailable':'controllerStoragePolicyUnavailable','workflow-storage-busy':'controllerStorageBusy','workflow-storage-request-ended':'controllerStorageEnded','workflow-storage-pending':'controllerStoragePending','workflow-storage-capacity':'controllerStorageCapacity','workflow-storage-unavailable':'controllerStorageUnavailable'})[error?.code]||(error?.name==='AbortError'||error?.status===408?'controllerStorageEnded':error?.status===403?'controllerStorageDenied':error?.status===503?'controllerStorageBusy':'controllerStorageUnavailable');}
async function controllerStorageRequest(controller){
 const timer=setTimeout(()=>controller.abort(),12000),active=()=>{if(controller.signal.aborted)throw new DOMException('Request canceled','AbortError');};
 try{active();const response=await fetch('/api/v1/system/storage',{method:'GET',headers:{'X-AccessWeaver-Token':state.token},credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal});active();if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type')||''))throw new Error('controllerStorageInvalidResponse');const blob=await readSystemDownload(response,4096);active();const bytes=await blob.arrayBuffer();active();let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new Error('controllerStorageInvalidResponse');}if(!response.ok)throw Object.assign(new Error('Storage status unavailable'),{status:response.status,...(controllerStorageCodes.has(value?.code)?{code:value.code}:{})});return value;}
 finally{clearTimeout(timer);controller.abort();}
}
async function refreshControllerStorage(){
 updateControllerStorageAvailability();if(!supportAvailable()||controllerStorageUI.loading)return;const context=controllerStorageUI.context,generation=++controllerStorageUI.generation,controller=new AbortController();controllerStorageUI.controller=controller;controllerStorageUI.loading=true;controllerStorageUI.bad=false;renderControllerStorage();updateControllerStorageAvailability();
 const current=()=>context===historyContext()&&context===controllerStorageUI.context&&generation===controllerStorageUI.generation&&state.view==='system'&&supportAvailable();
 try{const status=controllerStorageProjection(await controllerStorageRequest(controller));if(!current())return;controllerStorageUI.status=status;controllerStorageUI.message='controllerStorageState_'+status.state;}
 catch(error){if(current()){controllerStorageUI.status=null;controllerStorageUI.message=controllerStorageError(error);controllerStorageUI.bad=true;}}
 finally{if(current()){controllerStorageUI.loading=false;controllerStorageUI.controller=null;renderControllerStorage();updateControllerStorageAvailability();}}
}
async function chooseSystemFolder(){const context=historyContext();try{const job=await apiRequest('/api/v1/system/folder','POST',{});if(context!==historyContext()||state.view!=='system'||!supportAvailable())return;systemUI.folderJob=job.id;renderSystemJob(job);pollSystemJob();}catch(error){if(context===historyContext()&&state.view==='system'&&!handleWorkflowLifecycleAdmission(error)&&!handleControllerStorageAdmission(error))toast(error.message,true);}}
function clearControllerStorageRefusal(){if(controllerStorageUI.refusal){controllerStorageUI.refusal='';renderControllerStorage();}}
function handleControllerStorageAdmission(error){
 if(error?.status!==409||!['workflow-storage-capacity','workflow-storage-pending'].includes(error?.code)||!supportAvailable()||state.view!=='system')return false;
 updateControllerStorageAvailability();invalidateSystemPlan();workflowLifecycleUI.refusalEpoch++;controllerStorageUI.refusal=error.code;renderControllerStorage();updateControllerStorageAvailability();const message=t(error.code==='workflow-storage-capacity'?'controllerStorageAdmissionCapacity':'controllerStorageAdmissionPending');toast(message,true);$('controller-storage-title').focus();return true;
}

const systemNavigation=document.createElement('button');systemNavigation.type='button';systemNavigation.className='nav-item';systemNavigation.dataset.view='system';systemNavigation.dataset.i18n='systemTools';systemNavigation.textContent=t('systemTools');systemNavigation.addEventListener('click',()=>navigate('system',true));document.querySelector('.main-nav').appendChild(systemNavigation);
$('system-form').addEventListener('submit',event=>{event.preventDefault();previewSystem()});
$('system-form').addEventListener('input',invalidateSystemPlan);$('system-form').addEventListener('change',invalidateSystemPlan);
$('system-engine').addEventListener('change',()=>{renderSystemPresets();refreshSystemFields()});
$('system-action').addEventListener('change',()=>{refreshSystemFields()});
$('system-dns').addEventListener('change',()=>{refreshSystemFields()});
$('system-folder').addEventListener('click',chooseSystemFolder);
$('system-clear-apps').addEventListener('click',()=>{$('system-applications').value='';invalidateSystemPlan()});
$('system-preset').addEventListener('change',()=>{const p=systemUI.presets[Number($('system-preset').value)];if($('system-preset').value!==''&&p){$('system-args').value=p.args.join('\n');invalidateSystemPlan()}});
$('system-consent').addEventListener('change',()=>{$('system-apply').disabled=!systemUI.plan?.ready||!$('system-consent').checked||workflowLifecycleBlocked()});
$('system-apply').addEventListener('click',applySystem);
$('system-export').addEventListener('click',exportSystemRequest);
$('system-export-status').addEventListener('click',()=>exportSystemReport('status'));
$('system-export-history').addEventListener('click',()=>exportSystemReport('history'));
updateSystemExportButtons();
$('system-inspect').addEventListener('click',()=>previewSystem({action:'discover'}));
$('system-cancel').addEventListener('click',async()=>{try{renderSystemJob(await apiRequest('/api/v1/system/cancel','POST',{}))}catch(e){toast(e.message,true)}});
$('system-history').addEventListener('click',openHistory);
$('history-lifecycle-refresh').addEventListener('click',refreshWorkflowLifecycle);
$('controller-storage-refresh').addEventListener('click',refreshControllerStorage);
$('reconcile-refresh').addEventListener('click',refreshReconciliationStatus);
$('reconcile-preview').addEventListener('click',()=>previewReconciliation(false));
$('reconcile-resume').addEventListener('click',()=>previewReconciliation(true));
$('reconcile-receipt').addEventListener('click',readReconciliationReceipt);
$('reconcile-apply').addEventListener('click',applyReconciliation);
$('reconcile-consent').addEventListener('change',updateReconciliationAvailability);
for(const id of ['reconcile-generation','reconcile-operation'])$(id).addEventListener('input',reconciliationInputsChanged);
$('history-capture').addEventListener('click',captureHistory);
$('history-cancel-capture').addEventListener('click',cancelHistoryCapture);
$('history-refresh').addEventListener('click',()=>loadHistoryPage('',null,[]));
$('history-previous').addEventListener('click',historyPreviousPage);
$('history-next').addEventListener('click',historyNextPage);
$('history-export-record').addEventListener('click',exportHistoryRecord);
if(state.view==='system')loadSystemTools().catch(e=>{setTextOutput('system-output',e.message)});
updateTranslations();
