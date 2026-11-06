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
  invalidateSystemPlan();systemUI.busy=true;const revision=systemUI.revision;
  try {if(!coreAvailable())throw new Error(t('coreRequired'));const plan=await apiRequest('/api/v1/system/preview','POST',request);if(revision!==systemUI.revision)return;systemUI.plan=plan;setTextOutput('system-plan',JSON.stringify({operation:plan.request,requiresAdministrator:plan.requiresAdministrator,steps:plan.steps,issues:plan.issues,warnings:plan.warnings,expiresAt:plan.expiresAt},null,2));$('system-consent').disabled=!plan.ready;$('system-export').disabled=false;}
  catch(error){setTextOutput('system-plan',error.message);toast(error.message,true)}finally{systemUI.busy=false}
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
  catch(error){setTextOutput('system-output',error.message);toast(error.message,true)}finally{systemUI.busy=false}
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
function historyNavigationChanged(view){if(view!=='system'){historyStopRequests();historyUI.open=false;}}
function updateHistoryAvailability(){
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
function refreshHistoryLanguage(){renderHistoryMessage();renderHistoryRows();renderHistoryDetail();updateHistoryAvailability();}
function historyError(error){
 if(error?.reportTooLarge)return 'historyCapacity';
 if(error?.status===409){historyUI.inventory=null;historyUI.items=[];historyUI.cursor='';historyUI.nextCursor='';historyUI.trail=[];historyClearDetail();return 'historyCaptureNeeded';}
 return ({400:'historyInvalidResponse',404:'historyRecordUnavailable',408:'historyRequestEnded',413:'historyCapacity',503:'historyBusy'})[error?.status]||(error?.name==='AbortError'?'historyRequestEnded':error?.message==='historyInvalidResponse'?'historyInvalidResponse':'historyFailed');
}
async function historyRequest(path,controller,{method='GET',body,maxBytes=2*1024*1024,timeout=12000}={}){
 const timer=setTimeout(()=>controller.abort(),timeout),token=state.token;
 try{
  const response=await fetch(path,{method,headers:{'X-AccessWeaver-Token':token,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal});
  if(!response.ok)throw Object.assign(new Error('historyRequestFailed'),{status:response.status});
  if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type')||''))throw new Error('historyInvalidResponse');
  const blob=await readSystemDownload(response,maxBytes),bytes=await blob.arrayBuffer();
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
 historyReset();historyUI.context=historyContext();historyUI.open=true;historyUI.capturing=true;
 const context=historyUI.context,generation=historyUI.generation,controller=new AbortController();historyUI.captureController=controller;
 setHistoryMessage('historyCapturing');renderHistoryRows();renderHistoryDetail();updateHistoryAvailability();
 try{
  const inventory=historyInventory(await historyRequest('/api/v1/system/history/inventory',controller,{method:'POST',body:{},timeout:5*60*1000}));
  if(!historyCurrent(context,generation))return;
  historyUI.inventory=inventory;await loadHistoryPage('',inventory.snapshot,[]);
 }catch(error){if(historyCurrent(context,generation)){setHistoryMessage(historyError(error),{},true);renderHistoryRows();renderHistoryDetail();}}
 finally{if(historyCurrent(context,generation)){historyUI.capturing=false;renderHistoryRows();updateHistoryAvailability();}}
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
  const inventory=historyInventory(page.inventory),nextCursor=page.nextCursor===undefined?'':page.nextCursor;
  if(snapshot&&inventory.snapshot!==snapshot||!Array.isArray(page.items)||page.items.length>64||typeof nextCursor!=='string'||nextCursor&&(!historyOpaque(nextCursor)||[cursor,...trail].includes(nextCursor)))throw new Error('historyInvalidResponse');
  const items=page.items.map(historyRecord);if(new Set(items.map(record=>record.recordRef)).size!==items.length)throw new Error('historyInvalidResponse');
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
$('system-export-status').addEventListener('click',()=>exportSystemReport('status'));
$('system-export-history').addEventListener('click',()=>exportSystemReport('history'));
updateSystemExportButtons();
$('system-inspect').addEventListener('click',()=>previewSystem({action:'discover'}));
$('system-cancel').addEventListener('click',async()=>{try{renderSystemJob(await apiRequest('/api/v1/system/cancel','POST',{}))}catch(e){toast(e.message,true)}});
$('system-history').addEventListener('click',openHistory);
$('history-capture').addEventListener('click',captureHistory);
$('history-cancel-capture').addEventListener('click',cancelHistoryCapture);
$('history-refresh').addEventListener('click',()=>loadHistoryPage('',null,[]));
$('history-previous').addEventListener('click',historyPreviousPage);
$('history-next').addEventListener('click',historyNextPage);
$('history-export-record').addEventListener('click',exportHistoryRecord);
if(state.view==='system')loadSystemTools().catch(e=>{setTextOutput('system-output',e.message)});
updateTranslations();
