/* AccessWeaver dashboard · no external libraries, analytics, CDNs or accounts. */
'use strict';
const $=id=>document.getElementById(id);
const $$=selector=>Array.from(document.querySelectorAll(selector));
const narrowNavigation=window.matchMedia('(max-width: 760px)');
function setSidebarOpen(open){
  const sidebar=$('sidebar');
  sidebar.classList.toggle('open',open);$('menu-toggle').setAttribute('aria-expanded',String(open));
  sidebar.inert=narrowNavigation.matches&&!open;
  if(open&&narrowNavigation.matches)(sidebar.querySelector('.nav-item.active')||sidebar.querySelector('.nav-item'))?.focus();
}

function setTextOutput(id,text){
  const target=$(id);target.textContent=text;target.tabIndex=target.textContent?0:-1;
  if(id==='system-output'){$('system-output-limited').hidden=true;target.removeAttribute('aria-describedby');}
}
// Bound display work independently of retained/exported JSON. Each container is
// visited lazily with an explicit stack; a deep value never reaches stringify.
function formatJSONPreview(value){
  const maxText=128*1024,maxNodes=4096,maxDepth=32,maxString=4096;
  const chunks=[],ancestors=new Set(),stack=[{value,depth:0}];
  let length=0,nodes=0,limited=false,full=false;
  function clip(text,limit){
    if(text.length<=limit)return text;
    limited=true;let end=Math.max(0,limit-1);
    if(end&&text.charCodeAt(end-1)>=0xd800&&text.charCodeAt(end-1)<=0xdbff)end--;
    return limit?text.slice(0,end)+'…':'';
  }
  function write(text){
    if(text.length>maxText-length){const room=maxText-length;text=clip(text,room);limited=true;full=true;}
    chunks.push(text);length+=text.length;
  }
  function* entries(object){
    if(Array.isArray(object)){for(let i=0;i<object.length;i++)yield [null,object[i]];}
    else for(const key in object)if(Object.prototype.hasOwnProperty.call(object,key)){
      const child=object[key];if(!['undefined','function','symbol'].includes(typeof child))yield [key,child];
    }
  }
  while(stack.length&&!full){
    const frame=stack.pop();
    if(frame.iterator){
      const next=frame.iterator.next();
      if(next.done){if(!frame.first)write('\n'+'  '.repeat(frame.depth));write(frame.array?']':'}');ancestors.delete(frame.object);continue;}
      write((frame.first?'\n':',\n')+'  '.repeat(frame.depth+1));frame.first=false;
      if(!frame.array)write(JSON.stringify(clip(next.value[0],maxString))+': ');
      stack.push(frame,{value:next.value[1],depth:frame.depth+1});continue;
    }
    if(++nodes>maxNodes){limited=true;write(JSON.stringify('…'));break;}
    const item=frame.value;
    if(item===null||typeof item==='boolean'||typeof item==='number'){write(JSON.stringify(item));continue;}
    if(typeof item==='string'){write(JSON.stringify(clip(item,maxString)));continue;}
    if(typeof item!=='object'){limited=true;write('null');continue;}
    if(frame.depth>=maxDepth||ancestors.has(item)){limited=true;write(JSON.stringify('…'));continue;}
    ancestors.add(item);const array=Array.isArray(item);write(array?'[':'{');
    stack.push({iterator:entries(item),object:item,array,depth:frame.depth,first:true});
  }
  return {text:chunks.join(''),limited};
}
function showSystemOutput(value){
  const preview=formatJSONPreview(value);setTextOutput('system-output',preview.text);
  $('system-output-limited').hidden=!preview.limited;
  if(preview.limited)$('system-output').setAttribute('aria-describedby','system-output-limited');
}
function setEditorFeedback(text,error=false){setTextOutput('editor-feedback',text);$('editor-feedback').className=error?'error':'';}

const icon=(name)=>`<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const escapeHTML=(s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const splitLines=s=>String(s||'').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
const uniqueId=(base,existing)=>{let p=base.replace(/[^a-z0-9-]/g,'-').replace(/-+/g,'-').replace(/^-|-$/g,'').slice(0,55)||'profile';if(!/^[a-z]/.test(p)||p.length<2)p='my-'+p;let n=p,i=2;while(existing.some(x=>x.id===n))n=`${p}-${i++}`;return n};
const exampleEngines=[
 {id:'byedpi',name:'ByeDPI',kind:'proxy',platforms:['windows','linux','darwin','freebsd','openbsd'],includes:true,excludes:true,applications:false,source:'https://github.com/hufrea/byedpi',notes:'Local SOCKS proxy; configure apps separately.'},
 {id:'zapret2',name:'Zapret2',kind:'packet',platforms:['windows','linux','freebsd','openbsd'],includes:true,excludes:true,applications:false,source:'https://github.com/bol-van/zapret2',notes:'Requires platform-specific packet interception configuration.'},
 {id:'zapret',name:'Zapret',kind:'packet',platforms:['windows','linux','darwin','freebsd','openbsd'],includes:true,excludes:true,applications:false,source:'https://github.com/bol-van/zapret',notes:'Upstream EOL; macOS support is partial.'},
 {id:'goodbyedpi',name:'GoodbyeDPI',kind:'packet',platforms:['windows'],includes:true,excludes:false,applications:false,source:'https://github.com/ValdikSS/GoodbyeDPI',notes:'Windows only; uses WinDivert.'},
 {id:'wiresock',name:'WireSock SDK',kind:'vpn',platforms:['windows'],includes:false,excludes:false,applications:true,source:'https://wiresock.net/wiresock-sdk/',license:'Proprietary SDK EULA; evaluation and commercial terms differ',notes:'Windows SDK foreground client; vendor installation and existing configuration required. Vendor telemetry and license terms apply.'},
 {id:'wireguard',name:'WireGuard',kind:'vpn',platforms:['windows','linux','darwin','freebsd','openbsd'],includes:false,excludes:false,applications:false,source:'https://www.wireguard.com/',integration:'external',notes:'Reference integration. Manage tunnels with the official OS client.'},
 {id:'spoofdpi',name:'SpoofDPI',kind:'proxy',platforms:['windows','linux','darwin'],includes:false,excludes:false,applications:false,source:'https://github.com/xvzc/SpoofDPI',notes:'Optional external proxy engine.'},
 {id:'sing-box',name:'sing-box',kind:'proxy',platforms:['windows','linux','darwin','freebsd','openbsd'],includes:false,excludes:false,applications:false,source:'https://sing-box.sagernet.org/',notes:'External configured proxy core.'},
 {id:'xray',name:'Xray-core',kind:'proxy',platforms:['windows','linux','darwin','freebsd'],includes:false,excludes:false,applications:false,source:'https://github.com/XTLS/Xray-core',notes:'External configured proxy core.'}
];
const en={workspace:'PERSONAL WORKSPACE',workspaceLabel:'WORKSPACE',navDashboard:'Overview',navProfiles:'Profiles & rules',navEngines:'Engine library',navDiagnostics:'Diagnostics',navSettings:'Settings',preferences:'PREFERENCES',privacy:'Built for your privacy',privacyText:'AccessWeaver has no accounts or telemetry. Optional engines have their own privacy and licensing terms.',upstream:'Explore upstream engines ↗',console:'Console',localOnly:'LOCAL ONLY',networkWorkspace:'NETWORK WORKSPACE',welcome:'Your connection, your rules.',welcomeText:'One thoughtful place to manage access, routing tools and diagnostics.',runDiagnostic:'Run diagnostics',connectionOverview:'CONNECTION OVERVIEW',currentStatus:'CURRENT STATUS',selectProfile:'Select profile',manageProfiles:'Manage profiles',noSilentChanges:'No silent DNS or route changes',yourProfiles:'YOUR PROFILES',profilesDesc:'Fully editable, portable configurations',savedLocally:'Saved locally',engineSupport:'ENGINE LIBRARY',engineDesc:'Optional, independently installed tools',quickProfiles:'Quick access profiles',quickProfilesText:'Your saved configurations, ready to inspect and customize.',viewAll:'View all profiles',controlTitle:'You stay in control',controlText:'AccessWeaver does not download unknown binaries, change your DNS, or configure the whole system without an explicit action. Engine availability depends on your platform.',advancedTools:'Advanced tools',advancedText:'CLI commands, JSON profiles and diagnosis reports',profilesTitle:'Profiles & rules',profilesSubtitle:'Customize every strategy, domain list and executable with clarity.',import:'Import JSON',createProfile:'Create profile',enginesTitle:'Engine library',enginesSubtitle:'One interface for independently maintained open networking tools.',externalTools:'External tools, deliberately separate',externalNote:'Engines are never downloaded or installed silently. Add an official executable path in each profile. Support for domain lists varies by adapter.',diagnosticsTitle:'Connection diagnostics',diagnosticsSubtitle:'Understand DNS resolution, TCP reachability and verified TLS behavior.',newTest:'New connectivity test',diagnosticNote:'Read-only tests. No route, DNS, or system settings are changed.',hostname:'Hostname',timeout:'Timeout (seconds)',verifyTLS:'Verify TLS certificate and handshake',startTest:'Start test',testResults:'Test results',noResults:'No tests yet',noResultsText:'Run a connectivity test to see individual network stages.',settingsTitle:'Settings',settingsSubtitle:'A few deliberate choices, with powerful customization where it matters.',language:'Language',languageDesc:'Choose the interface language. README defaults to English.',appearance:'Appearance',appearanceDesc:'Switch between midnight and daylight surfaces.',environment:'Runtime environment',environmentDesc:'Platform-aware engine rules, with no automatic elevated privileges.',repository:'Project & licensing',repositoryDesc:'Original AccessWeaver source code is 0BSD. External engines retain their own licenses.',runtimeLogs:'Runtime activity',runtimeLogsDesc:'View recent local engine output. Logs are held only in process memory.',viewLogs:'View logs',footerText:'Built for transparency. Powered by your choices.',profileStudio:'PROFILE STUDIO',guidedEditor:'Guided editor',jsonEditor:'Advanced JSON',profileId:'Profile ID',displayName:'Display name',description:'Description',engine:'Engine',category:'Category',binaryPath:'External executable (absolute path or PATH name)',arguments:'Arguments (one argument per line, no shell)',domainRules:'Domain rules',includedDomains:'Include domains (one per line)',excludedDomains:'Exclude domains (one per line)',rulesWarning:'Domain lists are only mapped for compatible engines. Unsupported rules are rejected when starting.',moreOptions:'Advanced settings, app paths & integrity',apps:'Application paths (one per line; not yet applied by engines)',probeHost:'Probe hostname',probePort:'Probe port',probeTLS:'Verify probe TLS certificate',notes:'Notes',jsonHelp:'Full schema editing. Unknown fields and invalid values are rejected before saving.',cancel:'Cancel',saveChanges:'Save changes',recentLogs:'Recent engine logs',logsVolatile:'Only recent in-memory logs are displayed.',copyLogs:'Copy logs',ready:'Ready when you are',readyDesc:'Choose a profile to start a compatible local engine. Nothing runs automatically.',running:'Process running',runningDesc:'The engine process is active. Connectivity and routing must be independently verified.',offline:'Offline profile studio',offlineDesc:'Editing and exporting profiles work here; running engines requires the installed local core.',notRunning:'NOT RUNNING',runningBadge:'PROCESS RUNNING',offlineBadge:'EDITOR ONLY',edit:'Edit',start:'Start',stop:'Stop',duplicate:'Duplicate',export:'Export',delete:'Delete',allEngines:'All engines',searchProfiles:'Search profiles, engines, notes...',profilesShown:'profiles',saved:'Profile saved',imported:'Profile imported',deleted:'Profile deleted',created:'Profile created',confirmDelete:'Delete this profile? This cannot be undone.',confirmStart:'Start this external engine process? Verify the binary and options first. It may require administrator privileges or change connectivity.',startFailed:'Could not start',stopped:'Engine stopped',startOk:'Engine process launched; verify connectivity.',engineUnsupported:'Not supported here',engineSupported:'Platform listed',readDocs:'Source & docs ↗',noProfiles:'No matching profiles. Create one to get started.',missingServer:'Local core unavailable: offline editing mode. No networking engine can be started.',editorTitleNew:'Create profile',editorTitleEdit:'Edit profile',savedOffline:'Saved in this browser only',testRunning:'Testing...',testDone:'Test completed',testFailed:'Test failed',jsonError:'Invalid JSON',importInvalid:'Unable to import JSON profile',settingsLogsEmpty:'No runtime output has been captured.',copySuccess:'Copied',unsupportedRules:'This adapter does not automatically apply domain/app rules.'};
const tr={workspace:'KİŞİSEL ÇALIŞMA ALANI',workspaceLabel:'ÇALIŞMA ALANI',navDashboard:'Genel bakış',navProfiles:'Profiller ve kurallar',navEngines:'Motor kütüphanesi',navDiagnostics:'Tanılama',navSettings:'Ayarlar',preferences:'TERCİHLER',privacy:'Gizliliğiniz için tasarlandı',privacyText:'AccessWeaver hesap veya telemetri kullanmaz. İsteğe bağlı motorların gizlilik ve lisans koşulları ayrıdır.',upstream:'Kaynak motorları incele ↗',console:'Panel',localOnly:'YALNIZCA YEREL',networkWorkspace:'AĞ ÇALIŞMA ALANI',welcome:'Bağlantınız, kurallarınız.',welcomeText:'Erişim, ağ araçları ve tanılamayı tek bir yerden yönetin.',runDiagnostic:'Tanılamayı çalıştır',connectionOverview:'BAĞLANTI ÖZETİ',currentStatus:'GÜNCEL DURUM',selectProfile:'Profil seç',manageProfiles:'Profilleri yönet',noSilentChanges:'Gizlice DNS veya rota değiştirmez',yourProfiles:'PROFİLLERİNİZ',profilesDesc:'Tamamen düzenlenebilir, taşınabilir ayarlar',savedLocally:'Yerel kaydedildi',engineSupport:'MOTOR KÜTÜPHANESİ',engineDesc:'İsteğe bağlı, bağımsız kurulan araçlar',quickProfiles:'Hızlı erişim profilleri',quickProfilesText:'İncelemeye ve özelleştirmeye hazır kayıtlı profiller.',viewAll:'Tüm profilleri gör',controlTitle:'Kontrol sizde',controlText:'AccessWeaver bilinmeyen dosyaları indirmez, DNS değiştirmez veya açık bir işlem olmadan sistem yapılandırmasını değiştirmez. Motorlar işletim sistemine bağlıdır.',advancedTools:'Gelişmiş araçlar',advancedText:'CLI komutları, JSON profilleri ve tanılama raporları',profilesTitle:'Profiller ve kurallar',profilesSubtitle:'Her stratejiyi, alan adı listesini ve uygulama dosyasını düzenleyin.',import:'JSON içe aktar',createProfile:'Profil oluştur',enginesTitle:'Motor kütüphanesi',enginesSubtitle:'Bağımsız sürdürülen ağ araçları için tek bir arayüz.',externalTools:'Harici araçlar bilinçli olarak ayrıdır',externalNote:'Motorlar otomatik indirilmez veya kurulmaz. Profilinize resmi uygulama yolunu yazın. Alan adı listesi desteği motorlara göre değişir.',diagnosticsTitle:'Bağlantı tanılaması',diagnosticsSubtitle:'DNS, TCP erişilebilirliği ve doğrulanmış TLS davranışını inceleyin.',newTest:'Yeni bağlantı testi',diagnosticNote:'Yalnızca okuma testi. Sistem, DNS veya rota ayarları değişmez.',hostname:'Sunucu adı',timeout:'Zaman aşımı (saniye)',verifyTLS:'TLS sertifikasını ve el sıkışmasını doğrula',startTest:'Testi başlat',testResults:'Test sonuçları',noResults:'Henüz test yok',noResultsText:'Ağ aşamalarını görmek için bağlantı testi yapın.',settingsTitle:'Ayarlar',settingsSubtitle:'Önemli alanlarda kapsamlı özelleştirme, diğerlerinde sadelik.',language:'Dil',languageDesc:'Arayüz dilinizi seçin. Varsayılan README İngilizcedir.',appearance:'Görünüm',appearanceDesc:'Koyu ve açık görünüm arasında geçiş yapın.',environment:'Çalışma ortamı',environmentDesc:'İşletim sistemine uygun motor kuralları ve açık yetki yönetimi.',repository:'Proje ve lisans',repositoryDesc:'Özgün AccessWeaver kodu 0BSD lisanslıdır. Harici motorların lisansları ayrıdır.',runtimeLogs:'Çalışma günlükleri',runtimeLogsDesc:'Son motor çıktısını inceleyin. Günlükler yalnızca bellekte tutulur.',viewLogs:'Günlükleri gör',footerText:'Şeffaflık için tasarlandı. Karar sizin.',profileStudio:'PROFİL STÜDYOSU',guidedEditor:'Kolay düzenleme',jsonEditor:'Gelişmiş JSON',profileId:'Profil kimliği',displayName:'Görünen ad',description:'Açıklama',engine:'Motor',category:'Kategori',binaryPath:'Harici program dosyası (tam yol veya PATH)',arguments:'Parametreler (her satırda bir adet, kabuk kullanılmaz)',domainRules:'Alan adı kuralları',includedDomains:'Dahil edilen alan adları (her satırda bir)',excludedDomains:'Hariç tutulan alan adları (her satırda bir)',rulesWarning:'Alan adı listeleri yalnızca destekleyen motorlara aktarılır. Desteklenmeyen kurallar çalıştırmayı engeller.',moreOptions:'Gelişmiş ayarlar, uygulama yolları ve bütünlük',apps:'Uygulama yolları (her satırda bir; henüz uygulanmıyor)',probeHost:'Test sunucusu',probePort:'Test portu',probeTLS:'Test TLS sertifikasını doğrula',notes:'Notlar',jsonHelp:'Tam şema düzenleme. Geçersiz veya bilinmeyen alanlar reddedilir.',cancel:'Vazgeç',saveChanges:'Kaydet',recentLogs:'Son motor günlükleri',logsVolatile:'Yalnızca bellekteki son günlükler gösterilir.',copyLogs:'Günlükleri kopyala',ready:'Bağlanmaya hazır',readyDesc:'Uyumlu bir yerel motoru çalıştırmak için profil seçin. Otomatik başlatma yoktur.',running:'İşlem çalışıyor',runningDesc:'Motor işlemi çalışıyor. Bağlantı ve yönlendirme ayrıca doğrulanmalıdır.',offline:'Çevrimdışı profil stüdyosu',offlineDesc:'Profil düzenleme/dışa aktarma çalışır; motor çalıştırmak için yerel çekirdek gerekir.',notRunning:'ÇALIŞMIYOR',runningBadge:'İŞLEM ÇALIŞIYOR',offlineBadge:'YALNIZCA DÜZENLEME',edit:'Düzenle',start:'Başlat',stop:'Durdur',duplicate:'Çoğalt',export:'Dışa aktar',delete:'Sil',allEngines:'Tüm motorlar',searchProfiles:'Profil, motor ve not ara...',profilesShown:'profil',saved:'Profil kaydedildi',imported:'Profil içe aktarıldı',deleted:'Profil silindi',created:'Profil oluşturuldu',confirmDelete:'Bu profil silinsin mi? Geri alınamaz.',confirmStart:'Harici motor başlatılsın mı? Önce dosyayı ve parametreleri doğrulayın. Yönetici yetkisi gerekebilir veya bağlantı etkilenebilir.',startFailed:'Başlatılamadı',stopped:'Motor durduruldu',startOk:'Motor işlemi başlatıldı; bağlantıyı doğrulayın.',engineUnsupported:'Burada desteklenmiyor',engineSupported:'Platform listede',readDocs:'Kaynak ve belgeler ↗',noProfiles:'Eşleşen profil yok. Başlamak için oluşturun.',missingServer:'Yerel çekirdek yok: çevrimdışı düzenleme. Ağ motoru çalıştırılamaz.',editorTitleNew:'Profil oluştur',editorTitleEdit:'Profili düzenle',savedOffline:'Yalnızca tarayıcıda kaydedildi',testRunning:'Test yapılıyor...',testDone:'Test tamamlandı',testFailed:'Test başarısız',jsonError:'Geçersiz JSON',importInvalid:'JSON profili içe aktarılamadı',settingsLogsEmpty:'Henüz motor çıktısı bulunmuyor.',copySuccess:'Kopyalandı',unsupportedRules:'Bu adaptör alan adı/uygulama kurallarını otomatik uygulamaz.'};

Object.assign(en, {
  skipContent:'Skip to content', configurationStudio:'CONFIGURATION STUDIO', integrationCatalog:'INTEGRATION CATALOG', networkIntelligence:'NETWORK INTELLIGENCE', yourEnvironment:'YOUR ENVIRONMENT', runtimeLabel:'RUNTIME', filterEngine:'Filter by engine', tcpPort:'TCP port', midnight:'Midnight', daylight:'Daylight', toggleNavigation:'Toggle navigation', toggleTheme:'Toggle theme', close:'Close', profileJSON:'Profile JSON', checksum:'SHA-256 executable checksum (optional)',
  profileStorage:'Profile storage', coreStorage:'Profiles are saved by the local core. Browser preferences stay in this browser.', browserStorage:'Profiles are saved in this browser only. Export them before clearing browser data or moving to another device.', coreStorageBadge:'LOCAL CORE', browserStorageBadge:'THIS BROWSER', reconnect:'Reconnect', disconnected:'Core disconnected', disconnectedDesc:'The last runtime state is no longer current. Reconnect to check the process and continue.', disconnectedNotice:'Connection to the local core was lost. Runtime state is unknown; your unsaved work is still here.', offlineNotice:'Browser editor mode. Profiles can be saved and exported here; engine launch and diagnostics need the local core.', connecting:'Connecting to the local core…', connectedAgain:'Connected to the local core', switchStore:'The local core is available. Export browser profiles before switching if you need them. Switch to core profiles now?', storageFailed:'Browser storage is unavailable or full. Your changes have not been saved. Export the profile to keep a copy.',
  platformCoverage:'A clear view of platform support', platformCoverageDesc:'The local core and an engine have separate requirements.', desktopCore:'Local core', partialCore:'Selected engines', mobileEditor:'Browser editor', windowsSupport:'Local engine management. Packet tools may need WinDivert and administrator rights.', linuxSupport:'Local engine management. Packet tools require separately configured firewall or queue hooks.', macSupport:'Local core with selected proxies. Packet interception and tunnel setup are limited or external.', bsdSupport:'Selected upstream engines and builds. Check the exact BSD variant and packet hooks.', androidSupport:'This interface edits profiles in a browser. Native VPN or proxy integration needs a separate Android client; it is not bundled.', iosSupport:'This interface edits profiles in a browser. iOS does not run these desktop engine processes; use a separate authorized native client.',
  managedIntegration:'MANAGED PROCESS', externalIntegration:'EXTERNAL SETUP', includesLabel:'Includes', excludesLabel:'Excludes', appRules:'App rules', supportedRule:'Mapped', unsupportedRule:'External / unsupported', createForEngine:'Create profile', setupRequired:'Setup required', engineAvailable:'Compatible platform', engineExternal:'External manager', platformUnknown:'Check platform', engineSource:'Official source', engineDocs:'Read setup docs', noArguments:'No additional arguments',
  configPath:'External configuration file (optional absolute path)', configPathHelp:'Required for WireSock, sing-box and Xray. Existing files are used without modification.', exclusionExamples:'Add exclusion examples:', windowsUpdate:'Windows Update', rulesWarning:'Examples are a starting point, not complete OS or game exclusions. Domain rules cannot isolate all application traffic. Unsupported rules prevent launch.', supportedIncludes:'Include domains are mapped by this adapter.', unsupportedIncludes:'Include domains are not mapped by this adapter.', supportedExcludes:'Exclude domains are mapped by this adapter.', unsupportedExcludes:'Exclude domains are not mapped by this adapter.', appRulesNote:'Application paths are stored for planning; no adapter applies them automatically.', addedExclusions:'Example exclusions added. Review their scope before use.', includeCount:'included', excludeCount:'excluded',
  preview:'Check setup', launchReview:'LAUNCH REVIEW', reviewSetup:'Review engine setup', editProfile:'Edit profile', startEngine:'Start engine', launchConsent:'Starting runs this external executable with your current permissions. Inspect the file, arguments and any external configuration first.', launchNotConnectivity:'Readiness does not verify connectivity.', checkingSetup:'Checking executable and profile…', setupReady:'Launch prerequisites found', setupBlocked:'Resolve before launch', executable:'Executable', launchArguments:'Argument vector · no shell', workingDirectory:'Working directory', warnings:'Review notes', issues:'Setup issues', previewUnavailable:'Setup checks require the local core.', readyToConfigure:'Configure and check setup',
  guideSpoof:'Use a compatible HTTP proxy build. Inspect its system-proxy options; some macOS releases change proxy settings automatically.', guideByedpi:'A local SOCKS proxy. Set the app’s proxy separately; launch does not route the whole device.', guideZapret:'Packet processing needs compatible interception hooks or drivers. Supply a tested strategy for your network.', guideGoodbye:'Windows packet processing with WinDivert. Domain includes are mapped; exclusions are unsupported.', guideWiresock:'Use the official WireSock SDK foreground client and an existing configuration. Per-app routing belongs in that file. The SDK has vendor telemetry and separate evaluation/commercial license terms.', guideWireguard:'Manage the tunnel with the platform’s official tools. AccessWeaver stores this profile but does not launch a tunnel manager.', guideProxy:'Supply your installed executable and matching configuration. Configure proxy or tunnel routing separately.',
  discardChanges:'Discard your unsaved profile changes?', duplicateId:'This ID already exists. Choose a different ID or edit the existing profile.', immutableId:'A saved profile ID cannot change. Duplicate the profile instead.', invalidProfile:'The file must contain a single profile object.', unknownField:'Unknown field', invalidField:'Invalid value for', requiredField:'Required field', invalidVersion:'Profile version must be 1.', invalidId:'Use 2–63 lowercase letters, digits and hyphens; start with a letter.', invalidEngine:'Choose an engine from the library.', invalidDomain:'Use an ASCII/IDNA domain name, without a URL or spaces.', duplicateDomain:'Duplicate domain', conflictingDomain:'A domain cannot be both included and excluded', invalidSHA:'SHA-256 must contain exactly 64 hexadecimal characters.', fileTooLarge:'File exceeds 1 MiB.', importReview:'Review the imported profile, then save. Existing profiles are preserved.', importRenamed:'This ID already exists. A new ID was assigned; review and save the copy.', saving:'Saving…', unsavedChanges:'Unsaved changes', newProfileName:'My custom profile', customCategory:'Custom', copySuffix:'copy', defaultDescription:'An editable engine configuration',
  activeEdit:'Stop the active profile before editing it.', otherRunning:'Stop the running profile before launching another.', coreRequired:'This action needs a connected local core.', failedState:'Engine exited', failedDesc:'The engine is no longer running. Check its output and setup before restarting.', exitError:'Engine output', exportReport:'Export report', reportHost:'Tested host', testPassed:'All requested checks passed', testIncomplete:'One or more checks failed', noProbe:'No diagnostic report to export', argsPrecision:'One literal argument per line. Whitespace and empty arguments from JSON are preserved.', profileSaved:'Profile saved', loading:'Loading…', refreshLogs:'Refresh logs', storageRecovery:'Some browser profile data could not be read. It is preserved in storage. Export a backup from Settings before repairing it.', exportBrowserBackup:'Export browser backup', storageUnreadable:'Stored profile JSON is unreadable. It has been preserved; export its backup in Settings before repairing browser storage.'
});
Object.assign(tr, {
  skipContent:'İçeriğe geç', configurationStudio:'YAPILANDIRMA STÜDYOSU', integrationCatalog:'ENTEGRASYON KATALOĞU', networkIntelligence:'AĞ TANILAMA', yourEnvironment:'ÇALIŞMA ORTAMINIZ', runtimeLabel:'ÇALIŞMA ZAMANI', filterEngine:'Motora göre filtrele', tcpPort:'TCP portu', midnight:'Koyu', daylight:'Açık', toggleNavigation:'Gezinmeyi aç/kapat', toggleTheme:'Görünümü değiştir', close:'Kapat', profileJSON:'Profil JSON verisi', checksum:'SHA-256 program sağlama toplamı (isteğe bağlı)',
  profileStorage:'Profil depolama', coreStorage:'Profilleri yerel çekirdek kaydeder. Arayüz tercihleri bu tarayıcıda kalır.', browserStorage:'Profiller yalnızca bu tarayıcıya kaydedilir. Tarayıcı verilerini silmeden veya cihaz değiştirmeden önce dışa aktarın.', coreStorageBadge:'YEREL ÇEKİRDEK', browserStorageBadge:'BU TARAYICI', reconnect:'Yeniden bağlan', disconnected:'Çekirdek bağlantısı kesildi', disconnectedDesc:'Son çalışma durumu güncel değil. İşlemi kontrol etmek ve devam etmek için yeniden bağlanın.', disconnectedNotice:'Yerel çekirdekle bağlantı kesildi. İşlem durumu bilinmiyor; kaydedilmemiş çalışmanız burada duruyor.', offlineNotice:'Tarayıcı düzenleme modu. Profilleri kaydedip dışa aktarabilirsiniz; motor ve tanılama için yerel çekirdek gerekir.', connecting:'Yerel çekirdeğe bağlanılıyor…', connectedAgain:'Yerel çekirdeğe bağlanıldı', switchStore:'Yerel çekirdek kullanılabilir. Gerekiyorsa geçmeden önce tarayıcı profillerini dışa aktarın. Şimdi çekirdek profillerine geçilsin mi?', storageFailed:'Tarayıcı depolaması kullanılamıyor veya dolu. Değişiklikler kaydedilmedi. Kopyasını korumak için profili dışa aktarın.',
  platformCoverage:'Platform desteğine açık bir bakış', platformCoverageDesc:'Yerel çekirdek ve motor ayrı gereksinimlere sahiptir.', desktopCore:'Yerel çekirdek', partialCore:'Seçili motorlar', mobileEditor:'Tarayıcı düzenleyicisi', windowsSupport:'Yerel motor yönetimi. Paket araçları WinDivert ve yönetici yetkisi gerektirebilir.', linuxSupport:'Yerel motor yönetimi. Paket araçları ayrıca yapılandırılan güvenlik duvarı veya kuyruk kuralları gerektirir.', macSupport:'Seçili vekil sunucularla yerel çekirdek. Paket yakalama ve tünel kurulumu sınırlıdır veya haricidir.', bsdSupport:'Seçili motorlar ve derlemeler. BSD sürümünü ve paket yakalama gereksinimlerini kontrol edin.', androidSupport:'Bu arayüz tarayıcıda profil düzenler. Yerel VPN veya vekil sunucu entegrasyonu ayrı bir Android istemcisi gerektirir; pakete dahil değildir.', iosSupport:'Bu arayüz tarayıcıda profil düzenler. iOS bu masaüstü motor işlemlerini çalıştırmaz; ayrı ve yetkili bir yerel istemci kullanın.',
  managedIntegration:'YÖNETİLEN İŞLEM', externalIntegration:'HARİCİ KURULUM', includesLabel:'Dahil', excludesLabel:'Hariç', appRules:'Uygulama kuralları', supportedRule:'Uygulanır', unsupportedRule:'Harici / desteklenmiyor', createForEngine:'Profil oluştur', setupRequired:'Kurulum gerekli', engineAvailable:'Uyumlu platform', engineExternal:'Harici yönetim', platformUnknown:'Platformu kontrol et', engineSource:'Resmi kaynak', engineDocs:'Kurulum belgeleri', noArguments:'Ek parametre yok',
  configPath:'Harici yapılandırma dosyası (isteğe bağlı tam yol)', configPathHelp:'WireSock, sing-box ve Xray için gereklidir. Mevcut dosyalar değiştirilmeden kullanılır.', exclusionExamples:'Hariç tutma örneği ekle:', windowsUpdate:'Windows Update', rulesWarning:'Örnekler tüm sistem veya oyun trafiğini kapsamaz. Alan adı kuralları uygulama trafiğini tam olarak ayıramaz. Desteklenmeyen kurallar başlatmayı engeller.', supportedIncludes:'Bu adaptör dahil edilen alan adlarını uygular.', unsupportedIncludes:'Bu adaptör dahil edilen alan adlarını uygulamaz.', supportedExcludes:'Bu adaptör hariç tutulan alan adlarını uygular.', unsupportedExcludes:'Bu adaptör hariç tutulan alan adlarını uygulamaz.', appRulesNote:'Uygulama yolları planlama için saklanır; hiçbir adaptör bunları otomatik uygulamaz.', addedExclusions:'Hariç tutma örnekleri eklendi. Kullanmadan önce kapsamlarını inceleyin.', includeCount:'dahil', excludeCount:'hariç',
  preview:'Kurulumu kontrol et', launchReview:'BAŞLATMA İNCELEMESİ', reviewSetup:'Motor kurulumunu incele', editProfile:'Profili düzenle', startEngine:'Motoru başlat', launchConsent:'Başlatma, bu harici programı mevcut yetkilerinizle çalıştırır. Önce dosyayı, parametreleri ve harici yapılandırmayı inceleyin.', launchNotConnectivity:'Hazır olması bağlantıyı doğrulamaz.', checkingSetup:'Program ve profil kontrol ediliyor…', setupReady:'Başlatma önkoşulları bulundu', setupBlocked:'Başlatmadan önce çözün', executable:'Program dosyası', launchArguments:'Parametre listesi · kabuk yok', workingDirectory:'Çalışma dizini', warnings:'İnceleme notları', issues:'Kurulum sorunları', previewUnavailable:'Kurulum kontrolü için yerel çekirdek gerekir.', readyToConfigure:'Yapılandırın ve kurulumu kontrol edin',
  guideSpoof:'Uyumlu bir HTTP vekil sunucu derlemesi kullanın. Sistem vekil sunucu seçeneklerini inceleyin; bazı macOS sürümleri bu ayarları otomatik değiştirir.', guideByedpi:'Yerel SOCKS vekil sunucusu. Uygulamanın vekil sunucusunu ayrıca ayarlayın; başlatmak tüm cihazı yönlendirmez.', guideZapret:'Paket işleme için uyumlu yakalama kuralları veya sürücüler gerekir. Ağınızda test edilmiş bir strateji kullanın.', guideGoodbye:'WinDivert ile Windows paket işleme. Dahil listeleri uygulanır; hariç listeleri desteklenmez.', guideWiresock:'Resmi WireSock SDK istemcisini ve mevcut yapılandırmayı kullanın. Uygulama yönlendirmesi o dosyada ayarlanır. SDK üretici telemetrisi ve ayrı değerlendirme/ticari lisans koşulları içerir.', guideWireguard:'Tüneli platformun resmi araçlarıyla yönetin. AccessWeaver bu profili saklar ancak tünel yöneticisini çalıştırmaz.', guideProxy:'Kurulu program dosyanızı ve uygun yapılandırmayı belirtin. Vekil sunucu veya tünel yönlendirmesini ayrıca ayarlayın.',
  discardChanges:'Kaydedilmemiş profil değişiklikleri atılsın mı?', duplicateId:'Bu kimlik zaten var. Başka bir kimlik seçin veya mevcut profili düzenleyin.', immutableId:'Kayıtlı profil kimliği değiştirilemez. Bunun yerine profili çoğaltın.', invalidProfile:'Dosya tek bir profil nesnesi içermelidir.', unknownField:'Bilinmeyen alan', invalidField:'Geçersiz alan değeri', requiredField:'Gerekli alan', invalidVersion:'Profil sürümü 1 olmalıdır.', invalidId:'Harfle başlayan 2–63 küçük harf, rakam veya tire kullanın.', invalidEngine:'Kütüphaneden bir motor seçin.', invalidDomain:'URL veya boşluk olmadan ASCII/IDNA alan adı kullanın.', duplicateDomain:'Yinelenen alan adı', conflictingDomain:'Bir alan adı hem dahil hem hariç olamaz', invalidSHA:'SHA-256 tam olarak 64 onaltılık karakter içermelidir.', fileTooLarge:'Dosya 1 MiB sınırını aşıyor.', importReview:'İçe aktarılan profili inceleyip kaydedin. Mevcut profiller korunur.', importRenamed:'Bu kimlik zaten var. Yeni bir kimlik atandı; kopyayı inceleyip kaydedin.', saving:'Kaydediliyor…', unsavedChanges:'Kaydedilmemiş değişiklikler', newProfileName:'Özel profilim', customCategory:'Özel', copySuffix:'kopya', defaultDescription:'Düzenlenebilir motor yapılandırması',
  activeEdit:'Düzenlemeden önce etkin profili durdurun.', otherRunning:'Başka profil başlatmadan önce çalışan profili durdurun.', coreRequired:'Bu işlem bağlı bir yerel çekirdek gerektirir.', failedState:'Motor sonlandı', failedDesc:'Motor artık çalışmıyor. Yeniden başlatmadan önce çıktıyı ve kurulumu inceleyin.', exitError:'Motor çıktısı', exportReport:'Raporu dışa aktar', reportHost:'Test edilen sunucu', testPassed:'İstenen kontroller başarılı', testIncomplete:'Bir veya daha fazla kontrol başarısız', noProbe:'Dışa aktarılacak tanılama raporu yok', argsPrecision:'Her satır bir gerçek parametredir. JSON boş parametreleri ve boşlukları korunur.', profileSaved:'Profil kaydedildi', loading:'Yükleniyor…', refreshLogs:'Günlükleri yenile', storageRecovery:'Bazı tarayıcı profilleri okunamadı. Depolamada korundular. Onarmadan önce Ayarlar bölümünden yedeği dışa aktarın.', exportBrowserBackup:'Tarayıcı yedeğini dışa aktar', storageUnreadable:'Kayıtlı profil JSON verisi okunamıyor ve korundu. Tarayıcı depolamasını onarmadan önce Ayarlar bölümünden yedeği dışa aktarın.'
});

Object.assign(en,{systemTools:'Installation & repair',systemSubtitle:'Manage access methods, application routing and recovery.',inspectSystem:'Inspect system',systemBoundary:'Keep this dashboard unelevated. Review machine changes here, then apply the request with the separately elevated system apply CLI. Installed services stay active after closing the dashboard.',operation:'Operation',component:'Component or application',setupMode:'Setup mode',pureTunnel:'Alternative: WireSock only',combinedTunnel:'Standard: WireSock + ByeDPI DLL',customSetup:'Custom applications',splitSetup:'ByeDPI + ProxiFyre',dllSetup:'ByeDPI DLL for Discord',persistentService:'Persistent service',presetCollection:'Strategy preset',customArguments:'Custom arguments',applicationSelection:'Additional application names or folders (one per line)',includeBrowsers:'Include browsers',periodicReconnect:'Periodic WireSock reconnect',dnsMethod:'DNS method',leaveDNS:'Keep current DNS',scanLevel:'Strategy scan level',quickScan:'Quick',standardScan:'Standard',fullScan:'Full',enableListTask:'Enable hostlist / refresh task',cleanPTB:'Remove stable Discord when installing PTB',componentPaths:'Component paths and downloads',componentBundle:'Existing component bundle folder (optional)',privateConfig:'Existing private WireGuard configuration (optional)',managedProfile:'Managed profile name',officialDownload:'Official download URL (optional)',reviewOperation:'Review operation',operationReview:'Operation review',confirmSystemChanges:'I reviewed the operation and its system changes',applyOperation:'Apply reviewed operation',cancelOperation:'Cancel running operation',operationHistory:'History',operationResult:'Result & recovery'});
Object.assign(tr,{systemTools:'Kurulum ve onarım',systemSubtitle:'Erişim yöntemlerini, uygulama yönlendirmesini ve kurtarmayı yönetin.',inspectSystem:'Sistemi incele',systemBoundary:'Bu paneli yönetici olmadan kullanın. Sistem değişikliklerini burada inceleyin, ardından isteği ayrı olarak yönetici yetkisiyle açılan system apply komutuyla uygulayın. Kurulan hizmetler panel kapandıktan sonra da çalışır.',operation:'İşlem',component:'Bileşen veya uygulama',setupMode:'Kurulum yöntemi',pureTunnel:'Alternatif: yalnızca WireSock',combinedTunnel:'Standart: WireSock + ByeDPI DLL',customSetup:'Özel uygulamalar',splitSetup:'ByeDPI + ProxiFyre',dllSetup:'Discord için ByeDPI DLL',persistentService:'Kalıcı hizmet',presetCollection:'Strateji hazır ayarı',customArguments:'Özel parametreler',applicationSelection:'Ek uygulama adları veya klasörler (satır başına bir)',includeBrowsers:'Tarayıcıları dahil et',periodicReconnect:'WireSock bağlantısını düzenli yenile',dnsMethod:'DNS yöntemi',leaveDNS:'Mevcut DNS ayarını koru',scanLevel:'Strateji tarama seviyesi',quickScan:'Hızlı',standardScan:'Standart',fullScan:'Tam',enableListTask:'Alan adı listesini / yenileme görevini etkinleştir',cleanPTB:'PTB kurarken standart Discord sürümünü kaldır',componentPaths:'Bileşen yolları ve indirmeler',componentBundle:'Mevcut bileşen paketi klasörü (isteğe bağlı)',privateConfig:'Mevcut özel WireGuard yapılandırması (isteğe bağlı)',managedProfile:'Yönetilen profil adı',officialDownload:'Resmi indirme adresi (isteğe bağlı)',reviewOperation:'İşlemi incele',operationReview:'İşlem incelemesi',confirmSystemChanges:'İşlemi ve sistem değişikliklerini inceledim',applyOperation:'İncelenen işlemi uygula',cancelOperation:'Çalışan işlemi iptal et',operationHistory:'Geçmiş',operationResult:'Sonuç ve kurtarma'});

Object.assign(en,{apps:'Application names or folders (WireSock)',appRulesNote:'WireSock application rules are generated into a private configuration. Use Installation & repair for ProxiFyre and Secure Connect 3.x.'});
Object.assign(tr,{apps:'Uygulama adları veya klasörler (WireSock)',appRulesNote:'WireSock uygulama kuralları özel yapılandırmaya yazılır. ProxiFyre ve Secure Connect 3.x için Kurulum ve onarım bölümünü kullanın.'});
Object.assign(en,{cloudflareTerms:'I accept Cloudflare terms for new WARP account registration'});
Object.assign(tr,{cloudflareTerms:'Yeni WARP hesabı kaydı için Cloudflare koşullarını kabul ediyorum'});
Object.assign(en,{chooseFolder:'Add folder',clearApplications:'Clear application list',scanTargets:'Scan targets (one hostname per line)',recoveryJournal:'Recovery journal filename',onceMode:'One-shot run'});
Object.assign(tr,{chooseFolder:'Klasör ekle',clearApplications:'Uygulama listesini temizle',scanTargets:'Tarama hedefleri (her satırda bir sunucu adı)',recoveryJournal:'Kurtarma günlüğü dosya adı',onceMode:'Tek seferlik çalıştır'});
Object.assign(en,{updateAvailable:'Update available'});
Object.assign(tr,{updateAvailable:'Güncelleme mevcut'});

Object.assign(en,{jsonPreviewLimited:'Preview shortened. Export the corresponding JSON to read all details.',exportSystemStatus:'Export latest status',exportSystemHistory:'Export full history',systemExportPrivacy:'These exports can contain private configuration, paths and tool output. Store them privately. Nothing is uploaded.',systemExportFailed:'Could not export this report.',systemExportTooLarge:'The report exceeds the download size limit.'});
Object.assign(tr,{jsonPreviewLimited:'Önizleme kısaltıldı. Tüm ayrıntıları okumak için ilgili JSON dosyasını dışa aktarın.',exportSystemStatus:'Son durumu dışa aktar',exportSystemHistory:'Tüm geçmişi dışa aktar',systemExportPrivacy:'Bu dosyalar özel yapılandırma, yollar ve araç çıktıları içerebilir. Güvenli bir yerde saklayın. Hiçbir yere yüklenmez.',systemExportFailed:'Bu rapor dışa aktarılamadı.',systemExportTooLarge:'Rapor indirme boyutu sınırını aşıyor.'});
Object.assign(en,{exportSystemRequest:'Export reviewed request',exportSystemRequestNote:'Request files can contain private paths or arguments. Store them privately, review them again in the CLI, and confirm separately.'});
Object.assign(tr,{exportSystemRequest:'İncelenen isteği dışa aktar',exportSystemRequestNote:'İstek dosyaları özel yollar veya parametreler içerebilir. Güvenli bir yerde saklayın, komut satırında yeniden inceleyin ve ayrıca onaylayın.'});

Object.assign(en,{supportSummary:'Support summary',exportSupportSummary:'Export support summary',supportSummaryDesc:'Export build identity, counts and status labels. Profile contents, identifiers, paths, logs and credentials are excluded. Nothing is uploaded.'});
Object.assign(tr,{supportSummary:'Destek özeti',exportSupportSummary:'Destek özetini dışa aktar',supportSummaryDesc:'Derleme kimliğini, sayıları ve durum etiketlerini dışa aktarır. Profil içerikleri, kimlikleri, yollar, günlükler ve kimlik bilgileri dahil edilmez. Hiçbir yere yüklenmez.'});
Object.assign(en,{shutdownPending:'Shutdown unconfirmed',shutdownPendingDesc:'The previous engine has not been confirmed stopped. Starting another engine is blocked. You can still edit profiles and view logs.',shutdownPendingBadge:'SHUTDOWN UNCONFIRMED'});
Object.assign(tr,{shutdownPending:'Kapanış doğrulanmadı',shutdownPendingDesc:'Önceki motorun durduğu doğrulanmadı. Başka bir motor başlatılamaz. Profilleri düzenleyebilir ve günlükleri görüntüleyebilirsiniz.',shutdownPendingBadge:'KAPANIŞ DOĞRULANMADI'});

const storage = {
  get(key) { try { return localStorage.getItem(key); } catch { return null; } },
  set(key, value) { localStorage.setItem(key, value); },
  preference(key, value) { try { this.set(key, value); } catch { /* Preferences remain usable for this session. */ } }
};
Object.assign(en,{"historyListTitle":"History records","historyPreviewTitle":"Record preview","historyLargePreview":"This record is too large for the desktop preview. Download the exact raw record to inspect all bytes privately.","historyTitle":"Workflow history","historyCaptureNotice":"Capture private history metadata before browsing. Capturing does not delete records or recovery evidence.","historyCapture":"Capture history","historyRefresh":"Reload capture","historyRecord":"Record","historyState":"State","historyTime":"Recorded time","historySize":"Size","historyClassification":"Record type","historyProtection":"Protection","historyPrevious":"Previous page","historyNext":"Next page","historyRawPrivacy":"Raw records can contain private configuration, paths, errors and tool output. Nothing is uploaded. Store downloads privately.","historyExportRecord":"Download exact raw record","historyProtected":"Recovery evidence is protected. Record retirement is not available.","historyUnknown":"Unknown","historyBytes":"bytes","historyLegacyRecord":"Retained record","historyUnknownOperation":"Unknown operation","historyNoCapture":"No history capture is loaded. Existing records remain unchanged.","historyInventorySummary":"Capture: {count} entries, {size}. Created {at}.","historyPageSummary":"Showing {count} entries from this capture.","historyEmpty":"This capture contains no entries.","historyDetailTitle":"Record: {record}","historyDetailLoading":"Loading the exact selected record…","historyRawUnavailable":"This item cannot be safely read as a bounded regular record. Its evidence remains unchanged.","historyDetailUnavailable":"A structured preview is unavailable. Download the exact raw record to inspect it privately.","historyCapturing":"Capturing private history metadata… Existing evidence will not be deleted.","historyLoading":"Loading captured history…","historyCaptureNeeded":"History needs a new capture. Select Capture history; existing records remain unchanged.","historyRecordUnavailable":"The selected record is unavailable. Capture history again to review its current state.","historyRequestEnded":"The history request ended before completion. Try again; no records were deleted.","historyCapacity":"History exceeds the inspection limits. All records and recovery evidence remain retained.","historyBusy":"History is busy. Try again shortly; no operation will be repeated automatically.","historyInvalidResponse":"The history response could not be verified. No download was created.","historyFailed":"History could not be read. Existing records and recovery evidence remain unchanged.","historyClass_canonical":"Recognized record","historyClass_legacy":"Legacy record","historyClass_malformed":"Invalid JSON record","historyClass_oversized":"Above inspection limit","historyClass_special":"Unsupported file type","historyClass_unreadable":"Unreadable record","historyState_running":"Running","historyState_succeeded":"Succeeded","historyState_failed":"Failed","historyState_interrupted":"Interrupted","historyState_unknown":"Unknown","historyCancelCapture":"Cancel capture request","historyCaptureCanceled":"Capture request canceled. Existing records and recovery evidence remain unchanged. Reload the capture to check for completed metadata."});
Object.assign(tr,{"historyListTitle":"Geçmiş kayıtları","historyPreviewTitle":"Kayıt önizlemesi","historyLargePreview":"Bu kayıt, masaüstü önizlemesi için çok büyük. Tüm baytları özel olarak incelemek için ham kaydı olduğu gibi indirin.","historyTitle":"İşlem geçmişi","historyCaptureNotice":"Göz atmadan önce özel geçmiş meta verilerini kaydedin. Bu işlem kayıtları veya kurtarma kanıtlarını silmez.","historyCapture":"Geçmiş görüntüsü oluştur","historyRefresh":"Görüntüyü yeniden yükle","historyRecord":"Kayıt","historyState":"Durum","historyTime":"Kayıt zamanı","historySize":"Boyut","historyClassification":"Kayıt türü","historyProtection":"Koruma","historyPrevious":"Önceki sayfa","historyNext":"Sonraki sayfa","historyRawPrivacy":"Ham kayıtlar özel yapılandırma, yollar, hatalar ve araç çıktıları içerebilir. Hiçbir veri yüklenmez. İndirilen dosyaları gizli tutun.","historyExportRecord":"Ham kaydı olduğu gibi indir","historyProtected":"Kurtarma kanıtları korunuyor. Kayıtları kaldırma özelliği henüz kullanılamıyor.","historyUnknown":"Bilinmiyor","historyBytes":"bayt","historyLegacyRecord":"Korunan kayıt","historyUnknownOperation":"Bilinmeyen işlem","historyNoCapture":"Geçmiş görüntüsü yüklenmedi. Mevcut kayıtlar değişmeden korunur.","historyInventorySummary":"Görüntü: {count} öğe, {size}. Oluşturulma: {at}.","historyPageSummary":"Bu görüntüdeki {count} öğe gösteriliyor.","historyEmpty":"Bu görüntüde öğe yok.","historyDetailTitle":"Kayıt: {record}","historyDetailLoading":"Seçilen kayıt olduğu gibi yükleniyor…","historyRawUnavailable":"Bu öğe, boyutu sınırlı normal bir kayıt olarak güvenle okunamıyor. Kanıtlar değişmeden korunur.","historyDetailUnavailable":"Yapılandırılmış önizleme kullanılamıyor. Özel olarak incelemek için ham kaydı olduğu gibi indirin.","historyCapturing":"Özel geçmiş meta verileri kaydediliyor… Mevcut kanıtlar silinmez.","historyLoading":"Kaydedilen geçmiş yükleniyor…","historyCaptureNeeded":"Yeni bir geçmiş görüntüsü gerekiyor. Geçmiş görüntüsü oluştur seçeneğini kullanın; mevcut kayıtlar değişmez.","historyRecordUnavailable":"Seçilen kayıt kullanılamıyor. Güncel durumunu incelemek için geçmişi yeniden kaydedin.","historyRequestEnded":"Geçmiş isteği tamamlanmadan sona erdi. Yeniden deneyin; hiçbir kayıt silinmedi.","historyCapacity":"Geçmiş, inceleme sınırlarını aşıyor. Tüm kayıtlar ve kurtarma kanıtları korunur.","historyBusy":"Geçmiş şu anda meşgul. Biraz sonra yeniden deneyin; hiçbir işlem otomatik tekrarlanmaz.","historyInvalidResponse":"Geçmiş yanıtı doğrulanamadı. İndirme dosyası oluşturulmadı.","historyFailed":"Geçmiş okunamadı. Mevcut kayıtlar ve kurtarma kanıtları değişmeden korunur.","historyClass_canonical":"Tanınan kayıt","historyClass_legacy":"Eski biçimli kayıt","historyClass_malformed":"Geçersiz JSON kaydı","historyClass_oversized":"İnceleme sınırını aşıyor","historyClass_special":"Desteklenmeyen dosya türü","historyClass_unreadable":"Okunamayan kayıt","historyState_running":"Çalışıyor","historyState_succeeded":"Başarılı","historyState_failed":"Başarısız","historyState_interrupted":"Kesintiye uğradı","historyState_unknown":"Bilinmiyor","historyCancelCapture":"Görüntü oluşturma isteğini iptal et","historyCaptureCanceled":"Görüntü oluşturma isteği iptal edildi. Mevcut kayıtlar ve kurtarma kanıtları değişmedi. Tamamlanan meta verileri denetlemek için görüntüyü yeniden yükleyin."});
const state = {
  profileEditingOnly:false,
  lang: ['en','tr','ru','es'].includes(storage.get('aw.lang')) ? storage.get('aw.lang') : 'en',
  theme: storage.get('aw.theme') === 'light' ? 'light' : 'dark',
  offline: false, disconnected: false, loading: true, coreAuthenticated: false, platform: 'unknown',
  engines: [], profiles: [], runtime: {state:'stopped', log:[]}, token:'',
  view:'dashboard', profileGridRendered:false, editing:null, editorTab:'simple', lastProbe:null,
  launch:null, busy:false, polling:false, reconnecting:false, preservedProfiles:[], storageBlocked:false
};
Object.assign(en,{"lifecycleTitle":"Completion tracking","lifecycleRefresh":"Refresh completion status","lifecycleNotice":"Tracks local worker and record closure only. It does not certify vendor changes or permit deleting recovery evidence.","lifecycleNotLoaded":"Completion status has not been read. Existing evidence is unchanged.","lifecycleLoading":"Reading local completion evidence…","lifecycleState_none":"No local completion receipt is tracked. Legacy evidence remains protected; this is not an admission or storage-capacity grant.","lifecycleState_intent":"A local workflow intent is unresolved. Preserve its inputs and recovery evidence.","lifecycleState_sealed":"A local result is sealed, but owner release is unconfirmed. Preserve recovery evidence.","lifecycleState_released":"Local worker, record and original lease closure was observed. Vendor cleanup and evidence retirement are not certified.","lifecycleState_blocked":"Local completion evidence requires inspection. New workflow admission is blocked.","lifecycleAdmissionBlocked":"New workflows are blocked by unresolved local completion evidence. Keep the inputs and recovery evidence; history inspection and current-job cancellation remain available. Nothing is retried automatically.","lifecycleGeneration":"Tracked workflow","lifecycleBusy":"Completion status is busy or unavailable. Try this read again; no operation was retried.","lifecycleEnded":"The completion status request ended. Evidence is unchanged.","lifecycleUnavailable":"Completion status could not be verified. No clean completion is assumed."});
Object.assign(tr,{"lifecycleTitle":"Tamamlanma takibi","lifecycleRefresh":"Tamamlanma durumunu yenile","lifecycleNotice":"Yalnızca yerel çalışan ve kayıt kapanışını izler. Üretici değişikliklerini doğrulamaz ve kurtarma kanıtlarını silme izni vermez.","lifecycleNotLoaded":"Tamamlanma durumu okunmadı. Mevcut kanıtlar değişmedi.","lifecycleLoading":"Yerel tamamlanma kanıtları okunuyor…","lifecycleState_none":"İzlenen yerel tamamlanma kaydı yok. Eski kanıtlar korunur; bu durum yeni işlem veya depolama kapasitesi izni değildir.","lifecycleState_intent":"Yerel işlem niyeti çözümlenmedi. Girdileri ve kurtarma kanıtlarını koruyun.","lifecycleState_sealed":"Yerel sonuç mühürlendi ancak sahiplerin bırakıldığı doğrulanmadı. Kurtarma kanıtlarını koruyun.","lifecycleState_released":"Yerel çalışan, kayıt ve ilk kilit sahipliğinin kapanışı gözlendi. Üretici temizliği ve kanıt kaldırma izni doğrulanmaz.","lifecycleState_blocked":"Yerel tamamlanma kanıtları incelenmeli. Yeni işlem kabulü engellendi.","lifecycleAdmissionBlocked":"Çözümlenmemiş yerel tamamlanma kanıtları yeni işlemleri engelliyor. Girdileri ve kurtarma kanıtlarını koruyun; geçmiş incelemesi ve çalışan işlemi iptal etme kullanılabilir. Hiçbir işlem otomatik tekrarlanmaz.","lifecycleGeneration":"İzlenen işlem","lifecycleBusy":"Tamamlanma durumu meşgul veya kullanılamıyor. Okumayı yeniden deneyin; hiçbir işlem tekrarlanmadı.","lifecycleEnded":"Tamamlanma durumu isteği sona erdi. Kanıtlar değişmedi.","lifecycleUnavailable":"Tamamlanma durumu doğrulanamadı. Temiz kapanış varsayılmaz."});
const probeUI={generation:0,context:'',operation:null,completed:null,notice:'',failure:''};
Object.assign(en,{"probeCancel":"Cancel test","probeCanceled":"Cancellation requested. Inputs are kept. Incomplete results are discarded; no test is retried automatically.","probeInputsCleared":"Inputs changed. Previous diagnostic results were cleared. Start a test explicitly.","probeContextCleared":"The connection, session or desktop mode changed. Previous diagnostic results were cleared. Inputs are kept.","probeViewCleared":"Diagnostic view closed. Inputs are kept and previous results were cleared. No test is retried automatically.","probeBusy":"Another diagnostic is active or still finishing. Inputs are kept. Wait, then start a test explicitly; nothing is retried automatically.","probeRequestEnded":"The diagnostic request ended before completion. Inputs are kept. Start another test explicitly."});
Object.assign(tr,{"probeCancel":"Testi iptal et","probeCanceled":"İptal istendi. Girdiler korunur. Tamamlanmamış sonuçlar atılır; hiçbir test otomatik tekrarlanmaz.","probeInputsCleared":"Girdiler değişti. Önceki tanılama sonuçları temizlendi. Testi açıkça yeniden başlatın.","probeContextCleared":"Bağlantı, oturum veya masaüstü modu değişti. Önceki tanılama sonuçları temizlendi. Girdiler korunur.","probeViewCleared":"Tanılama görünümü kapatıldı. Girdiler korundu ve önceki sonuçlar temizlendi. Hiçbir test otomatik tekrarlanmaz.","probeBusy":"Başka bir tanılama çalışıyor veya hâlâ tamamlanıyor. Girdiler korunur. Bekleyip testi açıkça başlatın; otomatik yeniden deneme yapılmaz.","probeRequestEnded":"Tanılama isteği tamamlanmadan sona erdi. Girdiler korunur. Yeni bir testi açıkça başlatın."});
Object.assign(en,{"reconcileTitle":"Review local closure","reconcileRefresh":"Refresh reconciliation status","reconcileNotice":"Review positive local ownership evidence before recording release. This does not certify vendor cleanup, erase records or permit retirement.","reconcileGenerationInput":"Workflow identifier (optional: current)","reconcileOperationInput":"Known reconciliation identifier","reconcileInputNote":"Use identifiers returned by this app. Unknown or crashed owners cannot be assumed released. Inspection and current-job cancellation remain available.","reconcileReviewCurrent":"Review local release","reconcileReviewResume":"Review resuming this operation","reconcileReadReceipt":"Read operation receipt","reconcileStopReceipt":"Stop checking receipt","reconcileReviewTitle":"Review before applying","reconcileReviewNotice":"Only the reviewed local release is reconciled. Original workflow failures and recovery evidence remain preserved.","reconcileConsent":"I reviewed this local release, its identifiers and preserved metadata. Apply it once.","reconcileApply":"Apply reviewed reconciliation","reconcileReceiptTitle":"Completed local receipt","reconcileReceiptNotice":"This confirms only original local owner release. The original workflow outcome is unchanged; vendor state and retirement remain unverified.","reconcileObjects":"Closed metadata stages to preserve","reconcilePreservedObjects":"Metadata stages retained by the operation","reconcileObjectRef":"Object reference","reconcileDigest":"Fingerprint","reconcileGeneration":"Workflow identifier","reconcileOperation":"Reconciliation identifier","reconcileExpires":"Review expires","reconcileRevision":"Review fingerprint","reconcileCompletedAt":"Local completion recorded","reconcileRole":"Closed acknowledgment metadata","reconcileNotLoaded":"No reconciliation review is loaded. Existing evidence is unchanged.","reconcileReadingStatus":"Reading local reconciliation status…","reconcileReviewing":"Reading exact local evidence for review… No release is applied yet.","reconcileReviewReady":"Review the exact identifiers and preserved metadata, then give separate consent to apply once.","reconcileApplying":"Applying this reviewed local reconciliation once. Leaving stops browser waiting, not a committed operation; keep its identifier.","reconcileReadingReceipt":"Reading the exact operation receipt…","reconcileReceiptPending":"No completed receipt yet. Checking this identifier read-only; stopping checks does not undo the operation.","reconcileStillPending":"No completed receipt was observed. Keep the identifier and evidence. Read again or explicitly review resumption; Apply is never replayed automatically.","reconcileReceiptNeeded":"Keep the reconciliation identifier. Read its receipt to confirm the local outcome. Pending work needs a new explicit resume review; Apply is never replayed automatically.","reconcileWatchStopped":"Receipt checks stopped. The identifier and evidence are retained; no operation was undone or repeated.","reconcileCompleted":"Reviewed local closure is recorded. Original outcomes and evidence remain preserved; this is not vendor cleanup or retirement approval.","reconcileState_none":"No current reconciliation operation is tracked. Legacy evidence remains protected.","reconcileState_available":"Positive local proof is available for explicit review. This is not an automatic release or an admission grant.","reconcileState_pending":"A reconciliation intent is pending. Read its known receipt; resumption always needs a fresh review.","reconcileState_completed":"A completed local receipt is available for inspection. It does not change the original workflow outcome.","reconcileState_unavailable":"Positive local ownership proof is unavailable. Preserve the original evidence.","reconcileInvalidResponse":"The reconciliation response could not be verified. No release is assumed.","reconcileInvalid":"Use valid identifiers and review the operation again.","reconcileUnavailable":"Positive local ownership proof is unavailable. A new session cannot assume crashed owners released their resources; preserve the evidence.","reconcileConflict":"Local evidence changed. Review it again; no Apply request is replayed.","reconcileExpired":"The review expired. Consent is cleared; review again before applying.","reconcilePending":"The operation is incomplete. Preserve its identifier and read its receipt before reviewing any resumption.","reconcileDenied":"Administrator policy does not permit lifecycle reconciliation. Other profile permissions do not grant it.","reconcilePolicyUnavailable":"Administrator policy could not be verified. Reconciliation remains unavailable.","reconcileEnded":"The browser request ended before a confirmed response. Preserve known operation identifiers and inspect receipts.","reconcileBusy":"Local reconciliation is busy. Try the read or review explicitly later; no mutation is queued or replayed.","reconcileStoreUnavailable":"Local reconciliation storage could not be verified. Preserve its evidence and known identifiers."});
Object.assign(tr,{"reconcileTitle":"Yerel kapanışı incele","reconcileRefresh":"Uzlaştırma durumunu yenile","reconcileNotice":"Bırakmayı kaydetmeden önce yerel sahiplik kanıtını inceleyin. Bu işlem üretici temizliğini doğrulamaz, kayıtları silmez veya kaldırma izni vermez.","reconcileGenerationInput":"İşlem kimliği (isteğe bağlı: geçerli işlem)","reconcileOperationInput":"Bilinen uzlaştırma kimliği","reconcileInputNote":"Bu uygulamanın verdiği kimlikleri kullanın. Bilinmeyen veya çöken sahiplerin bırakıldığı varsayılamaz. İnceleme ve çalışan işlemi iptal etme kullanılabilir.","reconcileReviewCurrent":"Yerel bırakmayı incele","reconcileReviewResume":"Bu işlemi sürdürmeyi incele","reconcileReadReceipt":"İşlem makbuzunu oku","reconcileStopReceipt":"Makbuzu denetlemeyi durdur","reconcileReviewTitle":"Uygulamadan önce inceleyin","reconcileReviewNotice":"Yalnızca incelenen yerel bırakma uzlaştırılır. İlk işlem hataları ve kurtarma kanıtları korunur.","reconcileConsent":"Bu yerel bırakmayı, kimliklerini ve korunan meta verileri inceledim. Bir kez uygula.","reconcileApply":"İncelenen uzlaştırmayı uygula","reconcileReceiptTitle":"Tamamlanan yerel makbuz","reconcileReceiptNotice":"Bu makbuz yalnızca ilk yerel sahiplerin bırakılmasını doğrular. İlk işlem sonucu değişmez; üretici durumu ve kayıt kaldırma doğrulanmaz.","reconcileObjects":"Korunacak kapalı meta veri aşamaları","reconcilePreservedObjects":"İşlemin koruduğu meta veri aşamaları","reconcileObjectRef":"Nesne referansı","reconcileDigest":"Parmak izi","reconcileGeneration":"İşlem kimliği","reconcileOperation":"Uzlaştırma kimliği","reconcileExpires":"İncelemenin bitişi","reconcileRevision":"İnceleme parmak izi","reconcileCompletedAt":"Yerel tamamlanma kaydı","reconcileRole":"Kapalı onay meta verisi","reconcileNotLoaded":"Uzlaştırma incelemesi yüklenmedi. Mevcut kanıtlar değişmedi.","reconcileReadingStatus":"Yerel uzlaştırma durumu okunuyor…","reconcileReviewing":"İnceleme için yerel kanıtlar okunuyor… Henüz bırakma uygulanmadı.","reconcileReviewReady":"Tam kimlikleri ve korunacak meta verileri inceleyin; bir kez uygulamak için ayrı onay verin.","reconcileApplying":"İncelenen yerel uzlaştırma bir kez uygulanıyor. Ayrılmak tarayıcı beklemesini durdurur, kaydedilmiş işlemi değil; kimliği saklayın.","reconcileReadingReceipt":"İşlem makbuzu olduğu gibi okunuyor…","reconcileReceiptPending":"Tamamlanan makbuz henüz yok. Bu kimlik salt okunur olarak denetleniyor; denetimi durdurmak işlemi geri almaz.","reconcileStillPending":"Tamamlanan makbuz gözlenmedi. Kimliği ve kanıtları saklayın. Yeniden okuyun veya sürdürmeyi açıkça inceleyin; Uygula otomatik tekrarlanmaz.","reconcileReceiptNeeded":"Uzlaştırma kimliğini saklayın. Yerel sonucu doğrulamak için makbuzu okuyun. Bekleyen iş için yeni ve açık bir sürdürme incelemesi gerekir; Uygula otomatik tekrarlanmaz.","reconcileWatchStopped":"Makbuz denetimi durduruldu. Kimlik ve kanıtlar korunur; hiçbir işlem geri alınmadı veya tekrarlanmadı.","reconcileCompleted":"İncelenen yerel kapanış kaydedildi. İlk sonuçlar ve kanıtlar korunur; bu işlem üretici temizliği veya kayıt kaldırma onayı değildir.","reconcileState_none":"İzlenen geçerli uzlaştırma işlemi yok. Eski kanıtlar korunur.","reconcileState_available":"Açık inceleme için olumlu yerel kanıt mevcut. Bu durum otomatik bırakma veya yeni işlem izni değildir.","reconcileState_pending":"Uzlaştırma niyeti bekliyor. Bilinen makbuzu okuyun; sürdürmek her zaman yeni inceleme gerektirir.","reconcileState_completed":"İncelemek için tamamlanmış yerel makbuz mevcut. İlk işlem sonucunu değiştirmez.","reconcileState_unavailable":"Olumlu yerel sahiplik kanıtı kullanılamıyor. İlk kanıtları koruyun.","reconcileInvalidResponse":"Uzlaştırma yanıtı doğrulanamadı. Bırakma varsayılmaz.","reconcileInvalid":"Geçerli kimlikler kullanıp işlemi yeniden inceleyin.","reconcileUnavailable":"Olumlu yerel sahiplik kanıtı kullanılamıyor. Yeni bir oturum, çöken sahiplerin kaynaklarını bıraktığını varsayamaz; kanıtları koruyun.","reconcileConflict":"Yerel kanıtlar değişti. Yeniden inceleyin; Uygula isteği tekrarlanmaz.","reconcileExpired":"İncelemenin süresi doldu. Onay temizlendi; uygulamadan önce yeniden inceleyin.","reconcilePending":"İşlem tamamlanmadı. Sürdürmeyi incelemeden önce kimliğini koruyup makbuzunu okuyun.","reconcileDenied":"Yönetici ilkesi yaşam döngüsü uzlaştırmasına izin vermiyor. Diğer profil izinleri bu yetkiyi vermez.","reconcilePolicyUnavailable":"Yönetici ilkesi doğrulanamadı. Uzlaştırma kullanılamıyor.","reconcileEnded":"Tarayıcı isteği doğrulanmış yanıttan önce sona erdi. Bilinen işlem kimliklerini koruyup makbuzları inceleyin.","reconcileBusy":"Yerel uzlaştırma meşgul. Okumayı veya incelemeyi daha sonra açıkça deneyin; hiçbir değişiklik kuyruğa alınmaz veya tekrarlanmaz.","reconcileStoreUnavailable":"Yerel uzlaştırma depolaması doğrulanamadı. Kanıtları ve bilinen kimlikleri koruyun."});
Object.assign(en,{reconcileIntentDigest:'Intent SHA-256',reconcileSealDigest:'Seal SHA-256',reconcileAckDigest:'Release acknowledgment SHA-256'});
Object.assign(tr,{reconcileIntentDigest:'Niyet SHA-256',reconcileSealDigest:'Mühür SHA-256',reconcileAckDigest:'Bırakma onayı SHA-256'});
Object.assign(en,{historyStagingPending:'An incomplete inventory capture has retained metadata. Another capture cannot start. Existing records remain protected. A previous view and selected detail are restored only after fresh revision checks. No deletion, repair or retry occurs automatically.'});
Object.assign(tr,{historyStagingPending:'Tamamlanmamış bir envanter kaydının meta verileri korunuyor. Yeni kayıt başlatılamaz. Mevcut kayıtlar korunur. Önceki görünüm ve seçili ayrıntı yalnızca güncel sürüm denetimlerinden sonra geri yüklenir. Silme, onarım veya yeniden deneme otomatik yapılmaz.'});
Object.assign(en,{"controllerStorageTitle":"Controller evidence storage","controllerStorageRefresh":"Refresh storage observation","controllerStorageNotice":"Planned controller evidence per workflow start and its original completion metadata only. History capture, reconciliation maintenance and legacy or untracked files are excluded. Logical commitments do not measure disk usage or free space.","controllerStorageLimits":"This status does not enforce an aggregate quota, guarantee physical space, contain native writers or bound worker journals. It grants no admission, deletion, cleanup or retirement.","controllerStorageNotLoaded":"Storage observation has not been read. Existing evidence is unchanged.","controllerStorageLoading":"Reading controller storage commitments…","controllerStorageState_uninitialized":"Controller tracking is not initialized. Legacy and untracked evidence is not included; this does not mean the disk is empty.","controllerStorageState_tracked":"Tracked controller commitments are reported. This observation does not authorize a new operation or certify completed finalization.","controllerStorageState_pending":"Tracked storage has unresolved commitments. A zero reservation is not evidence of free space. Preserve inputs and evidence; finalization and ownership are not assumed complete.","controllerStorageGenerations":"Tracked generations","controllerStorageReserved":"Reserved logical bytes","controllerStorageRetained":"Retained logical charge","controllerStorageUncertain":"Uncertain logical charge","controllerStorageFinalization":"Logical allowance for finalization","controllerStorageGeneration":"Tracked generation","controllerStorageFolderAction":"Choose an application folder","controllerStorageInvalidResponse":"The storage response could not be verified. No clean or empty state is assumed.","controllerStorageDenied":"Administrator policy does not permit this storage inspection.","controllerStoragePolicyUnavailable":"Administrator policy could not be verified. Storage inspection remains unavailable.","controllerStorageBusy":"Storage observation is busy. Refresh explicitly later; no operation is queued or repeated.","controllerStorageEnded":"The storage request ended before confirmation. Existing evidence and operation inputs remain preserved.","controllerStoragePending":"Controller storage evidence is pending or unconfirmed. Preserve it; no completed finalization or admission is assumed.","controllerStorageCapacity":"Reported controller commitments exceed a source limit. This does not measure available physical space. Preserve the evidence.","controllerStorageUnavailable":"Controller storage commitments could not be verified. No clean or empty state is assumed.","controllerStorageAdmissionCapacity":"Controller storage limits refused the request. Inputs and recovery selections are preserved; consent was cleared. Inspect storage and explicitly request a new review. Nothing is queued or replayed.","controllerStorageAdmissionPending":"Controller storage requires explicit review. Keep the inputs and evidence. Status alone cannot clear this refusal; request a new operation review explicitly. Backend admission checks still apply. Nothing is retried automatically."});
Object.assign(tr,{"controllerStorageTitle":"Denetleyici kanıt depolaması","controllerStorageRefresh":"Depolama gözlemini yenile","controllerStorageNotice":"Yalnızca her işlem başlangıcı için planlanan denetleyici kanıtı ve ilk tamamlanma meta verileri. Geçmiş görüntüsü, uzlaştırma bakımı, eski veya izlenmeyen dosyalar dahil değildir. Mantıksal taahhütler disk kullanımı veya boş alanı ölçmez.","controllerStorageLimits":"Bu durum toplam kota uygulamaz, fiziksel alanı garanti etmez, yerel yazıcıları sınırlamaz veya çalışan günlüklerine sınır koymaz. Başlatma, silme, temizleme veya kayıt kaldırma izni vermez.","controllerStorageNotLoaded":"Depolama gözlemi okunmadı. Mevcut kanıtlar değişmedi.","controllerStorageLoading":"Denetleyici depolama taahhütleri okunuyor…","controllerStorageState_uninitialized":"Denetleyici takibi başlatılmadı. Eski ve izlenmeyen kanıtlar dahil değildir; bu, diskin boş olduğu anlamına gelmez.","controllerStorageState_tracked":"İzlenen denetleyici taahhütleri gösteriliyor. Bu gözlem yeni işlem izni vermez veya sonlandırmanın tamamlandığını doğrulamaz.","controllerStorageState_pending":"İzlenen depolama taahhütleri çözümlenmedi. Sıfır rezerv, boş alan kanıtı değildir. Girdileri ve kanıtları koruyun; sonlandırma ve sahipliğin tamamlandığı varsayılmaz.","controllerStorageGenerations":"İzlenen nesiller","controllerStorageReserved":"Ayrılan mantıksal baytlar","controllerStorageRetained":"Korunan mantıksal yük","controllerStorageUncertain":"Belirsiz mantıksal yük","controllerStorageFinalization":"Sonlandırma için mantıksal pay","controllerStorageGeneration":"İzlenen nesil","controllerStorageFolderAction":"Uygulama klasörü seç","controllerStorageInvalidResponse":"Depolama yanıtı doğrulanamadı. Temiz veya boş durum varsayılmaz.","controllerStorageDenied":"Yönetici ilkesi bu depolama incelemesine izin vermiyor.","controllerStoragePolicyUnavailable":"Yönetici ilkesi doğrulanamadı. Depolama incelemesi kullanılamıyor.","controllerStorageBusy":"Depolama gözlemi meşgul. Daha sonra açıkça yenileyin; işlem kuyruğa alınmaz veya tekrarlanmaz.","controllerStorageEnded":"Depolama isteği doğrulanmadan sona erdi. Mevcut kanıtlar ve işlem girdileri korunur.","controllerStoragePending":"Denetleyici depolama kanıtları bekliyor veya doğrulanmadı. Koruyun; sonlandırma veya işlem izni varsayılmaz.","controllerStorageCapacity":"Bildirilen denetleyici taahhütleri kaynak sınırını aşıyor. Bu, fiziksel boş alanı ölçmez. Kanıtları koruyun.","controllerStorageUnavailable":"Denetleyici depolama taahhütleri doğrulanamadı. Temiz veya boş durum varsayılmaz.","controllerStorageAdmissionCapacity":"Denetleyici depolama sınırları isteği reddetti. Girdiler ve kurtarma seçimleri korundu; onay temizlendi. Depolamayı inceleyip açıkça yeni inceleme isteyin. İşlem kuyruğa alınmaz veya tekrarlanmaz.","controllerStorageAdmissionPending":"Denetleyici depolaması açık inceleme gerektiriyor. Girdileri ve kanıtları koruyun. Yalnız durum okumak bu reddi temizlemez; açıkça yeni işlem incelemesi isteyin. Sunucu kabul denetimleri geçerlidir. Otomatik yeniden deneme yapılmaz."});
const translations = {en,tr,...(typeof extraLocales==='object'?extraLocales:{})};
const diagnosticCopy = {"en": {"diagnosticsSubtitle": "Check an explicit direct or proxy path using TCP/TLS or UDP/STUN.", "probePath": "Network path", "probeTransport": "Protocol", "pathDirect": "Direct", "probeProxy": "Proxy host:port (no credentials)", "probeScope": "The selected path only. No direct fallback. This does not prove engine routing, voice or QUIC connectivity.", "probeSTUN": "Enter a STUN server you trust. One UDP binding exchange; the server and reported address are unauthenticated.", "reportPath": "Tested path"}, "tr": {"diagnosticsSubtitle": "TCP/TLS veya UDP/STUN ile do\u011frudan ya da vekil sunucu yolunu test edin.", "probePath": "A\u011f yolu", "probeTransport": "Protokol", "pathDirect": "Do\u011frudan", "probeProxy": "Vekil sunucu:port (kimlik bilgisi yok)", "probeScope": "Yaln\u0131zca se\u00e7ilen yol test edilir. Do\u011frudan ba\u011flant\u0131ya ge\u00e7ilmez. Motor y\u00f6nlendirmesi, ses veya QUIC ba\u011flant\u0131s\u0131n\u0131 kan\u0131tlamaz.", "probeSTUN": "G\u00fcvendi\u011finiz bir STUN sunucusu girin. Tek UDP iste\u011fi; sunucu ve bildirdi\u011fi adres do\u011frulanmaz.", "reportPath": "Test edilen yol"}, "es": {"diagnosticsSubtitle": "Comprueba una ruta directa o por proxy con TCP/TLS o UDP/STUN.", "probePath": "Ruta de red", "probeTransport": "Protocolo", "pathDirect": "Directa", "probeProxy": "Proxy host:puerto (sin credenciales)", "probeScope": "Solo la ruta elegida. Sin alternativa directa. No demuestra el enrutamiento del motor ni la conectividad de voz o QUIC.", "probeSTUN": "Introduce un servidor STUN de confianza. Un intercambio UDP; el servidor y la direcci\u00f3n indicada no se autentican.", "reportPath": "Ruta comprobada"}, "ru": {"diagnosticsSubtitle": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043f\u0440\u044f\u043c\u043e\u0433\u043e \u043f\u0443\u0442\u0438 \u0438\u043b\u0438 \u043f\u0440\u043e\u043a\u0441\u0438: TCP/TLS \u0438\u043b\u0438 UDP/STUN.", "probePath": "\u0421\u0435\u0442\u0435\u0432\u043e\u0439 \u043f\u0443\u0442\u044c", "probeTransport": "\u041f\u0440\u043e\u0442\u043e\u043a\u043e\u043b", "pathDirect": "\u041d\u0430\u043f\u0440\u044f\u043c\u0443\u044e", "probeProxy": "\u041f\u0440\u043e\u043a\u0441\u0438 host:port (\u0431\u0435\u0437 \u0443\u0447\u0451\u0442\u043d\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445)", "probeScope": "\u0422\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0439 \u043f\u0443\u0442\u044c, \u0431\u0435\u0437 \u043f\u0435\u0440\u0435\u0445\u043e\u0434\u0430 \u043d\u0430\u043f\u0440\u044f\u043c\u0443\u044e. \u041d\u0435 \u0434\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442 \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0438\u0437\u0430\u0446\u0438\u044e \u0434\u0432\u0438\u0436\u043a\u0430, \u0441\u0432\u044f\u0437\u044c \u0434\u043b\u044f \u0433\u043e\u043b\u043e\u0441\u0430 \u0438\u043b\u0438 QUIC.", "probeSTUN": "\u0423\u043a\u0430\u0436\u0438\u0442\u0435 \u0434\u043e\u0432\u0435\u0440\u0435\u043d\u043d\u044b\u0439 STUN-\u0441\u0435\u0440\u0432\u0435\u0440. \u041e\u0434\u0438\u043d UDP-\u043e\u0431\u043c\u0435\u043d; \u0441\u0435\u0440\u0432\u0435\u0440 \u0438 \u0441\u043e\u043e\u0431\u0449\u0451\u043d\u043d\u044b\u0439 \u0430\u0434\u0440\u0435\u0441 \u043d\u0435 \u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u0446\u0438\u0440\u0443\u044e\u0442\u0441\u044f.", "reportPath": "\u041f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043d\u044b\u0439 \u043f\u0443\u0442\u044c"}};
for (const [lang,words] of Object.entries(diagnosticCopy)) Object.assign(translations[lang],words);
const profileAuditCopy={en:{profileAuditNotice:'Recorded profile editing: saves and deletes require audit recording. Engine, system, diagnostics and support actions are unavailable in this session.'},tr:{profileAuditNotice:'Kayıtlı profil düzenleme: kaydetme ve silme işlemleri denetim kaydı gerektirir. Bu oturumda motor, sistem, tanılama ve destek işlemleri kullanılamaz.'},ru:{profileAuditNotice:'Редактирование профилей с журналом: сохранение и удаление требуют записи аудита. Движки, системные операции, диагностика и поддержка недоступны в этом сеансе.'},es:{profileAuditNotice:'Edición de perfiles con registro: guardar y eliminar requieren un registro de auditoría. Los motores, las acciones del sistema, los diagnósticos y el soporte no están disponibles en esta sesión.'}};
for(const [lang,words] of Object.entries(profileAuditCopy))Object.assign(translations[lang],words);
const t = key => (translations[state.lang] || en)[key] || en[key] || key;
const clone = value => JSON.parse(JSON.stringify(value));
function copyName(name) {
  const suffix = ' (' + t('copySuffix') + ')';
  let shortened = name;
  while (new TextEncoder().encode(shortened + suffix).length > 100) shortened = Array.from(shortened).slice(0,-1).join('');
  return shortened + suffix;
}
const platformName = value => ({windows:'Windows',linux:'Linux',darwin:'macOS',freebsd:'FreeBSD',openbsd:'OpenBSD',android:'Android',ios:'iOS',browser:t('mobileEditor'),unknown:'—'})[value] || value;
const coreAvailable = () => !state.offline && !state.disconnected && !state.loading;
const lifecyclePending = () => state.runtime.lifecyclePending === true;
const supportAvailable = () => !state.profileEditingOnly && !!state.coreAuthenticated && !!state.token && !state.loading;
const safeSource = source => /^https?:\/\//i.test(source || '') ? escapeHTML(source) : '#';
function readSession(){
  const credential=new URLSearchParams(location.hash.slice(1)).get('accessweaver-session');
  if(credential&&/^[A-Za-z0-9_-]{43}$/.test(credential)){
    state.token=credential;
    try{sessionStorage.setItem('aw.session',credential)}catch{}
    history.replaceState(null,'',(location.pathname||'/')+(location.search||'')+'#dashboard');
    updateSupportAvailability();
    return;
  }
  try{const saved=sessionStorage.getItem('aw.session');if(/^[A-Za-z0-9_-]{43}$/.test(saved||''))state.token=saved}catch{}
  updateSupportAvailability();
}
const engineGuide = id => t(({spoofdpi:'guideSpoof',byedpi:'guideByedpi',zapret:'guideZapret',zapret2:'guideZapret',goodbyedpi:'guideGoodbye',wiresock:'guideWiresock',wireguard:'guideWireguard'})[id] || 'guideProxy');

function toast(message, bad=false) {
  const target = $('toast');
  target.textContent = message;
  target.className = bad ? 'visible error' : 'visible';
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { target.className = ''; }, bad ? 6500 : 4000);
}
function updateTranslations() {
  document.documentElement.lang = state.lang;
  $$('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  $$('[data-i18n-aria]').forEach(el => { el.setAttribute('aria-label',t(el.dataset.i18nAria)); });
  $('lang-toggle').innerHTML = state.lang.toUpperCase() + ' <span aria-hidden="true">⌄</span>';
  $('lang-toggle').setAttribute('aria-label',t('language') + ': ' + state.lang.toUpperCase());
  $('settings-language').value = state.lang;
  $('profile-search').placeholder = t('searchProfiles');
  const filter = $('profile-filter').value || 'all';
  $('profile-filter').innerHTML = `<option value="all">${escapeHTML(t('allEngines'))}</option>` + engineOptions();
  $('profile-filter').value = state.engines.some(e => e.id === filter) ? filter : 'all';
  if (state.editing) {
    $('editor-title').textContent = t(state.editing.isNew ? 'editorTitleNew' : 'editorTitleEdit');
    updateEditorGuidance();
  }
  if (state.lastProbe) renderProbe(state.lastProbe); else renderProbeNotice();
  updateProbeAvailability();
  updateBreadcrumb();
}
function changeLanguage(lang) {
  state.lang = ['en','tr','ru','es'].includes(lang) ? lang : 'en';
  storage.preference('aw.lang',state.lang);
  updateTranslations();
  renderAll();
  if(typeof refreshSystemLanguage==='function')refreshSystemLanguage();
}
function setTheme(theme) {
  state.theme = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = state.theme;
  document.querySelector('meta[name="theme-color"]').content = state.theme === 'dark' ? '#0b1020' : '#f5f7fb';
  storage.preference('aw.theme',state.theme);
  $('settings-theme').value = state.theme;
  $('theme-toggle').innerHTML = icon(state.theme === 'dark' ? 'sun' : 'moon');
}
function updateBreadcrumb() {
  const label = {dashboard:'navDashboard',profiles:'navProfiles',engines:'navEngines',diagnostics:'navDiagnostics',settings:'navSettings',system:'systemTools'};
  $('crumb-name').textContent = t(label[state.view]);
}
function navigate(view, focus=false) {
  if (!['dashboard','profiles','engines','diagnostics','settings','system'].includes(view)) return;
  if(state.profileEditingOnly&&['system','diagnostics'].includes(view)){toast(t('profileAuditNotice'));view='profiles';}
  state.view = view;
  $$('.view').forEach(el => { el.classList.toggle('active',el.id === 'view-' + view); });
  $$('.nav-item').forEach(el => {
    const active = el.dataset.view === view;
    el.classList.toggle('active',active);
    if (active) el.setAttribute('aria-current','page'); else el.removeAttribute('aria-current');
  });
  if(view==='profiles'&&!state.profileGridRendered)renderProfiles();
  updateBreadcrumb();
  setSidebarOpen(false);
  if (location.hash !== '#' + view) location.hash = view;
  window.scrollTo(0,0);
  if (focus) $('content').focus({preventScroll:true});
  probeNavigationChanged(view);
  supportNavigationChanged(view);
  if(typeof historyNavigationChanged==='function')historyNavigationChanged(view);
  if(view==='system'&&coreAvailable()&&typeof loadSystemTools==='function')loadSystemTools().catch(error=>{setTextOutput('system-output',error.message)});
}
async function apiRequest(path, method='GET', data, timeout=12000, externalSignal) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const ensureActive = () => {if(controller.signal.aborted)throw new DOMException('Request canceled','AbortError');};
  if(externalSignal?.aborted)abort();else externalSignal?.addEventListener('abort',abort,{once:true});
  const timer = setTimeout(abort,timeout);
  try {
    ensureActive();
    const response = await fetch(path, {
      method, headers:{...(data !== undefined ? {'Content-Type':'application/json'} : {}),'X-AccessWeaver-Token':state.token},
      body:data === undefined ? undefined : JSON.stringify(data), cache:'no-store', signal:controller.signal
    });
    ensureActive();
    let json;
    try { json = await response.json(); } catch(error) { ensureActive(); if(error?.name==='AbortError')throw error; throw new Error(t('disconnectedDesc')); }
    ensureActive();
    if (!response.ok) throw Object.assign(new Error(json.error || `HTTP ${response.status}`),{status:response.status,...(['workflow-storage-invalid','workflow-storage-denied','workflow-storage-policy-unavailable','workflow-storage-busy','workflow-storage-request-ended','workflow-storage-pending','workflow-storage-capacity','workflow-storage-unavailable','workflow-lifecycle-pending','diagnostic-busy','reconciliation-invalid','reconciliation-unavailable','reconciliation-conflict','reconciliation-expired','reconciliation-pending','reconciliation-denied','reconciliation-policy-unavailable','reconciliation-request-ended','reconciliation-busy','reconciliation-store-unavailable'].includes(json.code)?{code:json.code}:{})});
    return json;
  } finally { clearTimeout(timer); externalSignal?.removeEventListener('abort',abort); }
}
function engineOptions() {
  return state.engines.map(e => `<option value="${escapeHTML(e.id)}">${escapeHTML(e.name)}</option>`).join('');
}
async function readCore() {
  if(!state.token)throw new Error(t('coreRequired'));
  const boot = await apiRequest('/api/bootstrap');
  if (!boot.platform) throw new Error(t('coreRequired'));
  state.coreAuthenticated = true;
  state.profileEditingOnly = boot.profileEditingOnly === true;
  updateProbeAvailability();
  updateSupportAvailability();
  if(typeof updateSystemExportButtons==='function')updateSystemExportButtons();
  const [engines,profiles,runtime] = await Promise.all([
    apiRequest('/api/v1/engines'),apiRequest('/api/v1/profiles'),apiRequest('/api/v1/runtime')
  ]);
  if (!Array.isArray(engines) || !Array.isArray(profiles)) throw new Error(t('invalidProfile'));
  document.querySelectorAll('[data-app-version]').forEach(node => { node.textContent = boot.version || 'unknown'; });
  return {platform:boot.platform,engines,profiles,runtime};
}
async function initialize() {
  readSession();
  setTheme(state.theme);
  updateTranslations();
  navigate(location.hash.slice(1) || 'dashboard');
  try { Object.assign(state,await readCore()); }
  catch {
    state.offline = true;
    state.platform = /Android/i.test(navigator.userAgent) ? 'android' : /iPhone|iPad/i.test(navigator.userAgent) ? 'ios' : 'browser';
    state.engines = exampleEngines;
    try {
      const saved = JSON.parse(storage.get('aw.profiles') || '[]');
      if (!Array.isArray(saved)) throw new Error(t('invalidProfile'));
      state.profiles = [];
      for (const profile of saved) {
        try { state.profiles.push(validateProfile(profile)); }
        catch { state.preservedProfiles.push(profile); }
      }
      if (state.preservedProfiles.length) toast(t('storageRecovery'),true);
    } catch (err) { state.profiles = []; state.storageBlocked = true; toast(t('storageUnreadable'),true); }
  }
  state.loading = false;
  $('p-engine').innerHTML = engineOptions();
  updateTranslations();
  renderAll();
  setInterval(pollStatus,2000);
  if(!state.profileEditingOnly&&state.view==='system'&&typeof loadSystemTools==='function')loadSystemTools().catch(error=>{setTextOutput('system-output',error.message)});
}
async function reconnect() {
  if (state.reconnecting || state.editing) { if (state.editing) toast(t('discardChanges')); return; }
  state.reconnecting = true;
  $('reconnect-button').disabled = true;
  try {
    const core = await readCore();
    if (state.offline && state.profiles.length && !confirm(t('switchStore'))) return;
    Object.assign(state,core,{offline:false,disconnected:false});
    $('p-engine').innerHTML = engineOptions();
    updateTranslations();
    renderAll();
    toast(t('connectedAgain'));
  } catch (err) { toast(t('missingServer'),true); }
  finally { state.reconnecting = false; $('reconnect-button').disabled = false; }
}
async function pollStatus() {
  if (state.offline || state.loading || state.polling || state.disconnected || document.hidden) return;
  state.polling = true;
  try {
    const old = [state.runtime.state,state.runtime.profileId,state.runtime.pid,lifecyclePending()].join(':');
    state.runtime = await apiRequest('/api/v1/runtime','GET',undefined,6000);
    renderHero();
    if (old !== [state.runtime.state,state.runtime.profileId,state.runtime.pid,lifecyclePending()].join(':')) renderProfiles();
    if (!$('logs-modal').hidden) renderLogs();
  } catch { state.disconnected = true; renderAll(); }
  finally { state.polling = false; }
}
function renderHero() {
  $('profile-audit-notice').hidden=!state.profileEditingOnly;
  $('profile-audit-notice').textContent=t('profileAuditNotice');
  $$('[data-action="diagnose"], [data-view="diagnostics"], [data-view="system"]').forEach(node=>{node.disabled=state.profileEditingOnly});
  if(state.profileEditingOnly&&['system','diagnostics'].includes(state.view))navigate('profiles');
  const pending = lifecyclePending();
  const running = !pending && state.runtime.state === 'running';
  const failed = ['failed','exited','error'].includes(state.runtime.state);
  const status = state.disconnected ? 'disconnected' : state.offline ? 'offline' : pending ? 'shutdownPending' : running ? 'running' : failed ? 'failedState' : 'ready';
  $('hero-status').textContent = state.loading ? t('connecting') : t(status);
  $('hero-description').textContent = t(state.disconnected ? 'disconnectedDesc' : state.offline ? 'offlineDesc' : pending ? 'shutdownPendingDesc' : running ? 'runningDesc' : failed ? 'failedDesc' : 'readyDesc');
  $('status-badge').textContent = t(state.disconnected ? 'disconnected' : state.offline ? 'offlineBadge' : pending ? 'shutdownPendingBadge' : running ? 'runningBadge' : 'notRunning');
  $('status-badge').className = 'tag ' + (state.disconnected || pending ? 'tag-red' : running && coreAvailable() ? 'tag-teal' : state.offline ? 'tag-purple' : 'tag-neutral');
  $('running-engine').textContent = running ? state.runtime.engine + ' · PID ' + state.runtime.pid : '—';
  $('stats-profiles').textContent = state.profiles.length;
  $('stats-engines').textContent = state.engines.length;
  $('nav-profile-count').textContent = state.profiles.length;
  $('stats-platform').textContent = platformName(state.platform);
  $('settings-platform').textContent = platformName(state.platform);
  $('hero-primary').innerHTML = icon(pending ? 'alert' : running && coreAvailable() ? 'stop' : 'layers') + `<span>${t(pending ? 'shutdownPending' : running && coreAvailable() ? 'stop' : 'selectProfile')}</span>`;
  $('hero-primary').disabled = pending || state.loading || state.busy;
  $('connection-notice').hidden = !state.offline && !state.disconnected;
  $('connection-notice-text').textContent = t(state.disconnected ? 'disconnectedNotice' : 'offlineNotice');
  $('storage-description').textContent = t(state.storageBlocked || state.preservedProfiles.length ? 'storageRecovery' : state.offline ? 'browserStorage' : 'coreStorage');
  $('export-browser-backup').hidden = !state.offline;
  $('storage-badge').textContent = t(state.offline ? 'browserStorageBadge' : 'coreStorageBadge');
  $('preview-profile').disabled = !coreAvailable() || !!state.editing?.saving;
  updateProbeAvailability();
  $('show-logs').disabled = state.offline || state.loading;
  updateSupportAvailability();
  if(typeof updateSystemExportButtons==='function')updateSystemExportButtons();
  if (pending && state.launch) {
    state.launch.ready = false;
    $('launch-plan').textContent = t('shutdownPendingDesc');
  }
  $('launch-confirm').disabled = pending || state.profileEditingOnly || !coreAvailable() || !state.launch?.ready || state.busy;
}
function profileCard(p, full=false) {
  const active = !lifecyclePending() && coreAvailable() && state.runtime.state === 'running' && state.runtime.profileId === p.id;
  const heading = full ? 'h2' : 'h3';
  const e = state.engines.find(x => x.id === p.engine);
  const external = e?.integration === 'external' || p.engine === 'wireguard';
  const capable = e?.platforms?.includes(state.platform) && !external;
  const desc = p.description || p.notes || t('defaultDescription');
  const includes = p.routing?.includeDomains?.length || 0;
  const excludes = p.routing?.excludeDomains?.length || 0;
  const profileAction = (action, symbol, label, disabled=false) => `<button data-profile-action="${action}" data-profile-id="${escapeHTML(p.id)}" aria-label="${escapeHTML(t(label))}: ${escapeHTML(p.name)}" title="${escapeHTML(t(label))}" ${disabled ? 'disabled' : ''}>${icon(symbol)}</button>`;
  return `<article class="profile-card ${active ? 'profile-active' : ''}"><div class="profile-top"><div class="profile-symbol ${p.engine === 'byedpi' ? 'teal' : ''}">${icon(['wiresock','wireguard'].includes(p.engine) ? 'shield' : p.engine === 'byedpi' ? 'globe' : 'layers')}</div><span class="tag ${active ? 'tag-teal' : 'tag-neutral'}">${active ? t('runningBadge') : escapeHTML(p.category || t('customCategory'))}</span></div><${heading} class="profile-card-heading"><button class="profile-title" data-profile-action="edit" data-profile-id="${escapeHTML(p.id)}">${escapeHTML(p.name)}</button></${heading}><p title="${escapeHTML(desc)}">${escapeHTML(desc)}</p><div class="profile-rules"><span>${icon('globe')}${includes} ${t('includeCount')}</span><span>${icon('shield')}${excludes} ${t('excludeCount')}</span></div><div class="profile-card-foot"><span class="engine-label">${escapeHTML(e?.name || p.engine)}</span><div class="profile-card-actions">${profileAction(active ? 'stop' : 'run',active ? 'stop' : 'play',active ? 'stop' : 'reviewSetup',lifecyclePending() || state.profileEditingOnly || !coreAvailable() || state.busy || external)}${profileAction('edit','pen','edit',active)}${profileAction('duplicate','copy','duplicate',state.busy)}${profileAction('export','download','export')}${full ? profileAction('delete','trash','delete',active || state.busy) : ''}</div></div>${full ? `<div class="profile-availability"><span class="availability-dot ${capable ? 'available' : ''}"></span>${escapeHTML(t(external ? 'engineExternal' : capable ? 'engineAvailable' : state.offline ? 'platformUnknown' : 'engineUnsupported'))}</div>` : ''}</article>`;
}
function renderProfiles() {
  const focus = rememberFocus(document.activeElement);
  const term = $('profile-search').value.toLocaleLowerCase(state.lang).trim();
  const filter = $('profile-filter').value || 'all';
  const selected = state.profiles.filter(p => (filter === 'all' || p.engine === filter) && [p.name,p.engine,p.id,p.description,p.notes].join(' ').toLocaleLowerCase(state.lang).includes(term));
  const empty = `<div class="empty-card">${icon('layers')}<p>${escapeHTML(t('noProfiles'))}</p><button class="btn btn-outline" data-create-profile>${escapeHTML(t('createProfile'))}</button></div>`;
  $('quick-profiles').innerHTML = state.profiles.length ? state.profiles.slice(0,3).map(p => profileCard(p)).join('') : empty;
  // Build the full collection on demand; keep it current after its first visit.
  if(state.view==='profiles'||state.profileGridRendered){
    $('all-profiles').innerHTML = selected.length ? selected.map(p => profileCard(p,true)).join('') : empty;
    $('profile-result-count').textContent = selected.length + ' / ' + state.profiles.length + ' ' + t('profilesShown');
    state.profileGridRendered=true;
  }
  restoreReplacedFocus(focus);
}
function renderEngines() {
  const focus = rememberFocus(document.activeElement);
  $('engines-grid').innerHTML = state.engines.map(e => {
    const external = e.integration === 'external' || e.id === 'wireguard';
    const supported = e.platforms.includes(state.platform) && !external;
    const rule = (label,enabled) => `<span class="capability ${enabled ? 'supported' : ''}">${icon(enabled ? 'check' : 'x')}${escapeHTML(t(label))}</span>`;
    return `<article class="engine-card"><div class="engine-card-header"><div><h3>${escapeHTML(e.name)}</h3><span class="engine-kind">${escapeHTML(t(external ? 'externalIntegration' : 'managedIntegration'))}</span></div><span class="engine-type">${icon(e.kind === 'vpn' ? 'shield' : e.kind === 'packet' ? 'layers' : 'globe')}</span></div><p>${escapeHTML(state.lang !== 'en' ? engineGuide(e.id) : e.notes)}</p><div class="platform-pills">${e.platforms.map(p => `<span class="${p === state.platform ? 'current-platform' : ''}">${escapeHTML(platformName(p))}</span>`).join('')}</div><div class="engine-capabilities">${rule('includesLabel',e.includes)}${rule('excludesLabel',e.excludes)}${e.license ? `<span class="license-label">${escapeHTML(e.license)}</span>` : ''}</div><div class="engine-card-foot"><a href="${safeSource(e.source)}" target="_blank" rel="noopener noreferrer">${escapeHTML(t('readDocs'))}</a><button class="text-button" data-engine-create="${escapeHTML(e.id)}">${escapeHTML(t('createForEngine'))} ${icon('plus')}</button></div><span class="engine-platform-status">${escapeHTML(t(external ? 'engineExternal' : supported ? 'engineAvailable' : state.offline ? 'platformUnknown' : 'engineUnsupported'))}</span></article>`;
  }).join('');
  const platforms = [ ['Windows','desktopCore','windowsSupport'],['Linux','desktopCore','linuxSupport'],['macOS','partialCore','macSupport'],['BSD','partialCore','bsdSupport'],['Android','mobileEditor','androidSupport'],['iOS','mobileEditor','iosSupport'] ];
  $('platform-matrix').innerHTML = platforms.map(([name,badge,desc]) => `<article><div><h3>${name}</h3><span class="tag tag-neutral">${escapeHTML(t(badge))}</span></div><p>${escapeHTML(t(desc))}</p></article>`).join('');
  restoreReplacedFocus(focus);
}
function renderAll() { renderHero(); renderProfiles(); renderEngines(); }

// Validate before any write, including offline saves. Keep the schema aligned with profile.Profile.
function validateProfile(p) {
  const object = (value,keys,path) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(t('invalidField') + ': ' + path);
    for (const key of Object.keys(value)) if (!keys.includes(key)) throw new Error(t('unknownField') + ': ' + (path ? path + '.' : '') + key);
  };
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error(t('invalidProfile'));
  object(p,['version','id','name','description','category','engine','binary','configPath','sha256','args','routing','probe','notes','updatedAt'],'');
  const string = (key,max,required=false) => {
    if (p[key] === undefined && !required) return;
    if (typeof p[key] !== 'string' || new TextEncoder().encode(p[key]).length > max || p[key].includes('\0') || (required && !p[key].trim())) throw new Error(t('invalidField') + ': ' + key);
  };
  if (p.version !== 1) throw new Error(t('invalidVersion'));
  if (typeof p.id !== 'string' || !/^[a-z][a-z0-9-]{1,62}$/.test(p.id)) throw new Error(t('invalidId'));
  string('name',100,true); string('description',4000); string('notes',10000); string('category',1048576); string('binary',2048); string('configPath',4096); string('sha256',64); string('engine',50,true);
  if (state.engines.length && !state.engines.some(e => e.id === p.engine)) throw new Error(t('invalidEngine'));
  if (/[\r\n]/.test((p.binary || '') + (p.configPath || ''))) throw new Error(t('invalidField') + ': binary / configPath');
  if (p.sha256 && !/^[a-f\d]{64}$/i.test(p.sha256)) throw new Error(t('invalidSHA'));
  if (p.updatedAt !== undefined && (typeof p.updatedAt !== 'string' || Number.isNaN(Date.parse(p.updatedAt)))) throw new Error(t('invalidField') + ': updatedAt');
  const strings = (value,max,count,path) => {
    if (value === null || value === undefined) return [];
    if (!Array.isArray(value) || value.length > count || value.some(v => typeof v !== 'string' || new TextEncoder().encode(v).length > max || v.includes('\0'))) throw new Error(t('invalidField') + ': ' + path);
    return value;
  };
  strings(p.args,4096,128,'args');
  object(p.routing,['includeDomains','excludeDomains','applications'],'routing');
  const validDomain = value => value.length > 0 && value.length <= 253 && /^(\^)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value);
  const domains = field => {
    const values = strings(p.routing[field],253,4096,'routing.' + field);
    const seen = new Set();
    for (const value of values) {
      if (!validDomain(value)) throw new Error(t('invalidDomain') + ' ' + value);
      const normalized = value.toLowerCase();
      if (seen.has(normalized)) throw new Error(t('duplicateDomain') + ': ' + value);
      seen.add(normalized);
    }
    return seen;
  };
  const includes = domains('includeDomains'), excludes = domains('excludeDomains');
  for (const value of includes) if (excludes.has(value)) throw new Error(t('conflictingDomain') + ': ' + value);
  const apps = strings(p.routing.applications,2048,100,'routing.applications');
  if (apps.some(v => !v.trim())) throw new Error(t('invalidField') + ': routing.applications');
  object(p.probe,['host','port','tls','timeoutSeconds'],'probe');
  const validIPv6 = value => {
    if (!value.includes(':') || value.includes(':::') || !/^[a-f\d:.]+$/i.test(value)) return false;
    const halves = value.split('::');
    if (halves.length > 2 || (halves.length === 1 && (value.startsWith(':') || value.endsWith(':')))) return false;
    const parts = value.split(':').filter(Boolean);
    let count = 0;
    for (let i = 0; i < parts.length; i++) {
      if (parts[i].includes('.')) { if (i !== parts.length - 1 || !/^\d{1,3}(\.\d{1,3}){3}$/.test(parts[i]) || parts[i].split('.').some(n => Number(n) > 255)) return false; count += 2; }
      else { if (!/^[a-f\d]{1,4}$/i.test(parts[i])) return false; count++; }
    }
    return halves.length === 2 ? count < 8 : count === 8;
  };
  if (typeof p.probe.host !== 'string' || (p.probe.host && (p.probe.host.startsWith('^') || (!validDomain(p.probe.host) && !validIPv6(p.probe.host))))) throw new Error(t('invalidDomain') + ' (probe.host)');
  if (!Number.isInteger(p.probe.port) || p.probe.port < 1 || p.probe.port > 65535) throw new Error(t('invalidField') + ': probe.port');
  if (typeof p.probe.tls !== 'boolean') throw new Error(t('invalidField') + ': probe.tls');
  if (!Number.isInteger(p.probe.timeoutSeconds) || p.probe.timeoutSeconds < 1 || p.probe.timeoutSeconds > 60) throw new Error(t('invalidField') + ': probe.timeoutSeconds');
  return p;
}
function newProfile(engine='byedpi') {
  showEditor({version:1,id:uniqueId('my-' + (engine === 'byedpi' ? 'profile' : engine),state.profiles),name:t('newProfileName'),description:'',category:t('customCategory'),engine,binary:'',configPath:'',sha256:'',args:[],routing:{includeDomains:[],excludeDomains:[],applications:[]},probe:{host:'discord.com',port:443,tls:true,timeoutSeconds:5},notes:''},true);
}
// Remember logical controls as well as nodes: async reviews and saves replace
// profile/engine cards. Compare data values instead of interpolating selectors.
function rememberFocus(element) {
  if (!element || element === document.body || element === document.documentElement) return null;
  const anchor = {element,id:element.id};
  const grid = element.closest?.('#quick-profiles,#all-profiles');
  if (grid && element.dataset.profileAction) Object.assign(anchor,{kind:'profile',scope:grid.id,profile:element.dataset.profileId,action:element.dataset.profileAction,title:element.classList.contains('profile-title')});
  else if (element.dataset?.engineCreate) Object.assign(anchor,{kind:'engine',engine:element.dataset.engineCreate});
  else if (grid && element.getAttribute('data-create-profile') !== null) Object.assign(anchor,{kind:'empty',scope:grid.id});
  return anchor;
}
function restoreFocus(anchor) {
  if (!anchor) return false;
  const available = element => element?.isConnected && !element.disabled && !element.closest('[hidden],[inert]') && element.getClientRects().length;
  let target = anchor.element;
  if (!available(target)) {
    if (anchor.kind === 'profile') target = Array.from($(anchor.scope).querySelectorAll('[data-profile-action]')).find(element => {
      const action = element.dataset.profileAction;
      const matches = ['run','stop'].includes(anchor.action) ? ['run','stop'].includes(action) : action === anchor.action;
      return available(element) && matches && element.dataset.profileId === anchor.profile && element.classList.contains('profile-title') === anchor.title;
    });
    else if (anchor.kind === 'engine') target = Array.from($('engines-grid').querySelectorAll('[data-engine-create]')).find(element => available(element) && element.dataset.engineCreate === anchor.engine);
    else if (anchor.kind === 'empty') target = Array.from($(anchor.scope).querySelectorAll('[data-create-profile]')).find(available);
    else if (anchor.id) target = $(anchor.id);
  }
  if (!available(target)) return false;
  target.focus();
  return document.activeElement === target;
}
function restoreReplacedFocus(anchor) {
  if (anchor && !anchor.element.isConnected && !restoreFocus(anchor)) $('content').focus({preventScroll:true});
}
function setModal(id,open) {
  const modal = $(id);
  if (open) modal.returnFocus = rememberFocus(document.activeElement);
  modal.hidden = !open;
  const modalOpen = $$('.modal-backdrop').some(el => !el.hidden);
  document.querySelector('.app-shell').inert = modalOpen;
  document.body.classList.toggle('modal-open',modalOpen);
  if (!open) {
    if (!restoreFocus(modal.returnFocus) && !modalOpen) $('content').focus({preventScroll:true});
    modal.returnFocus = null;
  }
}
function showEditor(p,isNew=false) {
  if (!lifecyclePending() && coreAvailable() && state.runtime.state === 'running' && state.runtime.profileId === p.id && !isNew) { toast(t('activeEdit'),true); return; }
  state.editing = {original:p.id,isNew,profile:clone(p),dirty:false,saving:false};
  fillSimple(state.editing.profile);
  $('editor-title').textContent = t(isNew ? 'editorTitleNew' : 'editorTitleEdit');
  $('p-id').disabled = !isNew;
  state.editorTab = 'simple';
  switchEditor('simple',false);
  setEditorFeedback('');
  $('editor-preview').hidden = true;
  setModal('editor-modal',true);
  $('p-name').focus();
}
function fillSimple(p) {
  const val = (id,value) => { $(id).value = value ?? ''; };
  val('p-id',p.id); val('p-name',p.name); val('p-description',p.description); val('p-category',p.category); val('p-engine',p.engine); val('p-binary',p.binary); val('p-config',p.configPath); val('p-sha',p.sha256);
  val('p-args',(p.args || []).join('\n'));
  if (state.editing) state.editing.argsDisplay = $('p-args').value;
  val('p-includes',(p.routing?.includeDomains || []).join('\n')); val('p-excludes',(p.routing?.excludeDomains || []).join('\n')); val('p-apps',(p.routing?.applications || []).join('\n'));
  val('p-probe-host',p.probe?.host ?? 'discord.com'); val('p-probe-port',p.probe?.port ?? 443); val('p-probe-timeout',p.probe?.timeoutSeconds ?? 5); $('p-probe-tls').checked = p.probe?.tls ?? true; val('p-notes',p.notes);
  updateEditorGuidance();
}
function fromSimple() {
  const p = state.editing.profile, val = id => $(id).value.trim();
  const rawArgs = $('p-args').value;
  // An unchanged textarea round-trips even an empty argument or embedded newline from advanced JSON.
  const args = rawArgs === (state.editing.argsDisplay ?? (p.args || []).join('\n')) ? clone(p.args || []) : rawArgs === '' ? [] : rawArgs.split(/\r?\n/);
  return {...p,id:val('p-id'),name:val('p-name'),description:val('p-description'),category:val('p-category'),engine:val('p-engine'),binary:val('p-binary'),configPath:val('p-config'),sha256:val('p-sha'),args,routing:{includeDomains:splitLines($('p-includes').value),excludeDomains:splitLines($('p-excludes').value),applications:splitLines($('p-apps').value)},probe:{host:val('p-probe-host'),port:Number(val('p-probe-port')),tls:$('p-probe-tls').checked,timeoutSeconds:Number(val('p-probe-timeout'))},notes:val('p-notes')};
}
function currentEditorProfile() {
  return validateProfile(state.editorTab === 'advanced' ? JSON.parse($('p-json').value) : fromSimple());
}
function switchEditor(tab,transfer=true) {
  if (!state.editing || state.editing.saving) return;
  if (transfer && tab !== state.editorTab) {
    try {
      const p = currentEditorProfile();
      state.editing.profile = clone(p);
      if (tab === 'advanced') $('p-json').value = JSON.stringify(p,null,2);
      else fillSimple(p);
    } catch (err) { editorError(err); return; }
  }
  state.editorTab = tab;
  $$('.modal-tab').forEach(el => {
    const active = el.dataset.editorTab === tab;
    el.classList.toggle('active',active); el.setAttribute('aria-selected',String(active)); el.tabIndex = active ? 0 : -1;
  });
  $('editor-simple').hidden = tab !== 'simple';
  $('editor-advanced').hidden = tab !== 'advanced';
  if (tab === 'advanced' && !transfer) $('p-json').value = JSON.stringify(state.editing.profile,null,2);
  setEditorFeedback(state.editing.dirty ? t('unsavedChanges') : '');
}
function editorError(err) {
  setEditorFeedback(err.message,true);
  $('editor-feedback').focus({preventScroll:true});
  toast(err.message,true);
}
function markDirty() {
  if (!state.editing) return;
  state.editing.dirty = true;
  setEditorFeedback(t('unsavedChanges'));
  $('editor-preview').hidden = true;
  updateEditorGuidance();
}
function closeEditor(force=false) {
  if (state.editing?.saving) return;
  if (!force && state.editing?.dirty && !confirm(t('discardChanges'))) return;
  setModal('editor-modal',false);
  state.editing = null;
}
function updateEditorGuidance() {
  const e = state.engines.find(x => x.id === $('p-engine').value);
  if (!e) return;
  $('engine-guidance').innerHTML = `<div>${icon('info')}<strong>${escapeHTML(e.name)}</strong><a href="${safeSource(e.source)}" target="_blank" rel="noopener noreferrer">${escapeHTML(t('engineDocs'))} ↗</a></div><p>${escapeHTML(engineGuide(e.id))}</p>`;
  $('p-binary').placeholder = e.executables?.[0] || ({byedpi:'ciadpi',zapret2:'nfqws2',zapret:'nfqws',goodbyedpi:'goodbyedpi.exe',wiresock:'wiresock-client.exe'})[e.id] || e.id;
  $('rule-capability').textContent = t(e.includes ? 'supportedIncludes' : 'unsupportedIncludes') + ' ' + t(e.excludes ? 'supportedExcludes' : 'unsupportedExcludes');
  $('domain-count').textContent = splitLines($('p-includes').value).length + ' ' + t('includeCount') + ' · ' + splitLines($('p-excludes').value).length + ' ' + t('excludeCount');
  $('p-includes').setAttribute('aria-describedby','rule-capability');
  $('p-excludes').setAttribute('aria-describedby','rule-capability');
}
function commitOffline(profiles) {
  if (state.storageBlocked) throw new Error(t('storageUnreadable'));
  try { storage.set('aw.profiles',JSON.stringify([...profiles,...state.preservedProfiles])); }
  catch { throw new Error(t('storageFailed')); }
  state.profiles = profiles;
}
async function persist(p) {
  if(state.profileEditingOnly&&!coreAvailable())throw new Error(t('coreRequired'));
  validateProfile(p);
  if (new TextEncoder().encode(JSON.stringify(p,null,2)).length > (1 << 20)) throw new Error(t('fileTooLarge'));
  if (state.disconnected) throw new Error(t('coreRequired'));
  if (state.offline) {
    const next = state.profiles.map(existing => existing.id === p.id ? clone(p) : existing);
    if (!next.some(existing => existing.id === p.id)) next.push(clone(p));
    commitOffline(next);
    return p;
  }
  const saved = await apiRequest('/api/v1/profiles/' + encodeURIComponent(p.id),'PUT',p);
  const i = state.profiles.findIndex(existing => existing.id === saved.id);
  if (i >= 0) state.profiles[i] = saved; else state.profiles.push(saved);
  return saved;
}
function setEditorBusy(busy) {
  const controls = Array.from($('editor-modal').querySelectorAll('input,textarea,select,button'));
  for (const control of controls) {
    if (busy) { control.wasDisabled = control.disabled; control.disabled = true; }
    else if (control.wasDisabled !== undefined) { control.disabled = control.wasDisabled; delete control.wasDisabled; }
  }
}
async function saveEditor() {
  if (!state.editing || state.editing.saving) return;
  try {
    if (state.editorTab === 'simple' && !$('profile-form').reportValidity()) return;
    const p = currentEditorProfile();
    if (!state.editing.isNew && p.id !== state.editing.original) throw new Error(t('immutableId'));
    if (state.editing.isNew && state.profiles.some(existing => existing.id === p.id)) throw new Error(t('duplicateId'));
    state.editing.saving = true;
    setEditorBusy(true);
    setEditorFeedback(t('saving'));
    $('editor-feedback').focus({preventScroll:true});
    await persist(p);
    state.editing.saving = false;
    renderAll();
    closeEditor(true);
    toast(t(state.offline ? 'savedOffline' : 'saved'));
  } catch (err) { if (state.editing) state.editing.saving = false; editorError(err); }
  finally { setEditorBusy(false); $('save-profile').disabled = false; }
}
// A support download belongs to one explicit Settings request, not merely to
// whichever session happens to be current when an earlier response arrives.
const supportExportUI={generation:0,context:'',operation:null};
function supportContext(){return JSON.stringify([state.token,!!state.coreAuthenticated,!!state.profileEditingOnly,!!state.offline,!!state.disconnected,!!state.loading]);}
function invalidateSupportExport(){
  const operation=supportExportUI.operation;
  supportExportUI.generation++;supportExportUI.operation=null;state.supportExporting=false;
  operation?.controller.abort();
}
function updateSupportAvailability(){
  const context=supportContext();
  if(supportExportUI.context!==context){invalidateSupportExport();supportExportUI.context=context;}
  $('export-support').disabled=!supportAvailable()||!!supportExportUI.operation;
}
function supportNavigationChanged(view){
  if(view!=='settings')invalidateSupportExport();
  updateSupportAvailability();
}
function supportExportCurrent(operation){
  return supportExportUI.operation===operation&&supportExportUI.generation===operation.generation&&supportContext()===operation.context&&state.view==='settings'&&supportAvailable();
}
function supportMetadataReport(report){
  const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
  const fields=(value,required,optional=[])=>object(value)&&required.every(key=>Object.prototype.hasOwnProperty.call(value,key))&&Object.keys(value).every(key=>required.includes(key)||optional.includes(key));
  const text=value=>typeof value==='string'&&value.length<=256;
  const count=value=>Number.isSafeInteger(value)&&value>=0;
  const engine=value=>['zapret','zapret2','byedpi','goodbyedpi','wiresock','wireguard','spoofdpi','sing-box','xray','other'].includes(value);
  if(!fields(report,['schemaVersion','scope','generatedAt','build','profiles','runtime','workflow'])||report.schemaVersion!==1||report.scope!=='metadata-only'||!text(report.generatedAt)||!Number.isFinite(Date.parse(report.generatedAt)))throw new Error('Invalid support metadata');
  const buildFields=['version','commit','sourceState','builtAt','goVersion','platform','arch'];
  if(!fields(report.build,buildFields)||!buildFields.every(key=>text(report.build[key])))throw new Error('Invalid support metadata');
  const profiles=report.profiles,runtime=report.runtime,workflow=report.workflow;
  if(!fields(profiles,['status','total'],['byEngine'])||!['available','unavailable'].includes(profiles.status)||(profiles.status==='available'?!count(profiles.total):profiles.total!==null))throw new Error('Invalid support metadata');
  if(profiles.byEngine!==undefined&&(!object(profiles.byEngine)||Object.entries(profiles.byEngine).some(([key,value])=>!engine(key)||!count(value))||(profiles.status==='unavailable'&&Object.keys(profiles.byEngine).length)))throw new Error('Invalid support metadata');
  if(!fields(runtime,['state','errorPresent','logLines'],['engine'])||!['stopped','running','stopping','error','unknown'].includes(runtime.state)||typeof runtime.errorPresent!=='boolean'||!count(runtime.logLines)||(runtime.engine!==undefined&&!engine(runtime.engine)))throw new Error('Invalid support metadata');
  if(!fields(workflow,['state','errorPresent','resultPresent'],['action'])||!['idle','running','succeeded','failed','interrupted','unknown'].includes(workflow.state)||typeof workflow.errorPresent!=='boolean'||typeof workflow.resultPresent!=='boolean'||(workflow.action!==undefined&&(!text(workflow.action)||!/^[-a-z0-9]+$/.test(workflow.action))))throw new Error('Invalid support metadata');
  return report;
}
async function readSupportSummary(operation){
  const maximum=16*1024,signal=operation.controller.signal;
  const active=()=>{if(signal.aborted||!supportExportCurrent(operation))throw new DOMException('Request canceled','AbortError');};
  active();
  const response=await fetch('/api/v1/support',{method:'GET',headers:{'X-AccessWeaver-Token':operation.token},cache:'no-store',redirect:'error',signal});
  active();
  if(!response.ok||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type')||''))throw new Error('Support summary unavailable');
  const length=response.headers.get('Content-Length');
  if(length!==null&&(!/^\d+$/.test(length)||Number(length)>maximum))throw new Error('Support summary unavailable');
  if(!response.body?.getReader)throw new Error('Support summary unavailable');
  const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});
  let total=0,text='',complete=false;
  try{
    while(true){
      const part=await reader.read();active();
      if(part.done){complete=true;break;}
      if((!ArrayBuffer.isView(part.value)||Object.prototype.toString.call(part.value)!=='[object Uint8Array]')||part.value.byteLength>maximum-total)throw new Error('Support summary unavailable');
      total+=part.value.byteLength;text+=decoder.decode(part.value,{stream:true});
    }
    text+=decoder.decode();active();
    return supportMetadataReport(JSON.parse(text));
  }finally{
    if(!complete){operation.controller.abort();try{await reader.cancel();}catch{}}
    reader.releaseLock();
  }
}
async function exportSupportSummary(){
  updateSupportAvailability();
  if(state.view!=='settings'||!supportAvailable()){toast(t(state.profileEditingOnly?'profileAuditNotice':'coreRequired'),true);return;}
  if(supportExportUI.operation)return;
  const operation={generation:++supportExportUI.generation,context:supportContext(),token:state.token,controller:new AbortController()};
  supportExportUI.operation=operation;state.supportExporting=true;updateSupportAvailability();
  const timer=setTimeout(()=>operation.controller.abort(),12000);
  try{
    const report=await readSupportSummary(operation);
    if(!supportExportCurrent(operation)||operation.controller.signal.aborted)return;
    downloadFile(JSON.stringify(report,null,2)+'\n','accessweaver-support-summary.json');
  }catch(error){
    if(supportExportCurrent(operation))toast(t('disconnectedDesc'),true);
  }finally{
    clearTimeout(timer);
    if(supportExportUI.operation===operation){supportExportUI.operation=null;state.supportExporting=false;operation.controller.abort();updateSupportAvailability();}
  }
}
function downloadFile(data,name,mime='application/json') {
  const url = URL.createObjectURL(new Blob([data],{type:mime}));
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url),1500);
}
async function importProfile(file) {
  try {
    if (file.size > 1 << 20) throw new Error(t('fileTooLarge'));
    const p = clone(validateProfile(JSON.parse(await file.text())));
    const collision = state.profiles.some(existing => existing.id === p.id);
    if (collision) { p.id = uniqueId(p.id + '-import',state.profiles); p.name = copyName(p.name); }
    delete p.updatedAt;
    showEditor(p,true);
    state.editing.dirty = true;
    setEditorFeedback(t(collision ? 'importRenamed' : 'importReview'));
  } catch (err) { toast(t('importInvalid') + ': ' + err.message,true); }
}
async function handleProfileAction(action,id) {
  let acquiredBusy = false;
  const p = state.profiles.find(profile => profile.id === id);
  if (!p && action !== 'stop') return;
  try {
    if (action === 'edit') { showEditor(p); return; }
    if (action === 'export') { downloadFile(JSON.stringify(p,null,2) + '\n',p.id + '.json'); return; }
    if (state.busy) return;
    if (action === 'duplicate') {
      const copied = clone(p); copied.id = uniqueId(p.id + '-copy',state.profiles); copied.name = copyName(p.name); delete copied.updatedAt;
      showEditor(copied,true); state.editing.dirty = true; return;
    }
    if (action === 'delete') {
      if (!confirm(t('confirmDelete') + '\n\n' + p.name)) return;
      acquiredBusy = true; state.busy = true;
      if (state.offline) commitOffline(state.profiles.filter(profile => profile.id !== id));
      else { if (!coreAvailable()) throw new Error(t('coreRequired')); await apiRequest('/api/v1/profiles/' + encodeURIComponent(id),'DELETE',{expectedUpdatedAt:p.updatedAt}); state.profiles = state.profiles.filter(profile => profile.id !== id); }
      renderAll(); toast(t('deleted')); return;
    }
    if (action === 'run') { await reviewLaunch(p); return; }
    if (action === 'stop') {
      if (!coreAvailable()) throw new Error(t('coreRequired'));
      acquiredBusy = true; state.busy = true; renderHero();
      state.runtime = await apiRequest('/api/v1/stop','POST',{});
      toast(t('stopped'));
    }
  } catch (err) { toast(err.message,true); }
  finally { if (acquiredBusy) state.busy = false; renderAll(); }
}

function renderPlan(plan,target) {
  const list = (values,kind) => (values || []).length ? `<div class="plan-${kind}"><strong>${escapeHTML(t(kind === 'issues' ? 'issues' : 'warnings'))}</strong><ul>${values.map(value => `<li>${escapeHTML(value)}</li>`).join('')}</ul></div>` : '';
  target.innerHTML = `<div class="plan-status ${plan.ready ? 'ready' : 'blocked'}">${icon(plan.ready ? 'check' : 'alert')}<strong>${escapeHTML(t(plan.ready ? 'setupReady' : 'setupBlocked'))}</strong></div>${list(plan.issues,'issues')}<dl><dt>${escapeHTML(t('executable'))}</dt><dd><code>${escapeHTML(plan.binary || '—')}</code></dd><dt>${escapeHTML(t('launchArguments'))}</dt><dd class="plan-args">${(plan.args || []).length ? plan.args.map((arg,i) => `<code><span>${i + 1}</span>${escapeHTML(JSON.stringify(arg))}</code>`).join('') : escapeHTML(t('noArguments'))}</dd>${plan.workingDirectory ? `<dt>${escapeHTML(t('workingDirectory'))}</dt><dd><code>${escapeHTML(plan.workingDirectory)}</code></dd>` : ''}</dl>${list(plan.warnings,'warnings')}`;
}
async function previewEditor() {
  if (!coreAvailable()) { toast(t('previewUnavailable'),true); return; }
  const editor = state.editing;
  try {
    const p = currentEditorProfile(), target = $('editor-preview');
    $('preview-profile').disabled = true;
    target.hidden = false; target.textContent = t('checkingSetup');
    const plan = await apiRequest('/api/v1/preview','POST',p);
    if (state.editing !== editor) return;
    renderPlan(plan,target);
    target.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'nearest'});
  } catch (err) { editorError(err); $('editor-preview').hidden = true; }
  finally { $('preview-profile').disabled = !coreAvailable(); }
}
async function reviewLaunch(p) {
  if (!coreAvailable()) throw new Error(t('coreRequired'));
  if (lifecyclePending()) throw new Error(t('shutdownPendingDesc'));
  if (state.runtime.state === 'running') throw new Error(t('otherRunning'));
  const launch = {profile:p,ready:false};
  state.launch = launch;
  $('launch-profile-name').textContent = p.name;
  $('launch-plan').textContent = t('checkingSetup');
  $('launch-confirm').disabled = true;
  setModal('launch-modal',true);
  $('close-launch').focus();
  try {
    const current = await apiRequest('/api/v1/profiles/' + encodeURIComponent(p.id));
    if (state.launch !== launch) return;
    if (lifecyclePending()) throw new Error(t('shutdownPendingDesc'));
    launch.profile = current;
    $('launch-profile-name').textContent = current.name;
    const index = state.profiles.findIndex(profile => profile.id === current.id);
    if (index >= 0) state.profiles[index] = current;
    const plan = await apiRequest('/api/v1/preview','POST',current);
    if (state.launch !== launch) return;
    if (lifecyclePending()) throw new Error(t('shutdownPendingDesc'));
    launch.ready = !!plan.ready;
    renderPlan(plan,$('launch-plan'));
    $('launch-confirm').disabled = !plan.ready || !coreAvailable();
  } catch (err) { if (state.launch === launch) $('launch-plan').textContent = err.message; }
}
function closeLaunch() {
  if (state.busy) return;
  setModal('launch-modal',false); state.launch = null;
}
async function confirmLaunch() {
  if (lifecyclePending() || !state.launch?.ready || state.busy || !coreAvailable()) return;
  const launch = state.launch, id = launch.profile.id;
  state.busy = true; $('launch-confirm').disabled = true; $('launch-edit').disabled = true;
  try {
    state.runtime = await apiRequest('/api/v1/start','POST',{id,confirm:true,expectedUpdatedAt:launch.profile.updatedAt},20000);
    state.busy = false;
    closeLaunch(); renderAll(); toast(t('startOk'));
  } catch (err) { toast(err.message,true); if (state.launch === launch) { launch.ready = false; $('launch-plan').insertAdjacentHTML('afterbegin',`<p class="plan-error">${escapeHTML(err.message)}</p>`); } }
  finally { state.busy = false; $('launch-edit').disabled = false; renderHero(); }
}
function addExclusions(group) {
  const groups = {updates:['windowsupdate.com','update.microsoft.com','delivery.mp.microsoft.com'],steam:['steampowered.com','steamcontent.com','steamstatic.com'],riot:['riotgames.com']};
  const values = splitLines($('p-excludes').value);
  const includes = new Set(splitLines($('p-includes').value).map(s => s.toLowerCase()));
  const seen = new Set(values.map(s => s.toLowerCase()));
  for (const domain of groups[group] || []) if (!seen.has(domain) && !includes.has(domain)) { values.push(domain); seen.add(domain); }
  $('p-excludes').value = values.join('\n'); markDirty(); toast(t('addedExclusions'));
}
function updateProbeMode(reset = false) {
 const stun = $('probe-transport').value === 'stun';
 $('probe-http-option').disabled = stun;
 if (stun && $('probe-path').value === 'http-connect') $('probe-path').value = 'direct';
 const proxied = $('probe-path').value !== 'direct';
 $('probe-proxy-field').hidden = !proxied;
 $('probe-proxy').disabled = !proxied;
 $('probe-proxy').required = proxied;
 $('probe-tls').disabled = stun;
 if (reset) {
  $('probe-host').value = stun ? '' : 'discord.com';
  $('probe-port').value = stun ? 3478 : 443;
  $('probe-tls').checked = !stun;
 }
 $('probe-stun-note').hidden = !stun;
}
function probeRequest() {
 const path = $('probe-path').value || 'direct', transport = $('probe-transport').value || 'tcp';
 return {host:$('probe-host').value.trim(),port:Number($('probe-port').value),timeoutSeconds:Number($('probe-timeout').value),tls:transport === 'tcp' && $('probe-tls').checked,path,transport,...(path === 'direct' ? {} : {proxy:$('probe-proxy').value.trim()})};
}
function probeContext(){return JSON.stringify([state.token,!!state.coreAuthenticated,!!state.profileEditingOnly,!!state.offline,!!state.disconnected,!!state.loading]);}
function probeAvailable(){return !state.profileEditingOnly&&!!state.token&&coreAvailable();}
function probeFingerprint(request=probeRequest()){return JSON.stringify(request);}
function renderProbeNotice(){
 if(!probeUI.notice)return;
 $('diagnostic-results').className='empty-results';
 $('diagnostic-results').textContent=t(probeUI.notice)+(probeUI.failure?': '+probeUI.failure:'');
}
function updateProbeButtons(){
 const active=!!probeUI.operation;
 $('probe-submit').disabled=!probeAvailable()||active;
 const button=$('probe-submit'),label=(active?'busy:':'ready:')+state.lang;
 // Input change can fire during a pointer click's focus transition. Keep the
 // existing button children when its state/language did not actually change.
 if(button.dataset.probeLabel!==label){button.innerHTML=icon(active?'pulse':'play')+'<span>'+t(active?'testRunning':'startTest')+'</span>';button.dataset.probeLabel=label;}
 $('probe-cancel').disabled=!active;
}
function invalidateProbe(notice){
 const operation=probeUI.operation;
 const hadOutput=!!operation||!!probeUI.completed||state.lastProbe!==null||!!probeUI.notice;
 // Invalidate before abort: even a transport that ignores cancellation cannot
 // publish its report/error or release a newer operation in its finally block.
 probeUI.generation++;probeUI.operation=null;probeUI.completed=null;
 state.probing=false;state.lastProbe=null;probeUI.failure='';
 if(hadOutput)probeUI.notice=notice;
 $('export-report').hidden=true;$('diagnostic-meta').hidden=true;
 $('diagnostic-meta').replaceChildren();
 renderProbeNotice();updateProbeButtons();operation?.controller.abort();
}
function updateProbeAvailability(){
 const context=probeContext();
 if(probeUI.context!==context){invalidateProbe('probeContextCleared');probeUI.context=context;}
 updateProbeButtons();
}
function probeNavigationChanged(view){if(view!=='diagnostics')invalidateProbe('probeViewCleared');}
function probeInputsChanged(){invalidateProbe('probeInputsCleared');}
function cancelProbe(){
 if(!probeUI.operation)return;
 invalidateProbe('probeCanceled');
 if(probeAvailable())$('probe-submit').focus();
}
function probeCurrent(operation){
 return probeUI.operation===operation&&probeUI.generation===operation.generation&&probeContext()===operation.context&&state.view==='diagnostics'&&probeAvailable()&&probeFingerprint()===operation.fingerprint;
}
async function runProbe() {
 updateProbeAvailability();
 if(state.view!=='diagnostics'||!probeAvailable()){toast(t(state.profileEditingOnly?'profileAuditNotice':'coreRequired'),true);return;}
 if(probeUI.operation)return;
 const request=Object.freeze(probeRequest()),controller=new AbortController();
 const operation={generation:++probeUI.generation,context:probeContext(),request,fingerprint:probeFingerprint(request),controller};
 probeUI.operation=operation;probeUI.completed=null;probeUI.notice='testRunning';probeUI.failure='';state.probing=true;state.lastProbe=null;
 $('export-report').hidden=true;$('diagnostic-meta').hidden=true;$('diagnostic-meta').replaceChildren();renderProbeNotice();updateProbeButtons();
 try{
  const report=await apiRequest('/api/v1/diagnose','POST',request,(request.timeoutSeconds+10)*1000,controller.signal);
  if(!probeCurrent(operation)){if(probeUI.operation===operation)invalidateProbe('probeContextCleared');return;}
  probeUI.completed={context:operation.context,fingerprint:operation.fingerprint,report};state.lastProbe=report;probeUI.notice='';renderProbe(report);
 }catch(error){
  if(!probeCurrent(operation)){if(probeUI.operation===operation)invalidateProbe('probeContextCleared');return;}
  probeUI.notice=error.status===503&&error.code==='diagnostic-busy'?'probeBusy':error.name==='AbortError'?'probeRequestEnded':'testFailed';
  probeUI.failure=probeUI.notice==='testFailed'?error.message:'';renderProbeNotice();
 }finally{
  if(probeUI.operation===operation){probeUI.operation=null;state.probing=false;controller.abort();updateProbeAvailability();}
 }
}
function exportProbeReport(){
 updateProbeAvailability();
 const completed=probeUI.completed;
 if(!completed||state.view!=='diagnostics'||!probeAvailable()||completed.context!==probeContext()||completed.fingerprint!==probeFingerprint()||state.lastProbe!==completed.report){if(completed||state.lastProbe)invalidateProbe('probeInputsCleared');return;}
 downloadFile(JSON.stringify(completed.report,null,2)+'\n','accessweaver-diagnostics-'+completed.report.host+'.json');
}
function renderProbe(report) {
  const checks = report.checks || [], passed = checks.length > 0 && checks.every(c => c.status === 'ok');
  $('diagnostic-meta').hidden = false;
  $('diagnostic-meta').innerHTML = `<strong>${escapeHTML(report.host)}:${Number(report.port)}</strong><p>${escapeHTML(t('reportPath'))}: ${escapeHTML(report.path || 'direct')} / ${escapeHTML(report.transport || 'tcp')}${report.proxy ? ' / ' + escapeHTML(report.proxy) : ''}</p><span>${escapeHTML(new Date(report.at).toLocaleString(state.lang))}</span><p class="${passed ? 'success-text' : 'error-text'}">${escapeHTML(t(passed ? 'testPassed' : 'testIncomplete'))}</p>`;
  $('diagnostic-results').className = 'result-list';
  $('diagnostic-results').innerHTML = checks.map(c => `<div class="result-item"><span class="result-icon ${c.status === 'ok' ? '' : 'error'}">${icon(c.status === 'ok' ? 'check' : 'alert')}</span><div class="result-content"><h3>${escapeHTML(c.name)} · ${escapeHTML(({en:['PASSED','FAILED'],tr:['BAŞARILI','BAŞARISIZ'],ru:['УСПЕШНО','ОШИБКА'],es:['CORRECTO','FALLIDO']})[state.lang][c.status === 'ok' ? 0 : 1])}</h3><p>${escapeHTML(c.detail)}</p></div><span class="result-duration">${Number(c.durationMs) || 0} ms</span></div>`).join('');
  $('export-report').hidden = false;
}
function renderLogs() { $('log-output').textContent = (state.runtime.log || []).join('\n') || t('settingsLogsEmpty'); }
async function showLogs() {
  if (coreAvailable()) await pollStatus();
  renderLogs(); setModal('logs-modal',true); $('close-logs').focus();
}
function trapModalKeys(event) {
  const open = $$('.modal-backdrop').filter(el => !el.hidden);
  const modal = open[open.length - 1];
  if (!modal) {
    if(event.key==='Escape'&&$('sidebar').classList.contains('open')){event.preventDefault();setSidebarOpen(false);$('menu-toggle').focus()}
    return;
  }
  if (event.key === 'Escape') {
    event.preventDefault();
    if (modal.id === 'editor-modal') closeEditor();
    else if (modal.id === 'launch-modal') closeLaunch();
    else setModal(modal.id,false);
  }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's' && modal.id === 'editor-modal') { event.preventDefault(); saveEditor(); }
  if (event.key !== 'Tab') return;
  const focusable = Array.from(modal.querySelectorAll('button,input,textarea,select,a[href],summary,[tabindex]')).filter(el => el.tabIndex >= 0 && !el.matches(':disabled') && !el.closest('[hidden],[inert]') && el.getClientRects().length && getComputedStyle(el).visibility === 'visible');
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (!first) {
    event.preventDefault();
    modal.querySelector('[role="dialog"]')?.focus({preventScroll:true});
    return;
  }
  const sequential = focusable.includes(document.activeElement);
  if (event.shiftKey && (document.activeElement === first || !sequential)) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && (document.activeElement === last || !sequential)) { event.preventDefault(); first.focus(); }
}
function bindEvents() {
  $$('.nav-item').forEach(el => el.addEventListener('click',() => navigate(el.dataset.view,true)));
  $$('[data-action]').forEach(el => el.addEventListener('click',() => navigate(el.dataset.action === 'diagnose' ? 'diagnostics' : el.dataset.action,true)));
  window.addEventListener('hashchange',() => navigate(location.hash.slice(1) || 'dashboard'));
  window.addEventListener('pagehide',()=>{invalidateSupportExport();updateSupportAvailability()});
  window.addEventListener('beforeunload',event => { if (state.editing?.dirty) { event.preventDefault(); event.returnValue = ''; } });
  $('menu-toggle').addEventListener('click',() => setSidebarOpen(!$('sidebar').classList.contains('open')));
  narrowNavigation.addEventListener('change',() => {
    const inside=$('sidebar').contains(document.activeElement);setSidebarOpen(false);
    if(inside&&narrowNavigation.matches)$('menu-toggle').focus();
  });
  document.addEventListener('focusin',event => {
    if(narrowNavigation.matches&&$('sidebar').classList.contains('open')&&!$('sidebar').contains(event.target))setSidebarOpen(false);
  });
  setSidebarOpen(false);
  $('theme-toggle').addEventListener('click',() => setTheme(state.theme === 'dark' ? 'light' : 'dark'));
  $('lang-toggle').addEventListener('click',() => {const languages=['en','tr','ru','es'];changeLanguage(languages[(languages.indexOf(state.lang)+1)%languages.length]);});
  $('settings-language').addEventListener('change',event => changeLanguage(event.target.value));
  $('settings-theme').addEventListener('change',event => setTheme(event.target.value));
  $('new-profile').addEventListener('click',() => newProfile());
  $('hero-primary').addEventListener('click',() => { if (lifecyclePending()) return; if (coreAvailable() && state.runtime.state === 'running') handleProfileAction('stop',state.runtime.profileId); else navigate('profiles',true); });
  $('import-button').addEventListener('click',() => $('import-file').click());
  $('import-file').addEventListener('change',event => { const file = event.target.files?.[0]; event.target.value = ''; if (file) importProfile(file); });
  $('profile-search').addEventListener('input',renderProfiles);
  $('profile-filter').addEventListener('change',renderProfiles);
  $('reconnect-button').addEventListener('click',reconnect);
  $('export-browser-backup').addEventListener('click',() => downloadFile(storage.get('aw.profiles') || '[]','accessweaver-browser-backup.json'));
  document.addEventListener('click',event => {
    const action = event.target.closest('[data-profile-action]');
    if (action && !action.disabled) handleProfileAction(action.dataset.profileAction,action.dataset.profileId);
    const engine = event.target.closest('[data-engine-create]'); if (engine) newProfile(engine.dataset.engineCreate);
    if (event.target.closest('[data-create-profile]')) newProfile();
    const exclusion = event.target.closest('[data-exclusion]'); if (exclusion) addExclusions(exclusion.dataset.exclusion);
  });
  $('close-editor').addEventListener('click',() => closeEditor());
  $('cancel-editor').addEventListener('click',() => closeEditor());
  $('save-profile').addEventListener('click',saveEditor);
  $('preview-profile').addEventListener('click',previewEditor);
  $$('.modal-tab').forEach(el => {
    el.addEventListener('click',() => switchEditor(el.dataset.editorTab));
    el.addEventListener('keydown',event => { if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') { event.preventDefault(); const next = state.editorTab === 'simple' ? 'advanced' : 'simple'; switchEditor(next); $('tab-' + state.editorTab).focus(); } });
  });
  $('profile-form').addEventListener('submit',event => { event.preventDefault(); saveEditor(); });
  $('profile-form').addEventListener('input',markDirty);
  $('profile-form').addEventListener('change',markDirty);
  $('p-json').addEventListener('input',markDirty);
  $('probe-path').addEventListener('change',() => updateProbeMode());
  $('probe-transport').addEventListener('change',() => updateProbeMode(true));
  updateProbeMode();
  $('diagnostic-form').addEventListener('input',probeInputsChanged);
  $('diagnostic-form').addEventListener('change',probeInputsChanged);
  $('diagnostic-form').addEventListener('submit',event => { event.preventDefault(); runProbe(); });
  $('probe-cancel').addEventListener('click',cancelProbe);
  $('export-report').addEventListener('click',exportProbeReport);
  $('show-logs').addEventListener('click',showLogs);
  $('export-support').addEventListener('click',exportSupportSummary);
  $('close-logs').addEventListener('click',() => setModal('logs-modal',false));
  $('logs-copy').addEventListener('click',async () => { try { await navigator.clipboard.writeText($('log-output').textContent); toast(t('copySuccess')); } catch (err) { toast(err.message,true); } });
  $('close-launch').addEventListener('click',closeLaunch);
  $('launch-confirm').addEventListener('click',confirmLaunch);
  $('launch-edit').addEventListener('click',() => { if (state.busy) return; const p = state.launch?.profile; closeLaunch(); if (p) showEditor(p); });
  document.addEventListener('keydown',trapModalKeys);
}
bindEvents();initialize();
