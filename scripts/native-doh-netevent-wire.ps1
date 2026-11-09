# Definitions only. The guarded actual-product coordinator owns this lifecycle.
function New-DoHNetEventOperationEvidence {
    return @{stage='not-inspected';family='none';hresult=0;cimStatus=-1;modeKind='not-inspected';statusKind='not-inspected'}
}
function Assert-DoHNetEventSources([object]$State) {
    foreach($file in $State.ndis.hashes.Keys){if((Get-FileHash -LiteralPath (Join-Path $State.ndis.project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.ndis.hashes[$file]){throw 'Product capture source changed'}}
}
function Invoke-DoHNetEventProcess([object]$State,[string]$Program,[string[]]$Arguments,[byte[]]$InputBytes=$null) {
    Assert-DoHNetEventSources $State
    $text=Invoke-NativeDNSWireProcess $State $Program $Arguments $InputBytes
    Assert-DoHNetEventSources $State
    return $text
}
function Initialize-DoHNetEventState([object]$State,[string]$Project,[hashtable]$Hashes) {
    $root=[IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'),('AccessWeaver-NetEventControl-'+[guid]::NewGuid().ToString('N')))
    Assert-NativeOrdinaryPath $root;if(Test-Path -LiteralPath $root){throw 'Existing product capture root'}
    [void][IO.Directory]::CreateDirectory($root);$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($identity.User);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $root -AclObject $acl -ErrorAction Stop
    $State.etl=Join-Path $root 'capture.etl';$State.pcap=Join-Path $root 'capture.pcapng'
    $State.ndis=@{root=$root;project=$Project;hashes=$Hashes.Clone();plan=$null;digest='';prepared=$false;count=0;created=$false;configuredUtcTicks=0L;phaseVerified=$false;public=@{
        phaseReadEvidence=(New-DoHPhaseReadEvidence);phaseEvidence=(New-DoHPhaseEvidence);operationEvidence=(New-DoHNetEventOperationEvidence);cleanupCode='none';sessionVerified=$false;sessionRemoved=$false;preflightEmpty=$false;
        filterEvidence=@{policy='product-doh-all';endpointMask=15;etherTypeMask=3;protocolMask=3;portsFiltered=$false;verified=$false};
        offloadPrepareEvidence=(New-NativeDoHOffloadEvidence 'prepare');offloadStageEvidence=@();offloadVerifyEvidence=(New-NativeDoHOffloadEvidence 'verify');offloadMeasureEvidence=(New-NativeDoHOffloadEvidence 'verify');offloadRestoreEvidence=@();
        lossEvidence=(New-NativeNDISLossEvidence);eventEvidence=(New-NativeNDISHeaderEvidence);fragmentEvidence=(New-NativeNDISFragmentEvidence);catalogEvidence=(New-NativeNDISCatalogEvidence);extractionEvidence=(New-NativeNDISExtractionEvidence);conversionEvidence=(New-NativeNDISConversionEvidence);tlsWireEvidence=(New-DoHNetEventTlsEvidence);etlBytes=0;pcapBytes=0;captureBounded=$false
    }}
}
function Invoke-DoHNetEventOperation([object]$State,[string]$Operation) {
    $State.ndis.operationCode='none';$State.ndis.public.operationEvidence=(New-DoHNetEventOperationEvidence)
    foreach($file in $State.ndis.hashes.Keys){if((Get-FileHash -LiteralPath (Join-Path $State.ndis.project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.ndis.hashes[$file]){throw 'NDIS source changed'}}
    $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($State.ndis.plan | ConvertTo-Json -Compress)))
    $text=Invoke-DoHNetEventProcess $State $State.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'netevent-control-operation.ps1'),'-Operation',$Operation,'-PlanBase64',$payload)
    $v=$text | ConvertFrom-Json -ErrorAction Stop
    $keys=@('diagnostic','code','sessionGuid','state','sessionVerified','providerVerified','emptyBefore','emptyAfter')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 8 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.code -cnotin @('none','operation','plan','enum','session','identity','configuration','state','provider','filters','inventory','original') -or $v.state -cnotin @('unknown','absent','running','stopped')){throw 'NDIS operation shape'}
    foreach($key in @('sessionVerified','providerVerified','emptyBefore','emptyAfter')){if($v.$key -isnot [bool]){throw 'NDIS operation shape'}}
    $diag=$v.diagnostic
    if($diag -isnot [pscustomobject] -or @($diag.PSObject.Properties).Count -ne 6 -or @($diag.PSObject.Properties.Name | Where-Object {$_ -cnotin @('stage','family','hresult','cimStatus','modeKind','statusKind')}).Count -ne 0 -or $diag.stage -cnotin @('initial','enum-metadata','inventory-readback','session-readback','provider-readback','create-request','provider-request','start-request','stop-request','remove-request') -or $diag.family -cnotin @('none','cim','win32','argument','state','invocation','other') -or ($diag.hresult -isnot [int] -and $diag.hresult -isnot [long]) -or $diag.hresult -lt -2147483648 -or $diag.hresult -gt 2147483647 -or ($diag.cimStatus -isnot [int] -and $diag.cimStatus -isnot [long]) -or $diag.cimStatus -lt -1 -or $diag.cimStatus -gt 65535 -or $diag.modeKind -cnotin @('null','enum','string','numeric','other','not-inspected') -or $diag.statusKind -cnotin @('null','enum','string','numeric','other','not-inspected')){throw 'NDIS diagnostic shape'}
    $State.ndis.public.operationEvidence=@{stage=$diag.stage;family=$diag.family;hresult=$diag.hresult;cimStatus=$diag.cimStatus;modeKind=$diag.modeKind;statusKind=$diag.statusKind}
    if($v.code -cne 'none'){$State.ndis.operationCode=$v.code;throw 'NDIS native operation refused'}
    if($v.sessionGuid -isnot [string] -or ($v.sessionGuid -and $v.sessionGuid -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')){throw 'NDIS operation identity'}
    if($v.sessionGuid){if($State.ndis.plan.guid -and $State.ndis.plan.guid -cne $v.sessionGuid){throw 'NDIS operation identity'};$State.ndis.plan.guid=$v.sessionGuid}
    return $v
}
function Invoke-DoHNetEventOffload([object]$State,[string]$Operation,[int]$Ordinal=-1) {
    foreach($file in $State.ndis.hashes.Keys){if((Get-FileHash -LiteralPath (Join-Path $State.ndis.project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.ndis.hashes[$file]){throw 'Offload source changed'}}
    $arguments=@('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'doh-offload-operation.ps1'),'-Operation',$Operation,'-PrivateRoot',$State.ndis.root,'-Ordinal',([string]$Ordinal));if($Operation -cne 'prepare'){$expected=$State.ndis.digest;$arguments+=@('-ExpectedDigest',$expected)}
    $text=Invoke-DoHNetEventProcess $State $State.eventTool $arguments;$reply=$text | ConvertFrom-Json -ErrorAction Stop
    if($reply -isnot [pscustomobject] -or @($reply.PSObject.Properties).Count -ne 2 -or @($reply.PSObject.Properties.Name | Where-Object {$_ -cnotin @('summary','digest')}).Count -ne 0 -or $reply.digest -isnot [string]){throw 'Private offload IPC'}
    $summary=Get-NativeDoHOffloadEvidence ($reply.summary | ConvertTo-Json -Depth 4 -Compress) $Operation
    if($Operation -ceq 'prepare' -and $summary.code -ceq 'none'){if($reply.digest -cnotmatch '^[a-f0-9]{64}$'){throw 'Private offload digest'};$State.ndis.digest=$reply.digest}elseif($reply.digest){throw 'Unexpected private offload digest'}
    return $summary
}
function New-DoHNetEventTlsEvidence([string]$Code='not-inspected') {
    $r=New-NativeNDISTlsWireEvidence $Code;$r['plaintextPackets']=0;return $r
}
function Get-DoHNetEventTlsEvidence([string]$Text) {
    $bad=New-DoHNetEventTlsEvidence 'invalid';$bad.observation='refused';if($Text.Length -gt 16384){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $codes=@('ascii','block-bound','block-shape','capture-bound','capture-drops','capture-empty','capture-options','client-hello','client-sni','decoder-failed','environment','ethernet-protocol','ethernet-shape','flow-bound','input-bound','input-incomplete','input-read','interface-bound','interface-link','interface-snaplen','ip-fragment','ipv4-bound','ipv4-shape','ipv6-bound','ipv6-extension','ipv6-shape','none','packet-bound','packet-kind','packet-shape','packet-snaplen','packet-truncated','provider-port','provider-scope','section-length','section-magic','section-required','section-shape','section-version','server-hello','statistics-shape','tcp-bound','tcp-gap','tcp-overlap','tcp-reset','tcp-reuse','tcp-segment-bound','tcp-shape','tcp-stream-bound','tcp-syn-required','tcp-syn-shape','tls-change-cipher','tls-handshake-bound','tls-hello-required','tls-record','tls-truncated','transport-shape','udp-shape')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 4 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin @('schemaVersion','outcome','code','evidence')}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.code -cnotin $codes -or $v.outcome -cnotin @('decoded','refused')){return $bad}
    if($v.outcome -ceq 'refused'){if($v.code -ceq 'none' -or $null -ne $v.evidence){return $bad};$r=New-DoHNetEventTlsEvidence $v.code;$r.observation='refused';return $r}
    $e=$v.evidence
    if($v.code -cne 'none' -or $e -isnot [pscustomobject] -or @($e.PSObject.Properties).Count -ne 9 -or @($e.PSObject.Properties.Name | Where-Object {$_ -cnotin @('schemaVersion','observation','packets','plaintextPackets','flows','dnsPayloadDecrypted','ordinaryResolverBound','negativeControlPassed','productionQualificationComplete')}).Count -ne 0 -or $e.schemaVersion -isnot [int] -or $e.schemaVersion -ne 1 -or $e.observation -cnotin @('tls-observed','insufficient') -or $e.packets -isnot [int] -or $e.packets -lt 1 -or $e.packets -gt 4096 -or $e.plaintextPackets -isnot [int] -or $e.plaintextPackets -lt 0 -or $e.plaintextPackets -gt $e.packets -or $e.flows -isnot [array] -or $e.flows.Count -gt 32){return $bad}
    foreach($key in @('dnsPayloadDecrypted','ordinaryResolverBound','negativeControlPassed','productionQualificationComplete')){if($e.$key -isnot [bool] -or $e.$key){return $bad}}
    $r=New-DoHNetEventTlsEvidence 'none';$r.observation=$e.observation;$r.packets=$e.packets;$r.plaintextPackets=$e.plaintextPackets;$positive=$false
    foreach($flow in $e.flows){
        if($flow -isnot [pscustomobject] -or @($flow.PSObject.Properties).Count -ne 6 -or @($flow.PSObject.Properties.Name | Where-Object {$_ -cnotin @('provider','clientHello','serverHello','outboundEncryptedRecords','inboundEncryptedRecords','records')}).Count -ne 0 -or $flow.provider -cnotin @('google-v4','quad9-v4','google-v6','quad9-v6') -or $flow.clientHello -isnot [bool] -or -not $flow.clientHello -or $flow.serverHello -isnot [bool] -or -not $flow.serverHello){return $bad}
        foreach($key in @('outboundEncryptedRecords','inboundEncryptedRecords','records')){if(($flow.$key -isnot [int] -and $flow.$key -isnot [long]) -or $flow.$key -lt 0 -or $flow.$key -gt 4194304){return $bad}}
        if($flow.records -lt $flow.outboundEncryptedRecords+$flow.inboundEncryptedRecords+2){return $bad}
        $r.tlsFlows++;$r.providerMask=$r.providerMask -bor $(switch -CaseSensitive ($flow.provider){'google-v4'{1}'quad9-v4'{2}'google-v6'{4}'quad9-v6'{8}});$r.outboundEncryptedRecords+=$flow.outboundEncryptedRecords;$r.inboundEncryptedRecords+=$flow.inboundEncryptedRecords;if($flow.outboundEncryptedRecords -gt 0 -and $flow.inboundEncryptedRecords -gt 0){$positive=$true}
    }
    if(($e.observation -ceq 'tls-observed') -ne ($positive -and $e.plaintextPackets -eq 0)){return $bad};return $r
}
function Start-DoHNetEventCapture([object]$State) {
    $State.phase='decoder-preflight';$version=Invoke-DoHNetEventProcess $State $State.node @('--version')
    if($version.Trim() -cne 'v26.8.2'){throw 'Product capture Node version'}
    $probe=Invoke-DoHNetEventProcess $State $State.node @($State.decoder) (New-NativeDNSWireProbeBytes)
    $e=Get-DoHNetEventTlsEvidence $probe;if($e.code -cne 'capture-empty' -or $e.observation -cne 'refused'){throw 'Product capture decoder preflight'}
    if(@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop).Count -ne 0){throw 'Product capture name policy'}
    $State.phase='firewall-preflight';Assert-NativeDNSWireFirewall
    $State.phase='baseline-resolver';[void](Invoke-NativeDNSWireQuery 'example.com');$State.flags.baselineResolverPassed=$true
    $State.ndis.plan=@{name=('awndis-'+[guid]::NewGuid().ToString('N'));file=$State.etl;guid='';originalVerified=$false;capturePolicy='product-doh-all'}
    $State.phase='monitor-preflight';$v=Invoke-DoHNetEventOperation $State 'preflight';$State.ndis.public.preflightEmpty=$v.emptyBefore
    if(-not $v.emptyBefore){throw 'Product capture inventory'}
    $State.phase='capture-create';$v=Invoke-DoHNetEventOperation $State 'create';$State.ndis.public.sessionVerified=$v.sessionVerified;$State.ndis.created=$true
    $State.phase='offload-prepare';$v=Invoke-DoHNetEventOffload $State 'prepare';$State.ndis.public.offloadPrepareEvidence=$v
    if($v.code -cne 'none'){throw 'Product capture offload plan'};$State.ndis.prepared=$true;$State.ndis.count=$v.adapters
    $rows=[Collections.Generic.List[object]]::new();$State.phase='offload-stage'
    for($ordinal=0;$ordinal -lt $State.ndis.count;$ordinal++){$v=Invoke-DoHNetEventOffload $State 'stage' $ordinal;$rows.Add($v);$State.ndis.public.offloadStageEvidence=@($rows.ToArray());if($v.code -cne 'none'){throw 'Product capture offload stage'}}
    $State.phase='offload-verify';$v=Invoke-DoHNetEventOffload $State 'verify';$State.ndis.public.offloadVerifyEvidence=$v;if($v.code -cne 'none'){throw 'Product capture offload topology'}
    $State.phase='filter-verification';$v=Invoke-DoHNetEventOperation $State 'provider'
    if(-not $v.providerVerified){throw 'Product capture filters'};$State.ndis.public.filterEvidence.verified=$true;$State.flags.filtersVerified=$true
    $State.phase='capture-start';$State.startAttempted=$true;$v=Invoke-DoHNetEventOperation $State 'start'
    if($v.state -cne 'running'){throw 'Product capture start'};$State.flags.captureStarted=$true
}
function Stop-DoHNetEventCapture([object]$State) {
    if($null -ne $State.ndis.plan -and -not $State.stopped){$v=Invoke-DoHNetEventOperation $State 'stop';if($v.state -cnotin @('stopped','absent')){throw 'Product capture stop'};$State.stopped=$true;$State.flags.captureStopped=$true}
}
function Read-DoHNetEventCapture([object]$State) {
    $State.phase='capture-file';Measure-NativeDNSWireFile $State 'etl';$State.ndis.public.etlBytes=$State.etlBytes;$State.ndis.public.captureBounded=$true
    $State.phase='loss-metadata';$text=Invoke-DoHNetEventProcess $State $State.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'read-native-etl-loss.ps1'),'-CapturePath',$State.etl)
    $State.ndis.public.lossEvidence=Get-NativeNDISLossEvidence $text;if(-not (Test-NativeNDISLossEvidence $State.ndis.public.lossEvidence)){throw 'NDIS loss metadata unverified'}
    $State.phase='headers';$text=Invoke-DoHNetEventProcess $State $State.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeNDISHeaderProgram $State.etl))
    $State.ndis.public.eventEvidence=Get-NativeNDISHeaderEvidence $text
    $State.phase='fragment-headers';$text=Invoke-DoHNetEventProcess $State $State.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeNDISFragmentProgram $State.etl))
    $State.ndis.public.fragmentEvidence=Get-NativeNDISFragmentEvidence $text
    if(-not (Test-NativeNDISFragmentEvidence $State.ndis.public.fragmentEvidence)){throw 'NDIS fragment metadata unverified'}
    $f=$State.ndis.public.fragmentEvidence;$e=$State.ndis.public.eventEvidence
    if($e.code -cne 'complete' -or $e.records -ne $f.records -or $e.fragmentIDs -ne $f.fragmentIDs -or $e.unknownProviderIDs -ne $f.metadataIDs+$f.unknownProviderIDs -or $e.otherProviderRecords -ne $f.otherProviderRecords -or $e.missingProviderIDs -ne $f.missingProviderIDs){throw 'NDIS header enumerations disagree'}
    $State.phase='provider-catalog';$text=Invoke-DoHNetEventProcess $State $State.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeNDISCatalogLoader $State.etl (Join-Path $PSScriptRoot 'native-netevent-control.ps1')))
    $State.ndis.public.catalogEvidence=Get-NativeNDISCatalogEvidence $text
    if(-not (Test-NativeNDISCatalogEvidence $State.ndis.public.catalogEvidence)){throw 'NDIS provider catalog unresolved'}
    $catalog=$State.ndis.public.catalogEvidence
    if($catalog.records -ne $e.records -or $catalog.fragmentRecords -ne $e.fragmentIDs -or $catalog.metadataRecords+$catalog.ruleRecords+$catalog.inventoryRecords+$catalog.lifecycleRecords+$catalog.rundownRecords+$catalog.unknownRecords -ne $e.unknownProviderIDs -or $catalog.otherProviderRecords -ne $e.otherProviderRecords -or $catalog.missingProviderIDs -ne $e.missingProviderIDs -or $catalog.unrecognizedVersions -ne $e.unrecognizedVersions){throw 'NDIS catalog enumeration disagrees'}
    $State.phase='frame-extraction';$text=Invoke-DoHNetEventProcess $State $State.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'extract-native-ndis.ps1'),'-CapturePath',$State.etl,'-ExpectedFragments',([string]$f.fragmentIDs),'-ExpectedCaptureBytes',([string]$State.ndis.public.etlBytes))
    $State.ndis.public.extractionEvidence=Get-NativeNDISExtractionEvidence $text;$ex=$State.ndis.public.extractionEvidence
    if($ex.code -cne 'none' -or $ex.records -ne $catalog.records -or $ex.frames -ne $f.fragmentIDs -or -not $ex.payloadRead){throw 'Private NDIS extraction refused'}
    $State.phase='frame-conversion';$text=Invoke-DoHNetEventProcess $State $State.node @((Join-Path $PSScriptRoot 'ndis-private-convert.cjs'),$State.ndis.root)
    $State.ndis.public.conversionEvidence=Get-NativeNDISConversionEvidence $text;$cv=$State.ndis.public.conversionEvidence
    if($cv.outcome -cne 'converted' -or $cv.code -cne 'none' -or -not $cv.nativeFrameDataRead){throw 'Private NDIS conversion refused'}
    $q=$cv.summary
    if($q.frames -ne $f.fragmentIDs -or $q.ipv4+$q.ipv6 -ne $q.frames -or $q.tcp+$q.udp -ne $q.frames -or $q.sent -ne $f.sent -or $q.received -ne $f.received){throw 'Private conversion counts disagree'}
    $State.phase='pcap-file';$State.pcap=Join-Path $State.ndis.root 'capture.pcapng';Measure-NativeDNSWireFile $State 'pcap';$State.ndis.public.pcapBytes=$State.pcapBytes
    if($State.ndis.public.pcapBytes -ne $q.captureBytes){throw 'Private conversion file size disagrees'}

    $State.phase='phase-headers';$text=Invoke-DoHNetEventProcess $State $State.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'read-native-ndis-phases.ps1'),'-CapturePath',$State.etl,'-ExpectedFragments',([string]$f.fragmentIDs),'-ExpectedCaptureBytes',([string]$State.etlBytes),'-BoundaryUtcTicks',([string]$State.ndis.configuredUtcTicks))
    $State.ndis.public.phaseReadEvidence=Get-DoHPhaseReadEvidence $text;$pr=$State.ndis.public.phaseReadEvidence
    if($pr.code -ceq 'none' -and $pr.privateMapWritten -and $pr.records -eq $catalog.records -and $pr.frames -eq $f.fragmentIDs){
        $State.phase='phase-counts';$text=Invoke-DoHNetEventProcess $State $State.node @((Join-Path $PSScriptRoot 'ndis-private-phases.cjs'),$State.ndis.root)
        $State.ndis.public.phaseEvidence=Get-DoHPhaseEvidence $text;$pe=$State.ndis.public.phaseEvidence
        $State.ndis.phaseVerified=($pe.outcome -ceq 'complete' -and $pe.code -ceq 'none' -and $pe.records -eq $catalog.records -and $pe.frames -eq $q.frames -and $pe.tcpBefore+$pe.tcpAt+$pe.tcpAfter -eq $q.tcp -and $pe.udpBefore+$pe.udpAt+$pe.udpAfter -eq $q.udp -and $pe.sentBefore+$pe.sentAt+$pe.sentAfter -eq $q.sent -and $pe.receivedBefore+$pe.receivedAt+$pe.receivedAfter -eq $q.received)
    }
    $State.phase='tls-decode';$bytes=Read-NativeDNSWireCapture $State
    $text=Invoke-DoHNetEventProcess $State $State.node @($State.decoder) $bytes
    $State.ndis.public.tlsWireEvidence=Get-DoHNetEventTlsEvidence $text
    return $State.ndis.public.tlsWireEvidence
}
function Measure-DoHNetEventWire([object]$State) {
    $State.phase='plaintext-block';Assert-NativeDNSWireFirewall;Add-NativeDNSWireRule $State 'dns' 'UDP';Add-NativeDNSWireRule $State 'dns' 'TCP';$State.flags.plaintextBlocked=$true
    $State.phase='ordinary-query';[void](Invoke-NativeDNSWireQuery 'example.net');$State.flags.ordinaryQueryPassed=$true
    $State.phase='offload-measure';$v=Invoke-DoHNetEventOffload $State 'verify';$State.ndis.public.offloadMeasureEvidence=$v;if($v.code -cne 'none'){throw 'Product capture topology changed'}
    $State.phase='capture-stop';Stop-DoHNetEventCapture $State
    $State.phase='capture-read';$tw=Read-DoHNetEventCapture $State;$State.decoderCode=$tw.code
    $refused=(($tw.observation -ceq 'refused' -and $tw.code -cnotin @('none','invalid','not-inspected')) -or ($tw.observation -ceq 'insufficient' -and $tw.code -ceq 'none'))
    if(-not $refused){
        if($tw.code -cne 'none' -or $tw.observation -cne 'tls-observed' -or $tw.plaintextPackets -ne 0 -or $tw.packets -ne $State.ndis.public.fragmentEvidence.fragmentIDs -or $tw.tlsFlows -lt 1 -or $tw.providerMask -lt 1 -or $tw.providerMask -gt 15 -or $tw.outboundEncryptedRecords -lt 1 -or $tw.inboundEncryptedRecords -lt 1){throw 'Product TLS evidence refused'}
        $State.flags.tlsObserved=$true;$State.providers=$tw.providerMask;$State.outRecords=$tw.outboundEncryptedRecords;$State.inRecords=$tw.inboundEncryptedRecords;$State.tlsFlows=$tw.tlsFlows
    }
    try{
        $State.phase='tls-block';Add-NativeDNSWireRule $State 'tls' 'TCP';$State.flags.tlsBlocked=$true
        $State.phase='blocked-query';[void](Invoke-NativeDNSWireQuery 'example.org' -ExpectFailure);$State.flags.blockedQueryRejected=$true
    }catch{if($State.failurePhase -ceq 'none'){$State.failurePhase=$State.phase};throw}finally{
        $State.phase='tls-unblock';Remove-NativeDNSWireRules $State 'tls';$State.flags.tlsBlockRemoved=$true
    }
    $State.phase='resumed-query';[void](Invoke-NativeDNSWireQuery 'example.org');$State.flags.resumedQueryPassed=$true
    if($refused){$State.phase='decode';throw 'Product wire decoder refused'}
    if(-not $State.ndis.phaseVerified){$State.phase='phase-evidence';throw 'Product phase evidence unresolved'}
}
function Complete-DoHNetEventCleanup([object]$State) {
    $State.cleanupAttempted=$true;$good=$true
    $State.phase='cleanup-stop';try{Stop-DoHNetEventCapture $State}catch{$good=$false;$State.ndis.public.cleanupCode='stop'}
    if($State.ndis.prepared){
        $rows=[Collections.Generic.List[object]]::new();$State.phase='cleanup-offload'
        for($ordinal=0;$ordinal -lt $State.ndis.count;$ordinal++){
            try{$v=Invoke-DoHNetEventOffload $State 'restore' $ordinal;$rows.Add($v);if($v.code -cne 'none' -or -not $v.restored -or -not $v.readbackVerified){throw 'Product offload recovery refused'}}catch{$good=$false;$State.ndis.public.cleanupCode='offload'}
        };$State.ndis.public.offloadRestoreEvidence=@($rows.ToArray())
    }
    $State.phase='cleanup-state';try{if($null -eq $State.before){throw 'Product original state missing'};Assert-DNSAcceptanceRestored $State.before (Read-DNSAcceptanceState);$State.flags.originalStateVerified=$true}catch{$good=$false;$State.ndis.public.cleanupCode='original'}
    $State.phase='cleanup-rules';try{Remove-NativeDNSWireRules $State 'tls';Remove-NativeDNSWireRules $State 'dns';$State.flags.rulesRemoved=$true}catch{$good=$false;$State.ndis.public.cleanupCode='rules'}
    $State.phase='cleanup-resolver';try{[void](Invoke-NativeDNSWireQuery 'example.com');$State.flags.originalResolverPassed=$true}catch{$good=$false;$State.ndis.public.cleanupCode='resolver'}
    if(-not $good){throw 'Product capture recovery unresolved'}
    $State.phase='cleanup-session'
    if($null -ne $State.ndis.plan){$State.ndis.plan.originalVerified=$true;$v=Invoke-DoHNetEventOperation $State 'remove';if(-not $v.emptyAfter){throw 'Product capture retirement refused'};$State.ndis.public.sessionRemoved=$true;$State.flags.filtersRemoved=$true}
    else{$State.flags.filtersRemoved=$true}
    $State.phase='complete';$State.cleanupCompleted=$true
}
function Get-DoHNetEventSummary([object]$State) {
    $p=$State.ndis.public
    $passed=($State.flags.Count -eq 16 -and @($State.flags.Values | Where-Object {$_ -isnot [bool] -or -not $_}).Count -eq 0 -and $State.processes -eq $State.joined -and -not $State.processFailed -and $State.decoderCode -ceq 'none' -and $State.outRecords -gt 0 -and $State.inRecords -gt 0 -and $State.cleanupCompleted -and $State.ndis.phaseVerified -and $p.cleanupCode -ceq 'none' -and $p.preflightEmpty -and $p.sessionVerified -and $p.sessionRemoved -and $p.conversionEvidence.summary.tcpClosure.resetFlows -eq 0)
    return @{schemaVersion=1;backend='netevent-ndis';outcome=$(if($passed){'passed'}else{'failed'});phase=$State.phase;failurePhase=$State.failurePhase;decoderCode=$State.decoderCode;controls=$State.flags;capture=$p;toolProcesses=$State.processes;toolProcessesJoined=$State.joined;toolFailure=$State.processFailed;processFailureCode=$State.processFailureCode;etlBytes=$State.etlBytes;pcapBytes=$State.pcapBytes;tlsFlows=$State.tlsFlows;outboundEncryptedRecords=$State.outRecords;inboundEncryptedRecords=$State.inRecords;providerMask=$State.providers;rawCapturePublished=$false;productionQualificationComplete=$false}
}
