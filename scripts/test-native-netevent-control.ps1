# Fresh hosted NDIS capture control only. Never run locally.
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$ReportPath,[ValidateSet('control-google-v4','product-doh-all')][string]$CapturePolicy='control-google-v4')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Assert-NativeOrdinaryPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){
        if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Native fixture reparse boundary refused'}}
        $next=Split-Path -Parent $current;if($next -eq $current){break};$current=$next
    }
}
if(-not [IO.Path]::IsPathRooted($ReportPath)){throw 'Absolute control report path required'}
$ReportPath=[IO.Path]::GetFullPath($ReportPath);Assert-NativeOrdinaryPath $ReportPath
$reportParent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ReportPath)) -Force -ErrorAction Stop
if([IO.Path]::GetFileName($ReportPath) -cne 'status.json' -or -not $reportParent.PSIsContainer -or [IO.Directory]::GetFileSystemEntries($reportParent.FullName).Length -ne 0){throw 'Empty ordinary control report parent required'}
$reportCreated=$reportParent.CreationTimeUtc.Ticks;$project=Split-Path -Parent $PSScriptRoot
$sources=@('scripts/native-doh-offload-plan.ps1','scripts/doh-offload-operation.ps1','scripts/native-ipv6-route-table.ps1','scripts/read-native-ipv6-route-table.ps1','scripts/native-doh-route-state.ps1','scripts/read-native-doh-route-state.ps1','scripts/offload-control-operation.ps1','scripts/native-offload-state.ps1','scripts/read-native-offload-state.ps1','scripts/ndis-tls-control.cjs','scripts/dns-wire-stdin.cjs','scripts/extract-native-ndis.ps1','scripts/ndis-private-convert.cjs','scripts/dns-wire-ip-policy.cjs','scripts/dns-wire-evidence.cjs','scripts/ndis-frame-converter.cjs','scripts/test-ndis-frame-converter.cjs','scripts/native-netevent-control.ps1','scripts/native-etl-header.cs','scripts/read-native-etl-loss.ps1','scripts/netevent-control-operation.ps1','scripts/test-native-netevent-control.ps1','scripts/test-native-netevent-contracts.ps1','.github/workflows/native-netevent-control.yml','scripts/native-dns-wire.ps1','scripts/dns-acceptance-state.ps1')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$state=$null;$plan=$null;$environmentVerified=$false;$nativeProcessVerified=$false;$outcome='failed';$code='environment'
$emptyEvidence=@{stage='not-inspected';family='none';hresult=0;cimStatus=-1;modeKind='not-inspected';statusKind='not-inspected'}
$control=@{ipv6TableEvidence=$null;routeEvidence=$null;filterEvidence=$null;offloadPrepareEvidence=$null;offloadDigestEvidence=$null;offloadStageEvidence=@();offloadVerifyEvidence=$null;offloadMeasureEvidence=$null;offloadRestoreEvidence=@();offloadEvidence=$null;tlsStimulusEvidence=$null;tlsWireEvidence=$null;extractionEvidence=$null;conversionEvidence=$null;pcapBytes=0;catalogEvidence=$null;fragmentEvidence=$null;lossEvidence=$null;operationEvidence=$emptyEvidence;cleanupEvidence=$emptyEvidence;outcome='failed';phase='preflight';code='not-started';cleanupCode='none';preflightEmpty=$false;sessionVerified=$false;providerVerified=$false;captureStarted=$false;captureStopped=$false;connected=$false;captureBounded=$false;etlBytes=0;originalStateVerified=$false;originalResolverPassed=$false;sessionRemoved=$false;processes=0;joined=0;toolFailure=$false;eventEvidence=$null}
function Invoke-NativeNDISOperation([string]$Operation) {
    $script:lastOperationCode='none';$script:lastEvidence=$emptyEvidence
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){throw 'NDIS source changed'}}
    $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($script:plan | ConvertTo-Json -Compress)))
    $text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'netevent-control-operation.ps1'),'-Operation',$Operation,'-PlanBase64',$payload)
    $v=$text | ConvertFrom-Json -ErrorAction Stop
    $keys=@('diagnostic','code','sessionGuid','state','sessionVerified','providerVerified','emptyBefore','emptyAfter')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 8 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.code -cnotin @('none','operation','plan','enum','session','identity','configuration','state','provider','filters','inventory','original') -or $v.state -cnotin @('unknown','absent','running','stopped')){throw 'NDIS operation shape'}
    foreach($key in @('sessionVerified','providerVerified','emptyBefore','emptyAfter')){if($v.$key -isnot [bool]){throw 'NDIS operation shape'}}
    $diag=$v.diagnostic
    if($diag -isnot [pscustomobject] -or @($diag.PSObject.Properties).Count -ne 6 -or @($diag.PSObject.Properties.Name | Where-Object {$_ -cnotin @('stage','family','hresult','cimStatus','modeKind','statusKind')}).Count -ne 0 -or $diag.stage -cnotin @('initial','enum-metadata','inventory-readback','session-readback','provider-readback','create-request','provider-request','start-request','stop-request','remove-request') -or $diag.family -cnotin @('none','cim','win32','argument','state','invocation','other') -or ($diag.hresult -isnot [int] -and $diag.hresult -isnot [long]) -or $diag.hresult -lt -2147483648 -or $diag.hresult -gt 2147483647 -or ($diag.cimStatus -isnot [int] -and $diag.cimStatus -isnot [long]) -or $diag.cimStatus -lt -1 -or $diag.cimStatus -gt 65535 -or $diag.modeKind -cnotin @('null','enum','string','numeric','other','not-inspected') -or $diag.statusKind -cnotin @('null','enum','string','numeric','other','not-inspected')){throw 'NDIS diagnostic shape'}
    $script:lastEvidence=@{stage=$diag.stage;family=$diag.family;hresult=$diag.hresult;cimStatus=$diag.cimStatus;modeKind=$diag.modeKind;statusKind=$diag.statusKind}
    if($v.code -cne 'none'){$script:lastOperationCode=$v.code;throw 'NDIS native operation refused'}
    if($v.sessionGuid -isnot [string] -or ($v.sessionGuid -and $v.sessionGuid -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')){throw 'NDIS operation identity'}
    if($v.sessionGuid){if($script:plan.guid -and $script:plan.guid -cne $v.sessionGuid){throw 'NDIS operation identity'};$script:plan.guid=$v.sessionGuid}
    return $v
}
$script:lastOperationCode='none';$script:lastEvidence=$emptyEvidence;$script:offloadAttempted=$false;$script:offloadPrepared=$false;$script:offloadCount=0;$script:dohPlanDigest=''
function Invoke-NativeOffloadOperation([string]$Operation,[int]$Ordinal=-1,[switch]$RejectDigest) {
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){throw 'Offload source changed'}}
    $arguments=@('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'doh-offload-operation.ps1'),'-Operation',$Operation,'-PrivateRoot',$privateRoot,'-Ordinal',([string]$Ordinal));if($Operation -cne 'prepare'){$expected=$script:dohPlanDigest;if($RejectDigest){$expected=$(if($expected[0] -ceq '0'){'1'}else{'0'})+$expected.Substring(1)};$arguments+=@('-ExpectedDigest',$expected)}
    $text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool $arguments;$reply=$text | ConvertFrom-Json -ErrorAction Stop
    if($reply -isnot [pscustomobject] -or @($reply.PSObject.Properties).Count -ne 2 -or @($reply.PSObject.Properties.Name | Where-Object {$_ -cnotin @('summary','digest')}).Count -ne 0 -or $reply.digest -isnot [string]){throw 'Private offload IPC'}
    $summary=Get-NativeDoHOffloadEvidence ($reply.summary | ConvertTo-Json -Depth 4 -Compress) $Operation
    if($Operation -ceq 'prepare' -and $summary.code -ceq 'none'){if($reply.digest -cnotmatch '^[a-f0-9]{64}$'){throw 'Private offload digest'};$script:dohPlanDigest=$reply.digest}elseif($reply.digest){throw 'Unexpected private offload digest'}
    return $summary
}

try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:ACCESSWEAVER_EXPECT_GOOS -cne 'windows' -or $env:ACCESSWEAVER_EXPECT_GOARCH -cnotin @('amd64','arm64')){throw 'Hosted native Windows guard refused'}
    if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Stock Windows PowerShell5.1 required'}
    if($env:GITHUB_SHA -notmatch '^[a-f0-9]{40}$'){throw 'Native source or SDK identity missing'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Unexpected interop environment'}}
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if($computer.Model -notmatch 'Virtual|VMware' -or $computer.PartOfDomain -ne $false){throw 'Fresh non-domain virtual machine required'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Hosted administrator token required'}
    Add-Type -TypeDefinition '
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class AccessWeaverNetEventControlIdentity {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    public static bool Matches(string architecture) {
        using (Process process = Process.GetCurrentProcess()) {
            ushort machine, native;
            if (!IsWow64Process2(process.Handle, out machine, out native)) return false;
            return machine == 0 && native == (architecture == "amd64" ? 0x8664 : 0xaa64);
        }
    }
}
'
    if(-not [AccessWeaverNetEventControlIdentity]::Matches($env:ACCESSWEAVER_EXPECT_GOARCH)){throw 'Native PowerShell process architecture differs'}
    $nativeProcessVerified=$true
    $machineRoot=Join-Path $env:ProgramData 'AccessWeaver';Assert-NativeOrdinaryPath $machineRoot
    if((Test-Path -LiteralPath $machineRoot) -or @(Get-Service -Name 'AccessWeaver*' -ErrorAction SilentlyContinue).Count -ne 0){throw 'Preexisting product state refused'}
    $environmentVerified=$true;$code='private-root';$control.phase='private-root'
    $privateRoot=[IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'),('AccessWeaver-NetEventControl-'+[guid]::NewGuid().ToString('N')))
    Assert-NativeOrdinaryPath $privateRoot;if(Test-Path -LiteralPath $privateRoot){throw 'Existing private control root'}
    [void][IO.Directory]::CreateDirectory($privateRoot)
    $security=[Security.AccessControl.DirectorySecurity]::new();$security.SetOwner($identity.User);$security.SetAccessRuleProtection($true,$false)
    foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $privateRoot -AclObject $security -ErrorAction Stop
    $control.phase='helper-load'
    . (Join-Path $PSScriptRoot 'native-dns-wire.ps1')
    . (Join-Path $PSScriptRoot 'native-netevent-control.ps1')
    . (Join-Path $PSScriptRoot 'native-offload-state.ps1')
    . (Join-Path $PSScriptRoot 'native-doh-route-state.ps1')
    . (Join-Path $PSScriptRoot 'native-ipv6-route-table.ps1')
    . (Join-Path $PSScriptRoot 'native-doh-offload-plan.ps1')
    . (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
    $control.lossEvidence=New-NativeNDISLossEvidence
    $control.eventEvidence=New-NativeNDISHeaderEvidence
    $control.fragmentEvidence=New-NativeNDISFragmentEvidence
    $control.catalogEvidence=New-NativeNDISCatalogEvidence
    $control.extractionEvidence=New-NativeNDISExtractionEvidence
    $control.conversionEvidence=New-NativeNDISConversionEvidence
    $control.tlsStimulusEvidence=New-NativeNDISTlsStimulusEvidence
    $control.tlsWireEvidence=New-NativeNDISTlsWireEvidence
    $control.offloadDigestEvidence=New-NativeDoHOffloadEvidence 'stage'
    $control.offloadPrepareEvidence=New-NativeDoHOffloadEvidence 'prepare'
    $control.offloadVerifyEvidence=New-NativeDoHOffloadEvidence 'verify'
    $control.offloadMeasureEvidence=New-NativeDoHOffloadEvidence 'verify'
    $control.ipv6TableEvidence=New-NativeIPv6RouteTableEvidence
    $control.routeEvidence=New-NativeDoHRouteEvidence
    $control.offloadEvidence=New-NativeOffloadEvidence
    $code='baseline';$control.phase='baseline-tools';$script:state=New-NativeDNSWireState $privateRoot (Join-Path $PSScriptRoot 'dns-wire-stdin.cjs');$script:state.etl=Join-Path $privateRoot 'capture.etl'
    $control.phase='baseline-state';$script:state.before=Read-DNSAcceptanceState
    $control.phase='baseline-resolver';[void](Invoke-NativeDNSWireQuery 'example.com')
    $control.phase='offload-state';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'read-native-offload-state.ps1'))
    $control.offloadEvidence=Get-NativeOffloadEvidence $text;if($control.offloadEvidence.code -cne 'none'){throw 'Read-only offload state unresolved'}
    $control.phase='doh-route-state';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'read-native-doh-route-state.ps1'))
    $control.routeEvidence=Get-NativeDoHRouteEvidence $text;if($control.routeEvidence.code -cne 'complete' -or -not $control.routeEvidence.allConsistent -or ($control.routeEvidence.matchedMask -band 1) -eq 0){throw 'DoH route probe incomplete'}
    $control.phase='ipv6-route-table';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'read-native-ipv6-route-table.ps1'))
    $control.ipv6TableEvidence=Get-NativeIPv6RouteTableEvidence $text;if($control.ipv6TableEvidence.code -cne 'complete' -or -not $control.ipv6TableEvidence.consistent){throw 'Active IPv6 route table unverified'}
    $script:plan=@{name=('awndis-'+[guid]::NewGuid().ToString('N'));file=$script:state.etl;guid='';originalVerified=$false;capturePolicy=$CapturePolicy}
    $code='control';$control.phase='preflight';$v=Invoke-NativeNDISOperation 'preflight';$control.preflightEmpty=$v.emptyBefore
    if(-not $v.emptyBefore){throw 'NDIS preflight inventory'}
    $control.phase='create';$v=Invoke-NativeNDISOperation 'create';$control.sessionVerified=$v.sessionVerified
    $control.phase='offload-prepare';$script:offloadAttempted=$true;$control.offloadPrepareEvidence=Invoke-NativeOffloadOperation 'prepare'
    if($control.offloadPrepareEvidence.code -cne 'none'){throw 'General offload preparation unresolved'};$script:offloadPrepared=$true;$script:offloadCount=$control.offloadPrepareEvidence.adapters
    $control.phase='offload-digest';$control.offloadDigestEvidence=Invoke-NativeOffloadOperation 'stage' 0 -RejectDigest
    $guard=$control.offloadDigestEvidence;if($guard.code -cne 'plan' -or $guard.identityVerified -or $guard.readbackVerified -or $guard.changed -or $guard.restartRequested -or $guard.restartReturned -or $guard.restored -or $guard.topologyVerified -or $guard.adapters -ne 0 -or $guard.matchedMask -ne 0 -or $guard.unroutedMask -ne 0){throw 'Private digest refusal unverified'}
    $stageRows=[Collections.Generic.List[object]]::new();$control.phase='offload-stage'
    for($ordinal=0;$ordinal -lt $script:offloadCount;$ordinal++){$v=Invoke-NativeOffloadOperation 'stage' $ordinal;$stageRows.Add($v);$control.offloadStageEvidence=@($stageRows.ToArray());if($v.code -cne 'none'){throw 'General offload stage unresolved'}}
    $control.phase='offload-verify';$control.offloadVerifyEvidence=Invoke-NativeOffloadOperation 'verify';if($control.offloadVerifyEvidence.code -cne 'none'){throw 'General offload topology unresolved'}
    $control.phase='provider';$v=Invoke-NativeNDISOperation 'provider';$control.providerVerified=$v.providerVerified
    $policy=Get-NativeNetEventCapturePolicy $CapturePolicy;$control.filterEvidence=@{policy=$CapturePolicy;endpointMask=$policy.endpointMask;etherTypeMask=$policy.etherTypeMask;protocolMask=$policy.protocolMask;portsFiltered=$false;verified=$v.providerVerified}
    $control.phase='start';$v=Invoke-NativeNDISOperation 'start';$control.captureStarted=($v.state -ceq 'running')
    if(-not $control.captureStarted){throw 'NDIS start state'}
    $control.phase='tls-stimulus';$reply=Invoke-NativeDNSWireProcess $script:state $script:state.node @((Join-Path $PSScriptRoot 'ndis-tls-control.cjs'))
    $control.tlsStimulusEvidence=Get-NativeNDISTlsStimulusEvidence $reply;$control.connected=($control.tlsStimulusEvidence.outcome -ceq 'passed');if(-not $control.connected){throw 'Fixed DoH stimulus refused'}
    $control.phase='offload-measure';$control.offloadMeasureEvidence=Invoke-NativeOffloadOperation 'verify';if($control.offloadMeasureEvidence.code -cne 'none'){throw 'Capture offload topology changed'}
    $control.phase='stop';$v=Invoke-NativeNDISOperation 'stop';$control.captureStopped=($v.state -ceq 'stopped')
    if(-not $control.captureStopped){throw 'NDIS stop state'}
    $control.phase='capture-file';Measure-NativeDNSWireFile $script:state 'etl';$control.etlBytes=$script:state.etlBytes;$control.captureBounded=$true
    $control.phase='loss-metadata';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'read-native-etl-loss.ps1'),'-CapturePath',$script:state.etl)
    $control.lossEvidence=Get-NativeNDISLossEvidence $text;if(-not (Test-NativeNDISLossEvidence $control.lossEvidence)){throw 'NDIS loss metadata unverified'}
    $control.phase='headers';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeNDISHeaderProgram $script:state.etl))
    $control.eventEvidence=Get-NativeNDISHeaderEvidence $text
    $control.phase='fragment-headers';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeNDISFragmentProgram $script:state.etl))
    $control.fragmentEvidence=Get-NativeNDISFragmentEvidence $text
    if(-not (Test-NativeNDISFragmentEvidence $control.fragmentEvidence)){throw 'NDIS fragment metadata unverified'}
    $f=$control.fragmentEvidence;$e=$control.eventEvidence
    if($e.code -cne 'complete' -or $e.records -ne $f.records -or $e.fragmentIDs -ne $f.fragmentIDs -or $e.unknownProviderIDs -ne $f.metadataIDs+$f.unknownProviderIDs -or $e.otherProviderRecords -ne $f.otherProviderRecords -or $e.missingProviderIDs -ne $f.missingProviderIDs){throw 'NDIS header enumerations disagree'}
    $control.phase='provider-catalog';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeNDISCatalogLoader $script:state.etl (Join-Path $PSScriptRoot 'native-netevent-control.ps1')))
    $control.catalogEvidence=Get-NativeNDISCatalogEvidence $text
    if(-not (Test-NativeNDISCatalogEvidence $control.catalogEvidence)){throw 'NDIS provider catalog unresolved'}
    $catalog=$control.catalogEvidence
    if($catalog.records -ne $e.records -or $catalog.fragmentRecords -ne $e.fragmentIDs -or $catalog.metadataRecords+$catalog.ruleRecords+$catalog.inventoryRecords+$catalog.lifecycleRecords+$catalog.rundownRecords+$catalog.unknownRecords -ne $e.unknownProviderIDs -or $catalog.otherProviderRecords -ne $e.otherProviderRecords -or $catalog.missingProviderIDs -ne $e.missingProviderIDs -or $catalog.unrecognizedVersions -ne $e.unrecognizedVersions){throw 'NDIS catalog enumeration disagrees'}
    $control.phase='frame-extraction';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'extract-native-ndis.ps1'),'-CapturePath',$script:state.etl,'-ExpectedFragments',([string]$f.fragmentIDs),'-ExpectedCaptureBytes',([string]$control.etlBytes))
    $control.extractionEvidence=Get-NativeNDISExtractionEvidence $text;$ex=$control.extractionEvidence
    if($ex.code -cne 'none' -or $ex.records -ne $catalog.records -or $ex.frames -ne $f.fragmentIDs -or -not $ex.payloadRead){throw 'Private NDIS extraction refused'}
    $control.phase='frame-conversion';$text=Invoke-NativeDNSWireProcess $script:state $script:state.node @((Join-Path $PSScriptRoot 'ndis-private-convert.cjs'),$privateRoot)
    $control.conversionEvidence=Get-NativeNDISConversionEvidence $text;$cv=$control.conversionEvidence
    if($cv.outcome -cne 'converted' -or $cv.code -cne 'none' -or -not $cv.nativeFrameDataRead){throw 'Private NDIS conversion refused'}
    $q=$cv.summary
    if($q.frames -ne $f.fragmentIDs -or $q.ipv4 -ne $q.frames -or $q.tcp -ne $q.frames -or $q.ipv6 -ne 0 -or $q.udp -ne 0 -or $q.sent -ne $f.sent -or $q.received -ne $f.received){throw 'Private conversion counts disagree'}
    $control.phase='pcap-file';$script:state.pcap=Join-Path $privateRoot 'capture.pcapng';Measure-NativeDNSWireFile $script:state 'pcap';$control.pcapBytes=$script:state.pcapBytes
    if($control.pcapBytes -ne $q.captureBytes){throw 'Private conversion file size disagrees'}
    $control.phase='tls-decode';$bytes=Read-NativeDNSWireCapture $script:state
    $text=Invoke-NativeDNSWireProcess $script:state $script:state.node @($script:state.decoder) $bytes
    $control.tlsWireEvidence=Get-NativeNDISTlsWireEvidence $text;$tw=$control.tlsWireEvidence
    if($tw.code -cne 'none' -or $tw.observation -cne 'tls-observed' -or $tw.packets -ne $f.fragmentIDs -or $tw.tlsFlows -lt 1 -or $tw.providerMask -ne 1 -or $tw.outboundEncryptedRecords -lt 1 -or $tw.inboundEncryptedRecords -lt 1){throw 'Fixed TLS wire evidence refused'}
    if($control.eventEvidence.code -cne 'complete' -or $control.eventEvidence.fragmentIDs -le 0){$control.code='fragment-events-missing'}else{$control.code='none';$control.outcome='passed'}
}catch{$control.operationEvidence=$script:lastEvidence;$control.outcome='failed';$control.code=if($script:lastOperationCode -cne 'none'){$script:lastOperationCode}else{$control.phase}}
finally{
    if($null -ne $script:plan){
        try{$v=Invoke-NativeNDISOperation 'stop';$control.captureStopped=($v.state -cin @('stopped','absent'))}catch{$control.cleanupEvidence=$script:lastEvidence;$control.cleanupCode=if($script:lastOperationCode -cne 'none'){$script:lastOperationCode}else{'stop'}}
    }
    $offloadRestored=(-not $script:offloadPrepared)
    if($script:offloadPrepared){
        $offloadRestored=$true;$restoreRows=[Collections.Generic.List[object]]::new()
        for($ordinal=0;$ordinal -lt $script:offloadCount;$ordinal++){
            try{$v=Invoke-NativeOffloadOperation 'restore' $ordinal;$restoreRows.Add($v);if($v.code -cne 'none' -or -not $v.restored -or -not $v.readbackVerified){throw 'General offload restoration unresolved'}}catch{$offloadRestored=$false;$control.cleanupCode='offload'}
        };$control.offloadRestoreEvidence=@($restoreRows.ToArray())
    }
    if($null -ne $script:plan -or $script:offloadAttempted){
        try{
            Assert-DNSAcceptanceRestored $script:state.before (Read-DNSAcceptanceState);$control.originalStateVerified=$true
            [void](Invoke-NativeDNSWireQuery 'example.com');$control.originalResolverPassed=$true
            if(-not $offloadRestored){throw 'Offload restoration required before retirement'}
            if($null -ne $script:plan){$script:plan.originalVerified=$true;$v=Invoke-NativeNDISOperation 'remove';$control.sessionRemoved=$v.emptyAfter}
        }catch{$control.cleanupEvidence=$script:lastEvidence;if($control.cleanupCode -ceq 'none'){$control.cleanupCode=if($script:lastOperationCode -cne 'none'){$script:lastOperationCode}else{'recovery'}}}
    }
    if($null -ne $script:state){$control.processes=$script:state.processes;$control.joined=$script:state.joined;$control.toolFailure=$script:state.processFailed}
    $good=($control.outcome -ceq 'passed' -and (Test-NativeNDISLossEvidence $control.lossEvidence) -and (Test-NativeNDISFragmentEvidence $control.fragmentEvidence) -and (Test-NativeNDISCatalogEvidence $control.catalogEvidence) -and $control.extractionEvidence.code -ceq 'none' -and $control.conversionEvidence.outcome -ceq 'converted' -and $control.conversionEvidence.summary.tcpClosure.resetFlows -eq 0 -and $control.pcapBytes -gt 0 -and $control.tlsStimulusEvidence.outcome -ceq 'passed' -and $control.tlsWireEvidence.observation -ceq 'tls-observed' -and $control.tlsWireEvidence.code -ceq 'none' -and $control.offloadEvidence.code -ceq 'none' -and $control.ipv6TableEvidence.code -ceq 'complete' -and $control.ipv6TableEvidence.consistent -and $control.routeEvidence.code -ceq 'complete' -and $control.routeEvidence.allConsistent -and ($control.routeEvidence.matchedMask -band 1) -ne 0 -and $control.offloadDigestEvidence.code -ceq 'plan' -and $control.offloadPrepareEvidence.code -ceq 'none' -and $control.offloadVerifyEvidence.code -ceq 'none' -and $control.offloadMeasureEvidence.code -ceq 'none' -and @($control.offloadStageEvidence).Count -eq $script:offloadCount -and @($control.offloadRestoreEvidence).Count -eq $script:offloadCount -and $offloadRestored -and $control.preflightEmpty -and $control.sessionVerified -and $control.providerVerified -and $null -ne $control.filterEvidence -and $control.filterEvidence.verified -and $control.captureStarted -and $control.captureStopped -and $control.connected -and $control.captureBounded -and $control.originalStateVerified -and $control.originalResolverPassed -and $control.sessionRemoved -and $control.cleanupCode -ceq 'none' -and -not $control.toolFailure -and $control.processes -eq $control.joined)
    if($good){$outcome='passed';$code='none'}else{$outcome='failed';$code='control-failed';$control.outcome='failed'}
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){$outcome='failed';$code='source-changed'}}
    Assert-NativeOrdinaryPath $ReportPath;$parent=Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop
    if($parent.CreationTimeUtc.Ticks -ne $reportCreated -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed private report directory'}
    $report=@{schemaVersion=1;scope='hosted-netevent-capture-control';capturePolicy=$CapturePolicy;sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;platform='windows';architecture=$env:ACCESSWEAVER_EXPECT_GOARCH;edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();outcome=$outcome;code=$code;environmentVerified=$environmentVerified;nativeProcessVerified=$nativeProcessVerified;control=$control;productInvoked=$false;dnsSettingsChangesAttempted=$false;firewallRulesCreated=$false;rawCapturePublished=$false;encryptedTrafficQualified=$false;productionQualificationComplete=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 6 -Compress));if($bytes.Length -gt 16384){throw 'Fixed report bound'}
    $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
if($outcome -cne 'passed'){throw 'NetEvent capture control failed; fixed metadata retained'}
