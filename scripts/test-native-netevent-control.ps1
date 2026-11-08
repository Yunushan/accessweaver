# Fresh hosted NDIS capture control only. Never run locally.
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$ReportPath)
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
$sources=@('scripts/native-netevent-control.ps1','scripts/netevent-control-operation.ps1','scripts/test-native-netevent-control.ps1','scripts/test-native-netevent-contracts.ps1','.github/workflows/native-netevent-control.yml','scripts/native-dns-wire.ps1','scripts/dns-acceptance-state.ps1')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$state=$null;$plan=$null;$environmentVerified=$false;$nativeProcessVerified=$false;$outcome='failed';$code='environment'
$control=@{outcome='failed';phase='preflight';code='not-started';cleanupCode='none';preflightEmpty=$false;sessionVerified=$false;providerVerified=$false;captureStarted=$false;captureStopped=$false;connected=$false;captureBounded=$false;etlBytes=0;originalStateVerified=$false;originalResolverPassed=$false;sessionRemoved=$false;processes=0;joined=0;toolFailure=$false;eventEvidence=$null}
function Invoke-NativeNDISOperation([string]$Operation) {
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){throw 'NDIS source changed'}}
    $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($script:plan | ConvertTo-Json -Compress)))
    $text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'netevent-control-operation.ps1'),'-Operation',$Operation,'-PlanBase64',$payload)
    $v=$text | ConvertFrom-Json -ErrorAction Stop
    $keys=@('code','sessionGuid','state','sessionVerified','providerVerified','emptyBefore','emptyAfter')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 7 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.code -cnotin @('none','operation','plan','enum','session','identity','configuration','state','provider','filters','inventory','original') -or $v.state -cnotin @('unknown','absent','running','stopped')){throw 'NDIS operation shape'}
    foreach($key in @('sessionVerified','providerVerified','emptyBefore','emptyAfter')){if($v.$key -isnot [bool]){throw 'NDIS operation shape'}}
    if($v.code -cne 'none'){$script:lastOperationCode=$v.code;throw 'NDIS native operation refused'}
    if($v.sessionGuid -isnot [string] -or ($v.sessionGuid -and $v.sessionGuid -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')){throw 'NDIS operation identity'}
    if($v.sessionGuid){if($script:plan.guid -and $script:plan.guid -cne $v.sessionGuid){throw 'NDIS operation identity'};$script:plan.guid=$v.sessionGuid}
    return $v
}
$script:lastOperationCode='none'
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
    $environmentVerified=$true;$code='private-root'
    $privateRoot=[IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'),('AccessWeaver-NetEventControl-'+[guid]::NewGuid().ToString('N')))
    Assert-NativeOrdinaryPath $privateRoot;if(Test-Path -LiteralPath $privateRoot){throw 'Existing private control root'}
    [void][IO.Directory]::CreateDirectory($privateRoot)
    $security=[Security.AccessControl.DirectorySecurity]::new();$security.SetOwner($identity.User);$security.SetAccessRuleProtection($true,$false)
    foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $privateRoot -AclObject $security -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'native-dns-wire.ps1')
    . (Join-Path $PSScriptRoot 'native-netevent-control.ps1')
    . (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
    $control.eventEvidence=New-NativeNDISHeaderEvidence
    $code='baseline';$script:state=New-NativeDNSWireState $privateRoot '';$script:state.etl=Join-Path $privateRoot 'capture.etl'
    $script:state.before=Read-DNSAcceptanceState;[void](Invoke-NativeDNSWireQuery 'example.com')
    $script:plan=@{name=('awndis-'+[guid]::NewGuid().ToString('N'));file=$script:state.etl;guid='';originalVerified=$false}
    $code='control';$control.phase='preflight';$v=Invoke-NativeNDISOperation 'preflight';$control.preflightEmpty=$v.emptyBefore
    if(-not $v.emptyBefore){throw 'NDIS preflight inventory'}
    $control.phase='create';$v=Invoke-NativeNDISOperation 'create';$control.sessionVerified=$v.sessionVerified
    $control.phase='provider';$v=Invoke-NativeNDISOperation 'provider';$control.providerVerified=$v.providerVerified
    $control.phase='start';$v=Invoke-NativeNDISOperation 'start';$control.captureStarted=($v.state -ceq 'running')
    if(-not $control.captureStarted){throw 'NDIS start state'}
    $control.phase='connect';$reply=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeDNSCaptureControlProgram))
    $control.connected=($reply.Trim() -ceq 'connected');if(-not $control.connected){throw 'NDIS connection refused'}
    $control.phase='stop';$v=Invoke-NativeNDISOperation 'stop';$control.captureStopped=($v.state -ceq 'stopped')
    if(-not $control.captureStopped){throw 'NDIS stop state'}
    $control.phase='capture-file';Measure-NativeDNSWireFile $script:state 'etl';$control.etlBytes=$script:state.etlBytes;$control.captureBounded=$true
    $control.phase='headers';$text=Invoke-NativeDNSWireProcess $script:state $script:state.eventTool @('-NoProfile','-NonInteractive','-EncodedCommand',(Get-NativeNDISHeaderProgram $script:state.etl))
    $control.eventEvidence=Get-NativeNDISHeaderEvidence $text
    if($control.eventEvidence.code -cne 'complete' -or $control.eventEvidence.fragmentIDs -le 0){$control.code='fragment-events-missing'}else{$control.code='none';$control.outcome='passed'}
}catch{$control.outcome='failed';$control.code=if($script:lastOperationCode -cne 'none'){$script:lastOperationCode}else{$control.phase}}
finally{
    if($null -ne $script:plan){
        try{$v=Invoke-NativeNDISOperation 'stop';$control.captureStopped=($v.state -cin @('stopped','absent'))}catch{$control.cleanupCode=if($script:lastOperationCode -cne 'none'){$script:lastOperationCode}else{'stop'}}
        try{
            Assert-DNSAcceptanceRestored $script:state.before (Read-DNSAcceptanceState);$control.originalStateVerified=$true
            [void](Invoke-NativeDNSWireQuery 'example.com');$control.originalResolverPassed=$true;$script:plan.originalVerified=$true
            $v=Invoke-NativeNDISOperation 'remove';$control.sessionRemoved=$v.emptyAfter
        }catch{if($control.cleanupCode -ceq 'none'){$control.cleanupCode=if($script:lastOperationCode -cne 'none'){$script:lastOperationCode}else{'recovery'}}}
    }
    if($null -ne $script:state){$control.processes=$script:state.processes;$control.joined=$script:state.joined;$control.toolFailure=$script:state.processFailed}
    $good=($control.outcome -ceq 'passed' -and $control.preflightEmpty -and $control.sessionVerified -and $control.providerVerified -and $control.captureStarted -and $control.captureStopped -and $control.connected -and $control.captureBounded -and $control.originalStateVerified -and $control.originalResolverPassed -and $control.sessionRemoved -and $control.cleanupCode -ceq 'none' -and -not $control.toolFailure -and $control.processes -eq $control.joined)
    if($good){$outcome='passed';$code='none'}else{$outcome='failed';$code='control-failed';$control.outcome='failed'}
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){$outcome='failed';$code='source-changed'}}
    Assert-NativeOrdinaryPath $ReportPath;$parent=Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop
    if($parent.CreationTimeUtc.Ticks -ne $reportCreated -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed private report directory'}
    $report=@{schemaVersion=1;scope='hosted-netevent-capture-control';sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;platform='windows';architecture=$env:ACCESSWEAVER_EXPECT_GOARCH;edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();outcome=$outcome;code=$code;environmentVerified=$environmentVerified;nativeProcessVerified=$nativeProcessVerified;control=$control;productInvoked=$false;dnsSettingsChangesAttempted=$false;firewallRulesCreated=$false;rawCapturePublished=$false;encryptedTrafficQualified=$false;productionQualificationComplete=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 4 -Compress));if($bytes.Length -gt 8192){throw 'Fixed report bound'}
    $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
if($outcome -cne 'passed'){throw 'NetEvent capture control failed; fixed metadata retained'}
