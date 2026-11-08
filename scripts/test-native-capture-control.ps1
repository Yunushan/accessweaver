# Fresh hosted Windows capture control only. Never run locally.
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
$sources=@('scripts/test-native-capture-control.ps1','scripts/native-dns-wire.ps1','scripts/test-dns-wire-native-contracts.ps1','scripts/dns-wire-evidence.cjs','scripts/dns-wire-stdin.cjs','scripts/dns-acceptance-state.ps1','.github/workflows/native-capture-control.yml')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$state=$null;$control=$null;$environmentVerified=$false;$nativeProcessVerified=$false;$toolSHA256='';$outcome='failed';$code='environment'
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
public static class AccessWeaverCaptureControlIdentity {
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
    if(-not [AccessWeaverCaptureControlIdentity]::Matches($env:ACCESSWEAVER_EXPECT_GOARCH)){throw 'Native PowerShell process architecture differs'}
    $nativeProcessVerified=$true
    $machineRoot=Join-Path $env:ProgramData 'AccessWeaver';Assert-NativeOrdinaryPath $machineRoot
    if((Test-Path -LiteralPath $machineRoot) -or @(Get-Service -Name 'AccessWeaver*' -ErrorAction SilentlyContinue).Count -ne 0){throw 'Preexisting product state refused'}
    $environmentVerified=$true;$code='private-root'
    $privateRoot=[IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'),('AccessWeaver-CaptureControl-'+[guid]::NewGuid().ToString('N')))
    Assert-NativeOrdinaryPath $privateRoot;if(Test-Path -LiteralPath $privateRoot){throw 'Existing control root refused'}
    [void][IO.Directory]::CreateDirectory($privateRoot)
    $security=[Security.AccessControl.DirectorySecurity]::new();$security.SetOwner($identity.User);$security.SetAccessRuleProtection($true,$false)
    foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $privateRoot -AclObject $security -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'native-dns-wire.ps1')
    . (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
    $code='baseline';$state=New-NativeDNSWireState $privateRoot (Join-Path $PSScriptRoot 'dns-wire-stdin.cjs')
    $state.before=Read-DNSAcceptanceState
    Assert-NativeOrdinaryPath $state.tool;$toolSHA256=(Get-FileHash -LiteralPath $state.tool -Algorithm SHA256).Hash.ToLowerInvariant()
    $code='control';$control=Invoke-NativeDNSCaptureControl $state
    if($control.outcome -ceq 'passed'){$outcome='passed';$code='none'}else{$code='control-failed'}
}catch{$outcome='failed'}
finally{
    if($null -ne $state -and -not $state.cleanupAttempted){try{Complete-NativeDNSWireCleanup $state}catch{$outcome='failed';$code='cleanup'}}
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){$outcome='failed';$code='source-changed'}}
    Assert-NativeOrdinaryPath $ReportPath;$parent=Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop
    if($parent.CreationTimeUtc.Ticks -ne $reportCreated -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed control report parent refused'}
    $report=@{schemaVersion=1;scope='hosted-capture-positive-control';sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;platform='windows';architecture=$env:ACCESSWEAVER_EXPECT_GOARCH;edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();toolSHA256=$toolSHA256;outcome=$outcome;code=$code;environmentVerified=$environmentVerified;nativeProcessVerified=$nativeProcessVerified;control=$control;productInvoked=$false;dnsSettingsChangesAttempted=$false;firewallRulesCreated=$false;rawCapturePublished=$false;encryptedTrafficQualified=$false;productionQualificationComplete=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 4 -Compress));if($bytes.Length -gt 8192){throw 'Control report bound'}
    $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
if($outcome -cne 'passed'){throw 'Capture positive control failed; fixed metadata retained'}
