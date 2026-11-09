# Read-only verification on fresh GitHub-hosted Windows VMs only. Never run locally.
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$ReportPath)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:ACCESSWEAVER_EXPECT_GOOS -cne 'windows' -or $env:ACCESSWEAVER_EXPECT_GOARCH -cnotin @('amd64','arm64') -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Hosted readback guard'}
foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Readback interop guard'}}
function Assert-ReadbackOrdinaryPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Readback reparse boundary'}};$next=Split-Path -Parent $current;if($next -eq $current){break};$current=$next}
}
if(-not [IO.Path]::IsPathRooted($ReportPath)){throw 'Readback report path'}
$ReportPath=[IO.Path]::GetFullPath($ReportPath);Assert-ReadbackOrdinaryPath $ReportPath;$parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ReportPath)) -Force -ErrorAction Stop
if(-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Readback report parent'}
$parentCreated=$parent.CreationTimeUtc.Ticks;$project=Split-Path -Parent $PSScriptRoot
$files=@('internal/workflow/windows.ps1','scripts/test-native-dns-readback.ps1','scripts/check-native-environment.cjs','.github/workflows/native-dns-readback.yml');$hashes=@{}
foreach($file in $files){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$outcome='failed';$code='environment';$nativeProcessVerified=$false;$positiveVerified=$false;$ipv4MismatchRejected=$false;$ipv6MismatchRejected=$false
try {
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if($computer.PartOfDomain -ne $false -or $computer.Model -notmatch 'Virtual|VMware' -or -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Fresh elevated non-domain VM required'}
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class AccessWeaverDNSReadbackIdentity {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    public static bool Matches(string arch) {
        using (Process p = Process.GetCurrentProcess()) {
            ushort processMachine, nativeMachine;
            return IsWow64Process2(p.Handle, out processMachine, out nativeMachine) && processMachine == 0 && nativeMachine == (arch == "amd64" ? 0x8664 : 0xaa64);
        }
    }
}
"@
    if(-not [AccessWeaverDNSReadbackIdentity]::Matches($env:ACCESSWEAVER_EXPECT_GOARCH)){throw 'Readback architecture'};$nativeProcessVerified=$true
    $code='source'
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project 'internal/workflow/windows.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Readback source syntax'}
    $selected=@('Get-DNSClientFamily','Read-DNSClientInventory','Get-DNSClientRows','Get-OriginalDNSBounds','Get-StaticDNSServers','Assert-ConfiguredDNSServers')
    $allowed=$selected+@('Get-NetAdapter','Get-DnsClientServerAddress','Where-Object')
    foreach($name in $selected){
        $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
        if($nodes.Count -ne 1){throw 'Readback function identity'}
        foreach($command in $nodes[0].FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($command.GetCommandName() -cnotin $allowed){throw 'Readback command boundary'}}
        . ([scriptblock]::Create($nodes[0].Extent.Text))
    }
    $code='inventory';$adapters=@(Get-NetAdapter -ErrorAction Stop);$clients=@(Read-DNSClientInventory);if($adapters.Count -lt 1 -or $adapters.Count -gt 256 -or $clients.Count -gt 512){throw 'Readback inventory bound'};$selectedAdapter=$null;$record=$null;$expected4=@();$expected6=@()
    foreach($adapter in $adapters){
        if($adapter.Status -ne 'Up' -or $adapter.InterfaceDescription -match 'WireSock|WireGuard|TAP|TUN'){continue}
        $rows4=@(Get-DNSClientRows $clients $adapter.ifIndex 'IPv4');$rows6=@(Get-DNSClientRows $clients $adapter.ifIndex 'IPv6')
        if($rows4.Count -ne 1 -or $rows6.Count -ne 1 -or @($rows4[0].ServerAddresses).Count -eq 0 -or @($rows6[0].ServerAddresses).Count -eq 0){continue}
        try{$v4=@(Get-StaticDNSServers @($rows4[0].ServerAddresses) 'IPv4' $adapter.ifIndex);$v6=@(Get-StaticDNSServers @($rows6[0].ServerAddresses) 'IPv6' $adapter.ifIndex)}catch{continue}
        if($v4.Count -gt 8 -or $v6.Count -gt 8){continue}
        $selectedAdapter=$adapter;$record=@{guid=[string]$adapter.InterfaceGuid;bound4=$true;bound6=$true};$expected4=$v4;$expected6=$v6;break
    }
    if($null -eq $selectedAdapter){throw 'Readback dual-family inventory unavailable'}
    $code='positive';Assert-ConfiguredDNSServers @($selectedAdapter) @($record) @($expected4+$expected6);$positiveVerified=$true
    $code='ipv4-negative';$bad4=@($expected4.Clone());$bad4[0]=if($expected4[0] -ceq '192.0.2.254'){'198.51.100.254'}else{'192.0.2.254'}
    try{Assert-ConfiguredDNSServers @($selectedAdapter) @($record) @($bad4+$expected6)}catch{if($_.Exception.Message -cne 'Configured DNS servers differ'){throw 'IPv4 mismatch indeterminate'};$ipv4MismatchRejected=$true}
    if(-not $ipv4MismatchRejected){throw 'IPv4 mismatch accepted'}
    $code='ipv6-negative';$bad6=@($expected6.Clone());$bad6[0]=if($expected6[0] -ceq '2001:db8::254'){'2001:db8::253'}else{'2001:db8::254'}
    try{Assert-ConfiguredDNSServers @($selectedAdapter) @($record) @($expected4+$bad6)}catch{if($_.Exception.Message -cne 'Configured DNS servers differ'){throw 'IPv6 mismatch indeterminate'};$ipv6MismatchRejected=$true}
    if(-not $ipv6MismatchRejected){throw 'IPv6 mismatch accepted'}
    $code='final-readback';Assert-ConfiguredDNSServers @($selectedAdapter) @($record) @($expected4+$expected6)
    $outcome='passed';$code='none'
}catch{}finally{
    foreach($file in $files){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){$outcome='failed';$code='source'}}
    Assert-ReadbackOrdinaryPath $ReportPath;$current=Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
    if($current.CreationTimeUtc.Ticks -ne $parentCreated -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Readback report parent changed'}
    $report=@{schemaVersion=1;sourceCommit=$env:GITHUB_SHA;architecture=$env:ACCESSWEAVER_EXPECT_GOARCH;sourceSHA256=$hashes;outcome=$outcome;code=$code;nativeProcessVerified=$nativeProcessVerified;positiveVerified=$positiveVerified;ipv4MismatchRejected=$ipv4MismatchRejected;ipv6MismatchRejected=$ipv6MismatchRejected;dnsReadOnly=$true;dnsConfigurationChanged=$false;networkQueryInvoked=$false;productionQualificationComplete=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 4 -Compress));if($bytes.Length -gt 4096){throw 'Readback metadata bound'}
    $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
if($outcome -cne 'passed'){exit 1}
