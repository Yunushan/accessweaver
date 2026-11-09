# Fresh disposable GitHub-hosted Windows VMs only. Never run locally.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Binary,[Parameter(Mandatory=$true)][string]$BinarySHA256,[Parameter(Mandatory=$true)][string]$ReportPath)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Assert-NativeOrdinaryPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Query fixture reparse boundary'}};$next=Split-Path -Parent $current;if($next -eq $current){break};$current=$next}
}
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:ACCESSWEAVER_EXPECT_GOOS -cne 'windows' -or $env:ACCESSWEAVER_EXPECT_GOARCH -cnotin @('amd64','arm64') -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Hosted native query guard'}
foreach($key in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if(Test-Path ('Env:'+ $key)){throw 'Query interop boundary'}}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain){throw 'Fresh elevated non-domain VM required'}
if(-not [IO.Path]::IsPathRooted($ReportPath)){throw 'Query report path'}
Assert-NativeOrdinaryPath $ReportPath;$ReportPath=[IO.Path]::GetFullPath($ReportPath);$parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ReportPath)) -Force -ErrorAction Stop
if(-not $parent.PSIsContainer -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Query report parent'}
$parentCreated=$parent.CreationTimeUtc.Ticks
$project=Split-Path -Parent $PSScriptRoot;$sources=@('scripts/native-dns-query/main_windows.go','scripts/native-dns-query/main_windows_test.go','scripts/native-dns-query.ps1','scripts/test-native-dns-query-contracts.ps1','scripts/test-native-dns-query.ps1','scripts/native-dns-wire.ps1','scripts/dns-acceptance-state.ps1','scripts/check-native-environment.cjs','.github/workflows/native-dns-query.yml','go.mod','go.sum');$hashes=@{}
foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
. (Join-Path $PSScriptRoot 'native-dns-wire.ps1')
. (Join-Path $PSScriptRoot 'native-dns-query.ps1')
. (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
$Binary=[IO.Path]::GetFullPath($Binary);Assert-NativeOrdinaryPath $Binary;$item=Get-Item -LiteralPath $Binary -Force -ErrorAction Stop;$workspace=[IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\')+'\'
if(-not $Binary.StartsWith($workspace,[StringComparison]::OrdinalIgnoreCase) -or $item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 128MB -or $BinarySHA256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BinarySHA256){throw 'Query binary identity'}
$root=[IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'),('AccessWeaver-NativeQuery-'+[guid]::NewGuid().ToString('N')));Assert-NativeOrdinaryPath $root
if(Test-Path -LiteralPath $root){throw 'Existing query fixture root'}
[void][IO.Directory]::CreateDirectory($root);$rootCreated=(Get-Item -LiteralPath $root -Force).CreationTimeUtc.Ticks
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($identity.User);$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $root -AclObject $acl -ErrorAction Stop
$state=New-NativeDNSWireState $root (Join-Path $PSScriptRoot 'dns-wire-stdin.cjs');$state.queryProject=$project;$state.querySourceHashes=$hashes.Clone();$state.queryBinary=$Binary;$state.queryBinarySHA256=$BinarySHA256;$state.querySourceCommit=$env:GITHUB_SHA;$state.queryArchitecture=$env:ACCESSWEAVER_EXPECT_GOARCH
$outcome='failed';$code='preflight';$cleanupCode='none';$before=$null;$rulesRemoved=$false;$stateVerified=$false;$rootRemoved=$false;$evidence=@{probe=$null;positive=$null;blocked=$null;resumed=$null}
try {
    Assert-NativeFreshDNSSources $state
    if(@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop).Count -ne 0){throw 'Query name policy boundary'}
    Assert-NativeDNSWireFirewall
    $before=Read-DNSAcceptanceState
    $code='probe';$evidence.probe=Invoke-NativeFreshDNSQuery $state -Probe
    $code='positive';$evidence.positive=Invoke-NativeFreshDNSQuery $state 'example.net'
    $code='block';foreach($kind in @('dns','tls')){foreach($protocol in @('TCP','UDP')){Add-NativeDNSWireRule $state $kind $protocol}}
    $code='blocked';$evidence.blocked=Invoke-NativeFreshDNSQuery $state 'example.net' -ExpectFailure
    $code='unblock';Remove-NativeDNSWireRules $state 'tls';Remove-NativeDNSWireRules $state 'dns';$rulesRemoved=$true
    $code='resumed';$evidence.resumed=Invoke-NativeFreshDNSQuery $state 'example.net'
    $code='readback';Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);$stateVerified=$true
    Assert-NativeFreshDNSSources $state
    $outcome='passed';$code='none'
} catch {
    $outcome='failed'
    if($code -cin @('probe','positive','blocked','resumed') -and $null -ne $state.queryLastEvidence){$evidence[$code]=$state.queryLastEvidence}
} finally {
    $cleanupGood=$true
    foreach($kind in @('tls','dns')){try{Remove-NativeDNSWireRules $state $kind}catch{$cleanupGood=$false;$cleanupCode='rules'}}
    $rulesRemoved=$cleanupGood
    if($null -ne $before){try{Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);$stateVerified=$true}catch{$cleanupGood=$false;$cleanupCode='state'}}
    try{Assert-NativeFreshDNSSources $state}catch{$cleanupGood=$false;$cleanupCode='source'}
    try{Assert-NativeOrdinaryPath $root;$current=Get-Item -LiteralPath $root -Force -ErrorAction Stop;if([IO.Path]::GetFullPath($current.FullName) -cne $root -or $current.CreationTimeUtc.Ticks -ne $rootCreated -or -not $current.PSIsContainer -or [IO.Directory]::GetFileSystemEntries($root).Length -ne 0){throw 'Changed query root'};[IO.Directory]::Delete($root,$false);$rootRemoved=$true}catch{$cleanupGood=$false;$cleanupCode='root'}
    if(-not $cleanupGood -or $state.processes -ne $state.joined -or $state.processFailed){$outcome='failed';if($cleanupCode -ceq 'none'){$cleanupCode='process'}}
    $currentParent=Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
    if($currentParent.CreationTimeUtc.Ticks -ne $parentCreated -or ($currentParent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Query report parent changed'}
    $report=@{schemaVersion=1;sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;architecture=$env:ACCESSWEAVER_EXPECT_GOARCH;binarySHA256=$BinarySHA256;outcome=$outcome;code=$code;cleanupCode=$cleanupCode;queryEvidence=$evidence;toolProcesses=$state.processes;toolProcessesJoined=$state.joined;toolFailure=$state.processFailed;processFailureCode=$state.processFailureCode;rulesPrepared=$state.rules.Count;rulesRemoved=$rulesRemoved;originalStateVerified=$stateVerified;privateRootRemoved=$rootRemoved;globalCacheFlushed=$false;dnsSettingsChangesAttempted=$false;captureStarted=$false;productInvoked=$false;encryptedTrafficQualified=$false;productionQualificationComplete=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 6 -Compress));if($bytes.Length -gt 8192){throw 'Query report bound'}
    $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
if($outcome -cne 'passed'){exit 1}
