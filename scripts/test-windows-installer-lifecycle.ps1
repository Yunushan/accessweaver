# Actual driver-free installer acceptance, exclusively on disposable hosted Windows.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:OS -ne 'Windows_NT' -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:ACCESSWEAVER_DISPOSABLE_INSTALLER_ACCEPTANCE -cne '1' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver'){throw 'Installer execution requires explicit disposable hosted Windows opt-in'}
$source=$env:GITHUB_SHA;$sourceRef=$env:GITHUB_REF;$run=$env:GITHUB_RUN_ID
if($source -cnotmatch '^[a-f0-9]{40}$' -or $sourceRef -cnotmatch '^refs/heads/[A-Za-z0-9_./-]+$' -or $run -notmatch '^[0-9]+$'){throw 'Missing source-bound hosted context'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} finally {$identity.Dispose()}
if(-not $admin){throw 'Disposable installer acceptance requires an already elevated hosted token'}
if([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant() -cne @{amd64='x64';arm64='arm64'}[$Architecture]){throw 'Installer acceptance requires a matching native host'}
$project=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if((git -C $project rev-parse HEAD).Trim() -cne $source -or $LASTEXITCODE -ne 0 -or (git -C $project status --porcelain --untracked-files=no)){throw 'Expected a clean exact-source checkout'}
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-native-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-event-state.ps1')
$tokens=$null;$issues=$null
$workflow=Join-Path $project 'internal\workflow\windows.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($workflow,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Product workflow parse failed'}
foreach($name in @('No-Reparse','Quote-Arg','Native-Argument','New-ToolCapture','Receive-ToolCapture','Wait-ToolCapture','Stop-ToolTreeWithHelper','Stop-ToolTree','Run-Tool','Native','Get-DriverServiceControllers','Get-ServiceInspection','Under','Get-PEMachine',
        'Read-WorkflowUninstallRegistration','Get-WorkflowUninstallPath','Assert-WorkflowUninstallACL','Assert-WorkflowUninstallProtection','Get-AccessWeaverInstallerRecoveryState','Assert-NoPendingWorkflowInstallation','Open-WorkflowUninstallBinding')){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Expected one fixed product process/inspection helper'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Require([bool]$ok,[string]$message){if(-not $ok){$script:assertionFailure=$message;$frames=@(Get-PSCallStack);if($frames.Count -gt 1){$script:assertionFailureLine=$frames[1].ScriptLineNumber};throw $message}}
function Digest([string]$path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Assert-SetupCompletionReadback([string]$Log) {
    No-Reparse $Log
    $entry=Get-Item -LiteralPath $Log -ErrorAction Stop
    Require (-not $entry.PSIsContainer -and $entry.Length -gt 0 -and $entry.Length -le 4MB) 'Setup completion log is unavailable or exceeds its bound'
    Require ([IO.File]::ReadAllText($Log).Contains('AccessWeaver installed payload and registration verified. Pending installation record retired.')) 'Setup did not record verified completion'
}
function Remove-OwnedTree([string]$path,[string]$parent,[string]$leaf){
    $resolved=[IO.Path]::GetFullPath($path);$expected=[IO.Path]::Combine([IO.Path]::GetFullPath($parent),$leaf)
    Require ($resolved -ceq $expected) 'Owned cleanup path mismatch'
    No-Reparse $resolved
    if(Test-Path -LiteralPath $resolved){
        $items=@(Get-ChildItem -LiteralPath $resolved -Force -Recurse -ErrorAction Stop)
        Require ($items.Count -le 10000 -and -not @($items | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count) 'Owned cleanup contains unexpected aliases or excessive entries'
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
    }
}
$guid=[guid]::NewGuid().ToString('N')
$temporary=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\');No-Reparse $temporary
$capsuleLeaf='accessweaver-installer-'+$guid;$capsule=Join-Path $temporary $capsuleLeaf
$programFiles=[Environment]::GetFolderPath('ProgramFiles');No-Reparse $programFiles
$installLeaf='AccessWeaver lifecycle '+$guid;$install=Join-Path $programFiles $installLeaf
$managedParent=[Environment]::GetFolderPath('CommonApplicationData');$managed=Join-Path $managedParent 'AccessWeaver';No-Reparse $managed
$uninstallKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1'
function Registration {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($uninstallKey)
        if($null -eq $key){return $null}
        return @{version=[string]$key.GetValue('DisplayVersion');location=[string]$key.GetValue('InstallLocation')}
    } finally {if($key){$key.Dispose()};$base.Dispose()}
}
function Assert-LifecycleRegistrationAbsent([string]$Failure) {
    foreach($hive in @([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryHive]::CurrentUser)){
        foreach($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)){
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view);$key=$null
            try {$key=$base.OpenSubKey($uninstallKey);Require ($null -eq $key) $Failure} finally {if($key){$key.Dispose()};$base.Dispose()}
        }
    }
}
$installerLifecycleKey='SOFTWARE\AccessWeaver\Installer'
function Get-PendingInstallFixtureValue {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($installerLifecycleKey,$false)
        if($key){return $key.GetValue('PendingInstall')}
    } finally {if($key){$key.Dispose()};$base.Dispose()}
}
Assert-LifecycleRegistrationAbsent 'An existing product registration must never be used by this fixture'
Require ($null -eq (Get-PendingInstallFixtureValue)) 'An existing pending installation must never be used by this fixture'
Require (-not (Test-Path -LiteralPath $managed) -and -not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\AccessWeaver')) 'An existing managed installation must never be used by this fixture'
Require (-not (Test-Path -LiteralPath $install) -and -not (Test-Path -LiteralPath $capsule) -and -not (Test-Path -LiteralPath (Join-Path $programFiles 'AccessWeaver'))) 'Fixture and default product destinations must be new'
[void][IO.Directory]::CreateDirectory($capsule)
$root=$capsule;$profile=Join-Path $capsule 'user';$privateTemp=Join-Path $capsule 'process-temp'
foreach($dir in @($profile,$privateTemp,(Join-Path $profile 'roaming'),(Join-Path $profile 'local'))){[void][IO.Directory]::CreateDirectory($dir)}
$userMarker=Join-Path $profile 'user-state.json';[IO.File]::WriteAllText($userMarker,'{"preserve":"user-state"}')
$userHash=Digest $userMarker
$script:profileDataPath=$null;$script:profileDataHash=$null;$script:restoreFixtureConfiguration=$null
$group='AccessWeaver acceptance '+$guid
$groupPaths=@((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) $group),(Join-Path ([Environment]::GetFolderPath('Programs')) $group))
foreach($path in $groupPaths){Require (-not (Test-Path -LiteralPath $path)) 'Fixture start-menu folder already exists'}
function Invoke-Isolated([string]$binary,[string[]]$arguments,[int[]]$codes=@(0),[int]$Timeout=180){
    $saved=@{};foreach($entry in Get-ChildItem Env:){$saved[$entry.Name]=$entry.Value}
    $system=[Environment]::SystemDirectory;$windows=Split-Path -Parent $system
    $allowed=@{SystemRoot=$windows;WINDIR=$windows;SystemDrive=[IO.Path]::GetPathRoot($system).TrimEnd('\');ComSpec=(Join-Path $system 'cmd.exe');PATH=($system+';'+$windows);PATHEXT='.COM;.EXE;.BAT;.CMD';TEMP=$privateTemp;TMP=$privateTemp;USERPROFILE=$profile;APPDATA=(Join-Path $profile 'roaming');LOCALAPPDATA=(Join-Path $profile 'local');ProgramData=$managedParent;ALLUSERSPROFILE=$managedParent;ACCESSWEAVER_INSTALLER_REGISTRY_VERSION_PROBE='alpha'}
    if($script:restoreFixtureConfiguration){$allowed['ACCESSWEAVER_INSTALLER_RESTORE_FIXTURE']=$script:restoreFixtureConfiguration}
    foreach($name in @('ProgramFiles','ProgramFiles(x86)','ProgramW6432','CommonProgramFiles','CommonProgramFiles(x86)','CommonProgramW6432')){if($saved[$name]){$allowed[$name]=$saved[$name]}}
    try {
        foreach($entry in Get-ChildItem Env:){[Environment]::SetEnvironmentVariable($entry.Name,$null,'Process')}
        foreach($name in $allowed.Keys){[Environment]::SetEnvironmentVariable($name,$allowed[$name],'Process')}
        return (Native $binary $arguments $codes -Secret -Timeout $Timeout)
    } finally {
        foreach($entry in Get-ChildItem Env:){[Environment]::SetEnvironmentVariable($entry.Name,$null,'Process')}
        foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
    }
}
function Native-Record([string]$binary,[string[]]$arguments,[int[]]$codes=@(0),[int]$Timeout=180){
    # Reset before invocation: lastNative describes only the last returned call
    # and can otherwise misleadingly survive a later native exception.
    $attempt=[ordered]@{schemaVersion=1;toolClass=(Get-InstallerNativeToolClass $binary);timeoutMilliseconds=([long]$Timeout*1000);elapsedMilliseconds=0L;invocationReturned=$false;operationAccepted=$false;exitCode=$null;outputComplete=$null;failureCategory='in-progress'}
    $script:lastNativeAttempt=$attempt
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        $r=Invoke-Isolated $binary $arguments ((0..255)+@(3010,1641)) $Timeout
        $attempt.invocationReturned=$true
        if($null -eq $r -or $r -isnot [Collections.IDictionary] -or $r.exitCode -isnot [int] -or $r.outputComplete -isnot [bool]){
            $attempt.failureCategory='invalid-native-result'
            throw 'Native installer result is incomplete'
        }
        $attempt.exitCode=$r.exitCode;$attempt.outputComplete=$r.outputComplete
        $script:lastNative=@{file=[IO.Path]::GetFileName($binary);exitCode=$r.exitCode;outputComplete=$r.outputComplete}
        $attempt.failureCategory='unexpected-exit'
        Require ($codes -contains $r.exitCode) 'Installer operation returned an unexpected exit code'
        $attempt.failureCategory='incomplete-output'
        Require $r.outputComplete 'Native installer process left incomplete output capture'
        $attempt.operationAccepted=$true;$attempt.failureCategory='none'
        return @{result=$r;milliseconds=$clock.ElapsedMilliseconds}
    } catch {
        if(-not $attempt.invocationReturned){$attempt.failureCategory=Get-InstallerNativeFailureCategory $binary $_.Exception.Message}
        throw
    } finally {
        $clock.Stop();$attempt.elapsedMilliseconds=$clock.ElapsedMilliseconds
    }
}
function State-Snapshot {
    $inspection=Get-ServiceInspection;Require ($null -eq $inspection.error) 'Service inspection was incomplete'
    $services=@($inspection.services | Where-Object {$_.name -match '^(AccessWeaver-|WinDivert|NDISRD|wiresock)'} | Sort-Object name)
    $script:stateFirewallRules=@(Get-NetFirewallRule -ErrorAction Stop)
    $firewall=@($script:stateFirewallRules | Sort-Object Name | Select-Object Name,Enabled,Direction,Action)
    $dns=@(Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    return (ConvertTo-Json -InputObject @{services=$services;firewall=$firewall;dns=$dns} -Depth 8 -Compress)
}
function State-Checkpoint([string]$Phase) {
    $snapshot=State-Snapshot
    $observation=New-InstallerStateCheckpoint $Phase $script:stateBaseline $script:statePrevious $snapshot
    $script:stateObservations+=,$observation
    $changes=@($observation.transition.domains.firewall.changes)
    $remaining=16-$script:firewallOriginObservations.Count
    if($changes.Count -gt $remaining -or $observation.transition.domains.firewall.changesTruncated){$script:firewallOriginTruncated=$true}
    try {
        $origins=New-InstallerFirewallOrigins $Phase $changes $script:statePreviousFirewallRules $script:stateFirewallRules $remaining
        $script:firewallOriginObservations+=@($origins)
    } catch {$script:firewallOriginUnavailable=$true}
    $script:statePreviousFirewallRules=$script:stateFirewallRules
    $script:statePrevious=$snapshot
    return $snapshot
}
function Read-FirewallEventDiagnostic([ref]$FailureObservation) {
    # Optional fixed metadata describes the failure boundary, not child launch
    # or a completed event-log read. Keep the existing event envelope unchanged.
    if($null -ne $FailureObservation){$FailureObservation.Value=[ordered]@{stage='none';nativeFailureCategory='none'}}
    $result=New-InstallerFirewallEventDiagnostic
    if($script:firewallOriginObservations.Count -eq 0){return $result}
    $result.status='unavailable';$result.unavailable=$true
    $attempted=$false;$startText=$null;$endText=$null;$failureStage='preparation'
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        $identities=@($script:firewallOriginObservations | ForEach-Object {$_.identitySHA256} | Sort-Object -Unique)
        $end=[datetime]::UtcNow;Assert-InstallerEventWindow $script:firewallEventWindowStartUtc $end $identities
        $startText=$script:firewallEventWindowStartUtc.ToString('o');$endText=$end.ToString('o')
        $escape={param([string]$value) "'"+$value.Replace("'","''")+"'"}
        $paths=@('windows-installer-state.ps1','windows-installer-native-state.ps1','windows-installer-event-state.ps1')
        $body='$ErrorActionPreference=''Stop'';'
        foreach($name in $paths){$body+=' . '+(&$escape (Join-Path (Join-Path $project 'scripts') $name))+';'}
        $body+='$start=[datetime]::ParseExact('+(&$escape $script:firewallEventWindowStartUtc.ToString('o'))+',''o'',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind);'
        $body+='$end=[datetime]::ParseExact('+(&$escape $end.ToString('o'))+',''o'',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind);'
        $body+='$value=Read-InstallerFirewallEventLog @('+((@($identities | ForEach-Object {&$escape $_})) -join ',')+') $start $end;ConvertTo-Json -InputObject $value -Depth 12 -Compress;'
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
        $shell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        # Do not use Native-Record: retain the original uninstaller attempt.
        $attempted=$true;$failureStage='native-invocation'
        $native=Invoke-Isolated $shell @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded) @(0) 10
        $failureStage='native-output'
        if($native.exitCode -ne 0 -or -not $native.outputComplete -or $native.stdout.Length -gt 65536 -or -not [string]::IsNullOrWhiteSpace($native.stderr)){throw 'Event diagnostic output unavailable'}
        $failureStage='json-decode';$value=$native.stdout | ConvertFrom-Json
        $failureStage='envelope-validation'
        # PowerShell 7 may materialize ISO strings as DateTime; 5.1 leaves
        # strings. Preserve the exact UTC roundtrip value in either runtime.
        foreach($name in @('windowStartUtc','windowEndUtc')){
            if($value.$name -is [datetime]){
                if($value.$name.Kind -ne [DateTimeKind]::Utc){throw 'Event diagnostic time is not UTC'}
                $value.$name=$value.$name.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
            }
        }
        $expected=@($result.Keys | Sort-Object);$actual=@($value.PSObject.Properties.Name | Sort-Object)
        if(($expected -join '|') -cne ($actual -join '|') -or $value.status -cne 'captured' -or $value.windowStartUtc -cne $startText -or $value.windowEndUtc -cne $endText -or -not $value.queryAttempted -or $value.eventLogConfigurationChanged -or $value.extraFirewallRuleQueriesPerformed -or $value.processOriginEstablished){throw 'Event diagnostic envelope differs'}
        $result=$value
    } catch { # Retain fixed unavailable metadata, never native XML/errors/output.
        $nativeFailureCategory='none'
        if($failureStage -ceq 'native-invocation'){$nativeFailureCategory=Get-InstallerNativeFailureCategory $shell $_.Exception.Message}
        if($null -ne $FailureObservation){$FailureObservation.Value=[ordered]@{stage=$failureStage;nativeFailureCategory=$nativeFailureCategory}}
        $result=New-InstallerFirewallEventDiagnostic;$result.status='unavailable';$result.unavailable=$true;$result.queryAttempted=$attempted;$result.windowStartUtc=$startText;$result.windowEndUtc=$endText
    } finally {$clock.Stop()}
    $result.queryElapsedMilliseconds=$clock.ElapsedMilliseconds
    return $result
}
function Installed-TreeFingerprint {
    No-Reparse $install
    $items=@(Get-ChildItem -LiteralPath $install -Force -Recurse -ErrorAction Stop)
    Require ($items.Count -le 10000 -and -not @($items | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count) 'Installed fixture contains unexpected aliases or excessive entries'
    $records=@($items | Where-Object {-not $_.PSIsContainer} | Sort-Object FullName | ForEach-Object {
        [ordered]@{relative=$_.FullName.Substring($install.Length+1);bytes=$_.Length;sha256=(Digest $_.FullName)}
    })
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $records -Depth 4 -Compress))
    $hash=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
}
function Registration-Fingerprint([Microsoft.Win32.RegistryKey]$ExistingKey=$null,[Microsoft.Win32.RegistryView]$View=[Microsoft.Win32.RegistryView]::Registry64) {
    $base=$null;$key=$ExistingKey;$ownsKey=$null -eq $ExistingKey
    try {
        if($ownsKey){$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$View);$key=$base.OpenSubKey($uninstallKey)}
        Require ($null -ne $key) 'Installed fixture registration disappeared'
        $names=@($key.GetValueNames() | Sort-Object)
        Require ($names.Count -le 256) 'Installer registration exceeds fixture bounds'
        $values=@($names | ForEach-Object {[ordered]@{name=$_;kind=[string]$key.GetValueKind($_);data=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}})
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $values -Depth 6 -Compress))
        $hash=[Security.Cryptography.SHA256]::Create()
        try {return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
    } finally {if($ownsKey -and $key){$key.Dispose()};if($base){$base.Dispose()}}
}
function Assert-UserState {
    Require ((Digest $userMarker) -ceq $userHash) 'An installer operation changed unrelated user state'
    if($script:profileDataPath){Require ((Digest $script:profileDataPath) -ceq $script:profileDataHash) 'An installer operation changed the actual saved AccessWeaver profile'}
}
function Create-UserProfile {
    $binary=Join-Path $install 'accessweaver.exe'
    $template=Native-Record $binary @('show','discord-proxy')
    $data=$template.result.stdout | ConvertFrom-Json
    $data.id='installer-preserve';$data.name='Preserved installer acceptance profile'
    $inputPath=Join-Path $capsule 'profile-input.json'
    [IO.File]::WriteAllText($inputPath,($data | ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))
    $null=Native-Record $binary @('import',$inputPath)
    $script:profileDataPath=Join-Path $profile 'roaming\AccessWeaver\profiles\installer-preserve.json'
    $script:profileDataHash=Digest $script:profileDataPath
    $verified=Native-Record $binary @('show','installer-preserve')
    Require (($verified.result.stdout | ConvertFrom-Json).name -ceq $data.name) 'Installed core did not round-trip the actual user profile'
}
function Assert-ManagedDetection([string]$Phase,$Expected,[bool]$Detected,[string]$DigestOverride=''){
    $hash=$Expected.payloadSha256
    if($DigestOverride){$hash=$DigestOverride}
    $uninstallerDigest=''
    if($Detected){$uninstallerDigest=Digest (Join-Path $install 'unins000.exe')}
    $output=@(& $detector -Version $Expected.version -Architecture $Architecture -PayloadSHA256 $hash -PayloadSBOMSHA256 $Expected.payloadSBOMSHA256 -InstallDirectory $install -UninstallerSHA256 $uninstallerDigest 2>&1)
    Require ($LASTEXITCODE -eq 0) 'Managed detection reported an inspection error'
    if($Detected){
        Require ($output.Count -eq 1 -and $output[0] -ceq 'AccessWeaver detected') 'Managed detection missed the approved payload'
    } else {
        Require ($output.Count -eq 0) 'Managed detection accepted an absent or unapproved payload'
    }
    $script:detectionCases+=,@{phase=$Phase;detected=$Detected}
}
function Assert-Installed($expected){
    $binary=Join-Path $install 'accessweaver.exe';No-Reparse $binary
    Require ((Digest $binary) -ceq $expected.payloadSha256) 'Installed payload differs from the compiled payload'
    $runtime=Native-Record $binary @('version','--json')
    $actual=$runtime.result.stdout | ConvertFrom-Json
    $build=$expected.payloadBuild
    Assert-InstallerPayloadIdentity $binary $actual @{version=$build.version;commit=$source;sourceState='clean';builtAt=$build.builtAt;goVersion=$build.goVersion;platform='windows';arch=$Architecture}
    Require ((Digest (Join-Path $install 'BUILD-INFO.json')) -ceq $expected.identityFileSHA256) 'Installed build metadata differs from its compiled identity'
    $registered=Registration
    Require ($null -ne $registered -and $registered.version -ceq $build.version -and $registered.location.TrimEnd('\') -ieq $install) 'Native uninstall registration differs from the installed target'
    foreach($path in $groupPaths){Require (-not (Test-Path -LiteralPath $path)) 'Silent no-icons installation created a start-menu folder'}
    Assert-UserState
}
$detector=Join-Path $PSScriptRoot 'detect-windows-installer.ps1'
$script:detectionCases=@()
$reportDirectory=Join-Path $project 'build\installer-lifecycle-checks';[void][IO.Directory]::CreateDirectory($reportDirectory)
$reportPath=Join-Path $reportDirectory ($Architecture+'.json')
$script:firewallEventWindowStartUtc=[datetime]::MinValue;
$script:stateObservations=@();$script:stateBaseline=$null;$script:statePrevious=$null;$script:assertionFailureLine=$null
$script:stateFirewallRules=@();$script:statePreviousFirewallRules=@();$script:firewallOriginObservations=@();$script:firewallOriginTruncated=$false;$script:firewallOriginUnavailable=$false
$pathRefusal=@()
$completionRefusal=$null
$stage='compile';$failureType=$null;$script:assertionFailure=$null;$script:lastNative=$null;$script:lastNativeAttempt=$null;$complete=$false;$builds=@();$observations=@();$architectureRefusal=$null;$pendingMarkerAccess=$null;$versionPolicyCases=@();$versionContractCases=0;$versionFixtureSHA256=$null;$lifecycleLockCases=@();$lifecycleLockFixtureSHA256=$null;$productLockSHA256=$null;$registryReadCases=@();$registryViewCases=@();$registryAccessCases=@();$failureSourceLine=$null;$registryFixtureSHA256=$null;$productRegistrySHA256=$null;$restorationCases=@();$productRestoreSHA256=$null;$restoreFixtureSourceSHA256=$null;$restoreFixtureBinarySHA256=$null;$restoreContractSourceSHA256=$null;$restoreContractBinarySHA256=$null;$restorationOwnerCases=@();$restoreOwnerFixtureSHA256=$null;$restorationLaunchCases=@();$restoreLaunchFixtureSHA256=$null
try {
    foreach($version in @('0.1.0-alpha','0.1.1-alpha')){
        $null=@(& (Join-Path $PSScriptRoot 'test-windows-installer.ps1') -ExpectedCompilerVersion '6.7.1' -TargetArch $Architecture -Version $version)
        $evidence=Join-Path $project ('build\installer-checks\'+$Architecture)
        $b=Get-Content -LiteralPath (Join-Path $evidence 'compiler-artifact.json') -Raw | ConvertFrom-Json
        Require ($b.sourceCommit -ceq $source -and $b.payloadBuild.sourceState -ceq 'clean' -and $b.payloadBuild.version -ceq $version -and $b.compilerVersion -ceq '6.7.1' -and $b.unsigned) 'Compiler evidence differs from the requested candidate'
        $builds+=,@{version=$version;installerName=$b.installerName;installerSHA256=$b.installerSha256;installerBytes=$b.installerBytes;payloadSha256=$b.payloadSha256;payloadSBOMSHA256=(Digest (Join-Path $evidence 'payload-SBOM.cdx.json'));payloadBuild=$b.payloadBuild;compilerSHA256=$b.compilerSha256;preprocessedSetupSHA256=$b.preprocessedSetupSha256;identityFileSHA256=(Digest (Join-Path $evidence 'payload-BUILD-INFO.json'))}
    }
    $stage='version-contracts'
    $compiler=Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Inno Setup 6\ISCC.exe'
    $fixtureSource=Join-Path $PSScriptRoot 'test-windows-installer-version.iss'
    $contractMatch=[regex]::Matches([IO.File]::ReadAllText($fixtureSource),'(?m)^#define AWVersionContractCases ([0-9]+)$')
    Require ($contractMatch.Count -eq 1 -and [int]$contractMatch[0].Groups[1].Value -gt 0) 'Missing fixed native version contract count'
    $versionContractCases=[int]$contractMatch[0].Groups[1].Value
    $null=@(& $compiler ('/DEvidenceRoot='+$capsule) $fixtureSource)
    Require ($LASTEXITCODE -eq 0) 'Native version fixture compilation failed'
    $versionFixture=Join-Path $capsule 'installer-version-contracts.exe'
    $versionFixtureSHA256=Digest $versionFixture
    $versionContracts=Native-Record $versionFixture @('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
    $stage='baseline';$script:firewallEventWindowStartUtc=[datetime]::UtcNow;$before=State-Snapshot;$script:stateBaseline=$before;$script:statePrevious=$before;$script:statePreviousFirewallRules=$script:stateFirewallRules;$script:stateObservations+=,(New-InstallerStateCheckpoint 'baseline' $before $before $before)
    Require (-not @(Get-Service -Name 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count) 'Existing product services are outside this fixture'
    Require (-not @(Get-NetFirewallRule -Name 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count) 'Existing product firewall rules are outside this fixture'
    $arguments=@('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/RESTARTEXITCODE=3010','/NOCLOSEAPPLICATIONS','/NORESTARTAPPLICATIONS','/NOICONS',('/DIR='+$install),('/GROUP='+$group))
    $stage='architecture-refusal'
    $otherArch=if($Architecture -ceq 'amd64'){'arm64'}else{'amd64'}
    $wrongStage=Join-Path $capsule 'opposite-target-payload'
    [void][IO.Directory]::CreateDirectory($wrongStage)
    Copy-Item -LiteralPath (Join-Path $project 'LICENSE') -Destination $wrongStage
    foreach($file in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
        [IO.File]::WriteAllText((Join-Path $wrongStage $file),'inert opposite-target payload')
    }
    $preprocessed=Join-Path $capsule 'opposite-target.iss'
    $null=@(& $compiler ('/DBuildRoot='+$wrongStage) '/DReleaseVersion=0.1.0-alpha' ('/DTargetArch='+$otherArch) ('/DEvidenceOutput='+$preprocessed) (Join-Path $PSScriptRoot 'windows-installer.iss'))
    Require ($LASTEXITCODE -eq 0) 'Opposite-target installer probe compilation failed'
    $null=Assert-InstallerSetupScript $preprocessed $otherArch '0.1.0-alpha'
    $wrongSetup=Join-Path $capsule ('accessweaver-0.1.0-alpha-windows-'+$otherArch+'-setup.exe')
    $wrongDigest=Digest $wrongSetup
    $refusalLog=Join-Path $capsule 'architecture-refusal.log'
    $refused=Native-Record $wrongSetup ($arguments+@('/LOG='+$refusalLog)) @(1)
    No-Reparse $refusalLog
    $info=Get-Item -LiteralPath $refusalLog -ErrorAction Stop
    Require (-not $info.PSIsContainer -and $info.Length -gt 0 -and $info.Length -le 64KB) 'Architecture refusal log is unavailable or outside fixture bounds'
    $lines=[IO.File]::ReadAllLines($refusalLog)
    $marker='This program does not support the version of Windows your computer is running.'
    $markerVerified=@($lines | Where-Object {$_.Trim() -ceq $marker}).Count -eq 1
    Require $markerVerified 'Setup did not log the platform admission refusal'
    Require (-not (Test-Path -LiteralPath $install -ErrorAction Stop) -and
        -not (Test-Path -LiteralPath $managed -ErrorAction Stop) -and
        -not @($groupPaths | Where-Object {Test-Path -LiteralPath $_ -ErrorAction Stop}).Count) 'Opposite-target Setup wrote installation files'
    Assert-LifecycleRegistrationAbsent 'Opposite-target Setup wrote a product registration'
    Require ((State-Snapshot) -ceq $before) 'Opposite-target Setup changed machine state'
    $architectureRefusal=[ordered]@{target=('windows/'+$otherArch);fixtureSHA256=$wrongDigest;
        exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;
        platformRefusalLogged=$true;installationAbsent=$true;registrationsAbsent=$true;machineStateUnchanged=$true}
    $first=Join-Path $project ('build\'+$builds[0].installerName)
    Require ((Digest $first) -ceq $builds[0].installerSHA256) 'Installer changed after compilation'
    $stage='installation-path-refusal'
    $pathRefusal=@()
    $physical=Join-Path $capsule 'junction-target'
    $junction=Join-Path $capsule 'junction'
    [void][IO.Directory]::CreateDirectory($physical)
    $witness=Join-Path $physical 'preserve.txt'
    [IO.File]::WriteAllText($witness,'owned junction target witness')
    $witnessDigest=Digest $witness
    [void](New-Item -ItemType Junction -Path $junction -Target $physical -ErrorAction Stop)
    try {
        Require ((Get-Item -LiteralPath $junction -Force -ErrorAction Stop).LinkType -ceq 'Junction') 'Installation path fixture requires a junction'
        foreach($kind in @('leaf-junction','ancestor-junction')){
            $destination=if($kind -ceq 'leaf-junction'){$junction}else{Join-Path $junction 'missing-installation'}
            $argsForAlias=@($arguments | Where-Object {$_ -notlike '/DIR=*'})+@('/DIR='+$destination)
            $refusalLog=Join-Path $capsule ($kind+'.log')
            $refused=Native-Record $first ($argsForAlias+@('/LOG='+$refusalLog)) @(7)
            No-Reparse $refusalLog
            $size=(Get-Item -LiteralPath $refusalLog -ErrorAction Stop).Length
            Require ($size -gt 0 -and $size -le 1MB) 'Installation path refusal log is unavailable or exceeds its bound'
            Require ([IO.File]::ReadAllText($refusalLog).Contains('AccessWeaver requires a local installation directory without junctions or symbolic links.')) 'Setup did not log the installation path refusal'
            Require ([IO.Directory]::GetFileSystemEntries($physical).Length -eq 1 -and (Digest $witness) -ceq $witnessDigest) 'Refused Setup changed the owned junction target'
            Require ($null -eq (Get-PendingInstallFixtureValue) -and (State-Snapshot) -ceq $before) 'Refused Setup changed pending or machine state'
            Assert-LifecycleRegistrationAbsent 'Refused Setup created a product registration'
            $pathRefusal+=,@{kind=$kind;exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;
                preflightRefusalLogged=$true;targetPreserved=$true;pendingMarkerAbsent=$true;registrationsAbsent=$true;machineStateUnchanged=$true}
        }
    } finally {
        $item=Get-Item -LiteralPath $junction -Force -ErrorAction Stop
        Require ($item.LinkType -ceq 'Junction' -and $item.FullName -ieq $junction) 'Owned junction identity changed before cleanup'
        [IO.Directory]::Delete($junction,$false)
    }
    Assert-ManagedDetection 'before-install' $builds[0] $false
    $stage='install'
    $completionLog=Join-Path $capsule 'clean-install-completion.log'
    $installed=Native-Record $first ($arguments+@('/LOG='+$completionLog))
    Assert-SetupCompletionReadback $completionLog
    Assert-Installed $builds[0];Create-UserProfile
    $marker=Join-Path $install 'unrelated-preserve.txt';[IO.File]::WriteAllText($marker,'unrelated-existing-file');$markerHash=Digest $marker
    $observations+=,@{operation='install';exitCode=$installed.result.exitCode;elapsedMilliseconds=$installed.milliseconds;deadlineMilliseconds=180000;payloadAndRegistrationVerified=$true}
    Assert-ManagedDetection 'after-install' $builds[0] $true
    Assert-ManagedDetection 'wrong-digest' $builds[0] $false ('0'*64)
    $null=State-Checkpoint 'after-install'
    $stage='setup-completion-refusal'
    $faultSource=Join-Path $capsule 'setup-completion-source'
    $faultPayload=Join-Path $capsule 'setup-completion-payload'
    foreach($folder in @($faultSource,$faultPayload)){[void][IO.Directory]::CreateDirectory($folder)}
    foreach($name in @('windows-installer-lock.iss','windows-installer-version.iss','windows-installer-registry.iss','windows-installer-restore.iss')){
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $faultSource -ErrorAction Stop
    }
    $productSetup=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer.iss'))
    $digestDefinition='#define PayloadSBOMDigest GetSHA256OfFile(PayloadSBOMPath)'
    Require ([regex]::Matches($productSetup,[regex]::Escape($digestDefinition)).Count -eq 1) 'Expected exactly one Setup SBOM digest definition'
    $faultSetup=Join-Path $faultSource 'windows-installer.iss'
    $wrongDigest='0'*64
    [IO.File]::WriteAllText($faultSetup,$productSetup.Replace($digestDefinition,('#define PayloadSBOMDigest "'+$wrongDigest+'"')))
    Copy-Item -LiteralPath (Join-Path $project 'LICENSE') -Destination $faultPayload -ErrorAction Stop
    foreach($name in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
        [IO.File]::WriteAllText((Join-Path $faultPayload $name),'inert completion fixture')
    }
    $faultTarget=Join-Path $faultPayload 'SBOM.cdx.json'
    Require ((Digest $faultTarget) -cne $wrongDigest) 'Setup completion fixture does not differ from the expected digest'
    $null=@(& $compiler ('/DBuildRoot='+$faultPayload) ('/DReleaseVersion='+$builds[0].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Setup completion fault fixture compilation failed'
    $faultInstaller=Join-Path $capsule $builds[0].installerName
    $faultLog=Join-Path $capsule 'setup-completion-refusal.log'
    $refused=Native-Record $faultInstaller ($arguments+@('/LOG='+$faultLog)) @(1603)
    No-Reparse $faultLog
    $faultLogSize=(Get-Item -LiteralPath $faultLog -ErrorAction Stop).Length
    Require ($faultLogSize -gt 0 -and $faultLogSize -le 4MB) 'Setup completion refusal log is unavailable or exceeds its bound'
    Require ([IO.File]::ReadAllText($faultLog).Contains('AccessWeaver installed payload or registration verification failed. Pending installation record retained.')) 'Setup did not record the readback refusal'
    $installedRegistration=Registration
    Require ($null -ne $installedRegistration -and $installedRegistration.version -ceq $builds[0].version -and
        $installedRegistration.location.TrimEnd('\') -ieq $install) 'Setup completion fault did not reach registration'
    foreach($name in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
        $installedFile=Join-Path $install $name
        No-Reparse $installedFile
        Require ((Digest $installedFile) -ceq (Digest (Join-Path $faultPayload $name))) 'Setup completion fault did not copy the expected fixture bytes'
    }
    Require ((Get-PendingInstallFixtureValue) -ceq ($builds[0].version+'|'+$install)) 'Setup completion refusal did not retain its own pending record'
    $detectorOutput=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 (Digest (Join-Path $install 'accessweaver.exe')) -InstallDirectory $install 2>&1)
    Require ($LASTEXITCODE -eq 1 -and $detectorOutput.Count -eq 0) 'Managed detection accepted the pending installation'
    Require ((State-Snapshot) -ceq $before) 'Setup completion refusal changed observed machine state'
    Assert-UserState
    Require ((Digest $marker) -ceq $markerHash) 'Setup completion refusal changed an unrelated file'
    $completionRefusal=[ordered]@{
        fixtureSHA256=(Digest $faultInstaller);exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;
        refusalLogged=$true;installedFixtureVerified=$true;pendingMarkerRetained=$true;managedDetectionRefused=$true;machineStateUnchanged=$true;
        profilePreserved=$true;unrelatedFilePreserved=$true;genuineRetryVerified=$false
    }
    $stage='setup-completion-retry'
    $completionLog=Join-Path $capsule 'setup-completion-retry.log'
    $null=Native-Record $first ($arguments+@('/LOG='+$completionLog))
    Assert-SetupCompletionReadback $completionLog
    Assert-Installed $builds[0]
    Require ((Digest $marker) -ceq $markerHash) 'Setup completion retry changed an unrelated file'
    Require ($null -eq (Get-PendingInstallFixtureValue)) 'Genuine Setup retry did not retire the completion marker'
    $completionRefusal.genuineRetryVerified=$true
    $stage='upgrade';$second=Join-Path $project ('build\'+$builds[1].installerName)
    Require ((Digest $second) -ceq $builds[1].installerSHA256) 'Upgrade installer changed after compilation'
    $stage='redirected-upgrade'
    $redirectedDestination=Join-Path $capsule 'redirected-upgrade'
    $redirectedArguments=@($arguments | Where-Object {$_ -notlike '/DIR=*'})+@('/DIR='+$redirectedDestination)
    $redirectedLog=Join-Path $capsule 'redirected-upgrade.log'
    $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
    $machineBeforeUpgrade=State-Snapshot
    Assert-UserState
    $redirectedUpgrade=Native-Record $second ($redirectedArguments+@('/LOG='+$redirectedLog)) @(7)
    No-Reparse $redirectedLog
    $logFile=Get-Item -LiteralPath $redirectedLog -ErrorAction Stop
    Require (-not $logFile.PSIsContainer -and $logFile.Length -gt 0 -and $logFile.Length -le 1MB) 'Redirected upgrade log is unavailable or exceeds its bound'
    Require ([IO.File]::ReadAllText($redirectedLog).Contains('Upgrade or reinstall AccessWeaver in its registered installation directory.')) 'Redirected upgrade did not reach the registered directory check'
    Require (-not (Test-Path -LiteralPath $redirectedDestination -ErrorAction Stop) -and $null -eq (Get-PendingInstallFixtureValue)) 'Redirected upgrade created a destination or recovery marker'
    Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Redirected upgrade changed installed files or registration'
    Assert-Installed $builds[0]
    Require ((State-Snapshot) -ceq $machineBeforeUpgrade) 'Redirected upgrade changed observed machine state'
    $observations+=,@{operation='refused-redirected-upgrade';exitCode=$redirectedUpgrade.result.exitCode;
        elapsedMilliseconds=$redirectedUpgrade.milliseconds;deadlineMilliseconds=180000;
        preflightRefusalLogged=$true;alternateDestinationAbsent=$true;pendingMarkerAbsent=$true;
        installedFileTreePreserved=$true;completeRegistrationPreserved=$true;profilePreserved=$true;machineStateUnchanged=$true}
    $stage='locked-payload-upgrade'
    $machineBeforeUpgrade=State-Snapshot
    $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
    $upgradeLog=Join-Path $capsule 'locked-upgrade.log'
    $payloadGuard=[IO.File]::Open((Join-Path $install 'accessweaver.exe'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $blocked=Native-Record $second ($arguments+@('/LOG='+$upgradeLog)) @(7)
    } finally {$payloadGuard.Dispose()}
    $logFile=Get-Item -LiteralPath $upgradeLog
    Require ($logFile.Length -gt 0 -and $logFile.Length -le 1MB) 'Locked upgrade log is missing or exceeds its bound'
    $reason='The AccessWeaver executable cannot be replaced. Close it and release any file locks before retrying setup.'
    Require ([IO.File]::ReadAllText($upgradeLog).Contains($reason)) 'Locked upgrade did not reach the executable replacement preflight'
    Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Locked upgrade changed installed files or registration'
    Assert-Installed $builds[0]
    Require ((State-Snapshot) -ceq $machineBeforeUpgrade) 'Locked upgrade changed observed machine state'
    $observations+=,@{operation='refused-locked-upgrade';exitCode=$blocked.result.exitCode;elapsedMilliseconds=$blocked.milliseconds;deadlineMilliseconds=180000;preflightRefusalLogged=$true;installedFileTreePreserved=$true;completeRegistrationPreserved=$true;profilePreserved=$true;machineStateUnchanged=$true}
    $stage='upgrade'
    $upgraded=Native-Record $second $arguments;Assert-Installed $builds[1]
    Require ((Digest $marker) -ceq $markerHash) 'Upgrade changed an unrelated installed-directory file'
    $observations+=,@{operation='upgrade';exitCode=$upgraded.result.exitCode;elapsedMilliseconds=$upgraded.milliseconds;deadlineMilliseconds=180000;payloadAndRegistrationVerified=$true;unrelatedStatePreserved=$true}
    Assert-ManagedDetection 'after-upgrade' $builds[1] $true
    Assert-ManagedDetection 'superseded-version' $builds[0] $false
    $null=State-Checkpoint 'after-upgrade'
    $stage='reinstall'
    $reinstalled=Native-Record $second $arguments;Assert-Installed $builds[1]
    Require ((Digest $marker) -ceq $markerHash) 'Reinstall changed an unrelated installed-directory file'
    $observations+=,@{operation='reinstall';exitCode=$reinstalled.result.exitCode;elapsedMilliseconds=$reinstalled.milliseconds;deadlineMilliseconds=180000;payloadAndRegistrationVerified=$true;unrelatedStatePreserved=$true}
    Assert-ManagedDetection 'after-reinstall' $builds[1] $true
    $null=State-Checkpoint 'after-reinstall'
    Require ((Read-InstallerPEMachine (Join-Path $install 'unins000.exe')) -eq 0x014c) 'Pinned Inno uninstaller differs from the supported x86 native-handle ABI'
    $stage='active-setup-uninstall';$lifecycleLockCases=@()
    $setupMutexName='Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092'
    $setupMutex=[Threading.Mutex]::new($false,$setupMutexName);$ownsSetupMutex=$false
    try {
        $ownsSetupMutex=$setupMutex.WaitOne(0)
        Require $ownsSetupMutex 'The fixture could not reserve its setup mutex'
        $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
        $busyRemoval=Native-Record (Join-Path $install 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') (0..255)
        $binaryPresent=Test-Path -LiteralPath (Join-Path $install 'accessweaver.exe')
        $registrationPresent=$null -ne (Registration)
        $treeAfter=if(Test-Path -LiteralPath $install){Installed-TreeFingerprint}else{'absent'}
        $registrationAfter=if($registrationPresent){Registration-Fingerprint}else{'absent'}
        $lifecycleLockCases+=,@{name='active-setup-blocks-uninstall';exitCode=$busyRemoval.result.exitCode;elapsedMilliseconds=$busyRemoval.milliseconds;payloadPresent=$binaryPresent;registrationPresent=$registrationPresent;installedFileTreePreserved=($treeAfter -ceq $treeBefore);registrationValuesPreserved=($registrationAfter -ceq $registrationBefore)}
        Require ($busyRemoval.result.exitCode -ne 0 -and $binaryPresent -and $registrationPresent -and $treeAfter -ceq $treeBefore -and $registrationAfter -ceq $registrationBefore) 'Uninstaller changed the installation while a setup mutex was active'
        Assert-Installed $builds[1]
        Require (-not (Test-Path -LiteralPath $managed)) 'Refused concurrent removal unexpectedly created machine recovery state'
    } finally {if($ownsSetupMutex){$setupMutex.ReleaseMutex()};$setupMutex.Dispose()}
    $null=State-Checkpoint 'after-active-setup-uninstall'
    $stage='lifecycle-lock-contracts'
    function Assert-DetectorRefusal([string]$Phase){
        $expected=$builds[1]
        $output=@(& $detector -Version $expected.version -Architecture $Architecture -PayloadSHA256 $expected.payloadSha256 -InstallDirectory $install 2>&1)
        Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection reported a result during a lifecycle inspection refusal'
        $script:detectionCases+=,@{phase=$Phase;detected=$false;inspectionRefused=$true}
    }
    $lockName='Global\AccessWeaver-Lifecycle-B13D4677-4660-4E63-B3DB-03077ACBB092'
    $lockFixture=Join-Path $PSScriptRoot 'fixtures\InstallerLifecycleLock.cs'
    Add-Type -Path $lockFixture
    $lifecycleLockFixtureSHA256=Digest $lockFixture
    $productLockSHA256=Digest (Join-Path $PSScriptRoot 'windows-installer-lock.iss')
    $uninstallArguments=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
    function Assert-LockRefusal([string]$name,[string]$binary,[string[]]$argsForChild){
        $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
        $refused=Native-Record $binary $argsForChild (0..255)
        $treeAfter=Installed-TreeFingerprint;$registrationAfter=Registration-Fingerprint
        Require ($refused.result.exitCode -ne 0 -and $treeBefore -ceq $treeAfter -and $registrationBefore -ceq $registrationAfter) 'Lifecycle lock refusal changed installation state or reported success'
        Assert-Installed $builds[1]
        Require (-not (Test-Path -LiteralPath $managed)) 'Refused lifecycle contention unexpectedly changed machine recovery state'
        return @{name=$name;exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;installedFileTreePreserved=$true;registrationValuesPreserved=$true;profilePreserved=$true;machineRecoveryStateAbsent=$true}
    }
    $mutex=[Threading.Mutex]::new($false,$lockName);$ownsMutex=$false
    try {
        $ownsMutex=$mutex.WaitOne(0);Require $ownsMutex 'Lifecycle fixture could not obtain exclusive ownership'
        Assert-DetectorRefusal 'active-lifecycle-refused'
        $lifecycleLockCases+=,(Assert-LockRefusal 'active-lifecycle-blocks-setup' $second $arguments)
        $lifecycleLockCases+=,(Assert-LockRefusal 'active-lifecycle-blocks-uninstall' (Join-Path $install 'unins000.exe') $uninstallArguments)
    } finally {if($ownsMutex){$mutex.ReleaseMutex()};$mutex.Dispose()}
    try {
        [AccessWeaverLifecycleLockFixture]::Abandon($lockName)
        Assert-DetectorRefusal 'abandoned-lifecycle-refused'
        $lifecycleLockCases+=,(Assert-LockRefusal 'abandoned-lifecycle-refused' $second $arguments)
    } finally {[AccessWeaverLifecycleLockFixture]::Close()}
    $collision=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$lockName)
    try {
        $lifecycleLockCases+=,(Assert-LockRefusal 'different-kernel-object-refused' $second $arguments)
    } finally {$collision.Dispose()}
    # Successful setup after all holders close proves the fixture leaves no lock.
    $resumed=Native-Record $second $arguments;Assert-Installed $builds[1]
    Assert-ManagedDetection 'after-lifecycle-locks' $builds[1] $true
    $lifecycleLockCases+=,@{name='released-lifecycle-allows-setup';exitCode=$resumed.result.exitCode;elapsedMilliseconds=$resumed.milliseconds;payloadAndRegistrationVerified=$true;profilePreserved=$true}
    $null=State-Checkpoint 'after-lifecycle-locks'
    $stage='pending-installation'
    $registryFixture=Join-Path $PSScriptRoot 'fixtures\InstallerRegistryFixture.cs'
    Add-Type -Path $registryFixture
    $registryFixtureSHA256=Digest $registryFixture
    $pendingValue=$builds[1].version+'|'+$install
    Require ($null -eq (Get-PendingInstallFixtureValue)) 'Successful Setup did not clear its pending record'
    Require ((Get-AccessWeaverInstallerRecoveryState) -ceq 'clear') 'Controller did not observe cleared Setup recovery state'
    $failedCopyLog=Join-Path $capsule 'failed-install-copy.log'
    $installedSBOM=Join-Path $install 'SBOM.cdx.json'
    $sbomBeforeFailure=Digest $installedSBOM
    $sbomGuard=[IO.File]::Open($installedSBOM,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $failedCopy=Native-Record $second ($arguments+@('/LOG='+$failedCopyLog)) @(4,5)
    } finally {$sbomGuard.Dispose()}
    Require ((Get-Item -LiteralPath $failedCopyLog).Length -le 1MB) 'Failed installation log exceeds its bound'
    $copyLog=[IO.File]::ReadAllText($failedCopyLog)
    Require ($copyLog.Contains('Starting the installation process.') -and
        $copyLog.Contains($installedSBOM) -and
        $copyLog.Contains('An error occurred while trying to replace the existing file:')) 'Setup did not encounter the expected native SBOM replacement failure'
    Require ((Get-PendingInstallFixtureValue) -ceq $pendingValue) 'Failed Setup did not retain its own pending installation record'
    Require ((Get-AccessWeaverInstallerRecoveryState) -ceq 'pending') 'Controller did not observe the native Setup recovery marker'
    Require ((Digest $installedSBOM) -ceq $sbomBeforeFailure) 'Failed Setup changed the locked SBOM'
    Assert-UserState
    $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
    Assert-DetectorRefusal 'pending-install-refused'
    $controllerRefused=$false
    try {
        $pendingBinding=Open-WorkflowUninstallBinding $Architecture
        if($pendingBinding){$pendingBinding.stream.Dispose()}
    } catch {
        $controllerRefused=$_.Exception.Message -ceq 'An AccessWeaver installation is incomplete. Retry the approved installer before uninstalling.'
    }
    Require $controllerRefused 'Controller uninstall binding accepted a pending installation'
    $stage='pending-marker-access-policy'
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($installerLifecycleKey,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::FullControl)
        Require ($null -ne $key -and $key.GetValue('PendingInstall') -ceq $pendingValue) 'Owned Setup recovery marker changed before the access-denial fixture'
        $access=[Security.AccessControl.AccessControlSections]::Access
        $originalSDDL=$key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access)
        $restoreSecurity=[Security.AccessControl.RegistrySecurity]::new()
        $restoreSecurity.SetSecurityDescriptorSddlForm($originalSDDL,$access)
        $deniedSecurity=[Security.AccessControl.RegistrySecurity]::new()
        $deniedSecurity.SetSecurityDescriptorSddlForm($originalSDDL,$access)
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $deniedSecurity.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($identity.User,[Security.AccessControl.RegistryRights]::QueryValues,[Security.AccessControl.AccessControlType]::Deny))
        } finally {$identity.Dispose()}
        try {
            $key.SetAccessControl($deniedSecurity)
            $deniedSDDL=$key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access)
            $queryStatus=[InstallerRegistryFixture]::QueryStatus64($base,$installerLifecycleKey)
            Require ($queryStatus -eq 5) 'Setup recovery marker denial did not produce native ERROR_ACCESS_DENIED'
            $discovery=Native-Record (Join-Path $install 'accessweaver.exe') @('system','discover') @(0) 45
            $job=ConvertFrom-Json -InputObject $discovery.result.stdout -ErrorAction Stop
            Require ($job.action -ceq 'discover' -and $job.state -ceq 'succeeded' -and
                $job.result.data.installerRecovery -ceq 'unavailable' -and
                $job.result.data.conflicts -ccontains 'AccessWeaver Setup recovery state could not be read. Ask an administrator to verify it before uninstalling.') 'Installed discovery did not distinguish denied marker access'
            Assert-DetectorRefusal 'pending-marker-access-denied'
            $controllerRefused=$false
            try {
                $deniedBinding=Open-WorkflowUninstallBinding $Architecture
                if($deniedBinding){$deniedBinding.stream.Dispose()}
            } catch {
                $controllerRefused=$_.Exception.Message -ceq 'AccessWeaver Setup recovery state could not be read. Ask an administrator to verify it before uninstalling.'
            }
            Require $controllerRefused 'Controller uninstall binding accepted a denied recovery marker'
            $deniedLog=Join-Path $capsule 'denied-marker-uninstall.log'
            $deniedUninstall=Native-Record (Join-Path $install 'unins000.exe') ($uninstallArguments+@('/LOG='+$deniedLog)) @(1)
            Require ((Get-Item -LiteralPath $deniedLog).Length -le 1MB -and
                [IO.File]::ReadAllText($deniedLog).Contains('Cannot verify the AccessWeaver pending installation record.')) 'Native uninstaller did not report denied recovery marker access'
            Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore -and
                $key.GetValue('PendingInstall') -ceq $pendingValue -and $key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access) -ceq $deniedSDDL) 'Denied recovery marker inspection changed protected state'
            Assert-UserState
        } finally {$key.SetAccessControl($restoreSecurity)}
        Require ($key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access) -ceq $originalSDDL -and
            (Get-AccessWeaverInstallerRecoveryState) -ceq 'pending') 'Setup recovery marker access was not restored'
        $pendingMarkerAccess=@{
            nativeQueryStatus=$queryStatus;nativeUninstallExitCode=$deniedUninstall.result.exitCode;
            discoveryReportedUnavailable=$true;managedDetectionRefused=$true;controllerUninstallBindingRefused=$true;
            nativeUninstallerRefusalLogged=$true;installationRegistrationAndMarkerPreserved=$true;profilePreserved=$true;
            fixtureDACLRestored=$true;pendingStateObservedAfterRestore=$true
        }
    } finally {
        if($key){$key.Dispose()}
        $base.Dispose()
    }
    $stage='pending-installation-retry'
    $null=Native-Record (Join-Path $install 'unins000.exe') $uninstallArguments @(1)
    $other=Join-Path $capsule 'wrong-install-destination'
    $redirected=@($arguments | Where-Object {$_ -notlike '/DIR=*'})+@('/DIR='+$other)
    $null=Native-Record $second $redirected @(7)
    $pendingLog=Join-Path $capsule 'older-pending-setup.log'
    $null=Native-Record $first ($arguments+@('/LOG='+$pendingLog)) @(1)
    Require ((Get-Item -LiteralPath $pendingLog).Length -le 1MB) 'Pending upgrade refusal log exceeds its bound'
    Require ([IO.File]::ReadAllText($pendingLog).Contains('Retry with the same or a newer approved installer.')) 'Older Setup did not report the pending version refusal'
    Require ((Get-PendingInstallFixtureValue) -ceq $pendingValue -and -not (Test-Path -LiteralPath $other)) 'Refused lifecycle operations changed the pending record or alternate destination'
    Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Pending-install refusal changed installed files or registration'
    Assert-UserState
    $completionLog=Join-Path $capsule 'retry-install-completion.log'
    $null=Native-Record $second ($arguments+@('/LOG='+$completionLog))
    Assert-SetupCompletionReadback $completionLog
    Assert-Installed $builds[1]
    Require ($null -eq (Get-PendingInstallFixtureValue)) 'Successful retry left the pending installation record'
    Require ((Get-AccessWeaverInstallerRecoveryState) -ceq 'clear') 'Controller did not observe cleared recovery state after retry'
    Assert-ManagedDetection 'after-pending-install-retry' $builds[1] $true
    $observations+=,@{
        operation='recover-failed-install-copy';exitCode=$failedCopy.result.exitCode;
        elapsedMilliseconds=$failedCopy.milliseconds;deadlineMilliseconds=180000;
        copyFailureLogged=$true;pendingRecordCreatedBySetup=$true;lockedSBOMPreserved=$true;
        refusedOperationsPreservedInstallation=$true;controllerUninstallBindingRefused=$true;profilePreserved=$true;
        approvedPackageDetectedAfterRetry=$true;pendingRecordClearedAfterRetry=$true
    }
    $stage='refused-downgrade'
    $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
    $downgrade=Native-Record $first $arguments (0..255)
    $treeAfter=Installed-TreeFingerprint;$registrationAfter=Registration-Fingerprint
    $after=Native-Record (Join-Path $install 'accessweaver.exe') @('version','--json')
    $afterIdentity=$after.result.stdout | ConvertFrom-Json
    $observations+=,@{operation='refused-downgrade';exitCode=$downgrade.result.exitCode;elapsedMilliseconds=$downgrade.milliseconds;deadlineMilliseconds=180000;installedVersionAfter=$afterIdentity.version;installedFileTreePreserved=($treeAfter -ceq $treeBefore);completeRegistrationPreserved=($registrationAfter -ceq $registrationBefore)}
    Require ($downgrade.result.exitCode -ne 0) 'Older installer accepted an unattended downgrade over the newer installation'
    Require ($treeAfter -ceq $treeBefore -and $registrationAfter -ceq $registrationBefore) 'Refused downgrade changed installed files or registration'
    Assert-Installed $builds[1]
    Require ((Digest $marker) -ceq $markerHash) 'Refused downgrade changed an unrelated file'
    Assert-ManagedDetection 'after-refused-downgrade' $builds[1] $true
    $null=State-Checkpoint 'after-refused-downgrade'
    $stage='version-registration-policy';$versionPolicyCases=@()
    foreach($case in @(
        @{name='same-core-stable';value='0.1.0';kind=[Microsoft.Win32.RegistryValueKind]::String},
        @{name='newer-prerelease';value='0.1.0-beta.2+fixture';kind=[Microsoft.Win32.RegistryValueKind]::String},
        @{name='invalid-version';value='not-a-release';kind=[Microsoft.Win32.RegistryValueKind]::String},
        @{name='leading-zero';value='00.1.0';kind=[Microsoft.Win32.RegistryValueKind]::String},
        @{name='missing-version';value=$null;kind=$null},
        @{name='wrong-type';value=123;kind=[Microsoft.Win32.RegistryValueKind]::DWord}
    )){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $key=$null
        try {
            $key=$base.OpenSubKey($uninstallKey,$true);Require ($null -ne $key) 'Owned installation registration is unavailable'
            $originalVersion=$key.GetValue('DisplayVersion')
            $originalKind=$key.GetValueKind('DisplayVersion')
            try {
                if($null -eq $case.value){$key.DeleteValue('DisplayVersion')}else{$key.SetValue('DisplayVersion',$case.value,$case.kind)}
                $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
                $refusal=Native-Record $first $arguments (0..255)
                $treeAfter=Installed-TreeFingerprint;$registrationAfter=Registration-Fingerprint
                Require ($refusal.result.exitCode -ne 0 -and $treeAfter -ceq $treeBefore -and $registrationAfter -ceq $registrationBefore) 'Registered-version policy allowed replacement or changed protected installation state'
                $versionPolicyCases+=,@{name=$case.name;exitCode=$refusal.result.exitCode;elapsedMilliseconds=$refusal.milliseconds;installedFileTreePreserved=$true;completeRegistrationPreserved=$true}
            } finally {$key.SetValue('DisplayVersion',$originalVersion,$originalKind)}
        } finally {if($key){$key.Dispose()};$base.Dispose()}
        Assert-Installed $builds[1]
    }
    $null=State-Checkpoint 'after-version-policy'
    $stage='registry-read-boundaries';$registryReadCases=@()
    foreach($case in @(
        @{name='maximum-string-accepted';value=('0.0.0-'+('a'*250));kind=[Microsoft.Win32.RegistryValueKind]::String;expected=0},
        @{name='maximum-expand-literal-accepted';value=('0.0.0-'+('a'*250));kind=[Microsoft.Win32.RegistryValueKind]::ExpandString;expected=0},
        @{name='over-budget-string-refused';value=('0.0.0-'+('a'*251));kind=[Microsoft.Win32.RegistryValueKind]::String;expected=1},
        @{name='oversized-string-refused';value=('0.0.0-'+('a'*65536));kind=[Microsoft.Win32.RegistryValueKind]::String;expected=1},
        @{name='environment-reference-not-expanded';value='0.0.0-%ACCESSWEAVER_INSTALLER_REGISTRY_VERSION_PROBE%';kind=[Microsoft.Win32.RegistryValueKind]::ExpandString;expected=1}
    )){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
        try {
            $key=$base.OpenSubKey($uninstallKey,$true);Require ($null -ne $key) 'Owned installation registration is unavailable'
            $originalVersion=$key.GetValue('DisplayVersion');$originalKind=$key.GetValueKind('DisplayVersion')
            try {
                $key.SetValue('DisplayVersion',$case.value,$case.kind)
                $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint $key
                # A successful Inno reinstall replaces the registry leaf. Do not
                # retain its old handle when restoring the fixture metadata.
                if($case.expected -eq 0){$key.Dispose();$key=$null}
                $resultCase=Native-Record $second $arguments (0..255)
                Require ($resultCase.result.exitCode -eq $case.expected) 'Bounded registry version handling returned an unexpected result'
                if($case.expected -ne 0){
                    Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint $key) -ceq $registrationBefore) 'Registry value refusal changed installed state'
                }
                $registryReadCases+=,@{name=$case.name;expectedExitCode=$case.expected;exitCode=$resultCase.result.exitCode;elapsedMilliseconds=$resultCase.milliseconds;fixtureUTF16Bytes=([Text.Encoding]::Unicode.GetByteCount($case.value)+2);refusedStatePreserved=($case.expected -ne 0);profilePreserved=$true}
            } finally {
                if($null -eq $key){$key=$base.OpenSubKey($uninstallKey,$true);Require ($null -ne $key) 'Owned registration disappeared after boundary setup'}
                $key.SetValue('DisplayVersion',$originalVersion,$originalKind)
            }
        } finally {if($key){$key.Dispose()};$base.Dispose()}
        Assert-Installed $builds[1]
    }
    $null=State-Checkpoint 'after-registry-read-boundaries'
    $stage='registry-view-policy'
    $productRegistrySHA256=Digest (Join-Path $PSScriptRoot 'windows-installer-registry.iss')
    $parentPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $productLeaf='{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1'
    $backupLeaf='AccessWeaver-owned-fixture-'+$guid
    $base32=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry32)
    $base64=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $parent32=$null;$parent64=$null;$key32=$null;$created32=$false;$renamed64=$false
    try {
        $parent32=$base32.OpenSubKey($parentPath,$true);$parent64=$base64.OpenSubKey($parentPath,$true)
        Require ($null -ne $parent32 -and $null -ne $parent64) 'Owned registry fixture parents are unavailable'
        foreach($check in @(@{parent=$parent32;leaf=$productLeaf},@{parent=$parent64;leaf=$backupLeaf})){
            $existing=$check.parent.OpenSubKey($check.leaf)
            try {Require ($null -eq $existing) 'Registry view fixture destination already exists'} finally {if($existing){$existing.Dispose()}}
        }
        $key32=$parent32.CreateSubKey($productLeaf);$created32=$true
        $key32.SetValue('DisplayVersion',$builds[1].version,[Microsoft.Win32.RegistryValueKind]::String)
        $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
        $view32Before=Registration-Fingerprint $key32
        $ambiguous=Native-Record $second $arguments (0..255)
        Require ($ambiguous.result.exitCode -eq 1 -and (Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore -and (Registration-Fingerprint $key32) -ceq $view32Before) 'Ambiguous registry views allowed setup or changed installed state'
        Assert-UserState
        $registryViewCases+=,@{name='ambiguous-views-refused';exitCode=$ambiguous.result.exitCode;elapsedMilliseconds=$ambiguous.milliseconds;installedFileTreePreserved=$true;registrationValuesPreserved=$true;profilePreserved=$true}
        [InstallerRegistryFixture]::Rename($parent64,$productLeaf,$backupLeaf);$renamed64=$true
        try {
            $absent=$parent64.OpenSubKey($productLeaf)
            try {Require ($null -eq $absent) '64-bit registration was not hidden for the isolated view fixture'} finally {if($absent){$absent.Dispose()}}
            $older=Native-Record $first $arguments (0..255)
            $backup=$parent64.OpenSubKey($backupLeaf)
            try {Require ($null -ne $backup -and (Registration-Fingerprint $backup) -ceq $registrationBefore) 'Refused 32-bit-view downgrade changed the retained 64-bit registration'} finally {if($backup){$backup.Dispose()}}
            $unexpected=$parent64.OpenSubKey($productLeaf)
            try {Require ($null -eq $unexpected) '32-bit-view downgrade created unexpected 64-bit registration'} finally {if($unexpected){$unexpected.Dispose()}}
            Require ($older.result.exitCode -eq 1 -and (Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint $key32) -ceq $view32Before) '32-bit-only registration allowed downgrade or changed installed state'
            Assert-UserState
            $registryViewCases+=,@{name='32-bit-only-newer-version-refused';exitCode=$older.result.exitCode;elapsedMilliseconds=$older.milliseconds;installedFileTreePreserved=$true;registrationValuesPreserved=$true;profilePreserved=$true}
        } finally {
            # RegRenameKey refuses an existing destination; preserve unexpected
            # state for review rather than deleting/overwriting either key.
            if($renamed64){[InstallerRegistryFixture]::Rename($parent64,$backupLeaf,$productLeaf);$renamed64=$false}
        }
    } finally {
        if($created32 -and $key32){
            try {
                Require ($key32.SubKeyCount -eq 0 -and $key32.ValueCount -eq 1 -and $key32.GetValueNames()[0] -ceq 'DisplayVersion' -and $key32.GetValueKind('DisplayVersion') -eq [Microsoft.Win32.RegistryValueKind]::String -and $key32.GetValue('DisplayVersion') -ceq $builds[1].version) 'Unexpected 32-bit fixture state must be retained for review'
                $key32.Dispose();$key32=$null
                $parent32.DeleteSubKey($productLeaf,$true)
            } finally {if($key32){$key32.Dispose()}}
        }
        if($parent64){$parent64.Dispose()};if($parent32){$parent32.Dispose()};$base64.Dispose();$base32.Dispose()
    }
    Assert-Installed $builds[1]
    $null=State-Checkpoint 'after-registry-view-policy'
    $stage='registry-access-policy'
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null;$restoreSecurity=$null
    try {
        $key=$base.OpenSubKey($uninstallKey,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::FullControl)
        Require ($null -ne $key) 'Owned key is unavailable for isolated access-denial fixture'
        $access=[Security.AccessControl.AccessControlSections]::Access
        $originalSDDL=$key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access)
        $restoreSecurity=[Security.AccessControl.RegistrySecurity]::new();$restoreSecurity.SetSecurityDescriptorSddlForm($originalSDDL,$access)
        $deniedSecurity=[Security.AccessControl.RegistrySecurity]::new();$deniedSecurity.SetSecurityDescriptorSddlForm($originalSDDL,$access)
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        try {$deniedSecurity.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($identity.User,[Security.AccessControl.RegistryRights]::QueryValues,[Security.AccessControl.AccessControlType]::Deny))} finally {$identity.Dispose()}
        try {
            $key.SetAccessControl($deniedSecurity)
            $deniedSDDL=$key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access)
            # Framework versions wrap this deliberate denial differently.
            # Require the exact native result instead of matching exceptions.
            $queryStatus=[InstallerRegistryFixture]::QueryStatus64($base,$uninstallKey)
            Require ($queryStatus -eq 5) 'Owned-key query denial did not produce native ERROR_ACCESS_DENIED'
            # Existing handle retains its granted rights for inspection/restore.
            $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint $key
            $denied=Native-Record $second $arguments (0..255)
            Require ($denied.result.exitCode -eq 1 -and (Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint $key) -ceq $registrationBefore -and $key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access) -ceq $deniedSDDL) 'Denied registration read allowed setup or changed protected state'
            Assert-UserState
            $registryAccessCases+=,@{name='denied-product-key-refused';exitCode=$denied.result.exitCode;elapsedMilliseconds=$denied.milliseconds;queryDenialIndependentlyObserved=$true;nativeQueryStatus=$queryStatus;installedFileTreePreserved=$true;registrationValuesPreserved=$true;fixtureDACLUnchangedDuringRefusal=$true;profilePreserved=$true}
        } finally {$key.SetAccessControl($restoreSecurity)}
        Require ($key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access) -ceq $originalSDDL) 'Owned key access-control restoration differs from the original'
        $registryAccessCases[-1].fixtureDACLRestored=$true
    } finally {if($key){$key.Dispose()};$base.Dispose()}
    Assert-Installed $builds[1]
    $null=State-Checkpoint 'after-registry-access-policy'
    $stage='restoration-launch-failures'
    $launchFixture=Join-Path $PSScriptRoot 'fixtures\InstallerRestorationLaunch.cs'
    Add-Type -Path $launchFixture
    $restoreLaunchFixtureSHA256=Digest $launchFixture
    $core=Join-Path $install 'accessweaver.exe';No-Reparse $core
    $launchBackup=Join-Path $capsule 'launch-original-controller.exe'
    [IO.File]::Copy($core,$launchBackup,$false)
    Require ((Digest $launchBackup) -ceq $builds[1].payloadSha256) 'Launch fixture backup differs from the installed controller'
    $fileAccess=[Security.AccessControl.AccessControlSections]::Access
    $originalFileSDDL=[IO.File]::GetAccessControl($core,$fileAccess).GetSecurityDescriptorSddlForm($fileAccess)
    foreach($case in @(
        @{name='missing-controller-refused';kind='missing';nativeErrors=@(2)},
        @{name='truncated-controller-refused';kind='truncated';nativeErrors=@(193,1392)},
        @{name='malformed-controller-refused';kind='malformed';nativeErrors=@(193,1392)},
        @{name='execution-denied-controller-refused';kind='denied';nativeErrors=@(5)}
    )){
        $stage='restoration-launch-'+$case.kind;$caseRecord=$null
        try {
            switch($case.kind){
                'missing' {[IO.File]::Delete($core)}
                'truncated' {[IO.File]::WriteAllBytes($core,[byte[]]@(0,0,0,0))}
                'malformed' {[IO.File]::WriteAllBytes($core,[byte[]]::new(4096))}
                'denied' {
                    $deniedSecurity=[Security.AccessControl.FileSecurity]::new()
                    $deniedSecurity.SetSecurityDescriptorSddlForm($originalFileSDDL,$fileAccess)
                    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
                    try {$deniedSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity.User,[Security.AccessControl.FileSystemRights]::ExecuteFile,[Security.AccessControl.AccessControlType]::Deny))} finally {$identity.Dispose()}
                    [IO.File]::SetAccessControl($core,$deniedSecurity)
                }
            }
            $controllerPresent=[IO.File]::Exists($core)
            Require ($controllerPresent -eq ($case.kind -cne 'missing')) 'Launch fixture controller state differs from its expected precondition'
            $fixtureSDDL=if($controllerPresent){[IO.File]::GetAccessControl($core,$fileAccess).GetSecurityDescriptorSddlForm($fileAccess)}else{$null}
            $probe=[InstallerRestorationLaunch]::Probe($core)
            Require (-not $probe.Started -and $case.nativeErrors -contains $probe.NativeError) 'Independent native launch probe did not confirm the expected rejection category'
            $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
            $logPath=Join-Path $capsule ($case.name+'.log')
            Require (-not (Test-Path -LiteralPath $logPath)) 'Launch fixture log already exists'
            $attempt=Native-Record (Join-Path $install 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG='+$logPath)) @(1)
            Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Native restoration launch failure changed installation state'
            $fileDACLUnchanged=$false
            if($controllerPresent){
                Require ([IO.File]::GetAccessControl($core,$fileAccess).GetSecurityDescriptorSddlForm($fileAccess) -ceq $fixtureSDDL) 'Launch refusal changed the fixture controller DACL'
                $fileDACLUnchanged=$true
            }
            Assert-UserState
            Require (-not (Test-Path -LiteralPath $managed)) 'Unlaunched controller unexpectedly created machine recovery state'
            No-Reparse $logPath;Require ((Get-Item -LiteralPath $logPath).Length -le 4MB) 'Launch refusal log exceeds bounds'
            $log=[IO.File]::ReadAllText($logPath)
            $nativeMatches=[regex]::Matches($log,'(?m)AccessWeaver system restoration failed; process result/error code: ([0-9]{1,10})\r?$')
            Require ($nativeMatches.Count -eq 1) 'Native launch refusal did not retain exactly one bounded numeric error'
            $observedNativeError=[long]::Parse($nativeMatches[0].Groups[1].Value,[Globalization.CultureInfo]::InvariantCulture)
            Require ($observedNativeError -le [uint32]::MaxValue) 'Native launch error exceeds the Windows error-code range'
            $launchPhaseObserved=$log.Contains('AccessWeaver could not launch the restoration controller.')
            $expectedErrorObserved=$observedNativeError -eq $probe.NativeError
            $caseRecord=@{name=$case.name;failurePhase='launch-controller';launchPhaseObserved=$launchPhaseObserved;expectedNativeError=$probe.NativeError;independentProbeStarted=$probe.Started;independentProbeNativeError=$probe.NativeError;nativeError=$observedNativeError;nativeErrorLogVerified=($launchPhaseObserved -and $expectedErrorObserved);exitCode=$attempt.result.exitCode;elapsedMilliseconds=$attempt.milliseconds;observationDeadlineMilliseconds=180000;controllerPresentDuringRefusal=$controllerPresent;installedFileTreePreserved=$true;registrationValuesPreserved=$true;profilePreserved=$true;fileDACLCheckApplicable=$controllerPresent;fileDACLUnchangedDuringRefusal=$fileDACLUnchanged;originalControllerAndDACLRestored=$false;restoredControllerRuntimeVerified=$false}
            # Preserve fixed numeric observations even when the expectation fails.
            $restorationLaunchCases+=,$caseRecord
            Require ($launchPhaseObserved -and $expectedErrorObserved) 'Native launch refusal did not retain its fixed phase and exact error code'
        } finally {
            # Reconstruct a modified security object so SetAccessControl really
            # persists the saved DACL; never change the parent installation ACL.
            if([IO.File]::Exists($core)){
                No-Reparse $core
                $restoreSecurity=[Security.AccessControl.FileSecurity]::new();$restoreSecurity.SetSecurityDescriptorSddlForm($originalFileSDDL,$fileAccess)
                [IO.File]::SetAccessControl($core,$restoreSecurity)
            }
            [IO.File]::Copy($launchBackup,$core,$true)
            $restoreSecurity=[Security.AccessControl.FileSecurity]::new();$restoreSecurity.SetSecurityDescriptorSddlForm($originalFileSDDL,$fileAccess)
            [IO.File]::SetAccessControl($core,$restoreSecurity)
            Require ((Digest $core) -ceq $builds[1].payloadSha256 -and [IO.File]::GetAccessControl($core,$fileAccess).GetSecurityDescriptorSddlForm($fileAccess) -ceq $originalFileSDDL) 'Launch fixture controller bytes or DACL were not restored'
            if($caseRecord){$caseRecord.originalControllerAndDACLRestored=$true}
        }
        Assert-Installed $builds[1]
        $caseRecord.restoredControllerRuntimeVerified=$true
    }
    $null=State-Checkpoint 'after-restoration-launch-failures'
    $stage='restoration-ownership-contracts'
    $restoreOwnerFixture=Join-Path $PSScriptRoot 'fixtures\InstallerRestorationOwner.cs'
    Add-Type -Path $restoreOwnerFixture -ReferencedAssemblies @('System.dll','System.Core.dll','System.Runtime.Serialization.dll','System.Xml.dll')
    $restoreOwnerFixtureSHA256=Digest $restoreOwnerFixture
    $restoreFixtureSource=Join-Path $PSScriptRoot 'fixtures\installer-restoration\main.go'
    $restoreFixtureSourceSHA256=Digest $restoreFixtureSource
    $productRestoreSHA256=Digest (Join-Path $PSScriptRoot 'windows-installer-restore.iss')
    $fixtureController=Join-Path $capsule 'restoration-controller.exe'
    $null=@(& go build -trimpath -buildvcs=false -o $fixtureController ./scripts/fixtures/installer-restoration)
    Require ($LASTEXITCODE -eq 0) 'Native restoration fixture compilation failed'
    Assert-InstallerPEArchitecture $fixtureController $Architecture
    $restoreFixtureBinarySHA256=Digest $fixtureController
    $restoreContractSource=Join-Path $PSScriptRoot 'test-windows-installer-restore.iss'
    $restoreContractSourceSHA256=Digest $restoreContractSource
    $null=@(& $compiler ('/DEvidenceRoot='+$capsule) $restoreContractSource)
    Require ($LASTEXITCODE -eq 0) 'Shared restoration contract compilation failed'
    $restoreContract=Join-Path $capsule 'installer-restoration-contracts.exe'
    $restoreContractBinarySHA256=Digest $restoreContract
    function Assert-FixtureProcessExited($idRecord){
        Require ($idRecord.pid -is [int] -or $idRecord.pid -is [long]) 'Fixture process identity is missing'
        Require ($idRecord.created -is [long] -and [long]$idRecord.pid -gt 0 -and [long]$idRecord.created -gt 0) 'Fixture process identity is invalid or imprecisely decoded'
        $process=$null
        try {
            try {$process=[Diagnostics.Process]::GetProcessById([int]$idRecord.pid)} catch [ArgumentException] {return}
            if($process.HasExited){return}
            # Reused PIDs are a different process and must never be signaled.
            Require ($process.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$idRecord.created) 'Restoration left an owned fixture process running'
        } finally {if($process){$process.Dispose()}}
    }
    $core=Join-Path $install 'accessweaver.exe';$originalCore=Join-Path $capsule 'original-controller.exe'
    [IO.File]::Copy($core,$originalCore,$false)
    Require ((Digest $originalCore) -ceq $builds[1].payloadSha256) 'Original controller backup differs from the installed candidate'
    try {
        foreach($case in @(
            @{name='failed-controller-descendant-cleaned';mode='exit-failure-with-child';contract=$false;deadline=180000;minimum=0},
            @{name='successful-controller-orphan-refused';mode='exit-success-with-child';contract=$true;deadline=180000;minimum=5000},
            @{name='stalled-controller-deadline-refused';mode='hang-with-child';contract=$false;deadline=360000;minimum=300000},
            @{name='terminated-uninstaller-owner-cleans-children';mode='owner-termination-with-child';contract=$false;deadline=180000;minimum=0;owner=$true}
        )){
            $stage='restoration-'+$case.name
            [IO.File]::Copy($fixtureController,$core,$true)
            $configuration=Join-Path $capsule ($case.name+'.json')
            [IO.File]::WriteAllText($configuration,('{"mode":"'+$case.mode+'"}'),[Text.UTF8Encoding]::new($false))
            $script:restoreFixtureConfiguration=$configuration
            $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
            $logPath=Join-Path $capsule ($case.name+'.log')
            Require (-not (Test-Path -LiteralPath $logPath)) 'Restoration fixture log already exists'
            if($case.owner){
                $ownerUninstallerHash=Digest (Join-Path $install 'unins000.exe')
                $observer=[InstallerRestorationOwner]::new(($configuration+'.ready'),$core,$restoreFixtureBinarySHA256,$ownerUninstallerHash,$privateTemp)
                try {
                    $attempt=Native-Record (Join-Path $install 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG='+$logPath)) (1..255)
                } finally {
                    try {
                        $ownerResult=$observer.Complete()
                        $restorationOwnerCases+=,@{name='terminated-live-uninstaller-owner';uninstallerImageSHA256=$ownerUninstallerHash;fixtureImageSHA256=$restoreFixtureBinarySHA256;passed=$ownerResult.Passed;stage=$ownerResult.Stage;ownerImageVerified=$ownerResult.OwnerImageVerified;rootAndChildImagesVerified=$ownerResult.RootAndChildImagesVerified;creationTimesVerified=$ownerResult.CreationTimesVerified;onlyOwnerSignaled=$ownerResult.OnlyOwnerSignaled;ownerExitCode=$ownerResult.OwnerExitCode;ownerExitConfirmed=$ownerResult.OwnerExitConfirmed;rootExitConfirmed=$ownerResult.RootExitConfirmed;childExitConfirmed=$ownerResult.ChildExitConfirmed;cleanupMilliseconds=$ownerResult.CleanupMilliseconds}
                    } finally {$observer.Dispose()}
                }
                Require ($ownerResult.Passed -and $ownerResult.OwnerExitCode -eq 167 -and $ownerResult.OnlyOwnerSignaled) 'Abrupt uninstaller-owner termination did not independently confirm descendant cleanup'
            }elseif($case.contract){
                $attempt=Native-Record $restoreContract @('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/Controller='+$core)) @(0)
            }else{
                $attempt=Native-Record (Join-Path $install 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG='+$logPath)) @(1) ([int]($case.deadline/1000))
            }
            Require ($attempt.milliseconds -ge $case.minimum -and $attempt.milliseconds -lt $case.deadline) 'Restoration ownership/deadline case finished outside its expected bound'
            $readyPath=$configuration+'.ready';No-Reparse $readyPath
            Require ((Get-Item -LiteralPath $readyPath).Length -le 4096) 'Restoration fixture observation exceeds bounds'
            $ready=Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
            Require ($ready.mode -ceq $case.mode -and $ready.root.pid -ne $ready.child.pid) 'Restoration fixture did not start the expected independent child'
            Assert-FixtureProcessExited $ready.root;Assert-FixtureProcessExited $ready.child
            Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Refused restoration changed installed files or registration'
            Assert-UserState
            Require (-not (Test-Path -LiteralPath $managed)) 'Inert restoration fixture unexpectedly created machine recovery state'
            $timeoutLogVerified=$false
            if($case.mode -ceq 'exit-failure-with-child'){
                No-Reparse $logPath;Require ((Get-Item -LiteralPath $logPath).Length -le 4MB) 'Restoration fixture log exceeds bounds'
                $log=[IO.File]::ReadAllText($logPath)
                Require ($log.Contains('AccessWeaver system restoration failed; process result/error code: 7')) 'Failed controller did not retain its exact native exit code'
            }
            if($case.mode -ceq 'hang-with-child'){
                No-Reparse $logPath;Require ((Get-Item -LiteralPath $logPath).Length -le 4MB) 'Restoration fixture log exceeds bounds'
                $log=[IO.File]::ReadAllText($logPath)
                Require ($log.Contains('AccessWeaver system restoration exceeded its five-minute deadline.') -and $log.Contains('AccessWeaver system restoration failed; process result/error code: 1460')) 'Stalled uninstaller did not retain the expected deadline refusal'
                $timeoutLogVerified=$true
            }
            $restorationCases+=,@{name=$case.name;mode=$case.mode;usesActualProductUninstaller=(-not $case.contract);exitCode=$attempt.result.exitCode;elapsedMilliseconds=$attempt.milliseconds;observationDeadlineMilliseconds=$case.deadline;restorationDeadlineMilliseconds=$(if($case.contract){5000}else{300000});ownedRootAndChildExitVerified=$true;installedFileTreePreserved=$true;registrationValuesPreserved=$true;profilePreserved=$true;timeoutLogVerified=$timeoutLogVerified}
            $script:restoreFixtureConfiguration=$null
            [IO.File]::Copy($originalCore,$core,$true)
            Assert-Installed $builds[1]
        }
    } finally {
        $script:restoreFixtureConfiguration=$null
        [IO.File]::Copy($originalCore,$core,$true)
    }
    Assert-Installed $builds[1]
    $null=State-Checkpoint 'after-restoration-ownership-contracts'
    $stage='refused-uninstall-registration'
    $uninstaller=Join-Path $install 'unins000.exe';No-Reparse $uninstaller;$uninstallerHash=Digest $uninstaller
    $silent=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
    $treeBefore=Installed-TreeFingerprint;$machineBeforeRemoval=State-Snapshot
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($uninstallKey,$true)
        Require ($null -ne $key) 'Owned installation registration is unavailable'
        $originalLocation=$key.GetValue('InstallLocation')
        $locationKind=$key.GetValueKind('InstallLocation')
        try {
            $wrongLocation=Join-Path $capsule 'mismatched-uninstall-registration'
            $key.SetValue('InstallLocation',($wrongLocation+[char]92),[Microsoft.Win32.RegistryValueKind]::String)
            $registrationBefore=Registration-Fingerprint $key
            $registrationRefusalLog=Join-Path $capsule 'uninstall-registration-refusal.log'
            $registrationRefusal=Native-Record $uninstaller ($silent+@('/LOG='+$registrationRefusalLog)) @(1)
            No-Reparse $registrationRefusalLog
            $logFile=Get-Item -LiteralPath $registrationRefusalLog -ErrorAction Stop
            Require (-not $logFile.PSIsContainer -and $logFile.Length -gt 0 -and $logFile.Length -le 1MB) 'Uninstall registration refusal log is unavailable or exceeds its bound'
            $log=[IO.File]::ReadAllText($registrationRefusalLog)
            Require ($log.Contains('This uninstaller does not match the active AccessWeaver installation directory.')) 'Uninstall did not log the registration refusal'
            Require (-not (Test-Path -LiteralPath $managed -ErrorAction Stop) -and -not $log.Contains('AccessWeaver system restoration starts at the uninstall step.')) 'Uninstall reached machine restoration after the registration refusal'
            Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint $key) -ceq $registrationBefore) 'Uninstall registration refusal changed installed files or registration'
            Assert-UserState
            Require ((State-Snapshot) -ceq $machineBeforeRemoval) 'Uninstall registration refusal changed observed machine state'
        } finally {$key.SetValue('InstallLocation',$originalLocation,$locationKind)}
    } finally {if($key){$key.Dispose()};$base.Dispose()}
    Assert-Installed $builds[1]
    $observations+=,@{operation='refused-uninstall-registration';exitCode=$registrationRefusal.result.exitCode;
        elapsedMilliseconds=$registrationRefusal.milliseconds;deadlineMilliseconds=180000;preflightRefusalLogged=$true;
        restorationStateAbsent=$true;installedFileTreePreserved=$true;completeRegistrationPreserved=$true;
        profilePreserved=$true;machineStateUnchanged=$true}
    $stage='refused-uninstall'
    $binding=Open-WorkflowUninstallBinding $Architecture
    Require ($null -ne $binding) 'Installed product registration could not be resolved for workflow uninstall'
    try {
        Require ($binding.path -ieq $uninstaller -and $binding.sha256 -ieq $uninstallerHash) 'Workflow uninstall did not bind the actual registered uninstaller'
    } finally {$binding.stream.Dispose()}
    $request=Join-Path $install 'uninstall-system.json';No-Reparse $request
    # The child must refuse through the real workflow when its mutex is busy.
    # A different valid JSON action must not select the elevated operation.
    [IO.File]::WriteAllText($request,'{"action":"discover"}')
    $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
    $workflowMutexSecurity=[Security.AccessControl.MutexSecurity]::new()
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){
        $principal=[Security.Principal.SecurityIdentifier]::new($sid)
        $workflowMutexSecurity.AddAccessRule([Security.AccessControl.MutexAccessRule]::new($principal,'FullControl','Allow'))
    }
    $createdWorkflowMutex=$false
    $workflowMutex=[Threading.Mutex]::new($false,'Global\AccessWeaver-SystemWorkflows',[ref]$createdWorkflowMutex,$workflowMutexSecurity)
    $ownsWorkflowMutex=$false
    try {
        $ownsWorkflowMutex=$workflowMutex.WaitOne(0)
        Require ($createdWorkflowMutex -and $ownsWorkflowMutex) 'The fixture could not reserve a new system workflow mutex'
        $blocked=Native-Record $core @('system','installer-restore','--confirm') @(1)
        $job=ConvertFrom-Json -InputObject $blocked.result.stdout -ErrorAction Stop
        Require ($job.action -ceq 'remove-all' -and $job.state -ceq 'failed' -and
            $job.result.error -ceq 'Another AccessWeaver system workflow is already running') 'The fixed restoration command did not observe the real workflow lock'
        $refusalLog=Join-Path $capsule 'fixed-restoration-refusal.log'
        $refused=Native-Record $uninstaller ($silent+@('/LOG='+$refusalLog)) @(1)
        No-Reparse $refusalLog
        Require ((Get-Item -LiteralPath $refusalLog -ErrorAction Stop).Length -le 4MB) 'Fixed restoration refusal log exceeds bounds'
        $log=[IO.File]::ReadAllText($refusalLog)
        Require ($log.Contains('AccessWeaver system restoration starts at the uninstall step.') -and
            $log.Contains('AccessWeaver system restoration did not complete successfully.') -and
            $log.Contains('AccessWeaver system restoration failed; process result/error code: 1') -and
            $log.Contains('CurUninstallStepChanged raised an exception (fatal).') -and
            -not $log.Contains('Removed all?')) 'Uninstaller did not abort at the confirmed uninstall step after restoration failed'
        Assert-Installed $builds[1]
        Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore -and
            (Digest $uninstaller) -ceq $uninstallerHash -and (Digest $marker) -ceq $markerHash) 'Refused uninstall changed owned or unrelated files'
        Require (-not (Test-Path -LiteralPath $managed)) 'Busy restoration unexpectedly created machine recovery state'
    } finally {
        if($ownsWorkflowMutex){$workflowMutex.ReleaseMutex()}
        $workflowMutex.Dispose()
    }
    $observations+=,@{operation='refused-uninstall';exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;controllerAndRegistrationRetained=$true;unrelatedStatePreserved=$true;workflowLockRefusalVerified=$true;registeredUninstallerBindingVerified=$true}
    Assert-ManagedDetection 'after-refused-uninstall' $builds[1] $true
    $null=State-Checkpoint 'before-uninstall'
    $stage='uninstall'
    [IO.File]::Delete($request)
    $removed=Native-Record $uninstaller $silent
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    do {
        $owned=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {$_.ExecutablePath -and ($_.ExecutablePath.StartsWith($install+'\',[StringComparison]::OrdinalIgnoreCase) -or $_.ExecutablePath.StartsWith($privateTemp+'\',[StringComparison]::OrdinalIgnoreCase))})
        if(-not $owned.Count -and -not (Test-Path -LiteralPath $uninstaller)){break}
        Start-Sleep -Milliseconds 200
    } while([DateTime]::UtcNow -lt $deadline)
    Require (-not $owned.Count -and -not (Test-Path -LiteralPath $uninstaller) -and -not (Test-Path -LiteralPath (Join-Path $install 'accessweaver.exe')) -and $null -eq (Registration)) 'Uninstall did not remove owned files/registration or finish its clone'
    Assert-UserState
    Require ((Digest $marker) -ceq $markerHash) 'Uninstall changed unrelated state'
    Require (@(Get-ChildItem -LiteralPath $install -File -Recurse -Force).Count -eq 1) 'Uninstall left unexpected payload files'
    foreach($path in $groupPaths){Require (-not (Test-Path -LiteralPath $path)) 'Uninstall left a fixture start-menu folder'}
    $journals=@(Get-ChildItem -LiteralPath (Join-Path $managed 'logs') -File -Filter 'workflow-*.json')
    Require ($journals.Count -eq 1) 'Expected exactly one recovery journal from clean removal'
    $journal=Get-Content -LiteralPath $journals[0].FullName -Raw | ConvertFrom-Json
    Require ($journal.action -ceq 'remove-all' -and $journal.state -ceq 'succeeded') 'Recovery-aware uninstall did not record successful machine restoration'
    Assert-ManagedDetection 'after-uninstall' $builds[1] $false
    $after=State-Checkpoint 'after-uninstall'
    Require ($after -ceq $before) 'Installer lifecycle changed selected services, firewall rules or DNS configuration'
    $observations+=,@{operation='uninstall';exitCode=$removed.result.exitCode;elapsedMilliseconds=$removed.milliseconds;deadlineMilliseconds=180000;ownedPayloadAndRegistrationRemoved=$true;unrelatedStatePreserved=$true;recoveryJournalRetained=$true;legacyRequestAbsent=$true}
    $stage='cleanup'
    # Only the known successful journal may remain in the newly created store.
    $files=@(Get-ChildItem -LiteralPath $managed -File -Recurse -Force)
    Require ($files.Count -eq 1 -and $files[0].FullName -ceq $journals[0].FullName) 'Unrelated recovery files must be retained for review'
    Remove-OwnedTree $managed $managedParent 'AccessWeaver'
    Remove-OwnedTree $install $programFiles $installLeaf
    Remove-OwnedTree $capsule $temporary $capsuleLeaf
    $complete=$true
} catch {$failureType=$_.Exception.GetType().FullName;$failureSourceLine=$_.InvocationInfo.ScriptLineNumber;if($null -ne $script:assertionFailureLine){$failureSourceLine=$script:assertionFailureLine}}
$eventDiagnostics=New-InstallerFirewallEventDiagnostic
if(-not $complete){$eventDiagnostics=Read-FirewallEventDiagnostic}
$originDiagnostics=[ordered]@{schemaVersion=1;source='captured-rule-properties';maxRecords=16;maxPropertyBytes=4096;records=@($script:firewallOriginObservations);truncated=$script:firewallOriginTruncated;unavailable=$script:firewallOriginUnavailable;extraNativeQueriesPerformed=$false;processOriginEstablished=$false}
$record=[ordered]@{schemaVersion=26;setupCompletionRefusal=$completionRefusal;setupCompletionReadbackVerified=$complete;installationPathRefusals=$pathRefusal;pendingMarkerAccess=$pendingMarkerAccess;architectureRefusal=$architectureRefusal;managedDetectionCases=$script:detectionCases;managedDetectionSourceSHA256=(Digest $detector);eventDiagnosticsSourceSHA256=(Digest (Join-Path $PSScriptRoot 'windows-installer-event-state.ps1'));firewallEventDiagnostics=$eventDiagnostics;nativeDiagnosticsSourceSHA256=(Digest (Join-Path $PSScriptRoot 'windows-installer-native-state.ps1'));lastNativeAttempt=$script:lastNativeAttempt;firewallOriginDiagnostics=$originDiagnostics;sourceCommit=$source;sourceRef=$sourceRef;runID=$run;target=('windows/'+$Architecture);compilerVersion='6.7.1';stateObservations=$script:stateObservations;stateDiagnosticsSourceSHA256=(Digest (Join-Path $PSScriptRoot 'windows-installer-state.ps1'));builds=$builds;operations=$observations;lifecycleLockCases=$lifecycleLockCases;lifecycleLockFixtureSHA256=$lifecycleLockFixtureSHA256;productLockSHA256=$productLockSHA256;versionPolicyCases=$versionPolicyCases;registryReadCases=$registryReadCases;registryReadBufferBytes=514;restorationCases=$restorationCases;restorationLaunchCases=$restorationLaunchCases;restoreLaunchFixtureSHA256=$restoreLaunchFixtureSHA256;restorationOwnerCases=$restorationOwnerCases;restorationOwnerTerminationTested=$complete;restoreOwnerFixtureSHA256=$restoreOwnerFixtureSHA256;productRestoreSHA256=$productRestoreSHA256;restoreFixtureSourceSHA256=$restoreFixtureSourceSHA256;restoreFixtureBinarySHA256=$restoreFixtureBinarySHA256;restoreContractSourceSHA256=$restoreContractSourceSHA256;restoreContractBinarySHA256=$restoreContractBinarySHA256;registryViewCases=$registryViewCases;registryAccessCases=$registryAccessCases;registryFixtureSHA256=$registryFixtureSHA256;productRegistrySHA256=$productRegistrySHA256;versionContractCases=$versionContractCases;versionFixtureSHA256=$versionFixtureSHA256;passed=$complete;stage=$stage;failureType=$failureType;failureSourceLine=$failureSourceLine;assertionFailure=$script:assertionFailure;lastNative=$script:lastNative;actualUserProfilePreservationVerified=$complete;childEnvironmentSanitized=$true;selectedServiceFirewallDNSStateUnchanged=$complete;ownedFixturesRemoved=$complete;unsigned=$true;publisherSignatureVerified=$false;rebootTested=$false;downgradeTested=$complete;crashOrPowerLossTested=$false;vendorDriverOrRoutingQualified=$false;productionQualificationComplete=$false}
$record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding utf8
if(-not $complete){throw ('Disposable installer acceptance failed at '+$stage+' ('+$failureType+'); owned fixture retained on the disposable runner')}
Write-Output 'Actual clean install, upgrade, reinstall, refused downgrade, refused restoration/uninstall and successful recovery-aware uninstall passed; public scoped evidence retained.'
