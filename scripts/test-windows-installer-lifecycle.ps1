# Actual driver-free installer acceptance, exclusively on disposable hosted Windows.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture,[switch]$ProtectedRegistrationPublication)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:OS -ne 'Windows_NT' -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:ACCESSWEAVER_DISPOSABLE_INSTALLER_ACCEPTANCE -cne '1' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver'){throw 'Installer execution requires explicit disposable hosted Windows opt-in'}
if($ProtectedRegistrationPublication -and $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch'){throw 'Protected registration acceptance requires manual disposable dispatch'}
$source=$env:GITHUB_SHA;$sourceRef=$env:GITHUB_REF;$run=$env:GITHUB_RUN_ID;$runAttempt=$env:GITHUB_RUN_ATTEMPT
if($source -cnotmatch '^[a-f0-9]{40}$' -or $sourceRef -cnotmatch '^refs/heads/[A-Za-z0-9_./-]+$' -or $run -notmatch '^[0-9]+$' -or $runAttempt -cnotmatch '\A[1-9][0-9]{0,19}\z'){throw 'Missing source-bound hosted context'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$script:installerAdministratorSID=$null
try {
    $admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($admin){try {$script:installerAdministratorSID=$identity.User.Value} catch {}}
} finally {$identity.Dispose()}
if(-not $admin){throw 'Disposable installer acceptance requires an already elevated hosted token'}
if([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant() -cne @{amd64='x64';arm64='arm64'}[$Architecture]){throw 'Installer acceptance requires a matching native host'}
$project=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if((git -C $project rev-parse HEAD).Trim() -cne $source -or $LASTEXITCODE -ne 0 -or (git -C $project status --porcelain --untracked-files=no)){throw 'Expected a clean exact-source checkout'}
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-native-state.ps1')
$script:uninstallBindingFailureCode=$null
. (Join-Path $PSScriptRoot 'windows-installer-event-state.ps1')
$tokens=$null;$issues=$null
$workflow=Join-Path $project 'internal\workflow\windows.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($workflow,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Product workflow parse failed'}
foreach($name in @('No-Reparse','Quote-Arg','Native-Argument','New-ToolCapture','Receive-ToolCapture','Wait-ToolCapture','Stop-ToolTreeWithHelper','Stop-ToolTree','Run-Tool','Native','Get-DriverServiceControllers','Get-ServiceInspection','Under','Get-PEMachine',
        'Read-WorkflowUninstallRegistration','Get-WorkflowUninstallPath','Assert-WorkflowUninstallACL','Assert-WorkflowUninstallProtection','Initialize-AccessWeaverInstallerRecoveryRegistry','Get-AccessWeaverInstallerRecoveryState','Assert-NoPendingWorkflowInstallation','Assert-NoAccessWeaverSetup','Open-WorkflowUninstallBinding','Close-WorkflowUninstallBinding')){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Expected one fixed product process/inspection helper'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}

# Pass-through test instrumentation. Every protected operation still calls its
# original controller function; diagnostic errors never replace its outcome.
$script:installerOriginalACL=(Get-Command Assert-WorkflowUninstallACL).ScriptBlock
$script:installerOriginalProtection=(Get-Command Assert-WorkflowUninstallProtection).ScriptBlock
$script:installerProtectionRole='unknown'
$script:installerProtectionDiagnostic=$null
$script:installerProtectionDiagnosticStage=$null
function Assert-WorkflowUninstallACL($Acl,[int]$WriteRights) {
    try {& $script:installerOriginalACL $Acl $WriteRights}
    catch {
        if($null -eq $script:installerProtectionDiagnostic -or $script:installerProtectionDiagnosticStage -cne $stage){
            try {
                $script:installerProtectionDiagnostic=Get-InstallerACLFailureDiagnostic $Acl $WriteRights $script:installerProtectionRole $_.Exception.Message $script:installerAdministratorSID
                $script:installerProtectionDiagnosticStage=$stage
            } catch {}
        }
        throw
    }
}
function Assert-WorkflowUninstallProtection([string]$Path) {
    $previousRole=$script:installerProtectionRole
    try {
        $script:installerProtectionRole='unknown'
        try {$script:installerProtectionRole=Get-InstallerProtectionPathRole $Path $install $programFiles} catch {}
        & $script:installerOriginalProtection $Path
    } finally {$script:installerProtectionRole=$previousRole}
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
$script:preservedProfiles=[Collections.Generic.List[hashtable]]::new();$script:restoreFixtureConfiguration=$null
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
        $r=Invoke-Isolated $binary $arguments ((0..255)+@(3010,1641)+$codes) $Timeout
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
    foreach($fixtureProfile in $script:preservedProfiles){
        Require ((Digest $fixtureProfile.path) -ceq $fixtureProfile.sha256) 'An installer operation changed an actual saved AccessWeaver profile'
    }
}
function Assert-ProfileReadback([string]$Binary,$Expected) {
    $verified=Native-Record $Binary @('show',$Expected.id)
    $actual=$verified.result.stdout | ConvertFrom-Json
    Require ($actual.id -ceq $Expected.id -and $actual.name -ceq $Expected.name) 'Installed core did not round-trip the actual user profile'
}
function Create-UserProfile([string]$ID='installer-preserve',[string]$Name='Preserved installer acceptance profile') {
    $binary=Join-Path $install 'accessweaver.exe'
    $template=Native-Record $binary @('show','discord-proxy')
    $data=$template.result.stdout | ConvertFrom-Json
    $data.id=$ID;$data.name=$Name
    $inputPath=Join-Path $capsule ($ID+'-input.json')
    [IO.File]::WriteAllText($inputPath,($data | ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))
    $null=Native-Record $binary @('import',$inputPath)
    $savedPath=Join-Path $profile ('roaming\AccessWeaver\profiles\'+$ID+'.json')
    $record=@{id=$ID;name=$Name;path=$savedPath;sha256=(Digest $savedPath)}
    Assert-ProfileReadback $binary $record
    $script:preservedProfiles.Add($record)
}
function Assert-ManagedDetection([string]$Phase,$Expected,[bool]$Detected,[string]$DigestOverride='', [switch]$UseRegisteredDirectory,[switch]$InspectionRefused){
    $hash=$Expected.payloadSha256
    if($DigestOverride){$hash=$DigestOverride}
    $uninstallerDigest=''
    if($Detected){$uninstallerDigest=Digest (Join-Path $install 'unins000.exe')}
    $location=if($UseRegisteredDirectory){@{UseRegisteredDirectory=$true}}else{@{InstallDirectory=$install}}
    $output=@(& $detector -Version $Expected.version -Architecture $Architecture -PayloadSHA256 $hash -PayloadSBOMSHA256 $Expected.payloadSBOMSHA256 -BuildInfoSHA256 $Expected.identityFileSHA256 -UninstallerSHA256 $uninstallerDigest @location 2>&1)
    if($InspectionRefused){
        Require (-not $Detected -and $LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection did not refuse the invalid installation'
        $script:detectionCases+=,@{phase=$Phase;detected=$false;inspectionRefused=$true}
        return
    }
    Require ($LASTEXITCODE -eq 0) 'Managed detection reported an inspection error'
    if($Detected){
        Require ($output.Count -eq 1 -and $output[0] -ceq 'AccessWeaver detected') 'Managed detection missed the approved payload'
    } else {
        Require ($output.Count -eq 0) 'Managed detection accepted an absent or unapproved payload'
    }
    $script:detectionCases+=,@{phase=$Phase;detected=$Detected}
}
function Assert-DetectorRefusal([string]$Phase,[switch]$VerifyMatchingPendingStatus,[switch]$UseRegisteredDirectory){
    $expected=$builds[1]
    $arguments=@{Version=$expected.version;Architecture=$Architecture;PayloadSHA256=$expected.payloadSha256}
    if($UseRegisteredDirectory){$arguments.UseRegisteredDirectory=$true}
    else{$arguments.InstallDirectory=$install}
    $observation=@{phase=$Phase;detected=$false;inspectionRefused=$true}
    $previous=$env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY
    try {
        $env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY=$null
        $output=@(& $detector @arguments 2>&1)
        Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection reported a result during a lifecycle inspection refusal'
        if($VerifyMatchingPendingStatus){
            $env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY='1'
            $fingerprint=$expected.stagedPayloadSHA256
            if(-not $fingerprint){
                $sidecar=Join-Path $project ('build\'+$expected.installerName+'.cdx.json')
                $sbom=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($sidecar))
                $property=@($sbom.metadata.component.properties | Where-Object name -CEQ 'accessweaver:windows-staged-payload-sha256')
                Require ($property.Count -eq 1) 'Installer SBOM has no unique compiled payload fingerprint'
                $fingerprint=$property[0].value
            }
            Require ($fingerprint -cmatch '\A[a-f0-9]{64}\z') 'Installer has no verified compiled payload fingerprint'
            $material=$baselineArgument.Substring('/AWUpgradeFrom='.Length)+'|'+$Architecture+'|'+$fingerprint
            $sha=[Security.Cryptography.SHA256]::Create()
            try {$pin=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($material)))).Replace('-','').ToLowerInvariant()}
            finally {$sha.Dispose()}
            $output=@(& $detector @arguments -PendingApprovalSHA256 $pin 2>&1)
            Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 1 -and $output[0] -ceq 'AccessWeaver managed upgrade pending') 'Managed detection did not report the matching pending upgrade'
            $otherPin=if($pin[0] -ceq '0'){'1'+$pin.Substring(1)}else{'0'+$pin.Substring(1)}
            $output=@(& $detector @arguments -PendingApprovalSHA256 $otherPin 2>&1)
            Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 1 -and $output[0] -ceq 'AccessWeaver installation pending') 'Managed detection accepted a different approval digest'
            $observation.matchingPendingStatusReported=$true
        }
    } finally {$env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY=$previous}
    $script:detectionCases+=,$observation
}
function Assert-Installed($expected){
    $binary=Join-Path $install 'accessweaver.exe';No-Reparse $binary
    Require ((Digest $binary) -ceq $expected.payloadSha256) 'Installed payload differs from the compiled payload'
    $runtime=Native-Record $binary @('version','--json')
    $actual=$runtime.result.stdout | ConvertFrom-Json
    $build=$expected.payloadBuild
    Assert-InstallerPayloadIdentity $binary $actual @{version=$build.version;commit=$source;sourceState='clean';builtAt=$build.builtAt;goVersion=$build.goVersion;platform='windows';arch=$Architecture}
    Require ((Digest (Join-Path $install 'BUILD-INFO.json')) -ceq $expected.identityFileSHA256) 'Installed build metadata differs from its compiled identity'
    $runtimeNotice=Join-Path $install 'licenses\Inno-Setup-License.txt'
    No-Reparse $runtimeNotice
    Require ((Digest $runtimeNotice) -ceq $expected.innoRuntimeNoticeSHA256) 'Installed Inno Setup runtime notice differs from the compiled notice'
    $registered=Registration
    Require ($null -ne $registered -and $registered.version -ceq $build.version -and $registered.location.TrimEnd('\') -ieq $install) 'Native uninstall registration differs from the installed target'
    foreach($path in $groupPaths){Require (-not (Test-Path -LiteralPath $path)) 'Silent no-icons installation created a start-menu folder'}
    Assert-UserState
}
function Assert-InstallerRemoved([string]$Uninstaller) {
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    do {
        $owned=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.ExecutablePath -and ($_.ExecutablePath.StartsWith($install+'\',[StringComparison]::OrdinalIgnoreCase) -or
            $_.ExecutablePath.StartsWith($privateTemp+'\',[StringComparison]::OrdinalIgnoreCase))
        })
        if(-not $owned.Count -and -not (Test-Path -LiteralPath $Uninstaller)){break}
        Start-Sleep -Milliseconds 200
    } while([DateTime]::UtcNow -lt $deadline)
    Require (-not $owned.Count -and -not (Test-Path -LiteralPath $Uninstaller) -and
        -not (Test-Path -LiteralPath (Join-Path $install 'accessweaver.exe'))) 'Uninstall did not remove owned files or finish its clone'
    Assert-LifecycleRegistrationAbsent 'Uninstall left product registration'
    Require ($null -eq (Get-PendingInstallFixtureValue)) 'Uninstall left a pending installation'
    Assert-UserState
    Require ((Digest $marker) -ceq $markerHash) 'Uninstall changed unrelated state'
    Require (@(Get-ChildItem -LiteralPath $install -File -Recurse -Force).Count -eq 1) 'Uninstall left unexpected payload files'
    foreach($path in $groupPaths){Require (-not (Test-Path -LiteralPath $path)) 'Uninstall left a fixture start-menu folder'}
}
function Assert-SuccessfulRestorationJournal([string]$Path) {
    No-Reparse $Path
    $item=Get-Item -LiteralPath $Path -ErrorAction Stop
    Require (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le 4MB) 'Restoration journal is unavailable or exceeds its bound'
    $journal=[IO.File]::ReadAllText($Path) | ConvertFrom-Json
    Require ($journal.action -ceq 'remove-all' -and $journal.state -ceq 'succeeded') 'Recovery-aware uninstall did not record successful machine restoration'
}
$detector=Join-Path $PSScriptRoot 'detect-windows-installer.ps1'
$script:detectionCases=@()
if($ProtectedRegistrationPublication){
    . (Join-Path $PSScriptRoot 'test-windows-installer-protected-publication.ps1')
    Invoke-ProtectedRegistrationAcceptance
    return
}
$reportDirectory=Join-Path $project 'build\installer-lifecycle-checks';[void][IO.Directory]::CreateDirectory($reportDirectory)
$reportPath=Join-Path $reportDirectory ($Architecture+'.json')
$script:firewallEventWindowStartUtc=[datetime]::MinValue;
$script:stateObservations=@();$script:stateBaseline=$null;$script:statePrevious=$null;$script:assertionFailureLine=$null
$script:stateFirewallRules=@();$script:statePreviousFirewallRules=@();$script:firewallOriginObservations=@();$script:firewallOriginTruncated=$false;$script:firewallOriginUnavailable=$false
$pathRefusal=@()
$uninstallLicenseRefusal=$null
$controllerDocumentationRefusals=@()
$nativeDocumentationRefusals=@()
$completionRefusal=$null
$documentationCompletionRefusal=$null
$setupRetirementFlush=$null
$setupUninstallRegistrationRefusal=$null
$setupUpgradeBaseline=$null
$stage='compile';$failureType=$null;$script:assertionFailure=$null;$script:lastNative=$null;$script:lastNativeAttempt=$null;$complete=$false;$builds=@();$observations=@();$architectureRefusal=$null;$pendingMarkerAccess=$null;$lateCompatibilityRefusal=$null;$versionPolicyCases=@();$versionContractCases=0;$versionFixtureSHA256=$null;$lifecycleLockCases=@();$lifecycleLockFixtureSHA256=$null;$productLockSHA256=$null;$registryReadCases=@();$registryViewCases=@();$registryAccessCases=@();$failureSourceLine=$null;$registryFixtureSHA256=$null;$productRegistrySHA256=$null;$restorationCases=@();$postRestorationRefusal=$null;$setupMarkerReplacement=$null;$productRestoreSHA256=$null;$restoreFixtureSourceSHA256=$null;$restoreFixtureBinarySHA256=$null;$restoreContractSourceSHA256=$null;$restoreContractBinarySHA256=$null;$restorationOwnerCases=@();$restoreOwnerFixtureSHA256=$null;$restorationLaunchCases=@();$restoreLaunchFixtureSHA256=$null
try {
    $buildDirectory=Join-Path $project 'build'
    $stagePattern='installer-'+$Architecture+'-*'
    foreach($version in @('0.1.0-alpha','0.1.1-alpha')){
        $previousStages=@([IO.Directory]::EnumerateDirectories($buildDirectory,$stagePattern))
        $null=@(& (Join-Path $PSScriptRoot 'test-windows-installer.ps1') -ExpectedCompilerVersion '6.7.1' -TargetArch $Architecture -Version $version)
        $newStages=@([IO.Directory]::EnumerateDirectories($buildDirectory,$stagePattern) | Where-Object {$_ -cnotin $previousStages})
        Require ($newStages.Count -eq 1) 'Expected one staged payload for this installer build'
        $candidateStage=$newStages[0]
        $evidence=Join-Path $project ('build\installer-checks\'+$Architecture)
        $b=Get-Content -LiteralPath (Join-Path $evidence 'compiler-artifact.json') -Raw | ConvertFrom-Json
        Require ($b.sourceCommit -ceq $source -and $b.payloadBuild.sourceState -ceq 'clean' -and $b.payloadBuild.version -ceq $version -and $b.compilerVersion -ceq '6.7.1' -and $b.unsigned) 'Compiler evidence differs from the requested candidate'
        $notice=Join-Path $evidence 'licenses\Inno-Setup-License.txt'
        No-Reparse $notice
        $builds+=,@{version=$version;innoRuntimeNoticeSHA256=(Digest $notice);installerName=$b.installerName;installerSHA256=$b.installerSha256;installerBytes=$b.installerBytes;payloadSha256=$b.payloadSha256;payloadSBOMSHA256=(Digest (Join-Path $evidence 'payload-SBOM.cdx.json'));payloadBuild=$b.payloadBuild;compilerSHA256=$b.compilerSha256;preprocessedSetupSHA256=$b.preprocessedSetupSha256;identityFileSHA256=(Digest (Join-Path $evidence 'payload-BUILD-INFO.json'))}
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
    $nestedDestination=Join-Path $capsule 'nested-installation'
    $docsDestination=Join-Path $capsule 'nested-docs-installation'
    [void][IO.Directory]::CreateDirectory((Join-Path $docsDestination 'docs'))
    [void][IO.Directory]::CreateDirectory($nestedDestination)
    $packagedAliases=@(Join-Path $nestedDestination 'licenses';Join-Path $nestedDestination 'docs';
        Join-Path $docsDestination 'docs\assets';Join-Path $docsDestination 'docs\qualification')
    [void](New-Item -ItemType Junction -Path $junction -Target $physical -ErrorAction Stop)
    try {
        Require ((Get-Item -LiteralPath $junction -Force -ErrorAction Stop).LinkType -ceq 'Junction') 'Installation path fixture requires a junction'
        foreach($kind in @('leaf-junction','ancestor-junction','licenses-junction','docs-junction','docs-assets-junction','docs-qualification-junction')){
            $packagedAlias=switch($kind){
                'licenses-junction' {$packagedAliases[0]}
                'docs-junction' {$packagedAliases[1]}
                'docs-assets-junction' {$packagedAliases[2]}
                'docs-qualification-junction' {$packagedAliases[3]}
            }
            if($packagedAlias){[void](New-Item -ItemType Junction -Path $packagedAlias -Target $physical -ErrorAction Stop)}
            $destination=switch($kind){
                'leaf-junction' {$junction}
                'ancestor-junction' {Join-Path $junction 'missing-installation'}
                'licenses-junction' {$nestedDestination}
                'docs-junction' {$nestedDestination}
                default {$docsDestination}
            }
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
            if($packagedAlias){
                Require ([IO.Directory]::GetFileSystemEntries($destination).Length -eq 1 -and
                    [IO.Directory]::GetFileSystemEntries((Split-Path -Parent $packagedAlias)).Length -eq 1 -and
                    (Get-Item -LiteralPath $packagedAlias -Force -ErrorAction Stop).LinkType -ceq 'Junction') 'Refused Setup changed the nested installation destination'
                [IO.Directory]::Delete($packagedAlias,$false)
            }
            $pathRefusal+=,@{kind=$kind;exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;
                preflightRefusalLogged=$true;targetPreserved=$true;pendingMarkerAbsent=$true;registrationsAbsent=$true;machineStateUnchanged=$true}
        }
    } finally {
        foreach($alias in @($junction)+$packagedAliases){
            $item=Get-Item -LiteralPath $alias -Force -ErrorAction SilentlyContinue
            if($null -eq $item){continue}
            Require ($item.LinkType -ceq 'Junction' -and $item.FullName -ieq $alias) 'Owned junction identity changed before cleanup'
            [IO.Directory]::Delete($alias,$false)
        }
        [IO.Directory]::Delete($nestedDestination,$false)
        [IO.Directory]::Delete((Join-Path $docsDestination 'docs'),$false)
        [IO.Directory]::Delete($docsDestination,$false)
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
    $stage='managed-detection-license-readback'
    $notice=Join-Path $install 'licenses\Go-runtime-LICENSE'
    No-Reparse $notice
    Require ((Get-Item -LiteralPath $notice).Length -gt 0 -and (Get-Item -LiteralPath $notice).Length -le 1MB) 'Expected an installed bounded Go runtime notice'
    $originalNotice=[IO.File]::ReadAllBytes($notice)
    try {
        [IO.File]::WriteAllText($notice,'inert tampered notice')
        Assert-ManagedDetection 'changed-notice' $builds[0] $false
        [IO.File]::Delete($notice)
        Assert-ManagedDetection 'missing-notice-refused' $builds[0] $false -InspectionRefused
    } finally {[IO.File]::WriteAllBytes($notice,$originalNotice)}
    Assert-ManagedDetection 'after-notice-restoration' $builds[0] $true
    $null=State-Checkpoint 'after-install'
    $stage='setup-completion-refusal'
    $faultSource=Join-Path $capsule 'setup-completion-source'
    $faultPayload=Join-Path $capsule 'setup-completion-payload'
    foreach($folder in @($faultSource,$faultPayload)){[void][IO.Directory]::CreateDirectory($folder)}
    $productSetup=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer.iss'))
    # Fault variants keep the genuine Setup mode and its source-owned includes.
    $fixtureIncludes=[regex]::Matches($productSetup,'(?m)^[ 	]*#include[ 	]+"([^"\r\n]+)"')
    Require ($fixtureIncludes.Count -gt 0) 'Expected local installer source includes'
    foreach($include in $fixtureIncludes){
        $name=$include.Groups[1].Value
        Require ($name -cmatch '\Awindows-installer-[a-z-]+\.iss\z') 'Unexpected installer include name'
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $faultSource -ErrorAction Stop
    }
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

    $uninstallInjectionPoint='    AWInstallFinished := True;'
    Require ([regex]::Matches($productSetup,[regex]::Escape($uninstallInjectionPoint)).Count -eq 1) 'Expected one Setup completion fault boundary'
    $registerFault=@'
    if not RegWriteStringValue(HKLM64,
      'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1',
      'QuietUninstallString', '"' + ExpandConstant('{uninstallexe}') + '" /VERYSILENT') then
      RaiseException('Could not modify the owned quiet uninstall fixture.');
'@
    $genuinePayload=Join-Path $capsule 'setup-completion-verified-payload'
    [void][IO.Directory]::CreateDirectory($genuinePayload)
    foreach($file in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
        Copy-Item -LiteralPath (Join-Path $install $file) -Destination $genuinePayload -ErrorAction Stop
    }
    Copy-Item -LiteralPath (Join-Path $project 'LICENSE') -Destination $genuinePayload -ErrorAction Stop
    $genuineNotices=Join-Path $genuinePayload 'licenses'
    [void][IO.Directory]::CreateDirectory($genuineNotices)
    Copy-Item -LiteralPath (Join-Path $install 'licenses\Inno-Setup-License.txt') -Destination $genuineNotices -ErrorAction Stop
    $stage='setup-documentation-completion-refusal'
    $genuineDocs=Join-Path $genuinePayload 'docs'
    [void][IO.Directory]::CreateDirectory($genuineDocs)
    $installedDocument=Join-Path $install 'docs\WINDOWS_WORKFLOWS.md'
    $originalDocumentDigest=Digest $installedDocument
    $originalDocumentLength=(Get-Item -LiteralPath $installedDocument -ErrorAction Stop).Length
    Copy-Item -LiteralPath $installedDocument -Destination $genuineDocs -ErrorAction Stop
    $documentationFault=@"
procedure AWAlterFixtureDocumentation;
var Path: String; Content: AnsiString;
begin
  Path := ExpandConstant('{app}\docs\WINDOWS_WORKFLOWS.md');
  if not LoadStringFromFile(Path, Content) or (Length(Content) = 0) then
    RaiseException('The copied documentation fixture is unavailable.');
  if Content[1] = 'A' then Content[1] := 'B'
  else Content[1] := 'A';
  if not SaveStringToFile(Path, Content, False) then
    RaiseException('The copied documentation fixture could not be changed.');
  Log('AccessWeaver post-copy documentation fault injected.');
end;

"@
    $stepPoint='procedure CurStepChanged(CurStep: TSetupStep);'
    Require ([regex]::Matches($productSetup,[regex]::Escape($stepPoint)).Count -eq 1) 'Expected one Setup step boundary'
    $fixture=$productSetup.Replace($stepPoint,$documentationFault+$stepPoint).Replace($uninstallInjectionPoint,
        $uninstallInjectionPoint+[Environment]::NewLine+'    AWAlterFixtureDocumentation;')
    [IO.File]::WriteAllText($faultSetup,$fixture)
    $null=@(& $compiler ('/DBuildRoot='+$genuinePayload) ('/DReleaseVersion='+$builds[0].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Post-copy documentation fault fixture compilation failed'
    $documentationLog=Join-Path $capsule 'setup-documentation-completion-refusal.log'
    $refused=Native-Record $faultInstaller ($arguments+@('/LOG='+$documentationLog)) @(1603)
    No-Reparse $documentationLog
    $logSize=(Get-Item -LiteralPath $documentationLog -ErrorAction Stop).Length
    Require ($logSize -gt 0 -and $logSize -le 4MB) 'Documentation completion refusal log is unavailable or exceeds its bound'
    $log=[IO.File]::ReadAllText($documentationLog)
    Require ($log.Contains('AccessWeaver post-copy documentation fault injected.') -and
        $log.Contains('AccessWeaver installed payload or registration verification failed. Pending installation record retained.') -and
        -not $log.Contains('Pending installation record retired.')) 'Setup did not refuse the changed documentation at completion'
    Require ((Get-PendingInstallFixtureValue) -ceq ($builds[0].version+'|'+$install)) 'Setup did not retain the pending record for changed documentation'
    Require ((Get-Item -LiteralPath $installedDocument -ErrorAction Stop).Length -eq $originalDocumentLength -and
        (Digest $installedDocument) -cne $originalDocumentDigest -and
        (Digest (Join-Path $install 'accessweaver.exe')) -ceq $builds[0].payloadSha256) 'Documentation fault did not isolate a same-size change'
    $detectorOutput=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -InstallDirectory $install 2>&1)
    Require ($LASTEXITCODE -eq 1 -and $detectorOutput.Count -eq 0) 'Managed detection accepted an installation with changed documentation and a pending marker'
    Require ((State-Snapshot) -ceq $before -and (Digest $marker) -ceq $markerHash) 'Documentation failure changed unrelated machine state'
    Assert-UserState
    $documentationCompletionRefusal=[ordered]@{
        fixtureSHA256=(Digest $faultInstaller);exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;
        refusalLogged=$true;installedFixtureVerified=$true;pendingMarkerRetained=$true;managedDetectionRefused=$true;machineStateUnchanged=$true;
        profilePreserved=$true;unrelatedFilePreserved=$true;genuineRetryVerified=$false;sameSizeDocumentationChangeVerified=$true;
        documentationRestored=$false
    }
    $stage='setup-documentation-completion-retry'
    $documentationRetryLog=Join-Path $capsule 'setup-documentation-completion-retry.log'
    $null=Native-Record $first ($arguments+@('/LOG='+$documentationRetryLog))
    Assert-SetupCompletionReadback $documentationRetryLog
    Assert-Installed $builds[0]
    Require ((Digest $installedDocument) -ceq $originalDocumentDigest -and $null -eq (Get-PendingInstallFixtureValue)) 'Genuine Setup did not restore documentation and retire the pending record'
    $documentationCompletionRefusal.genuineRetryVerified=$true
    $documentationCompletionRefusal.documentationRestored=$true

    $stage='setup-uninstall-registration-refusal'
    $uninstaller=Join-Path $install 'unins000.exe'
    $quietValue='QuietUninstallString'
    $originalQuiet='"'+$uninstaller+'" /SILENT'
    $expectedQuiet='"'+$uninstaller+'" /VERYSILENT'
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($uninstallKey,$false)
        Require ($null -ne $key -and $key.GetValueKind($quietValue) -eq [Microsoft.Win32.RegistryValueKind]::String -and
            $key.GetValue($quietValue) -ceq $originalQuiet) 'Expected the verified original quiet uninstall command'
        $originalRegistration=Registration-Fingerprint $key
    } finally {if($key){$key.Dispose()};$base.Dispose()}
    [IO.File]::WriteAllText($faultSetup,$productSetup.Replace($uninstallInjectionPoint,
        $uninstallInjectionPoint+[Environment]::NewLine+$registerFault))
    $null=@(& $compiler ('/DBuildRoot='+$genuinePayload) ('/DReleaseVersion='+$builds[0].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Uninstall registration fault fixture compilation failed'
    $registrationLog=Join-Path $capsule 'setup-uninstall-registration-refusal.log'
    $refused=Native-Record $faultInstaller ($arguments+@('/LOG='+$registrationLog)) @(1603)
    No-Reparse $registrationLog
    $logBytes=(Get-Item -LiteralPath $registrationLog -ErrorAction Stop).Length
    Require ($logBytes -gt 0 -and $logBytes -le 4MB) 'Uninstall registration fault log exceeded its limits'
    $log=[IO.File]::ReadAllText($registrationLog)
    Require ($log.Contains('AccessWeaver installed payload or registration verification failed. Pending installation record retained.') -and
        -not $log.Contains('Pending installation record retired.')) 'Setup did not refuse the changed uninstall command'
    $registrationPending=Get-PendingInstallFixtureValue
    Require ($registrationPending -ceq ($builds[0].version+'|'+$install)) 'Uninstall registration refusal lost its pending record'
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($uninstallKey,$false)
        Require ($null -ne $key -and $key.GetValue('UninstallString') -ceq ('"'+$uninstaller+'"') -and
            $key.GetValueKind($quietValue) -eq [Microsoft.Win32.RegistryValueKind]::String -and
            $key.GetValue($quietValue) -ceq $expectedQuiet) 'Setup did not retain the controlled command change'
        $alteredRegistration=Registration-Fingerprint $key
    } finally {if($key){$key.Dispose()};$base.Dispose()}
    Assert-Installed $builds[0]
    $detectorOutput=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -InstallDirectory $install 2>&1)
    Require ($LASTEXITCODE -eq 1 -and $detectorOutput.Count -eq 0) 'Managed detection accepted the incomplete setup'
    Require ((State-Snapshot) -ceq $before -and (Digest $marker) -ceq $markerHash) 'Changed uninstall registration affected unrelated machine state'
    Assert-UserState
    $setupUninstallRegistrationRefusal=[ordered]@{
        fixtureSHA256=(Digest $faultInstaller);exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;
        refusalLogged=$true;changedCommandPreserved=$true;installedPayloadVerified=$true;pendingMarkerRetained=$true;
        managedDetectionRefused=$true;unrelatedStatePreserved=$true;genuineRetryVerified=$false
    }
    $stage='setup-uninstall-registration-altered-retry'
    $alteredTree=Installed-TreeFingerprint
    $alteredRetryLog=Join-Path $capsule 'setup-uninstall-registration-altered-retry.log'
    $null=Native-Record $first ($arguments+@('/LOG='+$alteredRetryLog)) @(3)
    No-Reparse $alteredRetryLog
    $retryLogSize=(Get-Item -LiteralPath $alteredRetryLog -ErrorAction Stop).Length
    Require ($retryLogSize -gt 0 -and $retryLogSize -le 4MB) 'Protected registration retry log is unavailable or exceeds its bound'
    Require ([IO.File]::ReadAllText($alteredRetryLog).Contains('AccessWeaver protected registration or legacy approval refused.')) 'Expected Setup to refuse the changed protected registration'
    Require ((Registration-Fingerprint) -ceq $alteredRegistration -and (Installed-TreeFingerprint) -ceq $alteredTree -and
        (Get-PendingInstallFixtureValue) -ceq $registrationPending -and (State-Snapshot) -ceq $before) 'Refused Setup retry changed the fixture state'
    Assert-UserState

    # The fixture owns the deliberate edit. Restore its verified original value
    # only while the altered registration and pending record still match.
    $stage='setup-uninstall-registration-fixture-restore'
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($uninstallKey,$true)
        Require ($null -ne $key -and (Registration-Fingerprint $key) -ceq $alteredRegistration -and
            (Get-PendingInstallFixtureValue) -ceq $registrationPending) 'The controlled registration changed before fixture restoration'
        $key.SetValue($quietValue,$originalQuiet,[Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
        Require ((Registration-Fingerprint $key) -ceq $originalRegistration) 'Fixture did not restore the original registration'
    } finally {if($key){$key.Dispose()};$base.Dispose()}

    $stage='setup-uninstall-registration-retry'
    $completionLog=Join-Path $capsule 'setup-uninstall-registration-retry.log'
    $null=Native-Record $first ($arguments+@('/LOG='+$completionLog))
    Assert-SetupCompletionReadback $completionLog
    Assert-Installed $builds[0]
    Require ($null -eq (Get-PendingInstallFixtureValue)) 'Genuine Setup retry retained an incomplete registration marker'
    $retryDetection=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -UninstallerSHA256 (Digest $uninstaller) -InstallDirectory $install 2>&1)
    Require ($LASTEXITCODE -eq 0 -and $retryDetection.Count -eq 1 -and $retryDetection[0] -ceq 'AccessWeaver detected') 'Genuine Setup retry did not restore managed detection'
    Require ((State-Snapshot) -ceq $before -and (Digest $marker) -ceq $markerHash) 'Setup registration retry affected unrelated machine state'
    Assert-UserState
    $setupUninstallRegistrationRefusal.genuineRetryVerified=$true

    $stage='setup-missing-uninstall-data'
    $dataRemoval=@'
    if not RenameFile(ChangeFileExt(ExpandConstant('{uninstallexe}'), '.dat'),
      ChangeFileExt(ExpandConstant('{uninstallexe}'), '.aw-fixture-backup')) then
      RaiseException('Cannot move the owned uninstall data fixture.');
'@
    [IO.File]::WriteAllText($faultSetup,$productSetup.Replace($uninstallInjectionPoint,
        $uninstallInjectionPoint+[Environment]::NewLine+$dataRemoval))
    $null=@(& $compiler ('/DBuildRoot='+$genuinePayload) ('/DReleaseVersion='+$builds[0].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Missing uninstall data fixture compilation failed'
    $missingDataLog=Join-Path $capsule 'setup-uninstall-data-refusal.log'
    $uninstallData=Join-Path $install 'unins000.dat'
    $dataBackup=[IO.Path]::ChangeExtension($uninstallData,'.aw-fixture-backup')
    Require (-not (Test-Path -LiteralPath $dataBackup)) 'Unexpected uninstall data fixture backup'
    try {
        $null=Native-Record $faultInstaller ($arguments+@('/LOG='+$missingDataLog)) @(1603)
        No-Reparse $missingDataLog
        $size=(Get-Item -LiteralPath $missingDataLog -ErrorAction Stop).Length
        Require ($size -gt 0 -and $size -le 4MB -and
            [IO.File]::ReadAllText($missingDataLog).Contains('AccessWeaver installed payload or registration verification failed. Pending installation record retained.')) 'Missing uninstall data did not trigger completion refusal'
        Require ((Test-Path -LiteralPath $dataBackup -PathType Leaf) -and -not (Test-Path -LiteralPath $uninstallData) -and
            (Get-PendingInstallFixtureValue) -ceq ($builds[0].version+'|'+$install)) 'Setup did not retain the pending record with missing uninstall data'
    } finally {
        if(Test-Path -LiteralPath $dataBackup -PathType Leaf){
            No-Reparse $dataBackup
            [IO.File]::Move($dataBackup,$uninstallData)
        }
    }
    $dataRetryLog=Join-Path $capsule 'setup-uninstall-data-retry.log'
    $null=Native-Record $first ($arguments+@('/LOG='+$dataRetryLog))
    Assert-SetupCompletionReadback $dataRetryLog
    Assert-Installed $builds[0]
    Require ((Test-Path -LiteralPath $uninstallData -PathType Leaf) -and $null -eq (Get-PendingInstallFixtureValue)) 'Approved Setup retry did not verify uninstall data and retire the marker'
    $uninstallDataRecoveryVerified=$true
    $stage='managed-detection-hard-linked-controller'
    $uninstallerDigest=Digest (Join-Path $install 'unins000.exe')
    $detectedCore=Join-Path $install 'accessweaver.exe'
    $linkedCore=Join-Path $install 'detection-controller-link.exe'
    $null=New-Item -ItemType HardLink -Path $linkedCore -Target $detectedCore -ErrorAction Stop
    try {
        Require ((Digest $linkedCore) -ceq $builds[0].payloadSha256) 'Hard-linked detection fixture does not match the approved bytes'
        $output=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -UninstallerSHA256 $uninstallerDigest -InstallDirectory $install 2>&1)
        Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection accepted a hard-linked controller'
        Require ((Digest $detectedCore) -ceq $builds[0].payloadSha256 -and
            (Digest $linkedCore) -ceq $builds[0].payloadSha256) 'Managed detection altered the hard-linked fixture'
        $script:detectionCases+=,@{phase='hard-linked-controller-refused';detected=$false;inspectionRefused=$true}
    } finally {[IO.File]::Delete($linkedCore)}
    $stage='managed-detection-after-hard-link-removal'
    Assert-ManagedDetection 'after-hard-link-removal' $builds[0] $true -UseRegisteredDirectory

    $stage='managed-detection-redirected-licenses'
    $installedLicenses=Join-Path $install 'licenses'
    # Directory.Move requires the backup on the same volume as the installation.
    # The uniquely owned installation is already checked before fixture mutation.
    $savedLicenses=Join-Path $install 'saved-detection-licenses'
    No-Reparse $savedLicenses
    Require (-not (Test-Path -LiteralPath $savedLicenses -ErrorAction Stop)) 'License directory backup must be new'
    $redirectedLicenses=Join-Path $capsule 'redirected-detection-licenses'
    [void][IO.Directory]::CreateDirectory($redirectedLicenses)
    $witness=Join-Path $redirectedLicenses 'Go-runtime-LICENSE'
    [IO.File]::WriteAllText($witness,'owned license directory witness')
    $witnessHash=Digest $witness
    No-Reparse $installedLicenses
    $treeBefore=Installed-TreeFingerprint
    $registrationBefore=Registration-Fingerprint
    $machineBefore=State-Snapshot
    [IO.Directory]::Move($installedLicenses,$savedLicenses)
    try {
        [void](New-Item -ItemType Junction -Path $installedLicenses -Target $redirectedLicenses -ErrorAction Stop)
        try {
            $output=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -InstallDirectory $install 2>&1)
            Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection accepted a junction at the packaged licenses directory'
            Require ([IO.Directory]::GetFileSystemEntries($redirectedLicenses).Length -eq 1 -and
                (Digest $witness) -ceq $witnessHash) 'Managed detection changed the junction target'
            $script:detectionCases+=,@{phase='redirected-licenses-refused';detected=$false;inspectionRefused=$true}

            $stage='uninstall-redirected-licenses'
            $bindingRefused=$false
            $refusalCode='no-refusal-observed'
            try {
                $binding=Open-WorkflowUninstallBinding $Architecture
                if($binding){Close-WorkflowUninstallBinding $binding}
            } catch {
                $refusalCode=Get-InstallerUninstallBindingRefusalCategory $_.Exception.Message
                $bindingRefused=$refusalCode -ceq 'package-directory-refused'
            }
            if(-not $bindingRefused){$script:uninstallBindingFailureCode=$refusalCode}
            Require $bindingRefused 'Controller uninstall inspection accepted the license junction'
            $logPath=Join-Path $capsule 'uninstall-redirected-licenses.log'
            $attempt=Native-Record $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG='+$logPath)) @(1)
            No-Reparse $logPath
            $logSize=(Get-Item -LiteralPath $logPath -ErrorAction Stop).Length
            Require ($logSize -gt 0 -and $logSize -le 1MB) 'Redirected license refusal log is unavailable or exceeds its bound'
            $log=[IO.File]::ReadAllText($logPath)
            Require ($log.Contains('AccessWeaver requires a local installation directory without junctions or symbolic links.') -and
                -not $log.Contains('AccessWeaver system restoration starts at the uninstall step.')) 'Redirected license directory did not prevent restoration'
            Require ([IO.Directory]::GetFileSystemEntries($redirectedLicenses).Length -eq 1 -and
                (Digest $witness) -ceq $witnessHash) 'Uninstall changed the license junction target'
            Require (-not (Test-Path -LiteralPath $managed -ErrorAction Stop) -and
                (State-Snapshot) -ceq $machineBefore) 'Refused uninstall changed machine state or published a restoration journal'
            Assert-UserState
        } finally {
            $alias=Get-Item -LiteralPath $installedLicenses -Force -ErrorAction Stop
            Require ($alias.LinkType -ceq 'Junction' -and $alias.FullName -ieq $installedLicenses) 'License fixture junction changed before cleanup'
            [IO.Directory]::Delete($installedLicenses,$false)
        }
    } finally {[IO.Directory]::Move($savedLicenses,$installedLicenses)}
    Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Refused uninstall changed installed files or registration'
    $uninstallLicenseRefusal=@{exitCode=$attempt.result.exitCode;elapsedMilliseconds=$attempt.milliseconds;deadlineMilliseconds=180000;
        refusedBeforeRestoration=$true;controllerBindingRefused=$true;targetPreserved=$true;installedFileTreePreserved=$true;registrationPreserved=$true;
        profilePreserved=$true;machineStateUnchanged=$true}
    Assert-ManagedDetection 'after-license-directory-restoration' $builds[0] $true -UseRegisteredDirectory

    $stage='managed-detection-redirected-documentation'
    $savedDocumentation=Join-Path $install 'saved-detection-documentation'
    No-Reparse $savedDocumentation
    Require (-not (Test-Path -LiteralPath $savedDocumentation -ErrorAction Stop)) 'Documentation directory backup must be new'
    $documentationTarget=Join-Path $capsule 'documentation-junction-target'
    [void][IO.Directory]::CreateDirectory($documentationTarget)
    foreach($case in @(
        @{relative='docs';phase='redirected-docs-refused';witness='WINDOWS_WORKFLOWS.md'},
        @{relative='docs\assets';phase='redirected-docs-assets-refused';witness='dashboard.png'},
        @{relative='docs\qualification';phase='redirected-docs-qualification-refused';witness='00082ef0719a-quarantine-diagnostic-failure.json'}
    )){
        $documentation=Join-Path $install $case.relative
        No-Reparse $documentation
        $documentationSource=Join-Path $documentation $case.witness
        No-Reparse $documentationSource
        Require ([IO.File]::Exists($documentationSource)) 'Expected a packaged documentation witness'
        $documentationWitness=Join-Path $documentationTarget $case.witness
        [IO.File]::WriteAllText($documentationWitness,'owned documentation junction target witness')
        $documentationHash=Digest $documentationWitness
        $treeBefore=Installed-TreeFingerprint
        $registrationBefore=Registration-Fingerprint
        $machineBefore=State-Snapshot
        [IO.Directory]::Move($documentation,$savedDocumentation)
        try {
            [void](New-Item -ItemType Junction -Path $documentation -Target $documentationTarget -ErrorAction Stop)
            try {
                $output=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -InstallDirectory $install 2>&1)
                Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection accepted redirected package documentation'
                Require ([IO.Directory]::GetFileSystemEntries($documentationTarget).Length -eq 1 -and
                    (Digest $documentationWitness) -ceq $documentationHash) 'Managed detection changed the documentation junction target'
                $bindingRefused=$false
                $refusalCode='no-refusal-observed'
                try {
                    $binding=Open-WorkflowUninstallBinding $Architecture
                    if($binding){Close-WorkflowUninstallBinding $binding}
                } catch {
                    $refusalCode=Get-InstallerUninstallBindingRefusalCategory $_.Exception.Message
                    $bindingRefused=$refusalCode -ceq 'package-directory-refused'
                }
                if(-not $bindingRefused){$script:uninstallBindingFailureCode=$refusalCode}
                Require $bindingRefused 'Controller uninstall inspection accepted redirected package documentation'
                $controllerDocumentationRefusals+=,$case.phase
                $script:detectionCases+=,@{phase=$case.phase;detected=$false;inspectionRefused=$true}
                $stage='native-uninstall-redirected-documentation'
                $logPath=Join-Path $capsule ($case.phase+'.log')
                $attempt=Native-Record $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG='+$logPath)) @(1)
                No-Reparse $logPath
                $logSize=(Get-Item -LiteralPath $logPath -ErrorAction Stop).Length
                Require ($logSize -gt 0 -and $logSize -le 1MB) 'Documentation refusal log is outside its bound'
                $log=[IO.File]::ReadAllText($logPath)
                Require ($log.Contains('AccessWeaver requires a local installation directory without junctions or symbolic links.') -and
                    -not $log.Contains('AccessWeaver system restoration starts at the uninstall step.')) 'Redirected documentation did not prevent restoration'
                Require ([IO.Directory]::GetFileSystemEntries($documentationTarget).Length -eq 1 -and
                    (Digest $documentationWitness) -ceq $documentationHash) 'Uninstall changed the documentation junction target'
                Require (-not (Test-Path -LiteralPath $managed -ErrorAction Stop) -and
                    (State-Snapshot) -ceq $machineBefore) 'Refused documentation uninstall changed machine state or published a restoration journal'
                Assert-UserState
            } finally {
                $alias=Get-Item -LiteralPath $documentation -Force -ErrorAction Stop
                Require ($alias.LinkType -ceq 'Junction' -and $alias.FullName -ieq $documentation) 'Documentation fixture junction changed before cleanup'
                [IO.Directory]::Delete($documentation,$false)
            }
        } finally {[IO.Directory]::Move($savedDocumentation,$documentation)}
        Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Refused documentation uninstall changed installed files or registration'
        $nativeDocumentationRefusals+=,@{phase=$case.phase;exitCode=$attempt.result.exitCode;
            elapsedMilliseconds=$attempt.milliseconds;deadlineMilliseconds=180000;
            refusedBeforeRestoration=$true;targetPreserved=$true;installedFileTreePreserved=$true;
            registrationPreserved=$true;profilePreserved=$true;machineStateUnchanged=$true}
        [IO.File]::Delete($documentationWitness)
    }
    Assert-ManagedDetection 'after-documentation-directory-restoration' $builds[0] $true -UseRegisteredDirectory

    $stage='managed-detection-missing-uninstall-data'
    [IO.File]::Move($uninstallData,$dataBackup)
    try {
        $output=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -UninstallerSHA256 $uninstallerDigest -InstallDirectory $install 2>&1)
        Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0 -and $null -eq (Get-PendingInstallFixtureValue)) 'Managed detection accepted missing uninstall data on a completed installation'
        $bindingRefused=$false
        try {
            $brokenBinding=Open-WorkflowUninstallBinding $Architecture
            if($brokenBinding){Close-WorkflowUninstallBinding $brokenBinding}
        } catch {$bindingRefused=$true}
        Require $bindingRefused 'Controller uninstall inspection accepted a missing uninstall data file'
    } finally {[IO.File]::Move($dataBackup,$uninstallData)}
    $output=@(& $detector -Version $builds[0].version -Architecture $Architecture -PayloadSHA256 $builds[0].payloadSha256 -UninstallerSHA256 $uninstallerDigest -InstallDirectory $install 2>&1)
    Require ($LASTEXITCODE -eq 0 -and $output.Count -eq 1 -and $output[0] -ceq 'AccessWeaver detected') 'Managed detection did not recognize the installation after uninstall data was restored'
    $uninstallDataDetectionVerified=$true

    $stage='setup-pending-marker-replacement'
    # Protected publication uses the original pending record. Replace it only
    # after verification, while the completion routine still holds its handles.
    $guardPoint='    AWPendingRetirementFailed := True;'
    Require ([regex]::Matches($productSetup,[regex]::Escape($guardPoint)).Count -eq 1) 'Expected one Setup retirement fixture boundary'
    $checkGuards=@'
    if not Verified then RaiseException('Could not verify the Setup guard fixture.');
    AWAssertFixtureDeleteDenied(Destination, $02200000);
    AWAssertFixtureDeleteDenied(Destination + '\licenses', $02200000);
    AWAssertFixtureDeleteDenied(Destination + '\docs', $02200000);
    AWAssertFixtureDeleteDenied(Destination + '\docs\assets', $02200000);
    AWAssertFixtureDeleteDenied(Destination + '\docs\qualification', $02200000);
    AWAssertFixtureDeleteDenied(Destination + '\accessweaver.exe', $00200000);
    AWAssertFixtureDeleteDenied(Destination + '\BUILD-INFO.json', $00200000);
    AWAssertFixtureDeleteDenied(Destination + '\SBOM.cdx.json', $00200000);
    AWAssertFixtureDeleteDenied(Destination + '\licenses\Inno-Setup-License.txt', $00200000);
    AWAssertFixtureDeleteDenied(Destination + '\docs\WINDOWS_WORKFLOWS.md', $00200000);
    AWAssertFixtureDeleteDenied(ExpandConstant('{uninstallexe}'), $00200000);
    AWAssertFixtureDeleteDenied(ChangeFileExt(ExpandConstant('{uninstallexe}'), '.dat'), $00200000);
    Log('AccessWeaver completion subject and directory sharing guards verified.');
'@
    $fixtureRoutine=@'
procedure AWAssertFixtureDeleteDenied(const Path: String; Flags: LongWord);
var Handle, Code: LongWord;
begin
  { Request DELETE without changing the file or directory. }
  Handle := AWOpenReplaceProbe(Path, $00010000, 7, 0, 3, Flags, 0);
  Code := DLLGetLastError;
  if Handle <> $FFFFFFFF then begin
    AWCloseNativeHandle(Handle);
    RaiseException('Setup completion fixture unexpectedly allowed DELETE access.');
  end;
  if Code <> 32 then RaiseException('Setup completion fixture expected a sharing violation.');
end;

'@
    $routinePoint='procedure AWCompleteInstallation(const Destination: String);'
    Require ([regex]::Matches($productSetup,[regex]::Escape($routinePoint)).Count -eq 1) 'Expected one Setup completion routine'
    $replacement="    if not AWWriteLifecycleString(AWPendingInstall, '"+$builds[1].version+"|' + Destination, True) then RaiseException('Could not change the owned pending installation fixture.');"
    $fixtureSetup=$productSetup.Replace($routinePoint,$fixtureRoutine+$routinePoint)
    $injected=@($checkGuards,$replacement,$guardPoint) -join [Environment]::NewLine
    [IO.File]::WriteAllText($faultSetup,$fixtureSetup.Replace($guardPoint,$injected))
    $null=@(& $compiler ('/DBuildRoot='+$genuinePayload) ('/DReleaseVersion='+$builds[0].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Pending-marker replacement fixture compilation failed'
    $refusalLog=Join-Path $capsule 'pending-marker-replacement.log'
    try {
        $replaced=Native-Record $faultInstaller ($arguments+@('/LOG='+$refusalLog)) @(1603)
        No-Reparse $refusalLog
        $size=(Get-Item -LiteralPath $refusalLog).Length
        Require ($size -gt 0 -and $size -le 4MB) 'Pending-marker replacement log is unavailable or exceeds bounds'
        $log=[IO.File]::ReadAllText($refusalLog)
        Require ($log.Contains('AccessWeaver pending installation record changed or could not be verified.') -and
            -not $log.Contains('Pending installation record retired.')) 'Setup retired a different pending record'
        Require ($log.Contains('AccessWeaver completion subject and directory sharing guards verified.')) 'Setup released a verified subject or the installation directory before retirement'
        Require ((Get-PendingInstallFixtureValue) -ceq ($builds[1].version+'|'+$install)) 'Setup changed the replacement marker'
        Assert-Installed $builds[0]
        Require ((Digest $marker) -ceq $markerHash -and (State-Snapshot) -ceq $before) 'Pending-marker replacement changed unrelated state'
        $setupMarkerReplacement=@{packageDirectoryGuardsVerified=$true;innoRuntimeNoticeGuardVerified=$true;exitCode=$replaced.result.exitCode;elapsedMilliseconds=$replaced.milliseconds;deadlineMilliseconds=180000;
            replacementPreserved=$true;completionRefusalLogged=$true;approvedPayloadVerified=$true;unrelatedStatePreserved=$true;subjectAndDirectoryGuardsVerified=$true}
    } finally {
        $pending=Get-PendingInstallFixtureValue
        if($pending -ceq ($builds[1].version+'|'+$install)){
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
            try {
                $key=$base.OpenSubKey('SOFTWARE\AccessWeaver\Installer',$true)
                Require ($null -ne $key) 'Owned pending fixture registry key disappeared'
                try {
                    Require ($key.GetValue('PendingInstall') -ceq $pending) 'Pending fixture changed during cleanup'
                    $key.DeleteValue('PendingInstall',$true)
                } finally {$key.Dispose()}
            } finally {$base.Dispose()}
        }
    }
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
    $replacementCases=@(
        @{file='accessweaver.exe';reason='The AccessWeaver executable cannot be replaced.';operation='refused-locked-upgrade'},
        @{file='BUILD-INFO.json';reason='The AccessWeaver BUILD-INFO.json cannot be replaced.';operation='refused-locked-build-info-upgrade'},
        @{file='SBOM.cdx.json';reason='The AccessWeaver SBOM.cdx.json cannot be replaced.';operation='refused-locked-sbom-upgrade'},
        @{file='docs\WINDOWS_WORKFLOWS.md';reason='The shipped AccessWeaver file cannot be replaced: docs\WINDOWS_WORKFLOWS.md.';operation=''}
    )
    foreach($case in $replacementCases){
        $logName=if($case.operation){$case.operation}else{'refused-locked-'+$case.file.Replace('\','-')}
        $upgradeLog=Join-Path $capsule ($logName+'.log')
        $guard=[IO.File]::Open((Join-Path $install $case.file),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try {
            $blocked=Native-Record $second ($arguments+@('/LOG='+$upgradeLog)) @(7)
        } finally {$guard.Dispose()}
        No-Reparse $upgradeLog
        $logFile=Get-Item -LiteralPath $upgradeLog -ErrorAction Stop
        Require (-not $logFile.PSIsContainer -and $logFile.Length -gt 0 -and $logFile.Length -le 1MB) 'Locked upgrade log is missing or exceeds its bound'
        Require ([IO.File]::ReadAllText($upgradeLog).Contains($case.reason)) 'Locked upgrade did not reach the expected release-file replacement preflight'
        Require ($null -eq (Get-PendingInstallFixtureValue)) 'Locked upgrade created a pending installation record'
        Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore) 'Locked upgrade changed installed files or registration'
        Assert-Installed $builds[0];Assert-UserState
        Require ((State-Snapshot) -ceq $machineBeforeUpgrade) 'Locked upgrade changed observed machine state'
        if($case.operation){
            $observations+=,@{operation=$case.operation;exitCode=$blocked.result.exitCode;elapsedMilliseconds=$blocked.milliseconds;deadlineMilliseconds=180000;preflightRefusalLogged=$true;pendingMarkerAbsent=$true;installedFileTreePreserved=$true;completeRegistrationPreserved=$true;profilePreserved=$true;machineStateUnchanged=$true}
        }
    }
    $stage='hard-linked-payload-upgrade'
    foreach($case in $replacementCases){
        $subject=Join-Path $install $case.file
        $subjectName=$case.file.Replace('\','-')
        $alias=Join-Path $install ('upgrade-alias-'+$subjectName)
        $upgradeLog=Join-Path $capsule ('upgrade-alias-'+$subjectName+'.log')
        $original=Digest $subject
        $null=New-Item -ItemType HardLink -Path $alias -Target $subject -ErrorAction Stop
        try {
            $null=Native-Record $second ($arguments+@('/LOG='+$upgradeLog)) @(7)
            No-Reparse $upgradeLog
            $size=(Get-Item -LiteralPath $upgradeLog -ErrorAction Stop).Length
            Require ($size -gt 0 -and $size -le 1MB) 'Hard-linked upgrade log is missing or exceeds its bound'
            Require ([IO.File]::ReadAllText($upgradeLog).Contains($case.reason)) 'Hard-linked upgrade did not reach release-file preflight'
            Require ((Digest $alias) -ceq $original -and (Digest $subject) -ceq $original -and
                $null -eq (Get-PendingInstallFixtureValue)) 'Hard-linked upgrade changed a release file or published a pending record'
        } finally {[IO.File]::Delete($alias)}
        Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore -and
            (State-Snapshot) -ceq $machineBeforeUpgrade) 'Hard-linked upgrade changed installed or machine state'
        Assert-UserState
    }
    $stage='read-only-payload-upgrade'
    foreach($case in $replacementCases){
        $subject=Join-Path $install $case.file
        $subjectName=$case.file.Replace('\','-')
        $upgradeLog=Join-Path $capsule ('upgrade-read-only-'+$subjectName+'.log')
        $originalAttributes=[IO.File]::GetAttributes($subject)
        Require (($originalAttributes -band [IO.FileAttributes]::ReadOnly) -eq 0) 'Installed release fixture is already read-only'
        $readOnlyAttributes=$originalAttributes -bor [IO.FileAttributes]::ReadOnly
        [IO.File]::SetAttributes($subject,$readOnlyAttributes)
        try {
            $null=Native-Record $second ($arguments+@('/LOG='+$upgradeLog)) @(7)
            No-Reparse $upgradeLog
            $size=(Get-Item -LiteralPath $upgradeLog -ErrorAction Stop).Length
            Require ($size -gt 0 -and $size -le 1MB) 'Read-only upgrade log is missing or exceeds its bound'
            Require ([IO.File]::ReadAllText($upgradeLog).Contains($case.reason)) 'Read-only upgrade did not reach release-file preflight'
            Require ([IO.File]::GetAttributes($subject) -eq $readOnlyAttributes -and
                $null -eq (Get-PendingInstallFixtureValue)) 'Read-only upgrade changed file attributes or published a pending record'
        } finally {[IO.File]::SetAttributes($subject,$originalAttributes)}
        Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint) -ceq $registrationBefore -and
            (State-Snapshot) -ceq $machineBeforeUpgrade) 'Read-only upgrade changed installed or machine state'
        Assert-UserState
    }
    $stage='upgrade'
    $baselineVersion=$builds[0].version
    $baselinePayload=Digest (Join-Path $install 'accessweaver.exe')
    $baselineSBOM=Digest (Join-Path $install 'SBOM.cdx.json')
    $baselineBuildPath=Join-Path $install 'BUILD-INFO.json'
    Require ((Get-Item -LiteralPath $baselineBuildPath).Length -le 64KB) 'Prior build metadata exceeds its retention bound'
    $baselineBuildBytes=[IO.File]::ReadAllBytes($baselineBuildPath)
    $baselineBuild=Digest $baselineBuildPath
    $baselineArgument="/AWUpgradeFrom=$baselineVersion,$baselinePayload,$baselineSBOM,$baselineBuild"
    $beforeBaselineRefusal=Installed-TreeFingerprint
    $beforeRegistrationRefusal=Registration-Fingerprint
    $beforeMachineRefusal=State-Snapshot
    $baselineLog=Join-Path $capsule 'managed-upgrade-baseline-refusal.log'
    $badBaseline="/AWUpgradeFrom=$baselineVersion,$baselinePayload,$baselineSBOM,"+('0'*64)
    $wrongBaseline=Native-Record $second ($arguments+@($badBaseline,('/LOG='+$baselineLog))) @(7)
    No-Reparse $baselineLog
    $baselineLogSize=(Get-Item -LiteralPath $baselineLog -ErrorAction Stop).Length
    Require ($baselineLogSize -gt 0 -and $baselineLogSize -le 4MB) 'Managed upgrade refusal log exceeds its bounds'
    Require ([IO.File]::ReadAllText($baselineLog).Contains('The installed AccessWeaver release differs from the approved upgrade baseline.')) 'Managed upgrade did not reach the pinned baseline check'
    Require ((Installed-TreeFingerprint) -ceq $beforeBaselineRefusal -and (Registration-Fingerprint) -ceq $beforeRegistrationRefusal -and
        (State-Snapshot) -ceq $beforeMachineRefusal -and $null -eq (Get-PendingInstallFixtureValue)) 'Managed upgrade baseline refusal changed installed state'
    Assert-UserState
    $upgradePayload=Join-Path $capsule 'managed-upgrade-payload'
    $productSource=Join-Path $PSScriptRoot 'windows-installer.iss'
    Assert-InstallerPackageDirectories $candidateStage $productSource
    Copy-Item -LiteralPath $candidateStage -Destination $upgradePayload -Recurse -ErrorAction Stop
    Assert-InstallerPackageDirectories $upgradePayload $productSource
    Require ((Digest (Join-Path $upgradePayload 'accessweaver.exe')) -ceq $builds[1].payloadSha256 -and
        (Digest (Join-Path $upgradePayload 'BUILD-INFO.json')) -ceq $builds[1].identityFileSHA256 -and
        (Digest (Join-Path $upgradePayload 'SBOM.cdx.json')) -ceq $builds[1].payloadSBOMSHA256) 'Managed upgrade recovery fixture differs from the candidate'
    # Both fault fixtures terminate only their own Setup process.
    $retirementPoint='    AWPendingRetirementFailed := True;'
    Require ([regex]::Matches($productSetup,[regex]::Escape($retirementPoint)).Count -eq 1) 'Expected one managed upgrade recovery fixture boundary'
    $abruptExitCode=197
    $partialCopyExitCode=198
    $retirementFault=@"
$retirementPoint
    if not Verified then RaiseException('Managed upgrade recovery fixture did not verify the installed release.');
    if not AWPendingInstallMatches(Destination) then RaiseException('Managed upgrade recovery fixture did not verify the pending record.');
    AWFixtureTerminateProcess(AWFixtureCurrentProcess, $abruptExitCode);
    RaiseException('Managed upgrade recovery fixture unexpectedly continued.');
"@
    $fixtureDeclarations=@'
function AWFixtureCurrentProcess: LongWord;
  external 'GetCurrentProcess@kernel32.dll stdcall';
function AWFixtureTerminateProcess(Process: LongWord; ExitCode: LongWord): Integer;
  external 'TerminateProcess@kernel32.dll stdcall';

'@
    $declarationPoint='procedure AWCompleteInstallation(const Destination: String);'
    Require ([regex]::Matches($productSetup,[regex]::Escape($declarationPoint)).Count -eq 1) 'Expected one managed upgrade fixture declaration point'
    $interruptedSource=$productSetup.Replace($declarationPoint,$fixtureDeclarations+[Environment]::NewLine+$declarationPoint)
    $stage='managed-upgrade-partial-copy'
    $copyCallback='; BeforeInstall: AWCheckPackageCopyDestination'
    Require ([regex]::Matches($productSetup,[regex]::Escape($copyCallback)).Count -eq 1) 'Expected one hosted package copy callback'
    $partialCopyFault=@"
procedure AWFixtureStopDuringCopy;
var Path, Name, Destination: String;
begin
  Path := CurrentFilename;
  if Copy(Path, 1, 1) = '{' then Path := ExpandConstant(Path);
  if Copy(Path, 1, 4) = '\\?\' then Delete(Path, 1, 4);
  Destination := ExpandConstant('{app}');
  if not AWIsInstallationDirectory(Destination, ExtractFileDir(Path)) then Exit;
  Name := ExtractFileName(Path);
  if (CompareText(Name, 'accessweaver.exe') <> 0) and (CompareText(Name, 'BUILD-INFO.json') <> 0) and
     (CompareText(Name, 'SBOM.cdx.json') <> 0) then Exit;
  if not AWPendingInstallMatches(Destination) then RaiseException('Partial copy fixture did not verify its pending record.');
  AWFixtureTerminateProcess(AWFixtureCurrentProcess, $partialCopyExitCode);
  RaiseException('Partial copy fixture unexpectedly continued.');
end;

"@
    $partialSource=$interruptedSource.Replace($copyCallback,$copyCallback+'; AfterInstall: AWFixtureStopDuringCopy').Replace(
        $declarationPoint,$partialCopyFault+$declarationPoint)
    [IO.File]::WriteAllText($faultSetup,$partialSource)
    $null=@(& $compiler ('/DBuildRoot='+$upgradePayload) ('/DReleaseVersion='+$builds[1].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Partial copy fault fixture compilation failed'
    $interruptedSetup=Join-Path $capsule $builds[1].installerName
    $partialSetupDigest=Digest $interruptedSetup
    Require ($partialSetupDigest -cne $builds[1].installerSHA256) 'Partial copy fault fixture matches the genuine installer'
    $partialLog=Join-Path $capsule 'managed-upgrade-partial-copy.log'
    $preexistingTemp=Join-Path $install 'is-preexisted.tmp'
    [IO.File]::Copy((Join-Path $install 'unins000.exe'),$preexistingTemp,$false)
    $preexistingTempDigest=Digest $preexistingTemp
    $temporaryFilesBefore=@(Get-ChildItem -LiteralPath $install -File -Force -Filter '*.tmp' -ErrorAction Stop | ForEach-Object Name)
    $partial=Native-Record $interruptedSetup ($arguments+@($baselineArgument,('/LOG='+$partialLog))) @($partialCopyExitCode)
    No-Reparse $partialLog
    $partialSize=(Get-Item -LiteralPath $partialLog -ErrorAction Stop).Length
    Require ($partialSize -gt 0 -and $partialSize -le 4MB) 'Partial copy log is missing or exceeds its bounds'
    $partialText=[IO.File]::ReadAllText($partialLog)
    $verifiedMarker='AccessWeaver approved upgrade baseline verified.'
    Require ([regex]::Matches($partialText,[regex]::Escape($verifiedMarker)).Count -ge 2 -and
        -not $partialText.Contains('Pending installation record retired.')) 'Partial copy did not interrupt an approved upgrade'
    $newSubjects=0
    foreach($subject in @(
        @{name='accessweaver.exe';previous=$baselinePayload;updated=$builds[1].payloadSha256},
        @{name='BUILD-INFO.json';previous=$baselineBuild;updated=$builds[1].identityFileSHA256},
        @{name='SBOM.cdx.json';previous=$baselineSBOM;updated=$builds[1].payloadSBOMSHA256}
    )){
        Require ($subject.previous -cne $subject.updated) 'Partial copy fixture requires distinct old and new release subjects'
        $subjectPath=Join-Path $install $subject.name
        No-Reparse $subjectPath
        $actual=Digest $subjectPath
        Require ($actual -cin @($subject.previous,$subject.updated)) 'Partial copy left a release subject outside its approved digests'
        if($actual -ceq $subject.updated){$newSubjects++}
    }
    Require ($newSubjects -eq 1) 'Partial copy did not leave exactly one updated release subject'
    $partialPending=Get-PendingInstallFixtureValue
    Require ($partialPending -cmatch ('\A'+[regex]::Escape($builds[1].version+'|'+$install)+'\|[a-f0-9]{64}\z') -and
        (Registration-Fingerprint) -ceq $beforeRegistrationRefusal -and (State-Snapshot) -ceq $beforeMachineRefusal -and
        (Digest $marker) -ceq $markerHash) 'Partial copy failed to preserve its approval, registration or unrelated state'
    Assert-UserState
    Assert-DetectorRefusal 'managed-upgrade-partial-copy-pending' -VerifyMatchingPendingStatus
    $orphanedTemps=@(Get-ChildItem -LiteralPath $install -File -Force -Filter '*.tmp' -ErrorAction Stop |
        Where-Object {$_.Name -cnotin $temporaryFilesBefore -and $_.Name -match '\Ais-[0-9a-z]{10}\.tmp\z'})
    Require ($orphanedTemps.Count -eq 1 -and $orphanedTemps[0].Length -gt 0 -and $orphanedTemps[0].Length -le 512MB) 'Partial copy did not leave one bounded staged uninstaller'
    No-Reparse $orphanedTemps[0].FullName
    $streamTemp=Join-Path $install 'is-streamkeep.tmp'
    [IO.File]::Copy($orphanedTemps[0].FullName,$streamTemp,$false)
    $streamTempDigest=Digest $streamTemp
    $streamName='retained-fixture-stream'
    $streamContents='Existing stream on a separate fixture file'
    Set-Content -LiteralPath $streamTemp -Stream $streamName -Value $streamContents -NoNewline -ErrorAction Stop

    $stage='managed-upgrade-retained-after-copy'
    [IO.File]::WriteAllText($faultSetup,$interruptedSource.Replace($retirementPoint,$retirementFault))
    $null=@(& $compiler ('/DBuildRoot='+$upgradePayload) ('/DReleaseVersion='+$builds[1].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Managed upgrade recovery fixture compilation failed'
    $interruptedSetupDigest=Digest $interruptedSetup
    Require ($interruptedSetupDigest -cne $builds[1].installerSHA256 -and $interruptedSetupDigest -cne $partialSetupDigest) 'Managed recovery fault fixtures must differ from each other and the genuine installer'
    $interruptedLog=Join-Path $capsule 'managed-upgrade-interrupted.log'
    $interrupted=Native-Record $interruptedSetup ($arguments+@($baselineArgument,('/LOG='+$interruptedLog))) @($abruptExitCode)
    No-Reparse $interruptedLog
    $interruptedSize=(Get-Item -LiteralPath $interruptedLog -ErrorAction Stop).Length
    Require ($interruptedSize -gt 0 -and $interruptedSize -le 4MB) 'Managed upgrade interruption log exceeds its bounds'
    $interruptedText=[IO.File]::ReadAllText($interruptedLog)
    $resumeMarker='AccessWeaver approved upgrade resumed from its pending installation record.'
    Require ([regex]::Matches($interruptedText,[regex]::Escape($resumeMarker)).Count -ge 2 -and
        -not $interruptedText.Contains('Pending installation record retired.')) 'Matching payload did not resume the partial copy before the second interruption'
    Assert-Installed $builds[1]
    $managedPending=Get-PendingInstallFixtureValue
    Require ($managedPending -ceq $partialPending) 'Resumed upgrade did not retain the exact bound pending record'
    Assert-DetectorRefusal 'managed-upgrade-pending'

    $stage='managed-upgrade-refuse-different-retry'
    $treeBeforeRetry=Installed-TreeFingerprint;$registrationBeforeRetry=Registration-Fingerprint
    $null=@(& $compiler ('/DBuildRoot='+$faultPayload) ('/DReleaseVersion='+$builds[1].version) ('/DTargetArch='+$Architecture) (Join-Path $PSScriptRoot 'windows-installer.iss'))
    Require ($LASTEXITCODE -eq 0 -and (Digest $interruptedSetup) -cne $interruptedSetupDigest) 'Different managed upgrade recovery fixture compilation failed'
    $documentationContainer=Join-Path $capsule 'managed-upgrade-altered-documentation'
    [void][IO.Directory]::CreateDirectory($documentationContainer)
    $documentationPayload=Join-Path $documentationContainer 'payload'
    Copy-Item -LiteralPath $upgradePayload -Destination $documentationPayload -Recurse -ErrorAction Stop
    $changedDocument=Join-Path $documentationPayload 'docs\WINDOWS_WORKFLOWS.md'
    [IO.File]::AppendAllText($changedDocument,[Environment]::NewLine+'Synthetic changed documentation')
    Require ((Digest (Join-Path $documentationPayload 'accessweaver.exe')) -ceq $builds[1].payloadSha256 -and
        (Digest (Join-Path $documentationPayload 'BUILD-INFO.json')) -ceq $builds[1].identityFileSHA256 -and
        (Digest (Join-Path $documentationPayload 'SBOM.cdx.json')) -ceq $builds[1].payloadSBOMSHA256 -and
        (Digest $changedDocument) -cne (Digest (Join-Path $upgradePayload 'docs\WINDOWS_WORKFLOWS.md'))) 'Documentation-only retry fixture changed an approved subject or retained the document'
    $null=@(& $compiler ('/DBuildRoot='+$documentationPayload) ('/DReleaseVersion='+$builds[1].version) ('/DTargetArch='+$Architecture) $productSource)
    Require ($LASTEXITCODE -eq 0) 'Documentation-only managed upgrade retry fixture compilation failed'
    $documentationSetup=Join-Path $documentationContainer $builds[1].installerName
    foreach($case in @(
        @{name='missing-baseline';setup=$second;extra=@()},
        @{name='different-baseline';setup=$second;extra=@($badBaseline)},
        @{name='different-candidate';setup=$interruptedSetup;extra=@($baselineArgument)},
        @{name='changed-documentation';setup=$documentationSetup;extra=@($baselineArgument)}
    )){
        $refusedRetry=Join-Path $capsule ($case.name+'.log')
        $null=Native-Record $case.setup ($arguments+$case.extra+@('/LOG='+$refusedRetry)) @(7)
        No-Reparse $refusedRetry
        $size=(Get-Item -LiteralPath $refusedRetry -ErrorAction Stop).Length
        Require ($size -gt 0 -and $size -le 4MB -and
            [IO.File]::ReadAllText($refusedRetry).Contains('with its original approved installer and baseline argument.')) 'Managed upgrade retry did not refuse the different approval'
        Require ((Get-PendingInstallFixtureValue) -ceq $managedPending -and (Installed-TreeFingerprint) -ceq $treeBeforeRetry -and
            (Registration-Fingerprint) -ceq $registrationBeforeRetry -and (State-Snapshot) -ceq $beforeMachineRefusal) 'Refused managed retry changed installed state'
        Assert-UserState
    }
    $stage='managed-upgrade-locked-temporary-uninstaller'
    $lockedTemp=$orphanedTemps[0].FullName
    No-Reparse $lockedTemp
    $lockedTempDigest=Digest $lockedTemp
    $lockedTempLog=Join-Path $capsule 'managed-upgrade-locked-temporary-uninstaller.log'
    $heldTemp=[IO.File]::Open($lockedTemp,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $lockedTempResult=Native-Record $second ($arguments+@($baselineArgument,('/LOG='+$lockedTempLog))) @(1603)
        No-Reparse $lockedTempLog
        $lockedTempLogSize=(Get-Item -LiteralPath $lockedTempLog -ErrorAction Stop).Length
        Require ($lockedTempLogSize -gt 0 -and $lockedTempLogSize -le 4MB) 'Locked temporary uninstaller log is unavailable or exceeds its bound'
        $lockedTempText=[IO.File]::ReadAllText($lockedTempLog)
        Require ($lockedTempText.Contains('AccessWeaver could not retire a verified temporary uninstaller. Pending installation record retained.') -and
            -not $lockedTempText.Contains('Pending installation record retired.')) 'Setup reported completion despite a locked verified temporary uninstaller'
        Require ((Get-PendingInstallFixtureValue) -ceq $managedPending -and (Digest $lockedTemp) -ceq $lockedTempDigest) 'Locked cleanup changed the verified temporary uninstaller or its pending approval'
        $output=@(& $detector -Version $builds[1].version -Architecture $Architecture -PayloadSHA256 $builds[1].payloadSha256 -InstallDirectory $install 2>&1)
        Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection accepted the installation while verified cleanup was blocked'
        Assert-UserState
    } finally {$heldTemp.Dispose()}

    $stage='managed-upgrade-retirement-flush-failure'
    $flushPoint='    if Result and Flush then Flushed := AWFlushRegistryKey(Key) = 0;'
    Require ([regex]::Matches($productSetup,[regex]::Escape($flushPoint)).Count -eq 1) 'Expected one Setup retirement flush boundary'
    $flushFault=@"
    if Result and Flush then begin
      Log('AccessWeaver retirement flush failure injected after verified deletion.');
      Flushed := False;
    end;
"@
    [IO.File]::WriteAllText($faultSetup,$productSetup.Replace($flushPoint,$flushFault))
    $null=@(& $compiler ('/DBuildRoot='+$upgradePayload) ('/DReleaseVersion='+$builds[1].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Managed upgrade retirement flush fixture compilation failed'
    $flushSetupDigest=Digest $interruptedSetup
    Require ($flushSetupDigest -cne $builds[1].installerSHA256 -and $flushSetupDigest -cne $interruptedSetupDigest) 'Retirement flush fixture must differ from the genuine and abrupt-termination installers'
    $flushLog=Join-Path $capsule 'managed-upgrade-retirement-flush-failure.log'
    $flushRefused=Native-Record $interruptedSetup ($arguments+@($baselineArgument,('/LOG='+$flushLog))) @(1603)
    No-Reparse $flushLog
    $flushLogSize=(Get-Item -LiteralPath $flushLog -ErrorAction Stop).Length
    Require ($flushLogSize -gt 0 -and $flushLogSize -le 4MB) 'Managed upgrade retirement flush log exceeds its bounds'
    $flushText=[IO.File]::ReadAllText($flushLog)
    Require ($flushText.Contains('AccessWeaver retirement flush failure injected after verified deletion.') -and
        $flushText.Contains('AccessWeaver pending installation record restored after retirement flush failed.') -and
        -not $flushText.Contains('Pending installation record retired.')) 'Managed upgrade did not restore the record after retirement failed'
    Require ((Get-PendingInstallFixtureValue) -ceq $managedPending) 'Retirement flush failure did not restore the exact managed upgrade record'
    $output=@(& $detector -Version $builds[1].version -Architecture $Architecture -PayloadSHA256 $builds[1].payloadSha256 -InstallDirectory $install 2>&1)
    Require ($LASTEXITCODE -eq 1 -and $output.Count -eq 0) 'Managed detection accepted the pending installation after the failed flush'
    Assert-Installed $builds[1]
    Require ((State-Snapshot) -ceq $beforeMachineRefusal -and (Digest $marker) -ceq $markerHash) 'Retirement flush failure changed unrelated machine state'
    Assert-UserState
    $setupRetirementFlush=@{fixtureSHA256=$flushSetupDigest;exitCode=$flushRefused.result.exitCode;
        elapsedMilliseconds=$flushRefused.milliseconds;deadlineMilliseconds=180000;deletionObserved=$true;
        originalMarkerRestored=$true;managedDetectionRefused=$true;profilePreserved=$true;
        unrelatedStatePreserved=$true;matchingRetryRetiredMarker=$false}
    $stage='managed-upgrade-unknown-file-refusal'
    $registrationBeforeRetry=Registration-Fingerprint
    [IO.File]::WriteAllText($baselineBuildPath,'unapproved recovery fixture bytes')
    $changedBuild=Digest $baselineBuildPath
    $changedTree=Installed-TreeFingerprint
    $changedLog=Join-Path $capsule 'managed-upgrade-unknown-file.log'
    $null=Native-Record $second ($arguments+@($baselineArgument,('/LOG='+$changedLog))) @(7)
    No-Reparse $changedLog
    $logSize=(Get-Item -LiteralPath $changedLog -ErrorAction Stop).Length
    Require ($logSize -gt 0 -and $logSize -le 4MB -and
        [IO.File]::ReadAllText($changedLog).Contains('The interrupted AccessWeaver upgrade contains files or registration outside the approved releases.')) 'Managed retry did not refuse unexpected bytes'
    Require ((Digest $baselineBuildPath) -ceq $changedBuild -and (Installed-TreeFingerprint) -ceq $changedTree -and
        (Get-PendingInstallFixtureValue) -ceq $managedPending -and (Registration-Fingerprint) -ceq $registrationBeforeRetry) 'Refused recovery altered unexpected bytes or retired its record'
    Assert-UserState
    $stage='managed-upgrade-matching-retry'
    # Exercise the old metadata, new executable and a missing SBOM in one retry.
    [IO.File]::WriteAllBytes($baselineBuildPath,$baselineBuildBytes)
    Require ((Digest $baselineBuildPath) -ceq $baselineBuild -and
        (Digest (Join-Path $install 'accessweaver.exe')) -ceq $builds[1].payloadSha256) 'Mixed recovery fixture does not match its approved old and new files'
    [IO.File]::Delete((Join-Path $install 'SBOM.cdx.json'))
    $approvedBaselineLog=Join-Path $capsule 'managed-upgrade-baseline-retry.log'
    $upgraded=Native-Record $second ($arguments+@($baselineArgument,('/LOG='+$approvedBaselineLog)))
    Assert-SetupCompletionReadback $approvedBaselineLog
    Require ([regex]::Matches([IO.File]::ReadAllText($approvedBaselineLog),[regex]::Escape($resumeMarker)).Count -ge 2 -and
        $null -eq (Get-PendingInstallFixtureValue)) 'Matching managed retry did not resume before copy and retire its record'
    Assert-Installed $builds[1]
    $setupRetirementFlush.matchingRetryRetiredMarker=$true
    $stage='managed-upgrade-partial-copy-cleanup'
    Require ((Digest $preexistingTemp) -ceq $preexistingTempDigest -and
        (Digest $streamTemp) -ceq $streamTempDigest -and
        (Get-Content -LiteralPath $streamTemp -Stream $streamName -Raw -ErrorAction Stop) -ceq $streamContents) 'Managed retry changed a preexisting file or a file with a named stream'
    foreach($fixtureTemp in @($preexistingTemp,$streamTemp)){
        No-Reparse $fixtureTemp
        [IO.File]::Delete($fixtureTemp)
    }
    $retainedTemporaryFiles=@(Get-ChildItem -LiteralPath $install -File -Force -Filter '*.tmp' -ErrorAction Stop |
        Where-Object {$_.Name -cnotin $temporaryFilesBefore}).Count
    $setupUpgradeBaseline=@{refusalExitCode=$wrongBaseline.result.exitCode;refusalElapsedMilliseconds=$wrongBaseline.milliseconds;
        deadlineMilliseconds=180000;installedStatePreserved=$true;profilePreserved=$true;pendingMarkerAbsent=$true;
        matchingUpgradeAccepted=$true;copyCompletedBeforeRecovery=$true;changedRetryRefused=$true;
        matchingRetryRetiredMarker=$true;changedDocumentationRetryRefused=$true;
        abruptTerminationExitCode=$interrupted.result.exitCode;partialCopyExitCode=$partial.result.exitCode;
        partialCopyMixedSubjectsVerified=$true;partialCopyRetryVerified=$true;partialCopyTemporaryFilesRetained=$retainedTemporaryFiles;
        partialCopyUnrelatedFilesPreserved=$true;lockedTemporaryUninstallerExitCode=$lockedTempResult.result.exitCode;
        lockedTemporaryUninstallerPendingVerified=$true}
    Require ($retainedTemporaryFiles -eq 0) 'Managed upgrade retry retained temporary files from the interrupted copy'
    Require ((Digest $marker) -ceq $markerHash) 'Upgrade changed an unrelated installed-directory file'
    $observations+=,@{operation='upgrade';exitCode=$upgraded.result.exitCode;elapsedMilliseconds=$upgraded.milliseconds;deadlineMilliseconds=180000;payloadAndRegistrationVerified=$true;unrelatedStatePreserved=$true}
    Assert-ManagedDetection 'after-upgrade' $builds[1] $true -UseRegisteredDirectory
    Assert-ManagedDetection 'superseded-version' $builds[0] $false -UseRegisteredDirectory
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
    $lockedCompatibilityFile=Join-Path $install 'uninstall-system.json'
    $compatibilityDigest=Digest $lockedCompatibilityFile
    # Open a native sharing lock after both preflights and the pending-marker readback.
    $pendingReadbackPoint="        RaiseException('Cannot verify the AccessWeaver pending installation record after writing it.');"
    $deinitPoint='  if AWManagedTempCandidates <> nil then AWManagedTempCandidates.Free;'
    foreach($point in @($pendingReadbackPoint,$declarationPoint,$deinitPoint)){
        Require ([regex]::Matches($productSetup,[regex]::Escape($point)).Count -eq 1) 'Expected one late file lock fixture boundary'
    }
    $lateCompatibilityLock=@'
      AWFixtureCompatibilityHandle := AWOpenReplaceProbe(Destination + '\uninstall-system.json',
        $80000000, $00000003, 0, 3, $00200000, 0);
      if AWFixtureCompatibilityHandle = $FFFFFFFF then
        RaiseException('Could not acquire the AccessWeaver fixture compatibility-file lock.');
      Log('AccessWeaver fixture acquired its compatibility-file lock after pending readback.');
'@
    $closeCompatibilityLock=@'
  if (AWFixtureCompatibilityHandle <> 0) and (AWFixtureCompatibilityHandle <> $FFFFFFFF) then
    AWCloseNativeHandle(AWFixtureCompatibilityHandle);
'@
    $lateLockSource=$productSetup.Replace($declarationPoint,('var AWFixtureCompatibilityHandle: LongWord;'+[Environment]::NewLine+$declarationPoint)).
        Replace($pendingReadbackPoint,($pendingReadbackPoint+[Environment]::NewLine+$lateCompatibilityLock)).
        Replace($deinitPoint,($closeCompatibilityLock+[Environment]::NewLine+$deinitPoint))
    [IO.File]::WriteAllText($faultSetup,$lateLockSource)
    $null=@(& $compiler ('/DBuildRoot='+$upgradePayload) ('/DReleaseVersion='+$builds[1].version) ('/DTargetArch='+$Architecture) $faultSetup)
    Require ($LASTEXITCODE -eq 0) 'Late compatibility-file lock fixture compilation failed'
    $lateLockSetupDigest=Digest $interruptedSetup
    Require ($lateLockSetupDigest -cne $builds[1].installerSHA256) 'Late compatibility-file lock fixture must differ from genuine Setup'
    $failedCopy=Native-Record $interruptedSetup ($arguments+@('/LOG='+$failedCopyLog)) (0..255)
    No-Reparse $failedCopyLog
    $copyLogSize=(Get-Item -LiteralPath $failedCopyLog -ErrorAction Stop).Length
    Require ($copyLogSize -gt 0 -and $copyLogSize -le 1MB) 'Failed installation log is unavailable or exceeds its bound'
    $copyLog=[IO.File]::ReadAllText($failedCopyLog)
    $lateCompatibilityRefusal=[ordered]@{
        fixtureSHA256=$lateLockSetupDigest;setupExitCode=$failedCopy.result.exitCode;
        installationStarted=$copyLog.Contains('Starting the installation process.');
        lateLockAcquired=$copyLog.Contains('AccessWeaver fixture acquired its compatibility-file lock after pending readback.');
        destinationGuardRefused=$copyLog.Contains('An AccessWeaver package file destination cannot be safely replaced. Setup recovery is required.');
        pendingMarkerRetained=(Get-PendingInstallFixtureValue) -ceq $pendingValue;
        lockedFilePreserved=(Digest $lockedCompatibilityFile) -ceq $compatibilityDigest
    }
    Require ($lateCompatibilityRefusal.setupExitCode -in @(4,5) -and $lateCompatibilityRefusal.installationStarted -and
        $lateCompatibilityRefusal.lateLockAcquired -and $lateCompatibilityRefusal.destinationGuardRefused) 'Setup did not refuse replacement through the late per-file destination guard'
    Require $lateCompatibilityRefusal.pendingMarkerRetained 'Failed Setup did not retain its own pending installation record'
    Require ((Get-AccessWeaverInstallerRecoveryState) -ceq 'pending') 'Controller did not observe the native Setup recovery marker'
    Require $lateCompatibilityRefusal.lockedFilePreserved 'Failed Setup changed the locked compatibility file'
    Assert-UserState
    $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
    Assert-DetectorRefusal 'pending-install-refused'
    $controllerRefused=$false
    try {
        $pendingBinding=Open-WorkflowUninstallBinding $Architecture
        if($pendingBinding){Close-WorkflowUninstallBinding $pendingBinding}
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
                if($deniedBinding){Close-WorkflowUninstallBinding $deniedBinding}
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
        copyFailureLogged=$true;pendingRecordCreatedBySetup=$true;lockedCompatibilityFilePreserved=$true;
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
    $maximumVersion='0.0.0-'+('a'*250)
    $protectedRegistrationRefusal='AccessWeaver protected registration or legacy approval refused.'
    $boundedReadRefusal='The installed AccessWeaver version is unreadable, oversized or has an unsupported type.'
    foreach($case in @(
        @{name='maximum-string-accepted';value=$maximumVersion;kind=[Microsoft.Win32.RegistryValueKind]::String;syncName=$true;expected=0;reason=''},
        @{name='inconsistent-display-name-refused';value=$maximumVersion;kind=[Microsoft.Win32.RegistryValueKind]::String;syncName=$false;expected=3;reason=$protectedRegistrationRefusal},
        @{name='maximum-expand-literal-owned-refused';value=$maximumVersion;kind=[Microsoft.Win32.RegistryValueKind]::ExpandString;syncName=$true;expected=3;reason=$protectedRegistrationRefusal},
        @{name='over-budget-string-refused';value=('0.0.0-'+('a'*251));kind=[Microsoft.Win32.RegistryValueKind]::String;syncName=$false;expected=1;reason=$boundedReadRefusal},
        @{name='oversized-string-refused';value=('0.0.0-'+('a'*65536));kind=[Microsoft.Win32.RegistryValueKind]::String;syncName=$false;expected=1;reason=$boundedReadRefusal},
        @{name='environment-reference-not-expanded';value='0.0.0-%ACCESSWEAVER_INSTALLER_REGISTRY_VERSION_PROBE%';kind=[Microsoft.Win32.RegistryValueKind]::ExpandString;syncName=$false;expected=1;reason='The installed AccessWeaver version is invalid.'}
    )){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
        try {
            $key=$base.OpenSubKey($uninstallKey,$true);Require ($null -ne $key) 'Owned installation registration is unavailable'
            $originalVersion=$key.GetValue('DisplayVersion');$originalKind=$key.GetValueKind('DisplayVersion')
            $originalName=$key.GetValue('DisplayName');$originalNameKind=$key.GetValueKind('DisplayName')
            try {
                $key.SetValue('DisplayVersion',$case.value,$case.kind)
                if($case.syncName){
                    $display='AccessWeaver version '+$case.value
                    $key.SetValue('DisplayName',$display.Substring(0,[Math]::Min(259,$display.Length)),[Microsoft.Win32.RegistryValueKind]::String)
                }
                $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint $key
                if($case.expected -eq 0){$key.Dispose();$key=$null}
                $registryLog=Join-Path $capsule ('registry-boundary-'+$case.name+'.log')
                $resultCase=Native-Record $second ($arguments+@('/LOG='+$registryLog)) (0..255)
                No-Reparse $registryLog
                $logSize=(Get-Item -LiteralPath $registryLog -ErrorAction Stop).Length
                Require ($logSize -gt 0 -and $logSize -le 1MB) 'Registry boundary Setup log is unavailable or exceeds its bound'
                $registryText=[IO.File]::ReadAllText($registryLog)
                $refusalReasonVerified=$case.expected -ne 0 -and $registryText.Contains($case.reason)
                $refusedStatePreserved=$case.expected -ne 0 -and (Installed-TreeFingerprint) -ceq $treeBefore -and
                    (Registration-Fingerprint $key) -ceq $registrationBefore
                Assert-UserState
                $registryReadCases+=,@{name=$case.name;expectedExitCode=$case.expected;exitCode=$resultCase.result.exitCode;
                    elapsedMilliseconds=$resultCase.milliseconds;fixtureUTF16Bytes=([Text.Encoding]::Unicode.GetByteCount($case.value)+2);
                    refusedStatePreserved=$refusedStatePreserved;refusalReasonVerified=$refusalReasonVerified;profilePreserved=$true}
                Require ($resultCase.result.exitCode -eq $case.expected) 'Bounded registry version handling returned an unexpected result'
                if($case.expected -ne 0){
                    Require ($refusalReasonVerified -and $refusedStatePreserved) 'Registry refusal did not verify its cause and preserved installation'
                }
            } finally {
                if($null -eq $key){$key=$base.OpenSubKey($uninstallKey,$true);Require ($null -ne $key) 'Owned registration disappeared after boundary setup'}
                $key.SetValue('DisplayVersion',$originalVersion,$originalKind)
                if($case.syncName){$key.SetValue('DisplayName',$originalName,$originalNameKind)}
            }
        } finally {if($key){$key.Dispose()};$base.Dispose()}
        Assert-Installed $builds[1]
        Require ($null -eq (Get-PendingInstallFixtureValue)) 'Registry boundary case left a pending installation record'
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
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $accessParent=$null;$originalKey=$null;$deniedKey=$null
    $savedLeaf='AccessWeaver-registration-saved-'+$guid
    $deniedLeaf='AccessWeaver-registration-denied-'+$guid
    $deniedCreated=$false;$deniedMounted=$false;$originalHidden=$false
    $fixtureMarker='AccessWeaverRegistryAccessFixture'
    try {
        $accessParent=$base.OpenSubKey($parentPath,$true)
        Require ($null -ne $accessParent) 'Owned fixture parent is unavailable'
        $originalKey=$accessParent.OpenSubKey($productLeaf,$false)
        Require ($null -ne $originalKey) 'Owned product registration is unavailable'
        $sections=[Security.AccessControl.AccessControlSections]'Access,Owner,Group'
        $originalSDDL=$originalKey.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)
        $originalFingerprint=Registration-Fingerprint $originalKey
        $names=$accessParent.GetSubKeyNames()
        Require ($savedLeaf -notin $names -and $deniedLeaf -notin $names) 'Registry access fixture name already exists'
        $deniedKey=$accessParent.CreateSubKey($deniedLeaf,$true)
        Require ($null -ne $deniedKey) 'Could not create the disposable registry access fixture'
        $deniedCreated=$true
        $deniedKey.SetValue($fixtureMarker,$guid,[Microsoft.Win32.RegistryValueKind]::String)
        $deniedKey.Dispose();$deniedKey=$null
        $deniedKey=$accessParent.OpenSubKey($deniedLeaf,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::FullControl)
        Require ($null -ne $deniedKey -and $deniedKey.GetValue($fixtureMarker) -ceq $guid) 'Could not hold the known registry fixture with DACL write access'
        $access=[Security.AccessControl.AccessControlSections]::Access
        $deniedSecurity=$deniedKey.GetAccessControl($access)
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $deniedSecurity.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new(
                $identity.User,[Security.AccessControl.RegistryRights]::QueryValues,[Security.AccessControl.AccessControlType]::Deny))
        } finally {$identity.Dispose()}
        $deniedKey.SetAccessControl($deniedSecurity)
        $deniedSDDL=$deniedKey.GetAccessControl($access).GetSecurityDescriptorSddlForm($access)
        $deniedFingerprint=Registration-Fingerprint $deniedKey
        # Stage the denial at the normal product path while retaining the original key.
        try {
            [InstallerRegistryFixture]::Rename($accessParent,$productLeaf,$savedLeaf);$originalHidden=$true
            [InstallerRegistryFixture]::Rename($accessParent,$deniedLeaf,$productLeaf);$deniedMounted=$true
            $queryStatus=[InstallerRegistryFixture]::QueryStatus64($base,$uninstallKey)
            Require ($queryStatus -eq 5) 'Disposable product-key denial did not produce native ERROR_ACCESS_DENIED'
            $treeBefore=Installed-TreeFingerprint
            $deniedLog=Join-Path $capsule 'denied-product-registry.log'
            $denied=Native-Record $second ($arguments+@('/LOG='+$deniedLog)) @(1)
            No-Reparse $deniedLog
            $logSize=(Get-Item -LiteralPath $deniedLog -ErrorAction Stop).Length
            Require ($logSize -gt 0 -and $logSize -le 1MB -and
                [IO.File]::ReadAllText($deniedLog).Contains('Cannot read the AccessWeaver installation registration. Review access and retry.')) 'Native Setup did not report the registry access refusal'
            Require ((Installed-TreeFingerprint) -ceq $treeBefore -and
                (Registration-Fingerprint $deniedKey) -ceq $deniedFingerprint -and
                $deniedKey.GetAccessControl($access).GetSecurityDescriptorSddlForm($access) -ceq $deniedSDDL -and
                (Registration-Fingerprint $originalKey) -ceq $originalFingerprint -and
                $originalKey.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections) -ceq $originalSDDL -and
                $null -eq (Get-PendingInstallFixtureValue)) 'Denied registration read changed protected state'
            Assert-UserState
        } finally {
            # RegRenameKey refuses a pre-existing destination and preserves both leaves.
            if($deniedMounted){[InstallerRegistryFixture]::Rename($accessParent,$productLeaf,$deniedLeaf);$deniedMounted=$false}
            if($originalHidden){[InstallerRegistryFixture]::Rename($accessParent,$savedLeaf,$productLeaf);$originalHidden=$false}
        }
        $namedKey=$accessParent.OpenSubKey($productLeaf,$false)
        try {
            Require ($null -ne $namedKey -and (Registration-Fingerprint $namedKey) -ceq $originalFingerprint -and
                $namedKey.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections) -ceq $originalSDDL -and
                [InstallerRegistryFixture]::QueryStatus64($base,$uninstallKey) -eq 0) 'Original protected registration did not return with its exact security descriptor and values'
        } finally {if($namedKey){$namedKey.Dispose()}}
    } finally {
        try {
            if($deniedCreated -and -not $deniedMounted){
                if($null -eq $deniedKey){$deniedKey=$accessParent.OpenSubKey($deniedLeaf,$false)}
                Require ($null -ne $deniedKey -and $deniedKey.GetValue($fixtureMarker) -ceq $guid -and $deniedKey.SubKeyCount -eq 0) 'Refusing to delete a changed registry access fixture'
                $deniedKey.Dispose();$deniedKey=$null
                [InstallerRegistryFixture]::DeleteEmptyDeniedLeaf64($accessParent,$deniedLeaf)
                Require ($deniedLeaf -notin $accessParent.GetSubKeyNames()) 'Disposable registry access fixture remains after deletion'
            }
        } finally {
            if($deniedKey){$deniedKey.Dispose()}
            if($originalKey){$originalKey.Dispose()}
            if($accessParent){$accessParent.Dispose()}
            $base.Dispose()
        }
    }
    $registryAccessCases+=,@{name='denied-product-key-refused';exitCode=$denied.result.exitCode;elapsedMilliseconds=$denied.milliseconds;
        queryDenialIndependentlyObserved=$true;nativeQueryStatus=$queryStatus;refusalReasonVerified=$true;installedFileTreePreserved=$true;
        registrationValuesPreserved=$true;fixtureDACLUnchangedDuringRefusal=$true;profilePreserved=$true;
        originalRegistrationRestored=$true;originalSecurityDescriptorPreserved=$true;separateFixtureKeyRemoved=$true}
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
        @{name='same-size-controller-mismatch-refused';kind='wrong-digest'},
        @{name='hard-linked-controller-refused';kind='hardlink'},
        @{name='execution-denied-controller-refused';kind='denied';nativeErrors=@(5)}
    )){
        $stage='restoration-launch-'+$case.kind;$caseRecord=$null
        $hardlinkSource=Join-Path $install 'hardlink-controller-source.exe'
        try {
            switch($case.kind){
                'missing' {[IO.File]::Delete($core)}
                'truncated' {[IO.File]::WriteAllBytes($core,[byte[]]@(0,0,0,0))}
                'malformed' {[IO.File]::WriteAllBytes($core,[byte[]]::new(4096))}
                'hardlink' {
                    [IO.File]::Copy($launchBackup,$hardlinkSource,$false)
                    [IO.File]::Delete($core)
                    $null=New-Item -ItemType HardLink -Path $core -Target $hardlinkSource -ErrorAction Stop
                    Require ((Digest $core) -ceq $builds[1].payloadSha256) 'Hard link fixture does not match the approved bytes'
                }
                'wrong-digest' {
                    $stream=[IO.File]::Open($core,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                    try {
                        $stream.Position=$stream.Length-1
                        $last=$stream.ReadByte()
                        $stream.Position=$stream.Length-1
                        $stream.WriteByte([byte]($last -bxor 1))
                    } finally {$stream.Dispose()}
                    Require ((Get-Item -LiteralPath $core).Length -eq (Get-Item -LiteralPath $launchBackup).Length -and
                        (Digest $core) -cne $builds[1].payloadSha256) 'Same-size modification did not change the installed digest'
                }
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
            $probe=$null
            if($case.nativeErrors){
                $probe=[InstallerRestorationLaunch]::Probe($core)
                Require (-not $probe.Started -and $case.nativeErrors -contains $probe.NativeError) 'Independent native launch probe did not confirm the expected rejection category'
            }
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
            if($case.kind -cne 'denied'){
                $preserved=$log.Contains('Cannot verify the installed AccessWeaver restoration controller.') -and
                    -not $log.Contains('AccessWeaver system restoration starts at the uninstall step.') -and $nativeMatches.Count -eq 0
                $caseRecord=@{name=$case.name;failurePhase='verify-controller';controllerVerificationRefusalLogged=$preserved;exitCode=$attempt.result.exitCode;
                    elapsedMilliseconds=$attempt.milliseconds;observationDeadlineMilliseconds=180000;installedFileTreePreserved=$true;
                    registrationValuesPreserved=$true;profilePreserved=$true;originalControllerAndDACLRestored=$false;restoredControllerRuntimeVerified=$false}
                $restorationLaunchCases+=,$caseRecord
                Require $preserved 'Unexpected restoration launch after controller verification failed'
            }else{
                Require ($nativeMatches.Count -eq 1) 'Native launch refusal did not retain exactly one bounded numeric error'
                $observedNativeError=[long]::Parse($nativeMatches[0].Groups[1].Value,[Globalization.CultureInfo]::InvariantCulture)
                Require ($observedNativeError -le [uint32]::MaxValue) 'Native launch error exceeds the Windows error-code range'
                $launchPhaseObserved=$log.Contains('AccessWeaver could not launch the restoration controller.')
                $expectedErrorObserved=$observedNativeError -eq $probe.NativeError
                $caseRecord=@{name=$case.name;failurePhase='launch-controller';launchPhaseObserved=$launchPhaseObserved;expectedNativeError=$probe.NativeError;independentProbeStarted=$probe.Started;independentProbeNativeError=$probe.NativeError;nativeError=$observedNativeError;nativeErrorLogVerified=($launchPhaseObserved -and $expectedErrorObserved);exitCode=$attempt.result.exitCode;elapsedMilliseconds=$attempt.milliseconds;observationDeadlineMilliseconds=180000;controllerPresentDuringRefusal=$controllerPresent;installedFileTreePreserved=$true;registrationValuesPreserved=$true;profilePreserved=$true;fileDACLCheckApplicable=$controllerPresent;fileDACLUnchangedDuringRefusal=$fileDACLUnchanged;originalControllerAndDACLRestored=$false;restoredControllerRuntimeVerified=$false}
                # Preserve fixed numeric observations even when the expectation fails.
                $restorationLaunchCases+=,$caseRecord
                Require ($launchPhaseObserved -and $expectedErrorObserved) 'Native launch refusal did not retain its fixed phase and exact error code'
            }
        } finally {
            if($case.kind -ceq 'hardlink'){
                if((Test-Path -LiteralPath $hardlinkSource) -and (Test-Path -LiteralPath $core) -and $caseRecord){
                    Require ((Digest $hardlinkSource) -ceq $builds[1].payloadSha256) 'Uninstaller changed the hard link target'
                }
                [IO.File]::Delete($core)
                [IO.File]::Delete($hardlinkSource)
            }
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
    $core=Join-Path $install 'accessweaver.exe'
    # Compile the same installer source with the inert controller as its
    # packaged payload. The genuine uninstaller must never admit these bytes.
    $restorePayload=Join-Path $capsule 'restore-fixture-payload'
    [void][IO.Directory]::CreateDirectory($restorePayload)
    Copy-Item -LiteralPath $fixtureController -Destination (Join-Path $restorePayload 'accessweaver.exe')
    foreach($file in @('BUILD-INFO.json','SBOM.cdx.json')){
        Copy-Item -LiteralPath (Join-Path $install $file) -Destination $restorePayload
    }
    Copy-Item -LiteralPath (Join-Path $project 'LICENSE') -Destination $restorePayload
    $null=@(& $compiler ('/DBuildRoot='+$restorePayload) ('/DReleaseVersion='+$builds[1].version) ('/DTargetArch='+$Architecture) (Join-Path $PSScriptRoot 'windows-installer.iss'))
    Require ($LASTEXITCODE -eq 0) 'Restoration controller fixture package compilation failed'
    $restoreSetup=Join-Path $capsule $builds[1].installerName
    try {
        $null=Native-Record $restoreSetup $arguments
        Require ((Digest $core) -ceq $restoreFixtureBinarySHA256 -and $null -eq (Get-PendingInstallFixtureValue)) 'Restoration fixture was not installed and verified'
        $stage='restoration-registration-drift'
        $configuration=Join-Path $capsule 'restoration-registration-drift.json'
        $fixtureRequest=@{mode='change-registration-before-success';expectedVersion=$builds[1].version;replacementVersion=$builds[0].version}
        [IO.File]::WriteAllText($configuration,($fixtureRequest | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        $script:restoreFixtureConfiguration=$configuration
        $treeBefore=Installed-TreeFingerprint;$registrationBefore=Registration-Fingerprint
        $beforeDrift=State-Snapshot
        $logPath=Join-Path $capsule 'restoration-registration-drift.log'
        $attempt=Native-Record (Join-Path $install 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG='+$logPath)) @(1)
        $script:restoreFixtureConfiguration=$null
        $readyPath=$configuration+'.ready';No-Reparse $readyPath
        Require ((Get-Item -LiteralPath $readyPath).Length -le 4096) 'Registration-change marker exceeds bounds'
        $ready=[IO.File]::ReadAllText($readyPath) | ConvertFrom-Json
        Require ($ready.mode -ceq $fixtureRequest.mode -and (Registration).version -ceq $builds[0].version) 'Restoration did not publish the owned registration change'
        No-Reparse $logPath
        Require ((Get-Item -LiteralPath $logPath).Length -le 4MB) 'Registration-change refusal log exceeds bounds'
        $log=[IO.File]::ReadAllText($logPath)
        Require ($log.Contains('AccessWeaver system restoration starts at the uninstall step.') -and
            $log.Contains('AccessWeaver installation registration or pending state changed during restoration.') -and
            -not $log.Contains('AccessWeaver system restoration failed; process result/error code:') -and
            -not $log.Contains('Removed all?')) 'Registration drift did not stop deletion after successful restoration'
        Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (State-Snapshot) -ceq $beforeDrift -and
            -not (Test-Path -LiteralPath $managed)) 'Post-restoration refusal changed installed or unrelated state'
        Assert-UserState
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        try {
            $key=$base.OpenSubKey($uninstallKey,$true)
            Require ($null -ne $key) 'Owned registration disappeared before repair'
            try {
                Require ($key.GetValue('DisplayVersion') -ceq $builds[0].version) 'Owned registration changed again'
                $key.SetValue('DisplayVersion',$builds[1].version,[Microsoft.Win32.RegistryValueKind]::String)
                Require ((Registration-Fingerprint $key) -ceq $registrationBefore) 'Post-restoration refusal changed other registration values'
            } finally {$key.Dispose()}
        } finally {$base.Dispose()}
        $postRestorationRefusal=@{exitCode=$attempt.result.exitCode;elapsedMilliseconds=$attempt.milliseconds;deadlineMilliseconds=180000;
            restorationSucceededBeforeRefusal=$true;registrationChangeObserved=$true;deletionRefused=$true;installedFileTreePreserved=$true;
            otherRegistrationValuesPreserved=$true;profilePreserved=$true;machineStateUnchanged=$true}
        foreach($case in @(
            @{name='failed-controller-descendant-cleaned';mode='exit-failure-with-child';contract=$false;deadline=180000;minimum=0},
            @{name='successful-controller-orphan-refused';mode='exit-success-with-child';contract=$true;deadline=180000;minimum=5000},
            @{name='stalled-controller-deadline-refused';mode='hang-with-child';contract=$false;deadline=360000;minimum=300000},
            @{name='terminated-uninstaller-owner-cleans-children';mode='owner-termination-with-child';contract=$false;deadline=180000;minimum=0;owner=$true}
        )){
            $stage='restoration-'+$case.name
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
        }
    } finally {
        $script:restoreFixtureConfiguration=$null
        $null=Native-Record $second $arguments
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
        $wrongLocation=Join-Path $capsule 'mismatched-uninstall-registration'
        foreach($case in @(
            @{key='InstallLocation';value=($wrongLocation+[char]92);name='refused-uninstall-registration';log='This uninstaller does not match the active AccessWeaver installation directory.'},
            @{key='DisplayVersion';value=$builds[0].version;name='refused-uninstall-registration-version';log='This uninstaller version does not match the active AccessWeaver registration.'},
            @{key='QuietUninstallString';value=('"'+$uninstaller+'" /VERYSILENT');name='refused-uninstall-registration-command';log='The registered AccessWeaver uninstall commands do not match the installed uninstaller.'}
        )){
            $stage=$case.name
            $originalValue=$key.GetValue($case.key)
            $originalKind=$key.GetValueKind($case.key)
            try {
                $key.SetValue($case.key,$case.value,[Microsoft.Win32.RegistryValueKind]::String)
                $registrationBefore=Registration-Fingerprint $key
                $registrationRefusalLog=Join-Path $capsule ($case.name+'.log')
                $registrationRefusal=Native-Record $uninstaller ($silent+@('/LOG='+$registrationRefusalLog)) @(1)
                No-Reparse $registrationRefusalLog
                $logFile=Get-Item -LiteralPath $registrationRefusalLog -ErrorAction Stop
                Require (-not $logFile.PSIsContainer -and $logFile.Length -gt 0 -and $logFile.Length -le 1MB) 'Uninstall registration refusal log is unavailable or exceeds its bound'
                $log=[IO.File]::ReadAllText($registrationRefusalLog)
                Require ($log.Contains($case.log)) 'Uninstall did not log the expected registration refusal'
                Require (-not (Test-Path -LiteralPath $managed -ErrorAction Stop) -and -not $log.Contains('AccessWeaver system restoration starts at the uninstall step.')) 'Uninstall reached machine restoration after the registration refusal'
                Require ((Installed-TreeFingerprint) -ceq $treeBefore -and (Registration-Fingerprint $key) -ceq $registrationBefore) 'Uninstall registration refusal changed installed files or registration'
                Assert-UserState
                Require ((State-Snapshot) -ceq $machineBeforeRemoval) 'Uninstall registration refusal changed observed machine state'
            } finally {$key.SetValue($case.key,$originalValue,$originalKind)}
            $observations+=,@{operation=$case.name;exitCode=$registrationRefusal.result.exitCode;
                elapsedMilliseconds=$registrationRefusal.milliseconds;deadlineMilliseconds=180000;preflightRefusalLogged=$true;
                restorationStateAbsent=$true;installedFileTreePreserved=$true;completeRegistrationPreserved=$true;
                profilePreserved=$true;machineStateUnchanged=$true}
        }
    } finally {if($key){$key.Dispose()};$base.Dispose()}
    Assert-Installed $builds[1]
    $stage='refused-uninstall'
    $binding=Open-WorkflowUninstallBinding $Architecture
    Require ($null -ne $binding) 'Installed product registration could not be resolved for workflow uninstall'
    try {
        Require ($binding.path -ieq $uninstaller -and $binding.sha256 -ieq $uninstallerHash -and $binding.dataSHA256 -ieq (Digest $uninstallData)) 'Workflow uninstall did not bind the actual registered uninstaller'
    } finally {Close-WorkflowUninstallBinding $binding}
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
    $stage='write-newer-profile'
    Create-UserProfile 'installer-rollback' 'Profile written before installer rollback'
    Require ($script:preservedProfiles.Count -eq 2) 'Expected profiles written by both fixture versions'
    $null=State-Checkpoint 'before-uninstall'
    $stage='uninstall'
    [IO.File]::Delete($request)
    $removed=Native-Record $uninstaller $silent
    Assert-InstallerRemoved $uninstaller
    $journalDirectory=Join-Path $managed 'logs'
    $journals=@(Get-ChildItem -LiteralPath $journalDirectory -File -Filter 'workflow-*.json')
    Require ($journals.Count -eq 1) 'Expected exactly one recovery journal from clean removal'
    $retainedJournal=$journals[0].FullName
    Assert-SuccessfulRestorationJournal $retainedJournal
    $retainedDigest=Digest $retainedJournal
    Assert-ManagedDetection 'after-uninstall' $builds[1] $false
    $after=State-Checkpoint 'after-uninstall'
    Require ($after -ceq $before) 'Installer lifecycle changed selected services, firewall rules or DNS configuration'
    $observations+=,@{operation='uninstall';exitCode=$removed.result.exitCode;elapsedMilliseconds=$removed.milliseconds;deadlineMilliseconds=180000;ownedPayloadAndRegistrationRemoved=$true;unrelatedStatePreserved=$true;recoveryJournalRetained=$true;legacyRequestAbsent=$true}
    $stage='restore-previous-version'
    No-Reparse $first
    $rollbackInstallerDigest=Digest $first
    Require ($rollbackInstallerDigest -ceq $builds[0].installerSHA256) 'Earlier installer changed before rollback'
    $rollbackLog=Join-Path $capsule 'previous-version-setup.log'
    $restored=Native-Record $first ($arguments+@('/LOG='+$rollbackLog))
    Assert-SetupCompletionReadback $rollbackLog
    Assert-Installed $builds[0]
    Assert-ManagedDetection 'after-rollback' $builds[0] $true
    Assert-ManagedDetection 'newer-version-after-rollback' $builds[1] $false
    foreach($fixtureProfile in $script:preservedProfiles){
        Assert-ProfileReadback $core $fixtureProfile
    }
    Assert-UserState
    Require ((Digest $retainedJournal) -ceq $retainedDigest) 'Rollback changed the first removal journal'
    Require ((Digest $marker) -ceq $markerHash) 'Rollback changed an unrelated installed-directory file'
    Require ((State-Checkpoint 'after-rollback') -ceq $before) 'Rollback changed selected services, firewall rules or DNS configuration'
    $observations+=,@{operation='restore-previous-version';exitCode=$restored.result.exitCode;elapsedMilliseconds=$restored.milliseconds;deadlineMilliseconds=180000;
        version=$builds[0].version;installerSHA256=$rollbackInstallerDigest;payloadSHA256=$builds[0].payloadSha256;
        setupCompletionVerified=$true;originalAndNewerProfilesReadBack=$true;originalRecoveryJournalPreserved=$true}

    $stage='uninstall-previous-version'
    $removedPrevious=Native-Record $uninstaller $silent
    Assert-InstallerRemoved $uninstaller
    Assert-ManagedDetection 'after-rollback-uninstall' $builds[0] $false
    Require ((Digest $retainedJournal) -ceq $retainedDigest) 'Removing the earlier version changed the first removal journal'
    $finalJournals=@(Get-ChildItem -LiteralPath $journalDirectory -File -Filter 'workflow-*.json')
    $newJournal=@($finalJournals | Where-Object {$_.FullName -cne $retainedJournal})
    Require ($finalJournals.Count -eq 2 -and $newJournal.Count -eq 1) 'Removing the earlier version did not retain a distinct recovery journal'
    Assert-SuccessfulRestorationJournal $newJournal[0].FullName
    Require ((State-Checkpoint 'after-rollback-uninstall') -ceq $before) 'Removing the earlier version changed selected services, firewall rules or DNS configuration'
    $observations+=,@{operation='uninstall-previous-version';exitCode=$removedPrevious.result.exitCode;elapsedMilliseconds=$removedPrevious.milliseconds;deadlineMilliseconds=180000;
        ownedPayloadAndRegistrationRemoved=$true;profilesPreserved=$true;bothRecoveryJournalsVerified=$true}

    $stage='cleanup'
    # Remove only the store containing the two successful fixture journals.
    $files=@(Get-ChildItem -LiteralPath $managed -File -Recurse -Force)
    Require ($files.Count -eq 2 -and -not @($files | Where-Object {
        $_.FullName -cne $retainedJournal -and $_.FullName -cne $newJournal[0].FullName
    }).Count) 'Unrelated recovery files must be retained for review'
    Remove-OwnedTree $managed $managedParent 'AccessWeaver'
    Remove-OwnedTree $install $programFiles $installLeaf
    Remove-OwnedTree $capsule $temporary $capsuleLeaf
    $complete=$true
} catch {$failureType=$_.Exception.GetType().FullName;$failureSourceLine=$_.InvocationInfo.ScriptLineNumber;if($null -ne $script:assertionFailureLine){$failureSourceLine=$script:assertionFailureLine}}
$eventDiagnostics=New-InstallerFirewallEventDiagnostic
if(-not $complete){$eventDiagnostics=Read-FirewallEventDiagnostic}
$originDiagnostics=[ordered]@{schemaVersion=1;source='captured-rule-properties';maxRecords=16;maxPropertyBytes=4096;records=@($script:firewallOriginObservations);truncated=$script:firewallOriginTruncated;unavailable=$script:firewallOriginUnavailable;extraNativeQueriesPerformed=$false;processOriginEstablished=$false}
$record=[ordered]@{schemaVersion=64;lateCompatibilityRefusal=$lateCompatibilityRefusal;nativeDocumentationRefusals=$nativeDocumentationRefusals;controllerDocumentationRefusals=$controllerDocumentationRefusals;uninstallLicenseRefusal=$uninstallLicenseRefusal;uninstallDataDetectionVerified=[bool]$uninstallDataDetectionVerified;uninstallDataRecoveryVerified=[bool]$uninstallDataRecoveryVerified;setupUpgradeBaseline=$setupUpgradeBaseline;setupUninstallRegistrationRefusal=$setupUninstallRegistrationRefusal;setupMarkerReplacement=$setupMarkerReplacement;postRestorationRefusal=$postRestorationRefusal;setupCompletionRefusal=$completionRefusal;setupDocumentationCompletionRefusal=$documentationCompletionRefusal;setupRetirementFlush=$setupRetirementFlush;setupCompletionReadbackVerified=$complete;installationPathRefusals=$pathRefusal;pendingMarkerAccess=$pendingMarkerAccess;architectureRefusal=$architectureRefusal;managedDetectionCases=$script:detectionCases;managedDetectionSourceSHA256=(Digest $detector);eventDiagnosticsSourceSHA256=(Digest (Join-Path $PSScriptRoot 'windows-installer-event-state.ps1'));firewallEventDiagnostics=$eventDiagnostics;nativeDiagnosticsSourceSHA256=(Digest (Join-Path $PSScriptRoot 'windows-installer-native-state.ps1'));lastNativeAttempt=$script:lastNativeAttempt;firewallOriginDiagnostics=$originDiagnostics;sourceCommit=$source;sourceRef=$sourceRef;runID=$run;runAttempt=$runAttempt;target=('windows/'+$Architecture);compilerVersion='6.7.1';stateObservations=$script:stateObservations;stateDiagnosticsSourceSHA256=(Digest (Join-Path $PSScriptRoot 'windows-installer-state.ps1'));builds=$builds;operations=$observations;lifecycleLockCases=$lifecycleLockCases;lifecycleLockFixtureSHA256=$lifecycleLockFixtureSHA256;productLockSHA256=$productLockSHA256;versionPolicyCases=$versionPolicyCases;registryReadCases=$registryReadCases;registryReadBufferBytes=514;restorationCases=$restorationCases;restorationLaunchCases=$restorationLaunchCases;restoreLaunchFixtureSHA256=$restoreLaunchFixtureSHA256;restorationOwnerCases=$restorationOwnerCases;restorationOwnerTerminationTested=$complete;restoreOwnerFixtureSHA256=$restoreOwnerFixtureSHA256;productRestoreSHA256=$productRestoreSHA256;restoreFixtureSourceSHA256=$restoreFixtureSourceSHA256;restoreFixtureBinarySHA256=$restoreFixtureBinarySHA256;restoreContractSourceSHA256=$restoreContractSourceSHA256;restoreContractBinarySHA256=$restoreContractBinarySHA256;registryViewCases=$registryViewCases;registryAccessCases=$registryAccessCases;registryFixtureSHA256=$registryFixtureSHA256;productRegistrySHA256=$productRegistrySHA256;versionContractCases=$versionContractCases;versionFixtureSHA256=$versionFixtureSHA256;passed=$complete;stage=$stage;failureType=$failureType;failureSourceLine=$failureSourceLine;assertionFailure=$script:assertionFailure;lastNative=$script:lastNative;actualUserProfilePreservationVerified=$complete;childEnvironmentSanitized=$true;selectedServiceFirewallDNSStateUnchanged=$complete;ownedFixturesRemoved=$complete;unsigned=$true;publisherSignatureVerified=$false;rebootTested=$false;downgradeTested=$complete;crashOrPowerLossTested=$false;vendorDriverOrRoutingQualified=$false;productionQualificationComplete=$false}
if($null -ne $script:uninstallBindingFailureCode){$record.uninstallBindingFailureCode=$script:uninstallBindingFailureCode}
if(-not $complete -and $null -ne $script:installerProtectionDiagnostic -and $script:installerProtectionDiagnosticStage -ceq $stage){$record.uninstallProtectionDiagnostic=$script:installerProtectionDiagnostic}
$record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding utf8
if(-not $complete){throw ('Disposable installer acceptance failed at '+$stage+' ('+$failureType+'); owned fixture retained on the disposable runner')}
Write-Output 'Clean install, upgrade, reinstall, refused in-place downgrade, recovery-aware removal and previous-version rollback passed.'
