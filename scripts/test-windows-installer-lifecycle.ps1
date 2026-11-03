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
$tokens=$null;$issues=$null
$workflow=Join-Path $project 'internal\workflow\windows.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($workflow,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Product workflow parse failed'}
foreach($name in @('No-Reparse','Quote-Arg','Native-Argument','New-ToolCapture','Receive-ToolCapture','Wait-ToolCapture','Stop-ToolTreeWithHelper','Stop-ToolTree','Run-Tool','Native','Get-DriverServiceControllers','Get-ServiceInspection')){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Expected one fixed product process/inspection helper'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Require([bool]$ok,[string]$message){if(-not $ok){$script:assertionFailure=$message;throw $message}}
function Digest([string]$path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
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
foreach($hive in @([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryHive]::CurrentUser)){
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view);$key=$null
        try {$key=$base.OpenSubKey($uninstallKey);Require ($null -eq $key) 'An existing product registration must never be used by this fixture'} finally {if($key){$key.Dispose()};$base.Dispose()}
    }
}
Require (-not (Test-Path -LiteralPath $managed) -and -not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\AccessWeaver')) 'An existing managed installation must never be used by this fixture'
Require (-not (Test-Path -LiteralPath $install) -and -not (Test-Path -LiteralPath $capsule) -and -not (Test-Path -LiteralPath (Join-Path $programFiles 'AccessWeaver'))) 'Fixture and default product destinations must be new'
[void][IO.Directory]::CreateDirectory($capsule)
$root=$capsule;$profile=Join-Path $capsule 'user';$privateTemp=Join-Path $capsule 'process-temp'
foreach($dir in @($profile,$privateTemp,(Join-Path $profile 'roaming'),(Join-Path $profile 'local'))){[void][IO.Directory]::CreateDirectory($dir)}
$userMarker=Join-Path $profile 'user-state.json';[IO.File]::WriteAllText($userMarker,'{"preserve":"user-state"}')
$userHash=Digest $userMarker
$script:profileDataPath=$null;$script:profileDataHash=$null
$group='AccessWeaver acceptance '+$guid
$groupPaths=@((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) $group),(Join-Path ([Environment]::GetFolderPath('Programs')) $group))
foreach($path in $groupPaths){Require (-not (Test-Path -LiteralPath $path)) 'Fixture start-menu folder already exists'}
function Invoke-Isolated([string]$binary,[string[]]$arguments,[int[]]$codes=@(0)){
    $saved=@{};foreach($entry in Get-ChildItem Env:){$saved[$entry.Name]=$entry.Value}
    $system=[Environment]::SystemDirectory;$windows=Split-Path -Parent $system
    $allowed=@{SystemRoot=$windows;WINDIR=$windows;SystemDrive=[IO.Path]::GetPathRoot($system).TrimEnd('\');ComSpec=(Join-Path $system 'cmd.exe');PATH=($system+';'+$windows);PATHEXT='.COM;.EXE;.BAT;.CMD';TEMP=$privateTemp;TMP=$privateTemp;USERPROFILE=$profile;APPDATA=(Join-Path $profile 'roaming');LOCALAPPDATA=(Join-Path $profile 'local');ProgramData=$managedParent;ALLUSERSPROFILE=$managedParent}
    foreach($name in @('ProgramFiles','ProgramFiles(x86)','ProgramW6432','CommonProgramFiles','CommonProgramFiles(x86)','CommonProgramW6432')){if($saved[$name]){$allowed[$name]=$saved[$name]}}
    try {
        foreach($entry in Get-ChildItem Env:){[Environment]::SetEnvironmentVariable($entry.Name,$null,'Process')}
        foreach($name in $allowed.Keys){[Environment]::SetEnvironmentVariable($name,$allowed[$name],'Process')}
        return (Native $binary $arguments $codes -Secret -Timeout 180)
    } finally {
        foreach($entry in Get-ChildItem Env:){[Environment]::SetEnvironmentVariable($entry.Name,$null,'Process')}
        foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
    }
}
function Native-Record([string]$binary,[string[]]$arguments,[int[]]$codes=@(0)){
    $clock=[Diagnostics.Stopwatch]::StartNew();$r=Invoke-Isolated $binary $arguments ((0..255)+@(3010,1641));$clock.Stop()
    $script:lastNative=@{file=[IO.Path]::GetFileName($binary);exitCode=$r.exitCode;outputComplete=$r.outputComplete}
    Require ($codes -contains $r.exitCode) 'Installer operation returned an unexpected exit code'
    Require $r.outputComplete 'Native installer process left incomplete output capture'
    return @{result=$r;milliseconds=$clock.ElapsedMilliseconds}
}
function State-Snapshot {
    $inspection=Get-ServiceInspection;Require ($null -eq $inspection.error) 'Service inspection was incomplete'
    $services=@($inspection.services | Where-Object {$_.name -match '^(AccessWeaver-|WinDivert|NDISRD|wiresock)'} | Sort-Object name)
    $firewall=@(Get-NetFirewallRule -ErrorAction Stop | Sort-Object Name | Select-Object Name,Enabled,Direction,Action)
    $dns=@(Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    return (ConvertTo-Json -InputObject @{services=$services;firewall=$firewall;dns=$dns} -Depth 8 -Compress)
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
function Registration-Fingerprint {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($uninstallKey);Require ($null -ne $key) 'Installed fixture registration disappeared'
        $names=@($key.GetValueNames() | Sort-Object)
        Require ($names.Count -le 256) 'Installer registration exceeds fixture bounds'
        $values=@($names | ForEach-Object {[ordered]@{name=$_;kind=[string]$key.GetValueKind($_);data=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}})
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $values -Depth 6 -Compress))
        $hash=[Security.Cryptography.SHA256]::Create()
        try {return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
    } finally {if($key){$key.Dispose()};$base.Dispose()}
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
$reportDirectory=Join-Path $project 'build\installer-lifecycle-checks';[void][IO.Directory]::CreateDirectory($reportDirectory)
$reportPath=Join-Path $reportDirectory ($Architecture+'.json')
$stage='compile';$failureType=$null;$script:assertionFailure=$null;$script:lastNative=$null;$complete=$false;$builds=@();$observations=@();$versionPolicyCases=@();$versionContractCases=0;$versionFixtureSHA256=$null
try {
    foreach($version in @('0.1.0-alpha','0.1.1-alpha')){
        $null=@(& (Join-Path $PSScriptRoot 'test-windows-installer.ps1') -ExpectedCompilerVersion '6.7.1' -TargetArch $Architecture -Version $version)
        $evidence=Join-Path $project ('build\installer-checks\'+$Architecture)
        $b=Get-Content -LiteralPath (Join-Path $evidence 'compiler-artifact.json') -Raw | ConvertFrom-Json
        Require ($b.sourceCommit -ceq $source -and $b.payloadBuild.sourceState -ceq 'clean' -and $b.payloadBuild.version -ceq $version -and $b.compilerVersion -ceq '6.7.1' -and $b.unsigned) 'Compiler evidence differs from the requested candidate'
        $builds+=,@{version=$version;installerName=$b.installerName;installerSHA256=$b.installerSha256;installerBytes=$b.installerBytes;payloadSha256=$b.payloadSha256;payloadBuild=$b.payloadBuild;compilerSHA256=$b.compilerSha256;preprocessedSetupSHA256=$b.preprocessedSetupSha256;identityFileSHA256=(Digest (Join-Path $evidence 'payload-BUILD-INFO.json'))}
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
    $stage='baseline';$before=State-Snapshot
    Require (-not @(Get-Service -Name 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count) 'Existing product services are outside this fixture'
    Require (-not @(Get-NetFirewallRule -Name 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count) 'Existing product firewall rules are outside this fixture'
    $arguments=@('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/RESTARTEXITCODE=3010','/NOCLOSEAPPLICATIONS','/NORESTARTAPPLICATIONS','/NOICONS',('/DIR='+$install),('/GROUP='+$group))
    $stage='install';$first=Join-Path $project ('build\'+$builds[0].installerName)
    Require ((Digest $first) -ceq $builds[0].installerSHA256) 'Installer changed after compilation'
    $installed=Native-Record $first $arguments;Assert-Installed $builds[0];Create-UserProfile
    $marker=Join-Path $install 'unrelated-preserve.txt';[IO.File]::WriteAllText($marker,'unrelated-existing-file');$markerHash=Digest $marker
    $observations+=,@{operation='install';exitCode=$installed.result.exitCode;elapsedMilliseconds=$installed.milliseconds;deadlineMilliseconds=180000;payloadAndRegistrationVerified=$true}
    $stage='upgrade';$second=Join-Path $project ('build\'+$builds[1].installerName)
    Require ((Digest $second) -ceq $builds[1].installerSHA256) 'Upgrade installer changed after compilation'
    $upgraded=Native-Record $second $arguments;Assert-Installed $builds[1]
    Require ((Digest $marker) -ceq $markerHash) 'Upgrade changed an unrelated installed-directory file'
    $observations+=,@{operation='upgrade';exitCode=$upgraded.result.exitCode;elapsedMilliseconds=$upgraded.milliseconds;deadlineMilliseconds=180000;payloadAndRegistrationVerified=$true;unrelatedStatePreserved=$true}
    $stage='reinstall'
    $reinstalled=Native-Record $second $arguments;Assert-Installed $builds[1]
    Require ((Digest $marker) -ceq $markerHash) 'Reinstall changed an unrelated installed-directory file'
    $observations+=,@{operation='reinstall';exitCode=$reinstalled.result.exitCode;elapsedMilliseconds=$reinstalled.milliseconds;deadlineMilliseconds=180000;payloadAndRegistrationVerified=$true;unrelatedStatePreserved=$true}
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
    $stage='refused-uninstall'
    $uninstaller=Join-Path $install 'unins000.exe';No-Reparse $uninstaller;$uninstallerHash=Digest $uninstaller
    $request=Join-Path $install 'uninstall-system.json';$original=[IO.File]::ReadAllBytes($request)
    $silent=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
    try {
        [IO.File]::WriteAllText($request,'{"action":')
        $refused=Native-Record $uninstaller $silent (0..255)
        Require ($refused.result.exitCode -ne 0) 'Uninstaller reported success after restoration input was rejected'
        Assert-Installed $builds[1]
        Require ((Digest $uninstaller) -ceq $uninstallerHash -and (Digest $marker) -ceq $markerHash) 'Refused uninstall changed owned or unrelated files'
        Require (-not (Test-Path -LiteralPath $managed)) 'Rejected restore input unexpectedly created machine recovery state'
    } finally {if(Test-Path -LiteralPath $request){No-Reparse $request;[IO.File]::WriteAllBytes($request,$original)}}
    $observations+=,@{operation='refused-uninstall';exitCode=$refused.result.exitCode;elapsedMilliseconds=$refused.milliseconds;deadlineMilliseconds=180000;controllerAndRegistrationRetained=$true;unrelatedStatePreserved=$true}
    $stage='uninstall';$removed=Native-Record $uninstaller $silent
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
    Require ((State-Snapshot) -ceq $before) 'Installer lifecycle changed selected services, firewall rules or DNS configuration'
    $observations+=,@{operation='uninstall';exitCode=$removed.result.exitCode;elapsedMilliseconds=$removed.milliseconds;deadlineMilliseconds=180000;ownedPayloadAndRegistrationRemoved=$true;unrelatedStatePreserved=$true;recoveryJournalRetained=$true}
    $stage='cleanup'
    # Only the known successful journal may remain in the newly created store.
    $files=@(Get-ChildItem -LiteralPath $managed -File -Recurse -Force)
    Require ($files.Count -eq 1 -and $files[0].FullName -ceq $journals[0].FullName) 'Unrelated recovery files must be retained for review'
    Remove-OwnedTree $managed $managedParent 'AccessWeaver'
    Remove-OwnedTree $install $programFiles $installLeaf
    Remove-OwnedTree $capsule $temporary $capsuleLeaf
    $complete=$true
} catch {$failureType=$_.Exception.GetType().FullName}
$record=[ordered]@{schemaVersion=2;sourceCommit=$source;sourceRef=$sourceRef;runID=$run;target=('windows/'+$Architecture);compilerVersion='6.7.1';builds=$builds;operations=$observations;versionPolicyCases=$versionPolicyCases;versionContractCases=$versionContractCases;versionFixtureSHA256=$versionFixtureSHA256;passed=$complete;stage=$stage;failureType=$failureType;assertionFailure=$script:assertionFailure;lastNative=$script:lastNative;actualUserProfilePreservationVerified=$complete;childEnvironmentSanitized=$true;selectedServiceFirewallDNSStateUnchanged=$complete;ownedFixturesRemoved=$complete;unsigned=$true;publisherSignatureVerified=$false;rebootTested=$false;downgradeTested=$complete;crashOrPowerLossTested=$false;vendorDriverOrRoutingQualified=$false;productionQualificationComplete=$false}
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
if(-not $complete){throw ('Disposable installer acceptance failed at '+$stage+' ('+$failureType+'); owned fixture retained on the disposable runner')}
Write-Output 'Actual clean install, upgrade, reinstall, refused downgrade, refused restoration/uninstall and successful recovery-aware uninstall passed; public scoped evidence retained.'
