# Exercise the actual reboot evidence functions without installing or restarting anything.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-installer-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Reboot fixture failed parsing'}
foreach($name in @('Assert-LaterGuestBoot','Assert-RebootIdentity','Get-RebootInstallMode','Test-RebootDowngradeInputs','Assert-RebootDowngradeLog','Assert-RebootUpgradeOrder','Write-NewRebootEvidence','Invoke-ApprovedInstaller','Get-RebootMetadataDigest','Get-RebootInstalledTreeDigest','Get-RebootRegistrationFingerprint','Save-RebootFixtureProfile','Assert-RebootUserProfile','Assert-RebootInstalledState','Assert-RebootPackageRemoved','Assert-InstalledDetection','Assert-InstalledPublisher')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected a single reboot fixture evidence function'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Assert-Refused([scriptblock]$Action){
    $refused=$false
    try {& $Action}catch{$refused=$true}
    if(-not $refused){throw 'Unexpected reboot evidence acceptance'}
}
Assert-LaterGuestBoot '639303000000000000' '639303000000000001'
Assert-Refused {Assert-LaterGuestBoot '639303000000000000' '639303000000000000'}
Assert-Refused {Assert-LaterGuestBoot '639303000000000001' '639303000000000000'}
Assert-Refused {Assert-LaterGuestBoot 'missing' '639303000000000000'}
$pin='a'*64
$expected=@{
    schemaVersion=6;runID=('b'*32);architecture='amd64';version='1.0.0';
    installMode='clean';previousVersion='';previousPayloadSHA256='';previousSetupSHA256='';previousPublisherSHA256='';userProfilePreservedThroughUpgrade=$false;
    setupSHA256=$pin;payloadSHA256=$pin;payloadSBOMSHA256=('f'*64);publisherSHA256=$pin;userSID='synthetic-user';guestID='10000000-2000-3000-4000-000000000005';
    detectorSHA256=$pin;fixtureSHA256=$pin;commonSHA256=$pin;publisherVerifierSHA256=$pin
}
$saved=$expected.Clone()
$saved.uninstallerSHA256=$pin
$saved.setupExitCode=0
$saved.installedTreeSHA256=('b'*64)
$saved.registrationSHA256=('c'*64)
$saved.userProfileSHA256=('d'*64)
Assert-RebootIdentity $saved $expected
foreach($key in $saved.Keys){
    $changed=$saved.Clone()
    $changed[$key]='changed'
    Assert-Refused {Assert-RebootIdentity $changed $expected}
}
$oldSchema=$saved.Clone();$oldSchema.schemaVersion=5
Assert-Refused {Assert-RebootIdentity $oldSchema $expected}

& {
    $previousExitCode=Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $hadExitCode=$null -ne $previousExitCode
    if($hadExitCode){$savedExitCode=$previousExitCode.Value}
    try {
        $Version='2.0.0';$PayloadSHA256='a'*64;$PayloadSBOMSHA256='b'*64
        $PublisherCertificateSHA256='c'*64;$Architecture='amd64';$controller='inert.exe'
        $trace=[Collections.Generic.List[object]]::new()
        $behavior=@{publisherCode=0;detectorCode=0;detected=$true}
        $detector={
            param($Version,$Architecture,$PayloadSHA256,$UninstallerSHA256,$PayloadSBOMSHA256)
            $trace.Add(@{version=$Version;arch=$Architecture;payload=$PayloadSHA256;uninstaller=$UninstallerSHA256;sbom=$PayloadSBOMSHA256})
            $global:LASTEXITCODE=$behavior.detectorCode
            if($behavior.detected){Write-Output 'AccessWeaver detected'}
        }
        $publisher={
            param($Artifact,$ArtifactSHA256,$PublisherCertificateSHA256)
            $trace.Add(@{artifact=$Artifact;sha256=$ArtifactSHA256;publisher=$PublisherCertificateSHA256})
            $global:LASTEXITCODE=$behavior.publisherCode
        }
        Assert-InstalledDetection $true -UninstallerDigest ('d'*64)
        Assert-InstalledPublisher
        if($trace[0].version -cne $Version -or $trace[0].arch -cne $Architecture -or
           $trace[0].payload -cne $PayloadSHA256 -or $trace[0].sbom -cne $PayloadSBOMSHA256 -or $trace[0].uninstaller -cne ('d'*64) -or
           $trace[1].artifact -cne $controller -or $trace[1].sha256 -cne $PayloadSHA256 -or $trace[1].publisher -cne $PublisherCertificateSHA256){
            throw 'Installed candidate pins did not reach verification'
        }
        Assert-InstalledDetection $true '1.0.0' ('e'*64) -CandidateSBOMSHA256 ''
        if($trace[2].version -cne '1.0.0' -or $trace[2].payload -cne ('e'*64) -or $trace[2].sbom){
            throw 'The previous installation received the current SBOM pin'
        }
        $behavior.detected=$false
        Assert-Refused {Assert-InstalledDetection $true}
        $behavior.detectorCode=1
        Assert-Refused {Assert-InstalledDetection $true}
        $behavior.publisherCode=1
        Assert-Refused {Assert-InstalledPublisher}
    } finally {
        # Actions uses LASTEXITCODE as the step status. Restore the caller's
        # value so simulated detector/publisher failures cannot fail the step.
        if($hadExitCode){$global:LASTEXITCODE=$savedExitCode}
        else{Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue}
    }
}
if((Get-RebootInstallMode '2.0.0' $pin '' '') -cne 'clean'){throw 'Clean baseline was refused'}
$priorDigest='e'*64
if((Get-RebootInstallMode '2.0.0' $pin '1.0.0' $priorDigest) -cne 'upgrade'){throw 'Pinned upgrade baseline was refused'}
Assert-Refused {Get-RebootInstallMode '2.0.0' $pin '1.0.0' ''}
Assert-Refused {Get-RebootInstallMode '2.0.0' $pin '' $priorDigest}
Assert-Refused {Get-RebootInstallMode '2.0.0' $pin '2.0.0' $priorDigest}
Assert-Refused {Get-RebootInstallMode '2.0.0' $pin '1.0.0' $pin}
$olderSetupDigest='f'*64
if(Test-RebootDowngradeInputs 'upgrade' $pin '' ''){throw 'Unrequested downgrade was enabled'}
if(-not (Test-RebootDowngradeInputs 'upgrade' $pin $olderSetupDigest $pin)){throw 'Approved downgrade fixture was refused'}
Assert-Refused {Test-RebootDowngradeInputs 'clean' $pin $olderSetupDigest $pin}
Assert-Refused {Test-RebootDowngradeInputs 'upgrade' $pin $pin $pin}
Assert-Refused {Test-RebootDowngradeInputs 'upgrade' $pin $olderSetupDigest ''}
Assert-Refused {Test-RebootDowngradeInputs 'upgrade' $pin '' $pin}
$comparison=@{currentVersion='1.0.0';version='2.0.0';updateAvailable=$true}
Assert-RebootUpgradeOrder $comparison '1.0.0' '2.0.0'
foreach($value in @($false,'true',0)){
    $comparison.updateAvailable=$value
    Assert-Refused {Assert-RebootUpgradeOrder $comparison '1.0.0' '2.0.0'}
}
$comparison.updateAvailable=$true
Assert-Refused {Assert-RebootUpgradeOrder $comparison '1.0.1' '2.0.0'}
Assert-Refused {Assert-RebootUpgradeOrder $comparison '1.0.0' '2.0.1'}
$upgradeExpected=$expected.Clone()
$upgradeExpected.installMode='upgrade';$upgradeExpected.previousVersion='0.9.0';$upgradeExpected.previousPayloadSHA256=$priorDigest
$upgraded=$saved.Clone()
$upgraded.installMode='upgrade';$upgraded.previousVersion='0.9.0';$upgraded.previousPayloadSHA256=$priorDigest
$upgraded.userProfilePreservedThroughUpgrade=$true
Assert-RebootIdentity $upgraded $upgradeExpected
$upgraded.previousSetupSHA256=$olderSetupDigest
$upgraded.previousPublisherSHA256=$pin
Assert-Refused {Assert-RebootIdentity $upgraded $upgradeExpected}
$upgradeExpected.previousSetupSHA256=$olderSetupDigest
$upgradeExpected.previousPublisherSHA256=$pin
Assert-RebootIdentity $upgraded $upgradeExpected
Assert-Refused {Assert-RebootIdentity $upgraded $expected}
$upgraded.userProfilePreservedThroughUpgrade=$false
Assert-Refused {Assert-RebootIdentity $upgraded $upgradeExpected}
$pending=$saved.Clone();$pending.setupExitCode=3010
Assert-RebootIdentity $pending $expected
foreach($code in @(-1,1,1641,'3010')){
    $pending.setupExitCode=$code
    Assert-Refused {Assert-RebootIdentity $pending $expected}
}
$root=[IO.Path]::Combine([IO.Path]::GetTempPath(),('accessweaver-reboot-'+[guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($root)
$path=Join-Path $root 'result.json'
try {
    Assert-Refused {Write-NewRebootEvidence $path @{oversized=('x'*8192)}}
    if([IO.Directory]::GetFileSystemEntries($root).Length -ne 0){throw 'Oversized publication left evidence'}
    Write-NewRebootEvidence $path $saved
    $bytes=[IO.File]::ReadAllText($path)
    Assert-RebootIdentity ($bytes|ConvertFrom-Json) $expected
    Assert-Refused {Write-NewRebootEvidence $path @{changed=$true}}
    if([IO.File]::ReadAllText($path) -cne $bytes){throw 'Existing reboot evidence was overwritten'}
    if([IO.Directory]::GetFileSystemEntries($root).Length -ne 1){throw 'Publication left a staging file'}
} finally {
    [IO.File]::Delete($path)
    [IO.Directory]::Delete($root)
}

Assert-RebootInstalledState $saved $saved.installedTreeSHA256 $saved.registrationSHA256
Assert-Refused {Assert-RebootInstalledState $saved ('d'*64) $saved.registrationSHA256}
Assert-Refused {Assert-RebootInstalledState $saved $saved.installedTreeSHA256 ('d'*64)}

$key=[pscustomobject]@{
    SubKeyCount=0;ValueCount=2;Names=@('Version','Install')
    Values=@{Version='1.0.0';Install='synthetic location'}
    Kinds=@{Version=[Microsoft.Win32.RegistryValueKind]::String;Install=[Microsoft.Win32.RegistryValueKind]::String}
}
$key | Add-Member ScriptMethod GetValueNames {return ,([string[]]$this.Names.Clone())}
$key | Add-Member ScriptMethod GetValueKind {param($Name);return $this.Kinds[$Name]}
$key | Add-Member ScriptMethod GetValue {
    param($Name,$Default,$Options)
    if($Options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames){throw 'Unexpected registry read options'}
    return $this.Values[$Name]
}
$fingerprint=Get-RebootRegistrationFingerprint $key
$key.Names=@('Install','Version')
if((Get-RebootRegistrationFingerprint $key) -cne $fingerprint){throw 'Registry enumeration order changed its fingerprint'}
$key.Values.Version='2.0.0'
if((Get-RebootRegistrationFingerprint $key) -ceq $fingerprint){throw 'Registration value change was missed'}
$key.Values.Version='1.0.0'
$key.Kinds.Install=[Microsoft.Win32.RegistryValueKind]::ExpandString
if((Get-RebootRegistrationFingerprint $key) -ceq $fingerprint){throw 'Registration value kind change was missed'}
$key.Values.Remove('Install')
Assert-Refused {Get-RebootRegistrationFingerprint $key}
Assert-Refused {Get-RebootRegistrationFingerprint $null}

# Only the owned, inert fixture tree can reach these path and digest boundaries.
function Assert-RebootPath([string]$Path){
    if($Path -cnotin @($tree,$log)){throw 'Unexpected fixture path'}
}
function Get-RebootDigest([string]$Path,[switch]$AllowEmpty){
    if($Path -cnotin @($payload,$notice)){throw 'Unexpected fixture file digest'}
    if(-not [IO.File]::Exists($Path)){throw 'Expected an existing fixture file'}
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
[void][IO.Directory]::CreateDirectory($root)
$tree=Join-Path $root 'installed'
$log=Join-Path $root 'downgrade.log'
$sub=Join-Path $tree 'notices'
$payload=Join-Path $tree 'accessweaver.exe'
$notice=Join-Path $sub 'NOTICE.txt'
try {
    Assert-RebootPackageRemoved $tree
    $policy='A newer AccessWeaver version is installed. Use a current or newer installer. This installer will not downgrade it.'
    [IO.File]::WriteAllText($log,"2026-11-13 12:34:56.789   $policy")
    Assert-RebootDowngradeLog $log
    foreach($invalid in @('', 'An unrelated installer initialization failed.', ('prefix '+$policy), ('x'*1MB+$policy))){
        [IO.File]::WriteAllText($log,$invalid)
        Assert-Refused {Assert-RebootDowngradeLog $log}
    }
    [void][IO.Directory]::CreateDirectory($sub)
    [IO.File]::WriteAllText($payload,'synthetic payload')
    [IO.File]::WriteAllText($notice,'original notice')
    $first=Get-RebootInstalledTreeDigest $tree
    if($first -cnotmatch '\A[a-f0-9]{64}\z' -or (Get-RebootInstalledTreeDigest $tree) -cne $first){
        throw 'Installed tree digest is not repeatable'
    }
    [IO.File]::WriteAllText($notice,'modified notice')
    if((Get-RebootInstalledTreeDigest $tree) -ceq $first){throw 'Changed package content was missed'}
    [IO.File]::WriteAllText($notice,'original notice')
    $extra=Join-Path $tree 'empty'
    [void][IO.Directory]::CreateDirectory($extra)
    try {
        if((Get-RebootInstalledTreeDigest $tree) -ceq $first){throw 'Added directory was missed'}
    } finally {[IO.Directory]::Delete($extra)}
    Assert-Refused {Assert-RebootPackageRemoved $tree}
    [IO.File]::Delete($payload)
    [IO.File]::Delete($notice)
    [IO.Directory]::Delete($sub)
    Assert-RebootPackageRemoved $tree
} finally {
    [IO.File]::Delete($log)
    if([IO.File]::Exists($payload)){[IO.File]::Delete($payload)}
    if([IO.Directory]::Exists($sub)){[IO.File]::Delete($notice);[IO.Directory]::Delete($sub)}
    if([IO.Directory]::Exists($tree)){[IO.Directory]::Delete($tree)}
    [IO.Directory]::Delete($root)
}

function Start-Process {
    [CmdletBinding()]param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru)
    if($FilePath -cne 'inert.exe' -or $WindowStyle -cne 'Hidden' -or -not $PassThru){
        throw 'Unexpected fixture process launch'
    }
    return $script:process
}
foreach($test in @(
    @{code=0;allow=$true;timely=$true;accepted=$true},
    @{code=0;allow=$false;timely=$true;accepted=$true},
    @{code=3010;allow=$true;timely=$true;accepted=$true},
    @{code=3010;allow=$false;timely=$true;accepted=$false},
    @{code=1641;allow=$true;timely=$true;accepted=$false},
    @{code=8;allow=$true;timely=$true;accepted=$false},
    @{code=1;allow=$false;expected=1;timely=$true;accepted=$true},
    @{code=0;allow=$false;expected=1;timely=$true;accepted=$false},
    @{code=2;allow=$false;expected=1;timely=$true;accepted=$false},
    @{code=0;allow=$true;timely=$false;accepted=$false}
)){
    $script:process=[pscustomobject]@{ExitCode=$test.code;Timely=$test.timely;Waits=@();Disposed=$false}
    $script:process | Add-Member ScriptMethod WaitForExit {
        param($Milliseconds)
        if($args.Count -ne 0 -or ($null -ne $Milliseconds -and $Milliseconds -ne 180000)){throw 'Unexpected fixture wait'}
        if($null -eq $Milliseconds){$this.Waits+=@('actual');return}
        $this.Waits+=@('bounded')
        return $this.Timely
    }
    $script:process | Add-Member ScriptMethod Dispose {
        $this.Disposed=$true
    }
    $code=$null;$accepted=$false
    try {
        $code=Invoke-ApprovedInstaller 'inert.exe' @('/NORESTART') -AllowRestartRequired:$test.allow -ExpectedExitCode ([int]$test.expected)
        $accepted=$true
    }catch{}
    $waitOrder=if($test.timely){'bounded'}else{'bounded,actual'}
    if($accepted -ne $test.accepted -or ($accepted -and $code -ne $test.code) -or
        -not $script:process.Disposed -or ($script:process.Waits -join ',') -cne $waitOrder){
        throw 'Installer fixture accepted an invalid exit or abandoned the owned process'
    }
}
$installer=(Get-Command Invoke-ApprovedInstaller).ScriptBlock
function Invoke-ApprovedInstaller {
    param($Path,$Arguments)
    if($Path -cne 'fixture-controller.exe' -or $Arguments.Count -ne 2 -or $Arguments[0] -cne 'import' -or
        $Arguments[1] -cne ('"'+$profileInput+'"') -or $env:ACCESSWEAVER_HOME -cne $fixtureStore){
        throw 'Profile import escaped its intended controller or user store'
    }
    $record=[IO.File]::ReadAllText($profileInput) | ConvertFrom-Json
    if($record.id -cne 'installer-reboot-synthetic' -or $record.version -ne 1 -or $record.engine -cne 'byedpi'){
        throw 'Expected fixed synthetic profile'
    }
    if($script:failImport){throw 'Synthetic import failed'}
    return 0
}
[void][IO.Directory]::CreateDirectory($root)
$fixtureStore=Join-Path $root 'user-store'
$profileInput=Join-Path $root 'profile-input.json'
$oldHome=$env:ACCESSWEAVER_HOME
try {
    $script:failImport=$false
    Save-RebootFixtureProfile 'fixture-controller.exe' $fixtureStore $profileInput 'installer-reboot-synthetic'
    if($env:ACCESSWEAVER_HOME -cne $oldHome){throw 'Profile import retained its temporary environment'}
    [IO.File]::Delete($profileInput)
    $script:failImport=$true
    Assert-Refused {Save-RebootFixtureProfile 'fixture-controller.exe' $fixtureStore $profileInput 'installer-reboot-synthetic'}
    if($env:ACCESSWEAVER_HOME -cne $oldHome){throw 'Failed profile import retained its temporary environment'}
    $notice=$profileInput
    $digest=Get-RebootDigest $profileInput
    Assert-RebootUserProfile $profileInput $digest
    [IO.File]::WriteAllText($profileInput,'changed profile')
    Assert-Refused {Assert-RebootUserProfile $profileInput $digest}
    [IO.File]::Delete($profileInput)
    Assert-Refused {Assert-RebootUserProfile $profileInput $digest}
} finally {
    $env:ACCESSWEAVER_HOME=$oldHome
    Set-Item Function:Invoke-ApprovedInstaller $installer
    [IO.File]::Delete($profileInput)
    [IO.Directory]::Delete($root)
}
Write-Output 'Installer reboot identity, upgrade and downgrade admission, package, registration, saved profile, process ownership and publication checks passed.'
