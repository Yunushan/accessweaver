# Exercise the actual reboot evidence functions without installing or restarting anything.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-installer-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Reboot fixture failed parsing'}
foreach($name in @('Assert-LaterGuestBoot','Assert-RebootIdentity','Write-NewRebootEvidence','Invoke-ApprovedInstaller','Get-RebootMetadataDigest','Get-RebootInstalledTreeDigest','Get-RebootRegistrationFingerprint','Assert-RebootInstalledState','Assert-RebootPackageRemoved')){
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
    schemaVersion=2;runID=('b'*32);architecture='amd64';version='1.0.0';
    setupSHA256=$pin;payloadSHA256=$pin;publisherSHA256=$pin;guestID='10000000-2000-3000-4000-000000000005';
    detectorSHA256=$pin;fixtureSHA256=$pin;commonSHA256=$pin;publisherVerifierSHA256=$pin
}
$saved=$expected.Clone()
$saved.uninstallerSHA256=$pin
$saved.setupExitCode=0
$saved.installedTreeSHA256=('b'*64)
$saved.registrationSHA256=('c'*64)
Assert-RebootIdentity $saved $expected
foreach($key in $saved.Keys){
    $changed=$saved.Clone()
    $changed[$key]='changed'
    Assert-Refused {Assert-RebootIdentity $changed $expected}
}
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
    if($Path -cne $tree){throw 'Unexpected fixture tree root'}
}
function Get-RebootDigest([string]$Path,[switch]$AllowEmpty){
    if($Path -cnotin @($payload,$notice)){throw 'Unexpected fixture file digest'}
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
[void][IO.Directory]::CreateDirectory($root)
$tree=Join-Path $root 'installed'
$sub=Join-Path $tree 'notices'
$payload=Join-Path $tree 'accessweaver.exe'
$notice=Join-Path $sub 'NOTICE.txt'
try {
    Assert-RebootPackageRemoved $tree
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
        $code=Invoke-ApprovedInstaller 'inert.exe' @('/NORESTART') -AllowRestartRequired:$test.allow
        $accepted=$true
    }catch{}
    $waitOrder=if($test.timely){'bounded'}else{'bounded,actual'}
    if($accepted -ne $test.accepted -or ($accepted -and $code -ne $test.code) -or
        -not $script:process.Disposed -or ($script:process.Waits -join ',') -cne $waitOrder){
        throw 'Installer fixture accepted an invalid exit or abandoned the owned process'
    }
}
Write-Output 'Installer reboot identity, installed tree, registration, process ownership and atomic publication checks passed.'
