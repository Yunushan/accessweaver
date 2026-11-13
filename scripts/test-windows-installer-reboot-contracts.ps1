# Exercise the actual reboot evidence functions without installing or restarting anything.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-installer-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Reboot fixture failed parsing'}
foreach($name in @('Assert-LaterGuestBoot','Assert-RebootIdentity','Write-NewRebootEvidence','Invoke-ApprovedInstaller')){
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
    schemaVersion=1;runID=('b'*32);architecture='amd64';version='1.0.0';
    setupSHA256=$pin;payloadSHA256=$pin;publisherSHA256=$pin;guestID='10000000-2000-3000-4000-000000000005';
    detectorSHA256=$pin;fixtureSHA256=$pin;commonSHA256=$pin;publisherVerifierSHA256=$pin
}
$saved=$expected.Clone()
$saved.uninstallerSHA256=$pin
$saved.setupExitCode=0
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
Write-Output 'Installer reboot identity, time ordering, process ownership and atomic publication checks passed.'
