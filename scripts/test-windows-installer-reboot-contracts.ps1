# Exercise the actual reboot evidence functions without installing or restarting anything.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-installer-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Reboot fixture failed parsing'}
foreach($name in @('Assert-LaterGuestBoot','Assert-RebootIdentity','Write-NewRebootEvidence')){
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
Assert-RebootIdentity $saved $expected
foreach($key in $saved.Keys){
    $changed=$saved.Clone()
    $changed[$key]='changed'
    Assert-Refused {Assert-RebootIdentity $changed $expected}
}
$path=[IO.Path]::Combine([IO.Path]::GetTempPath(),('accessweaver-reboot-'+[guid]::NewGuid().ToString('N')+'.json'))
try {
    Write-NewRebootEvidence $path $saved
    $bytes=[IO.File]::ReadAllText($path)
    Assert-RebootIdentity ($bytes|ConvertFrom-Json) $expected
    Assert-Refused {Write-NewRebootEvidence $path @{changed=$true}}
    if([IO.File]::ReadAllText($path) -cne $bytes){throw 'Existing reboot evidence was overwritten'}
} finally {[IO.File]::Delete($path)}
Write-Output 'Installer reboot identity, time ordering and exclusive publication checks passed.'
