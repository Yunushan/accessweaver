# Test reboot admission and result publication without touching DNS or rebooting a host.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS reboot fixture failed parsing'}
foreach($name in @('Assert-DNSRebootAdmission','Save-DNSRebootRecord')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected one DNS reboot evidence function'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Refuse([scriptblock]$Action){
    $rejected=$false
    try {& $Action}catch{$rejected=$true}
    if(-not $rejected){throw 'Invalid DNS reboot evidence was accepted'}
}
$saved=@{schemaVersion=3;method='doh';guestID='synthetic';
    binarySHA256=('a'*64);fixtureSHA256=('b'*64);oracleSHA256=('c'*64);snapshotSHA256=('d'*64);
    boot='639303000000000000'}
$current=$saved.Clone()
$current.boot='639303000000000001'
Assert-DNSRebootAdmission $saved $current
foreach($field in @('guestID','binarySHA256','fixtureSHA256','oracleSHA256','snapshotSHA256')){
    $changed=$current.Clone()
    $changed[$field]='different'
    Refuse {Assert-DNSRebootAdmission $saved $changed}
}
foreach($value in @($saved.boot,'639302000000000000','unknown')){
    $changed=$current.Clone()
    $changed.boot=$value
    Refuse {Assert-DNSRebootAdmission $saved $changed}
}
$legacy=$saved.Clone()
$legacy.schemaVersion=2
Refuse {Assert-DNSRebootAdmission $legacy $current}
$target=Join-Path ([IO.Path]::GetTempPath()) ('aw-dns-reboot-'+[guid]::NewGuid().ToString('N')+'.json')
try {
    Refuse {Save-DNSRebootRecord $target @{data=('x'*1MB)}}
    if([IO.File]::Exists($target)){throw 'Oversized evidence left a partial result'}
    Save-DNSRebootRecord $target $saved
    $before=[IO.File]::ReadAllText($target)
    Refuse {Save-DNSRebootRecord $target $current}
    if([IO.File]::ReadAllText($target) -cne $before){throw 'Replay overwrote existing evidence'}
} finally {[IO.File]::Delete($target)}
Write-Output 'Twelve DNS reboot admission and publication checks passed.'
