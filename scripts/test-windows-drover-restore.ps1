# Run the actual Drover restore functions against inert files and mocked ACL/process boundaries.
$ErrorActionPreference='Stop'
$source=Join-Path (Split-Path -Parent $PSScriptRoot) 'internal\workflow\windows.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Windows workflow source failed parsing'}
foreach($name in @('No-Reparse','Get-DroverFileHash','Get-DroverRestorePlan','Restore-Drover')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Missing Drover fixture function'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Assert-TrustedItem([string]$path){No-Reparse $path}
function Stop-AppProcesses([string]$variant){
    if($variant -cne 'discord'){throw 'Wrong client selected'}
    $script:stops++
}
function Event([string]$text){$script:events++}
function Remove-Item {
    param($LiteralPath,$ErrorAction)
    if($LiteralPath -ieq $second -and $script:denySecond){throw 'Synthetic failed removal'}
    if($LiteralPath -ine $second -and $LiteralPath -ine $manifest){throw 'Unexpected fixture mutation'}
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -ErrorAction Stop
}
function Require([bool]$condition,[string]$reason){if(-not $condition){throw $reason}}
function Assert-Refused {
    $refused=$false
    try {Restore-Drover}catch{$refused=$true}
    Require $refused 'An unsafe or failed restoration was accepted'
}
$temp=[IO.Path]::Combine([IO.Path]::GetTempPath(),('accessweaver-drover-'+[guid]::NewGuid().ToString('N')))
$previous=$env:LOCALAPPDATA
$env:LOCALAPPDATA=Join-Path $temp 'user'
$root=Join-Path $temp 'machine'
$version=Join-Path $env:LOCALAPPDATA 'Discord\app-1.0.0'
$profiles=Join-Path $root 'profiles'
$backups=Join-Path $root 'backups'
$manifest=Join-Path $profiles 'drover-owned.json'
$first=Join-Path $version 'version.dll'
$second=Join-Path $version 'drover.ini'
$backup=Join-Path $backups ('a'*32)
$files=@($first,$second,$backup,$manifest)
try {
    foreach($path in @($version,$profiles,$backups)){[void][IO.Directory]::CreateDirectory($path)}
    [IO.File]::WriteAllText($backup,'original DLL')
    [IO.File]::WriteAllText($first,'installed DLL')
    [IO.File]::WriteAllText($second,'installed INI')
    $original=Get-DroverFileHash $backup
    $installed=Get-DroverFileHash $first
    $installedINI=Get-DroverFileHash $second
    $records=@(
        @{path=$first;backup=$backup;installedHash=$installed;originalHash=$original},
        @{path=$second;backup=$null;installedHash=$installedINI;originalHash=$null}
    )
    function Write-Manifest($entries){[IO.File]::WriteAllText($manifest,(ConvertTo-Json -InputObject $entries))}
    Write-Manifest $records
    $script:stops=0;$script:events=0;$script:denySecond=$false;$script:externalEffectsPending=$false

    [IO.File]::WriteAllText($second,'foreign edit')
    Assert-Refused
    Require ($script:stops -eq 0 -and (Get-DroverFileHash $first) -ceq $installed -and
             [IO.File]::Exists($manifest) -and -not $script:externalEffectsPending) 'Late conflict caused side effects'
    [IO.File]::WriteAllText($second,'installed INI')
    Write-Manifest @($records[0],$records[0])
    Assert-Refused
    Require ($script:stops -eq 0 -and (Get-DroverFileHash $first) -ceq $installed) 'Duplicate path caused side effects'
    Write-Manifest @($records[0],@{path=(Join-Path $env:LOCALAPPDATA 'Unrelated\version.dll');installedHash=$installed})
    Assert-Refused
    Require ($script:stops -eq 0 -and (Get-DroverFileHash $first) -ceq $installed) 'Out-of-scope target caused side effects'
    Write-Manifest $records
    [IO.File]::WriteAllText($backup,'modified original')
    Assert-Refused
    Require ($script:stops -eq 0 -and (Get-DroverFileHash $first) -ceq $installed) 'Modified backup caused side effects'
    [IO.File]::WriteAllText($backup,'original DLL')

    $script:denySecond=$true
    Assert-Refused
    Require ($script:stops -eq 1 -and (Get-DroverFileHash $first) -ceq $original -and
             [IO.File]::Exists($manifest) -and $script:events -eq 0 -and $script:externalEffectsPending) 'Partial restore lost ownership evidence'
    $script:denySecond=$false
    Restore-Drover
    Require ($script:stops -eq 2 -and (Get-DroverFileHash $first) -ceq $original -and
             -not [IO.File]::Exists($second) -and -not [IO.File]::Exists($manifest) -and $script:events -eq 1) 'Retry could not finish verified restoration'

    [IO.File]::WriteAllText($first,'installed DLL')
    [void]$records[0].Remove('originalHash')
    Write-Manifest @($records[0])
    Restore-Drover
    Require ((Get-DroverFileHash $first) -ceq $original -and -not [IO.File]::Exists($manifest)) 'Existing ownership record could not be restored'
    [IO.File]::Delete($first)
    [IO.Directory]::Delete($version)
    Write-Manifest @($records[0])
    $before=$script:stops
    Restore-Drover
    Require (-not [IO.Directory]::Exists($version) -and [IO.File]::Exists($backup) -and
             -not [IO.File]::Exists($manifest) -and $script:stops -eq $before) 'Retired version was recreated or lost its backup'

} finally {
    $env:LOCALAPPDATA=$previous
    foreach($path in $files){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
    foreach($directory in @($version,(Split-Path -Parent $version),(Join-Path $temp 'user'),$profiles,$backups,$root,$temp)){
        if([IO.Directory]::Exists($directory)){[IO.Directory]::Delete($directory)}
    }
}
Write-Output 'Eight bounded Drover restoration scenarios passed.'
