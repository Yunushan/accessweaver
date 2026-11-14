# Run the actual Drover restore functions against inert files and mocked ACL/process boundaries.
$ErrorActionPreference='Stop'
$source=Join-Path (Split-Path -Parent $PSScriptRoot) 'internal\workflow\windows.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Windows workflow source failed parsing'}
foreach($name in @('No-Reparse','Install-Drover','Assert-RecordedServiceBinding','Recover-Operation','Rollback','Assert-DroverApplication','Set-DroverFile','Get-DroverFileHash','Get-DroverRestorePlan','Read-DroverManifest','Assert-DroverManifestUnchanged','Read-WorkflowRecoveryJournalBytes','Throw-WorkflowRecoveryJournalReadFailure','Get-WorkflowBytesSHA256','Restore-Drover')){
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
    if($script:changeOnStop){[IO.File]::AppendAllText($manifest,' ')}
    if($script:verifyPrepared){
        if(-not [IO.File]::Exists($manifest) -or $script:undo.Count -ne 1 -or
           $script:undo[0].kind -cne 'drover' -or
           $script:undo[0].manifestSHA256 -ine (Get-DroverFileHash $manifest) -or
           [IO.File]::Exists($first) -or [IO.File]::Exists($second)){throw 'Install changed files before publishing recovery'}
        if($script:breakInstall){[IO.File]::WriteAllText($ini,'changed input')}
    }
}
function Event([string]$text){$script:events++}
function Save-Journal {
    if([IO.File]::Exists($manifest)){throw 'Ownership was published before journaling'}
    $script:journaled=$true
}
function Ensure-Asset([string]$asset){
    if($asset -cne 'drover'){throw 'Unexpected fixture asset'}
    return $dll
}
function Discord-Directories {return $version}
function Read-WorkflowRecoveryJournal([string]$Path){return @{undo=@($script:savedRecovery)}}
function Remove-Item {
    param($LiteralPath,$ErrorAction)
    if($LiteralPath -ieq $second -and $script:denySecond){throw 'Synthetic failed removal'}
    if($LiteralPath -ine $first -and $LiteralPath -ine $second -and $LiteralPath -ine $manifest){throw 'Unexpected fixture mutation'}
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
$application=Join-Path $version 'Discord.exe'
$first=Join-Path $version 'version.dll'
$second=Join-Path $version 'drover.ini'
$backup=Join-Path $backups ('a'*32)
$assets=Join-Path $root 'components'
$dll=Join-Path $assets 'fixture.dll'
$ini=Join-Path $assets 'drover.ini'
$files=@($application,$first,$second,$backup,$manifest,$dll,$ini)
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

    foreach($broken in @([byte[]]@(0xff),[byte[]]::new(1MB+1))){
        [IO.File]::WriteAllBytes($manifest,$broken)
        Assert-Refused
        Require ($script:stops -eq 0 -and (Get-DroverFileHash $first) -ceq $installed) 'Invalid ownership bytes reached restoration'
    }

    Write-Manifest $records
    $priorHash=Get-DroverFileHash $manifest
    $script:changeOnStop=$true
    Assert-Refused
    Require ($script:stops -eq 1 -and (Get-DroverFileHash $manifest) -cne $priorHash -and
        (Get-DroverFileHash $first) -ceq $installed -and
        (Get-DroverFileHash $second) -ceq $installedINI -and $script:events -eq 0) 'Ownership edit during process stop reached file mutation'
    $script:changeOnStop=$false
    $script:stops=0
    Write-Manifest $records

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

    foreach($path in @($version,$assets)){[void][IO.Directory]::CreateDirectory($path)}
    [IO.File]::WriteAllText($application,'original Discord executable')
    [IO.File]::WriteAllText($dll,'new DLL')
    [IO.File]::WriteAllText($ini,'new INI')
    $script:undo=[Collections.Generic.List[object]]::new()
    $script:verifyPrepared=$true
    $script:breakInstall=$true
    $script:journaled=$false
    $failed=$false
    try {Install-Drover}catch{
        if($_.Exception.Message -cne 'Drover source changed before publication'){throw}
        $failed=$true
    }
    Require ($failed -and $script:journaled -and [IO.File]::Exists($first) -and
             -not [IO.File]::Exists($second) -and [IO.File]::Exists($manifest)) 'Partial install could not be identified'
    $oldDigest=$script:undo[0].manifestSHA256
    $manifestJSON=[IO.File]::ReadAllText($manifest)
    Require ($manifestJSON -notmatch '"originalHash"\s*:\s*\{') 'Absent original hash did not serialize as JSON null'
    $script:verifyPrepared=$false
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 0 -and -not [IO.File]::Exists($first) -and
             -not [IO.File]::Exists($manifest)) 'Digest-bound rollback did not restore the incomplete install'

    [IO.File]::WriteAllText($ini,'new INI')
    $script:undo.Clear()
    $script:breakInstall=$false
    $script:verifyPrepared=$true
    Install-Drover
    $script:verifyPrepared=$false
    Require ([IO.File]::Exists($first) -and [IO.File]::Exists($second)) 'Complete install did not publish both files'
    $script:undo.Clear()
    $script:undo.Add(@{kind='drover';manifestSHA256=$oldDigest})
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and [IO.File]::Exists($manifest) -and
             [IO.File]::Exists($first) -and [IO.File]::Exists($second)) 'Stale rollback changed the current installation'
    $script:savedRecovery=@(
        @{kind='drover';manifestSHA256=$oldDigest},
        @{kind='service';name='AccessWeaver-byedpi'}
    )
    function Stop-Service {throw 'Stale explicit recovery reached service mutation'}
    $r=@{journalId=('workflow-'+('a'*32)+'.json')}
    $refused=$false
    try {Recover-Operation}catch{$refused=$_.Exception.Message -ceq 'Drover recovery journal differs from the current ownership record'}
    Require ($refused -and $script:undo.Count -eq 1 -and [IO.File]::Exists($first) -and
             [IO.File]::Exists($second)) 'Stale explicit recovery reached rollback'
    [IO.File]::WriteAllText($application,'replacement Discord executable')
    $before=$script:stops
    Assert-Refused
    Require ($script:stops -eq $before -and [IO.File]::Exists($manifest) -and
             [IO.File]::Exists($first) -and [IO.File]::Exists($second)) 'Changed application allowed recovery mutation'
    [IO.File]::Delete($application)
    Assert-Refused
    Require ($script:stops -eq $before -and [IO.File]::Exists($manifest) -and
             [IO.File]::Exists($first) -and [IO.File]::Exists($second)) 'Incomplete version directory allowed recovery mutation'
    [IO.File]::WriteAllText($application,'original Discord executable')
    Restore-Drover
    Require (-not [IO.File]::Exists($manifest) -and -not [IO.File]::Exists($first) -and
             -not [IO.File]::Exists($second)) 'Normal removal could not restore the latest installation'

    [IO.File]::WriteAllText($second,'installed INI')
    Write-Manifest @($records[1])
    Restore-Drover
    Require (-not [IO.File]::Exists($second) -and -not [IO.File]::Exists($manifest)) 'Single-entry ownership array did not restore'

    $legacy=@{path=$second;backup=$null;installedHash=$installedINI;originalHash=[pscustomobject]@{unexpected=$true};
        applicationSHA256=(Get-DroverFileHash $application);deploymentID=('a'*32)}
    [IO.File]::WriteAllText($second,'installed INI')
    Write-Manifest @($legacy)
    Assert-Refused
    Require ([IO.File]::Exists($second) -and [IO.File]::Exists($manifest)) 'Malformed original hash changed recovery state'
    $legacy.originalHash=[pscustomobject]@{}
    Write-Manifest @($legacy)
    Restore-Drover
    Require (-not [IO.File]::Exists($second) -and -not [IO.File]::Exists($manifest)) 'Stock-shell legacy ownership record could not restore'

    $script:undo.Clear()
    Install-Drover
    foreach($path in @($application,$first,$second)){[IO.File]::Delete($path)}
    [IO.Directory]::Delete($version)
    $before=$script:stops
    Restore-Drover
    Require (-not [IO.Directory]::Exists($version) -and -not [IO.File]::Exists($manifest) -and
             $script:stops -eq $before) 'Version removed after setup could not be retired safely'
} finally {
    $env:LOCALAPPDATA=$previous
    foreach($path in $files){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
    foreach($directory in @($version,(Split-Path -Parent $version),(Join-Path $temp 'user'),$profiles,$backups,$assets,$root,$temp)){
        if([IO.Directory]::Exists($directory)){[IO.Directory]::Delete($directory)}
    }
}
Write-Output 'Bounded Drover install and restoration scenarios passed.'
