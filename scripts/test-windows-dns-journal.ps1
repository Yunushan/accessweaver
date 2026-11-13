# Exercise the real journal dispatcher on inert snapshot files and mocked mutation boundaries.
$ErrorActionPreference='Stop'
$path=Join-Path (Split-Path -Parent $PSScriptRoot) 'internal\workflow\windows.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS journal source failed parsing'}
foreach($name in @('No-Reparse','Publish-WorkflowFile','Get-WorkflowBytesSHA256','Confirm-DNSRecoverySnapshot','Recover-Operation','Rollback','Save-Journal')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected one DNS journal function'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Require([bool]$Condition,[string]$Failure){if(-not $Condition){throw $Failure}}
function Read-WorkflowRecoveryJournal {return @{undo=$script:saved}}
$saveJournal=(Get-Command Save-Journal).ScriptBlock
function Save-Journal {$script:journalWrites++}
function Event {}
function Stop-Service {
    param($Name,[switch]$Force,$ErrorAction)
    if($Name -cne 'AccessWeaver-dnscrypt' -or [IO.File]::Exists($snapshot)){throw 'Service stopped before DNS restoration'}
    $script:order.Add('stop')
}
function Native {
    param($Program,$Arguments,$Allowed)
    if($Arguments.Count -ne 2 -or ($Arguments -join ',') -cne 'delete,AccessWeaver-dnscrypt'){
        throw 'Unexpected native mutation'
    }
    $script:order.Add('delete')
}
function Restore-DNS {
    $script:restores++
    $script:order.Add('restore')
    if($script:failRestore){throw 'Synthetic DNS restore failure'}
    [IO.File]::Delete($snapshot)
    $script:dnsTouched=$false
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('aw-dns-journal-'+[guid]::NewGuid().ToString('N'))
$profiles=Join-Path $root 'profiles'
[void][IO.Directory]::CreateDirectory($profiles)
$snapshot=Join-Path $profiles 'dns-original.json'
$r=@{journalId=('workflow-'+('a'*32)+'.json')}
$script:undo=[Collections.Generic.List[object]]::new()
$script:journalWrites=0
$script:restores=0
$script:failRestore=$false
$script:dnsTouched=$false
$script:order=[Collections.Generic.List[string]]::new()
$originalSystemRoot=$env:SystemRoot
if(-not $env:SystemRoot){$env:SystemRoot=[IO.Path]::GetTempPath()}
$serviceConfig=Join-Path $root 'dnscrypt.toml'
$script:journalPath=Join-Path $root $r.journalId
$script:journalState='running'
$script:events=[Collections.Generic.List[string]]::new()
try {
    [IO.File]::WriteAllText($snapshot,'first synthetic snapshot')
    $first=(Get-FileHash -LiteralPath $snapshot).Hash
    [IO.File]::WriteAllText($snapshot,'second synthetic snapshot')
    $current=(Get-FileHash -LiteralPath $snapshot).Hash
    foreach($entry in @(@{kind='dns';snapshotSHA256=$first},@{kind='dns'},
                         @{kind='dns';snapshotSHA256=@($current,$current)},
                         @{kind='file';path=$snapshot})){
        $script:saved=@($entry,@{kind='service';name='AccessWeaver-byedpi'})
        $refused=$false
        try {Recover-Operation}catch{$refused=$_.Exception.Message -match '^DNS recovery journal '}
        Require ($refused -and $script:restores -eq 0 -and $script:journalWrites -eq 0 -and $script:undo.Count -eq 0) 'An unbound journal reached rollback'
    }
    $script:saved=@(@{kind='dns';snapshotSHA256=$current})
    Recover-Operation
    Require ($script:restores -eq 1 -and $script:journalWrites -eq 1 -and -not [IO.File]::Exists($snapshot)) 'Bound journal did not retire the snapshot'

    $script:saved=@(@{kind='file';path=$snapshot;backup='outside fixture'},@{kind='dns'})
    Recover-Operation
    Require ($script:restores -eq 1 -and $script:journalWrites -eq 2 -and -not [IO.File]::Exists($snapshot)) 'Legacy file undo tried to recreate the retired snapshot'

    $firstBytes=[Text.Encoding]::UTF8.GetBytes('first snapshot publication')
    $secondBytes=[Text.Encoding]::UTF8.GetBytes('second snapshot publication')
    Publish-WorkflowFile $snapshot $firstBytes
    Require (Confirm-DNSRecoverySnapshot (Get-WorkflowBytesSHA256 $firstBytes)) 'Initial snapshot publication changed its bytes'
    $next=Get-WorkflowBytesSHA256 $secondBytes
    $script:undo.Clear()
    $script:undo.Add(@{kind='dns';snapshotSHA256=$next})
    & $saveJournal
    $prepared=[IO.File]::ReadAllText($script:journalPath) | ConvertFrom-Json
    Require ($prepared.undo[0].snapshotSHA256 -ceq $next -and
        (Confirm-DNSRecoverySnapshot (Get-WorkflowBytesSHA256 $firstBytes))) 'Journal preparation changed the active snapshot'
    Publish-WorkflowFile $snapshot $secondBytes
    Require (Confirm-DNSRecoverySnapshot (Get-WorkflowBytesSHA256 $secondBytes)) 'Snapshot replacement changed its bytes'
    $script:journalState='succeeded'
    & $saveJournal
    $finished=[IO.File]::ReadAllText($script:journalPath) | ConvertFrom-Json
    Require ($finished.state -ceq 'succeeded' -and $finished.undo[0].snapshotSHA256 -ceq $next) 'Journal replacement lost the snapshot binding'
    Require ([IO.Directory]::GetFileSystemEntries($profiles).Length -eq 1 -and
        [IO.Directory]::GetFileSystemEntries($root).Length -eq 2) 'Successful publication left a sidecar'
    $directoryTarget=Join-Path $profiles 'directory-target'
    [void][IO.Directory]::CreateDirectory($directoryTarget)
    try {
        $refused=$false
        try {Publish-WorkflowFile $directoryTarget $firstBytes}catch{$refused=$true}
        Require ($refused -and [IO.Directory]::Exists($directoryTarget) -and
            [IO.Directory]::GetFileSystemEntries($profiles).Length -eq 2) 'Failed publication changed its target or left a sidecar'
    } finally {[IO.Directory]::Delete($directoryTarget)}

    [IO.File]::WriteAllText($serviceConfig,'inert resolver configuration')
    $configHash=(Get-FileHash -LiteralPath $serviceConfig).Hash
    $fileUndo=@{kind='file';path=$serviceConfig;expectedHash=$configHash}
    $serviceUndo=@{kind='service';name='AccessWeaver-dnscrypt'}
    $dnsUndo=@{kind='dns';snapshotSHA256=$next}
    $script:undo.Clear()
    foreach($entry in @($dnsUndo,$fileUndo,$serviceUndo)){$script:undo.Add($entry)}

    $script:order.Clear()
    $script:failRestore=$true
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and $rollback[0] -ceq 'Synthetic DNS restore failure' -and
        ($script:order -join ',') -ceq 'restore' -and [IO.File]::Exists($snapshot) -and
        (Get-FileHash -LiteralPath $serviceConfig).Hash -ceq $configHash) 'Failed DNS restoration tore down the resolver'

    $script:order.Clear()
    $script:failRestore=$false
    $dnsUndo.snapshotSHA256=$first
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and $script:order.Count -eq 0 -and [IO.File]::Exists($serviceConfig)) 'Mismatched DNS rollback tore down the resolver'

    $dnsUndo.snapshotSHA256=$next
    $script:undo.Add($dnsUndo)
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and $script:order.Count -eq 0 -and [IO.File]::Exists($serviceConfig)) 'Duplicate DNS rollback entries reached mutation'
    $script:undo.RemoveAt($script:undo.Count-1)

    [IO.File]::Delete($snapshot)
    $script:dnsTouched=$true
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and $script:order.Count -eq 0 -and [IO.File]::Exists($serviceConfig)) 'Missing active snapshot tore down the resolver'

    Publish-WorkflowFile $snapshot $secondBytes
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 0 -and ($script:order -join ',') -ceq 'restore,stop,delete' -and
        -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($serviceConfig)) 'Retry did not restore DNS before retiring the resolver'
} finally {
    $env:SystemRoot=$originalSystemRoot
    [IO.File]::Delete($serviceConfig)
    [IO.File]::Delete($snapshot)
    [IO.File]::Delete($script:journalPath)
    [IO.Directory]::Delete($profiles)
    [IO.Directory]::Delete($root)
}
Write-Output 'Seventeen DNS journal binding, rollback and publication checks passed.'
