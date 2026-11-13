# Exercise the real journal dispatcher on inert snapshot files and mocked mutation boundaries.
$ErrorActionPreference='Stop'
$path=Join-Path (Split-Path -Parent $PSScriptRoot) 'internal\workflow\windows.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS journal source failed parsing'}
foreach($name in @('No-Reparse','Confirm-DNSRecoverySnapshot','Recover-Operation','Rollback')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected one DNS journal function'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Require([bool]$Condition,[string]$Failure){if(-not $Condition){throw $Failure}}
function Read-WorkflowRecoveryJournal {return @{undo=$script:saved}}
function Save-Journal {$script:journalWrites++}
function Event {}
function Stop-Service {throw 'Stale journal reached service mutation'}
function Restore-DNS {
    $script:restores++
    [IO.File]::Delete($snapshot)
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('aw-dns-journal-'+[guid]::NewGuid().ToString('N'))
$profiles=Join-Path $root 'profiles'
[void][IO.Directory]::CreateDirectory($profiles)
$snapshot=Join-Path $profiles 'dns-original.json'
$r=@{journalId=('workflow-'+('a'*32)+'.json')}
$script:undo=[Collections.Generic.List[object]]::new()
$script:journalWrites=0
$script:restores=0
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
} finally {
    [IO.File]::Delete($snapshot)
    [IO.Directory]::Delete($profiles)
    [IO.Directory]::Delete($root)
}
Write-Output 'Six DNS journal binding and rollback checks passed.'
