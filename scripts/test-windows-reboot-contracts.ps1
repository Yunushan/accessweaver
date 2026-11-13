# Test reboot admission and result publication without touching DNS or rebooting a host.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS reboot fixture failed parsing'}
foreach($name in @('Assert-DNSRebootAdmission','Save-DNSRebootRecord','Get-DNSRebootJournalID','Assert-DNSRebootJournal')){
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
$journalId='workflow-'+('a'*32)+'.json'
$saved=@{schemaVersion=4;method='doh';guestID='synthetic';
    binarySHA256=('a'*64);fixtureSHA256=('b'*64);oracleSHA256=('c'*64);snapshotSHA256=('D'*64);
    journalId=$journalId;journalSHA256=('E'*64);boot='639303000000000000'}
$current=$saved.Clone()
$current.boot='639303000000000001'
Assert-DNSRebootAdmission $saved $current
foreach($field in @('guestID','binarySHA256','fixtureSHA256','oracleSHA256','snapshotSHA256','journalId','journalSHA256')){
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
$legacy.schemaVersion=3
Refuse {Assert-DNSRebootAdmission $legacy $current}
foreach($value in @('..\\'+$journalId,'workflow-'+('A'*32)+'.json','foreign.json')){
    $invalid=$saved.Clone();$invalid.journalId=$value
    $changed=$current.Clone();$changed.journalId=$value
    Refuse {Assert-DNSRebootAdmission $invalid $changed}
}
$log=[IO.Path]::Combine([IO.Path]::GetTempPath(),'synthetic-dns-logs')
$journal=[IO.Path]::Combine($log,$journalId)
if((Get-DNSRebootJournalID $journal $log) -cne $journalId){throw 'Exact protected journal name was not retained'}
Refuse {Get-DNSRebootJournalID $journalId $log}
Refuse {Get-DNSRebootJournalID ([IO.Path]::Combine($log,'different',$journalId)) $log}
Refuse {Get-DNSRebootJournalID ([IO.Path]::Combine($log,'..','synthetic-dns-logs',$journalId)) $log}
$dns=@{kind='dns';snapshotSHA256=$saved.snapshotSHA256}
$file=@{kind='file';path='synthetic config'}
Assert-DNSRebootJournal @{action='dns';state='succeeded';undo=@($dns,$file)} $saved.snapshotSHA256
foreach($invalid in @(
    @{action='install';state='succeeded';undo=@($dns)},
    @{action='dns';state='running';undo=@($dns)},
    @{action='dns';state='succeeded';undo=@($file)},
    @{action='dns';state='succeeded';undo=@($dns,$dns)},
    @{action='dns';state='succeeded';undo=@(@{kind='dns';snapshotSHA256=('F'*64)})}
)){Refuse {Assert-DNSRebootJournal $invalid $saved.snapshotSHA256}}

# Run only the actual post-verification cleanup block with synthetic state.
$nodes=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.Finally -and $node.Finally.Extent.Text.Contains("$"+'outcome.journalRecoveryAccepted=$true')
},$true))
if($nodes.Count -ne 1){throw 'DNS reboot recovery cleanup was not found'}
foreach($command in $nodes[0].Finally.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
    if($command.GetCommandName() -cnotin @('Invoke-TestWorkflow','Assert-DNSAcceptanceRestored','Read-DNSAcceptanceState',
            'Assert-RebootResolver','Test-Path','Get-Service','Save-DNSRebootRecord')){
        throw 'DNS reboot cleanup source has an unexpected command boundary'
    }
}
$block=$nodes[0].Finally.Extent.Text
$cleanup=[scriptblock]::Create($block.Substring(1,$block.Length-2))
function Invoke-TestWorkflow([hashtable]$Request) {
    $script:trace.Add($Request.action)
    switch($Request.action){
        'recover' {
            if($Request.journalId -cne $journalId){throw 'Unexpected journal identity'}
            if($script:failure -eq 'recover'){throw 'Synthetic recovery refusal'}
            if($script:failure -ne 'snapshot'){$script:snapshotPresent=$false}
        }
        'remove-all' {
            if($script:failure -eq 'remove'){throw 'Synthetic teardown refusal'}
            $script:snapshotPresent=$false
        }
        default {throw 'Unexpected workflow request'}
    }
}
function Assert-DNSAcceptanceRestored {
    if($script:trace.Count -eq 1 -and $script:failure -eq 'state'){throw 'Synthetic state mismatch'}
}
function Read-DNSAcceptanceState {return @{}}
function Assert-RebootResolver {
    if($script:trace.Count -eq 1 -and $script:failure -eq 'resolver'){throw 'Synthetic resolver failure'}
}
function Test-Path {param($LiteralPath,$ErrorAction);if($LiteralPath -cne $snapshot){throw 'Unexpected snapshot path'};return $script:snapshotPresent}
function Get-Service {param($Name,$ErrorAction);if($Name -cne 'AccessWeaver-*'){throw 'Unexpected service pattern'}}
$save=(Get-Command Save-DNSRebootRecord).ScriptBlock
function Save-DNSRebootRecord {param($Path,$Record);if($Path -cne $report){throw 'Unexpected report path'};$script:published=$Record}
$report='synthetic report';$snapshot='synthetic snapshot'
foreach($failure in @('none','recover','state','resolver','snapshot','remove')){
    $script:failure=$failure;$script:trace=[Collections.Generic.List[string]]::new()
    $script:snapshotPresent=$true;$script:published=$null
    $outcome=@{stage='complete';cleanupStage='not-started';journalRecoveryAccepted=$false;originalStateRestored=$false;originalResolverVerified=$false;snapshotRetired=$false;servicesRemoved=$false}
    & $cleanup
    $stage=switch($failure){
        'none' {'complete'}
        'recover' {'journal-recovery'}
        'state' {'original-state'}
        'resolver' {'original-resolver'}
        'snapshot' {'snapshot-retirement'}
        'remove' {'recovered'}
    }
    if($script:published.cleanupStage -cne $stage -or $script:published.passed -ne ($failure -ceq 'none') -or
        ($script:trace -join ',') -cne 'recover,remove-all'){
        throw 'DNS reboot cleanup failed to distinguish journal recovery from teardown'
    }
}
Set-Item Function:Save-DNSRebootRecord $save
$target=Join-Path ([IO.Path]::GetTempPath()) ('aw-dns-reboot-'+[guid]::NewGuid().ToString('N')+'.json')
try {
    Refuse {Save-DNSRebootRecord $target @{data=('x'*1MB)}}
    if([IO.File]::Exists($target)){throw 'Oversized evidence left a partial result'}
    Save-DNSRebootRecord $target $saved
    $before=[IO.File]::ReadAllText($target)
    Refuse {Save-DNSRebootRecord $target $current}
    if([IO.File]::ReadAllText($target) -cne $before){throw 'Replay overwrote existing evidence'}
} finally {[IO.File]::Delete($target)}
Write-Output 'DNS reboot admission, protected journal, recovery ordering and publication checks passed.'
