# Test reboot admission and result publication without touching DNS or rebooting a host.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS reboot fixture failed parsing'}
foreach($name in @('Assert-DNSRebootAdmission','Save-DNSRebootRecord','Get-DNSRebootJournalID','Assert-DNSRebootJournal',
        'Get-DNSRebootCoverage','Assert-DNSRebootConfigured','Assert-RebootResolver','Wait-DNSRebootObservation','Test-DNSRebootServicesRemoved')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected one DNS reboot evidence function'}
    if($name -cin @('Get-DNSRebootCoverage','Assert-DNSRebootConfigured','Assert-RebootResolver','Wait-DNSRebootObservation','Test-DNSRebootServicesRemoved')){
        foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
            $callback=$command.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and
                $command.CommandElements[0] -is [Management.Automation.Language.VariableExpressionAst] -and
                $command.CommandElements[0].VariablePath.UserPath -ceq 'Observe'
            if(-not $callback -and $command.GetCommandName() -cnotin @('Clear-DnsClientCache','Resolve-DnsName','Start-Sleep','Get-Service','ForEach-Object','Where-Object','Get-DNSAcceptanceIndex','Assert-DNSAcceptanceConfigured')){
                throw 'DNS reboot observation has an unexpected command boundary'
            }
        }
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Refuse([scriptblock]$Action){
    $rejected=$false
    try {& $Action}catch{$rejected=$true}
    if(-not $rejected){throw 'Invalid DNS reboot evidence was accepted'}
}
$journalId='workflow-'+('a'*32)+'.json'
$saved=@{schemaVersion=6;qualificationID=('a'*32);method='doh';guestID='synthetic';
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
$legacy.schemaVersion=5
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
$dns=@{kind='dns';snapshotSHA256=$saved.snapshotSHA256;snapshotActive=$true}
$file=@{kind='file';path='synthetic config'}
Assert-DNSRebootJournal @{action='dns';state='succeeded';undo=@($dns,$file)} $saved.snapshotSHA256
foreach($invalid in @(
    @{action='install';state='succeeded';undo=@($dns)},
    @{action='dns';state='running';undo=@($dns)},
    @{action='dns';state='succeeded';undo=@($file)},
    @{action='dns';state='succeeded';undo=@($dns,$dns)},
    @{action='dns';state='succeeded';undo=@(@{kind='dns';snapshotSHA256=('F'*64);snapshotActive=$true})},
    @{action='dns';state='succeeded';undo=@(@{kind='dns';snapshotSHA256=$saved.snapshotSHA256;snapshotActive=$false})}
)){Refuse {Assert-DNSRebootJournal $invalid $saved.snapshotSHA256}}

# The shared oracle definitions perform no host reads when imported.
. (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
& {
    $primary='00000000-0000-0000-0000-000000000001'
    $secondary='00000000-0000-0000-0000-000000000002'
    $primaryRow=@{guid=$primary;selected=$true;ipv4=@{mode='dhcp';servers=@()};ipv6=@{mode='static';servers=@('2001:db8::1')}}
    $secondaryRow=@{guid=$secondary;selected=$false;ipv4=@{mode='static';servers=@('192.0.2.1')};ipv6=@{mode='dhcp';servers=@()}}
    $baseline=@{schemaVersion=1;adapters=@($primaryRow,$secondaryRow);dohAvailable=$false;doh=@()}
    $coverage=Get-DNSRebootCoverage $baseline 'static-ipv6'
    if($coverage['static-ipv6'] -ne 1 -or $coverage['dhcp-ipv4'] -ne 1 -or
        $coverage['static-ipv4'] -ne 0 -or $coverage['dhcp-ipv6'] -ne 0){
        throw 'DNS reboot coverage must count only selected families'
    }
    foreach($missing in @('static-ipv4','dhcp-ipv6','invalid','')){
        Refuse {Get-DNSRebootCoverage $baseline $missing}
    }
    $configuredRow=$primaryRow.Clone()
    $configuredRow.ipv4=@{mode='static';servers=@('127.0.0.1')}
    $configuredRow.ipv6=@{mode='static';servers=@('::1')}
    $configured=$baseline.Clone();$configured.adapters=@($configuredRow,$secondaryRow)
    Assert-DNSRebootConfigured $baseline $configured 'dnscrypt'
    $secondaryRow.selected=$true
    Refuse {Assert-DNSRebootConfigured $baseline $configured 'dnscrypt'}
    $configuredRow.selected=$false
    $secondaryRow.selected=$false
    Refuse {Assert-DNSRebootConfigured $baseline $configured 'dnscrypt'}
    $secondaryRow.selected=$true
    Refuse {Assert-DNSRebootConfigured $baseline $configured 'dnscrypt'}
    $secondaryRow.selected=$false
    $configuredRow.selected=$true
    $configuredRow.ipv4=@{mode='static';servers=@('192.0.2.1')}
    Refuse {Assert-DNSRebootConfigured $baseline $configured 'dnscrypt'}
}

# Run the actual observation functions with no resolver or service access.
& {
    $state=@{flushes=0;queries=0;waits=0;attempts=0;cacheFails=$false;serviceFails=$false;services=@()}
    function Clear-DnsClientCache {
        [CmdletBinding()]param()
        if($ErrorActionPreference -ne 'Stop'){throw 'DNS cache clear must fail closed'}
        $state.flushes++
        if($state.cacheFails){throw 'Synthetic cache flush failure'}
    }
    function Resolve-DnsName {
        [CmdletBinding()]param($Name,$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout)
        $state.queries++
        if($Name -cne 'example.com.' -or $Type -cne 'A' -or -not $DnsOnly -or -not $NoHostsFile -or
           -not $QuickTimeout -or $ErrorActionPreference -ne 'Stop'){throw 'Unexpected ordinary DNS request'}
        $state.answers
    }
    function Get-Service {
        [CmdletBinding()]param()
        if($ErrorActionPreference -ne 'Stop' -or $state.serviceFails){throw 'Synthetic service inventory failure'}
        $state.services
    }
    function Start-Sleep {
        param($Seconds)
        if($Seconds -ne 1){throw 'Unexpected retry interval'}
        $state.waits++
    }
    $answer=@{Name='example.com.';Type='A';Section='Answer';IPAddress='192.0.2.15'}
    $state.answers=@([pscustomobject]$answer)
    Assert-RebootResolver
    foreach($invalid in @(
        @{Name='example.net.'},@{Type='AAAA'},@{Section='Additional'},@{IPAddress='2001:db8::1'},@{IPAddress='invalid'}
    )){
        $row=$answer.Clone()
        foreach($key in $invalid.Keys){$row[$key]=$invalid[$key]}
        $state.answers=@([pscustomobject]$row)
        Refuse {Assert-RebootResolver}
    }
    $state.answers=@()
    Refuse {Assert-RebootResolver}
    $state.cacheFails=$true
    Refuse {Assert-RebootResolver}
    if($state.flushes -ne 8 -or $state.queries -ne 7){throw 'Failed cache flush allowed a DNS query'}

    Wait-DNSRebootObservation {
        $state.attempts++
        if($state.attempts -eq 1){throw 'Synthetic automatic service startup delay'}
    }
    if($state.attempts -ne 2 -or $state.waits -ne 1){throw 'Automatic startup retry did not re-observe state'}
    Refuse {Wait-DNSRebootObservation {throw 'Synthetic persistent startup failure'} 0}
    if($state.waits -ne 1){throw 'Expired startup window accepted a further retry'}

    $state.services=@([pscustomobject]@{ServiceName='UnrelatedFixtureService'})
    if(-not (Test-DNSRebootServicesRemoved)){throw 'Unrelated service prevented verified cleanup'}
    $state.services+=@([pscustomobject]@{ServiceName='AccessWeaver-dnscrypt'})
    if(Test-DNSRebootServicesRemoved){throw 'Running or stopped AccessWeaver service was credited as absent'}
    $state.services=@([pscustomobject]@{ServiceName=$null})
    Refuse {Test-DNSRebootServicesRemoved}
    $state.services=@()
    Refuse {Test-DNSRebootServicesRemoved}
    $state.serviceFails=$true
    Refuse {Test-DNSRebootServicesRemoved}
}

# Run only the actual post-verification cleanup block with synthetic state.
$nodes=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.Finally -and $node.Finally.Extent.Text.Contains("$"+'outcome.journalRecoveryAccepted=$true')
},$true))
if($nodes.Count -ne 1){throw 'DNS reboot recovery cleanup was not found'}
foreach($command in $nodes[0].Finally.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
    if($command.GetCommandName() -cnotin @('Invoke-TestWorkflow','Assert-DNSAcceptanceRestored','Read-DNSAcceptanceState',
            'Assert-RebootResolver','Test-Path','Test-DNSRebootServicesRemoved','Save-DNSRebootRecord')){
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
function Test-DNSRebootServicesRemoved {
    if($script:failure -eq 'inventory'){throw 'Synthetic teardown inventory failure'}
    return $script:failure -ne 'service'
}
$save=(Get-Command Save-DNSRebootRecord).ScriptBlock
function Save-DNSRebootRecord {param($Path,$Record);if($Path -cne $report){throw 'Unexpected report path'};$script:published=$Record}
$report='synthetic report';$snapshot='synthetic snapshot'
foreach($failure in @('none','recover','state','resolver','snapshot','remove','inventory','service')){
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
        'inventory' {'recovered'}
        'service' {'recovered'}
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
# Exercise only the startup handoff functions against owned inert files.
$startupSource=Join-Path $PSScriptRoot 'vmware-reboot-resume.ps1'
$startup=[Management.Automation.Language.Parser]::ParseFile($startupSource,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS reboot startup failed parsing'}
$selected=@('Read-DNSRebootReport','Assert-DNSRebootPublicReport','Publish-DNSRebootPublicReport','Complete-DNSRebootStartup')
foreach($name in $selected){
    $nodes=@($startup.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected one DNS startup handoff function'}
    foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
        $callback=$command.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and
            $command.CommandElements[0] -is [Management.Automation.Language.VariableExpressionAst] -and
            $command.CommandElements[0].VariablePath.UserPath -cin @('Verify','Retire')
        if(-not $callback -and $command.GetCommandName() -cnotin ($selected+@('Get-Item','Where-Object','ConvertFrom-Json','Join-Path','Split-Path'))){
            throw 'DNS startup handoff source has an unexpected command boundary'
        }
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$root=[IO.Path]::Combine([IO.Path]::GetTempPath(),('aw-dns-reboot-publication-'+[guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($root)
$shared=Join-Path $root 'share'
$destination=Join-Path $shared 'reboot-results.json'
$report=Join-Path $root 'reboot-results.json'
$record=@{schemaVersion=6;qualificationID=('a'*32);method='doh';binarySHA256=('A'*64);fixtureSHA256=('B'*64);oracleSHA256=('C'*64)
    requiredOriginalMode='static-ipv6';originalModeCoverage=@{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=1}
    rebootVerified=$true;servicesVerified=$true;configuredStateVerified=$true;resolverVerified=$true
    journalBindingVerified=$true;journalRecoveryAccepted=$true;originalStateRestored=$true;originalResolverVerified=$true
    snapshotRetired=$true;servicesRemoved=$true;passed=$true;stage='complete';cleanupStage='complete'}
foreach($invalid in @(
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0},
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=0},
    @{'dhcp-ipv4'=1;'static-ipv4'=-1;'dhcp-ipv6'=0;'static-ipv6'=1},
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'='1'},
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=1;unknown=0}
)){
    $candidate=$record.Clone();$candidate.originalModeCoverage=$invalid
    $data=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $candidate -Depth 8))
    Refuse {Assert-DNSRebootPublicReport $data}
}
$script:verifications=0;$script:retirements=0
$verify={
    $script:verifications++
    Save-DNSRebootRecord $report $record
}
$retire={$script:retirements++}
try {
    Refuse {Complete-DNSRebootStartup $report $destination $verify $retire}
    if($script:verifications -ne 1 -or $script:retirements -ne 0 -or -not [IO.File]::Exists($report)){
        throw 'Unavailable share discarded the result or retired the task'
    }
    [void][IO.Directory]::CreateDirectory($shared)
    Refuse {Complete-DNSRebootStartup $report $destination $verify {throw 'Synthetic task retirement failure'}}
    if(-not [IO.File]::Exists($destination)){throw 'Task retirement failure lost the published result'}
    if(-not (Complete-DNSRebootStartup $report $destination $verify $retire) -or $script:verifications -ne 1 -or
        $script:retirements -ne 1 -or [IO.Directory]::GetFileSystemEntries($shared).Length -ne 1){
        throw 'Publication retry repeated verification or left a staging file'
    }
    [IO.File]::Delete($destination)
    $different=$record.Clone();$different.qualificationID=('b'*32)
    Save-DNSRebootRecord $destination $different
    $before=[IO.File]::ReadAllText($destination)
    Refuse {Complete-DNSRebootStartup $report $destination $verify $retire}
    if([IO.File]::ReadAllText($destination) -cne $before -or $script:retirements -ne 1){
        throw 'Publication replaced different evidence or retired its task'
    }
    [IO.File]::Delete($destination)
    [IO.File]::Delete($report)
    $record.servicesVerified=$false
    Save-DNSRebootRecord $report $record
    Refuse {Complete-DNSRebootStartup $report $destination $verify $retire}
    if([IO.File]::Exists($destination) -or $script:retirements -ne 1){
        throw 'Inconsistent passing report was published'
    }
    [IO.File]::Delete($report)
    $record.stage='services';$record.passed=$false
    $passed=Complete-DNSRebootStartup $report $destination {
        Save-DNSRebootRecord $report $record
        throw 'Synthetic acceptance failure with evidence'
    } $retire
    if($passed -or -not [IO.File]::Exists($destination) -or $script:retirements -ne 2){
        throw 'Completed failed report was lost or reported as passed'
    }
    [IO.File]::Delete($destination)
    [IO.File]::Delete($report)
    Refuse {Complete-DNSRebootStartup $report $destination {throw 'Synthetic interruption before publication'} $retire}
    if([IO.File]::Exists($destination) -or $script:retirements -ne 2){
        throw 'Interrupted verification fabricated evidence or retired the task'
    }
} finally {
    [IO.File]::Delete($destination)
    [IO.File]::Delete($report)
    if([IO.Directory]::Exists($shared)){[IO.Directory]::Delete($shared)}
    [IO.Directory]::Delete($root)
}
Write-Output 'DNS reboot admission, journal recovery, atomic results and startup publication checks passed.'
