# Test reboot admission and result publication without touching DNS or rebooting a host.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-reboot.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS reboot fixture failed parsing'}
foreach($name in @('Assert-DNSRebootAdmission','Save-DNSRebootRecord','Open-DNSRebootInput','Read-DNSRebootRecord',
        'Get-DNSRebootDigest','Assert-DNSRebootControllerArchitecture','Open-ApprovedDNSRebootController','Get-DNSRebootJournalID','Assert-DNSRebootJournal',
        'Get-DNSRebootCoverage','Assert-DNSRebootConfigured','Assert-RebootResolver','Assert-DNSRebootActiveResolver','Wait-DNSRebootObservation','Test-DNSRebootServicesRemoved',
        'Invoke-DNSRebootPreparation')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected one DNS reboot evidence function'}
    if($name -cin @('Get-DNSRebootCoverage','Assert-DNSRebootConfigured','Assert-RebootResolver','Assert-DNSRebootActiveResolver','Wait-DNSRebootObservation','Test-DNSRebootServicesRemoved')){
        foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
            $callback=$command.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and
                $command.CommandElements[0] -is [Management.Automation.Language.VariableExpressionAst] -and
                $command.CommandElements[0].VariablePath.UserPath -ceq 'Observe'
            if(-not $callback -and $command.GetCommandName() -cnotin @('Clear-DnsClientCache','Resolve-DnsName','Assert-RebootResolver','Start-Sleep','Get-Service','ForEach-Object','Where-Object','Get-DNSAcceptanceIndex','Assert-DNSAcceptanceConfigured')){
                throw 'DNS reboot observation has an unexpected command boundary'
            }
        }
    }
    if($name -ceq 'Invoke-DNSRebootPreparation'){
        $commands=@($nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true))
        if($commands.Count -ne 2 -or $commands[0].Extent.Text -cne '& $Prepare' -or
            $commands[1].Extent.Text -cne '& $Recover'){throw 'DNS preparation contract permits only closed callbacks'}
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Refuse([scriptblock]$Action){
    $rejected=$false
    try {& $Action}catch{$rejected=$true}
    if(-not $rejected){throw 'Invalid DNS reboot evidence was accepted'}
}
# The parsed object and digest must come from the same bounded observation.
$readFixture=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-dns-reboot-read-'+[guid]::NewGuid().ToString('N')+'.json')
$encoding=[Text.UTF8Encoding]::new($false,$true)
try {
    $first=$encoding.GetBytes('{"schemaVersion":7,"method":"doh"}')
    $stream=[IO.File]::Open($readFixture,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($first,0,$first.Length)} finally {$stream.Dispose()}
    $observed=Read-DNSRebootRecord $readFixture $first.Length
    if($observed.record.method -cne 'doh' -or $observed.sha256 -cne (Get-FileHash -LiteralPath $readFixture -Algorithm SHA256).Hash){
        throw 'DNS reboot record did not bind its parsed bytes'
    }
    Refuse {Read-DNSRebootRecord $readFixture ($first.Length-1)}
    Refuse {Read-DNSRebootRecord (Split-Path -Parent $readFixture) 1MB}
    foreach($bad in @(
        @{bytes=[byte[]]@()},
        @{bytes=$encoding.GetBytes('[{"method":"dnscrypt"}]')},
        @{bytes=$encoding.GetBytes('{"method":')},
        @{bytes=[byte[]]@(123,34,255,34,58,48,125)},
        @{bytes=([byte[]]($first+[byte]0))}
    )){
        [IO.File]::WriteAllBytes($readFixture,$bad.bytes)
        Refuse {Read-DNSRebootRecord $readFixture 1MB}
    }
    $withBom=[byte[]](@(239,187,191)+$encoding.GetBytes('{"schemaVersion":7,"method":"dnscrypt"}'))
    [IO.File]::WriteAllBytes($readFixture,$withBom)
    $changed=Read-DNSRebootRecord $readFixture 1MB
    if($changed.record.method -cne 'dnscrypt' -or $changed.sha256 -ceq $observed.sha256 -or
        $changed.sha256 -cne (Get-FileHash -LiteralPath $readFixture -Algorithm SHA256).Hash -or $observed.record.method -cne 'doh'){
        throw 'DNS reboot record lost its original observation after replacement'
    }
} finally {[IO.File]::Delete($readFixture)}

# Exercise candidate pinning through the same Windows file handle used at dispatch.
$controllerFixture=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-dns-pin-'+[guid]::NewGuid().ToString('N'))
$controller=$null
try {
    $image=[byte[]]::new(90)
    $image[0]=0x4d;$image[1]=0x5a;$image[60]=64;$image[64]=0x50;$image[65]=0x45
    $image[68]=0x64;$image[69]=0x86;$image[88]=0x0b;$image[89]=0x02
    [IO.File]::WriteAllBytes($controllerFixture,$image)
    $digest=(Get-FileHash -LiteralPath $controllerFixture -Algorithm SHA256).Hash
    Refuse {Open-ApprovedDNSRebootController $controllerFixture 'invalid' 'amd64'}
    Refuse {Open-ApprovedDNSRebootController $controllerFixture ('0'*64) 'amd64'}
    Refuse {Open-ApprovedDNSRebootController $controllerFixture $digest 'arm64'}
    $controller=Open-ApprovedDNSRebootController $controllerFixture $digest.ToLowerInvariant() 'amd64'
    if($controller -isnot [IO.FileStream]){throw 'DNS reboot controller approval did not retain its file handle'}
    if($env:OS -ceq 'Windows_NT'){
        Refuse {[IO.File]::WriteAllText($controllerFixture,'replacement')}
        Refuse {[IO.File]::Delete($controllerFixture)}
    }
    $controller.Dispose()
    [IO.File]::WriteAllText($controllerFixture,'replacement')
    Refuse {Open-ApprovedDNSRebootController $controllerFixture $digest 'amd64'}
    $armImage=$image.Clone();$armImage[69]=0xaa
    [IO.File]::WriteAllBytes($controllerFixture,$armImage)
    $armDigest=(Get-FileHash -LiteralPath $controllerFixture -Algorithm SHA256).Hash
    $armController=Open-ApprovedDNSRebootController $controllerFixture $armDigest 'arm64'
    try {Refuse {Assert-DNSRebootControllerArchitecture $armController 'amd64'}}
    finally {$armController.Dispose()}
    foreach($bad in @(@{index=60;value=255},@{index=64;value=0},@{index=89;value=1})){
        $invalid=$image.Clone();$invalid[$bad.index]=$bad.value
        [IO.File]::WriteAllBytes($controllerFixture,$invalid)
        $invalidDigest=(Get-FileHash -LiteralPath $controllerFixture -Algorithm SHA256).Hash
        Refuse {Open-ApprovedDNSRebootController $controllerFixture $invalidDigest 'amd64'}
    }
} finally {
    if($null -ne $controller){$controller.Dispose()}
    [IO.File]::Delete($controllerFixture)
}

# Exercise the actual preparation boundary with a success, each failed stage
# and a second failure while attempting to restore.
$steps=@('install','configure','verify','save')
foreach($failAt in @('none')+$steps){
    $calls=[Collections.Generic.List[string]]::new()
    $failure=$null
    try {
        Invoke-DNSRebootPreparation {
            foreach($step in $steps){
                $calls.Add($step)
                if($step -ceq $failAt){throw ('Preparation failed during '+$step)}
            }
        } {$calls.Add('restore')}
    } catch {$failure=$_.Exception}
    $expected=@($steps)
    if($failAt -cne 'none'){
        $expected=@($steps[0..([Array]::IndexOf($steps,$failAt))])+@('restore')
        if($null -eq $failure -or $failure.Message -cne ('Preparation failed during '+$failAt)){
            throw 'Preparation failure was lost after cleanup'
        }
    } elseif($null -ne $failure){throw 'Successful DNS preparation reported a failure'}
    if(($calls -join ',') -cne ($expected -join ',')){throw 'Unexpected DNS preparation or recovery order'}
}
$combined=$null
try {
    Invoke-DNSRebootPreparation {throw 'Preparation failed'} {throw 'Recovery failed'}
} catch {$combined=$_.Exception}
if($combined -isnot [AggregateException] -or $combined.InnerExceptions.Count -ne 2 -or
    $combined.InnerExceptions[0].Message -cne 'Preparation failed' -or
    $combined.InnerExceptions[1].Message -cne 'Recovery failed'){
    throw 'Preparation and recovery failures must both be retained'
}

$bootstrap=Join-Path $PSScriptRoot 'vmware-test-bootstrap.ps1'
$bootstrapAst=[Management.Automation.Language.Parser]::ParseFile($bootstrap,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'VMware bootstrap failed parsing'}
$stageCommands=@($bootstrapAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -cin @('Get-ScheduledTask','Copy-TestInputs')
},$true))
if($stageCommands.Count -ne 2 -or $stageCommands[0].GetCommandName() -cne 'Get-ScheduledTask' -or
    $stageCommands[1].GetCommandName() -cne 'Copy-TestInputs'){
    throw 'Pending reboot verification must be checked before overwriting staged inputs'
}
$rebootBlock=@($bootstrapAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.SwitchStatementAst] -and
        @($node.Clauses | Where-Object {$_.Item1.Value -ceq 'reboot-prepare'}).Count -eq 1
},$true))
if($rebootBlock.Count -ne 1){throw 'Expected one VMware DNS preparation stage'}
$body=($rebootBlock[0].Clauses | Where-Object {$_.Item1.Value -ceq 'reboot-prepare'}).Item2
$stages=@($body.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and (
        $node.GetCommandName() -cin @('Register-ScheduledTask','Unregister-ScheduledTask') -or
        ($node.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and
         $node.Extent.Text -cmatch '^& \$fixturePath -Phase Prepare'))
},$true))
if($stages.Count -ne 3 -or $stages[0].GetCommandName() -cne 'Register-ScheduledTask' -or
    $stages[1].Extent.Text -cnotmatch '-Phase Prepare.+-ExecutableSHA256 \$digest.+-QualificationID \$qualificationID' -or $stages[2].GetCommandName() -cne 'Unregister-ScheduledTask'){
    throw 'VMware DNS preparation must follow task registration and retire the task on failure'
}
$journalId='workflow-'+('a'*32)+'.json'
$saved=@{schemaVersion=8;architecture='amd64';qualificationID=('a'*32);method='doh';requiredOriginalMode='static-ipv6';guestID='synthetic';
    binarySHA256=('a'*64);fixtureSHA256=('b'*64);oracleSHA256=('c'*64);snapshotSHA256=('D'*64);
    journalId=$journalId;journalSHA256=('E'*64);boot='639303000000000000'}
$current=$saved.Clone()
$current.boot='639303000000000001'
Assert-DNSRebootAdmission $saved $current
$changed=$current.Clone();$changed.method='dnscrypt'
Refuse {Assert-DNSRebootAdmission $saved $changed}
$changed=$current.Clone();$changed.requiredOriginalMode='dhcp-ipv4'
Refuse {Assert-DNSRebootAdmission $saved $changed}
foreach($field in @('qualificationID','guestID','binarySHA256','fixtureSHA256','oracleSHA256','snapshotSHA256','journalId','journalSHA256')){
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
$legacy.schemaVersion=6
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
    $state=@{flushes=0;requests=[Collections.Generic.List[string]]::new();waits=0;attempts=0;
        cacheFails=$false;serviceFails=$false;services=@();answers=@{};failedListener='';
        servers=[Collections.Generic.List[string]]::new()}
    function Clear-DnsClientCache {
        [CmdletBinding()]param()
        if($ErrorActionPreference -ne 'Stop'){throw 'DNS cache clear must fail closed'}
        $state.flushes++
        if($state.cacheFails){throw 'Synthetic cache flush failure'}
    }
    function Resolve-DnsName {
        [CmdletBinding()]param($Name,$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout,[string]$Server)
        if($Name -cne 'example.com.' -or $Type -cnotin @('A','AAAA') -or -not $DnsOnly -or -not $NoHostsFile -or
           -not $QuickTimeout -or $ErrorActionPreference -ne 'Stop'){throw 'Unexpected ordinary DNS request'}
        $state.requests.Add($Type)
        $state.servers.Add($Server)
        if($Server -and $Server -ceq $state.failedListener){throw 'Synthetic listener failure'}
        $state.answers[$Type]
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
    $answer6=@{Name='example.com.';Type='AAAA';Section='Answer';IPAddress='2001:db8::15'}
    $state.answers=@{A=@([pscustomobject]$answer);AAAA=@([pscustomobject]$answer6)}
    Assert-RebootResolver
    if(($state.requests -join ',') -cne 'A,AAAA'){throw 'The fixture did not verify both ordinary DNS record types'}
    foreach($invalid in @(
        @{Name='example.net.'},@{Type='AAAA'},@{Section='Additional'},@{IPAddress='2001:db8::1'},@{IPAddress='invalid'}
    )){
        $row=$answer.Clone()
        foreach($key in $invalid.Keys){$row[$key]=$invalid[$key]}
        $state.answers.A=@([pscustomobject]$row)
        $state.requests.Clear()
        Refuse {Assert-RebootResolver}
        if(($state.requests -join ',') -cne 'A'){throw 'An invalid A answer was credited'}
    }
    $state.answers.A=@([pscustomobject]$answer)
    foreach($invalid in @(
        @{Name='example.net.'},@{Type='A'},@{Section='Additional'},@{IPAddress='192.0.2.15'},
        @{IPAddress='::ffff:192.0.2.15'},@{IPAddress='invalid'}
    )){
        $row=$answer6.Clone()
        foreach($key in $invalid.Keys){$row[$key]=$invalid[$key]}
        $state.answers.AAAA=@([pscustomobject]$row)
        $state.requests.Clear()
        Refuse {Assert-RebootResolver}
        if(($state.requests -join ',') -cne 'A,AAAA'){throw 'The fixture did not reach the invalid AAAA answer'}
    }
    $state.answers.AAAA=@()
    Refuse {Assert-RebootResolver}
    $state.cacheFails=$true
    $state.requests.Clear()
    Refuse {Assert-RebootResolver}
    if($state.flushes -ne 14 -or $state.requests.Count){throw 'Failed cache flush allowed a DNS query'}

    $state.cacheFails=$false
    $state.answers.AAAA=@([pscustomobject]$answer6)
    $coverage=[ordered]@{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=1}
    $state.servers.Clear()
    Assert-DNSRebootActiveResolver $coverage 'dnscrypt'
    if(($state.servers -join ',') -cne ',,127.0.0.1,127.0.0.1,::1,::1'){
        throw 'Dual-family DNSCrypt verification did not query both loopback listeners'
    }
    foreach($listener in @('127.0.0.1','::1')){
        $state.failedListener=$listener
        Refuse {Assert-DNSRebootActiveResolver $coverage 'dnscrypt'}
    }
    $state.servers.Clear()
    Assert-DNSRebootActiveResolver $coverage 'doh'
    if($state.servers.Count -ne 2 -or ($state.servers -join ',') -cne ','){
        throw 'DoH verification must use the ordinary resolver'
    }
    $state.servers.Clear()
    $coverage['static-ipv6']=0
    Assert-DNSRebootActiveResolver $coverage 'dnscrypt'
    if(($state.servers -join ',') -cne ',,127.0.0.1,127.0.0.1'){
        throw 'IPv4-only DNSCrypt verification queried an unassigned listener'
    }
    $state.servers.Clear()
    $state.failedListener='127.0.0.1'
    $coverage['dhcp-ipv4']=0
    $coverage['dhcp-ipv6']=1
    Assert-DNSRebootActiveResolver $coverage 'dnscrypt'
    if(($state.servers -join ',') -cne ',,::1,::1'){
        throw 'IPv6-only DNSCrypt verification queried an unassigned listener'
    }

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
            'Assert-RebootResolver','Test-Path','Test-DNSRebootServicesRemoved','Save-DNSRebootRecord','Get-DNSRebootDigest','Join-Path')){
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
            if($script:failure -in @('recover','recover-and-remove')){throw 'Synthetic recovery refusal'}
            if($script:failure -ne 'snapshot'){$script:snapshotPresent=$false}
        }
        'remove-all' {
            if($script:failure -in @('remove','recover-and-remove')){throw 'Synthetic teardown refusal'}
            $script:snapshotPresent=$script:failure -ceq 'teardown-snapshot'
        }
        default {throw 'Unexpected workflow request'}
    }
}
function Assert-DNSAcceptanceRestored {
    $phase=$script:trace[-1]
    $script:stateReads[$phase]++
    $failure=if($phase -ceq 'recover'){'state'}else{'teardown-state'}
    if(($script:stateReads[$phase] -eq 1 -and $script:failure -ceq $failure) -or
        ($script:stateReads[$phase] -eq 2 -and $script:failure -ceq "$failure-after-probe")){
        throw 'Synthetic state mismatch'
    }
}
function Read-DNSAcceptanceState {return @{}}
function Assert-RebootResolver {
    if(($script:trace[-1] -eq 'recover' -and $script:failure -eq 'resolver') -or
        ($script:trace[-1] -eq 'remove-all' -and $script:failure -eq 'teardown-resolver')){throw 'Synthetic resolver failure'}
}
function Test-Path {param($LiteralPath,$ErrorAction);if($LiteralPath -cne $snapshot){throw 'Unexpected snapshot path'};return $script:snapshotPresent}
function Test-DNSRebootServicesRemoved {
    if($script:failure -eq 'inventory'){throw 'Synthetic teardown inventory failure'}
    return $script:failure -ne 'service'
}
$save=(Get-Command Save-DNSRebootRecord).ScriptBlock
function Save-DNSRebootRecord {param($Path,$Record);if($Path -cne $report){throw 'Unexpected report path'};$script:published=$Record}
$report='synthetic report';$snapshot=Join-Path ([IO.Path]::GetTempPath()) 'synthetic snapshot';$journalPath='synthetic journal'
$current.snapshotSHA256='D'*64
$receiptPath=Join-Path ([IO.Path]::GetDirectoryName($snapshot)) ('dns-restored-'+('d'*64)+'.receipt')
$receiptDigest='96CA1E8D176B8F0FB41DC5A66BDD553BA480489369ABC337A7C5B397D3C8279D'
$digestCommand=(Get-Command Get-DNSRebootDigest).ScriptBlock
function Get-DNSRebootDigest {
    param($Path,$Maximum)
    if($Path -ceq $receiptPath -and $Maximum -eq 64){
        switch($script:failure){
            'receipt-missing' {throw 'Synthetic missing receipt'}
            'receipt-mismatch' {return 'F'*64}
            default {return $receiptDigest}
        }
    }
    if($Path -cne $journalPath -or $Maximum -ne 8MB){throw 'Unexpected journal read'}
    if($script:failure -ceq 'journal-changed'){return 'F'*64}
    return $current.journalSHA256
}
foreach($failure in @('none','journal-changed','recover','state','resolver','state-after-probe','snapshot','receipt-missing','receipt-mismatch','remove',
        'teardown-state','teardown-resolver','teardown-state-after-probe','teardown-snapshot','inventory','service','recover-and-remove')){
    $script:failure=$failure;$script:trace=[Collections.Generic.List[string]]::new()
    $script:stateReads=@{recover=0;'remove-all'=0}
    $script:snapshotPresent=$true;$script:published=$null
    $outcome=@{stage='complete';cleanupStage='not-started';teardownStage='not-started';journalRecoveryAccepted=$false;originalStateRestored=$false;originalResolverVerified=$false;snapshotRetired=$false;restorationReceiptVerified=$false;servicesRemoved=$false}
    & $cleanup
    $stage=switch($failure){
        'journal-changed' {'journal-recovery'}
        'recover' {'journal-recovery'}
        'state' {'original-state'}
        'resolver' {'original-resolver'}
        'state-after-probe' {'original-resolver'}
        'snapshot' {'snapshot-retirement'}
        {$_ -cin @('receipt-missing','receipt-mismatch')} {'restoration-receipt'}
        'recover-and-remove' {'journal-recovery'}
        default {'recovered'}
    }
    $teardown=switch($failure){
        'remove' {'remove-all'}
        'recover-and-remove' {'remove-all'}
        'teardown-state' {'original-state'}
        'teardown-resolver' {'original-resolver'}
        'teardown-state-after-probe' {'original-resolver'}
        'teardown-snapshot' {'snapshot-retirement'}
        'inventory' {'service-inventory'}
        'service' {'services-remain'}
        default {'complete'}
    }
    $expectedTrace=if($failure -ceq 'journal-changed'){'remove-all'}else{'recover,remove-all'}
    if($script:published.cleanupStage -cne $stage -or $script:published.teardownStage -cne $teardown -or
        $script:published.originalResolverVerified -ne ($stage -cin @('snapshot-retirement','restoration-receipt','recovered')) -or
        $script:published.restorationReceiptVerified -ne ($stage -ceq 'recovered') -or
        $script:published.servicesRemoved -ne ($teardown -ceq 'complete') -or $script:published.passed -ne ($failure -ceq 'none') -or
        ($script:trace -join ',') -cne $expectedTrace){
        throw 'DNS reboot cleanup failed to distinguish journal recovery from teardown'
    }
    if($failure -ceq 'none' -and ($script:stateReads.recover -ne 2 -or $script:stateReads['remove-all'] -ne 2)){
        throw 'Passing recovery and teardown must verify original state on both sides of the resolver probe'
    }
}
Set-Item Function:Save-DNSRebootRecord $save
Set-Item Function:Get-DNSRebootDigest $digestCommand
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
$report=Join-Path $root 'reboot-results.json'
$record=@{schemaVersion=10;architecture='amd64';qualificationID=('a'*32);method='doh';binarySHA256=('A'*64);fixtureSHA256=('B'*64);oracleSHA256=('C'*64)
    requiredOriginalMode='static-ipv6';originalModeCoverage=@{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=1}
    rebootVerified=$true;servicesVerified=$true;configuredStateVerified=$true;resolverVerified=$true
    journalBindingVerified=$true;journalRecoveryAccepted=$true;originalStateRestored=$true;originalResolverVerified=$true
    snapshotRetired=$true;restorationReceiptVerified=$true;servicesRemoved=$true;passed=$true;stage='complete';cleanupStage='recovered';teardownStage='complete'}
$legacy=$record.Clone();$legacy.schemaVersion=9;$legacy.Remove('architecture')
$pin=$record.binarySHA256.ToLowerInvariant()
$qualificationID=$record.qualificationID
$method=$record.method
$originalMode=$record.requiredOriginalMode
$fixturePin=$record.fixtureSHA256.ToLowerInvariant()
$oraclePin=$record.oracleSHA256.ToLowerInvariant()
$destination=Join-Path $shared ('reboot-results-'+$qualificationID+'.json')
$secondID='b'*32
$secondDestination=Join-Path $shared ('reboot-results-'+$secondID+'.json')
Refuse {Assert-DNSRebootPublicReport ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $legacy -Depth 8))) $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
foreach($invalid in @(
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0},
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=0},
    @{'dhcp-ipv4'=1;'static-ipv4'=-1;'dhcp-ipv6'=0;'static-ipv6'=1},
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'='1'},
    @{'dhcp-ipv4'=1;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=1;unknown=0}
)){
    $candidate=$record.Clone();$candidate.originalModeCoverage=$invalid
    $data=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $candidate -Depth 8))
    Refuse {Assert-DNSRebootPublicReport $data $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
}
foreach($invalid in @(
    @{stage='services';servicesVerified=$false},
    @{cleanupStage='original-resolver'},
    @{restorationReceiptVerified=$false},
    @{architecture='arm64'},
    @{cleanupStage='restoration-receipt';restorationReceiptVerified=$true},
    @{teardownStage='services-remain'},
    @{teardownStage='unknown';servicesRemoved=$false}
)){
    $candidate=$record.Clone()
    $candidate.passed=$false
    foreach($key in $invalid.Keys){$candidate[$key]=$invalid[$key]}
    $data=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $candidate -Depth 8))
    Refuse {Assert-DNSRebootPublicReport $data $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
}
$candidate=$record.Clone()
$candidate.cleanupStage='restoration-receipt';$candidate.restorationReceiptVerified=$false;$candidate.passed=$false
$data=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $candidate -Depth 8))
if((Assert-DNSRebootPublicReport $data $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64') -ne $false){
    throw 'A missing restoration receipt was credited as a pass'
}
$candidate=$record.Clone()
$candidate.stage='configured-readback';$candidate.configuredStateVerified=$false;$candidate.resolverVerified=$false
$candidate.cleanupStage='original-state';$candidate.originalStateRestored=$false;$candidate.originalResolverVerified=$false
$candidate.snapshotRetired=$false;$candidate.restorationReceiptVerified=$false;$candidate.teardownStage='complete';$candidate.passed=$false
$data=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $candidate -Depth 8))
if((Assert-DNSRebootPublicReport $data $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64') -ne $false){
    throw 'Successful bulk teardown was credited as successful journal recovery'
}
$startupCommand=$startup.EndBlock.Extent.Text
if($startupCommand -cnotmatch '-Phase Verify -Executable \$binary -ExecutableSHA256 \$ExecutableSHA256 -QualificationID \$QualificationID -DNS \$DNS -RequiredOriginalMode \$RequiredOriginalMode -FixtureSHA256 \$FixtureSHA256 -OracleSHA256 \$OracleSHA256' -or
   $body.Extent.Text -cnotmatch '-ExecutableSHA256 ''\+\$digest\+'' -QualificationID ''\+\$qualificationID\+'' -DNS ''\+\$method\+'' -RequiredOriginalMode ''\+\$originalMode\+'' -FixtureSHA256 ''\+\$fixtureDigest\+'' -OracleSHA256 ''\+\$oracleDigest' -or
   $stages[1].Extent.Text -cnotmatch '-DNS \$method -RequiredOriginalMode \$originalMode -QualificationID \$qualificationID -FixtureSHA256 \$fixtureDigest -OracleSHA256 \$oracleDigest'){
    throw 'Scheduled reboot verification does not inherit the approved controller and script digests, qualification ID, DNS method and original adapter mode'
}
$script:verifications=0;$script:retirements=0
$verify={
    $script:verifications++
    Save-DNSRebootRecord $report $record
}
$retire={$script:retirements++}
try {
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
    if($script:verifications -ne 1 -or $script:retirements -ne 0 -or -not [IO.File]::Exists($report)){
        throw 'Unavailable share discarded the result or retired the task'
    }
    [void][IO.Directory]::CreateDirectory($shared)
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire ('0'*64) $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin ('b'*32) $method $originalMode $fixturePin $oraclePin 'amd64'}
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID 'dnscrypt' $originalMode $fixturePin $oraclePin 'amd64'}
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID $method 'dhcp-ipv4' $fixturePin $oraclePin 'amd64'}
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID $method $originalMode ('0'*64) $oraclePin 'amd64'}
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID $method $originalMode $fixturePin ('0'*64) 'amd64'}
    if([IO.File]::Exists($destination) -or $script:verifications -ne 1 -or $script:retirements -ne 0){
        throw 'A mismatched DNS reboot report was published or retired its task'
    }
    Refuse {Complete-DNSRebootStartup $report $shared $verify {throw 'Synthetic task retirement failure'} $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
    if(-not [IO.File]::Exists($destination)){throw 'Task retirement failure lost the published result'}
    if(-not (Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64') -or $script:verifications -ne 1 -or
        $script:retirements -ne 1 -or [IO.Directory]::GetFileSystemEntries($shared).Length -ne 1){
        throw 'Publication retry repeated verification or left a staging file'
    }
    [IO.File]::Delete($report)
    $firstReport=[IO.File]::ReadAllText($destination)
    $second=$record.Clone();$second.qualificationID=$secondID
    Save-DNSRebootRecord $report $second
    if(-not (Complete-DNSRebootStartup $report $shared {throw 'Existing second report must be reused'} $retire $pin $secondID $method $originalMode $fixturePin $oraclePin 'amd64') -or
        [IO.File]::ReadAllText($destination) -cne $firstReport -or
        (Get-Content -LiteralPath $secondDestination -Raw | ConvertFrom-Json).qualificationID -cne $secondID){
        throw 'Qualifications could not publish independently to the same share'
    }
    [IO.File]::Delete($report)
    Save-DNSRebootRecord $report $record
    [IO.File]::Delete($destination)
    $different=$record.Clone();$different.qualificationID=$secondID
    Save-DNSRebootRecord $destination $different
    $before=[IO.File]::ReadAllText($destination)
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
    if([IO.File]::ReadAllText($destination) -cne $before -or $script:retirements -ne 2){
        throw 'Publication replaced different evidence or retired its task'
    }
    [IO.File]::Delete($destination)
    [IO.File]::Delete($report)
    $record.servicesVerified=$false
    Save-DNSRebootRecord $report $record
    Refuse {Complete-DNSRebootStartup $report $shared $verify $retire $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
    if([IO.File]::Exists($destination) -or $script:retirements -ne 2){
        throw 'Inconsistent passing report was published'
    }
    [IO.File]::Delete($report)
    $record.stage='services';$record.configuredStateVerified=$false;$record.resolverVerified=$false;$record.passed=$false
    $passed=Complete-DNSRebootStartup $report $shared {
        Save-DNSRebootRecord $report $record
        throw 'Synthetic acceptance failure with evidence'
    } $retire $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'
    if($passed -or -not [IO.File]::Exists($destination) -or $script:retirements -ne 3){
        throw 'Completed failed report was lost or reported as passed'
    }
    [IO.File]::Delete($destination)
    [IO.File]::Delete($report)
    Refuse {Complete-DNSRebootStartup $report $shared {throw 'Synthetic interruption before publication'} $retire $pin $qualificationID $method $originalMode $fixturePin $oraclePin 'amd64'}
    if([IO.File]::Exists($destination) -or $script:retirements -ne 3){
        throw 'Interrupted verification fabricated evidence or retired the task'
    }
} finally {
    [IO.File]::Delete($destination)
    [IO.File]::Delete($secondDestination)
    [IO.File]::Delete($report)
    if([IO.Directory]::Exists($shared)){[IO.Directory]::Delete($shared)}
    [IO.Directory]::Delete($root)
}
Write-Output 'DNS reboot admission, journal recovery, atomic results and startup publication checks passed.'
