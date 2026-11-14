# Exercise the real journal dispatcher on inert snapshot files and mocked mutation boundaries.
$ErrorActionPreference='Stop'
$path=Join-Path (Split-Path -Parent $PSScriptRoot) 'internal\workflow\windows.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DNS journal source failed parsing'}
foreach($name in @('No-Reparse','Under','Quote-Arg','Publish-WorkflowFile','Get-WorkflowBytesSHA256','Throw-WorkflowRecoveryJournalReadFailure','Read-WorkflowRecoveryJournalBytes','Read-DNSRecoveryFileBytes','Get-DNSRecoverySnapshotDigest','Get-DNSRecoveryReceiptPath','Save-DNSRecoveryReceipt','Confirm-DNSRecoveryEntry','Confirm-DNSRecoverySnapshot','Recover-Operation','Get-WorkflowFileHash','Copy-WorkflowFileToNewPath','Replace-StagedWorkflowFile','Publish-StagedWorkflowFile','Publish-RecordedWorkflowFile','Backup-File','Restore-RecordedWorkflowFile','Rollback','Remove-All','Get-ManagedFirewallRule','Remove-ManagedFirewallRule','Firewall','Save-Journal','Invoke-ManagedServiceControl','Get-ManagedServiceCommandDigest','Read-ManagedServiceCommand','Read-ManagedServiceRegistration','Assert-ManagedServiceOwnership','Assert-RecordedServiceBinding','Wait-RecordedServiceAbsent','Remove-RecordedService')){
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
function Test-DNSCryptListenerNeeded {return [bool]$script:resolverInUse}
function Wait-RecordedServiceStopped([string]$Name) {
    if($Name -cne 'AccessWeaver-dnscrypt'){throw 'Unexpected service stop wait'}
    $script:order.Add('wait-stopped')
    if($script:serviceFault -ceq 'stop-timeout'){throw 'Synthetic service stop timeout'}
}
function Assert-TrustedItem([string]$Path){No-Reparse $Path;[void](Get-Item -LiteralPath $Path -Force -ErrorAction Stop)}
function Get-CimInstance {
    param($ClassName,$Filter,$ErrorAction)
    if($ClassName -cne 'Win32_Service' -or $Filter -cne "Name='AccessWeaver-dnscrypt'"){throw 'Unexpected service identity lookup'}
    if($script:serviceFault -ceq 'identity'){throw 'Synthetic service identity unavailable'}
    return [pscustomobject]@{Name='AccessWeaver-dnscrypt';PathName=$script:serviceCommand}
}
function Native {
    param($Program,$Arguments,$Allowed,[switch]$Secret,[int]$Timeout)
    if($Arguments.Count -ne 2 -or $Arguments[1] -cne 'AccessWeaver-dnscrypt' -or
        $Arguments[0] -cnotin @('query','stop','delete') -or -not $Secret -or $Timeout -ne 5){
        throw 'Unexpected native service request'
    }
    if($Arguments[0] -cne 'query' -and [IO.File]::Exists($snapshot)){throw 'Service mutation started before DNS restoration'}
    if($Arguments[0] -ne 'query' -or -not [IO.File]::Exists($snapshot)){$script:order.Add($Arguments[0])}
    switch($Arguments[0]){
        'query' {
            if($script:serviceFault -ceq 'inspect'){throw 'Synthetic SCM inspection failure'}
            if($script:serviceFault -ceq 'truncated'){return @{exitCode=1060;outputComplete=$false}}
            if($script:serviceState -ceq 'pending' -and $script:serviceFault -ceq 'pending-then-absent'){
                $script:serviceFault=''
                return @{exitCode=1072;outputComplete=$true}
            }
            if($script:serviceState -ceq 'pending' -and -not $script:serviceFault){$script:serviceState='absent'}
            $exitCode=switch($script:serviceState){'absent' {1060};'pending' {1072};default {0}}
        }
        'stop' {
            if($script:serviceFault -ceq 'stop-command'){throw 'Synthetic SCM stop failure'}
            $exitCode=if($script:serviceState -ceq 'stopped'){1062}else{0}
            $script:serviceState='stopped'
        }
        'delete' {
            if($script:serviceState -cne 'stopped'){throw 'Unstopped service reached deletion'}
            $script:serviceState='pending';$exitCode=0
        }
    }
    Require ($exitCode -in $Allowed) 'Unexpected SCM accepted-code set'
    return @{exitCode=$exitCode;outputComplete=$true}
}
function Restore-DNS {
    $script:restores++
    $script:order.Add('restore')
    if($script:failRestore){throw 'Synthetic DNS restore failure'}
    Save-DNSRecoveryReceipt (Get-DNSRecoverySnapshotDigest)
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
$script:failRestore=$false
$script:serviceFault='';$script:serviceState='running'
$script:serviceCommand='inert service-host command --instance='+('1'*32)
$script:order=[Collections.Generic.List[string]]::new()
$originalSystemRoot=$env:SystemRoot
if(-not $env:SystemRoot){$env:SystemRoot=[IO.Path]::GetTempPath()}
$serviceConfig=Join-Path $root 'dnscrypt.toml'
$script:journalPath=Join-Path $root $r.journalId
$script:journalState='running'
$script:events=[Collections.Generic.List[string]]::new()
try {
    & {
        $calls=[Collections.Generic.List[string]]::new()
        $fixture=@{present=$true;restoreFails=$true;inspectionFails=$false;methodFails=$false}
        $digest='A'*64
        function Get-DNSRecoverySnapshotDigest {
            if($fixture.inspectionFails){throw 'Synthetic snapshot inspection failure'}
            if($fixture.present){return $digest}
        }
        function Restore-DNS([string]$ExpectedSHA256) {
            Require ($ExpectedSHA256 -ceq $digest) 'Remove-all bypassed the active snapshot binding'
            $calls.Add('restore')
            if($fixture.restoreFails){throw 'Synthetic DNS restoration failure'}
            $fixture.present=$false
        }
        function Remove-Method {
            param($engine,[switch]$OwnedOnly)
            Require (-not $fixture.present) 'Remove-all touched a managed method while DNS recovery remained active'
            Require ([bool]$OwnedOnly -eq ($engine -ceq 'windivert')) 'Remove-all lost the WinDivert ownership restriction'
            $calls.Add($engine)
            if($fixture.methodFails -and $engine -ceq 'wiresock'){throw 'Synthetic later cleanup failure'}
        }
        $refused=$false
        try{Remove-All}catch{$refused=$_.Exception.Message -ceq 'Synthetic DNS restoration failure'}
        Require ($refused -and ($calls -join ',') -ceq 'restore' -and $fixture.present) 'Failed DNS restoration allowed partial cleanup'
        $calls.Clear();$fixture.inspectionFails=$true
        $refused=$false
        try{Remove-All}catch{$refused=$_.Exception.Message -ceq 'Synthetic snapshot inspection failure'}
        Require ($refused -and $calls.Count -eq 0) 'Unreadable snapshot state allowed cleanup'
        $fixture.inspectionFails=$false;$fixture.restoreFails=$false;$fixture.methodFails=$true
        $refused=$false
        try{Remove-All}catch{$refused=$_.Exception.Message -ceq 'Synthetic later cleanup failure'}
        Require ($refused -and -not $fixture.present -and ($calls -join ',') -ceq 'restore,byedpi,zapret,zapret2,goodbyedpi,wiresock') 'Later cleanup failure did not preserve completed DNS restoration'
        $calls.Clear();$fixture.methodFails=$false
        Remove-All
        Require (($calls -join ',') -ceq 'byedpi,zapret,zapret2,goodbyedpi,wiresock,windivert,dnscrypt') 'Remove-all retry repeated DNS restoration or changed cleanup order'
    }

    & {
        $assetNames=@{byedpi='ciadpi.exe';proxifyre='ProxiFyre.exe'}
        $name='AccessWeaver-byedpi-Inbound'
        $program=Join-Path $root 'components\byedpi\ciadpi.exe'
        $state=@{rules=@{};journal=0;creates=0;removes=0;keep=$false;failRead=$false;warn=$false;failJournal=$false}
        function Get-NetFirewallRule {
            [CmdletBinding()]param($PolicyStore)
            Require ($PolicyStore -ceq 'PersistentStore' -and $ErrorActionPreference -eq 'Stop') 'Unexpected firewall inventory scope'
            if($state.failRead){throw 'Synthetic inventory refusal'}
            if($state.warn){Write-Warning 'Synthetic incomplete rule inventory'}
            return @($state.rules.Values)
        }
        function Get-NetFirewallApplicationFilter {
            [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
            Require ($PolicyStore -ceq 'PersistentStore' -and $ErrorActionPreference -eq 'Stop') 'Unexpected firewall filter scope'
            return @{Program=$AssociatedNetFirewallRule.Program}
        }
        function Save-Journal {
            if($state.failJournal){throw 'Synthetic journal refusal'}
            $state.journal++
        }
        function New-NetFirewallRule {
            [CmdletBinding()]param($Name,$DisplayName,$Description,$Program,$Direction,$Action,$Profile,$PolicyStore)
            Require ($PolicyStore -ceq 'PersistentStore' -and $ErrorActionPreference -eq 'Stop' -and
                $state.journal -gt $state.creates -and $script:undo[$state.creates].instance -ceq ($Description.Split(' ')[-1])) 'Firewall rule creation preceded its journal binding'
            $state.creates++
            $state.rules[$Name]=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Description=$Description;
                Program=$Program;Direction=$Direction;Action=$Action;Profile=$Profile;Enabled='True'}
        }
        function Remove-NetFirewallRule {
            [CmdletBinding(SupportsShouldProcess)]param($InputObject)
            Require ([object]::ReferenceEquals($InputObject,$state.rules[$InputObject.Name]) -and
                $ErrorActionPreference -eq 'Stop') 'Firewall removal did not use the verified rule object'
            $state.removes++
            if(-not $state.keep){$state.rules.Remove($InputObject.Name)}
        }
        $state.failJournal=$true
        $failed=$false
        try{Firewall 'byedpi' $program}catch{$failed=$_.Exception.Message -ceq 'Synthetic journal refusal'}
        Require ($failed -and $state.creates -eq 0) 'Firewall rule was created after journal failure'
        $script:undo.Clear()
        $state.failJournal=$false
        Firewall 'byedpi' $program
        Require ($state.creates -eq 2 -and $state.journal -eq 2 -and $script:undo.Count -eq 2) 'Firewall rules lack independently journaled identities'
        Firewall 'byedpi' $program
        Require ($state.creates -eq 2) 'Existing matching firewall rules were replaced'
        $instance=$script:undo[0].instance;$ruleID=$name+'-'+$instance;$rule=$state.rules[$ruleID]
        foreach($change in @('stale','legacy','program','direction','inventory','warning','duplicate')){
            $rule.Program=$program;$rule.Direction='Inbound';$state.failRead=$false;$state.warn=$false
            $pin=$instance
            switch($change){
                'stale' {$pin='f'*32}
                'legacy' {$pin=''}
                'program' {$rule.Program='C:\Other\ciadpi.exe'}
                'direction' {$rule.Direction='Outbound'}
                'inventory' {$state.failRead=$true}
                'warning' {$state.warn=$true}
                'duplicate' {$duplicate=$rule.PSObject.Copy();$duplicate.Name=$name;$state.rules[$name]=$duplicate}
            }
            $failed=$false
            try{Remove-ManagedFirewallRule $name $pin -Journal}catch{$failed=$true}
            Require ($failed -and $state.removes -eq 0) 'Unverified firewall rule reached removal'
        }
        $state.rules.Remove($name)
        $rule.Program=$program;$rule.Direction='Inbound';$state.failRead=$false;$state.keep=$true
        $file=Join-Path $root 'synthetic-firewall-component.exe'
        [IO.File]::WriteAllText($file,'inert component')
        try {
            $script:undo.Clear()
            $script:undo.Add(@{kind='file';path=$file;expectedHash=(Get-FileHash -LiteralPath $file).Hash})
            $script:undo.Add(@{kind='firewall';name=$name;instance=$instance})
            $errors=@(Rollback)
            Require ($errors.Count -eq 1 -and [IO.File]::Exists($file)) 'Firewall rollback failure removed an earlier component file'
        } finally {[IO.File]::Delete($file)}
        $outbound='AccessWeaver-byedpi-Outbound'
        $outboundID=@($state.rules.Keys | Where-Object {$_ -clike ($outbound+'-*')})[0]
        $failed=$false
        try{Remove-ManagedFirewallRule $name $instance -Journal}catch{$failed=$_.Exception.Message -ceq 'Managed firewall rule removal could not be verified'}
        Require ($failed -and $state.removes -eq 2) 'Firewall rule persistence after delete was credited as cleanup'
        $state.keep=$false
        Remove-ManagedFirewallRule $name $instance -Journal
        Remove-ManagedFirewallRule $name $instance -Journal
        Require ($state.removes -eq 3 -and -not $state.rules.ContainsKey($ruleID)) 'Firewall rollback did not verify removal or tolerate retry'
        $legacy=$state.rules[$outboundID]
        $state.rules.Remove($outboundID)
        $legacy.Name=$outbound;$legacy.Description=''
        $state.rules[$outbound]=$legacy
        Remove-ManagedFirewallRule $outbound
        Require ($state.removes -eq 4 -and $state.rules.Count -eq 0) 'Explicit cleanup did not accept a matching legacy rule'
        $script:undo.Clear()
        $script:externalEffectsPending=$false
    }

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

    $completedReceipt=Get-DNSRecoveryReceiptPath $current
    Require ([IO.File]::Exists($completedReceipt)) 'Verified recovery did not save a receipt'
    [IO.File]::Delete($completedReceipt)
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
    & {
        $attempts=[Collections.Generic.List[int]]::new()
        $delayLog=[Collections.Generic.List[int]]::new()
        function Replace-StagedWorkflowFile([string]$Staged,[string]$Target){
            if($Target -cne $snapshot){throw 'Unexpected retry fixture destination'}
            $attempts.Add($attempts.Count+1)
            if($attempts.Count -eq 1){throw [IO.IOException]::new('Inert transient replacement error',-2147023721)}
            [IO.File]::WriteAllBytes($Target,[IO.File]::ReadAllBytes($Staged))
            [IO.File]::Delete($Staged)
        }
        function Start-Sleep([int]$Milliseconds){
            $delayLog.Add($Milliseconds)
            if($fixtureChanged){[IO.File]::WriteAllText($snapshot,'independent edit')}
        }
        $fixtureChanged=$false
        Publish-WorkflowFile $snapshot $firstBytes -BeforeHash $next
        $firstHash=Get-WorkflowBytesSHA256 $firstBytes
        Require ($attempts.Count -eq 2 -and ($delayLog -join ',') -ceq '50' -and
            (Confirm-DNSRecoverySnapshot $firstHash)) 'Snapshot publication did not retry the transient replacement'
        $attempts.Clear();$delayLog.Clear();$fixtureChanged=$true
        $refused=$false
        try{Publish-WorkflowFile $snapshot $secondBytes -BeforeHash $firstHash}catch{
            $refused=$_.Exception.Message -ceq 'Workflow files changed before replacement'
        }
        Require ($refused -and $attempts.Count -eq 1 -and [IO.File]::ReadAllText($snapshot) -ceq 'independent edit') 'Snapshot retry overwrote an independent edit'
        $refused=$false
        try{Publish-WorkflowFile $snapshot $secondBytes -BeforeHash ''}catch{
            $refused=$_.Exception.Message -ceq 'Workflow files changed before replacement'
        }
        Require ($refused -and $attempts.Count -eq 1 -and [IO.File]::ReadAllText($snapshot) -ceq 'independent edit') 'Fresh snapshot publication replaced an occupied destination'
        [IO.File]::WriteAllBytes($snapshot,$secondBytes)
    }
    & {
        $config=Join-Path $root 'dnscrypt-proxy.toml'
        $backups=Join-Path $root 'backups'
        [void][IO.Directory]::CreateDirectory($backups)
        $originalUndo=$script:undo
        $script:undo=[Collections.Generic.List[object]]::new()
        try {
            Publish-WorkflowFile $config $firstBytes -Recorded -BeforeHash ''
            $originalHash=Get-WorkflowBytesSHA256 $firstBytes
            Require ((Get-WorkflowFileHash $config) -ceq $originalHash -and $script:undo.Count -eq 1) 'New configuration publication was not recorded'
            $record=$script:undo[0]
            Publish-WorkflowFile $config $secondBytes -Recorded -BeforeHash $originalHash
            Require ((Get-WorkflowFileHash $config) -ceq $next -and $record.expectedHash -ceq $next -and
                -not $record.ContainsKey('pendingHash')) 'Configuration replacement was not recorded'
            [IO.File]::WriteAllText($config,'independent edit')
            $refused=$false
            try{Publish-WorkflowFile $config $firstBytes -Recorded -BeforeHash $next}catch{
                $refused=$_.Exception.Message -ceq 'Workflow files changed before replacement'
            }
            Require ($refused -and [IO.File]::ReadAllText($config) -ceq 'independent edit' -and
                $record.expectedHash -ceq $next -and -not $record.ContainsKey('pendingHash')) 'Recorded publication overwrote an independent configuration'
        } finally {
            [IO.File]::Delete($config)
            foreach($entry in $script:undo){
                if($entry.backup){[IO.File]::Delete($entry.backup)}
            }
            [IO.Directory]::Delete($backups)
            $script:undo=$originalUndo
        }
    }
    & {
        $receiptPath=Get-DNSRecoveryReceiptPath $next
        function Replace-StagedWorkflowFile([string]$Staged,[string]$Target){
            if($Target -cne $receiptPath){throw 'Unexpected receipt fixture destination'}
            if($publishCorruptReceipt){[IO.File]::WriteAllText($Target,('F'*64));[IO.File]::Delete($Staged)}
        }
        foreach($publishCorruptReceipt in @($false,$true)){
            [IO.File]::WriteAllText($receiptPath,('A'*64))
            $refused=$false
            try{Save-DNSRecoveryReceipt $next}catch{
                $refused=$_.Exception.Message -ceq 'Workflow file publication could not be verified'
            }
            Require ($refused -and [IO.File]::Exists($snapshot)) 'Unverified receipt was accepted before snapshot retirement'
            [IO.File]::Delete($receiptPath)
        }
    }
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
    $serviceUndo=@{kind='service';name='AccessWeaver-dnscrypt';commandSHA256=(Get-ManagedServiceCommandDigest $script:serviceCommand)}
    $dnsUndo=@{kind='dns';snapshotSHA256=$next;snapshotActive=$true}
    $script:undo.Clear()
    foreach($entry in @($dnsUndo,$fileUndo,$serviceUndo)){$script:undo.Add($entry)}

    $script:order.Clear()
    $originalCommand=$script:serviceCommand
    $script:serviceCommand='inert service-host command --instance='+('2'*32)
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and $rollback[0] -ceq 'Recovery journal does not match the current managed service' -and
        $script:order.Count -eq 0 -and [IO.File]::Exists($snapshot) -and [IO.File]::Exists($serviceConfig)) 'Stale service rollback changed DNS or files'
    $script:serviceCommand=$originalCommand
    $script:saved=@($dnsUndo,@{kind='service';name='AccessWeaver-dnscrypt'})
    $refused=$false
    try{Recover-Operation}catch{$refused=$_.Exception.Message -match '^Recovery journal has no service binding'}
    Require ($refused -and $script:order.Count -eq 0 -and [IO.File]::Exists($snapshot)) 'Unbound service journal reached recovery'
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
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and ($script:order -join ',') -ceq 'query' -and
        [IO.File]::Exists($serviceConfig)) 'Missing active snapshot tore down the resolver'
    $script:order.Clear()

    $script:saved=@($dnsUndo,$serviceUndo)
    $script:undo.Clear()
    $refused=$false
    try{Recover-Operation}catch{$refused=$_.Exception.Message -match 'missing without a verified restoration receipt'}
    Require ($refused -and $script:order.Count -eq 0 -and $script:undo.Count -eq 0) 'Fresh worker trusted an absent active snapshot'
    $receipt=Get-DNSRecoveryReceiptPath $next
    [IO.File]::WriteAllText($receipt,('X'*64))
    $refused=$false
    try{Recover-Operation}catch{$refused=$_.Exception.Message -match 'missing without a verified restoration receipt'}
    Require ($refused -and $script:order.Count -eq 0) 'Malformed restoration receipt allowed teardown'
    [IO.File]::Delete($receipt)

    foreach($size in @(0,63,65,8192)){
        [IO.File]::WriteAllText($receipt,('A'*$size))
        $refused=$false
        try{Recover-Operation}catch{$refused=$_.Exception.Message -match 'missing without a verified restoration receipt'}
        Require ($refused -and $script:order.Count -eq 0) 'Wrong-size restoration receipt allowed teardown'
    }
    [IO.File]::WriteAllText($receipt,$next.ToUpperInvariant())
    $receiptLock=[IO.File]::Open($receipt,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{
        $refused=$false
        try{Recover-Operation}catch{$refused=$_.Exception.Message -match 'missing without a verified restoration receipt'}
        Require ($refused -and $script:order.Count -eq 0) 'Locked restoration receipt allowed teardown'
    }finally{$receiptLock.Dispose()}
    Require (-not (Confirm-DNSRecoveryEntry $dnsUndo)) 'An exact restoration receipt did not allow cleanup'
    & {
        $readRecoveryFile=(Get-Command Read-DNSRecoveryFileBytes).ScriptBlock
        function Read-DNSRecoveryFileBytes([string]$Path,[int]$Maximum){
            $frame=& $readRecoveryFile $Path $Maximum
            if($Path -ceq $receipt){[IO.File]::WriteAllBytes($snapshot,$reappearingSnapshot)}
            if($null -ne $frame){return ,$frame}
        }
        $reappearingSnapshot=$firstBytes
        $refused=$false
        try{Recover-Operation}catch{$refused=$_.Exception.Message -match 'does not match the active snapshot'}
        Require ($refused -and $script:order.Count -eq 0 -and [IO.File]::Exists($snapshot)) 'Receipt bypassed a newly active different snapshot'
        [IO.File]::Delete($snapshot)
        $reappearingSnapshot=$secondBytes
        Require (Confirm-DNSRecoveryEntry $dnsUndo) 'Receipt bypassed restoration of the newly active matching snapshot'
        [IO.File]::Delete($snapshot)
    }
    [IO.File]::Delete($receipt)

    $dnsUndo.snapshotActive=$false
    Require (-not (Confirm-DNSRecoveryEntry $dnsUndo)) 'Unpublished snapshot was treated as active'
    $dnsUndo.snapshotActive=$true
    foreach($entry in @($dnsUndo,$fileUndo,$serviceUndo)){$script:undo.Add($entry)}
    Publish-WorkflowFile $snapshot $secondBytes
    $script:serviceFault='pending-then-absent'
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 0 -and ($script:order -join ',') -ceq 'restore,query,stop,wait-stopped,delete,query,query' -and
        -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($serviceConfig)) 'Retry did not verify service removal before file rollback'
    $script:order.Clear()
    Recover-Operation
    $script:undo.Insert(1,$fileUndo)
    Require (($script:order -join ',') -ceq 'query,query,query') 'Already retired service was mutated during retry'

    $failureModes=@(
        @{fault='inspect';trace='query'},
        @{fault='truncated';trace='query'},
        @{fault='identity';trace='query'},
        @{fault='stop-command';trace='query,query,stop'},
        @{fault='stop-timeout';trace='query,query,stop,wait-stopped'}
    )
    foreach($case in $failureModes){
        [IO.File]::WriteAllText($serviceConfig,'inert resolver configuration')
        $script:serviceFault=$case.fault;$script:serviceState='running';$script:order.Clear()
        $rollback=@(Rollback)
        Require ($rollback.Count -eq 1 -and ($script:order -join ',') -ceq $case.trace -and
            (Get-FileHash -LiteralPath $serviceConfig).Hash -ceq $configHash) 'Unverified service rollback removed a dependent file'
    }
    $script:resolverInUse=$true;$script:serviceFault='';$script:serviceState='running';$script:order.Clear()
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and $rollback[0] -match '^DNSCrypt service retained' -and
        $script:serviceState -ceq 'running' -and ($script:order -join ',') -ceq 'query,query' -and
        (Get-FileHash -LiteralPath $serviceConfig).Hash -ceq $configHash) 'Rollback stopped a resolver that was still needed'
    $script:resolverInUse=$false
    $script:serviceFault='pending';$script:serviceState='stopped';$script:order.Clear()
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 1 -and $rollback[0] -match '^Managed service removal is pending' -and
        $script:order[0] -ceq 'query' -and $script:order[2] -ceq 'stop' -and $script:order[3] -ceq 'delete' -and
        [IO.File]::Exists($serviceConfig)) 'Delete acceptance was mistaken for verified service removal'
    $script:serviceFault='';$script:order.Clear()
    $rollback=@(Rollback)
    Require ($rollback.Count -eq 0 -and ($script:order -join ',') -ceq 'query,query' -and
        -not [IO.File]::Exists($serviceConfig)) 'Retry did not complete deferred file recovery'
    [IO.File]::Delete($receipt)

    $services=Join-Path $root 'services'
    [void][IO.Directory]::CreateDirectory($services)
    $hostBytes=[Text.Encoding]::UTF8.GetBytes('synthetic service host')
    $hostHash=(Get-WorkflowBytesSHA256 $hostBytes).ToLowerInvariant()
    $hostPath=Join-Path $services ('host-'+$hostHash+'.exe')
    $config=Join-Path $services 'dnscrypt.json'
    $registration=Join-Path $services 'dnscrypt.registration'
    [IO.File]::WriteAllBytes($hostPath,$hostBytes)
    [IO.File]::WriteAllText($config,'synthetic protected service config')
    $legacyCommand=(Quote-Arg $hostPath)+' service-host '+(Quote-Arg $config)
    $modernCommand=$legacyCommand+' --instance='+('a'*32)
    $script:serviceState='running';$script:order.Clear()
    $script:serviceCommand=$legacyCommand
    $entry=Assert-ManagedServiceOwnership 'AccessWeaver-dnscrypt'
    Require ($entry.commandSHA256 -ceq (Get-ManagedServiceCommandDigest $legacyCommand)) 'Protected legacy registration was refused'

    $script:serviceCommand=$modernCommand
    $refused=$false
    try {Assert-ManagedServiceOwnership 'AccessWeaver-dnscrypt'}catch{$refused=$true}
    Require $refused 'Modern registration without its ownership record was accepted'
    [IO.File]::WriteAllText($registration,(Get-ManagedServiceCommandDigest $modernCommand))
    $entry=Assert-ManagedServiceOwnership 'AccessWeaver-dnscrypt'
    Require ($entry.commandSHA256 -ceq (Get-ManagedServiceCommandDigest $modernCommand)) 'Exact protected modern registration was refused'

    foreach($command in @($legacyCommand,($legacyCommand+' --instance='+('b'*32)),($modernCommand.Replace($config,(Join-Path $root 'other.json'))),'foreign.exe')){
        $script:serviceCommand=$command
        $refused=$false
        try {Assert-ManagedServiceOwnership 'AccessWeaver-dnscrypt'}catch{$refused=$true}
        Require $refused 'A substituted registration was accepted for explicit removal'
    }
    $script:serviceCommand=$modernCommand
    [IO.File]::WriteAllText($hostPath,'replacement host')
    $refused=$false
    try {Assert-ManagedServiceOwnership 'AccessWeaver-dnscrypt'}catch{$refused=$_.Exception.Message -match '^Managed service host content differs'}
    Require ($refused -and @($script:order | Where-Object {$_ -cne 'query'}).Count -eq 0) 'Changed host reached service mutation'
    [IO.File]::WriteAllBytes($hostPath,$hostBytes)
    $entry=Assert-ManagedServiceOwnership 'AccessWeaver-dnscrypt'
    $script:resolverInUse=$true;$script:order.Clear()
    $refused=$false
    try {Remove-RecordedService 'AccessWeaver-dnscrypt' -Entry $entry}catch{$refused=$_.Exception.Message -match '^DNSCrypt service retained'}
    Require ($refused -and $script:serviceState -ceq 'running' -and
        ($script:order -join ',') -ceq 'query') 'Explicit removal stopped a resolver that was still needed'
    $script:resolverInUse=$false
    Remove-RecordedService 'AccessWeaver-dnscrypt' -Entry $entry
    Require ($script:serviceState -ceq 'absent') 'Verified explicit removal did not retire the service'
} finally {
    foreach($path in @($registration,$config,$hostPath)){if($path){[IO.File]::Delete($path)}}
    if($services){[IO.Directory]::Delete($services)}
    $env:SystemRoot=$originalSystemRoot
    [IO.File]::Delete($serviceConfig)
    [IO.File]::Delete($snapshot)
    [IO.File]::Delete($script:journalPath)
    foreach($digest in @($current,$next)){
        if($digest){[IO.File]::Delete((Get-DNSRecoveryReceiptPath $digest))}
    }
    [IO.Directory]::Delete($profiles)
    [IO.Directory]::Delete($root)
}
Write-Output 'DNS journal binding, DNS-first remove-all, firewall and service ownership, retirement, rollback and publication checks passed.'
