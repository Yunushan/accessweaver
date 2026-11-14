# Selected-function contracts only: no worker top level or real OS DNS/registry,
# service, network, process, account or installation operations are invoked.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell,[string]$ReportPath)
$ErrorActionPreference='Stop'
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Windows PowerShell 5.1 Desktop is required'}
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Management','Microsoft.PowerShell.Management.psd1')) -ErrorAction Stop
$PSModuleAutoLoadingPreference='None'
$reportParent=$null;$reportCreated=0
if($ReportPath){
    if(-not [IO.Path]::IsPathRooted($ReportPath)){throw 'Contract report needs an absolute owned path'}
    $ReportPath=[IO.Path]::GetFullPath($ReportPath)
    $reportParent=Microsoft.PowerShell.Management\Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ReportPath)) -Force -ErrorAction Stop
    if(-not $reportParent.PSIsContainer -or ($reportParent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($reportParent.FullName).Length -ne 0){throw 'Contract report needs an existing empty ordinary parent'}
    $reportCreated=$reportParent.CreationTimeUtc.Ticks
}
$project=Split-Path -Parent $PSScriptRoot
$sourcePath=Join-Path $project 'internal/workflow/windows.ps1'
$sourceHash=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'DNS workflow source did not parse'}
$selected=@('Assert-DNSCryptConfiguration','Restore-DNSCryptAfterRestartFailure','Assert-DNSCryptServiceState','Read-ManagedServiceCommand','Read-ManagedServiceRegistration','Get-ManagedServiceCommandDigest','Assert-DNSMutationAdapter','Test-DNSRecoveryUsesAdapterOwnership','Test-DNSFamilyMatchesOriginal','Read-ObservedDNSFamily','Test-DNSFamilyNeedsRollback','Get-ActiveDNSAdapters','Assert-ConfiguredDNSDohPolicy','Get-DNSDohProviders','Test-DNSRecoveryUsesDohOwnership','Get-DNSOriginalDohEntry','Test-DNSDohEntriesEqual','Test-DNSRecoveryOwnsDoh','Get-DNSClientMutationRow','Read-DNSRecoveryFileBytes','Read-DNSRecoverySnapshot','Assert-DNSRecoverySnapshotUnchanged','Read-WorkflowRecoveryJournalBytes','Throw-WorkflowRecoveryJournalReadFailure','Get-WorkflowBytesSHA256','Confirm-DNSRecoverySnapshot','Get-DNSRecoverySnapshotDigest','Assert-ConfiguredDNSServers','Assert-RestoredDNSState','Get-StaticDNSServers','Get-DNSClientFamily','Read-DNSClientInventory','Get-DNSClientRows','Get-OriginalDNSBounds','Assert-OriginalDNSModes','Read-OriginalDNSFamily','Read-OriginalDNSAdapter','Read-OriginalDNSNameServer','Read-DNSStaticOverride','Test-DNSIPv4Answer','Wait-DNSCryptListeners','Get-DNSCryptAdapterIdentities','Test-DNSCryptListenerNeeded','Configure-DNS','Restore-DNS','Remove-Method','Remove-All')
$allowed=@('Read-OwnedWireSockProfile','Remove-WireSockRefreshTask','Disconnect-OwnedWireSock','Native','Remove-ModernWireSockProfile','Restore-Drover','Get-ManagedFirewallRule','Remove-RecordedService','Remove-ManagedFirewallRule','Remove-Method','Under','Assert-DNSCryptConfiguration','Restore-DNSCryptAfterRestartFailure','Assert-DNSCryptServiceState','Read-ManagedServiceCommand','Read-ManagedServiceRegistration','Get-ManagedServiceCommandDigest','Get-CimInstance','Assert-DNSMutationAdapter','Test-DNSRecoveryUsesAdapterOwnership','Test-DNSFamilyMatchesOriginal','Read-ObservedDNSFamily','Test-DNSFamilyNeedsRollback','Get-ActiveDNSAdapters','Assert-ConfiguredDNSDohPolicy','Get-DNSDohProviders','Test-DNSRecoveryUsesDohOwnership','Get-DNSOriginalDohEntry','Test-DNSDohEntriesEqual','Test-DNSRecoveryOwnsDoh','Get-DNSClientMutationRow','Read-DNSRecoveryFileBytes','Read-DNSRecoverySnapshot','Assert-DNSRecoverySnapshotUnchanged','Read-WorkflowRecoveryJournalBytes','Throw-WorkflowRecoveryJournalReadFailure','Get-WorkflowBytesSHA256','Confirm-DNSRecoverySnapshot','Get-DNSRecoverySnapshotDigest','Save-DNSRecoveryReceipt','Publish-WorkflowFile','No-Reparse','Get-Item','Assert-ConfiguredDNSServers','Assert-RestoredDNSState','Get-StaticDNSServers','Get-DNSClientFamily','Read-DNSClientInventory','Get-DNSClientRows','Get-OriginalDNSBounds','Assert-OriginalDNSModes','Read-OriginalDNSFamily','Read-OriginalDNSAdapter','Read-OriginalDNSNameServer','Read-DNSStaticOverride','Test-DNSIPv4Answer','Wait-DNSCryptListeners','Get-DNSCryptAdapterIdentities','Test-DNSCryptListenerNeeded','Restore-DNS','Get-ItemProperty','Get-Command','Join-Path','Get-NetAdapter','Where-Object','ForEach-Object','Select-Object','Test-Path','Get-DnsClientServerAddress','Get-DnsClientDohServerAddress','Get-FileHash','Add-Member','ConvertTo-Json','Save-Journal','Ensure-Asset','Split-Path','Assert-ManagedServiceOwnership','Assert-RecordedServiceBinding','Get-Service','Restore-RecordedWorkflowFile','Install-EngineService','Set-Service','Start-Service','Restart-Service','Stop-Service','Set-DnsClientDohServerAddress','Add-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress','Set-DnsClientServerAddress','Clear-DnsClientCache','Resolve-DnsName','Start-Sleep','Event','ConvertFrom-Json','Remove-Item')
foreach($name in $selected){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required DNS function is unavailable'}
    foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
        $commandName=$command.GetCommandName()
        if(-not $commandName -or $commandName -notin $allowed){throw 'DNS contract source contains an unapproved command boundary'}
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
if((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne $sourceHash){throw 'DNS source changed while selecting functions'}
$ownerPath=[IO.Path]::GetFullPath([IO.Path]::Combine([IO.Path]::GetTempPath(),('accessweaver-dns-contracts-'+[guid]::NewGuid().ToString('N'))))
$owner=[IO.Directory]::CreateDirectory($ownerPath)
$ownerMarker=[IO.Path]::Combine($ownerPath,'.fixture-owner')
$ownerToken=[guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($ownerMarker,$ownerToken,[Text.UTF8Encoding]::new($false))
$script:checks=0;$script:caseNumber=0
$script:contractOutcome='failed';$script:contractCode='unexpected-contract-error'
$script:closedContractCodes=@('doh-keeps-listener-for-adapter-identity-drift','doh-keeps-listener-for-owned-inactive-adapter','doh-stops-listener-after-last-adapter-switch','doh-keeps-listener-for-excluded-adapter','doh-keeps-listener-for-original-static-dns','stored-dns-mismatch-before-effects','stored-dns-restore-retains-snapshot','configure-refuses-drift-during-resolver-query','configure-ignores-unselected-adapter-during-resolver-query','configure-doh-preserves-independent-policy','restore-doh-refuses-unowned-policy','restore-doh-resumes-partial-configuration','restore-doh-conditional-needs-capability','restore-doh-rejects-invalid-ownership','configure-doh-refuses-stale-reconfiguration','restore-doh-refuses-concurrent-policy','restore-doh-keeps-independent-policy','rollback-keeps-independent-adapter-settings','rollback-skips-restored-adapter-family','restore-doh-repairs-stable-malformed-policy','configure-dnscrypt-loopback-readback','doh-keeps-old-resolver-until-verified','dns-service-ownership-before-effects','dns-service-binding-before-mutation','dnscrypt-preserves-independent-doh','first-doh-captures-global-policy','dnscrypt-keeps-existing-doh-originals','invalid-doh-recovery-scope','dnscrypt-restarts-verified-service','dnscrypt-reuses-unchanged-configuration','dnscrypt-listeners-before-adapters','dnscrypt-listener-retries-only-unready-family','dnscrypt-listener-refusal-preserves-adapter-state','dnscrypt-listener-refuses-invalid-answers','ordinary-resolver-requires-address-answer','configure-adapter-readback-refuses','configure-adapter-readback-retains','configure-adapter-readback-retries','configure-adapter-readback-recovers','configure-post-policy-refuses','configure-post-policy-recovers','configure-policy-readback-before-adapters','configure-policy-refusal-retains-recovery','configure-policy-recovery-completes','configure-policy-query-before-verification','scope-capture-flat-ordered','scope-rebinds-current-adapter','scope-family-extension','scope-invalid-before-effects','scope-dhcp-reset-preserved','scope-global-and-ipv4-preserved','changed-adapter-retains-before-interface-read','capture-index-change-before-snapshot','capture-drift-before-snapshot','capture-drift-before-adapter-write','reconfigure-preserves-independent-adapter-dns','non-dns-adapter-not-targeted','single-family-capture-and-restore','new-family-originals-extended','family-extension-before-effects','client-inventory-before-effects','family-flags-preflight','owned-family-missing-retained','invalid-recovery-identities-before-inspection','restore-uses-refreshed-guid-index','changed-adapter-retains-before-dns-read','case-insensitive-down-adapter-restoration','reconfiguration-rotates-recovery-identity','existing-originals-never-recaptured','new-adapter-originals-persisted','extended-snapshot-restores-both-adapters','extension-failure-before-effects','invalid-configuration-preflight','configuration-uses-current-guid-index','source-uncovered-dns-write','absent','absent-entry-idempotence-and-unrelated-preservation','accessweaver-dns-contracts-','add','all-providers-no-plaintext-fallback','ambiguous-adapter','bad-doh','bad-flags','capture-inspection-failure-not-empty','case','confirmed-absent-entry-not-removed-again','confirmed-absent-mode-is-dhcp','current-doh-query-before-effects','dns','doh','duplicate-doh','empty-adapters','empty-static','exact-original-doh-restored','expected-refusal','false','fixture-cleanup-incomplete','guid-recovery-uses-current-index','invalid-recovery-preflight','legacy-no-doh-recovery-supported','malformed-mode-not-empty','missing-adapter','no-false-restored-event','none','original-snapshot-retained','partial-removal-retains-needed-recovery','profiles','recovery-retry-completes-after-confirmed-inspection','registry-error-not-dhcp','remove','snapshot-publication-binds-prior-bytes','snapshot-frame-refused','snapshot-preflight-change-refused','snapshot-journal-digest-refused','configure-interface-reuse-before-setter','restore-interface-reuse-before-setter','restore-retirement-requires-absence','restore-retirement-refuses-replaced-snapshot','restore-delayed-observation','restore-adapter-row-fence','restore-inspection-before-effects','saved-doh-needs-capability','set','snapshot-before-native-effects','journal-before-snapshot','snapshot-must-match-journal','activation-before-native-effects','receipt-before-retirement','source-doh-inspection-failed','source-doh-mutation-failed','source-registry-inspection-failed','source-snapshot-removal-failed','source-snapshot-write-failed','true','unexpected-contract-error','unknown-test-code')
function Assert-DNS([bool]$Condition,[string]$Code){if(-not $Condition){$script:contractCode=if($Code -in $script:closedContractCodes){$Code}else{'unknown-test-code'};throw ('DNS contract failed: '+$script:contractCode)};$script:checks++}
function Reject-DNS([scriptblock]$Operation,[string]$ExpectedMessage){
    $failed=$false
    try{& $Operation | Out-Null}catch{$failed=-not $ExpectedMessage -or $_.Exception.Message.StartsWith($ExpectedMessage,[StringComparison]::Ordinal)}
    Assert-DNS $failed 'expected-refusal'
}
function New-DNSCase {
    $script:caseNumber++
    $script:root=[IO.Path]::Combine($ownerPath,('case'+$script:caseNumber))
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($root,'profiles'))
    $script:snapshot=Join-Path $root 'profiles/dns-original.json'
    $script:present=@{'Get-DnsClientDohServerAddress'=$true;'Set-DnsClientDohServerAddress'=$true;'Add-DnsClientDohServerAddress'=$true;'Remove-DnsClientDohServerAddress'=$true}
    $script:adapters=@([pscustomobject]@{Status='Up';InterfaceDescription='Fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000001}';ifIndex=77})
    $script:mode4='192.0.2.53';$script:mode6='absent';$script:registryFailure='';$script:emptyDnsRead=$false;$script:failDohRead=0;$script:dohReads=0
    $script:storedDNS=@{};$script:storedDNSFault='';$script:captureDrift=''
    $script:exposure=@{};$script:renumberAfterInventory=$false;$script:inventoryFailure=$false;$script:duplicateInventory=$false;$script:numericFamilies=$false
    $script:appliedDNS=@{};$script:readbackFault='';$script:readbackFaultArmed=$false;$script:silentDohFault='';$script:registryReads=[Collections.Generic.List[string]]::new();$script:dnsValues=@{};$script:renumberDuringDoh=$false;$script:reuseIndexDuringDoh=$false;$script:disappearDuringDoh=$false;$script:dnsReadCount=0;$script:dnsInterfaceReads=0
    $script:replaceSnapshotOnAdapterRead=$false;$script:replaceSnapshotOnJournalSave=$false
    $script:hiddenInventoryReads=0;$script:hiddenInventoryDrift=''
    $script:replaceSnapshotOnReceiptSave=$false
    $script:replaceSnapshotOnActivation=$false;$script:replaceSnapshotOnInterfaceRead=0
    $script:failAction='';$script:failAddress='';$script:failDelete=$false;$script:failSnapshotWrite=$false;$script:failJournalWrite=$false;$script:corruptSnapshotWrite=$false;$script:failActivationWrite=$false;$script:failReceiptWrite=$false
    $script:configureDohReadFault='';$script:postConfigureDohReadFault='';$script:configureDohFaultAddress='';$script:resolverQueries=0;$script:configurationLag=0;$script:readbackWaits=0
    $script:resolverServicePresent=$false;$script:resolverOwnershipFault=$false;$script:resolverBindingFailureRead=0;$script:resolverBindingReads=0;$script:serviceRestarts=0;$script:dnscryptConfigReads=0;$script:dnscryptConfigWrites=0;$script:stageDNSCrypt=$false;$script:changeDNSCryptBeforePublish=$false;$script:changeDNSCryptAfter='';$script:failDNSCryptRestart=$false;$script:allowNewResolver=$false;$script:newResolverRegistered=$false;$script:serviceStops=0;$script:serviceStartupChanges=0
    $script:resolverReadbacks=0;$script:resolverReadbackFault='';$script:expectedResolverStartup=''
    $script:resolverStopped=$false;$script:serviceStarts=0
    $script:restartRecoveryOriginal=$null;$script:restartRecoveryWrites=0;$script:restartRecoveryFault=''
    $script:resolverCommand='synthetic DNSCrypt service command'
    $script:resolverDigest=Get-ManagedServiceCommandDigest $script:resolverCommand
    $script:listenerQueries=[Collections.Generic.List[string]]::new()
    $script:ordinaryResolverWaits=0;$script:emptyOrdinaryAnswers=0;$script:resolverDrift=''
    $script:listenerReplies=@{};$script:listenerChecksBeforeAdapters=$true;$script:listenerWaits=0;$script:refuseListenerWait=$false
    $script:dnsRowFault='';$script:unverifiedDNSWrites=0;$script:failDNSSetterFamily=''
    $script:recoveryLag=0;$script:renumberDuringRecoveryRead=$false;$script:reuseBeforeDNSSetter=$false;$script:reuseOnFinalRegistryRead=$false;$script:silentSnapshotRemoval=$false
    $script:changeDohAfterAdapterWrite='';$script:changeDohAfterProviderWrite=$false
    $script:changeDohOnActivation='';$script:changeDNSOnActivation=''
    $script:currentDoh=@{};$script:calls=[Collections.Generic.List[object]]::new();$script:events=[Collections.Generic.List[string]]::new()
    $script:undo=[Collections.Generic.List[object]]::new();$script:dnsConfigured=$false;$script:journals=0;$script:journalDigest=$null;$script:journalActive=$false;$script:receiptDigest=$null
}
function Original-DNSFixture {
    return @{adapters=@(@{guid='{00000000-0000-0000-0000-000000000001}';index=77;ipv4=@('192.0.2.53');ipv6=@('2001:db8::53');dhcp4=$false;dhcp6=$true});doh=@()}
}
function Old-DohFixture {return [pscustomobject]@{ServerAddress='8.8.8.8';DohTemplate='https://original.invalid/dns-query';AllowFallbackToUdp=$true;AutoUpgrade=$false}}
function Write-DNSFixture([object]$Data){[IO.File]::WriteAllText($snapshot,(Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Data -Depth 12),[Text.UTF8Encoding]::new($false))}
function Assert-SnapshotRetained([string]$Hash){Assert-DNS ([IO.File]::Exists($snapshot) -and (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -ceq $Hash) 'original-snapshot-retained';Assert-DNS (-not ($script:events -contains 'Original DNS and DoH settings restored')) 'no-false-restored-event'}
function Snapshot-Hash {return (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash}
function Mutation-Count {return @($script:calls | Where-Object {$_.kind -in @('dns','add','set','remove')}).Count}
# Every OS/state-changing command reachable from the selected functions is a
# closed source fixture. Command discovery is mocked too; no module fallback.
function Get-Command {[CmdletBinding()]param([string[]]$Name);foreach($item in $Name){if(-not $script:present.ContainsKey($item)){throw 'Unexpected DNS command discovery'};if($script:present[$item]){[pscustomobject]@{Name=$item;CommandType='Function'}}}}
function Get-NetAdapter {
    [CmdletBinding()]param([switch]$IncludeHidden)
    if($script:replaceSnapshotOnAdapterRead){
        $script:replaceSnapshotOnAdapterRead=$false
        [IO.File]::AppendAllText($snapshot,' ')
    }
    if($IncludeHidden){
        $script:hiddenInventoryReads++
        if($script:hiddenInventoryReads -eq 2){
            switch($script:hiddenInventoryDrift){
                'renumber' {$script:adapters[0].ifIndex=101}
                'replace' {$script:adapters[0].InterfaceGuid='{00000000-0000-0000-0000-000000000003}'}
                'duplicate-index' {$script:adapters[1].ifIndex=$script:adapters[0].ifIndex}
                'duplicate-guid' {$script:adapters[1].InterfaceGuid=$script:adapters[0].InterfaceGuid}
                'missing' {$script:adapters=@($script:adapters[0])}
                'unreadable' {throw 'source hidden adapter inventory failure'}
            }
        }
    }
    foreach($adapter in $script:adapters){
        [pscustomobject]@{Status=$adapter.Status;InterfaceDescription=$adapter.InterfaceDescription;InterfaceGuid=$adapter.InterfaceGuid;ifIndex=$adapter.ifIndex}
    }
}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Name)
    if($LiteralPath -notmatch '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6?\\Parameters\\Interfaces\\'){throw 'Unexpected registry fixture path'}
    if((Mutation-Count) -eq 0){$script:registryReads.Add($LiteralPath)}
    $family=if($LiteralPath -match 'Tcpip6'){'IPv6'}else{'IPv4'}
    $guid=$LiteralPath.Substring($LiteralPath.LastIndexOf('\')+1);$matching=@($script:adapters | Where-Object {$_.InterfaceGuid -eq $guid});if($matching.Count -eq 1){$key=([string]$matching[0].ifIndex)+'/'+$family;if($script:exposure.ContainsKey($key) -and -not $script:exposure[$key]){throw 'source-unexposed-registry-read'}}
    if($script:registryFailure -eq $family){Write-Error 'source-registry-inspection-failed';return}
    $stateKey=$guid+'/'+$family
    if($script:reuseOnFinalRegistryRead -and $script:dnsInterfaceReads -eq 1){
        $script:reuseOnFinalRegistryRead=$false
        $script:adapters[0].ifIndex=101
        $script:adapters+=@([pscustomobject]@{
            Status='Up';InterfaceDescription='Replacement fixture adapter'
            InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=77
        })
    }
    if($script:appliedDNS.ContainsKey($stateKey)){
        $state=$script:appliedDNS[$stateKey]
        if($script:storedDNS.ContainsKey($stateKey)){return [pscustomobject]@{NameServer=$script:storedDNS[$stateKey]}}
        if($script:storedDNSFault -ceq 'dhcp'){return [pscustomobject]@{NameServer=''}}
        if($script:storedDNSFault -ceq 'wrong-address' -and $family -ceq 'IPv4'){return [pscustomobject]@{NameServer='198.51.100.99'}}
        return [pscustomobject]@{NameServer=$(if($state.dhcp){''}else{$state.values -join ', '})}
    }
    if($script:storedDNS.ContainsKey($stateKey)){return [pscustomobject]@{NameServer=$script:storedDNS[$stateKey]}}
    $value=if($family -eq 'IPv4'){$script:mode4}else{$script:mode6}
    if($value -is [string] -and $value -ceq 'absent'){return [pscustomobject]@{}}
    if($value -is [string] -and $matching.Count -eq 1 -and $script:dnsValues.ContainsKey($key) -and $script:dnsValues[$key].Count -gt 0){$value=$script:dnsValues[$key] -join ', '}
    if($script:captureDrift -and $family -ceq 'IPv4'){
        if($script:captureDrift -ceq 'mode'){$script:mode4='absent'}
        else {$script:dnsValues[$key]=@('198.51.100.53')}
        $script:captureDrift=''
    }
    return [pscustomobject]@{NameServer=$value}
}
function Get-DnsClientServerAddress {
    [CmdletBinding()]param($InterfaceIndex,$AddressFamily)
    $script:dnsReadCount++;if($null -ne $InterfaceIndex){$script:dnsInterfaceReads++}
    if($script:inventoryFailure -or $script:readbackFaultArmed){throw 'source-client-inventory-failed'}
    if($script:emptyDnsRead){return}
    $recoveryLagged=$null -eq $InterfaceIndex -and $script:recoveryLag -gt 0 -and (Mutation-Count) -gt 0
    if($recoveryLagged){$script:recoveryLag--}
    $lagged=($null -eq $InterfaceIndex -and $script:configurationLag -gt 0 -and $script:appliedDNS.Count -gt 0);if($lagged){$script:configurationLag--}
    $indexes=[Collections.Generic.HashSet[int]]::new()
    foreach($adapter in $script:adapters){
        if($null -ne $InterfaceIndex -and $adapter.ifIndex -ne $InterfaceIndex){continue}
        if(-not $indexes.Add([int]$adapter.ifIndex)){continue}
        foreach($family in @('IPv4','IPv6')){
            if($AddressFamily -and $family -ne $AddressFamily){continue}
            $key=([string]$adapter.ifIndex)+'/'+$family
            if($script:exposure.ContainsKey($key) -and -not $script:exposure[$key]){continue}
            $stateKey=([string]$adapter.InterfaceGuid)+'/'+$family
            $values=if($script:appliedDNS.ContainsKey($stateKey)){@($script:appliedDNS[$stateKey].values)}elseif($script:dnsValues.ContainsKey($key)){@($script:dnsValues[$key])}elseif($family -eq 'IPv4'){@('192.0.2.53')}else{@('2001:db8::53')}
            if($lagged -and $family -ceq 'IPv4'){$values=@('192.0.2.53')}
            if($recoveryLagged -and $family -ceq 'IPv4'){$values=@('198.51.100.90')}
            $af=if($script:numericFamilies){if($family -eq 'IPv4'){2}else{23}}else{$family}
            $row=[pscustomobject]@{InterfaceIndex=$adapter.ifIndex;AddressFamily=$af;ServerAddresses=@($values)}
            if($null -ne $InterfaceIndex){
                if($script:dnsRowFault -eq 'index'){$row.InterfaceIndex=99}
                if($script:dnsRowFault -eq 'family'){$row.AddressFamily='IPv6'}
            }
            $row
            if($script:duplicateInventory -and $null -eq $InterfaceIndex){$row}
        }
    }
    if($null -ne $InterfaceIndex -and $script:dnsInterfaceReads -eq $script:replaceSnapshotOnInterfaceRead){
        [IO.File]::AppendAllText($snapshot,' ')
    }
    if($null -ne $InterfaceIndex -and $script:dnsRowFault -eq 'status'){$script:adapters[0].Status='Disconnected'}
    if($null -ne $InterfaceIndex -and $script:reuseBeforeDNSSetter){
        $script:adapters[0].ifIndex=101
        $script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='Replacement fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=77})
        $script:reuseBeforeDNSSetter=$false
    }
    if($null -eq $InterfaceIndex -and $script:renumberDuringRecoveryRead -and (Mutation-Count) -gt 0){
        $script:adapters[0].ifIndex=101
        $script:renumberDuringRecoveryRead=$false
    }
    if($null -eq $InterfaceIndex -and $script:renumberAfterInventory){$script:adapters[0].ifIndex=101;$script:renumberAfterInventory=$false}
}
function Set-DnsClientServerAddress {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,$InterfaceIndex,[string[]]$ServerAddresses,[switch]$ResetServerAddresses)
    process {
        $script:unverifiedDNSWrites++
        $index=if($null -ne $InputObject){$InputObject.InterfaceIndex}else{$InterfaceIndex}
        $matches=@($script:adapters | Where-Object {$_.ifIndex -eq $index});$saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
        $records=@($saved.adapters | Where-Object {$_.guid -eq $matches[0].InterfaceGuid})
        if($matches.Count -ne 1 -or $records.Count -ne 1){throw 'source-uncovered-dns-write'}
        $family=Get-DNSClientFamily $InputObject.AddressFamily;$number=if($family -eq 'IPv4'){'4'}else{'6'};$bounds=Get-OriginalDNSBounds $records[0]
        if(-not $bounds['bound'+$number]){throw 'source-uncovered-family-write'}
        if($family -ceq $script:failDNSSetterFamily){throw 'source-dns-setter-failed'}
        $script:calls.Add(@{kind='dns';index=$index;family=$family;servers=@($ServerAddresses);reset=[bool]$ResetServerAddresses})
        if($script:changeDohAfterAdapterWrite){
            switch ($script:changeDohAfterAdapterWrite){
                'add' {$script:currentDoh['8.8.8.8']=Old-DohFixture;$script:currentDoh['8.8.8.8'].DohTemplate='https://independent.invalid/dns-query'}
                'remove' {$script:currentDoh.Remove('8.8.8.8')}
                'template' {$script:currentDoh['8.8.8.8'].DohTemplate='https://independent.invalid/dns-query'}
                'fallback' {$script:currentDoh['8.8.8.8'].AllowFallbackToUdp=$false}
                'upgrade' {$script:currentDoh['8.8.8.8'].AutoUpgrade=$true}
            }
            $script:changeDohAfterAdapterWrite=''
        }
        if($script:readbackFault -ceq 'noop'){return}
        $state=@{dhcp=[bool]$ResetServerAddresses;values=@($ServerAddresses)}
        if($script:readbackFault -ceq 'wrong-mode' -and $ResetServerAddresses){$state.dhcp=$false;$state.values=@('2001:db8::99')}
        if(-not $ResetServerAddresses){
            if($script:readbackFault -ceq 'wrong-value' -and $state.values.Count -gt 0){$state.values[0]='198.51.100.99'}
            if($script:readbackFault -ceq 'empty-static'){$state.values=@()}
            if($script:readbackFault -ceq 'wrong-order' -and $state.values.Count -gt 1){[array]::Reverse($state.values)}
        }
        $script:appliedDNS[([string]$matches[0].InterfaceGuid)+'/'+$family]=$state
        if($script:readbackFault -ceq 'read-error' -and $family -ceq 'IPv6'){$script:readbackFaultArmed=$true}
        if($script:readbackFault -ceq 'adapter-missing' -and $family -ceq 'IPv6'){$script:adapters=@()}

    }
}
function Get-DnsClientDohServerAddress {
    [CmdletBinding()]param($ServerAddress)
    if(-not $script:present['Get-DnsClientDohServerAddress']){throw 'Unavailable DoH query invoked'}
    if($script:renumberDuringDoh){$script:adapters[0].ifIndex=101;$script:renumberDuringDoh=$false}
    if($script:reuseIndexDuringDoh){$script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='Replacement fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=77});$script:reuseIndexDuringDoh=$false}
    if($script:disappearDuringDoh){$script:adapters=@();$script:disappearDuringDoh=$false}
    $script:dohReads++;if($script:failDohRead -eq $script:dohReads){Write-Error 'source-doh-inspection-failed';return}
    if($ServerAddress){throw 'Per-address absent/error inference is not allowed'}
    $rows=@($script:currentDoh.Values | Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade)
    if(($script:dohReads -eq 6 -and $script:configureDohReadFault) -or ($script:dohReads -eq 7 -and $script:postConfigureDohReadFault)){
        $target=@($rows | Where-Object {$_.ServerAddress -ceq $script:configureDohFaultAddress})[0]
        $fault=if($script:dohReads -eq 6){$script:configureDohReadFault}else{$script:postConfigureDohReadFault}
        switch -CaseSensitive ($fault){
            'missing' {$rows=@($rows | Where-Object {$_.ServerAddress -cne $script:configureDohFaultAddress})}
            'duplicate' {$rows+=@($target)}
            'wrong-template' {$target.DohTemplate='https://stale.invalid/dns-query'}
            'empty-template' {$target.DohTemplate=''}
            'upgrade-disabled' {$target.AutoUpgrade=$false}
            'upgrade-coerced' {$target.AutoUpgrade='true'}
            'fallback-enabled' {$target.AllowFallbackToUdp=$true}
            'fallback-coerced' {$target.AllowFallbackToUdp='false'}
            default {throw 'Unexpected fixture fault'}
        }
    }
    return $rows
}
function Set-DNSFixtureDoh([string]$Kind,[string]$Address,[string]$Template,[bool]$Fallback,[bool]$Upgrade) {
    $script:calls.Add(@{kind=$Kind;address=$Address})
    if($script:failAction -eq $Kind -and $script:failAddress -eq $Address){Write-Error 'source-doh-mutation-failed';return}
    if($script:silentDohFault -ceq $Kind -and $Address -ceq '8.8.8.8'){return}
    if($script:changeDohAfterProviderWrite -and $Address -ceq '8.8.8.8'){
        $script:currentDoh['9.9.9.9'].DohTemplate='https://independent.invalid/dns-query'
        $script:changeDohAfterProviderWrite=$false
    }
    if($Kind -eq 'remove'){if(-not $script:currentDoh.ContainsKey($Address)){throw 'Remove requires an existing DoH entry'};$script:currentDoh.Remove($Address);return}
    if($Kind -eq 'set' -and -not $script:currentDoh.ContainsKey($Address)){throw 'Set requires an existing DoH entry'}
    if($Kind -eq 'add' -and $script:currentDoh.ContainsKey($Address)){throw 'Add requires an absent DoH entry'}
    $script:currentDoh[$Address]=[pscustomobject]@{ServerAddress=$Address;DohTemplate=$Template;AllowFallbackToUdp=$Fallback;AutoUpgrade=$Upgrade}
}
function Add-DnsClientDohServerAddress {[CmdletBinding()]param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);Set-DNSFixtureDoh 'add' $ServerAddress $DohTemplate $AllowFallbackToUdp $AutoUpgrade}
function Set-DnsClientDohServerAddress {[CmdletBinding()]param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);Set-DNSFixtureDoh 'set' $ServerAddress $DohTemplate $AllowFallbackToUdp $AutoUpgrade}
function Remove-DnsClientDohServerAddress {[CmdletBinding()]param($ServerAddress);Set-DNSFixtureDoh 'remove' $ServerAddress '' $false $false}
function Assert-DNSFixturePath([string]$LiteralPath){if([IO.Path]::GetFullPath($LiteralPath) -cne [IO.Path]::GetFullPath($snapshot)){throw 'Unexpected fixture filesystem path'}}
function No-Reparse([string]$Path){
    if($script:stageDNSCrypt -and $Path -cin @((Join-Path $root 'dnscrypt-proxy.toml'),(Join-Path $root 'example-dnscrypt-proxy.toml'))){
        $script:dnscryptConfigReads++
        return
    }
    Assert-DNSFixturePath $Path
}
function Publish-WorkflowFile([string]$Path,[byte[]]$Bytes,[string]$BeforeHash,[switch]$Recorded){
    if($Recorded){
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
        if(-not $script:stageDNSCrypt -or $Path -cne (Join-Path $root 'dnscrypt-proxy.toml') -or
            $text -cnotmatch '127\.0\.0\.1:53' -or $text -cnotmatch '\[::1\]:53' -or
            -not $PSBoundParameters.ContainsKey('BeforeHash')){throw 'Unexpected DNS fixture write'}
        if($script:changeDNSCryptBeforePublish){[IO.File]::WriteAllText($Path,'independent configuration')}
        $current=if([IO.File]::Exists($Path)){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}else{''}
        if($current -cne $BeforeHash){throw 'Workflow files changed before replacement'}
        if($script:restartRecoveryOriginal){
            $script:undo.Add(@{kind='file';path=$Path;originalHash=$BeforeHash;expectedHash=(Get-WorkflowBytesSHA256 $Bytes)})
        }
        [IO.File]::WriteAllBytes($Path,$Bytes)
        $script:dnscryptConfigWrites++
        if($script:changeDNSCryptAfter -ceq 'publish'){[IO.File]::Delete($Path)}
        return
    }
    Assert-DNSFixturePath $Path
    $current=if([IO.File]::Exists($Path)){Snapshot-Hash}else{''}
    Assert-DNS ($PSBoundParameters.ContainsKey('BeforeHash') -and $current -ceq $BeforeHash) 'snapshot-publication-binds-prior-bytes'
    Assert-DNS ($script:journals -gt 0 -and $script:undo.Count -eq 1 -and
        $script:undo[0].kind -ceq 'dns' -and
        $script:journalDigest -ceq (Get-WorkflowBytesSHA256 $Bytes)) 'journal-before-snapshot'
    if($script:failSnapshotWrite){throw 'source-snapshot-write-failed'}
    if($script:corruptSnapshotWrite){$Bytes[0]=0}
    [IO.File]::WriteAllBytes($Path,$Bytes)
}
function Save-DNSRecoveryReceipt([string]$Digest) {
    Assert-DNS ($Digest -ceq (Snapshot-Hash)) 'receipt-before-retirement'
    if($script:failReceiptWrite){throw 'Fixture receipt write failed'}
    $script:receiptDigest=$Digest
    if($script:replaceSnapshotOnReceiptSave){[IO.File]::AppendAllText($snapshot,' ')}
}
function Remove-Item {[CmdletBinding()]param($LiteralPath);Assert-DNSFixturePath $LiteralPath;Assert-DNS ($script:receiptDigest -ceq (Snapshot-Hash)) 'receipt-before-retirement';if($script:failDelete){Write-Error 'source-snapshot-removal-failed';return};if($script:silentSnapshotRemoval){return};Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -ErrorAction Stop}
function Save-Journal {
    if($script:failJournalWrite){throw 'Fixture journal write failed'}
    if($script:replaceSnapshotOnJournalSave){[IO.File]::AppendAllText($snapshot,' ')}
    if($script:undo[0].snapshotActive -and $script:failActivationWrite){throw 'Fixture activation write failed'}
    $script:journalDigest=$script:undo[0].snapshotSHA256
    $script:journalActive=($script:undo[0].snapshotActive -eq $true)
    if($script:journalActive -and $script:replaceSnapshotOnActivation){[IO.File]::AppendAllText($snapshot,' ')}
    if($script:journalActive -and $script:changeDNSOnActivation){
        $guid=[string]$script:adapters[0].InterfaceGuid
        $script:appliedDNS[$guid+'/IPv4']=@{
            dhcp=($script:changeDNSOnActivation -ceq 'mode')
            values=@('198.51.100.53')
        }
    }
    if($script:journalActive -and $script:changeDohOnActivation){
        if($script:changeDohOnActivation -ceq 'remove'){
            $script:currentDoh.Remove('8.8.8.8')
        }else{
            $script:currentDoh['8.8.8.8']=Old-DohFixture
            $script:currentDoh['8.8.8.8'].DohTemplate='https://independent.invalid/dns-query'
        }
    }
    $script:journals++
}
function Event([string]$Text){$script:events.Add($Text)}
function Assert-ManagedServiceOwnership([string]$Name){
    if($Name -cne 'AccessWeaver-dnscrypt'){throw 'Unexpected DNS service name'}
    if($script:resolverOwnershipFault){throw 'Fixture DNS service ownership refusal'}
    if($script:resolverServicePresent){return @{name=$Name;commandSHA256=$script:resolverDigest}}
}
function Assert-RecordedServiceBinding($Entry){
    if($Entry.name -cne 'AccessWeaver-dnscrypt' -or $Entry.commandSHA256 -cne $script:resolverDigest){throw 'Unexpected DNS service binding'}
    $script:resolverBindingReads++
    if($script:resolverBindingReads -eq $script:resolverBindingFailureRead){throw 'Fixture DNS service identity changed'}
    return 0
}
function Get-CimInstance {
    [CmdletBinding()]param($ClassName,$Filter)
    if($ClassName -cne 'Win32_Service' -or $Filter -cne "Name='AccessWeaver-dnscrypt'" -or
        $PSBoundParameters['ErrorAction'] -ne 'Stop' -or -not $script:resolverServicePresent -or
        $script:expectedResolverStartup -cnotin @('Automatic','Manual')){throw 'Unexpected DNS service readback'}
    $script:resolverReadbacks++
    $mode=if($script:expectedResolverStartup -ceq 'Manual'){'Manual'}else{'Auto'}
    $state=if($mode -ceq 'Manual'){'Stopped'}else{'Running'}
    $row=[pscustomobject]@{Name='AccessWeaver-dnscrypt';PathName=$script:resolverCommand;StartMode=$mode;State=$state}
    switch -CaseSensitive ($script:resolverReadbackFault){
        'mode' {$row.StartMode='Manual'}
        'state' {$row.State='Stopped'}
        'command' {$row.PathName='replacement fixture command'}
        'still-running' {$row.State='Running'}
        'still-auto' {$row.StartMode='Auto'}
        'missing' {return}
        'late-mode' {if($script:resolverReadbacks -ge 2){$row.StartMode='Manual'}}
    }
    return $row
}
function Get-Service {
    [CmdletBinding()]param($Name)
    if($Name -cne 'AccessWeaver-dnscrypt'){throw 'Unexpected service name'}
    if($script:resolverServicePresent){
        $service=[pscustomobject]@{Status=$(if($script:resolverStopped){'Stopped'}else{'Running'})}
        $service | Add-Member ScriptMethod WaitForStatus {
            param($State,$Timeout)
            if($State -cne 'Running' -or $Timeout.TotalSeconds -ne 20 -or $this.Status -cne 'Running'){throw 'Unexpected fixture service wait'}
        }
        return $service
    }
}
function Clear-DnsClientCache {[CmdletBinding()]param()}
function Resolve-DnsName {
    [CmdletBinding()]param($Name,$Server,$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout)
    if(-not $Server){
        if($Name -cne 'example.com.' -or $Type -cne 'A' -or -not $DnsOnly -or -not $NoHostsFile -or -not $QuickTimeout){
            throw 'Unexpected ordinary DNS resolver query'
        }
        $script:resolverQueries++
        if($script:changeDNSCryptAfter -ceq 'ordinary-probe'){
            [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),'independent configuration')
        }
        if($script:resolverQueries -le $script:emptyOrdinaryAnswers){return}
        switch -CaseSensitive ($script:resolverDrift){
            'policy' {$script:currentDoh['8.8.8.8'].AllowFallbackToUdp=$true}
            'stored-dhcp' {$script:storedDNSFault='dhcp'}
            'server' {$script:appliedDNS[([string]$script:adapters[0].InterfaceGuid)+'/IPv4'].values[0]='198.51.100.53'}
            'family-added' {$script:exposure['77/IPv6']=$true}
            'family-removed' {$script:exposure['77/IPv6']=$false}
            {$_ -cin @('adapter-added','adapter-selection-changed','unselected-adapter-added','index-duplicated')} {
                $description=if($_ -cin @('unselected-adapter-added','index-duplicated')){'WireGuard fixture'}else{'Another fixture adapter'}
                $index=if($_ -ceq 'index-duplicated'){77}else{88}
                if($_ -ceq 'adapter-selection-changed'){$script:adapters[0].InterfaceDescription='WireGuard fixture'}
                $script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription=$description;InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=$index})
            }
        }
        return [pscustomobject]@{Name='example.com.';Type='A';Section='Answer';IPAddress='192.0.2.15'}
    }
    if($Server -cnotin @('127.0.0.1','::1') -or $Name -cne 'example.net.' -or $Type -cne 'A' -or
        -not $DnsOnly -or -not $NoHostsFile -or -not $QuickTimeout -or $ErrorActionPreference -ne 'Stop'){
        throw 'Unexpected DNSCrypt listener probe'
    }
    if((Mutation-Count) -ne 0){$script:listenerChecksBeforeAdapters=$false}
    $script:listenerQueries.Add($Server)
    if($script:changeDNSCryptAfter -ceq 'listener' -and $script:listenerQueries.Count -eq 1){
        [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),'independent configuration')
    }
    $reply=if($script:listenerReplies.ContainsKey($Server)){$script:listenerReplies[$Server].Dequeue()}else{'answer'}
    switch($reply){
        'timeout' {throw 'Synthetic resolver timeout'}
        'empty' {return}
        'wrong-name' {return [pscustomobject]@{Name='example.org';Type='A';Section='Answer';IPAddress='192.0.2.15'}}
        'bad-address' {return [pscustomobject]@{Name='example.net';Type='A';Section='Answer';IPAddress='2001:db8::2'}}
        'authority' {return [pscustomobject]@{Name='example.net';Type='A';Section='Authority';IPAddress='192.0.2.15'}}
        'answer' {return [pscustomobject]@{Name='example.net.';Type='A';Section='Answer';IPAddress='192.0.2.15'}}
        default {throw 'Unexpected synthetic response'}
    }
}
function Start-Sleep {
    param($Milliseconds,$Seconds)
    if($Milliseconds -eq 250 -and -not $Seconds){$script:readbackWaits++;return}
    if($Seconds -eq 2 -and -not $Milliseconds){$script:ordinaryResolverWaits++;return}
    if($Milliseconds -eq 500 -and -not $Seconds){
        $script:listenerWaits++
        if($script:refuseListenerWait){throw 'Synthetic loopback wait boundary'}
        return
    }
    throw 'Unexpected resolver wait'
}
function Ensure-Asset([string]$Engine){
    if(-not $script:stageDNSCrypt -or $Engine -cne 'dnscrypt'){throw 'Native component access is forbidden in DNS contracts'}
    return Join-Path $root 'dnscrypt-proxy.exe'
}
function Install-EngineService([string]$Engine,[string]$Binary,[string[]]$Arguments,[switch]$DeferAutomaticStartup){
    $config=Join-Path $root 'dnscrypt-proxy.toml'
    if(-not $script:allowNewResolver -or $Engine -cne 'dnscrypt' -or $script:resolverServicePresent -or
        $Binary -cne (Join-Path $root 'dnscrypt-proxy.exe') -or $Arguments.Count -ne 2 -or
        $Arguments[0] -cne '-config' -or $Arguments[1] -cne $config -or -not $DeferAutomaticStartup){
        throw 'Service installation is forbidden in DNS contracts'
    }
    $script:newResolverRegistered=$true
    $script:resolverServicePresent=$true
    return @{kind='service';name='AccessWeaver-dnscrypt';commandSHA256=$script:resolverDigest}
}
function Set-Service {
    param($Name,$StartupType,$ErrorAction)
    if($Name -cne 'AccessWeaver-dnscrypt' -or $ErrorAction -cne 'Stop' -or
        ($StartupType -ceq 'Manual' -and $script:serviceStops -ne 1) -or
        $StartupType -cnotin @('Manual','Automatic')){throw 'Unexpected service startup change'}
    if($StartupType -ceq 'Automatic'){
        $bindings=if($script:newResolverRegistered){1}else{3}
        if(-not $script:stageDNSCrypt -or $script:resolverBindingReads -ne $bindings -or
            $script:listenerQueries.Count -eq 0 -or -not $script:listenerChecksBeforeAdapters -or
            $script:resolverStopped -or $script:resolverQueries -ne 0 -or (Mutation-Count) -ne 0){
            throw 'Resolver startup changed out of order'
        }
    }
    $script:expectedResolverStartup=$StartupType
    $script:serviceStartupChanges++
}
function Restore-RecordedWorkflowFile($Record) {
    $path=Join-Path $root 'dnscrypt-proxy.toml'
    if(-not $script:restartRecoveryOriginal -or $Record.path -cne $path -or
       $Record.originalHash -cne (Get-WorkflowBytesSHA256 $script:restartRecoveryOriginal) -or
       $Record.expectedHash -cne (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash){
        throw 'DNSCrypt recovery file differs from journal'
    }
    [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
    $script:restartRecoveryWrites++
}
function Start-Service {
    param($InputObject,$ErrorAction)
    if($InputObject.Status -cne 'Stopped' -or $ErrorAction -cne 'Stop' -or
        -not $script:stageDNSCrypt -or $script:serviceStartupChanges -ne 0){throw 'Unexpected fixture service start'}
    $script:serviceStarts++
    if($script:restartRecoveryFault -ceq 'start'){throw 'Synthetic original DNSCrypt startup failure'}
    $script:resolverStopped=$false
    $InputObject.Status='Running'
}
function Restart-Service {
    param($InputObject,$ErrorAction)
    if($InputObject.Status -cne 'Running' -or $ErrorAction -cne 'Stop' -or
        -not $script:stageDNSCrypt -or $script:serviceStartupChanges -ne 0){throw 'Unexpected fixture service restart'}
    $script:serviceRestarts++
    if($script:failDNSCryptRestart){
        $script:resolverStopped=$true
        $InputObject.Status='Stopped'
        if($script:restartRecoveryFault -ceq 'file'){
            [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),'independent configuration')
        }
        throw 'Synthetic DNSCrypt service restart failure'
    }
}
function Stop-Service {
    param($Name,$ErrorAction)
    if($Name -cne 'AccessWeaver-dnscrypt' -or -not $script:resolverServicePresent -or $script:resolverQueries -lt 1){
        throw 'Old resolver stopped before DoH verification'
    }
    $script:serviceStops++
}
try {
    # Legacy zones validate saved ownership; zone-free setter values are bound
    # to the freshly GUID-resolved family row, including after renumbering.
    New-DNSCase;$script:mode6='fe80::53%77';$script:dnsValues['77/IPv6']=@('fe80::53%77','2001:0db8::0054','fe80::55%77')
    Configure-DNS 'doh';$saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS (@($saved.adapters[0].ipv6).Count -eq 3 -and $saved.adapters[0].ipv6[0] -is [string] -and ($saved.adapters[0].ipv6 -join ',') -ceq 'fe80::53,2001:db8::54,fe80::55' -and -not $saved.adapters[0].dhcp6) 'scope-capture-flat-ordered'
    $script:calls.Clear();$script:adapters[0].ifIndex=88;Restore-DNS
    $writes=@($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.family -eq 'IPv6'})
    Assert-DNS ($writes.Count -eq 1 -and $writes[0].index -eq 88 -and -not $writes[0].reset -and ($writes[0].servers -join ',') -ceq 'fe80::53,2001:db8::54,fe80::55' -and -not [IO.File]::Exists($snapshot)) 'scope-rebinds-current-adapter'
    foreach($original in @('fe80::53','fe80::53%77')){
        New-DNSCase;$saved=Original-DNSFixture;$saved.adapters[0].dhcp6=$false;$saved.adapters[0].ipv6=@($original);Write-DNSFixture $saved
        # A second change after restoration preflight must also use the GUID.
        $script:adapters[0].ifIndex=88;$script:renumberDuringDoh=$true;Restore-DNS
        $writes=@($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.family -eq 'IPv6'})
        Assert-DNS ($writes.Count -eq 1 -and $writes[0].index -eq 101 -and @($writes[0].servers).Count -eq 1 -and $writes[0].servers[0] -ceq 'fe80::53' -and -not [IO.File]::Exists($snapshot)) 'scope-rebinds-current-adapter'
    }
    New-DNSCase;$script:exposure['77/IPv6']=$false;Configure-DNS 'doh'
    $script:adapters[0].ifIndex=88;$script:mode6='fe80::53%88';$script:dnsValues['88/IPv6']=@('fe80::53%88')
    Configure-DNS 'doh';$saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS ($saved.adapters[0].index -eq 77 -and $saved.adapters[0].bound6 -and @($saved.adapters[0].ipv6).Count -eq 1 -and $saved.adapters[0].ipv6[0] -ceq 'fe80::53' -and $saved.adapters[0].ipv4[0] -ceq '192.0.2.53') 'scope-family-extension'
    $script:calls.Clear();$script:adapters[0].ifIndex=99;Restore-DNS
    $writes=@($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.family -eq 'IPv6'})
    Assert-DNS ($writes.Count -eq 1 -and $writes[0].index -eq 99 -and $writes[0].servers[0] -ceq 'fe80::53' -and -not [IO.File]::Exists($snapshot)) 'scope-family-extension'
    # Invalid second-family or second-adapter data must precede all effects,
    # including the first valid family's reset and global DoH changes.
    $invalid=@(
        @{values=@('fe80::53%78');index=77},@{values=@('fe80::53%77');index=$null},
        @{values=@('fe80::53%77');index=0},@{values=@('fe80::53%77');index=77.5},
        @{values=@('fe80::53%eth0');index=77},@{values=@('fe80::53%');index=77},
        @{values=@('fe80::53%4294967296');index=77},@{values=@('fe80::53%0');index=77},
        @{values=@('2001:db8::53%77');index=77},@{values=@('192.0.2.53');index=77},
        @{values=@('fe80::53%77%77');index=77},@{values=@(42);index=77},
        @{values=@(' ');index=77},@{values=@();index=77},@{values=@(@('fe80::53','fe80::54'), 'fe80::55');index=77}
    )
    foreach($bad in $invalid){
        foreach($position in @('second-family','second-adapter')){
            foreach($action in @('configure','restore')){
                New-DNSCase;$saved=Original-DNSFixture;$saved.adapters[0].dhcp4=$true
                if($position -eq 'second-adapter'){
                    $script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='Second fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
                    $other=Original-DNSFixture;$other.adapters[0].guid=$script:adapters[1].InterfaceGuid;$saved.adapters+=@($other.adapters[0])
                }
                $record=$saved.adapters[-1];$record.dhcp6=$false;$record.ipv6=$bad.values;$record.index=$bad.index
                $saved.doh=@((Old-DohFixture));Write-DNSFixture $saved;$hash=Snapshot-Hash
                if($action -eq 'configure'){Reject-DNS {Configure-DNS 'doh'}}else{Reject-DNS {Restore-DNS}}
                Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0 -and $script:journals -eq 0 -and -not $script:journalActive) 'scope-invalid-before-effects'
            }
        }
    }
    foreach($values in @(@('fe80::53%78'),@('fe80::53%eth0'),@('2001:db8::53%77'))){
        New-DNSCase;$script:mode6='static';$script:dnsValues['77/IPv6']=$values;Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0 -and $script:journals -eq 0) 'scope-invalid-before-effects'
    }
    # DHCP DNS is restored by resetting the family, even when the observed
    # dynamic address carries a zone that is no longer relevant.
    New-DNSCase;$script:dnsValues['77/IPv6']=@('fe80::53%77');Configure-DNS 'doh';$script:calls.Clear();$script:adapters[0].ifIndex=88;Restore-DNS
    $writes=@($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.family -eq 'IPv6'})
    Assert-DNS ($writes.Count -eq 1 -and $writes[0].reset -and $writes[0].index -eq 88) 'scope-dhcp-reset-preserved'
    Assert-DNS ((@(Get-StaticDNSServers @('2001:0db8::0053') 'IPv6' 77) -join ',') -ceq '2001:db8::53' -and (@(Get-StaticDNSServers @('192.0.2.53','198.51.100.54') 'IPv4' 77) -join ',') -ceq '192.0.2.53,198.51.100.54') 'scope-global-and-ipv4-preserved'
    Reject-DNS {Get-StaticDNSServers @('fe80::53') 'IPv5' 77}
    foreach($family in @('IPv4','IPv6')){
        New-DNSCase;$script:registryFailure=$family
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0 -and $script:journals -eq 0 -and -not $script:journalActive) 'registry-error-not-dhcp'
    }
    New-DNSCase;$script:mode4=42;Reject-DNS {Configure-DNS 'doh'};Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0) 'malformed-mode-not-empty'
    New-DNSCase;$script:failDohRead=1;Reject-DNS {Configure-DNS 'doh'};Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0) 'capture-inspection-failure-not-empty'
    New-DNSCase;$script:failSnapshotWrite=$true;Reject-DNS {Configure-DNS 'doh'}
    Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:journalActive -and $script:journals -eq 1 -and
        -not [IO.File]::Exists($snapshot)) 'snapshot-before-native-effects'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:failJournalWrite=$true
    Reject-DNS {Configure-DNS 'doh'};Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:journalActive -and $script:journals -eq 0) 'journal-before-snapshot'
    New-DNSCase;$script:corruptSnapshotWrite=$true;Reject-DNS {Configure-DNS 'doh'}
    Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:journalActive -and $script:journals -eq 1 -and
        (Snapshot-Hash) -cne $script:journalDigest) 'snapshot-must-match-journal'
    New-DNSCase;$script:failActivationWrite=$true;Reject-DNS {Configure-DNS 'doh'}
    Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:journalActive -and $script:journals -eq 1 -and
        (Snapshot-Hash) -ceq $script:journalDigest) 'activation-before-native-effects'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:failReceiptWrite=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    Assert-DNS ($null -eq $script:receiptDigest) 'receipt-before-retirement'
    New-DNSCase;$script:failDohRead=2;Reject-DNS {Configure-DNS 'doh'};Assert-DNS ([IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0) 'current-doh-query-before-effects'
    New-DNSCase;$script:mode4='absent';$script:currentDoh['8.8.8.8']=Old-DohFixture
    Configure-DNS 'doh'
    $saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS ($saved.adapters[0].dhcp4 -and $saved.adapters[0].dhcp6) 'confirmed-absent-mode-is-dhcp'
    Assert-DNS ($script:currentDoh.Count -eq 4 -and @($script:currentDoh.Values | Where-Object {$_.AllowFallbackToUdp -ne $false -or $_.AutoUpgrade -ne $true}).Count -eq 0) 'all-providers-no-plaintext-fallback'
    # Independently pin all four authorities, including bracketed IPv6 URIs.
    $expectedTemplates=@{'8.8.8.8'='https://8.8.8.8/dns-query';'9.9.9.9'='https://9.9.9.9/dns-query';'2001:4860:4860::8888'='https://[2001:4860:4860::8888]/dns-query';'2620:fe::fe'='https://[2620:fe::fe]/dns-query'}
    foreach($address in $expectedTemplates.Keys){Assert-DNS ($script:currentDoh[$address].DohTemplate -ceq $expectedTemplates[$address]) 'all-providers-no-plaintext-fallback'}
    # Successful setters with absent, ambiguous, stale or unsafe readback must
    # never activate adapter DNS or query through an unverified resolver policy.
    foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
        foreach($fault in @('missing','duplicate','wrong-template','empty-template','upgrade-disabled','upgrade-coerced','fallback-enabled','fallback-coerced')){
            New-DNSCase;$script:configureDohFaultAddress=$address;$script:configureDohReadFault=$fault
            Reject-DNS {Configure-DNS 'doh'}
            Assert-DNS (@($script:calls | Where-Object {$_.kind -ceq 'dns'}).Count -eq 0 -and $script:resolverQueries -eq 0 -and -not $script:dnsConfigured -and $script:events.Count -eq 0) 'configure-policy-readback-before-adapters'
            $hash=Snapshot-Hash;Assert-SnapshotRetained $hash
            Assert-DNS ($script:journalActive -and $script:undo.Count -eq 1 -and $script:journals -eq 2) 'configure-policy-refusal-retains-recovery'
            $script:configureDohReadFault='';Restore-DNS
            Assert-DNS (-not [IO.File]::Exists($snapshot)) 'configure-policy-recovery-completes'
        }
    }
    foreach($kind in @('add','set','read-error')){
        New-DNSCase
        if($kind -ceq 'set'){$script:currentDoh['8.8.8.8']=Old-DohFixture}
        if($kind -ceq 'read-error'){$script:failDohRead=6}else{$script:silentDohFault=$kind}
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS (@($script:calls | Where-Object {$_.kind -ceq 'dns'}).Count -eq 0 -and $script:resolverQueries -eq 0 -and -not $script:dnsConfigured) 'configure-policy-readback-before-adapters'
        $hash=Snapshot-Hash;Assert-SnapshotRetained $hash
        $script:silentDohFault='';$script:failDohRead=0;Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'configure-policy-recovery-completes'
    }
    New-DNSCase;Configure-DNS 'doh'
    Assert-DNS ($script:dohReads -eq 8 -and $script:resolverQueries -eq 1 -and $script:dnsConfigured) 'configure-policy-query-before-verification'
    foreach($change in @('add','remove','template')){
        New-DNSCase
        if($change -cne 'add'){$script:currentDoh['8.8.8.8']=Old-DohFixture}
        $script:changeDohOnActivation=$change
        Reject-DNS {Configure-DNS 'doh'} 'DoH policy changed during configuration'
        $hash=Snapshot-Hash;Assert-SnapshotRetained $hash
        Assert-DNS ($script:journalActive -and (Mutation-Count) -eq 0 -and $script:resolverQueries -eq 0) 'configure-doh-preserves-independent-policy'
        # Journal rollback uses the same digest-bound restoration path.
        Reject-DNS {Restore-DNS $script:undo[0].snapshotSHA256} 'Managed DoH policy has changed independently'
        Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and $null -eq $script:receiptDigest) 'restore-doh-refuses-unowned-policy'
    }
    New-DNSCase
    $script:currentDoh['9.9.9.9']=Old-DohFixture
    $script:currentDoh['9.9.9.9'].ServerAddress='9.9.9.9'
    $script:changeDohAfterProviderWrite=$true
    Reject-DNS {Configure-DNS 'doh'} 'DoH policy changed during configuration'
    $hash=Snapshot-Hash
    Assert-DNS ($script:currentDoh['8.8.8.8'].DohTemplate -ceq 'https://8.8.8.8/dns-query' -and
        $script:currentDoh['9.9.9.9'].DohTemplate -ceq 'https://independent.invalid/dns-query' -and
        (Mutation-Count) -eq 1) 'configure-doh-preserves-independent-policy'
    Reject-DNS {Restore-DNS $hash} 'Managed DoH policy has changed independently';Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 1) 'restore-doh-refuses-unowned-policy'
    Reject-DNS {Configure-DNS 'doh'} 'Managed DoH policy has changed independently';Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 1 -and $script:journals -eq 2) 'configure-doh-refuses-stale-reconfiguration'
    $script:currentDoh['9.9.9.9'].DohTemplate='https://original.invalid/dns-query'
    Restore-DNS $hash
    Assert-DNS (-not $script:currentDoh.ContainsKey('8.8.8.8') -and
        $script:currentDoh['9.9.9.9'].DohTemplate -ceq 'https://original.invalid/dns-query' -and
        @($script:calls | Where-Object {$_.address -eq '9.9.9.9'}).Count -eq 0 -and
        -not [IO.File]::Exists($snapshot)) 'restore-doh-resumes-partial-configuration'
    New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash;$script:calls.Clear()
    $script:present['Get-DnsClientDohServerAddress']=$false
    Reject-DNS {Restore-DNS $hash} 'Original DoH metadata cannot be restored';Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 0) 'restore-doh-conditional-needs-capability'
    foreach($marker in @('true',$false,$null,$true)){
        New-DNSCase
        $saved=Original-DNSFixture
        $saved.dohManaged=$false
        $saved.dohConditional=$marker
        Write-DNSFixture $saved;$hash=Snapshot-Hash
        Reject-DNS {Restore-DNS $hash} 'Original DNS snapshot has invalid DoH ownership metadata';Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:dohReads -eq 0) 'restore-doh-rejects-invalid-ownership'
    }
    # Successful setters are not proof that the selected families adopted the
    # intended addresses; retry only reads, then refuse without a resolver query.
    foreach($fault in @('noop','wrong-value','empty-static','wrong-order','read-error','adapter-missing','stored-dhcp','stored-address')){
        New-DNSCase;$originalAdapters=@($script:adapters);$script:readbackFault=$fault
        if($fault -ceq 'stored-dhcp'){$script:storedDNSFault='dhcp'}
        if($fault -ceq 'stored-address'){$script:storedDNSFault='wrong-address'}
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS ($script:resolverQueries -eq 0 -and -not $script:dnsConfigured -and $script:readbackWaits -eq 39) 'configure-adapter-readback-refuses'
        $hash=Snapshot-Hash;Assert-SnapshotRetained $hash
        Assert-DNS ($script:journalActive -and $script:undo.Count -eq 1 -and $script:journals -eq 2) 'configure-adapter-readback-retains'
        $script:readbackFault='';$script:readbackFaultArmed=$false;$script:storedDNSFault='';$script:adapters=$originalAdapters;Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'configure-adapter-readback-recovers'
    }
    foreach($method in @('doh','dnscrypt')){
        New-DNSCase
        Write-DNSFixture (Original-DNSFixture)
        $oldDigest=Snapshot-Hash
        $script:resolverOwnershipFault=$true
        Reject-DNS {Configure-DNS $method}
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:journals -eq 0 -and $script:undo.Count -eq 0 -and
            (Snapshot-Hash) -ceq $oldDigest -and $script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0) 'dns-service-ownership-before-effects'
    }
    New-DNSCase;$script:resolverServicePresent=$true;$script:resolverBindingFailureRead=1
    Reject-DNS {Configure-DNS 'dnscrypt'}
    Assert-DNS ((Mutation-Count) -eq 0 -and $script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0) 'dns-service-binding-before-mutation'
    New-DNSCase;$script:resolverServicePresent=$true;$script:resolverBindingFailureRead=1
    Reject-DNS {Configure-DNS 'doh'}
    Assert-DNS ($script:resolverQueries -eq 1 -and $script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0 -and
        -not $script:dnsConfigured) 'dns-service-binding-before-mutation'
    New-DNSCase;$script:resolverServicePresent=$true;$script:readbackFault='read-error'
    Reject-DNS {Configure-DNS 'doh'}
    Assert-DNS ($script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0 -and $script:resolverQueries -eq 0) 'doh-keeps-old-resolver-until-verified'
    New-DNSCase;$script:resolverServicePresent=$true
    Configure-DNS 'doh'
    Assert-DNS ($script:serviceStops -eq 1 -and $script:serviceStartupChanges -eq 1 -and $script:dnsConfigured) 'doh-keeps-old-resolver-until-verified'
    foreach($fault in @('still-running','still-auto','command','changed-binding')){
        New-DNSCase;$script:resolverServicePresent=$true
        if($fault -ceq 'changed-binding'){
            $script:resolverBindingFailureRead=2
            Reject-DNS {Configure-DNS 'doh'} 'Fixture DNS service identity changed'
        }else{
            $script:resolverReadbackFault=$fault
            $expected=if($fault -ceq 'command'){'DNSCrypt service identity changed'}else{'DNSCrypt service manual startup or stopped state could not be verified'}
            Reject-DNS {Configure-DNS 'doh'} $expected
        }
        $hash=Snapshot-Hash;Assert-SnapshotRetained $hash
        $expectedStartupWrites=[int]($fault -cne 'changed-binding')
        Assert-DNS ($script:resolverQueries -eq 1 -and $script:serviceStops -eq 1 -and
            $script:serviceStartupChanges -eq $expectedStartupWrites -and
            $script:resolverReadbacks -eq $expectedStartupWrites -and -not $script:dnsConfigured) 'doh-keeps-old-resolver-until-verified'
    }
    foreach($dependency in @('effective','stored','unreadable')){
        New-DNSCase;$script:resolverServicePresent=$true;$script:stageDNSCrypt=$true
        $inactiveGuid='{00000000-0000-0000-0000-000000000002}'
        $inactive=[pscustomobject]@{Status='Up';InterfaceDescription='Second fixture adapter';InterfaceGuid=$inactiveGuid;ifIndex=88}
        $script:adapters+=@($inactive)
        [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        Configure-DNS 'dnscrypt'
        $inactive.Status='Down'
        if($dependency -cne 'effective'){
            # Model a stale effective row while its stored override still
            # points at the old listener, or the stored value is unreadable.
            $script:appliedDNS[$inactiveGuid+'/IPv4'].values=@('192.0.2.53')
            $script:appliedDNS[$inactiveGuid+'/IPv6'].values=@('2001:db8::53')
            $script:storedDNS[$inactiveGuid+'/IPv6']=if($dependency -ceq 'stored'){'0:0:0:0:0:0:0:1'}else{42}
        }
        $script:serviceStartupChanges=0;$script:resolverQueries=0;$script:dnsConfigured=$false
        Configure-DNS 'doh'
        Assert-DNS ($script:dnsConfigured -and $script:resolverQueries -eq 1 -and
            $script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0) 'doh-keeps-listener-for-owned-inactive-adapter'
        $script:storedDNS.Clear()
        $script:appliedDNS[$inactiveGuid+'/IPv4'].values=@('127.0.0.1')
        $script:appliedDNS[$inactiveGuid+'/IPv6'].values=@('::1')
        $inactive.Status='Up'
        Configure-DNS 'doh'
        Assert-DNS ($script:dnsConfigured -and $script:serviceStops -eq 1 -and
            $script:serviceStartupChanges -eq 1) 'doh-stops-listener-after-last-adapter-switch'
    }
    New-DNSCase;$script:resolverServicePresent=$true
    $script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='WireGuard fixture';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
    $inactive=$script:adapters[1]
    $inactive.Status='Down'
    $script:dnsValues['88/IPv6']=@('2001:db8::53')
    $script:storedDNS[([string]$inactive.InterfaceGuid)+'/IPv6']='0:0:0:0:0:0:0:1'
    Configure-DNS 'doh'
    Assert-DNS ($script:dnsConfigured -and $script:serviceStops -eq 0 -and
        $script:serviceStartupChanges -eq 0) 'doh-keeps-listener-for-excluded-adapter'
    $script:storedDNS.Clear()
    $script:dnsValues['88/IPv6']=@('0:0:0:0:0:0:0:1')
    Assert-DNS (Test-DNSCryptListenerNeeded) 'doh-keeps-listener-for-excluded-adapter'
    $script:dnsValues['88/IPv6']=@('2001:db8::53')
    Assert-DNS (-not (Test-DNSCryptListenerNeeded)) 'doh-stops-listener-after-last-adapter-switch'
    foreach($drift in @('renumber','replace','duplicate-index','duplicate-guid','missing','unreadable')){
        New-DNSCase
        $script:adapters+=@([pscustomobject]@{Status='Down';InterfaceDescription='Hidden fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
        $script:hiddenInventoryDrift=$drift
        Assert-DNS ((Test-DNSCryptListenerNeeded) -and $script:hiddenInventoryReads -eq 2) 'doh-keeps-listener-for-adapter-identity-drift'
    }
    New-DNSCase;$script:resolverServicePresent=$true
    $script:hiddenInventoryDrift='unreadable'
    Configure-DNS 'doh'
    Assert-DNS ($script:dnsConfigured -and $script:hiddenInventoryReads -eq 2 -and $script:serviceStops -eq 0 -and
        $script:serviceStartupChanges -eq 0) 'doh-keeps-listener-for-adapter-identity-drift'
    New-DNSCase;$script:resolverServicePresent=$true
    $script:mode4='127.0.0.1';$script:dnsValues['77/IPv4']=@('127.0.0.1')
    Configure-DNS 'doh'
    Assert-DNS ($script:dnsConfigured -and $script:serviceStops -eq 0 -and
        $script:serviceStartupChanges -eq 0) 'doh-keeps-listener-for-original-static-dns'
    Restore-DNS
    Assert-DNS ($script:serviceStops -eq 0 -and -not [IO.File]::Exists($snapshot)) 'doh-keeps-listener-for-original-static-dns'
    foreach($failureRead in @(0,2)){
        New-DNSCase
        $script:stageDNSCrypt=$true;$script:resolverServicePresent=$true;$script:resolverBindingFailureRead=$failureRead
        # Create an owned inert placeholder for the unmocked Test-Path.
        [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        if($failureRead){
            Reject-DNS {Configure-DNS 'dnscrypt'}
            Assert-DNS ($script:resolverBindingReads -eq 2 -and $script:serviceRestarts -eq 0 -and
                $script:serviceStartupChanges -eq 0 -and (Mutation-Count) -eq 0) 'dns-service-binding-before-mutation'
        }else{
            Configure-DNS 'dnscrypt'
            Assert-DNS ($script:resolverBindingReads -eq 3 -and $script:dnscryptConfigReads -eq 6 -and
                $script:dnscryptConfigWrites -eq 1 -and $script:serviceRestarts -eq 1 -and
                $script:serviceStartupChanges -eq 1 -and $script:dnsConfigured) 'dnscrypt-restarts-verified-service'
        }
        [IO.File]::Delete((Join-Path $root 'dnscrypt-proxy.toml'))
    }
    foreach($initiallyStopped in @($false,$true)){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $script:resolverStopped=$initiallyStopped
        $path=Join-Path $root 'dnscrypt-proxy.toml'
        $configText="server_names = ['google']`r`nlisten_addresses = ['127.0.0.1:53', '[::1]:53']`r`n"
        [IO.File]::WriteAllText($path,$configText,[Text.UTF8Encoding]::new($false))
        # Reapplying with the already-configured loopback addresses must verify
        # both listeners and the ordinary resolver without restarting it.
        $script:mode4='127.0.0.1';$script:dnsValues['77/IPv4']=@('127.0.0.1')
        Configure-DNS 'dnscrypt'
        Assert-DNS ($script:dnsConfigured -and $script:dnscryptConfigWrites -eq 0 -and
            $script:serviceRestarts -eq 0 -and $script:serviceStarts -eq [int]$initiallyStopped -and
            ($script:listenerQueries -join ',') -ceq '127.0.0.1,::1' -and $script:resolverQueries -eq 1 -and
            [IO.File]::ReadAllText($path) -ceq $configText) 'dnscrypt-reuses-unchanged-configuration'
    }
    foreach($fault in @('mode','state','late-mode')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $script:resolverReadbackFault=$fault
        [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        Reject-DNS {Configure-DNS 'dnscrypt'} 'DNSCrypt service automatic startup or running state could not be verified'
        $late=[int]($fault -ceq 'late-mode')
        Assert-DNS ($script:serviceStartupChanges -eq 1 -and $script:resolverReadbacks -eq (1+$late) -and
            (Mutation-Count) -eq (2*$late) -and $script:resolverQueries -eq $late -and
            $script:journalActive -and (Snapshot-Hash) -ceq $script:journalDigest -and
            -not $script:dnsConfigured) 'dnscrypt-listeners-before-adapters'
    }
    foreach($fault in @('','file','start','binding')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true;$script:failDNSCryptRestart=$true
        $script:restartRecoveryFault=$fault
        if($fault -ceq 'binding'){$script:resolverBindingFailureRead=3}
        $path=Join-Path $root 'dnscrypt-proxy.toml'
        $original="listen_addresses = ['192.0.2.53:53']"
        $script:restartRecoveryOriginal=[Text.UTF8Encoding]::new($false).GetBytes($original)
        [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
        $expected=if($fault){'DNSCrypt restart failed and the original service could not be recovered'}else{'Synthetic DNSCrypt service restart failure'}
        Reject-DNS {Configure-DNS 'dnscrypt'} $expected
        $restored=$fault -cnotin @('file','binding')
        Assert-DNS ($script:serviceRestarts -eq 1 -and $script:dnscryptConfigWrites -eq 1 -and
            $script:restartRecoveryWrites -eq [int]$restored -and $script:serviceStarts -eq [int]$restored -and
            $script:resolverStopped -eq [bool]$fault -and
            ([IO.File]::ReadAllText($path) -ceq $original) -eq $restored -and
            $script:serviceStartupChanges -eq 0 -and (Mutation-Count) -eq 0 -and
            $script:resolverQueries -eq 0 -and $script:journalActive -and -not $script:dnsConfigured) 'dns-service-binding-before-mutation'
        if($fault -ceq 'file'){
            Assert-DNS ([IO.File]::ReadAllText($path) -ceq 'independent configuration') 'dns-service-binding-before-mutation'
        }
    }

    foreach($existingConfig in @($true,$false)){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $target=Join-Path $root 'dnscrypt-proxy.toml'
        $source=if($existingConfig){$target}else{Join-Path $root 'example-dnscrypt-proxy.toml'}
        [IO.File]::WriteAllText($source,"listen_addresses = ['192.0.2.53:53']")
        $script:changeDNSCryptBeforePublish=$true
        Reject-DNS {Configure-DNS 'dnscrypt'} 'Workflow files changed before replacement'
        Assert-DNS ([IO.File]::ReadAllText($target) -ceq 'independent configuration' -and
            $script:dnscryptConfigWrites -eq 0 -and $script:serviceRestarts -eq 0 -and
            (Mutation-Count) -eq 0) 'dns-service-binding-before-mutation'
    }
    foreach($stage in @('publish','listener','ordinary-probe')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true;$script:changeDNSCryptAfter=$stage
        $target=Join-Path $root 'dnscrypt-proxy.toml'
        [IO.File]::WriteAllText($target,"listen_addresses = ['192.0.2.53:53']")
        Reject-DNS {Configure-DNS 'dnscrypt'} 'DNSCrypt configuration changed after publication'
        $writes=if($stage -ceq 'ordinary-probe'){2}else{0}
        $preserved=if($stage -ceq 'publish'){-not [IO.File]::Exists($target)}else{
            [IO.File]::ReadAllText($target) -ceq 'independent configuration'
        }
        Assert-DNS ($preserved -and $script:serviceRestarts -eq [int]($stage -cne 'publish') -and
            $script:serviceStartupChanges -eq [int]($stage -ceq 'ordinary-probe') -and (Mutation-Count) -eq $writes -and
            $script:journalDigest -ceq (Snapshot-Hash) -and -not $script:dnsConfigured) 'dns-service-binding-before-mutation'
    }
    foreach($transition in @('dnscrypt-only','dnscrypt-to-doh','doh-to-dnscrypt')){
        New-DNSCase
        $script:stageDNSCrypt=$true
        $script:resolverServicePresent=$true
        [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        $originalDoh=Old-DohFixture
        $script:currentDoh['8.8.8.8']=$originalDoh
        if($transition -ceq 'doh-to-dnscrypt'){
            Configure-DNS 'doh'
            $script:resolverBindingReads=0
            $script:serviceStartupChanges=0
            $script:resolverQueries=0
            $script:calls.Clear()
            $script:resolverStopped=$true
        }
        $readsBeforeCrypt=$script:dohReads
        Configure-DNS 'dnscrypt'
        $scope=(Read-DNSRecoverySnapshot).record
        if($transition -ceq 'doh-to-dnscrypt'){
            Assert-DNS ($scope.dohManaged -eq $true -and $scope.doh[0].DohTemplate -ceq $originalDoh.DohTemplate -and
                $script:dohReads -eq $readsBeforeCrypt) 'dnscrypt-keeps-existing-doh-originals'
        }else{
            Assert-DNS ($scope.dohManaged -is [bool] -and -not $scope.dohManaged -and @($scope.doh).Count -eq 0 -and
                $script:dohReads -eq 0) 'dnscrypt-preserves-independent-doh'
            $originalDoh=Old-DohFixture
            $originalDoh.DohTemplate='https://independent.invalid/dns-query'
            $script:currentDoh['8.8.8.8']=$originalDoh
            if($transition -ceq 'dnscrypt-to-doh'){
                Configure-DNS 'doh'
                $scope=(Read-DNSRecoverySnapshot).record
                Assert-DNS ($scope.dohManaged -eq $true -and $scope.doh[0].DohTemplate -ceq $originalDoh.DohTemplate) 'first-doh-captures-global-policy'
            }else{
                # Missing DoH management commands must not prevent DNSCrypt-only recovery.
                $script:present['Remove-DnsClientDohServerAddress']=$false
            }
        }
        Restore-DNS
        Assert-DNS ($script:currentDoh['8.8.8.8'].DohTemplate -ceq $originalDoh.DohTemplate -and
            -not [IO.File]::Exists($snapshot) -and ($transition -cne 'dnscrypt-only' -or $script:dohReads -eq 0)) 'dnscrypt-preserves-independent-doh'
    }
    foreach($scope in @('false',$false,$null)){
        New-DNSCase
        $saved=Original-DNSFixture
        $saved.dohManaged=$scope
        $saved.doh=@((Old-DohFixture))
        Write-DNSFixture $saved
        $hash=Snapshot-Hash
        Reject-DNS {Restore-DNS}
        Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0) 'invalid-doh-recovery-scope'
    }
    New-DNSCase;$script:emptyOrdinaryAnswers=1
    Configure-DNS 'doh'
    Assert-DNS ($script:resolverQueries -eq 2 -and $script:ordinaryResolverWaits -eq 1 -and
        $script:dnsConfigured) 'ordinary-resolver-requires-address-answer'
    foreach($drift in @('policy','server','stored-dhcp','family-added','family-removed','adapter-added','adapter-selection-changed','index-duplicated')){
        New-DNSCase;$script:resolverDrift=$drift;$script:resolverServicePresent=$true
        if($drift -ceq 'family-added'){$script:exposure['77/IPv6']=$false}
        $expected=switch($drift){
            'policy' {'Configured DoH policy changed during resolver verification'}
            'server' {'Configured DNS servers differ'}
            'stored-dhcp' {'Stored DNS servers do not match the configured static addresses'}
            'adapter-added' {'Active DNS adapter coverage changed during readback'}
            {$_ -cin @('adapter-selection-changed','index-duplicated')} {'Configured DNS adapter changed during readback'}
            default {'Configured DNS family coverage changed during readback'}
        }
        Reject-DNS {Configure-DNS 'doh'} $expected
        Assert-DNS ($script:resolverQueries -eq 1 -and -not $script:dnsConfigured -and $script:events.Count -eq 0 -and
            $script:serviceStops -eq 0 -and $script:journalActive -and (Snapshot-Hash) -ceq $script:journalDigest) 'configure-refuses-drift-during-resolver-query'
    }
    New-DNSCase;$script:resolverDrift='server';$script:resolverServicePresent=$true;$script:stageDNSCrypt=$true
    [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
    Reject-DNS {Configure-DNS 'dnscrypt'} 'Configured DNS servers differ'
    Assert-DNS ($script:resolverQueries -eq 1 -and -not $script:dnsConfigured -and $script:events.Count -eq 0 -and
        $script:journalActive -and (Snapshot-Hash) -ceq $script:journalDigest) 'configure-refuses-drift-during-resolver-query'
    New-DNSCase;$script:resolverDrift='unselected-adapter-added'
    Configure-DNS 'doh'
    Assert-DNS ($script:dnsConfigured -and $script:resolverQueries -eq 1) 'configure-ignores-unselected-adapter-during-resolver-query'
    foreach($invalidReply in @('timeout','empty','wrong-name','bad-address','authority')){
        New-DNSCase
        $script:listenerReplies['::1']=[Collections.Generic.Queue[string]]::new()
        $script:listenerReplies['::1'].Enqueue($invalidReply)
        Reject-DNS {Wait-DNSCryptListeners @('::1') 0}
        Assert-DNS ($script:listenerQueries.Count -eq 1) 'dnscrypt-listener-refuses-invalid-answers'
    }
    foreach($fault in @('none','listener','binding','mode','state','command','missing','late-mode')){
        New-DNSCase
        $script:stageDNSCrypt=$true;$script:allowNewResolver=$true
        [IO.File]::WriteAllText((Join-Path $root 'example-dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        if($fault -ceq 'listener'){
            $script:refuseListenerWait=$true
            $script:listenerReplies['::1']=[Collections.Generic.Queue[string]]::new()
            $script:listenerReplies['::1'].Enqueue('timeout')
            Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic loopback wait boundary'
        }elseif($fault -ceq 'binding'){
            $script:resolverBindingFailureRead=1
            Reject-DNS {Configure-DNS 'dnscrypt'} 'Fixture DNS service identity changed'
        }elseif($fault -ceq 'none'){
            Configure-DNS 'dnscrypt'
        }else{
            $script:resolverReadbackFault=$fault
            $expected=switch -CaseSensitive ($fault){
                'missing' {'Managed service registration could not be verified'}
                'command' {'DNSCrypt service identity changed during startup verification'}
                default {'DNSCrypt service automatic startup or running state could not be verified'}
            }
            Reject-DNS {Configure-DNS 'dnscrypt'} $expected
        }
        $startupAttempted=$fault -cnotin @('listener','binding')
        $adaptersChanged=$fault -cin @('none','late-mode')
        Assert-DNS ($script:newResolverRegistered -and $script:serviceRestarts -eq 0 -and
            $script:dnsConfigured -eq ($fault -ceq 'none') -and
            $script:serviceStartupChanges -eq [int]$startupAttempted -and
            $script:resolverReadbacks -eq ([int]$startupAttempted+[int]$adaptersChanged) -and
            (Mutation-Count) -eq (2*[int]$adaptersChanged)) 'dnscrypt-listeners-before-adapters'
    }
    foreach($family in @('IPv4','IPv6','both','failure')){
        New-DNSCase
        $script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        if($family -ceq 'IPv4'){$script:exposure['77/IPv6']=$false}
        if($family -ceq 'IPv6'){$script:exposure['77/IPv4']=$false}
        if($family -cin @('both','failure')){
            $script:listenerReplies['::1']=[Collections.Generic.Queue[string]]::new()
            $script:listenerReplies['::1'].Enqueue('timeout')
            $script:listenerReplies['::1'].Enqueue('answer')
        }
        if($family -ceq 'failure'){
            $script:refuseListenerWait=$true
            Reject-DNS {Configure-DNS 'dnscrypt'}
            Assert-DNS ((Mutation-Count) -eq 0 -and $script:resolverQueries -eq 0 -and $script:journalActive -and
                $script:serviceStartupChanges -eq 0 -and [IO.File]::Exists($snapshot) -and
                -not $script:dnsConfigured) 'dnscrypt-listener-refusal-preserves-adapter-state'
        } else {
            Configure-DNS 'dnscrypt'
            $expected=switch($family){'IPv4' {'127.0.0.1'} 'IPv6' {'::1'} 'both' {'127.0.0.1,::1,::1'}}
            Assert-DNS ($script:listenerChecksBeforeAdapters -and ($script:listenerQueries -join ',') -ceq $expected -and
                $script:resolverQueries -eq 1 -and $script:dnsConfigured) 'dnscrypt-listeners-before-adapters'
            if($family -ceq 'both'){
                Assert-DNS ($script:listenerWaits -eq 1) 'dnscrypt-listener-retries-only-unready-family'
            }
        }
    }
    # DNSCrypt uses loopback in each family; validate the same readback helper
    # against synthetic state without invoking its service or component path.
    New-DNSCase;$fixture=Original-DNSFixture;$guid=[string]$script:adapters[0].InterfaceGuid
    $script:appliedDNS[$guid+'/IPv4']=@{values=@('127.0.0.1')};$script:appliedDNS[$guid+'/IPv6']=@{values=@('::1')}
    $ok=$true;try{Assert-ConfiguredDNSServers $script:adapters @($fixture.adapters) @('127.0.0.1','::1')}catch{$ok=$false}
    Assert-DNS $ok 'configure-dnscrypt-loopback-readback'
    New-DNSCase;$script:configurationLag=2;Configure-DNS 'doh'
    Assert-DNS ($script:readbackWaits -eq 2 -and $script:resolverQueries -eq 1 -and @($script:calls | Where-Object {$_.kind -ceq 'dns'}).Count -eq 2) 'configure-adapter-readback-retries'
    foreach($fault in @('missing','duplicate','wrong-template','upgrade-disabled','fallback-enabled')){
        New-DNSCase;$script:configureDohFaultAddress='8.8.8.8';$script:postConfigureDohReadFault=$fault
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS ($script:resolverQueries -eq 0 -and -not $script:dnsConfigured -and $script:journalActive) 'configure-post-policy-refuses'
        $hash=Snapshot-Hash;Assert-SnapshotRetained $hash
        $script:postConfigureDohReadFault='';Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'configure-post-policy-recovers'
    }
    New-DNSCase
    $script:storedDNS[([string]$script:adapters[0].InterfaceGuid)+'/IPv4']='198.51.100.99'
    Reject-DNS {Configure-DNS 'doh'} 'Stored static DNS servers differ'
    Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0 -and $script:journals -eq 0) 'stored-dns-mismatch-before-effects'

    New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash
    $script:storedDNSFault='wrong-address'
    Reject-DNS {Restore-DNS $hash} 'Stored static DNS servers differ'
    Assert-SnapshotRetained $hash
    Assert-DNS (-not $script:receiptDigest) 'stored-dns-restore-retains-snapshot'
    $script:storedDNSFault='';Restore-DNS $hash
    Assert-DNS (-not [IO.File]::Exists($snapshot)) 'recovery-retry-completes-after-confirmed-inspection'

    foreach($family in @('IPv4','IPv6')){
        New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash
        $key=([string]$script:adapters[0].InterfaceGuid)+'/'+$family
        $independent=if($family -ceq 'IPv4'){'198.51.100.53'}else{'2001:db8::54'}
        $script:appliedDNS[$key]=@{dhcp=$false;values=@($independent)}
        $script:calls.Clear()
        Reject-DNS {Restore-DNS $hash} 'Adapter DNS settings changed independently'
        Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:receiptDigest -and
            $script:appliedDNS[$key].values[0] -ceq $independent) 'rollback-keeps-independent-adapter-settings'
        foreach($operation in @({Remove-Method 'dnscrypt'},{Remove-All})){
            Reject-DNS $operation 'Adapter DNS settings changed independently'
            Assert-SnapshotRetained $hash
            Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:receiptDigest -and
                $script:appliedDNS[$key].values[0] -ceq $independent) 'rollback-keeps-independent-adapter-settings'
        }
        Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'recovery-retry-completes-after-confirmed-inspection'
    }

    New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash
    $script:calls.Clear();$script:failDNSSetterFamily='IPv6'
    Reject-DNS {Restore-DNS $hash} 'source-dns-setter-failed'
    Assert-SnapshotRetained $hash
    $writes=@($script:calls | Where-Object {$_.kind -ceq 'dns'})
    Assert-DNS ($writes.Count -eq 1 -and $writes[0].family -ceq 'IPv4' -and
        ($writes[0].servers -join ',') -ceq '192.0.2.53') 'rollback-skips-restored-adapter-family'
    $script:calls.Clear();$script:unverifiedDNSWrites=0;$script:failDNSSetterFamily=''
    Restore-DNS $hash
    $writes=@($script:calls | Where-Object {$_.kind -ceq 'dns'})
    Assert-DNS ($writes.Count -eq 1 -and $script:unverifiedDNSWrites -eq 1 -and
        $writes[0].family -ceq 'IPv6' -and $writes[0].reset -and
        $script:receiptDigest -ceq $hash -and -not [IO.File]::Exists($snapshot)) 'rollback-skips-restored-adapter-family'

    foreach($stage in @('preflight','after-publication')){
        New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash
        $guid=[string]$script:adapters[0].InterfaceGuid
        $script:calls.Clear();$script:unverifiedDNSWrites=0
        $initialSaves=$script:journals
        if($stage -ceq 'preflight'){
            $script:appliedDNS[$guid+'/IPv4']=@{dhcp=$false;values=@('198.51.100.53')}
        }else{
            $script:changeDNSOnActivation='servers'
        }
        Reject-DNS {Configure-DNS 'doh'} 'Adapter DNS settings changed independently'
        $expectedSaves=if($stage -ceq 'preflight'){$initialSaves}else{$initialSaves+2}
        $expectedHash=if($stage -ceq 'preflight'){$hash}else{$script:journalDigest}
        Assert-DNS ($script:journals -eq $expectedSaves -and (Snapshot-Hash) -ceq $expectedHash -and
            (Mutation-Count) -eq 0 -and $script:unverifiedDNSWrites -eq 0 -and
            ($script:appliedDNS[$guid+'/IPv4'].values -join ',') -ceq '198.51.100.53') 'reconfigure-preserves-independent-adapter-dns'
    }

    # Reconfiguration must not overwrite first originals with managed DNS state.
    New-DNSCase;$saved=Original-DNSFixture;$saved.doh=@((Old-DohFixture));Write-DNSFixture $saved;$hash=Snapshot-Hash;$script:mode4='127.0.0.1'
    Configure-DNS 'doh'
    $bound=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS ($bound.recoveryID -cmatch '^[a-f0-9]{32}$' -and $bound.adapters[0].ipv4[0] -ceq '192.0.2.53' -and
        $bound.doh[0].DohTemplate -ceq 'https://original.invalid/dns-query' -and $script:registryReads.Count -eq 0 -and
        $script:undo.Count -eq 1 -and $script:undo[0].snapshotSHA256 -ceq (Snapshot-Hash)) 'existing-originals-never-recaptured'
    # A legitimate new adapter gets its own originals before any DNS mutation.
    New-DNSCase;$saved=Original-DNSFixture;$saved.doh=@((Old-DohFixture));Write-DNSFixture $saved
    $script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='Second fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
    $script:dnsValues['88/IPv4']=@('198.51.100.53');$script:dnsValues['88/IPv6']=@('2001:db8:2::53')
    Configure-DNS 'doh'
    $saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS ($saved.adapters.Count -eq 2 -and $saved.adapters[0].ipv4[0] -ceq '192.0.2.53' -and $saved.adapters[1].ipv4[0] -ceq '198.51.100.53' -and $saved.adapters[1].ipv6[0] -ceq '2001:db8:2::53' -and -not $saved.adapters[1].dhcp4 -and $saved.adapters[1].dhcp6 -and $saved.doh[0].DohTemplate -ceq 'https://original.invalid/dns-query' -and $script:registryReads.Count -eq 4) 'new-adapter-originals-persisted'
    Restore-DNS
    Assert-DNS (-not [IO.File]::Exists($snapshot) -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -eq 88 -and $_.family -eq 'IPv4' -and $_.servers[0] -ceq '198.51.100.53'}).Count -eq 1 -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -eq 77 -and $_.family -eq 'IPv4' -and $_.servers[0] -ceq '192.0.2.53'}).Count -eq 1 -and $script:currentDoh['8.8.8.8'].DohTemplate -ceq 'https://original.invalid/dns-query') 'extended-snapshot-restores-both-adapters'
    foreach($method in @('doh','dnscrypt')){
        foreach($failure in @('registry','empty-read','empty-static','persist')){
            New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash
            $script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='Second fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
            switch($failure){
                'registry' {$script:registryFailure='IPv6'}
                'empty-read' {$script:emptyDnsRead=$true}
                'empty-static' {$script:dnsValues['88/IPv4']=@()}
                'persist' {$script:failSnapshotWrite=$true}
            }
            Reject-DNS {Configure-DNS $method};Assert-SnapshotRetained $hash
            $expectedSaves=[int]($failure -eq 'persist')
            Assert-DNS ((Mutation-Count) -eq 0 -and $script:journals -eq $expectedSaves -and $script:undo.Count -eq $expectedSaves -and -not $script:journalActive) 'extension-failure-before-effects'
        }
        foreach($failure in @('empty','flags','static','missing','ambiguous','duplicate')){
            New-DNSCase;$saved=Original-DNSFixture
            switch($failure){
                'empty' {$saved.adapters=@()}
                'flags' {$saved.adapters[0].dhcp4='false'}
                'static' {$saved.adapters[0].ipv4=@()}
                'missing' {$script:adapters[0].InterfaceGuid='{00000000-0000-0000-0000-000000000002}'}
                'ambiguous' {$script:adapters+=@($script:adapters[0])}
                'duplicate' {$saved.adapters+=@($saved.adapters[0])}
            }
            Write-DNSFixture $saved;$hash=Snapshot-Hash;Reject-DNS {Configure-DNS $method};Assert-SnapshotRetained $hash
            Assert-DNS ((Mutation-Count) -eq 0 -and $script:journals -eq 0 -and -not $script:journalActive) 'invalid-configuration-preflight'
        }
    }
    New-DNSCase;$script:numericFamilies=$true
    $script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='Up fixture without DNS clients';InterfaceGuid='{00000000-0000-0000-0000-000000000003}';ifIndex=99})
    $script:exposure['99/IPv4']=$false;$script:exposure['99/IPv6']=$false
    Configure-DNS 'doh';$saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS ($saved.adapters.Count -eq 1 -and $saved.adapters[0].bound4 -and $saved.adapters[0].bound6 -and $script:registryReads.Count -eq 4 -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -eq 99}).Count -eq 0) 'non-dns-adapter-not-targeted'
    foreach($family in @('IPv4','IPv6')){
        New-DNSCase;$other=if($family -eq 'IPv4'){'IPv6'}else{'IPv4'};$script:exposure['77/'+$other]=$false;$script:mode6='2001:db8::53'
        Configure-DNS 'doh';$saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot));$number=if($family -eq 'IPv4'){'4'}else{'6'};$unused=if($number -eq '4'){'6'}else{'4'}
        Restore-DNS
        Assert-DNS ($saved.adapters[0].('bound'+$number) -and -not $saved.adapters[0].('bound'+$unused) -and @($saved.adapters[0].('ipv'+$unused)).Count -eq 0 -and $script:registryReads.Count -eq 2 -and @($script:calls | Where-Object {$_.kind -eq 'dns'}).Count -eq 2 -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.family -ne $family}).Count -eq 0 -and -not [IO.File]::Exists($snapshot)) 'single-family-capture-and-restore'
    }
    New-DNSCase;$script:exposure['77/IPv6']=$false;$script:currentDoh['8.8.8.8']=Old-DohFixture
    Configure-DNS 'doh';$script:calls.Clear();$script:exposure['77/IPv6']=$true;$script:mode4='127.0.0.1';$script:mode6='2001:db8::53';$script:dnsValues['77/IPv4']=@('8.8.8.8','9.9.9.9')
    Configure-DNS 'doh';$saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS ($saved.adapters[0].bound4 -and $saved.adapters[0].bound6 -and $saved.adapters[0].ipv4[0] -ceq '192.0.2.53' -and $saved.adapters[0].ipv6[0] -ceq '2001:db8::53' -and $saved.doh[0].DohTemplate -ceq 'https://original.invalid/dns-query' -and $script:registryReads.Count -eq 6) 'new-family-originals-extended'
    Restore-DNS
    foreach($failure in @('capture','persist')){
        foreach($method in @('doh','dnscrypt')){
            New-DNSCase;$saved=Original-DNSFixture;$saved.adapters[0].bound4=$true;$saved.adapters[0].bound6=$false;$saved.adapters[0].ipv6=@();$saved.adapters[0].dhcp6=$false;Write-DNSFixture $saved;$hash=Snapshot-Hash
            if($failure -eq 'capture'){$script:registryFailure='IPv6'}else{$script:failSnapshotWrite=$true}
            Reject-DNS {Configure-DNS $method};Assert-SnapshotRetained $hash
            $expectedSaves=[int]($failure -eq 'persist')
            Assert-DNS ((Mutation-Count) -eq 0 -and $script:journals -eq $expectedSaves -and -not $script:journalActive) 'family-extension-before-effects'
        }
    }
    foreach($method in @('doh','dnscrypt')){
        foreach($drift in @('mode','servers')){
            New-DNSCase;$script:captureDrift=$drift
            Reject-DNS {Configure-DNS $method} 'Original DNS settings changed during capture'
            Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0 -and
                $script:journals -eq 0 -and $script:dnscryptConfigWrites -eq 0 -and $script:serviceRestarts -eq 0) 'capture-drift-before-snapshot'
        }
    }
    foreach($method in @('doh','dnscrypt')){
        foreach($drift in @('mode','servers')){
            New-DNSCase;$script:changeDNSOnActivation=$drift
            if($method -ceq 'dnscrypt'){
                $script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
                [IO.File]::WriteAllText((Join-Path $root 'dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
            }
            Reject-DNS {Configure-DNS $method} 'Original DNS settings changed before the adapter update'
            $guid=[string]$script:adapters[0].InterfaceGuid
            $state=$script:appliedDNS[$guid+'/IPv4']
            Assert-DNS ($script:journalActive -and $script:journalDigest -ceq (Snapshot-Hash) -and
                $script:unverifiedDNSWrites -eq 0 -and $script:resolverQueries -eq 0 -and
                $state.dhcp -eq ($drift -ceq 'mode') -and
                ($state.values -join ',') -ceq '198.51.100.53') 'capture-drift-before-adapter-write'
        }
    }
    foreach($change in @('renumber','duplicate')){
        New-DNSCase
        if($change -ceq 'renumber'){$script:renumberAfterInventory=$true}
        else {$script:adapters+=@([pscustomobject]@{Status='Up';InterfaceDescription='Duplicate index';InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=77})}
        Reject-DNS {Configure-DNS 'doh'} 'An adapter changed during original DNS capture'
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0 -and
            $script:registryReads.Count -eq 0) 'capture-index-change-before-snapshot'
    }
    foreach($failure in @('query','duplicate','empty')){
        New-DNSCase
        switch($failure){'query' {$script:inventoryFailure=$true} 'duplicate' {$script:duplicateInventory=$true} 'empty' {$script:emptyDnsRead=$true}}
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0 -and $script:registryReads.Count -eq 0 -and $script:undo.Count -eq 0) 'client-inventory-before-effects'
    }
    foreach($failure in @('half','type','none','unused-data')){
        foreach($action in @('configure','restore')){
            New-DNSCase;$saved=Original-DNSFixture
            switch($failure){
                'half' {$saved.adapters[0].bound4=$true}
                'type' {$saved.adapters[0].bound4='true';$saved.adapters[0].bound6=$true}
                'none' {$saved.adapters[0].bound4=$false;$saved.adapters[0].bound6=$false}
                'unused-data' {$saved.adapters[0].bound4=$true;$saved.adapters[0].bound6=$false}
            }
            Write-DNSFixture $saved;$hash=Snapshot-Hash
            if($action -eq 'restore'){Reject-DNS {Restore-DNS}}else{Reject-DNS {Configure-DNS 'doh'}}
            Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'family-flags-preflight'
        }
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:exposure['77/IPv6']=$false
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0 -and $script:dohReads -eq 0) 'owned-family-missing-retained'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:renumberDuringDoh=$true
    Configure-DNS 'doh'
    Assert-DNS (@($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -eq 101}).Count -eq 2 -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -ne 101}).Count -eq 0) 'configuration-uses-current-guid-index'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:failDohRead=1
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'restore-inspection-before-effects'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:emptyDnsRead=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'restore-inspection-before-effects'
    foreach($mode in @('empty-adapters','bad-flags','empty-static','missing-adapter','ambiguous-adapter','duplicate-doh','bad-doh')){
        New-DNSCase;$saved=Original-DNSFixture
        switch($mode){
            'empty-adapters' {$saved.adapters=@()}
            'bad-flags' {$saved.adapters[0].dhcp4='false'}
            'empty-static' {$saved.adapters[0].ipv4=@()}
            'missing-adapter' {$saved.adapters+=@{guid='{00000000-0000-0000-0000-000000000002}';index=88;ipv4=@('192.0.2.54');ipv6=@();dhcp4=$false;dhcp6=$true}}
            'ambiguous-adapter' {$script:adapters+=@($script:adapters[0])}
            'duplicate-doh' {$saved.doh=@((Old-DohFixture),(Old-DohFixture))}
            'bad-doh' {$item=Old-DohFixture;$item.AllowFallbackToUdp='true';$saved.doh=@($item)}
        }
        Write-DNSFixture $saved;$hash=Snapshot-Hash;Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'invalid-recovery-preflight'
    }
    foreach($mode in @('duplicate-identical','duplicate-conflicting','duplicate-case','missing-guid','blank-guid','numeric-guid','null-record')){
        New-DNSCase;$saved=Original-DNSFixture
        switch($mode){
            'duplicate-identical' {$saved.adapters+=@($saved.adapters[0])}
            'duplicate-conflicting' {$other=Original-DNSFixture;$other.adapters[0].ipv4=@('198.51.100.53');$saved.adapters+=@($other.adapters[0])}
            'duplicate-case' {$saved.adapters[0].guid='{ABCDEF00-0000-0000-0000-000000000001}';$script:adapters[0].InterfaceGuid=$saved.adapters[0].guid;$other=Original-DNSFixture;$other.adapters[0].guid=$saved.adapters[0].guid.ToLowerInvariant();$saved.adapters+=@($other.adapters[0])}
            'missing-guid' {$saved.adapters[0].Remove('guid')}
            'blank-guid' {$saved.adapters[0].guid=' ';$script:adapters[0].InterfaceGuid=' '}
            'numeric-guid' {$saved.adapters[0].guid=77;$script:adapters[0].InterfaceGuid=77}
            'null-record' {$saved.adapters+=@($null)}
        }
        Write-DNSFixture $saved;$hash=Snapshot-Hash
        Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:dohReads -eq 0 -and $script:dnsReadCount -eq 0) 'invalid-recovery-identities-before-inspection'
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:renumberDuringDoh=$true;$script:reuseIndexDuringDoh=$true
    Restore-DNS
    Assert-DNS (-not [IO.File]::Exists($snapshot) -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -eq 101}).Count -eq 2 -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -ne 101}).Count -eq 0) 'restore-uses-refreshed-guid-index'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:disappearDuringDoh=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 0 -and $script:dnsReadCount -eq 1 -and $script:dnsInterfaceReads -eq 0) 'changed-adapter-retains-before-interface-read'
    New-DNSCase;$saved=Original-DNSFixture;$saved.adapters[0].guid='{ABCDEF00-0000-0000-0000-000000000001}';$script:adapters[0].InterfaceGuid=$saved.adapters[0].guid.ToLowerInvariant();$script:adapters[0].Status='Down';Write-DNSFixture $saved
    Restore-DNS
    Assert-DNS (-not [IO.File]::Exists($snapshot) -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -eq 77}).Count -eq 2) 'case-insensitive-down-adapter-restoration'
    foreach($change in @('add','remove','template','fallback','upgrade')){
        New-DNSCase;$saved=Original-DNSFixture;$saved.doh=@((Old-DohFixture))
        if($change -cne 'add'){$script:currentDoh['8.8.8.8']=Old-DohFixture}
        Write-DNSFixture $saved;$hash=Snapshot-Hash;$script:changeDohAfterAdapterWrite=$change
        Reject-DNS {Restore-DNS} 'DoH policy changed during restoration';Assert-SnapshotRetained $hash
        Assert-DNS (@($script:calls | Where-Object {$_.kind -in @('add','set','remove')}).Count -eq 0 -and
            $script:receiptDigest -eq $null) 'restore-doh-refuses-concurrent-policy'
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash
    foreach($address in @('8.8.8.8','9.9.9.9')){
        $script:currentDoh[$address]=Old-DohFixture
        $script:currentDoh[$address].ServerAddress=$address
    }
    $script:changeDohAfterProviderWrite=$true
    Reject-DNS {Restore-DNS} 'DoH policy changed during restoration';Assert-SnapshotRetained $hash
    Assert-DNS (-not $script:currentDoh.ContainsKey('8.8.8.8') -and
        $script:currentDoh['9.9.9.9'].DohTemplate -ceq 'https://independent.invalid/dns-query' -and
        @($script:calls | Where-Object {$_.address -eq '9.9.9.9'}).Count -eq 0) 'restore-doh-keeps-independent-policy'
    New-DNSCase;$saved=Original-DNSFixture;$saved.doh=@((Old-DohFixture));Write-DNSFixture $saved
    $script:currentDoh['8.8.8.8']=Old-DohFixture;$script:currentDoh['8.8.8.8'].AutoUpgrade='false'
    Restore-DNS
    Assert-DNS (-not [IO.File]::Exists($snapshot) -and $script:currentDoh['8.8.8.8'].AutoUpgrade -is [bool] -and
        -not $script:currentDoh['8.8.8.8'].AutoUpgrade) 'restore-doh-repairs-stable-malformed-policy'
    foreach($kind in @('set','add','remove')){
        New-DNSCase;$saved=Original-DNSFixture
        if($kind -ne 'remove'){$saved.doh=@((Old-DohFixture))}
        if($kind -ne 'add'){$script:currentDoh['8.8.8.8']=[pscustomobject]@{ServerAddress='8.8.8.8';DohTemplate='https://changed.invalid/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true}}
        Write-DNSFixture $saved;$hash=Snapshot-Hash;$script:failAction=$kind;$script:failAddress='8.8.8.8'
        Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
        $script:failAction='';Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'recovery-retry-completes-after-confirmed-inspection'
        if($kind -ne 'remove'){Assert-DNS ($script:currentDoh['8.8.8.8'].DohTemplate -ceq 'https://original.invalid/dns-query' -and $script:currentDoh['8.8.8.8'].AllowFallbackToUdp -and -not $script:currentDoh['8.8.8.8'].AutoUpgrade) 'exact-original-doh-restored'}
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash
    foreach($address in @('8.8.8.8','9.9.9.9')){$script:currentDoh[$address]=[pscustomobject]@{ServerAddress=$address;DohTemplate='https://changed.invalid/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true}}
    $script:failAction='remove';$script:failAddress='9.9.9.9'
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    Assert-DNS (-not $script:currentDoh.ContainsKey('8.8.8.8') -and $script:currentDoh.ContainsKey('9.9.9.9')) 'partial-removal-retains-needed-recovery'
    $script:failAction='';Restore-DNS
    Assert-DNS (@($script:calls | Where-Object {$_.kind -eq 'remove' -and $_.address -eq '8.8.8.8'}).Count -eq 1 -and -not [IO.File]::Exists($snapshot)) 'confirmed-absent-entry-not-removed-again'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:adapters[0].ifIndex=101
    $script:currentDoh['192.0.2.90']=[pscustomobject]@{ServerAddress='192.0.2.90';DohTemplate='https://unrelated.invalid/dns-query';AllowFallbackToUdp=$true;AutoUpgrade=$false}
    Restore-DNS
    Assert-DNS (@($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -ne 101}).Count -eq 0) 'guid-recovery-uses-current-index'
    Assert-DNS ($script:currentDoh.ContainsKey('192.0.2.90') -and @($script:calls | Where-Object {$_.kind -eq 'remove'}).Count -eq 0) 'absent-entry-idempotence-and-unrelated-preservation'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:failDelete=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    New-DNSCase;$saved=Original-DNSFixture;$saved.doh=@((Old-DohFixture));Write-DNSFixture $saved;$hash=Snapshot-Hash;$script:present['Get-DnsClientDohServerAddress']=$false
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'saved-doh-needs-capability'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:present['Get-DnsClientDohServerAddress']=$false;Restore-DNS
    Assert-DNS (-not [IO.File]::Exists($snapshot)) 'legacy-no-doh-recovery-supported'
    foreach($fault in @('reuse','index','family','status')){
        New-DNSCase
        if($fault -ceq 'reuse'){$script:reuseBeforeDNSSetter=$true}else{$script:dnsRowFault=$fault}
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS ($script:dnsInterfaceReads -eq 1 -and $script:unverifiedDNSWrites -eq 0 -and
            $script:resolverQueries -eq 0 -and $script:journalActive -and [IO.File]::Exists($snapshot) -and
            $script:undo[0].snapshotSHA256 -ceq (Snapshot-Hash)) 'configure-interface-reuse-before-setter'
    }
    foreach($mode in @('configure','rollback')){
        New-DNSCase
        if($mode -ceq 'rollback'){
            Configure-DNS 'doh';$hash=Snapshot-Hash
            $script:calls.Clear();$script:dnsInterfaceReads=0;$script:unverifiedDNSWrites=0
            $script:reuseOnFinalRegistryRead=$true
            Reject-DNS {Restore-DNS $hash} 'A DNS adapter changed before the update'
            Assert-SnapshotRetained $hash
        }else{
            $script:reuseOnFinalRegistryRead=$true
            Reject-DNS {Configure-DNS 'doh'} 'A DNS adapter changed before the update'
            Assert-SnapshotRetained $script:journalDigest
        }
        Assert-DNS ($script:dnsInterfaceReads -eq 1 -and $script:unverifiedDNSWrites -eq 0 -and
            $script:adapters[0].ifIndex -eq 101 -and $script:adapters[1].ifIndex -eq 77) 'configure-interface-reuse-before-setter'
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:reuseBeforeDNSSetter=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 0 -and $script:dnsInterfaceReads -eq 1) 'restore-interface-reuse-before-setter'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:silentSnapshotRemoval=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 2) 'restore-retirement-requires-absence'
    New-DNSCase
    Write-DNSFixture (Original-DNSFixture)
    $hash=Snapshot-Hash
    $script:replaceSnapshotOnReceiptSave=$true
    $refused=$false
    try{Restore-DNS}catch{$refused=$_.Exception.Message -ceq 'Original DNS snapshot changed during preflight; retain it for review'}
    Assert-DNS ($refused -and $script:receiptDigest -ceq $hash -and [IO.File]::Exists($snapshot) -and
        (Snapshot-Hash) -cne $hash -and -not ($script:events -contains 'Original DNS and DoH settings restored')) 'restore-retirement-refuses-replaced-snapshot'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:recoveryLag=2
    Restore-DNS
    Assert-DNS ($script:readbackWaits -eq 2 -and (Mutation-Count) -eq 2 -and -not [IO.File]::Exists($snapshot)) 'restore-delayed-observation'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:renumberDuringRecoveryRead=$true
    Restore-DNS
    Assert-DNS ($script:readbackWaits -eq 1 -and (Mutation-Count) -eq 2 -and
        $script:adapters[0].ifIndex -eq 101 -and -not [IO.File]::Exists($snapshot)) 'restore-adapter-row-fence'
    # Successful native returns with wrong state must not consume first originals.
    foreach($fault in @('noop','wrong-mode','wrong-value','empty-static','wrong-order','read-error','adapter-missing')){
        New-DNSCase;$script:dnsValues['77/IPv4']=@('192.0.2.53','198.51.100.54')
        $originalAdapters=@($script:adapters);Configure-DNS 'doh';$hash=Snapshot-Hash;$script:readbackFault=$fault
        Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
        $script:readbackFault='';$script:readbackFaultArmed=$false;$script:adapters=$originalAdapters;Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'recovery-retry-completes-after-confirmed-inspection'
    }
    foreach($kind in @('set','add','remove')){
        New-DNSCase;$saved=Original-DNSFixture
        if($kind -cne 'remove'){$saved.doh=@((Old-DohFixture))}
        if($kind -cne 'add'){$script:currentDoh['8.8.8.8']=[pscustomobject]@{ServerAddress='8.8.8.8';DohTemplate='https://changed.invalid/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true}}
        Write-DNSFixture $saved;$hash=Snapshot-Hash;$script:silentDohFault=$kind
        Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
        $script:silentDohFault='';Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'recovery-retry-completes-after-confirmed-inspection'
    }
    if((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne $sourceHash){throw 'DNS workflow source changed during contracts'}
    foreach($invalidSnapshot in @('invalid-utf8','over-limit','array','raw-nul')){
        New-DNSCase
        switch($invalidSnapshot){
            'invalid-utf8' {[IO.File]::WriteAllBytes($snapshot,[byte[]](0xc3,0x28))}
            'over-limit' {
                $fixtureStream=[IO.File]::Open($snapshot,[IO.FileMode]::CreateNew)
                try {$fixtureStream.SetLength(8MB+1)} finally {$fixtureStream.Dispose()}
            }
            'array' {[IO.File]::WriteAllText($snapshot,'[{}]')}
            'raw-nul' {[IO.File]::WriteAllBytes($snapshot,[byte[]](0x7b,0,0x7d))}
        }
        $hash=Snapshot-Hash
        Reject-DNS {Restore-DNS}
        Reject-DNS {Configure-DNS 'doh'}
        Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:journals -eq 0) 'snapshot-frame-refused'
    }
    New-DNSCase
    Write-DNSFixture (Original-DNSFixture)
    $hash=Snapshot-Hash
    Reject-DNS {Restore-DNS ('0'*64)}
    Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 0 -and $script:dnsReadCount -eq 0) 'snapshot-journal-digest-refused'

    foreach($mode in @('restore','configure')){
        New-DNSCase
        Write-DNSFixture (Original-DNSFixture)
        $hash=Snapshot-Hash
        if($mode -ceq 'restore'){
            $script:replaceSnapshotOnAdapterRead=$true
            Reject-DNS {Restore-DNS $hash}
        }else{
            $script:replaceSnapshotOnJournalSave=$true
            Reject-DNS {Configure-DNS 'doh'}
        }
        Assert-DNS ([IO.File]::Exists($snapshot) -and (Snapshot-Hash) -cne $hash -and
            (Mutation-Count) -eq 0 -and -not $script:receiptDigest) 'snapshot-preflight-change-refused'
    }

    foreach($method in @('doh','dnscrypt')){
        New-DNSCase;$script:replaceSnapshotOnActivation=$true
        Reject-DNS {Configure-DNS $method} 'Original DNS snapshot changed'
        Assert-DNS ((Snapshot-Hash) -cne $script:journalDigest -and (Mutation-Count) -eq 0 -and
            $script:dnscryptConfigWrites -eq 0 -and $script:serviceRestarts -eq 0) 'snapshot-preflight-change-refused'
    }
    foreach($mode in @('restore','configure')){
        New-DNSCase;$script:replaceSnapshotOnInterfaceRead=2
        if($mode -ceq 'restore'){
            Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash
            Reject-DNS {Restore-DNS $hash} 'Original DNS snapshot changed'
        }else{
            Reject-DNS {Configure-DNS 'doh'} 'Original DNS snapshot changed'
            $hash=$script:journalDigest
        }
        Assert-DNS ((Snapshot-Hash) -cne $hash -and $script:unverifiedDNSWrites -eq 1 -and
            $script:resolverQueries -eq 0 -and -not $script:receiptDigest) 'snapshot-preflight-change-refused'
    }

    New-DNSCase;Configure-DNS 'doh';$firstDigest=$script:undo[0].snapshotSHA256
    Configure-DNS 'doh'
    Assert-DNS ($script:undo.Count -eq 1 -and $firstDigest -cne $script:undo[0].snapshotSHA256 -and
        $script:undo[0].snapshotSHA256 -ceq (Snapshot-Hash)) 'reconfiguration-rotates-recovery-identity'
    $script:contractOutcome='passed';$script:contractCode='none'
    Write-Output ('DNS contracts passed: '+$script:checks+'; PowerShell '+$PSVersionTable.PSVersion.ToString()+' '+$PSVersionTable.PSEdition+'; source '+$sourceHash.ToLowerInvariant())
} finally {
    # One shell owns cleanup. Resolve and verify the explicitly created fixture
    # root before any recursive delete; do not cross to cmd/batch for deletion.
    $bodyOutcome=$script:contractOutcome;$bodyCode=$script:contractCode
    $script:contractOutcome='failed';$script:contractCode='fixture-cleanup-incomplete'
    try {
        $current=Microsoft.PowerShell.Management\Get-Item -LiteralPath $ownerPath -Force -ErrorAction Stop
        $marker=Microsoft.PowerShell.Management\Get-Item -LiteralPath $ownerMarker -Force -ErrorAction Stop
        if([IO.Path]::GetFullPath($current.FullName) -cne $ownerPath -or -not $current.PSIsContainer -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $marker.PSIsContainer -or ($marker.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $marker.Length -ne 32 -or [IO.File]::ReadAllText($ownerMarker) -cne $ownerToken){throw 'Changed DNS fixture root retained'}
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $ownerPath -Recurse -Force -ErrorAction Stop
        $script:contractOutcome=$bodyOutcome;$script:contractCode=$bodyCode
    } finally {
        if($ReportPath){
            $parent=Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop
            if($parent.FullName -cne $reportParent.FullName -or $parent.CreationTimeUtc.Ticks -ne $reportCreated -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed contract report parent retained'}
            $commit=[string]$env:GITHUB_SHA
            if($commit -and $commit -notmatch '^[0-9a-f]{40}$'){throw 'Contract source identity is invalid'}
            if($PSVersionTable.PSEdition -notin @('Core','Desktop') -or $script:contractCode -notin $script:closedContractCodes){throw 'Contract output metadata is invalid'}
            $report=@{schemaVersion=1;sourceCommit=$commit;workflowSHA256=$sourceHash.ToLowerInvariant();fixtureSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();outcome=$script:contractOutcome;code=$script:contractCode;checks=$script:checks;realDnsChanged=$false;nativeDnsQualified=$false}
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes((Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $report -Compress))
            if($bytes.Length -gt 4096){throw 'Contract output exceeds fixed metadata limit'}
            $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
        }
    }
}
