# Selected-function contracts and embedded type compilation use synthetic records.
# All DNS, registry, service, network and installation effects remain mocked.
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
# Compile the exact embedded probe and exercise only synthetic unmanaged records.
# The DNS entry point is never called by this fixture.
& {
    $function=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-OrdinaryDNSAddress'},$true)
    $csharp=$function.Find({param($node)$node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.StringConstantType -eq 'SingleQuotedHereString'},$true)
    if(-not $csharp){throw 'DNS source type missing'}
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $csharp.Value -ErrorAction Stop
    $flags=[Reflection.BindingFlags]'Static,NonPublic'
    if([AccessWeaver.DNSHealth].GetField('QueryOptions',$flags).GetRawConstantValue() -ne 0x19c8 -or
        [AccessWeaver.DNSHealth].GetField('QueryName',$flags).GetRawConstantValue() -cne 'example.com'){
        throw 'Unexpected DNS query policy'
    }
    $marshal=[Runtime.InteropServices.Marshal]
    $ptrSize=[IntPtr]::Size
    $headerSize=2*$ptrSize+16
    $method=[AccessWeaver.DNSHealth].GetMethod('HasAddress',[Reflection.BindingFlags]'Static,NonPublic')
    $checks=[Collections.Generic.List[int]]::new()
    function Assert-Record([string]$Name,[int16]$Type,[int16]$Length,[int]$Section,[string]$Address,[int16]$Requested,[bool]$Expected,[switch]$Loop) {
        $row=$marshal::AllocHGlobal($headerSize+16)
        $namePointer=$marshal::StringToHGlobalUni($Name)
        try {
            $marshal::Copy([byte[]]::new($headerSize+16),0,$row,$headerSize+16)
            if($Loop){$marshal::WriteIntPtr($row,0,$row)}
            $marshal::WriteIntPtr($row,$ptrSize,$namePointer)
            $marshal::WriteInt16($row,2*$ptrSize,$Type)
            $marshal::WriteInt16($row,2*$ptrSize+2,$Length)
            $marshal::WriteInt32($row,2*$ptrSize+4,$Section)
            $bytes=[Net.IPAddress]::Parse($Address).GetAddressBytes()
            $marshal::Copy($bytes,0,[IntPtr]::Add($row,$headerSize),$bytes.Length)
            [uint16]$requestedType=$Requested
            if($method.Invoke($null,@($row,$requestedType)) -ne $Expected){throw 'Unexpected DNS record assessment'}
            $checks.Add(1)
        } finally {
            $marshal::FreeHGlobal($row)
            $marshal::FreeHGlobal($namePointer)
        }
    }
    Assert-Record 'EXAMPLE.COM.' 1 4 1 '192.0.2.25' 1 $true
    Assert-Record 'example.com' 28 16 1 '2001:db8::25' 28 $true
    Assert-Record 'example.org' 28 16 1 '2001:db8::25' 28 $false
    Assert-Record 'example.com' 28 16 2 '2001:db8::25' 28 $false
    Assert-Record 'example.com' 28 16 1 '::ffff:192.0.2.25' 28 $false
    Assert-Record 'example.com' 28 4 1 '2001:db8::25' 28 $false
    Assert-Record 'example.com' 1 4 1 '192.0.2.25' 28 $false
    Assert-Record 'example.com' 1 4 1 '192.0.2.25' 1 $false -Loop
    if($checks.Count -ne 8){throw "Incomplete synthetic verification"}
    Write-Output "Compiled $($PSVersionTable.PSEdition). Verified $($checks.Count) synthetic DNS records"
}
$selected=@('Assert-DNSCryptConfiguration','Get-DNSCryptReloadFile','Restore-DNSCryptAfterActivationFailure','Assert-DNSCryptServiceState','Read-ManagedServiceCommand','Read-ManagedServiceRegistration','Get-ManagedServiceCommandDigest','Assert-DNSMutationAdapter','Test-DNSRecoveryUsesAdapterOwnership','Test-DNSFamilyMatchesOriginal','Read-ObservedDNSFamily','Test-DNSFamilyNeedsRollback','Get-ActiveDNSAdapters','Assert-ConfiguredDNSDohPolicy','Get-DNSDohProviders','Test-DNSRecoveryUsesDohOwnership','Get-DNSOriginalDohEntry','Test-DNSDohEntriesEqual','Test-DNSRecoveryOwnsDoh','Get-DNSClientMutationRow','Read-DNSRecoveryFileBytes','Read-DNSRecoverySnapshot','Assert-DNSRecoverySnapshotUnchanged','Get-WorkflowRecoveryJournalLimit','Read-WorkflowRecoveryJournalBytes','Throw-WorkflowRecoveryJournalReadFailure','Get-WorkflowBytesSHA256','Confirm-DNSRecoverySnapshot','Get-DNSRecoverySnapshotDigest','Assert-ConfiguredDNSServers','Assert-RestoredDNSFamily','Assert-RestoredDNSState','Get-StaticDNSServers','Get-DNSClientFamily','Read-DNSClientInventory','Get-DNSClientRows','Get-OriginalDNSBounds','Assert-OriginalDNSModes','Read-OriginalDNSFamily','Read-OriginalDNSAdapter','Read-OriginalDNSNameServer','Get-DNSOverridePath','Read-DNSStaticOverride','Test-DNSAddressAnswer','Wait-OrdinaryDNSResolver','Wait-DNSCryptListeners','Get-ManagedDNSCryptListenerOwner','Wait-ManagedDNSCryptListeners','Get-EffectiveDNSCryptListeners','Assert-EffectiveDNSCryptListeners','Get-DNSCryptAdapterIdentities','Test-DNSCryptLoopbackAddress','Get-DNSCryptIndependentFamilies','Test-DNSCryptListenerNeeded','Assert-DNSCryptCanBeRemoved','Configure-DNS','Restore-DNS','Remove-Method','Remove-All')
$allowed=@('Read-OwnedWireSockProfile','Remove-WireSockRefreshTask','Disconnect-OwnedWireSock','Native','Remove-ModernWireSockProfile','Restore-Drover','Get-ManagedFirewallRule','Remove-RecordedService','Remove-ManagedFirewallRule','Remove-Method','Under','Assert-DNSCryptConfiguration','Get-WorkflowFileHash','Get-DNSCryptReloadFile','Restore-DNSCryptAfterActivationFailure','Assert-DNSCryptServiceState','Read-ManagedServiceCommand','Read-ManagedServiceRegistration','Get-ManagedServiceCommandDigest','Get-CimInstance','Get-NetTCPConnection','Get-NetUDPEndpoint','Assert-DNSMutationAdapter','Test-DNSRecoveryUsesAdapterOwnership','Test-DNSFamilyMatchesOriginal','Read-ObservedDNSFamily','Test-DNSFamilyNeedsRollback','Get-ActiveDNSAdapters','Assert-ConfiguredDNSDohPolicy','Get-DNSDohProviders','Test-DNSRecoveryUsesDohOwnership','Get-DNSOriginalDohEntry','Test-DNSDohEntriesEqual','Test-DNSRecoveryOwnsDoh','Get-DNSClientMutationRow','Read-DNSRecoveryFileBytes','Read-DNSRecoverySnapshot','Assert-DNSRecoverySnapshotUnchanged','Get-WorkflowRecoveryJournalLimit','Read-WorkflowRecoveryJournalBytes','Throw-WorkflowRecoveryJournalReadFailure','Get-WorkflowBytesSHA256','Confirm-DNSRecoverySnapshot','Get-DNSRecoverySnapshotDigest','Save-DNSRecoveryReceipt','Publish-WorkflowFile','No-Reparse','Get-Item','Assert-ConfiguredDNSServers','Assert-RestoredDNSFamily','Assert-RestoredDNSState','Get-StaticDNSServers','Get-DNSClientFamily','Read-DNSClientInventory','Get-DNSClientRows','Get-OriginalDNSBounds','Assert-OriginalDNSModes','Read-OriginalDNSFamily','Read-OriginalDNSAdapter','Read-OriginalDNSNameServer','Get-DNSOverridePath','Read-DNSStaticOverride','Test-DNSAddressAnswer','Wait-OrdinaryDNSResolver','Wait-DNSCryptListeners','Get-ManagedDNSCryptListenerOwner','Wait-ManagedDNSCryptListeners','Get-EffectiveDNSCryptListeners','Assert-EffectiveDNSCryptListeners','Get-DNSCryptAdapterIdentities','Test-DNSCryptLoopbackAddress','Get-DNSCryptIndependentFamilies','Test-DNSCryptListenerNeeded','Assert-DNSCryptCanBeRemoved','Restore-DNS','Get-ItemProperty','Get-Command','Join-Path','Get-NetAdapter','Where-Object','ForEach-Object','Select-Object','Test-Path','Get-DnsClientServerAddress','Get-DnsClientDohServerAddress','Get-FileHash','Add-Member','ConvertTo-Json','Save-Journal','Ensure-Asset','Split-Path','Assert-ManagedServiceOwnership','Assert-RecordedServiceBinding','Get-Service','Restore-RecordedWorkflowFile','Install-EngineService','Set-Service','Start-Service','Restart-Service','Stop-Service','Set-DnsClientDohServerAddress','Add-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress','Set-DnsClientServerAddress','Clear-DnsClientCache','Resolve-DnsName','Start-Sleep','Event','ConvertFrom-Json','Remove-Item','Remove-VerifiedDNSRecoverySnapshot')
$selected+=@('Set-RestoredDNSFamily','Wait-RecordedServiceStopped','Assert-DNSCryptLoopbackPortsAvailable','Assert-DNSCryptListenerUnchanged')
$allowed+=@('Assert-DNSCryptLoopbackPortsAvailable','Assert-DNSCryptListenerUnchanged','Get-DNSCryptConnectionSharingIdentity','Test-DNSCryptExclusiveUDPBind','Get-DNSCryptSharingProbe','Assert-DNSCryptSharingProbe')
$selected+=@('Get-DNSCryptConnectionSharingIdentity','Get-DNSCryptSharingProbe','Assert-DNSCryptSharingProbe')
$allowed+=@('Set-RestoredDNSFamily','Invoke-DNSInterfaceSettings','Test-DNSCryptTransportAnswer','Read-DNSCryptProbeName')
$selected+=@('Read-DNSCryptProbeName','Test-DNSCryptProbeReply')
$dohFirewallFunctions=@('Get-DNSDohPlaintextBlockID','Assert-DNSDohFirewallAvailable','Read-DNSDohPlaintextRules','Get-DNSDohPlaintextRule','Assert-DNSDohPlaintextRuleOwnership','Assert-DNSDohPlaintextBlock','Enable-DNSDohPlaintextBlock','Remove-DNSDohPlaintextBlock')
$dnsCopyFunctions=@('ConvertFrom-DNSRecoverySnapshotBytes','Get-DNSRecoveryCopyPath','Read-DNSRecoveryCopy','Assert-DNSRecoveryCopyMatches','Publish-DNSRecoveryCopy')
$retirementFunctions=@('Wait-DNSCryptServiceTransition','New-DNSCryptRetirementRecord','Read-DNSCryptRetirementState','Restore-DNSCryptRetirement','Rollback')
$dohFirewallFunctions+=@('Get-DNSDohFirewallProfileBits','Get-DNSDohPlaintextRuleName','Assert-DNSDohEffectiveStatus')
$allowed+='Test-OrdinaryDNSAddress'
$selected+=$dohFirewallFunctions+$dnsCopyFunctions+$retirementFunctions
$allowed+='Get-DNSDohActiveProfileMask'
$allowed+=$retirementFunctions+@('Backup-File','Confirm-DNSRecoveryEntry','Select-Object','Remove-WireSockRefreshTask','Move-Item')
$allowed+=$dohFirewallFunctions+$dnsCopyFunctions+@('Get-NetFirewallProfile','Get-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Get-NetFirewallServiceFilter','Get-NetFirewallApplicationFilter','Get-NetFirewallInterfaceFilter','Get-NetFirewallInterfaceTypeFilter','Get-NetFirewallSecurityFilter','New-NetFirewallRule','Remove-NetFirewallRule')
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
$script:closedContractCodes=@('recorded-service-wait-uses-service-provider','doh-retirement-rechecks-firewall-before-effects','doh-retirement-firewall-loss-recovers','dnscrypt-retirement-transition-recovers','dnscrypt-retirement-transition-drift-refused','dnscrypt-service-transition-timeout','dnscrypt-reload-durable-before-publication','dnscrypt-reload-recovers-pending-publication','dnscrypt-reload-invalid-pending-hash','dnscrypt-reload-preflight-preserves-original','doh-preserves-listener-needed-during-probe','explicit-restore-refuses-concurrent-adapter-dns','dnscrypt-reload-retains-snapshot-until-listener-recovers','doh-restarts-listener-for-post-stop-dependency','doh-verifies-after-stopping-dnscrypt','configured-dns-rejects-client-drift-during-registry-read','configured-dns-rejects-topology-drift-during-registry-read','doh-reapply-verifies-without-redundant-setters','doh-keeps-listener-for-adapter-identity-drift','doh-keeps-listener-for-owned-inactive-adapter','doh-stops-listener-after-last-adapter-switch','doh-keeps-listener-for-excluded-adapter','dnscrypt-loopback-mapped-ipv4','dnscrypt-dependency-change-stable-adapter','doh-keeps-listener-for-stored-unexposed-family','doh-retires-listener-with-confirmed-absent-unexposed-key','doh-keeps-listener-for-original-static-dns','stored-dns-mismatch-before-effects','stored-dns-restore-retains-snapshot','configure-refuses-drift-during-resolver-query','configure-ignores-unselected-adapter-during-resolver-query','configure-doh-preserves-independent-policy','restore-doh-refuses-unowned-policy','restore-doh-resumes-partial-configuration','restore-doh-conditional-needs-capability','restore-doh-rejects-invalid-ownership','configure-doh-refuses-stale-reconfiguration','restore-doh-refuses-concurrent-policy','restore-doh-keeps-independent-policy','doh-only-recovery-records-effects','doh-noop-recovery-has-no-effects','rollback-keeps-independent-adapter-settings','rollback-skips-restored-adapter-family','restore-doh-repairs-stable-malformed-policy','configure-dnscrypt-loopback-readback','doh-keeps-old-resolver-until-verified','dns-service-ownership-before-effects','dns-service-binding-before-mutation','dnscrypt-preserves-independent-doh','first-doh-captures-global-policy','dnscrypt-keeps-existing-doh-originals','invalid-doh-recovery-scope','dnscrypt-restarts-verified-service','dnscrypt-recovers-original-after-stopped-activation-failure','dnscrypt-reuses-unchanged-configuration','dnscrypt-listeners-before-adapters','dnscrypt-listener-rechecks-both-families','dnscrypt-managed-listener-owner','dnscrypt-refuses-unowned-dns-before-adapter-switch','dnscrypt-restores-when-listener-owner-changes','dnscrypt-listener-refusal-preserves-adapter-state','dnscrypt-listener-refuses-invalid-answers','dnscrypt-listener-refuses-invalid-aaaa','dnscrypt-listener-refuses-missing-aaaa-before-adapters','dnscrypt-listener-retries-missing-aaaa','dnscrypt-verifies-all-listeners-after-adapter-switch','dnscrypt-recovers-after-late-listener-failure','ordinary-resolver-requires-address-answer','ordinary-resolver-retries-missing-aaaa','ordinary-resolver-rejects-invalid-aaaa','configure-restores-when-aaaa-is-missing','configure-adapter-readback-refuses','configure-adapter-readback-retains','configure-adapter-readback-retries','configure-adapter-readback-recovers','configure-post-policy-refuses','configure-post-policy-recovers','configure-policy-readback-before-adapters','configure-policy-refusal-retains-recovery','configure-policy-recovery-completes','configure-policy-query-before-verification','scope-capture-flat-ordered','scope-rebinds-current-adapter','scope-family-extension','scope-invalid-before-effects','scope-dhcp-reset-preserved','scope-global-and-ipv4-preserved','changed-adapter-retains-before-interface-read','capture-index-change-before-snapshot','capture-drift-before-snapshot','capture-drift-before-adapter-write','reconfigure-preserves-independent-adapter-dns','non-dns-adapter-not-targeted','single-family-capture-and-restore','new-family-originals-extended','family-extension-before-effects','client-inventory-before-effects','family-flags-preflight','owned-family-missing-retained','invalid-recovery-identities-before-inspection','restore-uses-refreshed-guid-index','changed-adapter-retains-before-dns-read','case-insensitive-down-adapter-restoration','reconfiguration-rotates-recovery-identity','existing-originals-never-recaptured','new-adapter-originals-persisted','extended-snapshot-restores-both-adapters','extension-failure-before-effects','invalid-configuration-preflight','configuration-uses-current-guid-index','source-uncovered-dns-write','absent','absent-entry-idempotence-and-unrelated-preservation','accessweaver-dns-contracts-','add','all-providers-no-plaintext-fallback','ambiguous-adapter','bad-doh','bad-flags','capture-inspection-failure-not-empty','case','confirmed-absent-entry-not-removed-again','confirmed-absent-mode-is-dhcp','current-doh-query-before-effects','dns','doh','duplicate-doh','empty-adapters','empty-static','exact-original-doh-restored','expected-refusal','false','fixture-cleanup-incomplete','guid-recovery-uses-current-index','invalid-recovery-preflight','legacy-no-doh-recovery-supported','malformed-mode-not-empty','missing-adapter','no-false-restored-event','none','original-snapshot-retained','partial-removal-retains-needed-recovery','profiles','recovery-retry-completes-after-confirmed-inspection','registry-error-not-dhcp','remove','snapshot-publication-binds-prior-bytes','snapshot-frame-refused','snapshot-preflight-change-refused','snapshot-journal-digest-refused','configure-interface-reuse-before-setter','restore-interface-reuse-before-setter','restore-retirement-requires-absence','restore-retirement-refuses-replaced-snapshot','restore-retirement-retains-after-state-drift','restore-retirement-retries-after-state-drift','restore-delayed-observation','restore-adapter-row-fence','restore-final-adapter-fence','restore-final-client-readback','restore-inspection-before-effects','saved-doh-needs-capability','set','snapshot-before-native-effects','journal-before-snapshot','snapshot-must-match-journal','activation-before-native-effects','receipt-before-retirement','source-doh-inspection-failed','source-doh-mutation-failed','source-registry-inspection-failed','source-snapshot-removal-failed','source-snapshot-write-failed','true','unexpected-contract-error','unknown-test-code','doh-firewall-refuses-unavailable-service','doh-firewall-owned-protection','doh-firewall-keeps-identity','doh-firewall-preserves-foreign-rule','doh-firewall-recovery-cleans-rules','doh-firewall-refusal-keeps-recovery','doh-firewall-normalizes-host-addresses','dnscrypt-clears-doh-firewall','doh-firewall-preserves-filter-drift','doh-firewall-refuses-incomplete-filters','doh-firewall-unmatched-rule-preserved','doh-firewall-missing-snapshot-preserved','doh-firewall-matched-snapshot-recovers','doh-firewall-active-only-conflict','dns-recovery-copy-before-effects','dns-recovery-copy-bound-write','dns-recovery-copy-bound-delete','dns-recovery-copy-corruption-refused','dns-recovery-copy-retirement-retried','dnscrypt-retirement-journal-before-stop','dnscrypt-retirement-retry-keeps-snapshot','dnscrypt-retirement-retry-restores-service','dnscrypt-retirement-refuses-drift')
$script:closedContractCodes+=@('restore-refuses-legacy-sibling-reset','restore-scopes-automatic-and-static-families','restore-native-refusal-never-falls-back')
$script:closedContractCodes+=@('doh-firewall-full-status-representations','doh-firewall-nonfull-status-refused')
$script:closedContractCodes+=@('doh-firewall-cim-raw-status','doh-firewall-cim-format-not-authority')
$script:closedContractCodes+=@('doh-firewall-missing-store-reason','doh-firewall-diagnostic-does-not-mutate','doh-firewall-known-enforcement-reason','doh-firewall-status-diagnostic-does-not-mutate','doh-firewall-unavailable-or-unsupported-reason','doh-firewall-malformed-diagnostic-does-not-mutate')
$script:closedContractCodes+=@('dnscrypt-port-conflict-before-mutation','dnscrypt-unreadable-port-before-mutation','dnscrypt-port-inventory-observed','dnscrypt-port-drift-before-service','dnscrypt-port-drift-recovers','doh-firewall-loss-before-next-adapter-write','doh-firewall-loss-restores-applied-family')
$script:closedContractCodes+=@('doh-firewall-loss-stops-resolver-probes','doh-probe-firewall-loss-restores-state')
$script:closedContractCodes+=@('dnscrypt-refuses-replaced-listener-during-cutover','dnscrypt-recovers-after-cutover-owner-loss')
$script:closedContractCodes+=@('dnscrypt-udp-compressed-positive','dnscrypt-udp-uncompressed-positive','dnscrypt-udp-rejects-id','dnscrypt-udp-rejects-truncated','dnscrypt-udp-rejects-rcode','dnscrypt-udp-rejects-question-type','dnscrypt-udp-rejects-authority','dnscrypt-udp-rejects-unrelated','dnscrypt-udp-rejects-rdata','dnscrypt-udp-rejects-mapped','dnscrypt-udp-rejects-pointer','dnscrypt-udp-rejects-trailing')
$script:closedContractCodes+=@('dnscrypt-requires-both-transports-on-each-loopback','dnscrypt-tcp-cannot-mask-udp-failure','dnscrypt-recovery-retains-a-only-probe','dnscrypt-udp-failure-blocks-adapter-mutation')
$script:closedContractCodes+=@('doh-firewall-covers-concurrent-active-profiles','doh-firewall-refuses-profile-transitions','doh-firewall-recovers-legacy-pair','doh-firewall-migrates-legacy-pair-without-dropping-protection')
$script:closedContractCodes+=@('dnscrypt-sharing-admits-only-verified-service','dnscrypt-sharing-renewal-stops-setup','dnscrypt-sharing-binds-owned-challenge','dnscrypt-sharing-challenge-failure-blocks-adapter-writes','dnscrypt-sharing-challenge-recovery','dnscrypt-sharing-reuses-owned-challenge','dnscrypt-sharing-challenge-needs-exact-answer')
function Assert-DNS([bool]$Condition,[string]$Code){if(-not $Condition){$script:contractCode=if($Code -in $script:closedContractCodes){$Code}else{'unknown-test-code'};throw ('DNS contract failed: '+$script:contractCode)};$script:checks++}
function Reject-DNS([scriptblock]$Operation,[string]$ExpectedMessage){
    $failed=$false
    try{& $Operation | Out-Null}catch{$failed=-not $ExpectedMessage -or $_.Exception.Message.StartsWith($ExpectedMessage,[StringComparison]::Ordinal)}
    Assert-DNS $failed 'expected-refusal'
}
function New-DNSCase([switch]$ExistingResolver) {
    $script:caseNumber++
    $script:root=[IO.Path]::Combine($ownerPath,('case'+$script:caseNumber))
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($root,'profiles'))
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'components\dnscrypt'))
    $script:snapshot=Join-Path $root 'profiles/dns-original.json'
    $script:copyPath=Get-DNSRecoveryCopyPath
    $script:DNSCryptPortRows=@{}
    $script:DNSCryptPortReads=[Collections.Generic.List[string]]::new()
    $script:failDNSCryptPortRead=$false;$script:portConflictOnStaging=$false
    $script:sharingMode='';$script:sharingBindFailure='';$script:sharingQueries=0
    $script:sharingBinds=[Collections.Generic.List[string]]::new()
    $script:sharingProbePath=$null;$script:sharingProbeReads=0;$script:sharingChallengeFailure=$false
    $script:failCopyPublication=$false;$script:failCopyRetirement=$false
    $script:dohFirewallRules=@{};$script:dohFirewallWrites=0;$script:dohFirewallFault=''
    $script:dohFirewallActiveMask=4;$script:dohFirewallMaskReads=0
    $script:firewallOnRetirementJournal='';$script:firewallAfterAdapterWrite='';$script:firewallAfterAProbe=''
    $script:present=@{'Get-DnsClientDohServerAddress'=$true;'Set-DnsClientDohServerAddress'=$true;'Add-DnsClientDohServerAddress'=$true;'Remove-DnsClientDohServerAddress'=$true}
    $script:adapters=@([pscustomobject]@{Status='Up';InterfaceDescription='Fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000001}';ifIndex=77})
    $script:mode4='192.0.2.53';$script:mode6='absent';$script:registryFailure='';$script:emptyDnsRead=$false;$script:failDohRead=0;$script:dohReads=0
    $script:storedDNS=@{};$script:storedDNSFault='';$script:captureDrift=''
    $script:exposure=@{};$script:renumberAfterInventory=$false;$script:inventoryFailure=$false;$script:duplicateInventory=$false;$script:numericFamilies=$false
    $script:appliedDNS=@{};$script:readbackFault='';$script:readbackFaultArmed=$false;$script:silentDohFault='';$script:registryReads=[Collections.Generic.List[string]]::new();$script:dnsValues=@{};$script:renumberDuringDoh=$false;$script:reuseIndexDuringDoh=$false;$script:disappearDuringDoh=$false;$script:dnsReadCount=0;$script:dnsInterfaceReads=0
    $script:replaceSnapshotOnAdapterRead=$false;$script:replaceSnapshotOnJournalSave=$false
    $script:hiddenInventoryReads=0;$script:hiddenInventoryDrift='';$script:lateLoopbackDNS='';$script:finalDependencyDrift='';$script:unexposedKeyStates=@{}
    $script:replaceSnapshotOnReceiptSave=$false;$script:dnsDriftOnReceiptSave='';$script:failRestoreAdapterAfterResolverQuery=$false
    $script:replaceSnapshotOnActivation=$false;$script:replaceSnapshotOnInterfaceRead=0
    $script:failAction='';$script:failAddress='';$script:failDelete=$false;$script:failSnapshotWrite=$false;$script:failJournalWrite=$false;$script:corruptSnapshotWrite=$false;$script:failActivationWrite=$false;$script:failReceiptWrite=$false
    $script:configureDohReadFault='';$script:postConfigureDohReadFault='';$script:configureDohFaultAddress='';$script:resolverQueries=0;$script:configurationLag=0;$script:readbackWaits=0
    $script:resolverServicePresent=$false;$script:resolverOwnershipFault=$false;$script:resolverBindingFailureRead=0;$script:resolverBindingReads=0;$script:serviceRestarts=0;$script:dnscryptConfigReads=0;$script:dnscryptConfigWrites=0;$script:stageDNSCrypt=$false;$script:changeDNSCryptBeforePublish=$false;$script:changeDNSCryptAfter='';$script:failDNSCryptRestart=$false;$script:allowNewResolver=$false;$script:newResolverRegistered=$false;$script:serviceStops=0;$script:serviceStartupChanges=0;$script:loopbackAfterServiceStop=$false
    $script:resolverReadbacks=0;$script:resolverReadbackFault='';$script:expectedResolverStartup='';$script:failResolverStartupWrite=$false
    $script:resolverStopped=$false;$script:serviceStarts=0
    $script:serviceTransition=[Collections.Generic.Queue[string]]::new()
    $script:serviceTransitionRefreshes=0;$script:serviceTransitionFault=''
    $script:configPublicationInterruption='';$script:configPublicationJournal=$null;$script:failReloadJournal=$false
    $script:restartRecoveryOriginal=$null;$script:restartRecoveryWrites=0;$script:restartRecoveryFault='';$script:restartListenerFailure=$false;$script:failChangedConfigStart=$false
    $script:resolverCommand='synthetic DNSCrypt service command'
    $script:resolverDigest=Get-ManagedServiceCommandDigest $script:resolverCommand
    $script:listenerQueries=[Collections.Generic.List[string]]::new()
    $script:finalListenerQueries=[Collections.Generic.List[string]]::new();$script:finalListenerFailure=''
    $script:listenerAAAAQueries=[Collections.Generic.List[string]]::new()
    $script:finalListenerAAAAQueries=[Collections.Generic.List[string]]::new()
    $script:listenerAAAAFault='';$script:listenerAAAAFaultServer='::1'
    $script:listenerUDPFault='';$script:listenerTransports=[Collections.Generic.List[string]]::new()
    $script:finalListenerMissingAAAA=''
    $script:listenerOwnerFault='';$script:initialOwnerReads=0;$script:finalOwnerReads=0
    $script:ordinaryResolverWaits=0;$script:emptyOrdinaryAnswers=0;$script:resolverDrift='';$script:postRetirementFault='';$script:postRetirementQueries=0
    $script:resolverAAAAQueries=0;$script:emptyOrdinaryAAAAAnswers=0;$script:ordinaryAAAAFault=''
    $script:listenerReplies=@{};$script:listenerChecksBeforeAdapters=$true;$script:listenerWaits=0;$script:refuseListenerWait=$false
    $script:dnsRowFault='';$script:explicitRestoreDrift='';$script:unverifiedDNSWrites=0;$script:failDNSSetterFamily=''
    $script:dnsInterfaceSettingsMode='available';$script:dnsInterfaceSettingsCalls=[Collections.Generic.List[object]]::new()
    $script:scopedDNSSetter=$false;$script:legacyDNSResetChangesSibling=$false
    $script:recoveryLag=0;$script:renumberDuringRecoveryRead=$false;$script:adapterDriftDuringFinalDohRead='';$script:clientDriftDuringReceiptReadback='';$script:reuseBeforeDNSSetter=$false;$script:reuseOnFinalRegistryRead=$false;$script:configuredRegistryTopologyDrift='';$script:configuredClientDrift='';$script:silentSnapshotRemoval=$false
    $script:changeDohAfterAdapterWrite='';$script:changeDohAfterProviderWrite=$false
    $script:changeDohOnActivation='';$script:changeDNSOnActivation=''
    $script:externalEffectsPending=$false
    $script:currentDoh=@{};$script:calls=[Collections.Generic.List[object]]::new();$script:events=[Collections.Generic.List[string]]::new()
    $script:undo=[Collections.Generic.List[object]]::new();$script:dnsConfigured=$false;$script:journals=0;$script:journalDigest=$null;$script:journalActive=$false;$script:receiptDigest=$null
    $script:cacheFlushFault='';$script:cacheFlushes=0
    $script:savedRetirement=$null;$script:failRetirementJournal=$false;$script:retirementRecovery=$false
    if($ExistingResolver){
        [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),"listen_addresses = ['127.0.0.1:53']")
        $script:resolverServicePresent=$true
    }
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
function Get-DNSDohActiveProfileMask {
    $script:dohFirewallMaskReads++
    if($script:dohFirewallFault -ceq 'profile-changed' -and $script:dohFirewallMaskReads -gt 1){return 2}
    return $script:dohFirewallActiveMask
}
function Get-NetFirewallProfile {
    [CmdletBinding()]param($PolicyStore)
    if($PolicyStore -cne 'ActiveStore'){throw 'Unexpected firewall profile inspection'}
    foreach($profile in @('Domain','Private','Public')){
        [pscustomobject]@{Name=$profile;Enabled=($script:dohFirewallFault -ne 'disabled');AllowLocalFirewallRules='NotConfigured';DisabledInterfaceAliases=@('NotConfigured')}
    }
}
function Get-NetFirewallRule {
    [CmdletBinding()]param($PolicyStore,[switch]$TracePolicyStore)
    if($PolicyStore -cnotin @('ActiveStore','PersistentStore') -or [bool]$TracePolicyStore -ne ($PolicyStore -ceq 'ActiveStore')){
        throw 'Unexpected firewall rule inspection'
    }
    foreach($rule in $script:dohFirewallRules.Values){
        $copy=$rule.Clone()
        $copy.fixtureStore=$PolicyStore
        if($script:dohFirewallFault -ceq ('missing-TCP-'+$PolicyStore) -and $copy.Name.Contains('-TCP-')){continue}
        if($script:dohFirewallFault -ceq ('missing-UDP-'+$PolicyStore) -and $copy.Name.Contains('-UDP-')){continue}
        if($PolicyStore -ceq 'ActiveStore'){
            $profileBit=if($copy.Profile -cin @('Domain','Private','Public')){(Get-DNSDohFirewallProfileBits)[$copy.Profile]}else{0}
            $expectedActive=($copy.Profile -ceq 'Any') -or (($script:dohFirewallActiveMask -band $profileBit) -ne 0)
            $copy.EnforcementStatus=if($expectedActive){'Full'}else{'InactiveProfile'}
            if($expectedActive -and $script:dohFirewallFault -ceq 'inactive'){$copy.EnforcementStatus='LocalFirewallRulesDisallowed'}
            if($expectedActive -and $script:dohFirewallFault -ceq 'enforcement-shape'){$copy.EnforcementStatus=$script:dohFirewallEnforcement}
            if($copy.Profile -ceq 'Private' -and $script:dohFirewallFault -ceq 'inactive-profile-drift'){$copy.EnforcementStatus='Full'}
            if($script:dohFirewallFault -ceq 'narrow-effective'){$copy.InterfaceAlias='Fixture adapter'}
        }
        $copy
    }
}
function New-NetFirewallRule {
    [CmdletBinding()]param($Name,$DisplayName,$Description,$PolicyStore,$Direction,$Action,$Enabled,$Profile,$Protocol,$RemotePort,$RemoteAddress,$Service)
    $saved=Read-DNSRecoverySnapshot
    $id=$saved.record.dohPlaintextBlockID
    if(-not $id -or $Name -cne ('AccessWeaver-DoH-Plaintext-'+$Protocol+'-'+$id+'-'+$Profile) -or
        $Protocol -cnotin @('TCP','UDP') -or $Profile -cnotin @('Domain','Private','Public') -or
        $PolicyStore -cne 'PersistentStore' -or $Service -cne 'Dnscache' -or $script:dohFirewallRules.ContainsKey($Name)){
        throw 'Unexpected firewall rule creation or missing recovery ownership'
    }
    if($script:dohFirewallFault -ceq 'second-write' -and $Protocol -ceq 'UDP'){throw 'Synthetic second DoH rule creation failure'}
    $script:dohFirewallRules[$Name]=@{Name=$Name;Description=$Description;Direction=$Direction;Action=$Action;Enabled=$Enabled;
        Profile=$Profile;Protocol=$Protocol;RemotePort=$RemotePort;RemoteAddress=$RemoteAddress;Service=$Service;Program='Any';
        EnforcementStatus='Full';PolicyStoreSourceType='Local';LooseSourceMapping=$false;LocalOnlyMapping=$false;
        RemoteDynamicKeywordAddresses=$null;DynamicTarget='Any';InterfaceAlias='Any';InterfaceType='Any';
        Authentication='NotRequired';Encryption='NotRequired';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'}
    $script:dohFirewallWrites++
}
function Assert-FixtureFirewallFilterStore($Rule,[string]$Store) {
    if(-not $Rule -or $Rule.fixtureStore -cne $Store){throw 'Firewall filter query did not retain its policy store'}
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
    $rule=$AssociatedNetFirewallRule
    Assert-FixtureFirewallFilterStore $rule $PolicyStore
    [pscustomobject]@{Protocol=$rule.Protocol;RemotePort=$rule.RemotePort;LocalPort='Any';DynamicTarget=$rule.DynamicTarget}
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
    Assert-FixtureFirewallFilterStore $AssociatedNetFirewallRule $PolicyStore
    [pscustomobject]@{RemoteAddress=$AssociatedNetFirewallRule.RemoteAddress;LocalAddress='Any'}
}
function Get-NetFirewallServiceFilter {
    [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
    Assert-FixtureFirewallFilterStore $AssociatedNetFirewallRule $PolicyStore
    [pscustomobject]@{Service=$AssociatedNetFirewallRule.Service}
}
function Get-NetFirewallApplicationFilter {
    [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
    Assert-FixtureFirewallFilterStore $AssociatedNetFirewallRule $PolicyStore
    [pscustomobject]@{Program=$AssociatedNetFirewallRule.Program;Package=$null}
}
function Get-NetFirewallInterfaceFilter {
    [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
    Assert-FixtureFirewallFilterStore $AssociatedNetFirewallRule $PolicyStore
    [pscustomobject]@{InterfaceAlias=$AssociatedNetFirewallRule.InterfaceAlias}
}
function Get-NetFirewallInterfaceTypeFilter {
    [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
    Assert-FixtureFirewallFilterStore $AssociatedNetFirewallRule $PolicyStore
    [pscustomobject]@{InterfaceType=$AssociatedNetFirewallRule.InterfaceType}
}
function Get-NetFirewallSecurityFilter {
    [CmdletBinding()]param($AssociatedNetFirewallRule,$PolicyStore)
    $rule=$AssociatedNetFirewallRule
    Assert-FixtureFirewallFilterStore $rule $PolicyStore
    if($script:dohFirewallFault -ceq 'filter-warning'){Write-Warning 'Synthetic incomplete security filter read'}
    [pscustomobject]@{Authentication=$rule.Authentication;Encryption=$rule.Encryption;OverrideBlockRules=$false;
        LocalUser=$rule.LocalUser;RemoteUser=$rule.RemoteUser;RemoteMachine=$rule.RemoteMachine}
}
function Remove-NetFirewallRule {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule)
    process {
        if(-not $script:dohFirewallRules.ContainsKey($Rule.Name)){throw 'Unexpected firewall rule removal'}
        $script:dohFirewallRules.Remove($Rule.Name)
    }
}
function Get-NetAdapter {
    [CmdletBinding()]param([switch]$IncludeHidden)
    if($script:replaceSnapshotOnAdapterRead){
        $script:replaceSnapshotOnAdapterRead=$false
        [IO.File]::AppendAllText($snapshot,' ')
    }
    if($IncludeHidden){
        $script:hiddenInventoryReads++
        if($script:hiddenInventoryReads -eq 2){
            if($script:lateLoopbackDNS -ceq 'effective'){$script:dnsValues['88/IPv6']=@('::1')}
            if($script:lateLoopbackDNS -ceq 'stored'){$script:storedDNS[([string]$script:adapters[1].InterfaceGuid)+'/IPv6']='::1'}
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
    $guid=$LiteralPath.Substring($LiteralPath.LastIndexOf('\')+1)
    $matching=@($script:adapters | Where-Object {$_.InterfaceGuid -eq $guid})
    if($matching.Count -eq 1){
        $key=([string]$matching[0].ifIndex)+'/'+$family
        $exposed=-not $script:exposure.ContainsKey($key) -or $script:exposure[$key]
        if($script:hiddenInventoryReads -eq 2 -and $key -ceq '88/IPv6'){
            switch($script:finalDependencyDrift){
                'loopback' {$script:dnsValues[$key]=@('::1')}
                'new-family' {$script:exposure[$key]=$true}
            }
        }
        if(-not $exposed){
            switch($script:unexposedKeyStates[$key]){
                'missing' {throw [Management.Automation.ItemNotFoundException]::new('Inert absent registry key')}
                'present' {}
                default {throw 'source-unexposed-registry-read'}
            }
        }
    }
    if($script:registryFailure -eq $family){Write-Error 'source-registry-inspection-failed';return}
    $stateKey=$guid+'/'+$family
    if($family -ceq 'IPv6' -and $script:configuredRegistryTopologyDrift){
        if($script:configuredRegistryTopologyDrift -ceq 'replace'){
            $script:adapters[0].InterfaceGuid='{00000000-0000-0000-0000-000000000003}'
        }else{
            $script:adapters+=@([pscustomobject]@{
                Status='Disconnected';InterfaceDescription='Replacement fixture adapter'
                InterfaceGuid='{00000000-0000-0000-0000-000000000003}';ifIndex=$script:adapters[0].ifIndex
            })
        }
        $script:configuredRegistryTopologyDrift=''
    }
    if($script:reuseOnFinalRegistryRead -and $script:dnsInterfaceReads -eq 1){
        $script:reuseOnFinalRegistryRead=$false
        $script:adapters[0].ifIndex=101
        $script:adapters+=@([pscustomobject]@{
            Status='Up';InterfaceDescription='Replacement fixture adapter'
            InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=77
        })
    }
    $driftFamily=if($script:configuredClientDrift -ceq 'family-added'){'IPv4'}else{'IPv6'}
    if($script:configuredClientDrift -and $family -ceq $driftFamily){
        switch($script:configuredClientDrift){
            'family-added' {$script:exposure['77/IPv6']=$true}
            'family-removed' {$script:exposure['77/IPv6']=$false}
            'adapter-gains-dns' {$script:exposure['88/IPv4']=$true}
            'server-order' {$script:appliedDNS[$guid+'/IPv4'].values=@('9.9.9.9','8.8.8.8')}
        }
        $script:configuredClientDrift=''
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
            if($null -ne $InterfaceIndex -and $script:explicitRestoreDrift -and $family -ceq 'IPv4'){
                $applied=switch($script:explicitRestoreDrift){
                    'static' {@{dhcp=$false;values=@('198.51.100.53')}}
                    'dhcp' {@{dhcp=$true;values=@('192.0.2.42')}}
                }
                $script:appliedDNS[$stateKey]=$applied
                $script:explicitRestoreDrift=''
            }
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
function Invoke-DNSInterfaceSettings([guid]$Adapter,[bool]$IPv6,[string]$NameServers) {
    $script:dnsInterfaceSettingsCalls.Add(@{adapter=$Adapter;ipv6=$IPv6;servers=$NameServers})
    if($script:dnsInterfaceSettingsMode -ceq 'unavailable'){return $false}
    if($script:dnsInterfaceSettingsMode -ceq 'refused'){throw 'Windows refused the family-scoped DNS update'}
    $target=@($script:adapters | Where-Object {[guid]$_.InterfaceGuid -eq $Adapter})
    if($target.Count -ne 1){throw 'Native fixture setter target is invalid'}
    $row=[pscustomobject]@{InterfaceIndex=$target[0].ifIndex;AddressFamily=$(if($IPv6){23}else{2})}
    $script:scopedDNSSetter=$true
    try {
        if($NameServers -ceq ''){$row | Set-DnsClientServerAddress -ResetServerAddresses}
        else{$row | Set-DnsClientServerAddress -ServerAddresses $NameServers.Split(',')}
    } finally {$script:scopedDNSSetter=$false}
    return $true
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
        if($family -ceq $script:failDNSSetterFamily -or
            ($script:failRestoreAdapterAfterResolverQuery -and $script:resolverQueries -gt 0)){throw 'source-dns-setter-failed'}
        $script:calls.Add(@{kind='dns';index=$index;family=$family;servers=@($ServerAddresses);reset=[bool]$ResetServerAddresses})
        if($script:firewallAfterAdapterWrite){
            $script:dohFirewallFault=$script:firewallAfterAdapterWrite
            $script:firewallAfterAdapterWrite=''
        }
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
        $addresses=if($ResetServerAddresses){@()}else{@($ServerAddresses)}
        $state=@{dhcp=[bool]$ResetServerAddresses;values=@($addresses)}
        if($script:readbackFault -ceq 'wrong-mode' -and $ResetServerAddresses){$state.dhcp=$false;$state.values=@('2001:db8::99')}
        if(-not $ResetServerAddresses){
            if($script:readbackFault -ceq 'wrong-value' -and $state.values.Count -gt 0){$state.values[0]='198.51.100.99'}
            if($script:readbackFault -ceq 'empty-static'){$state.values=@()}
            if($script:readbackFault -ceq 'wrong-order' -and $state.values.Count -gt 1){[array]::Reverse($state.values)}
        }
        $script:appliedDNS[([string]$matches[0].InterfaceGuid)+'/'+$family]=$state
        if($ResetServerAddresses -and $script:legacyDNSResetChangesSibling -and -not $script:scopedDNSSetter){
            $sibling=if($family -ceq 'IPv4'){'IPv6'}else{'IPv4'}
            $script:appliedDNS[([string]$matches[0].InterfaceGuid)+'/'+$sibling]=@{dhcp=$true;values=@()}
        }
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
    $script:dohReads++
    if($script:dohReads -eq 6 -and $script:adapterDriftDuringFinalDohRead){
        if($script:adapterDriftDuringFinalDohRead -ceq 'renumber'){$script:adapters[0].ifIndex=101}
        else{$script:adapters[0].InterfaceGuid='{00000000-0000-0000-0000-000000000003}'}
    }
    if($script:receiptDigest -and $script:clientDriftDuringReceiptReadback){
        $guid=[string]$script:adapters[0].InterfaceGuid
        switch($script:clientDriftDuringReceiptReadback){
            'static-address' {$script:appliedDNS[$guid+'/IPv4'].values=@('198.51.100.99')}
            'static-mode' {$script:appliedDNS[$guid+'/IPv4'].dhcp=$true}
            'missing-row' {$script:exposure['77/IPv6']=$false}
            'dhcp-lease' {$script:appliedDNS[$guid+'/IPv6'].values=@('2001:db8::99')}
        }
    }
    if($script:failDohRead -eq $script:dohReads){Write-Error 'source-doh-inspection-failed';return}
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
    $script:calls.Add(@{kind=$Kind;address=$Address;effectsAtAttempt=$script:externalEffectsPending})
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
    if($script:sharingProbePath -and $Path -ceq $script:sharingProbePath){return}
    if($script:stageDNSCrypt -and $Path -cin @((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),(Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'))){
        $script:dnscryptConfigReads++
        return
    }
    if($script:resolverServicePresent -and $Path -ceq (Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml')){return}
    if($Path -cne $script:copyPath){Assert-DNSFixturePath $Path}
}
function Backup-File([string]$Path){
    if(-not $script:stageDNSCrypt -or $Path -cne (Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml')){
        throw 'Unexpected DNS fixture backup'
    }
    $saved=@($script:undo | Where-Object {$_.kind -ceq 'file' -and $_.path -ceq $Path})
    if($saved.Count -eq 1){return $saved[0]}
    if($saved.Count -or -not [IO.File]::Exists($Path)){throw 'Unexpected DNS fixture backup source'}
    $script:restartRecoveryOriginal=[IO.File]::ReadAllBytes($Path)
    $record=@{kind='file';path=$Path;originalHash=(Get-WorkflowBytesSHA256 $script:restartRecoveryOriginal)}
    $script:undo.Add($record)
    Save-Journal
    return $record
}
function Publish-WorkflowFile([string]$Path,[byte[]]$Bytes,[string]$BeforeHash,[switch]$Recorded){
    if($Recorded){
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
        $marker=[regex]::Match([IO.Path]::GetFileName($Path),'\Aaccessweaver-loopback-([a-f0-9]{32})\.txt\z')
        if($marker.Success){
            $expected=Join-Path $root ('components\dnscrypt\'+$marker.Value)
            $answer='accessweaver-'+$marker.Groups[1].Value+".invalid 192.0.2.42`n"
            if($Path -cne $expected -or $BeforeHash -or [IO.File]::Exists($Path) -or $answer -cne $text){
                throw 'Unexpected DNSCrypt challenge file publication'
            }
            $script:sharingProbePath=$Path
            $script:undo.Add(@{kind='file';path=$Path;backup='';expectedHash=(Get-WorkflowBytesSHA256 $Bytes)})
            Save-Journal
            [IO.File]::WriteAllBytes($Path,$Bytes)
            return
        }
        if(-not $script:stageDNSCrypt -or $Path -cne (Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml') -or
            $text -cnotmatch '127\.0\.0\.1:53' -or $text -cnotmatch '\[::1\]:53' -or
            -not $PSBoundParameters.ContainsKey('BeforeHash')){throw 'Unexpected DNS fixture write'}
        if($script:changeDNSCryptBeforePublish){[IO.File]::WriteAllText($Path,'independent configuration')}
        $current=if([IO.File]::Exists($Path)){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}else{''}
        if($current -cne $BeforeHash){throw 'Workflow files changed before replacement'}
        if($BeforeHash){
            $record=Backup-File $Path
            $record.pendingHash=Get-WorkflowBytesSHA256 $Bytes
            Save-Journal
            if($script:configPublicationInterruption){
                Assert-DNS ($script:savedReload.Count -eq 1 -and $script:savedReload[0].originalHash -ceq $BeforeHash) 'dnscrypt-reload-durable-before-publication'
                $script:configPublicationJournal=@($script:undo | ForEach-Object {$_.Clone()})
                if($script:configPublicationInterruption -ceq 'replaced'){[IO.File]::WriteAllBytes($Path,$Bytes)}
                throw 'Synthetic DNSCrypt publication interruption'
            }
        }
        [IO.File]::WriteAllBytes($Path,$Bytes)
        if($BeforeHash){
            $record.expectedHash=$record.pendingHash
            $record.Remove('pendingHash')
            Save-Journal
        }
        $script:dnscryptConfigWrites++
        if($script:changeDNSCryptAfter -ceq 'publish'){[IO.File]::Delete($Path)}
        return
    }
    if($Path -ceq $script:copyPath){
        $prior=if([IO.File]::Exists($Path)){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}else{''}
        Assert-DNS ($PSBoundParameters.ContainsKey('BeforeHash') -and $prior -ceq $BeforeHash -and
            (Snapshot-Hash) -ceq [Text.Encoding]::ASCII.GetString($Bytes,0,64)) 'dns-recovery-copy-bound-write'
        if($script:failCopyPublication){throw 'Synthetic recovery copy write failure'}
        [IO.File]::WriteAllBytes($Path,$Bytes)
        return
    }
    Assert-DNSFixturePath $Path
    $current=if([IO.File]::Exists($Path)){Snapshot-Hash}else{''}
    Assert-DNS ($PSBoundParameters.ContainsKey('BeforeHash') -and $current -ceq $BeforeHash) 'snapshot-publication-binds-prior-bytes'
    Assert-DNS ($script:journals -gt 0 -and @($script:undo | Where-Object {$_.kind -ceq 'dns'}).Count -eq 1 -and
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
    switch -CaseSensitive ($script:dnsDriftOnReceiptSave){
        'adapter' {$script:adapters[0].InterfaceGuid='{00000000-0000-0000-0000-000000000003}'}
        'address' {
            $key=([string]$script:adapters[0].InterfaceGuid)+'/IPv4'
            $script:appliedDNS[$key]=@{dhcp=$false;values=@('198.51.100.99')}
        }
        'policy' {
            $changed=Old-DohFixture
            $changed.DohTemplate='https://independent.invalid/dns-query'
            $script:currentDoh[$changed.ServerAddress]=$changed
        }
    }
}
function Remove-Item {throw 'Unexpected path-based removal in DNS recovery contracts'}
function Remove-VerifiedDNSRecoverySnapshot([string]$Path,[string]$ExpectedSHA256,[int]$Maximum=8MB){
    if($Path -ceq $script:copyPath){
        Assert-DNS ($Maximum -eq (8MB+65) -and (Snapshot-Hash) -ceq $script:receiptDigest -and
            (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $ExpectedSHA256) 'dns-recovery-copy-bound-delete'
        if($script:failCopyRetirement){throw 'Synthetic recovery copy retirement failure'}
        [IO.File]::Delete($Path)
        return
    }
    Assert-DNSFixturePath $Path
    Assert-DNS ($script:receiptDigest -ceq $ExpectedSHA256) 'receipt-before-retirement'
    Assert-DNSRecoverySnapshotUnchanged $ExpectedSHA256
    if($script:failDelete){throw 'source-snapshot-removal-failed'}
    if(-not $script:silentSnapshotRemoval){[IO.File]::Delete($Path)}
}
function Save-Journal {
    if($script:undo[0].dnscryptRetirement -and $script:failRetirementJournal){throw 'Fixture retirement journal write failed'}
    if($script:failJournalWrite){throw 'Fixture journal write failed'}
    if($script:failReloadJournal -and @($script:undo | Where-Object {$_.kind -ceq 'dnscrypt-reload'}).Count){throw 'Fixture reload journal write failed'}
    if($script:replaceSnapshotOnJournalSave){[IO.File]::AppendAllText($snapshot,' ')}
    if($script:undo[0].snapshotActive -and $script:failActivationWrite){throw 'Fixture activation write failed'}
    $wasActive=$script:journalActive
    $script:journalDigest=$script:undo[0].snapshotSHA256
    $script:journalActive=($script:undo[0].snapshotActive -eq $true)
    $activating=$script:journalActive -and -not $wasActive
    if($activating -and $script:replaceSnapshotOnActivation){[IO.File]::AppendAllText($snapshot,' ')}
    if($activating -and $script:changeDNSOnActivation){
        $guid=[string]$script:adapters[0].InterfaceGuid
        $script:appliedDNS[$guid+'/IPv4']=@{
            dhcp=($script:changeDNSOnActivation -ceq 'mode')
            values=@('198.51.100.53')
        }
    }
    if($activating -and $script:changeDohOnActivation){
        if($script:changeDohOnActivation -ceq 'remove'){
            $script:currentDoh.Remove('8.8.8.8')
        }else{
            $script:currentDoh['8.8.8.8']=Old-DohFixture
            $script:currentDoh['8.8.8.8'].DohTemplate='https://independent.invalid/dns-query'
        }
    }
    $script:savedReload=@($script:undo | Where-Object {$_.kind -ceq 'dnscrypt-reload'} | ForEach-Object { $_.Clone() })
    $script:savedRetirement=$null
    if($script:undo[0].dnscryptRetirement){
        $script:savedRetirement=Microsoft.PowerShell.Utility\ConvertFrom-Json (Microsoft.PowerShell.Utility\ConvertTo-Json $script:undo[0] -Depth 5 -Compress)
        if($script:firewallOnRetirementJournal){$script:dohFirewallFault=$script:firewallOnRetirementJournal}
    }
    $script:journals++
}
function Confirm-DNSRecoveryEntry($Entry) {
    if(Confirm-DNSRecoverySnapshot $Entry.snapshotSHA256){return $true}
    if($script:receiptDigest -cne $Entry.snapshotSHA256){throw 'Fixture DNS recovery binding refused'}
    return $false
}
function Move-Item {throw 'Unexpected rollback move in DNS contracts'}
function Remove-WireSockRefreshTask {throw 'Unexpected rollback task in DNS contracts'}
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
    [CmdletBinding()]param($ClassName,$Filter,$Namespace)
    if($Namespace -ceq 'root/StandardCimv2'){
        $filters=@{
            MSFT_NetTCPConnection='LocalPort = 53 AND State = 2'
            MSFT_NetUDPEndpoint='LocalPort = 53'
        }
        if(-not $filters.ContainsKey($ClassName) -or $Filter -cne $filters[$ClassName] -or
            $PSBoundParameters['ErrorAction'] -ne 'Stop'){throw 'Unexpected DNSCrypt port inventory query'}
        $script:DNSCryptPortReads.Add($ClassName)
        if($script:failDNSCryptPortRead){throw 'Fixture port inventory failure'}
        if($script:DNSCryptPortRows.ContainsKey($ClassName)){return $script:DNSCryptPortRows[$ClassName]}
        return
    }
    if($script:sharingMode -and $Filter -ceq "ProcessId=4242 AND State='Running'" -and $ClassName -ceq 'Win32_Service'){
        $name=if($script:sharingMode -ceq 'foreign'){'Unrelated'}else{'SharedAccess'}
        [pscustomobject]@{Name=$name;ProcessId=[uint32]4242;State='Running'}
        if($script:sharingMode -ceq 'shared') {[pscustomobject]@{Name='Unrelated';ProcessId=[uint32]4242;State='Running'}}
        return
    }
    if($script:sharingMode -and $Filter -ceq 'ProcessId=4242' -and $ClassName -ceq 'Win32_Process'){
        $script:sharingQueries++
        $time=[datetime]::new(2025,1,1,0,0,0,[DateTimeKind]::Utc)
        if($script:sharingMode -ceq 'changed' -and $script:sharingQueries -gt 2){$time=$time.AddSeconds(1)}
        $image=if($script:sharingMode -ceq 'wrong-image'){Join-Path $root 'svchost.exe'}else{[IO.Path]::Combine([Environment]::SystemDirectory,'svchost.exe')}
        return [pscustomobject]@{ExecutablePath=$image;ProcessId=[uint32]4242;CreationDate=$time}
    }
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
function Test-DNSCryptExclusiveUDPBind([Net.IPAddress]$Address) {
    $literal=$Address.ToString()
    if($literal -cnotin @('127.0.0.1','::1')){throw 'Unexpected exclusive loopback bind'}
    $script:sharingBinds.Add($literal)
    return $literal -cne $script:sharingBindFailure
}
# Exercise the exact ownership reader against private providers in the
# focused cases below. Configuration cases supply a synthetic identity.
$readFixtureListenerOwner=(Microsoft.PowerShell.Core\Get-Command -Name Get-ManagedDNSCryptListenerOwner -CommandType Function).ScriptBlock
function Get-ManagedDNSCryptListenerOwner([string[]]$Servers,[string]$Binary,$Entry,$SharingProbe){
    if($Binary -cne (Join-Path $root 'components\dnscrypt\dnscrypt-proxy.exe') -or
        -not $Servers.Count -or $Entry.name -cne 'AccessWeaver-dnscrypt' -or
        $Entry.commandSHA256 -cne $script:resolverDigest -or -not $script:resolverServicePresent){
        throw 'Unexpected DNSCrypt listener ownership verification'
    }
    if($SharingProbe){
        if($Servers -cnotcontains '127.0.0.1'){throw 'Expected the IPv4 DNSCrypt challenge endpoint'}
        Assert-DNSCryptSharingProbe $SharingProbe
    }
    if($script:resolverQueries){
        $script:finalOwnerReads++
        if($script:listenerOwnerFault -ceq 'final-replaced' -and $script:finalListenerAAAAQueries.Count -eq 2){return 'replacement'}
        if($script:listenerOwnerFault -ceq 'final-stable-replacement' -and $script:finalOwnerReads -ge 3){return 'replacement'}
        if($script:listenerOwnerFault -ceq 'before-aaaa'){return 'replacement'}
    }else{
        $script:initialOwnerReads++
        if($script:listenerOwnerFault -ceq 'initial-foreign'){throw 'Synthetic unowned listener'}
        if($script:listenerOwnerFault -ceq 'between-adapters' -and (Mutation-Count) -eq 1){return 'replacement'}
    }
    return 'managed-fixture-owner'
}
function Get-Service {
    [CmdletBinding()]param($Name)
    if($Name -cin @('MpsSvc','Dnscache')){
        return [pscustomobject]@{Status=$(if($Name -ceq 'Dnscache' -and $script:dohFirewallFault -ceq 'client-stopped'){'Stopped'}else{'Running'})}
    }
    if($Name -cne 'AccessWeaver-dnscrypt'){throw 'Unexpected service name'}
    if($script:resolverServicePresent){
        $startup=if($script:expectedResolverStartup){$script:expectedResolverStartup}else{'Automatic'}
        $status=if($script:serviceTransition.Count){$script:serviceTransition.Peek()}elseif($script:resolverStopped){'Stopped'}else{'Running'}
        $service=[pscustomobject]@{Status=$status;StartType=$startup}
        $service | Add-Member ScriptMethod Refresh {
            $script:serviceTransitionRefreshes++
            [void]$script:serviceTransition.Dequeue()
            $this.Status=$script:serviceTransition.Peek()
            if($this.Status -cin @('Running','Stopped')){
                $script:resolverStopped=$this.Status -ceq 'Stopped'
                [void]$script:serviceTransition.Dequeue()
            }
            if($script:serviceTransitionFault -ceq 'binding'){
                $script:resolverBindingFailureRead=$script:resolverBindingReads+1
            }elseif($script:serviceTransitionFault -ceq 'snapshot'){
                $record=[IO.File]::ReadAllText($snapshot) | ConvertFrom-Json
                $record.recoveryID='b'*32
                [IO.File]::WriteAllText($snapshot,($record | ConvertTo-Json -Depth 10))
            }
        }
        $service | Add-Member ScriptMethod WaitForStatus {
            param($State,$Timeout)
            if($State -cne 'Running' -or $Timeout.TotalSeconds -ne 20 -or $this.Status -cne 'Running'){throw 'Unexpected fixture service wait'}
        }
        return $service
    }
}
function Clear-DnsClientCache {
    [CmdletBinding()]param()
    $script:cacheFlushes++
    if($script:cacheFlushFault -ceq 'unavailable'){Write-Error 'source-dns-cache-flush-failed'}
    if($script:cacheFlushFault -ceq 'firewall'){$script:dohFirewallFault='inactive'}
    if($script:cacheFlushFault -ceq 'adapter-drift'){
        $key=([string]$script:adapters[0].InterfaceGuid)+'/IPv4'
        $script:appliedDNS[$key]=@{dhcp=$false;values=@('198.51.100.53')}
    }
}
function Test-DNSCryptTransportAnswer([string]$Server,[string]$Type,[string]$Protocol,[string]$Challenge) {
    if($Challenge){
        $script:sharingProbeReads++
        if($Server -cne '127.0.0.1' -or $Type -cne 'A' -or $Protocol -cne 'UDP' -or
            $Challenge -cnotmatch '\Aaccessweaver-[a-f0-9]{32}\.invalid\z'){throw 'Unexpected managed challenge query'}
        return -not $script:sharingChallengeFailure
    }
    if($Server -cnotin @('127.0.0.1','::1') -or $Type -cnotin @('A','AAAA') -or $Protocol -cnotin @('UDP','TCP')){
        throw 'Unexpected direct DNSCrypt probe'
    }
    $script:listenerTransports.Add("$Protocol/$Server/$Type")
    if($Protocol -ceq 'UDP'){return "$Server/$Type" -cne $script:listenerUDPFault}
    $answers=@(Resolve-DnsName -Name 'example.net.' -Server $Server -Type $Type -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
    return Test-DNSAddressAnswer $answers 'example.net' $Type
}
function Test-OrdinaryDNSAddress([string]$Type) {
    $answers=@(Resolve-DnsName -Name 'example.com.' -Type $Type -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
    return Test-DNSAddressAnswer $answers 'example.com' $Type
}
function Resolve-DnsName {
    [CmdletBinding()]param($Name,$Server,$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout)
    if(-not $Server){
        if($Name -cne 'example.com.' -or $Type -cnotin @('A','AAAA') -or
            -not $DnsOnly -or -not $NoHostsFile -or -not $QuickTimeout -or $ErrorActionPreference -ne 'Stop'){
            throw 'Unexpected ordinary DNS resolver query'
        }
        if($Type -ceq 'AAAA'){
            $script:resolverAAAAQueries++
            if($script:resolverDrift -ceq 'firewall' -or
                ($script:resolverStopped -and $script:postRetirementFault -ceq 'firewall')){
                $script:dohFirewallFault='inactive'
            }
            if($script:resolverAAAAQueries -le $script:emptyOrdinaryAAAAAnswers){return}
            $answer=@{Name=$Name;Type='AAAA';Section='Answer';IPAddress='2001:db8::15'}
            switch -CaseSensitive ($script:ordinaryAAAAFault){
                'wrong-name' {$answer.Name='example.org.'}
                'wrong-type' {$answer.Type='A'}
                'authority' {$answer.Section='Authority'}
                'ipv4' {$answer.IPAddress='192.0.2.15'}
                'mapped-ipv4' {$answer.IPAddress='::ffff:192.0.2.15'}
            }
            return [pscustomobject]$answer
        }
        $script:resolverQueries++
        if($script:firewallAfterAProbe -ceq 'first' -or
            ($script:firewallAfterAProbe -ceq 'after-service-stop' -and $script:resolverStopped)){
            $script:dohFirewallFault='inactive'
        }
        if($script:changeDNSCryptAfter -ceq 'ordinary-probe'){
            [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),'independent configuration')
        }
        if($script:resolverQueries -le $script:emptyOrdinaryAnswers){return}
        if($script:serviceStops -gt 0 -and $script:resolverStopped){
            $script:postRetirementQueries++
            switch -CaseSensitive ($script:postRetirementFault){
                'empty' {return}
                'retry' {if($script:postRetirementQueries -eq 1){return}}
                'late-dependency' {$script:dnsValues['88/IPv6']=@('::1')}
                'policy' {$script:currentDoh['8.8.8.8'].AllowFallbackToUdp=$true}
                'server' {$script:appliedDNS[([string]$script:adapters[0].InterfaceGuid)+'/IPv4'].values[0]='198.51.100.53'}
                'service' {$script:resolverReadbackFault='still-running'}
            }
        }
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
    if($Server -cnotin @('127.0.0.1','::1') -or $Name -cne 'example.net.' -or $Type -cnotin @('A','AAAA') -or
        -not $DnsOnly -or -not $NoHostsFile -or -not $QuickTimeout -or $ErrorActionPreference -ne 'Stop'){
        throw 'Unexpected DNSCrypt listener probe'
    }
    if($Type -ceq 'AAAA'){
        if($script:restartRecoveryWrites){throw 'Original listener recovery uses the existing A check'}
        $answer=@{Name=$Name;Type='AAAA';Section='Answer';IPAddress='2001:db8::15'}
        if($script:resolverQueries){
            $script:finalListenerAAAAQueries.Add($Server)
            if($Server -ceq $script:finalListenerMissingAAAA){return}
        }else{
            $script:listenerAAAAQueries.Add($Server)
            if($Server -ceq $script:listenerAAAAFaultServer){
                switch -CaseSensitive ($script:listenerAAAAFault){
                    'timeout' {throw 'Synthetic AAAA resolver timeout'}
                    'empty' {return}
                    'once' {
                        if(@($script:listenerAAAAQueries | Where-Object {$_ -ceq $Server}).Count -eq 1){return}
                    }
                    'wrong-name' {$answer.Name='example.org.'}
                    'wrong-type' {$answer.Type='A'}
                    'authority' {$answer.Section='Authority'}
                    'ipv4' {$answer.IPAddress='192.0.2.15'}
                    'mapped-ipv4' {$answer.IPAddress='::ffff:192.0.2.15'}
                }
            }
        }
        return [pscustomobject]$answer
    }
    if($script:restartRecoveryWrites){
        if($script:restartListenerFailure){throw 'Synthetic recovery listener timeout'}
        return [pscustomobject]@{Name='example.net.';Type='A';Section='Answer';IPAddress='192.0.2.15'}
    }
    if($script:resolverQueries){
        $script:finalListenerQueries.Add($Server)
        if($Server -ceq $script:finalListenerFailure){throw 'Synthetic final resolver timeout'}
        return [pscustomobject]@{Name='example.net.';Type='A';Section='Answer';IPAddress='192.0.2.15'}
    }
    if((Mutation-Count) -ne 0){$script:listenerChecksBeforeAdapters=$false}
    $script:listenerQueries.Add($Server)
    if($script:changeDNSCryptAfter -ceq 'listener' -and $script:listenerQueries.Count -eq 1){
        [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),'independent configuration')
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
    if($Seconds -eq 2 -and -not $Milliseconds){
        $script:ordinaryResolverWaits++
        if($script:postRetirementQueries -and $script:postRetirementFault -ceq 'empty'){
            Microsoft.PowerShell.Utility\Start-Sleep -Seconds $Seconds
        }
        return
    }
    if($Milliseconds -eq 500 -and -not $Seconds){
        $script:listenerWaits++
        if($script:refuseListenerWait){throw 'Synthetic loopback wait boundary'}
        return
    }
    throw 'Unexpected resolver wait'
}
function Ensure-Asset([string]$Engine){
    if(-not $script:stageDNSCrypt -or $Engine -cne 'dnscrypt'){throw 'Native component access is forbidden in DNS contracts'}
    if($script:portConflictOnStaging){
        $script:DNSCryptPortRows.MSFT_NetUDPEndpoint=[pscustomobject]@{LocalPort=[uint16]53;LocalAddress='0.0.0.0'}
    }
    return Join-Path $root 'components\dnscrypt\dnscrypt-proxy.exe'
}
function Install-EngineService([string]$Engine,[string]$Binary,[string[]]$Arguments,[switch]$DeferAutomaticStartup){
    $config=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
    if(-not $script:allowNewResolver -or $Engine -cne 'dnscrypt' -or $script:resolverServicePresent -or
        $Binary -cne (Join-Path $root 'components\dnscrypt\dnscrypt-proxy.exe') -or $Arguments.Count -ne 2 -or
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
        ($StartupType -ceq 'Manual' -and $script:serviceStops -ne 1 -and -not $script:restartRecoveryWrites) -or
        $StartupType -cnotin @('Manual','Automatic')){throw 'Unexpected service startup change'}
    if($StartupType -ceq 'Automatic' -and -not $script:retirementRecovery){
        $bindings=if($script:newResolverRegistered){1}elseif(@($script:undo | Where-Object {$_.kind -ceq 'dnscrypt-reload'}).Count){4}else{3}
        if(-not $script:stageDNSCrypt -or $script:resolverBindingReads -ne $bindings -or
            $script:listenerQueries.Count -eq 0 -or -not $script:listenerChecksBeforeAdapters -or
            $script:resolverStopped -or $script:resolverQueries -ne 0 -or (Mutation-Count) -ne 0){
            throw 'Resolver startup changed out of order'
        }
    }
    $script:expectedResolverStartup=$StartupType
    $script:serviceStartupChanges++
    if($script:failResolverStartupWrite){throw 'Synthetic DNSCrypt startup write failure'}
}
function Get-WorkflowFileHash([string]$Path) {
    if($Path -cne (Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml')){
        throw 'Unexpected DNSCrypt recovery path'
    }
    if([IO.File]::Exists($Path)){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}
function Restore-RecordedWorkflowFile($Record) {
    if($script:sharingProbePath -and $Record.path -ceq $script:sharingProbePath){
        if($Record.expectedHash -cne (Get-FileHash -LiteralPath $Record.path -Algorithm SHA256).Hash){
            throw 'DNSCrypt challenge ownership changed during rollback'
        }
        [IO.File]::Delete($Record.path)
        return
    }
    $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
    if(-not $script:restartRecoveryOriginal -or $Record.path -cne $path -or
       $Record.originalHash -cne (Get-WorkflowBytesSHA256 $script:restartRecoveryOriginal) -or
       (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cnotin @($Record.expectedHash,$Record.originalHash,$Record.pendingHash)){
        throw 'DNSCrypt recovery file differs from journal'
    }
    if($script:resolverQueries -gt 0 -and
        ((Snapshot-Hash) -cne $script:journalDigest -or $script:receiptDigest -or
         @($script:appliedDNS.Values | Where-Object {$_.values -contains '127.0.0.1'}).Count -or
         @($script:appliedDNS.Values | Where-Object {$_.values -contains '::1'}).Count -ne [int]($script:mode6 -ceq '::1'))){
        throw 'Resolver file restored before adapter recovery or after snapshot retirement'
    }
    [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
    $script:restartRecoveryWrites++
}
function Start-Service {
    param($InputObject,$ErrorAction)
    if($InputObject.Status -cne 'Stopped' -or $ErrorAction -cne 'Stop' -or
        (-not $script:retirementRecovery -and ((-not $script:stageDNSCrypt -and -not $script:loopbackAfterServiceStop -and
            $script:postRetirementFault -cne 'late-dependency') -or $script:serviceStartupChanges -ne 0))){throw 'Unexpected fixture service start'}
    $script:serviceStarts++
    if($script:failChangedConfigStart -and -not $script:restartRecoveryWrites){throw 'Synthetic changed DNSCrypt startup failure'}
    if($script:restartRecoveryFault -ceq 'start'){throw 'Synthetic original DNSCrypt startup failure'}
    $script:resolverStopped=$false
    $InputObject.Status='Running'
}
function Restart-Service {
    param($InputObject,$ErrorAction)
    if($InputObject.Status -cne 'Running' -or $ErrorAction -cne 'Stop' -or
        -not $script:stageDNSCrypt -or ($script:serviceStartupChanges -ne 0 -and -not $script:restartRecoveryWrites)){
        throw 'Unexpected fixture service restart'
    }
    if(-not $script:restartRecoveryWrites -and $script:savedReload.Count -ne 1){throw 'Replacement resolver activated before recording reload'}
    $script:serviceRestarts++
    if($script:failDNSCryptRestart){
        $script:resolverStopped=$true
        $InputObject.Status='Stopped'
        if($script:restartRecoveryFault -ceq 'file'){
            [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),'independent configuration')
        }
        throw 'Synthetic DNSCrypt service restart failure'
    }
}
function Stop-Service {
    param($Name,$ErrorAction)
    if($Name -cne 'AccessWeaver-dnscrypt' -or -not $script:resolverServicePresent -or $script:resolverQueries -lt 1){
        throw 'Old resolver stopped before DoH verification'
    }
    if(-not $script:savedRetirement -or $script:savedRetirement.snapshotSHA256 -cne (Snapshot-Hash) -or
        $script:savedRetirement.dnscryptRetirement.commandSHA256 -cne $script:resolverDigest){throw 'Resolver stopped before its recovery record was saved'}
    $script:serviceStops++
    $script:resolverStopped=$true
    if($script:loopbackAfterServiceStop){$script:dnsValues['88/IPv6']=@('::1')}
}
try {
    # Exercise the actual guard with both CDXML-friendly and documented CIM
    # representations. Only a single exact Full state may admit DNS mutation.
    foreach($representation in @(
        @{value='Full'},@{value=[uint16]1},@{value=[uint16[]]@(1)},
        @{value=[int32]1},@{value=[uint64]1}
    )){
        New-DNSCase
        $script:dohFirewallFault='enforcement-shape';$script:dohFirewallEnforcement=$representation.value
        Configure-DNS 'doh'
        Assert-DNS ($script:dnsConfigured -and (Mutation-Count) -gt 0 -and $script:dohFirewallWrites -eq 6) 'doh-firewall-full-status-representations'
    }
    $nonFull=@(
        @{value=$null},@{value=[uint16[]]@()},@{value=[uint16[]]@(1,2)},
        @{value=[uint16[]]@(1,1)},@{value=@('Full','Full')},@{value=@('Full','LocalFirewallRulesDisallowed')},
        @{value='1'},@{value=$true},@{value=[double]1},@{value=[decimal]1},
        @{value=[ConsoleColor]::DarkBlue},@{value='full'},@{value='Unknown'}
    )
    foreach($code in 0..23){if($code -ne 1){$nonFull+=@{value=[uint16[]]@($code)}}}
    foreach($representation in $nonFull){
        New-DNSCase
        $script:dohFirewallFault='enforcement-shape';$script:dohFirewallEnforcement=$representation.value
        Reject-DNS {Configure-DNS 'doh'} 'Managed DoH plaintext protection is missing from effective Windows Firewall policy'
        Assert-DNS (-not $script:dnsConfigured -and (Mutation-Count) -eq 0) 'doh-firewall-nonfull-status-refused'
    }
    # Public failures must identify only fixed source-known reasons. Do not echo
    # provider strings, rule IDs, addresses or account/adapter metadata.
    foreach($store in @('PersistentStore','ActiveStore')){
        foreach($protocol in @('TCP','UDP')){
            New-DNSCase
            Configure-DNS 'doh'
            $id=(Read-DNSRecoverySnapshot).record.dohPlaintextBlockID
            $before=Mutation-Count
            $script:dohFirewallFault='missing-'+$protocol+'-'+$store
            $reason=if($store -ceq 'PersistentStore'){'persistent rule missing'}else{'effective rule missing'}
            $message=''
            try{Assert-DNSDohPlaintextBlock $id}catch{$message=$_.Exception.Message}
            Assert-DNS ($message -ceq ('Managed DoH plaintext protection is missing from effective Windows Firewall policy: '+$reason)) 'doh-firewall-missing-store-reason'
            Assert-DNS ((Mutation-Count) -eq $before) 'doh-firewall-diagnostic-does-not-mutate'
        }
    }
    $statusLabels=@(
        'Invalid','Full','FirewallOffInProfile','CategoryOff','DisabledObject','InactiveProfile','LocalAddressResolutionEmpty','RemoteAddressResolutionEmpty','LocalPortResolutionEmpty','RemotePortResolutionEmpty','InterfaceResolutionEmpty','ApplicationResolutionEmpty',
        'RemoteMachineEmpty','RemoteUserEmpty','LocalGlobalOpenPortsDisallowed','LocalAuthorizedApplicationsDisallowed','LocalFirewallRulesDisallowed','LocalConsecRulesDisallowed','NotTargetPlatform','OptimizedOut','LocalUserEmpty','TransportMachinesEmpty','TunnelMachinesEmpty','TupleResolutionEmpty'
    )
    foreach($code in 0..23){
        if($code -eq 1){continue}
        foreach($value in @([uint16]$code,$statusLabels[$code])){
            New-DNSCase
            Configure-DNS 'doh'
            $id=(Read-DNSRecoverySnapshot).record.dohPlaintextBlockID
            $before=Mutation-Count
            $script:dohFirewallFault='enforcement-shape';$script:dohFirewallEnforcement=$value
            $message=''
            try{Assert-DNSDohPlaintextBlock $id}catch{$message=$_.Exception.Message}
            Assert-DNS ($message -ceq ('Managed DoH plaintext protection is missing from effective Windows Firewall policy: '+$statusLabels[$code])) 'doh-firewall-known-enforcement-reason'
            Assert-DNS ((Mutation-Count) -eq $before) 'doh-firewall-status-diagnostic-does-not-mutate'
        }
    }
    foreach($code in 0..23){
        if($code -eq 1){continue}
        foreach($value in @([uint16]$code,$statusLabels[$code])){
            New-DNSCase
            Configure-DNS 'doh'
            $id=(Read-DNSRecoverySnapshot).record.dohPlaintextBlockID
            $before=Mutation-Count
            # A private, unsupported member is never emitted or admitted.
            $script:dohFirewallFault='enforcement-shape'
            $script:dohFirewallEnforcement=@('Full',$value,'PRIVATE_PROVIDER_TEXT')
            $message=''
            try{Assert-DNSDohPlaintextBlock $id}catch{$message=$_.Exception.Message}
            Assert-DNS ($message -ceq ('Managed DoH plaintext protection is missing from effective Windows Firewall policy: '+$statusLabels[$code])) 'doh-firewall-known-enforcement-reason'
            Assert-DNS ((Mutation-Count) -eq $before) 'doh-firewall-status-diagnostic-does-not-mutate'
        }
    }
    foreach($case in @(
        @{value=$null;reason='enforcement status unavailable'},
        @{value=[uint16[]]@();reason='enforcement status unavailable'},
        @{value=[uint16[]]@(1,1);reason='repeated Full statuses'},
        @{value=@('Full','Full');reason='repeated Full statuses'},
        @{value=[uint16[]]@(1,5);reason='mixed Full and InactiveProfile statuses'},
        @{value=@('InactiveProfile','Full');reason='mixed Full and InactiveProfile statuses'},
        @{value=[uint16[]]@(5,5);reason='repeated InactiveProfile statuses'},
        @{value=@($null,'Full');reason='enforcement status ambiguous'},
        @{value=@(1,'5');reason='enforcement status ambiguous'},
        @{value=@([double]1,[double]5);reason='enforcement status ambiguous'},
        @{value=[uint16[]]@(1)*32;reason='repeated Full statuses'},
        @{value=[uint16[]]@(1)*33;reason='enforcement status ambiguous'},
        @{value=(@([uint16]1)*32)+@([uint16]2);reason='enforcement status ambiguous'},
        @{value=@('Full','private provider text');reason='enforcement status ambiguous'},
        @{value='private provider text';reason='enforcement status unsupported'},
        @{value='16';reason='enforcement status unsupported'},
        @{value=$true;reason='enforcement status unsupported'},
        @{value=[double]16;reason='enforcement status unsupported'},
        @{value=[uint64]::MaxValue;reason='enforcement status unsupported'}
    )){
        New-DNSCase
        Configure-DNS 'doh'
        $id=(Read-DNSRecoverySnapshot).record.dohPlaintextBlockID
        $before=Mutation-Count
        $script:dohFirewallFault='enforcement-shape';$script:dohFirewallEnforcement=$case.value
        $message=''
        try{Assert-DNSDohPlaintextBlock $id}catch{$message=$_.Exception.Message}
        Assert-DNS ($message -ceq ('Managed DoH plaintext protection is missing from effective Windows Firewall policy: '+$case.reason)) 'doh-firewall-unavailable-or-unsupported-reason'
        Assert-DNS ((Mutation-Count) -eq $before) 'doh-firewall-malformed-diagnostic-does-not-mutate'
    }
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        # In-memory CIM only. An ETS ScriptProperty must never become authority,
        # even when it would display Full or throw private formatter text.
        & {
            $fixtureRule=$null
            foreach($case in @(
                @{value=[uint16[]]@(1);type=[Microsoft.Management.Infrastructure.CimType]::UInt16Array;reason=''},
                @{value=[uint16[]]@(2);type=[Microsoft.Management.Infrastructure.CimType]::UInt16Array;reason='FirewallOffInProfile'},
                @{value=[uint16[]]@(0);type=[Microsoft.Management.Infrastructure.CimType]::UInt16Array;reason='Invalid'},
                @{value=[uint16[]]@(1,1);type=[Microsoft.Management.Infrastructure.CimType]::UInt16Array;reason='repeated Full statuses'},
                @{value=[uint16[]]@(1,5);type=[Microsoft.Management.Infrastructure.CimType]::UInt16Array;reason='mixed Full and InactiveProfile statuses'},
                @{value=[uint16]1;type=[Microsoft.Management.Infrastructure.CimType]::UInt16;reason='enforcement status unavailable'},
                @{value=[string[]]@('Full');type=[Microsoft.Management.Infrastructure.CimType]::StringArray;reason='enforcement status unavailable'},
                @{missing=$true;reason='enforcement status unavailable'}
            )){
                $fixtureRule=[Microsoft.Management.Infrastructure.CimInstance]::new('MSFT_NetFirewallRule','root/standardcimv2')
                try {
                    if(-not $case.missing){
                        $property=[Microsoft.Management.Infrastructure.CimProperty]::Create('EnforcementStatus',$case.value,$case.type,[Microsoft.Management.Infrastructure.CimFlags]::None)
                        $fixtureRule.CimInstanceProperties.Add($property)
                    }
                    $fixtureRule|Add-Member -MemberType ScriptProperty -Name EnforcementStatus -Value {throw 'PRIVATE_FORMATTER_TEXT'} -Force
                    $message='';$before=Mutation-Count
                    try{Assert-DNSDohEffectiveStatus $fixtureRule}catch{$message=$_.Exception.Message}
                    $expected=if($case.reason){'Managed DoH plaintext protection is missing from effective Windows Firewall policy: '+$case.reason}else{''}
                    Assert-DNS ($message -ceq $expected) 'doh-firewall-cim-raw-status'
                    Assert-DNS ((Mutation-Count) -eq $before -and -not $message.Contains('PRIVATE_FORMATTER_TEXT')) 'doh-firewall-cim-format-not-authority'
                } finally {$fixtureRule.Dispose();$fixtureRule=$null}
            }
        }
    }
    foreach($requirement in @(
        @{fault='disabled';message='Windows Firewall policy does not permit managed DoH plaintext protection'},
        @{fault='client-stopped';message='Windows Firewall and DNS Client must be running for managed DoH'}
    )){
        New-DNSCase
        $script:dohFirewallFault=$requirement.fault
        Reject-DNS {Configure-DNS 'doh'} $requirement.message
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:dohFirewallWrites -eq 0 -and -not [IO.File]::Exists($snapshot)) 'doh-firewall-refuses-unavailable-service'
    }
    New-DNSCase
    foreach($mask in @(1,2,5,7)){
        New-DNSCase;$script:dohFirewallActiveMask=$mask
        Configure-DNS 'doh'
        Assert-DNS ($script:dnsConfigured -and $script:dohFirewallWrites -eq 6 -and
            (Mutation-Count) -gt 0) 'doh-firewall-covers-concurrent-active-profiles'
    }
    foreach($fault in @('profile-changed','inactive-profile-drift')){
        New-DNSCase;$script:dohFirewallFault=$fault
        $expected=if($fault -ceq 'profile-changed'){'Active Windows Firewall profiles changed during managed DoH verification'}else{'Managed DoH plaintext protection is missing from effective Windows Firewall policy: inactive profile status differs'}
        Reject-DNS {Configure-DNS 'doh'} $expected
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:dohFirewallRules.Count -eq 6 -and
            [IO.File]::Exists($snapshot)) 'doh-firewall-refuses-profile-transitions'
        $script:dohFirewallFault=''
        Restore-DNS
    }
    foreach($migrate in @($false,$true)){
        New-DNSCase
        Configure-DNS 'doh'
        $legacyID=(Read-DNSRecoverySnapshot).record.dohPlaintextBlockID
        $legacyRules=@{}
        foreach($protocol in @('TCP','UDP')){
            $baseName='AccessWeaver-DoH-Plaintext-'+$protocol+'-'+$legacyID
            $legacy=$script:dohFirewallRules[$baseName+'-Public'].Clone()
            $legacy.Name=$baseName
            $legacy.Profile='Any'
            $legacyRules[$baseName]=$legacy
        }
        $script:dohFirewallRules=$legacyRules
        if($migrate){
            Configure-DNS 'doh'
            Assert-DNS ($script:dohFirewallRules.Count -eq 8 -and
                (Read-DNSRecoverySnapshot).record.dohPlaintextBlockID -ceq $legacyID) 'doh-firewall-migrates-legacy-pair-without-dropping-protection'
        }
        Restore-DNS
        Assert-DNS ($script:dohFirewallRules.Count -eq 0 -and -not [IO.File]::Exists($snapshot)) 'doh-firewall-recovers-legacy-pair'
    }
    New-DNSCase
    Configure-DNS 'doh'
    $id=(Read-DNSRecoverySnapshot).record.dohPlaintextBlockID
    Assert-DNS ($id -cmatch '\A[a-f0-9]{32}\z' -and $script:dohFirewallRules.Count -eq 6 -and $script:dohFirewallWrites -eq 6) 'doh-firewall-owned-protection'
    Configure-DNS 'doh'
    Assert-DNS ((Read-DNSRecoverySnapshot).record.dohPlaintextBlockID -ceq $id -and $script:dohFirewallWrites -eq 6) 'doh-firewall-keeps-identity'
    $tcp='AccessWeaver-DoH-Plaintext-TCP-'+$id+'-Public'
    $script:dohFirewallRules[$tcp].RemoteAddress=@('8.8.8.8/255.255.255.255','9.9.9.9/32','2001:4860:4860:0:0:0:0:8888/128','2620:fe::fe')
    Assert-DNS ($null -ne (Get-DNSDohPlaintextRule $id 'TCP' 'ActiveStore' -Profile Public)) 'doh-firewall-normalizes-host-addresses'
    $script:dohFirewallRules[$tcp].Service='Unrelated'
    $script:calls.Clear()
    Reject-DNS {Restore-DNS} 'Managed DoH plaintext protection rule changed independently'
    Assert-DNS ((Mutation-Count) -eq 0 -and $script:dohFirewallRules.Count -eq 6 -and [IO.File]::Exists($snapshot)) 'doh-firewall-preserves-foreign-rule'
    $script:dohFirewallRules[$tcp].Service='Dnscache'
    foreach($edit in @(
        @{field='InterfaceAlias';value='Fixture adapter'},
        @{field='InterfaceType';value='Wireless'},
        @{field='Authentication';value='Required'},
        @{field='LocalUser';value='Fixture security selector'},
        @{field='LocalOnlyMapping';value=$true},
        @{field='RemoteDynamicKeywordAddresses';value='Fixture dynamic keyword'}
    )){
        $rule=$script:dohFirewallRules[$tcp]
        $originalValue=$rule[$edit.field]
        $rule[$edit.field]=$edit.value
        $hash=Snapshot-Hash
        Reject-DNS {Configure-DNS 'doh'} 'Managed DoH plaintext protection rule changed independently'
        Reject-DNS {Restore-DNS} 'Managed DoH plaintext protection rule changed independently'
        Assert-DNS ((Snapshot-Hash) -ceq $hash -and (Mutation-Count) -eq 0 -and
            $script:dohFirewallWrites -eq 6 -and $script:dohFirewallRules.Count -eq 6 -and
            $rule[$edit.field] -ceq $edit.value) 'doh-firewall-preserves-filter-drift'
        $rule[$edit.field]=$originalValue
    }
    foreach($fault in @('filter-warning','narrow-effective')){
        $script:dohFirewallFault=$fault
        $hash=Snapshot-Hash
        Reject-DNS {Restore-DNS}
        Assert-DNS ((Snapshot-Hash) -ceq $hash -and (Mutation-Count) -eq 0 -and
            $script:dohFirewallRules.Count -eq 6) 'doh-firewall-refuses-incomplete-filters'
    }
    $script:dohFirewallFault=''
    Restore-DNS
    Assert-DNS ($script:dohFirewallRules.Count -eq 0 -and -not [IO.File]::Exists($snapshot)) 'doh-firewall-recovery-cleans-rules'
    foreach($fault in @('inactive','second-write')){
        New-DNSCase
        $script:dohFirewallFault=$fault
        Reject-DNS {Configure-DNS 'doh'}
        $expectedCount=if($fault -ceq 'inactive'){6}else{3}
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:dohFirewallRules.Count -eq $expectedCount -and [IO.File]::Exists($snapshot)) 'doh-firewall-refusal-keeps-recovery'
        $script:dohFirewallFault=''
        Restore-DNS
        Assert-DNS ($script:dohFirewallRules.Count -eq 0 -and -not [IO.File]::Exists($snapshot)) 'doh-firewall-recovery-cleans-rules'
    }

    New-DNSCase
    Configure-DNS 'doh'
    $id=(Read-DNSRecoverySnapshot).record.dohPlaintextBlockID
    $before=Snapshot-Hash
    $script:calls.Clear()
    $orphan='AccessWeaver-DoH-Plaintext-TCP-'+('b'*32)
    $script:dohFirewallRules[$orphan]=@{Name=$orphan}
    $conflict='Managed DoH firewall rules do not match the current DNS recovery snapshot'
    Reject-DNS {Configure-DNS 'doh'} $conflict
    Reject-DNS {Restore-DNS} $conflict
    Assert-DNS ((Snapshot-Hash) -ceq $before -and (Mutation-Count) -eq 0 -and
        $script:dohFirewallWrites -eq 6 -and $script:dohFirewallRules.Count -eq 7) 'doh-firewall-unmatched-rule-preserved'
    $script:dohFirewallRules.Remove($orphan)
    $savedPath=Join-Path $root 'profiles/fixture-retained-snapshot.json'
    $savedCopy=Join-Path $root 'profiles/fixture-retained-snapshot.copy'
    [IO.File]::Move($snapshot,$savedPath)
    [IO.File]::Move($script:copyPath,$savedCopy)
    foreach($operation in @({Configure-DNS 'doh'},{Configure-DNS 'dnscrypt'},{Restore-DNS},{Remove-All})){
        Reject-DNS $operation $conflict
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Get-FileHash -LiteralPath $savedPath -Algorithm SHA256).Hash -ceq $before -and
            (Mutation-Count) -eq 0 -and $script:dohFirewallWrites -eq 6 -and $script:dohFirewallRules.Count -eq 6) 'doh-firewall-missing-snapshot-preserved'
    }
    [IO.File]::Move($savedCopy,$script:copyPath)
    Reject-DNS {Configure-DNS 'doh'} 'Original DNS snapshot is missing; use dns-restore'
    Reject-DNS {Restore-DNS ('a'*64)} 'DNS recovery journal does not match the active snapshot'
    $script:dohFirewallRules['Unrelated rule']=@{Name='Unrelated rule'}
    Restore-DNS $before
    Assert-DNS ($script:dohFirewallRules.Count -eq 1 -and $script:dohFirewallRules.ContainsKey('Unrelated rule') -and
        -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($script:copyPath)) 'doh-firewall-matched-snapshot-recovers'

    New-DNSCase;Configure-DNS 'doh'
    $previous=(Read-DNSRecoveryCopy).fileSHA256
    $script:calls.Clear()
    $script:failCopyPublication=$true
    Reject-DNS {Configure-DNS 'doh'} 'Synthetic recovery copy write failure'
    Assert-DNS ((Mutation-Count) -eq 0 -and (Read-DNSRecoverySnapshot).record.previousRecoveryCopySHA256 -ceq $previous -and
        (Read-DNSRecoveryCopy).fileSHA256 -ceq $previous) 'dns-recovery-copy-before-effects'
    $script:failCopyRetirement=$true
    Reject-DNS {Restore-DNS} 'Synthetic recovery copy retirement failure'
    Assert-DNS ([IO.File]::Exists($snapshot) -and [IO.File]::Exists($script:copyPath)) 'dns-recovery-copy-retirement-retried'
    $script:failCopyRetirement=$false
    Restore-DNS
    Assert-DNS (-not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($script:copyPath)) 'dns-recovery-copy-retirement-retried'

    New-DNSCase;Configure-DNS 'doh'
    $script:calls.Clear()
    [IO.File]::Delete($snapshot)
    [IO.File]::AppendAllText($script:copyPath,' ')
    Reject-DNS {Restore-DNS} 'Original DNS recovery copy could not be verified'
    Assert-DNS ((Mutation-Count) -eq 0 -and -not [IO.File]::Exists($snapshot)) 'dns-recovery-copy-corruption-refused'

    & {
        New-DNSCase
        function Get-NetFirewallRule {
            [CmdletBinding()]param($PolicyStore,[switch]$TracePolicyStore)
            if($PolicyStore -ceq 'ActiveStore'){[pscustomobject]@{Name='AccessWeaver-DoH-Plaintext-UDP-'+('c'*32)}}
        }
        foreach($operation in @({Configure-DNS 'doh'},{Configure-DNS 'dnscrypt'},{Restore-DNS},{Remove-All})){
            Reject-DNS $operation 'Managed DoH firewall rules do not match the current DNS recovery snapshot'
            Assert-DNS ((Mutation-Count) -eq 0 -and -not [IO.File]::Exists($snapshot)) 'doh-firewall-active-only-conflict'
        }
    }

    & {
        $hostPath='C:\Fixture\host.exe'
        $binary='C:\Fixture\dnscrypt-proxy.exe'
        $command='"'+$hostPath+'" service-host "C:\Fixture\dnscrypt.json"'
        $entry=@{name='AccessWeaver-dnscrypt';commandSHA256=(Get-ManagedServiceCommandDigest $command)}
        $started=[datetime]'2026-01-01T00:00:00Z'
        $addresses=@('127.0.0.1','::1')
        function Read-ManagedServiceRegistration([string]$Name){
            if($Name -cne 'AccessWeaver-dnscrypt'){throw 'Unexpected ownership registration'}
            return $service
        }
        function Get-NetTCPConnection {
            [CmdletBinding()]param($State,$LocalPort)
            if($State -cne 'Listen' -or $LocalPort -ne 53 -or $ErrorActionPreference -ne 'Stop'){
                throw 'Unexpected TCP ownership query'
            }
            return $tcpRows
        }
        function Get-NetUDPEndpoint {
            [CmdletBinding()]param($LocalPort)
            if($LocalPort -ne 53 -or $ErrorActionPreference -ne 'Stop'){throw 'Unexpected UDP ownership query'}
            return $udpRows
        }
        function Get-CimInstance {
            [CmdletBinding()]param($ClassName,$Filter)
            if($ClassName -cne 'Win32_Process' -or $ErrorActionPreference -ne 'Stop'){
                throw 'Unexpected ownership process query'
            }
            switch -CaseSensitive ($Filter){
                'ProcessId=42' {return $hostProcess}
                'ProcessId=43' {return $child}
                default {throw 'Unexpected ownership process identity'}
            }
        }
        function Get-DNSCryptConnectionSharingIdentity([uint32]$Owner){
            if($Owner -eq 99){return $sharingOwner}
        }
        $endpointFailures=@{
            'missing-udp'='listener-endpoint-missing';'missing-ipv6'='listener-endpoint-missing'
            'wildcard'='listener-udp-other-owner';'mapped-wildcard'='listener-udp-other-owner'
            'same-owner-wildcard'='listener-udp-same-owner';'tcp-wildcard'='listener-tcp-wildcard'
            'unknown-owner-wildcard'='listener-udp-unknown-owner'
            'duplicate'='listener-endpoint-duplicate';'mixed-pids'='listener-endpoint-conflict'
            'unknown-pid'='listener-endpoint-owner';'invalid-row'='listener-endpoint-row'
        }
        foreach($fault in @('','missing-udp','missing-ipv6','wildcard','mapped-wildcard','same-owner-wildcard',
                'unknown-owner-wildcard','tcp-wildcard','duplicate','mixed-pids','unknown-pid','invalid-row',
                'wrong-host','wrong-child','wrong-parent','reused-parent-pid','host-disappeared','child-disappeared','changed-command','service-stopped')){
            $service=[pscustomobject]@{PathName=$command;State='Running';ProcessId=[uint32]42}
            $hostProcess=[pscustomobject]@{ProcessId=[uint32]42;ExecutablePath=$hostPath;CreationDate=$started}
            $child=[pscustomobject]@{ProcessId=[uint32]43;ParentProcessId=[uint32]42;ExecutablePath=$binary;CreationDate=$started.AddSeconds(1)}
            $tcpRows=@(foreach($address in $addresses){[pscustomobject]@{LocalAddress=$address;LocalPort=53;OwningProcess=[uint32]43}})
            $udpRows=@(foreach($address in $addresses){[pscustomobject]@{LocalAddress=$address;LocalPort=53;OwningProcess=[uint32]43}})
            switch -CaseSensitive ($fault){
                'missing-udp' {$udpRows=@()}
                'missing-ipv6' {$tcpRows=@($tcpRows[0])}
                'wildcard' {$udpRows+=[pscustomobject]@{LocalAddress='::';LocalPort=53;OwningProcess=[uint32]99}}
                'mapped-wildcard' {$udpRows+=[pscustomobject]@{LocalAddress='::ffff:0.0.0.0';LocalPort=53;OwningProcess=[uint32]99}}
                'same-owner-wildcard' {$udpRows+=[pscustomobject]@{LocalAddress='::';LocalPort=53;OwningProcess=[uint32]43}}
                'unknown-owner-wildcard' {$udpRows+=[pscustomobject]@{LocalAddress='::';LocalPort=53;OwningProcess=[uint32]0}}
                'tcp-wildcard' {$tcpRows+=[pscustomobject]@{LocalAddress='0.0.0.0';LocalPort=53;OwningProcess=[uint32]99}}
                'duplicate' {$tcpRows+=[pscustomobject]@{LocalAddress='::ffff:127.0.0.1';LocalPort=53;OwningProcess=[uint32]43}}
                'mixed-pids' {$udpRows[1].OwningProcess=[uint32]99}
                'unknown-pid' {$udpRows[1].OwningProcess=[uint32]0}
                'invalid-row' {$udpRows[1].LocalAddress='invalid'}
                'wrong-host' {$hostProcess.ExecutablePath=$binary}
                'wrong-child' {$child.ExecutablePath=$hostPath}
                'wrong-parent' {$child.ParentProcessId=[uint32]99}
                'reused-parent-pid' {$hostProcess.CreationDate=$started.AddSeconds(2)}
                'host-disappeared' {$hostProcess=$null}
                'child-disappeared' {$child=$null}
                'changed-command' {$service.PathName+=' --changed'}
                'service-stopped' {$service.State='Stopped'}
            }
            if($fault){
                $refused=$false
                try{& $readFixtureListenerOwner $addresses $binary $entry | Out-Null}catch{
                    $refused=$_.Exception.Message -match '^(Managed DNSCrypt|Running DNSCrypt|DNSCrypt listener|DNSCrypt port|Expected TCP and UDP|Wildcard DNS)'
                }
                Assert-DNS $refused 'dnscrypt-managed-listener-owner'
                if($endpointFailures.ContainsKey($fault)){
                    Assert-DNS ($script:dnsOperationStage -ceq $endpointFailures[$fault]) 'dnscrypt-managed-listener-owner'
                }
            }else{
                $udpRows+=[pscustomobject]@{LocalAddress='192.0.2.53';LocalPort=53;OwningProcess=[uint32]99}
                $identity=& $readFixtureListenerOwner $addresses $binary $entry
                Assert-DNS ($identity -ceq ('42:{0}:43:{1}' -f $started.Ticks,$child.CreationDate.Ticks)) 'dnscrypt-managed-listener-owner'
                $child.CreationDate=$child.CreationDate.AddSeconds(1)
                Assert-DNS ((& $readFixtureListenerOwner $addresses $binary $entry) -cne $identity) 'dnscrypt-managed-listener-owner'
                New-DNSCase
                $script:sharingProbePath=Join-Path $root 'sharing-probe.txt'
                $data=[Text.Encoding]::ASCII.GetBytes('synthetic protected probe')
                [IO.File]::WriteAllBytes($script:sharingProbePath,$data)
                $sharingOwner='99:123'
                $probe=@{path=$script:sharingProbePath;hash=(Get-WorkflowBytesSHA256 $data);expectedSharing=$sharingOwner}
                $sharingRow=[pscustomobject]@{LocalAddress='0.0.0.0';LocalPort=53;OwningProcess=[uint32]99}
                $udpRows+=@($sharingRow)
                $withSharing=& $readFixtureListenerOwner $addresses $binary $entry $probe
                Assert-DNS ($withSharing.EndsWith('|99:123',[StringComparison]::Ordinal)) 'dnscrypt-sharing-binds-owned-challenge'
                $sharingOwner='99:124'
                Reject-DNS {& $readFixtureListenerOwner $addresses $binary $entry $probe} 'Internet Connection Sharing changed after DNSCrypt admission'
                $sharingOwner='99:123'
                $udpRows+=@($sharingRow)
                Reject-DNS {& $readFixtureListenerOwner $addresses $binary $entry $probe} 'Wildcard DNS listener makes loopback ownership ambiguous'
            }
        }
    }
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
    New-DNSCase -ExistingResolver;$script:readbackFault='read-error'
    Reject-DNS {Configure-DNS 'doh'}
    Assert-DNS ($script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0 -and $script:resolverQueries -eq 0) 'doh-keeps-old-resolver-until-verified'
    New-DNSCase -ExistingResolver
    Configure-DNS 'doh'
    Assert-DNS ($script:serviceStops -eq 1 -and $script:serviceStartupChanges -eq 1 -and
        $script:resolverQueries -eq 2 -and $script:postRetirementQueries -eq 1 -and
        $script:resolverReadbacks -eq 1 -and $script:dnsConfigured) 'doh-verifies-after-stopping-dnscrypt'
    New-DNSCase -ExistingResolver;$script:postRetirementFault='retry'
    Configure-DNS 'doh'
    Assert-DNS ($script:postRetirementQueries -eq 2 -and $script:ordinaryResolverWaits -eq 1 -and
        $script:dnsConfigured) 'doh-verifies-after-stopping-dnscrypt'
    New-DNSCase
    $script:firewallAfterAdapterWrite='inactive'
    Reject-DNS {Configure-DNS 'doh'} 'Managed DoH plaintext protection is missing from effective Windows Firewall policy'
    $writes=@($script:calls | Where-Object {$_.kind -ceq 'dns'})
    Assert-DNS ($writes.Count -eq 1 -and $writes[0].family -ceq 'IPv4' -and $script:journalActive -and
        $script:resolverQueries -eq 0 -and -not $script:dnsConfigured) 'doh-firewall-loss-before-next-adapter-write'
    Assert-SnapshotRetained $script:journalDigest
    $errors=@(Rollback)
    $writes=@($script:calls | Where-Object {$_.kind -ceq 'dns'})
    Assert-DNS ($errors.Count -eq 0 -and $writes.Count -eq 2 -and $writes[1].family -ceq 'IPv4' -and
        ($writes[1].servers -join ',') -ceq '192.0.2.53' -and $script:currentDoh.Count -eq 0 -and
        $script:dohFirewallRules.Count -eq 0 -and -not [IO.File]::Exists($snapshot) -and
        -not [IO.File]::Exists($copyPath)) 'doh-firewall-loss-restores-applied-family'

    foreach($probeLoss in @('before-aaaa','before-retry','after-service-stop')){
        $afterStop=$probeLoss -ceq 'after-service-stop'
        New-DNSCase -ExistingResolver:$afterStop
        $script:firewallAfterAProbe=if($afterStop){'after-service-stop'}else{'first'}
        if($probeLoss -ceq 'before-retry'){$script:emptyOrdinaryAnswers=1}
        Reject-DNS {Configure-DNS 'doh'} 'Managed DoH plaintext protection is missing from effective Windows Firewall policy'
        $expectedA=1+[int]$afterStop
        Assert-DNS ($script:resolverQueries -eq $expectedA -and
            $script:resolverAAAAQueries -eq [int]$afterStop -and $script:serviceStops -eq [int]$afterStop -and
            $script:ordinaryResolverWaits -eq [int]($probeLoss -ceq 'before-retry') -and
            -not $script:dnsConfigured) 'doh-firewall-loss-stops-resolver-probes'
        Assert-SnapshotRetained $script:journalDigest

        $script:retirementRecovery=$afterStop
        $errors=@(Rollback)
        $restored=$script:appliedDNS[([string]$script:adapters[0].InterfaceGuid)+'/IPv4']
        Assert-DNS ($errors.Count -eq 0 -and $script:serviceStarts -eq [int]$afterStop -and
            -not $script:resolverStopped -and ($restored.values -join ',') -ceq '192.0.2.53' -and
            $script:dohFirewallRules.Count -eq 0 -and $script:currentDoh.Count -eq 0 -and
            -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($copyPath)) 'doh-probe-firewall-loss-restores-state'
    }

    foreach($guardLoss in @('first-probe','journal','second-probe')){
        New-DNSCase -ExistingResolver
        switch -CaseSensitive ($guardLoss){
            'first-probe' {$script:resolverDrift='firewall'}
            'journal' {$script:firewallOnRetirementJournal='inactive'}
            'second-probe' {$script:postRetirementFault='firewall'}
        }
        Reject-DNS {Configure-DNS 'doh'} 'Managed DoH plaintext protection is missing from effective Windows Firewall policy'
        $stopped=[int]($guardLoss -ceq 'second-probe')
        Assert-DNS ($script:serviceStops -eq $stopped -and $script:serviceStartupChanges -eq 0 -and
            $script:resolverQueries -eq (1+$stopped) -and $null -ne $script:savedRetirement -and
            -not $script:dnsConfigured -and $script:events.Count -eq 0) 'doh-retirement-rechecks-firewall-before-effects'
        Assert-SnapshotRetained $script:journalDigest

        $script:undo.Clear()
        $script:undo.Add($script:savedRetirement)
        $script:retirementRecovery=$true
        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 0 -and $script:serviceStarts -eq $stopped -and
            -not $script:resolverStopped -and -not [IO.File]::Exists($snapshot) -and
            $script:dohFirewallRules.Count -eq 0) 'doh-retirement-firewall-loss-recovers'
    }
    foreach($listenerFailure in @($false,$true)){
        New-DNSCase -ExistingResolver;$script:loopbackAfterServiceStop=$true
        $script:adapters+=@([pscustomobject]@{Status='Down';InterfaceDescription='Hidden fixture adapter';
            InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
        if($listenerFailure){
            $script:finalListenerFailure='::1';$script:refuseListenerWait=$true
            Reject-DNS {Configure-DNS 'doh'} 'Synthetic loopback wait boundary'
            Assert-SnapshotRetained $script:journalDigest
        }else{
            Configure-DNS 'doh'
        }
        Assert-DNS ($script:serviceStops -eq 1 -and $script:serviceStarts -eq 1 -and -not $script:resolverStopped -and
            $script:serviceStartupChanges -eq 0 -and $script:resolverQueries -eq 1 -and $script:finalListenerQueries.Count -gt 0 -and
            $script:finalListenerQueries[0] -ceq '::1' -and $script:dnsConfigured -eq (-not $listenerFailure)) 'doh-restarts-listener-for-post-stop-dependency'
    }
    New-DNSCase -ExistingResolver;$script:postRetirementFault='late-dependency'
    $script:adapters+=@([pscustomobject]@{Status='Down';InterfaceDescription='Hidden fixture adapter';
        InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
    Configure-DNS 'doh'
    Assert-DNS ($script:serviceStops -eq 1 -and $script:serviceStarts -eq 1 -and -not $script:resolverStopped -and
        $script:serviceStartupChanges -eq 0 -and $script:postRetirementQueries -eq 1 -and
        ($script:finalListenerQueries -join ',') -ceq '::1' -and $script:dnsConfigured) 'doh-preserves-listener-needed-during-probe'
    foreach($fault in @('empty','policy','server','service')){
        New-DNSCase -ExistingResolver;$script:postRetirementFault=$fault
        $expected=switch($fault){
            'empty' {'DoH resolver verification failed after stopping DNSCrypt'}
            'policy' {'Configured DoH policy changed after stopping DNSCrypt'}
            'server' {'Configured DNS servers differ'}
            'service' {'DNSCrypt service manual startup or stopped state could not be verified'}
        }
        Reject-DNS {Configure-DNS 'doh'} $expected
        Assert-SnapshotRetained $script:journalDigest
        Assert-DNS ($script:serviceStops -eq 1 -and $script:serviceStartupChanges -eq [int]($fault -ceq 'service') -and
            $script:postRetirementQueries -ge 1 -and $script:journalActive -and
            -not $script:dnsConfigured -and $script:events.Count -eq 0) 'doh-verifies-after-stopping-dnscrypt'
    }
    New-DNSCase -ExistingResolver
    $script:failRetirementJournal=$true
    Reject-DNS {Configure-DNS 'doh'} 'Fixture retirement journal write failed'
    Assert-DNS ($script:serviceStops -eq 0 -and -not $script:resolverStopped -and -not $script:undo[0].dnscryptRetirement) 'dnscrypt-retirement-journal-before-stop'

    foreach($fault in @('failed-query','failed-service-readback')){
        New-DNSCase -ExistingResolver
        $script:postRetirementFault=if($fault -ceq 'failed-query'){'empty'}else{'service'}
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS ($script:resolverStopped -and $script:serviceStops -eq 1 -and $script:savedRetirement.dnscryptRetirement.startup -ceq 'Automatic') 'dnscrypt-retirement-journal-before-stop'

        # Recover using the serialized observation after the original worker exits.
        $script:undo.Clear()
        $script:undo.Add($script:savedRetirement)
        $script:retirementRecovery=$true
        $script:resolverReadbackFault=''
        $script:restartRecoveryFault='start'
        $configured=(Mutation-Count)
        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 1 -and $errors[0] -ceq 'Synthetic original DNSCrypt startup failure' -and
            (Mutation-Count) -eq $configured -and $script:resolverStopped -and [IO.File]::Exists($snapshot) -and
            [IO.File]::Exists($copyPath)) 'dnscrypt-retirement-retry-keeps-snapshot'

        $script:restartRecoveryFault=''
        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 0 -and -not $script:resolverStopped -and $script:serviceStarts -eq 2 -and
            (-not $script:expectedResolverStartup -or $script:expectedResolverStartup -ceq 'Automatic') -and
            -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($copyPath) -and $script:receiptDigest -ceq $script:undo[0].snapshotSHA256) 'dnscrypt-retirement-retry-restores-service'

        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 0 -and $script:serviceStarts -eq 2) 'dnscrypt-retirement-retry-restores-service'
    }

    New-DNSCase -ExistingResolver
    Configure-DNS 'doh'
    $script:retirementRecovery=$true
    $script:undo.Clear()
    $script:undo.Add($script:savedRetirement)
    [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),'independent resolver configuration')
    $configured=(Mutation-Count)
    $errors=@(Rollback)
    Assert-DNS ($errors.Count -eq 1 -and $errors[0].StartsWith('DNSCrypt configuration changed after publication') -and
        (Mutation-Count) -eq $configured -and $script:serviceStarts -eq 0 -and
        $script:expectedResolverStartup -ceq 'Manual' -and [IO.File]::Exists($snapshot)) 'dnscrypt-retirement-refuses-drift'

    foreach($transition in @('StartPending','StopPending')){
        New-DNSCase -ExistingResolver
        Configure-DNS 'doh'
        $script:undo.Clear()
        $script:undo.Add($script:savedRetirement)
        $script:retirementRecovery=$true
        $script:serviceTransition.Enqueue($transition)
        $script:serviceTransition.Enqueue($(if($transition -ceq 'StartPending'){'Running'}else{'Stopped'}))
        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 0 -and $script:serviceTransitionRefreshes -eq 1 -and
            $script:serviceStarts -eq [int]($transition -ceq 'StopPending') -and
            -not $script:resolverStopped -and -not [IO.File]::Exists($snapshot)) 'dnscrypt-retirement-transition-recovers'
    }
    foreach($fault in @('binding','snapshot')){
        New-DNSCase -ExistingResolver
        Configure-DNS 'doh'
        $configured=(Mutation-Count)
        $script:undo.Clear()
        $script:undo.Add($script:savedRetirement)
        $script:retirementRecovery=$true
        $script:serviceTransitionFault=$fault
        $script:serviceTransition.Enqueue('StartPending')
        $script:serviceTransition.Enqueue('Running')
        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 1 -and $script:serviceTransitionRefreshes -eq 1 -and
            $script:serviceStartupChanges -eq 1 -and $script:serviceStarts -eq 0 -and
            (Mutation-Count) -eq $configured -and [IO.File]::Exists($snapshot)) 'dnscrypt-retirement-transition-drift-refused'
    }
    & {
        $inertService=[pscustomobject]@{Waits=0}
        $inertService | Add-Member ScriptMethod WaitForStatus {
            param($State,[TimeSpan]$Limit)
            if($State -cne 'Stopped' -or $Limit.TotalSeconds -ne 20){throw 'Unexpected recorded service wait'}
            $this.Waits++
        }
        function Get-Service {
            [CmdletBinding()]param($Name)
            if($Name -cne 'AccessWeaver-dnscrypt' -or $ErrorActionPreference -ne 'Stop'){
                throw 'Unexpected recorded service lookup'
            }
            return $inertService
        }
        Wait-RecordedServiceStopped 'AccessWeaver-dnscrypt'
        Assert-DNS ($inertService.Waits -eq 1) 'recorded-service-wait-uses-service-provider'
    }
    $pendingService=[pscustomobject]@{Status='StopPending'}
    Reject-DNS {Wait-DNSCryptServiceTransition $pendingService 0} 'DNSCrypt service transition did not finish'
    Assert-DNS ($pendingService.Status -ceq 'StopPending') 'dnscrypt-service-transition-timeout'

    foreach($fault in @('still-running','still-auto','command','changed-binding')){
        New-DNSCase -ExistingResolver
        if($fault -ceq 'changed-binding'){
            $script:resolverBindingFailureRead=3
            Reject-DNS {Configure-DNS 'doh'} 'Fixture DNS service identity changed'
        }else{
            $script:resolverReadbackFault=$fault
            $expected=if($fault -ceq 'command'){'DNSCrypt service identity changed'}else{'DNSCrypt service manual startup or stopped state could not be verified'}
            Reject-DNS {Configure-DNS 'doh'} $expected
        }
        $hash=Snapshot-Hash;Assert-SnapshotRetained $hash
        $expectedStartupWrites=[int]($fault -cne 'changed-binding')
        Assert-DNS ($script:resolverQueries -eq 2 -and $script:serviceStops -eq 1 -and
            $script:serviceStartupChanges -eq $expectedStartupWrites -and
            $script:resolverReadbacks -eq $expectedStartupWrites -and -not $script:dnsConfigured) 'doh-keeps-old-resolver-until-verified'
    }
    foreach($dependency in @('effective','stored','unreadable')){
        New-DNSCase;$script:resolverServicePresent=$true;$script:stageDNSCrypt=$true
        $inactiveGuid='{00000000-0000-0000-0000-000000000002}'
        $inactive=[pscustomobject]@{Status='Up';InterfaceDescription='Second fixture adapter';InterfaceGuid=$inactiveGuid;ifIndex=88}
        $script:adapters+=@($inactive)
        [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
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
    foreach($location in @('effective','stored','original')){
        New-DNSCase
        $guid='{00000000-0000-0000-0000-000000000002}'
        $script:adapters+=@([pscustomobject]@{Status='Down';InterfaceDescription='Hidden fixture adapter';InterfaceGuid=$guid;ifIndex=88})
        $records=@()
        switch($location){
            'effective' {$script:dnsValues['88/IPv6']=@('::ffff:127.7.8.9')}
            'stored' {$script:storedDNS[$guid+'/IPv6']='::ffff:127.7.8.9'}
            'original' {
                $records=@(@{guid=$guid;index=88;ipv4=@();ipv6=@('::ffff:127.7.8.9');
                    dhcp4=$false;dhcp6=$false;bound4=$false;bound6=$true})
            }
        }
        Assert-DNS (Test-DNSCryptListenerNeeded $records) 'dnscrypt-loopback-mapped-ipv4'
    }
    foreach($location in @('effective','stored')){
        New-DNSCase;$script:resolverServicePresent=$true
        $script:adapters+=@([pscustomobject]@{Status='Down';InterfaceDescription='Hidden fixture adapter';
            InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
        $script:lateLoopbackDNS=$location
        Configure-DNS 'doh'
        Assert-DNS ($script:dnsConfigured -and $script:hiddenInventoryReads -eq 2 -and
            $script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0) 'dnscrypt-dependency-change-stable-adapter'
    }
    foreach($drift in @('loopback','new-family')){
        New-DNSCase;$script:resolverServicePresent=$true
        $script:adapters+=@([pscustomobject]@{Status='Down';InterfaceDescription='Hidden fixture adapter';
            InterfaceGuid='{00000000-0000-0000-0000-000000000002}';ifIndex=88})
        if($drift -ceq 'new-family'){
            $script:exposure['88/IPv6']=$false
            $script:unexposedKeyStates['88/IPv6']='missing'
        }
        $script:finalDependencyDrift=$drift
        Configure-DNS 'doh'
        Assert-DNS ($script:dnsConfigured -and $script:hiddenInventoryReads -eq 2 -and
            $script:serviceStops -eq 0 -and $script:serviceStartupChanges -eq 0) 'dnscrypt-dependency-change-stable-adapter'
    }
    foreach($family in @('IPv4','IPv6')){
        foreach($state in @('stored-loopback','absent-key','unreadable')){
            New-DNSCase -ExistingResolver
            $guid='{00000000-0000-0000-0000-000000000002}'
            $script:adapters+=@([pscustomobject]@{Status='Down';InterfaceDescription='Hidden fixture adapter';InterfaceGuid=$guid;ifIndex=88})
            $key='88/'+$family
            $script:exposure[$key]=$false
            if($state -ceq 'stored-loopback'){
                $script:unexposedKeyStates[$key]='present'
                $script:storedDNS[$guid+'/'+$family]=if($family -ceq 'IPv4'){'127.0.0.2'}else{'0:0:0:0:0:0:0:1'}
            }elseif($state -ceq 'absent-key'){
                $script:unexposedKeyStates[$key]='missing'
            }
            Configure-DNS 'doh'
            $retire=$state -ceq 'absent-key'
            $code=if($retire){'doh-retires-listener-with-confirmed-absent-unexposed-key'}else{'doh-keeps-listener-for-stored-unexposed-family'}
            Assert-DNS ($script:dnsConfigured -and $script:serviceStops -eq [int]$retire -and
                $script:serviceStartupChanges -eq [int]$retire) $code
        }
    }
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
        [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        if($failureRead){
            Reject-DNS {Configure-DNS 'dnscrypt'}
            Assert-DNS ($script:resolverBindingReads -eq 2 -and $script:serviceRestarts -eq 0 -and
                $script:serviceStartupChanges -eq 0 -and (Mutation-Count) -eq 0) 'dns-service-binding-before-mutation'
        }else{
            Configure-DNS 'dnscrypt'
            Assert-DNS ($script:resolverBindingReads -eq 4 -and $script:dnscryptConfigReads -eq 6 -and
                $script:dnscryptConfigWrites -eq 1 -and $script:serviceRestarts -eq 1 -and
                $script:serviceStartupChanges -eq 1 -and $script:dnsConfigured) 'dnscrypt-restarts-verified-service'
        }
        [IO.File]::Delete((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'))
    }
    foreach($phase in @('not-replaced','replaced')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        $original="listen_addresses = ['192.0.2.53:53']"
        [IO.File]::WriteAllText($path,$original)
        $script:configPublicationInterruption=$phase
        Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic DNSCrypt publication interruption'
        Assert-DNS ($script:serviceRestarts -eq 0 -and (Mutation-Count) -eq 0 -and
            ([IO.File]::ReadAllText($path) -cne $original) -eq ($phase -ceq 'replaced')) 'dnscrypt-reload-durable-before-publication'

        # A fresh worker sees the last durable journal after file replacement,
        # before the publisher can promote pendingHash to expectedHash.
        $script:undo.Clear()
        foreach($entry in $script:configPublicationJournal){$script:undo.Add($entry)}
        $record=@($script:undo | Where-Object {$_.kind -ceq 'file'})[0]
        $pending=$record.pendingHash
        $record.pendingHash='invalid'
        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 1 -and $errors[0] -ceq 'DNSCrypt configuration recovery contains an invalid pending digest' -and
            $script:serviceRestarts -eq 0 -and [IO.File]::Exists($snapshot)) 'dnscrypt-reload-invalid-pending-hash'
        $record.pendingHash=$pending
        if($phase -ceq 'replaced'){
            $script:serviceTransition.Enqueue('StartPending')
            $script:serviceTransition.Enqueue('Running')
        }

        $errors=@(Rollback)
        Assert-DNS ($errors.Count -eq 0 -and $script:serviceRestarts -eq 1 -and
            $script:serviceTransitionRefreshes -eq [int]($phase -ceq 'replaced') -and
            [IO.File]::ReadAllText($path) -ceq $original -and -not [IO.File]::Exists($snapshot)) 'dnscrypt-reload-recovers-pending-publication'
    }
    New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
    $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
    $original="listen_addresses = ['192.0.2.53:53']"
    [IO.File]::WriteAllText($path,$original)
    $script:failReloadJournal=$true
    Reject-DNS {Configure-DNS 'dnscrypt'} 'Fixture reload journal write failed'
    Assert-DNS ($script:dnscryptConfigWrites -eq 0 -and $script:serviceRestarts -eq 0 -and
        [IO.File]::ReadAllText($path) -ceq $original -and (Mutation-Count) -eq 0) 'dnscrypt-reload-preflight-preserves-original'

    foreach($initiallyStopped in @($false,$true)){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $script:resolverStopped=$initiallyStopped
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
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
    foreach($fault in @('start','listener','startup-policy')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true;$script:resolverStopped=$true
        $script:failChangedConfigStart=$fault -ceq 'start'
        $script:failResolverStartupWrite=$fault -ceq 'startup-policy'
        if($fault -ceq 'listener'){
            $script:listenerReplies['::1']=[Collections.Generic.Queue[string]]::new()
            $script:listenerReplies['::1'].Enqueue('timeout')
            $script:refuseListenerWait=$true
        }
        # Retain the live adapter's existing loopback configuration when
        # activation fails before any adapter changes are admitted.
        $script:mode4='127.0.0.1';$script:dnsValues['77/IPv4']=@('127.0.0.1')
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        $original="server_names = ['google']`r`nlisten_addresses = ['127.0.0.1:53']`r`n"
        $script:restartRecoveryOriginal=[Text.UTF8Encoding]::new($false).GetBytes($original)
        [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
        $expected=switch($fault){
            'start' {'Synthetic changed DNSCrypt startup failure'}
            'listener' {'Synthetic loopback wait boundary'}
            'startup-policy' {'Synthetic DNSCrypt startup write failure'}
        }
        Reject-DNS {Configure-DNS 'dnscrypt'} $expected
        $failedStart=[int]($fault -ceq 'start')
        Assert-DNS ($script:serviceStarts -eq (1+$failedStart) -and $script:serviceRestarts -eq (1-$failedStart) -and
            -not $script:resolverStopped -and $script:restartRecoveryWrites -eq 1 -and
            [IO.File]::ReadAllText($path) -ceq $original -and $script:mode4 -ceq '127.0.0.1' -and
            (Mutation-Count) -eq 0 -and $script:resolverQueries -eq 0 -and -not $script:dnsConfigured -and
            $script:journalActive -and (Snapshot-Hash) -ceq $script:journalDigest) 'dnscrypt-recovers-original-after-stopped-activation-failure'
    }
    foreach($fault in @('write','mode','state','late-mode')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $script:resolverReadbackFault=$fault
        $script:failResolverStartupWrite=$fault -ceq 'write'
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        $original="listen_addresses = ['192.0.2.53:53']"
        $script:restartRecoveryOriginal=[Text.UTF8Encoding]::new($false).GetBytes($original)
        [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
        $expected=if($fault -ceq 'write'){'Synthetic DNSCrypt startup write failure'}else{'DNSCrypt service automatic startup or running state could not be verified'}
        Reject-DNS {Configure-DNS 'dnscrypt'} $expected
        $late=[int]($fault -ceq 'late-mode')
        Assert-DNS ($script:serviceStartupChanges -eq 1 -and $script:resolverReadbacks -eq ([int]($fault -cne 'write')+$late) -and
            (Mutation-Count) -eq (4*$late) -and $script:resolverQueries -eq $late -and
            $script:serviceRestarts -eq 2 -and $script:restartRecoveryWrites -eq 1 -and
            [IO.File]::ReadAllText($path) -ceq $original -and
            $script:journalActive -and
            $(if($late){$script:receiptDigest -ceq $script:journalDigest -and -not [IO.File]::Exists($snapshot)}else{(Snapshot-Hash) -ceq $script:journalDigest}) -and
            -not $script:dnsConfigured) 'dnscrypt-listeners-before-adapters'
    }
    foreach($fault in @('','file','start','binding')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true;$script:failDNSCryptRestart=$true
        $script:restartRecoveryFault=$fault
        if($fault -ceq 'binding'){$script:resolverBindingFailureRead=4}
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        $original="listen_addresses = ['192.0.2.53:53']"
        $script:restartRecoveryOriginal=[Text.UTF8Encoding]::new($false).GetBytes($original)
        [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
        $expected=if($fault){'DNSCrypt activation failed and the original service could not be recovered'}else{'Synthetic DNSCrypt service restart failure'}
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
        $target=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        $source=if($existingConfig){$target}else{Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'}
        [IO.File]::WriteAllText($source,"listen_addresses = ['192.0.2.53:53']")
        $script:changeDNSCryptBeforePublish=$true
        Reject-DNS {Configure-DNS 'dnscrypt'} 'Workflow files changed before replacement'
        Assert-DNS ([IO.File]::ReadAllText($target) -ceq 'independent configuration' -and
            $script:dnscryptConfigWrites -eq 0 -and $script:serviceRestarts -eq 0 -and
            (Mutation-Count) -eq 0) 'dns-service-binding-before-mutation'
    }
    foreach($stage in @('publish','listener','ordinary-probe')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true;$script:changeDNSCryptAfter=$stage
        $target=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        [IO.File]::WriteAllText($target,"listen_addresses = ['192.0.2.53:53']")
        $expected=switch($stage){
            'publish' {'DNSCrypt configuration changed after publication'}
            'ordinary-probe' {'DNSCrypt configuration differs from the recorded activation'}
            default {'DNSCrypt activation failed and the original service could not be recovered'}
        }
        Reject-DNS {Configure-DNS 'dnscrypt'} $expected
        $writes=if($stage -ceq 'ordinary-probe'){2}else{0}
        $preserved=if($stage -ceq 'publish'){-not [IO.File]::Exists($target)}else{
            [IO.File]::ReadAllText($target) -ceq 'independent configuration'
        }
        Assert-DNS ($preserved -and $script:serviceRestarts -eq [int]($stage -cne 'publish') -and
            $script:serviceStartupChanges -eq [int]($stage -ceq 'ordinary-probe') -and (Mutation-Count) -eq $writes -and
            (-not $script:receiptDigest -and $script:journalDigest -ceq (Snapshot-Hash)) -and
            -not $script:dnsConfigured) 'dns-service-binding-before-mutation'
    }
    foreach($transition in @('dnscrypt-only','dnscrypt-to-doh','doh-to-dnscrypt')){
        New-DNSCase
        $script:stageDNSCrypt=$true
        $script:resolverServicePresent=$true
        [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
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
            Assert-DNS ($script:dohFirewallRules.Count -eq 0) 'dnscrypt-clears-doh-firewall'
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
    New-DNSCase;$script:emptyOrdinaryAnswers=1;$script:cacheFlushFault='unavailable'
    Configure-DNS 'doh'
    Assert-DNS ($script:cacheFlushes -eq 0 -and $script:resolverQueries -eq 2 -and $script:resolverAAAAQueries -eq 1 -and
        $script:ordinaryResolverWaits -eq 1 -and $script:dnsConfigured) 'ordinary-resolver-requires-address-answer'
    New-DNSCase;$script:emptyOrdinaryAAAAAnswers=1
    Configure-DNS 'doh'
    Assert-DNS ($script:resolverQueries -eq 2 -and $script:resolverAAAAQueries -eq 2 -and
        $script:ordinaryResolverWaits -eq 1 -and $script:dnsConfigured) 'ordinary-resolver-retries-missing-aaaa'
    foreach($fault in @('wrong-name','wrong-type','authority','ipv4','mapped-ipv4')){
        New-DNSCase;$script:ordinaryAAAAFault=$fault
        Assert-DNS (-not (Wait-OrdinaryDNSResolver 0) -and $script:resolverQueries -eq 1 -and
            $script:resolverAAAAQueries -eq 1) 'ordinary-resolver-rejects-invalid-aaaa'
    }
    New-DNSCase;$script:emptyOrdinaryAAAAAnswers=1
    & {
        $probe=${function:Wait-OrdinaryDNSResolver}
        function Wait-OrdinaryDNSResolver([int]$TimeoutSeconds,[string]$DohProtectionID,$DNSCryptListener) {
            Assert-DNS ($TimeoutSeconds -eq 90) 'configure-restores-when-aaaa-is-missing'
            & $probe 0 -DohProtectionID $DohProtectionID -DNSCryptListener $DNSCryptListener
        }
        Reject-DNS {Configure-DNS 'doh'} 'Resolver verification failed; original DNS settings restored'
    }
    $restored=$script:appliedDNS[([string]$script:adapters[0].InterfaceGuid)+'/IPv4']
    Assert-DNS ($script:resolverQueries -eq 1 -and $script:resolverAAAAQueries -eq 1 -and
        -not $script:dnsConfigured -and -not [IO.File]::Exists($snapshot) -and $script:receiptDigest -and
        ($restored.values -join ',') -ceq '192.0.2.53' -and $script:currentDoh.Count -eq 0) 'configure-restores-when-aaaa-is-missing'
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
    [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
    Reject-DNS {Configure-DNS 'dnscrypt'} 'Adapter DNS settings changed independently'
    Assert-DNS ($script:resolverQueries -eq 1 -and -not $script:dnsConfigured -and $script:events.Count -eq 0 -and
        $script:serviceRestarts -eq 1 -and $script:restartRecoveryWrites -eq 0 -and
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
    foreach($invalidReply in @('timeout','empty','wrong-name','wrong-type','authority','ipv4','mapped-ipv4')){
        New-DNSCase
        $script:listenerAAAAFault=$invalidReply
        Reject-DNS {Wait-DNSCryptListeners @('::1') -TimeoutSeconds 0 -RequireBothAddressTypes}
        Assert-DNS (($script:listenerQueries -join ',') -ceq '::1' -and
            ($script:listenerAAAAQueries -join ',') -ceq '::1') 'dnscrypt-listener-refuses-invalid-aaaa'
    }
    foreach($type in @(1,28)){
        $name=[byte[]](7,101,120,97,109,112,108,101,3,110,101,116,0)
        $query=[byte[]](@(12,34,1,0,0,1,0,0,0,0,0,0)+$name+@(0,$type,0,1))
        $address=if($type -eq 1){[Net.IPAddress]::Parse('192.0.2.15')}else{[Net.IPAddress]::Parse('2001:db8::15')}
        $rdata=$address.GetAddressBytes()
        $answer=[byte[]](@(0,$type,0,1,0,0,0,30,0,$rdata.Length)+$rdata)
        $reply=[byte[]]($query+@(192,12)+$answer)
        $reply[2]=129;$reply[3]=128;$reply[7]=1
        Assert-DNS (Test-DNSCryptProbeReply $reply $query $type) 'dnscrypt-udp-compressed-positive'
        $plain=[byte[]]($reply[0..($query.Length-1)]+$name+$answer)
        Assert-DNS (Test-DNSCryptProbeReply $plain $query $type) 'dnscrypt-udp-uncompressed-positive'
        foreach($fault in @('id','truncated','rcode','question-type','authority','unrelated','rdata','mapped','pointer','trailing')){
            $bad=$reply.Clone()
            switch -CaseSensitive ($fault){
                'id' {$bad[1]=35}
                'truncated' {$bad[2]=131}
                'rcode' {$bad[3]=131}
                'question-type' {$bad[$query.Length-3]=16}
                'authority' {$bad[7]=0;$bad[9]=1}
                'unrelated' {$bad=$plain.Clone();$bad[$query.Length+1]=120}
                'rdata' {$bad=[byte[]]$bad[0..($bad.Length-2)]}
                'mapped' {
                    if($type -eq 1){continue}
                    [array]::Copy(([Net.IPAddress]::Parse('::ffff:192.0.2.15').GetAddressBytes()),0,$bad,$bad.Length-16,16)
                }
                'pointer' {$bad[$query.Length+1]=$query.Length}
                'trailing' {$bad=[byte[]]($bad+@(0))}
            }
            if($fault -ceq 'mapped' -and $type -eq 1){continue}
            $accepted=$false
            try {$accepted=Test-DNSCryptProbeReply $bad $query $type}catch{
                if($fault -cne 'pointer' -or $_.Exception.Message -cne 'Malformed DNSCrypt probe name'){throw}
            }
            Assert-DNS (-not $accepted) ('dnscrypt-udp-rejects-'+$fault)
        }
    }
    New-DNSCase;$script:cacheFlushFault='unavailable'
    Wait-DNSCryptListeners @('127.0.0.1','::1') -TimeoutSeconds 0 -RequireBothAddressTypes -RequireBothTransports
    Assert-DNS ($script:cacheFlushes -eq 0 -and ($script:listenerTransports -join ',') -ceq 'UDP/127.0.0.1/A,TCP/127.0.0.1/A,UDP/127.0.0.1/AAAA,TCP/127.0.0.1/AAAA,UDP/::1/A,TCP/::1/A,UDP/::1/AAAA,TCP/::1/AAAA') 'dnscrypt-requires-both-transports-on-each-loopback'
    New-DNSCase;$script:listenerUDPFault='::1/AAAA'
    Reject-DNS {Wait-DNSCryptListeners @('::1') -TimeoutSeconds 0 -RequireBothAddressTypes -RequireBothTransports}
    Assert-DNS (($script:listenerTransports -join ',') -ceq 'UDP/::1/A,TCP/::1/A,UDP/::1/AAAA') 'dnscrypt-tcp-cannot-mask-udp-failure'
    New-DNSCase
    Wait-DNSCryptListeners @('::1') -TimeoutSeconds 0
    Assert-DNS ($script:listenerTransports.Count -eq 0 -and $script:listenerQueries.Count -eq 1 -and
        $script:listenerAAAAQueries.Count -eq 0) 'dnscrypt-recovery-retains-a-only-probe'
    foreach($reason in @('foreign','shared','wrong-image','bind-failure','duplicate')){
        New-DNSCase
        $script:sharingMode=$reason
        $wildcard=[pscustomobject]@{LocalPort=[uint16]53;LocalAddress='0.0.0.0';OwningProcess=[uint32]4242}
        $script:DNSCryptPortRows.MSFT_NetUDPEndpoint=if($reason -ceq 'duplicate'){@($wildcard,$wildcard)}else{$wildcard}
        if($reason -ceq 'bind-failure'){$script:sharingBindFailure='::1'}
        Reject-DNS {Assert-DNSCryptLoopbackPortsAvailable} 'DNSCrypt requires TCP and UDP port 53'
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0) 'dnscrypt-sharing-admits-only-verified-service'
    }
    foreach($mode in @('stable','changed','challenge-failed')){
        New-DNSCase
        $script:stageDNSCrypt=$true;$script:allowNewResolver=$true
        $script:sharingMode=$mode;$script:sharingChallengeFailure=$mode -ceq 'challenge-failed'
        $script:DNSCryptPortRows.MSFT_NetUDPEndpoint=[pscustomobject]@{LocalPort=[uint16]53;LocalAddress='0.0.0.0';OwningProcess=[uint32]4242}
        $directory=Join-Path $root 'components\dnscrypt'
        $config=Join-Path $directory 'dnscrypt-proxy.toml'
        [IO.File]::WriteAllText((Join-Path $directory 'example-dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        if($mode -ceq 'changed'){
            Reject-DNS {Configure-DNS 'dnscrypt'} 'DNSCrypt port ownership changed during setup'
            Assert-DNS (-not $script:sharingProbePath -and -not $script:newResolverRegistered -and
                (Mutation-Count) -eq 0) 'dnscrypt-sharing-renewal-stops-setup'
        }elseif($mode -ceq 'challenge-failed'){
            $script:refuseListenerWait=$true
            Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic loopback wait boundary'
            Assert-DNS ($script:sharingProbeReads -eq 1 -and $script:sharingProbePath -and
                [IO.File]::Exists($script:sharingProbePath) -and (Mutation-Count) -eq 0) 'dnscrypt-sharing-challenge-failure-blocks-adapter-writes'
            $record=@($script:undo | Where-Object {$_.path -ceq $script:sharingProbePath})
            Assert-DNS ($record.Count -eq 1 -and $record[0].kind -ceq 'file' -and
                $record[0].expectedHash -ceq (Get-FileHash -LiteralPath $script:sharingProbePath -Algorithm SHA256).Hash) 'dnscrypt-sharing-challenge-recovery'
            $errors=@(Rollback)
            Assert-DNS ($errors.Count -eq 0 -and -not [IO.File]::Exists($script:sharingProbePath)) 'dnscrypt-sharing-challenge-recovery'
        }else{
            Configure-DNS 'dnscrypt'
            Assert-DNS ($script:dnsConfigured -and $script:sharingProbeReads -eq 2 -and
                ($script:sharingBinds -join ',') -ceq '127.0.0.1,::1,127.0.0.1,::1' -and
                $script:sharingProbePath -and [IO.File]::Exists($script:sharingProbePath)) 'dnscrypt-sharing-binds-owned-challenge'
            $configuration=[IO.File]::ReadAllText($config)
            $probe=Get-DNSCryptSharingProbe $configuration $directory ''
            Assert-DNS (-not $probe.create -and $probe.path -ceq $script:sharingProbePath) 'dnscrypt-sharing-reuses-owned-challenge'
            [IO.File]::AppendAllText($script:sharingProbePath,'tampered')
            Reject-DNS {Get-DNSCryptSharingProbe $configuration $directory ''} 'DNSCrypt loopback challenge file changed independently'
        }
    }
    New-DNSCase
    $label='accessweaver-'+('a'*32)
    $query=[byte[]](@(12,34,0,0,0,1,0,0,0,0,0,0,$label.Length)+[Text.Encoding]::ASCII.GetBytes($label)+
        @(7)+[Text.Encoding]::ASCII.GetBytes('invalid')+@(0,0,1,0,1))
    $reply=[byte[]]($query+@(192,12,0,1,0,1,0,0,0,30,0,4,192,0,2,42))
    $reply[2]=128;$reply[7]=1
    Assert-DNS ((Test-DNSCryptProbeReply $reply $query 1 ($label+'.invalid') '192.0.2.42') -and
        -not (Test-DNSCryptProbeReply $reply $query 1 ($label+'.invalid') '192.0.2.43') -and
        -not (Test-DNSCryptProbeReply $reply $query 1 ('accessweaver-'+('b'*32)+'.invalid') '192.0.2.42')) 'dnscrypt-sharing-challenge-needs-exact-answer'
    foreach($conflict in @(
        @{class='MSFT_NetUDPEndpoint';address='0.0.0.0'},
        @{class='MSFT_NetTCPConnection';address='::'},
        @{class='MSFT_NetUDPEndpoint';address='::ffff:127.0.0.1'},
        @{class='MSFT_NetTCPConnection';address='::1'}
    )){
        New-DNSCase
        $script:DNSCryptPortRows[$conflict.class]=[pscustomobject]@{LocalPort=[uint16]53;LocalAddress=$conflict.address}
        Reject-DNS {Configure-DNS 'dnscrypt'} 'DNSCrypt requires TCP and UDP port 53'
        Assert-DNS ($script:dnsOperationStage -ceq 'configuration-port-in-use' -and
            -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($script:copyPath) -and
            -not $script:journalActive -and -not $script:newResolverRegistered -and (Mutation-Count) -eq 0) 'dnscrypt-port-conflict-before-mutation'
    }
    foreach($readFailure in @('provider','invalid-address','wrong-port')){
        New-DNSCase
        $script:failDNSCryptPortRead=$readFailure -ceq 'provider'
        if($readFailure -ceq 'invalid-address'){
            $script:DNSCryptPortRows.MSFT_NetTCPConnection=[pscustomobject]@{LocalPort=[uint16]53;LocalAddress='invalid'}
        }elseif($readFailure -ceq 'wrong-port'){
            $script:DNSCryptPortRows.MSFT_NetUDPEndpoint=[pscustomobject]@{LocalPort=[uint16]54;LocalAddress='127.0.0.1'}
        }
        Reject-DNS {Configure-DNS 'dnscrypt'} 'DNSCrypt could not inspect local port 53 before setup'
        Assert-DNS ($script:dnsOperationStage -ceq 'configuration-port-inventory' -and
            -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($script:copyPath) -and
            -not $script:journalActive -and -not $script:newResolverRegistered -and (Mutation-Count) -eq 0) 'dnscrypt-unreadable-port-before-mutation'
    }

    New-DNSCase;$script:stageDNSCrypt=$true;$script:allowNewResolver=$true;$script:portConflictOnStaging=$true
    $example=Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'
    $config=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
    [IO.File]::WriteAllText($example,"listen_addresses = ['192.0.2.53:53']")
    Reject-DNS {Configure-DNS 'dnscrypt'} 'DNSCrypt requires TCP and UDP port 53'
    Assert-DNS ($script:dnsOperationStage -ceq 'configuration-port-in-use' -and
        @($script:DNSCryptPortReads | Where-Object {$_ -ceq 'MSFT_NetUDPEndpoint'}).Count -eq 2 -and
        -not [IO.File]::Exists($config) -and -not $script:newResolverRegistered -and
        $script:serviceStartupChanges -eq 0 -and $script:resolverQueries -eq 0 -and (Mutation-Count) -eq 0) 'dnscrypt-port-drift-before-service'
    Assert-SnapshotRetained $script:journalDigest
    $errors=@(Rollback)
    Assert-DNS ($errors.Count -eq 0 -and (Mutation-Count) -eq 0 -and
        -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($copyPath)) 'dnscrypt-port-drift-recovers'

    New-DNSCase;$script:stageDNSCrypt=$true;$script:allowNewResolver=$true
    $script:DNSCryptPortRows.MSFT_NetUDPEndpoint=[pscustomobject]@{LocalPort=[uint16]53;LocalAddress='192.0.2.53'}
    $script:listenerAAAAFault='empty';$script:refuseListenerWait=$true
    [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
    Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic loopback wait boundary'
    Assert-DNS ($script:DNSCryptPortReads.Count -eq 4 -and
        @($script:DNSCryptPortReads | Where-Object {$_ -ceq 'MSFT_NetTCPConnection'}).Count -eq 2 -and
        @($script:DNSCryptPortReads | Where-Object {$_ -ceq 'MSFT_NetUDPEndpoint'}).Count -eq 2) 'dnscrypt-port-inventory-observed'
    Assert-DNS (($script:listenerAAAAQueries -join ',') -ceq '127.0.0.1,::1' -and
        (Mutation-Count) -eq 0 -and $script:serviceStartupChanges -eq 0 -and $script:resolverQueries -eq 0 -and
        $script:journalActive -and -not $script:dnsConfigured) 'dnscrypt-listener-refuses-missing-aaaa-before-adapters'

    New-DNSCase;$script:stageDNSCrypt=$true;$script:allowNewResolver=$true
    $script:listenerUDPFault='127.0.0.1/A';$script:refuseListenerWait=$true
    [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
    Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic loopback wait boundary'
    Assert-DNS (($script:listenerTransports -contains 'UDP/127.0.0.1/A') -and
        ($script:listenerTransports -notcontains 'TCP/127.0.0.1/A') -and (Mutation-Count) -eq 0 -and
        $script:serviceStartupChanges -eq 0 -and $script:resolverQueries -eq 0 -and
        $script:journalActive -and -not $script:dnsConfigured) 'dnscrypt-udp-failure-blocks-adapter-mutation'

    New-DNSCase;$script:stageDNSCrypt=$true;$script:allowNewResolver=$true
    $script:listenerAAAAFault='once'
    [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
    Configure-DNS 'dnscrypt'
    Assert-DNS (($script:listenerAAAAQueries -join ',') -ceq '127.0.0.1,::1,127.0.0.1,::1' -and
        ($script:finalListenerAAAAQueries -join ',') -ceq '127.0.0.1,::1' -and
        $script:listenerWaits -eq 1 -and $script:dnsConfigured) 'dnscrypt-listener-retries-missing-aaaa'

    foreach($fault in @('none','listener','binding','mode','state','command','missing','late-mode')){
        New-DNSCase
        $script:stageDNSCrypt=$true;$script:allowNewResolver=$true
        [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
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
        [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
        if($family -ceq 'IPv4'){$script:exposure['77/IPv6']=$false}
        if($family -ceq 'IPv6'){$script:exposure['77/IPv4']=$false}
        if($family -cin @('both','failure')){
            $script:listenerReplies['::1']=[Collections.Generic.Queue[string]]::new()
            $script:listenerReplies['::1'].Enqueue('timeout')
            $script:listenerReplies['::1'].Enqueue('answer')
        }
        if($family -ceq 'failure'){
            $script:refuseListenerWait=$true
            $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
            $script:restartRecoveryOriginal=[IO.File]::ReadAllBytes($path)
            Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic loopback wait boundary'
            Assert-DNS ((Mutation-Count) -eq 0 -and $script:resolverQueries -eq 0 -and $script:journalActive -and
                $script:serviceStartupChanges -eq 0 -and [IO.File]::Exists($snapshot) -and
                $script:serviceRestarts -eq 2 -and $script:restartRecoveryWrites -eq 1 -and
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq (Get-WorkflowBytesSHA256 $script:restartRecoveryOriginal) -and
                -not $script:dnsConfigured) 'dnscrypt-listener-refusal-preserves-adapter-state'
        } else {
            Configure-DNS 'dnscrypt'
            $expected=switch($family){'IPv4' {'127.0.0.1'} 'IPv6' {'::1'} 'both' {'127.0.0.1,::1,127.0.0.1,::1'}}
            Assert-DNS ($script:listenerChecksBeforeAdapters -and ($script:listenerQueries -join ',') -ceq $expected -and
                $script:resolverQueries -eq 1 -and $script:dnsConfigured) 'dnscrypt-listeners-before-adapters'
            if($family -ceq 'both'){
                Assert-DNS ($script:listenerWaits -eq 1) 'dnscrypt-listener-rechecks-both-families'
            }
            $finalExpected=switch($family){'IPv4' {'127.0.0.1'} 'IPv6' {'::1'} 'both' {'127.0.0.1,::1'}}
            Assert-DNS (($script:finalListenerQueries -join ',') -ceq $finalExpected) 'dnscrypt-verifies-all-listeners-after-adapter-switch'
        }
    }
    New-DNSCase;$script:stageDNSCrypt=$true;$script:allowNewResolver=$true
    $script:listenerOwnerFault='initial-foreign';$script:refuseListenerWait=$true
    [IO.File]::WriteAllText((Join-Path $root 'components\dnscrypt\example-dnscrypt-proxy.toml'),"listen_addresses = ['192.0.2.53:53']")
    Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic loopback wait boundary'
    Assert-DNS ($script:initialOwnerReads -eq 1 -and $script:listenerQueries.Count -eq 0 -and
        (Mutation-Count) -eq 0 -and $script:serviceStartupChanges -eq 0 -and
        $script:journalActive -and -not $script:dnsConfigured) 'dnscrypt-refuses-unowned-dns-before-adapter-switch'

    foreach($ownerFault in @('final-replaced','final-stable-replacement')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $script:listenerOwnerFault=$ownerFault;$script:refuseListenerWait=$true
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        [IO.File]::WriteAllText($path,"listen_addresses = ['192.0.2.53:53']")
        $script:restartRecoveryOriginal=[IO.File]::ReadAllBytes($path)
        $expected=if($ownerFault -ceq 'final-replaced'){'Synthetic loopback wait boundary'}else{'Managed DNSCrypt listener changed during final resolver verification'}
        Reject-DNS {Configure-DNS 'dnscrypt'} $expected
        Assert-DNS ($script:initialOwnerReads -eq 5 -and $script:finalOwnerReads -eq 4 -and
            ($script:finalListenerAAAAQueries -join ',') -ceq '127.0.0.1,::1' -and
            $script:restartRecoveryWrites -eq 1 -and -not [IO.File]::Exists($snapshot) -and
            -not $script:dnsConfigured) 'dnscrypt-restores-when-listener-owner-changes'
    }

    foreach($boundary in @('between-adapters','before-aaaa')){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $script:listenerOwnerFault=$boundary
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        [IO.File]::WriteAllText($path,"server_names = ['google']`r`nlisten_addresses = ['127.0.0.1:53', '[::1]:53']`r`n",[Text.UTF8Encoding]::new($false))
        Reject-DNS {Configure-DNS 'dnscrypt'} 'Managed DNSCrypt listener changed after startup verification'
        $writes=if($boundary -ceq 'before-aaaa'){2}else{1}
        Assert-DNS ((Mutation-Count) -eq $writes -and $script:dnsOperationStage -ceq 'listener-owner-changed' -and
            $script:resolverQueries -eq [int]($boundary -ceq 'before-aaaa') -and $script:resolverAAAAQueries -eq 0 -and
            $script:finalListenerQueries.Count -eq 0 -and -not $script:dnsConfigured) 'dnscrypt-refuses-replaced-listener-during-cutover'
        Assert-SnapshotRetained $script:journalDigest
        $errors=@(Rollback)
        $restored=$script:appliedDNS[([string]$script:adapters[0].InterfaceGuid)+'/IPv4']
        Assert-DNS ($errors.Count -eq 0 -and ($restored.values -join ',') -ceq '192.0.2.53' -and
            -not [IO.File]::Exists($snapshot) -and -not [IO.File]::Exists($copyPath)) 'dnscrypt-recovers-after-cutover-owner-loss'
    }

    foreach($fault in @('127.0.0.1','::1','AAAA')){
        $failedListener=if($fault -ceq 'AAAA'){'::1'}else{$fault}
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        [IO.File]::WriteAllText($path,"server_names = ['google']`r`nlisten_addresses = ['127.0.0.1:53', '[::1]:53']`r`n",[Text.UTF8Encoding]::new($false))
        if($fault -ceq 'AAAA'){$script:finalListenerMissingAAAA=$failedListener}
        else{$script:finalListenerFailure=$failedListener}
        $script:refuseListenerWait=$true
        Reject-DNS {Configure-DNS 'dnscrypt'} 'Synthetic loopback wait boundary'
        $hash=Snapshot-Hash
        $expectedFinalAAAA=switch($fault){'127.0.0.1' {'::1'} '::1' {'127.0.0.1'} 'AAAA' {'127.0.0.1,::1'}}
        Assert-DNS (($script:listenerQueries -join ',') -ceq '127.0.0.1,::1' -and
            ($script:listenerAAAAQueries -join ',') -ceq '127.0.0.1,::1' -and
            ($script:finalListenerQueries -join ',') -ceq '127.0.0.1,::1' -and
            ($script:finalListenerAAAAQueries -join ',') -ceq $expectedFinalAAAA -and
            $script:resolverQueries -eq 1 -and (Mutation-Count) -eq 2 -and
            $script:journalActive -and $hash -ceq $script:journalDigest -and
            -not $script:dnsConfigured) 'dnscrypt-verifies-all-listeners-after-adapter-switch'
        Restore-DNS $hash
        Assert-DNS ($script:receiptDigest -ceq $hash -and -not [IO.File]::Exists($snapshot)) 'dnscrypt-recovers-after-late-listener-failure'
    }
    # Exercise late failure with a changed configuration and an existing service.
    foreach($restoreFails in @($false,$true)){
        New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
        $script:expectedResolverStartup='Manual'
        $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
        $original="server_names = ['google']`r`nlisten_addresses = ['127.0.0.1:53']`r`n"
        $script:restartRecoveryOriginal=[Text.UTF8Encoding]::new($false).GetBytes($original)
        [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
        $script:finalListenerFailure='::1';$script:refuseListenerWait=$true
        $script:failRestoreAdapterAfterResolverQuery=$restoreFails
        $expected=if($restoreFails){'source-dns-setter-failed'}else{'Synthetic loopback wait boundary'}
        Reject-DNS {Configure-DNS 'dnscrypt'} $expected
        if($restoreFails){
            Assert-SnapshotRetained $script:journalDigest
            Assert-DNS ($script:serviceRestarts -eq 1 -and $script:restartRecoveryWrites -eq 0 -and
                $script:expectedResolverStartup -ceq 'Automatic' -and
                [IO.File]::ReadAllText($path) -cne $original) 'dnscrypt-recovers-after-late-listener-failure'
        }else{
            Assert-DNS ($script:receiptDigest -ceq $script:journalDigest -and -not [IO.File]::Exists($snapshot) -and
                $script:serviceRestarts -eq 2 -and $script:restartRecoveryWrites -eq 1 -and
                $script:expectedResolverStartup -ceq 'Manual' -and $script:serviceStartupChanges -eq 2 -and
                [IO.File]::ReadAllText($path) -ceq $original) 'dnscrypt-recovers-after-late-listener-failure'
        }
    }
    New-DNSCase;$script:stageDNSCrypt=$true;$script:resolverServicePresent=$true
    $script:mode6='::1';$script:dnsValues['77/IPv6']=@('::1')
    $path=Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'
    $original="server_names = ['google']`r`nlisten_addresses = ['[::1]:53']`r`n"
    $script:restartRecoveryOriginal=[Text.UTF8Encoding]::new($false).GetBytes($original)
    [IO.File]::WriteAllBytes($path,$script:restartRecoveryOriginal)
    $script:finalListenerFailure='::1';$script:refuseListenerWait=$true;$script:restartListenerFailure=$true
    Reject-DNS {Configure-DNS 'dnscrypt'} 'DNSCrypt activation failed and the original service could not be recovered'
    $hash=$script:journalDigest
    Assert-SnapshotRetained $hash
    Assert-DNS (-not $script:receiptDigest -and $script:restartRecoveryWrites -eq 1 -and
        $script:serviceRestarts -eq 2 -and [IO.File]::ReadAllText($path) -ceq $original) 'dnscrypt-reload-retains-snapshot-until-listener-recovers'
    $script:restartListenerFailure=$false
    Restore-DNS $hash -ResolverReload $script:savedReload[0]
    Assert-DNS ($script:receiptDigest -ceq $hash -and -not [IO.File]::Exists($snapshot) -and
        $script:restartRecoveryWrites -eq 2 -and $script:serviceRestarts -eq 3) 'dnscrypt-reload-retains-snapshot-until-listener-recovers'

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

    New-DNSCase
    $script:mode4='absent';$script:mode6='2001:db8::53'
    Configure-DNS 'doh';$hash=Snapshot-Hash
    $script:calls.Clear()
    $script:dnsInterfaceSettingsMode='unavailable'
    $script:legacyDNSResetChangesSibling=$true
    Reject-DNS {Restore-DNS} 'Adapter DNS settings changed during restoration'
    Assert-SnapshotRetained $hash
    Assert-DNS (@($script:calls | Where-Object kind -CEQ 'dns').Count -eq 1) 'restore-refuses-legacy-sibling-reset'
    $script:dnsInterfaceSettingsMode='available'
    Restore-DNS
    $operations=@($script:dnsInterfaceSettingsCalls | Select-Object -Last 2)
    Assert-DNS ($operations.Count -eq 2 -and $operations[0].adapter -eq [guid]$script:adapters[0].InterfaceGuid -and
        $operations[1].adapter -eq $operations[0].adapter -and -not $operations[0].ipv6 -and $operations[0].servers -ceq '' -and
        $operations[1].ipv6 -and $operations[1].servers -ceq '2001:db8::53' -and
        -not [IO.File]::Exists($snapshot) -and $script:receiptDigest -ceq $hash) 'restore-scopes-automatic-and-static-families'

    New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash
    $script:calls.Clear()
    $script:dnsInterfaceSettingsMode='refused'
    Reject-DNS {Restore-DNS} 'Windows refused the family-scoped DNS update'
    Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 0 -and $script:dnsInterfaceSettingsCalls.Count -eq 1 -and
        -not $script:receiptDigest) 'restore-native-refusal-never-falls-back'

    foreach($drift in @('static','dhcp')){
        New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash
        $key=([string]$script:adapters[0].InterfaceGuid)+'/IPv4'
        $script:calls.Clear();$script:explicitRestoreDrift=$drift
        Reject-DNS {Restore-DNS} 'Adapter DNS settings changed during restoration'
        Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:receiptDigest -and
            $script:appliedDNS[$key].dhcp -eq ($drift -ceq 'dhcp') -and
            $script:appliedDNS[$key].values[0] -cin @('198.51.100.53','192.0.2.42')) 'explicit-restore-refuses-concurrent-adapter-dns'
        Restore-DNS
        Assert-DNS ($script:receiptDigest -ceq $hash -and -not [IO.File]::Exists($snapshot)) 'explicit-restore-refuses-concurrent-adapter-dns'
    }

    foreach($fault in @('unavailable','adapter-drift')){
        New-DNSCase
        Configure-DNS 'doh'
        $hash=Snapshot-Hash
        $queries=$script:resolverQueries
        $flushes=$script:cacheFlushes
        $script:cacheFlushFault=$fault
        Reject-DNS {Restore-DNS $hash}
        Assert-SnapshotRetained $hash
        Assert-DNS (-not $script:receiptDigest -and $script:cacheFlushes -eq ($flushes+1) -and
            $script:resolverQueries -eq $queries) ('restore-cache-flush-retains-snapshot-'+$fault)
        $script:cacheFlushFault=''
        Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and $script:receiptDigest -ceq $hash -and
            $script:cacheFlushes -eq ($flushes+2) -and $script:resolverQueries -eq $queries) 'restore-cache-flush-retry'
    }

    # The original adapter state already matches, so only the DoH setter can
    # mark the failed recovery as having potentially changed the machine.
    foreach($kind in @('add','set','remove')){
        New-DNSCase
        $saved=Original-DNSFixture
        $saved.adapterConditional=$true
        if($kind -cne 'remove'){$saved.doh=@((Old-DohFixture))}
        if($kind -cne 'add'){
            $script:currentDoh['8.8.8.8']=[pscustomobject]@{
                ServerAddress='8.8.8.8';DohTemplate='https://8.8.8.8/dns-query'
                AllowFallbackToUdp=$false;AutoUpgrade=$true
            }
        }
        Write-DNSFixture $saved
        $hash=Snapshot-Hash
        $script:failAction=$kind;$script:failAddress='8.8.8.8'
        Reject-DNS {Restore-DNS $hash} 'source-doh-mutation-failed'
        Assert-SnapshotRetained $hash
        $writes=@($script:calls | Where-Object {$_.kind -in @('dns','add','set','remove')})
        Assert-DNS ($writes.Count -eq 1 -and $writes[0].kind -ceq $kind -and $writes[0].effectsAtAttempt -and
            $script:externalEffectsPending -and -not $script:receiptDigest) 'doh-only-recovery-records-effects'
    }
    New-DNSCase
    $saved=Original-DNSFixture
    $saved.adapterConditional=$true
    Write-DNSFixture $saved
    $hash=Snapshot-Hash
    Restore-DNS $hash
    Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:externalEffectsPending -and
        $script:receiptDigest -ceq $hash -and -not [IO.File]::Exists($snapshot)) 'doh-noop-recovery-has-no-effects'

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
    Assert-DNS ($saved.adapters[0].bound4 -and $saved.adapters[0].bound6 -and $saved.adapters[0].ipv4[0] -ceq '192.0.2.53' -and $saved.adapters[0].ipv6[0] -ceq '2001:db8::53' -and $saved.doh[0].DohTemplate -ceq 'https://original.invalid/dns-query' -and $script:registryReads.Count -ge 6 -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.family -ceq 'IPv6'}).Count -eq 1 -and @($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.family -ceq 'IPv4'}).Count -eq 0) 'new-family-originals-extended'
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
                $script:restartRecoveryOriginal=[Text.UTF8Encoding]::new($false).GetBytes("listen_addresses = ['192.0.2.53:53']")
                [IO.File]::WriteAllBytes((Join-Path $root 'components\dnscrypt\dnscrypt-proxy.toml'),$script:restartRecoveryOriginal)
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
    foreach($drift in @(
        @{kind='adapter';failure='An original adapter changed during restoration verification'},
        @{kind='address';failure='Restored static DNS order or value could not be verified'},
        @{kind='policy';failure='Restored DoH policy could not be verified'}
    )){
        New-DNSCase
        $saved=Original-DNSFixture
        $saved.doh=@((Old-DohFixture))
        Write-DNSFixture $saved
        $hash=Snapshot-Hash
        $script:dnsDriftOnReceiptSave=$drift.kind
        Reject-DNS {Restore-DNS $hash} $drift.failure
        Assert-SnapshotRetained $hash
        Assert-DNS ($script:receiptDigest -ceq $hash -and (Mutation-Count) -eq 3) 'restore-retirement-retains-after-state-drift'
        if($drift.kind -ceq 'address'){
            $key=([string]$script:adapters[0].InterfaceGuid)+'/IPv4'
            Assert-DNS ($script:appliedDNS[$key].values[0] -ceq '198.51.100.99') 'restore-retirement-retains-after-state-drift'
        }
        if($drift.kind -ceq 'policy'){
            Assert-DNS ($script:currentDoh['8.8.8.8'].DohTemplate -ceq 'https://independent.invalid/dns-query') 'restore-retirement-retains-after-state-drift'
        }
        $script:dnsDriftOnReceiptSave=''
        $script:adapters[0].InterfaceGuid=$saved.adapters[0].guid
        Restore-DNS $hash
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and $script:receiptDigest -ceq $hash -and
            $script:events -contains 'Original DNS and DoH settings restored') 'restore-retirement-retries-after-state-drift'
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:recoveryLag=2
    Restore-DNS
    Assert-DNS ($script:readbackWaits -eq 2 -and (Mutation-Count) -eq 2 -and -not [IO.File]::Exists($snapshot)) 'restore-delayed-observation'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:renumberDuringRecoveryRead=$true
    Restore-DNS
    Assert-DNS ($script:readbackWaits -eq 1 -and (Mutation-Count) -eq 2 -and
        $script:adapters[0].ifIndex -eq 101 -and -not [IO.File]::Exists($snapshot)) 'restore-adapter-row-fence'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:adapterDriftDuringFinalDohRead='renumber'
    Restore-DNS
    Assert-DNS ($script:readbackWaits -eq 1 -and (Mutation-Count) -eq 2 -and
        $script:adapters[0].ifIndex -eq 101 -and -not [IO.File]::Exists($snapshot)) 'restore-final-adapter-fence'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:adapterDriftDuringFinalDohRead='replace'
    Reject-DNS {Restore-DNS}
    Assert-SnapshotRetained $hash
    Assert-DNS ((Mutation-Count) -eq 2 -and $script:readbackWaits -eq 39 -and -not $script:receiptDigest) 'restore-final-adapter-fence'
    foreach($drift in @(
        @{kind='static-address';failure='Restored static DNS order or value could not be verified'},
        @{kind='static-mode';failure='Restored DNS mode could not be verified'},
        @{kind='missing-row';failure='Original adapter DNS family could not be inspected'}
    )){
        New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash
        $script:clientDriftDuringReceiptReadback=$drift.kind
        Reject-DNS {Restore-DNS} $drift.failure
        Assert-SnapshotRetained $hash
        Assert-DNS ($script:receiptDigest -ceq $hash -and (Mutation-Count) -eq 2) 'restore-final-client-readback'
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture)
    $script:clientDriftDuringReceiptReadback='dhcp-lease'
    Restore-DNS
    $dhcp=$script:appliedDNS[([string]$script:adapters[0].InterfaceGuid)+'/IPv6']
    Assert-DNS (-not [IO.File]::Exists($snapshot) -and $dhcp.dhcp -and $dhcp.values[0] -ceq '2001:db8::99') 'restore-final-client-readback'

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

    foreach($drift in @('replace','duplicate-index')){
        New-DNSCase;Configure-DNS 'doh';$hash=Snapshot-Hash
        $selected=@(Get-NetAdapter);$saved=(Read-DNSRecoverySnapshot).record
        $servers=@(Get-DNSDohProviders | ForEach-Object {$_.ServerAddress})
        $script:calls.Clear();$script:unverifiedDNSWrites=0
        $script:configuredRegistryTopologyDrift=$drift
        Reject-DNS {Assert-ConfiguredDNSServers $selected $saved.adapters $servers} 'Configured DNS adapter changed during readback'
        Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and $script:unverifiedDNSWrites -eq 0 -and
            -not $script:configuredRegistryTopologyDrift) 'configured-dns-rejects-topology-drift-during-registry-read'
    }

    foreach($drift in @('family-added','family-removed','adapter-gains-dns','server-order')){
        New-DNSCase
        if($drift -ceq 'family-added'){$script:exposure['77/IPv6']=$false}
        if($drift -ceq 'adapter-gains-dns'){
            $script:adapters+=@([pscustomobject]@{
                InterfaceGuid='{00000000-0000-0000-0000-000000000002}'
                ifIndex=88;Status='Up';InterfaceDescription='Fixture adapter without DNS'
            })
            $script:exposure['88/IPv4']=$false
            $script:exposure['88/IPv6']=$false
        }
        Configure-DNS 'doh'
        $hash=Snapshot-Hash
        $selected=@(Get-ActiveDNSAdapters @(Get-NetAdapter) @(Read-DNSClientInventory))
        $saved=(Read-DNSRecoverySnapshot).record
        $servers=@(Get-DNSDohProviders | ForEach-Object {$_.ServerAddress})
        $script:calls.Clear();$script:configuredClientDrift=$drift
        $expected=switch($drift){
            'adapter-gains-dns' {'Active DNS adapter coverage changed during readback'}
            'server-order' {'Configured DNS servers changed during readback'}
            default {'Configured DNS family coverage changed during readback'}
        }
        Reject-DNS {Assert-ConfiguredDNSServers $selected $saved.adapters $servers} $expected
        Assert-SnapshotRetained $hash
        Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:configuredClientDrift) 'configured-dns-rejects-client-drift-during-registry-read'
    }

    New-DNSCase;Configure-DNS 'doh';$firstDigest=$script:undo[0].snapshotSHA256
    $script:calls.Clear();$script:unverifiedDNSWrites=0
    $queries=$script:resolverQueries
    Configure-DNS 'doh'
    Assert-DNS ($script:unverifiedDNSWrites -eq 0 -and (Mutation-Count) -eq 0 -and
        $script:resolverQueries -eq ($queries+1)) 'doh-reapply-verifies-without-redundant-setters'
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
