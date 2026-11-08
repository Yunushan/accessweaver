# Pure coordination for native DoH/DNSCrypt: boundaries are explicit callbacks. The hosted
# driver supplies the source-built CLI, independent state reader and OS resolver.
function Invoke-NativeDoHScenario([scriptblock]$Apply,[scriptblock]$Capture,[scriptblock]$Resolve,[string]$Method='doh',[string]$ScenarioKind='roundtrip',[scriptblock]$InduceFailure,[scriptblock]$ResolveFailed,[scriptblock]$ResolveRestored) {
    $result=@{outcome='failed';code='baseline';operationCode='none';restorationCode='none';verificationCode='none';baselineCaptured=$false;configurationAttempted=$false;configurationAccepted=$false;configuredStateVerified=$false;resolverPassed=$false;restorationAttempted=$false;restorationAccepted=$false;restoredStateVerified=$false;failureInjected=$false;failedResolverVerified=$false;restoredResolverVerified=$false}
    try {
        if($ScenarioKind -cnotin @('roundtrip','service-loss') -or ($ScenarioKind -ceq 'service-loss' -and ($Method -cne 'dnscrypt' -or $null -eq $InduceFailure -or $null -eq $ResolveFailed -or $null -eq $ResolveRestored)) -or $Method -cnotin @('doh','dnscrypt') -or $null -eq $Apply -or $null -eq $Capture -or $null -eq $Resolve){throw 'Missing native DoH boundary'}
        $before=& $Capture;$index=Get-DNSAcceptanceIndex $before
        if(($Method -ceq 'doh' -and -not $before.dohAvailable) -or @($index.adapters.Values | Where-Object {$_.selected}).Count -eq 0){throw 'Native DoH baseline cannot support this scenario'}
        $result.baselineCaptured=$true
    } catch {$result.operationCode='baseline';return $result}
    $phase='configuration'
    try {
        $result.configurationAttempted=$true
        [void](& $Apply @{action='dns';dns=$Method})
        $result.configurationAccepted=$true;$phase='configured-state'
        Assert-DNSAcceptanceConfigured $before (& $Capture) $Method
        $result.configuredStateVerified=$true;$phase='ordinary-resolver'
        [void](& $Resolve)
        $result.resolverPassed=$true
        if($ScenarioKind -ceq 'service-loss'){
            $phase='fault-injection';[void](& $InduceFailure);$result.failureInjected=$true
            $phase='failed-resolver';[void](& $ResolveFailed);$result.failedResolverVerified=$true
        }
    } catch {$result.operationCode=$phase}
    finally {
        $phase='restoration';$result.restorationAttempted=$true
        try {
            [void](& $Apply @{action='dns-restore'})
            $result.restorationAccepted=$true
        } catch {$result.restorationCode='restoration'}
        # Inspect the final state even when the explicit restore command failed:
        # the operation may already have rolled itself back, or cleanup may fail.
        try {
            Assert-DNSAcceptanceRestored $before (& $Capture)
            $result.restoredStateVerified=$true
        } catch {$result.verificationCode='restored-state'}
        if($ScenarioKind -ceq 'service-loss' -and $result.restoredStateVerified){
            try{[void](& $ResolveRestored);$result.restoredResolverVerified=$true}catch{$result.verificationCode='restored-resolver'}
        }
    }
    if($result.operationCode -ceq 'none' -and $result.restorationCode -ceq 'none' -and $result.verificationCode -ceq 'none'){$result.outcome='passed';$result.code='none'}
    elseif($result.operationCode -cne 'none'){$result.code='operation-failed'}else{$result.code='restore-failed'}
    return $result
}

# Pure fixed-domain DNS fixture: no network, process or OS operations here.
function New-NativeDNSFailureResponse([byte[]]$Packet) {
    if($null -eq $Packet -or $Packet.Length -lt 29 -or $Packet.Length -gt 4096 -or ($Packet[2] -band 0xf8) -ne 0 -or $Packet[4] -ne 0 -or $Packet[5] -ne 1 -or $Packet[6] -ne 0 -or $Packet[7] -ne 0 -or $Packet[8] -ne 0 -or $Packet[9] -ne 0){throw 'Fixed DNS query shape refused'}
    if($Packet[12] -ne 7 -or $Packet[20] -ne 3 -or $Packet[24] -ne 0 -or [Text.Encoding]::ASCII.GetString($Packet,13,7).ToLowerInvariant() -cne 'example' -or [Text.Encoding]::ASCII.GetString($Packet,21,3).ToLowerInvariant() -cne 'com'){throw 'Fixed DNS query name refused'}
    if($Packet[25] -ne 0 -or $Packet[26] -notin @(1,28,65) -or $Packet[27] -ne 0 -or $Packet[28] -ne 1){throw 'Fixed DNS question type refused'}
    if($Packet[10] -ne 0 -or $Packet[11] -notin @(0,1)){throw 'Fixed DNS additional count refused'}
    if($Packet[11] -eq 0){if($Packet.Length -ne 29){throw 'Fixed DNS trailing bytes refused'}}else{
        if($Packet.Length -lt 40 -or $Packet[29] -ne 0 -or $Packet[30] -ne 0 -or $Packet[31] -ne 41 -or $Packet[34] -ne 0 -or $Packet[35] -ne 0 -or $Packet.Length -ne (40+256*[int]$Packet[38]+[int]$Packet[39])){throw 'Fixed DNS EDNS shape refused'}
    }
    $response=[byte[]]::new(29);[Array]::Copy($Packet,$response,29)
    $response[2]=[byte](0x80 -bor ($Packet[2] -band 1));$response[3]=0x82
    $response[10]=0;$response[11]=0
    return ,$response
}
# Configure returns a strict bool indicating the actual CLI rejected the change.
# Recovery is inspected before any emergency fixture restore is admitted.
function Invoke-NativeDNSRollbackScenario([scriptblock]$Configure,[scriptblock]$Capture,[scriptblock]$Observe,[scriptblock]$Resolve,[scriptblock]$EmergencyRestore) {
    $result=@{outcome='failed';code='baseline';operationCode='none';recoveryCode='none';baselineCaptured=$false;baselineResolverPassed=$false;configurationAttempted=$false;configurationRejected=$false;configuredStateObserved=$false;forwardedFailureObserved=$false;originalStateRestored=$false;restoredResolverPassed=$false;emergencyRestoreAttempted=$false}
    try {
        if($null -eq $Configure -or $null -eq $Capture -or $null -eq $Observe -or $null -eq $Resolve -or $null -eq $EmergencyRestore){throw 'Rollback fixture boundary missing'}
        $before=& $Capture;$index=Get-DNSAcceptanceIndex $before
        if(@($index.adapters.Values | Where-Object {$_.selected}).Count -eq 0){throw 'Rollback fixture has no selected adapter'}
        $result.baselineCaptured=$true;[void](& $Resolve);$result.baselineResolverPassed=$true
    }catch{$result.operationCode='baseline';return $result}
    $phase='configuration'
    try {
        $result.configurationAttempted=$true;$rejected=& $Configure
        if($rejected -isnot [bool] -or -not $rejected){throw 'Actual configuration did not reject'}
        $result.configurationRejected=$true;$phase='effects-observation'
        $observed=& $Observe
        if($observed -isnot [hashtable] -or $observed.Count -ne 2 -or $observed.configured -isnot [bool] -or $observed.forwarded -isnot [bool]){throw 'Rollback observation shape differs'}
        $result.configuredStateObserved=$observed.configured;$result.forwardedFailureObserved=$observed.forwarded
        if(-not $observed.configured -or -not $observed.forwarded){throw 'Native configuration/failure effects unobserved'}
    }catch{$result.operationCode=$phase}
    finally {
        try{Assert-DNSAcceptanceRestored $before (& $Capture);$result.originalStateRestored=$true}catch{$result.recoveryCode='restored-state'}
        if($result.originalStateRestored){
            try{[void](& $Resolve);$result.restoredResolverPassed=$true}catch{$result.recoveryCode='restored-resolver'}
        }else{
            $result.emergencyRestoreAttempted=$true
            try{[void](& $EmergencyRestore)}catch{}
        }
    }
    if($result.operationCode -ceq 'none' -and $result.recoveryCode -ceq 'none'){$result.outcome='passed';$result.code='none'}
    elseif($result.operationCode -cne 'none'){$result.code='operation-failed'}else{$result.code='recovery-failed'}
    return $result
}

# Only a source-known marker leaves the private bounded output stream as a bool.
function Get-NativeDNSVerificationMarker([string]$Previous,[string]$Chunk) {
    $marker='Resolver verification failed; original DNS settings restored:'
    if($Previous.Length -ge $marker.Length -or $Chunk.Length -gt 4096){throw 'Resolver verification marker input bound exceeded'}
    $combined=$Previous+$Chunk;$start=[Math]::Max(0,$combined.Length-($marker.Length-1))
    return @{matched=$combined.Contains($marker);suffix=$combined.Substring($start)}
}

# Closed fixture-only I/O vocabulary. Exception text never enters a public report.
function Get-NativeDNSForwarderFailure([Exception]$Failure) {
    for($depth=0;$null -ne $Failure -and $depth -lt 16;$depth++){
        if($Failure -is [Net.Sockets.SocketException]){if($Failure.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionReset){return 'peer-closed'};return 'socket-io'}
        switch -CaseSensitive ($Failure.Message){
            'Forwarded DNS packet bound exceeded' {return 'packet-bound'}
            'Forwarded DNS request count exceeded' {return 'request-bound'}
            'Non-loopback forwarder peer refused' {return 'peer-bound'}
            'Forwarded DNS error response incomplete' {return 'response-write'}
            {$_ -cin @('Fixed DNS query shape refused','Fixed DNS query name refused','Fixed DNS question type refused','Fixed DNS additional count refused','Fixed DNS trailing bytes refused','Fixed DNS EDNS shape refused')} {return 'packet-shape'}
        }
        $Failure=$Failure.InnerException
    }
    return 'unexpected-io'
}
