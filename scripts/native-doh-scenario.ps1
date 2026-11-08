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

# Closed component preparation diagnostics; caller sanitizes HTTP status first.
function Get-NativeDNSComponentFailure([Exception]$Failure,[int]$HTTPStatus=0) {
    if($HTTPStatus -in @(400,401,403,404,408,429,500,502,503,504)){return ('http-'+$HTTPStatus)}
    if($HTTPStatus -eq -1){return 'http-other'}
    for($depth=0;$null -ne $Failure -and $depth -lt 16;$depth++){
        switch -CaseSensitive ($Failure.Message){
            'DNSCrypt native architecture refused' {return 'native-architecture'}
            'DNSCrypt upstream size differs' {return 'upstream-size'}
            'DNSCrypt upstream bound exceeded' {return 'upstream-bound'}
            'DNSCrypt upstream digest differs' {return 'upstream-digest'}
            'DNSCrypt upstream entry bound exceeded' {return 'archive-count'}
            'DNSCrypt upstream member shape differs' {return 'member-shape'}
            'DNSCrypt member bound exceeded' {return 'member-bound'}
            'DNSCrypt member incomplete' {return 'member-incomplete'}
            'DNSCrypt PE header differs' {return 'pe-header'}
            'DNSCrypt PE offset differs' {return 'pe-offset'}
            'DNSCrypt PE native machine differs' {return 'pe-machine'}
        }
        if($Failure -is [OperationCanceledException]){return 'timeout'}
        if($Failure -is [UnauthorizedAccessException]){return 'access'}
        if($Failure -is [IO.InvalidDataException]){return 'archive-data'}
        if($Failure.GetType().FullName -ceq 'System.Net.Http.HttpRequestException'){return 'http-request'}
        if($Failure -is [IO.IOException]){return 'io'}
        $Failure=$Failure.InnerException
    }
    return 'unexpected'
}

# Returns an admitted wait, or -1. All retries share the original90second budget.
function Get-NativeDNSComponentRetry([int]$Status,[int]$Attempt,[long]$RemainingMilliseconds,[long]$RetryAfterMilliseconds=0) {
    if($Status -notin @(408,500,502,503,504) -or $Attempt -lt 1 -or $Attempt -ge 3 -or $RemainingMilliseconds -le 0 -or $RemainingMilliseconds -gt 90000 -or $RetryAfterMilliseconds -lt 0){return -1L}
    $wait=[Math]::Max([long]$Attempt*1000,$RetryAfterMilliseconds)
    if($wait -ge $RemainingMilliseconds){return -1L}
    return $wait
}

# The fixture changes only a disposable hosted machine. Its outer baseline and
# resolver are verified again after unconditional teardown of staged DNS state.
function Invoke-NativeDNSStaticFixture([scriptblock]$Capture,[scriptblock]$Resolve,[scriptblock]$Stage,[scriptblock]$Exercise,[scriptblock]$Unstage) {
    $result=@{outcome='failed';code='baseline';operationCode='none';cleanupCode='none';baselineCaptured=$false;baselineResolverPassed=$false;stagingAttempted=$false;stagingVerified=$false;exerciseAttempted=$false;exercisePassed=$false;cleanupAttempted=$false;originalStateRestored=$false;originalResolverPassed=$false}
    try {
        if($null -eq $Capture -or $null -eq $Resolve -or $null -eq $Stage -or $null -eq $Exercise -or $null -eq $Unstage){throw 'Missing native static fixture boundary'}
        $before=& $Capture;[void](Get-DNSAcceptanceIndex $before);$result.baselineCaptured=$true
        $resolved=& $Resolve
        if($resolved -isnot [bool] -or -not $resolved){throw 'Native fixture baseline resolver failed'}
        $result.baselineResolverPassed=$true
    }catch{$result.operationCode='baseline';return $result}
    $phase='stage'
    try {
        $result.stagingAttempted=$true;$staged=& $Stage $before
        if($staged -isnot [bool] -or -not $staged){throw 'Native static staging failed'}
        $result.stagingVerified=$true;$phase='exercise';$result.exerciseAttempted=$true
        $exercised=& $Exercise
        if($exercised -isnot [bool] -or -not $exercised){throw 'Native static exercise failed'}
        $result.exercisePassed=$true
    }catch{$result.operationCode=$phase}
    finally {
        $result.cleanupAttempted=$true
        try {[void](& $Unstage $before)}catch{$result.cleanupCode='unstage'}
        try {Assert-DNSAcceptanceRestored $before (& $Capture);$result.originalStateRestored=$true}catch{if($result.cleanupCode -ceq 'none'){$result.cleanupCode='state'}}
        if($result.originalStateRestored){
            try {
                $resolved=& $Resolve
                if($resolved -isnot [bool] -or -not $resolved){throw 'Native fixture original resolver failed'}
                $result.originalResolverPassed=$true
            }catch{if($result.cleanupCode -ceq 'none'){$result.cleanupCode='resolver'}}
        }
    }
    if($result.operationCode -ceq 'none' -and $result.cleanupCode -ceq 'none'){$result.outcome='passed';$result.code='none'}
    elseif($result.operationCode -cne 'none'){$result.code='operation-failed'}else{$result.code='cleanup-failed'}
    return $result
}

# Closed diagnostics only. Exception text/type names never leave this boundary.
function Get-NativeDNSStaticFailure([Exception]$Exception) {
    $current=$Exception
    for($depth=0;$null -ne $current -and $depth -lt 16;$depth++){
        switch -CaseSensitive ($current.Message){
            'No dual-family native static fixture adapter' {return 'no-family'}
            'No active native link-local interface' {return 'no-link-local'}
            'Static fixture adapter identity changed' {return 'adapter-changed'}
            'Static fixture family changed' {return 'family-changed'}
            'Static fixture firewall policy unavailable' {return 'firewall-policy'}
            'Static fixture address is local' {return 'fixture-address-local'}
            'Static fixture firewall identity collision' {return 'firewall-identity'}
            'Static fixture firewall rule not active' {return 'firewall-active'}
            'Static fixture firewall filters differ' {return 'firewall-filter'}
            'Static fixture firewall ownership differs' {return 'firewall-owner'}
            'Static fixture firewall removal incomplete' {return 'firewall-removal'}
            'Static fixture firewall cleanup failed' {return 'firewall-cleanup'}
            'Invalid DNS acceptance adapter identity' {return 'read-adapter-identity'}
            'Invalid DNS acceptance address' {return 'read-address'}
            'DNS acceptance address family mismatch' {return 'read-family'}
            'DNS acceptance IPv6 scope does not identify this adapter' {return 'read-scope'}
            'DNS acceptance dormant registry state exceeds its bound' {return 'read-dormant-bound'}
            'DNS acceptance adapter inventory is empty' {return 'read-empty-inventory'}
            'DNS acceptance client identity malformed' {return 'read-client-identity'}
            'DNS acceptance client family malformed' {return 'read-client-family'}
            'DNS acceptance client family duplicated' {return 'read-client-duplicate'}
            'Duplicate DNS acceptance adapter identity' {return 'read-adapter-duplicate'}
            'DNS acceptance adapter changed during capture' {return 'read-adapter-changed'}
            'DNS acceptance exposed-family registry state is missing' {return 'read-registry-missing'}
            'DNS acceptance registry mode is malformed' {return 'read-registry-mode'}
            'DNS acceptance static servers are missing' {return 'read-static-empty'}
            'DNS acceptance DoH metadata malformed or duplicated' {return 'read-doh-metadata'}
            'DNS acceptance state schema is invalid; prepare a new baseline' {return 'saved-schema'}
            'DNS acceptance adapter state is duplicated or malformed' {return 'saved-adapter'}
            'DNS acceptance saved mode is invalid' {return 'saved-mode'}
            'DNS acceptance saved server list is invalid' {return 'saved-servers'}
            'DNS acceptance dormant state fingerprint is missing' {return 'saved-dormant'}
            'DNS acceptance selected adapter exposes no client' {return 'saved-selected'}
            'DNS acceptance saved DoH metadata is malformed or duplicated' {return 'saved-doh'}
            'DNS acceptance DoH capability metadata is inconsistent' {return 'saved-doh-capability'}
            'DNS acceptance adapter inventory changed' {return 'state-inventory'}
            'DNS acceptance original adapter is missing' {return 'state-adapter'}
            'DNS acceptance original DHCP/static mode differs' {return 'state-mode'}
            'DNS acceptance dormant registry state differs' {return 'state-dormant'}
            'DNS acceptance original static server count differs' {return 'state-count'}
            'DNS acceptance original static server order or value differs' {return 'state-order'}
            'DNS acceptance original DoH capability or inventory differs' {return 'state-doh-inventory'}
            'DNS acceptance original DoH entry is missing' {return 'state-doh-entry'}
            'DNS acceptance original DoH metadata differs' {return 'state-doh-metadata'}
        }
        if($current.GetType().FullName -ceq 'Microsoft.Management.Infrastructure.CimException'){return 'cim'}
        if($current -is [Management.Automation.ParameterBindingException]){return 'parameter'}
        if($current -is [InvalidCastException]){return 'cast'}
        if($current -is [ArgumentException]){return 'argument'}
        $current=$current.InnerException
    }
    return 'unexpected'
}
