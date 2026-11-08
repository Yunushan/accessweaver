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
