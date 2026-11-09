# Count/relative-time diagnostics only. This module never changes a trial verdict.
function New-NativeDNSRecoveryObservation {
    return @{schemaVersion=1;outcome='not-run';code='not-needed';diagnosticOnly=$true;initialOutcome='not-recorded';initialFailureKind='none';samples=@();laterSuccessObserved=$false;productionQualificationComplete=$false}
}
function Read-NativeDNSRecoveryMilliseconds([object]$Clock) {
    if($Clock -isnot [Diagnostics.Stopwatch] -or -not $Clock.IsRunning){throw 'Recovery clock boundary'}
    $value=[long][Math]::Floor($Clock.Elapsed.TotalMilliseconds)
    if($value -lt 0 -or $value -gt 120000){throw 'Recovery clock bound'}
    return $value
}
function Wait-NativeDNSRecoveryOffset([object]$Clock,[long]$TargetMilliseconds) {
    if($TargetMilliseconds -notin @(5000,10000,15000,35000,65000)){throw 'Recovery schedule boundary'}
    while($true){
        $now=Read-NativeDNSRecoveryMilliseconds $Clock
        if($now -ge $TargetMilliseconds){return $now}
        Start-Sleep -Milliseconds ([int][Math]::Min(250,($TargetMilliseconds-$now)))
    }
}
function Observe-NativeDNSRecovery([object]$State,[object]$Clock,[object]$InitialEvidence,[object]$InitialTiming,[string]$InitialOutcome,[string]$InitialCode) {
    $result=New-NativeDNSRecoveryObservation;$result.outcome='refused';$result.code='precondition'
    try {
        if($InitialOutcome -cne 'failed' -or $InitialCode -cne 'resumed'){return $result}
        $first=Get-NativeFreshDNSQueryReport ($InitialEvidence | ConvertTo-Json -Depth 3 -Compress) $State.querySourceCommit $State.queryArchitecture
        if($first.outcome -cne 'refused' -or $first.code -cne 'query-failed' -or $first.failureKind -cne 'timeout' -or -not $first.queryInvoked -or -not $first.recordsReleased){return $result}
        if($InitialTiming -isnot [hashtable] -or $InitialTiming.Count -ne 3 -or $InitialTiming.attempted -isnot [bool] -or -not $InitialTiming.attempted){return $result}
        foreach($key in @('startMilliseconds','endMilliseconds')){if(($InitialTiming[$key] -isnot [int] -and $InitialTiming[$key] -isnot [long]) -or $InitialTiming[$key] -lt 0 -or $InitialTiming[$key] -gt 120000){return $result}}
        if($InitialTiming.endMilliseconds -lt $InitialTiming.startMilliseconds -or $State.processFailed){return $result}
        $result.initialOutcome='failed';$result.initialFailureKind='timeout';$previous=[long]$InitialTiming.endMilliseconds
        foreach($target in @(5000,10000,15000,35000,65000)){
            $result.code='clock';$start=Wait-NativeDNSRecoveryOffset $Clock $target
            if(($start -isnot [int] -and $start -isnot [long]) -or $start -lt $target -or $start -lt $previous -or $start -gt 120000){return $result}
            $result.code='query';$query=$null
            try{$query=Invoke-NativeFreshDNSQuery $State 'example.net'}catch{
                if($State.processFailed){$result.code='process';return $result}
                if($null -eq $State.queryLastEvidence){return $result}
                $query=Get-NativeFreshDNSQueryReport ($State.queryLastEvidence | ConvertTo-Json -Depth 3 -Compress) $State.querySourceCommit $State.queryArchitecture
            }
            $query=Get-NativeFreshDNSQueryReport ($query | ConvertTo-Json -Depth 3 -Compress) $State.querySourceCommit $State.queryArchitecture
            if(-not $query.queryInvoked -or $query.outcome -ceq 'ready'){return $result}
            $result.code='clock';$end=Read-NativeDNSRecoveryMilliseconds $Clock
            if(($end -isnot [int] -and $end -isnot [long]) -or $end -lt $start -or $end -gt 120000){return $result}
            $result.samples+=@(@{targetMilliseconds=$target;startMilliseconds=$start;endMilliseconds=$end;queryEvidence=$query})
            if($query.outcome -ceq 'answered'){$result.laterSuccessObserved=$true}
            $previous=[long]$end
        }
        $result.outcome='observed';$result.code='none'
    }catch{}
    return $result
}
