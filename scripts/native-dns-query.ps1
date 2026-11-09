# Definitions only. Guarded hosted callers own the binary, process and source proof.
function Get-NativeFreshDNSQueryReport([string]$Text,[string]$SourceCommit,[string]$Architecture) {
    if($Text.Length -gt 2048 -or $SourceCommit -cnotmatch '^[a-f0-9]{40}$' -or $Architecture -cnotin @('amd64','arm64')){throw 'Fresh DNS report boundary'}
    try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{throw 'Fresh DNS report JSON'}
    $keys=@('schemaVersion','sourceCommit','architecture','queryOptions','outcome','code','failureKind','answerCount','recordCount','queryInvoked','recordsReleased','productionQualificationComplete')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 12 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 2 -or $v.sourceCommit -cne $SourceCommit -or $v.architecture -cne $Architecture -or $v.queryOptions -isnot [int] -or $v.queryOptions -ne 6600 -or $v.outcome -cnotin @('ready','answered','refused') -or $v.code -cnotin @('none','environment','arguments','query-failed','record-bound','record-shape','answer-bound')){throw 'Fresh DNS report shape'}
    if($v.failureKind -isnot [string] -or $v.failureKind -cnotin @('none','timeout','name-error','server-failure','refused','no-records','no-network','other') -or (($v.code -ceq 'query-failed') -ne ($v.failureKind -cne 'none'))){throw 'Fresh DNS error category'}
    foreach($key in @('queryInvoked','recordsReleased','productionQualificationComplete')){if($v.$key -isnot [bool]){throw 'Fresh DNS report type'}}
    foreach($key in @('answerCount','recordCount')){if(($v.$key -isnot [int] -and $v.$key -isnot [long]) -or $v.$key -lt 0){throw 'Fresh DNS report count'}}
    if($v.answerCount -gt 64 -or $v.recordCount -gt 128 -or -not $v.recordsReleased -or $v.productionQualificationComplete){throw 'Fresh DNS report ownership'}
    if($v.outcome -ceq 'ready'){
        if($v.code -cne 'none' -or $v.queryInvoked -or $v.answerCount -ne 0 -or $v.recordCount -ne 0){throw 'Fresh DNS readiness shape'}
    }elseif($v.outcome -ceq 'answered'){
        if($v.code -cne 'none' -or -not $v.queryInvoked -or $v.answerCount -lt 1 -or $v.answerCount -gt $v.recordCount){throw 'Fresh DNS answer shape'}
    }else{
        if($v.code -ceq 'none' -or $v.answerCount -ne 0){throw 'Fresh DNS refusal shape'}
        if($v.code -cin @('environment','arguments')){if($v.queryInvoked -or $v.recordCount -ne 0){throw 'Fresh DNS admission shape'}}
        elseif(-not $v.queryInvoked -or ($v.code -ceq 'query-failed' -and $v.recordCount -ne 0)){throw 'Fresh DNS query refusal shape'}
    }
    return $v
}
function Assert-NativeFreshDNSSources([object]$State) {
    foreach($file in $State.querySourceHashes.Keys){if((Get-FileHash -LiteralPath (Join-Path $State.queryProject $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.querySourceHashes[$file]){throw 'Fresh DNS source changed'}}
}
function Invoke-NativeFreshDNSQuery([object]$State,[string]$Name,[switch]$ExpectFailure,[switch]$Probe) {
    $State.queryLastEvidence=$null
    if(($Probe -and ($Name -or $ExpectFailure)) -or (-not $Probe -and $Name -cnotin @('example.com','example.net','example.org'))){throw 'Fresh DNS request boundary'}
    Assert-NativeFreshDNSSources $State
    if((Get-FileHash -LiteralPath $State.queryBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.queryBinarySHA256){throw 'Fresh DNS binary changed'}
    $arguments=if($Probe){@('--probe')}else{@('--query',$Name)}
    $text=Invoke-NativeDNSWireProcess $State $State.queryBinary $arguments
    Assert-NativeFreshDNSSources $State
    if((Get-FileHash -LiteralPath $State.queryBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.queryBinarySHA256){throw 'Fresh DNS binary changed'}
    $v=Get-NativeFreshDNSQueryReport $text $State.querySourceCommit $State.queryArchitecture
    # Preserve only the fully normalized closed report, including refusals.
    $State.queryLastEvidence=$v
    if($Probe){if($v.outcome -cne 'ready'){throw 'Fresh DNS readiness refused'}}
    elseif($ExpectFailure){if($v.outcome -cne 'refused' -or $v.code -cne 'query-failed' -or -not $v.queryInvoked){throw 'Fresh DNS blocked query not rejected'}}
    elseif($v.outcome -cne 'answered'){throw 'Fresh DNS ordinary lookup refused'}
    return $v
}
