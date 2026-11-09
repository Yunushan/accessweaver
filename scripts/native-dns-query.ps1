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
# Independent diagnostic definitions. Never publish candidate server addresses.
function Select-NativeDNSDiagnosticServer([object[]]$Adapters,[object[]]$Rows) {
    $active=@($Adapters | Where-Object {$_.Status -ceq 'Up' -and $_.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN'} | ForEach-Object {[int]$_.ifIndex})
    if($active.Count -eq 0){return @{server=$null;code='no-active-adapter'}}
    $found=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($row in $Rows){
        if([int]$row.InterfaceIndex -notin $active){continue}
        foreach($value in @($row.ServerAddresses)){
            $address=$null
            if($value -isnot [string] -or -not [Net.IPAddress]::TryParse($value,[ref]$address)){return @{server=$null;code='invalid-address'}}
            if($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return @{server=$null;code='ipv6-present'}}
            $bytes=$address.GetAddressBytes()
            if($bytes[0] -eq 0 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)){return @{server=$null;code='ineligible-address'}}
            [void]$found.Add($address.ToString())
        }
    }
    if($found.Count -eq 0){return @{server=$null;code='no-server'}}
    if($found.Count -ne 1){return @{server=$null;code='multiple-servers'}}
    return @{server=@($found)[0];code='selected'}
}
function Get-NativeDNSDirectValue([object]$Value) {
    $keys=@('outcome','code','answerCount')
    if($Value -isnot [pscustomobject] -or @($Value.PSObject.Properties).Count -ne 3 -or @($Value.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $Value.outcome -cnotin @('answered','refused') -or $Value.code -cnotin @('none','server','arguments','timeout','cancelled','query-failed','answer-bound','answer-shape','no-ipv4') -or ($Value.answerCount -isnot [int] -and $Value.answerCount -isnot [long]) -or $Value.answerCount -lt 0 -or $Value.answerCount -gt 64){throw 'Direct DNS result shape'}
    if($Value.outcome -ceq 'answered'){if($Value.code -cne 'none' -or $Value.answerCount -lt 1){throw 'Direct DNS answer shape'}}elseif($Value.code -ceq 'none' -or $Value.answerCount -ne 0){throw 'Direct DNS refusal shape'}
    return $Value
}
function Get-NativeDNSDiagnosticReport([string]$Text,[string]$Source,[string]$Architecture,[string]$Mode) {
    if($Text.Length -gt 4096 -or $Source -cnotmatch '^[a-f0-9]{40}$' -or $Architecture -cnotin @('amd64','arm64') -or $Mode -cnotin @('direct','compare')){throw 'Diagnostic DNS boundary'}
    try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{throw 'Diagnostic DNS JSON'}
    $keys=if($Mode -ceq 'direct'){@('schemaVersion','sourceCommit','architecture','result','productionQualificationComplete')}else{@('schemaVersion','sourceCommit','architecture','outcome','code','pair','productionQualificationComplete')}
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne $keys.Count -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.sourceCommit -cne $Source -or $v.architecture -cne $Architecture -or $v.productionQualificationComplete -isnot [bool] -or $v.productionQualificationComplete){throw 'Diagnostic DNS envelope'}
    if($Mode -ceq 'direct'){[void](Get-NativeDNSDirectValue $v.result);return $v}
    if($v.outcome -cnotin @('observed','refused') -or $v.code -cnotin @('none','server','no-overlap')){throw 'Diagnostic DNS comparison'}
    if($null -eq $v.pair){if($v.outcome -cne 'refused' -or $v.code -cne 'server'){throw 'Diagnostic DNS missing pair'};return $v}
    $pair=$v.pair;$pairKeys=@('first','second','overlapped')
    if($pair -isnot [pscustomobject] -or @($pair.PSObject.Properties).Count -ne 3 -or @($pair.PSObject.Properties.Name | Where-Object {$_ -cnotin $pairKeys}).Count -ne 0 -or $pair.overlapped -isnot [bool]){throw 'Diagnostic DNS pair'}
    foreach($part in @($pair.first,$pair.second)){
        $partKeys=@('startMicroseconds','endMicroseconds','value')
        if($part -isnot [pscustomobject] -or @($part.PSObject.Properties).Count -ne 3 -or @($part.PSObject.Properties.Name | Where-Object {$_ -cnotin $partKeys}).Count -ne 0){throw 'Diagnostic DNS timing shape'}
        foreach($key in @('startMicroseconds','endMicroseconds')){if(($part.$key -isnot [int] -and $part.$key -isnot [long]) -or $part.$key -lt 0 -or $part.$key -gt 15000000){throw 'Diagnostic DNS timing bound'}}
        if($part.endMicroseconds -lt $part.startMicroseconds){throw 'Diagnostic DNS timing order'}
    }
    [void](Get-NativeFreshDNSQueryReport ($pair.first.value | ConvertTo-Json -Compress -Depth 4) $Source $Architecture)
    [void](Get-NativeDNSDirectValue $pair.second.value)
    $overlap=($pair.first.startMicroseconds -lt $pair.second.endMicroseconds -and $pair.second.startMicroseconds -lt $pair.first.endMicroseconds)
    if($pair.overlapped -ne $overlap -or ($overlap -and ($v.outcome -cne 'observed' -or $v.code -cne 'none')) -or (-not $overlap -and ($v.outcome -cne 'refused' -or $v.code -cne 'no-overlap'))){throw 'Diagnostic DNS overlap'}
    return $v
}
function Invoke-NativeDNSDiagnostic([object]$State,[string]$Server,[string]$Mode) {
    if($Mode -cnotin @('direct','compare') -or $Server -notmatch '^[0-9.]{7,15}$'){throw 'Diagnostic DNS request'}
    Assert-NativeFreshDNSSources $State
    if((Get-FileHash -LiteralPath $State.queryBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.queryBinarySHA256){throw 'Diagnostic DNS binary changed'}
    $text=Invoke-NativeDNSWireProcess $State $State.queryBinary @('--'+$Mode) ([Text.Encoding]::ASCII.GetBytes($Server))
    Assert-NativeFreshDNSSources $State
    if((Get-FileHash -LiteralPath $State.queryBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.queryBinarySHA256){throw 'Diagnostic DNS binary changed'}
    return (Get-NativeDNSDiagnosticReport $text $State.querySourceCommit $State.queryArchitecture $Mode)
}
