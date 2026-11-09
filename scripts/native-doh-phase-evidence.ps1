# Pure closed count-only phase projections. Private ticks/vectors never enter these objects.
function Get-DoHPhaseNumberKeys {return @('records','frames','before','at','after','tcpBefore','tcpAt','tcpAfter','udpBefore','udpAt','udpAfter','sentBefore','sentAt','sentAfter','receivedBefore','receivedAt','receivedAfter')}
function New-DoHPhaseReadEvidence([string]$Code='not-inspected'){return @{schemaVersion=1;code=$Code;records=0;frames=0;privateMapWritten=$false}}
function Get-DoHPhaseReadEvidence([string]$Text) {
    $bad=New-DoHPhaseReadEvidence 'invalid';if($Text.Length -gt 2048){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('schemaVersion','code','records','frames','privateMapWritten')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 5 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.code -cnotin @('none','environment','boundary','path','read','timestamp','bound','source','output') -or $v.privateMapWritten -isnot [bool]){return $bad}
    foreach($key in @('records','frames')){if(($v.$key -isnot [int] -and $v.$key -isnot [long]) -or $v.$key -lt 0 -or $v.$key -gt 4096){return $bad}}
    if($v.frames -gt $v.records -or ($v.code -ceq 'none') -ne $v.privateMapWritten -or ($v.privateMapWritten -and $v.frames -lt 1)){return $bad}
    return @{schemaVersion=1;code=$v.code;records=$v.records;frames=$v.frames;privateMapWritten=$v.privateMapWritten}
}
function New-DoHPhaseEvidence([string]$Code='not-inspected') {
    $r=@{schemaVersion=1;outcome='not-inspected';code=$Code;nativeFrameDataRead=$false;sourceBound=$false;productionQualificationComplete=$false};foreach($key in (Get-DoHPhaseNumberKeys)){$r[$key]=0};return $r
}
function Get-DoHPhaseEvidence([string]$Text) {
    $bad=New-DoHPhaseEvidence 'invalid';$bad.outcome='refused';if($Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $numbers=Get-DoHPhaseNumberKeys;$keys=@('schemaVersion','outcome','code','nativeFrameDataRead','sourceBound','productionQualificationComplete')+$numbers
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne $keys.Count -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.outcome -cnotin @('complete','refused') -or $v.code -cnotin @('none','environment','private-path','private-file','private-document','phase-document','phase-source','phase-count','conversion') -or $v.nativeFrameDataRead -isnot [bool] -or $v.sourceBound -isnot [bool] -or $v.productionQualificationComplete -isnot [bool] -or $v.productionQualificationComplete){return $bad}
    foreach($key in $numbers){if(($v.$key -isnot [int] -and $v.$key -isnot [long]) -or $v.$key -lt 0 -or $v.$key -gt 4096){return $bad}}
    if($v.outcome -ceq 'complete'){
        if($v.code -cne 'none' -or -not $v.nativeFrameDataRead -or -not $v.sourceBound -or $v.frames -lt 1 -or $v.records -lt $v.frames -or $v.before+$v.at+$v.after -ne $v.frames){return $bad}
        foreach($bucket in @('Before','At','After')){if($v.('tcp'+$bucket)+$v.('udp'+$bucket) -ne $v.($bucket.ToLowerInvariant()) -or $v.('sent'+$bucket)+$v.('received'+$bucket) -ne $v.($bucket.ToLowerInvariant())){return $bad}}
    }elseif($v.code -ceq 'none' -or $v.sourceBound -or @($numbers | Where-Object {$v.$_ -ne 0}).Count -ne 0){return $bad}
    $r=New-DoHPhaseEvidence $v.code;$r.outcome=$v.outcome;$r.nativeFrameDataRead=$v.nativeFrameDataRead;$r.sourceBound=$v.sourceBound;foreach($key in $numbers){$r[$key]=$v.$key};return $r
}
