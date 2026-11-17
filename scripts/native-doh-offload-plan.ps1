# Definitions only. General fixed-endpoint offload planning and closed public evidence.
function Get-NativeDoHOffloadFields([object]$Value,[string[]]$Keys) {
    if($Value -is [hashtable]){$names=@($Value.psbase.Keys)}elseif($Value -is [pscustomobject]){if(@($Value.PSObject.Properties | Where-Object {$_.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty}).Count){throw 'DoH offload plan'};$names=@($Value.PSObject.Properties.Name)}else{throw 'DoH offload plan'}
    if($names.Count -ne $Keys.Count -or @($names | Where-Object {$_ -cnotin $Keys}).Count){throw 'DoH offload plan'};$r=@{};foreach($key in $Keys){$r[$key]=$Value.$key};return $r
}
function ConvertTo-NativeDoHOffloadBinding([object]$Value) {
    $r=Get-NativeDoHOffloadFields $Value @('index','guid','name','description','instance','maximumVersion','V1IPv4Enabled','IPv4Enabled','IPv6Enabled')
    if(($r.index -isnot [uint32] -and $r.index -isnot [int] -and $r.index -isnot [long]) -or $r.index -lt 1 -or $r.index -gt 4294967295 -or $r.maximumVersion -isnot [int] -or $r.maximumVersion -lt 0 -or $r.maximumVersion -gt 2){throw 'DoH offload plan'};$r.index=[uint32]$r.index
    $id=[guid]::Empty;if($r.guid -isnot [string] -or -not [guid]::TryParse($r.guid,[ref]$id) -or $id -eq [guid]::Empty){throw 'DoH offload plan'};$r.guid=$id.ToString('D')
    foreach($key in @('name','description','instance')){if($r[$key] -isnot [string] -or $r[$key].Length -lt 1 -or $r[$key].Length -gt $(if($key -ceq 'instance'){4096}else{1024})){throw 'DoH offload plan'}}
    foreach($key in @('V1IPv4Enabled','IPv4Enabled','IPv6Enabled')){if($r[$key] -isnot [bool]){throw 'DoH offload plan'}};return $r
}
function New-NativeDoHOffloadPlan([object[]]$Observations,[object]$IPv4Table,[object]$IPv6Table) {
    if($Observations.Count -ne 4){throw 'DoH offload route'}
    $trace=Get-NativeDoHRouteEvidence ((ConvertTo-NativeDoHRouteEvidence $Observations) | ConvertTo-Json -Depth 5 -Compress);if($trace.code -cne 'complete' -or -not $trace.allConsistent){throw 'DoH offload route'}
    $tables=@($IPv4Table,$IPv6Table);foreach($table in $tables){$v=Get-NativeIPv6RouteTableEvidence ($table | ConvertTo-Json -Compress);if($v.code -cne 'complete' -or -not $v.consistent){throw 'DoH offload table'}}
    $entries=[Collections.Generic.List[object]]::new();$matched=0;$unrouted=0;$ordinal=0
    foreach($row in $Observations){
        $mask=@(1,2,4,8)[$ordinal];if($row.mask -ne $mask){throw 'DoH offload route'};$ordinal++;$table=if($mask -le 2){$IPv4Table}else{$IPv6Table};$firstMatches=if($mask -cin @(1,4)){$table.firstGoogleMatches}else{$table.firstQuad9Matches};$secondMatches=if($mask -cin @(1,4)){$table.secondGoogleMatches}else{$table.secondQuad9Matches}
        if($row.first.code -ceq 'matched' -and $row.second.code -ceq 'matched'){
            if($firstMatches -le 0 -or $secondMatches -le 0){throw 'DoH offload table'};$a=ConvertTo-NativeDoHOffloadBinding $row.first.binding;$b=ConvertTo-NativeDoHOffloadBinding $row.second.binding
            if(-not (Test-NativeOffloadBindingEqual $a $b)){throw 'DoH offload identity'};$matched=$matched -bor $mask;$entry=$null
            foreach($candidate in $entries){if($candidate.binding.guid -ceq $a.guid){$entry=$candidate;break}}
            if($null -eq $entry){foreach($other in $entries){if($other.binding.index -eq $a.index -or [string]::Equals($other.binding.instance,$a.instance,[StringComparison]::Ordinal) -or [string]::Equals($other.binding.description,$a.description,[StringComparison]::Ordinal)){throw 'DoH offload identity'}};$entry=@{binding=$a;endpointMask=0;familyMask=0};$entries.Add($entry)}elseif(-not (Test-NativeOffloadBindingEqual $entry.binding $a)){throw 'DoH offload identity'}
            $entry.endpointMask=$entry.endpointMask -bor $mask;$entry.familyMask=$entry.familyMask -bor $(if($mask -le 2){1}else{2})
        }else{if($firstMatches -ne 0 -or $secondMatches -ne 0){throw 'DoH offload route'};$unrouted=$unrouted -bor $mask}
    }
    if($entries.Count -lt 1 -or $entries.Count -gt 4 -or ($matched -bor $unrouted) -ne 15){throw 'DoH offload route'}
    foreach($entry in $entries){if($entry.binding.maximumVersion -lt 2 -and ((($entry.familyMask -band 1) -ne 0 -and $entry.binding.IPv4Enabled) -or (($entry.familyMask -band 2) -ne 0 -and $entry.binding.IPv6Enabled))){throw 'DoH offload capability'}}
    return @{schemaVersion=1;policy='product-doh-all';matchedMask=$matched;unroutedMask=$unrouted;adapters=@($entries.ToArray())}
}
function Read-NativeDoHOffloadPlan([object]$Value) {
    $p=Get-NativeDoHOffloadFields $Value @('schemaVersion','policy','matchedMask','unroutedMask','adapters')
    if($p.schemaVersion -isnot [int] -or $p.schemaVersion -ne 1 -or $p.policy -cne 'product-doh-all' -or $p.matchedMask -isnot [int] -or $p.unroutedMask -isnot [int] -or $p.matchedMask -lt 1 -or $p.matchedMask -gt 15 -or $p.unroutedMask -lt 0 -or $p.unroutedMask -gt 15 -or ($p.matchedMask -bor $p.unroutedMask) -ne 15 -or ($p.matchedMask -band $p.unroutedMask) -ne 0 -or $p.adapters -isnot [array] -or $p.adapters.Count -lt 1 -or $p.adapters.Count -gt 4){throw 'DoH offload plan'}
    $entries=[Collections.Generic.List[object]]::new();$ids=@{};$instances=@{};$indices=@{};$descriptions=@{};$seen=0
    foreach($value in $p.adapters){$e=Get-NativeDoHOffloadFields $value @('binding','endpointMask','familyMask');$e.binding=ConvertTo-NativeDoHOffloadBinding $e.binding
        if($e.endpointMask -isnot [int] -or $e.endpointMask -lt 1 -or $e.endpointMask -gt 15 -or ($e.endpointMask -band $seen) -ne 0 -or ($e.endpointMask -band $p.matchedMask) -ne $e.endpointMask -or $e.familyMask -isnot [int] -or $e.familyMask -ne ($(if(($e.endpointMask -band 3) -ne 0){1}else{0}) -bor $(if(($e.endpointMask -band 12) -ne 0){2}else{0})) -or $ids.ContainsKey($e.binding.guid) -or $instances.ContainsKey($e.binding.instance) -or $indices.ContainsKey([string]$e.binding.index) -or $descriptions.ContainsKey($e.binding.description)){throw 'DoH offload plan'}
        if($e.binding.maximumVersion -lt 2 -and ((($e.familyMask -band 1) -ne 0 -and $e.binding.IPv4Enabled) -or (($e.familyMask -band 2) -ne 0 -and $e.binding.IPv6Enabled))){throw 'DoH offload capability'}
        $seen=$seen -bor $e.endpointMask;$ids[$e.binding.guid]=$true;$instances[$e.binding.instance]=$true;$indices[[string]$e.binding.index]=$true;$descriptions[$e.binding.description]=$true;$entries.Add($e)
    };if($seen -ne $p.matchedMask){throw 'DoH offload plan'};$p.adapters=@($entries.ToArray());return $p
}
function Test-NativeDoHOffloadState([object]$Entry,[object]$Current,[string]$Mode) {
    if($Mode -cnotin @('stage','restore','recover') -or -not (Test-NativeOffloadOwner $Entry.binding $Current) -or $Entry.binding.maximumVersion -ne $Current.maximumVersion -or $Entry.binding.V1IPv4Enabled -ne $Current.V1IPv4Enabled){return $false}
    foreach($spec in @(@{key='IPv4Enabled';bit=1},@{key='IPv6Enabled';bit=2})){
        $original=$Entry.binding[$spec.key];$value=$Current[$spec.key];if($value -isnot [bool]){return $false};$targeted=($Entry.familyMask -band $spec.bit) -ne 0
        if($Mode -ceq 'restore' -or -not $targeted){if($original -ne $value){return $false}}elseif($Mode -ceq 'stage'){if($value){return $false}}elseif(-not $original -and $value){return $false}
    };return $true
}
function Test-NativeDoHOffloadTopology([object]$Before,[object]$After) {
    if($Before.matchedMask -ne $After.matchedMask -or $Before.unroutedMask -ne $After.unroutedMask -or $Before.adapters.Count -ne $After.adapters.Count){return $false}
    foreach($entry in $Before.adapters){$found=$false;foreach($current in $After.adapters){if($current.endpointMask -eq $entry.endpointMask -and $current.familyMask -eq $entry.familyMask -and (Test-NativeOffloadOwner $entry.binding $current.binding)){$found=$true;break}};if(-not $found){return $false}};return $true
}
function New-NativeDoHOffloadEvidence([string]$Operation) {return @{schemaVersion=1;operation=$Operation;code='not-inspected';adapters=0;matchedMask=0;unroutedMask=0;ordinal=-1;identityVerified=$false;readbackVerified=$false;changed=$false;restartRequested=$false;restartReturned=$false;restored=$false;topologyVerified=$false}}
function Get-NativeDoHOffloadEvidence([string]$Text,[string]$Operation) {
    $bad=New-NativeDoHOffloadEvidence $Operation;$bad.code='invalid';if($Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('schemaVersion','operation','code','adapters','matchedMask','unroutedMask','ordinal','identityVerified','readbackVerified','changed','restartRequested','restartReturned','restored','topologyVerified')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 14 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.operation -cne $Operation -or $Operation -cnotin @('prepare','stage','restore','verify') -or $v.code -cnotin @('none','environment','path','plan','inventory','route','table','identity','state','capability','apply','readback','output','table-bound','table-class','table-family','table-store','table-index','table-prefix','table-next-hop','table-metric')){return $bad}
    foreach($key in @('adapters','matchedMask','unroutedMask','ordinal')){if($v.$key -isnot [int]){return $bad}};if($v.adapters -lt 0 -or $v.adapters -gt 4 -or $v.matchedMask -lt 0 -or $v.matchedMask -gt 15 -or $v.unroutedMask -lt 0 -or $v.unroutedMask -gt 15 -or $v.ordinal -lt -1 -or $v.ordinal -gt 3){return $bad}
    foreach($key in @('identityVerified','readbackVerified','changed','restartRequested','restartReturned','restored','topologyVerified')){if($v.$key -isnot [bool]){return $bad}}
    if($v.code -ceq 'none'){
        if($v.adapters -lt 1 -or $v.matchedMask -lt 1 -or ($v.matchedMask -bor $v.unroutedMask) -ne 15 -or ($v.matchedMask -band $v.unroutedMask) -ne 0 -or -not $v.identityVerified -or -not $v.readbackVerified -or $v.restartRequested -ne $v.changed -or $v.restartReturned -ne $v.changed -or $v.restored -ne ($Operation -ceq 'restore')){return $bad}
        if($Operation -cin @('prepare','verify')){if($v.ordinal -ne -1 -or $v.changed -or -not $v.topologyVerified){return $bad}}elseif($v.ordinal -lt 0 -or $v.ordinal -ge $v.adapters -or $v.topologyVerified){return $bad}
    };$r=New-NativeDoHOffloadEvidence $Operation;foreach($key in $keys){$r[$key]=$v.$key};return $r
}
