# Definitions only. Closed read-only route evidence; identities remain private.
function New-NativeDoHRouteEvidence([string]$Code='not-inspected') {
    return @{schemaVersion=1;code=$Code;matchedMask=0;sameAdapterMask=0;adapterCount=0;allConsistent=$false;allRoutesMatched=$false;records=@()}
}
function ConvertTo-NativeDoHRouteEvidence([object[]]$Observations) {
    if($Observations.Count -ne 4){throw 'DoH route bound'};$r=New-NativeDoHRouteEvidence 'complete';$rows=[Collections.Generic.List[object]]::new();$ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$base='';$ordinal=0;$r.allConsistent=$true
    foreach($item in $Observations){
        if($item.mask -ne @(1,2,4,8)[$ordinal]){throw 'DoH route mask'};$ordinal++;$first=$item.first;$second=$item.second
        $row=@{mask=[int]$item.mask;firstCode=$first.code;secondCode=$second.code;firstCategory=[int]$first.category;secondCategory=[int]$second.category;firstCimStatus=[int]$first.cimStatus;secondCimStatus=[int]$second.cimStatus;firstHresult=[int]$first.hresult;secondHresult=[int]$second.hresult;consistent=$false}
        if($first.code -ceq 'matched' -and $second.code -ceq 'matched'){
            foreach($binding in @($first.binding,$second.binding)){
                if($binding -isnot [hashtable] -or $binding.Count -ne 9){throw 'DoH route binding'}
                foreach($key in @('index','guid','name','description','instance','maximumVersion','V1IPv4Enabled','IPv4Enabled','IPv6Enabled')){if(-not $binding.ContainsKey($key)){throw 'DoH route binding'}}
                $id=[guid]::Empty;if($binding.index -isnot [uint32] -or $binding.index -eq 0 -or $binding.guid -isnot [string] -or -not [guid]::TryParse($binding.guid,[ref]$id) -or $id -eq [guid]::Empty){throw 'DoH route binding'}
            }
            $row.consistent=Test-NativeOffloadBindingEqual $first.binding $second.binding
            if($row.consistent){$r.matchedMask=$r.matchedMask -bor $item.mask;[void]$ids.Add($second.binding.guid);if($item.mask -eq 1){$base=$second.binding.guid};if($base -and $base -ceq $second.binding.guid){$r.sameAdapterMask=$r.sameAdapterMask -bor $item.mask}}
        }else{$row.consistent=($first.code -ceq $second.code -and $first.category -eq $second.category -and $first.cimStatus -eq $second.cimStatus -and $first.hresult -eq $second.hresult)}
        if(-not $row.consistent){$r.allConsistent=$false};$rows.Add($row)
    }
    $r.records=@($rows.ToArray());$r.adapterCount=$ids.Count;$r.allRoutesMatched=($r.matchedMask -eq 15 -and $r.allConsistent);return $r
}
function Get-NativeDoHRouteEvidence([string]$Text) {
    $bad=New-NativeDoHRouteEvidence 'invalid';if($Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('schemaVersion','code','matchedMask','sameAdapterMask','adapterCount','allConsistent','allRoutesMatched','records')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 8 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.code -cnotin @('complete','environment','metadata','inventory','read')){return $bad}
    foreach($key in @('matchedMask','sameAdapterMask','adapterCount')){if($v.$key -isnot [int] -or $v.$key -lt 0 -or $v.$key -gt $(if($key -ceq 'adapterCount'){4}else{15})){return $bad}}
    if($v.allConsistent -isnot [bool] -or $v.allRoutesMatched -isnot [bool] -or $v.records -isnot [array]){return $bad}
    if($v.code -cne 'complete'){if($v.matchedMask -ne 0 -or $v.sameAdapterMask -ne 0 -or $v.adapterCount -ne 0 -or $v.allConsistent -or $v.allRoutesMatched -or $v.records.Count -ne 0){return $bad};return (New-NativeDoHRouteEvidence $v.code)}
    if($v.records.Count -ne 4){return $bad};$ordinal=0;$matched=0;$consistent=$true;$rows=[Collections.Generic.List[object]]::new();$count=0
    $rowKeys=@('mask','firstCode','secondCode','firstCategory','secondCategory','firstCimStatus','secondCimStatus','firstHresult','secondHresult','consistent')
    foreach($row in $v.records){
        if($row -isnot [pscustomobject] -or @($row.PSObject.Properties).Count -ne 10 -or @($row.PSObject.Properties.Name | Where-Object {$_ -cnotin $rowKeys}).Count -ne 0 -or $row.mask -isnot [int] -or $row.mask -ne @(1,2,4,8)[$ordinal] -or $row.consistent -isnot [bool]){return $bad};$ordinal++
        foreach($prefix in @('first','second')){
            if($row.($prefix+'Code') -cnotin @('matched','empty','read-refused','binding-refused')){return $bad}
            foreach($part in @('Category','CimStatus','Hresult')){$value=$row.($prefix+$part);$min=if($part -ceq 'Hresult'){-2147483648}else{-1};$max=if($part -ceq 'Category'){255}elseif($part -ceq 'CimStatus'){65535}else{2147483647};if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt $min -or $value -gt $max){return $bad}}
            if($row.($prefix+'Code') -cne 'read-refused' -and ($row.($prefix+'Category') -ne -1 -or $row.($prefix+'CimStatus') -ne -1 -or $row.($prefix+'Hresult') -ne 0)){return $bad}
        }
        if($row.consistent){if($row.firstCode -cne $row.secondCode){return $bad};if($row.firstCode -ceq 'matched'){$matched=$matched -bor $row.mask;$count++}elseif($row.firstCategory -ne $row.secondCategory -or $row.firstCimStatus -ne $row.secondCimStatus -or $row.firstHresult -ne $row.secondHresult){return $bad}}else{$consistent=$false}
        $copy=@{};foreach($key in $rowKeys){$copy[$key]=$row.$key};$rows.Add($copy)
    }
    if($v.matchedMask -ne $matched -or $v.allConsistent -ne $consistent -or $v.allRoutesMatched -ne ($matched -eq 15 -and $consistent) -or (($v.sameAdapterMask -band $matched) -ne $v.sameAdapterMask) -or $v.adapterCount -gt $count -or (($v.adapterCount -eq 0) -ne ($count -eq 0))){return $bad}
    if(($matched -band 1) -eq 0){if($v.sameAdapterMask -ne 0){return $bad}}elseif(($v.sameAdapterMask -band 1) -eq 0 -or ($v.adapterCount -eq 1 -and $v.sameAdapterMask -ne $matched) -or ($v.adapterCount -gt 1 -and $v.sameAdapterMask -eq $matched)){return $bad}
    $r=New-NativeDoHRouteEvidence 'complete';foreach($key in @('matchedMask','sameAdapterMask','adapterCount','allConsistent','allRoutesMatched')){$r[$key]=$v.$key};$r.records=@($rows.ToArray());return $r
}
