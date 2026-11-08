# Definitions only. Complete bounded active IPv6 table projection; no route values published.
function Test-NativeIPv6PrefixMatch([byte[]]$Prefix,[int]$Bits,[byte[]]$Target) {
    if($Prefix.Length -ne 16 -or $Target.Length -ne 16 -or $Bits -lt 0 -or $Bits -gt 128){throw 'IPv6 route prefix'}
    $matched=$true;for($i=0;$i -lt 16;$i++){$remaining=[Math]::Max(0,[Math]::Min(8,$Bits-8*$i));$mask=if($remaining -eq 0){0}else{(255 -shl (8-$remaining)) -band 255};if(($Prefix[$i] -band (255 -bxor $mask)) -ne 0){throw 'IPv6 route prefix'};if(($Prefix[$i] -band $mask) -ne ($Target[$i] -band $mask)){$matched=$false}};return $matched
}
function Read-NativeIPv6RouteTable([object[]]$Rows) {
    if($Rows.Count -gt 256){throw 'IPv6 route bound'};$keys=[Collections.Generic.List[string]]::new();$google=[Net.IPAddress]::Parse('2001:4860:4860::8888').GetAddressBytes();$quad9=[Net.IPAddress]::Parse('2620:fe::fe').GetAddressBytes();$g=0;$q=0
    foreach($row in $Rows){
        if($row.CimClass.CimClassName -cne 'MSFT_NetRoute'){throw 'IPv6 route class'}
        $family=Get-NativeOffloadRaw $row 'AddressFamily';$store=Get-NativeOffloadRaw $row 'Store';$index=Get-NativeOffloadRaw $row 'InterfaceIndex';$prefix=Get-NativeOffloadRaw $row 'DestinationPrefix';$next=Get-NativeOffloadRaw $row 'NextHop';$metric=Get-NativeOffloadRaw $row 'RouteMetric'
        if($family -isnot [uint16] -or $family -ne 23){throw 'IPv6 route family'};if($store -isnot [byte] -or $store -ne 1){throw 'IPv6 route store'};if($index -isnot [uint32] -or $index -eq 0){throw 'IPv6 route index'};if($metric -isnot [uint16]){throw 'IPv6 route metric'}
        if($prefix -isnot [string] -or $prefix.Length -gt 80 -or $prefix -cnotmatch '^[0-9a-fA-F:]+/[0-9]{1,3}$'){throw 'IPv6 route prefix'};$parts=$prefix.Split('/');$ip=$null;$bits=[int]$parts[1]
        if($bits -gt 128 -or -not [Net.IPAddress]::TryParse($parts[0],[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6){throw 'IPv6 route prefix'};$bytes=$ip.GetAddressBytes()
        if(Test-NativeIPv6PrefixMatch $bytes $bits $google){$g++};if(Test-NativeIPv6PrefixMatch $bytes $bits $quad9){$q++}
        $hop=$null;if($next -isnot [string] -or $next.Length -gt 80 -or $next -cnotmatch '^[0-9a-fA-F:]+(%[0-9]{1,10})?$' -or -not [Net.IPAddress]::TryParse($next,[ref]$hop) -or $hop.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6){throw 'IPv6 route next-hop'}
        if($hop.ScopeId -ne 0){if(-not $hop.IsIPv6LinkLocal -or $hop.ScopeId -ne $index){throw 'IPv6 route next-hop'};$hop.ScopeId=0}
        $keys.Add($ip.ToString()+'/'+$bits.ToString([Globalization.CultureInfo]::InvariantCulture)+'|'+$index.ToString([Globalization.CultureInfo]::InvariantCulture)+'|'+$hop.ToString()+'|'+$metric.ToString([Globalization.CultureInfo]::InvariantCulture))
    };$keys.Sort([StringComparer]::Ordinal);return @{rows=$Rows.Count;googleMatches=$g;quad9Matches=$q;signatures=@($keys.ToArray())}
}
function New-NativeIPv6RouteTableEvidence([string]$Code='not-inspected') {return @{schemaVersion=1;code=$Code;firstRows=-1;secondRows=-1;firstGoogleMatches=-1;secondGoogleMatches=-1;firstQuad9Matches=-1;secondQuad9Matches=-1;consistent=$false;noEndpointRoutes=$false}}
function ConvertTo-NativeIPv6RouteTableEvidence([object]$First,[object]$Second) {
    $r=New-NativeIPv6RouteTableEvidence 'complete';$r.firstRows=$First.rows;$r.secondRows=$Second.rows;$r.firstGoogleMatches=$First.googleMatches;$r.secondGoogleMatches=$Second.googleMatches;$r.firstQuad9Matches=$First.quad9Matches;$r.secondQuad9Matches=$Second.quad9Matches;$r.consistent=($First.signatures.Count -eq $Second.signatures.Count)
    if($r.consistent){for($i=0;$i -lt $First.signatures.Count;$i++){if(-not [string]::Equals($First.signatures[$i],$Second.signatures[$i],[StringComparison]::Ordinal)){$r.consistent=$false;break}}};$r.noEndpointRoutes=($r.consistent -and $r.firstGoogleMatches -eq 0 -and $r.secondGoogleMatches -eq 0 -and $r.firstQuad9Matches -eq 0 -and $r.secondQuad9Matches -eq 0);return $r
}
function Get-NativeIPv6RouteTableEvidence([string]$Text) {
    $bad=New-NativeIPv6RouteTableEvidence 'invalid';if($Text.Length -gt 2048){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $counts=@('firstRows','secondRows','firstGoogleMatches','secondGoogleMatches','firstQuad9Matches','secondQuad9Matches');$keys=@('schemaVersion','code','consistent','noEndpointRoutes')+$counts
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 10 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.code -cnotin @('complete','environment','metadata','read','bound','class','family','store','index','prefix','next-hop','metric') -or $v.consistent -isnot [bool] -or $v.noEndpointRoutes -isnot [bool]){return $bad}
    foreach($key in $counts){if($v.$key -isnot [int] -or $v.$key -lt -1 -or $v.$key -gt 256){return $bad}}
    if($v.code -cne 'complete'){foreach($key in $counts){if($v.$key -ne -1){return $bad}};if($v.consistent -or $v.noEndpointRoutes){return $bad};return (New-NativeIPv6RouteTableEvidence $v.code)}
    foreach($key in $counts){if($v.$key -lt 0){return $bad}}
    if($v.firstGoogleMatches -gt $v.firstRows -or $v.firstQuad9Matches -gt $v.firstRows -or $v.secondGoogleMatches -gt $v.secondRows -or $v.secondQuad9Matches -gt $v.secondRows -or ($v.consistent -and ($v.firstRows -ne $v.secondRows -or $v.firstGoogleMatches -ne $v.secondGoogleMatches -or $v.firstQuad9Matches -ne $v.secondQuad9Matches)) -or $v.noEndpointRoutes -ne ($v.consistent -and $v.firstGoogleMatches -eq 0 -and $v.secondGoogleMatches -eq 0 -and $v.firstQuad9Matches -eq 0 -and $v.secondQuad9Matches -eq 0)){return $bad}
    $r=New-NativeIPv6RouteTableEvidence 'complete';foreach($key in $keys){$r[$key]=$v.$key};return $r
}
