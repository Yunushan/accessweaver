# Pure count-only baseline classification. Live inventory is supplied by the
# guarded collector; addresses, adapter identities and templates stay private.
function New-DoHBaselineResolverEvidence([string]$Code='not-inspected') {
    return @{schemaVersion=1;code=$Code;captured=$false;selectedAdapters=0;exposedFamilies=0;dhcpFamilies=0;staticFamilies=0;unexposedFamilies=0;resolverAddresses=0;knownResolverAddresses=0;otherResolverAddresses=0;resolverProviderMask=0;metadataMask=0;namedTemplateMask=0;literalTemplateMask=0;otherTemplateMask=0;autoUpgradeMask=0;udpFallbackMask=0}
}
function Get-DoHBaselineFailure([Exception]$Exception) {
    $current=$Exception
    for($depth=0;$null -ne $current -and $depth -lt 16;$depth++){
        switch -CaseSensitive ($current.Message){
            'Baseline inventory bound' {return 'bound'}
            'Baseline adapter duplicate' {return 'adapter'}
            'Baseline adapter missing' {return 'adapter'}
            'Baseline adapter changed' {return 'adapter'}
            'Invalid DNS acceptance adapter identity' {return 'adapter'}
            'Baseline client identity' {return 'inventory'}
            'Baseline client duplicate' {return 'inventory'}
            'Baseline client family' {return 'family'}
            'Baseline family changed' {return 'family'}
            'Baseline family missing' {return 'family'}
            'Baseline resolver count' {return 'address'}
            'Baseline static resolver count changed' {return 'address'}
            'Baseline static resolver changed' {return 'address'}
            'Invalid DNS acceptance address' {return 'address'}
            'DNS acceptance address family mismatch' {return 'address'}
            'DNS acceptance IPv6 scope does not identify this adapter' {return 'scope'}
        }
        $current=$current.InnerException
    }
    return 'read'
}
function Get-DoHBaselineResolverEvidence([object]$Before,[object[]]$FirstAdapters,[object[]]$ClientRows,[object[]]$LastAdapters) {
    if(@($FirstAdapters).Count -lt 1 -or @($FirstAdapters).Count -gt 256 -or @($LastAdapters).Count -lt 1 -or @($LastAdapters).Count -gt 256 -or @($ClientRows).Count -gt 512 -or @($Before.adapters).Count -gt 256 -or @($Before.doh).Count -gt 256){throw 'Baseline inventory bound'}
    $original=Get-DNSAcceptanceIndex $Before;$first=@{};$last=@{}
    foreach($pair in @(@{input=$FirstAdapters;output=$first},@{input=$LastAdapters;output=$last})){
        foreach($adapter in $pair.input){$guid=Convert-DNSAcceptanceGuid ([string]$adapter.InterfaceGuid);if($pair.output.ContainsKey($guid)){throw 'Baseline adapter duplicate'};$pair.output[$guid]=$adapter}
    }
    $clients=@{}
    foreach($row in $ClientRows){
        $index=0
        if($null -eq $row -or -not [int]::TryParse([string]$row.InterfaceIndex,[ref]$index) -or $index -le 0){throw 'Baseline client identity'}
        $family=switch([string]$row.AddressFamily){ {$_ -in @('2','IPv4','InterNetwork')} {'IPv4'} {$_ -in @('23','IPv6','InterNetworkV6')} {'IPv6'} default {throw 'Baseline client family'}}
        $key=([string]$index)+'/'+$family;if($clients.ContainsKey($key)){throw 'Baseline client duplicate'};$clients[$key]=$row
    }
    $fixed=@{'8.8.8.8'=1;'9.9.9.9'=2;'2001:4860:4860::8888'=4;'2620:fe::fe'=8}
    $r=New-DoHBaselineResolverEvidence 'complete'
    foreach($record in $original.adapters.Values){
        if(-not $record.selected){continue};$guid=Convert-DNSAcceptanceGuid $record.guid
        if(-not $first.ContainsKey($guid) -or -not $last.ContainsKey($guid)){throw 'Baseline adapter missing'}
        $firstIndex=0;$lastIndex=0
        if(-not [int]::TryParse([string]$first[$guid].ifIndex,[ref]$firstIndex) -or -not [int]::TryParse([string]$last[$guid].ifIndex,[ref]$lastIndex) -or $firstIndex -le 0 -or $firstIndex -ne $lastIndex -or [string]$first[$guid].Status -cne 'Up' -or [string]$last[$guid].Status -cne 'Up'){throw 'Baseline adapter changed'}
        $r.selectedAdapters++
        foreach($family in @('IPv4','IPv6')){
            $saved=if($family -ceq 'IPv4'){$record.ipv4}else{$record.ipv6};$key=([string]$firstIndex)+'/'+$family
            if($saved.mode -ceq 'not-exposed'){if($clients.ContainsKey($key)){throw 'Baseline family changed'};$r.unexposedFamilies++;continue}
            if(-not $clients.ContainsKey($key)){throw 'Baseline family missing'};$r.exposedFamilies++
            if($saved.mode -ceq 'dhcp'){$r.dhcpFamilies++}else{$r.staticFamilies++}
            $values=@(if($null -ne $clients[$key].ServerAddresses){$clients[$key].ServerAddresses})
            if($values.Count -gt 16){throw 'Baseline resolver count'}
            $ordinal=0
            if($saved.mode -ceq 'static' -and @($saved.servers).Count -ne $values.Count){throw 'Baseline static resolver count changed'}
            foreach($value in $values){
                $address=Convert-DNSAcceptanceAddress $value $family $firstIndex
                if($saved.mode -ceq 'static' -and $address -cne (Convert-DNSAcceptanceAddress $saved.servers[$ordinal] $family)){throw 'Baseline static resolver changed'}
                $ordinal++;$r.resolverAddresses++
                if($fixed.ContainsKey($address)){$r.knownResolverAddresses++;$r.resolverProviderMask=$r.resolverProviderMask -bor $fixed[$address]}else{$r.otherResolverAddresses++}
            }
        }
    }
    if($r.selectedAdapters -eq 0){throw 'Baseline selected adapter missing'}
    foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
        if(-not $original.doh.ContainsKey($address)){continue};$entry=$original.doh[$address];$mask=$fixed[$address];$r.metadataMask=$r.metadataMask -bor $mask
        $named=if($mask -in @(1,4)){'https://dns.google/dns-query'}else{'https://dns.quad9.net/dns-query'}
        $literal=switch -CaseSensitive ($address){'8.8.8.8'{'https://8.8.8.8/dns-query'}'9.9.9.9'{'https://9.9.9.9/dns-query'}'2001:4860:4860::8888'{'https://[2001:4860:4860::8888]/dns-query'}'2620:fe::fe'{'https://[2620:fe::fe]/dns-query'}}
        if($entry.template -ceq $named){$r.namedTemplateMask=$r.namedTemplateMask -bor $mask}elseif($entry.template -ceq $literal){$r.literalTemplateMask=$r.literalTemplateMask -bor $mask}else{$r.otherTemplateMask=$r.otherTemplateMask -bor $mask}
        if($entry.upgrade){$r.autoUpgradeMask=$r.autoUpgradeMask -bor $mask};if($entry.fallback){$r.udpFallbackMask=$r.udpFallbackMask -bor $mask}
    }
    $r.captured=$true;return $r
}
