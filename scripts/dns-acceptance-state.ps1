# Independent native acceptance oracle. Reads state only; the round-trip callback
# is supplied by the disposable guest harness. No product worker is imported.
function Convert-DNSAcceptanceGuid([object]$Value) {
    $parsed=[guid]::Empty
    if($Value -isnot [string] -or -not [guid]::TryParse($Value,[ref]$parsed) -or $parsed -eq [guid]::Empty){throw 'Invalid DNS acceptance adapter identity'}
    return $parsed.ToString('D')
}
function Convert-DNSAcceptanceAddress([object]$Value,[string]$Family,[int]$InterfaceIndex=0) {
    $parsed=$null
    if($Value -isnot [string] -or -not [Net.IPAddress]::TryParse($Value,[ref]$parsed)){throw 'Invalid DNS acceptance address'}
    if(($Family -eq 'IPv4' -and $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) -or ($Family -eq 'IPv6' -and $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6)){throw 'DNS acceptance address family mismatch'}
    if($Family -ceq 'IPv6' -and $parsed.ScopeId -gt 0){
        if(-not $parsed.IsIPv6LinkLocal -or $InterfaceIndex -le 0 -or $parsed.ScopeId -ne $InterfaceIndex){throw 'DNS acceptance IPv6 scope does not identify this adapter'}
        # The enclosing record supplies stable GUID identity for link-local DNS.
        $parsed.ScopeId=0
    }
    return $parsed.ToString()
}
function Read-DNSAcceptanceState([ref]$Stage) {
    if($null -ne $Stage){$Stage.Value='inventory'}
    $inventory=@(Get-NetAdapter -ErrorAction Stop)
    if($inventory.Count -eq 0){throw 'DNS acceptance adapter inventory is empty'}
    $known=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$adapters=@()
    foreach($adapter in $inventory){
        $guid=Convert-DNSAcceptanceGuid ([string]$adapter.InterfaceGuid)
        if(-not $known.Add($guid)){throw 'Duplicate DNS acceptance adapter identity'}
        $families=@{}
        foreach($family in @('IPv4','IPv6')){
            $service=if($family -eq 'IPv4'){'Tcpip'}else{'Tcpip6'}
            $path='HKLM:\SYSTEM\CurrentControlSet\Services\'+$service+'\Parameters\Interfaces\{'+$guid+'}'
            if($null -ne $Stage){$Stage.Value=if($family -ceq 'IPv4'){'registry-ipv4'}else{'registry-ipv6'}}
            $items=@(Get-ItemProperty -LiteralPath $path -ErrorAction Stop)
            if($items.Count -ne 1 -or $null -eq $items[0]){throw 'DNS acceptance registry inspection incomplete'}
            $property=$items[0].PSObject.Properties['NameServer'];$value=if($null -ne $property){$property.Value}else{$null}
            if($null -ne $value -and $value -isnot [string]){throw 'DNS acceptance registry mode is malformed'}
            $mode=if([string]::IsNullOrWhiteSpace($value)){'dhcp'}else{'static'}
            if($null -ne $Stage){$Stage.Value=if($family -ceq 'IPv4'){'servers-ipv4'}else{'servers-ipv6'}}
            $settings=@(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family -ErrorAction Stop)
            if($settings.Count -ne 1 -or $null -eq $settings[0]){throw 'DNS acceptance address inspection incomplete'}
            $servers=@()
            if($mode -eq 'static'){
                foreach($address in @($settings[0].ServerAddresses)){$servers+=@(Convert-DNSAcceptanceAddress $address $family $adapter.ifIndex)}
                if($servers.Count -eq 0){throw 'DNS acceptance static servers are missing'}
            }
            # DHCP leases can legitimately supply different servers after reboot.
            # The independent registry read proves reset mode, not lease equality.
            $families[$family]=@{mode=$mode;servers=@($servers)}
        }
        $adapters+=@{guid=$guid;selected=($adapter.Status -eq 'Up' -and $adapter.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN');ipv4=$families.IPv4;ipv6=$families.IPv6}
    }
    if($null -ne $Stage){$Stage.Value='doh-capability'}
    $available=[bool](Get-Command 'Get-DnsClientDohServerAddress' -ErrorAction SilentlyContinue)
    $doh=@();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if($available){
        if($null -ne $Stage){$Stage.Value='doh-metadata'}
        foreach($entry in @(Get-DnsClientDohServerAddress -ErrorAction Stop)){
            if($null -eq $entry){throw 'DNS acceptance DoH inspection incomplete'}
            $address=Convert-DNSAcceptanceAddress $entry.ServerAddress ''
            if(-not $seen.Add($address) -or $entry.DohTemplate -isnot [string] -or [string]::IsNullOrWhiteSpace($entry.DohTemplate) -or $entry.AllowFallbackToUdp -isnot [bool] -or $entry.AutoUpgrade -isnot [bool]){throw 'DNS acceptance DoH metadata malformed or duplicated'}
            $doh+=@{address=$address;template=$entry.DohTemplate;fallback=$entry.AllowFallbackToUdp;upgrade=$entry.AutoUpgrade}
        }
    }
    if($null -ne $Stage){$Stage.Value='complete'}
    return @{schemaVersion=1;adapters=@($adapters);dohAvailable=$available;doh=@($doh)}
}
function Get-DNSAcceptanceIndex([object]$State) {
    if($null -eq $State -or ($State.schemaVersion -isnot [int] -and $State.schemaVersion -isnot [long]) -or $State.schemaVersion -ne 1 -or $State.dohAvailable -isnot [bool] -or @($State.adapters).Count -eq 0){throw 'DNS acceptance state schema is invalid; prepare a new baseline'}
    $adapters=@{};$doh=@{}
    foreach($record in @($State.adapters)){
        $guid=Convert-DNSAcceptanceGuid $record.guid
        if($adapters.ContainsKey($guid) -or $record.selected -isnot [bool]){throw 'DNS acceptance adapter state is duplicated or malformed'}
        foreach($family in @('IPv4','IPv6')){
            $item=if($family -eq 'IPv4'){$record.ipv4}else{$record.ipv6}
            if($null -eq $item -or $item.mode -cnotin @('dhcp','static')){throw 'DNS acceptance saved mode is invalid'}
            $servers=@($item.servers)
            if(($item.mode -ceq 'dhcp' -and $servers.Count -ne 0) -or ($item.mode -ceq 'static' -and $servers.Count -eq 0)){throw 'DNS acceptance saved server list is invalid'}
            foreach($address in $servers){[void](Convert-DNSAcceptanceAddress $address $family)}
        }
        $adapters[$guid]=$record
    }
    foreach($entry in @($State.doh)){
        $address=Convert-DNSAcceptanceAddress $entry.address ''
        if($doh.ContainsKey($address) -or $entry.template -isnot [string] -or [string]::IsNullOrWhiteSpace($entry.template) -or $entry.fallback -isnot [bool] -or $entry.upgrade -isnot [bool]){throw 'DNS acceptance saved DoH metadata is malformed or duplicated'}
        $doh[$address]=$entry
    }
    if(-not $State.dohAvailable -and $doh.Count -ne 0){throw 'DNS acceptance DoH capability metadata is inconsistent'}
    return @{adapters=$adapters;doh=$doh}
}
function Assert-DNSAcceptanceRestored([object]$Before,[object]$After) {
    $expected=Get-DNSAcceptanceIndex $Before;$actual=Get-DNSAcceptanceIndex $After
    if($expected.adapters.Count -ne $actual.adapters.Count){throw 'DNS acceptance adapter inventory changed'}
    foreach($guid in $expected.adapters.Keys){
        if(-not $actual.adapters.ContainsKey($guid)){throw 'DNS acceptance original adapter is missing'}
        foreach($family in @('ipv4','ipv6')){
            $old=$expected.adapters[$guid].$family;$new=$actual.adapters[$guid].$family
            if($old.mode -cne $new.mode){throw 'DNS acceptance original DHCP/static mode differs'}
            $oldServers=@($old.servers);$newServers=@($new.servers)
            if($oldServers.Count -ne $newServers.Count){throw 'DNS acceptance original static server count differs'}
            for($i=0;$i -lt $oldServers.Count;$i++){
                if((Convert-DNSAcceptanceAddress $oldServers[$i] '') -cne (Convert-DNSAcceptanceAddress $newServers[$i] '')){throw 'DNS acceptance original static server order or value differs'}
            }
        }
    }
    if($Before.dohAvailable -ne $After.dohAvailable -or $expected.doh.Count -ne $actual.doh.Count){throw 'DNS acceptance original DoH capability or inventory differs'}
    foreach($address in $expected.doh.Keys){
        if(-not $actual.doh.ContainsKey($address)){throw 'DNS acceptance original DoH entry is missing'}
        $old=$expected.doh[$address];$new=$actual.doh[$address]
        if($old.template -cne $new.template -or $old.fallback -ne $new.fallback -or $old.upgrade -ne $new.upgrade){throw 'DNS acceptance original DoH metadata differs'}
    }
}
function Assert-DNSAcceptanceConfigured([object]$Before,[object]$Current,[string]$Method) {
    if($Method -cnotin @('doh','dnscrypt')){throw 'Unknown DNS acceptance method'}
    $original=Get-DNSAcceptanceIndex $Before;$actual=Get-DNSAcceptanceIndex $Current
    $selected=@($original.adapters.Values | Where-Object {$_.selected})
    if($selected.Count -eq 0){throw 'DNS acceptance has no selected original adapter'}
    $v4=if($Method -ceq 'doh'){@('8.8.8.8','9.9.9.9')}else{@('127.0.0.1')}
    $v6=if($Method -ceq 'doh'){@('2001:4860:4860::8888','2620:fe::fe')}else{@('::1')}
    foreach($record in $selected){
        $guid=Convert-DNSAcceptanceGuid $record.guid
        if(-not $actual.adapters.ContainsKey($guid)){throw 'DNS acceptance configured adapter is missing'}
        foreach($family in @('ipv4','ipv6')){
            [string[]]$expected=if($family -eq 'ipv4'){@($v4)}else{@($v6)};$observed=$actual.adapters[$guid].$family;$servers=@($observed.servers)
            if($observed.mode -cne 'static' -or $servers.Count -ne $expected.Count){throw 'DNS acceptance configured family or mode differs'}
            for($i=0;$i -lt $expected.Count;$i++){if((Convert-DNSAcceptanceAddress $servers[$i] '') -cne $expected[$i]){throw 'DNS acceptance configured server differs'}}
        }
    }
    if($Method -ceq 'doh'){
        if(-not $Current.dohAvailable){throw 'Native DoH acceptance capability missing'}
        foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
            $template=if($address -in @('8.8.8.8','2001:4860:4860::8888')){'https://dns.google/dns-query'}else{'https://dns.quad9.net/dns-query'}
            if(-not $actual.doh.ContainsKey($address)){throw 'Native DoH acceptance provider missing'}
            $entry=$actual.doh[$address]
            if($entry.template -cne $template -or $entry.fallback -or -not $entry.upgrade){throw 'Native DoH acceptance provider policy differs'}
        }
    }
}
function Invoke-DNSAcceptanceRoundTrip([string]$Method,[scriptblock]$Apply) {
    if($Method -cnotin @('doh','dnscrypt') -or $null -eq $Apply){throw 'Invalid DNS acceptance round-trip request'}
    $before=Read-DNSAcceptanceState;$operationError=$null;$restoreError=$null
    try {
        [void](& $Apply @{action='dns';dns=$Method})
        if($Method -ceq 'dnscrypt' -and (Get-Service 'AccessWeaver-dnscrypt' -ErrorAction Stop).Status -ne 'Running'){throw 'DNSCrypt acceptance service is not running'}
        Assert-DNSAcceptanceConfigured $before (Read-DNSAcceptanceState) $Method
        Clear-DnsClientCache -ErrorAction Stop
        [void](Resolve-DnsName 'example.com' -DnsOnly -QuickTimeout -ErrorAction Stop)
    } catch {$operationError=$_.Exception}
    try {
        [void](& $Apply @{action='dns-restore'})
        Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState)
    } catch {$restoreError=$_.Exception}
    if($null -ne $operationError -and $null -ne $restoreError){throw [AggregateException]::new('DNS acceptance operation and restoration failed',[Exception[]]@($operationError,$restoreError))}
    if($null -ne $operationError){throw $operationError}
    if($null -ne $restoreError){throw $restoreError}
}
