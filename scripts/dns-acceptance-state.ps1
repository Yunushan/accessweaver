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
function Read-DNSAcceptanceRegistry([string]$Guid,[string]$Family) {
    $service=if($Family -ceq 'IPv4'){'Tcpip'}else{'Tcpip6'};$key=$null
    try {
        $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(('SYSTEM\CurrentControlSet\Services\'+$service+'\Parameters\Interfaces\{'+$Guid+'}'))
        if($null -eq $key){return @{present=$false;hasValue=$false;kind='absent';value=$null}}
        $hasValue=@($key.GetValueNames()) -icontains 'NameServer'
        if(-not $hasValue){return @{present=$true;hasValue=$false;kind='absent';value=$null}}
        return @{present=$true;hasValue=$true;kind=$key.GetValueKind('NameServer').ToString();value=$key.GetValue('NameServer',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
    } finally {if($null -ne $key){$key.Close()}}
}
function Get-DNSAcceptanceRegistryHash([object]$Registry) {
    $ordered=[ordered]@{present=$Registry.present;hasValue=$Registry.hasValue;kind=$Registry.kind;value=$Registry.value}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($ordered|ConvertTo-Json -Compress -Depth 6))
    if($bytes.Length -gt 65536){throw 'DNS acceptance dormant registry state exceeds its bound'}
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
}
function Read-DNSAcceptanceState([ref]$Stage,[ref]$Progress) {
    if($null -ne $Stage){$Stage.Value='inventory'}
    $inventory=@(Get-NetAdapter -ErrorAction Stop)
    if($null -ne $Progress){$Progress.Value=@{adapterTotal=$inventory.Count;adapterOrdinal=0;selected=$false}}
    if($inventory.Count -eq 0){throw 'DNS acceptance adapter inventory is empty'}
    if($null -ne $Stage){$Stage.Value='dns-inventory'}
    # Independent full inventory. Successful absence is an explicit state, never
    # inferred from a failed per-interface lookup or a missing registry key.
    $addresses=@(Get-DnsClientServerAddress -ErrorAction Stop);$clientIndex=@{}
    foreach($entry in $addresses){
        $index=[uint32]0
        if($null -eq $entry -or -not [uint32]::TryParse([string]$entry.InterfaceIndex,[ref]$index) -or $index -eq 0){throw 'DNS acceptance client identity malformed'}
        $family=switch([string]$entry.AddressFamily){ {$_ -in @('2','IPv4','InterNetwork')} {'IPv4'} {$_ -in @('23','IPv6','InterNetworkV6')} {'IPv6'} default {throw 'DNS acceptance client family malformed'}}
        $key=([string]$index)+'/'+$family
        if($clientIndex.ContainsKey($key)){throw 'DNS acceptance client family duplicated'};$clientIndex[$key]=$entry
    }
    $bindings=@{};$indexes=[Collections.Generic.HashSet[uint32]]::new();$adapters=@()
    foreach($adapter in $inventory){
        if($null -ne $Progress){$Progress.Value.adapterOrdinal++;$Progress.Value.selected=($adapter.Status -eq 'Up' -and $adapter.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN')}
        $guid=Convert-DNSAcceptanceGuid ([string]$adapter.InterfaceGuid)
        if($bindings.ContainsKey($guid)){throw 'Duplicate DNS acceptance adapter identity'}
        $index=[uint32]0
        if(-not [uint32]::TryParse([string]$adapter.ifIndex,[ref]$index) -or $index -eq 0 -or -not $indexes.Add($index)){
            throw 'DNS acceptance adapter changed during capture'
        }
        $eligible=$adapter.Status -eq 'Up' -and $adapter.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN'
        $bindings[$guid]=@{index=$index;eligible=$eligible}
        $current=@(Get-NetAdapter -ErrorAction Stop | Where-Object {(Convert-DNSAcceptanceGuid ([string]$_.InterfaceGuid)) -ceq $guid})
        if($current.Count -ne 1 -or $current[0].ifIndex -ne $adapter.ifIndex){throw 'DNS acceptance adapter changed during capture'}
        $families=@{};$exposed=$false
        foreach($family in @('IPv4','IPv6')){
            if($null -ne $Stage){$Stage.Value='registry-'+$family.ToLowerInvariant()}
            try {$registry=Read-DNSAcceptanceRegistry $guid $family} catch {
                if($null -ne $Stage){$Stage.Value='registry-error-'+$family.ToLowerInvariant()};throw
            }
            $key=([string]$adapter.ifIndex)+'/'+$family
            if(-not $clientIndex.ContainsKey($key)){
                $families[$family]=@{mode='not-exposed';servers=@();registryHash=(Get-DNSAcceptanceRegistryHash $registry)}
                continue
            }
            $exposed=$true
            if(-not $registry.present){throw 'DNS acceptance exposed-family registry state is missing'}
            if($null -ne $Stage){$Stage.Value='registry-mode-'+$family.ToLowerInvariant()}
            $value=$registry.value
            if($null -ne $value -and $value -isnot [string]){throw 'DNS acceptance registry mode is malformed'}
            $mode=if([string]::IsNullOrWhiteSpace($value)){'dhcp'}else{'static'};$servers=@()
            if($null -ne $Stage){$Stage.Value='servers-'+$family.ToLowerInvariant()}
            if($mode -ceq 'static'){
                foreach($address in @($clientIndex[$key].ServerAddresses)){$servers+=@(Convert-DNSAcceptanceAddress $address $family $adapter.ifIndex)}
                if($servers.Count -eq 0){throw 'DNS acceptance static servers are missing'}
            }
            $families[$family]=@{mode=$mode;servers=@($servers)}
        }
        $selected=$exposed -and $eligible
        if($null -ne $Progress){$Progress.Value.selected=$selected}
        $adapters+=@{guid=$guid;selected=$selected;ipv4=$families.IPv4;ipv6=$families.IPv6}
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
    # The DoH and registry reads can overlap a change after the last per-adapter
    # check. Fence the entire observation by GUID, index and selection inputs.
    if($null -ne $Stage){$Stage.Value='inventory'}
    $final=@(Get-NetAdapter -ErrorAction Stop)
    $seenAdapters=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if($final.Count -ne $bindings.Count){throw 'DNS acceptance adapter changed during capture'}
    foreach($adapter in $final){
        $guid=Convert-DNSAcceptanceGuid ([string]$adapter.InterfaceGuid)
        $binding=$bindings[$guid]
        $eligible=$adapter.Status -eq 'Up' -and $adapter.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN'
        if(-not $seenAdapters.Add($guid) -or $null -eq $binding -or
           $adapter.ifIndex -ne $binding.index -or $eligible -ne $binding.eligible){
            throw 'DNS acceptance adapter changed during capture'
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
            if($null -eq $item -or $item.mode -cnotin @('dhcp','static','not-exposed')){throw 'DNS acceptance saved mode is invalid'}
            $servers=@($item.servers)
            if(($item.mode -cin @('dhcp','not-exposed') -and $servers.Count -ne 0) -or ($item.mode -ceq 'static' -and $servers.Count -eq 0)){throw 'DNS acceptance saved server list is invalid'}
            if($item.mode -ceq 'not-exposed' -and ($item.registryHash -isnot [string] -or $item.registryHash -notmatch '^[a-f0-9]{64}$')){throw 'DNS acceptance dormant state fingerprint is missing'}
            foreach($address in $servers){[void](Convert-DNSAcceptanceAddress $address $family)}
        }
        if($record.selected -and $record.ipv4.mode -ceq 'not-exposed' -and $record.ipv6.mode -ceq 'not-exposed'){throw 'DNS acceptance selected adapter exposes no client'}
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
function Assert-DNSAcceptanceFamilyPreserved([object]$Old,[object]$New) {
    if($Old.mode -cne $New.mode){throw 'DNS acceptance original DHCP/static mode differs'}
    if($Old.mode -ceq 'not-exposed' -and $Old.registryHash -cne $New.registryHash){throw 'DNS acceptance dormant registry state differs'}
    $oldServers=@($Old.servers);$newServers=@($New.servers)
    if($oldServers.Count -ne $newServers.Count){throw 'DNS acceptance original static server count differs'}
    for($i=0;$i -lt $oldServers.Count;$i++){
        if((Convert-DNSAcceptanceAddress $oldServers[$i] '') -cne (Convert-DNSAcceptanceAddress $newServers[$i] '')){throw 'DNS acceptance original static server order or value differs'}
    }
}
function Assert-DNSAcceptanceRestored([object]$Before,[object]$After) {
    $expected=Get-DNSAcceptanceIndex $Before;$actual=Get-DNSAcceptanceIndex $After
    if($expected.adapters.Count -ne $actual.adapters.Count){throw 'DNS acceptance adapter inventory changed'}
    foreach($guid in $expected.adapters.Keys){
        if(-not $actual.adapters.ContainsKey($guid)){throw 'DNS acceptance original adapter is missing'}
        foreach($family in @('ipv4','ipv6')){
            Assert-DNSAcceptanceFamilyPreserved $expected.adapters[$guid].$family $actual.adapters[$guid].$family
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
    if(@($original.adapters.Values | Where-Object {$_.selected}).Count -eq 0){throw 'DNS acceptance has no selected original adapter'}
    if($original.adapters.Count -ne $actual.adapters.Count){throw 'DNS acceptance adapter inventory changed'}
    $v4=if($Method -ceq 'doh'){@('8.8.8.8','9.9.9.9')}else{@('127.0.0.1')}
    $v6=if($Method -ceq 'doh'){@('2001:4860:4860::8888','2620:fe::fe')}else{@('::1')}
    foreach($guid in $original.adapters.Keys){
        $record=$original.adapters[$guid]
        if(-not $actual.adapters.ContainsKey($guid)){throw 'DNS acceptance configured adapter is missing'}
        if($record.selected -ne $actual.adapters[$guid].selected){throw 'DNS acceptance configured adapter selection changed'}
        foreach($family in @('ipv4','ipv6')){
            if(-not $record.selected -or $record.$family.mode -ceq 'not-exposed'){
                Assert-DNSAcceptanceFamilyPreserved $record.$family $actual.adapters[$guid].$family
                continue
            }
            [string[]]$expected=if($family -eq 'ipv4'){@($v4)}else{@($v6)};$observed=$actual.adapters[$guid].$family;$servers=@($observed.servers)
            if($observed.mode -cne 'static' -or $servers.Count -ne $expected.Count){throw 'DNS acceptance configured family or mode differs'}
            for($i=0;$i -lt $expected.Count;$i++){if((Convert-DNSAcceptanceAddress $servers[$i] '') -cne $expected[$i]){throw 'DNS acceptance configured server differs'}}
        }
    }
    if($Before.dohAvailable -ne $Current.dohAvailable){throw 'DNS acceptance DoH capability changed during configuration'}
    $managedProviders=@()
    if($Method -ceq 'doh'){
        if(-not $Current.dohAvailable){throw 'Native DoH acceptance capability missing'}
        $managedProviders=@($v4)+@($v6)
        foreach($address in $managedProviders){
            $template=switch -CaseSensitive ($address){'8.8.8.8'{'https://8.8.8.8/dns-query'}'9.9.9.9'{'https://9.9.9.9/dns-query'}'2001:4860:4860::8888'{'https://[2001:4860:4860::8888]/dns-query'}'2620:fe::fe'{'https://[2620:fe::fe]/dns-query'}default{throw 'Unexpected fixed DoH provider'}}
            if(-not $actual.doh.ContainsKey($address)){throw 'Native DoH acceptance provider missing'}
            $entry=$actual.doh[$address]
            if($entry.template -cne $template -or $entry.fallback -or -not $entry.upgrade){throw 'Native DoH acceptance provider policy differs'}
        }
    }
    foreach($address in $original.doh.Keys){
        if($address -in $managedProviders){continue}
        $old=$original.doh[$address];$new=$actual.doh[$address]
        if($null -eq $new -or $old.template -cne $new.template -or $old.fallback -ne $new.fallback -or $old.upgrade -ne $new.upgrade){
            throw 'DNS acceptance unrelated DoH policy changed'
        }
    }
    foreach($address in $actual.doh.Keys){
        if($address -notin $managedProviders -and -not $original.doh.ContainsKey($address)){
            throw 'DNS acceptance unrelated DoH policy changed'
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
