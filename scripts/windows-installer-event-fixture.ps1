# Pure ownership and metadata guards for the separate hosted event probe.
# No cmdlet here reads or changes the OS. Identical replacement by another
# administrator remains inside the trust boundary; these are not atomic guards.
function Get-InstallerEventFixtureKeys($Value) {
    if($Value -is [Collections.IDictionary]){return @($Value.Keys | Sort-Object -CaseSensitive)}
    if($null -eq $Value){return @()}
    return @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)
}
function Test-InstallerEventFixtureKeys($Value,[string[]]$Names) {
    return ((@(Get-InstallerEventFixtureKeys $Value) -join '|') -ceq (@($Names | Sort-Object -CaseSensitive) -join '|'))
}
function Get-InstallerEventFixtureProperties($Object,[string[]]$Names) {
    if($null -eq $Object -or $Names.Count -gt 64){throw 'Event fixture object is incomplete'}
    $result=[ordered]@{}
    foreach($name in $Names){
        $property=$Object.PSObject.Properties[$name]
        if($null -eq $property){$result[$name]=[ordered]@{present=$false};continue}
        if($null -eq $property.Value){$result[$name]=[ordered]@{present=$true;isNull=$true};continue}
        $items=@($property.Value);if($items.Count -gt 128){throw 'Event fixture property exceeds budget'}
        $values=@()
        foreach($item in $items){
            if($null -eq $item){$values+=,$null;continue}
            $value=[string]$item
            if($value.Length -gt 4096 -or [Text.UTF8Encoding]::new($false).GetByteCount($value) -gt 4096){throw 'Event fixture property exceeds budget'}
            $values+=,$value
        }
        $result[$name]=[ordered]@{present=$true;values=$values}
    }
    return $result
}
function Get-InstallerEventFixtureCimBinding($Object,[string]$ClassName) {
    $cim=$Object.PSObject.Properties['CimSystemProperties']
    if($null -eq $cim -or $null -eq $cim.Value -or [string]$cim.Value.ClassName -cne $ClassName -or ([string]$cim.Value.Namespace).Replace('\','/') -ine 'root/standardcimv2'){throw 'Event fixture CIM binding differs'}
    return Get-InstallerEventFixtureProperties $cim.Value @('ClassName','Namespace','ServerName','Path')
}
function Get-InstallerEventFixtureCimProperties($Object) {
    $properties=@($Object.CimInstanceProperties)
    if($properties.Count -lt 1 -or $properties.Count -gt 64){throw 'Event fixture provider properties are incomplete or excessive'}
    $result=[ordered]@{}
    foreach($property in @($properties | Sort-Object Name -CaseSensitive)){
        $name=[string]$property.Name
        if($name -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,63}$' -or $result.Contains($name)){throw 'Event fixture provider property is ambiguous'}
        $holder=[pscustomobject]@{value=$property.Value}
        $result[$name]=[ordered]@{type=[string]$property.CimType;flags=[string]$property.Flags;data=(Get-InstallerEventFixtureProperties $holder @('value'))}
    }
    return $result
}
function New-InstallerEventFixtureOwnership($Rule,$Filters,[string]$Name,[string]$Token) {
    if($Name -cnotmatch '^AccessWeaverDiagnosticFixture-[a-f0-9]{64}$' -or $Token -cnotmatch '^[a-f0-9]{32}$'){throw 'Event fixture ownership input differs'}
    if($null -eq $Rule -or [string]$Rule.Name -cne $Name -or [string]::IsNullOrEmpty([string]$Rule.InstanceID) -or [string]$Rule.DisplayName -cne $Name -or [string]$Rule.Description -cne ('AccessWeaver event diagnostic '+$Token) -or [string]$Rule.Group -cne ('AccessWeaver event fixture '+$Token) -or [string]$Rule.Enabled -cne 'False' -or [string]$Rule.Direction -cne 'Outbound' -or [string]$Rule.Action -cne 'Allow' -or [string]$Rule.Profile -cne 'Any'){throw 'Event fixture rule ownership differs'}
    $spec=[ordered]@{
        application=@{class='MSFT_NetApplicationFilter';fields=@('InstanceID','Program','Package')}
        address=@{class='MSFT_NetAddressFilter';fields=@('InstanceID','LocalAddress','RemoteAddress','RemoteDynamicKeywordAddresses')}
        port=@{class='MSFT_NetProtocolPortFilter';fields=@('InstanceID','Protocol','LocalPort','RemotePort','IcmpType','DynamicTarget')}
        service=@{class='MSFT_NetServiceFilter';fields=@('InstanceID','Service')}
        interface=@{class='MSFT_NetInterfaceFilter';fields=@('InstanceID','InterfaceAlias')}
        interfaceType=@{class='MSFT_NetInterfaceTypeFilter';fields=@('InstanceID','InterfaceType')}
        security=@{class='MSFT_NetNetworkLayerSecurityFilter';fields=@('InstanceID','Authentication','Encryption','OverrideBlockRules','LocalUser','RemoteUser','RemoteMachine')}
    }
    if(-not (Test-InstallerEventFixtureKeys $Filters @($spec.Keys))){throw 'Event fixture filter set differs'}
    $material=[ordered]@{store='PersistentStore';binding=(Get-InstallerEventFixtureCimBinding $Rule 'MSFT_NetFirewallRule');provider=(Get-InstallerEventFixtureCimProperties $Rule);rule=(Get-InstallerEventFixtureProperties $Rule @('Name','InstanceID','DisplayName','Description','Group','Enabled','Direction','Action','Profile','EdgeTraversalPolicy','LooseSourceMapping','LocalOnlyMapping','Owner','Platforms','PolicyStoreSourceType','PolicyStoreSource'));filters=[ordered]@{}}
    foreach($kind in $spec.Keys){
        $items=@($Filters[$kind]);if($items.Count -ne 1 -or $null -eq $items[0]){throw 'Event fixture filter identity is ambiguous'}
        $material.filters[$kind]=[ordered]@{binding=(Get-InstallerEventFixtureCimBinding $items[0] $spec[$kind].class);provider=(Get-InstallerEventFixtureCimProperties $items[0]);properties=(Get-InstallerEventFixtureProperties $items[0] $spec[$kind].fields)}
    }
    $serialized=ConvertTo-Json -InputObject $material -Depth 16 -Compress
    if([Text.UTF8Encoding]::new($false).GetByteCount($serialized) -gt 65536){throw 'Event fixture ownership exceeds budget'}
    return [ordered]@{identitySHA256=(Get-InstallerStateTextHash $Name);sha256=(Get-InstallerStateTextHash $serialized)}
}
function Assert-InstallerEventFixtureOwnership($Expected,$Rule,$Filters,[string]$Name,[string]$Token) {
    if(-not (Test-InstallerEventFixtureKeys $Expected @('identitySHA256','sha256'))){throw 'Event fixture retained ownership differs'}
    $current=New-InstallerEventFixtureOwnership $Rule $Filters $Name $Token
    if($Expected.identitySHA256 -cne $current.identitySHA256 -or $Expected.sha256 -cne $current.sha256){throw 'Event fixture changed before cleanup'}
}
function Assert-InstallerEventFixtureTransition([string]$Before,[string]$During,[string]$Identity) {
    $comparison=Compare-InstallerState $Before $During
    $firewall=$comparison.domains.firewall
    if($Identity -cnotmatch '^[a-f0-9]{64}$' -or $comparison.exactMatch -or -not $comparison.domains.services.serializedEqual -or -not $comparison.domains.dns.serializedEqual -or $firewall.added -ne 1 -or $firewall.removed -ne 0 -or $firewall.changed -ne 0 -or $firewall.rowSerializationChanges -ne 0 -or $firewall.changes.Count -ne 1 -or $firewall.changesTruncated -or $firewall.afterRows -ne $firewall.beforeRows+1 -or $firewall.changes[0].identitySHA256 -cne $Identity -or $firewall.changes[0].kind -cne 'added' -or $firewall.changes[0].classification -cne 'other'){throw 'Event fixture controlled transition differs'}
    return $comparison
}
function Test-InstallerEventFixtureInteger($Value,[long]$Maximum) {
    return (($Value -is [int] -or $Value -is [long]) -and $Value -ge 0 -and $Value -le $Maximum)
}
function Assert-InstallerEventFixtureDiagnostic($Value,[string]$Identity,[datetime]$Start) {
    $factory=New-InstallerFirewallEventDiagnostic
    if(-not (Test-InstallerEventFixtureKeys $Value @($factory.Keys))){throw 'Event fixture diagnostic envelope differs'}
    foreach($name in @('schemaVersion','source','queryDeadlineMilliseconds','maxEvents','maxRecords','maxXmlBytes','maxFieldBytes','eventLogConfigurationChanged','extraFirewallRuleQueriesPerformed','processOriginEstablished')){
        if($factory[$name] -is [int]){if(-not (Test-InstallerEventFixtureInteger $Value.$name ([int]::MaxValue)) -or $Value.$name -ne $factory[$name]){throw 'Event fixture diagnostic constant differs'}}
        elseif($null -eq $Value.$name -or $Value.$name.GetType() -ne $factory[$name].GetType() -or $Value.$name -cne $factory[$name]){throw 'Event fixture diagnostic constant differs'}
    }
    if($Value.queryAttempted -isnot [bool] -or -not $Value.queryAttempted -or @('captured','unavailable') -cnotcontains $Value.status -or $Value.unavailable -isnot [bool] -or $Value.eventsLimitReached -isnot [bool] -or $Value.recordsTruncated -isnot [bool] -or -not (Test-InstallerEventFixtureInteger $Value.queryElapsedMilliseconds ([long]::MaxValue)) -or -not (Test-InstallerEventFixtureInteger $Value.eventsExamined 128) -or -not (Test-InstallerEventFixtureInteger $Value.invalidEvents $Value.eventsExamined) -or $Value.records -isnot [array] -or $Value.records.Count -gt 16){throw 'Event fixture diagnostic bounds differ'}
    $times=@()
    foreach($name in @('windowStartUtc','windowEndUtc')){
        $raw=$Value.$name
        if($raw -is [datetime]){$parsed=$raw}else{$parsed=[datetime]::ParseExact([string]$raw,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)}
        if($parsed.Kind -ne [DateTimeKind]::Utc){throw 'Event fixture diagnostic time differs'}
        $times+=,$parsed
    }
    if($times[0] -ne $Start -or $times[1] -lt $times[0] -or ($times[1]-$times[0]).TotalHours -gt 2){throw 'Event fixture diagnostic window differs'}
    if($Value.status -ceq 'unavailable'){
        if(-not $Value.unavailable -or $Value.eventsExamined -ne 0 -or $Value.invalidEvents -ne 0 -or $Value.eventsLimitReached -or $Value.recordsTruncated -or $Value.records.Count -ne 0){throw 'Event fixture unavailable state differs'}
        return
    }
    if($Value.unavailable -or ($Value.eventsLimitReached -and $Value.eventsExamined -ne 128) -or $Value.records.Count -gt $Value.eventsExamined-$Value.invalidEvents -or ($Value.recordsTruncated -and ($Value.records.Count -ne 16 -or $Value.eventsExamined -lt 17))){throw 'Event fixture captured state differs'}
    foreach($record in $Value.records){
        if(-not (Test-InstallerEventFixtureKeys $record @('identitySHA256','eventId','recordId','occurredAtUtc','modifyingApplicationBasenameClass','fields')) -or $record.identitySHA256 -cne $Identity -or -not (Test-InstallerEventFixtureInteger $record.eventId ([int]::MaxValue)) -or $record.eventId -lt 1 -or $record.recordId -isnot [string] -or $record.recordId -cnotmatch '^[1-9][0-9]{0,19}$' -or @('absent','omitted','other','core','setup','uninstaller','service-host-basename') -cnotcontains $record.modifyingApplicationBasenameClass){throw 'Event fixture record identity differs'}
        [uint64]$number=0;if(-not [System.UInt64]::TryParse($record.recordId,[ref]$number)){throw 'Event fixture record number differs'}
        $raw=$record.occurredAtUtc;if($raw -is [datetime]){$occurred=$raw}else{$occurred=[datetime]::ParseExact([string]$raw,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)}
        if($occurred.Kind -ne [DateTimeKind]::Utc -or $occurred -lt $times[0] -or $occurred -gt $times[1]){throw 'Event fixture record time differs'}
        if(-not (Test-InstallerEventFixtureKeys $record.fields @('ModifyingApplication','ModifyingUser','ApplicationPath','ServiceName','Origin'))){throw 'Event fixture record fields differ'}
        $application=$record.fields.ModifyingApplication
        if((-not $application.present -and $record.modifyingApplicationBasenameClass -cne 'absent') -or ($application.present -and $application.omitted -eq $true -and $record.modifyingApplicationBasenameClass -cne 'omitted') -or ($application.present -and $application.omitted -ne $true -and @('absent','omitted') -ccontains $record.modifyingApplicationBasenameClass)){throw 'Event fixture application classification differs'}
        foreach($name in @('ModifyingApplication','ModifyingUser','ApplicationPath','ServiceName','Origin')){
            $field=$record.fields.$name
            if($field.present -isnot [bool]){throw 'Event fixture field presence differs'}
            if(-not $field.present){if(-not (Test-InstallerEventFixtureKeys $field @('present'))){throw 'Event fixture absent field differs'}}
            elseif($field.omitted -eq $true){if(-not (Test-InstallerEventFixtureKeys $field @('present','omitted')) -or $field.omitted -isnot [bool]){throw 'Event fixture omitted field differs'}}
            elseif(-not (Test-InstallerEventFixtureKeys $field @('present','utf8Bytes','sha256')) -or -not (Test-InstallerEventFixtureInteger $field.utf8Bytes 4096) -or $field.sha256 -isnot [string] -or $field.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Event fixture field fingerprint differs'}
        }
    }
}
