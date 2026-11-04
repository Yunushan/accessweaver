# Metadata-only firewall event diagnostics. Conversion functions are pure;
# Read-InstallerFirewallEventLog performs one explicit local read only when the
# opted-in hosted fixture starts it in a bounded isolated child after drift.
function New-InstallerFirewallEventDiagnostic {
    return [ordered]@{schemaVersion=1;source='existing-local-firewall-event-log';status='not-needed';queryAttempted=$false;queryDeadlineMilliseconds=10000;queryElapsedMilliseconds=0L;maxEvents=128;maxRecords=16;maxXmlBytes=65536;maxFieldBytes=4096;windowStartUtc=$null;windowEndUtc=$null;eventsExamined=0;invalidEvents=0;eventsLimitReached=$false;records=@();recordsTruncated=$false;unavailable=$false;eventLogConfigurationChanged=$false;extraFirewallRuleQueriesPerformed=$false;processOriginEstablished=$false}
}
function Assert-InstallerEventWindow([datetime]$Start,[datetime]$End,[string[]]$Identities) {
    if($Start.Kind -ne [DateTimeKind]::Utc -or $End.Kind -ne [DateTimeKind]::Utc -or $Start -eq [datetime]::MinValue -or $End -lt $Start -or ($End-$Start).TotalHours -gt 2 -or $Identities.Count -lt 1 -or $Identities.Count -gt 16){throw 'Invalid bounded event diagnostic input'}
    foreach($identity in $Identities){if($identity -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid bounded event identity'}}
}
function Get-InstallerEventField($Field) {
    if($null -eq $Field){return [ordered]@{present=$false}}
    $value=[string]$Field
    if($value.Length -gt 4096){return [ordered]@{present=$true;omitted=$true}}
    $count=[Text.UTF8Encoding]::new($false).GetByteCount($value)
    if($count -gt 4096){return [ordered]@{present=$true;omitted=$true}}
    return [ordered]@{present=$true;utf8Bytes=$count;sha256=(Get-InstallerStateTextHash $value)}
}
function Convert-InstallerFirewallEvent([string]$Xml,[string[]]$Identities,[datetime]$Start,[datetime]$End) {
    Assert-InstallerEventWindow $Start $End $Identities
    if($Xml.Length -gt 65536 -or [Text.UTF8Encoding]::new($false).GetByteCount($Xml) -gt 65536){throw 'Event XML exceeds diagnostic budget'}
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=65536
    $inputReader=[IO.StringReader]::new($Xml);$reader=$null
    try {
        $reader=[Xml.XmlReader]::Create($inputReader,$settings);$document=[Xml.XmlDocument]::new();$document.XmlResolver=$null;$document.Load($reader)
    } finally {if($reader){$reader.Dispose()};$inputReader.Dispose()}
    $ns=[Xml.XmlNamespaceManager]::new($document.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    if($document.DocumentElement.LocalName -cne 'Event' -or $document.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/win/2004/08/events/event'){throw 'Unexpected event XML envelope'}
    $systems=$document.SelectNodes('/e:Event/e:System',$ns);$dataNodes=$document.SelectNodes('/e:Event/e:EventData',$ns)
    if($systems.Count -ne 1 -or $dataNodes.Count -ne 1){throw 'Ambiguous event XML sections'}
    $provider=$document.SelectNodes('/e:Event/e:System/e:Provider',$ns);$channel=$document.SelectNodes('/e:Event/e:System/e:Channel',$ns)
    if($provider.Count -ne 1 -or $channel.Count -ne 1 -or $provider[0].GetAttribute('Name') -cne 'Microsoft-Windows-Windows Firewall With Advanced Security' -or $channel[0].InnerText -cne 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'){return $null}
    $times=$document.SelectNodes('/e:Event/e:System/e:TimeCreated',$ns);$ids=$document.SelectNodes('/e:Event/e:System/e:EventID',$ns);$records=$document.SelectNodes('/e:Event/e:System/e:EventRecordID',$ns)
    $eventId=0;[uint64]$recordId=0
    if($times.Count -ne 1 -or $ids.Count -ne 1 -or $records.Count -ne 1 -or -not [int]::TryParse($ids[0].InnerText,[ref]$eventId) -or $eventId -lt 1 -or -not [ulong]::TryParse($records[0].InnerText,[ref]$recordId) -or $recordId -lt 1){throw 'Incomplete event identity'}
    $occurred=[Xml.XmlConvert]::ToDateTime($times[0].GetAttribute('SystemTime'),[Xml.XmlDateTimeSerializationMode]::Utc)
    if($occurred -lt $Start -or $occurred -gt $End){return $null}
    $fields=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $nodes=$document.SelectNodes('/e:Event/e:EventData/e:Data',$ns)
    if($nodes.Count -gt 128){throw 'Excessive event fields'}
    foreach($node in $nodes){$name=$node.GetAttribute('Name');if($name -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,63}$' -or $fields.ContainsKey($name)){throw 'Ambiguous event fields'};$fields.Add($name,$node.InnerText)}
    if(-not $fields.ContainsKey('RuleId')){return $null}
    $identity=$fields['RuleId'];if($identity.Length -gt 4096 -or [Text.UTF8Encoding]::new($false).GetByteCount($identity) -gt 4096){throw 'Excessive event rule identity'}
    $fingerprint=Get-InstallerStateTextHash $identity
    if($Identities -cnotcontains $fingerprint){return $null}
    $safe=[ordered]@{}
    foreach($name in @('ModifyingApplication','ModifyingUser','ApplicationPath','ServiceName','Origin')){
        $value=$null;if($fields.ContainsKey($name)){$value=$fields[$name]}
        $safe[$name]=Get-InstallerEventField $value
    }
    # A leaf-name class is an observation, not a verified image or caller.
    $class='absent'
    if($fields.ContainsKey('ModifyingApplication')){
        $class='other';$value=$fields['ModifyingApplication']
        if($value.Length -le 4096 -and [Text.UTF8Encoding]::new($false).GetByteCount($value) -le 4096){
            $class=Get-InstallerNativeToolClass $value
            if($class -ceq 'other' -and [IO.Path]::GetFileName($value) -ieq 'svchost.exe'){$class='service-host-basename'}
        }else{$class='omitted'}
    }
    return [ordered]@{identitySHA256=$fingerprint;eventId=$eventId;recordId=$recordId.ToString([Globalization.CultureInfo]::InvariantCulture);occurredAtUtc=$occurred.ToString('o',[Globalization.CultureInfo]::InvariantCulture);modifyingApplicationBasenameClass=$class;fields=$safe}
}
function Convert-InstallerFirewallEvents([string[]]$Xml,[string[]]$Identities,[datetime]$Start,[datetime]$End,[bool]$LimitReached=$false) {
    Assert-InstallerEventWindow $Start $End $Identities
    if($Xml.Count -gt 128){throw 'Excessive event diagnostic input'}
    $result=New-InstallerFirewallEventDiagnostic;$result.status='captured';$result.queryAttempted=$true;$result.windowStartUtc=$Start.ToString('o');$result.windowEndUtc=$End.ToString('o');$result.eventsLimitReached=$LimitReached
    $records=[Collections.Generic.List[object]]::new()
    foreach($entry in $Xml){
        $result.eventsExamined++
        try {$item=Convert-InstallerFirewallEvent $entry $Identities $Start $End} catch {$result.invalidEvents++;continue}
        if($null -eq $item){continue}
        if($records.Count -lt 16){$records.Add($item)}else{$result.recordsTruncated=$true}
    }
    $result.records=@($records.ToArray());return $result
}
function Read-InstallerFirewallEventLog([string[]]$Identities,[datetime]$Start,[datetime]$End,[scriptblock]$Read=$null) {
    Assert-InstallerEventWindow $Start $End $Identities
    if($null -eq $Read){$Read={param($filter,$maximum)
        try {Microsoft.PowerShell.Diagnostics\Get-WinEvent -FilterHashtable $filter -MaxEvents $maximum -ErrorAction Stop}
        catch {if(($_.FullyQualifiedErrorId -split ',')[0] -cne 'NoMatchingEventsFound'){throw}}
    }}
    $events=@(&$Read @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';StartTime=$Start;EndTime=$End} 129)
    try {
        if($events.Count -gt 129){throw 'Event query exceeded diagnostic budget'}
        $xml=[Collections.Generic.List[string]]::new()
        foreach($event in @($events | Select-Object -First 128)){
            try {$value=[string]$event.ToXml();if($value.Length -gt 65536 -or [Text.UTF8Encoding]::new($false).GetByteCount($value) -gt 65536){$value=''};$xml.Add($value)} catch {$xml.Add('')}
        }
        return Convert-InstallerFirewallEvents @($xml.ToArray()) $Identities $Start $End ($events.Count -gt 128)
    } finally {foreach($event in $events){if($event -is [IDisposable]){$event.Dispose()}}}
}
