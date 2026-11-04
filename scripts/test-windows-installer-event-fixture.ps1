# Pure synthetic ownership, state and public-output guards; no native calls.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-event-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-event-fixture.ps1')
function Assert-Fixture([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Assert-FixtureRefused([scriptblock]$Action){$refused=$false;try{&$Action}catch{$refused=$true};Assert-Fixture $refused 'Unsafe synthetic fixture input was accepted'}
function New-SyntheticFixtureCim([string]$Class,[hashtable]$Properties){
    $result=[pscustomobject]$Properties
    $result | Add-Member NoteProperty CimSystemProperties ([pscustomobject]@{ClassName=$Class;Namespace='root/standardcimv2';ServerName='PRIVATE_HOST';Path=('PRIVATE_CIM_PATH_'+$Class)})
    $native=@();foreach($name in @($Properties.Keys | Sort-Object -CaseSensitive)){$native+=,[pscustomobject]@{Name=$name;Value=$Properties[$name];CimType='String';Flags='ReadOnly'}}
    $result | Add-Member NoteProperty CimInstanceProperties $native
    return $result
}
$name='AccessWeaverDiagnosticFixture-'+('a'*64);$token='b'*32
$rule=New-SyntheticFixtureCim 'MSFT_NetFirewallRule' @{Name=$name;InstanceID='PRIVATE_RULE_INSTANCE';DisplayName=$name;Description=('AccessWeaver event diagnostic '+$token);Group=('AccessWeaver event fixture '+$token);Enabled='False';Direction='Outbound';Action='Allow';Profile='Any';Owner='PRIVATE_OWNER'}
$filters=[ordered]@{}
foreach($entry in @(@('application','MSFT_NetApplicationFilter'),@('address','MSFT_NetAddressFilter'),@('port','MSFT_NetProtocolPortFilter'),@('service','MSFT_NetServiceFilter'),@('interface','MSFT_NetInterfaceFilter'),@('interfaceType','MSFT_NetInterfaceTypeFilter'),@('security','MSFT_NetNetworkLayerSecurityFilter'))){$filters[$entry[0]]=@(New-SyntheticFixtureCim $entry[1] @{InstanceID=('PRIVATE_FILTER_'+$entry[0]);Value='PRIVATE_CONFIGURATION'})}
$ownership=New-InstallerEventFixtureOwnership $rule $filters $name $token
Assert-Fixture ($ownership.identitySHA256 -ceq (Get-InstallerStateTextHash $name) -and $ownership.sha256 -cmatch '^[a-f0-9]{64}$') 'Ownership fingerprints differ'
Assert-InstallerEventFixtureOwnership $ownership $rule $filters $name $token
$public=ConvertTo-Json -InputObject $ownership -Compress
foreach($private in @($name,$token,'PRIVATE_')){Assert-Fixture (-not $public.Contains($private)) 'Raw ownership material escaped'}
foreach($field in @('Name','DisplayName','Description','Group','Enabled','Direction','Action','Profile','InstanceID','Owner')){
    $original=$rule.$field;$rule.$field='PRIVATE_REPLACED'
    Assert-FixtureRefused {Assert-InstallerEventFixtureOwnership $ownership $rule $filters $name $token}
    $rule.$field=$original
}
$original=$rule.CimSystemProperties.Path;$rule.CimSystemProperties.Path='PRIVATE_REPLACEMENT_PATH';Assert-FixtureRefused {Assert-InstallerEventFixtureOwnership $ownership $rule $filters $name $token};$rule.CimSystemProperties.Path=$original
foreach($kind in @($filters.Keys)){
    $original=$filters[$kind][0].CimInstanceProperties[0].Value;$filters[$kind][0].CimInstanceProperties[0].Value='PRIVATE_PROVIDER_EDIT'
    Assert-FixtureRefused {Assert-InstallerEventFixtureOwnership $ownership $rule $filters $name $token}
    $filters[$kind][0].CimInstanceProperties[0].Value=$original
}
$original=$filters.application;$filters.application=@($original[0],$original[0]);Assert-FixtureRefused {New-InstallerEventFixtureOwnership $rule $filters $name $token};$filters.application=$original
$original=$rule.CimInstanceProperties;$rule.CimInstanceProperties=@($original)+@([pscustomobject]@{Name='PRIVATE_UNKNOWN_FIELD';Value='private';CimType='String';Flags='ReadOnly'});Assert-FixtureRefused {Assert-InstallerEventFixtureOwnership $ownership $rule $filters $name $token};$rule.CimInstanceProperties=$original
Assert-FixtureRefused {New-InstallerEventFixtureOwnership $rule $filters ('AccessWeaver-*') $token}
Assert-FixtureRefused {New-InstallerEventFixtureOwnership $rule $filters $name 'private-token'}
$empty=ConvertTo-Json -InputObject @{services=@();firewall=@();dns=@()} -Compress
$during=ConvertTo-Json -InputObject @{services=@();firewall=@([pscustomobject]@{Name=$name;Enabled='False';Direction='Outbound';Action='Allow'});dns=@()} -Depth 8 -Compress
$change=Assert-InstallerEventFixtureTransition $empty $during $ownership.identitySHA256
Assert-Fixture (-not $change.exactMatch -and $change.domains.firewall.added -eq 1) 'Controlled drift was not refused'
$other=ConvertTo-Json -InputObject @{services=@();firewall=@([pscustomobject]@{Name=$name;Enabled='False';Direction='Outbound';Action='Allow'},[pscustomobject]@{Name='PRIVATE_UNRELATED';Enabled='True';Direction='Outbound';Action='Block'});dns=@()} -Depth 8 -Compress
Assert-FixtureRefused {Assert-InstallerEventFixtureTransition $empty $other $ownership.identitySHA256}
$dns=ConvertTo-Json -InputObject @{services=@();firewall=@([pscustomobject]@{Name=$name;Enabled='False';Direction='Outbound';Action='Allow'});dns=@([pscustomobject]@{InterfaceIndex=1;AddressFamily=2;ServerAddresses=@('PRIVATE_DNS')})} -Depth 8 -Compress
Assert-FixtureRefused {Assert-InstallerEventFixtureTransition $empty $dns $ownership.identitySHA256}
Assert-FixtureRefused {Assert-InstallerEventFixtureTransition $empty $empty $ownership.identitySHA256}
Assert-Fixture ((Compare-InstallerState $empty $empty).exactMatch) 'Baseline restoration comparison weakened'
$start=[datetime]::SpecifyKind([datetime]'2026-11-04T00:00:00',[DateTimeKind]::Utc)
$diag=New-InstallerFirewallEventDiagnostic;$diag.status='captured';$diag.queryAttempted=$true;$diag.windowStartUtc=$start.ToString('o');$diag.windowEndUtc=$start.AddMinutes(1).ToString('o')
Assert-InstallerEventFixtureDiagnostic $diag $ownership.identitySHA256 $start
$parsed=(ConvertTo-Json -InputObject $diag -Depth 20 -Compress) | ConvertFrom-Json
Assert-InstallerEventFixtureDiagnostic $parsed $ownership.identitySHA256 $start
$unavailable=New-InstallerFirewallEventDiagnostic;$unavailable.status='unavailable';$unavailable.unavailable=$true;$unavailable.queryAttempted=$true;$unavailable.windowStartUtc=$start.ToString('o');$unavailable.windowEndUtc=$start.AddMinutes(1).ToString('o')
Assert-InstallerEventFixtureDiagnostic $unavailable $ownership.identitySHA256 $start
foreach($entry in @(@('queryAttempted',$false),@('processOriginEstablished',$true),@('eventLogConfigurationChanged',$true),@('maxEvents',129),@('maxRecords',17),@('eventsExamined',129),@('queryElapsedMilliseconds',-1),@('records',@([pscustomobject]@{private='PRIVATE_RAW_EVENT'})),@('windowStartUtc','PRIVATE_TIME'))){
    $copy=(ConvertTo-Json -InputObject $diag -Depth 20 -Compress) | ConvertFrom-Json;$copy.($entry[0])=$entry[1]
    Assert-FixtureRefused {Assert-InstallerEventFixtureDiagnostic $copy $ownership.identitySHA256 $start}
}
$fields=[ordered]@{};foreach($field in @('ModifyingApplication','ModifyingUser','ApplicationPath','ServiceName','Origin')){$fields[$field]=[ordered]@{present=$false}}
$record=[ordered]@{identitySHA256=$ownership.identitySHA256;eventId=12345;recordId='9007199254740993';occurredAtUtc=$start.AddSeconds(1).ToString('o');modifyingApplicationBasenameClass='absent';fields=$fields}
$diag.records=@($record);$diag.eventsExamined=1
Assert-InstallerEventFixtureDiagnostic $diag $ownership.identitySHA256 $start
$record.fields.ModifyingUser=[ordered]@{present=$true;utf8Bytes=12;sha256=('c'*64)}
Assert-InstallerEventFixtureDiagnostic $diag $ownership.identitySHA256 $start
$record.fields.ModifyingUser.privatePath='PRIVATE_PATH';Assert-FixtureRefused {Assert-InstallerEventFixtureDiagnostic $diag $ownership.identitySHA256 $start};$record.fields.ModifyingUser.Remove('privatePath')
$record.identitySHA256='d'*64;Assert-FixtureRefused {Assert-InstallerEventFixtureDiagnostic $diag $ownership.identitySHA256 $start};$record.identitySHA256=$ownership.identitySHA256
$record.recordId='18446744073709551616';Assert-FixtureRefused {Assert-InstallerEventFixtureDiagnostic $diag $ownership.identitySHA256 $start}
$tokens=$null;$issues=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'test-windows-installer-event-native.ps1'),[ref]$tokens,[ref]$issues)
Assert-Fixture (-not $issues.Count) 'Native probe source did not parse'
Write-Output 'Pure ownership replacement, provider/filter binding, baseline drift/restoration, diagnostic privacy/caps and native source parse checks passed; no native query or mutation.'
