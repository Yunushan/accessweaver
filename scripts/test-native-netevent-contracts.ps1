# Hosted source contracts. Native boundaries are replaced before evaluation.
[CmdletBinding()]param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Hosted source contracts only'}
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop}
$PSModuleAutoLoadingPreference='None'
$project=Split-Path -Parent $PSScriptRoot;$sources=@('scripts/native-netevent-control.ps1','scripts/native-etl-header.cs','scripts/read-native-etl-loss.ps1','scripts/netevent-control-operation.ps1','scripts/test-native-netevent-control.ps1','scripts/test-native-netevent-contracts.ps1','.github/workflows/native-netevent-control.yml','scripts/native-dns-wire.ps1','scripts/dns-acceptance-state.ps1')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-netevent-control.ps1'),[ref]$tokens,[ref]$issues);if($issues.Count){throw 'Source syntax'}
$allowed=@('Get-NativeNDISTemplateSignature','New-NativeNDISCatalogEvidence','New-NativeNDISFragmentEvidence','New-NativeNDISLossEvidence','Get-NativeNDISLossEvidence','Test-NativeNDISLossEvidence','Get-NativeNetEventValue','Get-NativeNetEventInventory','Get-NativeNetEventEnums','Assert-NativeNetEventSession','Get-NativeNetEventState','Assert-NativeNetEventProvider','New-NetEventSession','Add-NetEventPacketCaptureProvider','Start-NetEventSession','Stop-NetEventSession','Remove-NetEventSession','Where-Object','New-NativeNDISHeaderEvidence','ConvertFrom-Json')
foreach($def in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
    if($def.Name -cin @('Get-NativeNetEventEnums','Get-NativeNetEventInventory')){continue}
    foreach($cmd in $def.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -cnotin $allowed){throw 'Source command boundary'}}
    . ([scriptblock]::Create($def.Extent.Text))
}
function Assert-N([bool]$Value){if(-not $Value){throw 'Synthetic source assertion'}}
function Reject-N([scriptblock]$Body){$rejected=$false;try{[void](& $Body)}catch{$rejected=$true};Assert-N $rejected}
function Reset-N {
    $script:sessions=@();$script:providers=@();$script:starts=0;$script:stops=0;$script:removes=0;$script:fault=''
    $script:plan=@{name=('awndis-'+('a'*32));file=([IO.Path]::Combine([IO.Path]::GetTempPath(),'capture.etl'));guid='';originalVerified=$false}
}
function Get-NativeNetEventEnums {return @{mode=0;capture=0}}
function Get-NativeNetEventInventory {return @{sessions=@($script:sessions);providers=@($script:providers)}}
function Set-RawN([object]$Row) {
    $properties=@{};foreach($property in $Row.PSObject.Properties){$properties[$property.Name]=[pscustomobject]@{Value=$property.Value}}
    $Row | Add-Member -MemberType NoteProperty -Name CimInstanceProperties -Value $properties
}
function New-NetEventSession {
    param($Name,$CaptureMode,$LocalFilePath,$MaxFileSize,$ErrorAction)
    Assert-N ($Name -ceq $script:plan.name -and $CaptureMode -ceq 'SaveToFile' -and $LocalFilePath -ceq $script:plan.file -and $MaxFileSize -eq 16)
    $script:sessions=@([pscustomobject]@{Name=$Name;Guid='11111111-2222-3333-4444-555555555555';CaptureMode=0;LocalFilePath=$LocalFilePath;MaxFileSize=16;SessionStatus='NotRunning'})
    Set-RawN $script:sessions[0]
    if($script:fault -ceq 'partial-create'){throw 'Synthetic partial create'}
}
function Add-NetEventPacketCaptureProvider {
    param($SessionName,$CaptureType,$MultiLayer,$EtherType,$IpAddresses,$IpProtocols,$TruncationLength,$Level,$MatchAnyKeyword,$MatchAllKeyword,$ErrorAction)
    Assert-N ($SessionName -ceq $script:plan.name -and $CaptureType -ceq 'Physical' -and -not $MultiLayer -and $EtherType[0] -eq 2048 -and $IpAddresses[0] -ceq '8.8.8.8' -and $IpProtocols[0] -eq 6 -and $TruncationLength -eq 65535 -and $Level -eq 5 -and $MatchAnyKeyword -eq [System.UInt64]::MaxValue -and $MatchAllKeyword -eq 0)
    $script:providers=@([pscustomobject]@{Guid='2ed6006e-4729-4609-b423-3ee7bcd678ef';SessionGuid=$script:sessions[0].Guid;SessionName=$SessionName;Level=5;CaptureType=0;MultiLayer=$false;EtherType=@(2048);IPAddresses=@('8.8.8.8');IPProtocols=@(6);TruncationLength=65535;MatchAnyKeyword=[System.UInt64]::MaxValue;MatchAllKeyword=[System.UInt64]0;LinkLayerAddress=@()})
    Set-RawN $script:providers[0]
}
function Start-NetEventSession {param($InputObject,$ErrorAction);Assert-N ($InputObject -eq $script:sessions[0]);$script:starts++;$InputObject.SessionStatus='Running'}
function Stop-NetEventSession {param($InputObject,$ErrorAction);Assert-N ($InputObject -eq $script:sessions[0]);$script:stops++;$InputObject.SessionStatus='NotRunning'}
function Remove-NetEventSession {param($InputObject,[switch]$Confirm,$ErrorAction);Assert-N ($InputObject -eq $script:sessions[0]);$script:removes++;$script:sessions=@();$script:providers=@()}
function Create-N {$r=Invoke-NativeNetEventOperation 'create' $script:plan;$script:plan.guid=$r.sessionGuid;return $r}
$cases=[Collections.Generic.List[object]]::new()
function Case-N([string]$Name,[scriptblock]$Body){$passed=$true;try{[void](& $Body)}catch{$passed=$false};$cases.Add(@{name=$Name;passed=$passed})}
Case-N 'complete-control-uses-owned-session-and-verifies-retirement' {
    Reset-N;Assert-N (Invoke-NativeNetEventOperation 'preflight' $script:plan).emptyBefore
    Assert-N (Create-N).sessionVerified;Assert-N (Invoke-NativeNetEventOperation 'provider' $script:plan).providerVerified
    Assert-N ((Invoke-NativeNetEventOperation 'start' $script:plan).state -ceq 'running');Assert-N ((Invoke-NativeNetEventOperation 'stop' $script:plan).state -ceq 'stopped')
    $script:plan.originalVerified=$true;Assert-N (Invoke-NativeNetEventOperation 'remove' $script:plan).emptyAfter
    Assert-N ($script:starts -eq 1 -and $script:stops -eq 1 -and $script:removes -eq 1)
}
Case-N 'preexisting-session-refuses-before-any-mutation' {Reset-N;[void](Create-N);$script:plan.name='awndis-'+('b'*32);Reject-N {Invoke-NativeNetEventOperation 'create' $script:plan};Assert-N ($script:starts -eq 0 -and $script:removes -eq 0)}
Case-N 'session-identity-path-mode-and-limit-drift-refuse' {
    foreach($field in @('Name','Guid','LocalFilePath','CaptureMode','MaxFileSize')){Reset-N;[void](Create-N);$r=$script:sessions[0];switch($field){'Name'{$r.CimInstanceProperties['Name'].Value='foreign'}'Guid'{$r.CimInstanceProperties['Guid'].Value='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'}'LocalFilePath'{$r.CimInstanceProperties['LocalFilePath'].Value=$r.CimInstanceProperties['LocalFilePath'].Value+'.other'}'CaptureMode'{$r.CimInstanceProperties['CaptureMode'].Value=1}'MaxFileSize'{$r.CimInstanceProperties['MaxFileSize'].Value=0}};Reject-N {Invoke-NativeNetEventOperation 'stop' $script:plan};Assert-N ($script:stops -eq 0)}
}
Case-N 'missing-mode-cannot-coerce-to-file-mode' {Reset-N;[void](Create-N);$script:sessions[0].CimInstanceProperties['CaptureMode'].Value=$null;Reject-N {Invoke-NativeNetEventOperation 'remove' $script:plan};Assert-N ($script:removes -eq 0)}
Case-N 'provider-owner-drift-prevents-start' {Reset-N;[void](Create-N);[void](Invoke-NativeNetEventOperation 'provider' $script:plan);$script:providers[0].CimInstanceProperties['SessionGuid'].Value='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';Reject-N {Invoke-NativeNetEventOperation 'start' $script:plan};Assert-N ($script:starts -eq 0)}
Case-N 'provider-filter-and-truncation-drift-prevents-start' {
    foreach($field in @('IPAddresses','IPProtocols','TruncationLength','CaptureType','MatchAnyKeyword')){Reset-N;[void](Create-N);[void](Invoke-NativeNetEventOperation 'provider' $script:plan);switch($field){'IPAddresses'{$script:providers[0].CimInstanceProperties['IPAddresses'].Value=@('9.9.9.9')}'IPProtocols'{$script:providers[0].CimInstanceProperties['IPProtocols'].Value=@(17)}'TruncationLength'{$script:providers[0].CimInstanceProperties['TruncationLength'].Value=128}'CaptureType'{$script:providers[0].CimInstanceProperties['CaptureType'].Value=$null}'MatchAnyKeyword'{$script:providers[0].CimInstanceProperties['MatchAnyKeyword'].Value=0}};Reject-N {Invoke-NativeNetEventOperation 'start' $script:plan};Assert-N ($script:starts -eq 0)}
}
Case-N 'partial-create-can-retire-only-matching-owned-session' {Reset-N;$script:fault='partial-create';Reject-N {Create-N};Assert-N ($script:sessions.Count -eq 1);$script:fault='';[void](Invoke-NativeNetEventOperation 'stop' $script:plan);$script:plan.originalVerified=$true;Assert-N (Invoke-NativeNetEventOperation 'remove' $script:plan).emptyAfter}
Case-N 'unverified-original-state-prevents-destructive-retirement' {Reset-N;[void](Create-N);Reject-N {Invoke-NativeNetEventOperation 'remove' $script:plan};Assert-N ($script:sessions.Count -eq 1 -and $script:removes -eq 0)}
Case-N 'unknown-session-state-is-retained' {Reset-N;[void](Create-N);$script:sessions[0].SessionStatus=1;Reject-N {Invoke-NativeNetEventOperation 'stop' $script:plan};Assert-N ($script:stops -eq 0 -and $script:removes -eq 0)}
Case-N 'running-session-cannot-be-removed' {Reset-N;[void](Create-N);[void](Invoke-NativeNetEventOperation 'provider' $script:plan);[void](Invoke-NativeNetEventOperation 'start' $script:plan);$script:plan.originalVerified=$true;Reject-N {Invoke-NativeNetEventOperation 'remove' $script:plan};Assert-N ($script:removes -eq 0)}
Case-N 'multiple-inventory-rows-prevent-mutation' {Reset-N;[void](Create-N);$script:sessions+=@($script:sessions[0]);Reject-N {Invoke-NativeNetEventOperation 'stop' $script:plan};Assert-N ($script:stops -eq 0)}
Case-N 'absent-cleanup-does-not-stop-or-remove-another-session' {Reset-N;Assert-N (Invoke-NativeNetEventOperation 'stop' $script:plan).emptyAfter;Assert-N (Invoke-NativeNetEventOperation 'remove' $script:plan).emptyAfter;Assert-N ($script:stops -eq 0 -and $script:removes -eq 0)}
Case-N 'formatted-display-properties-do-not-replace-typed-cim-values' {
    Reset-N;[void](Create-N);$script:sessions[0].MaxFileSize='16 MB';$script:sessions[0].CaptureMode='SaveToFile'
    Assert-N (Invoke-NativeNetEventOperation 'provider' $script:plan).providerVerified
    $script:providers[0].TruncationLength='65535 bytes'
    Assert-N ((Invoke-NativeNetEventOperation 'start' $script:plan).state -ceq 'running')
}
Case-N 'missing-typed-cim-field-cannot-use-a-display-fallback' {
    Reset-N;[void](Create-N);$script:sessions[0].CimInstanceProperties.Remove('MaxFileSize');Reject-N {Invoke-NativeNetEventOperation 'stop' $script:plan};Assert-N ($script:stops -eq 0)
}
Case-N 'ndis-headers-preserve-unknown-ids-versions-and-providers' {
    $r=New-NativeNDISHeaderEvidence 'complete';$g=[guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef';Add-NativeNDISHeader $r $g 1001 0;Add-NativeNDISHeader $r $g 170 1;Add-NativeNDISHeader $r $null 1001 0
    $v=Get-NativeNDISHeaderEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'complete' -and $v.records -eq 3 -and $v.fragmentIDs -eq 1 -and $v.unknownProviderIDs -eq 1 -and $v.missingProviderIDs -eq 1 -and $v.unrecognizedVersions -eq 1)
}
Case-N 'ndis-invalid-private-or-contradictory-reports-are-unknown' {
    foreach($fault in @('private','sum','boolean')){$r=New-NativeNDISHeaderEvidence 'complete';switch($fault){'private'{$r['private']='PRIVATE-SYNTHETIC'}'sum'{$r.records=1}'boolean'{$r.records=$false}};$v=Get-NativeNDISHeaderEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'invalid' -and $v.fragmentIDs -eq -1 -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))}
}
Case-N 'ndis-bound-and-unavailable-counts-remain-distinct' {$r=New-NativeNDISHeaderEvidence 'complete';$r.records=4096;Reject-N {Add-NativeNDISHeader $r $null 1 0};$v=Get-NativeNDISHeaderEvidence ((New-NativeNDISHeaderEvidence 'unavailable') | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'unavailable' -and $v.fragmentIDs -eq -1)}
Case-N 'ndis-header-program-retains-bounds-and-no-payload-access' {
    $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-NativeNDISHeaderProgram "PRIVATE-SYNTHETIC-'`nthrow 'never'")));$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
    Assert-N ($e.Count -eq 0 -and -not $body.Contains('PRIVATE-SYNTHETIC') -and $body.Contains('ReadEvent([TimeSpan]::FromMilliseconds(250))') -and $body.Contains('$record.Dispose()') -and $body.Contains('$reader.Dispose()') -and -not $body.Contains('FormatDescription') -and -not $body.Contains('.Properties') -and -not $body.Contains('.ToXml('))
}
function Good-LossN {
    return @{code='parsed';eventsLost=0;buffersLost=0;bufferSize=65536;buffersWritten=5;maximumFileSize=16;pointerSize=8;logFileMode=2;finalized=$true;closed=$true;nativeCode=0}
}
Case-N 'loss-metadata-requires-finalized-zero-loss-unwrapped-file' {
    $v=Get-NativeNDISLossEvidence ((Good-LossN) | ConvertTo-Json -Compress);Assert-N (Test-NativeNDISLossEvidence $v)
}
Case-N 'reported-loss-unfinalized-or-wrapped-metadata-cannot-pass' {
    foreach($field in @('eventsLost','buffersLost','finalized','closed','buffersWritten','pointerSize','maximumFileSize','logFileMode')){
        $v=Good-LossN;switch($field){'eventsLost'{$v.eventsLost=1}'buffersLost'{$v.buffersLost=1}'finalized'{$v.finalized=$false}'closed'{$v.closed=$false}'buffersWritten'{$v.buffersWritten=256}'pointerSize'{$v.pointerSize=4}'maximumFileSize'{$v.maximumFileSize=0}'logFileMode'{$v.logFileMode=8}}
        $r=Get-NativeNDISLossEvidence ($v | ConvertTo-Json -Compress);Assert-N (-not (Test-NativeNDISLossEvidence $r))
    }
}
Case-N 'loss-metadata-private-fields-and-invalid-numbers-are-refused' {
    foreach($fault in @('private','boolean','overflow')){$v=Good-LossN;switch($fault){'private'{$v['private']='PRIVATE-SYNTHETIC'}'boolean'{$v.eventsLost=$false}'overflow'{$v.buffersWritten=4294967296}};$r=Get-NativeNDISLossEvidence ($v | ConvertTo-Json -Compress);Assert-N ($r.code -ceq 'invalid' -and $r.eventsLost -eq -1 -and -not (($r | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))}
}
Case-N 'unavailable-or-unclosed-header-never-becomes-zero-loss' {
    foreach($code in @('open-failed','close-failed','unavailable')){$v=Good-LossN;$v.code=$code;$v.nativeCode=5;$r=Get-NativeNDISLossEvidence ($v | ConvertTo-Json -Compress);Assert-N ($r.eventsLost -eq -1 -and $r.buffersLost -eq -1 -and -not $r.closed -and -not (Test-NativeNDISLossEvidence $r))}
    $v=Good-LossN;$v.nativeCode=87;$r=Get-NativeNDISLossEvidence ($v | ConvertTo-Json -Compress);Assert-N ($r.code -ceq 'invalid')
}

function Good-FragmentN {
    $r=New-NativeNDISFragmentEvidence 'complete';$g=[guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef'
    Add-NativeNDISFragmentHeader $r $g 1001 0 ([long]7516192768)
    Add-NativeNDISFragmentHeader $r $g 1001 0 ([long]11811160064)
    return $r
}
Case-N 'fragment-keywords-require-single-ethernet-and-both-directions' {
    $r=Good-FragmentN;$v=Get-NativeNDISFragmentEvidence ($r | ConvertTo-Json -Compress);Assert-N (Test-NativeNDISFragmentEvidence $v)
    $g=[guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef';$r=New-NativeNDISFragmentEvidence 'complete'
    Add-NativeNDISFragmentHeader $r $g 1001 0 ([long]::MinValue+7516192768);Add-NativeNDISFragmentHeader $r $g 1001 0 ([long]::MinValue+11811160064)
    Assert-N (Test-NativeNDISFragmentEvidence (Get-NativeNDISFragmentEvidence ($r | ConvertTo-Json -Compress)))
}
Case-N 'split-wireless-wan-or-ambiguous-directions-cannot-qualify' {
    foreach($bits in @([long]4294967296,[long]7516258304,[long]7516193280,[long]7516258816,[long]16106127360,[long]3221225472)){
        $r=Good-FragmentN;Add-NativeNDISFragmentHeader $r ([guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef') 1001 0 $bits
        $v=Get-NativeNDISFragmentEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'complete' -and -not (Test-NativeNDISFragmentEvidence $v))
    }
}
Case-N 'missing-keywords-versions-and-unknown-ids-remain-explicit' {
    $r=Good-FragmentN;$g=[guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef';Add-NativeNDISFragmentHeader $r $g 1001 1 $null;Add-NativeNDISFragmentHeader $r $g 1002 0 0;Add-NativeNDISFragmentHeader $r $g 170 0 0;Add-NativeNDISFragmentHeader $r $null 1001 0 0
    $v=Get-NativeNDISFragmentEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'complete' -and $v.missingKeywords -eq 1 -and $v.unrecognizedVersions -eq 1 -and $v.metadataIDs -eq 1 -and $v.unknownProviderIDs -eq 1 -and $v.missingProviderIDs -eq 1 -and -not (Test-NativeNDISFragmentEvidence $v))
}
Case-N 'fragment-report-private-fields-and-inconsistent-counts-refused' {
    foreach($fault in @('private','boolean','partition','media','direction','missing','overflow')){$r=Good-FragmentN;switch($fault){'private'{$r['private']='PRIVATE-SYNTHETIC'}'boolean'{$r.sent=$false}'partition'{$r.singleEvent=0}'media'{$r.ethernet=0}'direction'{$r.received=0}'missing'{$r.missingKeywords=3}'overflow'{$r.records=4097}};$v=Get-NativeNDISFragmentEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'invalid' -and $v.fragmentIDs -eq -1 -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))}
    foreach($code in @('unavailable','bound')){$r=New-NativeNDISFragmentEvidence $code;$v=Get-NativeNDISFragmentEvidence ($r | ConvertTo-Json -Compress);Assert-N (-not (Test-NativeNDISFragmentEvidence $v))}
}
Case-N 'fragment-program-uses-header-only-bounded-disposed-reader' {
    $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-NativeNDISFragmentProgram "PRIVATE-SYNTHETIC-'`nthrow 'never'")));$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
    Assert-N ($e.Count -eq 0 -and -not $body.Contains('PRIVATE-SYNTHETIC') -and $body.Contains('$record.Keywords') -and $body.Contains('ReadEvent([TimeSpan]::FromMilliseconds(250))') -and $body.Contains('$record.Dispose()') -and $body.Contains('$reader.Dispose()') -and -not $body.Contains('FormatDescription') -and -not $body.Contains('.Properties') -and -not $body.Contains('.ToXml('))
}


function Template-N([string]$Fields) {
    $body='';foreach($field in $Fields.Split('|')){$parts=$field.Split(':');$body+='<data name="'+$parts[0]+'" inType="win:'+$parts[1]+'"'+$(if($parts.Count -eq 3){' length="'+$parts[2]+'"'}else{''})+'/>'}
    return '<template xmlns="http://schemas.microsoft.com/win/2004/08/events">'+$body+'</template>'
}
Case-N 'catalog-exact-fragment-and-rule-schemas-recognized' {
    Assert-N ((Get-NativeNDISCatalogClass 1001 0 4 (Template-N 'MiniportIfIndex:UInt32|LowerIfIndex:UInt32|FragmentSize:UInt32|Fragment:Binary:FragmentSize')) -ceq 'fragment')
    Assert-N ((Get-NativeNDISCatalogClass 1002 0 4 (Template-N 'MiniportIfIndex:UInt32|LowerIfIndex:UInt32|MetadataSize:UInt32|Metadata:Binary:MetadataSize')) -ceq 'metadata')
    Assert-N ((Get-NativeNDISCatalogClass 1011 0 4 (Template-N 'RulesCount:UInt32')) -ceq 'rules')
    Assert-N ((Get-NativeNDISCatalogClass 1016 0 4 (Template-N 'RuleId:UInt8|Directive:UInt8|Length:UInt16|Value:Binary:Length')) -ceq 'rules')
}
Case-N 'catalog-interface-inventory-requires-exact-primary-schema' {
    foreach($id in @(1012,1013)){Assert-N ((Get-NativeNDISCatalogClass $id 0 5 (Template-N 'FriendlyName:UnicodeString|UniqueName:UnicodeString|ServiceName:UnicodeString|Version:UnicodeString')) -ceq 'inventory')}
    foreach($id in @(1014,1015)){Assert-N ((Get-NativeNDISCatalogClass $id 0 5 (Template-N 'MiniportIfIndex:UInt32|LowerIfIndex:UInt32|MediaType:UInt32|ReferenceContext:UInt32')) -ceq 'inventory')}
}
Case-N 'catalog-changed-fields-versions-levels-and-ids-stay-unknown' {
    $template=Template-N 'RulesCount:UInt32'
    Assert-N ((Get-NativeNDISCatalogClass 1011 1 4 $template) -ceq 'unknown');Assert-N ((Get-NativeNDISCatalogClass 1011 0 2 $template) -ceq 'unknown');Assert-N ((Get-NativeNDISCatalogClass 2001 0 4 $template) -ceq 'unknown')
    foreach($fields in @('RulesCount:UInt16','Other:UInt32','RulesCount:UInt32|Other:UInt32')){Assert-N ((Get-NativeNDISCatalogClass 1011 0 4 (Template-N $fields)) -ceq 'unknown')}
}
Case-N 'catalog-template-parser-refuses-dtd-expansion-and-opaque-fields' {
    foreach($template in @('<!DOCTYPE template [<!ENTITY x SYSTEM "file:///PRIVATE-SYNTHETIC">]><template>&x;</template>','<template xmlns="PRIVATE-SYNTHETIC"><data name="RulesCount" inType="win:UInt32"/></template>',('<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><struct name="RulesCount"/></template>'),('x'*8193),'<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><data name="RulesCount" inType="win:UInt32" count="Other"/></template>')){Assert-N ((Get-NativeNDISTemplateSignature $template) -ceq '')}
}
Case-N 'catalog-unmapped-and-error-events-never-become-inventory' {
    $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=2;$r.recognizedDefinitions=2;$g=[guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef';$catalog=@{'1001:0'='fragment';'1016:0'='rules'}
    Add-NativeNDISCatalogHeader $r $catalog $g 1001 0;Add-NativeNDISCatalogHeader $r $catalog $g 1016 0;Assert-N (Test-NativeNDISCatalogEvidence (Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Compress)))
    Add-NativeNDISCatalogHeader $r $catalog $g 2001 0;Add-NativeNDISCatalogHeader $r $catalog $g 1001 1
    $r.schemas=@(@{id=2001;version=0;level=-1;records=1;code='missing';fields=@()},@{id=1001;version=1;level=-1;records=1;code='missing';fields=@()})
    $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.unknownRecords -eq 2 -and $v.unrecognizedVersions -eq 1 -and -not (Test-NativeNDISCatalogEvidence $v))
}
Case-N 'catalog-report-private-or-contradictory-fields-refused' {
    foreach($fault in @('private','boolean','sum','definitions','versions')){$r=New-NativeNDISCatalogEvidence 'complete';switch($fault){'private'{$r['private']='PRIVATE-SYNTHETIC'}'boolean'{$r.records=$false}'sum'{$r.records=1}'definitions'{$r.definitions=65}'versions'{$r.unrecognizedVersions=1}};$v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'invalid' -and $v.fragmentRecords -eq -1 -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))}
    $v=Get-NativeNDISCatalogEvidence ((New-NativeNDISCatalogEvidence 'unavailable') | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'unavailable' -and -not (Test-NativeNDISCatalogEvidence $v))
}
Case-N 'catalog-program-keeps-provider-source-and-event-values-separate' {
    $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-NativeNDISCatalogProgram "PRIVATE-SYNTHETIC-'`nthrow 'never'")));$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
    Assert-N ($e.Count -eq 0 -and -not $body.Contains('PRIVATE-SYNTHETIC') -and $body.Contains('$definition.Template') -and $body.Contains('$definition.Level.Value') -and $body.Contains('ProviderMetadata') -and $body.Contains('$provider.Dispose()') -and $body.Contains('$record.Dispose()') -and $body.Contains('$reader.Dispose()') -and -not $body.Contains('.Properties') -and -not $body.Contains('.ToXml(') -and -not $body.Contains('FormatDescription'))
}


Case-N 'catalog-shape-exports-static-definition-tokens-not-values' {
    $shape=@(Get-NativeNDISTemplateShape (Template-N 'MiniportIfIndex:UInt32|ReferenceContext:UInt64|Fragment:Binary:FragmentSize'))
    Assert-N ($shape.Count -eq 3 -and $shape[1] -ceq 'ReferenceContext:win:UInt64::' -and $shape[2] -ceq 'Fragment:win:Binary:FragmentSize:')
}
Case-N 'catalog-shape-refuses-nested-or-private-definition-text' {
    foreach($template in @('<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><data name="Field" inType="win:UInt32">PRIVATE-SYNTHETIC</data></template>','<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><data name="PRIVATE/SYNTHETIC" inType="win:UInt32"/></template>','<!DOCTYPE template [<!ENTITY x SYSTEM "file:///PRIVATE-SYNTHETIC">]><template>&x;</template>')){Assert-N (@(Get-NativeNDISTemplateShape $template).Count -eq 0)}
}
Case-N 'catalog-unknown-definition-shapes-are-bounded-and-counted' {
    $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=1;$r.records=2;$r.unknownRecords=2;$r.schemas=@(@{id=1001;version=0;level=4;records=2;code='projected';fields=@('Field:win:UInt32::')})
    $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'complete' -and $v.schemas.Count -eq 1 -and -not (Test-NativeNDISCatalogEvidence $v))
    $r.schemas[0].records=1;$v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'invalid')
}
Case-N 'catalog-schema-projection-rejects-extra-fields-and-invalid-tokens' {
    foreach($fault in @('private','path','boolean','duplicate')){
        $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=1;$r.records=1;$r.unknownRecords=1;$row=@{id=1001;version=0;level=4;records=1;code='projected';fields=@('Field:win:UInt32::')};$r.schemas=@($row)
        switch($fault){'private'{$row['private']='PRIVATE-SYNTHETIC'}'path'{$row.fields=@('PRIVATE/SYNTHETIC:win:UInt32::')}'boolean'{$row.id=$false}'duplicate'{$r.schemas=@($row,$row)}}
        $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    }
}

foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){throw 'Source changed'}}
$passed=@($cases | Where-Object {-not $_.passed}).Count -eq 0
[Console]::Out.WriteLine((@{schemaVersion=1;scope='actual-native-netevent-source';sourceSHA256=$hashes;cases=@($cases.ToArray());passed=$passed;realCaptureStarted=$false;realDnsChanged=$false;nativeQualified=$false} | ConvertTo-Json -Depth 6 -Compress))
if(-not $passed){exit 1}
