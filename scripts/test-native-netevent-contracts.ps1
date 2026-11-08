# Hosted source contracts. Native boundaries are replaced before evaluation.
[CmdletBinding()]param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Hosted source contracts only'}
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop}
$PSModuleAutoLoadingPreference='None'
$project=Split-Path -Parent $PSScriptRoot;$sources=@('scripts/offload-control-operation.ps1','scripts/native-offload-state.ps1','scripts/read-native-offload-state.ps1','scripts/ndis-tls-control.cjs','scripts/dns-wire-stdin.cjs','scripts/extract-native-ndis.ps1','scripts/ndis-private-convert.cjs','scripts/dns-wire-evidence.cjs','scripts/ndis-frame-converter.cjs','scripts/test-ndis-frame-converter.cjs','scripts/native-netevent-control.ps1','scripts/native-etl-header.cs','scripts/read-native-etl-loss.ps1','scripts/netevent-control-operation.ps1','scripts/test-native-netevent-control.ps1','scripts/test-native-netevent-contracts.ps1','.github/workflows/native-netevent-control.yml','scripts/native-dns-wire.ps1','scripts/dns-acceptance-state.ps1')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-netevent-control.ps1'),[ref]$tokens,[ref]$issues);if($issues.Count){throw 'Source syntax'}
$allowed=@('Get-NativeNetEventCapturePolicy','Assert-NativeNetEventFilterSet','Get-NativeNDISTcpClosureEvidence','Test-NativeOffloadOwner','Test-NativeOffloadOtherSettings','Read-NativeOffloadAdapterSnapshot','New-NativeOffloadChangeEvidence','Get-NativeOffloadRaw','New-NativeOffloadEvidence','New-NativeNDISTlsStimulusEvidence','New-NativeNDISTlsWireEvidence','New-NativeNDISExtractionEvidence','New-NativeNDISConversionEvidence','Get-NativeNDISTemplateTree','Add-NativeNDISTemplateTreeNode','Test-NativeNDISTemplateTree','Get-NativeNDISTemplateSignature','New-NativeNDISCatalogEvidence','New-NativeNDISFragmentEvidence','New-NativeNDISLossEvidence','Get-NativeNDISLossEvidence','Test-NativeNDISLossEvidence','Get-NativeNetEventValue','Get-NativeNetEventInventory','Get-NativeNetEventEnums','Assert-NativeNetEventSession','Get-NativeNetEventState','Assert-NativeNetEventProvider','New-NetEventSession','Add-NetEventPacketCaptureProvider','Start-NetEventSession','Stop-NetEventSession','Remove-NetEventSession','Where-Object','New-NativeNDISHeaderEvidence','ConvertFrom-Json')
foreach($sourceFile in @('native-netevent-control.ps1','native-offload-state.ps1')){
    $tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $sourceFile),[ref]$tokens,[ref]$issues);if($issues.Count){throw 'Source syntax'}
foreach($def in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
    if($def.Name -cin @('Get-NativeNetEventEnums','Get-NativeNetEventInventory')){continue}
    foreach($cmd in $def.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -cnotin $allowed){throw 'Source command boundary'}}
    . ([scriptblock]::Create($def.Extent.Text))
}
}
function Assert-N([bool]$Value){if(-not $Value){throw 'Synthetic source assertion'}}
function Reject-N([scriptblock]$Body){$rejected=$false;try{[void](& $Body)}catch{$rejected=$true};Assert-N $rejected}
function Reset-N {
    $script:sessions=@();$script:providers=@();$script:starts=0;$script:stops=0;$script:removes=0;$script:fault=''
    $script:plan=@{name=('awndis-'+('a'*32));file=([IO.Path]::Combine([IO.Path]::GetTempPath(),'capture.etl'));guid='';originalVerified=$false;capturePolicy='control-google-v4'}
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
    if($script:plan.capturePolicy -ceq 'product-doh-all'){Assert-N (($EtherType -join ',') -ceq '2048,34525' -and ($IpProtocols -join ',') -ceq '6,17' -and ($IpAddresses -join ',') -ceq '8.8.8.8,9.9.9.9,2001:4860:4860::8888,2620:fe::fe')}else{Assert-N ($EtherType.Count -eq 1 -and $IpProtocols.Count -eq 1 -and $IpAddresses.Count -eq 1)}
    $script:providers=@([pscustomobject]@{Guid='2ed6006e-4729-4609-b423-3ee7bcd678ef';SessionGuid=$script:sessions[0].Guid;SessionName=$SessionName;Level=5;CaptureType=0;MultiLayer=$false;EtherType=@($EtherType);IPAddresses=@($IpAddresses);IPProtocols=@($IpProtocols);TruncationLength=65535;MatchAnyKeyword=[System.UInt64]::MaxValue;MatchAllKeyword=[System.UInt64]0;LinkLayerAddress=@()})
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
    $r.schemas=@(@{id=2001;version=0;level=-1;records=1;code='missing';fields=@();task='';opcode='';templateKind='missing';tree=@()},@{id=1001;version=1;level=-1;records=1;code='missing';fields=@();task='';opcode='';templateKind='missing';tree=@()})
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
    $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=1;$r.records=2;$r.unknownRecords=2;$r.schemas=@(@{id=1001;version=0;level=4;records=2;code='projected';fields=@('Field:win:UInt32::');task='Task';opcode='win:Info';templateKind='data';tree=@()})
    $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'complete' -and $v.schemas.Count -eq 1 -and -not (Test-NativeNDISCatalogEvidence $v))
    $r.schemas[0].records=1;$v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'invalid')
}
Case-N 'catalog-schema-projection-rejects-extra-fields-and-invalid-tokens' {
    foreach($fault in @('private','path','boolean','duplicate')){
        $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=1;$r.records=1;$r.unknownRecords=1;$row=@{id=1001;version=0;level=4;records=1;code='projected';fields=@('Field:win:UInt32::');task='Task';opcode='win:Info';templateKind='data';tree=@()};$r.schemas=@($row)
        switch($fault){'private'{$row['private']='PRIVATE-SYNTHETIC'}'path'{$row.fields=@('PRIVATE/SYNTHETIC:win:UInt32::')}'boolean'{$row.id=$false}'duplicate'{$r.schemas=@($row,$row)}}
        $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    }
}


Case-N 'modern-gft-fragment-schema-must-match-both-extra-fields-exactly' {
    $fields='MiniportIfIndex:UInt32|LowerIfIndex:UInt32|FragmentSize:UInt32|Fragment:Binary:FragmentSize|GftFlowEntryId:UInt64|GftOffloadInformation:UInt64'
    Assert-N ((Get-NativeNDISCatalogClass 1001 0 4 (Template-N $fields)) -ceq 'fragment')
    Assert-N ((Get-NativeNDISCatalogClass 1001 0 4 (Template-N $fields.Replace('GftOffloadInformation:UInt64','GftOffloadInformation:UInt32'))) -ceq 'unknown')
    Assert-N ((Get-NativeNDISCatalogClass 1001 0 4 (Template-N ($fields+'|Other:UInt32'))) -ceq 'unknown')
}
Case-N 'lifecycle-schemas-remain-separate-from-inventory-and-errors' {
    $template=Template-N 'PreviousState:UInt8|NextState:UInt8|Location:UInt32|Context:UInt32'
    foreach($id in @(3001,3002)){Assert-N ((Get-NativeNDISCatalogClass $id 0 5 $template) -ceq 'lifecycle');Assert-N ((Get-NativeNDISCatalogClass $id 0 2 $template) -ceq 'unknown')}
    $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=2;$r.recognizedDefinitions=2;$g=[guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef';Add-NativeNDISCatalogHeader $r @{'3001:0'='lifecycle'} $g 3001 0
    $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'complete' -and $v.lifecycleRecords -eq 1 -and $v.inventoryRecords -eq 0 -and -not (Test-NativeNDISCatalogEvidence $v))
}
Case-N 'static-template-kind-does-not-infer-empty-or-structured-data' {
    Assert-N ((Get-NativeNDISTemplateKind '') -ceq 'empty');Assert-N ((Get-NativeNDISTemplateKind '<template xmlns="http://schemas.microsoft.com/win/2004/08/events"/>') -ceq 'empty')
    Assert-N ((Get-NativeNDISTemplateKind (Template-N 'Field:UInt32')) -ceq 'data')
    Assert-N ((Get-NativeNDISTemplateKind '<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><struct name="Fields" count="Count"/></template>') -ceq 'structured')
    Assert-N ((Get-NativeNDISTemplateKind '<!DOCTYPE template [<!ENTITY x SYSTEM "file:///PRIVATE-SYNTHETIC">]><template>&x;</template>') -ceq 'unsupported')
}
Case-N 'catalog-loader-keeps-private-input-encoded-and-command-line-bounded' {
    $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-NativeNDISCatalogLoader "PRIVATE-SYNTHETIC-'`nthrow 'never'" "PRIVATE-SYNTHETIC-'`nthrow 'never'")));$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
    Assert-N ($e.Count -eq 0 -and -not $body.Contains('PRIVATE-SYNTHETIC') -and $body.Contains('Get-NativeNDISCatalogProgram') -and $body.Length -lt 4096 -and -not $body.Contains('FormatDescription'))
}


function TreeTemplate-N {
    return '<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><data name="Count" inType="win:UInt32"/><struct name="Rows" count="Count"><data name="Code" inType="win:UInt32"/><data name="Value" inType="win:UInt64"/></struct></template>'
}
Case-N 'rundown-schema-recognition-requires-exact-primary-types-and-level' {
    $fields='SourceId:UInt8|RundownId:UInt32|Param1:UInt64|Param2:UInt64|ParamStr:UnicodeString|Description:UnicodeString'
    Assert-N ((Get-NativeNDISCatalogClass 5100 0 4 (Template-N $fields)) -ceq 'rundown')
    Assert-N ((Get-NativeNDISCatalogClass 5100 0 2 (Template-N $fields)) -ceq 'unknown');Assert-N ((Get-NativeNDISCatalogClass 5100 1 4 (Template-N $fields)) -ceq 'unknown')
    Assert-N ((Get-NativeNDISCatalogClass 5100 0 4 (Template-N $fields.Replace('Param2:UInt64','Param2:UInt32'))) -ceq 'unknown')
}
Case-N 'static-schema-tree-preserves-ordered-structure-and-count-reference' {
    $tree=@(Get-NativeNDISTemplateTree (TreeTemplate-N));Assert-N ($tree.Count -eq 5 -and $tree[0] -ceq 'D:Count:win:UInt32::' -and $tree[1] -ceq 'S:Rows::Count' -and $tree[4] -ceq 'E:Rows' -and (Test-NativeNDISTemplateTree $tree))
}
Case-N 'static-schema-tree-refuses-external-content-depth-and-size' {
    foreach($template in @('<!DOCTYPE template [<!ENTITY x SYSTEM "file:///PRIVATE-SYNTHETIC">]><template>&x;</template>',('<template xmlns="http://schemas.microsoft.com/win/2004/08/events">'+('<struct name="Rows">'*5)+'<data name="Value" inType="win:UInt32"/>'+('</struct>'*5)+'</template>'),('x'*8193),'<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><data name="Value" inType="win:UInt32">PRIVATE-SYNTHETIC</data></template>')){Assert-N (@(Get-NativeNDISTemplateTree $template).Count -eq 0)}
}
Case-N 'static-schema-tree-closed-grammar-requires-balanced-bounded-nesting' {
    $invalidTrees=[Collections.Generic.List[object]]::new()
    $invalidTrees.Add([object]@('S:Rows::Count','E:Other'))
    $invalidTrees.Add([object]@('E:Rows'))
    $invalidTrees.Add([object]@('S:Rows::Count'))
    $invalidTrees.Add([object]@('D:PRIVATE/SYNTHETIC:win:UInt32::'))
    $invalidTrees.Add([object]@('S:A::','S:B::','S:C::','S:D::','E:D','E:C','E:B','E:A'))
    $overflow=[object[]]::new(49);for($index=0;$index -lt $overflow.Length;$index++){$overflow[$index]='D:Value:win:UInt32::'};$invalidTrees.Add($overflow)
    Assert-N ($invalidTrees.Count -eq 6)
    foreach($tree in $invalidTrees){Assert-N ($tree -is [array] -and -not (Test-NativeNDISTemplateTree $tree))}
}
Case-N 'structured-definition-projection-never-implies-catalog-recognition' {
    $template=TreeTemplate-N;Assert-N ((Get-NativeNDISCatalogClass 5101 0 4 $template) -ceq 'unknown')
    $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=1;$r.records=1;$r.unknownRecords=1;$r.schemas=@(@{id=5101;version=0;level=4;records=1;code='unsupported';fields=@();task='';opcode='win:Info';templateKind='structured';tree=@(Get-NativeNDISTemplateTree $template)})
    $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'complete' -and $v.unknownRecords -eq 1 -and -not (Test-NativeNDISCatalogEvidence $v))
}
Case-N 'rundown-count-remains-separate-and-contradictions-are-refused' {
    $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=1;$r.recognizedDefinitions=1;Add-NativeNDISCatalogHeader $r @{'5100:0'='rundown'} ([guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef') 5100 0
    $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'complete' -and $v.rundownRecords -eq 1 -and $v.inventoryRecords -eq 0)
    $r.rundownRecords=2;Assert-N ((Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress)).code -ceq 'invalid')
}


function LayerTemplate-N {
    return '<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><data name="SourceId" inType="win:UInt8"/><data name="SourceName" inType="win:UnicodeString"/><data name="IfIndex" inType="win:UInt32"/><data name="LayerCount" inType="win:UInt16"/><struct name="LayerInfo" count="LayerCount"><data name="LayerId" inType="win:UInt32"/><data name="LayerName" inType="win:UnicodeString"/></struct></template>'
}
Case-N 'primary-layer-rundown-recognition-requires-exact-structure' {
    $template=LayerTemplate-N;Assert-N ((Get-NativeNDISCatalogClass 5101 0 4 $template) -ceq 'rundown')
    foreach($changed in @($template.Replace('count="LayerCount"','count="OtherCount"'),$template.Replace('name="LayerId" inType="win:UInt32"','name="LayerId" inType="win:UInt64"'),$template.Replace('name="LayerName"','name="OtherName"'))){Assert-N ((Get-NativeNDISCatalogClass 5101 0 4 $changed) -ceq 'unknown')}
    Assert-N ((Get-NativeNDISCatalogClass 5101 1 4 $template) -ceq 'unknown');Assert-N ((Get-NativeNDISCatalogClass 5101 0 2 $template) -ceq 'unknown')
}
Case-N 'complete-primary-catalog-retains-three-rundown-records-explicitly' {
    $r=New-NativeNDISCatalogEvidence 'complete';$r.definitions=3;$r.recognizedDefinitions=3;$g=[guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef';$catalog=@{'1001:0'='fragment';'5100:0'='rundown';'5101:0'='rundown'}
    Add-NativeNDISCatalogHeader $r $catalog $g 1001 0;Add-NativeNDISCatalogHeader $r $catalog $g 5100 0;Add-NativeNDISCatalogHeader $r $catalog $g 5100 0;Add-NativeNDISCatalogHeader $r $catalog $g 5101 0
    $v=Get-NativeNDISCatalogEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.rundownRecords -eq 3 -and $v.unknownRecords -eq 0 -and (Test-NativeNDISCatalogEvidence $v))
}


function PrivateValues-N([bool]$Modern=$false) {$n=if($Modern){4}else{2};$values=[object[]]::new($n);$values[0]=[uint32]14;$values[1]=[byte[]]::new(14);if($Modern){$values[2]=[uint64]0;$values[3]=[uint64]0};return ,$values}
function PrivateRecord-N([object]$Values,[bool]$Modern=$false) {return (ConvertTo-NativeNDISPrivateRecord ([guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef') ([int]1001) ([byte]0) ([long]7516192768) $Values $Modern)}
function ClosureReply-N {return @{schemaVersion=1;flows=1;sentFin=0;receivedFin=0;sentReset=0;receivedReset=0;beforeFin=0;afterSentFin=0;afterReceivedFin=0;afterBothFin=0;resetFlows=0;resetFlowsWithPayloadBoth=0;productionQualificationComplete=$false}}
function ConversionReply-N {
    return @{schemaVersion=1;outcome='converted';code='none';nativeFrameDataRead=$true;summary=@{schemaVersion=1;tcpClosure=(ClosureReply-N);frames=2;ipv4=2;ipv6=0;tcp=2;udp=0;sent=1;received=1;captureBytes=200;productionQualificationComplete=$false}}
}
Case-N 'private-fragment-projection-preserves-typed-legacy-bytes' {
    $r=PrivateRecord-N (PrivateValues-N);Assert-N ($r.Count -eq 6 -and $r.keywords -ceq '7516192768' -and $r.fragmentSize -eq 14 -and [Convert]::FromBase64String($r.fragment).Length -eq 14)
}
Case-N 'private-modern-projection-requires-typed-zero-offload-values' {
    $r=PrivateRecord-N (PrivateValues-N $true) $true;Assert-N ($r.gftFlowEntryId -ceq '0' -and $r.gftOffloadInformation -ceq '0')
    foreach($field in @(2,3)){$v=PrivateValues-N $true;$v[$field]=[uint64]1;Reject-N {PrivateRecord-N $v $true};$v[$field]=[int]0;Reject-N {PrivateRecord-N $v $true}}
}
Case-N 'private-projection-refuses-coerced-types-and-size-mismatches' {
    foreach($fault in @('size-type','bytes-type','size-value')){$v=PrivateValues-N;switch($fault){'size-type'{$v[0]=[int]14}'bytes-type'{$v[1]=@('PRIVATE-SYNTHETIC')}'size-value'{$v[0]=[uint32]15}};Reject-N {PrivateRecord-N $v}}
}
Case-N 'private-projection-refuses-identity-media-and-boundary-drift' {
    $v=PrivateValues-N
    foreach($bits in @([long]4294967296,[long]7516193280,[long]7516258304,[long]16106127360)){Reject-N {ConvertTo-NativeNDISPrivateRecord ([guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef') ([int]1001) ([byte]0) $bits $v $false}}
    Reject-N {ConvertTo-NativeNDISPrivateRecord ([guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef') ([int]1001) ([int]0) ([long]7516192768) $v $false}
}
Case-N 'extraction-public-summary-excludes-bytes-and-contradictory-counts' {
    $r=@{code='none';records=3;frames=2;bytesWritten=1000;payloadRead=$true};Assert-N ((Get-NativeNDISExtractionEvidence ($r | ConvertTo-Json -Compress)).code -ceq 'none')
    $r['private']='PRIVATE-SYNTHETIC';$v=Get-NativeNDISExtractionEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    $r.Remove('private');$r.frames=4;Assert-N ((Get-NativeNDISExtractionEvidence ($r | ConvertTo-Json -Compress)).code -ceq 'invalid')
}
Case-N 'conversion-public-summary-requires-closed-count-partitions' {
    $r=ConversionReply-N;Assert-N ((Get-NativeNDISConversionEvidence ($r | ConvertTo-Json -Depth 4 -Compress)).outcome -ceq 'converted')
    foreach($field in @('sent','tcp','ipv4')){$r=ConversionReply-N;$r.summary[$field]=0;Assert-N ((Get-NativeNDISConversionEvidence ($r | ConvertTo-Json -Depth 4 -Compress)).code -ceq 'invalid')}
    $r=ConversionReply-N;$r.summary['private']='PRIVATE-SYNTHETIC';Assert-N ((Get-NativeNDISConversionEvidence ($r | ConvertTo-Json -Depth 4 -Compress)).code -ceq 'invalid')
}
Case-N 'conversion-refusal-never-carries-a-packet-or-positive-summary' {
    $r=@{schemaVersion=1;outcome='refused';code='fragment-offload';nativeFrameDataRead=$true;summary=$null};$v=Get-NativeNDISConversionEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.outcome -ceq 'refused' -and $v.code -ceq 'fragment-offload' -and $null -eq $v.summary)
    $r.code='PRIVATE-SYNTHETIC';$v=Get-NativeNDISConversionEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
}
Case-N 'native-extractor-selects-fixed-properties-and-disposes-every-reader' {
    $body=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'extract-native-ndis.ps1'))
    Assert-N ($body.Contains('GetPropertyValues($selector)') -and $body.Contains("@('FragmentSize','Fragment')") -and $body.Contains("@('GftFlowEntryId','GftOffloadInformation')") -and $body.Contains('$record.Dispose()') -and $body.Contains('$selector.Dispose()') -and $body.Contains('$reader.Dispose()') -and $body.Contains('$stream.Dispose()') -and $body.Contains('FileMode]::CreateNew') -and -not $body.Contains('.Properties') -and -not $body.Contains('.ToXml(') -and -not $body.Contains('FormatDescription'))
}


function TlsStimulusReply-N {return @{schemaVersion=1;outcome='passed';code='none';tlsAuthorized=$true;responseValidated=$true;closed=$true;productionQualificationComplete=$false}}
function TlsWireReply-N {return @{schemaVersion=1;outcome='decoded';code='none';evidence=@{schemaVersion=1;observation='tls-observed';packets=10;plaintextPackets=0;flows=@(@{provider='google-v4';clientHello=$true;serverHello=$true;outboundEncryptedRecords=2;inboundEncryptedRecords=3;records=7});dnsPayloadDecrypted=$false;ordinaryResolverBound=$false;negativeControlPassed=$false;productionQualificationComplete=$false}}}
Case-N 'fixed-tls-stimulus-requires-authenticated-response-and-closed-client' {
    $r=TlsStimulusReply-N;Assert-N ((Get-NativeNDISTlsStimulusEvidence ($r | ConvertTo-Json -Compress)).outcome -ceq 'passed')
    foreach($field in @('tlsAuthorized','responseValidated','closed')){$r=TlsStimulusReply-N;$r[$field]=$false;Assert-N ((Get-NativeNDISTlsStimulusEvidence ($r | ConvertTo-Json -Compress)).code -ceq 'invalid')}
}
Case-N 'fixed-tls-stimulus-refuses-private-or-qualification-fields' {
    $r=TlsStimulusReply-N;$r['private']='PRIVATE-SYNTHETIC';$v=Get-NativeNDISTlsStimulusEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    $r=TlsStimulusReply-N;$r.productionQualificationComplete=$true;Assert-N ((Get-NativeNDISTlsStimulusEvidence ($r | ConvertTo-Json -Compress)).code -ceq 'invalid')
}
Case-N 'strict-tls-wire-projection-requires-positive-hello-and-record-evidence' {
    $r=TlsWireReply-N;$v=Get-NativeNDISTlsWireEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'none' -and $v.observation -ceq 'tls-observed' -and $v.providerMask -eq 1 -and $v.outboundEncryptedRecords -eq 2 -and $v.inboundEncryptedRecords -eq 3)
    $r=@{schemaVersion=1;outcome='refused';code='tcp-reset';evidence=$null};$v=Get-NativeNDISTlsWireEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'tcp-reset' -and $v.observation -ceq 'refused')
}
Case-N 'strict-tls-wire-projection-rejects-contradictions-private-data-and-product-claims' {
    foreach($fault in @('hello','encrypted','provider','private','binding','production')){
        $r=TlsWireReply-N;switch($fault){'hello'{$r.evidence.flows[0].serverHello=$false}'encrypted'{$r.evidence.flows[0].outboundEncryptedRecords=0}'provider'{$r.evidence.flows[0].provider='PRIVATE-SYNTHETIC'}'private'{$r.evidence['private']='PRIVATE-SYNTHETIC'}'binding'{$r.evidence.ordinaryResolverBound=$true}'production'{$r.evidence.productionQualificationComplete=$true}}
        $v=Get-NativeNDISTlsWireEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    }
}


function OffloadRow-N([string]$Class,[hashtable]$Values) {$p=@{};foreach($key in $Values.Keys){$p[$key]=[pscustomobject]@{Value=$Values[$key]}};return [pscustomobject]@{CimClass=[pscustomobject]@{CimClassName=$Class};CimInstanceProperties=$p}}
function OffloadInputs-N {
    return @{routes=@((OffloadRow-N 'MSFT_NetIPAddress' @{InterfaceIndex=[uint32]3}),(OffloadRow-N 'MSFT_NetRoute' @{InterfaceIndex=[uint32]3}));adapters=@((OffloadRow-N 'MSFT_NetAdapter' @{InterfaceIndex=[uint32]3;InterfaceGuid='11111111-2222-3333-4444-555555555555';Name='source-adapter';InterfaceDescription='source-description'}));settings=@((OffloadRow-N 'MSFT_NetAdapterLsoSettingData' @{Name='source-adapter';InterfaceDescription='source-description';InstanceID='source-instance';V1IPv4Enabled=$false;IPv4Enabled=$true;IPv6Enabled=$true;MaximumLsoVersionSupported=[uint32]2}))}
}
Case-N 'readonly-offload-binding-matches-typed-route-adapter-and-setting' {
    $v=OffloadInputs-N;$r=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings;Assert-N ($r.index -eq 3 -and $r.IPv4Enabled -and $r.maximumVersion -eq 2)
}
Case-N 'readonly-offload-binding-refuses-ambiguous-or-drifting-route' {
    foreach($fault in @('count','class','index')){$v=OffloadInputs-N;switch($fault){'count'{$v.routes+=@($v.routes[0])}'class'{$v.routes[1].CimClass.CimClassName='MSFT_NetIPAddress'}'index'{$v.routes[1].CimInstanceProperties['InterfaceIndex'].Value=[uint32]4}};Reject-N {Read-NativeOffloadBinding $v.routes $v.adapters $v.settings}}
}
Case-N 'readonly-offload-binding-refuses-foreign-setting-and-coerced-state' {
    foreach($fault in @('identity','boolean','version')){$v=OffloadInputs-N;switch($fault){'identity'{$v.settings[0].CimInstanceProperties['InterfaceDescription'].Value='source-foreign'}'boolean'{$v.settings[0].CimInstanceProperties['IPv4Enabled'].Value=1}'version'{$v.settings[0].CimInstanceProperties['MaximumLsoVersionSupported'].Value=[uint32]3}};Reject-N {Read-NativeOffloadBinding $v.routes $v.adapters $v.settings}}
}
Case-N 'readonly-offload-stability-compares-raw-identities-and-values' {
    $v=OffloadInputs-N;$a=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings;$b=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings;Assert-N (Test-NativeOffloadBindingEqual $a $b)
    foreach($key in @('guid','instance','IPv4Enabled')){$v=OffloadInputs-N;$b=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings;$b[$key]=if($key -ceq 'IPv4Enabled'){$false}else{'source-drift'};Assert-N (-not (Test-NativeOffloadBindingEqual $a $b))}
}
Case-N 'readonly-offload-public-summary-excludes-identifiers-and-mutations' {
    $r=New-NativeOffloadEvidence 'none';foreach($key in @('routeMatched','adapterMatched','settingMatched','getCapability','setCapability','noRestartCapability','routeStable','identityStable')){$r[$key]=$true};$r.ipv4Enabled=$true;$r.ipv6Enabled=$true;$r.v1Ipv4Enabled=$false;$r.maximumVersion=2
    Assert-N ((Get-NativeOffloadEvidence ($r | ConvertTo-Json -Compress)).code -ceq 'none')
    $r['private']='PRIVATE-SYNTHETIC';$v=Get-NativeOffloadEvidence ($r | ConvertTo-Json -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')));$r.Remove('private');$r.settingsChanged=$true;Assert-N ((Get-NativeOffloadEvidence ($r | ConvertTo-Json -Compress)).code -ceq 'invalid')
}
Case-N 'readonly-offload-entry-never-invokes-a-setter-or-restart' {
    $tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'read-native-offload-state.ps1'),[ref]$tokens,[ref]$issues);Assert-N ($issues.Count -eq 0)
    foreach($command in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){Assert-N ($command.GetCommandName() -cnotin @('Set-NetAdapterLso','Enable-NetAdapterLso','Disable-NetAdapterLso','Restart-NetAdapter','Disable-NetAdapter','Enable-NetAdapter'))}
}


function OffloadChangeReply-N([string]$Operation) {
    $r=New-NativeOffloadChangeEvidence $Operation;$r.code='none';$r.identityVerified=$true;$r.changeRequired=$true;$r.changeAttempted=$true;$r.changed=$true;$r.restartRequested=$true;$r.restartReturned=$true;$r.readbackVerified=$true;$r.preservedOthers=$true;$r.originalIPv4=$true;$r.currentIPv4=($Operation -ceq 'restore');$r.restored=($Operation -ceq 'restore');return $r
}
Case-N 'offload-restoration-binds-guid-after-interface-index-and-name-change' {
    $v=OffloadInputs-N;$a=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings
    $v.adapters[0].CimInstanceProperties['InterfaceIndex'].Value=[uint32]9;$v.adapters[0].CimInstanceProperties['Name'].Value='source-renamed';$v.settings[0].CimInstanceProperties['Name'].Value='source-renamed'
    $b=Read-NativeOffloadOwnerSnapshot $v.adapters $v.settings $a.guid;Assert-N ((Test-NativeOffloadOwner $a $b) -and $b.index -eq 9 -and -not (Test-NativeOffloadBindingEqual $a $b))
}
Case-N 'offload-restoration-refuses-missing-or-ambiguous-owner-guid' {
    foreach($fault in @('foreign','duplicate')){$v=OffloadInputs-N;$a=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings;if($fault -ceq 'foreign'){$v.adapters[0].CimInstanceProperties['InterfaceGuid'].Value='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'}else{$v.adapters+=@($v.adapters[0])};Reject-N {Read-NativeOffloadOwnerSnapshot $v.adapters $v.settings $a.guid}}
}
Case-N 'offload-restoration-owner-and-other-modes-cannot-drift' {
    $v=OffloadInputs-N;$a=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings
    foreach($key in @('guid','description','instance')){$b=$a.Clone();$b[$key]='source-foreign';Assert-N (-not (Test-NativeOffloadOwner $a $b))}
    foreach($key in @('maximumVersion','V1IPv4Enabled','IPv6Enabled')){$b=$a.Clone();$b[$key]=if($key -ceq 'maximumVersion'){1}else{-not $a[$key]};Assert-N (-not (Test-NativeOffloadOtherSettings $a $b))}
    $b=$a.Clone();$b.IPv4Enabled=$false;Assert-N (Test-NativeOffloadOtherSettings $a $b)
}
Case-N 'offload-setter-selects-one-exact-instance-name-and-description' {
    $v=OffloadInputs-N;$a=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings;Assert-N ((Select-NativeOffloadSetting $a $v.settings) -eq $v.settings[0])
    foreach($key in @('InstanceID','Name','InterfaceDescription')){$v=OffloadInputs-N;$v.settings[0].CimInstanceProperties[$key].Value='source-foreign';Reject-N {Select-NativeOffloadSetting $a $v.settings}}
    $v=OffloadInputs-N;Reject-N {Select-NativeOffloadSetting $a @($v.settings[0],$v.settings[0])}
}
Case-N 'offload-stage-and-restore-evidence-require-fresh-complete-readback' {
    foreach($op in @('stage','restore')){$r=OffloadChangeReply-N $op;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) $op).code -ceq 'none')
        foreach($field in @('identityVerified','readbackVerified','preservedOthers')){$r=OffloadChangeReply-N $op;$r[$field]=$false;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) $op).code -ceq 'invalid')}
    }
    $r=OffloadChangeReply-N 'restore';$r.currentIPv4=$false;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) 'restore').code -ceq 'invalid')
}
Case-N 'offload-change-evidence-excludes-private-fields-and-false-success' {
    $r=OffloadChangeReply-N 'stage';$r['private']='PRIVATE-SYNTHETIC';$v=Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) 'stage';Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    $r=New-NativeOffloadChangeEvidence 'restore';$r.code='not-staged';$r.restored=$true;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) 'restore').code -ceq 'not-staged');$r.changeAttempted=$true;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) 'restore').code -ceq 'invalid')
    $r=OffloadChangeReply-N 'stage';$r.currentIPv4=$true;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) 'stage').code -ceq 'invalid')
}
Case-N 'offload-instrumentation-setters-require-exact-object-and-restart-mode' {
    $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'offload-control-operation.ps1'),[ref]$t,[ref]$e);Assert-N ($e.Count -eq 0);$setters=0
    foreach($c in $a.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
        Assert-N ($c.GetCommandName() -cnotin @('Enable-NetAdapterLso','Disable-NetAdapterLso','Restart-NetAdapter','Disable-NetAdapter','Enable-NetAdapter','Set-NetAdapterAdvancedProperty'))
        if($c.GetCommandName() -ceq 'Set-NetAdapterLso'){$setters++;$p=@($c.CommandElements | Where-Object {$_ -is [Management.Automation.Language.CommandParameterAst]} | ForEach-Object {$_.ParameterName});Assert-N ('InputObject' -cin $p -and 'IPv4Enabled' -cin $p -and 'NoRestart' -cin $p -and 'Confirm' -cin $p -and 'Name' -cnotin $p);$mode=@($c.CommandElements | Where-Object {$_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ceq 'NoRestart'});Assert-N ($mode.Count -eq 1 -and $mode[0].Argument -is [Management.Automation.Language.VariableExpressionAst] -and $mode[0].Argument.VariablePath.UserPath -ceq 'false')}
    };Assert-N ($setters -eq 2)
}
Case-N 'offload-plan-is-durable-before-mutation-and-restored-before-retirement' {
    $body=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'offload-control-operation.ps1'));Assert-N ($body.IndexOf('FileMode]::CreateNew') -lt $body.IndexOf('Set-NetAdapterLso') -and $body.IndexOf('$stream.Flush($true)') -lt $body.IndexOf('Set-NetAdapterLso') -and $body.Contains("Read-NativeOffloadOwnerSnapshot $"+'inventory.adapters'))
    $driver=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'test-native-netevent-control.ps1'));$cleanup=$driver.Substring($driver.IndexOf("`nfinally{"));Assert-N ($cleanup.IndexOf("Invoke-NativeOffloadOperation 'restore'") -lt $cleanup.IndexOf("Invoke-NativeNDISOperation 'remove'") -and $cleanup.Contains("if(-not $"+'offloadRestored)'))
}

Case-N 'offload-private-acl-import-is-explicit-before-autoload-is-disabled' {
    $body=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'offload-control-operation.ps1'));Assert-N ($body.Contains("'Microsoft.PowerShell.Security'") -and $body.IndexOf("'Microsoft.PowerShell.Security'") -lt $body.IndexOf("$"+"PSModuleAutoLoadingPreference='None'") -and $body.Contains('Get-Acl -LiteralPath $root') -and $body.Contains("$"+"stage='path-acl'"))
}

Case-N 'offload-change-success-requires-returned-restart-for-each-setter' {
    foreach($op in @('stage','restore')){foreach($field in @('restartRequested','restartReturned')){$r=OffloadChangeReply-N $op;$r[$field]=$false;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) $op).code -ceq 'invalid')}}
    $r=OffloadChangeReply-N 'stage';$r.originalIPv4=$false;$r.changeRequired=$false;$r.changeAttempted=$false;$r.changed=$false;$r.restartRequested=$false;$r.restartReturned=$false;Assert-N ((Get-NativeOffloadChangeEvidence ($r | ConvertTo-Json -Compress) 'stage').code -ceq 'none')
}

Case-N 'offload-settling-requires-exact-owner-states-and-route-after-restart' {
    $v=OffloadInputs-N;$a=Read-NativeOffloadBinding $v.routes $v.adapters $v.settings;$b=$a.Clone();Assert-N (-not (Test-NativeOffloadReady $a $b $false $true));$b.IPv4Enabled=$false;Assert-N (Test-NativeOffloadReady $a $b $false $true)
    $b.index=9;Assert-N (-not (Test-NativeOffloadReady $a $b $false $true));Assert-N (Test-NativeOffloadReady $a $b $null $false);$b.instance='foreign';Assert-N (-not (Test-NativeOffloadReady $a $b $null $false))
    $body=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'offload-control-operation.ps1'));Assert-N ($body.Contains('$attempt -lt 4') -and $body.Contains('Start-Sleep -Milliseconds 500'))
}

Case-N 'tcp-closure-reducer-preserves-closed-reset-direction-and-order-counts' {
    $r=ConversionReply-N;$r.summary.tcpClosure.sentReset=1;$r.summary.tcpClosure.afterReceivedFin=1;$r.summary.tcpClosure.receivedFin=1;$r.summary.tcpClosure.resetFlows=1
    $v=Get-NativeNDISConversionEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'none' -and $v.summary.tcpClosure.sentReset -eq 1 -and $v.summary.tcpClosure.afterReceivedFin -eq 1 -and -not $v.summary.tcpClosure.productionQualificationComplete)
}
Case-N 'tcp-closure-reducer-refuses-private-fields-and-inconsistent-counts' {
    foreach($fault in @('private','boolean','partition','flow','fin','qualification')){$r=ConversionReply-N;switch($fault){'private'{$r.summary.tcpClosure['private']='PRIVATE-SYNTHETIC'}'boolean'{$r.summary.tcpClosure.sentReset=$false}'partition'{$r.summary.tcpClosure.beforeFin=1}'flow'{$r.summary.tcpClosure.resetFlows=2}'fin'{$r.summary.tcpClosure.sentFin=2}'qualification'{$r.summary.tcpClosure.productionQualificationComplete=$true}};$v=Get-NativeNDISConversionEvidence ($r | ConvertTo-Json -Depth 5 -Compress);Assert-N ($v.code -ceq 'invalid' -and -not (($v | ConvertTo-Json -Depth 5 -Compress).Contains('PRIVATE-SYNTHETIC')))}
}

Case-N 'full-doh-policy-contains-all-fixed-endpoints-families-and-protocols' {
    $p=Get-NativeNetEventCapturePolicy 'product-doh-all';Assert-N (($p.addresses -join ',') -ceq '8.8.8.8,9.9.9.9,2001:4860:4860::8888,2620:fe::fe' -and ($p.etherTypes -join ',') -ceq '2048,34525' -and ($p.protocols -join ',') -ceq '6,17' -and $p.endpointMask -eq 15 -and $p.etherTypeMask -eq 3 -and $p.protocolMask -eq 3)
    $p=Get-NativeNetEventCapturePolicy 'control-google-v4';Assert-N ($p.addresses.Count -eq 1 -and $p.endpointMask -eq 1 -and $p.etherTypeMask -eq 1 -and $p.protocolMask -eq 1)
}
Case-N 'unknown-capture-policy-refuses-before-session-creation' {
    Reset-N;$script:plan.capturePolicy='PRIVATE-SYNTHETIC';Reject-N {Create-N};Assert-N ($script:sessions.Count -eq 0 -and $script:starts -eq 0 -and $script:removes -eq 0)
}
Case-N 'full-doh-policy-uses-owned-session-for-complete-native-boundary' {
    Reset-N;$script:plan.capturePolicy='product-doh-all';Assert-N (Invoke-NativeNetEventOperation 'preflight' $script:plan).emptyBefore;Assert-N (Create-N).sessionVerified;Assert-N (Invoke-NativeNetEventOperation 'provider' $script:plan).providerVerified
    Assert-N ((Invoke-NativeNetEventOperation 'start' $script:plan).state -ceq 'running');Assert-N ((Invoke-NativeNetEventOperation 'stop' $script:plan).state -ceq 'stopped');$script:plan.originalVerified=$true;Assert-N (Invoke-NativeNetEventOperation 'remove' $script:plan).emptyAfter
}
Case-N 'full-endpoint-readback-is-an-exact-semantic-set' {
    $p=Get-NativeNetEventCapturePolicy 'product-doh-all';Assert-NativeNetEventFilterSet @('2620:FE:0000:0000:0000:0000:0000:00FE','2001:4860:4860:0:0:0:0:8888','9.9.9.9','8.8.8.8') $p.addresses 'address'
    foreach($values in @(@('8.8.8.8','9.9.9.9'),@('8.8.8.8','9.9.9.9','2001:4860:4860::8888','8.8.8.8'),@('8.8.8.8','9.9.9.9','2001:4860:4860::8888%2','2620:fe::fe'),@('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2001:db8::1'))){Reject-N {Assert-NativeNetEventFilterSet $values $p.addresses 'address'}}
}
Case-N 'full-family-and-protocol-readbacks-refuse-coercion-and-missing-values' {
    $p=Get-NativeNetEventCapturePolicy 'product-doh-all';Assert-NativeNetEventFilterSet @([byte]17,[uint32]6) $p.protocols 'number';Assert-NativeNetEventFilterSet @([uint16]34525,[int]2048) $p.etherTypes 'number'
    foreach($values in @(@('6',17),@($false,17),@(6),@(6,6),@(6,18))){Reject-N {Assert-NativeNetEventFilterSet $values $p.protocols 'number'}}
    Reject-N {Assert-NativeNetEventFilterSet @(2048) $p.etherTypes 'number'};Reject-N {Assert-NativeNetEventFilterSet @('2048',34525) $p.etherTypes 'number'}
}
Case-N 'full-filter-drift-prevents-start-and-destructive-session-retirement' {
    Reset-N;$script:plan.capturePolicy='product-doh-all';[void](Create-N);[void](Invoke-NativeNetEventOperation 'provider' $script:plan);$script:providers[0].CimInstanceProperties['IPAddresses'].Value=@('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2001:db8::1')
    Reject-N {Invoke-NativeNetEventOperation 'start' $script:plan};$script:plan.originalVerified=$true;Reject-N {Invoke-NativeNetEventOperation 'remove' $script:plan};Assert-N ($script:starts -eq 0 -and $script:removes -eq 0 -and $script:sessions.Count -eq 1)
}

foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){throw 'Source changed'}}
$passed=@($cases | Where-Object {-not $_.passed}).Count -eq 0
[Console]::Out.WriteLine((@{schemaVersion=1;scope='actual-native-netevent-source';sourceSHA256=$hashes;cases=@($cases.ToArray());passed=$passed;realCaptureStarted=$false;realDnsChanged=$false;nativeQualified=$false} | ConvertTo-Json -Depth 6 -Compress))
if(-not $passed){exit 1}
