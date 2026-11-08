# Hosted source contracts. Native boundaries are replaced before evaluation.
[CmdletBinding()]param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Hosted source contracts only'}
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop}
$PSModuleAutoLoadingPreference='None'
$project=Split-Path -Parent $PSScriptRoot;$sources=@('scripts/native-netevent-control.ps1','scripts/netevent-control-operation.ps1','scripts/test-native-netevent-control.ps1','scripts/test-native-netevent-contracts.ps1','.github/workflows/native-netevent-control.yml','scripts/native-dns-wire.ps1','scripts/dns-acceptance-state.ps1')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-netevent-control.ps1'),[ref]$tokens,[ref]$issues);if($issues.Count){throw 'Source syntax'}
$allowed=@('Get-NativeNetEventValue','Get-NativeNetEventInventory','Get-NativeNetEventEnums','Assert-NativeNetEventSession','Get-NativeNetEventState','Assert-NativeNetEventProvider','New-NetEventSession','Add-NetEventPacketCaptureProvider','Start-NetEventSession','Stop-NetEventSession','Remove-NetEventSession','Where-Object','New-NativeNDISHeaderEvidence','ConvertFrom-Json')
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
foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){throw 'Source changed'}}
$passed=@($cases | Where-Object {-not $_.passed}).Count -eq 0
[Console]::Out.WriteLine((@{schemaVersion=1;scope='actual-native-netevent-source';sourceSHA256=$hashes;cases=@($cases.ToArray());passed=$passed;realCaptureStarted=$false;realDnsChanged=$false;nativeQualified=$false} | ConvertTo-Json -Depth 4 -Compress))
if(-not $passed){exit 1}
