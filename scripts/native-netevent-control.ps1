# Definitions only. Native calls execute solely through guarded bounded children.
function Get-NativeNetEventEnums {
    $script:netEventStage='enum-metadata'
    $result=@{}
    foreach($spec in @(@{key='mode';command='New-NetEventSession';parameter='CaptureMode';value='SaveToFile'},@{key='capture';command='Add-NetEventPacketCaptureProvider';parameter='CaptureType';value='Physical'})){
        $type=(Get-Command $spec.command -ErrorAction Stop).Parameters[$spec.parameter].ParameterType
        if(-not $type.IsEnum -or -not [Enum]::IsDefined($type,$spec.value)){throw 'NetEvent enum'}
        $result[$spec.key]=[int][Enum]::Parse($type,$spec.value)
    };return $result
}
function Get-NativeNetEventInventory {
    $script:netEventStage='inventory-readback'
    $s=@();$p=@()
    try{$s=@(Get-NetEventSession -ErrorAction Stop | Select-Object -First 2)}catch{if($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound){throw}}
    try{$p=@(Get-NetEventPacketCaptureProvider -ErrorAction Stop | Select-Object -First 2)}catch{if($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound){throw}}
    foreach($row in @($s)+@($p)){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'NetEvent inventory'}}
    return @{sessions=$s;providers=$p}
}
function Get-NativeNetEventValue([object]$Row,[string]$Name) {
    # Read underlying typed CIM data, independent of display type extensions.
    $property=$Row.CimInstanceProperties[$Name]
    if($null -eq $property){throw 'NetEvent configuration'}
    return ,$property.Value
}
function Assert-NativeNetEventSession([object]$Row,[object]$Plan,[object]$Enums) {
    $script:netEventStage='session-readback'
    $name=Get-NativeNetEventValue $Row 'Name';$id=Get-NativeNetEventValue $Row 'Guid';$file=Get-NativeNetEventValue $Row 'LocalFilePath';$size=Get-NativeNetEventValue $Row 'MaxFileSize';$mode=Get-NativeNetEventValue $Row 'CaptureMode'
    $script:netEventModeValue=$mode;$script:netEventStatusValue=$Row.SessionStatus
    $guid=[guid]::Empty
    if($name -isnot [string] -or $name -cne $Plan.name -or $id -isnot [string] -or -not [guid]::TryParse($id,[ref]$guid) -or $guid -eq [guid]::Empty){throw 'NetEvent session'}
    if($Plan.guid -and $guid -ne [guid]$Plan.guid){throw 'NetEvent identity'}
    if($file -isnot [string] -or -not [IO.Path]::GetFullPath($file).Equals($Plan.file,[StringComparison]::OrdinalIgnoreCase) -or $size -is [bool] -or [long]$size -ne 16 -or $null -eq $mode -or $mode -is [bool] -or [int]$mode -ne $Enums.mode){throw 'NetEvent configuration'}
    return $guid.ToString('D')
}
function Get-NativeNetEventState([object]$Row) {
    $name=[string]$Row.SessionStatus
    if($name -ceq 'Running'){return 'running'}
    if($name -cin @('NotRunning','Stopped')){return 'stopped'}
    return 'unknown'
}
function Get-NativeNetEventCapturePolicy([string]$Name) {
    if($Name -ceq 'control-google-v4'){return @{name=$Name;addresses=@('8.8.8.8');protocols=@(6);etherTypes=@(2048);endpointMask=1;etherTypeMask=1;protocolMask=1}}
    if($Name -ceq 'product-doh-all'){return @{name=$Name;addresses=@('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe');protocols=@(6,17);etherTypes=@(2048,34525);endpointMask=15;etherTypeMask=3;protocolMask=3}}
    throw 'NetEvent plan'
}
function Assert-NativeNetEventFilterSet([object[]]$Actual,[object[]]$Expected,[string]$Kind) {
    if($Kind -cnotin @('address','number') -or $Actual.Count -ne $Expected.Count -or $Actual.Count -lt 1 -or $Actual.Count -gt 4){throw 'NetEvent filters'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($value in $Actual){
        if($Kind -ceq 'address'){
            if($value -isnot [string] -or $value.Length -gt 64 -or $value -cnotmatch '^[0-9a-fA-F:.]+$'){throw 'NetEvent filters'}
            $ip=$null;if(-not [Net.IPAddress]::TryParse($value,[ref]$ip)){throw 'NetEvent filters'};$key=$ip.ToString()
        }else{
            if(($value -isnot [byte] -and $value -isnot [uint16] -and $value -isnot [uint32] -and $value -isnot [int] -and $value -isnot [long]) -or [long]$value -lt 0 -or [long]$value -gt 65535){throw 'NetEvent filters'};$key=([long]$value).ToString([Globalization.CultureInfo]::InvariantCulture)
        }
        $matched=$false;foreach($wanted in $Expected){$canonical=if($Kind -ceq 'address'){([Net.IPAddress]::Parse([string]$wanted)).ToString()}else{([long]$wanted).ToString([Globalization.CultureInfo]::InvariantCulture)};if($key -ceq $canonical){$matched=$true;break}}
        if(-not $matched -or -not $seen.Add($key)){throw 'NetEvent filters'}
    }
}
function Assert-NativeNetEventProvider([object]$Row,[object]$Plan,[string]$Guid,[object]$Enums) {
    $script:netEventStage='provider-readback';$values=@{}
    foreach($key in @('Guid','SessionGuid','SessionName','Level','CaptureType','MultiLayer','TruncationLength','MatchAnyKeyword','MatchAllKeyword','IPAddresses','IPProtocols','EtherType','LinkLayerAddress')){$values[$key]=Get-NativeNetEventValue $Row $key}
    $provider=[guid]::Empty;$session=[guid]::Empty
    if(-not [guid]::TryParse([string]$values.Guid,[ref]$provider) -or $provider -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef' -or -not [guid]::TryParse([string]$values.SessionGuid,[ref]$session) -or $session -ne [guid]$Guid -or $values.SessionName -cne $Plan.name){throw 'NetEvent provider'}
    foreach($key in @('Level','CaptureType','TruncationLength','MatchAnyKeyword','MatchAllKeyword')){if($null -eq $values[$key] -or $values[$key] -is [bool]){throw 'NetEvent filters'}}
    if([int]$values.Level -ne 5 -or [int]$values.CaptureType -ne $Enums.capture -or $values.MultiLayer -isnot [bool] -or $values.MultiLayer -or [int]$values.TruncationLength -ne 65535 -or [System.UInt64]$values.MatchAnyKeyword -ne [System.UInt64]::MaxValue -or [System.UInt64]$values.MatchAllKeyword -ne 0){throw 'NetEvent filters'}
    $policy=Get-NativeNetEventCapturePolicy $Plan.capturePolicy
    Assert-NativeNetEventFilterSet @($values.IPAddresses) $policy.addresses 'address'
    Assert-NativeNetEventFilterSet @($values.IPProtocols) $policy.protocols 'number'
    Assert-NativeNetEventFilterSet @($values.EtherType) $policy.etherTypes 'number'
    if(@($values.LinkLayerAddress | Where-Object {$_}).Count -ne 0){throw 'NetEvent filters'}
}
function Invoke-NativeNetEventOperation([string]$Operation,[object]$Plan) {
    if($Operation -cnotin @('preflight','create','provider','start','stop','remove') -or $Plan.name -cnotmatch '^awndis-[a-f0-9]{32}$' -or $Plan.file -isnot [string] -or -not [IO.Path]::IsPathRooted($Plan.file) -or [IO.Path]::GetFileName($Plan.file) -cne 'capture.etl' -or $Plan.originalVerified -isnot [bool]){throw 'NetEvent plan'}
    if($Plan.guid -and ([string]$Plan.guid -cnotmatch '^[a-f0-9-]{36}$')){throw 'NetEvent plan'}
    $policy=Get-NativeNetEventCapturePolicy $Plan.capturePolicy
    $r=@{code='none';sessionGuid='';state='absent';sessionVerified=$false;providerVerified=$false;emptyBefore=$false;emptyAfter=$false}
    $inventory=Get-NativeNetEventInventory
    if($inventory.sessions.Count -gt 1 -or $inventory.providers.Count -gt 1){throw 'NetEvent inventory'}
    if($Operation -cin @('preflight','create')){
        if($inventory.sessions.Count -ne 0 -or $inventory.providers.Count -ne 0){throw 'NetEvent inventory'};$r.emptyBefore=$true
        if($Operation -ceq 'preflight'){return $r}
        $script:netEventStage='create-request'
        [void](New-NetEventSession -Name $Plan.name -CaptureMode SaveToFile -LocalFilePath $Plan.file -MaxFileSize 16 -ErrorAction Stop)
        $inventory=Get-NativeNetEventInventory
    }
    if($inventory.sessions.Count -eq 0){
        if($Operation -cin @('stop','remove') -and $inventory.providers.Count -eq 0){$r.emptyAfter=$true;return $r};throw 'NetEvent inventory'
    }
    $enums=Get-NativeNetEventEnums;$row=$inventory.sessions[0]
    $r.sessionGuid=Assert-NativeNetEventSession $row $Plan $enums;$r.sessionVerified=$true;$r.state=Get-NativeNetEventState $row
    if($r.state -ceq 'unknown'){throw 'NetEvent state'}
    if($inventory.providers.Count -eq 1){Assert-NativeNetEventProvider $inventory.providers[0] $Plan $r.sessionGuid $enums;$r.providerVerified=$true}
    if($Operation -ceq 'create'){if($r.state -cne 'stopped' -or $inventory.providers.Count -ne 0){throw 'NetEvent state'};return $r}
    if($Operation -ceq 'provider'){
        if($r.state -cne 'stopped' -or $inventory.providers.Count -ne 0){throw 'NetEvent inventory'}
        $script:netEventStage='provider-request'
        [void](Add-NetEventPacketCaptureProvider -SessionName $Plan.name -CaptureType Physical -MultiLayer $false -EtherType ([uint16[]]$policy.etherTypes) -IpAddresses ([string[]]$policy.addresses) -IpProtocols ([byte[]]$policy.protocols) -TruncationLength 65535 -Level 5 -MatchAnyKeyword ([System.UInt64]::MaxValue) -MatchAllKeyword ([System.UInt64]0) -ErrorAction Stop)
    }elseif($Operation -ceq 'start'){
        if($r.state -cne 'stopped' -or -not $r.providerVerified){throw 'NetEvent state'}
        $script:netEventStage='start-request'
        [void](Start-NetEventSession -InputObject $row -ErrorAction Stop)
    }elseif($Operation -ceq 'stop'){
        if($r.state -ceq 'running'){$script:netEventStage='stop-request';[void](Stop-NetEventSession -InputObject $row -ErrorAction Stop)}
    }elseif($Operation -ceq 'remove'){
        if(-not $Plan.originalVerified){throw 'NetEvent original'}
        if($r.state -cne 'stopped'){throw 'NetEvent state'}
        # The documented removal deletes associated objects. Reject any
        # unrecognized packet provider before acting on the exact CIM session.
        $script:netEventStage='remove-request'
        [void](Remove-NetEventSession -InputObject $row -Confirm:$false -ErrorAction Stop)
    }
    $after=Get-NativeNetEventInventory
    if($Operation -ceq 'remove'){
        if($after.sessions.Count -ne 0 -or $after.providers.Count -ne 0){throw 'NetEvent inventory'};$r.emptyAfter=$true;$r.state='absent';return $r
    }
    if($after.sessions.Count -ne 1 -or $after.providers.Count -gt 1 -or ($Operation -cin @('provider','start') -and $after.providers.Count -ne 1) -or ($Operation -ceq 'stop' -and $after.providers.Count -ne $inventory.providers.Count)){throw 'NetEvent inventory'}
    $verified=Assert-NativeNetEventSession $after.sessions[0] $Plan $enums
    if($verified -cne $r.sessionGuid){throw 'NetEvent identity'};$r.state=Get-NativeNetEventState $after.sessions[0]
    if(($Operation -ceq 'start' -and $r.state -cne 'running') -or ($Operation -cin @('provider','stop') -and $r.state -cne 'stopped')){throw 'NetEvent state'}
    if($after.providers.Count -eq 1){Assert-NativeNetEventProvider $after.providers[0] $Plan $r.sessionGuid $enums;$r.providerVerified=$true}
    if($Operation -ceq 'provider' -and -not $r.providerVerified){throw 'NetEvent provider'}
    return $r
}
function New-NativeNDISHeaderEvidence([string]$Code='not-inspected') {
    $r=@{code=$Code;records=-1;providerRecords=-1;fragmentIDs=-1;unknownProviderIDs=-1;otherProviderRecords=-1;missingProviderIDs=-1;unrecognizedVersions=-1}
    if($Code -cin @('complete','bound')){foreach($key in @('records','providerRecords','fragmentIDs','unknownProviderIDs','otherProviderRecords','missingProviderIDs','unrecognizedVersions')){$r[$key]=0}};return $r
}
function Add-NativeNDISHeader([object]$Evidence,[Nullable[guid]]$Provider,[int]$ID,[Nullable[byte]]$Version) {
    if($Evidence.code -cne 'complete' -or $Evidence.records -ge 4096 -or $ID -lt 0 -or $ID -gt 65535){throw 'NDIS header bound'};$Evidence.records++
    if($null -eq $Provider){$Evidence.missingProviderIDs++;$Evidence.otherProviderRecords++;return}
    if($Provider -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef'){$Evidence.otherProviderRecords++;return}
    $Evidence.providerRecords++;if($null -eq $Version -or $Version -ne 0){$Evidence.unrecognizedVersions++}
    if($ID -eq 1001){$Evidence.fragmentIDs++}else{$Evidence.unknownProviderIDs++}
}
function Get-NativeNDISHeaderEvidence([string]$Text) {
    $bad=New-NativeNDISHeaderEvidence 'invalid';if($Text.Length -gt 4096){return $bad}
    try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('records','providerRecords','fragmentIDs','unknownProviderIDs','otherProviderRecords','missingProviderIDs','unrecognizedVersions')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 8 -or $v.code -cnotin @('complete','bound','unavailable')){return $bad}
    foreach($key in $keys){if($null -eq $v.PSObject.Properties[$key]){return $bad};$n=$v.$key;if(($n -isnot [int] -and $n -isnot [long]) -or $n -lt -1 -or $n -gt 4096){return $bad};if(($v.code -ceq 'unavailable' -and $n -ne -1) -or ($v.code -cne 'unavailable' -and $n -lt 0)){return $bad}}
    if($v.code -cne 'unavailable' -and ($v.records -ne $v.providerRecords+$v.otherProviderRecords -or $v.providerRecords -ne $v.fragmentIDs+$v.unknownProviderIDs -or $v.missingProviderIDs -gt $v.otherProviderRecords -or $v.unrecognizedVersions -gt $v.providerRecords)){return $bad}
    $r=New-NativeNDISHeaderEvidence $v.code;foreach($key in $keys){$r[$key]=[int]$v.$key};return $r
}
function Get-NativeNDISHeaderProgram([string]$Path) {
    $prefix='function New-NativeNDISHeaderEvidence {'+${function:New-NativeNDISHeaderEvidence}.ToString()+"}`n"+'function Add-NativeNDISHeader {'+${function:Add-NativeNDISHeader}.ToString()+"}`n"
    $body=@'
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$PSModuleAutoLoadingPreference='None'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
$reader=$null;$r=New-NativeNDISHeaderEvidence 'unavailable'
try{
    $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATH__'))
    $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($path,[Diagnostics.Eventing.Reader.PathType]::FilePath);$query.ReverseDirection=$false;$query.TolerateQueryErrors=$false
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=16;$clock=[Diagnostics.Stopwatch]::StartNew();$r=New-NativeNDISHeaderEvidence 'complete'
    while($true){if($r.records -ge 4096 -or $clock.Elapsed.TotalSeconds -ge 3){$r.code='bound';break};$record=$reader.ReadEvent([TimeSpan]::FromMilliseconds(250));if($null -eq $record){break};try{Add-NativeNDISHeader $r $record.ProviderId $record.Id $record.Version}finally{$record.Dispose()}}
}catch{$r=New-NativeNDISHeaderEvidence 'unavailable'}finally{if($null -ne $reader){$reader.Dispose()}}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
'@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prefix+$body.Replace('__PATH__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Path)))))
}

function New-NativeNDISLossEvidence([string]$Code='not-inspected') {
    return @{code=$Code;eventsLost=-1;buffersLost=-1;bufferSize=-1;buffersWritten=-1;maximumFileSize=-1;pointerSize=-1;logFileMode=-1;finalized=$false;closed=$false;nativeCode=-1}
}
function Get-NativeNDISLossEvidence([string]$Text) {
    $bad=New-NativeNDISLossEvidence 'invalid';if($Text.Length -gt 4096){return $bad}
    try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('eventsLost','buffersLost','bufferSize','buffersWritten','maximumFileSize','pointerSize','logFileMode')
    $all=@('code','eventsLost','buffersLost','bufferSize','buffersWritten','maximumFileSize','pointerSize','logFileMode','finalized','closed','nativeCode')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 11 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $all}).Count -ne 0 -or $v.code -cnotin @('parsed','layout','open-failed','close-failed','unavailable') -or $v.finalized -isnot [bool] -or $v.closed -isnot [bool]){return $bad}
    foreach($key in $keys){$n=$v.$key;if(($n -isnot [int] -and $n -isnot [long]) -or $n -lt -1 -or $n -gt 4294967295){return $bad}}
    if(($v.nativeCode -isnot [int] -and $v.nativeCode -isnot [long]) -or $v.nativeCode -lt -1 -or $v.nativeCode -gt 65535){return $bad}
    $r=New-NativeNDISLossEvidence $v.code;$r.nativeCode=[int]$v.nativeCode
    if($v.code -ceq 'parsed'){
        if(@($keys | Where-Object {$v.$_ -lt 0}).Count -ne 0 -or -not $v.closed -or $v.nativeCode -ne 0){return $bad}
        foreach($key in $keys){$r[$key]=[long]$v.$key};$r.finalized=$v.finalized;$r.closed=$v.closed
    };return $r
}
function Test-NativeNDISLossEvidence([object]$Evidence) {
    return ($Evidence.code -ceq 'parsed' -and $Evidence.closed -and $Evidence.finalized -and $Evidence.nativeCode -eq 0 -and $Evidence.eventsLost -eq 0 -and $Evidence.buffersLost -eq 0 -and $Evidence.pointerSize -eq 8 -and $Evidence.maximumFileSize -eq 16 -and $Evidence.bufferSize -ge 1024 -and $Evidence.bufferSize -le 1048576 -and $Evidence.bufferSize%1024 -eq 0 -and $Evidence.buffersWritten -gt 0 -and ($Evidence.logFileMode -band 2) -ne 0 -and ($Evidence.logFileMode -band 8) -eq 0 -and ([decimal]$Evidence.bufferSize*[decimal]$Evidence.buffersWritten) -lt 16777216)
}


# Metadata only: documented NDIS event/keyword categories; never retain raw keywords.
function New-NativeNDISFragmentEvidence([string]$Code='not-inspected') {
    $r=@{code=$Code;records=-1;fragmentIDs=-1;singleEvent=-1;partialEvent=-1;ethernet=-1;wireless=-1;rawWan=-1;mediaConflict=-1;sent=-1;received=-1;directionUnknown=-1;missingKeywords=-1;unrecognizedVersions=-1;metadataIDs=-1;unknownProviderIDs=-1;otherProviderRecords=-1;missingProviderIDs=-1}
    if($Code -cin @('complete','bound')){foreach($key in @('records','fragmentIDs','singleEvent','partialEvent','ethernet','wireless','rawWan','mediaConflict','sent','received','directionUnknown','missingKeywords','unrecognizedVersions','metadataIDs','unknownProviderIDs','otherProviderRecords','missingProviderIDs')){$r[$key]=0}};return $r
}
function Add-NativeNDISFragmentHeader([object]$Evidence,[Nullable[guid]]$Provider,[int]$ID,[Nullable[byte]]$Version,[Nullable[long]]$Keywords) {
    if($Evidence.code -cne 'complete' -or $Evidence.records -ge 4096 -or $ID -lt 0 -or $ID -gt 65535){throw 'NDIS fragment header bound'};$Evidence.records++
    if($null -eq $Provider){$Evidence.missingProviderIDs++;$Evidence.otherProviderRecords++;return}
    if($Provider -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef'){$Evidence.otherProviderRecords++;return}
    if($ID -eq 1002){$Evidence.metadataIDs++;return}
    if($ID -ne 1001){$Evidence.unknownProviderIDs++;return}
    $Evidence.fragmentIDs++;if($null -eq $Version -or $Version -ne 0){$Evidence.unrecognizedVersions++}
    if($null -eq $Keywords){$Evidence.missingKeywords++;return}
    $bits=[long]$Keywords
    if(($bits -band 3221225472) -eq 3221225472){$Evidence.singleEvent++}else{$Evidence.partialEvent++}
    $wifi=($bits -band 65536) -ne 0;$wan=($bits -band 512) -ne 0
    if($wifi -and $wan){$Evidence.mediaConflict++}elseif($wifi){$Evidence.wireless++}elseif($wan){$Evidence.rawWan++}else{$Evidence.ethernet++}
    $send=($bits -band 4294967296) -ne 0;$receive=($bits -band 8589934592) -ne 0
    if($send -eq $receive){$Evidence.directionUnknown++}elseif($send){$Evidence.sent++}else{$Evidence.received++}
}
function Get-NativeNDISFragmentEvidence([string]$Text) {
    $bad=New-NativeNDISFragmentEvidence 'invalid';if($Text.Length -gt 4096){return $bad}
    try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('records','fragmentIDs','singleEvent','partialEvent','ethernet','wireless','rawWan','mediaConflict','sent','received','directionUnknown','missingKeywords','unrecognizedVersions','metadataIDs','unknownProviderIDs','otherProviderRecords','missingProviderIDs')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 18 -or $v.code -cnotin @('complete','bound','unavailable')){return $bad}
    foreach($key in $keys){if($null -eq $v.PSObject.Properties[$key]){return $bad};$n=$v.$key;if(($n -isnot [int] -and $n -isnot [long]) -or $n -lt -1 -or $n -gt 4096){return $bad};if(($v.code -ceq 'unavailable' -and $n -ne -1) -or ($v.code -cne 'unavailable' -and $n -lt 0)){return $bad}}
    if($v.code -cne 'unavailable'){
        $known=$v.fragmentIDs-$v.missingKeywords
        if($known -lt 0 -or $v.records -ne $v.fragmentIDs+$v.metadataIDs+$v.unknownProviderIDs+$v.otherProviderRecords -or $known -ne $v.singleEvent+$v.partialEvent -or $known -ne $v.ethernet+$v.wireless+$v.rawWan+$v.mediaConflict -or $known -ne $v.sent+$v.received+$v.directionUnknown -or $v.missingProviderIDs -gt $v.otherProviderRecords -or $v.unrecognizedVersions -gt $v.fragmentIDs){return $bad}
    }
    $r=New-NativeNDISFragmentEvidence $v.code;foreach($key in $keys){$r[$key]=[int]$v.$key};return $r
}
function Test-NativeNDISFragmentEvidence([object]$Evidence) {
    return ($null -ne $Evidence -and $Evidence.code -ceq 'complete' -and $Evidence.fragmentIDs -gt 0 -and $Evidence.singleEvent -eq $Evidence.fragmentIDs -and $Evidence.ethernet -eq $Evidence.fragmentIDs -and $Evidence.sent -gt 0 -and $Evidence.received -gt 0 -and $Evidence.directionUnknown -eq 0 -and $Evidence.missingKeywords -eq 0 -and $Evidence.unrecognizedVersions -eq 0 -and $Evidence.missingProviderIDs -eq 0)
}
function Get-NativeNDISFragmentProgram([string]$Path) {
    $prefix='function New-NativeNDISFragmentEvidence {'+${function:New-NativeNDISFragmentEvidence}.ToString()+"}`n"+'function Add-NativeNDISFragmentHeader {'+${function:Add-NativeNDISFragmentHeader}.ToString()+"}`n"
    $body=@'
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$PSModuleAutoLoadingPreference='None'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
$reader=$null;$r=New-NativeNDISFragmentEvidence 'unavailable'
try{
    $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATH__'))
    $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($path,[Diagnostics.Eventing.Reader.PathType]::FilePath);$query.ReverseDirection=$false;$query.TolerateQueryErrors=$false
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=16;$clock=[Diagnostics.Stopwatch]::StartNew();$r=New-NativeNDISFragmentEvidence 'complete'
    while($true){if($r.records -ge 4096 -or $clock.Elapsed.TotalSeconds -ge 3){$r.code='bound';break};$record=$reader.ReadEvent([TimeSpan]::FromMilliseconds(250));if($null -eq $record){break};try{Add-NativeNDISFragmentHeader $r $record.ProviderId $record.Id $record.Version $record.Keywords}finally{$record.Dispose()}}
}catch{$r=New-NativeNDISFragmentEvidence 'unavailable'}finally{if($null -ne $reader){$reader.Dispose()}}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
'@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prefix+$body.Replace('__PATH__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Path)))))
}


# Installed Windows provider metadata is the primary catalog. No event values are read.
function Get-NativeNDISTemplateSignature([string]$Template) {
    if(-not $Template -or $Template.Length -gt 8192){return ''}
    $reader=$null;$stream=$null
    try{
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=8192
        $stream=[IO.StringReader]::new($Template);$reader=[Xml.XmlReader]::Create($stream,$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $root=$doc.DocumentElement;$ns='http://schemas.microsoft.com/win/2004/08/events'
        if($root.LocalName -cne 'template' -or $root.NamespaceURI -cne $ns){return ''}
        $parts=[Collections.Generic.List[string]]::new()
        foreach($node in $root.ChildNodes){
            if($node.NodeType -eq [Xml.XmlNodeType]::Whitespace -or $node.NodeType -eq [Xml.XmlNodeType]::SignificantWhitespace){continue}
            if($node.NodeType -ne [Xml.XmlNodeType]::Element -or $node.LocalName -cne 'data' -or $node.NamespaceURI -cne $ns -or $node.HasChildNodes -or $parts.Count -ge 8){return ''}
            foreach($attribute in $node.Attributes){if($attribute.Name -cnotin @('name','inType','outType','map','length','count')){return ''}}
            if($node.HasAttribute('count')){return ''}
            $name=$node.GetAttribute('name');$type=$node.GetAttribute('inType');$length=$node.GetAttribute('length')
            if($name -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,31}$' -or $type -cnotin @('win:UInt8','win:UInt16','win:UInt32','win:UInt64','win:UnicodeString','win:Binary') -or ($length -and $length -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,31}$')){return ''}
            $parts.Add($name+':'+$type+':'+$length)
        }
        if($parts.Count -eq 0){return ''};return [string]::Join('|',$parts.ToArray())
    }catch{return ''}finally{if($null -ne $reader){$reader.Dispose()};if($null -ne $stream){$stream.Dispose()}}
}
function Get-NativeNDISCatalogClass([int]$ID,[int]$Version,[int]$Level,[string]$Template) {
    if($Version -ne 0 -or $Level -lt 4 -or $Level -gt 5){return 'unknown'}
    $signature=Get-NativeNDISTemplateSignature $Template
    if($ID -eq 1001 -and $signature -ceq 'MiniportIfIndex:win:UInt32:|LowerIfIndex:win:UInt32:|FragmentSize:win:UInt32:|Fragment:win:Binary:FragmentSize'){return 'fragment'}
    if($ID -eq 1001 -and $signature -ceq 'MiniportIfIndex:win:UInt32:|LowerIfIndex:win:UInt32:|FragmentSize:win:UInt32:|Fragment:win:Binary:FragmentSize|GftFlowEntryId:win:UInt64:|GftOffloadInformation:win:UInt64:'){return 'fragment'}
    if($ID -eq 1002 -and $signature -ceq 'MiniportIfIndex:win:UInt32:|LowerIfIndex:win:UInt32:|MetadataSize:win:UInt32:|Metadata:win:Binary:MetadataSize'){return 'metadata'}
    if($ID -eq 1011 -and $signature -ceq 'RulesCount:win:UInt32:'){return 'rules'}
    if($ID -eq 1016 -and $signature -ceq 'RuleId:win:UInt8:|Directive:win:UInt8:|Length:win:UInt16:|Value:win:Binary:Length'){return 'rules'}
    if($ID -cin @(1012,1013) -and $signature -ceq 'FriendlyName:win:UnicodeString:|UniqueName:win:UnicodeString:|ServiceName:win:UnicodeString:|Version:win:UnicodeString:'){return 'inventory'}
    if($ID -cin @(1014,1015) -and $signature -ceq 'MiniportIfIndex:win:UInt32:|LowerIfIndex:win:UInt32:|MediaType:win:UInt32:|ReferenceContext:win:UInt32:'){return 'inventory'}
    if($ID -cin @(3001,3002) -and $Level -eq 5 -and $signature -ceq 'PreviousState:win:UInt8:|NextState:win:UInt8:|Location:win:UInt32:|Context:win:UInt32:'){return 'lifecycle'}
    if($ID -eq 5100 -and $Level -eq 4 -and $signature -ceq 'SourceId:win:UInt8:|RundownId:win:UInt32:|Param1:win:UInt64:|Param2:win:UInt64:|ParamStr:win:UnicodeString:|Description:win:UnicodeString:'){return 'rundown'}
    if($ID -eq 5101 -and $Level -eq 4){
        $tree=@(Get-NativeNDISTemplateTree $Template)
        if([string]::Join('|',$tree) -ceq 'D:SourceId:win:UInt8::|D:SourceName:win:UnicodeString::|D:IfIndex:win:UInt32::|D:LayerCount:win:UInt16::|S:LayerInfo::LayerCount|D:LayerId:win:UInt32::|D:LayerName:win:UnicodeString::|E:LayerInfo'){return 'rundown'}
    }
    return 'unknown'
}
function New-NativeNDISCatalogEvidence([string]$Code='not-inspected') {
    $r=@{code=$Code;schemas=@();providerVerified=$false;definitions=-1;recognizedDefinitions=-1;records=-1;fragmentRecords=-1;metadataRecords=-1;ruleRecords=-1;inventoryRecords=-1;lifecycleRecords=-1;rundownRecords=-1;unknownRecords=-1;otherProviderRecords=-1;missingProviderIDs=-1;unrecognizedVersions=-1}
    if($Code -cin @('complete','bound')){$r.providerVerified=$true;foreach($key in @('definitions','recognizedDefinitions','records','fragmentRecords','metadataRecords','ruleRecords','inventoryRecords','lifecycleRecords','rundownRecords','unknownRecords','otherProviderRecords','missingProviderIDs','unrecognizedVersions')){$r[$key]=0}};return $r
}
function Add-NativeNDISCatalogHeader([object]$Evidence,[object]$Catalog,[Nullable[guid]]$Provider,[int]$ID,[Nullable[byte]]$Version) {
    if($Evidence.code -cne 'complete' -or $Evidence.records -ge 4096 -or $ID -lt 0 -or $ID -gt 65535){throw 'NDIS catalog header bound'};$Evidence.records++
    if($null -eq $Provider){$Evidence.missingProviderIDs++;$Evidence.otherProviderRecords++;return}
    if($Provider -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef'){$Evidence.otherProviderRecords++;return}
    if($null -eq $Version -or $Version -ne 0){$Evidence.unrecognizedVersions++;$Evidence.unknownRecords++;return}
    $key=([string]$ID)+':'+([string]$Version)
    $kind=if($Catalog.ContainsKey($key)){$Catalog[$key]}else{'unknown'}
    switch -CaseSensitive ($kind){'fragment'{$Evidence.fragmentRecords++}'metadata'{$Evidence.metadataRecords++}'rules'{$Evidence.ruleRecords++}'inventory'{$Evidence.inventoryRecords++}'lifecycle'{$Evidence.lifecycleRecords++}'rundown'{$Evidence.rundownRecords++}default{$Evidence.unknownRecords++}}
}
function Get-NativeNDISCatalogEvidence([string]$Text) {
    $bad=New-NativeNDISCatalogEvidence 'invalid';if($Text.Length -gt 12288){return $bad}
    try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('definitions','recognizedDefinitions','records','fragmentRecords','metadataRecords','ruleRecords','inventoryRecords','lifecycleRecords','rundownRecords','unknownRecords','otherProviderRecords','missingProviderIDs','unrecognizedVersions')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 16 -or $v.code -cnotin @('complete','bound','unavailable') -or $v.providerVerified -isnot [bool]){return $bad}
    foreach($key in $keys){if($null -eq $v.PSObject.Properties[$key]){return $bad};$n=$v.$key;if(($n -isnot [int] -and $n -isnot [long]) -or $n -lt -1 -or $n -gt 4096){return $bad};if(($v.code -ceq 'unavailable' -and $n -ne -1) -or ($v.code -cne 'unavailable' -and $n -lt 0)){return $bad}}
    if($v.code -ceq 'unavailable'){if($v.providerVerified){return $bad}}elseif(-not $v.providerVerified -or $v.definitions -gt 64 -or $v.recognizedDefinitions -gt $v.definitions -or $v.records -ne $v.fragmentRecords+$v.metadataRecords+$v.ruleRecords+$v.inventoryRecords+$v.lifecycleRecords+$v.rundownRecords+$v.unknownRecords+$v.otherProviderRecords -or $v.missingProviderIDs -gt $v.otherProviderRecords -or $v.unrecognizedVersions -gt $v.unknownRecords){return $bad}
    if($v.schemas -isnot [array] -or $v.schemas.Count -gt 16){return $bad}
    $seen=@{};$total=0;$rows=[Collections.Generic.List[object]]::new()
    foreach($row in $v.schemas){
        if($row -isnot [pscustomobject] -or @($row.PSObject.Properties).Count -ne 10 -or @($row.PSObject.Properties.Name | Where-Object {$_ -cnotin @('id','version','level','records','code','fields','task','opcode','templateKind','tree')}).Count -ne 0){return $bad}
        foreach($field in @('id','version','level','records')){if($row.$field -isnot [int] -and $row.$field -isnot [long]){return $bad}}
        if($row.id -lt 0 -or $row.id -gt 65535 -or $row.version -lt -1 -or $row.version -gt 255 -or $row.level -lt -1 -or $row.level -gt 255 -or $row.records -lt 1 -or $row.records -gt 4096 -or $row.code -cnotin @('projected','unsupported','missing') -or $row.fields -isnot [array] -or $row.fields.Count -gt 12){return $bad}
        foreach($field in @('task','opcode')){if($row.$field -isnot [string] -or ($row.$field -and $row.$field -cnotmatch '^[A-Za-z][A-Za-z0-9_.:-]{0,63}$')){return $bad}}
        if($row.templateKind -cnotin @('empty','data','structured','unsupported','missing')){return $bad}
        if(-not (Test-NativeNDISTemplateTree $row.tree)){return $bad}
        foreach($field in $row.fields){if($field -isnot [string] -or $field -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,47}:win:(UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64|HexInt32|HexInt64|UnicodeString|AnsiString|Binary|Boolean|GUID|Pointer|FILETIME|SYSTEMTIME|SID|SizeT):([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})?:([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})?$'){return $bad}}
        if(($row.code -ceq 'projected' -and $row.fields.Count -eq 0) -or ($row.code -cne 'projected' -and $row.fields.Count -ne 0) -or ($row.code -ceq 'missing' -and $row.level -ne -1)){return $bad}
        $key=([string]$row.id)+':'+([string]$row.version);if($seen.ContainsKey($key)){return $bad};$seen[$key]=$true;$total+=$row.records;$rows.Add(@{id=$row.id;version=$row.version;level=$row.level;records=$row.records;code=$row.code;fields=@($row.fields);task=$row.task;opcode=$row.opcode;templateKind=$row.templateKind;tree=@($row.tree)})
    }
    if(($v.code -cin @('complete','bound') -and $total -ne $v.unknownRecords) -or ($v.code -ceq 'unavailable' -and $rows.Count -ne 0)){return $bad}
    $r=New-NativeNDISCatalogEvidence $v.code;foreach($key in $keys){$r[$key]=[int]$v.$key};$r.schemas=@($rows.ToArray());return $r
}
function Test-NativeNDISCatalogEvidence([object]$Evidence) {
    return ($null -ne $Evidence -and $Evidence.code -ceq 'complete' -and $Evidence.providerVerified -and $Evidence.definitions -gt 0 -and $Evidence.recognizedDefinitions -gt 0 -and $Evidence.fragmentRecords -gt 0 -and $Evidence.unknownRecords -eq 0 -and $Evidence.missingProviderIDs -eq 0 -and $Evidence.unrecognizedVersions -eq 0)
}
function Get-NativeNDISCatalogProgram([string]$Path) {
    $prefix=''
    $prefix='function Get-NativeNDISTemplateSignature {'+${function:Get-NativeNDISTemplateSignature}.ToString()+"}`n"+'function Get-NativeNDISCatalogClass {'+${function:Get-NativeNDISCatalogClass}.ToString()+"}`n"+'function New-NativeNDISCatalogEvidence {'+${function:New-NativeNDISCatalogEvidence}.ToString()+"}`n"+'function Add-NativeNDISCatalogHeader {'+${function:Add-NativeNDISCatalogHeader}.ToString()+"}`n"
    $prefix+='function Get-NativeNDISTemplateShape {'+${function:Get-NativeNDISTemplateShape}.ToString()+"}`n"
    $prefix+='function Get-NativeNDISTemplateKind {'+${function:Get-NativeNDISTemplateKind}.ToString()+"}`n"
    $prefix+='function Add-NativeNDISTemplateTreeNode {'+${function:Add-NativeNDISTemplateTreeNode}.ToString()+"}`n"+'function Get-NativeNDISTemplateTree {'+${function:Get-NativeNDISTemplateTree}.ToString()+"}`n"
    $body=@'
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$PSModuleAutoLoadingPreference='None'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
$reader=$null;$provider=$null;$r=New-NativeNDISCatalogEvidence 'unavailable'
try{
    $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATH__'))
    $provider=[Diagnostics.Eventing.Reader.ProviderMetadata]::new('Microsoft-Windows-NDIS-PacketCapture')
    if($provider.Id -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef'){throw 'NDIS catalog provider'}
    $catalog=@{};$shapes=@{};$unmatched=@{};$r=New-NativeNDISCatalogEvidence 'complete';$clock=[Diagnostics.Stopwatch]::StartNew()
    foreach($definition in $provider.Events){
        if($r.definitions -ge 64 -or $clock.Elapsed.TotalSeconds -ge 3){$r.code='bound';break}
        $id=[long]$definition.Id;$version=[int]$definition.Version;if($id -lt 0 -or $id -gt 65535 -or $version -lt 0 -or $version -gt 255){throw 'NDIS catalog definition'}
        $key=([string]$id)+':'+([string]$version);if($catalog.ContainsKey($key)){throw 'NDIS catalog duplicate'}
        $kind=Get-NativeNDISCatalogClass ([int]$id) $version ([int]$definition.Level.Value) $definition.Template
        $shape=@(Get-NativeNDISTemplateShape $definition.Template);$task=[string]$definition.Task.Name;$opcode=[string]$definition.Opcode.Name
        foreach($name in @($task,$opcode)){if($name -and $name -cnotmatch '^[A-Za-z][A-Za-z0-9_.:-]{0,63}$'){throw 'NDIS static symbol shape'}}
        $shapes[$key]=@{id=[int]$id;version=$version;level=[int]$definition.Level.Value;records=0;code=$(if($shape.Count -gt 0){'projected'}else{'unsupported'});fields=$shape;task=$task;opcode=$opcode;templateKind=(Get-NativeNDISTemplateKind $definition.Template);tree=@(Get-NativeNDISTemplateTree $definition.Template)}
        $catalog[$key]=$kind;$r.definitions++;if($kind -cne 'unknown'){$r.recognizedDefinitions++}
    }
    if($r.code -cne 'complete'){throw 'NDIS catalog bound'}
    $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($path,[Diagnostics.Eventing.Reader.PathType]::FilePath);$query.ReverseDirection=$false;$query.TolerateQueryErrors=$false
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=16;$clock.Restart()
    while($true){if($r.records -ge 4096 -or $clock.Elapsed.TotalSeconds -ge 3){$r.code='bound';break};$record=$reader.ReadEvent([TimeSpan]::FromMilliseconds(250));if($null -eq $record){break};try{
        $beforeUnknown=$r.unknownRecords;Add-NativeNDISCatalogHeader $r $catalog $record.ProviderId $record.Id $record.Version
        if($r.unknownRecords -gt $beforeUnknown){
            $version=if($null -eq $record.Version){-1}else{[int]$record.Version};$key=([string]$record.Id)+':'+([string]$version)
            if(-not $unmatched.ContainsKey($key)){
                if($unmatched.Count -ge 16){throw 'NDIS schema projection bound'}
                $unmatched[$key]=if($shapes.ContainsKey($key)){$shapes[$key]}else{@{id=$record.Id;version=$version;level=-1;records=0;code='missing';fields=@();task='';opcode='';templateKind='missing';tree=@()}}
            };$unmatched[$key].records++
        }
    }finally{$record.Dispose()}}
    $r.schemas=@($unmatched.Values)
}catch{$r=New-NativeNDISCatalogEvidence 'unavailable'}finally{if($null -ne $reader){$reader.Dispose()};if($null -ne $provider){$provider.Dispose()}}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Depth 5 -Compress))
'@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prefix+$body.Replace('__PATH__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Path)))))
}


function Get-NativeNDISTemplateShape([string]$Template) {
    $reader=$null;$stream=$null
    try{
        if(-not $Template -or $Template.Length -gt 8192){return @()}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=8192
        $stream=[IO.StringReader]::new($Template);$reader=[Xml.XmlReader]::Create($stream,$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $root=$doc.DocumentElement;$ns='http://schemas.microsoft.com/win/2004/08/events';if($root.LocalName -cne 'template' -or $root.NamespaceURI -cne $ns){return @()}
        $parts=[Collections.Generic.List[string]]::new()
        foreach($node in $root.ChildNodes){
            if($node.NodeType -eq [Xml.XmlNodeType]::Whitespace -or $node.NodeType -eq [Xml.XmlNodeType]::SignificantWhitespace){continue}
            if($node.NodeType -ne [Xml.XmlNodeType]::Element -or $node.LocalName -cne 'data' -or $node.NamespaceURI -cne $ns -or $node.HasChildNodes -or $parts.Count -ge 12){return @()}
            foreach($attribute in $node.Attributes){if($attribute.Name -cnotin @('name','inType','outType','map','length','count')){return @()}}
            $name=$node.GetAttribute('name');$type=$node.GetAttribute('inType');$length=$node.GetAttribute('length');$count=$node.GetAttribute('count')
            if($name -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,47}$' -or $type -cnotin @('win:UInt8','win:UInt16','win:UInt32','win:UInt64','win:Int8','win:Int16','win:Int32','win:Int64','win:HexInt32','win:HexInt64','win:UnicodeString','win:AnsiString','win:Binary','win:Boolean','win:GUID','win:Pointer','win:FILETIME','win:SYSTEMTIME','win:SID','win:SizeT')){return @()}
            foreach($value in @($length,$count)){if($value -and $value -cnotmatch '^([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})$'){return @()}}
            $parts.Add($name+':'+$type+':'+$length+':'+$count)
        }
        return $parts.ToArray()
    }catch{return @()}finally{if($null -ne $reader){$reader.Dispose()};if($null -ne $stream){$stream.Dispose()}}
}


function Get-NativeNDISTemplateKind([string]$Template) {
    if(-not $Template){return 'empty'}
    $reader=$null;$stream=$null
    try{
        if($Template.Length -gt 8192){return 'unsupported'}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=8192
        $stream=[IO.StringReader]::new($Template);$reader=[Xml.XmlReader]::Create($stream,$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $root=$doc.DocumentElement;$ns='http://schemas.microsoft.com/win/2004/08/events';if($root.LocalName -cne 'template' -or $root.NamespaceURI -cne $ns){return 'unsupported'}
        if($root.ChildNodes.Count -eq 0){return 'empty'}
        $kind='data';foreach($node in $root.ChildNodes){if($node.NodeType -ne [Xml.XmlNodeType]::Element -or $node.NamespaceURI -cne $ns -or $node.LocalName -cnotin @('data','struct')){return 'unsupported'};if($node.LocalName -ceq 'struct'){$kind='structured'}};return $kind
    }catch{return 'unsupported'}finally{if($null -ne $reader){$reader.Dispose()};if($null -ne $stream){$stream.Dispose()}}
}
# Keep Windows command lines short; the attested catalog program is built in the child.
function Get-NativeNDISCatalogLoader([string]$Path,[string]$HelperPath) {
    $body=@'
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$PSModuleAutoLoadingPreference='None'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
. ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__HELPER__')))
$program=Get-NativeNDISCatalogProgram ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATH__')))
& ([scriptblock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($program))))
'@
    $body=$body.Replace('__HELPER__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($HelperPath))).Replace('__PATH__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Path)))
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
}


# Definition structure only. No captured property values or rendered XML are read.
function Add-NativeNDISTemplateTreeNode([object]$Node,[object]$Tokens,[int]$Depth) {
    if($Depth -gt 3 -or $Tokens.Count -ge 48 -or $Node.NodeType -ne [Xml.XmlNodeType]::Element -or $Node.NamespaceURI -cne 'http://schemas.microsoft.com/win/2004/08/events' -or $Node.LocalName -cnotin @('data','struct')){throw 'NDIS template tree bound'}
    $name=$Node.GetAttribute('name');$length=$Node.GetAttribute('length');$count=$Node.GetAttribute('count')
    if($name -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,47}$'){throw 'NDIS template tree name'}
    foreach($value in @($length,$count)){if($value -and $value -cnotmatch '^([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})$'){throw 'NDIS template tree count'}}
    if($Node.LocalName -ceq 'struct'){
        foreach($attribute in $Node.Attributes){if($attribute.Name -cnotin @('name','length','count')){throw 'NDIS template tree attribute'}}
        if($Depth -ge 3 -or $Node.ChildNodes.Count -eq 0){throw 'NDIS template tree structure'}
        $Tokens.Add('S:'+ $name+':'+$length+':'+$count)
        foreach($child in $Node.ChildNodes){Add-NativeNDISTemplateTreeNode $child $Tokens ($Depth+1)}
        if($Tokens.Count -ge 48){throw 'NDIS template tree bound'};$Tokens.Add('E:'+$name);return
    }
    foreach($attribute in $Node.Attributes){if($attribute.Name -cnotin @('name','inType','outType','map','length','count')){throw 'NDIS template tree attribute'}}
    $type=$Node.GetAttribute('inType')
    if($Node.HasChildNodes -or $type -cnotin @('win:UInt8','win:UInt16','win:UInt32','win:UInt64','win:Int8','win:Int16','win:Int32','win:Int64','win:HexInt32','win:HexInt64','win:UnicodeString','win:AnsiString','win:Binary','win:Boolean','win:GUID','win:Pointer','win:FILETIME','win:SYSTEMTIME','win:SID','win:SizeT')){throw 'NDIS template tree data'}
    $Tokens.Add('D:'+$name+':'+$type+':'+$length+':'+$count)
}
function Get-NativeNDISTemplateTree([string]$Template) {
    $reader=$null;$stream=$null
    try{
        if(-not $Template -or $Template.Length -gt 8192){return @()}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=8192
        $stream=[IO.StringReader]::new($Template);$reader=[Xml.XmlReader]::Create($stream,$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $root=$doc.DocumentElement;if($root.LocalName -cne 'template' -or $root.NamespaceURI -cne 'http://schemas.microsoft.com/win/2004/08/events'){return @()}
        $parts=[Collections.Generic.List[string]]::new();foreach($node in $root.ChildNodes){Add-NativeNDISTemplateTreeNode $node $parts 0};return $parts.ToArray()
    }catch{return @()}finally{if($null -ne $reader){$reader.Dispose()};if($null -ne $stream){$stream.Dispose()}}
}
function Test-NativeNDISTemplateTree([object]$Tree) {
    if($Tree -isnot [array] -or $Tree.Count -gt 48){return $false};$stack=[Collections.Generic.Stack[string]]::new()
    foreach($token in $Tree){
        if($token -isnot [string]){return $false}
        if($token -cmatch '^S:([A-Za-z][A-Za-z0-9_]{0,47}):([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})?:([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})?$'){
            if($stack.Count -ge 3){return $false};$stack.Push($Matches[1]);continue
        }
        if($token -cmatch '^E:([A-Za-z][A-Za-z0-9_]{0,47})$'){if($stack.Count -eq 0 -or $stack.Pop() -cne $Matches[1]){return $false};continue}
        if($token -cnotmatch '^D:[A-Za-z][A-Za-z0-9_]{0,47}:win:(UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64|HexInt32|HexInt64|UnicodeString|AnsiString|Binary|Boolean|GUID|Pointer|FILETIME|SYSTEMTIME|SID|SizeT):([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})?:([A-Za-z][A-Za-z0-9_]{0,47}|[0-9]{1,5})?$'){return $false}
    };return ($stack.Count -eq 0)
}


# Private projection only: never include this object in a published report.
function ConvertTo-NativeNDISPrivateRecord([object]$Provider,[object]$ID,[object]$Version,[object]$Keywords,[object]$Values,[bool]$Modern) {
    if($Provider -isnot [guid] -or $Provider -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef' -or $ID -isnot [int] -or $ID -ne 1001 -or $Version -isnot [byte] -or $Version -ne 0 -or $Keywords -isnot [long]){throw 'NDIS private record identity'}
    if(($Keywords -band 3221225472) -ne 3221225472 -or ($Keywords -band 66048) -ne 0 -or ($Keywords -band 12884901888) -notin @(4294967296,8589934592)){throw 'NDIS private record keywords'}
    $count=if($Modern){4}else{2}
    if($Values -isnot [Collections.IList] -or $Values.Count -ne $count -or $Values[0] -isnot [uint32] -or $Values[1] -isnot [byte[]] -or $Values[0] -lt 14 -or $Values[0] -gt 65535 -or $Values[1].Length -ne $Values[0]){throw 'NDIS private record values'}
    $r=@{provider='2ed6006e-4729-4609-b423-3ee7bcd678ef';id=1001;version=0;keywords=$Keywords.ToString([Globalization.CultureInfo]::InvariantCulture);fragmentSize=[int]$Values[0];fragment=[Convert]::ToBase64String($Values[1])}
    if($Modern){if($Values[2] -isnot [uint64] -or $Values[3] -isnot [uint64]){throw 'NDIS private record values'};if($Values[2] -ne 0 -or $Values[3] -ne 0){throw 'NDIS private record offload'};$r.gftFlowEntryId=$Values[2].ToString([Globalization.CultureInfo]::InvariantCulture);$r.gftOffloadInformation=$Values[3].ToString([Globalization.CultureInfo]::InvariantCulture)}
    return $r
}
function New-NativeNDISExtractionEvidence([string]$Code='not-inspected') {return @{code=$Code;records=0;frames=0;bytesWritten=0;payloadRead=$false}}
function Get-NativeNDISExtractionEvidence([string]$Text) {
    $bad=New-NativeNDISExtractionEvidence 'invalid';if($Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 5 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin @('code','records','frames','bytesWritten','payloadRead')}).Count -ne 0 -or $v.code -cnotin @('none','environment','path','source-schema','read','record','offload','bound','output') -or $v.payloadRead -isnot [bool]){return $bad}
    foreach($key in @('records','frames','bytesWritten')){if(($v.$key -isnot [int] -and $v.$key -isnot [long]) -or $v.$key -lt 0){return $bad}}
    if($v.records -gt 4096 -or $v.frames -gt $v.records -or $v.bytesWritten -gt 16777216 -or ($v.code -ceq 'none' -and ($v.frames -le 0 -or $v.bytesWritten -le 0 -or -not $v.payloadRead))){return $bad}
    return @{code=$v.code;records=[int]$v.records;frames=[int]$v.frames;bytesWritten=[int]$v.bytesWritten;payloadRead=$v.payloadRead}
}
function New-NativeNDISConversionEvidence {return @{schemaVersion=1;outcome='not-inspected';code='not-inspected';nativeFrameDataRead=$false;summary=$null}}
function Get-NativeNDISTcpClosureEvidence([object]$Value,[object]$Summary) {
    $v=$Value;$keys=@('flows','sentFin','receivedFin','sentReset','receivedReset','beforeFin','afterSentFin','afterReceivedFin','afterBothFin','resetFlows','resetFlowsWithPayloadBoth')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 13 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin (@('schemaVersion','productionQualificationComplete')+$keys)}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.productionQualificationComplete -isnot [bool] -or $v.productionQualificationComplete){return $null}
    foreach($key in $keys){if(($v.$key -isnot [int] -and $v.$key -isnot [long]) -or $v.$key -lt 0 -or $v.$key -gt 4096){return $null}}
    $resets=$v.sentReset+$v.receivedReset
    if($resets -ne $v.beforeFin+$v.afterSentFin+$v.afterReceivedFin+$v.afterBothFin -or $resets -gt $Summary.tcp -or $v.flows -gt $Summary.tcp -or (($v.flows -eq 0) -ne ($Summary.tcp -eq 0)) -or $v.sentFin -gt $Summary.sent -or $v.receivedFin -gt $Summary.received -or $v.sentFin+$v.receivedFin -gt $Summary.tcp -or $v.sentReset -gt $Summary.sent -or $v.receivedReset -gt $Summary.received -or $v.resetFlows -gt $v.flows -or $v.resetFlows -gt $resets -or (($v.resetFlows -eq 0) -ne ($resets -eq 0)) -or $v.resetFlowsWithPayloadBoth -gt $v.resetFlows){return $null}
    $r=@{schemaVersion=1;productionQualificationComplete=$false};foreach($key in $keys){$r[$key]=[int]$v.$key};return $r
}
function Get-NativeNDISConversionEvidence([string]$Text) {
    $bad=New-NativeNDISConversionEvidence;$bad.outcome='refused';$bad.code='invalid';if($Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 5 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin @('schemaVersion','outcome','code','nativeFrameDataRead','summary')}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.outcome -cnotin @('converted','refused') -or $v.nativeFrameDataRead -isnot [bool]){return $bad}
    $codes=@('none','environment','private-path','private-file','private-document','private-record','private-encoding','conversion-unavailable','record-shape','fragment-identity','fragment-keywords','fragment-boundaries','fragment-media','fragment-direction','fragment-offload-type','fragment-offload','fragment-length','ethernet-vlan','ethernet-type','ipv4-header','ipv4-length','ipv4-header-length','ipv4-zero-length','ipv4-short-length','ipv4-truncated','ipv6-header','ipv6-length','ip-fragment','frame-length','ipv6-extension','tcp-header','udp-length','transport-type','record-bound','capture-bound')
    if($v.code -cnotin $codes){return $bad}
    if($v.outcome -ceq 'refused'){if($v.code -ceq 'none' -or $null -ne $v.summary){return $bad};return @{schemaVersion=1;outcome='refused';code=$v.code;nativeFrameDataRead=$v.nativeFrameDataRead;summary=$null}}
    $q=$v.summary;$keys=@('frames','ipv4','ipv6','tcp','udp','sent','received','captureBytes')
    if($v.code -cne 'none' -or -not $v.nativeFrameDataRead -or $q -isnot [pscustomobject] -or @($q.PSObject.Properties).Count -ne 11 -or $null -eq $q.PSObject.Properties['tcpClosure'] -or $q.schemaVersion -isnot [int] -or $q.schemaVersion -ne 1 -or $q.productionQualificationComplete -isnot [bool] -or $q.productionQualificationComplete){return $bad}
    foreach($key in $keys){if($null -eq $q.PSObject.Properties[$key] -or ($q.$key -isnot [int] -and $q.$key -isnot [long]) -or $q.$key -lt 0 -or $q.$key -gt 16777216){return $bad}}
    if($q.frames -le 0 -or $q.frames -gt 4096 -or $q.frames -ne $q.ipv4+$q.ipv6 -or $q.frames -ne $q.tcp+$q.udp -or $q.frames -ne $q.sent+$q.received -or $q.captureBytes -le 48){return $bad}
    $closure=Get-NativeNDISTcpClosureEvidence $q.tcpClosure $q;if($null -eq $closure){return $bad}
    $summary=@{schemaVersion=1;productionQualificationComplete=$false;tcpClosure=$closure};foreach($key in $keys){$summary[$key]=[int]$q.$key}
    return @{schemaVersion=1;outcome='converted';code='none';nativeFrameDataRead=$true;summary=$summary}
}


function New-NativeNDISTlsStimulusEvidence {return @{schemaVersion=1;outcome='not-inspected';code='not-inspected';tlsAuthorized=$false;responseValidated=$false;closed=$false;productionQualificationComplete=$false}}
function Get-NativeNDISTlsStimulusEvidence([string]$Text) {
    $bad=New-NativeNDISTlsStimulusEvidence;$bad.outcome='failed';$bad.code='invalid';if($Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 7 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin @('schemaVersion','outcome','code','tlsAuthorized','responseValidated','closed','productionQualificationComplete')}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.outcome -cnotin @('passed','failed') -or $v.code -cnotin @('none','environment','tls','network','response','bound','timeout','close')){return $bad}
    foreach($key in @('tlsAuthorized','responseValidated','closed','productionQualificationComplete')){if($v.$key -isnot [bool]){return $bad}}
    if($v.productionQualificationComplete -or ($v.outcome -ceq 'passed' -and ($v.code -cne 'none' -or -not $v.tlsAuthorized -or -not $v.responseValidated -or -not $v.closed)) -or ($v.outcome -ceq 'failed' -and $v.code -ceq 'none')){return $bad}
    return @{schemaVersion=1;outcome=$v.outcome;code=$v.code;tlsAuthorized=$v.tlsAuthorized;responseValidated=$v.responseValidated;closed=$v.closed;productionQualificationComplete=$false}
}
function New-NativeNDISTlsWireEvidence([string]$Code='not-inspected') {return @{code=$Code;observation='not-inspected';packets=0;tlsFlows=0;outboundEncryptedRecords=0;inboundEncryptedRecords=0;providerMask=0}}
function Get-NativeNDISTlsWireEvidence([string]$Text) {
    $bad=New-NativeNDISTlsWireEvidence 'invalid';$bad.observation='refused';if($Text.Length -gt 16384){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $codes=@('ascii','block-bound','block-shape','capture-bound','capture-drops','capture-empty','capture-options','client-hello','client-sni','decoder-failed','environment','ethernet-protocol','ethernet-shape','flow-bound','input-bound','input-incomplete','input-read','interface-bound','interface-link','interface-snaplen','ip-fragment','ipv4-bound','ipv4-shape','ipv6-bound','ipv6-extension','ipv6-shape','none','packet-bound','packet-kind','packet-shape','packet-snaplen','packet-truncated','provider-port','provider-scope','section-length','section-magic','section-required','section-shape','section-version','server-hello','statistics-shape','tcp-bound','tcp-gap','tcp-overlap','tcp-reset','tcp-reuse','tcp-segment-bound','tcp-shape','tcp-stream-bound','tcp-syn-required','tcp-syn-shape','tls-change-cipher','tls-handshake-bound','tls-hello-required','tls-record','tls-truncated','transport-shape','udp-shape')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 4 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin @('schemaVersion','outcome','code','evidence')}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.code -cnotin $codes -or $v.outcome -cnotin @('decoded','refused')){return $bad}
    if($v.outcome -ceq 'refused'){if($v.code -ceq 'none' -or $null -ne $v.evidence){return $bad};$r=New-NativeNDISTlsWireEvidence $v.code;$r.observation='refused';return $r}
    $e=$v.evidence
    if($v.code -cne 'none' -or $e -isnot [pscustomobject] -or @($e.PSObject.Properties).Count -ne 9 -or @($e.PSObject.Properties.Name | Where-Object {$_ -cnotin @('schemaVersion','observation','packets','plaintextPackets','flows','dnsPayloadDecrypted','ordinaryResolverBound','negativeControlPassed','productionQualificationComplete')}).Count -ne 0 -or $e.schemaVersion -isnot [int] -or $e.schemaVersion -ne 1 -or $e.observation -cnotin @('tls-observed','insufficient') -or $e.packets -isnot [int] -or $e.packets -lt 1 -or $e.packets -gt 4096 -or $e.plaintextPackets -isnot [int] -or $e.plaintextPackets -ne 0 -or $e.flows -isnot [array] -or $e.flows.Count -gt 32){return $bad}
    foreach($key in @('dnsPayloadDecrypted','ordinaryResolverBound','negativeControlPassed','productionQualificationComplete')){if($e.$key -isnot [bool] -or $e.$key){return $bad}}
    $r=New-NativeNDISTlsWireEvidence 'none';$r.observation=$e.observation;$r.packets=$e.packets;$positive=$false
    foreach($flow in $e.flows){
        if($flow -isnot [pscustomobject] -or @($flow.PSObject.Properties).Count -ne 6 -or @($flow.PSObject.Properties.Name | Where-Object {$_ -cnotin @('provider','clientHello','serverHello','outboundEncryptedRecords','inboundEncryptedRecords','records')}).Count -ne 0 -or $flow.provider -cne 'google-v4' -or $flow.clientHello -isnot [bool] -or -not $flow.clientHello -or $flow.serverHello -isnot [bool] -or -not $flow.serverHello){return $bad}
        foreach($key in @('outboundEncryptedRecords','inboundEncryptedRecords','records')){if(($flow.$key -isnot [int] -and $flow.$key -isnot [long]) -or $flow.$key -lt 0 -or $flow.$key -gt 4194304){return $bad}}
        if($flow.records -lt $flow.outboundEncryptedRecords+$flow.inboundEncryptedRecords+2){return $bad}
        $r.tlsFlows++;$r.providerMask=1;$r.outboundEncryptedRecords+=$flow.outboundEncryptedRecords;$r.inboundEncryptedRecords+=$flow.inboundEncryptedRecords;if($flow.outboundEncryptedRecords -gt 0 -and $flow.inboundEncryptedRecords -gt 0){$positive=$true}
    }
    if(($e.observation -ceq 'tls-observed') -ne $positive){return $bad};return $r
}
