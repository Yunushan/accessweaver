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
function Assert-NativeNetEventProvider([object]$Row,[object]$Plan,[string]$Guid,[object]$Enums) {
    $script:netEventStage='provider-readback';$values=@{}
    foreach($key in @('Guid','SessionGuid','SessionName','Level','CaptureType','MultiLayer','TruncationLength','MatchAnyKeyword','MatchAllKeyword','IPAddresses','IPProtocols','EtherType','LinkLayerAddress')){$values[$key]=Get-NativeNetEventValue $Row $key}
    $provider=[guid]::Empty;$session=[guid]::Empty
    if(-not [guid]::TryParse([string]$values.Guid,[ref]$provider) -or $provider -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef' -or -not [guid]::TryParse([string]$values.SessionGuid,[ref]$session) -or $session -ne [guid]$Guid -or $values.SessionName -cne $Plan.name){throw 'NetEvent provider'}
    foreach($key in @('Level','CaptureType','TruncationLength','MatchAnyKeyword','MatchAllKeyword')){if($null -eq $values[$key] -or $values[$key] -is [bool]){throw 'NetEvent filters'}}
    if([int]$values.Level -ne 5 -or [int]$values.CaptureType -ne $Enums.capture -or $values.MultiLayer -isnot [bool] -or $values.MultiLayer -or [int]$values.TruncationLength -ne 65535 -or [System.UInt64]$values.MatchAnyKeyword -ne [System.UInt64]::MaxValue -or [System.UInt64]$values.MatchAllKeyword -ne 0){throw 'NetEvent filters'}
    if(@($values.IPAddresses).Count -ne 1 -or [string]$values.IPAddresses[0] -cne '8.8.8.8' -or @($values.IPProtocols).Count -ne 1 -or [int]$values.IPProtocols[0] -ne 6 -or @($values.EtherType).Count -ne 1 -or [int]$values.EtherType[0] -ne 2048 -or @($values.LinkLayerAddress | Where-Object {$_}).Count -ne 0){throw 'NetEvent filters'}
}
function Invoke-NativeNetEventOperation([string]$Operation,[object]$Plan) {
    if($Operation -cnotin @('preflight','create','provider','start','stop','remove') -or $Plan.name -cnotmatch '^awndis-[a-f0-9]{32}$' -or $Plan.file -isnot [string] -or -not [IO.Path]::IsPathRooted($Plan.file) -or [IO.Path]::GetFileName($Plan.file) -cne 'capture.etl' -or $Plan.originalVerified -isnot [bool]){throw 'NetEvent plan'}
    if($Plan.guid -and ([string]$Plan.guid -cnotmatch '^[a-f0-9-]{36}$')){throw 'NetEvent plan'}
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
        [void](Add-NetEventPacketCaptureProvider -SessionName $Plan.name -CaptureType Physical -MultiLayer $false -EtherType ([uint16[]]@(2048)) -IpAddresses @('8.8.8.8') -IpProtocols ([byte[]]@(6)) -TruncationLength 65535 -Level 5 -MatchAnyKeyword ([System.UInt64]::MaxValue) -MatchAllKeyword ([System.UInt64]0) -ErrorAction Stop)
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
