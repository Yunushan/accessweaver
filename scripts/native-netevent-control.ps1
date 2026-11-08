# Definitions only. Native calls execute solely through guarded bounded children.
function Get-NativeNetEventEnums {
    $result=@{}
    foreach($spec in @(@{key='mode';command='New-NetEventSession';parameter='CaptureMode';value='SaveToFile'},@{key='capture';command='Add-NetEventPacketCaptureProvider';parameter='CaptureType';value='Physical'})){
        $type=(Get-Command $spec.command -ErrorAction Stop).Parameters[$spec.parameter].ParameterType
        if(-not $type.IsEnum -or -not [Enum]::IsDefined($type,$spec.value)){throw 'NetEvent enum'}
        $result[$spec.key]=[int][Enum]::Parse($type,$spec.value)
    };return $result
}
function Get-NativeNetEventInventory {
    $s=@();$p=@()
    try{$s=@(Get-NetEventSession -ErrorAction Stop | Select-Object -First 2)}catch{if($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound){throw}}
    try{$p=@(Get-NetEventPacketCaptureProvider -ErrorAction Stop | Select-Object -First 2)}catch{if($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound){throw}}
    return @{sessions=$s;providers=$p}
}
function Assert-NativeNetEventSession([object]$Row,[object]$Plan,[object]$Enums) {
    $guid=[guid]::Empty
    if($Row.Name -isnot [string] -or $Row.Name -cne $Plan.name -or $Row.Guid -isnot [string] -or -not [guid]::TryParse($Row.Guid,[ref]$guid) -or $guid -eq [guid]::Empty){throw 'NetEvent session'}
    if($Plan.guid -and $guid -ne [guid]$Plan.guid){throw 'NetEvent identity'}
    if($Row.LocalFilePath -isnot [string] -or -not [IO.Path]::GetFullPath($Row.LocalFilePath).Equals($Plan.file,[StringComparison]::OrdinalIgnoreCase) -or $Row.MaxFileSize -is [bool] -or [long]$Row.MaxFileSize -ne 16 -or $null -eq $Row.CaptureMode -or $Row.CaptureMode -is [bool] -or [int]$Row.CaptureMode -ne $Enums.mode){throw 'NetEvent configuration'}
    return $guid.ToString('D')
}
function Get-NativeNetEventState([object]$Row) {
    $name=[string]$Row.SessionStatus
    if($name -ceq 'Running'){return 'running'}
    if($name -cin @('NotRunning','Stopped')){return 'stopped'}
    return 'unknown'
}
function Assert-NativeNetEventProvider([object]$Row,[object]$Plan,[string]$Guid,[object]$Enums) {
    $provider=[guid]::Empty;$session=[guid]::Empty
    if(-not [guid]::TryParse([string]$Row.Guid,[ref]$provider) -or $provider -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef' -or -not [guid]::TryParse([string]$Row.SessionGuid,[ref]$session) -or $session -ne [guid]$Guid -or $Row.SessionName -cne $Plan.name){throw 'NetEvent provider'}
    foreach($key in @('Level','CaptureType','TruncationLength','MatchAnyKeyword','MatchAllKeyword')){if($null -eq $Row.$key -or $Row.$key -is [bool]){throw 'NetEvent filters'}}
    if([int]$Row.Level -ne 5 -or [int]$Row.CaptureType -ne $Enums.capture -or $Row.MultiLayer -isnot [bool] -or $Row.MultiLayer -or [int]$Row.TruncationLength -ne 65535 -or [System.UInt64]$Row.MatchAnyKeyword -ne [System.UInt64]::MaxValue -or [System.UInt64]$Row.MatchAllKeyword -ne 0){throw 'NetEvent filters'}
    if(@($Row.IPAddresses).Count -ne 1 -or [string]$Row.IPAddresses[0] -cne '8.8.8.8' -or @($Row.IPProtocols).Count -ne 1 -or [int]$Row.IPProtocols[0] -ne 6 -or @($Row.EtherType).Count -ne 1 -or [int]$Row.EtherType[0] -ne 2048 -or @($Row.LinkLayerAddress | Where-Object {$_}).Count -ne 0){throw 'NetEvent filters'}
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
        [void](Add-NetEventPacketCaptureProvider -SessionName $Plan.name -CaptureType Physical -MultiLayer $false -EtherType ([uint16[]]@(2048)) -IpAddresses @('8.8.8.8') -IpProtocols ([byte[]]@(6)) -TruncationLength 65535 -Level 5 -MatchAnyKeyword ([System.UInt64]::MaxValue) -MatchAllKeyword ([System.UInt64]0) -ErrorAction Stop)
    }elseif($Operation -ceq 'start'){
        if($r.state -cne 'stopped' -or -not $r.providerVerified){throw 'NetEvent state'}
        [void](Start-NetEventSession -InputObject $row -ErrorAction Stop)
    }elseif($Operation -ceq 'stop'){
        if($r.state -ceq 'running'){[void](Stop-NetEventSession -InputObject $row -ErrorAction Stop)}
    }elseif($Operation -ceq 'remove'){
        if(-not $Plan.originalVerified){throw 'NetEvent original'}
        if($r.state -cne 'stopped'){throw 'NetEvent state'}
        # The documented removal deletes associated objects. Reject any
        # unrecognized packet provider before acting on the exact CIM session.
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
