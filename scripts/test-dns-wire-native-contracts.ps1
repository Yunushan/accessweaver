# Hosted actual-source contracts. All native boundaries are replaced before evaluation.
[CmdletBinding()]param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Set-StrictMode -Version Latest
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Management','Microsoft.PowerShell.Management.psd1')) -ErrorAction Stop
$PSModuleAutoLoadingPreference='None'
$project=Split-Path -Parent $PSScriptRoot;$path=Join-Path $PSScriptRoot 'native-dns-wire.ps1'
$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Wire source syntax'}
$excluded=@('Invoke-NativeDNSWireProcess','Read-NativeDNSWireCapture','Read-NativeDNSWireStatsInput','Get-NativeDNSWireItem')
$allowed=@('New-NativeDNSWireEventEvidence','Add-NativeDNSWireEventHeader','Get-NativeDNSWireEventProgram','Get-NativeDNSWireEventEvidence','Read-NativeDNSWireStatsInput','Get-NativeDNSWireStatsEvidence','Get-NativeDNSWireMonitorEvidence','Get-NativeDNSWireCounterEvidence','New-NativeDNSWireProbeBytes','Wait-NativeDNSWireWrite','Get-NativeDNSWireSetupCode','Assert-NativeOrdinaryPath','Get-Command','Join-Path','Where-Object','Select-Object','Invoke-NativeDNSWireProcess','Invoke-NativeDNSWireTool','Assert-NativeDNSWireStopped','Assert-NativeDNSWireEmptyFilters','Get-NativeDNSWireFilterRows','Assert-NativeDNSWireFilters','Get-NetFirewallProfile','Get-Service','Get-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Assert-NativeDNSWireRule','New-NetFirewallRule','Remove-NetFirewallRule','Assert-NativeDNSWireFirewall','Get-DnsClientNrptPolicy','Add-NativeDNSWireRule','Remove-NativeDNSWireRules','Stop-NativeDNSWireCapture','Clear-DnsClientCache','Resolve-DnsName','Invoke-NativeDNSWireQuery','Read-NativeDNSWireCapture','Measure-NativeDNSWireFile','Get-NativeDNSWireItem','ConvertFrom-Json','Assert-DNSAcceptanceRestored','Read-DNSAcceptanceState')
$definitions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false));$seen=@{}
foreach($definition in $definitions){
    if($seen.ContainsKey($definition.Name)){throw 'Duplicate wire source function'};$seen[$definition.Name]=$true
    if($definition.Name -cin $excluded){continue}
    foreach($command in $definition.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($command.GetCommandName() -cnotin $allowed){throw 'Wire source command boundary'}}
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Assert-NativeOrdinaryPath([string]$Path) {}
function Get-Command {param($Name,$CommandType,$ErrorAction);if($Name -cne 'node'){throw 'Source command refused'};return @([pscustomobject]@{Path='node-source';Source='source-is-not-an-application-path'},[pscustomobject]@{Path='node-other';Source='other-source'})}
function Assert-Wire([bool]$Condition){if(-not $Condition){throw 'Wire source assertion'}}
function New-WireCase {
    $script:fault='';$script:filters=@{};$script:rules=@{};$script:running=$false;$script:restored=$true;$script:events=[Collections.Generic.List[string]]::new();$script:addOrdinal=0;$script:counterReads=0;$script:etlSize=4096;$script:pcapSize=3;$script:itemReads=0
    $script:state=New-NativeDNSWireState ([IO.Path]::Combine([IO.Path]::GetTempPath(),'aw-wire-source')) ([IO.Path]::Combine([IO.Path]::GetTempPath(),'dns-wire-stdin.cjs'))
    $script:state.before='source-original'
}
function Invoke-NativeDNSWireProcess([object]$State,[string]$Program,[string[]]$Arguments,[byte[]]$InputBytes=$null) {
    $State.processes++;$State.joined++
    if($Program -ceq 'node-source'){
        if($Arguments.Count -eq 1 -and $Arguments[0] -ceq '--version'){return 'v26.8.2'}
        if($null -ne $InputBytes -and $InputBytes.Length -eq 48){
            Assert-Wire (-not $script:running -and $script:filters.Count -eq 0 -and $script:rules.Count -eq 0)
            if($script:fault -ceq 'decoder-preflight'){throw 'Source decoder unavailable'}
            return '{"schemaVersion":1,"outcome":"refused","code":"capture-empty","evidence":null}'
        }
        Assert-Wire ($null -ne $InputBytes -and $InputBytes.Length -eq 3 -and -not $script:running)
        if($script:fault -cin @('decoder-refusal','decoder-refusal-negative-succeeds')){return '{"schemaVersion":1,"outcome":"refused","code":"tcp-gap","evidence":null}'}
        return '{"schemaVersion":1,"outcome":"decoded","code":"none","evidence":{"schemaVersion":1,"observation":"tls-observed","plaintextPackets":0,"productionQualificationComplete":false,"flows":[{"provider":"google-v4","clientHello":true,"serverHello":true,"outboundEncryptedRecords":1,"inboundEncryptedRecords":1}]}}'
    }
    if($Program -ceq $State.eventTool){
        Assert-Wire (-not $script:running -and $State.flags.captureStopped -and $Arguments.Count -eq 4 -and $Arguments[0] -ceq '-NoProfile' -and $Arguments[1] -ceq '-NonInteractive' -and $Arguments[2] -ceq '-EncodedCommand')
        $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Arguments[3]));$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
        Assert-Wire ($e.Count -eq 0 -and $body.Contains([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($State.etl))))
        $r=New-NativeDNSWireEventEvidence 'complete';Add-NativeDNSWireEventHeader $r ([guid]'4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac') 160 0
        return ($r | ConvertTo-Json -Compress)
    }
    Assert-Wire ($Program -ceq $State.tool)
    switch -CaseSensitive ($Arguments[0]){
        'status' {
            if($Arguments.Count -eq 2){Assert-Wire ($script:running -and $State.flags.ordinaryQueryPassed -and $Arguments[1] -ceq '--buffer-info');return ("Logging mode: Circular`nLog file: "+$State.etl+"`nProvider Level Keywords`nMicrosoft-Windows-PktMon 4 0x12")}
            Assert-Wire ($Arguments.Count -eq 1);if($script:running){return 'Packet Monitor is running.'};return 'Packet Monitor is not running.'
        }
        'filter' {
            switch -CaseSensitive ($Arguments[1]){
                'list' {
                    if($script:filters.Count -eq 0){return 'No filters.'}
                    $lines=@('Packet Filters:');$i=0
                    foreach($name in @($script:filters.Keys | Sort-Object)){$i++;$f=$script:filters[$name];$port=if($script:fault -ceq 'filter-port'){853}else{$f.port};$lines+=@(([string]$i)+' '+$name+' '+$f.address+' '+$f.protocol+' '+$port)}
                    return ($lines -join "`n")
                }
                'add' {
                    Assert-Wire ($Arguments.Count -eq 9 -and $Arguments[3] -ceq '-i' -and $Arguments[5] -ceq '-t' -and $Arguments[7] -ceq '-p')
                    Assert-Wire ($Arguments[4] -cin @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe') -and $Arguments[6] -cin @('TCP','UDP') -and $Arguments[8] -cin @('443','53'))
                    $script:filters[$Arguments[2]]=@{address=$Arguments[4];protocol=$Arguments[6];port=$Arguments[8]};$script:addOrdinal++
                    if($script:fault -ceq 'partial-filter' -and $script:addOrdinal -eq 2){throw 'Source partial filter'}
                    return ''
                }
                'remove' {Assert-Wire (-not $script:running -and $Arguments.Count -eq 2);foreach($name in $script:filters.Keys){Assert-Wire (@($State.filters | Where-Object {$_.name -ceq $name}).Count -eq 1)};$script:events.Add('filter-remove');$script:filters.Clear();return ''}
            }
        }
        'start' {
            Assert-Wire ($script:filters.Count -eq 12 -and $State.flags.filtersVerified -and -not $script:running)
            Assert-Wire (($Arguments -join ',').Contains('--capture,--comp,all,--pkt-size,0') -and ($Arguments -join ',').Contains('--file-size,16,--log-mode,circular') -and $Arguments -cnotcontains '--flags')
            $script:running=$true;$script:events.Add('capture-start')
            if($script:fault -ceq 'partial-start'){throw 'Source partial capture start'};return ''
        }
        'counters' {
            Assert-Wire ($script:running -and $State.flags.ordinaryQueryPassed -and $Arguments.Count -cin @(3,5) -and $Arguments[1] -ceq '--json' -and $Arguments[2] -ceq '--zero')
            if($Arguments.Count -eq 5){Assert-Wire ($Arguments[3] -ceq '--type' -and $Arguments[4] -ceq 'flow' -and $script:counterReads -eq 1)}
            else{Assert-Wire ($script:counterReads -eq 0)}
            $script:counterReads++;return '{"Components":[{"Name":"PRIVATE-SYNTHETIC","PacketsIn":2,"PacketsOut":3}]}'
        }
        'stop' {$script:running=$false;$script:events.Add('capture-stop');return ''}
        'etl2txt' {Assert-Wire (-not $script:running -and $State.flags.captureStopped -and $Arguments.Count -eq 5 -and $Arguments[1] -ceq $State.etl -and $Arguments[2] -ceq '--stats-only' -and $Arguments[3] -ceq '--out' -and $Arguments[4] -ceq $State.statsPath);if($script:fault -ceq 'stats-fallback'){return 'PRIVATE-SYNTHETIC-UNRECOGNIZED'};return "Total packets: 10`nTotal events: 20`nEvents lost: 0`nBuffers lost: 0"}
        'etl2pcap' {Assert-Wire (-not $script:running);$script:events.Add('conversion');return ''}
    }
    throw 'Unexpected source tool operation'
}
function Read-NativeDNSWireStatsInput([object]$State,[string]$Stdout){
    Assert-Wire (-not $script:running -and $State.flags.captureStopped)
    return @{source=$(if($script:fault -ceq 'stats-fallback'){'stdout-fallback'}else{'file'});text=$Stdout}
}
function Get-NativeDNSWireItem([string]$Path){
    $script:itemReads++
    Assert-Wire ($Path -ceq $script:state.etl -or $Path -ceq $script:state.pcap)
    if($script:fault -ceq 'file-unavailable'){throw 'Source private file unavailable'}
    return [pscustomobject]@{Length=$(if($Path -ceq $script:state.etl){$script:etlSize}else{$script:pcapSize});PSIsContainer=$false}
}
function Read-NativeDNSWireCapture([object]$State){Assert-Wire (-not $script:running);$State.flags.captureBounded=$true;return ,([byte[]]@(1,2,3))}
function Get-DnsClientNrptPolicy {param([switch]$Effective,$ErrorAction);if($script:fault -ceq 'nrpt'){return [pscustomobject]@{Name='source-policy'}}}
function Get-NetFirewallProfile {param($PolicyStore,$ErrorAction);return [pscustomobject]@{Enabled=$true;AllowLocalFirewallRules=$true;DisabledInterfaceAliases=@()}}
function Get-Service {param($Name,$ErrorAction);Assert-Wire ($Name -ceq 'MpsSvc');return [pscustomobject]@{Status='Running'}}
function Get-NetFirewallRule {param($PolicyStore,$ErrorAction);return @($script:rules.Values)}
function New-NetFirewallRule {
    param($Name,$DisplayName,$Group,$PolicyStore,$Direction,$Action,$Enabled,$Profile,$Protocol,$RemotePort,$RemoteAddress,$ErrorAction)
    Assert-Wire ($PolicyStore -ceq 'PersistentStore' -and $Direction -ceq 'Outbound' -and $Action -ceq 'Block' -and $DisplayName -ceq 'AccessWeaver native DNS wire fixture')
    $script:rules[$Name]=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Group=$Group;Enabled=$true;Action=$Action;Direction=$Direction;Profile=$Profile;Protocol=$Protocol;RemotePort=@([string]$RemotePort);RemoteAddress=@($RemoteAddress)}
    $script:events.Add($(if($RemotePort -eq 53){'dns-block'}else{'tls-block'}))
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
    process {return [pscustomobject]@{Protocol=$InputObject.Protocol;RemotePort=$InputObject.RemotePort}}
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
    process {return [pscustomobject]@{RemoteAddress=$(if($script:fault -ceq 'rule-address'){@('Any')}else{$InputObject.RemoteAddress})}}
}
function Remove-NetFirewallRule {
    param($Name,$PolicyStore,$ErrorAction)
    $script:events.Add('rule-remove');if($script:fault -cne 'remove-noop'){$script:rules.Remove($Name)}
}
function Clear-DnsClientCache {param($ErrorAction);if($script:fault -ceq 'cache-failure'){throw 'Source cache refusal'}}
function Resolve-DnsName {
    param($Name,$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout,$ErrorAction)
    Assert-Wire ($Name -cin @('example.com','example.net','example.org') -and $Type -ceq 'A' -and $DnsOnly -and $NoHostsFile -and $QuickTimeout)
    $blocked=@($script:rules.Values | Where-Object {($_.RemotePort -join ',') -ceq '443'}).Count -gt 0
    if(($blocked -and $script:fault -cnotin @('negative-succeeds','decoder-refusal-negative-succeeds')) -or ($script:fault -ceq 'resumed-fails' -and $script:state.phase -ceq 'resumed-query')){throw 'Source query rejected'}
    $script:events.Add('query');return @([pscustomobject]@{NameHost='source-alias'},[pscustomobject]@{IPAddress='192.0.2.1'})
}
function Read-DNSAcceptanceState {if($script:restored){return 'source-original'};return 'source-changed'}
function Assert-DNSAcceptanceRestored([object]$Before,[object]$After){Assert-Wire ($Before -ceq 'source-original' -and $After -ceq 'source-original');$script:events.Add('original-state')}
$results=[Collections.Generic.List[object]]::new()
function Case-Wire([string]$Name,[scriptblock]$Body){$ok=$true;try{[void](& $Body)}catch{$ok=$false};$results.Add(@{name=$Name;passed=$ok})}
function Reject-Wire([scriptblock]$Body){$rejected=$false;try{[void](& $Body)}catch{$rejected=$true};Assert-Wire $rejected}
$oldSystemRoot=$env:SystemRoot
try {
    if(-not $env:SystemRoot){$env:SystemRoot=[IO.Path]::GetTempPath()}
    Case-Wire 'event-headers-partition-known-unknown-and-other-providers' {
        $r=New-NativeDNSWireEventEvidence 'complete';$p=[guid]'4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac'
        Add-NativeDNSWireEventHeader $r $p 160 0;Add-NativeDNSWireEventHeader $r $p 170 1;Add-NativeDNSWireEventHeader $r $p 20 0;Add-NativeDNSWireEventHeader $r $p 999 $null;Add-NativeDNSWireEventHeader $r ([guid]::Empty) 160 0
        $v=Get-NativeDNSWireEventEvidence ($r | ConvertTo-Json -Compress)
        Assert-Wire ($v.code -ceq 'complete' -and $v.records -eq 5 -and $v.providerRecords -eq 4 -and $v.framePayloadIDs -eq 1 -and $v.frameDropPayloadIDs -eq 1 -and $v.knownMetadataIDs -eq 1 -and $v.unknownProviderIDs -eq 1 -and $v.otherProviderRecords -eq 1 -and $v.unrecognizedVersions -eq 2)
    }
    Case-Wire 'event-header-bound-and-unavailable-preserve-uncertainty' {
        $r=New-NativeDNSWireEventEvidence 'complete';$r.records=4096;Reject-Wire {Add-NativeDNSWireEventHeader $r ([guid]::Empty) 1 0}
        $r=New-NativeDNSWireEventEvidence 'bound';Reject-Wire {Add-NativeDNSWireEventHeader $r ([guid]::Empty) 1 0}
        $v=Get-NativeDNSWireEventEvidence ($r | ConvertTo-Json -Compress);Assert-Wire ($v.code -ceq 'bound' -and $v.records -eq 0)
        $v=Get-NativeDNSWireEventEvidence ((New-NativeDNSWireEventEvidence 'unavailable') | ConvertTo-Json -Compress);Assert-Wire ($v.code -ceq 'unavailable' -and $v.records -eq -1 -and $v.framePayloadIDs -eq -1)
    }
    Case-Wire 'event-report-refuses-private-fields-and-contradictory-counts' {
        foreach($fault in @('private','boolean','sum','unknown-count','version','overflow')){
            $r=New-NativeDNSWireEventEvidence 'complete'
            switch($fault){'private'{$r['private']='PRIVATE-SYNTHETIC'}'boolean'{$r.records=$false}'sum'{$r.records=1}'unknown-count'{$r.records=-1}'version'{$r.unrecognizedVersions=1}'overflow'{$r.records=4097}}
            $v=Get-NativeDNSWireEventEvidence ($r | ConvertTo-Json -Compress);Assert-Wire ($v.code -ceq 'invalid' -and $v.records -eq -1 -and -not (($v | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
        }
        $v=Get-NativeDNSWireEventEvidence ('x'*4097);Assert-Wire ($v.code -ceq 'invalid' -and $v.records -eq -1)
    }
    Case-Wire 'event-program-is-syntax-only-and-cannot-interpolate-path-code' {
        $private="PRIVATE-SYNTHETIC-'`nthrow 'never'";$encoded=Get-NativeDNSWireEventProgram $private
        $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded));$t=$null;$e=$null;$programAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
        $programFunctions=@($programAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false));Assert-Wire ($programFunctions.Count -eq 2 -and $programFunctions[0].Body.ParamBlock.Parameters.Count -eq 1 -and $programFunctions[1].Body.ParamBlock.Parameters.Count -eq 4)
        Assert-Wire ($e.Count -eq 0 -and -not $body.Contains($private) -and $body.Contains('ReadEvent([TimeSpan]::FromMilliseconds(250))') -and $body.Contains('$record.Dispose()') -and $body.Contains('$reader.Dispose()') -and -not $body.Contains('FormatDescription') -and -not $body.Contains('.ToXml('))
    }
    Case-Wire 'statistics-fallback-retains-unknown-without-private-text' {
        New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='stats-fallback';Measure-NativeDNSWire $script:state;Complete-NativeDNSWireCleanup $script:state
        $r=Get-NativeDNSWireSummary $script:state
        Assert-Wire ($r.statsEvidence.source -ceq 'stdout-fallback' -and $r.statsEvidence.code -ceq 'unknown' -and $r.statsEvidence.packets -eq -1 -and $r.statsEvidence.events -eq -1 -and -not (($r | ConvertTo-Json -Depth 4 -Compress).Contains('PRIVATE-SYNTHETIC')))
    }
    Case-Wire 'etl-statistics-reduces-known-counts-without-private-text' {
        $r=Get-NativeDNSWireStatsEvidence "PRIVATE-SYNTHETIC-PATH`r`nTotal packets: 0`r`nTotal events: 20`r`nEvents lost: 0`r`nBuffers lost: 0`r`n"
        Assert-Wire ($r.code -ceq 'parsed' -and $r.packets -eq 0 -and $r.events -eq 20 -and $r.eventsLost -eq 0 -and $r.buffersLost -eq 0 -and -not (($r | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    }
    Case-Wire 'etl-statistics-unknown-invalid-and-contradiction-are-not-zero' {
        foreach($row in @(@{text='PRIVATE-SYNTHETIC: 0';code='unknown'},@{text='Packets: PRIVATE-SYNTHETIC';code='invalid'},@{text='Packets: -1';code='invalid'},@{text="Packets: 1`nTotal packets: 2";code='inconsistent'})){
            $r=Get-NativeDNSWireStatsEvidence $row.text;Assert-Wire ($r.code -ceq $row.code -and $r.packets -eq -1 -and $r.events -eq -1 -and $r.eventsLost -eq -1 -and $r.buffersLost -eq -1)
        }
    }
    Case-Wire 'etl-statistics-input-and-public-counts-are-bounded' {
        $r=Get-NativeDNSWireStatsEvidence (' ' * 65537);Assert-Wire ($r.code -ceq 'bound' -and $r.packets -eq -1)
        $r=Get-NativeDNSWireStatsEvidence ('x'+("`n" * 2049));Assert-Wire ($r.code -ceq 'bound' -and $r.events -eq -1)
        $r=Get-NativeDNSWireStatsEvidence 'Packets: 18446744073709551615';Assert-Wire ($r.code -ceq 'clipped' -and $r.packets -eq 2147483647 -and $r.events -eq -1)
        $r=Get-NativeDNSWireStatsEvidence 'Packets: 18446744073709551616';Assert-Wire ($r.code -ceq 'invalid' -and $r.packets -eq -1)
    }
    Case-Wire 'monitor-status-reduces-owned-details-without-private-paths' {
        foreach($header in @('Provider Level Keywords','Name Level Keywords')){foreach($level in @('4','0x4')){foreach($mask in @('0x12','0x0000000000000012')){foreach($lineEnding in @("`n","`r`n")){
            $text=(@('Logging mode: Circular','Log file: PRIVATE-SYNTHETIC',$header,('Microsoft-Windows-PktMon '+$level+' '+$mask),'') -join $lineEnding)
            $r=Get-NativeDNSWireMonitorEvidence $text 'PRIVATE-SYNTHETIC'
            Assert-Wire ($r.state -ceq 'owned-details' -and $r.ownedPathMentioned -and $r.providerMentioned -and $r.providerHeaderRecognized -and $r.keywordRowRecognized -and $r.circularSettingMentioned -and $r.rawPacketLogging -ceq 'enabled' -and -not (($r | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
        }}}}
    }
    Case-Wire 'monitor-status-does-not-infer-missing-settings' {
        $stopped=Get-NativeDNSWireMonitorEvidence 'Packet Monitor is not running.' 'PRIVATE-SYNTHETIC'
        $disabled=Get-NativeDNSWireMonitorEvidence "Log file: PRIVATE-SYNTHETIC`nProvider Level Keywords`nMicrosoft-Windows-PktMon 4 0x2" 'PRIVATE-SYNTHETIC'
        $unknown=Get-NativeDNSWireMonitorEvidence 'PRIVATE-SYNTHETIC 0x12' ''
        $rowOnly=Get-NativeDNSWireMonitorEvidence 'Microsoft-Windows-PktMon 0x4 0x0000000000000012' 'PRIVATE-SYNTHETIC'
        Assert-Wire (-not $rowOnly.providerHeaderRecognized -and $rowOnly.keywordRowRecognized -and $rowOnly.rawPacketLogging -ceq 'enabled')
        $oversized=Get-NativeDNSWireMonitorEvidence "Provider Level Keywords`nMicrosoft-Windows-PktMon 4 0x10000000000000000" 'PRIVATE-SYNTHETIC'
        Assert-Wire ($oversized.providerHeaderRecognized -and -not $oversized.keywordRowRecognized -and $oversized.rawPacketLogging -ceq 'unknown')
        Assert-Wire ($stopped.state -ceq 'stopped' -and $stopped.rawPacketLogging -ceq 'unknown' -and $disabled.rawPacketLogging -ceq 'disabled' -and $unknown.state -ceq 'unknown' -and -not $unknown.ownedPathMentioned -and -not $unknown.providerMentioned -and $unknown.rawPacketLogging -ceq 'unknown')
    }
    Case-Wire 'packet-counter-summary-ignores-private-metadata' {
        $r=Get-NativeDNSWireCounterEvidence '{"Components":[{"Name":"PRIVATE-SYNTHETIC","ID":98765,"PacketsIn":2,"PacketsOut":0,"Bytes":99999}]}'
        Assert-Wire ($r.code -ceq 'parsed' -and $r.fields -eq 2 -and $r.nonzero -and (@($r.Keys | Sort-Object) -join ',') -ceq 'code,fields,nonzero' -and -not (($r | ConvertTo-Json -Compress).Contains('PRIVATE-SYNTHETIC')))
    }
    Case-Wire 'zero-packet-counters-are-distinct-from-unknown-shape' {
        $zero=Get-NativeDNSWireCounterEvidence '{"PacketsIn":0,"PacketsOut":0}';$unknown=Get-NativeDNSWireCounterEvidence '{"PRIVATE-SYNTHETIC":99999}'
        Assert-Wire ($zero.code -ceq 'parsed' -and $zero.fields -eq 2 -and -not $zero.nonzero -and $unknown.code -ceq 'unknown-shape' -and $unknown.fields -eq 0 -and -not $unknown.nonzero)
    }
    Case-Wire 'invalid-packet-counter-values-never-leak' {
        foreach($text in @('{"Packets":-1}','{"Packets":0.5}','{"Packets":true}','{"Packets":"PRIVATE-SYNTHETIC"}')){
            $r=Get-NativeDNSWireCounterEvidence $text;Assert-Wire ($r.code -ceq 'invalid-counter' -and $r.fields -eq 0 -and -not $r.nonzero)
        }
        $r=Get-NativeDNSWireCounterEvidence 'PRIVATE-SYNTHETIC-NOT-JSON';Assert-Wire ($r.code -ceq 'invalid-json' -and $r.fields -eq 0 -and -not $r.nonzero)
    }
    Case-Wire 'packet-counter-input-and-traversal-are-bounded' {
        $r=Get-NativeDNSWireCounterEvidence (' ' * 65537);Assert-Wire ($r.code -ceq 'bound' -and $r.fields -eq 0 -and -not $r.nonzero)
        $text='{"Packets":1}';for($i=0;$i -lt 9;$i++){$text='{"Next":'+$text+'}'}
        $r=Get-NativeDNSWireCounterEvidence $text;Assert-Wire ($r.code -ceq 'bound' -and $r.fields -eq 0 -and -not $r.nonzero)
        $text='['+((@('{"Packets":0}') * 2049) -join ',')+']';$r=Get-NativeDNSWireCounterEvidence $text;Assert-Wire ($r.code -ceq 'bound' -and $r.fields -eq 0 -and -not $r.nonzero)
    }
    Case-Wire 'binary-stdin-startup-preserves-header-and-console-encoding' {
        $original=[Console]::InputEncoding;$before=([BitConverter]::ToString($original.GetPreamble()))
        $fake=[pscustomobject]@{Bytes=$null}
        $fake | Add-Member -MemberType ScriptMethod -Name Start -Value {
            $stream=[IO.MemoryStream]::new();$writer=[IO.StreamWriter]::new($stream,[Console]::InputEncoding,128,$true)
            try{$writer.AutoFlush=$true;$writer.BaseStream.Write([byte[]]@(10,13,13,10),0,4);$writer.Close();$this.Bytes=$stream.ToArray();return $true}finally{$writer.Dispose();$stream.Dispose()}
        }
        Assert-Wire (Start-NativeDNSWireChild $fake $true)
        Assert-Wire ($fake.Bytes.Length -eq 4 -and [BitConverter]::ToString($fake.Bytes) -ceq '0A-0D-0D-0A')
        Assert-Wire ([Console]::InputEncoding.CodePage -eq $original.CodePage -and [BitConverter]::ToString([Console]::InputEncoding.GetPreamble()) -ceq $before)
    }
    Case-Wire 'binary-stdin-startup-failure-restores-console-encoding' {
        $original=[Console]::InputEncoding;$before=[BitConverter]::ToString($original.GetPreamble())
        $fake=[pscustomobject]@{}
        $fake | Add-Member -MemberType ScriptMethod -Name Start -Value {throw 'Source synthetic startup failure'}
        Reject-Wire {Start-NativeDNSWireChild $fake $true}
        Assert-Wire ([Console]::InputEncoding.CodePage -eq $original.CodePage -and [BitConverter]::ToString([Console]::InputEncoding.GetPreamble()) -ceq $before)
    }
    Case-Wire 'preflight-is-a-complete-empty-pcapng-envelope' {
        $bytes=New-NativeDNSWireProbeBytes
        Assert-Wire ($bytes -is [byte[]] -and $bytes.Length -eq 48 -and [BitConverter]::ToString($bytes) -ceq '0A-0D-0D-0A-1C-00-00-00-4D-3C-2B-1A-01-00-00-00-FF-FF-FF-FF-FF-FF-FF-FF-1C-00-00-00-01-00-00-00-14-00-00-00-01-00-00-00-FF-FF-00-00-14-00-00-00')
    }
    Case-Wire 'stdin-write-completion-does-not-enter-json-stream' {
        $done=[Threading.Tasks.TaskCompletionSource[object]]::new();$done.SetResult('PRIVATE-SYNTHETIC-WRITE-RESULT')
        Assert-Wire (@(Wait-NativeDNSWireWrite $done.Task).Count -eq 0)
        $failed=[Threading.Tasks.TaskCompletionSource[object]]::new();$failed.SetException([Exception]::new('PRIVATE-SYNTHETIC-WRITE-ERROR'))
        Reject-Wire {Wait-NativeDNSWireWrite $failed.Task}
    }
    Case-Wire 'application-discovery-selects-one-file-path' {
        New-WireCase
        Assert-Wire ($script:state.node -is [string] -and $script:state.node -ceq 'node-source')
    }
    Case-Wire 'startup-errors-map-to-fixed-categories' {
        foreach($pair in @(@(2,'start-not-found'),@(5,'start-access'),@(193,'start-image'),@(267,'start-directory'),@(206,'start-path-bound'),@(740,'start-elevation'),@(1260,'start-policy'),@(1234,'start-os-other'))){
            $failure=[ComponentModel.Win32Exception]::new([int]$pair[0],'source-private-error')
            Assert-Wire ((Get-NativeDNSWireSetupCode $failure) -ceq $pair[1])
            Assert-Wire ((Get-NativeDNSWireSetupCode ([Exception]::new('source-private-wrapper',$failure))) -ceq $pair[1])
        }
        Assert-Wire ((Get-NativeDNSWireSetupCode ([ArgumentException]::new('source-private-error'))) -ceq 'start-argument')
        Assert-Wire ((Get-NativeDNSWireSetupCode ([InvalidOperationException]::new('source-private-error'))) -ceq 'start-state')
        Assert-Wire ((Get-NativeDNSWireSetupCode ([Exception]::new('source-private-error'))) -ceq 'setup')
    }
    Case-Wire 'decoder-preflight-refuses-before-native-effects' {
        New-WireCase;$script:fault='decoder-preflight'
        Reject-Wire {Start-NativeDNSWireCapture $script:state}
        Assert-Wire ($script:state.phase -ceq 'decoder-preflight' -and -not $script:running -and $script:filters.Count -eq 0 -and $script:rules.Count -eq 0 -and -not $script:state.startAttempted)
    }
    Case-Wire 'complete-real-source-control-and-cleanup-order' {
        New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;Complete-NativeDNSWireCleanup $script:state
        $r=Get-NativeDNSWireSummary $script:state
        Assert-Wire ($script:counterReads -eq 2 -and $r.packetCounters.code -ceq 'parsed' -and $r.flowPacketCounters.code -ceq 'parsed')
        Assert-Wire ($r.monitorEvidence.state -ceq 'owned-details' -and $r.monitorEvidence.rawPacketLogging -ceq 'enabled')
        Assert-Wire ($r.eventEvidence.code -ceq 'complete' -and $r.eventEvidence.framePayloadIDs -eq 1)
        Assert-Wire ($r.statsEvidence.source -ceq 'file' -and $r.statsEvidence.code -ceq 'parsed' -and $r.statsEvidence.packets -eq 10 -and $r.statsEvidence.events -eq 20)
        Assert-Wire ($r.outcome -ceq 'passed' -and -not $script:running -and $script:filters.Count -eq 0 -and $script:rules.Count -eq 0 -and $r.toolProcesses -eq $r.toolProcessesJoined -and $r.providerMask -eq 1)
        Assert-Wire ($script:events.IndexOf('query') -lt $script:events.IndexOf('capture-start') -and $script:events.IndexOf('capture-stop') -lt $script:events.IndexOf('conversion') -and $script:events.IndexOf('original-state') -lt $script:events.IndexOf('filter-remove'))
        Assert-Wire (-not (($r | ConvertTo-Json -Depth 6 -Compress).Contains($script:state.owner)))
    }
    Case-Wire 'filter-semantic-drift-prevents-capture' {New-WireCase;$script:fault='filter-port';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire (-not $script:running -and -not $script:state.startAttempted);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ($script:filters.Count -eq 0)}
    Case-Wire 'partial-filter-creation-retires-only-owned-filters' {New-WireCase;$script:fault='partial-filter';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire ($script:filters.Count -eq 2 -and -not $script:running);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ($script:filters.Count -eq 0)}
    Case-Wire 'partial-start-is-stopped-and-joined-before-cleanup' {New-WireCase;$script:fault='partial-start';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire $script:running;$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire (-not $script:running -and $script:state.flags.captureStopped)}
    Case-Wire 'existing-monitor-is-never-stopped' {New-WireCase;$script:running=$true;Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire ($script:running -and -not $script:state.startAttempted -and -not $script:events.Contains('capture-stop'))}
    Case-Wire 'effective-name-policy-refuses-before-new-filters' {New-WireCase;$script:fault='nrpt';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire ($script:filters.Count -eq 0 -and -not $script:state.startAttempted)}
    Case-Wire 'decoder-refusal-cannot-qualify-wire' {
        New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='decoder-refusal';Reject-Wire {Measure-NativeDNSWire $script:state}
        Assert-Wire (-not $script:state.flags.tlsObserved -and $script:state.flags.tlsBlocked -and $script:state.flags.blockedQueryRejected -and $script:state.flags.tlsBlockRemoved -and $script:state.flags.resumedQueryPassed -and $script:state.phase -ceq 'decode')
        $script:fault='';Complete-NativeDNSWireCleanup $script:state
        Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed' -and $script:state.decoderCode -ceq 'tcp-gap')
    }
    Case-Wire 'decoder-refusal-does-not-mask-failed-causal-control' {
        New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='decoder-refusal-negative-succeeds';Reject-Wire {Measure-NativeDNSWire $script:state}
        Assert-Wire ($script:state.decoderCode -ceq 'tcp-gap' -and $script:state.failurePhase -ceq 'blocked-query' -and -not $script:state.flags.tlsObserved -and -not $script:state.flags.blockedQueryRejected -and $script:state.flags.tlsBlockRemoved -and -not $script:state.flags.resumedQueryPassed)
        $script:fault='';Complete-NativeDNSWireCleanup $script:state
        Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed' -and $script:rules.Count -eq 0 -and $script:filters.Count -eq 0)
    }
    Case-Wire 'successful-blocked-query-is-not-a-negative-control' {New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='negative-succeeds';Reject-Wire {Measure-NativeDNSWire $script:state};Assert-Wire (-not $script:state.flags.blockedQueryRejected -and $script:state.flags.tlsBlockRemoved);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed')}
    Case-Wire 'cache-clear-failure-is-not-resolution-rejection' {New-WireCase;$script:fault='cache-failure';Reject-Wire {Invoke-NativeDNSWireQuery 'example.net' -ExpectFailure};Assert-Wire (-not $script:events.Contains('query'))}
    Case-Wire 'resumption-is-required-after-tls-rule-retirement' {New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='resumed-fails';Reject-Wire {Measure-NativeDNSWire $script:state};Assert-Wire (-not $script:state.flags.resumedQueryPassed -and $script:state.flags.tlsBlockRemoved);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed')}
    Case-Wire 'unverified-originals-retain-plaintext-blocks-and-filters' {New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;$script:restored=$false;Reject-Wire {Complete-NativeDNSWireCleanup $script:state};Assert-Wire (-not $script:running -and $script:rules.Count -eq 2 -and $script:filters.Count -eq 12 -and -not $script:state.flags.rulesRemoved)}
    Case-Wire 'retry-retirement-requires-fresh-state-verification' {New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;$script:restored=$false;Reject-Wire {Complete-NativeDNSWireCleanup $script:state};$script:restored=$true;Complete-NativeDNSWireCleanup $script:state;Assert-Wire ($script:rules.Count -eq 0 -and $script:filters.Count -eq 0)}
    Case-Wire 'silent-rule-removal-is-not-success' {New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='remove-noop';Reject-Wire {Measure-NativeDNSWire $script:state};Assert-Wire (-not $script:state.flags.tlsBlockRemoved);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed')}
    Case-Wire 'foreign-rule-ownership-refuses-deletion' {New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;foreach($rule in $script:rules.Values){$rule.DisplayName='source-foreign'};Reject-Wire {Complete-NativeDNSWireCleanup $script:state};Assert-Wire ($script:rules.Count -eq 2 -and $script:filters.Count -eq 12)}
    Case-Wire 'foreign-capture-filter-prevents-global-retirement' {New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;$script:filters['source-foreign']=@{address='203.0.113.1';protocol='TCP';port=443};Reject-Wire {Complete-NativeDNSWireCleanup $script:state};Assert-Wire ($script:filters.Count -eq 13 -and -not $script:state.flags.filtersRemoved)}
    Case-Wire 'capture-file-bound-admits-exact-configured-limit' {New-WireCase;$script:etlSize=16777216;Measure-NativeDNSWireFile $script:state 'etl';Assert-Wire ($script:state.etlBytes -eq 16777216 -and $script:state.captureFileCode -ceq 'ordinary')}
    Case-Wire 'capture-file-overflow-refuses-before-decoding' {New-WireCase;$script:etlSize=16777217;Reject-Wire {Measure-NativeDNSWireFile $script:state 'etl'};Assert-Wire ($script:state.captureFileCode -ceq 'oversized' -and -not $script:state.flags.captureBounded)}
    Case-Wire 'unavailable-capture-file-never-searches-alternate-paths' {New-WireCase;$script:fault='file-unavailable';Reject-Wire {Measure-NativeDNSWireFile $script:state 'etl'};Assert-Wire ($script:itemReads -eq 1 -and $script:state.captureFileCode -ceq 'unavailable')}
    Case-Wire 'wire-summary-excludes-private-paths-and-unknown-fields' {
        New-WireCase;$script:state.workdir='PRIVATE-SYNTHETIC-DIRECTORY'
        $r=Get-NativeDNSWireSummary $script:state
        $keys=@('eventEvidence','statsEvidence','monitorEvidence','flowPacketCounters','packetCounters','processFailureCode','failureExitCode','failureStdoutChars','failureStderrChars','failureElapsedMilliseconds','captureFileCode','etlBytes','pcapBytes','filterRows','filterCode','outcome','phase','failurePhase','decoderCode','controls','toolProcesses','toolProcessesJoined','toolFailure','tlsFlows','outboundEncryptedRecords','inboundEncryptedRecords','providerMask','rawCapturePublished','productionQualificationComplete')
        Assert-Wire ((@($r.Keys | Sort-Object) -join ',') -ceq (@($keys | Sort-Object) -join ',') -and -not (($r | ConvertTo-Json -Depth 4 -Compress).Contains('PRIVATE-SYNTHETIC')))
    }
    Case-Wire 'strict-stopped-and-empty-classifiers' {Reject-Wire {Assert-NativeDNSWireStopped "PRIVATE`nPacket Monitor is not running."};Reject-Wire {Assert-NativeDNSWireEmptyFilters "No filters.`n1 unknown"};Assert-NativeDNSWireStopped 'Packet Monitor is not running.';Assert-NativeDNSWireEmptyFilters "Packet Filters:`nNone"}
} finally {$env:SystemRoot=$oldSystemRoot}
if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $hash){throw 'Wire source changed'}
$passed=@($results | Where-Object {-not $_.passed}).Count -eq 0
[Console]::WriteLine((@{schemaVersion=1;scope='actual-native-wire-source';cases=@($results.ToArray());passed=$passed;realDnsChanged=$false;packetCaptureStarted=$false;nativeWireQualified=$false}|ConvertTo-Json -Depth 4 -Compress))
if(-not $passed){exit 1}
