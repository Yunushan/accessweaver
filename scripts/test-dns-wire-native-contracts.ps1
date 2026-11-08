# Hosted actual-source contracts. All native boundaries are replaced before evaluation.
[CmdletBinding()]param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
$project=Split-Path -Parent $PSScriptRoot;$path=Join-Path $PSScriptRoot 'native-dns-wire.ps1'
$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Wire source syntax'}
$excluded=@('Invoke-NativeDNSWireProcess','Read-NativeDNSWireCapture')
$allowed=@('Assert-NativeOrdinaryPath','Get-Command','Join-Path','Where-Object','Select-Object','Invoke-NativeDNSWireProcess','Invoke-NativeDNSWireTool','Assert-NativeDNSWireStopped','Assert-NativeDNSWireEmptyFilters','Get-NativeDNSWireFilterRows','Assert-NativeDNSWireFilters','Get-NetFirewallProfile','Get-Service','Get-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Assert-NativeDNSWireRule','New-NetFirewallRule','Remove-NetFirewallRule','Assert-NativeDNSWireFirewall','Get-DnsClientNrptPolicy','Add-NativeDNSWireRule','Remove-NativeDNSWireRules','Stop-NativeDNSWireCapture','Clear-DnsClientCache','Resolve-DnsName','Invoke-NativeDNSWireQuery','Read-NativeDNSWireCapture','ConvertFrom-Json','Assert-DNSAcceptanceRestored','Read-DNSAcceptanceState')
$definitions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false));$seen=@{}
foreach($definition in $definitions){
    if($seen.ContainsKey($definition.Name)){throw 'Duplicate wire source function'};$seen[$definition.Name]=$true
    if($definition.Name -cin $excluded){continue}
    foreach($command in $definition.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($command.GetCommandName() -cnotin $allowed){throw 'Wire source command boundary'}}
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Assert-NativeOrdinaryPath([string]$Path) {}
function Get-Command {param($Name,$CommandType,$ErrorAction);if($Name -cne 'node'){throw 'Source command refused'};return [pscustomobject]@{Source='node-source'}}
function Assert-Wire([bool]$Condition){if(-not $Condition){throw 'Wire source assertion'}}
function New-WireCase {
    $script:fault='';$script:filters=@{};$script:rules=@{};$script:running=$false;$script:restored=$true;$script:events=[Collections.Generic.List[string]]::new();$script:addOrdinal=0
    $script:state=New-NativeDNSWireState ([IO.Path]::Combine([IO.Path]::GetTempPath(),'aw-wire-source')) ([IO.Path]::Combine([IO.Path]::GetTempPath(),'dns-wire-stdin.cjs'))
    $script:state.before='source-original'
}
function Invoke-NativeDNSWireProcess([object]$State,[string]$Program,[string[]]$Arguments,[byte[]]$InputBytes=$null) {
    $State.processes++;$State.joined++
    if($Program -ceq 'node-source'){
        Assert-Wire ($null -ne $InputBytes -and $InputBytes.Length -eq 3 -and -not $script:running)
        if($script:fault -ceq 'decoder-refusal'){return '{"schemaVersion":1,"outcome":"refused","code":"tcp-gap","evidence":null}'}
        return '{"schemaVersion":1,"outcome":"decoded","code":"none","evidence":{"schemaVersion":1,"observation":"tls-observed","plaintextPackets":0,"productionQualificationComplete":false,"flows":[{"provider":"google-v4","clientHello":true,"serverHello":true,"outboundEncryptedRecords":1,"inboundEncryptedRecords":1}]}}'
    }
    Assert-Wire ($Program -ceq $State.tool)
    switch -CaseSensitive ($Arguments[0]){
        'status' {if($script:running){return 'Packet Monitor is running.'};return 'Packet Monitor is not running.'}
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
                'remove' {Assert-Wire (-not $script:running);$script:events.Add('filter-remove');$script:filters.Remove($Arguments[2]);return ''}
            }
        }
        'start' {
            Assert-Wire ($script:filters.Count -eq 12 -and $State.flags.filtersVerified -and -not $script:running)
            Assert-Wire (($Arguments -join ',').Contains('--capture,--comp,nics,--pkt-size,0') -and ($Arguments -join ',').Contains('--file-size,16,--log-mode,memory'))
            $script:running=$true;$script:events.Add('capture-start')
            if($script:fault -ceq 'partial-start'){throw 'Source partial capture start'};return ''
        }
        'stop' {$script:running=$false;$script:events.Add('capture-stop');return ''}
        'etl2pcap' {Assert-Wire (-not $script:running);$script:events.Add('conversion');return ''}
    }
    throw 'Unexpected source tool operation'
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
    Assert-Wire ($Name -cin @('example.com','example.net') -and $Type -ceq 'A' -and $DnsOnly -and $NoHostsFile -and $QuickTimeout)
    $blocked=@($script:rules.Values | Where-Object {($_.RemotePort -join ',') -ceq '443'}).Count -gt 0
    if(($blocked -and $script:fault -cne 'negative-succeeds') -or ($script:fault -ceq 'resumed-fails' -and $script:state.phase -ceq 'resumed-query')){throw 'Source query rejected'}
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
    Case-Wire 'complete-real-source-control-and-cleanup-order' {
        New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;Complete-NativeDNSWireCleanup $script:state
        $r=Get-NativeDNSWireSummary $script:state
        Assert-Wire ($r.outcome -ceq 'passed' -and -not $script:running -and $script:filters.Count -eq 0 -and $script:rules.Count -eq 0 -and $r.toolProcesses -eq $r.toolProcessesJoined -and $r.providerMask -eq 1)
        Assert-Wire ($script:events.IndexOf('query') -lt $script:events.IndexOf('capture-start') -and $script:events.IndexOf('capture-stop') -lt $script:events.IndexOf('conversion') -and $script:events.IndexOf('original-state') -lt $script:events.IndexOf('filter-remove'))
        Assert-Wire (-not (($r | ConvertTo-Json -Depth 6 -Compress).Contains('aw-wire-')))
    }
    Case-Wire 'filter-semantic-drift-prevents-capture' {New-WireCase;$script:fault='filter-port';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire (-not $script:running -and -not $script:state.startAttempted);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ($script:filters.Count -eq 0)}
    Case-Wire 'partial-filter-creation-retires-only-owned-filters' {New-WireCase;$script:fault='partial-filter';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire ($script:filters.Count -eq 2 -and -not $script:running);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ($script:filters.Count -eq 0)}
    Case-Wire 'partial-start-is-stopped-and-joined-before-cleanup' {New-WireCase;$script:fault='partial-start';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire $script:running;$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire (-not $script:running -and $script:state.flags.captureStopped)}
    Case-Wire 'existing-monitor-is-never-stopped' {New-WireCase;$script:running=$true;Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire ($script:running -and -not $script:state.startAttempted -and -not $script:events.Contains('capture-stop'))}
    Case-Wire 'effective-name-policy-refuses-before-new-filters' {New-WireCase;$script:fault='nrpt';Reject-Wire {Start-NativeDNSWireCapture $script:state};Assert-Wire ($script:filters.Count -eq 0 -and -not $script:state.startAttempted)}
    Case-Wire 'decoder-refusal-cannot-qualify-wire' {New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='decoder-refusal';Reject-Wire {Measure-NativeDNSWire $script:state};$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed' -and $script:state.decoderCode -ceq 'tcp-gap')}
    Case-Wire 'successful-blocked-query-is-not-a-negative-control' {New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='negative-succeeds';Reject-Wire {Measure-NativeDNSWire $script:state};Assert-Wire (-not $script:state.flags.blockedQueryRejected -and $script:state.flags.tlsBlockRemoved);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed')}
    Case-Wire 'cache-clear-failure-is-not-resolution-rejection' {New-WireCase;$script:fault='cache-failure';Reject-Wire {Invoke-NativeDNSWireQuery 'example.net' -ExpectFailure};Assert-Wire (-not $script:events.Contains('query'))}
    Case-Wire 'resumption-is-required-after-tls-rule-retirement' {New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='resumed-fails';Reject-Wire {Measure-NativeDNSWire $script:state};Assert-Wire (-not $script:state.flags.resumedQueryPassed -and $script:state.flags.tlsBlockRemoved);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed')}
    Case-Wire 'unverified-originals-retain-plaintext-blocks-and-filters' {New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;$script:restored=$false;Reject-Wire {Complete-NativeDNSWireCleanup $script:state};Assert-Wire (-not $script:running -and $script:rules.Count -eq 2 -and $script:filters.Count -eq 12 -and -not $script:state.flags.rulesRemoved)}
    Case-Wire 'retry-retirement-requires-fresh-state-verification' {New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;$script:restored=$false;Reject-Wire {Complete-NativeDNSWireCleanup $script:state};$script:restored=$true;Complete-NativeDNSWireCleanup $script:state;Assert-Wire ($script:rules.Count -eq 0 -and $script:filters.Count -eq 0)}
    Case-Wire 'silent-rule-removal-is-not-success' {New-WireCase;Start-NativeDNSWireCapture $script:state;$script:fault='remove-noop';Reject-Wire {Measure-NativeDNSWire $script:state};Assert-Wire (-not $script:state.flags.tlsBlockRemoved);$script:fault='';Complete-NativeDNSWireCleanup $script:state;Assert-Wire ((Get-NativeDNSWireSummary $script:state).outcome -ceq 'failed')}
    Case-Wire 'foreign-rule-ownership-refuses-deletion' {New-WireCase;Start-NativeDNSWireCapture $script:state;Measure-NativeDNSWire $script:state;foreach($rule in $script:rules.Values){$rule.DisplayName='source-foreign'};Reject-Wire {Complete-NativeDNSWireCleanup $script:state};Assert-Wire ($script:rules.Count -eq 2 -and $script:filters.Count -eq 12)}
    Case-Wire 'strict-stopped-and-empty-classifiers' {Reject-Wire {Assert-NativeDNSWireStopped "PRIVATE`nPacket Monitor is not running."};Reject-Wire {Assert-NativeDNSWireEmptyFilters "No filters.`n1 unknown"};Assert-NativeDNSWireStopped 'Packet Monitor is not running.';Assert-NativeDNSWireEmptyFilters "Packet Filters:`nNone"}
} finally {$env:SystemRoot=$oldSystemRoot}
if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $hash){throw 'Wire source changed'}
$passed=@($results | Where-Object {-not $_.passed}).Count -eq 0
[Console]::WriteLine((@{schemaVersion=1;scope='actual-native-wire-source';cases=@($results.ToArray());passed=$passed;realDnsChanged=$false;packetCaptureStarted=$false;nativeWireQualified=$false}|ConvertTo-Json -Depth 4 -Compress))
if(-not $passed){exit 1}
