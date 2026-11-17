# Exercise the real peer evidence parser with inert files and fixed counters.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-native-wiresock.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'WireSock source failed parsing'}
foreach($name in @('Read-PeerEvidence','Observe-PeerEvidence','Get-FixtureAdapterIPv4')){
    $nodes=@($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Missing bounded peer evidence function'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$file=[IO.Path]::GetTempFileName()
try {
    [IO.File]::WriteAllText($file,'{"last_handshake_time_sec":"0","rx_bytes":"0","tx_bytes":"0","initiation_received":false}')
    $sample=Observe-PeerEvidence $file
    if(-not $sample -or $sample.initiationReceived -or $sample.handshake -or $sample.receivedBytes -or $sample.sentBytes){
        throw 'Readable zero counters must remain an explicit observation'
    }
    [IO.File]::WriteAllText($file,'{"last_handshake_time_sec":"7","rx_bytes":"1","tx_bytes":"9","initiation_received":true,"private":"synthetic"}')
    $sample=Observe-PeerEvidence $file -WaitForTraffic
    if($sample.Count -ne 4 -or -not $sample.initiationReceived -or -not $sample.handshake -or -not $sample.receivedBytes -or -not $sample.sentBytes){
        throw 'Positive counters must project only the four fixed flags'
    }
    foreach($content in @(
        '',
        '{',
        '{"last_handshake_time_sec":"0","rx_bytes":"0","initiation_received":false}',
        '{"last_handshake_time_sec":1,"rx_bytes":"0","tx_bytes":"0","initiation_received":false}',
        '{"last_handshake_time_sec":"-1","rx_bytes":"0","tx_bytes":"0","initiation_received":false}',
        '{"last_handshake_time_sec":"9223372036854775808","rx_bytes":"0","tx_bytes":"0","initiation_received":false}',
        '{"last_handshake_time_sec":"0","rx_bytes":"0","tx_bytes":"0"}',
        '{"last_handshake_time_sec":"0","rx_bytes":"0","tx_bytes":"0","initiation_received":"false"}',
        (' '*4097)
    )){
        [IO.File]::WriteAllText($file,$content)
        $refused=$false
        try {$null=Read-PeerEvidence $file}catch{$refused=$true}
        if(-not $refused){throw 'Malformed or oversized peer counters were accepted'}
    }
    [IO.File]::WriteAllBytes($file,[byte[]]@(255,255))
    $refused=$false
    try {$null=Read-PeerEvidence $file}catch{$refused=$true}
    if(-not $refused){throw 'Invalid UTF-8 peer counters were accepted'}
} finally {
    [IO.File]::Delete($file)
}
function Find-NetRoute {
    [CmdletBinding()]param([string]$RemoteIPAddress)
    if($RemoteIPAddress -cne '203.0.113.1'){throw 'Unexpected fixture route query'}
    return $fixtureRoutes
}
function New-FixtureAddress([string]$Address,[string]$State='Preferred',[bool]$Skip=$false){
    return [pscustomobject]@{IPAddress=$Address;AddressFamily='IPv4';Type='Unicast';AddressState=$State;SkipAsSource=$Skip}
}
$route=[pscustomobject]@{DestinationPrefix='0.0.0.0/0';AddressFamily='IPv4'}
foreach($address in @('10.1.2.3','172.31.2.3','192.168.2.3')){
    $fixtureRoutes=@((New-FixtureAddress $address),$route)
    if((Get-FixtureAdapterIPv4) -cne $address){throw 'Expected the private source selected by Windows'}
}
$numeric=New-FixtureAddress '172.18.2.3'
$numeric.AddressFamily=[uint16]2;$numeric.Type=[byte]1;$numeric.AddressState=[uint16]4
$fixtureRoutes=@($numeric,$route)
if((Get-FixtureAdapterIPv4) -cne '172.18.2.3'){throw 'Expected documented CIM numeric values'}
foreach($fixtureRoutes in @(
    @(New-FixtureAddress '127.0.0.1'),
    @(New-FixtureAddress '203.0.113.7'),
    @(New-FixtureAddress '::ffff:10.1.2.3'),
    @(New-FixtureAddress '010.1.2.3'),
    @(New-FixtureAddress '10.1.2.3' -State 'Tentative'),
    @(New-FixtureAddress '10.1.2.3' -Skip $true),
    @((New-FixtureAddress '10.1.2.3'),(New-FixtureAddress '10.1.2.4'))
)){
    $refused=$false
    try {$null=Get-FixtureAdapterIPv4}catch{$refused=$_.Exception.Message -ceq 'An active private IPv4 source address is required for the adapter fixture'}
    if(-not $refused){throw 'Unsafe or ambiguous active source reached the WireSock fixture'}
}
Write-Output 'Bounded WireSock peer evidence and adapter source checks passed.'
