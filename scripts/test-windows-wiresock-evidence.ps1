# Exercise the real peer evidence parser with inert files and fixed counters.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'test-windows-native-wiresock.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'WireSock source failed parsing'}
foreach($name in @('Read-PeerEvidence','Observe-PeerEvidence')){
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
Write-Output 'Twelve bounded WireSock peer evidence checks passed.'
