# Exercise only the actual answer selector with inert query/cache boundaries.
# No resolver, cache, packet capture, process or machine configuration is used.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
$source=Join-Path $PSScriptRoot 'test-native-doh.ps1'
$sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Native DNS answer source did not parse'}
$nodes=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-NativeDNSAnswerCount'},$true))
if($nodes.Count -ne 1){throw 'Expected exactly one native DNS answer selector'}
foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
    if($command.GetCommandName() -cnotin @('Invoke-NativeFreshDNSQuery','Clear-DnsClientCache','Resolve-DnsName','Where-Object')){throw 'Unexpected answer selector command boundary'}
}
. ([scriptblock]::Create($nodes[0].Extent.Text))
$script:answerChecks=0
$script:trace=[Collections.Generic.List[string]]::new()
function Assert-AnswerContract([bool]$Value){if(-not $Value){throw 'Synthetic native DNS answer assertion'};$script:answerChecks++}
function Invoke-NativeFreshDNSQuery($State,[string]$Name){
    Assert-AnswerContract ([object]::ReferenceEquals($State,$script:wire) -and $Name -ceq 'example.com')
    $script:trace.Add('fresh')
    return @{answerCount=2}
}
function Clear-DnsClientCache {
    [CmdletBinding()]param()
    Assert-AnswerContract ($ErrorActionPreference -ceq 'Stop')
    $script:trace.Add('cache')
}
function Resolve-DnsName {
    [CmdletBinding()]param([string]$Name,[string]$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout)
    Assert-AnswerContract ($Name -ceq 'example.com' -and $Type -ceq $script:recordType -and $DnsOnly -and $NoHostsFile -and $QuickTimeout -and $ErrorActionPreference -ceq 'Stop')
    $script:trace.Add('ordinary')
    foreach($address in $script:addresses){[pscustomobject]@{IPAddress=$address}}
}
foreach($case in @(
    @{wire=$true;restored=$false;type='A';probe=$true;binding=$true;expected=2;trace='fresh'},
    @{wire=$true;restored=$true;type='A';probe=$false;binding=$false;expected=2;trace='cache,ordinary'},
    @{wire=$true;restored=$true;type='AAAA';probe=$false;binding=$false;expected=1;trace='cache,ordinary'},
    @{wire=$false;restored=$false;type='A';probe=$false;binding=$false;expected=2;trace='cache,ordinary'},
    @{wire=$false;restored=$false;type='AAAA';probe=$false;binding=$false;expected=1;trace='cache,ordinary'},
    @{wire=$true;restored=$false;type='AAAA';probe=$true;binding=$true;expected=-1;trace=''},
    @{wire=$true;restored=$false;type='A';probe=$false;binding=$true;expected=-1;trace=''},
    @{wire=$true;restored=$false;type='A';probe=$true;binding=$false;expected=-1;trace=''}
)){
    $WireTransport=$case.wire;$queryProbeReady=$case.probe;$script:recordType=$case.type
    $script:wire=if($case.binding){@{synthetic='binding'}}else{$null}
    $script:addresses=@('192.0.2.1','192.0.2.2','2001:db8::1','::ffff:192.0.2.3','invalid-address')
    $script:trace.Clear();$result=$null;$failure=$null
    try{$result=Get-NativeDNSAnswerCount -Restored:$case.restored -RecordType $case.type}catch{$failure=$_.Exception.Message}
    if($case.expected -eq -1){Assert-AnswerContract ($failure -ceq 'Wire query helper unavailable' -and $null -eq $result)}
    else{Assert-AnswerContract ($null -eq $failure -and $result -eq $case.expected)}
    Assert-AnswerContract (($script:trace -join ',') -ceq $case.trace)
}
# An ordinary resolver result needs a bounded answer in the requested family.
$WireTransport=$true;$queryProbeReady=$false;$script:wire=$null;$script:recordType='AAAA'
foreach($addresses in @(@('192.0.2.1','::ffff:192.0.2.2'),@(1..65 | ForEach-Object {'2001:db8::1'}))){
    $script:addresses=$addresses;$script:trace.Clear();$refused=$false
    try{$null=Get-NativeDNSAnswerCount -Restored -RecordType AAAA}catch{$refused=$_.Exception.Message -ceq 'Ordinary native DNS answer bounds failed'}
    Assert-AnswerContract ($refused -and ($script:trace -join ',') -ceq 'cache,ordinary')
}
if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne $sourceHash){throw 'Native DNS answer source changed'}
Write-Output ('PASS native DNS answer selector source contracts ('+$script:answerChecks+' checks; native boundaries mocked)')
