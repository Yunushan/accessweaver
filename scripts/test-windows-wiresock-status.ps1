# Pure selected-function contracts. No vendor code, service, registry or network
# settings are queried or changed.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project 'internal/workflow/windows.ps1'),[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'WireSock status source parse failed'}
$nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Get-WireSockReportedState'})
if($nodes.Count -ne 1){throw 'WireSock status function selection failed'}
. ([scriptblock]::Create($nodes[0].Extent.Text))
function Invoke-WireSockStatusContracts([string]$FixturePath) {
    $fixture=ConvertFrom-Json ([IO.File]::ReadAllText($FixturePath))
    if($fixture.schemaVersion -ne 1 -or $fixture.vendorVersion -cne '3.8.1.1' -or
        @($fixture.cultures.PSObject.Properties).Count -ne 21){throw 'WireSock status fixture identity failed'}
    $script:wireSockStatusChecks=0
    function Assert-Status([object]$Text,[bool]$Complete,[string]$ExpectedProfile,[string]$Want) {
        $actual=@(Get-WireSockReportedState @{stdout=$Text;outputComplete=$Complete} $ExpectedProfile)
        if($actual.Count -ne 1 -or $actual[0] -isnot [string] -or $actual[0] -cne $Want){
            throw 'WireSock status contract failed'
        }
        $script:wireSockStatusChecks++
    }
    $profile='AccessWeaver-'+('a'*32);$other='AccessWeaver-'+('b'*32)
    foreach($culture in $fixture.cultures.PSObject.Properties){
        foreach($state in $culture.Value.templates.PSObject.Properties){
            $text=$state.Value.Replace('{0}',$profile)
            Assert-Status $text $true '' $state.Name
            Assert-Status $text $true $profile $state.Name
            Assert-Status ("  "+$text+"  "+[char]13+[char]10+'External address: PRIVATE_ADDRESS') $true $profile $state.Name
            Assert-Status ($text+[char]10+'PRIVATE_UNRECOGNIZED_LINE') $true $profile 'Unknown'
            $external=$culture.Value.metadata.externalAddress.Replace('{0}','PRIVATE_ADDRESS')
            $network=$culture.Value.metadata.networkLock
            Assert-Status ($text+[char]10+$external+[char]10+$network) $true $profile $state.Name
            Assert-Status ($external+[char]10+$network) $true $profile 'Unknown'
            Assert-Status $text $false $profile 'Unknown'
            Assert-Status ($text+[char]10+$text) $true $profile 'Unknown'
            Assert-Status ($text+[char]10+'NotConnected') $true $profile 'Unknown'
            Assert-Status ($text+' PRIVATE_SUFFIX') $true $profile 'Unknown'
            Assert-Status ($text+[char]0) $true $profile 'Unknown'
            if($state.Value.Contains('{0}')){
                Assert-Status ($state.Value.Replace('{0}',$other)) $true $profile 'Unknown'
                Assert-Status ($state.Value.Replace('{0}','PRIVATE_PROFILE')) $true '' $state.Name
            }
        }
    }
    foreach($state in @('NotConnected','Connecting','Connected','Disconnecting','Disconnected')){
        Assert-Status $state $true '' $state
        Assert-Status ('Connection status: '+$state) $true '' $state
        $bound=if($state -cin @('NotConnected','Disconnected')){$state}else{'Unknown'}
        Assert-Status $state $true $profile $bound
        Assert-Status ('Status: '+$state) $true $profile $bound
    }
    foreach($bad in @('private','AccessWeaver-'+('A'*32),($profile+[char]10),($profile+'extra'),'../private')){
        Assert-Status 'Not connected' $true $bad 'Unknown'
    }
    foreach($text in @('','Not connected extra','Profile: Connected','Connection is Connected to an unverified profile',
        'Connected to server using profile PRIVATE_PROFILE',('x'*8193),($profile+' Connected'))){
        Assert-Status $text $true $profile 'Unknown'
    }
    Assert-Status $null $true '' 'Unknown'
    Assert-Status @('Connected') $true '' 'Unknown'
    Assert-Status 3 $true '' 'Unknown'
    [ordered]@{scope='pure-pinned-vendor-wiresock-status';powerShellMajor=$PSVersionTable.PSVersion.Major;
        cultures=21;checks=$script:wireSockStatusChecks;passed=$true;vendorCodeExecuted=$false;hostSettingsQueriedOrChanged=$false}
}
Invoke-WireSockStatusContracts (Join-Path $PSScriptRoot 'fixtures/wiresock-status-3.8.1.1.json')
