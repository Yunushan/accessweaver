# Load only the process and discovery predicates from the interactive fixture.
$ErrorActionPreference='Stop'
$fixture=Join-Path $PSScriptRoot 'test-windows-apps.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($fixture,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Interactive Windows app fixture failed parsing'}
foreach($name in @('Test-FixtureAppProcess','Get-FixtureAppImage','Assert-FixtureLiveImage','Test-FixtureCommunication','Test-FixtureAppChecks','Start-FixtureApp','Remove-FixtureApp')){
    $nodes=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($nodes.Count -ne 1){throw 'Expected one application evidence predicate'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$image='C:\Fixture\Discord.exe'
$valid=[pscustomobject]@{Path=$image;SessionId=7;HasExited=$false}
$wrongSession=[pscustomobject]@{Path=$image;SessionId=8;HasExited=$false}
$wrongPath=[pscustomobject]@{Path='C:\Other\Discord.exe';SessionId=7;HasExited=$false}
$exited=[pscustomobject]@{Path=$image;SessionId=7;HasExited=$true}
$unavailable=[pscustomobject]@{Path=$image;SessionId=7;HasExited=$null}
$unreadablePath=[pscustomobject]@{Path=$null;SessionId=7;HasExited=$false}
$otherUnreadablePath=[pscustomobject]@{Path=$null;SessionId=8;HasExited=$false}
$unreadableSession=[pscustomobject]@{Path=$image;SessionId=$null;HasExited=$false}
if((Test-FixtureAppProcess $image 7 @($wrongSession,$valid,$wrongPath)) -ne $true){throw 'Exact live desktop process was missed'}
if((Test-FixtureAppProcess $image 7 @($wrongSession,$wrongPath,$exited,$otherUnreadablePath)) -ne $false){throw 'Unrelated or exited process was accepted'}
if((Test-FixtureAppProcess $image 7 @()) -ne $false){throw 'Empty process inventory did not prove absence'}
foreach($process in @($unavailable,$unreadablePath,$unreadableSession)){
    if($null -ne (Test-FixtureAppProcess $image 7 @($wrongPath,$process))){throw 'Unobservable process was treated as absent'}
    if((Test-FixtureAppProcess $image 7 @($process,$valid)) -ne $true){throw 'An independent matching process was missed'}
}
$unrelated=[pscustomobject]@{ProcessName='other';HasExited=$null}
if((Test-FixtureAppProcess $image 7 @($unrelated) 'Discord') -ne $false){throw 'Unrelated process prevented absence verification'}
$unknownName=[pscustomobject]@{ProcessName=$null;HasExited=$false}
if($null -ne (Test-FixtureAppProcess $image 7 @($unknownName) 'Discord')){throw 'Unknown process name was treated as absent'}
$commands=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Check'
},$true))
$stages=@($commands | ForEach-Object {$_.CommandElements[1].Value})
$stableRemove=[array]::IndexOf($stages,'discord-remove')
$stableInstall=[array]::IndexOf($stages,'discord-install-for-ptb-clean')
$ptbClean=[array]::IndexOf($stages,'ptb-clean-install')
if($stableRemove -lt 0 -or $stableInstall -ne ($stableRemove+1) -or $ptbClean -ne ($stableInstall+1)){
    throw 'Stable Discord removal and clean PTB do not run independently'
}
$script:observations=[Collections.Generic.Queue[object]]::new()
function Find-FixtureLiveImage {
    if(-not $script:observations.Count){throw 'Fixture observation limit reached'}
    return $script:observations.Dequeue()
}
function Start-Sleep {param($Milliseconds);if($Milliseconds -ne 250){throw 'Unexpected fixture observation interval'}}
$script:observations.Enqueue($null)
$script:observations.Enqueue($false)
Assert-FixtureLiveImage $image $false
if($script:observations.Count){throw 'Indeterminate first read was credited as removal'}
$script:observations.Enqueue($null)
$refused=$false
try{Assert-FixtureLiveImage $image $false}catch{$refused=$_.Exception.Message -ceq 'Fixture observation limit reached'}
if(-not $refused){throw 'No conclusive readback was accepted as removal'}
if((Get-FixtureAppImage ([pscustomobject]@{discord=$image}) 'discord') -cne $image){throw 'Approved discovery identity was missed'}
if(Get-FixtureAppImage ([pscustomobject]@{'discord-ptb'=$null}) 'discord-ptb'){throw 'Absent discovery unexpectedly returned a path'}
foreach($inventory in @(
    [pscustomobject]@{},
    [pscustomobject]@{discord=@($image,$image)},
    [pscustomobject]@{discord='C:\Fixture\DiscordPTB.exe'},
    [pscustomobject]@{discord='\\untrusted\share\Discord.exe'},
    [pscustomobject]@{discord='C:\Fixture\Other\..\Discord.exe'}
)){
    $refused=$false
    try {$null=Get-FixtureAppImage $inventory 'discord'}catch{$refused=$true}
    if(-not $refused){throw 'Unverified discovery identity was accepted'}
}
# Drive the same prompt function with an inert process inventory and terminal.
$script:promptCount=0
$script:promptAnswer='PASS'
function Read-Host([string]$Prompt){
    if($Prompt -notmatch 'two-way|both directions'){throw 'Prompt omitted the two-way condition'}
    $script:promptCount++
    return $script:promptAnswer
}
foreach($kind in @('text','voice')){
    $script:observations.Enqueue($true)
    $script:observations.Enqueue($true)
    Test-FixtureCommunication 'discord' $image $kind
    if($script:observations.Count){throw 'Communication check omitted the post-prompt process check'}
}
if($script:promptCount -ne 2){throw 'Expected distinct text and voice confirmations'}
foreach($answer in @('','pass','PASS ')){
    $script:promptAnswer=$answer
    $script:observations.Enqueue($true)
    $refused=$false
    try{Test-FixtureCommunication 'discord-ptb' $image 'text'}catch{
        $refused=$_.Exception.Message -ceq 'Operator did not confirm two-way communication'
    }
    if(-not $refused -or $script:observations.Count){throw 'Unconfirmed communication was accepted'}
}
$before=$script:promptCount
$refused=$false
try{Test-FixtureCommunication 'splitcord' $image 'voice'}catch{
    $refused=$_.Exception.Message -ceq 'Fixture observation limit reached'
}
if(-not $refused -or $script:promptCount -ne $before){throw 'Communication was prompted without a live image'}
$script:promptAnswer='PASS'
$script:observations.Enqueue($true)
$refused=$false
try{Test-FixtureCommunication 'splitcord' $image 'voice'}catch{
    $refused=$_.Exception.Message -ceq 'Fixture observation limit reached'
}
if(-not $refused -or $script:promptCount -ne ($before+1)){throw 'Operator input replaced final live-image verification'}
$installedImages=@{discord=$image}
$launchTrace=[Collections.Generic.List[string]]::new()
$launchResult=@{application='discord';alreadyRunning=$false}
function Invoke-AppWorkflow([hashtable]$Request){
    if($Request.action -cne 'app-start' -or $Request.engine -cne 'discord'){throw 'Unexpected fixture launch request'}
    $launchTrace.Add('start')
    return $launchResult
}
$script:observations.Enqueue($false)
$script:observations.Enqueue($true)
Start-FixtureApp 'discord'
if($launchTrace.Count -ne 1 -or $script:observations.Count){throw 'Fresh start evidence omitted a baseline or readback'}
foreach($alreadyRunning in @($true,'false',$null)){
    $launchResult.alreadyRunning=$alreadyRunning
    $script:observations.Enqueue($false)
    $refused=$false
    try{Start-FixtureApp 'discord'}catch{$refused=$_.Exception.Message -ceq 'The application workflow did not confirm a fresh start'}
    if(-not $refused -or $script:observations.Count){throw 'Existing or untyped process evidence was credited as a new start'}
}
& {
    $replacement='C:\Fixture\Updated\Discord.exe'
    function Inspect-Apps {
        $trace.Add('discovery')
        if(-not $observed.Count){throw 'Unexpected removal inventory read'}
        return [pscustomobject]@{discord=$observed.Dequeue()}
    }
    function Invoke-AppWorkflow([hashtable]$Request){
        if($Request.action -cne 'app-remove' -or $Request.engine -cne 'discord'){throw 'Unexpected removal request'}
        $trace.Add('remove')
        return @{application='discord';removed=$removalOutcome}
    }
    function Assert-FixtureLiveImage([string]$Path,[bool]$Expected){
        if($Expected -or $Path -cnotin @($image,$replacement)){throw 'Unexpected removal process check'}
        $trace.Add('process:'+ $Path)
    }
    function Test-Path {
        [CmdletBinding()]param($LiteralPath,$PathType)
        if($ErrorActionPreference -ne 'Stop' -or $LiteralPath -cnotin @($image,$replacement)){throw 'Unexpected removal file check'}
        if($PathType -eq 'Leaf'){return $baselineHasFile}
        return $LiteralPath -ceq $remainingFile
    }
    foreach($case in @(
        @{name='missing';before=$null;previous=$image;file=$false;launch=$false;success=$false},
        @{name='unrecorded';before=$image;previous=$null;file=$true;launch=$false;success=$false},
        @{name='changed';before=$replacement;previous=$image;file=$true;launch=$false;success=$false},
        @{name='no-file';before=$image;previous=$image;file=$false;launch=$false;success=$false},
        @{name='ordinary';before=$image;previous=$image;file=$true;launch=$true;success=$true},
        @{name='workflow-no-op';before=$image;previous=$image;file=$true;result=$false;launch=$true;success=$false},
        @{name='workflow-invalid-result';before=$image;previous=$image;file=$true;result='true';launch=$true;success=$false},
        @{name='remains-discoverable';before=$image;previous=$image;file=$true;after=$image;launch=$true;success=$false},
        @{name='remains-on-disk';before=$image;previous=$image;file=$true;remaining=$image;launch=$true;success=$false},
        @{name='clean-guest';before=$null;previous=$image;cleanup=$true;launch=$false;success=$true},
        @{name='cleanup-newly-discovered';before=$replacement;previous=$image;cleanup=$true;launch=$true;success=$true},
        @{name='cleanup-must-check-previous';before=$replacement;previous=$image;cleanup=$true;remaining=$image;launch=$true;success=$false}
    )){
        $installedImages=@{discord=$case.previous}
        $removalOutcome=if($case.ContainsKey('result')){$case.result}else{$true}
        $baselineHasFile=$case.file
        $remainingFile=$case.remaining
        $trace=[Collections.Generic.List[string]]::new()
        $observed=[Collections.Generic.Queue[object]]::new()
        $observed.Enqueue($case.before)
        $observed.Enqueue($case.after)
        $passed=$false
        try{Remove-FixtureApp 'discord' -Cleanup:([bool]$case.cleanup);$passed=$true}catch{}
        if($passed -ne $case.success -or $trace.Contains('remove') -ne $case.launch){
            throw ('Unexpected removal result: '+$case.name)
        }
        if($passed -and $case.previous -and -not $trace.Contains('process:'+$case.previous)){
            throw ('Removal omitted the previous image: '+$case.name)
        }
        if($passed -and $case.before -and -not $trace.Contains('process:'+$case.before)){
            throw ('Removal omitted the discovered image: '+$case.name)
        }
    }
}
$communicationCalls=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Check-FixtureCommunications'
},$true))
foreach($case in @(
    @{variant='discord';start='discord-start-after-reinstall';remove='discord-remove'},
    @{variant='discord-ptb';start='ptb-start';remove='ptb-remove'},
    @{variant='splitcord';start='splitcord-start';remove='splitcord-remove'}
)){
    $calls=@($communicationCalls | Where-Object {$_.CommandElements[1].Value -ceq $case.variant})
    $start=$commands[[array]::IndexOf($stages,$case.start)].Extent.StartOffset
    $remove=$commands[[array]::IndexOf($stages,$case.remove)].Extent.StartOffset
    if($calls.Count -ne 1 -or $calls[0].Extent.StartOffset -le $start -or $calls[0].Extent.StartOffset -ge $remove){
        throw 'Communication checks must run with the intended client installed and started'
    }
}
$expected=@('discord-install','discord-start','cleanup-discord')
$complete=@(
    @{name='discord-start';passed=$true},@{name='discord-install';passed=$true},@{name='cleanup-discord';passed=$true}
)
if(-not (Test-FixtureAppChecks $complete $expected)){throw 'Complete application checks were rejected'}
foreach($bad in @(
    @{checks=@()},
    @{checks=$complete[0..1]},
    @{checks=@($complete[0],$complete[1],$complete[1])},
    @{checks=@($complete[0],$complete[1],@{name='Cleanup-Discord';passed=$true})},
    @{checks=@($complete[0],$complete[1],@{name='cleanup-discord';passed=$false})},
    @{checks=@($complete[0],$complete[1],@{name='cleanup-discord';passed='true'})},
    @{checks=@($complete[0],$complete[1],@{name='cleanup-discord'})}
)){
    if(Test-FixtureAppChecks $bad.checks $expected){throw 'Incomplete or invalid application evidence was credited'}
}
Write-Output 'Interactive Windows application evidence contracts passed.'
