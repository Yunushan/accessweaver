# Load only the process and discovery predicates from the interactive fixture.
$ErrorActionPreference='Stop'
$fixture=Join-Path $PSScriptRoot 'test-windows-apps.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($fixture,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Interactive Windows app fixture failed parsing'}
foreach($name in @('Test-FixtureAppProcess','Get-FixtureAppImage','Assert-FixtureLiveImage')){
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
Write-Output 'Twenty-one interactive Windows application evidence checks passed.'
