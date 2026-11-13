# Load only the process and discovery predicates from the interactive fixture.
$ErrorActionPreference='Stop'
$fixture=Join-Path $PSScriptRoot 'test-windows-apps.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($fixture,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Interactive Windows app fixture failed parsing'}
foreach($name in @('Test-FixtureAppProcess','Get-FixtureAppImage')){
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
if(-not (Test-FixtureAppProcess $image 7 @($wrongSession,$valid,$wrongPath))){throw 'Exact live desktop process was missed'}
if(Test-FixtureAppProcess $image 7 @($wrongSession,$wrongPath,$exited,$unavailable)){throw 'Unrelated or exited process was accepted'}
if(Test-FixtureAppProcess $image 7 @()){throw 'Empty process inventory matched'}
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
Write-Output 'Ten interactive Windows application evidence checks passed.'
