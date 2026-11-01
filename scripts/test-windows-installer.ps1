# Compile an unsigned candidate and record compiler/artifact identity. This does
# not install/uninstall anything or invoke machine maintenance operations.
[CmdletBinding()]
param([string]$ExpectedCompilerVersion='6.7.1',[string]$Compiler,[string]$Go='go')
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
if(-not $Compiler){
    $Compiler=Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
}
$Compiler=(Resolve-Path -LiteralPath $Compiler -ErrorAction Stop).Path
$info=(Get-Item -LiteralPath $Compiler).VersionInfo
$actualVersion='{0}.{1}.{2}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart
if($actualVersion -ne $ExpectedCompilerVersion){throw ('Expected Inno Setup '+$ExpectedCompilerVersion+' but runner provides '+$actualVersion+'; review the image/compiler update before changing the pin')}
$version='0.1.0-alpha'
& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -Compiler $Compiler -Go $Go -Version $version
$artifact=Join-Path $project ('build\accessweaver-'+$version+'-windows-amd64-setup.exe')
if(-not (Test-Path -LiteralPath $artifact -PathType Leaf)){throw 'Compiler produced no installer artifact'}
$record=[ordered]@{
    schemaVersion=1
    compilerVersion=$actualVersion
    compilerSha256=(Get-FileHash -LiteralPath $Compiler -Algorithm SHA256).Hash.ToLowerInvariant()
    compilerPath=$Compiler
    installerName=[IO.Path]::GetFileName($artifact)
    installerSha256=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    installerBytes=(Get-Item -LiteralPath $artifact).Length
    installed=$false
    unsigned=$true
    qualification='Compilation only; native install/upgrade/rollback/uninstall qualification remains required'
}
$recordPath=Join-Path $project 'build\installer-checks'
[void](New-Item -ItemType Directory -Force -Path $recordPath)
$record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $recordPath 'compiler-artifact.json') -Encoding UTF8
Write-Output 'Unsigned installer compiled. It was not executed.'
