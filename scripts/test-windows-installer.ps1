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
# ISCC 6.7.1 has no version-only switch and its console loader has no
# reliable PE version resource. Verify the engine banner from compilation.
$recordPath=Join-Path $project 'build\installer-checks'
[void](New-Item -ItemType Directory -Force -Path $recordPath)
$compileLog=Join-Path $recordPath 'compiler.log'
$version='0.1.0-alpha'
$compileOutput=@(& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -Compiler $Compiler -Go $Go -Version $version | Tee-Object -FilePath $compileLog)
$versionMatch=[regex]::Match(($compileOutput -join "`n"),'(?im)^Compiler engine version:\s*Inno Setup\s+(\d+\.\d+\.\d+)\b')
if(-not $versionMatch.Success){throw 'Could not determine the Inno Setup compiler-engine version from the compilation log'}
$actualVersion=$versionMatch.Groups[1].Value
if($actualVersion -ne $ExpectedCompilerVersion){throw ('Expected Inno Setup '+$ExpectedCompilerVersion+' but runner provides '+$actualVersion+'; review the image/compiler update before changing the pin')}
$artifact=Join-Path $project ('build\accessweaver-'+$version+'-windows-amd64-setup.exe')
if(-not (Test-Path -LiteralPath $artifact -PathType Leaf)){throw 'Compiler produced no installer artifact'}
$record=[ordered]@{
    schemaVersion=1
    compilerVersion=$actualVersion
    compilerVersionSource='ISCC compiler-engine compilation banner'
    compilerSha256=(Get-FileHash -LiteralPath $Compiler -Algorithm SHA256).Hash.ToLowerInvariant()
    compilerPath=$Compiler
    installerName=[IO.Path]::GetFileName($artifact)
    installerSha256=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    installerBytes=(Get-Item -LiteralPath $artifact).Length
    installed=$false
    unsigned=$true
    qualification='Compilation only; native install/upgrade/rollback/uninstall qualification remains required'
}
$record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $recordPath 'compiler-artifact.json') -Encoding UTF8
Write-Output 'Unsigned installer compiled. It was not executed.'
