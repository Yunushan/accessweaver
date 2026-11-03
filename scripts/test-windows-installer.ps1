# Compile an unsigned candidate and record compiler/artifact identity. This does
# not install/uninstall anything or invoke machine maintenance operations.
[CmdletBinding()]
param([string]$ExpectedCompilerVersion='6.7.1',[string]$Compiler,[string]$Go='go',[ValidateSet('amd64','arm64')][string]$TargetArch,[string]$Version='0.1.0-alpha')
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')
& (Join-Path $PSScriptRoot 'test-windows-installer-contracts.ps1')
$sdkJSON=& $Go env -json GOHOSTOS GOHOSTARCH GOVERSION
if($LASTEXITCODE -ne 0){throw 'Cannot inspect the installer Go SDK host'}
$sdk=($sdkJSON -join "`n") | ConvertFrom-Json
$TargetArch=Resolve-InstallerTarget $sdk.GOHOSTOS $sdk.GOHOSTARCH $TargetArch
if(-not $Compiler){
    $Compiler=Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
}
$Compiler=(Resolve-Path -LiteralPath $Compiler -ErrorAction Stop).Path
# ISCC 6.7.1 has no version-only switch and its console loader has no
# reliable PE version resource. Verify the engine banner from compilation.
$recordPath=Join-Path $project ('build\installer-checks\'+$TargetArch)
[void](New-Item -ItemType Directory -Force -Path $recordPath)
$compileLog=Join-Path $recordPath 'compiler.log'
$compileOutput=@(& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -Compiler $Compiler -Go $Go -Version $version -TargetArch $TargetArch | Tee-Object -FilePath $compileLog)
$versionMatch=[regex]::Match(($compileOutput -join "`n"),'(?im)^Compiler engine version:\s*Inno Setup\s+(\d+\.\d+\.\d+)\b')
if(-not $versionMatch.Success){throw 'Could not determine the Inno Setup compiler-engine version from the compilation log'}
$actualVersion=$versionMatch.Groups[1].Value
if($actualVersion -ne $ExpectedCompilerVersion){throw ('Expected Inno Setup '+$ExpectedCompilerVersion+' but runner provides '+$actualVersion+'; review the image/compiler update before changing the pin')}
$artifact=Join-Path $project ('build\accessweaver-'+$version+'-windows-'+$TargetArch+'-setup.exe')
if(-not (Test-Path -LiteralPath $artifact -PathType Leaf)){throw 'Compiler produced no installer artifact'}
$payload=Join-Path $recordPath 'payload.exe'
$identity=Get-Content -LiteralPath (Join-Path $recordPath 'payload-BUILD-INFO.json') -Raw | ConvertFrom-Json
Assert-InstallerPayloadIdentity $payload $identity @{version=$version;commit=$identity.commit;sourceState=$identity.sourceState;builtAt=$identity.builtAt;goVersion=$sdk.GOVERSION;platform='windows';arch=$TargetArch}
$setupMachine=Read-InstallerPEMachine $artifact
# The pinned Inno Setup 6 compiler uses an x86 bootstrap for either payload.
if($setupMachine -ne 0x014c){throw 'Unexpected Inno Setup 6 bootstrap machine'}
$preprocessed=Join-Path $recordPath 'setup-preprocessed.iss'
$setup=Assert-InstallerSetupScript $preprocessed $TargetArch $version
$record=[ordered]@{
    schemaVersion=2
    sourceCommit=$identity.commit
    payloadTarget=('windows/'+$TargetArch)
    payloadPEMachine=('0x{0:x4}' -f (Read-InstallerPEMachine $payload))
    payloadSha256=(Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant()
    payloadBuild=$identity
    payloadExecutedForIdentity=$true
    installerBootstrapMachine=('0x{0:x4}' -f $setupMachine)
    installerArchitectureRequirement=$setup.ArchitecturesAllowed
    installer64BitModeRequirement=$setup.ArchitecturesInstallIn64BitMode
    preprocessedSetupSha256=(Get-FileHash -LiteralPath $preprocessed -Algorithm SHA256).Hash.ToLowerInvariant()
    productionQualificationComplete=$false
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
