[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Compiler,
    [string]$Version='0.1.0-alpha',
    [string]$Go='go',
    [ValidateSet('amd64','arm64')][string]$TargetArch,
    [string]$SigningTool,
    [string]$PublisherCertificateSHA256
)
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')
Assert-InstallerReleaseVersion $Version
$callback=Join-Path $PSScriptRoot 'sign-windows-installer-artifact.ps1'
$signingArguments=@()
$organizationSigning=[bool]($SigningTool -or $PublisherCertificateSHA256)
if($organizationSigning){
    $shell=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $signingArguments=@(Get-InstallerSigningArguments $SigningTool $PublisherCertificateSHA256 $shell $callback)
    $signingToolItem=Get-Item -LiteralPath $SigningTool -Force
    if($signingToolItem.PSIsContainer -or ($signingToolItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'The approved signer must be a regular executable'
    }
}
$sdkJSON=& $Go env -json GOHOSTOS GOHOSTARCH GOVERSION
if($LASTEXITCODE -ne 0){throw 'Cannot inspect the installer Go SDK host'}
$sdk=($sdkJSON -join "`n") | ConvertFrom-Json
$TargetArch=Resolve-InstallerTarget $sdk.GOHOSTOS $sdk.GOHOSTARCH $TargetArch
$stage=Join-Path $project ('build\installer-'+$TargetArch+'-'+[guid]::NewGuid().ToString('N'))
if($organizationSigning){
    $signingRoot=$stage
    $stage=Join-Path $signingRoot 'payload'
    [void](New-Item -ItemType Directory -Path (Join-Path $signingRoot 'signed-uninstallers') -Force)
}
[void](New-Item -ItemType Directory -Force -Path $stage)
Push-Location $project
$previousOS=$env:GOOS;$previousArch=$env:GOARCH;$previousCGO=$env:CGO_ENABLED
$previousSigner=$env:ACCESSWEAVER_BUILD_SIGNER
$previousPublisher=$env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256
try {
    $env:GOOS='windows';$env:GOARCH=$TargetArch;$env:CGO_ENABLED='0'
    $commit='unknown';$sourceState='unknown'
    if(Get-Command git -ErrorAction SilentlyContinue){
        $revision=& git rev-parse HEAD 2>$null
        if($LASTEXITCODE -eq 0 -and $revision -match '^[a-f0-9]{40,64}$'){
            $commit=$revision;$sourceState='clean'
            $changes=& git status --porcelain --untracked-files=normal
            if($LASTEXITCODE -ne 0){throw 'Cannot determine source modification state'}
            if($changes){$sourceState='modified'}
        }
    }
    if($organizationSigning -and $sourceState -cne 'clean'){throw 'Organization signing requires a clean source checkout'}
    $builtAt=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $flags='-X github.com/Yunushan/accessweaver/internal/buildinfo.Version='+$Version+' -X github.com/Yunushan/accessweaver/internal/buildinfo.Commit='+$commit+' -X github.com/Yunushan/accessweaver/internal/buildinfo.SourceState='+$sourceState+' -X github.com/Yunushan/accessweaver/internal/buildinfo.BuiltAt='+$builtAt
    & $Go build -trimpath -buildvcs=false -ldflags $flags -o (Join-Path $stage 'accessweaver.exe') ./cmd/accessweaver
    if($LASTEXITCODE -ne 0){throw 'Go build failed'}
    Assert-InstallerPEArchitecture (Join-Path $stage 'accessweaver.exe') $TargetArch
    $payload=Join-Path $stage 'accessweaver.exe'
    if($organizationSigning){
        $env:ACCESSWEAVER_BUILD_SIGNER=$SigningTool
        $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256=$PublisherCertificateSHA256
        & $callback -Artifact $payload
    }
    $identity=& $payload version --json
    if($LASTEXITCODE -ne 0){throw 'Cannot read staged runtime build identity'}
    $buildIdentity=($identity -join "`n") | ConvertFrom-Json
    Assert-InstallerPayloadIdentity (Join-Path $stage 'accessweaver.exe') $buildIdentity @{version=$Version;commit=$commit;sourceState=$sourceState;builtAt=$builtAt;goVersion=$sdk.GOVERSION;platform='windows';arch=$TargetArch}
    [IO.File]::WriteAllText((Join-Path $stage 'BUILD-INFO.json'),($identity -join "`n"))
    foreach($file in @('LICENSE','README.md','README.tr.md','THIRD_PARTY.md','SECURITY.md')){Copy-Item -LiteralPath (Join-Path $project $file) -Destination $stage}
    Copy-Item -LiteralPath (Join-Path $project 'docs') -Destination (Join-Path $stage 'docs') -Recurse
    [void](New-Item -ItemType Directory -Path (Join-Path $stage 'licenses'))
    Copy-Item -LiteralPath (Join-Path $project 'internal\workflow\presets\LICENSE.SplitWire-Turkey') -Destination (Join-Path $stage 'licenses\SplitWire-Turkey-MIT.txt')
    $goRoot=& $Go env GOROOT
    if($LASTEXITCODE -ne 0){throw 'Could not locate Go runtime license'}
    Copy-Item -LiteralPath (Join-Path $goRoot 'LICENSE') -Destination (Join-Path $stage 'licenses\Go-runtime-LICENSE')
    # An upgraded installation can retain an older Inno uninstaller.
    [IO.File]::WriteAllText((Join-Path $stage 'uninstall-system.json'),'{"action":"remove-all"}')
    $compilerLicense=Join-Path (Split-Path -Parent $Compiler) 'License.txt'
    if(-not (Test-Path -LiteralPath $compilerLicense -PathType Leaf)){throw 'Inno Setup license evidence is missing'}
    Copy-Item -LiteralPath $compilerLicense -Destination (Join-Path $stage 'licenses\Inno-Setup-License.txt')
    $validator=Join-Path $project ('build\tools\sbom-schema-'+$TargetArch+'.exe')
    & $Go -C (Join-Path $project 'scripts\sbom-tools') build -mod=readonly -trimpath -o $validator .
    if($LASTEXITCODE -ne 0){throw 'SBOM validator build failed'}
    $payloadSBOM=Join-Path $stage 'SBOM.cdx.json'
    & python (Join-Path $project 'scripts\sbom.py') --binary (Join-Path $stage 'accessweaver.exe') --module-root $project --main ./cmd/accessweaver --identity (Join-Path $stage 'BUILD-INFO.json') --notices (Join-Path $stage 'licenses') --out $payloadSBOM --go $Go
    if($LASTEXITCODE -ne 0){throw 'Installer payload SBOM generation failed'}
    & $validator --schemas (Join-Path $project 'scripts\sbom\schema') $payloadSBOM
    if($LASTEXITCODE -ne 0){throw 'Installer payload SBOM validation failed'}
    $evidence=Join-Path $project ('build\installer-checks\'+$TargetArch)
    if($organizationSigning){$evidence=Join-Path $signingRoot 'evidence'}
    [void](New-Item -ItemType Directory -Force -Path $evidence)
    $preprocessed=Join-Path $evidence 'setup-preprocessed.iss'
    $compilerOutput=@(& $Compiler ('/DBuildRoot='+$stage) ('/DReleaseVersion='+$Version) ('/DTargetArch='+$TargetArch) ('/DEvidenceOutput='+$preprocessed) @signingArguments (Join-Path $PSScriptRoot 'windows-installer.iss'))
    if($LASTEXITCODE -ne 0){throw 'Installer compilation failed'}
    $null=Assert-InstallerSetupScript $preprocessed $TargetArch $Version -OrganizationSigning:$organizationSigning
    $compilerOutput | Write-Output
    $actualVersion=[regex]::Match(($compilerOutput -join "`n"),'(?im)^Compiler engine version:\s*Inno Setup\s+(\d+\.\d+\.\d+)\b')
    if(-not $actualVersion.Success){throw 'Could not identify installer compiler version'}
    $artifact=Join-Path $project ('build\accessweaver-'+$Version+'-windows-'+$TargetArch+'-setup.exe')
    if($organizationSigning){
        $artifact=Join-Path (Join-Path $signingRoot 'signed') ([IO.Path]::GetFileName($artifact))
        Assert-WindowsPublisherSignature (Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $artifact) $PublisherCertificateSHA256
    }
    & python (Join-Path $project 'scripts\sbom.py') --binary $artifact --payload-sbom $payloadSBOM --compiler $Compiler --compiler-version $actualVersion.Groups[1].Value --compiler-license $compilerLicense --notices (Join-Path $stage 'licenses') --out ($artifact+'.cdx.json')
    if($LASTEXITCODE -ne 0){throw 'Installer SBOM generation failed'}
    & $validator --schemas (Join-Path $project 'scripts\sbom\schema') ($artifact+'.cdx.json')
    if($LASTEXITCODE -ne 0){throw 'Installer SBOM validation failed'}
    Copy-Item -LiteralPath $payloadSBOM -Destination (Join-Path $evidence 'payload-SBOM.cdx.json') -Force
    Copy-Item -LiteralPath (Join-Path $stage 'BUILD-INFO.json') -Destination (Join-Path $evidence 'payload-BUILD-INFO.json') -Force
    Copy-Item -LiteralPath (Join-Path $stage 'accessweaver.exe') -Destination (Join-Path $evidence 'payload.exe') -Force
    Copy-Item -LiteralPath (Join-Path $stage 'licenses') -Destination $evidence -Recurse -Force
    $artifactHash=Get-FileHash -LiteralPath $artifact -Algorithm SHA256
    if($organizationSigning){
        $signingReceipt=[ordered]@{
            schemaVersion=1
            scope='windows-organization-signed-installer-build'
            sourceCommit=$commit
            target='windows/'+$TargetArch
            version=$Version
            installerSHA256=$artifactHash.Hash.ToLowerInvariant()
            payloadSHA256=(Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant()
            publisherCertificateSHA256=$PublisherCertificateSHA256.ToLowerInvariant()
            productionQualificationComplete=$false
        }
        [IO.File]::WriteAllText((Join-Path $evidence 'publisher-signing.json'),($signingReceipt | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    }
    $artifactHash
} finally {
    $env:GOOS=$previousOS;$env:GOARCH=$previousArch;$env:CGO_ENABLED=$previousCGO
    $env:ACCESSWEAVER_BUILD_SIGNER=$previousSigner
    $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256=$previousPublisher
    Pop-Location
}
