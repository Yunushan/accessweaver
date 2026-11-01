[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Compiler, [string]$Version='0.1.0-alpha', [string]$Go='go')
$ErrorActionPreference='Stop'
if($Version -notmatch '^\d+\.\d+\.\d+([.-][a-zA-Z0-9.-]+)?$'){throw 'Expected a semantic release version'}
$project=Split-Path -Parent $PSScriptRoot
$stage=Join-Path $project ('build\installer-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Force -Path $stage)
Push-Location $project
$previousOS=$env:GOOS;$previousArch=$env:GOARCH;$previousCGO=$env:CGO_ENABLED
try {
    $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
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
    $builtAt=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $flags='-X github.com/Yunushan/accessweaver/internal/buildinfo.Version='+$Version+' -X github.com/Yunushan/accessweaver/internal/buildinfo.Commit='+$commit+' -X github.com/Yunushan/accessweaver/internal/buildinfo.SourceState='+$sourceState+' -X github.com/Yunushan/accessweaver/internal/buildinfo.BuiltAt='+$builtAt
    & $Go build -trimpath -buildvcs=false -ldflags $flags -o (Join-Path $stage 'accessweaver.exe') ./cmd/accessweaver
    if($LASTEXITCODE -ne 0){throw 'Go build failed'}
    $identity=& (Join-Path $stage 'accessweaver.exe') version --json
    if($LASTEXITCODE -ne 0){throw 'Cannot read staged runtime build identity'}
    [IO.File]::WriteAllText((Join-Path $stage 'BUILD-INFO.json'),($identity -join "`n"))
    foreach($file in @('LICENSE','README.md','README.tr.md','THIRD_PARTY.md','SECURITY.md')){Copy-Item -LiteralPath (Join-Path $project $file) -Destination $stage}
    Copy-Item -LiteralPath (Join-Path $project 'docs') -Destination (Join-Path $stage 'docs') -Recurse
    [void](New-Item -ItemType Directory -Path (Join-Path $stage 'licenses'))
    Copy-Item -LiteralPath (Join-Path $project 'internal\workflow\presets\LICENSE.SplitWire-Turkey') -Destination (Join-Path $stage 'licenses\SplitWire-Turkey-MIT.txt')
    $goRoot=& $Go env GOROOT
    if($LASTEXITCODE -ne 0){throw 'Could not locate Go runtime license'}
    Copy-Item -LiteralPath (Join-Path $goRoot 'LICENSE') -Destination (Join-Path $stage 'licenses\Go-runtime-LICENSE')
    [IO.File]::WriteAllText((Join-Path $stage 'uninstall-system.json'),'{"action":"remove-all"}')
    & $Compiler ('/DBuildRoot='+$stage) ('/DReleaseVersion='+$Version) (Join-Path $PSScriptRoot 'windows-installer.iss')
    if($LASTEXITCODE -ne 0){throw 'Installer compilation failed'}
    $artifact=Join-Path $project ('build\accessweaver-'+$Version+'-windows-amd64-setup.exe')
    Get-FileHash -LiteralPath $artifact -Algorithm SHA256
} finally { $env:GOOS=$previousOS;$env:GOARCH=$previousArch;$env:CGO_ENABLED=$previousCGO;Pop-Location }
