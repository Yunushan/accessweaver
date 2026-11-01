# Optional third-party test fixture build; these dependencies are not core dependencies.
param([string]$Go='go',[string]$Output='build\vm-tests\sandbox\bundle')
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
$destination=[IO.Path]::GetFullPath((Join-Path $project $Output))
if(-not $destination.StartsWith(([IO.Path]::GetFullPath((Join-Path $project 'build'))+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture output must stay under the project build directory'}
[void](New-Item -ItemType Directory -Force -Path $destination)
$compiler=(Get-Command $Go -ErrorAction Stop).Source
$oldOS=$env:GOOS;$oldArch=$env:GOARCH;$oldCGO=$env:CGO_ENABLED
Push-Location (Join-Path $PSScriptRoot 'fixtures\wgpeer')
try{
    $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
    & $compiler mod download
    if($LASTEXITCODE -ne 0){throw 'Fixture dependency verification failed'}
    & $compiler build -trimpath -buildvcs=false -o (Join-Path $destination 'wgpeer.exe') .
    if($LASTEXITCODE -ne 0){throw 'WireGuard fixture build failed'}
    & $compiler build -trimpath -buildvcs=false -o (Join-Path $destination 'probe-selected.exe') ./cmd/probe
    if($LASTEXITCODE -ne 0){throw 'Network probe build failed'}
    Copy-Item -LiteralPath (Join-Path $destination 'probe-selected.exe') -Destination (Join-Path $destination 'probe-direct.exe') -Force
    $notices=Join-Path $destination 'fixture-licenses';[void](New-Item -ItemType Directory -Force -Path $notices)
    $modules=& $compiler list -m -f '{{.Path}}|{{.Dir}}' all
    if($LASTEXITCODE -ne 0){throw 'Could not enumerate fixture license sources'}
    foreach($line in $modules){$parts=$line.Split('|',2);if($parts.Length -ne 2 -or -not $parts[1]){continue};foreach($name in @('LICENSE','LICENSE.txt','COPYING','COPYRIGHT','NOTICE')){$path=Join-Path $parts[1] $name;if(Test-Path -LiteralPath $path){Copy-Item -LiteralPath $path -Destination (Join-Path $notices (($parts[0] -replace '[^a-zA-Z0-9.-]','_')+'-'+$name)) -Force}}}
    $goRoot=& $compiler env GOROOT
    if($LASTEXITCODE -ne 0){throw 'Could not locate Go runtime license'}
    Copy-Item -LiteralPath (Join-Path $goRoot 'LICENSE') -Destination (Join-Path $notices 'Go-runtime-LICENSE') -Force
    Copy-Item -LiteralPath (Join-Path $project 'LICENSE') -Destination (Join-Path $notices 'AccessWeaver-0BSD.txt') -Force
    foreach($name in @('go.mod','go.sum','README.md')){Copy-Item -LiteralPath $name -Destination (Join-Path $notices $name) -Force}
    $validator=Join-Path $project 'build\tools\sbom-schema.exe'
    & $compiler -C (Join-Path $project 'scripts\sbom-tools') build -mod=readonly -trimpath -o $validator .
    if($LASTEXITCODE -ne 0){throw 'SBOM validator build failed'}
    foreach($entry in @(@('wgpeer.exe','.'),@('probe-selected.exe','./cmd/probe'),@('probe-direct.exe','./cmd/probe'))){
        $binary=Join-Path $destination $entry[0]
        $sbom=$binary+'.cdx.json'
        & python (Join-Path $project 'scripts\sbom.py') --binary $binary --module-root $PWD.Path --main $entry[1] --fixture --notices $notices --out $sbom --go $compiler
        if($LASTEXITCODE -ne 0){throw 'Fixture SBOM generation failed'}
        & $validator --schemas (Join-Path $project 'scripts\sbom\schema') $sbom
        if($LASTEXITCODE -ne 0){throw 'Fixture SBOM schema validation failed'}
    }
    Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $destination 'wgpeer.exe'),(Join-Path $destination 'probe-selected.exe')
}finally{$env:GOOS=$oldOS;$env:GOARCH=$oldArch;$env:CGO_ENABLED=$oldCGO;Pop-Location}
