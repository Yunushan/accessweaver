# Build from this source checkout into .\bin; no system installation.
[CmdletBinding()]
param([switch]$Run)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw 'Install Go from https://go.dev/dl/ and rerun this script.'
    }
    New-Item -ItemType Directory -Force -Path bin | Out-Null
    go build -trimpath -o bin/accessweaver.exe ./cmd/accessweaver
    if ($LASTEXITCODE -ne 0) { throw "Go build failed with exit code $LASTEXITCODE." }
    Write-Host 'Built bin\accessweaver.exe. Start with: .\bin\accessweaver.exe ui'
    if ($Run) {
        & .\bin\accessweaver.exe ui
        if ($LASTEXITCODE -ne 0) { throw "AccessWeaver exited with code $LASTEXITCODE." }
    }
} finally {
    Pop-Location
}
