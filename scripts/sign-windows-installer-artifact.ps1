# Called directly for the payload and by Inno Setup for setup and uninstall.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Artifact)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')

$signer=$env:ACCESSWEAVER_BUILD_SIGNER
$publisher=$env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256
if($signer -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|$%\x00-\x1f]+\.exe\z' -or
    $publisher -cnotmatch '\A[a-fA-F0-9]{64}\z'){
    throw 'The installer build signing context is unavailable'
}
$absolute=[IO.Path]::GetFullPath($Artifact)
# Inno gives the uninstaller a .tmp suffix. Give the signer a PE filename
# and return only verified bytes to the compiler.
$directory=[IO.Path]::GetDirectoryName($absolute)
$candidate=Join-Path $directory ('sign-'+[guid]::NewGuid().ToString('N')+'.exe')
$original=[IO.File]::Open($absolute,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
    [IO.File]::Copy($absolute,$candidate,$false)
    try {
        & $signer $candidate | Out-Null
        if($LASTEXITCODE -ne 0){throw 'The organization signer failed for an installer artifact'}
        $signed=[IO.File]::Open($candidate,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            Assert-InstallerSigningStreamOnlyChange $original $signed
            $original.Position=0
            $signed.Position=0
            $originalSHA256=(Microsoft.PowerShell.Utility\Get-FileHash -InputStream $original -Algorithm SHA256).Hash
            $expectedSignedSHA256=(Microsoft.PowerShell.Utility\Get-FileHash -InputStream $signed -Algorithm SHA256).Hash
            $signedSHA256=Get-WindowsPublisherArtifactSHA256 $candidate $publisher $expectedSignedSHA256
        } finally {$signed.Dispose()}
        $original.Dispose()
        Complete-InstallerSigning $absolute $originalSHA256 $candidate $signedSHA256
    } finally {[IO.File]::Delete($candidate)}
} finally {$original.Dispose()}
