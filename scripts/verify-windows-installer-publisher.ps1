[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Artifact,
    [Parameter(Mandatory=$true)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$ArtifactSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$PublisherCertificateSHA256
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')

try {
    if($env:OS -cne 'Windows_NT'){throw 'Windows is required for Authenticode verification'}
    $absolute=[IO.Path]::GetFullPath($Artifact)
    if($absolute -notmatch '\A[A-Za-z]:\\[^:*?"<>|\x00-\x1f]+\.(exe|msi)\z'){
        throw 'Expected a local Windows executable or MSI path'
    }
    $entry=Get-Item -LiteralPath $absolute -Force
    if($entry.PSIsContainer){throw 'Expected an artifact file'}
    for($path=$absolute;$path;$path=[IO.Path]::GetDirectoryName($path)){
        $item=Get-Item -LiteralPath $path -Force
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Artifact path includes a reparse point'}
        if($path -ieq [IO.Path]::GetPathRoot($path)){break}
    }
    $file=[IO.File]::Open($absolute,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($file.Length -le 0 -or $file.Length -gt 512MB){throw 'Artifact is outside the verification size limit'}
        $actual=(Get-FileHash -InputStream $file -Algorithm SHA256).Hash
        if($actual -ine $ArtifactSHA256){throw 'Artifact digest differs from the approved release digest'}
        $signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $absolute
        Assert-WindowsPublisherSignature $signature $PublisherCertificateSHA256
    } finally {$file.Dispose()}
    [ordered]@{
        schemaVersion=1
        scope='windows-publisher-signature'
        artifactSHA256=$actual.ToLowerInvariant()
        publisherCertificateSHA256=$PublisherCertificateSHA256.ToLowerInvariant()
        embeddedSignatureVerified=$true
        timestampPresent=$true
    } | ConvertTo-Json -Compress
} catch {
    [Console]::Error.WriteLine('Windows publisher verification failed. Check the approved digests, local artifact, Windows trust and timestamp.')
    exit 1
}
