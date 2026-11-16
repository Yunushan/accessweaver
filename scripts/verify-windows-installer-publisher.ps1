[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Artifact,
    [Parameter(Mandatory=$true)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$ArtifactSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$PublisherCertificateSHA256
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')

try {
    $actual=Get-WindowsPublisherArtifactSHA256 $Artifact $PublisherCertificateSHA256 $ArtifactSHA256
    [ordered]@{
        schemaVersion=1
        scope='windows-publisher-signature'
        artifactSHA256=$actual.ToLowerInvariant()
        publisherCertificateSHA256=$PublisherCertificateSHA256.ToLowerInvariant()
        embeddedSignatureVerified=$true
        timestampPresent=$true
    } | ConvertTo-Json -Compress
    exit 0
} catch {
    [Console]::Error.WriteLine('Windows publisher verification failed. Check the approved digests, local artifact, Windows trust and timestamp.')
    exit 1
}
