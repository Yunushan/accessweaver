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
    Initialize-WindowsPublisherFileAccess
    $root=[IO.Path]::GetPathRoot($absolute)
    $parents=[Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $handle=$null
    $file=$null
    try {
        $parents.Add([AccessWeaver.PublisherFileAccess]::Open($root,$true))
        $volume=[AccessWeaver.PublisherFileAccess]::VolumeRoot($parents[0])
        $current=$volume
        $parent=[IO.Path]::GetDirectoryName($absolute)
        if($parent -ine $root){
            foreach($component in $parent.Substring($root.Length).Split('\')){
                $current=[IO.Path]::Combine($current,$component)
                $parents.Add([AccessWeaver.PublisherFileAccess]::Open($current,$true))
            }
        }
        $lockedPath=$volume+$absolute.Substring($root.Length)
        $handle=[AccessWeaver.PublisherFileAccess]::Open($lockedPath,$false)
        $file=[IO.FileStream]::new($handle,[IO.FileAccess]::Read)
        if($file.Length -le 0 -or $file.Length -gt 512MB){throw 'Artifact is outside the verification size limit'}
        $actual=(Microsoft.PowerShell.Utility\Get-FileHash -InputStream $file -Algorithm SHA256).Hash
        if($actual -ine $ArtifactSHA256){throw 'Artifact digest differs from the approved release digest'}
        $signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $lockedPath
        Assert-WindowsPublisherSignature $signature $PublisherCertificateSHA256
    } finally {
        try {
            if($null -ne $file){$file.Dispose()}
            elseif($null -ne $handle){$handle.Dispose()}
        } finally {
            for($i=$parents.Count-1;$i -ge 0;$i--){$parents[$i].Dispose()}
        }
    }
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
