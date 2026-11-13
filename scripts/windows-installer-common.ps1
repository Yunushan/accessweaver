# Installer build and verification checks. These helpers never install software or change the OS.
function Assert-InstallerReleaseVersion([string]$Version) {
    if($Version.Length -gt 256){throw 'Installer release version exceeds 256 characters'}
    $match=[regex]::Match($Version,'\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z')
    if(-not $match.Success){throw 'Expected a canonical semantic release version without a tag prefix'}
    foreach($identifier in ($match.Groups['pre'].Value -split '\.')){
        if($identifier -cmatch '\A[0-9]+\z' -and $identifier.Length -gt 1 -and $identifier[0] -eq '0'){throw 'Numeric prerelease identifiers cannot contain leading zeroes'}
    }
}

function Resolve-InstallerTarget([string]$HostOS, [string]$HostArch, [string]$TargetArch) {
    if($HostOS -cne 'windows' -or $HostArch -cnotin @('amd64','arm64')){throw 'Installer verification requires a Windows amd64 or arm64 Go SDK'}
    if(-not $TargetArch){$TargetArch=$HostArch}
    if($TargetArch -cnotin @('amd64','arm64') -or $TargetArch -cne $HostArch){throw 'Installer payload target must match the Go SDK host architecture so its identity can be executed'}
    return $TargetArch
}

function Read-InstallerPEMachine([string]$Path) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $reader=[IO.BinaryReader]::new($stream)
    try {
        if($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d){throw 'Installer input has no DOS executable header'}
        $stream.Position=0x3c
        $offset=$reader.ReadUInt32()
        if($offset -lt 64 -or $offset -gt ($stream.Length-6)){throw 'Installer input has an invalid PE header offset'}
        $stream.Position=$offset
        if($reader.ReadUInt32() -ne 0x00004550){throw 'Installer input has no PE signature'}
        return $reader.ReadUInt16()
    } finally { $reader.Dispose() }
}

function Assert-InstallerPayloadIdentity([string]$Binary, [object]$Identity, [hashtable]$Expected) {
    $arch=$Expected.arch
    if($Expected.platform -cne 'windows' -or $arch -cnotin @('amd64','arm64')){throw 'Invalid expected installer payload target'}
    Assert-InstallerPEArchitecture $Binary $arch
    foreach($key in @('version','commit','sourceState','builtAt','goVersion','platform','arch')){
        if(-not $Expected.ContainsKey($key) -or -not $Expected[$key] -or [string]$Identity.$key -cne [string]$Expected[$key]){throw ('Installer payload build identity mismatch: '+$key)}
    }
}

function Assert-InstallerPEArchitecture([string]$Binary, [string]$Arch) {
    if($Arch -cnotin @('amd64','arm64')){throw 'Invalid expected installer payload architecture'}
    $machine=Read-InstallerPEMachine $Binary
    $expectedMachine=if($Arch -ceq 'arm64'){0xaa64}else{0x8664}
    if($machine -ne $expectedMachine){throw 'Installer payload PE machine does not match its requested architecture'}
}

function Assert-InstallerSetupScript([string]$Path, [string]$TargetArch, [string]$Version, [switch]$OrganizationSigning) {
    if($TargetArch -cnotin @('amd64','arm64')){throw 'Invalid installer script target'}
    if((Get-Item -LiteralPath $Path).Length -gt 1MB){throw 'Preprocessed installer script exceeds evidence limit'}
    $architecture=if($TargetArch -ceq 'arm64'){'arm64'}else{'x64compatible'}
    $expected=@{SetupMutex='Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092';AllowNoIcons='yes';ArchitecturesAllowed=$architecture;ArchitecturesInstallIn64BitMode=$architecture;OutputBaseFilename=('accessweaver-'+$Version+'-windows-'+$TargetArch+'-setup')}
    if($OrganizationSigning){
        $expected.SignTool='accessweaverOrganization'
        $expected.SignedUninstaller='yes'
    }
    $actual=@{};$section=''
    foreach($line in [IO.File]::ReadAllLines($Path)){
        if($line -match '^\s*\[([^]]+)\]\s*$'){$section=$matches[1];continue}
        if($section -ieq 'Setup' -and $line -match '^\s*([^=;]+?)\s*=(.*)$'){
            $name=$matches[1].Trim();$value=$matches[2].Trim()
            if($expected.ContainsKey($name)){
                if($actual.ContainsKey($name)){throw 'Duplicate required directive in preprocessed installer'}
                $actual[$name]=$value
            }
        }
    }
    foreach($key in $expected.Keys){if($actual[$key] -cne $expected[$key]){throw ('Preprocessed installer directive mismatch: '+$key)}}
    return $actual
}

function Assert-WindowsPublisherSignature($Signature,[string]$PublisherCertificateSHA256) {
    if($PublisherCertificateSHA256 -cnotmatch '\A[a-fA-F0-9]{64}\z'){
        throw 'Expected a SHA-256 fingerprint of the approved publisher certificate'
    }
    if($null -eq $Signature -or $Signature.Status -ne 'Valid' -or
        $Signature.SignatureType -ne 'Authenticode' -or
        $null -eq $Signature.SignerCertificate -or $null -eq $Signature.TimeStamperCertificate){
        throw 'Artifact requires a Windows-valid embedded Authenticode signature and timestamp'
    }
    $certificateBytes=$Signature.SignerCertificate.RawData
    if($certificateBytes -isnot [byte[]] -or $certificateBytes.Length -eq 0 -or $certificateBytes.Length -gt 64KB){
        throw 'Artifact publisher certificate could not be verified'
    }
    $sha256=[Security.Cryptography.SHA256]::Create()
    try {
        $actual=[BitConverter]::ToString($sha256.ComputeHash($certificateBytes)).Replace('-','')
    } finally {$sha256.Dispose()}
    if($actual -ine $PublisherCertificateSHA256){throw 'Artifact publisher certificate differs from the approved certificate'}
}

function Get-InstallerSigningArguments([string]$SigningTool, [string]$PublisherCertificateSHA256, [string]$Shell, [string]$Callback) {
    if(-not $SigningTool -and -not $PublisherCertificateSHA256){return}
    if($PublisherCertificateSHA256 -cnotmatch '\A[a-fA-F0-9]{64}\z' -or
        $SigningTool -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|$%\x00-\x1f]+\.exe\z'){
        throw 'Signing requires an absolute local signer executable and an approved publisher SHA-256'
    }
    foreach($path in @($Shell,$Callback)){
        if($path -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|$%\x00-\x1f]+\.(exe|ps1)\z'){
            throw 'Inno signing requires local PowerShell and callback paths'
        }
    }
    '/DOrganizationSigning=1'
    ('/SaccessweaverOrganization=$q'+$Shell+'$q -NoProfile -NonInteractive -File $q'+$Callback+'$q -Artifact $f')
}

function Get-InstallerSigningLayout([IO.BinaryReader]$Reader) {
    $stream=$Reader.BaseStream
    if($stream.Length -lt 64 -or $stream.Length -gt 512MB -or $Reader.ReadUInt16() -ne 0x5a4d){
        throw 'Invalid installer signing input'
    }
    $stream.Position=60
    $pe=[long]$Reader.ReadUInt32()
    if($pe -lt 64 -or $pe -gt $stream.Length-24){throw 'Invalid installer PE offset'}
    $stream.Position=$pe
    if($Reader.ReadUInt32() -ne 0x4550){throw 'Invalid installer PE signature'}
    $stream.Position=$pe+20
    $optionalSize=$Reader.ReadUInt16()
    $optional=$pe+24
    if($optionalSize -lt 136 -or $optional+$optionalSize -gt $stream.Length){throw 'Invalid installer optional header'}
    $stream.Position=$optional
    $directories=switch($Reader.ReadUInt16()){
        0x10b {96}
        0x20b {112}
        default {throw 'Unknown installer PE format'}
    }
    if($optionalSize -lt $directories+40){throw 'Missing installer certificate directory'}
    $stream.Position=$optional+$directories-4
    if($Reader.ReadUInt32() -lt 5){throw 'Missing installer certificate directory'}
    $certificateField=$optional+$directories+32
    $stream.Position=$certificateField
    return @{
        checksum=$optional+64
        certificateField=$certificateField
        certificateOffset=[long]$Reader.ReadUInt32()
        certificateSize=[long]$Reader.ReadUInt32()
    }
}

function Assert-InstallerSigningOnlyChange([string]$Original,[string]$Signed) {
    $before=[IO.BinaryReader]::new([IO.File]::Open($Original,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
    try {
        $after=[IO.BinaryReader]::new([IO.File]::Open($Signed,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
        try {
            $source=Get-InstallerSigningLayout $before
            $target=Get-InstallerSigningLayout $after
            $originalLength=$before.BaseStream.Length
            $padding=(8-($originalLength%8))%8
            if($source.certificateOffset -ne 0 -or $source.certificateSize -ne 0 -or
                $source.checksum -ne $target.checksum -or $source.certificateField -ne $target.certificateField -or
                $target.certificateOffset -ne $originalLength+$padding -or $target.certificateSize -le 8 -or
                $target.certificateOffset+$target.certificateSize -ne $after.BaseStream.Length){
                throw 'Signer did not append a certificate table to the original unsigned PE'
            }

            $before.BaseStream.Position=0
            $after.BaseStream.Position=0
            $beforeHash=[Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
            $afterHash=[Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
            try {
                foreach($segment in @(
                    @{start=0;end=$source.checksum},
                    @{start=$source.checksum+4;end=$source.certificateField},
                    @{start=$source.certificateField+8;end=$originalLength}
                )){
                    $before.BaseStream.Position=$segment.start
                    $after.BaseStream.Position=$segment.start
                    $remaining=$segment.end-$segment.start
                    while($remaining -gt 0){
                        $size=[int][Math]::Min($remaining,1MB)
                        $sourceBytes=$before.ReadBytes($size)
                        $targetBytes=$after.ReadBytes($size)
                        if($sourceBytes.Length -ne $size -or $targetBytes.Length -ne $size){throw 'Incomplete installer signing comparison'}
                        $beforeHash.AppendData($sourceBytes)
                        $afterHash.AppendData($targetBytes)
                        $remaining-=$size
                    }
                }
                $sourceDigest=[BitConverter]::ToString($beforeHash.GetHashAndReset())
                $targetDigest=[BitConverter]::ToString($afterHash.GetHashAndReset())
                if($sourceDigest -cne $targetDigest){throw 'Signer modified non-signature installer bytes'}
            } finally {$beforeHash.Dispose();$afterHash.Dispose()}

            $after.BaseStream.Position=$originalLength
            for($index=0;$index -lt $padding;$index++){
                if($after.ReadByte() -ne 0){throw 'Unexpected nonzero certificate alignment bytes'}
            }
        } finally {$after.Dispose()}
    } finally {$before.Dispose()}
}
