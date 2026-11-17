# Installer build and verification checks. These helpers never install software or change the OS.
function Assert-InstallerReleaseVersion([string]$Version) {
    if($Version.Length -gt 256){throw 'Installer release version exceeds 256 characters'}
    $match=[regex]::Match($Version,'\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z')
    if(-not $match.Success){throw 'Expected a canonical semantic release version without a tag prefix'}
    foreach($identifier in ($match.Groups['pre'].Value -split '\.')){
        if($identifier -cmatch '\A[0-9]+\z' -and $identifier.Length -gt 1 -and $identifier[0] -eq '0'){throw 'Numeric prerelease identifiers cannot contain leading zeroes'}
    }
}

function Get-InstallerBuildTimestamp([string]$Epoch) {
    # Use the same bounds and UTC representation as the portable release build.
    $seconds=[uint32]0
    if($Epoch -cnotmatch '\A[0-9]{1,10}\z' -or -not [uint32]::TryParse($Epoch,[ref]$seconds)){
        throw 'SOURCE_DATE_EPOCH must be an integer between 0 and 4294967295'
    }
    return [DateTimeOffset]::FromUnixTimeSeconds($seconds).UtcDateTime.ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",[Globalization.CultureInfo]::InvariantCulture)
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

function Get-InstallerCompiledPayloadFingerprint([string]$CompiledFingerprint,[ref]$PayloadInventory) {
    $entries=[Collections.Generic.List[string]]::new()
    foreach($line in [regex]::Matches($CompiledFingerprint,"(?m)^[ \t]*Entries\.Add\('((?:[^'\r\n]|'')+)'\);[ \t]*\r?$")){
        $entry=$line.Groups[1].Value.Replace("''","'")
        $fields=$entry.Split('|')
        if($fields.Count -ne 3 -or -not $fields[0] -or
            $fields[1] -cnotmatch '\A[0-9]+\z' -or $fields[2] -cnotmatch '\A[a-fA-F0-9]{64}\z'){
            throw 'Compiled installer fingerprint contains an unsupported package path'
        }
        $entries.Add($entry)
    }
    if(-not $entries.Count){throw 'Compiled installer payload fingerprint is empty'}
    # Setup hashes the ordinal list as UTF-8 with a trailing Windows line break.
    $entries.Sort([StringComparer]::Ordinal)
    $contents=($entries -join "`r`n")+"`r`n"
    if($PayloadInventory){$PayloadInventory.Value=$contents}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($contents)))).Replace('-','').ToLowerInvariant()}
    finally {$sha.Dispose()}
}

function Assert-InstallerPackageDirectories([string]$Root,[string]$SetupScript,[string]$PreprocessedScript,[ref]$PayloadFingerprint,[ref]$PayloadInventory) {
    $source=[IO.File]::ReadAllText($SetupScript)
    $preflight=[regex]::Match($source,'(?ms)^function AWCheckPackageDirectories\(.*?^end;')
    if(-not $preflight.Success){throw 'Installer package directory preflight is missing'}
    $checked=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pattern="AWCheckPackageDirectory\(Destination \+ '\\([^']+)', Hold, Held\)"
    foreach($match in [regex]::Matches($preflight.Value,$pattern)){
        if(-not $checked.Add($match.Groups[1].Value)){throw 'Duplicate installer package directory check'}
    }

    $compiledReplacement=$null
    if($PreprocessedScript){
        $compiled=[IO.File]::ReadAllText($PreprocessedScript)
        $compiledReplacement=[regex]::Match($compiled,'(?ms)^function AWPayloadReplacementPreflight\(.*?^end;')
        $compiledCompletion=[regex]::Match($compiled,'(?ms)^function AWVerifyCompletedInstall\(.*?^end;')
        $compiledFingerprint=[regex]::Match($compiled,'(?ms)^function AWStagedPayloadDigest:.*?^end;')
        if(-not $compiledReplacement.Success -or -not $compiledCompletion.Success -or -not $compiledFingerprint.Success -or
            $compiled -cnotmatch '(?m)^Source: .*; BeforeInstall: AWCheckPackageCopyDestination\s*$'){
            throw 'Compiled installer package preflight, copy guard, completion verification or payload fingerprint is missing'
        }
        $releaseSubjects=@{
            'accessweaver.exe'='Executable'
            'BUILD-INFO.json'='BuildInfo'
            'SBOM.cdx.json'='SBOM'
            'licenses\Inno-Setup-License.txt'='RuntimeNotice'
        }
    }
    $rootItem=Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'Installer package staging root must be an ordinary directory'
    }
    $pending=[Collections.Generic.Queue[IO.DirectoryInfo]]::new()
    $pending.Enqueue($rootItem)
    $prefixLength=$rootItem.FullName.TrimEnd('\').Length+1
    while($pending.Count){
        foreach($entry in $pending.Dequeue().EnumerateFileSystemInfos()){
            if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){
                throw 'Installer package staging includes a reparse point'
            }
            $relative=$entry.FullName.Substring($prefixLength)
            if($entry -is [IO.DirectoryInfo]){
                if(-not $checked.Contains($relative)){
                    throw ('Installer package directory has no Setup and uninstall preflight: '+$relative)
                }
                $pending.Enqueue($entry)
            }elseif($compiledReplacement){
                $literal=$relative.Replace("'","''")
                if(-not $compiledReplacement.Value.Contains("AWCanReplaceInstalledFile(Destination + '\$literal')")){
                    throw ('Compiled installer omitted package-file replacement preflight: '+$relative)
                }
                $digest=(Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                $length=$entry.Length.ToString([Globalization.CultureInfo]::InvariantCulture)
                $check=if($releaseSubjects.ContainsKey($relative)){
                    $handle=$releaseSubjects[$relative]
                    "if not AWVerifyInstalledFile(Destination + '\$literal', '$digest', $length, True, $handle) then Exit;"
                }else{
                    "if not AWVerifyAndHoldPackageFile(Destination + '\$literal', '$digest', $length, Held) then Exit;"
                }
                if($compiledCompletion.Value.IndexOf($check,[StringComparison]::OrdinalIgnoreCase) -lt 0){
                    throw ('Compiled installer omitted the staged file identity at completion: '+$relative)
                }
                $fingerprintEntry="Entries.Add('$literal|$length|$digest');"
                if($compiledFingerprint.Value.IndexOf($fingerprintEntry,[StringComparison]::OrdinalIgnoreCase) -lt 0){
                    throw ('Compiled installer omitted the staged file from the upgrade fingerprint: '+$relative)
                }
            }
        }
    }
    if($PayloadFingerprint -or $PayloadInventory){
        $fingerprint=Get-InstallerCompiledPayloadFingerprint $compiledFingerprint.Value $PayloadInventory
        if($PayloadFingerprint){$PayloadFingerprint.Value=$fingerprint}
    }
}

function Read-InstallerPayloadInventory([string]$InventoryPath,[string]$InventorySHA256) {
    if($InventorySHA256 -cnotmatch '\A[a-fA-F0-9]{64}\z'){throw 'Expected the approved Setup payload inventory digest'}
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $stream=[IO.File]::Open($InventoryPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 1MB){throw 'Setup payload inventory is outside the size limit'}
        if((Get-FileHash -InputStream $stream -Algorithm SHA256).Hash -ine $InventorySHA256){throw 'Setup payload inventory digest mismatch'}
        $stream.Position=0
        $reader=[IO.StreamReader]::new($stream,$utf8,$false,4096,$true)
        try {$contents=$reader.ReadToEnd()} finally {$reader.Dispose()}
    } finally {$stream.Dispose()}
    $lineBreak="`r`n"
    $lines=$contents.Split(@($lineBreak),[StringSplitOptions]::None)
    if($lines.Length -lt 4 -or $lines.Length -gt 4097 -or $lines[-1] -cne ''){
        throw 'Setup payload inventory must use the compiled CRLF list format'
    }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $inventory=[Collections.Generic.List[object]]::new()
    $previous=''
    for($index=0;$index -lt $lines.Length-1;$index++){
        $line=$lines[$index]
        $fields=$line.Split('|')
        if($fields.Length -ne 3 -or [StringComparer]::Ordinal.Compare($previous,$line) -ge 0 -or
           $fields[1] -cnotmatch '\A(0|[1-9][0-9]{0,8})\z' -or [long]$fields[1] -gt 512MB -or
           $fields[2] -cnotmatch '\A[a-fA-F0-9]{64}\z'){
            throw 'Setup payload inventory has an invalid or out-of-order record'
        }
        $previous=$line
        $relative=$fields[0]
        $prefix=[IO.Path]::GetDirectoryName($relative)
        $leaf=$relative.Split('\')[-1]
        if($relative -cnotmatch '\A[^\\/:*?"<>|\p{C}\p{Zl}\p{Zp}~]+(?:\\[^\\/:*?"<>|\p{C}\p{Zl}\p{Zp}~]+)*\z' -or
           $relative.Length -gt 240 -or $relative.Contains('{#') -or
           ($prefix -and $prefix -inotin @('licenses','docs','docs\assets','docs\qualification')) -or
           $leaf -match '\A |[. ]\z|\A(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9\u00b9\u00b2\u00b3]) *(?:\.|\z)' -or
           (-not $prefix -and $leaf -match '\A(?:unins[0-9]{3}\.(?:exe|dat|msg)|is-.*\.tmp)\z')){
            throw 'Setup payload inventory contains an unsafe or unsupported package path'
        }
        if(-not $seen.Add($relative)){throw 'Setup payload inventory contains an ambiguous path'}
        $inventory.Add(@{path=$relative;size=[long]$fields[1];sha256=$fields[2].ToLowerInvariant()})
    }
    return $inventory.ToArray()
}

function New-InstallerRetiredPayloadPlan([string]$Root,[string]$InventoryPath,[string]$InventorySHA256,[string]$IncludePath) {
    $inventory=@(Read-InstallerPayloadInventory $InventoryPath $InventorySHA256)
    $rootPath=(Get-Item -LiteralPath $Root -Force -ErrorAction Stop).FullName
    $current=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($item in [IO.Directory]::EnumerateFiles($rootPath,'*',[IO.SearchOption]::AllDirectories)){
        [void]$current.Add($item.Substring($rootPath.Length+1))
    }
    $digestRecord='docs\windows-retired-payload.sha256'
    if(-not $current.Add($digestRecord)){throw 'The Setup retirement plan record is reserved'}
    $prior=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $statements=[Collections.Generic.List[string]]::new()
    foreach($file in $inventory){
        $prior.Add($file.path,$file.sha256)
        if(-not $current.Contains($file.path)){
            $literal=$file.path.Replace("'","''")
            $size=$file.size.ToString([Globalization.CultureInfo]::InvariantCulture)
            $statements.Add("  if not AWRetirePackageFile(Destination + '\$literal', '$($file.sha256)', $size) then Exit;")
        }
    }
    foreach($name in @('accessweaver.exe','SBOM.cdx.json','BUILD-INFO.json')){
        if(-not $prior.ContainsKey($name) -or -not $current.Contains($name)){throw 'Expected both Setup payloads to include their core identity files'}
    }
    $lineBreak="`r`n"
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $guard=@(
        'function AWRetiredPayloadMatchesApproval: Boolean;',
        'begin',
        "  Result := (AWLegacyApproval.Payload = '$($prior['accessweaver.exe'])') and",
        "    (AWLegacyApproval.SBOM = '$($prior['SBOM.cdx.json'])') and",
        "    (AWLegacyApproval.BuildInfo = '$($prior['BUILD-INFO.json'])');",
        'end;',
        'function AWRetireApprovedPackageFiles(const Destination: String): Boolean;',
        'begin',
        '  Result := False;'
    )
    $body=($guard+@($statements.ToArray())+@('  Result := True;','end;','')) -join $lineBreak
    [IO.File]::WriteAllText($IncludePath,$body,$utf8)
    $digest=(Get-FileHash -LiteralPath $IncludePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $record="retirement-plan-sha256=$digest$lineBreak"+"prior-payload-sha256=$($InventorySHA256.ToLowerInvariant())$lineBreak"
    # The normal compiled payload fingerprint covers this binding record.
    [IO.File]::WriteAllText((Join-Path $rootPath $digestRecord),$record,$utf8)
    return $digest
}

function Assert-InstallerSetupScript([string]$Path, [string]$TargetArch, [string]$Version, [switch]$OrganizationSigning) {
    if($TargetArch -cnotin @('amd64','arm64')){throw 'Invalid installer script target'}
    if((Get-Item -LiteralPath $Path).Length -gt 1MB){throw 'Preprocessed installer script exceeds evidence limit'}
    $architecture=if($TargetArch -ceq 'arm64'){'arm64'}else{'x64os'}
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

function Initialize-WindowsPublisherFileAccess {
    if('AccessWeaver.PublisherFileAccess' -as [type]){return}
    Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AccessWeaver
{
    public static class PublisherFileAccess
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTagInfo
        {
            public FileAttributes Attributes;
            public uint ReparseTag;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare sharing,
            IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
            out AttributeTagInfo information, uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path,
            uint capacity, uint flags);

        public static string VolumeRoot(SafeFileHandle directory)
        {
            const uint VolumeNameGuid = 1;
            const string prefix = @"\\?\Volume";
            var buffer = new StringBuilder(64);
            uint length = GetFinalPathNameByHandleW(directory, buffer, (uint)buffer.Capacity, VolumeNameGuid);
            string path = buffer.ToString();
            Guid volume;
            if (length == 0 || length >= buffer.Capacity ||
                !path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !path.EndsWith("\\", StringComparison.Ordinal) ||
                !Guid.TryParseExact(path.Substring(prefix.Length, path.Length - prefix.Length - 1), "B", out volume))
                throw new IOException("Artifact requires a local volume root");

            return path;
        }

        public static SafeFileHandle Open(string path, bool directory)
        {
            const uint FileListDirectory = 1;
            const uint GenericRead = 0x80000000;
            const uint OpenExisting = 3;
            const uint OpenReparsePoint = 0x00200000;
            const uint BackupSemantics = 0x02000000;
            const int FileAttributeTagInfo = 9;
            // Keep each path component open without write or delete sharing.
            var handle = CreateFileW(path, directory ? FileListDirectory : GenericRead, FileShare.Read,
                IntPtr.Zero, OpenExisting, OpenReparsePoint | (directory ? BackupSemantics : 0), IntPtr.Zero);
            AttributeTagInfo info;
            if (handle.IsInvalid || !GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
                out info, (uint)Marshal.SizeOf(typeof(AttributeTagInfo))) ||
                (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
                ((info.Attributes & FileAttributes.Directory) != 0) != directory)
            {
                handle.Dispose();
                throw new IOException("Artifact path is inaccessible, redirected or has the wrong type");
            }
            return handle;
        }
    }
}
'@
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

function Get-WindowsPublisherArtifactSHA256([string]$Path,[string]$PublisherCertificateSHA256,[string]$ExpectedSHA256='') {
    if($env:OS -cne 'Windows_NT'){throw 'Windows is required for Authenticode verification'}
    $absolute=[IO.Path]::GetFullPath($Path)
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
        if($ExpectedSHA256 -and $actual -ine $ExpectedSHA256){throw 'Artifact digest differs from the approved release digest'}
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
    return $actual.ToLowerInvariant()
}

function Assert-InstallerSBOMSubject([string]$Path,[string]$ExpectedSHA256) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 16MB){throw 'Installer SBOM is outside the evidence size limit'}
        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$false,4096,$true)
        try {$document=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ($reader.ReadToEnd()) -ErrorAction Stop}
        finally {$reader.Dispose()}
        $component=$document.metadata.component
        $hashes=@($component.hashes)
        if($document -isnot [pscustomobject] -or $document.bomFormat -cne 'CycloneDX' -or $document.specVersion -cne '1.6' -or
            $component -isnot [pscustomobject] -or $component.type -cne 'application' -or
            $hashes.Count -ne 1 -or $hashes[0] -isnot [pscustomobject] -or
            $hashes[0].alg -cne 'SHA-256' -or $hashes[0].content -isnot [string] -or $hashes[0].content -cnotmatch '\A[a-f0-9]{64}\z' -or
            $hashes[0].content -ine $ExpectedSHA256){
            throw 'Installer SBOM subject differs from the publisher-verified artifact'
        }
    } finally {$stream.Dispose()}
}

function Assert-InstallerSignerIdentity([string]$SigningTool,[string]$PublisherCertificateSHA256) {
    if($PublisherCertificateSHA256 -cnotmatch '\A[a-fA-F0-9]{64}\z' -or
        $SigningTool -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|$%\x00-\x1f]+\.exe\z'){
        throw 'Signing requires an absolute local signer executable and an approved publisher SHA-256'
    }
}

function Get-InstallerSigningArguments([string]$SigningTool,[string]$PublisherCertificateSHA256,[string]$Shell,[string]$Callback) {
    if(-not $SigningTool -and -not $PublisherCertificateSHA256){return}
    Assert-InstallerSignerIdentity $SigningTool $PublisherCertificateSHA256
    foreach($path in @($Shell,$Callback)){
        if($path -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|$%\x00-\x1f]+\.(exe|ps1)\z'){
            throw 'Inno signing requires local PowerShell and callback paths'
        }
    }
    '/DOrganizationSigning=1'
    ('/SaccessweaverOrganization=$q'+$Shell+'$q -NoProfile -NonInteractive -File $q'+$Callback+'$q -Artifact $f')
}

function Get-InstallerPayloadSigning([string]$SetupSigner,[string]$SetupPublisher,[string]$PayloadSigner,[string]$PayloadPublisher) {
    if($PayloadSigner -or $PayloadPublisher){
        Assert-InstallerSignerIdentity $SetupSigner $SetupPublisher
        Assert-InstallerSignerIdentity $PayloadSigner $PayloadPublisher
        return @{signer=$PayloadSigner;publisher=$PayloadPublisher}
    }
    return @{signer=$SetupSigner;publisher=$SetupPublisher}
}

function Invoke-InstallerSigningContext([string]$Signer,[string]$Publisher,[scriptblock]$Action) {
    $previousSigner=$env:ACCESSWEAVER_BUILD_SIGNER
    $previousPublisher=$env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256
    try {
        $env:ACCESSWEAVER_BUILD_SIGNER=$Signer
        $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256=$Publisher
        & $Action
    } finally {
        $env:ACCESSWEAVER_BUILD_SIGNER=$previousSigner
        $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256=$previousPublisher
    }
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

function Assert-InstallerSigningDigest([string]$Path,[string]$ExpectedSHA256) {
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if((Get-FileHash -InputStream $file -Algorithm SHA256).Hash -ine $ExpectedSHA256){
            throw 'Installer artifact changed during the signing handoff'
        }
    } finally {$file.Dispose()}
}

function Complete-InstallerSigning([string]$Original,[string]$OriginalSHA256,[string]$Signed,[string]$SignedSHA256) {
    Assert-InstallerSigningDigest $Signed $SignedSHA256
    Assert-InstallerSigningDigest $Original $OriginalSHA256
    [IO.File]::Replace($Signed,$Original,[NullString]::Value)
    Assert-InstallerSigningDigest $Original $SignedSHA256
}

function Assert-InstallerSigningStreamOnlyChange([IO.Stream]$Original,[IO.Stream]$Signed) {
    $Original.Position=0
    $Signed.Position=0
    $before=[IO.BinaryReader]::new($Original,[Text.Encoding]::UTF8,$true)
    try {
        $after=[IO.BinaryReader]::new($Signed,[Text.Encoding]::UTF8,$true)
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
