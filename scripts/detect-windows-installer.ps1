# Standalone read-only detection for an independently approved Windows payload.
[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$Architecture = '',
    [string]$PayloadSHA256 = '',
    [string]$InstallDirectory = '',
    [string]$UninstallerSHA256 = '',
    [string]$PayloadSBOMSHA256 = '',
    [string]$PayloadPublisherSHA256 = '',
    [switch]$UpgradeInventory,
    [string]$BuildInfoSHA256 = '',
    [switch]$UseRegisteredDirectory,
    [string]$PendingApprovalSHA256 = '',
    [string]$UninstallDataSHA256 = ''
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$registrationKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1'

function Read-AccessWeaverRegistration([Microsoft.Win32.RegistryView]$View) {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$View)
    $key=$null
    try {
        $key=$base.OpenSubKey($registrationKey,$false)
        if($null -eq $key){return $null}
        $options=[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        $version=$key.GetValue('DisplayVersion',$null,$options)
        $location=$key.GetValue('InstallLocation',$null,$options)
        if($version -isnot [string] -or $version.Length -eq 0 -or $version.Length -gt 256 -or
           $location -isnot [string] -or $location.Length -eq 0 -or $location.Length -gt 260 -or
           $key.GetValueKind('DisplayVersion') -ne [Microsoft.Win32.RegistryValueKind]::String -or
           $key.GetValueKind('InstallLocation') -ne [Microsoft.Win32.RegistryValueKind]::String){
            throw 'Invalid installed registration'
        }
        $record=@{version=$version;location=$location}
        if($UninstallerSHA256 -and $View -eq [Microsoft.Win32.RegistryView]::Registry64){
            foreach($name in @('UninstallString','QuietUninstallString')){
                $value=$key.GetValue($name,$null,$options)
                if($value -isnot [string] -or $value.Length -eq 0 -or $value.Length -gt 300 -or
                    $key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::String){
                    throw 'Invalid installed uninstall command'
                }
                $record[$name]=$value
            }
        }
        return $record
    } finally {
        if($null -ne $key){$key.Dispose()}
        $base.Dispose()
    }
}

function Get-AccessWeaverLocalDirectory([string]$Path) {
    $directory=$Path.TrimEnd('\')
    if($directory -notmatch '\A[A-Za-z]:\\[^:*?"<>|\x00-\x1f]+\z' -or $directory.Length -gt 259 -or
       $directory -cne [IO.Path]::GetFullPath($directory)){
        throw 'Expected a canonical local installation directory'
    }
    foreach($component in $directory.Substring(3).Split('\')){
        if(-not $component -or $component.EndsWith('.') -or $component.EndsWith(' ')){
            throw 'Installation directory has an ambiguous component'
        }
    }
    if([IO.DriveInfo]::new($directory.Substring(0,3)).DriveType -ne [IO.DriveType]::Fixed){
        throw 'Expected a fixed local installation drive'
    }
    return $directory
}

function Get-AccessWeaverRegisteredUninstaller($Registration,[string]$Directory) {
    $command=$Registration.UninstallString
    $quiet=$Registration.QuietUninstallString
    if($command -isnot [string] -or $quiet -isnot [string] -or $command.Length -gt 300 -or $quiet.Length -gt 300){
        throw 'Invalid installed uninstall command'
    }
    $match=[regex]::Match($command,'\A"(?<file>[^"\r\n]+\\unins[0-9]{3}\.exe)"(?<log> /LOG)?\z',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if(-not $match.Success){throw 'Invalid installed uninstall command'}
    $path=$match.Groups['file'].Value
    $expected=Join-Path $Directory ([IO.Path]::GetFileName($path))
    $expectedQuiet='"'+$expected+'" /SILENT'+$match.Groups['log'].Value
    if($path -ine $expected -or $quiet -ine $expectedQuiet){throw 'Uninstall registration differs from the installed directory'}
    return $expected
}
function Initialize-AccessWeaverInstalledFileAccess {
    if('AccessWeaver.InstallerFileAccess' -as [type]){return}
    Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AccessWeaver
{
    public static class InstallerFileAccess
    {
        private const uint ListDirectory = 1;
        private const uint GenericRead = 0x80000000;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;
        private const uint BackupSemantics = 0x02000000;
        private const int FileStandardInfo = 1;
        private const int FileAttributeTagInfo = 9;

        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTagInfo
        {
            public FileAttributes Attributes;
            public uint ReparseTag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StandardInfo
        {
            public long AllocationSize;
            public long EndOfFile;
            public uint NumberOfLinks;
            public byte DeletePending;
            public byte Directory;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare sharing,
            IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
            out AttributeTagInfo information, uint size);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
            out StandardInfo information, uint size);

        private static SafeFileHandle Open(string path, bool directory)
        {
            // Request directory read access so the open participates in share checks.
            // Hold directories without delete sharing and files without write or delete sharing.
            var handle = CreateFileW(path, directory ? ListDirectory : GenericRead,
                directory ? FileShare.ReadWrite : FileShare.Read, IntPtr.Zero, OpenExisting,
                OpenReparsePoint | (directory ? BackupSemantics : 0), IntPtr.Zero);
            try
            {
                AttributeTagInfo info;
                if (handle.IsInvalid || !GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
                    out info, (uint)Marshal.SizeOf(typeof(AttributeTagInfo))))
                    throw new IOException("Could not inspect the installed path");
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    ((info.Attributes & FileAttributes.Directory) != 0) != directory)
                    throw new IOException("Unexpected installed path type");
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static SafeFileHandle OpenDirectory(string path)
        {
            return Open(path, true);
        }

        public static FileStream OpenFile(string path, long maximum, bool requireSingleLink = false)
        {
            SafeFileHandle handle = Open(path, false);
            try
            {
                if (requireSingleLink)
                {
                    StandardInfo info;
                    if (!GetFileInformationByHandleEx(handle, FileStandardInfo,
                        out info, (uint)Marshal.SizeOf(typeof(StandardInfo))) || info.NumberOfLinks != 1)
                        throw new IOException("Installed file is not a verified single-link file");
                }
                var stream = new FileStream(handle, FileAccess.Read);
                try
                {
                    if (stream.Length <= 0 || stream.Length > maximum)
                        throw new IOException("Installed file size outside detection limits");
                    return stream;
                }
                catch
                {
                    stream.Dispose();
                    throw;
                }
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
    }
}
'@
}

function Enter-AccessWeaverDetection {
    # Claim ownership only when creating a new mutex. Waiting on an existing
    # one could consume the abandonment signal that Setup needs to inspect.
    $created=$false
    $mutex=[Threading.Mutex]::new($true,'Global\AccessWeaver-Lifecycle-B13D4677-4660-4E63-B3DB-03077ACBB092',[ref]$created)
    if(-not $created){
        $mutex.Dispose()
        throw 'An AccessWeaver lifecycle object already exists'
    }
    return $mutex
}

function Assert-NoAccessWeaverSetup {
    if(-not ('AccessWeaver.InstallerSetupMutex' -as [type])){
        Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace AccessWeaver
{
    public static class InstallerSetupMutex
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr OpenMutexW(uint access, bool inherit, string name);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static bool IsAbsent(string name)
        {
            // Inspect existence without waiting or creating another mutex.
            IntPtr handle = OpenMutexW(0x00100000, false, name); // SYNCHRONIZE
            if (handle == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == 2; // ERROR_FILE_NOT_FOUND

            if (!CloseHandle(handle))
                throw new InvalidOperationException("Could not close the AccessWeaver Setup mutex handle");
            return false;
        }
    }
}
'@
    }
    if(-not [AccessWeaver.InstallerSetupMutex]::IsAbsent('Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092')){
        throw 'AccessWeaver Setup is active or its mutex could not be inspected'
    }
}

function Initialize-AccessWeaverInstallerRecoveryRegistry {
    if('AccessWeaver.InstallerLifecycleRecoveryRegistry' -as [type]){return}
    Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AccessWeaver
{
    public static class InstallerLifecycleRecoveryRegistry
    {
        private static readonly IntPtr LocalMachine = new IntPtr(unchecked((int)0x80000002));
        private static readonly string[] Components = { "SOFTWARE", "AccessWeaver", "Installer" };
        private static readonly string[] ProductRegistration = {
            "SOFTWARE", "Microsoft", "Windows", "CurrentVersion", "Uninstall",
            "{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1"
        };
        private const int NotFound = 2;
        private const int Unsafe = 5;
        private const uint NoExpand = 0x10000000;
        private const uint QueryAny = NoExpand | 0xffff;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int RegOpenKeyExW(IntPtr parent, string name, uint options, uint access, out IntPtr key);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern int RegCloseKey(IntPtr key);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int RegQueryValueExW(IntPtr key, string value,
            IntPtr reserved, IntPtr type, IntPtr data, out uint size);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int RegGetValueW(IntPtr key, string subKey, string value,
            uint flags, IntPtr type, IntPtr data, out uint size);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int RegGetValueW(IntPtr key, string subKey, string value,
            uint flags, out uint type, [Out] byte[] data, ref uint size);

        private static int OpenPath(string[] components, uint view, int firstAllowedMissing, out IntPtr key)
        {
            key = IntPtr.Zero;
            IntPtr parent = LocalMachine;
            int status = 0;
            for (int index = 0; index < components.Length; index++)
            {
                IntPtr child;
                status = RegOpenKeyExW(parent, components[index], 8, view | 1, out child);
                if (status != 0)
                {
                    if (index < firstAllowedMissing)
                        status = Unsafe;
                    break;
                }

                uint size;
                if (RegQueryValueExW(child, "SymbolicLinkValue", IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, out size) != NotFound)
                {
                    RegCloseKey(child);
                    status = Unsafe;
                    break;
                }
                if (parent != LocalMachine && RegCloseKey(parent) != 0)
                {
                    RegCloseKey(child);
                    return Unsafe;
                }
                parent = child;
            }

            if (status == 0)
            {
                key = parent;
                return 0;
            }
            if (parent != LocalMachine && RegCloseKey(parent) != 0)
                return Unsafe;
            return status;
        }

        private static int ReadProductView(uint view)
        {
            IntPtr key;
            int status = OpenPath(ProductRegistration, view, 4, out key);
            if (status == 0 && RegCloseKey(key) != 0)
                return Unsafe;
            return status == 3 ? NotFound : status;
        }

        public static int QueryProductRegistration()
        {
            if (ReadProductView(0x0200) != NotFound)
                return Unsafe;
            return ReadProductView(0x0100);
        }

        public static int QueryStatus()
        {
            IntPtr key;
            int status = OpenPath(Components, 0x0100, 1, out key);
            if (status != 0)
                return status;

            uint size;
            status = RegGetValueW(key, null, "PendingInstall", QueryAny, IntPtr.Zero, IntPtr.Zero, out size);
            return RegCloseKey(key) == 0 ? status : Unsafe;
        }

        public static string ReadValue()
        {
            IntPtr key;
            if (OpenPath(Components, 0x0100, 1, out key) != 0)
                return null;

            // Match Setup's bound including the optional legacy retirement phase.
            byte[] buffer = new byte[1202];
            uint size = (uint)buffer.Length;
            uint type;
            int status = RegGetValueW(key, null, "PendingInstall", NoExpand | 2, out type, buffer, ref size);
            if (RegCloseKey(key) != 0 || status != 0 || type != 1 || size < 4 ||
                size > buffer.Length || size % 2 != 0)
                return null;

            int contentBytes = (int)size - 2;
            if (buffer[contentBytes] != 0 || buffer[contentBytes + 1] != 0)
                return null;

            string value = new UnicodeEncoding(false, false, true).GetString(buffer, 0, contentBytes);
            return value.IndexOf('\0') < 0 ? value : null;
        }
    }
}
'@
}

function Get-AccessWeaverInstallerRecoveryState {
    try {
        Initialize-AccessWeaverInstallerRecoveryRegistry
        # Only explicit component or value absence clears the recovery guard.
        switch ([AccessWeaver.InstallerLifecycleRecoveryRegistry]::QueryStatus()) {
            0 {return 'pending'}
            2 {return 'clear'}
            3 {return 'clear'}
            default {return 'unavailable'}
        }
    } catch {
        return 'unavailable'
    }
}

function Test-AccessWeaverManagedUpgradePending([string]$directory) {
    if(-not $PendingApprovalSHA256){return $false}
    try {
        Initialize-AccessWeaverInstallerRecoveryRegistry
        $record=[AccessWeaver.InstallerLifecycleRecoveryRegistry]::ReadValue()
        if(-not $record){return $false}

        $fields=$record.Split('|')
        $legacyRetirement=$fields.Count -eq 4 -and $fields[3] -ceq 'legacy-retirement'
        if(($fields.Count -ne 3 -and -not $legacyRetirement) -or
           -not [string]::Equals($fields[0],$Version,[StringComparison]::Ordinal) -or
           $fields[2] -cne $PendingApprovalSHA256){return $false}

        # A missing leaf is an expected state only for an explicitly recorded
        # legacy retirement. Do not treat a link or unreadable key as absent.
        $registrationStatus=0
        if($legacyRetirement){
            $registrationStatus=[AccessWeaver.InstallerLifecycleRecoveryRegistry]::QueryProductRegistration()
            if($registrationStatus -notin @(0,2)){return $false}
        }
        if($registrationStatus -eq 2){
            $registeredDirectory=Get-AccessWeaverLocalDirectory $fields[1]
        } else {
            $registration=Read-AccessWeaverRegistration Registry64
            if($null -eq $registration -or $null -ne (Read-AccessWeaverRegistration Registry32)){return $false}
            $registeredDirectory=Get-AccessWeaverLocalDirectory $registration.location
        }
        if(-not [string]::Equals($registeredDirectory,$fields[1],[StringComparison]::OrdinalIgnoreCase) -or
           (-not $UseRegisteredDirectory -and
            -not [string]::Equals($registeredDirectory,$directory,[StringComparison]::OrdinalIgnoreCase))){
            return $false
        }
        return [string]::Equals($record,[AccessWeaver.InstallerLifecycleRecoveryRegistry]::ReadValue(),[StringComparison]::Ordinal)
    } catch {
        return $false
    }
}

function Assert-NoPendingAccessWeaverInstallation([string]$directory) {
    $state=Get-AccessWeaverInstallerRecoveryState
    if($state -ceq 'pending'){
        $pending=[InvalidOperationException]::new('An AccessWeaver installation is incomplete')
        $pending.Data['AccessWeaverPendingInstall']=$true
        if($env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY -ceq '1'){
            $pending.Data['AccessWeaverManagedUpgradePending']=Test-AccessWeaverManagedUpgradePending $directory
        }
        throw $pending
    }
    if($state -cne 'clear'){throw 'AccessWeaver Setup recovery state could not be read'}
}

function Test-AccessWeaverInstalledPublisher([string]$Path,[string]$Expected) {
    $signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if($null -eq $signature -or $signature.Status -ne 'Valid' -or
        $signature.SignatureType -ne 'Authenticode' -or $null -eq $signature.TimeStamperCertificate){
        return $false
    }
    $certificate=$signature.SignerCertificate.RawData
    if($certificate -isnot [byte[]] -or $certificate.Length -eq 0 -or $certificate.Length -gt 64KB){return $false}
    $sha256=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($sha256.ComputeHash($certificate)).Replace('-','') -ieq $Expected)}
    finally {$sha256.Dispose()}
}

function Read-AccessWeaverPayloadNotices([IO.Stream]$SBOM) {
    $SBOM.Position=0
    $reader=[IO.StreamReader]::new($SBOM,[Text.UTF8Encoding]::new($false,$true),$false,4096,$true)
    try {
        $document=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ($reader.ReadToEnd()) -ErrorAction Stop
    } finally {$reader.Dispose()}
    $root=$document.metadata.component
    if($document.bomFormat -cne 'CycloneDX' -or $document.specVersion -cne '1.6' -or
       $root.type -cne 'application' -or @($document.components).Count -gt 4096){
        throw 'Installed SBOM notice metadata is invalid'
    }
    $notices=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $safePath=[regex]::new('\Alicenses/(?!(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|\z))[A-Za-z0-9._-]{1,240}(?<!\.)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    foreach($component in (@($root)+@($document.components))){
        $properties=@($component.properties | Where-Object {$_.name -ceq 'accessweaver:license-evidence'})
        if($properties.Count -eq 0 -and $component.type -ceq 'file' -and -not $component.licenses){continue}
        if($properties.Count -ne 1 -or $properties[0].value -isnot [string] -or
           -not $properties[0].value.TrimStart().StartsWith('[')){
            throw 'Installed SBOM notice metadata is invalid'
        }
        $records=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $properties[0].value -ErrorAction Stop
        if(-not $records){throw 'Installed SBOM notice metadata is invalid'}
        foreach($record in $records){
            if($record.path -isnot [string] -or -not $safePath.IsMatch($record.path) -or
               $record.sha256 -isnot [string] -or $record.sha256 -cnotmatch '\A[a-f0-9]{64}\z'){
                throw 'Installed SBOM notice metadata is invalid'
            }
            $name=$record.path.Substring('licenses/'.Length)
            if($notices.ContainsKey($name)){
                if($notices[$name] -cne $record.sha256){throw 'Installed SBOM notice digests conflict'}
            }else{
                if($notices.Count -ge 256){throw 'Installed SBOM notice inventory exceeds its limit'}
                $notices.Add($name,$record.sha256)
            }
        }
    }
    return ,$notices
}

function Test-AccessWeaverInstallation([string]$directory) {
    Assert-NoAccessWeaverSetup
    Assert-NoPendingAccessWeaverInstallation $directory
    $registration=Read-AccessWeaverRegistration Registry64
    if($null -ne (Read-AccessWeaverRegistration Registry32)){throw 'Unexpected alternate machine registration'}
    if($null -eq $registration -or $registration.version -cne $Version){return $false}
    $registeredDirectory=Get-AccessWeaverLocalDirectory $registration.location
    if($UseRegisteredDirectory){$directory=$registeredDirectory}
    elseif($registeredDirectory -ine $directory){throw 'Unexpected registered installation directory'}
    Initialize-AccessWeaverInstalledFileAccess
    $parents=[Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $noticeFiles=[Collections.Generic.List[IO.FileStream]]::new()
    $payload=$null;$uninstaller=$null;$uninstallData=$null;$sbom=$null;$buildInfo=$null
    try {
        $root=[IO.Path]::GetPathRoot($directory)
        $current=$root
        foreach($component in $directory.Substring($root.Length).Split('\')){
            $current=[IO.Path]::Combine($current,$component)
            $parents.Add([AccessWeaver.InstallerFileAccess]::OpenDirectory($current))
        }
        foreach($packageDirectory in @('licenses','docs','docs\assets','docs\qualification')){
            $parents.Add([AccessWeaver.InstallerFileAccess]::OpenDirectory((Join-Path $directory $packageDirectory)))
        }
        $payload=[AccessWeaver.InstallerFileAccess]::OpenFile((Join-Path $directory 'accessweaver.exe'),128MB,$true)
        if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $payload -Algorithm SHA256).Hash -ine $PayloadSHA256){return $false}
        if($PayloadSBOMSHA256){
            $sbom=[AccessWeaver.InstallerFileAccess]::OpenFile((Join-Path $directory 'SBOM.cdx.json'),4MB,$true)
            if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $sbom -Algorithm SHA256).Hash -ine $PayloadSBOMSHA256){return $false}
            $notices=Read-AccessWeaverPayloadNotices $sbom
            $licenseDirectory=Join-Path $directory 'licenses'
            $total=0L
            foreach($notice in $notices.GetEnumerator()){
                $file=[AccessWeaver.InstallerFileAccess]::OpenFile((Join-Path $licenseDirectory $notice.Key),1MB,$true)
                $noticeFiles.Add($file)
                $total+=$file.Length
                if($total -gt 16MB){throw 'Installed SBOM notices exceed the aggregate inspection limit'}
                if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $file -Algorithm SHA256).Hash -ine $notice.Value){return $false}
            }
        }
        if($BuildInfoSHA256){
            $buildInfo=[AccessWeaver.InstallerFileAccess]::OpenFile((Join-Path $directory 'BUILD-INFO.json'),64KB,$true)
            if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $buildInfo -Algorithm SHA256).Hash -ine $BuildInfoSHA256){return $false}
        }
        if($PayloadPublisherSHA256 -and -not (Test-AccessWeaverInstalledPublisher (Join-Path $directory 'accessweaver.exe') $PayloadPublisherSHA256)){
            return $false
        }
        if($UninstallerSHA256){
            $path=Get-AccessWeaverRegisteredUninstaller $registration $directory
            $uninstaller=[AccessWeaver.InstallerFileAccess]::OpenFile($path,512MB,$true)
            if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $uninstaller -Algorithm SHA256).Hash -ine $UninstallerSHA256){return $false}
            $dataPath=[IO.Path]::ChangeExtension($path,'.dat')
            $uninstallData=[AccessWeaver.InstallerFileAccess]::OpenFile($dataPath,512MB,$true)
            if($UninstallDataSHA256 -and
                (Microsoft.PowerShell.Utility\Get-FileHash -InputStream $uninstallData -Algorithm SHA256).Hash -ine $UninstallDataSHA256){return $false}
        }
        $confirmed=Read-AccessWeaverRegistration Registry64
        if($null -eq $confirmed -or $confirmed.version -cne $registration.version -or
            $confirmed.location -cne $registration.location -or $confirmed.UninstallString -cne $registration.UninstallString -or
            $confirmed.QuietUninstallString -cne $registration.QuietUninstallString -or $null -ne (Read-AccessWeaverRegistration Registry32)){
            throw 'Installation registration changed during detection'
        }
        Assert-NoPendingAccessWeaverInstallation $directory
        Assert-NoAccessWeaverSetup
    } finally {
        try {
            try {if($null -ne $uninstallData){$uninstallData.Dispose()}}
            finally {
                try {if($null -ne $uninstaller){$uninstaller.Dispose()}}
                finally {
                    try {if($null -ne $buildInfo){$buildInfo.Dispose()}}
                    finally {
                        try {if($null -ne $sbom){$sbom.Dispose()}}
                        finally {if($null -ne $payload){$payload.Dispose()}}
                    }
                }
            }
        } finally {
            try {
                for($i=$noticeFiles.Count-1;$i -ge 0;$i--){$noticeFiles[$i].Dispose()}
            } finally {
                for($i=$parents.Count-1;$i -ge 0;$i--){$parents[$i].Dispose()}
            }
        }
    }
    return $true
}

try {
    $targets=@{amd64='X64';arm64='Arm64'}
    if($env:OS -cne 'Windows_NT' -or $Architecture -cnotin @('amd64','arm64') -or
       $targets[$Architecture] -cne [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -or
       -not [Environment]::Is64BitProcess -or $Version.Length -gt 256 -or
       $Version -cnotmatch '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?\z' -or
       $PayloadSHA256 -notmatch '\A[a-fA-F0-9]{64}\z' -or
       ($PayloadSBOMSHA256 -and $PayloadSBOMSHA256 -notmatch '\A[a-fA-F0-9]{64}\z') -or
       ($BuildInfoSHA256 -and $BuildInfoSHA256 -notmatch '\A[a-fA-F0-9]{64}\z') -or
       ($PayloadPublisherSHA256 -and $PayloadPublisherSHA256 -notmatch '\A[a-fA-F0-9]{64}\z') -or
       ($PendingApprovalSHA256 -and $PendingApprovalSHA256 -cnotmatch '\A[a-f0-9]{64}\z') -or
       ($UpgradeInventory -and (-not $PayloadSBOMSHA256 -or -not $PayloadPublisherSHA256)) -or
       ($UninstallerSHA256 -and $UninstallerSHA256 -notmatch '\A[a-fA-F0-9]{64}\z') -or
       ($UninstallDataSHA256 -and (
           $UninstallDataSHA256 -notmatch '\A[a-fA-F0-9]{64}\z' -or -not $UninstallerSHA256 -or
           ($UpgradeInventory -and -not $BuildInfoSHA256)))){
        throw 'Expected pinned Windows payload identity and a matching 64-bit host'
    }
    if($UseRegisteredDirectory -and $InstallDirectory){throw 'Specify either a directory or registered location detection'}
    $directory=$null
    if(-not $UseRegisteredDirectory){
        if(-not $InstallDirectory){$InstallDirectory=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AccessWeaver'}
        $directory=Get-AccessWeaverLocalDirectory $InstallDirectory
    }
    $lifecycle=Enter-AccessWeaverDetection
    try {$detected=Test-AccessWeaverInstallation $directory}
    finally {
        try {$lifecycle.ReleaseMutex()}
        finally {$lifecycle.Dispose()}
    }
    if(-not $detected){exit 0}
    if($UpgradeInventory){
        $inventory=[ordered]@{
            schemaVersion=1
            target='windows/'+$Architecture
            version=$Version
            payloadSHA256=$PayloadSHA256.ToLowerInvariant()
            payloadSBOMSHA256=$PayloadSBOMSHA256.ToLowerInvariant()
            payloadPublisherSHA256=$PayloadPublisherSHA256.ToLowerInvariant()
        }
        if($BuildInfoSHA256){
            $inventory.schemaVersion=2
            $inventory.buildInfoSHA256=$BuildInfoSHA256.ToLowerInvariant()
        }
        if($UninstallDataSHA256){
            $inventory.schemaVersion=3
            $inventory.uninstallerSHA256=$UninstallerSHA256.ToLowerInvariant()
            $inventory.uninstallDataSHA256=$UninstallDataSHA256.ToLowerInvariant()
        }
        $inventory | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
    } else {Microsoft.PowerShell.Utility\Write-Output 'AccessWeaver detected'}
    exit 0
} catch {
    # Endpoint management uses stdout to determine detection. The release
    # verifier explicitly opts into fixed non-success statuses.
    if($env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY -ceq '1' -and $_.Exception.Data['AccessWeaverPendingInstall'] -eq $true){
        if($_.Exception.Data['AccessWeaverManagedUpgradePending'] -eq $true){
            Microsoft.PowerShell.Utility\Write-Output 'AccessWeaver managed upgrade pending'
        } else {
            Microsoft.PowerShell.Utility\Write-Output 'AccessWeaver installation pending'
        }
    }
    exit 1
}
