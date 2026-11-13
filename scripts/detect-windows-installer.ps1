# Standalone read-only detection for an independently approved Windows payload.
[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$Architecture = '',
    [string]$PayloadSHA256 = '',
    [string]$InstallDirectory = '',
    [string]$UninstallerSHA256 = '',
    [string]$PayloadSBOMSHA256 = ''
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
function Open-AccessWeaverInstalledFile([string]$Path,[long]$Maximum) {
    $root=[IO.Path]::GetPathRoot($Path)
    $current=$root
    foreach($component in $Path.Substring($root.Length).Split('\')){
        $current=[IO.Path]::Combine($current,$component)
        $entry=Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force
        if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Installation path contains a reparse point'}
    }
    if($entry.PSIsContainer){throw 'Expected a payload file'}
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($file.Length -le 0 -or $file.Length -gt $Maximum){throw 'Installed file size outside detection limits'}
        return ,$file
    } catch {$file.Dispose();throw}
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

function Get-AccessWeaverInstallerRecoveryState {
    # The detector ships standalone. Its source fixture checks both copies.
    try {
        if(-not ('AccessWeaver.InstallerRecoveryRegistry' -as [type])){
            Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace AccessWeaver
{
    public static class InstallerRecoveryRegistry
    {
        private static readonly IntPtr LocalMachine = new IntPtr(unchecked((int)0x80000002));
        private const uint QueryFlags = 0x1001ffff; // RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY | RRF_RT_ANY

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int RegGetValueW(IntPtr key, string subKey, string value,
            uint flags, IntPtr type, IntPtr data, out uint size);

        public static int QueryStatus()
        {
            uint size;
            return RegGetValueW(LocalMachine, @"SOFTWARE\AccessWeaver\Installer", "PendingInstall",
                QueryFlags, IntPtr.Zero, IntPtr.Zero, out size);
        }
    }
}
'@
        }
        # Only explicit key/path or value absence permits uninstall or detection.
        switch ([AccessWeaver.InstallerRecoveryRegistry]::QueryStatus()) {
            0 {return 'pending'}
            2 {return 'clear'} # ERROR_FILE_NOT_FOUND
            3 {return 'clear'} # ERROR_PATH_NOT_FOUND
            default {return 'unavailable'}
        }
    } catch {
        return 'unavailable'
    }
}

function Assert-NoPendingAccessWeaverInstallation {
    $state=Get-AccessWeaverInstallerRecoveryState
    if($state -ceq 'pending'){throw 'An AccessWeaver installation is incomplete'}
    if($state -cne 'clear'){throw 'AccessWeaver Setup recovery state could not be read'}
}

function Test-AccessWeaverInstallation([string]$directory) {
    Assert-NoPendingAccessWeaverInstallation
    $registration=Read-AccessWeaverRegistration Registry64
    if($null -ne (Read-AccessWeaverRegistration Registry32)){throw 'Unexpected alternate machine registration'}
    if($null -eq $registration -or $registration.version -cne $Version){return $false}
    if((Get-AccessWeaverLocalDirectory $registration.location) -ine $directory){throw 'Unexpected registered installation directory'}
    $payload=$null;$uninstaller=$null;$sbom=$null
    try {
        $payload=Open-AccessWeaverInstalledFile (Join-Path $directory 'accessweaver.exe') 128MB
        if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $payload -Algorithm SHA256).Hash -ine $PayloadSHA256){return $false}
        if($PayloadSBOMSHA256){
            $sbom=Open-AccessWeaverInstalledFile (Join-Path $directory 'SBOM.cdx.json') 4MB
            if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $sbom -Algorithm SHA256).Hash -ine $PayloadSBOMSHA256){return $false}
        }
        if($UninstallerSHA256){
            $path=Get-AccessWeaverRegisteredUninstaller $registration $directory
            $uninstaller=Open-AccessWeaverInstalledFile $path 512MB
            if((Microsoft.PowerShell.Utility\Get-FileHash -InputStream $uninstaller -Algorithm SHA256).Hash -ine $UninstallerSHA256){return $false}
        }
        $confirmed=Read-AccessWeaverRegistration Registry64
        if($null -eq $confirmed -or $confirmed.version -cne $registration.version -or
            $confirmed.location -cne $registration.location -or $confirmed.UninstallString -cne $registration.UninstallString -or
            $confirmed.QuietUninstallString -cne $registration.QuietUninstallString -or $null -ne (Read-AccessWeaverRegistration Registry32)){
            throw 'Installation registration changed during detection'
        }
    } finally {
        try {if($null -ne $uninstaller){$uninstaller.Dispose()}}
        finally {
            try {if($null -ne $sbom){$sbom.Dispose()}}
            finally {if($null -ne $payload){$payload.Dispose()}}
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
       ($UninstallerSHA256 -and $UninstallerSHA256 -notmatch '\A[a-fA-F0-9]{64}\z')){
        throw 'Expected pinned Windows payload identity and a matching 64-bit host'
    }
    if(-not $InstallDirectory){$InstallDirectory=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AccessWeaver'}
    $directory=Get-AccessWeaverLocalDirectory $InstallDirectory
    $lifecycle=Enter-AccessWeaverDetection
    try {$detected=Test-AccessWeaverInstallation $directory}
    finally {
        try {$lifecycle.ReleaseMutex()}
        finally {$lifecycle.Dispose()}
    }
    if(-not $detected){exit 0}
    Microsoft.PowerShell.Utility\Write-Output 'AccessWeaver detected'
    exit 0
} catch {
    # Endpoint management uses stdout to determine detection. Keep all other
    # paths silent, including private path, registry and exception details.
    exit 1
}
