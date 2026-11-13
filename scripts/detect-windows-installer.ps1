# Standalone read-only detection for an independently approved Windows payload.
[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$Architecture = '',
    [string]$PayloadSHA256 = '',
    [string]$InstallDirectory = ''
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
        return @{version=$version;location=$location}
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

function Test-AccessWeaverPayload([string]$Path,[string]$ExpectedSHA256) {
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
        if($file.Length -le 0 -or $file.Length -gt 128MB){throw 'Payload size outside detection limits'}
        return (Microsoft.PowerShell.Utility\Get-FileHash -InputStream $file -Algorithm SHA256).Hash -ieq $ExpectedSHA256
    } finally {$file.Dispose()}
}

try {
    $targets=@{amd64='X64';arm64='Arm64'}
    if($env:OS -cne 'Windows_NT' -or $Architecture -cnotin @('amd64','arm64') -or
       $targets[$Architecture] -cne [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -or
       -not [Environment]::Is64BitProcess -or $Version.Length -gt 256 -or
       $Version -cnotmatch '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?\z' -or
       $PayloadSHA256 -notmatch '\A[a-fA-F0-9]{64}\z'){
        throw 'Expected pinned Windows payload identity and a matching 64-bit host'
    }
    if(-not $InstallDirectory){$InstallDirectory=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AccessWeaver'}
    $directory=Get-AccessWeaverLocalDirectory $InstallDirectory
    $registration=Read-AccessWeaverRegistration Registry64
    if($null -ne (Read-AccessWeaverRegistration Registry32)){throw 'Unexpected alternate machine registration'}
    if($null -eq $registration -or $registration.version -cne $Version){exit 0}
    if((Get-AccessWeaverLocalDirectory $registration.location) -ine $directory){throw 'Unexpected registered installation directory'}
    $payload=Join-Path $directory 'accessweaver.exe'
    if(-not (Test-AccessWeaverPayload $payload $PayloadSHA256)){exit 0}
    $confirmed=Read-AccessWeaverRegistration Registry64
    if($null -eq $confirmed -or $confirmed.version -cne $registration.version -or
       $confirmed.location -cne $registration.location -or $null -ne (Read-AccessWeaverRegistration Registry32)){
        throw 'Installation registration changed during detection'
    }
    Microsoft.PowerShell.Utility\Write-Output 'AccessWeaver detected'
    exit 0
} catch {
    # Endpoint management uses stdout to determine detection. Keep all other
    # paths silent, including private path, registry and exception details.
    exit 1
}
