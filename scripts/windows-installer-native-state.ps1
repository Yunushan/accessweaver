# Pure classification of already captured native-attempt metadata. No OS query,
# process launch, native output, argument, basename or path is retained.
function Get-InstallerUninstallBindingRefusalCategory([string]$Message) {
    if($Message.Length -gt 4096){return 'unmapped-refusal'}
    switch -CaseSensitive ($Message) {
        'Registered AccessWeaver package directory is redirected or is not a directory' {return 'package-directory-refused'}
        'Registered AccessWeaver installation ownership could not be verified' {return 'untrusted-owner'}
        'Registered AccessWeaver installation access could not be verified' {return 'access-unavailable'}
        'Registered AccessWeaver installation is writable by an untrusted principal' {return 'untrusted-writer'}
        'Registered AccessWeaver installation must be a local Program Files directory' {return 'registered-path-refused'}
        'Registered AccessWeaver installation directory is ambiguous' {return 'registered-path-ambiguous'}
        'Registered AccessWeaver uninstall commands do not identify the installed uninstaller' {return 'registered-command-refused'}
        'AccessWeaver uninstall registration is incomplete' {return 'registration-incomplete'}
        'Unexpected alternate AccessWeaver machine registration' {return 'alternate-registration'}
        'Reparse points are not supported in installation paths' {return 'ancestor-reparse-point'}
        'AccessWeaver Setup is active or its mutex could not be inspected' {return 'setup-active-or-unavailable'}
        'An AccessWeaver installation is incomplete. Retry the approved installer before uninstalling.' {return 'installation-pending'}
        'AccessWeaver Setup recovery state could not be read. Ask an administrator to verify it before uninstalling.' {return 'recovery-unavailable'}
        default {return 'unmapped-refusal'}
    }
}

function Get-InstallerNativeToolClass([string]$Binary) {
    if($Binary.Length -gt 32768){return 'other'}
    $leaf=[IO.Path]::GetFileName($Binary)
    if($leaf -ieq 'accessweaver.exe'){return 'core'}
    if($leaf -imatch '^unins[0-9]{3}\.exe$'){return 'uninstaller'}
    if($leaf -imatch '^accessweaver-[A-Za-z0-9.+-]{1,100}-windows-(amd64|arm64)-setup\.exe$'){return 'setup'}
    return 'other'
}
function Get-InstallerNativeFailureCategory([string]$Binary,[string]$Message) {
    # Classify only the product helper's exact known error forms. A cleanup
    # exception can replace a timeout, so an unrecognized error proves neither.
    if($Binary.Length -gt 32768 -or $Message.Length -gt 4096){return 'other-native-error'}
    $leaf=[IO.Path]::GetFileName($Binary)
    if($Message -ceq ('Timed out: '+$leaf)){return 'tool-timeout'}
    $pattern='^Tool failed: '+[regex]::Escape($leaf)+' \(exit (-?[0-9]{1,10})\)$'
    $matched=[regex]::Match($Message,$pattern)
    $nativeCode=0
    if($matched.Success -and [int]::TryParse($matched.Groups[1].Value,[ref]$nativeCode)){return 'tool-exit'}
    return 'other-native-error'
}
