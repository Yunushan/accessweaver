# Pure classification of already captured native-attempt metadata. No OS query,
# process launch, native output, argument, basename or path is retained.
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
