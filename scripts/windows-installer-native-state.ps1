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

# Test diagnostics inspect an already captured ACL object, never the OS. Private
# identities and paths are reduced to fixed categories before report composition.
function Get-InstallerProtectionPathRole([string]$Path,[string]$Installation,[string]$ProgramFiles) {
    if(-not $Path -or -not $Installation -or -not $ProgramFiles -or
        $Path.Length -gt 32768 -or $Installation.Length -gt 32768 -or $ProgramFiles.Length -gt 32768){return 'unknown'}
    try {
        if($Path -ieq $Installation){return 'installation-directory'}
        if($Path -ieq $ProgramFiles){return 'program-files-parent'}
        foreach($entry in @(
            @{path='licenses';role='package-licenses'},@{path='docs';role='package-docs'},
            @{path='docs\assets';role='package-docs-assets'},@{path='docs\qualification';role='package-docs-qualification'},
            @{path='accessweaver.exe';role='controller'}
        )){
            if($Path -ieq [IO.Path]::Combine($Installation,$entry.path)){return $entry.role}
        }
        if([IO.Path]::GetDirectoryName($Path) -ieq $Installation){
            $leaf=[IO.Path]::GetFileName($Path)
            if($leaf -imatch '^unins[0-9]{3}\.exe$'){return 'uninstaller'}
            if($leaf -imatch '^unins[0-9]{3}\.dat$'){return 'uninstall-data'}
        }
    } catch {}
    return 'unknown'
}
function Get-InstallerACLPrincipalClass([string]$SID,[string]$AdministratorSID) {
    switch -CaseSensitive ($SID) {
        'S-1-5-18' {return 'system'}
        'S-1-5-32-544' {return 'administrators'}
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' {return 'trusted-installer'}
        'S-1-1-0' {return 'everyone'}
        'S-1-5-11' {return 'authenticated-users'}
        'S-1-5-32-545' {return 'users'}
        'S-1-3-0' {return 'creator-owner'}
    }
    if(-not $SID){return 'unavailable'}
    if($SID.Length -le 184 -and $SID -cmatch '^S-1-[0-9]+(?:-[0-9]+){1,15}$' -and
        $SID -ceq $AdministratorSID){return 'current-administrator'}
    return 'other'
}
function Get-InstallerACLFailureDiagnostic($Acl,[int]$WriteRights,[string]$Role,[string]$Message,[string]$AdministratorSID) {
    if($Role -cnotin @('registration','installation-directory','program-files-parent','package-licenses','package-docs',
        'package-docs-assets','package-docs-qualification','controller','uninstaller','uninstall-data')){$Role='unknown'}
    $record=[ordered]@{schemaVersion=1;scope=$Role;aclKind='unavailable';
        failureCategory=(Get-InstallerUninstallBindingRefusalCategory $Message);ownerClass='unavailable';
        writerClass='unavailable';matchedWriteBits=0;inherited=$null;inheritanceFlags=$null;propagationFlags=$null;
        aclSnapshotReadCompleted=$false;offendingAceFound=$false}
    if($Acl -is [Security.AccessControl.RegistrySecurity]){$record.aclKind='registry';$record.scope='registration'}
    elseif($Acl -is [Security.AccessControl.DirectorySecurity]){$record.aclKind='directory'}
    elseif($Acl -is [Security.AccessControl.FileSecurity]){$record.aclKind='file'}
    else{return $record}
    try {
        $record.ownerClass=Get-InstallerACLPrincipalClass ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) $AdministratorSID
        $rules=@($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if($rules.Count -gt 4096){return $record}
        $record.aclSnapshotReadCompleted=$true
        if($record.failureCategory -cne 'untrusted-writer'){return $record}
        $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        $writes=$WriteRights -bor 0x50000000
        foreach($rule in $rules){
            $rights=if($rule -is [Security.AccessControl.FileSystemAccessRule]){[int]$rule.FileSystemRights}
                elseif($rule -is [Security.AccessControl.RegistryAccessRule]){[int]$rule.RegistryRights}else{continue}
            $matched=$rights -band $writes
            if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
                -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $matched){
                $record.writerClass=Get-InstallerACLPrincipalClass $rule.IdentityReference.Value $AdministratorSID
                # Only recognized file/registry/generic write bits can leave the snapshot.
                $record.matchedWriteBits=$matched -band 0x500d0176
                $record.inherited=[bool]$rule.IsInherited
                $record.inheritanceFlags=[int]$rule.InheritanceFlags
                $record.propagationFlags=[int]$rule.PropagationFlags
                $record.offendingAceFound=$true
                break
            }
        }
    } catch {}
    return $record
}
