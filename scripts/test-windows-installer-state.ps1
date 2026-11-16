# Synthetic state diagnostics only. No installer, service, firewall or DNS call.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-state.ps1')
function Assert-State([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
$baseline='{"services":[],"firewall":[{"Name":"private-rule-name","Enabled":1,"Direction":1,"Action":2}],"dns":[{"InterfaceIndex":5,"AddressFamily":2,"ServerAddresses":["192.0.2.99","192.0.2.100"]}]}'
$same=Compare-InstallerState $baseline $baseline
Assert-State $same.exactMatch 'Equal snapshots were not exact'
Assert-State ($same.domains.firewall.changed -eq 0 -and $same.domains.dns.serializedEqual) 'Equal snapshots produced changed rows'
$dns=$baseline.Replace('192.0.2.99','198.51.100.77');$delta=Compare-InstallerState $baseline $dns
Assert-State (-not $delta.exactMatch -and $delta.domains.dns.changed -eq 1 -and $delta.domains.firewall.serializedEqual) 'DNS change was not isolated'
Assert-State ($delta.domains.dns.changes[0].fields -contains 'ServerAddresses') 'DNS changed field was lost'
$public=$delta | ConvertTo-Json -Depth 16
foreach($private in @('private-rule-name','192.0.2.99','192.0.2.100','198.51.100.77')){Assert-State (-not $public.Contains($private)) 'Raw private state escaped diagnostics'}
$firewall=$baseline.Replace('"Enabled":1','"Enabled":2');$delta=Compare-InstallerState $baseline $firewall
Assert-State ($delta.domains.firewall.changed -eq 1 -and $delta.domains.firewall.changes[0].fields -contains 'Enabled' -and $delta.domains.dns.serializedEqual) 'Firewall change was not isolated'
$reordered=$baseline.Replace('"Name":"private-rule-name","Enabled":1','"Enabled":1,"Name":"private-rule-name"');$delta=Compare-InstallerState $baseline $reordered
Assert-State (-not $delta.exactMatch -and $delta.domains.firewall.rowSerializationChanges -eq 1 -and $delta.domains.firewall.changed -eq 0) 'Representation drift was confused with field mutation'
$empty='{"services":[],"firewall":[],"dns":[]}';$delta=Compare-InstallerState $baseline $empty
Assert-State ($delta.domains.firewall.removed -eq 1 -and $delta.domains.dns.removed -eq 1) 'Removed rows were not counted'
$reverse=Compare-InstallerState $empty $baseline
Assert-State ($reverse.domains.firewall.added -eq 1 -and $reverse.domains.dns.added -eq 1) 'Added rows were not counted'
$bad='{"services":[],"firewall":[{"Name":"same"},{"Name":"same"}],"dns":[]}'
$rejected=$false;try{$null=Compare-InstallerState $bad $empty}catch{$rejected=$true};Assert-State $rejected 'Duplicate row identity was accepted'
Write-Output 'Synthetic exact-state difference, privacy and representation diagnostics passed.'

# A prior drift is retained against the original baseline, even if the next
# operation preserves it. Restoring baseline must still expose a transition.
$first=New-InstallerStateCheckpoint 'after-family' $baseline $baseline $firewall
Assert-State (-not $first.comparison.exactMatch -and -not $first.transition.exactMatch) 'Initial family drift was not localized'
$unchanged=New-InstallerStateCheckpoint 'before-uninstall' $baseline $firewall $firewall
Assert-State (-not $unchanged.comparison.exactMatch -and $unchanged.transition.exactMatch) 'Prior drift was silently rebased or attributed to an unchanged transition'
$restored=New-InstallerStateCheckpoint 'after-restore' $baseline $firewall $baseline
Assert-State ($restored.comparison.exactMatch -and -not $restored.transition.exactMatch) 'Transient mutation vanished when baseline was restored'
foreach($observation in @($first,$unchanged,$restored)){
    $public=$observation | ConvertTo-Json -Depth 16
    foreach($private in @('private-rule-name','192.0.2.99','192.0.2.100')){Assert-State (-not $public.Contains($private)) 'Raw state escaped transition diagnostics'}
}
foreach($phase in @('', '../private/path', 'private phase', ('x'*81))){
    $rejected=$false;try{$null=New-InstallerStateCheckpoint $phase $baseline $baseline $baseline}catch{$rejected=$true}
    Assert-State $rejected 'Unbounded or path-like phase was accepted'
}
Write-Output 'Original-baseline, changed-transition, prior-drift, restoration and privacy diagnostics passed.'

# Captured-object metadata is independently bounded and never queries the OS.
function Get-NetFirewallRule {throw 'Unexpected native firewall query in pure diagnostics'}
function Get-NetFirewallApplicationFilter {throw 'Unexpected native application query in pure diagnostics'}
$rule=[pscustomobject]@{Name='private-rule-name';PolicyStoreSourceType='Local';PolicyStoreSource='private-policy-store';Owner='S-1-5-21-private-owner';Group='private-group';Profile='Any';PrimaryStatus='OK';EnforcementStatus='Full'}
$added=@{identitySHA256=(Get-InstallerStateTextHash $rule.Name);kind='added'}
$origins=New-InstallerFirewallOrigins 'after-family' @($added) @() @($rule) 16
Assert-State ($origins.Count -eq 1 -and -not $origins[0].before.present -and $origins[0].after.present -and $origins[0].after.policySourceClass -ceq 'Local') 'Captured addition metadata was lost'
$public=ConvertTo-Json -InputObject $origins -Depth 16
foreach($private in @('private-rule-name','private-policy-store','S-1-5-21-private-owner','private-group')){Assert-State (-not $public.Contains($private)) 'Raw captured firewall metadata escaped'}
Assert-State ($origins[0].after.fields.Owner.sha256 -ceq (Get-InstallerStateTextHash $rule.Owner)) 'Captured owner fingerprint differs'
$removed=@{identitySHA256=$added.identitySHA256;kind='removed'}
$reverse=New-InstallerFirewallOrigins 'after-family' @($removed) @($rule) @() 16
Assert-State ($reverse.Count -eq 1 -and $reverse[0].before.present -and -not $reverse[0].after.present) 'Captured removal metadata was lost'
$noOrigins=New-InstallerFirewallOrigins 'after-family' @() @($rule) @($rule) 16
Assert-State ($noOrigins.Count -eq 0) 'Unchanged state emitted origin records'
$limited=New-InstallerFirewallOrigins 'after-family' (@($added)*32) @() @($rule) 3
Assert-State ($limited.Count -eq 3) 'Captured record budget was not enforced'
$none=New-InstallerFirewallOrigins 'after-family' @($added) @() @($rule) 0
Assert-State ($none.Count -eq 0) 'Zero remaining metadata budget was ignored'
$large=[pscustomobject]@{Name='private-large-rule';Owner=('x'*4097);Group=([string][char]0x754c)*2000;PolicyStoreSourceType='private-unrecognized-origin'}
$bounded=Get-InstallerCapturedFirewallMetadata $large
Assert-State ($bounded.fields.Owner.omitted -and $bounded.fields.Group.omitted -and $bounded.policySourceClass -ceq 'unclassified' -and -not $bounded.fields.Profile.present) 'Byte/missing/unrecognized metadata bounds differ'
$public=$bounded | ConvertTo-Json -Depth 16
Assert-State (-not $public.Contains('private-unrecognized-origin') -and -not $public.Contains('private-large-rule')) 'Unrecognized metadata escaped'
foreach($case in @(
    @{phase='../private';changes=@($added);before=@();after=@($rule);remaining=16},
    @{phase='after-family';changes=@($added);before=@();after=@($rule);remaining=17},
    @{phase='after-family';changes=(@($added)*33);before=@();after=@($rule);remaining=16},
    @{phase='after-family';changes=@($added);before=@();after=@($rule,$rule);remaining=16},
    @{phase='after-family';changes=@(@{identitySHA256='private';kind='added'});before=@();after=@($rule);remaining=16},
    @{phase='after-family';changes=@(@{identitySHA256=$added.identitySHA256;kind='private'});before=@();after=@($rule);remaining=16}
)){
    $rejected=$false;try{$null=New-InstallerFirewallOrigins $case.phase $case.changes $case.before $case.after $case.remaining}catch{$rejected=$true}
    Assert-State $rejected 'Malformed or excessive captured metadata was accepted'
}
Write-Output 'Captured firewall source/owner privacy, no-query behavior and independent record/string bounds passed.'

# Execute only the fixture's checkpoint function with a synthetic snapshot
# provider. This checks global frame bounds and retained comparisons, without
# sourcing the installer body or querying/changing any operating-system state.
$tokens=$null;$parseErrors=$null
$sourceAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'test-windows-installer-lifecycle.ps1'),[ref]$tokens,[ref]$parseErrors)
Assert-State (-not $parseErrors.Count) 'Lifecycle source did not parse'
$checkpointNodes=@($sourceAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'State-Checkpoint'})
Assert-State ($checkpointNodes.Count -eq 1) 'Expected exactly one lifecycle checkpoint function'
. ([scriptblock]::Create($checkpointNodes[0].Extent.Text))
$script:syntheticFrame=0
function State-Snapshot {
    $script:syntheticFrame++
    $script:stateFirewallRules=@([pscustomobject]@{Name=('private-captured-'+$script:syntheticFrame);PolicyStoreSourceType='Local';Owner='private-owner'})
    $selected=@($script:stateFirewallRules | Select-Object Name)
    return (ConvertTo-Json -InputObject @{services=@();firewall=$selected;dns=@()} -Compress -Depth 8)
}
$script:stateBaseline=$empty;$script:statePrevious=$empty;$script:statePreviousFirewallRules=@();$script:stateObservations=@();$script:firewallOriginObservations=@();$script:firewallOriginTruncated=$false;$script:firewallOriginUnavailable=$false
foreach($frame in 1..18){$null=State-Checkpoint ('after-family-'+$frame)}
Assert-State ($script:firewallOriginObservations.Count -eq 16 -and $script:firewallOriginTruncated -and -not $script:firewallOriginUnavailable) 'Global origin budget or diagnostic completeness changed'
Assert-State ($script:stateObservations.Count -eq 18) 'Diagnostic limits removed state checkpoints'
foreach($observation in $script:stateObservations){
    Assert-State (-not $observation.comparison.exactMatch -and -not $observation.transition.exactMatch -and $observation.comparison.beforeSHA256 -ceq (Get-InstallerStateTextHash $empty)) 'Origin diagnostics weakened or rebased original comparisons'
}
$public=ConvertTo-Json -InputObject $script:firewallOriginObservations -Depth 16
Assert-State (-not $public.Contains('private-captured-') -and -not $public.Contains('private-owner')) 'Checkpoint integration disclosed raw origin metadata'
Write-Output 'Checkpoint integration preserves comparisons and global origin limits with synthetic snapshots only.'


# Exercise the actual Native-Record wrapper with a fully synthetic invocation.
# Parse/import its function only; never source the disposable installer body.
. (Join-Path $PSScriptRoot 'windows-installer-native-state.ps1')
$packageRefusal='Registered AccessWeaver package directory is redirected or is not a directory'
Assert-State ((Get-InstallerUninstallBindingRefusalCategory $packageRefusal) -ceq 'package-directory-refused') 'The package-directory refusal was not identified'
Assert-State ((Get-InstallerUninstallBindingRefusalCategory 'Registered AccessWeaver installation ownership could not be verified') -ceq 'untrusted-owner') 'An earlier ownership refusal was confused with a package junction'
Assert-State ((Get-InstallerUninstallBindingRefusalCategory 'AccessWeaver Setup is active or its mutex could not be inspected') -ceq 'setup-active-or-unavailable') 'Setup admission failure was confused with package inspection'
foreach($message in @('PRIVATE_ACCOUNT PRIVATE_PATH PRIVATE_TOKEN',('prefix '+$packageRefusal),($packageRefusal+' suffix'),$packageRefusal.ToUpperInvariant(),('x'*4097),'')){
    $code=Get-InstallerUninstallBindingRefusalCategory $message
    Assert-State ($code -ceq 'unmapped-refusal' -and -not $code.Contains('PRIVATE')) 'Unrecognized or oversized native errors escaped the closed diagnostic category'
}

$nativeNodes=@($sourceAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Native-Record'})
Assert-State ($nativeNodes.Count -eq 1) 'Expected exactly one native record wrapper'
. ([scriptblock]::Create($nativeNodes[0].Extent.Text))
function Require([bool]$ok,[string]$message){if(-not $ok){throw $message}}
$script:syntheticNativeMode='success';$script:syntheticNativeCalls=0
function Invoke-Isolated([string]$binary,[string[]]$arguments,[int[]]$codes,[int]$Timeout){
    $script:syntheticNativeCalls++
    Assert-State ($Timeout -eq 180 -and $codes -contains 255 -and $codes -contains 3010 -and $codes -contains 1641) 'Wrapper changed timeout or diagnostic exit-code admission'
    $expectedToolClass=if($script:syntheticNativeMode -ceq 'custom-exit'){'setup'}else{'uninstaller'}
    Assert-State ($script:lastNativeAttempt.toolClass -ceq $expectedToolClass -and -not $script:lastNativeAttempt.invocationReturned -and $script:lastNativeAttempt.failureCategory -ceq 'in-progress' -and $null -eq $script:lastNativeAttempt.exitCode) 'Current native attempt was not reset before invocation'
    switch($script:syntheticNativeMode){
        'timeout' {throw ('Timed out: '+[IO.Path]::GetFileName($binary))}
        'tool-exit' {throw ('Tool failed: '+[IO.Path]::GetFileName($binary)+' (exit -1)')}
        'other' {throw 'PRIVATE_NATIVE_ERROR PRIVATE_ARGUMENT_TOKEN C:\private-input'}
        'large' {throw ('PRIVATE_NATIVE_ERROR'+('x'*8192))}
        'invalid' {return @{exitCode='PRIVATE_INVALID_VALUE';outputComplete=$true}}
        'missing' {return $null}
        'exit' {return @{exitCode=7;outputComplete=$true;stdout='PRIVATE_TOOL_OUTPUT'}}
        'custom-exit' {
            if($codes -notcontains 1603){throw ('Tool failed: '+[IO.Path]::GetFileName($binary)+' (exit 1603)')}
            return @{exitCode=1603;outputComplete=$true}
        }
        'incomplete' {return @{exitCode=0;outputComplete=$false;stderr='PRIVATE_TOOL_OUTPUT'}}
        default {return @{exitCode=0;outputComplete=$true;stdout='PRIVATE_TOOL_OUTPUT'}}
    }
}
$privateBinary=Join-Path ([IO.Path]::GetTempPath()) 'PRIVATE_DIRECTORY\unins000.exe'
$null=Native-Record $privateBinary @('PRIVATE_ARGUMENT_TOKEN')
$prior=$script:lastNative
Assert-State ($script:lastNativeAttempt.operationAccepted -and $script:lastNativeAttempt.failureCategory -ceq 'none') 'Successful attempt was not retained'
foreach($case in @(
    @{mode='timeout';category='tool-timeout';returned=$false;code=$null;complete=$null},
    @{mode='tool-exit';category='tool-exit';returned=$false;code=$null;complete=$null},
    @{mode='other';category='other-native-error';returned=$false;code=$null;complete=$null},
    @{mode='large';category='other-native-error';returned=$false;code=$null;complete=$null},
    @{mode='invalid';category='invalid-native-result';returned=$true;code=$null;complete=$null},
    @{mode='missing';category='invalid-native-result';returned=$true;code=$null;complete=$null},
    @{mode='exit';category='unexpected-exit';returned=$true;code=7;complete=$true},
    @{mode='incomplete';category='incomplete-output';returned=$true;code=0;complete=$false}
)){
    $script:syntheticNativeMode=$case.mode;$failed=$false
    try{$null=Native-Record $privateBinary @('PRIVATE_ARGUMENT_TOKEN')}catch{$failed=$true}
    Assert-State $failed 'Synthetic native failure was swallowed'
    $attempt=$script:lastNativeAttempt
    Assert-State ($attempt.invocationReturned -eq $case.returned -and -not $attempt.operationAccepted -and $attempt.failureCategory -ceq $case.category -and $attempt.exitCode -eq $case.code -and $attempt.outputComplete -eq $case.complete) 'Failed-attempt metadata differs'
    Assert-State ($attempt.elapsedMilliseconds -ge 0 -and $attempt.timeoutMilliseconds -eq 180000 -and $attempt.schemaVersion -eq 1) 'Failed-attempt timing or version was lost'
    $public=$attempt | ConvertTo-Json -Compress
    Assert-State ($public.Length -le 512) 'Native-attempt metadata is unbounded'
    foreach($private in @('PRIVATE_','unins000.exe','C:\private-input')){Assert-State (-not $public.Contains($private)) 'Private native material escaped the diagnostic envelope'}
    if(-not $case.returned){Assert-State ([object]::ReferenceEquals($prior,$script:lastNative)) 'A thrown invocation pretended to return a new native result'}
}
$script:syntheticNativeMode='custom-exit'
$syntheticSetup=Join-Path ([IO.Path]::GetTempPath()) 'PRIVATE_DIRECTORY\accessweaver-0.1.0-alpha-windows-arm64-setup.exe'
$custom=Native-Record $syntheticSetup @('PRIVATE_ARGUMENT_TOKEN') @(1603)
$attempt=$script:lastNativeAttempt
Assert-State ($custom.result.exitCode -eq 1603 -and $attempt.invocationReturned -and $attempt.operationAccepted -and $attempt.exitCode -eq 1603 -and $attempt.outputComplete -and $attempt.failureCategory -ceq 'none') 'Requested custom Setup exit was rejected or lost'
$failed=$false
try{$null=Native-Record $syntheticSetup @('PRIVATE_ARGUMENT_TOKEN')}catch{$failed=$true}
$attempt=$script:lastNativeAttempt
Assert-State ($failed -and -not $attempt.invocationReturned -and -not $attempt.operationAccepted -and $attempt.failureCategory -ceq 'tool-exit') 'A custom Setup exit was accepted without an explicit expectation'
Assert-State ($script:syntheticNativeCalls -eq 11) 'Synthetic wrapper coverage differs'
foreach($case in @(@{name='accessweaver.exe';wanted='core'},@{name='accessweaver-0.1.0-alpha-windows-arm64-setup.exe';wanted='setup'},@{name='unins009.exe';wanted='uninstaller'},@{name='PRIVATE_PROGRAM.exe';wanted='other'})){
    Assert-State ((Get-InstallerNativeToolClass $case.name) -ceq $case.wanted) 'Native tool classification differs'
}
foreach($message in @('Timed out: PRIVATE_OTHER.exe','Tool failed: unins000.exe (exit 9999999999)','PRIVATE_NATIVE_ERROR')){
    Assert-State ((Get-InstallerNativeFailureCategory $privateBinary $message) -ceq 'other-native-error') 'Unrecognized native error was attributed to a timeout or exit'
}
Write-Output 'Synthetic native-attempt reset, exception, privacy and unchanged deadline checks passed; no processes launched.'


& {
    param([string]$DiagnosticScriptRoot=$PSScriptRoot)
    # Closed protection diagnostic contracts: in-memory ACLs and fake owners only.
    $testAdmin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $testUsers=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $syntheticSID='S-1-5-21-101-202-303-404'
    $guardTokens=$null;$guardErrors=$null
    $guardAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $DiagnosticScriptRoot '..\internal\workflow\windows.ps1'),[ref]$guardTokens,[ref]$guardErrors)
    Assert-State (-not $guardErrors.Count) 'ACL source did not parse'
    $aclNode=@($guardAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Assert-WorkflowUninstallACL'})
    Assert-State ($aclNode.Count -eq 1) 'Expected one actual ACL decision function'
    . ([scriptblock]::Create($aclNode[0].Extent.Text))
    $script:installerOriginalACL=(Get-Command Assert-WorkflowUninstallACL).ScriptBlock
    $sourceTokens=$null;$sourceErrors=$null
    $sourceAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $DiagnosticScriptRoot 'test-windows-installer-lifecycle.ps1'),[ref]$sourceTokens,[ref]$sourceErrors)
    Assert-State (-not $sourceErrors.Count) 'Installer diagnostic wrappers did not parse'
    foreach($name in @('Assert-WorkflowUninstallACL','Assert-WorkflowUninstallProtection')){
        $selected=@($sourceAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
        Assert-State ($selected.Count -eq 1) 'Expected one pass-through diagnostic wrapper'
        . ([scriptblock]::Create($selected[0].Extent.Text))
    }
    $script:installerAdministratorSID=$syntheticSID
    $stage='synthetic-protection-initial'
    $script:installerProtectionDiagnosticStage=$null
    $script:installerProtectionRole='controller'
    $script:installerProtectionDiagnostic=$null
    $writeMessage='Registered AccessWeaver installation is writable by an untrusted principal'
    $shape=@('schemaVersion','scope','aclKind','failureCategory','ownerClass','writerClass','matchedWriteBits',
        'inherited','inheritanceFlags','propagationFlags','aclSnapshotReadCompleted','offendingAceFound')
    $snapshots=0
    foreach($case in @(
        @{acl=[Security.AccessControl.FileSecurity]::new();kind=[Security.AccessControl.FileSystemAccessRule];read=[Security.AccessControl.FileSystemRights]::ReadAndExecute;write=[Security.AccessControl.FileSystemRights]::Write;wanted='file';scope='controller'},
        @{acl=[Security.AccessControl.DirectorySecurity]::new();kind=[Security.AccessControl.FileSystemAccessRule];read=[Security.AccessControl.FileSystemRights]::ReadAndExecute;write=[Security.AccessControl.FileSystemRights]::Write;wanted='directory';scope='controller'},
        @{acl=[Security.AccessControl.RegistrySecurity]::new();kind=[Security.AccessControl.RegistryAccessRule];read=[Security.AccessControl.RegistryRights]::ReadKey;write=[Security.AccessControl.RegistryRights]::SetValue;wanted='registry';scope='registration'}
    )){
        $case.acl.SetOwner($testAdmin)
        $case.acl.AddAccessRule($case.kind::new($testAdmin,$case.write,'Allow'))
        $case.acl.AddAccessRule($case.kind::new($testUsers,$case.read,'Allow'))
        $script:installerProtectionDiagnostic=$null
        $accepted=@(Assert-WorkflowUninstallACL $case.acl ([int]$case.write))
        Assert-State ($accepted.Count -eq 0 -and $null -eq $script:installerProtectionDiagnostic) 'Wrapper changed a successful ACL outcome'
        $case.acl.AddAccessRule($case.kind::new($testUsers,$case.write,'Allow'))
        $refused=$false
        try{Assert-WorkflowUninstallACL $case.acl ([int]$case.write)}catch{$refused=$_.Exception.Message -ceq $writeMessage}
        Assert-State $refused 'Wrapper changed the original writable ACL refusal'
        $diag=$script:installerProtectionDiagnostic
        Assert-State ($diag.aclKind -ceq $case.wanted -and $diag.scope -ceq $case.scope -and $diag.ownerClass -ceq 'administrators' -and
            $diag.writerClass -ceq 'users' -and $diag.matchedWriteBits -eq [int]$case.write -and $diag.offendingAceFound -and
            $diag.aclSnapshotReadCompleted -and -not $diag.inherited -and $diag.failureCategory -ceq 'untrusted-writer') 'ACL snapshot classification differs from the actual refusal'
        Assert-State (@($diag.Keys | Where-Object {$_ -cnotin $shape}).Count -eq 0 -and $diag.Count -eq $shape.Count) 'Diagnostic acquired an unreviewed field'
        $first=$diag
        try{Assert-WorkflowUninstallACL $case.acl ([int]$case.write)}catch{}
        Assert-State ([object]::ReferenceEquals($first,$script:installerProtectionDiagnostic)) 'Later refusals replaced the first diagnostic'
        $public=$diag | ConvertTo-Json -Compress
        Assert-State ($public.Length -le 1024 -and -not $public.Contains($syntheticSID)) 'ACL identity escaped the bounded diagnostic'
        $snapshots++
        $script:wrapperAcl=$case.acl;$script:wrapperWrite=[int]$case.write
    }
    $previousDiagnostic=$script:installerProtectionDiagnostic
    $stage='synthetic-protection-next'
    try{Assert-WorkflowUninstallACL $script:wrapperAcl $script:wrapperWrite}catch{}
    Assert-State (-not [object]::ReferenceEquals($previousDiagnostic,$script:installerProtectionDiagnostic) -and
        $script:installerProtectionDiagnosticStage -ceq $stage) 'A previous stage diagnostic was attributed to a later protection failure'
    $privateRoot='C:\PRIVATE_ACCOUNT\PRIVATE_INSTALL'
    foreach($entry in @(
        @{path=$privateRoot;role='installation-directory'},
        @{path='C:\PRIVATE_ACCOUNT';role='program-files-parent'},
        @{path=($privateRoot+'\docs\assets');role='package-docs-assets'},
        @{path=($privateRoot+'\licenses');role='package-licenses'},
        @{path=($privateRoot+'\unins003.exe');role='uninstaller'},
        @{path=($privateRoot+'\unins003.dat');role='uninstall-data'},
        @{path=($privateRoot+'\PRIVATE_TOKEN');role='unknown'}
    )){
        Assert-State ((Get-InstallerProtectionPathRole $entry.path $privateRoot 'C:\PRIVATE_ACCOUNT') -ceq $entry.role) 'Private path was not reduced to the expected fixed role'
    }
    $specific=[Security.AccessControl.FileSecurity]::new();$specific.SetOwner($testAdmin)
    $specific.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($syntheticSID),[Security.AccessControl.FileSystemRights]::Write,'Allow'))
    $current=Get-InstallerACLFailureDiagnostic $specific ([int][Security.AccessControl.FileSystemRights]::Write) 'PRIVATE_PATH' $writeMessage $syntheticSID
    Assert-State ($current.writerClass -ceq 'current-administrator' -and $current.scope -ceq 'unknown') 'Current fixture administrator was not privately classified'
    # The native refusal retained an inherited registry writer outside the old
    # closed classes. Classify only fixed roles/families, never the actual SID.
    foreach($entry in @(
        @{sid='S-1-5-32-547';wanted='power-users'},
        @{sid='S-1-5-4';wanted='interactive'},
        @{sid='S-1-5-6';wanted='service-logon'},
        @{sid='S-1-5-19';wanted='local-service'},
        @{sid='S-1-5-20';wanted='network-service'},
        @{sid='S-1-5-12';wanted='restricted'},
        @{sid='S-1-5-33';wanted='write-restricted'},
        @{sid='S-1-15-2-1';wanted='all-application-packages'},
        @{sid='S-1-15-2-2';wanted='all-restricted-application-packages'},
        @{sid='S-1-5-32-999';wanted='builtin-other'},
        @{sid='S-1-5-80-101-202-303-404-505';wanted='service-account'},
        @{sid='S-1-15-3-101-202';wanted='application-capability'},
        @{sid='S-1-15-2-101-202';wanted='application-package'},
        @{sid='S-1-5-21-101-202-303-405';wanted='account-domain'}
    )){
        Assert-State ((Get-InstallerACLPrincipalClass $entry.sid '') -ceq $entry.wanted) 'Closed principal family classification differs'
        $registry=[Security.AccessControl.RegistrySecurity]::new()
        # The inherited ACE and write bits reproduce the public native receipt.
        $registry.SetSecurityDescriptorSddlForm(('O:BAG:BAD:(A;;KA;;;BA)(A;ID;0x10006;;;'+$entry.sid+')'))
        $script:installerProtectionDiagnostic=$null
        $refused=$false
        try{Assert-WorkflowUninstallACL $registry 0x000d0026}catch{$refused=$_.Exception.Message -ceq $writeMessage}
        $classified=$script:installerProtectionDiagnostic
        Assert-State ($refused -and $classified.writerClass -ceq $entry.wanted -and
            $classified.scope -ceq 'registration' -and $classified.inherited -and
            $classified.matchedWriteBits -eq 0x10006 -and $classified.offendingAceFound) 'Diagnostic principal classification changed the actual inherited registry writer refusal'
        $public=$classified | ConvertTo-Json -Compress
        Assert-State ($public.Length -le 1024 -and -not $public.Contains($entry.sid)) 'A principal identifier escaped the family diagnostic'
    }
    foreach($invalid in @('PRIVATE_SID',('S-1-5-21-'+('1'*185)),'S-1-5-21-101-PRIVATE_TOKEN')){
        Assert-State ((Get-InstallerACLPrincipalClass $invalid '') -ceq 'other') 'Invalid or excessive identifier acquired a principal family'
    }
    Assert-State ((Get-InstallerACLPrincipalClass $syntheticSID $syntheticSID) -ceq 'current-administrator') 'Account family replaced the exact current administrator classification'
    $inherited=[Security.AccessControl.DirectorySecurity]::new();$inherited.SetOwner($testAdmin)
    $inherited.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-3-0'),[Security.AccessControl.FileSystemRights]::Write,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::InheritOnly,'Allow'))
    & $script:installerOriginalACL $inherited ([int][Security.AccessControl.FileSystemRights]::Write)
    $inactive=Get-InstallerACLFailureDiagnostic $inherited ([int][Security.AccessControl.FileSystemRights]::Write) 'program-files-parent' $writeMessage $syntheticSID
    Assert-State (-not $inactive.offendingAceFound -and $inactive.matchedWriteBits -eq 0) 'Inherit-only rights were confused with a writable current object'
    $unknown=Get-InstallerACLFailureDiagnostic ([pscustomobject]@{PRIVATE_ACCOUNT='PRIVATE_TOKEN'}) 1 'PRIVATE_PATH' 'PRIVATE_ERROR' 'PRIVATE_SID'
    foreach($diag in @($current,$inactive,$unknown)){
        $public=$diag | ConvertTo-Json -Compress
        foreach($private in @('PRIVATE_',$syntheticSID,$privateRoot,$writeMessage)){
            Assert-State (-not $public.Contains($private)) 'Private input or raw error escaped the ACL diagnostic'
        }
        Assert-State ($public.Length -le 1024) 'ACL diagnostic exceeds its envelope'
    }
    $install=$privateRoot;$programFiles='C:\PRIVATE_ACCOUNT'
    $script:installerProtectionRole='unknown';$script:installerProtectionDiagnostic=$null;$script:protectionCalls=0
    $script:wrapperAcl=$specific;$script:wrapperWrite=[int][Security.AccessControl.FileSystemRights]::Write
    $script:installerOriginalProtection={param($Path)
        $script:protectionCalls++
        Assert-WorkflowUninstallACL $script:wrapperAcl $script:wrapperWrite
    }
    $refused=$false
    try{Assert-WorkflowUninstallProtection ($install+'\licenses')}catch{$refused=$_.Exception.Message -ceq $writeMessage}
    Assert-State ($refused -and $script:protectionCalls -eq 1 -and $script:installerProtectionRole -ceq 'unknown' -and
        $script:installerProtectionDiagnostic.scope -ceq 'package-licenses') 'Protected-call forwarding or role cleanup changed'
    & {
        function Get-InstallerACLFailureDiagnostic {throw 'Synthetic diagnostic fault'}
        $script:installerProtectionDiagnostic=$null;$refused=$false
        try{Assert-WorkflowUninstallACL $script:wrapperAcl $script:wrapperWrite}catch{$refused=$_.Exception.Message -ceq $writeMessage}
        Assert-State ($refused -and $null -eq $script:installerProtectionDiagnostic) 'Diagnostic failure replaced or swallowed the controller refusal'
    }
    & {
        function Get-InstallerProtectionPathRole {throw 'Synthetic diagnostic role fault'}
        $script:installerOriginalProtection={param($Path) return 'unchanged-success'}
        $value=Assert-WorkflowUninstallProtection ($install+'\licenses')
        Assert-State ($value -ceq 'unchanged-success' -and $script:installerProtectionRole -ceq 'unknown') 'Role diagnostic fault changed the protected operation return'
    }
    $emit=@($sourceAst.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('$record.uninstallProtectionDiagnostic=')
    })
    Assert-State ($emit.Count -eq 1) 'Expected one failure-only diagnostic projection'
    foreach($case in @(
        @{complete=$false;current=$true;present=$true;emit=$true},
        @{complete=$true;current=$true;present=$true;emit=$false},
        @{complete=$false;current=$false;present=$true;emit=$false},
        @{complete=$false;current=$true;present=$false;emit=$false}
    )){
        $complete=$case.complete;$record=[ordered]@{schemaVersion=61}
        $script:installerProtectionDiagnostic=if($case.present){$current}else{$null}
        $script:installerProtectionDiagnosticStage=if($case.current){$stage}else{'synthetic-earlier-stage'}
        . ([scriptblock]::Create($emit[0].Extent.Text))
        Assert-State ($record.Contains('uninstallProtectionDiagnostic') -eq $case.emit) 'Diagnostic changed successful report shape or disclosed stale-stage evidence'
    }
    Write-Output 'Synthetic ACL diagnostics preserve original decisions, first-fault ownership and privacy; no native state queried.'
}
