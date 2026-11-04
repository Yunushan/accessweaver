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
$nativeNodes=@($sourceAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Native-Record'})
Assert-State ($nativeNodes.Count -eq 1) 'Expected exactly one native record wrapper'
. ([scriptblock]::Create($nativeNodes[0].Extent.Text))
function Require([bool]$ok,[string]$message){if(-not $ok){throw $message}}
$script:syntheticNativeMode='success';$script:syntheticNativeCalls=0
function Invoke-Isolated([string]$binary,[string[]]$arguments,[int[]]$codes,[int]$Timeout){
    $script:syntheticNativeCalls++
    Assert-State ($Timeout -eq 180 -and $codes -contains 255 -and $codes -contains 3010 -and $codes -contains 1641) 'Wrapper changed timeout or diagnostic exit-code admission'
    Assert-State ($script:lastNativeAttempt.toolClass -ceq 'uninstaller' -and -not $script:lastNativeAttempt.invocationReturned -and $script:lastNativeAttempt.failureCategory -ceq 'in-progress' -and $null -eq $script:lastNativeAttempt.exitCode) 'Current native attempt was not reset before invocation'
    switch($script:syntheticNativeMode){
        'timeout' {throw ('Timed out: '+[IO.Path]::GetFileName($binary))}
        'tool-exit' {throw ('Tool failed: '+[IO.Path]::GetFileName($binary)+' (exit -1)')}
        'other' {throw 'PRIVATE_NATIVE_ERROR PRIVATE_ARGUMENT_TOKEN C:\private-input'}
        'large' {throw ('PRIVATE_NATIVE_ERROR'+('x'*8192))}
        'invalid' {return @{exitCode='PRIVATE_INVALID_VALUE';outputComplete=$true}}
        'missing' {return $null}
        'exit' {return @{exitCode=7;outputComplete=$true;stdout='PRIVATE_TOOL_OUTPUT'}}
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
Assert-State ($script:syntheticNativeCalls -eq 9) 'Synthetic wrapper coverage differs'
foreach($case in @(@{name='accessweaver.exe';wanted='core'},@{name='accessweaver-0.1.0-alpha-windows-arm64-setup.exe';wanted='setup'},@{name='unins009.exe';wanted='uninstaller'},@{name='PRIVATE_PROGRAM.exe';wanted='other'})){
    Assert-State ((Get-InstallerNativeToolClass $case.name) -ceq $case.wanted) 'Native tool classification differs'
}
foreach($message in @('Timed out: PRIVATE_OTHER.exe','Tool failed: unins000.exe (exit 9999999999)','PRIVATE_NATIVE_ERROR')){
    Assert-State ((Get-InstallerNativeFailureCategory $privateBinary $message) -ceq 'other-native-error') 'Unrecognized native error was attributed to a timeout or exit'
}
Write-Output 'Synthetic native-attempt reset, exception, privacy and unchanged deadline checks passed; no processes launched.'
