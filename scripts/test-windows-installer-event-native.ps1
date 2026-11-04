# Separate controlled native event-adapter probe on disposable hosted Windows.
# It never runs an installer, enables a rule/log, repairs unrelated state, or
# establishes a process origin. Do not source this file from a developer shell.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop';$WarningPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue';$VerbosePreference='SilentlyContinue';$DebugPreference='SilentlyContinue';$InformationPreference='SilentlyContinue'
if($env:OS -cne 'Windows_NT' -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:ACCESSWEAVER_DISPOSABLE_INSTALLER_EVENT_TEST -cne '1' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver'){throw 'Native event probe requires explicit disposable hosted Windows context'}
if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Native event probe requires hosted Windows PowerShell 5.1'}
$source=$env:GITHUB_SHA;$sourceRef=$env:GITHUB_REF;$run=$env:GITHUB_RUN_ID
if($source -cnotmatch '^[a-f0-9]{40}$' -or $sourceRef -cnotmatch '^refs/heads/[A-Za-z0-9_./-]+$' -or $run -cnotmatch '^[1-9][0-9]*$'){throw 'Native event probe requires source-bound hosted identity'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} finally {$identity.Dispose()}
if(-not $admin -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant() -cne @{amd64='x64';arm64='arm64'}[$Architecture]){throw 'Native event probe requires matching elevated hosted architecture'}
$project=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$head=@(& git -C $project rev-parse HEAD 2>$null);if($LASTEXITCODE -ne 0 -or $head.Count -ne 1 -or $head[0] -cne $source){throw 'Native event probe source differs'}
$dirty=@(& git -C $project status --porcelain --untracked-files=no 2>$null);if($LASTEXITCODE -ne 0 -or $dirty.Count){throw 'Native event probe requires clean tracked source'}
. (Join-Path $PSScriptRoot 'windows-installer-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-native-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-event-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-event-fixture.ps1')
function Get-EventProbeFunctionSource([string]$Path,[string]$Name){
    $tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$issues)
    if($issues.Count){throw 'Native event probe dependency parse failed'}
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $Name})
    if($nodes.Count -ne 1){throw 'Native event probe dependency definition differs'}
    return $nodes[0].Extent.Text
}
$workflowPath=Join-Path $project 'internal\workflow\windows.ps1'
foreach($name in @('No-Reparse','Quote-Arg','Native-Argument','New-ToolCapture','Receive-ToolCapture','Wait-ToolCapture','Stop-ToolTreeWithHelper','Stop-ToolTree','Run-Tool','Native','Get-DriverServiceControllers','Get-ServiceInspection','Private-DirectorySecurity')){. ([scriptblock]::Create((Get-EventProbeFunctionSource $workflowPath $name)))}
$lifecyclePath=Join-Path $PSScriptRoot 'test-windows-installer-lifecycle.ps1'
foreach($name in @('Require','Invoke-Isolated','State-Snapshot','Read-FirewallEventDiagnostic','Remove-OwnedTree')){. ([scriptblock]::Create((Get-EventProbeFunctionSource $lifecyclePath $name)))}
function Get-EventProbeSnapshot {
    $items=@(& {$WarningPreference='Continue';State-Snapshot} 3>&1)
    if($items.Count -ne 1 -or $items[0] -isnot [string]){throw 'Native event probe snapshot is incomplete'}
    return $items[0]
}
function Get-EventProbeOwnedBundle([string]$Name){
    $warnings=@()
    $rules=@(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
    if($rules.Count -ne 1 -or $rules[0] -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Native event probe rule identity is ambiguous'}
    $rule=$rules[0]
    $filters=[ordered]@{
        application=@(NetSecurity\Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
        address=@(NetSecurity\Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
        port=@(NetSecurity\Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
        service=@(NetSecurity\Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
        interface=@(NetSecurity\Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
        interfaceType=@(NetSecurity\Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
        security=@(NetSecurity\Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable +warnings -ErrorAction Stop)
    }
    if($warnings.Count){throw 'Native event probe filter enumeration was incomplete'}
    foreach($kind in $filters.Keys){if($filters[$kind].Count -ne 1 -or $filters[$kind][0] -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Native event probe filter identity is ambiguous'}}
    return @{rule=$rule;filters=$filters}
}
$dependencies=[ordered]@{}
foreach($path in @('scripts/test-windows-installer-event-native.ps1','scripts/windows-installer-event-fixture.ps1','scripts/test-windows-installer-lifecycle.ps1','scripts/windows-installer-state.ps1','scripts/windows-installer-native-state.ps1','scripts/windows-installer-event-state.ps1','internal/workflow/windows.ps1')){$dependencies[$path]=(Get-FileHash -LiteralPath (Join-Path $project $path) -Algorithm SHA256).Hash.ToLowerInvariant()}
$nonce=[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N');$token=[guid]::NewGuid().ToString('N')
$ruleName='AccessWeaverDiagnosticFixture-'+$nonce
if([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)){throw 'Native event probe temporary root is unavailable'}
$temporary=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
if($temporary.TrimEnd('\') -ceq [IO.Path]::GetPathRoot($temporary).TrimEnd('\') -or -not (Test-Path -LiteralPath $temporary -PathType Container)){throw 'Native event probe temporary root differs'}
$temporary=$temporary.TrimEnd('\');No-Reparse $temporary
$capsuleLeaf='accessweaver-event-probe-'+$nonce;$capsule=Join-Path $temporary $capsuleLeaf
$profile=Join-Path $capsule 'profile';$privateTemp=Join-Path $capsule 'process-temp';$root=$capsule
$managedParent=[Environment]::GetFolderPath('CommonApplicationData')
$marker=Join-Path $capsule '.owned-event-probe';$markerHash=Get-InstallerStateTextHash $token
$script:restoreFixtureConfiguration=$null;$script:assertionFailure=$null;$script:assertionFailureLine=$null
$script:firewallEventWindowStartUtc=[datetime]::MinValue;$script:firewallOriginObservations=@()
$attemptSentinel=[ordered]@{fixture='event-probe-attempt-sentinel'};$returnSentinel=[ordered]@{fixture='event-probe-return-sentinel'}
$script:lastNativeAttempt=$attemptSentinel;$script:lastNative=$returnSentinel
$attemptHash=Get-InstallerStateValueHash $attemptSentinel;$returnHash=Get-InstallerStateValueHash $returnSentinel
$stage='prepare';$failure=$null;$baseline=$null;$controlled=$null;$restored=$null;$ownership=$null;$capsuleOwned=$false
$created=$false;$creationAttempted=$false;$disabled=$false;$guardVerified=$false;$removed=$false;$tempRemoved=$false;$refused=$false;$adapterCalled=$false;$attemptPreserved=$false;$returnPreserved=$false;$baselineRestored=$false
$diagnostic=New-InstallerFirewallEventDiagnostic;$adapterFailure=[ordered]@{stage='none';nativeFailureCategory='none'}
try {
    if(Test-Path -LiteralPath $capsule){throw 'Native event probe capsule already exists'}
    [void][IO.Directory]::CreateDirectory($capsule,(Private-DirectorySecurity));No-Reparse $capsule
    $stream=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes($token);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    $capsuleOwned=$true
    foreach($path in @($profile,$privateTemp,(Join-Path $profile 'roaming'),(Join-Path $profile 'local'))){[void][IO.Directory]::CreateDirectory($path);No-Reparse $path}
    $stage='baseline';$script:firewallEventWindowStartUtc=[datetime]::UtcNow;$baseline=Get-EventProbeSnapshot
    $null=Compare-InstallerState $baseline $baseline
    if(@($script:stateFirewallRules | Where-Object {[string]$_.Name -ceq $ruleName}).Count){throw 'Native event probe identity already exists'}
    $activeWarnings=@();$active=@(NetSecurity\Get-NetFirewallRule -PolicyStore ActiveStore -WarningAction SilentlyContinue -WarningVariable activeWarnings -ErrorAction Stop)
    if($activeWarnings.Count){throw 'Native event probe active enumeration was incomplete'}
    if($active.Count -gt 10000 -or @($active | Where-Object {[string]$_.Name -ceq $ruleName}).Count){throw 'Native event probe active identity is unavailable'}
    $beforeRules=$script:stateFirewallRules
    $stage='create';$creationAttempted=$true
    $newWarnings=@();$new=@(NetSecurity\New-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -DisplayName $ruleName -Description ('AccessWeaver event diagnostic '+$token) -Group ('AccessWeaver event fixture '+$token) -Enabled 'False' -Profile Any -Direction Outbound -Action Allow -Protocol TCP -LocalPort Any -RemotePort 9 -LocalAddress Any -RemoteAddress '127.0.0.1' -WarningAction SilentlyContinue -WarningVariable newWarnings -ErrorAction Stop)
    if($newWarnings.Count){throw 'Native event probe creation was incomplete'}
    if($new.Count -ne 1 -or $new[0] -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Native event probe creation result is incomplete'}
    $stage='ownership';$bundle=Get-EventProbeOwnedBundle $ruleName
    $null=New-InstallerEventFixtureOwnership $new[0] $bundle.filters $ruleName $token
    if([string]$new[0].InstanceID -cne [string]$bundle.rule.InstanceID){throw 'Native event probe creation identity changed'}
    $ownership=New-InstallerEventFixtureOwnership $bundle.rule $bundle.filters $ruleName $token;$created=$true;$disabled=$true
    $stage='controlled-state';$during=Get-EventProbeSnapshot;$controlled=Compare-InstallerState $baseline $during
    $null=Assert-InstallerEventFixtureTransition $baseline $during $ownership.identitySHA256
    $expectedFailure='Controlled owned firewall drift must refuse unchanged-state acceptance'
    try {Require ($during -ceq $baseline) $expectedFailure} catch {if($script:assertionFailure -cne $expectedFailure){throw};$refused=$true}
    if(-not $refused){throw 'Native event probe did not refuse controlled drift'}
    $script:firewallOriginObservations=@(New-InstallerFirewallOrigins 'controlled-event-probe' @($controlled.domains.firewall.changes) $beforeRules $script:stateFirewallRules 16)
    if($script:firewallOriginObservations.Count -ne 1 -or $script:firewallOriginObservations[0].identitySHA256 -cne $ownership.identitySHA256){throw 'Native event probe captured identity differs'}
    $stage='diagnostic';$adapterCalled=$true;$candidateAdapterFailure=$null
    $candidateDiagnostic=Read-FirewallEventDiagnostic -FailureObservation ([ref]$candidateAdapterFailure)
    Set-InstallerEventFixtureDiagnosticObservation ([ref]$diagnostic) ([ref]$adapterFailure) $candidateDiagnostic $candidateAdapterFailure $ownership.identitySHA256 $script:firewallEventWindowStartUtc
    $attemptPreserved=([object]::ReferenceEquals($attemptSentinel,$script:lastNativeAttempt) -and (Get-InstallerStateValueHash $script:lastNativeAttempt) -ceq $attemptHash)
    $returnPreserved=([object]::ReferenceEquals($returnSentinel,$script:lastNative) -and (Get-InstallerStateValueHash $script:lastNative) -ceq $returnHash)
    if(-not $attemptPreserved -or -not $returnPreserved -or $script:assertionFailure -cne $expectedFailure){throw 'Native event probe replaced the original failure context'}
} catch {$failure=$stage}
finally {
    if($creationAttempted){
        try {
            $cleanupWarnings=@();$current=@(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable cleanupWarnings -ErrorAction Stop | Where-Object {[string]$_.Name -ceq $ruleName})
            if($cleanupWarnings.Count){throw 'Native event probe cleanup enumeration was incomplete'}
            if($current.Count -eq 0){$removed=$true;$guardVerified=($null -ne $ownership)}
            else {
                if($null -eq $ownership -or $current.Count -ne 1){throw 'Native event probe cleanup ownership is unavailable'}
                $bundle=Get-EventProbeOwnedBundle $ruleName
                Assert-InstallerEventFixtureOwnership $ownership $bundle.rule $bundle.filters $ruleName $token
                $guardVerified=$true
                $removeWarnings=@();NetSecurity\Remove-NetFirewallRule -InputObject $bundle.rule -Confirm:$false -WarningAction SilentlyContinue -WarningVariable removeWarnings -ErrorAction Stop
                if($removeWarnings.Count){throw 'Native event probe cleanup was incomplete'}
                $remainingWarnings=@();$remaining=@(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable remainingWarnings -ErrorAction Stop | Where-Object {[string]$_.Name -ceq $ruleName})
                if($remainingWarnings.Count){throw 'Native event probe final enumeration was incomplete'}
                if($remaining.Count){throw 'Native event probe rule removal is incomplete'}
                $removed=$true
            }
        } catch {$failure='cleanup-refused'}
    }
    if($null -ne $baseline){
        try {$after=Get-EventProbeSnapshot;$restored=Compare-InstallerState $baseline $after;$baselineRestored=$restored.exactMatch;if(-not $baselineRestored){$failure='baseline-not-restored'}} catch {$failure='baseline-restoration-unavailable'}
    }
    if($capsuleOwned){
        try {
            No-Reparse $capsule;No-Reparse $marker
            if((Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash.ToLowerInvariant() -cne $markerHash){throw 'Native event probe temporary ownership changed'}
            Remove-OwnedTree $capsule $temporary $capsuleLeaf
            $tempRemoved=-not (Test-Path -LiteralPath $capsule)
            if(-not $tempRemoved){throw 'Native event probe temporary cleanup is incomplete'}
        } catch {$failure='temporary-cleanup-refused'}
    }
}
$complete=($null -eq $failure -and $creationAttempted -and $created -and $disabled -and $guardVerified -and $removed -and $tempRemoved -and $baselineRestored -and $refused -and $adapterCalled -and $attemptPreserved -and $returnPreserved)
$record=[ordered]@{schemaVersion=2;sourceCommit=$source;sourceRef=$sourceRef;runID=$run;target=('windows/'+$Architecture);powershellVersion=$PSVersionTable.PSVersion.ToString();probeComplete=$complete;failureCategory=$failure;ruleCreationAttempted=$creationAttempted;ownedRuleCreated=$created;ownedRuleDisabled=$disabled;ownershipGuardVerified=$guardVerified;ownedRuleRemoved=$removed;ownedTemporaryDirectoryRemoved=$tempRemoved;baselineRestored=$baselineRestored;controlledDriftRefused=$refused;adapterCalled=$adapterCalled;nativeReadCompleted=($diagnostic.status -ceq 'captured');nativeAttemptSentinelPreserved=$attemptPreserved;nativeReturnSentinelPreserved=$returnPreserved;localStore='PersistentStore';ruleIdentitySHA256=(Get-InstallerStateTextHash $ruleName);ownershipSHA256=$(if($ownership){$ownership.sha256}else{$null});controlledComparison=$controlled;baselineComparison=$restored;firewallEventDiagnostics=$diagnostic;adapterFailure=$adapterFailure;dependenciesSHA256=$dependencies;eventLogConfigurationChanged=$false;unrelatedStateMutationAttempted=$false;ownershipComparisonAtomic=$false;installerExecutionPerformed=$false;processOriginEstablished=$false;productionQualificationComplete=$false;reportMaxBytes=131072}
$json=(ConvertTo-Json -InputObject $record -Depth 20 -Compress)+[Environment]::NewLine
if([Text.UTF8Encoding]::new($false).GetByteCount($json) -gt 131072){throw 'Native event probe public report exceeds budget'}
$reportDirectory=Join-Path $project 'build\installer-event-checks';No-Reparse $reportDirectory
try {
    [void][IO.Directory]::CreateDirectory($reportDirectory);No-Reparse $reportDirectory
    $reportPath=Join-Path $reportDirectory ($Architecture+'.json');No-Reparse $reportPath
    $reportStream=[IO.File]::Open($reportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$reportBytes=[Text.UTF8Encoding]::new($false).GetBytes($json);$reportStream.Write($reportBytes,0,$reportBytes.Length);$reportStream.Flush($true)} finally {$reportStream.Dispose()}
} catch {throw 'Native event probe public report could not be retained'}
if(-not $complete){throw 'Hosted native event probe failed; inspect bounded public result and retained fixture on disposable runner'}
Write-Output 'Controlled disabled-rule drift refused; original baseline restored and bounded event adapter outcome retained without origin attribution.'
