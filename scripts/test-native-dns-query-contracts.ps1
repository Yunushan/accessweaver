# Hosted source-only contracts; native/process/hash boundaries are replaced.
[CmdletBinding()]param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Hosted source contracts only'}
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
$project=Split-Path -Parent $PSScriptRoot;$sources=@('scripts/native-dns-query.ps1','scripts/native-dns-recovery-observation.ps1','scripts/test-native-dns-query-contracts.ps1','scripts/native-dns-query/main_windows.go','scripts/native-dns-query/main_windows_test.go', 'scripts/native-dns-direct/direct.go', 'scripts/native-dns-direct/direct_test.go','.github/workflows/native-dns-query.yml');$hashes=@{}
foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-dns-query.ps1'),[ref]$t,[ref]$e);if($e.Count){throw 'Query source syntax'}
foreach($def in $ast.EndBlock.Statements){
    if($def -isnot [Management.Automation.Language.FunctionDefinitionAst] -or $def.Name -cnotin @('Get-NativeFreshDNSQueryReport','Invoke-NativeFreshDNSQuery')){continue}
    foreach($cmd in $def.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -cnotin @('ConvertFrom-Json','Where-Object','Assert-NativeFreshDNSSources','Get-FileHash','Invoke-NativeDNSWireProcess','Get-NativeFreshDNSQueryReport')){throw 'Query source command boundary'}}
    . ([scriptblock]::Create($def.Extent.Text))
}
$t=$null;$e=$null;$recoveryAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-dns-recovery-observation.ps1'),[ref]$t,[ref]$e);if($e.Count){throw 'Recovery source syntax'}
foreach($def in $recoveryAst.EndBlock.Statements){
    if($def -isnot [Management.Automation.Language.FunctionDefinitionAst] -or $def.Name -cnotin @('New-NativeDNSRecoveryObservation','Observe-NativeDNSRecovery')){continue}
    foreach($cmd in $def.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -cnotin @('New-NativeDNSRecoveryObservation','Get-NativeFreshDNSQueryReport','ConvertTo-Json','Wait-NativeDNSRecoveryOffset','Read-NativeDNSRecoveryMilliseconds','Invoke-NativeFreshDNSQuery')){throw 'Recovery source command boundary'}}
    . ([scriptblock]::Create($def.Extent.Text))
}
$cases=[Collections.Generic.List[object]]::new();$source='a'*40;$arch='amd64'
function Assert-Q([bool]$Condition){if(-not $Condition){throw 'Query source assertion'}}
function Reject-Q([scriptblock]$Body){$failed=$false;try{[void](& $Body)}catch{$failed=$true};Assert-Q $failed}
function Case-Q([string]$Name,[scriptblock]$Body){$ok=$false;try{& $Body;$ok=$true}catch{};$cases.Add(@{name=$Name;passed=$ok})}
function New-Q {return @{schemaVersion=2;sourceCommit=$source;architecture=$arch;queryOptions=6600;outcome='answered';code='none';failureKind='none';answerCount=1;recordCount=1;queryInvoked=$true;recordsReleased=$true;productionQualificationComplete=$false}}
function Reset-Q {$script:recoveryNow=0L;$script:recoveryReplies=$null;$script:recoveryClockFault='';$script:reply=New-Q;$script:events=[Collections.Generic.List[string]]::new();$script:fault='';$script:sourceChecks=0;$script:hashReads=0;$script:state=@{querySourceCommit=$source;queryArchitecture=$arch;queryBinary='synthetic-query-binary';queryBinarySHA256=('b'*64);processFailed=$false}}
function Assert-NativeFreshDNSSources([object]$State){$script:sourceChecks++;if($script:fault -ceq 'source'){throw 'Synthetic source refusal'}}
function Get-FileHash {param($LiteralPath,$Algorithm);$script:hashReads++;return @{Hash=$(if($script:fault -ceq 'binary'){'c'*64}else{'b'*64})}}
function Invoke-NativeDNSWireProcess([object]$State,[string]$Program,[string[]]$Arguments){$script:events.Add('process');Assert-Q ($Program -ceq 'synthetic-query-binary');if($script:fault -ceq 'process'){$State.processFailed=$true;throw 'Synthetic timeout'};if($null -ne $script:recoveryReplies -and $script:recoveryReplies.Count -gt 0){$script:reply=$script:recoveryReplies.Dequeue();$script:recoveryNow+=10L};return ($script:reply | ConvertTo-Json -Compress)}
function Read-NativeDNSRecoveryMilliseconds([object]$Clock){if($script:recoveryClockFault -ceq 'end-regression'){return 0L};return $script:recoveryNow}
function Wait-NativeDNSRecoveryOffset([object]$Clock,[long]$TargetMilliseconds){if($script:recoveryClockFault -ceq 'start-regression'){return ($TargetMilliseconds-1L)};if($script:recoveryClockFault -ceq 'bound'){return 120001L};$script:recoveryNow=[long][Math]::Max($script:recoveryNow,$TargetMilliseconds);return $script:recoveryNow}
function New-QTimeout {$r=New-Q;$r.outcome='refused';$r.code='query-failed';$r.failureKind='timeout';$r.answerCount=0;$r.recordCount=0;return $r}
function Set-QRecovery([object[]]$Replies){$script:recoveryNow=10L;$script:recoveryReplies=[Collections.Generic.Queue[object]]::new();foreach($r in $Replies){$script:recoveryReplies.Enqueue($r)}}
Case-Q 'query-projection-accepts-exact-success' {$r=New-Q;$v=Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch;Assert-Q ($v.answerCount -eq 1 -and $v.recordsReleased)}
Case-Q 'query-projection-pins-source-architecture-and-options' {foreach($key in @('sourceCommit','architecture','queryOptions')){$r=New-Q;$r[$key]=switch($key){'sourceCommit'{'b'*40}'architecture'{'arm64'}'queryOptions'{0}};Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}}}
Case-Q 'query-projection-refuses-private-and-missing-fields' {$r=New-Q;$r.privateRecord='synthetic';Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch};$r=New-Q;$r.Remove('recordCount');Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}}
Case-Q 'query-projection-refuses-coerced-flags-and-counts' {foreach($key in @('queryInvoked','recordsReleased','productionQualificationComplete','answerCount','recordCount','queryOptions')){$r=New-Q;$r[$key]=[string]$r[$key];Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}}}
Case-Q 'query-projection-refuses-unreleased-or-unbounded-results' {foreach($key in @('recordsReleased','answerCount','recordCount')){$r=New-Q;$r[$key]=switch($key){'recordsReleased'{$false}'answerCount'{65}'recordCount'{129}};Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}}}
Case-Q 'query-projection-refuses-false-positive-readiness-and-answers' {$r=New-Q;$r.queryInvoked=$false;Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch};$r=New-Q;$r.outcome='ready';Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}}
Case-Q 'query-wrapper-proves-owned-child-and-before-after-hashes' {Reset-Q;$v=Invoke-NativeFreshDNSQuery $state 'example.net';Assert-Q ($v.outcome -ceq 'answered' -and $script:events.Count -eq 1 -and $script:sourceChecks -eq 2 -and $script:hashReads -eq 2)}
Case-Q 'query-wrapper-only-counts-native-query-error-as-rejection' {Reset-Q;$script:reply.outcome='refused';$script:reply.code='query-failed';$script:reply.failureKind='other';$script:reply.answerCount=0;$script:reply.recordCount=0;$v=Invoke-NativeFreshDNSQuery $state 'example.net' -ExpectFailure;Assert-Q ($v.queryInvoked -and $v.recordsReleased);foreach($code in @('record-bound','answer-bound','environment','arguments')){Reset-Q;$script:reply.outcome='refused';$script:reply.code=$code;$script:reply.answerCount=0;$script:reply.recordCount=0;Reject-Q {Invoke-NativeFreshDNSQuery $state 'example.net' -ExpectFailure}}}
Case-Q 'query-wrapper-never-turns-timeout-or-mutation-into-rejection' {foreach($fault in @('process','binary','source')){Reset-Q;$script:fault=$fault;Reject-Q {Invoke-NativeFreshDNSQuery $state 'example.net' -ExpectFailure};if($fault -cne 'process'){Assert-Q ($script:events.Count -eq 0)}}}
Case-Q 'query-wrapper-refuses-success-as-negative-control' {Reset-Q;Reject-Q {Invoke-NativeFreshDNSQuery $state 'example.net' -ExpectFailure}}
Case-Q 'query-wrapper-rejects-unknown-names-before-any-boundary' {Reset-Q;Reject-Q {Invoke-NativeFreshDNSQuery $state 'private.synthetic'};Assert-Q ($script:events.Count -eq 0 -and $script:sourceChecks -eq 0)}
Case-Q 'query-wrapper-probe-makes-no-dns-request' {Reset-Q;$script:reply.outcome='ready';$script:reply.answerCount=0;$script:reply.recordCount=0;$script:reply.queryInvoked=$false;$v=Invoke-NativeFreshDNSQuery $state -Probe;Assert-Q (-not $v.queryInvoked);Reject-Q {Invoke-NativeFreshDNSQuery $state 'example.net' -Probe}}
Case-Q 'query-projection-size-and-qualification-boundaries' {Reject-Q {Get-NativeFreshDNSQueryReport (' '*2049) $source $arch};$r=New-Q;$r.productionQualificationComplete=$true;Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}}
Case-Q 'query-wrapper-retains-only-normalized-failures-and-clears-stale-proof' {
    Reset-Q;$script:reply.outcome='refused';$script:reply.code='query-failed';$script:reply.failureKind='other';$script:reply.answerCount=0;$script:reply.recordCount=0
    Reject-Q {Invoke-NativeFreshDNSQuery $state 'example.net'}
    Assert-Q ($state.queryLastEvidence.code -ceq 'query-failed' -and $state.queryLastEvidence.queryInvoked -and $state.queryLastEvidence.recordsReleased)
    $script:reply=New-Q;$script:reply.privateRecord='synthetic';Reject-Q {Invoke-NativeFreshDNSQuery $state 'example.net'}
    Assert-Q ($null -eq $state.queryLastEvidence)
    $script:reply=New-Q;[void](Invoke-NativeFreshDNSQuery $state 'example.net');$script:fault='process';Reject-Q {Invoke-NativeFreshDNSQuery $state 'example.net'}
    Assert-Q ($null -eq $state.queryLastEvidence)
}
Case-Q 'query-error-category-is-closed-and-cannot-upgrade-refusal' {
    foreach($kind in @('private.synthetic','',42)){$r=New-Q;$r.failureKind=$kind;Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}}
    $r=New-Q;$r.failureKind='timeout';Reject-Q {Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch}
    $r.outcome='refused';$r.code='query-failed';$r.answerCount=0;$r.recordCount=0;$v=Get-NativeFreshDNSQueryReport ($r|ConvertTo-Json -Compress) $source $arch;Assert-Q ($v.failureKind -ceq 'timeout' -and $v.outcome -ceq 'refused')
}
Case-Q 'recovery-five-fixed-offsets-close-and-retain-first-failure' {
    Reset-Q;$first=New-QTimeout;$timing=@{attempted=$true;startMilliseconds=0L;endMilliseconds=10L};Set-QRecovery @((New-QTimeout),(New-QTimeout),(New-Q),(New-Q),(New-Q))
    $v=Observe-NativeDNSRecovery $state 'fake-clock' $first $timing 'failed' 'resumed'
    Assert-Q ($v.outcome -ceq 'observed' -and $v.code -ceq 'none' -and $v.samples.Count -eq 5 -and $v.initialOutcome -ceq 'failed' -and $v.initialFailureKind -ceq 'timeout' -and $v.laterSuccessObserved -and $v.diagnosticOnly -and -not $v.productionQualificationComplete)
    Assert-Q (($v.samples.targetMilliseconds -join ',') -ceq '5000,10000,15000,35000,65000' -and $first.outcome -ceq 'refused' -and $first.failureKind -ceq 'timeout')
    foreach($row in $v.samples){Assert-Q ($row.startMilliseconds -ge $row.targetMilliseconds -and $row.endMilliseconds -ge $row.startMilliseconds -and $row.queryEvidence.recordsReleased)}
}
Case-Q 'recovery-no-answer-remains-observation-not-qualification' {
    Reset-Q;$first=New-QTimeout;Set-QRecovery @((New-QTimeout),(New-QTimeout),(New-QTimeout),(New-QTimeout),(New-QTimeout));$v=Observe-NativeDNSRecovery $state 'fake-clock' $first @{attempted=$true;startMilliseconds=0L;endMilliseconds=10L} 'failed' 'resumed'
    Assert-Q ($v.outcome -ceq 'observed' -and -not $v.laterSuccessObserved -and $v.initialOutcome -ceq 'failed' -and -not $v.productionQualificationComplete)
}
Case-Q 'recovery-refuses-non-timeout-and-private-initial-proof' {
    foreach($fault in @('passed','kind','private','timing')){
        Reset-Q;$first=New-QTimeout;$out='failed';$timing=@{attempted=$true;startMilliseconds=0L;endMilliseconds=10L}
        switch($fault){'passed'{$out='passed'}'kind'{$first.failureKind='other'}'private'{$first.privateRecord='private.synthetic'}'timing'{$timing.endMilliseconds=-1}}
        $v=Observe-NativeDNSRecovery $state 'fake-clock' $first $timing $out 'resumed';Assert-Q ($v.outcome -ceq 'refused' -and $v.code -ceq 'precondition' -and $v.samples.Count -eq 0 -and $script:events.Count -eq 0)
    }
}
Case-Q 'recovery-clock-regression-and-bound-cannot-publish-partial-row' {
    foreach($fault in @('start-regression','end-regression','bound')){Reset-Q;Set-QRecovery @((New-Q));$script:recoveryClockFault=$fault;$v=Observe-NativeDNSRecovery $state 'fake-clock' (New-QTimeout) @{attempted=$true;startMilliseconds=0L;endMilliseconds=10L} 'failed' 'resumed';Assert-Q ($v.outcome -ceq 'refused' -and $v.code -ceq 'clock' -and $v.samples.Count -eq 0 -and -not $v.laterSuccessObserved)}
}
Case-Q 'recovery-process-source-and-private-query-refusal-do-not-upgrade' {
    foreach($fault in @('process','source','private')){Reset-Q;Set-QRecovery @((New-Q));if($fault -ceq 'private'){$r=New-Q;$r.privateRecord='private.synthetic';Set-QRecovery @($r)}else{$script:fault=$fault};$v=Observe-NativeDNSRecovery $state 'fake-clock' (New-QTimeout) @{attempted=$true;startMilliseconds=0L;endMilliseconds=10L} 'failed' 'resumed';Assert-Q ($v.outcome -ceq 'refused' -and $v.samples.Count -eq 0 -and -not $v.laterSuccessObserved -and $v.initialOutcome -ceq 'failed');Assert-Q (-not ($v|ConvertTo-Json -Depth 6 -Compress).Contains('private.synthetic'))}
}
Case-Q 'recovery-public-report-is-bounded-and-contains-no-private-time-or-data' {
    Reset-Q;Set-QRecovery @((New-Q),(New-Q),(New-Q),(New-Q),(New-Q));$v=Observe-NativeDNSRecovery $state 'fake-clock' (New-QTimeout) @{attempted=$true;startMilliseconds=0L;endMilliseconds=10L} 'failed' 'resumed';$text=$v|ConvertTo-Json -Depth 6 -Compress
    Assert-Q ($text.Length -le 3072 -and $v.Count -eq 9);foreach($secret in @('example.net','UtcTicks','DateTime','private.synthetic','IPAddress','sourceFramesSHA256')){Assert-Q (-not $text.Contains($secret))}
}
Case-Q 'recovery-caller-keeps-original-verdict-and-query-policy' {
    $text=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'test-native-dns-query.ps1'));$call='Observe-NativeDNSRecovery $state $unblockClock $evidence.resumed $resumptionTiming $outcome $code'
    Assert-Q ($text.Contains($call) -and ([regex]::Matches($text,[regex]::Escape("$"+"outcome='passed'"))).Count -eq 1 -and $text.IndexOf("$"+"outcome='passed'") -lt $text.IndexOf($call))
    $text=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'native-dns-recovery-observation.ps1'));foreach($boundary in @('Clear-DnsClientCache','Set-DnsClient','New-NetFirewallRule','Remove-NetFirewallRule','DateTime','UtcTicks')){Assert-Q (-not $text.Contains($boundary))}
    Assert-Q ($text.Contains('@(5000,10000,15000,35000,65000)') -and $text.Contains("Invoke-NativeFreshDNSQuery $"+"State 'example.net'"))
}
Case-Q 'preflight-stages-are-distinct-and-precede-native-effects' {
    $text=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'test-native-dns-query.ps1'))
    $markers=@('$code=''preflight-source''','$code=''preflight-nrpt''','$code=''preflight-firewall''','$code=''preflight-baseline''','$code=''probe''')
    $previous=-1;foreach($marker in $markers){$index=$text.IndexOf($marker);Assert-Q ($index -gt $previous);$previous=$index}
    Assert-Q (-not $text.Contains('Exception.Message'))
}
$passed=@($cases | Where-Object {-not $_.passed}).Count -eq 0
[Console]::Out.WriteLine((@{schemaVersion=1;sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;cases=@($cases.ToArray());passed=$passed;nativeQueryInvoked=$false;productInvoked=$false} | ConvertTo-Json -Depth 5 -Compress))
if(-not $passed){exit 1}
