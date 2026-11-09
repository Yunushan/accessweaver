# Hosted source-only contracts; native/process/hash boundaries are replaced.
[CmdletBinding()]param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Hosted source contracts only'}
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Stock source shell required'}
$project=Split-Path -Parent $PSScriptRoot;$sources=@('scripts/native-dns-query.ps1','scripts/test-native-dns-query-contracts.ps1','scripts/native-dns-query/main_windows.go','scripts/native-dns-query/main_windows_test.go','.github/workflows/native-dns-query.yml');$hashes=@{}
foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-dns-query.ps1'),[ref]$t,[ref]$e);if($e.Count){throw 'Query source syntax'}
foreach($def in $ast.EndBlock.Statements){
    if($def -isnot [Management.Automation.Language.FunctionDefinitionAst] -or $def.Name -cnotin @('Get-NativeFreshDNSQueryReport','Invoke-NativeFreshDNSQuery')){continue}
    foreach($cmd in $def.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -cnotin @('ConvertFrom-Json','Where-Object','Assert-NativeFreshDNSSources','Get-FileHash','Invoke-NativeDNSWireProcess','Get-NativeFreshDNSQueryReport')){throw 'Query source command boundary'}}
    . ([scriptblock]::Create($def.Extent.Text))
}
$cases=[Collections.Generic.List[object]]::new();$source='a'*40;$arch='amd64'
function Assert-Q([bool]$Condition){if(-not $Condition){throw 'Query source assertion'}}
function Reject-Q([scriptblock]$Body){$failed=$false;try{[void](& $Body)}catch{$failed=$true};Assert-Q $failed}
function Case-Q([string]$Name,[scriptblock]$Body){$ok=$false;try{& $Body;$ok=$true}catch{};$cases.Add(@{name=$Name;passed=$ok})}
function New-Q {return @{schemaVersion=2;sourceCommit=$source;architecture=$arch;queryOptions=6600;outcome='answered';code='none';failureKind='none';answerCount=1;recordCount=1;queryInvoked=$true;recordsReleased=$true;productionQualificationComplete=$false}}
function Reset-Q {$script:reply=New-Q;$script:events=[Collections.Generic.List[string]]::new();$script:fault='';$script:sourceChecks=0;$script:hashReads=0;$script:state=@{querySourceCommit=$source;queryArchitecture=$arch;queryBinary='synthetic-query-binary';queryBinarySHA256=('b'*64)}}
function Assert-NativeFreshDNSSources([object]$State){$script:sourceChecks++;if($script:fault -ceq 'source'){throw 'Synthetic source refusal'}}
function Get-FileHash {param($LiteralPath,$Algorithm);$script:hashReads++;return @{Hash=$(if($script:fault -ceq 'binary'){'c'*64}else{'b'*64})}}
function Invoke-NativeDNSWireProcess([object]$State,[string]$Program,[string[]]$Arguments){$script:events.Add('process');Assert-Q ($Program -ceq 'synthetic-query-binary');if($script:fault -ceq 'process'){throw 'Synthetic timeout'};return ($script:reply | ConvertTo-Json -Compress)}
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
$passed=@($cases | Where-Object {-not $_.passed}).Count -eq 0
[Console]::Out.WriteLine((@{schemaVersion=1;sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;cases=@($cases.ToArray());passed=$passed;nativeQueryInvoked=$false;productInvoked=$false} | ConvertTo-Json -Depth 5 -Compress))
if(-not $passed){exit 1}
