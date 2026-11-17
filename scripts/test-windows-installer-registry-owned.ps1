# Executes only the inert registry contract on an explicitly opted-in hosted VM.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:OS -cne 'Windows_NT' -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver' -or
    $env:ACCESSWEAVER_DISPOSABLE_WINDOWS_INSTALLER_REGISTRY_TEST -cne '1' -or $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch'){
    throw 'Registry ownership contract requires explicit disposable hosted Windows dispatch'
}
if($env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z' -or $env:GITHUB_RUN_ID -cnotmatch '\A[1-9][0-9]{0,19}\z' -or
    $env:GITHUB_RUN_ATTEMPT -cnotmatch '\A[1-9][0-9]{0,19}\z'){throw 'Registry contract source context unavailable'}
$arch=@{amd64='X64';arm64='Arm64'}[$Architecture]
if([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne $arch -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne $arch -or
    $env:RUNNER_ARCH.ToUpperInvariant() -cne $arch.ToUpperInvariant()){throw 'Registry contract requires a matching native host and shell'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
finally {$identity.Dispose()}
if(-not $admin){throw 'Registry contract requires an already elevated hosted token'}
$project=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if((git -C $project rev-parse HEAD).Trim() -cne $env:GITHUB_SHA -or $LASTEXITCODE -ne 0 -or
    (git -C $project status --porcelain --untracked-files=normal)){throw 'Registry contract requires a clean exact-source checkout'}
$compiler=Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Inno Setup 6\ISCC.exe'
if(-not (Test-Path -LiteralPath $compiler -PathType Leaf)){throw 'Pinned compiler unavailable'}
$build=Join-Path $project ('build\registry-ownership-work\'+$Architecture)
$receiptDir=Join-Path $project 'build\registry-ownership-evidence'
if((Test-Path -LiteralPath $build) -or (Test-Path -LiteralPath $receiptDir)){throw 'Registry ownership fixture output already exists'}
[void](New-Item -ItemType Directory -Path $build)
[void](New-Item -ItemType Directory -Path $receiptDir)
$fixture=Join-Path $PSScriptRoot 'test-windows-installer-registry-owned.iss'
$compile=@(& $compiler ('/DEvidenceRoot='+$build) ('/DSourceCommit='+$env:GITHUB_SHA) ('/DRunID='+$env:GITHUB_RUN_ID) ('/DRunAttempt='+$env:GITHUB_RUN_ATTEMPT) ('/DTargetArch='+$Architecture) $fixture 2>&1)
$compilerExit=$LASTEXITCODE
if($compilerExit -ne 0 -or ($compile -join [Environment]::NewLine) -cnotmatch '(?m)^Compiler engine version:\s*Inno Setup 6\.7\.1(?:\s|$)'){
    throw 'Registry ownership fixture did not compile with Inno Setup 6.7.1'
}
$exe=Join-Path $build ('registry-owned-contracts-'+$Architecture+'.exe')
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')
if((Read-InstallerPEMachine $exe) -ne 0x014c){throw 'Registry ownership fixture bootstrap is not the pinned x86 ABI'}
$process=Start-Process -FilePath $exe -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -WindowStyle Hidden -PassThru
try {
    if(-not $process.WaitForExit(60000)){
        $process.Kill($true)
        throw 'Registry ownership fixture exceeded its hosted deadline'
    }
    $processExit=$process.ExitCode
} finally {$process.Dispose()}
$path=Join-Path $build ('registry-owned-'+$Architecture+'.json')
if(-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 4096){
    throw 'Registry ownership fixture did not produce a bounded report'
}
$result=[IO.File]::ReadAllText($path) | ConvertFrom-Json -AsHashtable
$known=@('new-owned-fixture-parent','protected-child-created','creation-descriptor-exact','handle-not-inheritable',
    'atomic-class-roundtrip','existing-not-adopted-or-mutated','owned-partial-retry-opens','wrong-class-refused',
    'foreign-writer-descriptor-refused','nested-name-refused','invalid-tag-refused','link-to-existing-target-refused',
    'create-does-not-adopt-link','link-to-missing-target-refused','missing-link-target-not-created',
    'existing-link-target-preserved','new-transacted-registration-staged','abandoned-registration-invisible',
    'complete-registration-visible-after-commit','staged-upgrade-preserves-visible-prior',
    'abandoned-upgrade-preserves-prior','complete-upgrade-visible-after-commit',
    'transaction-rejects-existing-link','exact-owned-cleanup')
if($result.schemaVersion -ne 1 -or $result.sourceCommit -cne $env:GITHUB_SHA -or
    $result.runID -cne $env:GITHUB_RUN_ID -or $result.runAttempt -cne $env:GITHUB_RUN_ATTEMPT -or
    $result.architecture -cne $Architecture -or $result.compilerVersion -cne '6.7.1' -or
    $result.scope -cne 'disposable-protected-registry-ownership-contract' -or
    $result.descriptorResult -cnotin @('not-run','pass','descriptor-read','descriptor-format','descriptor-owner','descriptor-protection','descriptor-aces','descriptor-release') -or
    $result.cleanupResult -cnotin @('pass','held-delete','root-present-or-unreadable','fixture-or-handle-close') -or
    ($result.cleanupResult -ceq 'pass') -ne $result.cleanupComplete -or
    $result.productionRegistrationChanged -isnot [bool] -or $result.productionRegistrationChanged -or
    $result.productionQualificationComplete -isnot [bool] -or $result.productionQualificationComplete -or
    $result.cleanupComplete -isnot [bool] -or $result.passed -isnot [bool] -or $result.cases.Count -gt $known.Count){
    throw 'Registry ownership fixture report identity differs'
}
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$rows=@(foreach($case in $result.cases){
    if($case.Count -ne 3 -or $case.id -cnotin $known -or -not $seen.Add($case.id) -or
        $case.executed -isnot [bool] -or -not $case.executed -or $case.passed -isnot [bool]){
        throw 'Registry ownership fixture reported an unknown case'
    }
    [ordered]@{id=$case.id;executed=$true;passed=$case.passed}
})
$passed=$processExit -eq 0 -and $rows.Count -eq $known.Count -and $result.passed -and
    $result.cleanupComplete -and @($rows | Where-Object {-not $_.passed}).Count -eq 0
$producer=@('scripts/test-windows-installer-registry-owned.iss','scripts/windows-installer-registry-owned.iss',
    'scripts/windows-installer-registry-transaction.iss','scripts/windows-installer-registry.iss','scripts/windows-installer-version.iss',
    'scripts/test-windows-installer-registry-owned.ps1','scripts/windows-installer-common.ps1','.github/workflows/installer-lifecycle.yml')
$pins=[ordered]@{}
foreach($name in $producer){$pins[$name]=(Get-FileHash -LiteralPath (Join-Path $project $name) -Algorithm SHA256).Hash.ToLowerInvariant()}
$report=[ordered]@{
    schemaVersion=1;sourceCommit=$env:GITHUB_SHA;runID=$env:GITHUB_RUN_ID;runAttempt=$env:GITHUB_RUN_ATTEMPT
    architecture=$Architecture;compilerVersion='6.7.1';scope='disposable-protected-registry-ownership-contract'
    compilerSHA256=(Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant()
    fixtureSHA256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    sourceSHA256=$pins;cases=$rows;cleanupComplete=$result.cleanupComplete;passed=[bool]$passed
    descriptorResult=$result.descriptorResult;cleanupResult=$result.cleanupResult
    productionRegistrationChanged=$false;productionQualificationComplete=$false
}
[IO.File]::WriteAllText((Join-Path $receiptDir ($Architecture+'.json')),($report | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
if(-not $passed){throw 'Registry ownership fixture failed a fixed assertion or exact cleanup'}
