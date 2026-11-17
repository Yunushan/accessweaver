# Executes only the inert registry contract on an explicitly opted-in hosted VM.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Get-RegistryFixtureCaseIDs([string]$Source){
    # This is the checked-in, source-pinned fixture. Refuse nonliteral declarations.
    $calls=[regex]::Matches($Source,'(?m)^[ \t]*AWFixtureCase\(')
    $records=[regex]::Matches($Source,"(?m)^[ \t]*AWFixtureCase\('([a-z][a-z0-9-]{0,63})',")
    if($calls.Count -ne $records.Count -or $records.Count -lt 1 -or $records.Count -gt 48){
        throw 'Registry ownership fixture case catalog is invalid'
    }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($record in $records){
        $id=$record.Groups[1].Value
        if(-not $seen.Add($id)){throw 'Registry ownership fixture case catalog contains a duplicate'}
    }
    foreach($record in $records){$record.Groups[1].Value}
}
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
$build=Join-Path $project ('build\registry-ownership-work\'+$Architecture)
$receiptDir=Join-Path $project 'build\registry-ownership-evidence'
if((Test-Path -LiteralPath $build) -or (Test-Path -LiteralPath $receiptDir)){throw 'Registry ownership fixture output already exists'}
[void](New-Item -ItemType Directory -Path $build)
[void](New-Item -ItemType Directory -Path $receiptDir)
$producer=@('scripts/test-windows-installer-registry-owned.iss','scripts/windows-installer-registry-owned.iss',
    'scripts/windows-installer-registry-transaction.iss','scripts/windows-installer-registry.iss','scripts/windows-installer-version.iss',
    'scripts/test-windows-installer-registry-owned.ps1','scripts/windows-installer-common.ps1',
    'scripts/windows-installer.iss','scripts/detect-windows-installer.ps1','internal/workflow/windows.ps1',
    'scripts/test-windows-installer-contracts.ps1','scripts/test-windows-installer-detection.ps1',
    '.github/workflows/installer-lifecycle.yml')
$pins=[ordered]@{}
foreach($name in $producer){$pins[$name]=(Get-FileHash -LiteralPath (Join-Path $project $name) -Algorithm SHA256).Hash.ToLowerInvariant()}
$receiptPath=Join-Path $receiptDir ($Architecture+'.json')
$compilerSHA256=$null
$fixtureSHA256=$null
$processExit=$null
$reportWritten=$false
try {
    $fixture=Join-Path $PSScriptRoot 'test-windows-installer-registry-owned.iss'
    $stage='fixture-catalog'
    if((Get-Item -LiteralPath $fixture -ErrorAction Stop).Length -gt 128KB){
        throw 'Registry ownership fixture source exceeds its catalog budget'
    }
    $known=@(Get-RegistryFixtureCaseIDs ([IO.File]::ReadAllText($fixture)))
    $stage='compiler-identity'
    $compiler=Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Inno Setup 6\ISCC.exe'
    if(-not (Test-Path -LiteralPath $compiler -PathType Leaf)){throw 'Pinned compiler unavailable'}
    $compilerSHA256=(Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant()
    $caseCount=$known.Count.ToString([Globalization.CultureInfo]::InvariantCulture)
    $stage='compile'
    $compile=@(& $compiler ('/DEvidenceRoot='+$build) ('/DSourceCommit='+$env:GITHUB_SHA) ('/DRunID='+$env:GITHUB_RUN_ID) ('/DRunAttempt='+$env:GITHUB_RUN_ATTEMPT) ('/DTargetArch='+$Architecture) ('/DExpectedCaseCount='+$caseCount) $fixture 2>&1)
    $compilerExit=$LASTEXITCODE
    if($compilerExit -ne 0 -or ($compile -join [Environment]::NewLine) -cnotmatch '(?m)^Compiler engine version:\s*Inno Setup 6\.7\.1(?:\s|$)'){
        throw 'Registry ownership fixture did not compile with Inno Setup 6.7.1'
    }
    $stage='fixture-image'
    $exe=Join-Path $build ('registry-owned-contracts-'+$Architecture+'.exe')
    . (Join-Path $PSScriptRoot 'windows-installer-common.ps1')
    if((Read-InstallerPEMachine $exe) -ne 0x014c){throw 'Registry ownership fixture bootstrap is not the pinned x86 ABI'}
    $stage='launch'
    $fixtureSHA256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $process=Start-Process -FilePath $exe -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -WindowStyle Hidden -PassThru
    $stage='process-exit'
    try {
        if(-not $process.WaitForExit(60000)){
            $process.Kill($true)
            throw 'Registry ownership fixture exceeded its hosted deadline'
        }
        $processExit=$process.ExitCode
    } finally {$process.Dispose()}
    $stage='native-report'
    $path=Join-Path $build ('registry-owned-'+$Architecture+'.json')
    if(-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 4096){
        throw 'Registry ownership fixture did not produce a bounded report'
    }
    $result=[IO.File]::ReadAllText($path) | ConvertFrom-Json -AsHashtable
    $stage='report-identity'
    if($result.schemaVersion -ne 1 -or $result.sourceCommit -cne $env:GITHUB_SHA -or
        $result.runID -cne $env:GITHUB_RUN_ID -or $result.runAttempt -cne $env:GITHUB_RUN_ATTEMPT -or
        $result.architecture -cne $Architecture -or $result.compilerVersion -cne '6.7.1' -or
        $result.scope -cne 'disposable-protected-registry-ownership-contract' -or
        $result.descriptorResult -cnotin @('not-run','pass','descriptor-read','descriptor-template','descriptor-owner','descriptor-protection','descriptor-aces','descriptor-release') -or
        $result.cleanupResult -cnotin @('pass','held-delete','root-present-or-unreadable','fixture-or-handle-close') -or
        ($result.cleanupResult -ceq 'pass') -ne $result.cleanupComplete -or
        $result.productionRegistrationChanged -isnot [bool] -or $result.productionRegistrationChanged -or
        $result.productionQualificationComplete -isnot [bool] -or $result.productionQualificationComplete -or
        $result.cleanupComplete -isnot [bool] -or $result.passed -isnot [bool] -or $result.cases.Count -gt $known.Count){
        throw 'Registry ownership fixture report identity differs'
    }
    $stage='report-cases'
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
    $stage='report-write'
    $report=[ordered]@{
        schemaVersion=1;sourceCommit=$env:GITHUB_SHA;runID=$env:GITHUB_RUN_ID;runAttempt=$env:GITHUB_RUN_ATTEMPT
        architecture=$Architecture;compilerVersion='6.7.1';scope='disposable-protected-registry-ownership-contract'
        compilerSHA256=$compilerSHA256
        fixtureSHA256=$fixtureSHA256
        sourceSHA256=$pins;cases=$rows;cleanupComplete=$result.cleanupComplete;passed=[bool]$passed
        descriptorResult=$result.descriptorResult;cleanupResult=$result.cleanupResult
        productionRegistrationChanged=$false;productionQualificationComplete=$false
    }
    [IO.File]::WriteAllText($receiptPath,($report | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    $reportWritten=$true
    if(-not $passed){throw 'Registry ownership fixture failed a fixed assertion or exact cleanup'}
} finally {
    if(-not $reportWritten){
        # Keep only stage, source pins and the exact child's numeric exit code.
        # Missing native evidence cannot establish disposal or any case result.
        $failure=[ordered]@{
            schemaVersion=2;sourceCommit=$env:GITHUB_SHA;runID=$env:GITHUB_RUN_ID;runAttempt=$env:GITHUB_RUN_ATTEMPT
            architecture=$Architecture;scope='disposable-protected-registry-ownership-contract'
            stage=$stage;processExitCode=$processExit;compilerSHA256=$compilerSHA256
            fixtureSHA256=$fixtureSHA256;sourceSHA256=$pins;cleanupComplete=$null;passed=$false
            productionRegistrationChanged=$false;productionQualificationComplete=$false
        }
        [IO.File]::WriteAllText($receiptPath,($failure | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    }
}
