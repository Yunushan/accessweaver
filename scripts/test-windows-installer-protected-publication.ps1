# Reuses the disposable lifecycle harness's native launch, preservation and
# cleanup checks. The synthetic abort is compiled from the exact expanded Setup
# with one injected rollback boundary. The retry uses the unmodified candidate.
function Invoke-ProtectedRegistrationAcceptance {
    $reportDirectory=Join-Path $project 'build\installer-protected-publication-checks'
    [void][IO.Directory]::CreateDirectory($reportDirectory)
    $reportPath=Join-Path $reportDirectory ($Architecture+'.json')
    $sourceNames=@(
        '.github/workflows/installer-lifecycle.yml',
        'scripts/test-windows-installer-lifecycle.ps1',
        'scripts/test-windows-installer-protected-publication.ps1',
        'scripts/test-windows-installer.ps1',
        'scripts/build-windows-installer.ps1',
        'scripts/windows-installer-common.ps1',
        'scripts/windows-installer.iss',
        'scripts/windows-installer-version.iss',
        'scripts/windows-installer-lock.iss',
        'scripts/windows-installer-restore.iss',
        'scripts/windows-installer-registry.iss',
        'scripts/windows-installer-registry-owned.iss',
        'scripts/windows-installer-registry-transaction.iss',
        'scripts/windows-installer-registry-legacy.iss',
        'scripts/windows-installer-registry-publication.iss',
        'scripts/detect-windows-installer.ps1',
        'internal/workflow/windows.ps1'
    )
    $pins=[ordered]@{}
    foreach($name in $sourceNames){$pins[$name]=Digest (Join-Path $project $name)}
    $report=[ordered]@{
        schemaVersion=1;scope='disposable-protected-registration-setup'
        sourceCommit=$source;runID=$run;runAttempt=$runAttempt;architecture=$Architecture
        sourceSHA256=$pins;compilerSHA256=$null;compiledSetupSHA256=$null;faultedSetupSHA256=$null
        stagedPayloadSHA256=$null;stage='build';setupExitCode=$null;failureSourceLine=$null
        rolledBackPublication=$false;pendingInstallDetected=$false;recoveredPublication=$false
        previousDirectoryRepair=$false;managedUninstallBinding=$false;ownedPayloadAndRegistrationRemoved=$false
        userStatePreserved=$false;selectedMachineStateUnchanged=$false;scratchRemoved=$false
        passed=$false;productionQualificationComplete=$false
    }
    try {
        $version='0.1.0-alpha'
        $buildDirectory=Join-Path $project 'build'
        if(-not [IO.Directory]::Exists($buildDirectory)){[void][IO.Directory]::CreateDirectory($buildDirectory)}
        $stagePattern='installer-'+$Architecture+'-*'
        $previousStages=@([IO.Directory]::EnumerateDirectories($buildDirectory,$stagePattern))
        $null=@(& (Join-Path $PSScriptRoot 'test-windows-installer.ps1') -ExpectedCompilerVersion '6.7.1' -TargetArch $Architecture -Version $version)
        $staged=@([IO.Directory]::EnumerateDirectories($buildDirectory,$stagePattern) | Where-Object {$_ -cnotin $previousStages})
        Require ($staged.Count -eq 1) 'Protected Setup needs one exact staged payload'
        $evidence=Join-Path $buildDirectory ('installer-checks\'+$Architecture)
        $built=Get-Content -LiteralPath (Join-Path $evidence 'compiler-artifact.json') -Raw | ConvertFrom-Json
        Require ($built.sourceCommit -ceq $source -and $built.payloadBuild.sourceState -ceq 'clean' -and
            $built.payloadBuild.version -ceq $version -and $built.compilerVersion -ceq '6.7.1' -and $built.unsigned) 'Protected Setup input differs from its source or compiler'
        $expected=@{
            version=$version;payloadSha256=$built.payloadSha256;payloadBuild=$built.payloadBuild
            identityFileSHA256=(Digest (Join-Path $staged[0] 'BUILD-INFO.json'))
            payloadSBOMSHA256=(Digest (Join-Path $staged[0] 'SBOM.cdx.json'))
            innoRuntimeNoticeSHA256=(Digest (Join-Path $staged[0] 'licenses\Inno-Setup-License.txt'))
        }
        $compiler=Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Inno Setup 6\ISCC.exe'
        $report.compilerSHA256=Digest $compiler
        $report.stagedPayloadSHA256=Digest (Join-Path $staged[0] 'accessweaver.exe')
        Require ($report.compilerSHA256 -ceq $built.compilerSha256 -and $report.stagedPayloadSHA256 -ceq $expected.payloadSha256) 'Protected Setup inputs changed after normal staging'
        $report.stage='compile-protected'
        $realDirectory=Join-Path $capsule 'protected'
        $faultDirectory=Join-Path $capsule 'rollback'
        foreach($path in @($realDirectory,$faultDirectory)){[void][IO.Directory]::CreateDirectory($path)}
        $setupScript=Join-Path $PSScriptRoot 'windows-installer.iss'
        $expanded=Join-Path $capsule 'protected-expanded.iss'
        $compileArguments=@(('/DBuildRoot='+$staged[0]),('/DReleaseVersion='+$version),('/DTargetArch='+$Architecture),
            ('/DEvidenceOutput='+$expanded),'/DRequireInnoRuntimeNotice','/DProtectedRegistrationQualification=1',('/O'+$realDirectory),$setupScript)
        $null=@(& $compiler @compileArguments)
        Require ($LASTEXITCODE -eq 0) 'Protected Setup compilation failed'
        $null=Assert-InstallerSetupScript $expanded $Architecture $version
        $real=Join-Path $realDirectory $built.installerName
        $report.compiledSetupSHA256=Digest $real

        $report.stage='compile-rollback'
        $expandedText=[IO.File]::ReadAllText($expanded)
        $boundary='Finished := AWRegistryTransactionFinish(Transaction, Key, Staged);'
        $start=$expandedText.IndexOf('function AWPublishOwnedProductRegistration(', [StringComparison]::Ordinal)
        Require ($start -ge 0) 'Compiled protected publication entry point is missing'
        $finish=$expandedText.IndexOf('function AWProductRegistrationAbsent(', $start, [StringComparison]::Ordinal)
        Require ($finish -gt $start) 'Compiled protected publication boundary is missing'
        $publication=$expandedText.Substring($start,$finish-$start)
        Require ([regex]::Matches($publication,[regex]::Escape($boundary)).Count -eq 1 -and
            [regex]::Matches($expandedText,'(?m)^CreateUninstallRegKey=no\s*$').Count -eq 1) 'Expected protected publication without Inno registration'
        $rollback="if Staged then Log('AccessWeaver fixture reached the staged publication rollback.');"+[Environment]::NewLine+'      Staged := False;'+[Environment]::NewLine+'      '+$boundary
        $faultScript=Join-Path $capsule 'rollback-expanded.iss'
        [IO.File]::WriteAllText($faultScript,$expandedText.Substring(0,$start)+$publication.Replace($boundary,$rollback)+$expandedText.Substring($finish),[Text.UTF8Encoding]::new($true))
        $null=@(& $compiler ('/O'+$faultDirectory) $faultScript)
        Require ($LASTEXITCODE -eq 0) 'Protected Setup rollback fixture compilation failed'
        $fault=Join-Path $faultDirectory $built.installerName
        $report.faultedSetupSHA256=Digest $fault
        Require ($report.faultedSetupSHA256 -cne $report.compiledSetupSHA256) 'Rollback Setup must contain the injected fixture boundary'

        $baseline=State-Snapshot
        Require (-not @(Get-Service -Name 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count) 'Existing product services are outside this fixture'
        Require (-not @($script:stateFirewallRules | Where-Object Name -Like 'AccessWeaver-*').Count) 'Existing product firewall rules are outside this fixture'
        $silent=@('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOCLOSEAPPLICATIONS','/NORESTARTAPPLICATIONS','/NOICONS',('/GROUP='+$group))
        $installArguments=$silent+@('/DIR='+$install)
        $uninstaller=Join-Path $install 'unins000.exe'
        $uninstallData=[IO.Path]::ChangeExtension($uninstaller,'dat')
        $report.stage='rolled-back-publication'
        $faultLog=Join-Path $capsule 'publication-rollback.log'
        $failed=Native-Record $fault ($installArguments+@('/LOG='+$faultLog)) @(1603)
        $report.setupExitCode=$failed.result.exitCode
        No-Reparse $faultLog
        Require ((Get-Item -LiteralPath $faultLog).Length -le 4MB -and
            [IO.File]::ReadAllText($faultLog).Contains('AccessWeaver fixture reached the staged publication rollback.')) 'Setup did not stage protected publication before rollback'
        Assert-LifecycleRegistrationAbsent 'Rolled-back publication exposed a product registration'
        Require ((Get-PendingInstallFixtureValue) -ceq ($version+'|'+$install) -and
            (Digest (Join-Path $install 'accessweaver.exe')) -ceq $expected.payloadSha256 -and
            [IO.File]::Exists($uninstaller) -and [IO.File]::Exists($uninstallData)) 'Failed publication did not retain its installed payload and pending record'
        $report.rolledBackPublication=$true
        Assert-ManagedDetection 'protected-publication-pending' $expected $false -InspectionRefused
        $report.pendingInstallDetected=$true

        $report.stage='setup-recovery'
        $recoveryLog=Join-Path $capsule 'publication-recovery.log'
        $recovered=Native-Record $real ($installArguments+@('/LOG='+$recoveryLog))
        $report.setupExitCode=$recovered.result.exitCode
        Assert-SetupCompletionReadback $recoveryLog
        Assert-Installed $expected
        Require ($null -eq (Get-PendingInstallFixtureValue)) 'Successful retry did not retire the pending record'
        Assert-ManagedDetection 'protected-publication-recovered' $expected $true -UseRegisteredDirectory
        $report.recoveredPublication=$true

        $report.stage='previous-directory-repair'
        Create-UserProfile
        $marker=Join-Path $install 'unrelated-preserve.txt'
        [IO.File]::WriteAllText($marker,'unrelated-existing-file')
        $markerHash=Digest $marker
        $repairLog=Join-Path $capsule 'publication-repair.log'
        $repaired=Native-Record $real ($silent+@('/LOG='+$repairLog))
        $report.setupExitCode=$repaired.result.exitCode
        Assert-SetupCompletionReadback $repairLog
        Assert-Installed $expected
        Assert-ManagedDetection 'protected-publication-repaired' $expected $true -UseRegisteredDirectory
        Require ((Digest $marker) -ceq $markerHash -and
            -not (Test-Path -LiteralPath (Join-Path $programFiles 'AccessWeaver'))) 'Repair did not preserve the registered custom directory'
        $report.previousDirectoryRepair=$true

        $report.stage='managed-uninstall-binding'
        $binding=Open-WorkflowUninstallBinding $Architecture
        try {
            Require ($null -ne $binding -and $binding.path -ieq $uninstaller -and
                $binding.sha256 -ieq (Digest $uninstaller) -and
                $binding.dataSHA256 -ieq (Digest $uninstallData)) 'Controller did not bind the protected registration and installed uninstaller'
        } finally {if($binding){Close-WorkflowUninstallBinding $binding}}
        $report.managedUninstallBinding=$true

        $report.stage='owned-uninstall'
        $removed=Native-Record $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
        $report.setupExitCode=$removed.result.exitCode
        Assert-InstallerRemoved $uninstaller
        Assert-ManagedDetection 'protected-publication-removed' $expected $false
        $report.ownedPayloadAndRegistrationRemoved=$true
        $report.userStatePreserved=$true
        Require ((State-Snapshot) -ceq $baseline) 'Protected Setup changed selected service, firewall or DNS state'
        $report.selectedMachineStateUnchanged=$true

        $report.stage='cleanup'
        $files=@(Get-ChildItem -LiteralPath $managed -File -Recurse -Force)
        Require ($files.Count -eq 1 -and $files[0].DirectoryName -ieq (Join-Path $managed 'logs') -and
            $files[0].Name -clike 'workflow-*.json') 'Unexpected recovery files must be retained'
        Assert-SuccessfulRestorationJournal $files[0].FullName
        Remove-OwnedTree $managed $managedParent 'AccessWeaver'
        Remove-OwnedTree $install $programFiles $installLeaf
        Remove-OwnedTree $capsule $temporary $capsuleLeaf
        $report.scratchRemoved=$true
        $report.passed=$true
        $report.stage='complete'
    } catch {
        $report.failureSourceLine=if($script:assertionFailureLine){$script:assertionFailureLine}else{$_.InvocationInfo.ScriptLineNumber}
        if($null -ne $script:lastNativeAttempt){$report.setupExitCode=$script:lastNativeAttempt.exitCode}
    } finally {
        [IO.File]::WriteAllText($reportPath,($report | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    }
    if(-not $report.passed){throw ('Protected registration Setup acceptance failed at '+$report.stage)}
}
