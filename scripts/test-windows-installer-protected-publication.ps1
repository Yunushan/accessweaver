# Reuses the disposable lifecycle harness's native launch, preservation and
# cleanup checks. Fault variants come from exact expanded Setup source and
# recovery runs use the unmodified candidates.
function New-ProtectedPublicationSetup([string]$Version, [string]$Label, $Legacy) {
    $buildDirectory=Join-Path $project 'build'
    [void][IO.Directory]::CreateDirectory($buildDirectory)
    $stagePattern='installer-'+$Architecture+'-*'
    $previousStages=@([IO.Directory]::EnumerateDirectories($buildDirectory,$stagePattern))
    $null=@(& (Join-Path $PSScriptRoot 'test-windows-installer.ps1') -ExpectedCompilerVersion '6.7.1' -TargetArch $Architecture -Version $Version)
    $staged=@([IO.Directory]::EnumerateDirectories($buildDirectory,$stagePattern) | Where-Object {$_ -cnotin $previousStages})
    Require ($staged.Count -eq 1) 'Protected Setup needs one exact staged payload'
    $evidence=Join-Path $buildDirectory ('installer-checks\'+$Architecture)
    $built=Get-Content -LiteralPath (Join-Path $evidence 'compiler-artifact.json') -Raw | ConvertFrom-Json
    Require ($built.sourceCommit -ceq $source -and $built.payloadBuild.sourceState -ceq 'clean' -and
        $built.payloadBuild.version -ceq $Version -and $built.compilerVersion -ceq '6.7.1' -and $built.unsigned) 'Protected Setup input differs from its source or compiler'
    $expected=@{
        version=$Version;payloadSha256=$built.payloadSha256;payloadBuild=$built.payloadBuild;installerName=$built.installerName
        identityFileSHA256=(Digest (Join-Path $staged[0] 'BUILD-INFO.json'))
        payloadSBOMSHA256=(Digest (Join-Path $staged[0] 'SBOM.cdx.json'))
        innoRuntimeNoticeSHA256=(Digest (Join-Path $staged[0] 'licenses\Inno-Setup-License.txt'))
    }
    $compiler=Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Inno Setup 6\ISCC.exe'
    $normal=Join-Path $buildDirectory $built.installerName
    Require ((Digest $compiler) -ceq $built.compilerSha256 -and (Digest $normal) -ceq $built.installerSha256 -and
        (Digest (Join-Path $staged[0] 'accessweaver.exe')) -ceq $expected.payloadSha256) 'Protected Setup inputs changed after normal staging'
    $directory=Join-Path $capsule $Label
    [void][IO.Directory]::CreateDirectory($directory)
    $expanded=Join-Path $directory 'expanded.iss'
    $setupScript=Join-Path $PSScriptRoot 'windows-installer.iss'
    $planArguments=@()
    if($Legacy){
        $include=Join-Path $directory 'retirement.iss'
        $plan=New-InstallerRetiredPayloadPlan $staged[0] $Legacy.inventoryPath $Legacy.inventorySHA256 $include
        $planArguments=@(('/DRetiredPayloadInclude='+$include),('/DRetiredPayloadIncludeSHA256='+$plan))
    }
    $compileArguments=@(('/DBuildRoot='+$staged[0]),('/DReleaseVersion='+$Version),('/DTargetArch='+$Architecture),
        ('/DEvidenceOutput='+$expanded),'/DRequireInnoRuntimeNotice','/DProtectedRegistrationQualification=1',('/O'+$directory))+
        $planArguments+@($setupScript)
    $null=@(& $compiler @compileArguments)
    Require ($LASTEXITCODE -eq 0) 'Protected Setup compilation failed'
    $null=Assert-InstallerSetupScript $expanded $Architecture $Version
    $fingerprint=''
    Assert-InstallerPackageDirectories $staged[0] $setupScript $expanded ([ref]$fingerprint)
    $expected.stagedPayloadSHA256=$fingerprint
    $real=Join-Path $directory $built.installerName
    return @{
        expected=$expected;compiler=$compiler;compilerSHA256=$built.compilerSha256
        real=$real;expanded=$expanded;sha256=(Digest $real);stage=$staged[0]
    }
}

function New-LegacyRetirementFixtureSetup($First) {
    $setup=Join-Path $PSScriptRoot 'windows-installer.iss'
    $directory=Join-Path $capsule 'legacy-baseline'
    [void][IO.Directory]::CreateDirectory($directory)
    $expanded=Join-Path $directory 'legacy.iss'
    $inventoryPath=Join-Path $directory 'payload-files.txt'
    $files=@('docs\legacy-fixture-retired.txt','docs\legacy-fixture-edited.txt')
    $created=[Collections.Generic.List[string]]::new()
    $inventorySHA256='';$inventory=''
    try {
        foreach($relative in $files){
            $path=Join-Path $First.stage $relative
            $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $created.Add($path)
            try {
                $bytes=[Text.Encoding]::UTF8.GetBytes('Previously shipped AccessWeaver fixture')
                $stream.Write($bytes,0,$bytes.Length)
            } finally {$stream.Dispose()}
        }
        $compileArguments=@(('/DBuildRoot='+$First.stage),('/DReleaseVersion='+$First.expected.version),
            ('/DTargetArch='+$Architecture),('/DEvidenceOutput='+$expanded),'/DRequireInnoRuntimeNotice',('/O'+$directory),$setup)
        $null=@(& $First.compiler @compileArguments)
        Require ($LASTEXITCODE -eq 0) 'Legacy footprint fixture compilation failed'
        Assert-InstallerPackageDirectories $First.stage $setup $expanded ([ref]$inventorySHA256) ([ref]$inventory)
        [IO.File]::WriteAllText($inventoryPath,$inventory,[Text.UTF8Encoding]::new($false))
        Require ((Digest $inventoryPath) -ceq $inventorySHA256) 'Compiled legacy inventory changed when written'
    } finally {
        foreach($path in $created){[IO.File]::Delete($path)}
    }
    $installer=Join-Path $directory $First.expected.installerName
    return @{
        expected=$First.expected;normal=$installer;normalSHA256=(Digest $installer)
        inventoryPath=$inventoryPath;inventorySHA256=$inventorySHA256;files=$files
    }
}

function New-LegacyInterruptionSetup($Next) {
    $sourceText=[IO.File]::ReadAllText($Next.expanded)
    $boundary='if Result then SetArrayLength(AWPriorRegistration, 0);'
    Require ([regex]::Matches($sourceText,[regex]::Escape($boundary)).Count -eq 1 -and
        [regex]::Matches($sourceText,'(?m)^UninstallLogMode=overwrite\s*$').Count -eq 1) 'Legacy migration must discard its old uninstaller log and expose one committed boundary'
    $entry='function AWRetireApprovedLegacyRegistration(const Destination: String): Boolean;'
    Require ([regex]::Matches($sourceText,[regex]::Escape($entry)).Count -eq 1) 'Expected one bound legacy retirement entry point'
    $native=@'
function AWFixtureLegacyCurrentProcess: LongWord;
  external 'GetCurrentProcess@kernel32.dll stdcall';
function AWFixtureLegacyTerminate(Process, ExitCode: LongWord): Integer;
  external 'TerminateProcess@kernel32.dll stdcall';

'@
    $interruption=@'
if Result then begin
      SetArrayLength(AWPriorRegistration, 0);
      AWFixtureLegacyTerminate(AWFixtureLegacyCurrentProcess, 198);
      RaiseException('Unable to terminate the owned legacy migration fixture.');
    end;
'@
    $directory=Join-Path $capsule 'legacy-interruption'
    [void][IO.Directory]::CreateDirectory($directory)
    $script=Join-Path $directory 'interruption.iss'
    [IO.File]::WriteAllText($script,$sourceText.Replace($entry,$native+$entry).Replace($boundary,$interruption),[Text.UTF8Encoding]::new($true))
    $null=@(& $Next.compiler ('/O'+$directory) $script)
    Require ($LASTEXITCODE -eq 0) 'Committed legacy retirement fixture compilation failed'
    return (Join-Path $directory $Next.expected.installerName)
}

function Invoke-ProtectedLegacyMigration($First,$Next,[string]$Interrupted,[string[]]$InstallArguments,$Report) {
    $Report.stage='legacy-install'
    $before=$First.expected
    $after=$Next.expected
    Require ((Digest $First.normal) -ceq $First.normalSHA256) 'Legacy Setup changed after its normal build'
    $legacyLog=Join-Path $capsule 'legacy-install.log'
    $null=Native-Record $First.normal ($InstallArguments+@('/LOG='+$legacyLog))
    Assert-SetupCompletionReadback $legacyLog
    Assert-Installed $before
    $retired=Join-Path $install $First.files[0]
    $edited=Join-Path $install $First.files[1]
    $foreign=Join-Path $install 'docs\legacy-fixture-unrelated.txt'
    No-Reparse $retired;No-Reparse $edited
    $retiredPin=Digest $retired
    Require ((Digest $edited) -ceq $retiredPin) 'Legacy Setup did not copy the two old package files'
    [IO.File]::WriteAllText($edited,'Edited former package fixture')
    Require (-not (Test-Path -LiteralPath $foreign)) 'Unrelated fixture path already exists'
    [IO.File]::Copy($retired,$foreign,$false)
    $editedPin=Digest $edited
    $uninstaller=Join-Path $install 'unins000.exe'
    $uninstallData=[IO.Path]::ChangeExtension($uninstaller,'dat')
    $uninstallerPin=Digest $uninstaller
    $dataPin=Digest $uninstallData
    $baselinePrefix='/AWUpgradeFrom='+(@($before.version,$before.payloadSha256,$before.payloadSBOMSHA256,
        $before.identityFileSHA256,$uninstallerPin) -join ',')+','
    $baselineArgument=$baselinePrefix+$dataPin
    # Assert-DetectorRefusal verifies the pending pin against the candidate
    # staged payload and refuses a different pin using its existing contract.
    $builds=@($before,$after)

    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $writer=$null
    try {
        $writer=$base.OpenSubKey($uninstallKey,$true)
        Require ($null -ne $writer) 'Legacy migration needs a held writer for the verified prior entry'
        $beforeRegistration=Registration-Fingerprint $writer
        $Report.stage='legacy-wrong-approval'
        $wrongPin=if($dataPin[0] -ceq '0'){'1'+$dataPin.Substring(1)}else{'0'+$dataPin.Substring(1)}
        $refusalLog=Join-Path $capsule 'legacy-approval-refusal.log'
        $null=Native-Record $Next.real ($InstallArguments+@(($baselinePrefix+$wrongPin),('/LOG='+$refusalLog))) @(3,4,7)
        No-Reparse $refusalLog
        Require ((Get-Item -LiteralPath $refusalLog).Length -le 4MB -and
            [IO.File]::ReadAllText($refusalLog).Contains('Migration requires the approved prior installer files and registration.')) 'Wrong uninstaller-data hash did not reach legacy baseline refusal'
        Require (($null -eq (Get-PendingInstallFixtureValue)) -and
            (Registration-Fingerprint $writer) -ceq $beforeRegistration -and
            (Digest $uninstallData) -ceq $dataPin -and (Digest $uninstaller) -ceq $uninstallerPin) 'Wrong legacy approval changed registration, uninstall files or pending state'
        Assert-Installed $before
        $Report.legacyWrongApprovalRefused=$true

        $Report.stage='legacy-interrupted-after-retirement'
        $null=Native-Record $Interrupted ($InstallArguments+@($baselineArgument)) @(198)
        Assert-LifecycleRegistrationAbsent 'Interrupted retirement left a visible legacy or new registration'
        Require ((Digest (Join-Path $install 'accessweaver.exe')) -ceq $before.payloadSha256 -and
            (Digest (Join-Path $install 'SBOM.cdx.json')) -ceq $before.payloadSBOMSHA256 -and
            (Digest (Join-Path $install 'BUILD-INFO.json')) -ceq $before.identityFileSHA256 -and
            (Digest $uninstallData) -ceq $dataPin -and (Digest $uninstaller) -ceq $uninstallerPin) 'Interruption did not preserve the old installation before copy'
        Assert-DetectorRefusal 'legacy-retirement-pending' -VerifyMatchingPendingStatus
        Assert-DetectorRefusal 'legacy-retirement-managed-pending' -VerifyMatchingPendingStatus -UseRegisteredDirectory
        $Report.legacyInterruptionVerified=$true

        $Report.stage='legacy-retirement-locked-file'
        $retryArguments=@($InstallArguments | Where-Object {$_ -notlike '/DIR=*'})
        $retirementPin=Get-PendingInstallFixtureValue
        $retirementLog=Join-Path $capsule 'legacy-retired-file-locked.log'
        $locked=[IO.File]::Open($retired,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $null=Native-Record $Next.real ($retryArguments+@($baselineArgument,('/LOG='+$retirementLog))) @(1603)
            No-Reparse $retirementLog
            Require ((Get-Item -LiteralPath $retirementLog).Length -le 4MB -and
                [IO.File]::ReadAllText($retirementLog).Contains('AccessWeaver could not retire a verified prior package file.')) 'Locked file did not reach the retirement boundary'
            Require ((Get-PendingInstallFixtureValue) -ceq $retirementPin -and (Digest $retired) -ceq $retiredPin) 'Locked retirement changed the old file or pending approval'
        } finally {$locked.Dispose()}

        $Report.stage='legacy-approved-retry'
        $recoveryLog=Join-Path $capsule 'legacy-recovery.log'
        $null=Native-Record $Next.real ($retryArguments+@($baselineArgument,('/LOG='+$recoveryLog)))
        Assert-SetupCompletionReadback $recoveryLog
        Assert-Installed $after
        Require ($null -eq (Get-PendingInstallFixtureValue)) 'Approved migration retry left the pending record'
        Assert-ManagedDetection 'legacy-replacement' $after $true -UseRegisteredDirectory
        $Report.legacyRecoveryVerified=$true
        $Report.stage='legacy-retired-package-files'
        Require (-not (Test-Path -LiteralPath $retired) -and
            (Digest $edited) -ceq $editedPin -and (Digest $foreign) -ceq $retiredPin) 'Retirement failed to remove the exact old file or preserve unrelated contents'
        No-Reparse $edited;No-Reparse $foreign
        [IO.File]::Delete($edited)
        [IO.File]::Delete($foreign)
        $Report.legacyRetiredPackageCleanupVerified=$true

        $deletedHandle=$false
        try {$writer.SetValue('accessweaver-fixture-stale-writer',1,[Microsoft.Win32.RegistryValueKind]::DWord)}
        catch {
            $failure=$_.Exception
            while($failure.InnerException){$failure=$failure.InnerException}
            $deletedHandle=($failure.HResult -band 0xffff) -eq 1018
        }
        Require $deletedHandle 'Retired legacy handle could still change registration'
        $Report.legacyStaleWriterRefused=$true
    } finally {
        if($writer){$writer.Dispose()}
        $base.Dispose()
    }
    $Report.stage='legacy-replacement-uninstall'
    $removed=Native-Record $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
    $Report.setupExitCode=$removed.result.exitCode
    Assert-InstallerRemoved $uninstaller
    Assert-ManagedDetection 'legacy-replacement-removed' $after $false
    $Report.legacyReplacementRemoved=$true
}

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
        schemaVersion=4;scope='disposable-protected-registration-setup'
        sourceCommit=$source;runID=$run;runAttempt=$runAttempt;architecture=$Architecture
        sourceSHA256=$pins;compilerSHA256=$null;compiledSetupSHA256=$null;faultedSetupSHA256=$null
        stagedPayloadSHA256=$null;legacyInstallerSHA256=$null;migrationInstallerSHA256=$null;interruptedMigrationSHA256=$null
        stage='build';setupExitCode=$null;failureSourceLine=$null;bindingFailure=$null
        rolledBackPublication=$false;pendingInstallDetected=$false;recoveredPublication=$false
        previousDirectoryRepair=$false;managedUninstallBinding=$false;ownedPayloadAndRegistrationRemoved=$false
        legacyWrongApprovalRefused=$false;legacyInterruptionVerified=$false;legacyRecoveryVerified=$false
        legacyStaleWriterRefused=$false;legacyReplacementRemoved=$false;legacyRetiredPackageCleanupVerified=$false
        userStatePreserved=$false;selectedMachineStateUnchanged=$false;scratchRemoved=$false
        passed=$false;productionQualificationComplete=$false
    }
    try {
        $version='0.1.0-alpha'
        $first=New-ProtectedPublicationSetup $version 'protected'
        $expected=$first.expected
        $compiler=$first.compiler
        $report.compilerSHA256=$first.compilerSHA256
        $report.stagedPayloadSHA256=$expected.payloadSha256
        $builtName=$expected.installerName
        $real=$first.real
        $report.compiledSetupSHA256=$first.sha256
        $expanded=$first.expanded
        $faultDirectory=Join-Path $capsule 'rollback'
        [void][IO.Directory]::CreateDirectory($faultDirectory)

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
        $fault=Join-Path $faultDirectory $builtName
        $report.faultedSetupSHA256=Digest $fault
        Require ($report.faultedSetupSHA256 -cne $report.compiledSetupSHA256) 'Rollback Setup must contain the injected fixture boundary'

        $report.stage='compile-migration'
        $legacy=New-LegacyRetirementFixtureSetup $first
        $next=New-ProtectedPublicationSetup '0.1.1-alpha' 'protected-migration' $legacy
        $interrupted=New-LegacyInterruptionSetup $next
        $report.legacyInstallerSHA256=$legacy.normalSHA256
        $report.migrationInstallerSHA256=$next.sha256
        $report.interruptedMigrationSHA256=Digest $interrupted
        Require ($report.interruptedMigrationSHA256 -cne $report.migrationInstallerSHA256) 'Legacy interruption fixture must differ from the unmodified Setup'

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
        $binding=$null
        try {
            $binding=Open-WorkflowUninstallBinding $Architecture
            Require ($null -ne $binding -and $binding.path -ieq $uninstaller -and
                $binding.sha256 -ieq (Digest $uninstaller) -and
                $binding.dataSHA256 -ieq (Digest $uninstallData)) 'Controller did not bind the protected registration and installed uninstaller'
        } catch {
            $report.bindingFailure=switch -Exact ($_.Exception.Message) {
                'An AccessWeaver installation is incomplete. Retry the approved installer before uninstalling.' {'recovery-pending'}
                'AccessWeaver Setup recovery state could not be read. Ask an administrator to verify it before uninstalling.' {'recovery-unavailable'}
                'AccessWeaver Setup is active or its mutex could not be inspected' {'setup-active'}
                'Registered AccessWeaver installation ownership could not be verified' {'ownership'}
                'Registered AccessWeaver installation is writable by an untrusted principal' {'writable'}
                'Registered AccessWeaver installation access could not be verified' {'access'}
                'Registered AccessWeaver payload or uninstaller architecture could not be verified' {'architecture'}
                'Controller did not bind the protected registration and installed uninstaller' {'identity'}
                default {'other'}
            }
            throw
        } finally {if($binding){Close-WorkflowUninstallBinding $binding}}
        $report.managedUninstallBinding=$true

        $report.stage='owned-uninstall'
        $removed=Native-Record $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
        $report.setupExitCode=$removed.result.exitCode
        Assert-InstallerRemoved $uninstaller
        Assert-ManagedDetection 'protected-publication-removed' $expected $false
        $report.ownedPayloadAndRegistrationRemoved=$true
        $files=@(Get-ChildItem -LiteralPath $managed -File -Recurse -Force)
        Require ($files.Count -eq 1 -and $files[0].DirectoryName -ieq (Join-Path $managed 'logs') -and
            $files[0].Name -clike 'workflow-*.json') 'Unexpected recovery files must be retained'
        $firstJournal=$files[0].FullName
        $firstJournalPin=Digest $firstJournal
        Assert-SuccessfulRestorationJournal $firstJournal

        Invoke-ProtectedLegacyMigration $legacy $next $interrupted $installArguments $report
        $report.userStatePreserved=$true
        Require ((State-Snapshot) -ceq $baseline) 'Protected Setup changed selected service, firewall or DNS state'
        $report.selectedMachineStateUnchanged=$true

        $report.stage='cleanup'
        $files=@(Get-ChildItem -LiteralPath $managed -File -Recurse -Force)
        Require ($files.Count -eq 2 -and -not @($files | Where-Object {
            $_.DirectoryName -ine (Join-Path $managed 'logs') -or $_.Name -cnotlike 'workflow-*.json'
        }).Count -and (Digest $firstJournal) -ceq $firstJournalPin) 'Unrelated recovery files must be retained'
        foreach($file in $files){Assert-SuccessfulRestorationJournal $file.FullName}
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
