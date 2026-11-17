# Exercise the production detector with inert temporary files and mocked registry data.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'detect-windows-installer.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Managed detection source failed parsing'}
$nodes=@($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Read-AccessWeaverRegistration'
})
if($nodes.Count -ne 1){throw 'Expected one managed detector registry boundary'}
$node=$nodes[0].Extent
$probeName='Get-AccessWeaverInstallerRecoveryState'
$controller=Join-Path (Split-Path -Parent $PSScriptRoot) 'internal\workflow\windows.ps1'
$controllerAst=[Management.Automation.Language.Parser]::ParseFile($controller,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Controller recovery probe source failed parsing'}
$probes=@(foreach($scriptAst in @($ast,$controllerAst)){
    $scriptAst.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $probeName
    }
})
if($probes.Count -ne 2 -or $probes[0].Extent.Text -cne $probes[1].Extent.Text){
    throw 'Standalone detector and embedded controller recovery probes differ'
}
$nativeReaders=@(foreach($scriptAst in @($ast,$controllerAst)){
    $scriptAst.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $_.Name -ceq 'Initialize-AccessWeaverInstallerRecoveryRegistry'
    }
})
if($nativeReaders.Count -ne 2 -or $nativeReaders[0].Extent.Text -cne $nativeReaders[1].Extent.Text){
    throw 'Standalone detector and embedded controller registry readers differ'
}
$setupProbes=@(foreach($scriptAst in @($ast,$controllerAst)){
    $scriptAst.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Assert-NoAccessWeaverSetup'
    }
})
if($setupProbes.Count -ne 2 -or $setupProbes[0].Extent.Text -cne $setupProbes[1].Extent.Text){
    throw 'Standalone detector and embedded controller Setup mutex checks differ'
}
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-detection-'+[guid]::NewGuid().ToString('N'))
$fixtureDirectory=[IO.Directory]::CreateDirectory($testRoot)
$payload=Join-Path $testRoot 'accessweaver.exe'
$fixture=Join-Path $testRoot 'fixture.ps1'
$uninstaller=Join-Path $testRoot 'unins001.exe'
$uninstallData=[IO.Path]::ChangeExtension($uninstaller,'.dat')
$sbom=Join-Path $testRoot 'SBOM.cdx.json'
$notice=Join-Path $testRoot 'licenses\fixture-license.txt'
$buildInfo=Join-Path $testRoot 'BUILD-INFO.json'
$packageDirectories=@('licenses','docs','docs\assets','docs\qualification')
$buildInfoBytes=[Text.Encoding]::UTF8.GetBytes('{"version":"0.1.0-alpha"}')
try {
    foreach($directory in $packageDirectories){[void][IO.Directory]::CreateDirectory((Join-Path $testRoot $directory))}
    [IO.File]::WriteAllText($payload,'inert detection test data')
    $hash=(Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($uninstaller,'inert uninstaller fixture')
    $uninstallerHash=(Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash
    $noticeBytes=[Text.Encoding]::UTF8.GetBytes('Inert fixture license notice')
    [IO.File]::WriteAllBytes($notice,$noticeBytes)
    $noticeDigest=(Get-FileHash -LiteralPath $notice -Algorithm SHA256).Hash.ToLowerInvariant()
    $noticeEvidence=ConvertTo-Json -InputObject @(@{path='licenses/fixture-license.txt';sha256=$noticeDigest}) -Compress
    $sbomDocument=@{bomFormat='CycloneDX';specVersion='1.6';components=@()
        metadata=@{component=@{type='application';properties=@(@{name='accessweaver:license-evidence';value=$noticeEvidence})}}}
    $sbomBytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $sbomDocument -Depth 8 -Compress))
    [IO.File]::WriteAllBytes($sbom,$sbomBytes)
    $sbomHash=(Get-FileHash -LiteralPath $sbom -Algorithm SHA256).Hash
    $invalidSBOMBytes=[Text.Encoding]::UTF8.GetBytes('{"fixture":true}')
    $invalidSBOM=[IO.MemoryStream]::new($invalidSBOMBytes,$false)
    try {$invalidSBOMHash=(Get-FileHash -InputStream $invalidSBOM -Algorithm SHA256).Hash}
    finally {$invalidSBOM.Dispose()}
    [IO.File]::WriteAllBytes($buildInfo,$buildInfoBytes)
    $buildInfoHash=(Get-FileHash -LiteralPath $buildInfo -Algorithm SHA256).Hash
    $sha256=[Security.Cryptography.SHA256]::Create()
    try {$publisherHash=[BitConverter]::ToString($sha256.ComputeHash([byte[]]@(1,2,3))).Replace('-','')}
    finally {$sha256.Dispose()}
    $mock=@'
$script:mockReads=0
function Read-AccessWeaverRegistration([Microsoft.Win32.RegistryView]$View) {
    if($View -eq [Microsoft.Win32.RegistryView]::Registry32 -and $env:AW_DETECTION_FIXTURE -cnotin @('alternate','managed-pending-alternate')){return $null}
    if($env:AW_DETECTION_FIXTURE -cin @('absent','managed-pending-unregistered')){return $null}
    $script:mockReads++
    if($env:AW_DETECTION_FIXTURE -ceq 'setup-starts-during-inspection' -and $script:mockReads -eq 1){
        # Retain the fixture-only object until the isolated child process exits.
        $script:startedSetup=[Threading.Mutex]::new($false,'Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092')
    }
    $changed=$env:AW_DETECTION_FIXTURE -ceq 'registration-changed' -and $script:mockReads -gt 1
    $version=if($env:AW_DETECTION_FIXTURE -ceq 'other-version' -or $changed){'0.1.1-alpha'}else{'0.1.0-alpha'}
    $location=if($env:AW_DETECTION_FIXTURE -ceq 'other-path'){$PSScriptRoot+'-other'}else{$PSScriptRoot}
    $record=@{version=$version;location=$location+'\'}
    if($UninstallerSHA256 -and $env:AW_DETECTION_FIXTURE -cne 'missing-command'){
        $leaf=switch -CaseSensitive ($env:AW_DETECTION_FIXTURE){
            'redirected' {'..\unins001.exe'}
            'missing-uninstaller' {'unins002.exe'}
            default {'unins001.exe'}
        }
        $command='"'+(Join-Path $PSScriptRoot $leaf)+'"'
        $log=if($env:AW_DETECTION_FIXTURE -ceq 'logging'){' /LOG'}else{''}
        $record.UninstallString=$command+$log
        $record.QuietUninstallString=$command+' /SILENT'+$log
        if($env:AW_DETECTION_FIXTURE -ceq 'extra-arguments' -or
            ($env:AW_DETECTION_FIXTURE -ceq 'uninstaller-changed' -and $script:mockReads -gt 1)){
            $record.QuietUninstallString+=' /DIR=other'
        }
    }
    return $record
}
'@
    $original=[IO.File]::ReadAllText($source)
    $productionLock='Global\AccessWeaver-Lifecycle-B13D4677-4660-4E63-B3DB-03077ACBB092'
    $lockSource=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer-lock.iss'))
    if(-not $lockSource.Contains("'"+$productionLock+"'") -or -not $original.Contains("'"+$productionLock+"'")){
        throw 'Detector and installer lifecycle names differ'
    }
    $productionSetup='Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092'
    $setupSource=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer.iss'))
    if(-not $setupSource.Contains("SetupMutex="+$productionSetup) -or -not $original.Contains("'"+$productionSetup+"'")){
        throw 'Detector and legacy Inno Setup mutex names differ'
    }
    $fixtureSetup='Global\AccessWeaver-SetupDetectionTest-'+[guid]::NewGuid().ToString('N')
    $fixtureLock='Global\AccessWeaver-DetectionTest-'+[guid]::NewGuid().ToString('N')
    $mocked=$original.Substring(0,$node.StartOffset)+$mock+$original.Substring($node.EndOffset)
    # Keep the production status mapping and detector assertion. Replace only
    # the native call in the isolated child with fixed Win32 result codes.
    $nativeCall='[AccessWeaver.InstallerLifecycleRecoveryRegistry]::QueryStatus()'
    $fixtureStatus=@'
$(switch -CaseSensitive ($env:AW_DETECTION_FIXTURE){
    'pending' {0}
    {$_ -clike 'managed-pending-*'} {0}
    'marker-becomes-pending' {if($script:mockReads -eq 0){2}else{0}}
    'marker-path-absent' {3}
    'marker-access-denied' {5}
    'marker-key-deleted' {1018}
    'marker-query-failed' {throw 'Private fixture error'}
    default {2}
})
'@
    $probe=$probes[0].Extent.Text
    if(-not $probe.Contains($nativeCall)){throw 'Missing fixed native recovery query'}
    $mocked=$mocked.Replace($probe,$probe.Replace($nativeCall,$fixtureStatus))
    $nativeRecord='[AccessWeaver.InstallerLifecycleRecoveryRegistry]::ReadValue()'
    $fixtureRecord=@'
$(switch -CaseSensitive ($env:AW_DETECTION_FIXTURE){
    'managed-pending-wrong-version' {'0.1.1-alpha|'+$PSScriptRoot+'|'+('a'*64)}
    'managed-pending-wrong-path' {$Version+'|'+$PSScriptRoot+'-other|'+('a'*64)}
    'managed-pending-unmanaged' {$Version+'|'+$PSScriptRoot}
    'managed-pending-invalid-pin' {$Version+'|'+$PSScriptRoot+'|'+('z'*64)}
    'managed-pending-changed' {
        $pin=if($script:mockReads -eq 0){'a'*64}else{'b'*64}
        $Version+'|'+$PSScriptRoot+'|'+$pin
    }
    {$_ -clike 'managed-pending-*'} {$Version+'|'+$PSScriptRoot+'|'+('a'*64)}
})
'@
    if(([regex]::Matches($mocked,[regex]::Escape($nativeRecord))).Count -ne 2){throw 'Missing bounded registry marker probes'}
    $mocked=$mocked.Replace($nativeRecord,$fixtureRecord)
    $signatureCall='Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop'
    if(-not $mocked.Contains($signatureCall)){throw 'Missing installed publisher verification boundary'}
    $fixtureSignature=@'
$(if($Path -cne (Join-Path $PSScriptRoot 'accessweaver.exe')){throw 'Unexpected signature path'}
$held=$false
try {$writer=[IO.File]::OpenWrite($Path);$writer.Dispose()}catch [IO.IOException] {$held=$true}
if(-not $held){throw 'Installed payload was not held during publisher verification'}
$status=if($env:AW_DETECTION_FIXTURE -ceq 'publisher-untrusted'){'NotTrusted'}else{'Valid'}
$type=if($env:AW_DETECTION_FIXTURE -ceq 'publisher-catalog'){'Catalog'}else{'Authenticode'}
$timestamp=if($env:AW_DETECTION_FIXTURE -cne 'publisher-no-timestamp'){[pscustomobject]@{}}
$certificate=if($env:AW_DETECTION_FIXTURE -cne 'publisher-no-certificate'){[pscustomobject]@{RawData=[byte[]]@(1,2,3)}}
[pscustomobject]@{Status=$status;SignatureType=$type;SignerCertificate=$certificate;TimeStamperCertificate=$timestamp})
'@
    $mocked=$mocked.Replace($signatureCall,$fixtureSignature)
    [IO.File]::WriteAllText($fixture,$mocked.Replace($productionLock,$fixtureLock).Replace($productionSetup,$fixtureSetup))
    $arch=@{X64='amd64';Arm64='arm64'}[[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()]
    $stock=Join-Path $PSHOME 'powershell.exe'
    if(-not (Test-Path -LiteralPath $stock)){$stock=Join-Path $PSHOME 'pwsh.exe'}
    $saved=$env:AW_DETECTION_FIXTURE
    $savedRecovery=$env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY
    try {
        $cases=@(
            @{mode='pending';code=1;count=0;hash=$hash},
            @{mode='pending';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true},
            @{mode='managed-pending-match';code=1;count=0;hash=$hash},
            @{mode='managed-pending-match';code=1;count=1;hash=$hash;reportRecovery=$true;matchingPendingStatus=$true},
            @{mode='managed-pending-match';code=1;count=1;hash=$hash;reportRecovery=$true;matchingPendingStatus=$true;registered=$true;approval=('a'*64)},
            @{mode='managed-pending-match';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true;registered=$true;approval=('b'*64)},
            @{mode='managed-pending-match';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true;registered=$true;withoutApproval=$true},
            @{mode='managed-pending-wrong-version';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true},
            @{mode='managed-pending-wrong-path';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true},
            @{mode='managed-pending-unmanaged';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true},
            @{mode='managed-pending-invalid-pin';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true},
            @{mode='managed-pending-unregistered';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true;registered=$true},
            @{mode='managed-pending-alternate';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true;registered=$true},
            @{mode='managed-pending-changed';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true},
            @{mode='managed-pending-match';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true;otherDirectory=$true},
            @{mode='marker-becomes-pending';code=1;count=1;hash=$hash;reportRecovery=$true;pendingStatus=$true},
            @{mode='marker-access-denied';code=1;count=0;hash=$hash;reportRecovery=$true},
            @{mode='marker-query-failed';code=1;count=0;hash=$hash;reportRecovery=$true},
            @{mode='approved';code=0;count=1;hash=$hash;reportRecovery=$true},
            @{mode='marker-path-absent';code=0;count=1;hash=$hash},
            @{mode='setup-starts-during-inspection';code=1;count=0;hash=$hash},
            @{mode='marker-becomes-pending';code=1;count=0;hash=$hash},
            @{mode='marker-becomes-pending';code=1;count=0;hash=$hash;sbom=$sbomHash;publisher=$publisherHash;inventory=$true},
            @{mode='marker-access-denied';code=1;count=0;hash=$hash},
            @{mode='marker-key-deleted';code=1;count=0;hash=$hash},
            @{mode='marker-query-failed';code=1;count=0;hash=$hash},
            @{mode='approved';code=0;count=1;hash=$hash},
            @{mode='approved';code=0;count=0;hash=('0'*64)},
            @{mode='absent';code=0;count=0;hash=$hash},
            @{mode='other-version';code=0;count=0;hash=$hash},
            @{mode='other-path';code=1;count=0;hash=$hash},
            @{mode='alternate';code=1;count=0;hash=$hash},
            @{mode='registration-changed';code=1;count=0;hash=$hash},
            @{mode='approved';code=0;count=1;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='logging';code=0;count=1;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='approved';code=1;count=0;hash=$hash;uninstaller=$uninstallerHash;removeUninstallData=$true},
            @{mode='approved';code=1;count=0;hash=$hash;uninstaller=$uninstallerHash;emptyUninstallData=$true},
            @{mode='approved';code=0;count=1;hash=$hash;removeUninstallData=$true},
            @{mode='approved';code=0;count=0;hash=$hash;uninstaller=('0'*64)},
            @{mode='approved';code=1;count=0;hash=$hash;uninstaller='invalid'},
            @{mode='missing-command';code=1;count=0;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='redirected';code=1;count=0;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='missing-uninstaller';code=1;count=0;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='extra-arguments';code=1;count=0;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='uninstaller-changed';code=1;count=0;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='absent';code=0;count=0;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='other-version';code=0;count=0;hash=$hash;uninstaller=$uninstallerHash},
            @{mode='approved';code=0;count=1;hash=$hash;sbom=$sbomHash},
            @{mode='approved';code=0;count=1;hash=$hash;sbom=$sbomHash;uninstaller=$uninstallerHash},
            @{mode='approved';code=1;count=0;hash=$hash;sbom=$invalidSBOMHash;invalidSBOM=$true;label='invalid SBOM with a matching hash'},
            @{mode='approved';code=0;count=0;hash=$hash;sbom=$sbomHash;changedNotice=$true;label='changed SBOM-listed notice'},
            @{mode='approved';code=1;count=0;hash=$hash;sbom=$sbomHash;removeNotice=$true;label='missing SBOM-listed notice'},
            @{mode='approved';code=0;count=0;hash=$hash;sbom=('0'*64);uninstaller=$uninstallerHash},
            @{mode='approved';code=1;count=0;hash=$hash;sbom='invalid'},
            @{mode='approved';code=1;count=0;hash=$hash;sbom=$sbomHash;removeSBOM=$true},
            @{mode='approved';code=0;count=1;hash=$hash;removeSBOM=$true},
            @{mode='absent';code=0;count=0;hash=$hash;sbom=$sbomHash;removeSBOM=$true},
            @{mode='registration-changed';code=1;count=0;hash=$hash;sbom=$sbomHash},
            @{mode='approved';code=0;count=1;hash=$hash;buildInfo=$buildInfoHash;sbom=$sbomHash},
            @{mode='approved';code=0;count=0;hash=$hash;buildInfo=$buildInfoHash;changedBuildInfo=$true},
            @{mode='approved';code=1;count=0;hash=$hash;buildInfo=$buildInfoHash;removeBuildInfo=$true},
            @{mode='approved';code=0;count=1;hash=$hash;removeBuildInfo=$true},
            @{mode='approved';code=1;count=0;hash=$hash;buildInfo=$buildInfoHash;oversizedBuildInfo=$true},
            @{mode='approved';code=1;count=0;hash=$hash;buildInfo='invalid'},
            @{mode='absent';code=0;count=0;hash=$hash;buildInfo=$buildInfoHash;removeBuildInfo=$true},
            @{mode='approved';code=0;count=1;hash=$hash;publisher=$publisherHash},
            @{mode='approved';code=0;count=0;hash=$hash;publisher=('0'*64)},
            @{mode='approved';code=1;count=0;hash=$hash;publisher='invalid'},
            @{mode='publisher-untrusted';code=0;count=0;hash=$hash;publisher=$publisherHash},
            @{mode='publisher-catalog';code=0;count=0;hash=$hash;publisher=$publisherHash},
            @{mode='publisher-no-timestamp';code=0;count=0;hash=$hash;publisher=$publisherHash},
            @{mode='publisher-no-certificate';code=0;count=0;hash=$hash;publisher=$publisherHash},
            @{mode='approved';code=0;count=1;hash=$hash;sbom=$sbomHash;publisher=$publisherHash;inventory=$true},
            @{mode='approved';code=0;count=1;hash=$hash;sbom=$sbomHash;publisher=$publisherHash;inventory=$true;buildInfo=$buildInfoHash},
            @{mode='approved';code=0;count=0;hash=$hash;sbom=$sbomHash;publisher=$publisherHash;inventory=$true;buildInfo=$buildInfoHash;changedBuildInfo=$true},
            @{mode='approved';code=0;count=0;hash=$hash;sbom=$sbomHash;publisher=('0'*64);inventory=$true},
            @{mode='approved';code=1;count=0;hash=$hash;sbom=$sbomHash;inventory=$true},
            @{mode='approved';code=1;count=0;hash=$hash;publisher=$publisherHash;inventory=$true},
            @{mode='registration-changed';code=1;count=0;hash=$hash;sbom=$sbomHash;publisher=$publisherHash;inventory=$true},
            @{mode='pending';code=1;count=0;hash=$hash;sbom=$sbomHash;publisher=$publisherHash;inventory=$true}
        )
        foreach($case in $cases){
            if($case.removeUninstallData){[IO.File]::Delete($uninstallData)}
            elseif($case.emptyUninstallData){[IO.File]::WriteAllBytes($uninstallData,[byte[]]@())}
            else{[IO.File]::WriteAllText($uninstallData,'inert uninstall data fixture')}
            if($case.removeSBOM){[IO.File]::Delete($sbom)}
            elseif($case.invalidSBOM){[IO.File]::WriteAllBytes($sbom,$invalidSBOMBytes)}
            else{[IO.File]::WriteAllBytes($sbom,$sbomBytes)}
            if($case.removeNotice){[IO.File]::Delete($notice)}
            elseif($case.changedNotice){[IO.File]::WriteAllText($notice,'changed fixture notice')}
            else{[IO.File]::WriteAllBytes($notice,$noticeBytes)}
            if($case.removeBuildInfo){[IO.File]::Delete($buildInfo)}
            elseif($case.changedBuildInfo){[IO.File]::WriteAllText($buildInfo,'{"version":"0.1.1-alpha"}')}
            elseif($case.oversizedBuildInfo){[IO.File]::WriteAllBytes($buildInfo,[byte[]]::new(64KB+1))}
            else{[IO.File]::WriteAllBytes($buildInfo,$buildInfoBytes)}
            $env:AW_DETECTION_FIXTURE=$case.mode
            $env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY=if($case.reportRecovery){'1'}
            $arguments=@('-NoProfile','-NonInteractive','-File',$fixture,'-Version','0.1.0-alpha','-Architecture',$arch,'-PayloadSHA256',$case.hash)
            if($case.registered){$arguments+='-UseRegisteredDirectory'}
            elseif($case.otherDirectory){$arguments+=@('-InstallDirectory',($testRoot+'-other'))}
            else{$arguments+=@('-InstallDirectory',$testRoot)}
            if($case.uninstaller){$arguments+=@('-UninstallerSHA256',$case.uninstaller)}
            if($case.sbom){$arguments+=@('-PayloadSBOMSHA256',$case.sbom)}
            if($case.buildInfo){$arguments+=@('-BuildInfoSHA256',$case.buildInfo)}
            if($case.publisher){$arguments+=@('-PayloadPublisherSHA256',$case.publisher)}
            if($case.inventory){$arguments+='-UpgradeInventory'}
            if($case.mode -clike 'managed-pending-*' -and -not $case.withoutApproval){
                $pin=if($case.approval){$case.approval}else{'a'*64}
                $arguments+=@('-PendingApprovalSHA256',$pin)
            }
            $output=@(& $stock @arguments 2>&1)
            if($LASTEXITCODE -ne $case.code -or $output.Count -ne $case.count){
                $label=if($case.label){$case.label}else{$case.mode}
                throw ('Unexpected managed detection fixture result: '+$label)
            }
            if($case.count -eq 1){
                if($case.matchingPendingStatus){
                    if($output[0] -cne 'AccessWeaver managed upgrade pending'){throw 'Unexpected matching recovery status'}
                }elseif($case.pendingStatus){
                    if($output[0] -cne 'AccessWeaver installation pending'){throw 'Unexpected opt-in recovery status'}
                }elseif($case.inventory){
                    $record=$output[0] | ConvertFrom-Json
                    $schema=if($case.buildInfo){2}else{1}
                    if(@($record.PSObject.Properties).Count -ne (5+$schema) -or $record.schemaVersion -ne $schema -or
                       ($schema -eq 2 -and $record.buildInfoSHA256 -cne $buildInfoHash.ToLowerInvariant()) -or
                       $record.target -cne ('windows/'+$arch) -or $record.version -cne '0.1.0-alpha' -or
                       $record.payloadSHA256 -cne $hash.ToLowerInvariant() -or
                       $record.payloadSBOMSHA256 -cne $sbomHash.ToLowerInvariant() -or
                       $record.payloadPublisherSHA256 -cne $publisherHash.ToLowerInvariant()){
                        throw 'Unexpected upgrade inventory fields or values'
                    }
                } elseif($output[0] -cne 'AccessWeaver detected'){throw 'Unexpected managed detection output'}
            }
        }
        $env:AW_DETECTION_FIXTURE='approved'
        $env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY=$null
        $arguments=@('-NoProfile','-NonInteractive','-File',$fixture,'-Version','0.1.0-alpha','-Architecture',$arch,'-PayloadSHA256',$hash,'-InstallDirectory',$testRoot)
        function Assert-DetectionRefusal([string]$Reason='a retained lifecycle object') {
            $output=@(& $stock @arguments 2>&1)
            if($LASTEXITCODE -ne 1 -or $output.Count){throw ('Managed detection did not silently refuse '+$Reason)}
        }

        $active=[Threading.Mutex]::new($true,$fixtureLock)
        try {Assert-DetectionRefusal}
        finally {try {$active.ReleaseMutex()} finally {$active.Dispose()}}

        $idle=[Threading.Mutex]::new($false,$fixtureLock)
        try {Assert-DetectionRefusal}
        finally {$idle.Dispose()}

        $collision=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$fixtureLock)
        try {Assert-DetectionRefusal}
        finally {$collision.Dispose()}

        # A legacy Setup can hold only its Inno mutex, including an unowned
        # mutex. Also reject another object type occupying its fixed name.
        $legacySetup=[Threading.Mutex]::new($false,$fixtureSetup)
        try {
            Assert-DetectionRefusal
            $env:AW_DETECTION_FIXTURE='pending'
            $env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY='1'
            Assert-DetectionRefusal 'the legacy Setup mutex even with pending reporting enabled'
        } finally {
            $legacySetup.Dispose()
            $env:AW_DETECTION_FIXTURE='approved'
            $env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY=$null
        }
        $legacyCollision=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$fixtureSetup)
        try {Assert-DetectionRefusal}
        finally {$legacyCollision.Dispose()}

        Add-Type -Path (Join-Path $PSScriptRoot 'fixtures\InstallerLifecycleLock.cs')
        try {
            [AccessWeaverLifecycleLockFixture]::Abandon($fixtureLock)
            Assert-DetectionRefusal
            $retained=[Threading.Mutex]::OpenExisting($fixtureLock)
            try {
                try {
                    if($retained.WaitOne(0)){$retained.ReleaseMutex()}
                    throw 'Detection consumed the abandoned lifecycle signal'
                } catch [Threading.AbandonedMutexException] {$retained.ReleaseMutex()}
            } finally {$retained.Dispose()}
        } finally {[AccessWeaverLifecycleLockFixture]::Close()}

        $output=@(& $stock @arguments 2>&1)
        if($LASTEXITCODE -ne 0 -or $output.Count -ne 1 -or $output[0] -cne 'AccessWeaver detected'){
            throw 'Managed detection did not resume after lifecycle objects were released'
        }

        $savedDirectory=Join-Path $testRoot 'saved-package-directory'
        $junctionTarget=Join-Path $testRoot 'inert-package-directory-target'
        [void][IO.Directory]::CreateDirectory($junctionTarget)
        try {
            foreach($directory in $packageDirectories){
                $path=Join-Path $testRoot $directory
                [IO.Directory]::Move($path,$savedDirectory)
                try {
                    Assert-DetectionRefusal ('a missing '+$directory+' directory')
                    [IO.File]::WriteAllText($path,'inert non-directory fixture')
                    try {Assert-DetectionRefusal ('a regular file replacing '+$directory)}
                    finally {[IO.File]::Delete($path)}
                    [void](New-Item -ItemType Junction -Path $path -Target $junctionTarget -ErrorAction Stop)
                    try {Assert-DetectionRefusal ('a junction replacing '+$directory)}
                    finally {[IO.Directory]::Delete($path,$false)}
                } finally {[IO.Directory]::Move($savedDirectory,$path)}
            }
        } finally {[IO.Directory]::Delete($junctionTarget,$false)}

        # Exercise the detector's own native opens against ordinary paths and
        # junctions. The destination is fixture-owned and stays within the temp root.
        $nativeAccess=@($ast.EndBlock.Statements | Where-Object {
            $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $_.Name -ceq 'Initialize-AccessWeaverInstalledFileAccess'
        })
        if($nativeAccess.Count -ne 1){throw 'Expected one managed detector file access boundary'}
        . ([ScriptBlock]::Create($nativeAccess[0].Extent.Text))
        Initialize-AccessWeaverInstalledFileAccess
        [IO.File]::WriteAllText($uninstallData,'inert uninstall data fixture')
        $arguments+=@('-UninstallerSHA256',$uninstallerHash,'-PayloadSBOMSHA256',$sbomHash,'-BuildInfoSHA256',$buildInfoHash)
        $aliasPath=Join-Path $testRoot 'installed-subject-hardlink'
        foreach($file in @($uninstaller,$uninstallData,$sbom,$buildInfo)){
            try {
                [void](New-Item -ItemType HardLink -Path $aliasPath -Target $file -ErrorAction Stop)
                Assert-DetectionRefusal 'a hard-linked installed subject'
            } finally {
                if(Test-Path -LiteralPath $aliasPath){Remove-Item -LiteralPath $aliasPath}
            }
        }
        $output=@(& $stock @arguments 2>&1)
        if($LASTEXITCODE -ne 0 -or $output.Count -ne 1 -or $output[0] -cne 'AccessWeaver detected'){
            throw 'Managed detection did not resume after installed subject hardlinks were removed'
        }
        $leaf=Join-Path $testRoot 'native-leaf'
        $moved=Join-Path $testRoot 'native-moved'
        $junction=Join-Path $testRoot 'native-junction'
        [void][IO.Directory]::CreateDirectory($leaf)
        try {
            $guard=[AccessWeaver.InstallerFileAccess]::OpenDirectory($leaf)
            try {
                $renameRefused=$false
                try {[IO.Directory]::Move($leaf,$moved)}catch [IO.IOException] {$renameRefused=$true}
                if(-not $renameRefused){throw 'The detector directory handle allowed a rename'}
            } finally {$guard.Dispose()}
            [IO.Directory]::Move($leaf,$moved)
            [IO.Directory]::Move($moved,$leaf)
            [void](New-Item -ItemType Junction -Path $junction -Target $leaf)
            foreach($case in @(@{path=$junction;directory=$true},@{path=$junction;directory=$false},@{path=$leaf;directory=$false})){
                $unexpected=$null
                $refused=$false
                try {
                    if($case.directory){$unexpected=[AccessWeaver.InstallerFileAccess]::OpenDirectory($case.path)}
                    else{$unexpected=[AccessWeaver.InstallerFileAccess]::OpenFile($case.path,128MB)}
                } catch [IO.IOException] {$refused=$true}
                finally {if($null -ne $unexpected){$unexpected.Dispose()}}
                if(-not $refused){throw 'The detector accepted an invalid native path type'}
            }
        } finally {
            foreach($path in @($junction,$leaf,$moved)){
                if([IO.Directory]::Exists($path)){[IO.Directory]::Delete($path)}
            }
        }
    } finally {
        $env:AW_DETECTION_FIXTURE=$saved
        $env:ACCESSWEAVER_REPORT_INSTALLER_RECOVERY=$savedRecovery
    }
} finally {
    foreach($file in @($payload,$fixture,$uninstaller,$uninstallData,$sbom,$buildInfo,$notice)){
        if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}
    }
    for($i=$packageDirectories.Count-1;$i -ge 0;$i--){
        $path=Join-Path $testRoot $packageDirectories[$i]
        if([IO.Directory]::Exists($path)){[IO.Directory]::Delete($path,$false)}
    }
    $fixtureDirectory.Delete()
}
Write-Output ('Managed detection contracts passed: '+($cases.Count+27))
