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
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-detection-'+[guid]::NewGuid().ToString('N'))
$fixtureDirectory=[IO.Directory]::CreateDirectory($testRoot)
$payload=Join-Path $testRoot 'accessweaver.exe'
$fixture=Join-Path $testRoot 'fixture.ps1'
$uninstaller=Join-Path $testRoot 'unins001.exe'
$sbom=Join-Path $testRoot 'SBOM.cdx.json'
$buildInfo=Join-Path $testRoot 'BUILD-INFO.json'
$buildInfoBytes=[Text.Encoding]::UTF8.GetBytes('{"version":"0.1.0-alpha"}')
try {
    [IO.File]::WriteAllText($payload,'inert detection test data')
    $hash=(Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($uninstaller,'inert uninstaller fixture')
    $uninstallerHash=(Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash
    $sbomBytes=[Text.Encoding]::UTF8.GetBytes('{"fixture":true}')
    [IO.File]::WriteAllBytes($sbom,$sbomBytes)
    $sbomHash=(Get-FileHash -LiteralPath $sbom -Algorithm SHA256).Hash
    [IO.File]::WriteAllBytes($buildInfo,$buildInfoBytes)
    $buildInfoHash=(Get-FileHash -LiteralPath $buildInfo -Algorithm SHA256).Hash
    $sha256=[Security.Cryptography.SHA256]::Create()
    try {$publisherHash=[BitConverter]::ToString($sha256.ComputeHash([byte[]]@(1,2,3))).Replace('-','')}
    finally {$sha256.Dispose()}
    $mock=@'
$script:mockReads=0
function Read-AccessWeaverRegistration([Microsoft.Win32.RegistryView]$View) {
    if($View -eq [Microsoft.Win32.RegistryView]::Registry32 -and $env:AW_DETECTION_FIXTURE -cne 'alternate'){return $null}
    if($env:AW_DETECTION_FIXTURE -ceq 'absent'){return $null}
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
    $nativeCall='[AccessWeaver.InstallerRecoveryRegistry]::QueryStatus()'
    $fixtureStatus=@'
$(switch -CaseSensitive ($env:AW_DETECTION_FIXTURE){
    'pending' {0}
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
    try {
        $cases=@(
            @{mode='pending';code=1;count=0;hash=$hash},
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
            if($case.removeSBOM){[IO.File]::Delete($sbom)}else{[IO.File]::WriteAllBytes($sbom,$sbomBytes)}
            if($case.removeBuildInfo){[IO.File]::Delete($buildInfo)}
            elseif($case.changedBuildInfo){[IO.File]::WriteAllText($buildInfo,'{"version":"0.1.1-alpha"}')}
            elseif($case.oversizedBuildInfo){[IO.File]::WriteAllBytes($buildInfo,[byte[]]::new(64KB+1))}
            else{[IO.File]::WriteAllBytes($buildInfo,$buildInfoBytes)}
            $env:AW_DETECTION_FIXTURE=$case.mode
            $arguments=@('-NoProfile','-NonInteractive','-File',$fixture,'-Version','0.1.0-alpha','-Architecture',$arch,'-PayloadSHA256',$case.hash,'-InstallDirectory',$testRoot)
            if($case.uninstaller){$arguments+=@('-UninstallerSHA256',$case.uninstaller)}
            if($case.sbom){$arguments+=@('-PayloadSBOMSHA256',$case.sbom)}
            if($case.buildInfo){$arguments+=@('-BuildInfoSHA256',$case.buildInfo)}
            if($case.publisher){$arguments+=@('-PayloadPublisherSHA256',$case.publisher)}
            if($case.inventory){$arguments+='-UpgradeInventory'}
            $output=@(& $stock @arguments 2>&1)
            if($LASTEXITCODE -ne $case.code -or $output.Count -ne $case.count){throw ('Unexpected managed detection fixture result: '+$case.mode)}
            if($case.count -eq 1){
                if($case.inventory){
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
        $arguments=@('-NoProfile','-NonInteractive','-File',$fixture,'-Version','0.1.0-alpha','-Architecture',$arch,'-PayloadSHA256',$hash,'-InstallDirectory',$testRoot)
        function Assert-DetectionRefusal {
            $output=@(& $stock @arguments 2>&1)
            if($LASTEXITCODE -ne 1 -or $output.Count){throw 'Managed detection did not silently refuse a retained lifecycle object'}
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
        try {Assert-DetectionRefusal}
        finally {$legacySetup.Dispose()}
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
    } finally {$env:AW_DETECTION_FIXTURE=$saved}
} finally {
    foreach($file in @($payload,$fixture,$uninstaller,$sbom,$buildInfo)){
        if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}
    }
    $fixtureDirectory.Delete()
}
Write-Output ('Managed detection contracts passed: '+($cases.Count+7))
