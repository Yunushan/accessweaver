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
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-detection-'+[guid]::NewGuid().ToString('N'))
$fixtureDirectory=[IO.Directory]::CreateDirectory($testRoot)
$payload=Join-Path $testRoot 'accessweaver.exe'
$fixture=Join-Path $testRoot 'fixture.ps1'
$uninstaller=Join-Path $testRoot 'unins001.exe'
$sbom=Join-Path $testRoot 'SBOM.cdx.json'
try {
    [IO.File]::WriteAllText($payload,'inert detection test data')
    $hash=(Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($uninstaller,'inert uninstaller fixture')
    $uninstallerHash=(Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash
    $sbomBytes=[Text.Encoding]::UTF8.GetBytes('{"fixture":true}')
    [IO.File]::WriteAllBytes($sbom,$sbomBytes)
    $sbomHash=(Get-FileHash -LiteralPath $sbom -Algorithm SHA256).Hash
    $mock=@'
$script:mockReads=0
function Read-AccessWeaverRegistration([Microsoft.Win32.RegistryView]$View) {
    if($View -eq [Microsoft.Win32.RegistryView]::Registry32 -and $env:AW_DETECTION_FIXTURE -cne 'alternate'){return $null}
    if($env:AW_DETECTION_FIXTURE -ceq 'absent'){return $null}
    $script:mockReads++
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
    $fixtureLock='Global\AccessWeaver-DetectionTest-'+[guid]::NewGuid().ToString('N')
    $mocked=$original.Substring(0,$node.StartOffset)+$mock+$original.Substring($node.EndOffset)
    [IO.File]::WriteAllText($fixture,$mocked.Replace($productionLock,$fixtureLock))
    $arch=@{X64='amd64';Arm64='arm64'}[[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()]
    $stock=Join-Path $PSHOME 'powershell.exe'
    if(-not (Test-Path -LiteralPath $stock)){$stock=Join-Path $PSHOME 'pwsh.exe'}
    $saved=$env:AW_DETECTION_FIXTURE
    try {
        $cases=@(
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
            @{mode='registration-changed';code=1;count=0;hash=$hash;sbom=$sbomHash}
        )
        foreach($case in $cases){
            if($case.removeSBOM){[IO.File]::Delete($sbom)}else{[IO.File]::WriteAllBytes($sbom,$sbomBytes)}
            $env:AW_DETECTION_FIXTURE=$case.mode
            $arguments=@('-NoProfile','-NonInteractive','-File',$fixture,'-Version','0.1.0-alpha','-Architecture',$arch,'-PayloadSHA256',$case.hash,'-InstallDirectory',$testRoot)
            if($case.uninstaller){$arguments+=@('-UninstallerSHA256',$case.uninstaller)}
            if($case.sbom){$arguments+=@('-PayloadSBOMSHA256',$case.sbom)}
            $output=@(& $stock @arguments 2>&1)
            if($LASTEXITCODE -ne $case.code -or $output.Count -ne $case.count -or
               ($case.count -eq 1 -and $output[0] -cne 'AccessWeaver detected')){throw 'Unexpected managed detection fixture result'}
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
    foreach($file in @($payload,$fixture,$uninstaller,$sbom)){
        if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}
    }
    $fixtureDirectory.Delete()
}
Write-Output ('Managed detection contracts passed: '+($cases.Count+5))
