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
try {
    [IO.File]::WriteAllText($payload,'inert detection test data')
    $hash=(Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($uninstaller,'inert uninstaller fixture')
    $uninstallerHash=(Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash
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
    [IO.File]::WriteAllText($fixture,$original.Substring(0,$node.StartOffset)+$mock+$original.Substring($node.EndOffset))
    $arch=@{X64='amd64';Arm64='arm64'}[[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()]
    $stock=Join-Path $PSHOME 'powershell.exe'
    if(-not (Test-Path -LiteralPath $stock)){$stock=Join-Path $PSHOME 'pwsh.exe'}
    $saved=$env:AW_DETECTION_FIXTURE
    try {
        foreach($case in @(
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
            @{mode='other-version';code=0;count=0;hash=$hash;uninstaller=$uninstallerHash}
        )){
            $env:AW_DETECTION_FIXTURE=$case.mode
            $arguments=@('-NoProfile','-NonInteractive','-File',$fixture,'-Version','0.1.0-alpha','-Architecture',$arch,'-PayloadSHA256',$case.hash,'-InstallDirectory',$testRoot)
            if($case.uninstaller){$arguments+=@('-UninstallerSHA256',$case.uninstaller)}
            $output=@(& $stock @arguments 2>&1)
            if($LASTEXITCODE -ne $case.code -or $output.Count -ne $case.count -or
               ($case.count -eq 1 -and $output[0] -cne 'AccessWeaver detected')){throw 'Unexpected managed detection fixture result'}
        }
    } finally {$env:AW_DETECTION_FIXTURE=$saved}
} finally {
    foreach($file in @($payload,$fixture,$uninstaller)){
        if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}
    }
    $fixtureDirectory.Delete()
}
Write-Output 'Eighteen managed detection contracts passed.'
