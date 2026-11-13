# Local filesystem and pure-function contract tests. No services, drivers,
# application installs or network settings are changed by this test script.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
foreach($file in @('test-windows-vendor-preflight.ps1','test-windows-integration.ps1','dns-acceptance-state.ps1','test-dns-acceptance-state.ps1','build-windows-installer.ps1','test-windows-installer.ps1','test-windows-installer-contracts.ps1','windows-installer-common.ps1','build-windows-fixtures.ps1','test-windows-apps.ps1','test-windows-wiresock.ps1','test-windows-reboot.ps1','test-windows-storage.ps1','test-windows-uiaccess.ps1','vmware-test-bootstrap.ps1','vmware-reboot-resume.ps1')){$tokens=$null;$issues=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$tokens,[ref]$issues);if($issues.Count){throw ($issues|Out-String)}}
$tokens=$null;$parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $projectRoot 'internal\workflow\windows.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors|Out-String)}
foreach($node in $ast.EndBlock.Statements){if($node -is [System.Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($node.Extent.Text))}}
$testRoot=Join-Path $projectRoot ('build\workflow-tests-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Force -Path $testRoot)
$root=$testRoot;$script:undo=[Collections.Generic.List[object]]::new();$script:events=[Collections.Generic.List[string]]::new();$script:journalPath=$null
[void](New-Item -ItemType Directory -Force -Path (Join-Path $testRoot 'backups'))
function Assert([bool]$condition,[string]$message){if(-not $condition){throw $message};Write-Output ('PASS '+$message)}
# The OS identity comes from IsWow64Process2 in Go, outside the reviewed request.
# These fixtures only read inert MSI databases; signature/network/launch are mocked.
$previousPrerequisiteInput=$inputData;$previousPrerequisiteRequest=$r
$prerequisiteFunctions=@{}
foreach($name in @('Read-RemoteJSON','Download','Get-AuthenticodeSignature','Native','Event')){$prerequisiteFunctions[$name]=(Get-Command $name).ScriptBlock}
$prerequisiteRoot=Join-Path $testRoot 'prerequisites';[void](New-Item -ItemType Directory -Path $prerequisiteRoot)
$script:prerequisiteFixtures=@{}
foreach($platform in @('x64','Arm64','Intel')) {
    $path=Join-Path $prerequisiteRoot ('fixture-'+$platform+'.msi')
    $msi=$null;$database=$null;$summary=$null
    try {
        $msi=New-Object -ComObject WindowsInstaller.Installer
        $database=$msi.OpenDatabase($path,3)
        $summary=$database.SummaryInformation(1)
        [void]$summary.GetType().InvokeMember('Property',[Reflection.BindingFlags]::SetProperty,$null,$summary,@(7,($platform+';1033')))
        $summary.Persist();$database.Commit()
    } finally {foreach($object in @($summary,$database,$msi)){if($null -ne $object){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)}}}
    $script:prerequisiteFixtures[$platform]=$path
    Assert ((Get-MSIPlatform $path) -ceq $platform) ('Read-only MSI metadata preserves '+$platform+' without running an installer')
}
try {
    $script:prerequisiteCalls=[Collections.Generic.List[object]]::new()
    $script:prerequisiteSignature='Valid'
    $script:prerequisiteSignerSubject='CN=Other fixture publisher'
    function Get-AuthenticodeSignature {
        param($LiteralPath)
        $script:prerequisiteCalls.Add(@{kind='signature';path=$LiteralPath})
        return @{Status=$script:prerequisiteSignature;SignerCertificate=@{Subject=$script:prerequisiteSignerSubject}}
    }
    function Read-RemoteJSON {param($Headers,$Uri);$script:prerequisiteCalls.Add(@{kind='release';url=$Uri});return @{assets=$script:prerequisiteAssets}}
    function Download {param($url,$hash,$destination,[switch]$Signed,[string]$Publisher);$script:prerequisiteCalls.Add(@{kind='download';url=$url;hash=$hash});Copy-Item -LiteralPath $script:prerequisiteDownloadFixture -Destination $destination -Force}
    function Native {param($Program,$Arguments,$SuccessCodes);$script:prerequisiteCalls.Add(@{kind='launch';program=$Program;arguments=$Arguments;codes=$SuccessCodes});return @{exitCode=0}}
    function Event {param($text)}
    [void](New-Item -ItemType Directory -Force -Path (Join-Path $root 'downloads'))
    foreach($architecture in @('amd64','arm64')) {
        $inputData=[pscustomobject]@{nativeArchitecture=$architecture}
        $platform=if($architecture -eq 'amd64'){'x64'}else{'Arm64'}
        $plan=Prerequisite-Plan 'ndisapi'
        Assert ($plan.platform -ceq $platform) ($architecture+' prerequisite selection uses the native kernel architecture')
        foreach($other in @('x64','Arm64','x86')) {
            $matched=('Windows.Packet.Filter.3.6.2.1.'+$other+'.msi') -match $plan.assetPattern
            Assert ($matched -eq ($other -ieq $platform)) ($architecture+' prerequisite selection separates '+$other+' package names')
        }
        foreach($invalid in @(('Windows.Packet.Filter.evil.'+$platform+'.msi'),('prefix.Windows.Packet.Filter.3.6.2.1.'+$platform+'.msi'),('Windows.Packet.Filter.3.6.2.1.'+$platform+'.msi.exe'))) {
            Assert ($invalid -notmatch $plan.assetPattern) ($architecture+' prerequisite selection rejects malformed asset names')
        }
        $bundle=Join-Path $prerequisiteRoot ('bundle-'+$architecture);[void](New-Item -ItemType Directory -Path $bundle)
        foreach($other in @('x64','Arm64')) {Copy-Item -LiteralPath $script:prerequisiteFixtures[$other] -Destination (Join-Path $bundle ('Windows.Packet.Filter.3.6.2.1.'+$other+'.msi'))}
        $r=[pscustomobject]@{bundlePath=$bundle};$script:prerequisiteCalls.Clear()
        Install-Prerequisite 'ndisapi'
        $launch=@($script:prerequisiteCalls | Where-Object {$_.kind -eq 'launch'})
        Assert ($launch.Count -eq 1 -and $launch[0].arguments[1].EndsWith('.'+$platform+'.msi',[StringComparison]::OrdinalIgnoreCase) -and $launch[0].program -ceq (Join-Path $env:SystemRoot 'System32\msiexec.exe') -and ($launch[0].codes -join ',') -eq '0,3010,1641') ($architecture+' bundle selects only its platform, uses system MSI and preserves reboot exit codes')
        Assert (@($script:prerequisiteCalls | Where-Object {$_.kind -in @('release','download')}).Count -eq 0) ($architecture+' compatible bundle avoids remote retrieval')
        # A correct filename cannot override an incompatible MSI template.
        $selected=Join-Path $bundle ('Windows.Packet.Filter.3.6.2.1.'+$platform+'.msi')
        Copy-Item -LiteralPath $script:prerequisiteFixtures['Intel'] -Destination $selected -Force
        $script:prerequisiteCalls.Clear();$rejected=$false
        try {Install-Prerequisite 'ndisapi'}catch{$rejected=$_.Exception.Message -like '*MSI platform does not match*'}
        Assert ($rejected -and @($script:prerequisiteCalls | Where-Object {$_.kind -eq 'launch'}).Count -eq 0) ($architecture+' mismatched MSI metadata prevents execution despite a matching filename')
        Copy-Item -LiteralPath $script:prerequisiteFixtures[$platform] -Destination $selected -Force
        $duplicate=Join-Path $bundle ('Windows.Packet.Filter.3.6.1.1.'+$platform+'.msi');Copy-Item -LiteralPath $selected -Destination $duplicate
        $script:prerequisiteCalls.Clear();$rejected=$false
        try {Install-Prerequisite 'ndisapi'}catch{$rejected=$_.Exception.Message -like 'Multiple compatible*'}
        Assert ($rejected -and $script:prerequisiteCalls.Count -eq 0) ($architecture+' ambiguous local packages fail before signature checks or launch')
        Remove-Item -LiteralPath $duplicate
        $r=[pscustomobject]@{bundlePath=$null}
        $script:prerequisiteAssets=@(foreach($other in @('x64','Arm64','x86')){@{name=('Windows.Packet.Filter.3.6.2.1.'+$other+'.msi');browser_download_url=('https://github.com/wiresock/ndisapi/releases/download/v3.6.2/filter-'+$other+'.msi');digest=('sha256:'+('a'*64))}})
        $script:prerequisiteDownloadFixture=$script:prerequisiteFixtures[$platform];$script:prerequisiteCalls.Clear()
        Install-Prerequisite 'ndisapi'
        $downloads=@($script:prerequisiteCalls | Where-Object {$_.kind -eq 'download'})
        Assert ($downloads.Count -eq 1 -and $downloads[0].url.EndsWith('filter-'+$platform+'.msi',[StringComparison]::OrdinalIgnoreCase) -and $downloads[0].hash -eq ('a'*64)) ($architecture+' remote package selection preserves the exact vendor digest')
        Assert (@($script:prerequisiteCalls | Where-Object {$_.kind -eq 'launch'}).Count -eq 1) ($architecture+' matching remote MSI reaches only the mocked launcher')
        $matchingAsset=@($script:prerequisiteAssets | Where-Object {$_.name -match $plan.assetPattern})[0]
        foreach($assets in @(@($matchingAsset,$matchingAsset),@())) {
            $script:prerequisiteAssets=$assets;$script:prerequisiteCalls.Clear();$rejected=$false
            try {Install-Prerequisite 'ndisapi'}catch{$rejected=$_.Exception.Message -like 'Exactly one*'}
            Assert ($rejected -and @($script:prerequisiteCalls | Where-Object {$_.kind -in @('download','launch')}).Count -eq 0) ($architecture+' ambiguous or missing remote assets prevent download and launch')
        }
        $r=[pscustomobject]@{bundlePath=$bundle};$script:prerequisiteSignature='NotTrusted';$script:prerequisiteCalls.Clear();$rejected=$false
        try {Install-Prerequisite 'ndisapi'}catch{$rejected=$_.Exception.Message -eq 'Prerequisite signature is invalid'}
        Assert ($rejected -and @($script:prerequisiteCalls | Where-Object {$_.kind -eq 'launch'}).Count -eq 0) ($architecture+' invalid publisher signature prevents launch')
        $script:prerequisiteSignature='Valid'
    }
    foreach($architecture in @('','x86','unknown')) {
        $inputData=[pscustomobject]@{nativeArchitecture=$architecture};$script:prerequisiteCalls.Clear();$rejected=$false
        try {Install-Prerequisite 'ndisapi'}catch{$rejected=$_.Exception.Message -like 'Native Windows architecture is unavailable*'}
        Assert ($rejected -and $script:prerequisiteCalls.Count -eq 0) 'Unknown native architecture prevents prerequisite lookup, download and launch'
    }
    $inputData=[pscustomobject]@{}
    Assert ((Prerequisite-Plan 'vcredist').pattern -eq 'VC_redist.x64.exe') 'Visual C runtime selection remains separate from kernel driver architecture'
    $runtimeBundle=Join-Path $prerequisiteRoot 'runtime'
    [void](New-Item -ItemType Directory -Path $runtimeBundle)
    $runtimeFixture=Join-Path $runtimeBundle 'VC_redist.x64.exe'
    [IO.File]::WriteAllBytes($runtimeFixture,[byte[]]@(0))
    $r=[pscustomobject]@{bundlePath=$runtimeBundle}
    $script:prerequisiteCalls.Clear()
    $rejected=$false
    try {Install-Prerequisite 'vcredist'}catch{$rejected=$_.Exception.Message -ceq 'Visual C++ runtime publisher signature could not be verified'}
    Assert ($rejected -and @($script:prerequisiteCalls | Where-Object {$_.kind -eq 'launch'}).Count -eq 0) 'Bundled Visual C runtime rejects a valid signature from another publisher category'
    $failedRuntimeSignatures=@($script:prerequisiteCalls | Where-Object {$_.kind -eq 'signature'})
    Assert ($failedRuntimeSignatures.Count -eq 1 -and (Under $failedRuntimeSignatures[0].path (Join-Path $root 'downloads')) -and -not (Test-Path -LiteralPath $failedRuntimeSignatures[0].path)) 'Bundled prerequisite retires its protected copy after signature refusal'
    $script:prerequisiteSignerSubject='CN=Microsoft fixture'
    $script:prerequisiteCalls.Clear()
    Install-Prerequisite 'vcredist'
    $runtimeLaunches=@($script:prerequisiteCalls | Where-Object {$_.kind -eq 'launch'})
    $runtimeSignatures=@($script:prerequisiteCalls | Where-Object {$_.kind -eq 'signature'})
    Assert ($runtimeLaunches.Count -eq 1 -and $runtimeSignatures.Count -eq 1 -and $runtimeLaunches[0].program -ceq $runtimeSignatures[0].path) 'Bundled Visual C runtime accepts the expected publisher category before mocked launch'
    $runtimeStage=$runtimeLaunches[0].program
    Assert ((Under $runtimeStage (Join-Path $root 'downloads')) -and -not (Test-Path -LiteralPath $runtimeStage) -and (Test-Path -LiteralPath $runtimeFixture)) 'Bundled prerequisite launches only its verified protected copy and retires it'

    $previousPrerequisiteProgramFiles=$env:ProgramFiles
    try {
        $env:ProgramFiles=Join-Path $prerequisiteRoot 'program-files'
        $implicitRoot=Join-Path $env:ProgramFiles 'SplitWire-Turkey\Prerequisites'
        [void](New-Item -ItemType Directory -Path $implicitRoot -Force)
        Copy-Item -LiteralPath $runtimeFixture -Destination $implicitRoot
        $r=[pscustomobject]@{bundlePath=$null}
        $inputData=[pscustomobject]@{managedPolicy=$true;allowDownloads=$false}
        $script:prerequisiteCalls.Clear()
        $previousDownload=(Get-Command Download).ScriptBlock
        try {
            function Download { Require-DownloadPermission;throw 'Fixture reached an unauthorized download' }
            $rejected=$false
            try {Install-Prerequisite 'vcredist'}catch{$rejected=$_.Exception.Message -ceq 'Administrator policy disables remote component and release requests'}
            Assert ($rejected -and $script:prerequisiteCalls.Count -eq 0) 'Managed prerequisite ignores implicit unapproved local bundles'
        } finally {Set-Item Function:Download $previousDownload}
        $inputData=[pscustomobject]@{managedPolicy=$false}
        Install-Prerequisite 'vcredist'
        Assert (@($script:prerequisiteCalls | Where-Object {$_.kind -eq 'launch'}).Count -eq 1) 'Unmanaged prerequisite can still use the implicit local bundle'
    } finally {$env:ProgramFiles=$previousPrerequisiteProgramFiles}
    $rejected=$false;try{Prerequisite-Plan 'unknown'|Out-Null}catch{$rejected=$_.Exception.Message -eq 'Unknown prerequisite component'}
    Assert $rejected 'Unknown prerequisite names cannot fall back to Visual C runtime installation'
} finally {
    foreach($name in $prerequisiteFunctions.Keys){if($null -eq $prerequisiteFunctions[$name]){Remove-Item ('Function:'+$name)}else{Set-Item ('Function:'+$name) $prerequisiteFunctions[$name]}}
    $inputData=$previousPrerequisiteInput;$r=$previousPrerequisiteRequest
}

# Model prerequisite outcomes with no registry access or service changes.
$previousRebootRequired=$script:rebootRequired
$previousStandalonePrerequisiteRequest=$r
try {
    & {
        function Get-ItemProperty { return @{Installed=[int]$script:fixtureRuntimeRegistered} }
        function Get-DriverServiceControllers {
            [CmdletBinding()]param()
            [pscustomobject]@{ServiceName='UnrelatedFixtureDriver';Status='Running'}
            if($script:fixtureFilterRegistered){[pscustomobject]@{ServiceName='NDISRD';Status='Stopped'}}
        }
        function Install-Prerequisite([string]$component) {
            $script:prerequisiteRebootCalls.Add($component)
            if($component -eq $script:prerequisiteNeedsReboot){$script:rebootRequired=$true;return}
            if($component -eq $script:fixtureMissingRegistration){return}
            if($component -eq 'vcredist'){$script:fixtureRuntimeRegistered=$true}
            if($component -eq 'ndisapi'){$script:fixtureFilterRegistered=$true}
        }
        function Ensure-Asset { throw 'Fixture reached ProxiFyre asset resolution' }
        foreach($case in @(
            @{prerequisite='vcredist';calls='vcredist';message='Restart Windows after Visual C++ runtime installation, then retry ProxiFyre setup';label='Visual C runtime reboot defers packet filter and ProxiFyre setup'}
            @{prerequisite='ndisapi';calls='vcredist,ndisapi';message='Restart Windows after Windows Packet Filter installation, then retry ProxiFyre setup';label='Packet filter reboot defers ProxiFyre setup'}
        )){
            $script:rebootRequired=$false
            $script:prerequisiteNeedsReboot=$case.prerequisite
            $script:fixtureMissingRegistration=''
            $script:fixtureRuntimeRegistered=$false
            $script:fixtureFilterRegistered=$false
            $script:prerequisiteRebootCalls=[Collections.Generic.List[string]]::new()
            $refused=$false
            try {Setup-ProxiFyre '127.0.0.1:1080'}catch{$refused=$_.Exception.Message -ceq $case.message}
            Assert ($refused -and $script:rebootRequired -and ($script:prerequisiteRebootCalls -join ',') -ceq $case.calls) $case.label
        }
        foreach($case in @(
            @{missing='vcredist';calls='vcredist';message='Visual C++ runtime installation did not register the required runtime';label='ProxiFyre refuses a successful runtime install without registration'}
            @{missing='ndisapi';calls='vcredist,ndisapi';message='Windows Packet Filter installation did not register the required driver';label='ProxiFyre refuses a successful packet filter install without registration'}
            @{missing='';calls='vcredist,ndisapi';message='Fixture reached ProxiFyre asset resolution';label='ProxiFyre continues when both prerequisite registrations are visible'}
        )){
            $script:rebootRequired=$false
            $script:prerequisiteNeedsReboot=''
            $script:fixtureMissingRegistration=$case.missing
            $script:fixtureRuntimeRegistered=$false
            $script:fixtureFilterRegistered=$false
            $script:prerequisiteRebootCalls=[Collections.Generic.List[string]]::new()
            $expected=$false
            try {Setup-ProxiFyre '127.0.0.1:1080'}catch{$expected=$_.Exception.Message -ceq $case.message}
            Assert ($expected -and -not $script:rebootRequired -and ($script:prerequisiteRebootCalls -join ',') -ceq $case.calls) $case.label
        }
        $r=[pscustomobject]@{engine='ndisapi';dns='unchanged'}
        $script:rebootRequired=$false
        $script:prerequisiteNeedsReboot='ndisapi'
        $script:fixtureFilterRegistered=$false
        $pending=Install-Method
        Assert ($pending.rebootRequired -and $pending.prerequisite -ceq 'ndisapi' -and -not $pending.ContainsKey('installed')) 'Standalone prerequisite reports pending reboot without claiming installation'
        $script:rebootRequired=$false
        $script:prerequisiteNeedsReboot=''
        $script:fixtureMissingRegistration='ndisapi'
        $refused=$false
        try {Install-Method | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Windows Packet Filter installation did not register the required driver'}
        Assert $refused 'Standalone prerequisite refuses installer success without registration'
        $script:fixtureMissingRegistration=''
        $completed=Install-Method
        Assert ($completed.installed -ceq 'ndisapi' -and $script:fixtureFilterRegistered) 'Standalone prerequisite reports installation after registration'
    }
} finally {
    $script:rebootRequired=$previousRebootRequired
    $r=$previousStandalonePrerequisiteRequest
}

# Native component metadata fixtures are deliberately non-executable. No DLL
# is loaded; download, expansion, staging and event hooks stay within this fixture.
$previousComponentInput=$inputData;$previousComponentRequest=$r;$previousComponentRoot=$root;$previousAssetNames=$assetNames
$componentFunctions=@{}
foreach($name in @('Read-RemoteJSON','Download','Expand-Safe','Protect-Dir','Copy-Checked','Copy-Tree','Event')){$componentFunctions[$name]=(Get-Command $name).ScriptBlock}
function Write-InertPE([string]$path,[uint16]$machine) {
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path))
    $bytes=[byte[]]::new(256);$bytes[0]=0x4d;$bytes[1]=0x5a;[BitConverter]::GetBytes([uint32]128).CopyTo($bytes,60)
    $bytes[128]=0x50;$bytes[129]=0x45;[BitConverter]::GetBytes($machine).CopyTo($bytes,132)
    [IO.File]::WriteAllBytes($path,$bytes)
}
try {
    $assetNames=@{proxifyre='ProxiFyre.exe';wgcf='wgcf.exe';dnscrypt='dnscrypt-proxy.exe';zapret='winws.exe';zapret2='winws2.exe'}
    $script:componentCalls=[Collections.Generic.List[object]]::new();$script:componentTamperStaging=$false
    function Read-RemoteJSON {param($Headers,$Uri);$script:componentCalls.Add(@{kind='release';url=$Uri});return @{assets=$script:componentAssets}}
    function Protect-Dir {param($path);[void](New-Item -ItemType Directory -Force -Path $path)}
    function Copy-Checked {param($source,$destination);[void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination));Copy-Item -LiteralPath $source -Destination $destination -Force;if($script:componentTamperStaging){Write-InertPE $destination 0x014c}}
    function Copy-Tree {param($source,$destination);foreach($file in Get-ChildItem -LiteralPath $source -File){Copy-Checked $file.FullName (Join-Path $destination $file.Name)}}
    function Download {param($url,$hash,$destination);$script:componentCalls.Add(@{kind='download';url=$url;hash=$hash});if($destination.EndsWith('.exe')){Write-InertPE $destination $script:componentDownloadMachine}else{[IO.File]::WriteAllText($destination,'inert mocked archive')}}
    function Expand-Safe {param($archive,$destination);Write-InertPE (Join-Path $destination ('payload\'+$assetNames[$script:componentEngine])) $script:componentDownloadMachine}
    function Event {param($text);$script:componentCalls.Add(@{kind='event';text=$text})}
    $componentBase=Join-Path $testRoot 'native-components';[void](New-Item -ItemType Directory -Path $componentBase)
    foreach($machine in @(0x8664,0xaa64,0x014c)) {
        $path=Join-Path $componentBase ('machine-'+$machine+'.exe');Write-InertPE $path $machine
        Assert ((Get-PEMachine $path) -eq $machine) 'Bounded PE inspection reads the COFF machine without executing a fixture'
    }
    foreach($mode in @('short','dos-magic','offset-before-header','offset-overflow','pe-magic')) {
        $path=Join-Path $componentBase ($mode+'.exe');Write-InertPE $path 0xaa64;$bytes=[IO.File]::ReadAllBytes($path)
        switch($mode){'short' {$bytes=[byte[]]::new(63)} 'dos-magic' {$bytes[0]=0} 'offset-before-header' {[BitConverter]::GetBytes([uint32]1).CopyTo($bytes,60)} 'offset-overflow' {[BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($bytes,60)} 'pe-magic' {$bytes[128]=0}}
        [IO.File]::WriteAllBytes($path,$bytes)
        Assert ((Get-PEMachine $path) -eq 0) ($mode+' malformed PE metadata cannot establish a compatible machine')
    }
    foreach($engine in @('proxifyre','wgcf','dnscrypt')) {
        $script:componentEngine=$engine
        $names=@{proxifyre=@('ProxiFyre-v2.6.4-x64.zip','ProxiFyre-v2.6.4-ARM64.zip');wgcf=@('wgcf_2.3.1_windows_amd64.exe','wgcf_2.3.1_windows_arm64.exe');dnscrypt=@('dnscrypt-proxy-win64-2.1.20.zip','dnscrypt-proxy-winarm-2.1.20.zip')}
        $bundle=Join-Path $componentBase ('bundle-'+$engine)
        # Misleading folder labels must not override the actual machine field.
        $amdPath=Join-Path $bundle ('arm64\'+$assetNames[$engine]);Write-InertPE $amdPath 0x8664
        $armPath=Join-Path $bundle ('x64\'+$assetNames[$engine]);Write-InertPE $armPath 0xaa64
        foreach($architecture in @('amd64','arm64')) {
            $inputData=[pscustomobject]@{nativeArchitecture=$architecture};$plan=Component-ArchitecturePlan $engine
            $index=if($architecture -eq 'amd64'){0}else{1};$expectedPath=if($index -eq 0){$amdPath}else{$armPath}
            $root=Join-Path $componentBase ('local-'+$engine+'-'+$architecture);$r=[pscustomobject]@{bundlePath=$bundle}
            Assert ((Find-Source $engine) -eq $expectedPath) ($engine+' '+$architecture+' discovery selects PE metadata across misleading folder names')
            Assert ($names[$engine][$index] -match $plan.assetPattern -and $names[$engine][1-$index] -notmatch $plan.assetPattern) ($engine+' '+$architecture+' remote pattern separates native assets')
            foreach($invalid in @(('prefix-'+$names[$engine][$index]),($names[$engine][$index]+'.sha256'))) {Assert ($invalid -notmatch $plan.assetPattern) ($engine+' '+$architecture+' native pattern rejects unrelated and sidecar assets')}
            $script:componentCalls.Clear();$ready=Ensure-Asset $engine
            Assert ((Get-PEMachine $ready) -eq $plan.machine -and (Under $ready (Join-Path $root ('components\'+$engine)))) ($engine+' '+$architecture+' compatible bundle is staged with its native machine')
            Assert (@($script:componentCalls | Where-Object {$_.kind -in @('release','download')}).Count -eq 0) ($engine+' '+$architecture+' native bundle needs no remote fallback')
            $root=Join-Path $componentBase ('tampered-staging-'+$engine+'-'+$architecture)
            $script:componentTamperStaging=$true;$script:componentCalls.Clear();$rejected=$false
            try {Ensure-Asset $engine|Out-Null}catch{$rejected=$_.Exception.Message -eq 'Staged component does not match the native Windows architecture'}finally{$script:componentTamperStaging=$false}
            Assert ($rejected -and @($script:componentCalls | Where-Object {$_.kind -eq 'event'}).Count -eq 0) ($engine+' '+$architecture+' staged machine mismatch fails before a ready event')
            $root=Join-Path $componentBase ('remote-'+$engine+'-'+$architecture);$r=[pscustomobject]@{bundlePath=$null}
            $script:componentAssets=@(foreach($name in $names[$engine]){@{name=$name;browser_download_url=('https://github.com/vendor/component/releases/download/test/'+$name);digest=('sha256:'+('b'*64))}})
            $script:componentDownloadMachine=$plan.machine;$script:componentCalls.Clear();$ready=Ensure-Asset $engine
            $downloads=@($script:componentCalls | Where-Object {$_.kind -eq 'download'})
            Assert ($downloads.Count -eq 1 -and $downloads[0].url.EndsWith($names[$engine][$index]) -and $downloads[0].hash -eq ('b'*64) -and (Get-PEMachine $ready) -eq $plan.machine) ($engine+' '+$architecture+' remote selection stages the native asset and preserves its digest')
            foreach($mode in @('missing','duplicate','mismatched-payload')) {
                $root=Join-Path $componentBase ($mode+'-'+$engine+'-'+$architecture)
                $matching=$script:componentAssets[$index]
                $script:componentAssets=switch($mode){'missing' {@()} 'duplicate' {@($matching,$matching)} default {@($matching)}}
                if($mode -eq 'mismatched-payload'){$script:componentDownloadMachine=0x014c}
                $script:componentCalls.Clear();$rejected=$false
                try {Ensure-Asset $engine|Out-Null}catch{$rejected=if($mode -eq 'mismatched-payload'){$_.Exception.Message -like 'Downloaded component does not contain*'}else{$_.Exception.Message -like 'Exactly one native Windows asset*'}}
                Assert ($rejected -and @($script:componentCalls | Where-Object {$_.kind -eq 'event'}).Count -eq 0) ($engine+' '+$architecture+' '+$mode+' cannot report a ready component')
                $script:componentAssets=@(foreach($name in $names[$engine]){@{name=$name;browser_download_url=('https://github.com/vendor/component/releases/download/test/'+$name);digest=('sha256:'+('b'*64))}})
            }
        }
        $inputData=[pscustomobject]@{nativeArchitecture='unknown'};$script:componentCalls.Clear();$rejected=$false
        try {Ensure-Asset $engine|Out-Null}catch{$rejected=$_.Exception.Message -like 'Native Windows architecture is unavailable*'}
        Assert ($rejected -and $null -eq (Find-Source $engine) -and $script:componentCalls.Count -eq 0) ($engine+' unknown host identity refuses native component retrieval and readiness')
    }
    # Inert names only: discovery must never return another engine's file and
    # staging must not rename it into the requested executable.
    $previousProgramFiles=$env:ProgramFiles
    try {
        $env:ProgramFiles=Join-Path $componentBase 'empty-program-files';[void](New-Item -ItemType Directory -Force -Path $env:ProgramFiles)
        foreach($fixture in @(@('zapret','zapret-winws','winws.exe','winws2.exe'),@('zapret2','zapret-winws2','winws2.exe','winws.exe'))){
            $engine=$fixture[0];$bundle=Join-Path $componentBase ('preferred-'+$engine);$folder=Join-Path $bundle $fixture[1]
            [void](New-Item -ItemType Directory -Force -Path $folder)
            $expected=Join-Path $folder $fixture[2];[IO.File]::WriteAllText($expected,'correct inert file');[IO.File]::WriteAllText((Join-Path $folder $fixture[3]),'wrong inert file')
            $root=Join-Path $componentBase ('isolated-'+$engine);$r=[pscustomobject]@{bundlePath=$bundle}
            Assert ((Find-Source $engine) -ceq $expected) ($engine+' selects only its expected executable in the preferred folder')
            $wrongBundle=Join-Path $componentBase ('wrong-only-'+$engine);$wrongFolder=Join-Path $wrongBundle $fixture[1]
            [void](New-Item -ItemType Directory -Force -Path $wrongFolder);[IO.File]::WriteAllText((Join-Path $wrongFolder $fixture[3]),'wrong inert file')
            $r=[pscustomobject]@{bundlePath=$wrongBundle}
            Assert ($null -eq (Find-Source $engine)) ($engine+' refuses a preferred folder containing only the other executable')
        }
    } finally {$env:ProgramFiles=$previousProgramFiles}
} finally {
    foreach($name in $componentFunctions.Keys){Set-Item ('Function:'+$name) $componentFunctions[$name]}
    Remove-Item Function:Write-InertPE
    $inputData=$previousComponentInput;$r=$previousComponentRequest;$root=$previousComponentRoot;$assetNames=$previousAssetNames
}

# Isolated scan boundaries: inert files and closed mocks only. A plausible
# partial summary must never be saved or reach installation as a success.
$previousScanInput=$inputData;$previousScanRequest=$r;$previousScanRoot=$root;$previousScanAssetNames=$assetNames
$scanFunctions=@{};foreach($name in @('Ensure-Asset','Native','Write-Atomic','Install-Method','Protect-Dir','Assert-TrustedTree')){$scanFunctions[$name]=(Get-Command $name).ScriptBlock}
try {
    $root=Join-Path $testRoot 'scan-completion';$scanBundle=Join-Path $root 'bundle'
    [void](New-Item -ItemType Directory -Force -Path $scanBundle)
    [IO.File]::WriteAllText((Join-Path $scanBundle 'blockcheck2.sh'),'inert')
    [IO.File]::WriteAllText((Join-Path $scanBundle 'bash.exe'),'inert')
    $script:scanBinary=Join-Path $scanBundle 'winws2.exe';[IO.File]::WriteAllText($script:scanBinary,'inert')
    $inputData=[pscustomobject]@{ispHook=$null;controller='fixture-controller'}
    function Ensure-Asset {param($engine);if($engine -cne 'zapret2'){throw 'Unexpected fixture engine'};return $script:scanBinary}
    function Write-Atomic {param($path,$text);$script:scanWrites++}
    function Install-Method {$script:scanInstalls++;return @{fixture=$true}}
    function Native {
        param($program,$arguments,$codes,[switch]$Secret,[int]$Timeout)
        if($program -ceq 'fixture-controller'){
            $script:scanSelectionArgs=@($arguments)
            if($script:scanMode -ceq 'parser-missing'){return @{stdout='{"protocol":"https","args":["--lua-desync=fixture"]}'}}
            return @{stdout='{"protocol":"https","args":["--lua-desync=fixture"]}';outputComplete=($script:scanMode -cne 'parser-incomplete')}
        }
        if([IO.Path]::GetFileName($program) -cne 'bash.exe'){throw 'Unexpected fixture process'}
        if($script:scanMode -ceq 'scan-missing'){return @{stdout='* SUMMARY fixture'}}
        return @{stdout='* SUMMARY fixture';outputComplete=($script:scanMode -cne 'scan-incomplete')}
    }
    foreach($mode in @('scan-incomplete','scan-missing','parser-incomplete','parser-missing','complete','complete-default','complete-multi')){
        $script:scanMode=$mode;$script:scanWrites=0;$script:scanInstalls=0;$script:scanSelectionArgs=@()
        $targets=@();if($mode -eq 'complete-multi'){$targets=@('example.com','example.net')}elseif($mode -ne 'complete-default'){$targets=@('example.com')}
        $r=[pscustomobject]@{engine='zapret2';bundlePath=$scanBundle;scan='quick';targets=@($targets);dns='unchanged'}
        $oldPath=$env:PATH;$rejected=$false
        try {[void](Auto-Install)}catch{$rejected=$true}
        if($mode -like 'complete*'){
            Assert (-not $rejected -and $script:scanWrites -eq 1 -and $script:scanInstalls -eq 1) ('Complete '+$mode+' scan reaches only the mocked installer')
            $requireCommon=(@($script:scanSelectionArgs | Where-Object {$_ -ceq '--require-common'}).Count -eq 1)
            if($mode -eq 'complete'){Assert (-not $requireCommon) 'Single-target scan does not require a common section'}
            else{Assert $requireCommon ('Multi-target '+$mode+' scan requires a common section')}
        }elseif($mode -like 'scan-*'){
            Assert ($rejected -and $script:scanWrites -eq 0 -and $script:scanInstalls -eq 0) ('Scan rejects '+$mode+' before saving or installation')
        }else{
            Assert ($rejected -and $script:scanWrites -eq 1 -and $script:scanInstalls -eq 0) ('Scan rejects '+$mode+' before installation')
        }
        Assert ($env:PATH -ceq $oldPath) 'Scan restores the process PATH after success or refusal'
    }
    $inputData=[pscustomobject]@{managedPolicy=$true;ispHook=$null}
    $assetNames=@{zapret2='winws2.exe'}
    $r=[pscustomobject]@{engine='zapret2';bundlePath=$null;scan='quick';targets=@('example.com')}
    $script:scanWrites=0
    $refused=$false
    try {Scan-Strategies | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Managed strategy scans require an approved Windows blockcheck bundle'}
    Assert ($refused -and $script:scanWrites -eq 0) 'Managed strategy scan refuses an absent approved bundle before saving'
    $r.bundlePath=$scanBundle
    function Protect-Dir([string]$path){
        $script:stagedScanBundle=$path
        [void](New-Item -ItemType Directory -Path $path -Force)
    }
    function Assert-TrustedTree([string]$path){if($path -cne $script:stagedScanBundle){throw 'Unexpected managed scan cleanup target'}}
    function Native {
        param($program,$arguments,[int]$Timeout,$WorkingDirectory,$ChildEnvironment)
        if($program -cne (Join-Path $script:stagedScanBundle 'bash.exe') -or $arguments[-1] -notlike '*/blockcheck2.sh'){throw 'Unexpected staged scan executable or script'}
        if($env:BASH_ENV -cne 'fixture-startup' -or $ChildEnvironment.ContainsKey('BASH_ENV')){throw 'Managed scan did not isolate the child startup environment'}
        $system=Join-Path $env:SystemRoot 'System32'
        if($WorkingDirectory -cne $script:stagedScanBundle -or $ChildEnvironment.PATH -cne ($script:stagedScanBundle+';'+$system)){throw 'Managed scan used an unexpected working directory or search path'}
        if(-not (Under $ChildEnvironment.HOME $script:stagedScanBundle) -or $ChildEnvironment.TEMP -cne $ChildEnvironment.HOME){throw 'Managed scan did not keep state in the staged bundle'}
        if($ChildEnvironment.Count -ne 11 -or $ChildEnvironment.SCANLEVEL -cne 'quick' -or $ChildEnvironment.DOMAINS -cne 'example.com'){throw 'Managed scan child inputs changed'}
        return @{stdout='* SUMMARY fixture';outputComplete=$true}
    }
    $oldBashEnv=$env:BASH_ENV
    try {
        $env:BASH_ENV='fixture-startup'
        $stagedScan=Scan-Strategies
        if($env:BASH_ENV -cne 'fixture-startup'){throw 'Managed scan did not restore the Bash startup setting'}
    } finally {$env:BASH_ENV=$oldBashEnv}
    Assert ($stagedScan.scanLevel -ceq 'quick' -and $script:scanWrites -eq 1 -and (Under $script:stagedScanBundle (Join-Path $root 'temp')) -and -not (Test-Path -LiteralPath $script:stagedScanBundle)) 'Managed strategy scan runs from the staged approved bundle'
} finally {
    foreach($name in $scanFunctions.Keys){Set-Item ('Function:'+$name) $scanFunctions[$name]}
    $inputData=$previousScanInput;$r=$previousScanRequest;$root=$previousScanRoot;$assetNames=$previousScanAssetNames
}

# Failed real-vendor probes may export only bounded, sanitized error details.
$vendorTokens=$null;$vendorIssues=$null
$vendorAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'test-windows-vendor-preflight.ps1'),[ref]$vendorTokens,[ref]$vendorIssues)
Assert ($vendorIssues.Count -eq 0) 'Vendor preflight parses without executing its hosted-only entrypoint'
$redactor=@($vendorAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Public-VendorFailureMessages'})
Assert ($redactor.Count -eq 1) 'Vendor failure redactor has one explicit source definition'
. ([scriptblock]::Create($redactor[0].Extent.Text))
try {
    foreach($case in @(
        @{raw='ERROR cannot open C:\PRIVATE_FIXTURE\payload\file';expected='<path>'},
        @{raw='ERROR cannot open \\PRIVATE_FIXTURE\share\file';expected='<path>'},
        @{raw='ERROR ACCESS_TOKEN=PRIVATE_FIXTURE';expected='<redacted>'},
        @{raw='ERROR apiKey=PRIVATE_FIXTURE';expected='<redacted>'},
        @{raw='ERROR password=PRIVATE_FIXTURE';expected='<redacted>'},
        @{raw='ERROR Authorization: Bearer PRIVATE_FIXTURE';expected='<redacted>'},
        @{raw='ERROR principal S-1-5-21-1111-2222-3333-4444';expected='<sid>'}
    )){
        $safe=@(Public-VendorFailureMessages $case.raw)
        Assert ($safe.Count -eq 1 -and $safe[0].Contains($case.expected) -and $safe[0] -notmatch 'PRIVATE_FIXTURE|S-1-5-21-') 'Vendor failure detail excludes synthetic paths credentials and account identifiers'
    }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$identityName=$identity.Name} finally {$identity.Dispose()}
    foreach($name in @($identityName,[Environment]::MachineName)){
        $safe=@(Public-VendorFailureMessages ('ERROR invalid principal '+$name))
        Assert ($safe.Count -eq 1 -and -not $safe[0].Contains($name)) 'Vendor failure detail excludes the actual runner principal and machine name'
    }
    $safe=@(Public-VendorFailureMessages (((1..8 | ForEach-Object {'ERROR '+('x'*300)+[char]1}) -join [Environment]::NewLine)))
    Assert ($safe.Count -eq 4 -and @($safe | Where-Object {$_.Length -gt 160 -or $_ -match '[^\x20-\x7e]'}).Count -eq 0) 'Vendor failure detail bounds line count length and printable characters'
    Assert (@(Public-VendorFailureMessages 'ordinary help output').Count -eq 0) 'Vendor failure detail excludes ordinary non-error output'
} finally {Remove-Item Function:Public-VendorFailureMessages}

# These real read-only queries cover stock Windows services and device drivers.
$nativeServiceInspection=Get-ServiceInspection
Assert ($null -eq $nativeServiceInspection.error -and $nativeServiceInspection.services -is [array]) 'Native service and driver enumeration succeeds with an explicit array result'
$previousDriverProvider=(Get-Command Get-DriverServiceControllers).ScriptBlock
# Preserve partial results and every suppressed error, with no service/driver
# installation or state change. Driver-only cases prevent service-only coverage.
try {
    function Get-Service {
        [CmdletBinding()]param()
        $script:serviceQueryCalls++
        if($script:serviceQueryMode -eq 'throw'){throw 'PRIVATE_SERVICE_QUERY_DETAIL'}
        if($script:serviceQueryMode -in @('present','partial')){[pscustomobject]@{ServiceName='AccessWeaver-fixture';Status='Running'}}
        if($script:serviceQueryMode -in @('denied','partial','ordinary-denied-driver-present')){
            $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('PRIVATE_SERVICE_QUERY_DETAIL'),'CouldNotGetService',[Management.Automation.ErrorCategory]::PermissionDenied,$null))
        }elseif($script:serviceQueryMode -eq 'unknown'){
            $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('PRIVATE_SERVICE_QUERY_DETAIL'),'UnexpectedServiceLookup',[Management.Automation.ErrorCategory]::ObjectNotFound,$null))
        }elseif($script:serviceQueryMode -eq 'not-found'){
            $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('PRIVATE_SERVICE_QUERY_DETAIL'),'NoServiceFoundForGivenName',[Management.Automation.ErrorCategory]::ObjectNotFound,$null))
        }elseif($script:serviceQueryMode -eq 'bad-property'){
            $service=[pscustomobject]@{ServiceName='AccessWeaver-fixture'}
            $service | Add-Member -MemberType ScriptProperty -Name Status -Value {throw 'PRIVATE_SERVICE_QUERY_DETAIL'}
            $service
        }elseif($script:serviceQueryMode -eq 'bad-name'){[pscustomobject]@{ServiceName='';Status='Running'}}
        elseif($script:serviceQueryMode -eq 'duplicate'){[pscustomobject]@{ServiceName='WinDivert';Status='Running'}}
        if($script:serviceQueryMode -in @('present','partial')){[pscustomobject]@{ServiceName='WireSockAppService';Status='Stopped'}}
        if($script:serviceQueryMode -in @('present','partial','unrelated-only')){[pscustomobject]@{ServiceName='Unrelated-fixture';Status='Running'}}
    }
    function Get-DriverServiceControllers {
        [CmdletBinding()]param()
        $script:driverQueryCalls++
        if($script:serviceQueryMode -eq 'drivers-throw'){throw 'PRIVATE_SERVICE_QUERY_DETAIL'}
        if($script:serviceQueryMode -eq 'drivers-denied'){
            $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('PRIVATE_SERVICE_QUERY_DETAIL'),'CouldNotGetDevices',[Management.Automation.ErrorCategory]::PermissionDenied,$null))
        }elseif($script:serviceQueryMode -eq 'driver-property'){
            $driver=[pscustomobject]@{ServiceName='WinDivert'}
            $driver | Add-Member -MemberType ScriptProperty -Name Status -Value {throw 'PRIVATE_SERVICE_QUERY_DETAIL'}
            $driver
        }elseif($script:serviceQueryMode -eq 'duplicate'){[pscustomobject]@{ServiceName='windivert';Status='Running'}}
        elseif($script:serviceQueryMode -in @('present','partial','driver-only','ordinary-denied-driver-present')){
            [pscustomobject]@{ServiceName='WinDivert';Status='Running'}
            [pscustomobject]@{ServiceName='NDISRD';Status='Stopped'}
            [pscustomobject]@{ServiceName='Unrelated-driver';Status='Running'}
        }
    }
    foreach($mode in @('present','empty','unrelated-only','denied','unknown','not-found','partial','throw','bad-property','bad-name','driver-only','drivers-denied','drivers-throw','driver-property','ordinary-denied-driver-present','duplicate')){
        $script:serviceQueryMode=$mode;$script:serviceQueryCalls=0;$script:driverQueryCalls=0
        $inspection=Get-ServiceInspection
        Assert ($script:serviceQueryCalls -eq 1 -and $script:driverQueryCalls -eq 1) 'Service discovery enumerates ordinary services and device drivers once each'
        if($mode -in @('present','partial')){
            Assert ($inspection.services.Count -eq 4 -and $inspection.services[0].name -eq 'AccessWeaver-fixture' -and $inspection.services[0].owned -and $inspection.services[0].status -eq 'Running' -and $inspection.services[1].name -eq 'WireSockAppService' -and -not $inspection.services[1].owned) ($mode+' service inspection preserves selected values and excludes unrelated entries')
        }elseif($mode -in @('driver-only','ordinary-denied-driver-present')){
            Assert ($inspection.services.Count -eq 2 -and $inspection.services[0].name -eq 'WinDivert' -and $inspection.services[1].name -eq 'NDISRD') ($mode+' service inspection preserves driver coverage')
        }elseif($mode -eq 'duplicate'){
            Assert ($inspection.services.Count -eq 1 -and $inspection.services[0].name -eq 'WinDivert') 'Service inspection deduplicates names across providers without case sensitivity'
        }else{Assert ($inspection.services.Count -eq 0) ($mode+' service inspection does not invent entries')}
        if($mode -in @('present','empty','unrelated-only','driver-only','duplicate')){Assert ($null -eq $inspection.error) ($mode+' service inspection is known')}
        else{Assert (-not [string]::IsNullOrWhiteSpace($inspection.error)) ($mode+' service inspection remains explicitly incomplete')}
        Assert (($inspection|ConvertTo-Json -Depth 4) -notmatch 'PRIVATE_SERVICE_QUERY_DETAIL') 'Service inspection omits private error and exception details'
    }
} finally {Remove-Item Function:Get-Service;Set-Item Function:Get-DriverServiceControllers $previousDriverProvider}
# Evaluate only the isolated process-local TLS setup, with no HTTP operations.
$tlsStatements=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('[Net.ServicePointManager]::SecurityProtocol')})
Assert ($tlsStatements.Count -eq 1) 'HTTP TLS setup is conditional rather than an eager global initializer'
$tlsSetup=[scriptblock]::Create($tlsStatements[0].Extent.Text)
$previousTLS=[Net.ServicePointManager]::SecurityProtocol;$previousRequest=$r
try {
    foreach($action in @('discover','choose-folder','updates','download','install')) {
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::SystemDefault
        $r=[pscustomobject]@{action=$action}
        & $tlsSetup
        $expected=if($action -in @('discover','choose-folder')){[Net.SecurityProtocolType]::SystemDefault}else{[Net.SecurityProtocolType]::Tls12}
        Assert ([Net.ServicePointManager]::SecurityProtocol -eq $expected) ('Process-local TLS setup preserves the contract for '+$action)
    }
} finally {[Net.ServicePointManager]::SecurityProtocol=$previousTLS;$r=$previousRequest}
# Inert version directories verify application selection without launching Discord.
$previousLocalAppData=$env:LOCALAPPDATA
try {
    $env:LOCALAPPDATA=Join-Path $testRoot 'discord-selection-fixture'
    $appBase=Join-Path $env:LOCALAPPDATA 'Discord'
    foreach($name in @('app-1.0.9','app-1.0.10','app-unknown')){
        $directory=Join-Path $appBase $name;[void](New-Item -ItemType Directory -Path $directory -Force)
        [IO.File]::WriteAllText((Join-Path $directory 'Discord.exe'),'inert fixture')
    }
    (Get-Item -LiteralPath (Join-Path $appBase 'app-1.0.9')).LastWriteTimeUtc=[DateTime]::UtcNow
    (Get-Item -LiteralPath (Join-Path $appBase 'app-1.0.10')).LastWriteTimeUtc=[DateTime]::UtcNow.AddHours(-1)
    (Get-Item -LiteralPath (Join-Path $appBase 'app-unknown')).LastWriteTimeUtc=[DateTime]::UtcNow.AddHours(1)
    $found=@(Discord-Directories 'discord')
    Assert ($found.Count -eq 3 -and $found[0] -ceq (Join-Path $appBase 'app-1.0.10') -and $found[1] -ceq (Join-Path $appBase 'app-1.0.9')) 'Discord discovery selects the highest version before modification time'
    Assert ($found[2] -ceq (Join-Path $appBase 'app-unknown')) 'Discord discovery retains nonstandard directory fallback after valid versions'
    Assert ((Find-App 'discord') -ceq (Join-Path $appBase 'app-1.0.10\Discord.exe')) 'Discord application lookup uses the highest discovered version'
} finally {$env:LOCALAPPDATA=$previousLocalAppData}
# Exercise registered custom paths with inert files and an in-memory registry view.
& {
    $registrationKey='30120f3b-3e88-5c75-afec-3de1a3155a97'
    $machineKey='HKLM:\SOFTWARE\'+$registrationKey
    $alternateKey='HKLM:\SOFTWARE\WOW6432Node\'+$registrationKey
    $splitCordLocations=@{}
    $splitCordFirst=Join-Path $testRoot 'SplitCord fixture one'
    $splitCordSecond=Join-Path $testRoot 'SplitCord fixture two'
    foreach($directory in @($splitCordFirst,$splitCordSecond)){
        [void](New-Item -ItemType Directory -Path $directory)
        [IO.File]::WriteAllText((Join-Path $directory 'SplitCord-Turkey.exe'),'inert fixture')
    }
    function Test-Path {
        param([string]$LiteralPath,[string]$PathType,[string]$ErrorAction)
        if($LiteralPath -in @($machineKey,$alternateKey)){return $splitCordLocations.ContainsKey($LiteralPath)}
        $arguments=@{LiteralPath=$LiteralPath}
        if($PathType){$arguments.PathType=$PathType}
        if($ErrorAction){$arguments.ErrorAction=$ErrorAction}
        Microsoft.PowerShell.Management\Test-Path @arguments
    }
    function Get-ItemProperty {
        param([string]$LiteralPath,[string]$ErrorAction)
        if($LiteralPath -in @($machineKey,$alternateKey)){return @{InstallLocation=$splitCordLocations[$LiteralPath]}}
        Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath -ErrorAction $ErrorAction
    }
    $splitCordLocations[$machineKey]='\\server\share'
    $splitCordLocations[$alternateKey]=$splitCordFirst
    Assert ((Find-App 'splitcord') -ieq (Join-Path $splitCordFirst 'SplitCord-Turkey.exe')) 'SplitCord discovery uses the registered custom path from the alternate machine view'
    $splitCordLocations[$machineKey]=$splitCordFirst
    Assert ((Find-App 'splitcord') -ieq (Join-Path $splitCordFirst 'SplitCord-Turkey.exe')) 'SplitCord discovery deduplicates matching machine registrations'
    $splitCordLocations[$machineKey]=$splitCordSecond
    $ambiguous=$false
    try {Find-App 'splitcord' | Out-Null}catch{$ambiguous=$_.Exception.Message -ceq 'Multiple registered SplitCord installations matched'}
    Assert $ambiguous 'SplitCord discovery refuses two different registered installations'
}
# Custom installer admission is exercised without discovery or network access.
$previousWireSockCLI=(Get-Command WireSock-CLI).ScriptBlock;$previousWireSockRequest=$r
try {
    function WireSock-CLI {$script:wireSockDiscoveryCount++;return 'C:\fixture\wiresock.exe'}
    $script:wireSockDiscoveryCount=0;$r=[pscustomobject]@{downloadUrl='https://example.invalid/setup.exe';sha256=''}
    $rejected=$false;try{Install-WireSock}catch{$rejected=$true}
    Assert ($rejected -and $script:wireSockDiscoveryCount -eq 0) 'Custom WireSock installer without a hash is rejected before discovery'
    $script:wireSockDiscoveryCount=0;$r=[pscustomobject]@{downloadUrl='https://example.invalid/setup.exe';sha256=('a'*64)}
    $result=Install-WireSock
    Assert ($result -ceq 'C:\fixture\wiresock.exe' -and $script:wireSockDiscoveryCount -eq 1) 'Hashed custom WireSock request reaches mocked discovery'
    $script:wireSockDiscoveryCount=0;$r=[pscustomobject]@{downloadUrl='';sha256=''}
    $result=Install-WireSock
    Assert ($result -ceq 'C:\fixture\wiresock.exe' -and $script:wireSockDiscoveryCount -eq 1) 'Default WireSock request reaches mocked discovery'
} finally {Set-Item Function:WireSock-CLI $previousWireSockCLI;$r=$previousWireSockRequest}
$wireX64=WireSock-InstallerPlan 'amd64'
$wireARM64=WireSock-InstallerPlan 'arm64'
Assert ($wireX64.pattern -ceq 'wiresock-secure-connect-x64-*.exe' -and $wireARM64.pattern -ceq 'wiresock-secure-connect-arm64-*.exe' -and $wireX64.url -match 'platform=windows_x64' -and $wireARM64.url -match 'platform=windows_arm64' -and $wireX64.sha256 -cne $wireARM64.sha256) 'WireSock selects separate installer plans for native AMD64 and ARM64'
$refused=$false
try {WireSock-InstallerPlan 'unknown' | Out-Null}catch{$refused=$_.Exception.Message -like 'Native Windows architecture is unavailable*'}
Assert $refused 'WireSock refuses an installer plan for an unknown architecture'
# Exercise the bundled WireSock path using an inert file and mocked launch.
$previousWireSockRequest=$r
$previousWireSockRebootRequired=$script:rebootRequired
$previousWireSockInput=$inputData
$wireSockFixtureFunctions=@{}
foreach($name in @('WireSock-CLI','Get-AuthenticodeSignature','Native')){
    $wireSockFixtureFunctions[$name]=(Get-Command $name).ScriptBlock
}
try {
    $wireSockBundle=Join-Path $testRoot 'wiresock-bundle'
    [void](New-Item -ItemType Directory -Path $wireSockBundle)
    $inputData=[pscustomobject]@{nativeArchitecture='arm64'}
    $wireSockInstaller=Join-Path $wireSockBundle 'wiresock-secure-connect-arm64-fixture.exe'
    $otherArchitectureInstaller=Join-Path $wireSockBundle 'wiresock-secure-connect-x64-fixture.exe'
    [IO.File]::WriteAllBytes($otherArchitectureInstaller,[byte[]]@(1))
    [IO.File]::WriteAllBytes($wireSockInstaller,[byte[]]@(0))
    $r=[pscustomobject]@{bundlePath=$wireSockBundle}
    $script:fixtureWireSockInstalled=$false
    $script:fixtureWireSockLaunch=$null
    $script:fixtureWireSockSignedPath=$null
    $script:fixtureWireSockSubject='CN=Other fixture publisher'
    $script:fixtureWireSockReboot=$false
    $script:fixtureWireSockLookups=0
    $script:rebootRequired=$false
    function WireSock-CLI {
        $script:fixtureWireSockLookups++
        if($script:fixtureWireSockInstalled){return 'C:\fixture\wiresock.exe'}
    }
    function Get-AuthenticodeSignature {
        param($LiteralPath)
        $script:fixtureWireSockSignedPath=$LiteralPath
        return @{Status='Valid';SignerCertificate=@{Subject=$script:fixtureWireSockSubject}}
    }
    function Native {
        param($program,$arguments,$codes)
        if(-not (Test-Path -LiteralPath $program -PathType Leaf)){throw 'Missing staged installer at mocked launch'}
        $bytes=[IO.File]::ReadAllBytes($program)
        if($bytes.Length -ne 1 -or $bytes[0] -ne 0){throw 'WireSock selected an installer for the wrong architecture'}
        $script:fixtureWireSockLaunch=$program
        $script:fixtureWireSockInstalled=$true
        if($script:fixtureWireSockReboot){
            $script:rebootRequired=$true
            return @{exitCode=3010}
        }
        return @{exitCode=0}
    }
    $rejected=$false
    try {Install-WireSock | Out-Null}catch{$rejected=$_.Exception.Message -ceq 'WireSock installer publisher signature could not be verified'}
    Assert ($rejected -and -not $script:fixtureWireSockLaunch -and (Under $script:fixtureWireSockSignedPath (Join-Path $root 'downloads')) -and -not (Test-Path -LiteralPath $script:fixtureWireSockSignedPath)) 'Bundled WireSock rejects an unrelated publisher and retires the staged copy'
    $script:fixtureWireSockSubject='CN=WireSock fixture'
    $wireSockResult=Install-WireSock
    Assert ($wireSockResult -ceq 'C:\fixture\wiresock.exe' -and $script:fixtureWireSockLaunch -ceq $script:fixtureWireSockSignedPath -and (Under $script:fixtureWireSockLaunch (Join-Path $root 'downloads')) -and -not (Test-Path -LiteralPath $script:fixtureWireSockLaunch) -and (Test-Path -LiteralPath $wireSockInstaller)) 'Bundled WireSock launches only the verified staged installer and retires it'
    $script:fixtureWireSockInstalled=$false
    $script:fixtureWireSockReboot=$true
    $script:fixtureWireSockLookups=0
    $script:fixtureWireSockLaunch=$null
    $refused=$false
    try {Install-WireSock | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Restart Windows after WireSock installation, then retry setup'}
    Assert ($refused -and $script:rebootRequired -and $script:fixtureWireSockLookups -eq 1 -and $script:fixtureWireSockLaunch -and -not (Test-Path -LiteralPath $script:fixtureWireSockLaunch)) 'WireSock defers connection after an installer restart request'
} finally {
    $script:rebootRequired=$previousWireSockRebootRequired
    $inputData=$previousWireSockInput
    foreach($name in $wireSockFixtureFunctions.Keys){
        if($null -eq $wireSockFixtureFunctions[$name]){Remove-Item ('Function:'+$name)}
        else{Set-Item ('Function:'+$name) $wireSockFixtureFunctions[$name]}
    }
    $r=$previousWireSockRequest
}
# Check both service records before allowing a mocked vendor service start.
$previousWireSockEffects=$script:externalEffectsPending
try {
    & {
        function Get-Service {
            param($Name,$ErrorAction)
            return $script:wireSockServiceFixtures[$Name]
        }
        function Start-Service {
            param($InputObject,$ErrorAction)
            if(-not $script:externalEffectsPending){throw 'Fixture start did not record the vendor effect'}
            $script:wireSockServiceStarts.Add($InputObject.ServiceName)
            $InputObject.Status='Running'
        }
        $script:wireSockServiceStarts=[Collections.Generic.List[string]]::new()
        $script:externalEffectsPending=$false
        $app=[pscustomobject]@{ServiceName='WireSockAppService';Status='Stopped'}
        $connect=[pscustomobject]@{ServiceName='WireSockConnectService';Status='StartPending'}
        foreach($service in @($app,$connect)){
            $service | Add-Member ScriptMethod Refresh {}
            $service | Add-Member ScriptMethod WaitForStatus {
                param($status,$timeout)
                if($this.Status -ne $status -or $timeout.TotalSeconds -ne 20){throw 'Unexpected fixture service wait'}
            }
        }
        $script:wireSockServiceFixtures=@{WireSockAppService=$app}
        $refused=$false
        try {Start-WireSockServices}catch{$refused=$_.Exception.Message -like 'Vendor service missing: WireSockConnectService*'}
        Assert ($refused -and $script:wireSockServiceStarts.Count -eq 0 -and -not $script:externalEffectsPending) 'WireSock checks for both services before starting either'
        $script:wireSockServiceFixtures['WireSockConnectService']=$connect
        $refused=$false
        try {Start-WireSockServices}catch{$refused=$_.Exception.Message -ceq 'Vendor service is not ready for setup: WireSockConnectService'}
        Assert ($refused -and $script:wireSockServiceStarts.Count -eq 0 -and -not $script:externalEffectsPending) 'WireSock refuses transitional service state before starting either service'
        $app.Status='Running'
        $connect.Status='Stopped'
        Start-WireSockServices
        Assert (($script:wireSockServiceStarts -join ',') -ceq 'WireSockConnectService' -and $script:externalEffectsPending) 'WireSock starts only a stopped vendor service and records the external effect'
    }
} finally {$script:externalEffectsPending=$previousWireSockEffects}
# Fixed inert files exercise ownership input validation without vendor execution.
$previousOwnedRoot=$root;$previousOwnedRequest=$r;$previousOwnedProgramFiles=$env:ProgramFiles
try {
    & {
        $root=Join-Path $testRoot 'wiresock-ownership'
        $env:ProgramFiles=Join-Path $root 'programs'
        $profileDirectory=Join-Path $root 'profiles'
        [void][IO.Directory]::CreateDirectory($profileDirectory)
        $recordPath=Join-Path $profileDirectory 'wiresock-owned.json'
        $paths=@(Get-WireSockCLIPaths)
        foreach($path in @($paths[0],$paths[2])){
            [void][IO.Directory]::CreateDirectory((Split-Path -Parent $path))
            [IO.File]::WriteAllBytes($path,[byte[]]@(0))
        }
        $profile='AccessWeaver-'+('a'*32)
        @{cli=$paths[0];profile=$profile} | ConvertTo-Json -Compress | Set-Content -LiteralPath $recordPath -Encoding ASCII
        $accepted=Read-OwnedWireSockProfile $recordPath
        Assert (-not $accepted.legacy -and $accepted.cli -ceq $paths[0] -and $accepted.profile -ceq $profile) 'WireSock accepts the existing modern ownership record format'
        @{cli=$paths[2];profile='default';legacy=$true} | ConvertTo-Json -Compress | Set-Content -LiteralPath $recordPath -Encoding ASCII
        $accepted=Read-OwnedWireSockProfile $recordPath
        Assert ($accepted.legacy -and $accepted.cli -ceq $paths[2]) 'WireSock accepts its recorded legacy CLI alongside a modern installation'
        function Native {throw 'An invalid record reached a vendor command'}
        function Stop-Service {throw 'An invalid record reached a service change'}
        function New-ScheduledTaskAction {throw 'An invalid record reached task construction'}
        function Unregister-ScheduledTask {throw 'An invalid record reached task removal'}
        $r=[pscustomobject]@{enabled=$true}
        foreach($record in @(
            @{cli=(Join-Path $root 'outside.exe');profile=$profile},
            @{cli=$paths[0];profile='other-profile'},
            @{cli=$paths[2];profile=$profile;legacy='true'}
        )){
            $record | ConvertTo-Json -Compress | Set-Content -LiteralPath $recordPath -Encoding ASCII
            foreach($operation in @({Disconnect-WireSock},{Remove-Method 'wiresock'},{Refresh-Task})){
                $refused=$false
                try {& $operation}catch{$refused=$_.Exception.Message -ceq 'WireSock ownership record is invalid or its vendor CLI is unavailable'}
                if(-not $refused){throw 'WireSock operation did not reject the invalid ownership record'}
            }
        }
        Assert (Test-Path -LiteralPath $recordPath -PathType Leaf) 'WireSock rejects invalid records before commands or task changes'
        @{cli=$paths[0];profile=$profile} | ConvertTo-Json -Compress | Set-Content -LiteralPath $recordPath -Encoding ASCII
        $script:fixtureRefreshCalls=[Collections.Generic.List[string]]::new()
        $script:fixtureRefreshPresent=$true
        $script:fixtureRefreshRetained=$true
        function Get-RefreshTaskInspection {return @{present=$script:fixtureRefreshPresent}}
        function Disable-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);$script:fixtureRefreshCalls.Add('disable')}
        function Stop-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);$script:fixtureRefreshCalls.Add('stop')}
        function Unregister-ScheduledTask {
            param($TaskName,$TaskPath,$ErrorAction,$Confirm)
            if($TaskName -cne 'AccessWeaver-WireSock-Refresh' -or $TaskPath -cne '\' -or $ErrorAction -cne 'Stop'){throw 'Unexpected task removal target'}
            $script:fixtureRefreshCalls.Add('unregister')
            $script:fixtureRefreshPresent=$script:fixtureRefreshRetained
        }
        $vendorFailure=''
        $disconnectStatus=@{outputComplete=$true;stdout='Connected'}
        $disconnectFailure='Tool failed: wiresock-connect-cli.exe (exit 1)'
        function Native {
            param($program,$arguments,[switch]$Secret,[int]$Timeout)
            if(-not $Secret){throw 'Expected private WireSock command'}
            $script:fixtureRefreshCalls.Add($arguments[0])
            if($arguments[0] -ceq $vendorFailure){
                if($vendorFailure -ceq 'disconnect'){throw $disconnectFailure}
                throw 'Private synthetic vendor detail'
            }
            if($arguments[0] -ceq 'status'){
                if($Timeout -ne 15){throw 'Expected bounded WireSock status query'}
                return $disconnectStatus
            }
            return @{exitCode=0}
        }
        $effectsBeforeCleanup=$script:externalEffectsPending
        try {
            $refused=$false
            try {Disconnect-WireSock}catch{$refused=$_.Exception.Message -ceq 'WireSock reconnect task removal could not be verified'}
            Assert ($refused -and ($script:fixtureRefreshCalls -join ',') -ceq 'disable,stop,unregister' -and (Test-Path -LiteralPath $recordPath)) 'WireSock disconnect refuses while scheduled reconnect removal is unconfirmed'
            $script:fixtureRefreshCalls.Clear()
            $script:fixtureRefreshRetained=$false
            Disconnect-WireSock
            Assert (($script:fixtureRefreshCalls -join ',') -ceq 'disable,stop,unregister,disconnect' -and (Test-Path -LiteralPath $recordPath)) 'WireSock disconnect retires scheduled reconnect and retains its profile'
            $script:fixtureRefreshCalls.Clear()
            $script:fixtureRefreshPresent=$true
            $script:fixtureRefreshRetained=$true
            $refused=$false
            try {Remove-Method 'wiresock'}catch{$refused=$_.Exception.Message -ceq 'WireSock reconnect task removal could not be verified'}
            Assert ($refused -and ($script:fixtureRefreshCalls -join ',') -ceq 'disable,stop,unregister' -and (Test-Path -LiteralPath $recordPath)) 'WireSock retains the profile when reconnect task removal is unconfirmed'
            $script:fixtureRefreshRetained=$false
            $recordHash=(Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash
            foreach($case in @(
                @{verb='disconnect';calls='disconnect,status';message='WireSock disconnect command failed; the managed profile was retained'},
                @{verb='delete';calls='disconnect,delete';message='WireSock profile deletion command failed; the ownership record was retained'}
            )){
                $script:fixtureRefreshPresent=$true
                $script:fixtureRefreshCalls.Clear()
                $vendorFailure=$case.verb
                $refused=$false
                try {Remove-Method 'wiresock'}catch{$refused=$_.Exception.Message -ceq $case.message}
                if(-not $refused -or ($script:fixtureRefreshCalls -join ',') -cne ('disable,stop,unregister,'+$case.calls) -or
                    (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash -cne $recordHash){
                    throw 'WireSock removal failure did not preserve its fixed outcome and ownership record'
                }
            }
            Assert $true 'WireSock distinguishes disconnect and deletion failures and retains ownership'
            $script:fixtureRefreshPresent=$false
            $vendorFailure='disconnect'
            $disconnectStatus=@{outputComplete=$false;stdout='Disconnected'}
            $script:fixtureRefreshCalls.Clear()
            $refused=$false
            try {Remove-Method 'wiresock'}catch{$refused=$_.Exception.Message -ceq 'WireSock disconnect command failed; the managed profile was retained'}
            Assert ($refused -and ($script:fixtureRefreshCalls -join ',') -ceq 'disconnect,status' -and
                (Test-Path -LiteralPath $recordPath)) 'WireSock retains ownership when idle status output is incomplete'
            $disconnectStatus=@{outputComplete=$true;stdout='Status: NotConnected'}
            $disconnectFailure='Timed out: wiresock-connect-cli.exe'
            $script:fixtureRefreshCalls.Clear()
            $refused=$false
            try {Remove-Method 'wiresock'}catch{$refused=$_.Exception.Message -ceq 'WireSock disconnect command failed; the managed profile was retained'}
            Assert ($refused -and ($script:fixtureRefreshCalls -join ',') -ceq 'disconnect' -and
                (Test-Path -LiteralPath $recordPath)) 'WireSock retains ownership after an unconfirmed disconnect process exit'
            $disconnectFailure='Tool failed: wiresock-connect-cli.exe (exit 1)'
            $script:fixtureRefreshCalls.Clear()
            Remove-Method 'wiresock'
            Assert (($script:fixtureRefreshCalls -join ',') -ceq 'disconnect,status,delete' -and
                -not (Test-Path -LiteralPath $recordPath)) 'WireSock can remove its profile after a failed disconnect and confirmed idle status'
            @{cli=$paths[0];profile=$profile} | ConvertTo-Json -Compress | Set-Content -LiteralPath $recordPath -Encoding ASCII
            $script:fixtureRefreshPresent=$true
            $vendorFailure=''
            $script:fixtureRefreshCalls.Clear()
            Remove-Method 'wiresock'
            Assert (($script:fixtureRefreshCalls -join ',') -ceq 'disable,stop,unregister,disconnect,delete' -and -not (Test-Path -LiteralPath $recordPath)) 'WireSock retires the reconnect task before disconnecting or deleting the profile'
        } finally {$script:externalEffectsPending=$effectsBeforeCleanup}
    }
} finally {
    $root=$previousOwnedRoot;$r=$previousOwnedRequest;$env:ProgramFiles=$previousOwnedProgramFiles
}
# The vendor disconnect command is global, so import-only rollback must
# never send it. Model failures at both sides of the journal phase change.
& {
    $profileName='AccessWeaver-'+('b'*32)
    $script:fixtureWireSockRollbackCalls=[Collections.Generic.List[string]]::new()
    $previousUndo=$script:undo
    try {
        $script:undo=[Collections.Generic.List[object]]::new()
        $failDisconnect=$false
        $idleStatus='Disconnected'
        function Native {
            param($program,$arguments,[switch]$Secret,[int]$Timeout)
            if(-not $Secret -or ($arguments[0] -eq 'delete' -and $arguments[1] -cne $profileName)){
                throw 'Unexpected vendor cleanup command'
            }
            $script:fixtureWireSockRollbackCalls.Add($arguments[0])
            if($arguments[0] -ceq 'disconnect' -and $failDisconnect){throw 'Tool failed: wiresock-connect-cli.exe (exit 1)'}
            if($arguments[0] -ceq 'status'){
                if($Timeout -ne 15){throw 'Expected bounded WireSock status query'}
                return @{outputComplete=$true;stdout=$idleStatus}
            }
            return @{exitCode=0}
        }
        $entry=@{kind='wiresock';cli='C:\fixture\wiresock-connect-cli.exe';profile=$profileName;importOnly=$true}
        $script:undo.Add($entry)
        Assert (@(Rollback).Count -eq 0 -and ($script:fixtureWireSockRollbackCalls -join ',') -ceq 'delete') 'WireSock import-only recovery leaves the active connection alone'
        $entry.importOnly=$false
        $script:fixtureWireSockRollbackCalls.Clear()
        Assert (@(Rollback).Count -eq 0 -and ($script:fixtureWireSockRollbackCalls -join ',') -ceq 'disconnect,delete') 'WireSock recovery after a connection attempt retains both cleanup steps'
        $failDisconnect=$true
        $script:fixtureWireSockRollbackCalls.Clear()
        Assert (@(Rollback).Count -eq 0 -and ($script:fixtureWireSockRollbackCalls -join ',') -ceq 'disconnect,status,delete') 'WireSock recovery can delete its recorded profile after confirmed idle status'
        $idleStatus='Disconnecting'
        $script:fixtureWireSockRollbackCalls.Clear()
        Assert (@(Rollback).Count -eq 1 -and ($script:fixtureWireSockRollbackCalls -join ',') -ceq 'disconnect,status') 'WireSock recovery refuses deletion while the vendor is still disconnecting'
    } finally {$script:undo=$previousUndo}
}
# Drive the actual connection function and recover its generated undo entry.
& {
    $previousUndo=$script:undo
    try {
        $root=Join-Path $testRoot 'wiresock-phase-failures'
        $profiles=Join-Path $root 'profiles'
        [void][IO.Directory]::CreateDirectory($profiles)
        $originalConfig=Join-Path $root 'fixture.conf'
        [IO.File]::WriteAllText($originalConfig,'inert profile')
        $fixtureCli='C:\fixture\wiresock-connect-cli.exe'
        $calls=[Collections.Generic.List[string]]::new()
        function Install-WireSock {return $fixtureCli}
        function Start-WireSockServices {}
        function Copy-Checked {
            param($Source,$Destination)
            [IO.File]::Copy($Source,$Destination,$false)
            if($mode -ceq 'copy'){throw 'Fixture copy failure'}
        }
        function Write-Atomic {
            param($Path,$Text)
            if((Split-Path -Leaf $Path) -cne 'wiresock-owned.json' -or ($Text | ConvertFrom-Json).profile -cne $script:undo[0].profile){throw 'Unexpected ownership record'}
            $calls.Add('record')
        }
        function Event {}
        function Save-Journal {
            if($script:undo.Count -ne 1){throw 'Unexpected WireSock journal entry count'}
            $phase=$script:undo[0].importOnly
            if($phase -isnot [bool]){throw 'Unexpected WireSock journal phase'}
            if($phase){$calls.Add('save-import')}
            else{
                $calls.Add('save-connect')
                if($mode -ceq 'journal'){throw 'Fixture journal failure'}
            }
        }
        function Native {
            param($program,$arguments,[switch]$Secret,[int]$Timeout)
            if($program -cne $fixtureCli -or -not $Secret){throw 'Unexpected vendor command'}
            $command=$arguments[0]
            $entry=$script:undo[0]
            switch($command){
                'import' {
                    if(-not $entry.importOnly -or [IO.Path]::GetFileNameWithoutExtension($arguments[1]) -cne $entry.profile){
                        throw 'Import did not use the journaled profile'
                    }
                    if(-not [IO.File]::Exists($arguments[1])){throw 'Missing staged import configuration'}
                    $calls.Add($command)
                    if($mode -ceq 'import'){throw 'Fixture import failure'}
                }
                'connect' {
                    if($entry.importOnly -or $arguments[1] -cne $entry.profile){throw 'Connect did not use the journaled profile'}
                    $calls.Add($command)
                    if($mode -ceq 'connect'){throw 'Fixture connect failure'}
                }
                'status' {
                    if($Timeout -ne 15){throw 'Expected bounded status query'}
                    $calls.Add($command)
                    return $fixtureStatus
                }
                'disconnect' {$calls.Add($command)}
                'delete' {
                    if($arguments[1] -cne $entry.profile -or $entry.profile -cnotmatch '^AccessWeaver-[a-f0-9]{32}$'){
                        throw 'Rollback targeted a different profile'
                    }
                    $calls.Add($command)
                }
                default {throw 'Unexpected vendor command'}
            }
            return @{exitCode=0}
        }
        foreach($case in @(
            @{mode='copy';calls='';label='WireSock retires failed import staging before any vendor command'},
            @{mode='import';calls='save-import,import,delete';label='WireSock import failure rolls back only the generated profile'},
            @{mode='journal';calls='save-import,import,save-connect,delete';label='WireSock journal failure before connect preserves the active tunnel'},
            @{mode='connect';calls='save-import,import,save-connect,connect,disconnect,delete';label='WireSock connect failure uses the persisted connection recovery phase'}
        )){
            $mode=$case.mode
            $calls.Clear()
            $script:undo=[Collections.Generic.List[object]]::new()
            $failed=$false
            try {Connect-WireSock (Join-Path $root 'fixture.conf') | Out-Null}catch{
                $failed=$_.Exception.Message -ceq ('Fixture '+$mode+' failure')
            }
            if(@(Get-ChildItem -LiteralPath $profiles -Filter '*.conf').Count){throw 'Import configuration remains after failure'}
            $errors=@(Rollback)
            Assert ($failed -and $errors.Count -eq 0 -and ($calls -join ',') -ceq $case.calls) $case.label
        }
        $mode='complete'
        $checks=@(
            @{stdout="Connection status: Connected`r`nExternal address: 198.51.100.7";complete=$true;want='Connected'},
            @{stdout='NotConnected';complete=$true;want='NotConnected'},
            @{stdout='Connection is Connected to an unverified profile';complete=$true;want='Unknown'},
            @{stdout="Status: Connected`nStatus: Disconnected";complete=$true;want='Unknown'},
            @{stdout='Connected';complete=$false;want='Unknown'},
            @{stdout=('x'*8193);complete=$true;want='Unknown'}
        )
        foreach($check in $checks){
            $fixtureStatus=@{stdout=$check.stdout;outputComplete=$check.complete}
            if((Get-WireSockReportedState $fixtureStatus) -cne $check.want){throw 'Unexpected WireSock status projection'}
        }
        Assert $true 'WireSock records only a fixed vendor status and discards private output'
        foreach($check in $checks){
            $calls.Clear()
            $script:undo=[Collections.Generic.List[object]]::new()
            $fixtureStatus=@{stdout=$check.stdout;outputComplete=$check.complete}
            if($check.want -ceq 'Connected'){
                $status=Connect-WireSock $originalConfig
                if($status -cne 'Connected' -or ($calls -join ',') -cne 'save-import,import,save-connect,connect,status,record'){
                    throw 'Confirmed connection did not publish its ownership record'
                }
            }else {
                $refused=$false
                try {Connect-WireSock $originalConfig | Out-Null}catch{
                    $refused=$_.Exception.Message -ceq 'WireSock connection was not confirmed by vendor status'
                }
                $errors=@(Rollback)
                if(-not $refused -or $errors.Count -ne 0 -or
                    ($calls -join ',') -cne 'save-import,import,save-connect,connect,status,disconnect,delete'){
                    throw 'Unconfirmed connection did not use the persisted recovery phase'
                }
            }
        }
        Assert $true 'WireSock requires confirmed vendor status before publishing ownership'
        Assert (@(Get-ChildItem -LiteralPath $profiles -Filter '*.conf').Count -eq 0 -and [IO.File]::ReadAllText($originalConfig) -ceq 'inert profile') 'WireSock retires import copies after completion and preserves the generated profile'
    } finally {$script:undo=$previousUndo}
}
# Exercise the updates dispatch helper with fixed public-shape release metadata.
& {
    $inputData=@{controller='C:\fixture\accessweaver.exe';nativeArchitecture='amd64'}
    $calls=[Collections.Generic.List[string]]::new()
    $published='2026-01-02T00:00:00Z'
    function New-ReleaseAssets([string]$tag,[string]$arch){
        foreach($name in @('BUILD-MANIFEST.json','SHA256SUMS.txt','BUILD-PROVENANCE.sigstore.json',('accessweaver-'+$tag+'-windows-'+$arch+'.zip'))){
            @{name=$name;state='uploaded';digest=('sha256:'+('a'*64))}
        }
    }
    $metadata=@(
        @{draft=$true;prerelease=$false;tag_name='v99.0.0'},
        @{draft=$false;prerelease=$true;tag_name='v88.0.0'},
        @{draft='false';prerelease=$false;tag_name='v77.0.0'},
        @{draft=$false;prerelease=$false;tag_name=('1'*257)},
        @{draft=$false;prerelease=$false;tag_name=('v8.0.0'+[char]0)},
        @{draft=$false;prerelease=$true;tag_name='v2.0.0-rc.1';assets=@(New-ReleaseAssets 'v2.0.0-rc.1' 'amd64')},
        @{draft=$false;prerelease=$false;tag_name='v1.9.0+build.3';html_url='https://outside.invalid/ignored';published_at=$published;assets=@(New-ReleaseAssets 'v1.9.0+build.3' 'amd64')}
    )
    function Read-RemoteJSON {
        param($Uri,$Headers)
        if($Uri -cne 'https://api.github.com/repos/Yunushan/accessweaver/releases?per_page=30' -or $Headers['User-Agent'] -cne 'AccessWeaver'){throw 'Unexpected update metadata request'}
        return ,$metadata
    }
    function Native {
        param($Program,$Arguments,[switch]$Secret)
        if($Program -cne $inputData.controller -or -not $Secret){throw 'Unexpected update comparison process'}
        $calls.Add(($Arguments -join ','))
        return @{stdout=$comparison;outputComplete=$outputComplete}
    }
    $outputComplete=$true
    $comparison='{"version":"v1.9.0+build.3","currentVersion":"1.8.0","updateAvailable":true}'
    $result=Check-AccessWeaverUpdates
    Assert ($calls.Count -eq 1 -and $calls[0] -ceq 'system,check-version,--follow-channel,v2.0.0-rc.1,v1.9.0+build.3' -and
        $result.url -ceq 'https://github.com/Yunushan/accessweaver/releases/tag/v1.9.0%2Bbuild.3' -and
        $result.updateAvailable -eq $true -and $result.publishedAt -ceq $published) 'Update discovery filters release metadata and returns the official tag link'
    $metadata=@($metadata | Where-Object {$_.tag_name -ceq 'v2.0.0-rc.1'})
    $comparison='{"version":"","currentVersion":"1.8.0","updateAvailable":false}'
    $result=Check-AccessWeaverUpdates
    Assert ($calls.Count -eq 2 -and $result.currentVersion -ceq '1.8.0' -and $result.updateAvailable -eq $false -and
        $null -eq $result.url -and $null -eq $result.publishedAt) 'Update discovery preserves a no-compatible-release result'
    $comparison='{"version":"v3.0.0","currentVersion":"1.8.0","updateAvailable":true}'
    $refused=$false
    try{Check-AccessWeaverUpdates | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Selected AccessWeaver release was not in the reviewed metadata'}
    Assert ($refused -and $calls.Count -eq 3) 'Update discovery refuses a selected tag absent from admitted metadata'
    foreach($bad in @(@{value=$metadata[0]},@{value=@($metadata[0])*31})){
        $metadata=$bad.value
        $refused=$false
        try{Check-AccessWeaverUpdates | Out-Null}catch{$refused=$_.Exception.Message -ceq 'AccessWeaver release metadata did not contain a valid release list'}
        if(-not $refused){throw 'Unexpected release metadata shape outcome'}
    }
    Assert ($calls.Count -eq 3) 'Update discovery rejects invalid list shapes before comparison'
    $calls.Clear()
    $inputData.nativeArchitecture='arm64'
    $wrongArch=@(New-ReleaseAssets 'v9.0.0' 'amd64')
    $incomplete=@(New-ReleaseAssets 'v8.0.0' 'arm64' | Where-Object {$_.name -cne 'BUILD-PROVENANCE.sigstore.json'})
    $duplicate=@(New-ReleaseAssets 'v7.0.0' 'arm64')
    $duplicate+=@($duplicate[0])
    $badDigest=@(New-ReleaseAssets 'v6.0.0' 'arm64')
    $badDigest[0].digest='sha256:short'
    $pending=@(New-ReleaseAssets 'v5.0.0' 'arm64')
    $pending[0].state='starter'
    $metadata=@(
        @{draft=$false;prerelease=$false;tag_name='v9.0.0';assets=$wrongArch},
        @{draft=$false;prerelease=$false;tag_name='v8.0.0';assets=$incomplete},
        @{draft=$false;prerelease=$false;tag_name='v7.0.0';assets=$duplicate},
        @{draft=$false;prerelease=$false;tag_name='v6.0.0';assets=$badDigest},
        @{draft=$false;prerelease=$false;tag_name='v5.0.0';assets=$pending},
        @{draft=$false;prerelease=$false;tag_name='v4.0.0';assets=@(New-ReleaseAssets 'v4.0.0' 'arm64')}
    )
    $comparison='{"version":"v4.0.0","currentVersion":"1.8.0","updateAvailable":true}'
    $result=Check-AccessWeaverUpdates
    Assert ($result.version -ceq 'v4.0.0' -and $calls.Count -eq 1 -and $calls[0] -ceq 'system,check-version,--follow-channel,v4.0.0') 'Update discovery requires architecture-specific uploaded assets with digests'
    $calls.Clear()
    $inputData.nativeArchitecture=''
    $refused=$false
    try{Check-AccessWeaverUpdates | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Native Windows architecture is unavailable or unsupported for release discovery'}
    Assert ($refused -and $calls.Count -eq 0) 'Update discovery refuses unsupported native architecture'
    $inputData.nativeArchitecture='arm64'
    $outputComplete=$false
    $refused=$false
    try{Check-AccessWeaverUpdates | Out-Null}catch{$refused=$_.Exception.Message -ceq 'AccessWeaver release comparison returned an invalid result'}
    $outputComplete=$true
    $comparison='{"version":"v4.0.0","currentVersion":"1.8.0","updateAvailable":"true"}'
    $badType=$false
    try{Check-AccessWeaverUpdates | Out-Null}catch{$badType=$_.Exception.Message -ceq 'AccessWeaver release comparison returned an invalid result'}
    Assert ($refused -and $badType -and $calls.Count -eq 2) 'Update discovery rejects incomplete and invalid comparison results'
}
# Publisher-category checks use synthetic signature records only.
$signatureDiscord=[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Discord fixture'}}
$signatureMicrosoft=[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Microsoft fixture'}}
$signatureWireSock=[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=NT Kernel fixture'}}
Assert ((Test-InstallerPublisher 'discord' $signatureDiscord) -and -not (Test-InstallerPublisher 'discord' $signatureMicrosoft) -and -not (Test-InstallerPublisher 'discord' $signatureWireSock)) 'Discord installer rejects other publisher categories'
Assert ((Test-InstallerPublisher 'microsoft' $signatureMicrosoft) -and -not (Test-InstallerPublisher 'microsoft' $signatureDiscord) -and -not (Test-InstallerPublisher 'microsoft' $signatureWireSock)) 'Microsoft installer rejects other publisher categories'
Assert ((Test-InstallerPublisher 'wiresock' $signatureWireSock) -and -not (Test-InstallerPublisher 'wiresock' $signatureDiscord) -and -not (Test-InstallerPublisher 'wiresock' $signatureMicrosoft) -and -not (Test-InstallerPublisher '' $signatureWireSock)) 'WireSock installer requires its own publisher category'
$x64Pin=(WireSock-InstallerPlan 'amd64').sha256
$armPin=(WireSock-InstallerPlan 'arm64').sha256
$unknownSigner=[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Unmatched fixture'}}
$invalidSigner=[pscustomobject]@{Status='NotTrusted';SignerCertificate=$unknownSigner.SignerCertificate}
Assert ((Test-InstallerPublisher 'wiresock' $unknownSigner $x64Pin 'amd64') -and (Test-InstallerPublisher 'wiresock' $unknownSigner $armPin 'arm64')) 'WireSock recognizes its exact native installer pin with a Windows-valid signature'
Assert (-not (Test-InstallerPublisher 'wiresock' $invalidSigner $x64Pin 'amd64') -and -not (Test-InstallerPublisher 'wiresock' $unknownSigner ('a'*64) 'amd64') -and -not (Test-InstallerPublisher 'wiresock' $unknownSigner $armPin 'amd64') -and -not (Test-InstallerPublisher 'wiresock' $unknownSigner $x64Pin '') -and -not (Test-InstallerPublisher 'discord' $unknownSigner $x64Pin 'amd64')) 'WireSock pin recognition refuses invalid signatures and unrelated pins and categories'
# Model only an HKLM registration and a trusted installer cache. Nothing is executed.
& {
    $cacheRoot=Join-Path $testRoot 'wiresock-uninstall-fixture'
    $program=Join-Path $cacheRoot 'Package Cache\fixture.exe'
    $registration='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\fixture'
    $inputData=[pscustomobject]@{nativeArchitecture='amd64'}
    $calls=[Collections.Generic.List[string]]::new()
    $previousProgramData=$env:ProgramData
    $previousRebootRequired=$script:rebootRequired
    $script:rebootRequired=$false
    $verifyRemoval=$false
    $requestRestart=$false
    $remainingCLI=$false
    $remainingService=$false
    $serviceQueryFails=$false
    $ownershipRetirementFails=$false
    $ownedPath=Join-Path $root 'profiles\wiresock-owned.json'
    $fallbackCLI=Join-Path $env:ProgramFiles 'WireSock Secure Connect\bin\wiresock-client.exe'
    try {
        $env:ProgramData=$cacheRoot
        function WireSock-CLI {}
        function Get-Service {
            param($ErrorAction)
            if($serviceQueryFails){throw 'Private fixture service error'}
            if($remainingService -and -not $calls.Contains('wait')){[pscustomobject]@{ServiceName='WireSockConnectService'}}
            [pscustomobject]@{ServiceName='UnrelatedFixtureService'}
        }
        function Test-Path {
            param($LiteralPath)
            if($LiteralPath -ceq $ownedPath){return $verifyRemoval -and -not $calls.Contains('retire-ownership')}
            if($LiteralPath -ceq $fallbackCLI){return $remainingCLI -and -not $calls.Contains('wait')}
            if($verifyRemoval -and $LiteralPath -ceq $registration){
                $calls.Add('check-registration')
                return -not $calls.Contains('wait') -and -not $hiddenRecord
            }
            if($verifyRemoval -and $hiddenRecord -and $LiteralPath -ceq $hiddenRecord.PSPath){
                $calls.Add('check-hidden-registration')
                return -not $calls.Contains('wait')
            }
            return $LiteralPath -ceq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        }
        $record=@{PSPath=$registration;DisplayName='WireSock Secure Connect';UninstallString=('"'+$program+'" /uninstall')}
        $hiddenRecord=$null
        $entries=@(@{PSPath=$registration})
        function Get-ChildItem {param($LiteralPath);return $entries}
        function Get-ItemProperty {
            param($LiteralPath)
            if($hiddenRecord -and $LiteralPath -ceq $hiddenRecord.PSPath){return $hiddenRecord}
            return $record
        }
        function Get-AuthenticodeSignature {param($LiteralPath);return $fixtureSignature}
        function Get-FileHash {param($LiteralPath,$Algorithm);return @{Hash=$fixtureDigest}}
        function No-Reparse {param($Path);if($Path -cne $program){throw 'Unexpected cached executable'}}
        function Remove-WireSockRefreshTask {$calls.Add('task')}
        function Remove-Method {$calls.Add('profile')}
        function Start-Sleep {param($Milliseconds);$calls.Add('wait')}
        function Remove-Item {
            if($ownershipRetirementFails){throw 'Private fixture ownership error'}
            if($verifyRemoval){$calls.Add('retire-ownership')}
        }
        function Event {
            param($Text)
            if($verifyRemoval -and $Text -like 'Vendor uninstall*'){$calls.Add($Text)}
        }
        function Native {
            param($Program,$Arguments,$Codes,$Timeout)
            if($Program -cne $expectedProgram -or ($Arguments -join ',') -cne $expectedArguments){throw 'Unexpected uninstall invocation'}
            $calls.Add('uninstall')
            $script:rebootRequired=$requestRestart
        }
        $expectedProgram=$program
        $expectedArguments="/uninstall,/quiet,/norestart"
        $fixtureSignature=$unknownSigner
        $fixtureDigest=$x64Pin
        $result=Uninstall-WireSockProduct
        Assert ($result.product -ceq 'WireSock Secure Connect' -and ($calls -join ',') -ceq 'task,profile,uninstall') 'WireSock uninstall accepts a signed cached copy of its exact native installer'
        $fixtureDigest=$armPin
        $refused=$false
        try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Vendor uninstaller publisher signature could not be verified'}
        $wrongPinRefused=$refused
        $fixtureDigest=$x64Pin;$fixtureSignature=$invalidSigner
        $refused=$false
        try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Vendor uninstaller publisher signature could not be verified'}
        Assert ($wrongPinRefused -and $refused -and ($calls -join ',') -ceq 'task,profile,uninstall') 'WireSock uninstall refuses a different native pin or invalid signature before cleanup'
        $calls.Clear()
        $entries+=@(@{PSPath=$registration+'-second'})
        $refused=$false
        try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -like 'Multiple registered WireSock products matched*'}
        Assert ($refused -and $calls.Count -eq 0) 'WireSock uninstall refuses ambiguous registrations before cleanup'
        $entries=@(@{PSPath=$registration})
        $productCode='{b7678321-14b3-4439-a4ef-789452416058}'
        $otherCode='{c7678321-14b3-4439-a4ef-789452416058}'
        $hiddenRecord=@{
            PSPath=$registration+'-hidden'
            DisplayName='WireSock Secure Connect'
            WindowsInstaller=1
            SystemComponent=1
            PSChildName=$productCode
            UninstallString=('MsiExec.exe /I'+$productCode)
        }
        $entries=@(@{PSPath=$hiddenRecord.PSPath},@{PSPath=$registration})
        $record.BundleProviderKey='fixture-provider'
        $record.BundleCachePath=$program+'-other.exe'
        $fixtureSignature=$unknownSigner
        $refused=$false
        try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Registered vendor uninstaller is outside protected installation storage'}
        $cacheMismatchRefused=$refused
        $record.BundleCachePath=$program
        $hiddenRecord.UninstallString='MsiExec.exe /I'+$otherCode
        $refused=$false
        try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Registered WireSock MSI uninstall command does not match its product code'}
        Assert ($cacheMismatchRefused -and $refused -and $calls.Count -eq 0) 'WireSock paired uninstall refuses mismatched cache or MSI identity before cleanup'
        $hiddenRecord.UninstallString='MsiExec.exe /I'+$productCode
        $verifyRemoval=$true
        $result=Uninstall-WireSockProduct
        Assert (-not $result.rebootRequired -and ($calls -join ',') -ceq 'task,profile,uninstall,check-hidden-registration,check-registration,wait,check-hidden-registration,check-registration,retire-ownership,Vendor uninstall completed: WireSock Secure Connect') 'WireSock paired uninstall runs the bundle and waits for the hidden MSI'
        $verifyRemoval=$false
        $calls.Clear()
        $entries=@(@{PSPath=$registration})
        $hiddenRecord=$null
        $record.WindowsInstaller=1
        $record.PSChildName=$productCode
        $expectedProgram=Join-Path $env:SystemRoot 'System32\msiexec.exe'
        $expectedArguments='/x,'+$productCode+',/qn,/norestart'
        $record.UninstallString='MsiExec.exe /I'+$productCode
        $result=Uninstall-WireSockProduct
        Assert ($result.product -ceq 'WireSock Secure Connect' -and ($calls -join ',') -ceq 'task,profile,uninstall') 'WireSock MSI uninstall targets its registered product code'
        $calls.Clear()
        foreach($command in @(
            ('MsiExec.exe /I'+$otherCode),
            ('"C:\other.exe" msiexec /I'+$productCode),
            ('MsiExec.exe /I'+$productCode+' /I'+$otherCode)
        )){
            $record.UninstallString=$command
            $refused=$false
            try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Registered WireSock MSI uninstall command does not match its product code'}
            if(-not $refused){throw 'Unexpected MSI uninstall preflight outcome'}
        }
        Assert ($calls.Count -eq 0) 'WireSock MSI uninstall refuses mismatched or compound commands before cleanup'
        $record.UninstallString='MsiExec.exe /I'+$productCode
        $verifyRemoval=$true
        $result=Uninstall-WireSockProduct
        Assert (-not $result.rebootRequired -and ($calls -join ',') -ceq 'task,profile,uninstall,check-registration,wait,check-registration,retire-ownership,Vendor uninstall completed: WireSock Secure Connect') 'WireSock uninstall waits for the registered package to disappear'
        $calls.Clear()
        $verifyRemoval=$false
        foreach($mode in @('service','cli')){
            $calls.Clear()
            $remainingCLI=$mode -ceq 'cli'
            $remainingService=$mode -ceq 'service'
            $result=Uninstall-WireSockProduct
            if($result.rebootRequired -or ($calls -join ',') -cne 'task,profile,uninstall,wait'){
                throw 'Vendor uninstall did not wait for the remaining resource'
            }
        }
        Assert $true 'WireSock uninstall waits for remaining vendor services and secondary CLI paths'
        $remainingCLI=$false
        $remainingService=$false
        $serviceQueryFails=$true
        $calls.Clear()
        $refused=$false
        try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Vendor service removal could not be verified'}
        Assert ($refused -and -not $calls.Contains('retire-ownership')) 'WireSock uninstall refuses completion when service removal cannot be verified'
        $serviceQueryFails=$false
        $verifyRemoval=$true
        $ownershipRetirementFails=$true
        $calls.Clear()
        $refused=$false
        try {Uninstall-WireSockProduct | Out-Null}catch{$refused=$_.Exception.Message -ceq 'Vendor uninstall completed but the managed ownership record could not be retired'}
        Assert ($refused -and -not $calls.Contains('Vendor uninstall completed: WireSock Secure Connect')) 'WireSock uninstall reports an ownership record that could not be retired'
        $ownershipRetirementFails=$false
        $calls.Clear()
        $requestRestart=$true
        $result=Uninstall-WireSockProduct
        Assert ($result.rebootRequired -and ($calls -join ',') -ceq 'task,profile,uninstall,Vendor uninstall requires a Windows restart: WireSock Secure Connect') 'WireSock uninstall reports restart without claiming verified removal'
    } finally {
        $env:ProgramData=$previousProgramData
        $script:rebootRequired=$previousRebootRequired
    }
}
# Synthetic process records verify session-scoped launch observation without launching an app.
$fixtureApp='C:\fixture\SplitCord.exe'
$otherSession=[pscustomobject]@{Path=$fixtureApp;SessionId=9;HasExited=$false}
$sameSession=[pscustomobject]@{Path=$fixtureApp;SessionId=7;HasExited=$false}
$otherPath=[pscustomobject]@{Path='C:\fixture\Other.exe';SessionId=7;HasExited=$false}
Assert (-not (Test-AppProcessInSession $fixtureApp 7 @($otherSession))) 'App launch ignores matching processes in another session'
Assert (-not (Test-AppProcessInSession $fixtureApp 7 @($otherPath))) 'App launch ignores another executable in the current session'
Assert (Test-AppProcessInSession $fixtureApp 7 @($otherSession,$sameSession)) 'App launch accepts the matching executable in the current session'
$exitedApp=[pscustomobject]@{Path=$fixtureApp;SessionId=7;HasExited=$true}
$unreadableApp=[pscustomobject]@{Path=$fixtureApp;SessionId=7}
$unreadableApp | Add-Member ScriptProperty HasExited {throw 'Synthetic inaccessible process'}
Assert (-not (Test-AppProcessInSession $fixtureApp 7 @($exitedApp,$unreadableApp))) 'App launch requires a live matching process'
# Inert files, process records and command mocks exercise uninstall preflight.
$fixtureAppDirectory=Join-Path $testRoot 'splitcord-uninstall'
[void](New-Item -ItemType Directory -Path $fixtureAppDirectory)
$fixtureApp=Join-Path $fixtureAppDirectory 'SplitCord.exe'
$fixtureUninstaller=Join-Path $fixtureAppDirectory 'Uninstall.exe'
$secondUninstaller=Join-Path $fixtureAppDirectory 'Uninstall-old.exe'
[IO.File]::WriteAllBytes($fixtureApp,[byte[]]@(0))
$previousFindApp=(Get-Command Find-App).ScriptBlock
$previousDesktopGuard=(Get-Command Require-DesktopUser).ScriptBlock
try {
    function Find-App {param($variant);return $fixtureApp}
    function Require-DesktopUser {}
    function Get-Process {param($ErrorAction);return $appStopRecords}
    $fixtureSession=[Diagnostics.Process]::GetCurrentProcess().SessionId
    $script:appStopCalls=0;$script:appStopFailure=$true;$script:externalEffectsPending=$false
    $script:appStopWaits=0
    $script:appStopDisposals=0
    $script:appStopRecord=[pscustomobject]@{Path=$fixtureApp;SessionId=$fixtureSession;Handle=[IntPtr]123;HasExited=$false;ExitObserved=$false}
    $appStopRecords=@($script:appStopRecord)
    $script:appStopRecord | Add-Member ScriptMethod Kill {
        $script:appStopCalls++
        if($script:appStopFailure){throw 'private fixture detail'}
    }
    $script:appStopRecord | Add-Member ScriptMethod Dispose { $script:appStopDisposals++ }
    $script:appStopRecord | Add-Member ScriptMethod WaitForExit {
        param($milliseconds)
        $script:appStopWaits++
        if($milliseconds -ne 5000){throw 'Unexpected exit deadline'}
        return $this.ExitObserved
    }
    $rejected=$false;try{Remove-App 'splitcord'}catch{$rejected=$_.Exception.Message -ceq 'Expected exactly one SplitCord uninstaller'}
    Assert ($rejected -and $script:appStopCalls -eq 0 -and -not $script:externalEffectsPending) 'Application removal leaves processes running when the uninstaller is missing'
    [IO.File]::WriteAllBytes($fixtureUninstaller,[byte[]]@(0))
    [IO.File]::WriteAllBytes($secondUninstaller,[byte[]]@(0))
    $rejected=$false;try{Remove-App 'splitcord'}catch{$rejected=$_.Exception.Message -ceq 'Expected exactly one SplitCord uninstaller'}
    Assert ($rejected -and $script:appStopCalls -eq 0 -and -not $script:externalEffectsPending) 'Application removal leaves processes running when uninstallers are ambiguous'
    [IO.File]::Delete($secondUninstaller)
    $conflictingProcess=[pscustomobject]@{Path=$fixtureApp;SessionId=($fixtureSession+1)}
    $conflictingProcess | Add-Member ScriptMethod Dispose {}
    $appStopRecords=@($script:appStopRecord,$conflictingProcess)
    $rejected=$false
    try {Remove-App 'splitcord'}catch{$rejected=$_.Exception.Message -ceq 'A matching application is running in another Windows session'}
    Assert ($rejected -and $script:appStopCalls -eq 0 -and -not $script:externalEffectsPending) 'Application removal refuses a matching client in another session before stopping any process'
    $conflictingProcess.SessionId=$null
    $rejected=$false
    try {Remove-App 'splitcord'}catch{$rejected=$_.Exception.Message -ceq 'A matching application process session could not be verified'}
    Assert ($rejected -and $script:appStopCalls -eq 0 -and -not $script:externalEffectsPending) 'Application removal refuses an unverified matching session before stopping any process'
    $appStopRecords=@($script:appStopRecord)
    $script:appStopDisposals=0
    $rejected=$false;try{Remove-App 'splitcord'}catch{$rejected=$_.Exception.Message -ceq 'A matching application process could not be stopped; the operation was not continued'}
    Assert ($rejected -and $script:appStopCalls -eq 1 -and $script:externalEffectsPending) 'Application removal stops on a matching process failure and records an external effect'
    $script:appStopCalls=0;$script:appStopFailure=$true;$script:externalEffectsPending=$false
    $script:appStopRecord.HasExited=$true
    Stop-AppProcesses 'splitcord'
    Assert ($script:appStopCalls -eq 1 -and $script:externalEffectsPending) 'Application process exit race remains a recorded external effect'
    $script:appStopCalls=0;$script:appStopFailure=$false;$script:externalEffectsPending=$false
    $script:appStopRecord.HasExited=$false
    $rejected=$false
    try {Remove-App 'splitcord'}catch{$rejected=$_.Exception.Message -ceq 'A matching application process could not be stopped; the operation was not continued'}
    Assert ($rejected -and $script:appStopCalls -eq 1 -and $script:appStopWaits -eq 1 -and $script:externalEffectsPending) 'Application removal refuses an unconfirmed process exit'
    $script:appStopCalls=0;$script:appStopWaits=0;$script:externalEffectsPending=$false
    $script:appStopRecord.ExitObserved=$true
    Stop-AppProcesses 'splitcord'
    Assert ($script:appStopCalls -eq 1 -and $script:appStopWaits -eq 1 -and $script:appStopDisposals -eq 4 -and $script:externalEffectsPending) 'Application process stop records an external effect'
} finally {
    Remove-Item Function:Get-Process
    Set-Item Function:Find-App $previousFindApp;Set-Item Function:Require-DesktopUser $previousDesktopGuard
    $script:externalEffectsPending=$false
}
# Mock installer acquisition and user operations; never execute a vendor process.
$appInstallSaved=@{};foreach($name in @('Require-DesktopUser','Find-App','Remove-App','Download','Native','Wait-App','Event')){$appInstallSaved[$name]=(Get-Command $name).ScriptBlock}
$previousAppRequest=$r
$previousAppInput=$inputData
$previousAppRoot=$root
try {
    $root=Join-Path $testRoot 'app-install-fixture'
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'downloads'))
    $script:appInstallerChanged=$false
    $script:appPreviouslyInstalled=$false
    function Require-DesktopUser {}
    function Find-App {
        param($variant)
        $script:appInstallTrace.Add('find-'+$variant)
        if($variant -ceq 'discord' -or $script:appPreviouslyInstalled){return 'C:\fixture\Discord.exe'}
    }
    function Remove-App {
        param($variant)
        $script:appInstallTrace.Add('remove-stable')
        $script:appInstallerLocked=$false
        try {
            $writer=[IO.File]::OpenWrite($script:appInstallerDestination)
            $writer.Dispose()
        }catch [IO.IOException]{$script:appInstallerLocked=$true}
        if($script:appRemoveFailure){throw 'fixture remove failure'}
    }
    function Download {
        param($Url,$Hash,$Destination,[switch]$Signed,[string]$Publisher,[switch]$ReturnVerifiedHash)
        $script:appInstallTrace.Add('download:'+ $Publisher)
        $script:appDownloadURL=$Url
        if(-not $Signed -or -not $ReturnVerifiedHash){throw 'Expected signed Discord download with verified hash'}
        if($script:appDownloadFailure){throw 'fixture download failure'}
        $script:appInstallerDestination=$Destination
        [IO.File]::WriteAllText($Destination,'inert installer')
        $digest=(Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
        if($script:appInstallerChanged){[IO.File]::AppendAllText($Destination,' changed')}
        return $digest
    }
    function Native {
        param($Program,$Arguments,$Timeout)
        $script:appInstallTrace.Add('installer')
        $script:appInstallerLockedAtLaunch=$false
        try {
            $writer=[IO.File]::OpenWrite($Program)
            $writer.Dispose()
        }catch [IO.IOException]{$script:appInstallerLockedAtLaunch=$true}
        return @{exitCode=0;outputComplete=$true}
    }
    function Wait-App {param($variant,$installed,$seconds);$script:appInstallTrace.Add('verify-ptb')}
    function Event {param($text);$script:appInstallTrace.Add('event')}
    $r=[pscustomobject]@{clean=$true;sha256=''}
    $inputData=[pscustomobject]@{nativeArchitecture='amd64'}
    $script:appInstallTrace=[Collections.Generic.List[string]]::new();$script:appDownloadFailure=$true;$script:appRemoveFailure=$false
    $rejected=$false;try{Install-App 'discord-ptb'}catch{$rejected=$true}
    Assert ($rejected -and (($script:appInstallTrace -join ',') -ceq 'download:discord')) 'PTB clean download failure preserves the existing client'
    $script:appInstallTrace=[Collections.Generic.List[string]]::new();$script:appDownloadFailure=$false;$script:appRemoveFailure=$false
    $installed=Install-App 'discord-ptb'
    Assert (($script:appInstallTrace -join ',') -ceq 'download:discord,find-discord-ptb,find-discord,remove-stable,installer,verify-ptb,event') 'PTB clean stages the replacement before removing the existing client'
    $writer=[IO.File]::OpenWrite($script:appInstallerDestination)
    $writer.Dispose()
    Assert ($script:appInstallerLocked -and $script:appInstallerLockedAtLaunch) 'PTB clean retains a read-only installer handle through removal and launch'
    $script:appInstallTrace.Clear()
    $script:appInstallerChanged=$true
    $rejected=$false
    try {Install-App 'discord-ptb'}catch{$rejected=$_.Exception.Message -ceq 'Staged application installer differs from the verified download'}
    Assert ($rejected -and ($script:appInstallTrace -join ',') -ceq 'download:discord') 'PTB clean refuses a changed staged installer before removing the existing client'
    $script:appInstallerChanged=$false
    $script:appInstallTrace=[Collections.Generic.List[string]]::new();$script:appDownloadFailure=$false;$script:appRemoveFailure=$true
    $rejected=$false;try{Install-App 'discord-ptb'}catch{$rejected=$true}
    Assert ($rejected -and (($script:appInstallTrace -join ',') -ceq 'download:discord,find-discord-ptb,find-discord,remove-stable')) 'PTB clean removal failure prevents installer execution'
    $r.clean=$false
    $script:appRemoveFailure=$false
    foreach($case in @(
        @{arch='amd64';variant='discord';query='channel=stable&platform=win&arch=x64'},
        @{arch='arm64';variant='discord';query='channel=stable&platform=win&arch=arm64'},
        @{arch='arm64';variant='discord-ptb';query='channel=ptb&platform=win&arch=x64'}
    )){
        $script:appInstallTrace.Clear()
        $inputData.nativeArchitecture=$case.arch
        [void](Install-App $case.variant)
        $expectedURL='https://discord.com/api/downloads/distributions/app/installers/latest?'+$case.query
        $expectedTrace='download:discord,find-'+$case.variant+',installer,verify-ptb,event'
        if($script:appDownloadURL -cne $expectedURL -or ($script:appInstallTrace -join ',') -cne $expectedTrace){
            throw 'Unexpected Discord installer architecture selection'
        }
    }
    Assert $true 'Discord selects a native stable installer and retains the PTB x64 distribution'
    $script:appPreviouslyInstalled=$true
    $existing=Install-App 'discord-ptb'
    Assert ($installed.installed -eq $true -and $installed.previouslyInstalled -eq $false -and
        $existing.application -ceq 'discord-ptb' -and $existing.installed -eq $true -and $existing.previouslyInstalled -eq $true) 'Application setup distinguishes a newly observed installation from an existing one'
    $inputData.nativeArchitecture=''
    $r.clean=$true
    $script:appInstallTrace.Clear()
    $rejected=$false
    try {Install-App 'discord-ptb'}catch{$rejected=$_.Exception.Message -ceq 'Native Windows architecture is unavailable or unsupported for Discord installation'}
    Assert ($rejected -and $script:appInstallTrace.Count -eq 0) 'Discord refuses unknown architecture before download or client removal'
} finally {
    foreach($name in $appInstallSaved.Keys){Set-Item ('Function:'+ $name) $appInstallSaved[$name]}
    $r=$previousAppRequest
    $inputData=$previousAppInput
    $root=$previousAppRoot
}
# Exercise official release selection with fixed metadata and no vendor execution.
& {
    $r=[pscustomobject]@{sha256=''}
    $url='https://github.com/cagritaskn/SplitCord-Turkey/releases/download/1.0.4/SplitCord-Turkey-Setup-1.0.4.exe'
    $asset=@{name='SplitCord-Turkey-Setup-1.0.4.exe';state='uploaded';browser_download_url=$url;digest=('sha256:'+('a'*64))}
    $decoy=@{name='SplitCord-Setup-extra.exe';state='uploaded';browser_download_url='https://outside.invalid/setup.exe'}
    $release=@{tag_name='1.0.4';draft=$false;prerelease=$false;assets=@($decoy,$asset)}
    function Read-RemoteJSON {
        param($Uri,$Headers)
        if($Uri -cne 'https://api.github.com/repos/cagritaskn/SplitCord-Turkey/releases/latest'){throw 'Unexpected SplitCord metadata request'}
        return $release
    }
    $selected=Get-SplitCordInstaller
    Assert ($selected.url -ceq $url -and $selected.hash -ceq ('a'*64)) 'SplitCord selects the exact uploaded setup asset for the release tag'
    foreach($case in @(
        @{assets=@($asset,$asset);message='Expected one uploaded SplitCord installer for the selected release'},
        @{assets=@(@{name=$asset.name;state='starter';browser_download_url=$url});message='Expected one uploaded SplitCord installer for the selected release'},
        @{assets=@(@{name=$asset.name;state='uploaded';browser_download_url=($url -replace '/1\.0\.4/','/1.0.3/')});message='SplitCord installer URL does not match the selected release'}
    )){
        $release.assets=$case.assets
        $refused=$false
        try {Get-SplitCordInstaller | Out-Null}catch{$refused=$_.Exception.Message -ceq $case.message}
        if(-not $refused){throw 'Unexpected SplitCord asset refusal'}
    }
    Assert $true 'SplitCord refuses duplicate pending and wrong-release setup assets'
    $release.assets=@($asset)
    $r.sha256='b'*64
    $refused=$false
    try {Get-SplitCordInstaller | Out-Null}catch{$refused=$_.Exception.Message -ceq 'SplitCord installer digest conflicts with the requested SHA-256'}
    $asset.digest='sha256:bad'
    $malformed=$false
    try {Get-SplitCordInstaller | Out-Null}catch{$malformed=$_.Exception.Message -ceq 'SplitCord installer digest is invalid'}
    $asset.digest=$null
    $selected=Get-SplitCordInstaller
    $fallbackMatched=$selected.hash -ceq $r.sha256
    $r.sha256=''
    $missing=$false
    try {Get-SplitCordInstaller | Out-Null}catch{$missing=$_.Exception.Message -ceq 'SplitCord installer requires a published or explicitly supplied SHA-256'}
    Assert ($refused -and $malformed -and $fallbackMatched -and $missing) 'SplitCord checks the release digest and retains explicit hash fallback'
}
# Exercise both direct helper calls and the dispatcher before any real OS work.
$desktopGuard=(Get-Command Require-DesktopUser).ScriptBlock
$machineInitializer=(Get-Command Initialize-Changes).ScriptBlock
try{
    function Require-DesktopUser {throw 'blocked desktop token fixture'}
    foreach($helper in @('Install-App','Remove-App','Start-App')){
        $rejected=$false;try{& $helper 'discord'}catch{$rejected=$_.Exception.Message -eq 'blocked desktop token fixture'}
        Assert $rejected ($helper+' rejects an unsafe token before discovery or execution')
    }
    $script:machineInitializationCount=0
    function Initialize-Changes {$script:machineInitializationCount++}
    $r=[pscustomobject]@{action='app-repair'}
    $rejected=$false;try{Initialize-Operation}catch{$rejected=$_.Exception.Message -match 'privilege-separated'}
    Assert ($rejected -and $script:machineInitializationCount -eq 0) 'Combined repair blocked before privileged initialization'
    $inputData=[pscustomobject]@{resultPath=(Join-Path $testRoot 'user-job\result.json')}
    foreach($action in @('app-install','app-remove','app-start')){
        $r=[pscustomobject]@{action=$action;dns='unchanged'}
        $rejected=$false;try{Initialize-Operation}catch{$rejected=$_.Exception.Message -eq 'blocked desktop token fixture'}
        Assert ($rejected -and -not (Test-Path (Join-Path $testRoot 'user-job'))) ($action+' checks the token before staging files')
    }
    function Require-DesktopUser {}
    $r=[pscustomobject]@{action='app-install';dns='doh'}
    $rejected=$false;try{Initialize-Operation}catch{$rejected=$_.Exception.Message -match 'DNS separately'}
    Assert ($rejected -and -not (Test-Path (Join-Path $testRoot 'user-job'))) 'User application dispatch rejects system DNS changes before staging'
    $r=[pscustomobject]@{action='app-install';dns='unchanged'}
    Initialize-Operation
    Assert ($root -eq (Join-Path $testRoot 'user-job\application') -and $script:machineInitializationCount -eq 0 -and (Test-Path -LiteralPath $script:journalPath)) 'User application staging and journal avoid machine storage'
}finally{
    Set-Item Function:Require-DesktopUser $desktopGuard
    Set-Item Function:Initialize-Changes $machineInitializer
    $root=$testRoot;$script:journalPath=$null
}
$descriptor=Private-DirectorySecurity
Assert (Trusted-SecurityDescriptor $descriptor) 'Administrator-owned private storage descriptor accepted'
$descriptor.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
Assert (-not (Trusted-SecurityDescriptor $descriptor)) 'Unprivileged owner rejected even with a private DACL'
$descriptor=Private-DirectorySecurity
$descriptor.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Read','Allow'))
Assert (-not (Trusted-SecurityDescriptor $descriptor)) 'Explicit nonprivileged descendant access rejected'
Assert (Under (Join-Path $root 'components\file') $root) 'Contained paths accepted'
Assert (-not (Under (Join-Path $root '..\escape') $root)) 'Parent path escape rejected'
Assert (-not (Under ($root+'-sibling\file') $root)) 'Sibling prefix rejected'
Assert ((Quote-Arg 'with spaces') -eq '"with spaces"') 'Windows argument quoting preserves spaces'
Assert ((Quote-Arg '') -eq '""') 'Empty Windows argument preserved'
foreach($value in @('help','run','--help','/Query','safe=value','trailing\')){Assert ((Native-Argument $value) -ceq $value) 'Simple native verbs and switches remain unquoted for raw-command-line CLIs'}
foreach($value in @('with spaces','','quote"inside','literal&|<>^%!,;',('help'+[char]10),('non-ascii-'+[char]0x00e9))){Assert ((Native-Argument $value) -ceq (Quote-Arg $value)) 'Complex native argument values retain literal Windows escaping'}
$node=(Get-Command node -ErrorAction Stop).Source
$native=Native $node @('-e','process.stdout.write(JSON.stringify(process.argv.slice(1)))','with spaces','','trailing\','quote"inside','help','--flag=value','literal&|<>^%!,;','hyphen-name')
$nativeArgs=$native.stdout|ConvertFrom-Json
Assert ($nativeArgs.Count -eq 8 -and $nativeArgs[0] -eq 'with spaces' -and $nativeArgs[1] -eq '' -and $nativeArgs[2] -eq 'trailing\' -and $nativeArgs[3] -eq 'quote"inside' -and $nativeArgs[4] -ceq 'help' -and $nativeArgs[5] -ceq '--flag=value' -and $nativeArgs[6] -ceq 'literal&|<>^%!,;' -and $nativeArgs[7] -ceq 'hyphen-name') 'Native processes receive literal Windows arguments without shell evaluation'
Assert $native.outputComplete 'Ordinary native output reaches EOF'
$clock=[Diagnostics.Stopwatch]::StartNew()
[void](Native $node @('-e','require("child_process").spawn(process.execPath,["-e","setTimeout(()=>{},12000)"],{stdio:"inherit"});process.exit(0)'))
Assert ($clock.Elapsed.TotalSeconds -lt 10) 'Exited installer does not wait for a GUI child holding inherited output pipes'
# Real disposable children exercise cleanup independently of OS utility success.
# The failed/timed-out helper must stop the held parent and retain uncertainty.
foreach($mode in @('success','start-failure','failure','timeout')){
    $parent=[Diagnostics.Process]::new();$helper=[Diagnostics.Process]::new()
    $parent.StartInfo=[Diagnostics.ProcessStartInfo]::new()
    $parent.StartInfo.FileName=$node;$parent.StartInfo.Arguments='-e '+(Quote-Arg 'setTimeout(()=>{},60000)')
    $parent.StartInfo.UseShellExecute=$false;$parent.StartInfo.CreateNoWindow=$true
    $helper.StartInfo=[Diagnostics.ProcessStartInfo]::new()
    $helper.StartInfo.FileName=$node;$helper.StartInfo.UseShellExecute=$false;$helper.StartInfo.CreateNoWindow=$true
    $helper.StartInfo.RedirectStandardInput=$true;$helper.StartInfo.RedirectStandardOutput=$true;$helper.StartInfo.RedirectStandardError=$true
    try {
        [void]$parent.Start()
        $code=switch($mode){
            'success' {'process.kill('+ $parent.Id +');'}
            'failure' {'process.exit(23)'}
            'timeout' {'process.stdout.write("x".repeat(1024*1024));process.stderr.write("y".repeat(1024*1024));setTimeout(()=>{},60000)'}
        }
        $helper.StartInfo.Arguments='-e '+(Quote-Arg $code)
        if($mode -eq 'start-failure'){$helper.StartInfo.FileName=Join-Path $testRoot 'nonexistent-termination-helper.exe'}
        $clock=[Diagnostics.Stopwatch]::StartNew();$rejected=$false
        try{Stop-ToolTreeWithHelper $parent $helper -TimeoutMilliseconds 2000}catch{
            if($_.Exception.Message -notmatch 'tree cleanup is unconfirmed'){throw}
            $rejected=$true
        }
        Assert ($rejected -eq ($mode -ne 'success')) ('Tree cleanup preserves helper outcome: '+$mode)
        Assert ($clock.Elapsed.TotalSeconds -lt 8 -and $parent.HasExited -and ($mode -eq 'start-failure' -or $helper.HasExited)) ('Tree cleanup is bounded and stops both owned processes: '+$mode)
    } finally {
        foreach($child in @($helper,$parent)){
            try{if(-not $child.HasExited){$child.Kill();[void]$child.WaitForExit(2000)}}catch{}finally{$child.Dispose()}
        }
    }
}
$native=Native $node @('-e','process.stdout.write("out");process.stderr.write("err")') -Secret
Assert ($native.stdout -eq 'out' -and $native.stderr -eq 'err' -and $native.outputComplete) 'Both native output streams are drained completely'
foreach($stream in @('stdout','stderr')){
    $clock=[Diagnostics.Stopwatch]::StartNew();$rejected=$false
    $pidFile=Join-Path $testRoot ($stream+'-overflow.pid')
    try{Native $node @('-e',('require("fs").writeFileSync(process.argv[1],String(process.pid));process.'+$stream+'.write("x".repeat(5*1024*1024));setTimeout(()=>{},60000)'),$pidFile) -Timeout 15 -Secret|Out-Null}catch{$rejected=$_.Exception.Message -match 'capture limit'}
    Assert ($rejected -and $clock.Elapsed.TotalSeconds -lt 12) ($stream+' overflow stops the tool promptly and fails without retaining truncated success')
    $toolPid=[int][IO.File]::ReadAllText($pidFile)
    Assert (-not (Get-Process -Id $toolPid -ErrorAction SilentlyContinue)) ($stream+' overflow leaves no running fixture tool')
}
$native=Native $node @('-e','process.stdout.write("x".repeat(4*1024*1024));process.stderr.write("y".repeat(4*1024*1024))') -Secret
Assert ($native.stdout.Length -eq 4MB -and $native.stderr.Length -eq 4MB -and $native.outputComplete) 'Both streams accept their exact capture limit without truncation or deadlock'
$rejected=$false;try{Native $node @('-e','setTimeout(()=>{},60000)') -Timeout 1 -Secret|Out-Null}catch{$rejected=$_.Exception.Message -match 'Timed out'}
Assert $rejected 'A silent native tool still observes its timeout'
$rejected=$false;try{Native $node @('-e','process.exit(23)') -Secret|Out-Null}catch{$rejected=$_.Exception.Message -match 'exit 23'}
Assert $rejected 'Native failure exit codes are preserved'
[void](Native $node @('-e','process.exit(0)') -Timeout 86400 -Secret)
Assert $true 'One-shot tool timeout remains accepted without waiting for the deadline'
foreach($arg in @('--i=0.0.0.0','--po=9999','--dae','--service','--trans','-Ui0.0.0.0','-D','--','@options.txt')){
    $rejected=$false;try{Assert-ByeDPIArguments @($arg)}catch{$rejected=$_.Exception.Message -match 'reserves listener/process'}
    Assert $rejected ('Reserved installer argument rejected: '+$arg)
}
Assert-ByeDPIArguments @('--split','2','--disorder','--comment','ordinary text','','--comment','')
Assert $true 'Full strategy options and values remain accepted'
$originalConfigureDNS=(Get-Command Configure-DNS).ScriptBlock
try{
    function Configure-DNS {throw 'DNS must not run before argument validation'}
    $r=[pscustomobject]@{engine='byedpi';args=@('--i=0.0.0.0');dns='doh'}
    $rejected=$false;try{Install-Method}catch{$rejected=$_.Exception.Message -match 'reserves listener/process'}
    Assert $rejected 'Direct installer rejects reserved arguments before DNS or component changes'
}finally{Set-Item Function:Configure-DNS $originalConfigureDNS}
$r=[pscustomobject]@{applications=@('custom.exe','C:\Apps\Custom');browsers=$true}
$apps=@(Application-Names)
Assert ($apps -contains 'custom.exe' -and $apps -contains 'chrome.exe' -and $apps -contains 'Discord.exe') 'Default, custom and browser application rules compiled'
$packet=@(Packet-Arguments 'zapret2' @('--payload=tls_client_hello','--lua-desync=multidisorder:pos=2'))
Assert ($packet -contains '--wf-tcp-out=80,443') 'Strategy-only ISP presets receive a Windows packet capture filter'
$packet=@(Packet-Arguments 'zapret2' @('--wf-tcp-out=80','--lua-desync=oob:urp=0'))
Assert (@($packet|Where-Object {$_ -like '--wf-tcp*'}).Count -eq 1 -and $packet[0] -eq '--wf-tcp-out=80') 'An explicitly selected capture filter is preserved'
foreach($url in @('http://github.com/hufrea/byedpi/releases/download/v1/file.zip','https://evil.invalid/tool.exe','https://github.com/attacker/byedpi/releases/download/v1/file.zip','https://github.com/hufrea/byedpi/blob/main/tool.exe')){$rejected=$false;try{Allowed-Download $url}catch{$rejected=$true};Assert $rejected ('Unapproved URL rejected: '+$url)}
Allowed-Download 'https://github.com/hufrea/byedpi/releases/download/v0.17.3/byedpi.zip'
Assert $true 'Official release URL accepted'
$file=Join-Path $root 'managed.txt';[IO.File]::WriteAllText($file,'original')
Write-Atomic $file 'replacement';Write-Atomic $file 'replacement again'
Assert ((Get-Content -LiteralPath $file -Raw) -eq 'replacement again') 'Atomic replacement works for an existing file'
Assert ($script:undo.Count -eq 1) 'Original file backed up only once per transaction'
$newFile=Join-Path $root 'new.txt';Write-Atomic $newFile 'new'
$errors=@(Rollback)
Assert ($errors.Count -eq 0) 'Rollback completed without errors'
Assert ((Get-Content -LiteralPath $file -Raw) -eq 'original') 'Rollback restores original bytes'
Assert (-not (Test-Path -LiteralPath $newFile)) 'Rollback removes newly created files'
$script:undo.Clear();Write-Atomic $file 'installed';[IO.File]::WriteAllText($file,'changed outside operation')
$conflicts=@(Rollback)
Assert ($conflicts.Count -eq 1 -and (Get-Content -LiteralPath $file -Raw) -eq 'changed outside operation') 'Recovery refuses to overwrite independently changed files'
$script:undo.Clear();Write-Atomic $file 'installed with backup'
$backup=$script:undo[0].backup;[IO.File]::WriteAllText($backup,'corrupted recovery data')
$conflicts=@(Rollback)
Assert ($conflicts.Count -eq 1 -and (Get-Content -LiteralPath $file -Raw) -eq 'installed with backup') 'Recovery refuses a backup whose bytes differ from the recorded original digest'
$script:undo.Clear()
$source=Join-Path $root 'source.conf';[IO.File]::WriteAllText($source,"[Interface]`nPrivateKey = fixture-only`n[Peer]`nPublicKey = fixture-only`nEndpoint = example.invalid:2408`nAllowedApps = old.exe`n")
[void](New-Item -ItemType Directory -Force -Path (Join-Path $root 'profiles'))
$r=[pscustomobject]@{profileId='test-profile';configPath=$source;applications=@('custom.exe');browsers=$false}
$config=Make-Config;$text=Get-Content -LiteralPath $config -Raw
Assert ($text -match 'custom.exe' -and $text -notmatch 'old.exe') 'WireSock application policy replaces original selection in a private generated copy'
Assert ((Get-Content -LiteralPath $source -Raw) -match 'old.exe') 'Original WireGuard config remains unchanged'
$multiPeer=@"
[Interface]
PrivateKey = fixture-only

[Peer]
PublicKey = fixture-first
AllowedIPs = 192.0.2.0/24
#@ws:AllowedApps = old-prefixed.exe
#@ws: DisallowedApps = custom.exe
#@ws:DisallowedIPs = 192.0.2.1/32

[Peer]
PublicKey = fixture-second
AllowedIPs = 2001:db8::/32
DisallowedApps = old-direct.exe
# An ordinary comment about AllowedApps stays
"@
[IO.File]::WriteAllText($source,$multiPeer+"`n")
$text=Get-Content -LiteralPath (Make-Config) -Raw
$peerSections=@([regex]::Split($text,'(?m)(?=^\[Peer\])') | Where-Object {$_ -match '^\[Peer\]'})
$badPeers=@($peerSections | Where-Object {
    [regex]::Matches($_,'(?m)^AllowedApps[ \t]*=').Count -ne 1 -or $_ -notmatch '(?m)^AllowedApps = [^\r\n]*\bcustom\.exe\b'
})
$staleRule='(?im)^[ \t]*(?:DisallowedApps|#@ws:[ \t]*(?:AllowedApps|DisallowedApps))[ \t]*='
Assert ($peerSections.Count -eq 2 -and $badPeers.Count -eq 0 -and $text -notmatch $staleRule -and $text -notmatch 'old-prefixed\.exe|old-direct\.exe') 'WireSock replaces plain and prefixed application rules in every peer'
Assert ($text.Contains('#@ws:DisallowedIPs = 192.0.2.1/32') -and $text.Contains('# An ordinary comment about AllowedApps stays') -and [IO.File]::ReadAllText($source) -ceq ($multiPeer+"`n")) 'WireSock retains other peer rules and the original configuration'
[IO.File]::AppendAllText($source,"PostUp = arbitrary-command`n")
$rejected=$false;try{Make-Config|Out-Null}catch{$rejected=$true}
Assert $rejected 'WireGuard command hooks rejected'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=Join-Path $root 'traversal.zip';$zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
$entry=$zip.CreateEntry('../escape.txt');$writer=[IO.StreamWriter]::new($entry.Open());$writer.Write('bad');$writer.Dispose();$zip.Dispose()
$rejected=$false;try{Expand-Safe $archive (Join-Path $root 'extracted')}catch{$rejected=$true}
Assert $rejected 'Archive traversal rejected before extraction'
# Independent CPython ZIP/ZIP64 and malformed-metadata fixtures remain inert.
$archiveFixtures=Join-Path $testRoot 'component-archives'
& python (Join-Path $PSScriptRoot 'fixtures\component_archives.py') $archiveFixtures
Assert ($LASTEXITCODE -eq 0) 'Independent archive fixture generation succeeds without vendor execution'
$archiveCases=Get-Content -LiteralPath (Join-Path $archiveFixtures 'cases.json') -Raw | ConvertFrom-Json
$archiveUndo=$script:undo;$archiveJournal=$script:journalPath
try {
    $script:journalPath=$null
    foreach($case in $archiveCases){
        $script:undo=[Collections.Generic.List[object]]::new()
        $destination=Join-Path $archiveFixtures ([IO.Path]::GetFileNameWithoutExtension($case.name)+'-output')
        [void][IO.Directory]::CreateDirectory($destination)
        $original=Join-Path $destination 'root.txt';[IO.File]::WriteAllText($original,'original')
        $rejected=$false
        try{Expand-Safe (Join-Path $archiveFixtures $case.name) $destination}catch{if($case.expected -eq 'valid'){throw};$rejected=$true}
        if($case.expected -eq 'valid'){
            Assert (-not $rejected -and [IO.File]::ReadAllText($original) -ceq 'replacement') ($case.name+' extracts a valid archive and replaces only its planned file')
            foreach($record in $script:undo){Assert ($record.expectedHash -eq (Get-FileHash -LiteralPath $record.path -Algorithm SHA256).Hash) 'Archive journal records the actual streamed file hash'}
            $errors=@(Rollback)
            Assert ($errors.Count -eq 0 -and [IO.File]::ReadAllText($original) -ceq 'original') ($case.name+' restores the original file through the existing recovery journal')
        }else{
            Assert ($rejected -and [IO.File]::ReadAllText($original) -ceq 'original') ($case.name+' is rejected without replacing the original file')
            Assert (@(Get-ChildItem -LiteralPath $destination -Recurse -File | Where-Object {$_.FullName -ine $original}).Count -eq 0) ($case.name+' leaves no payload or extraction-temporary file')
        }
        Assert (@(Get-ChildItem -LiteralPath $destination -Recurse -File -Filter '.accessweaver-extract-*.tmp').Count -eq 0) 'Archive extraction always removes its owned staging file'
    }
} finally {$script:undo=$archiveUndo;$script:journalPath=$archiveJournal}

$previousAppData=$env:APPDATA
try{
    $env:APPDATA=Join-Path $testRoot 'fake-appdata';$cache=Join-Path $env:APPDATA 'discord';[void](New-Item -ItemType Directory -Force -Path $cache)
    [IO.File]::WriteAllText((Join-Path $cache 'cache.txt'),'original session fixture')
    $script:undo.Clear();Preserve-DiscordCache;$recovery=@(Rollback)
    Assert ($recovery.Count -eq 0 -and [IO.File]::ReadAllText((Join-Path $cache 'cache.txt')) -eq 'original session fixture') 'Failed repair can restore the preserved original cache'
    $script:undo.Clear();Preserve-DiscordCache;[void](New-Item -ItemType Directory -Path $cache);[IO.File]::WriteAllText((Join-Path $cache 'cache.txt'),'new session fixture')
    $recovery=@(Rollback)
    Assert ($recovery.Count -eq 1 -and [IO.File]::ReadAllText((Join-Path $cache 'cache.txt')) -eq 'new session fixture') 'Repair recovery preserves newly created cache and retains the original backup'
}finally{$env:APPDATA=$previousAppData;$script:undo.Clear()}
Write-Output 'Windows workflow contract tests completed. Test artifacts are under build/.'

# Run the current isolated DNS contracts in a fresh stock shell. The older
# inline mock predates per-family inventory and could not model readback.
$dnsShell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
& $dnsShell -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'test-dns-recovery-contracts.ps1') -RequireWindowsPowerShell | Out-Null
Assert ($LASTEXITCODE -eq 0) 'Dedicated DNS recovery contracts pass in an isolated stock shell'
$downloadFixtureOut=@()
$downloadFixtureExit=-1
$downloadSavedErrorPreference=$ErrorActionPreference
try {
    # Windows PowerShell can turn redirected native stderr into error records.
    # Keep the child exit code authoritative while suppressing private details.
    $ErrorActionPreference='Continue'
    $downloadFixtureOut=@(& $dnsShell -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'test-windows-component-downloads.ps1') -RequireWindowsPowerShell 2>$null)
    $downloadFixtureExit=$LASTEXITCODE
} finally {
    $ErrorActionPreference=$downloadSavedErrorPreference
}
$downloadStages=@(
    @('STAGE-ENTRY-PASS','Component download fixture entered'),
    @('STAGE-SOURCE-PARSE-PASS','Component download source parsed'),
    @('STAGE-DEFINITION-5-PASS','Component download first five definitions loaded'),
    @('STAGE-DEFINITION-10-PASS','Component download first ten definitions loaded'),
    @('STAGE-DEFINITION-15-PASS','Component download first fifteen definitions loaded'),
    @('STAGE-DEFINITION-20-PASS','Component download first twenty definitions loaded'),
    @('STAGE-DEFINITION-25-PASS','Component download first twenty-five definitions loaded'),
    @('STAGE-DEFINITIONS-PASS','Component download definitions fixture completed'),
    @('STAGE-STREAM-PASS','Component download stream fixture completed'),
    @('STAGE-COMPOSITION-PASS','Component download composition fixture completed'),
    @('STAGE-METADATA-PASS','Component download metadata fixture completed'),
    @('STAGE-REDIRECT-POLICY-PASS','Component redirect policy fixture completed'),
    @('STAGE-DOTNET-HOPS-PASS','Component .NET redirect fixture completed'),
    @('STAGE-CURL-OWNER-PASS','Component curl owner fixture completed'),
    @('STAGE-CURL-HOPS-PASS','Component curl redirect fixture completed')
)
foreach($stage in $downloadStages){if(@($downloadFixtureOut | Where-Object {$_ -ceq $stage[0]}).Count -eq 1){Write-Output ('PASS '+$stage[1])}else{Write-Output ('FAIL '+$stage[1])}}
Assert ($downloadFixtureExit -eq 0) 'Dedicated component download contracts pass in an isolated stock shell'

$oldInputData=$inputData
$inputData=[pscustomobject]@{managedPolicy=$true;allowDownloads=$false}
foreach($operation in @('release','download')){
    $rejected=$false
    try{if($operation -eq 'release'){Read-RemoteJSON -Uri 'https://invalid.invalid/not-called' -Headers @{}}else{Download 'https://invalid.invalid/not-called' '' 'not-written'}}catch{$rejected=$_.Exception.Message -match 'Administrator policy'}
    Assert $rejected ('Managed '+$operation+' blocked before any network or file operation')
}
$inputData=[pscustomobject]@{managedPolicy=$true;allowDownloads=$true}
Require-DownloadPermission
Assert $true 'Explicit managed download permission accepted without performing a request'
$inputData=[pscustomobject]@{managedPolicy=$false;allowDownloads=$false}
Require-DownloadPermission
Assert $true 'Unmanaged download behavior preserved'
$inputData=$oldInputData

$pinURL='https://github.com/hufrea/byedpi/releases/download/v-test/fixture.zip'
$pinHash=('a'*64)
$inputData=[pscustomobject]@{managedPolicy=$true;allowDownloads=$true;downloads=@(@{url=$pinURL;sha256=$pinHash})}
Assert ((Approved-DownloadHash $pinURL '') -eq $pinHash) 'Managed download uses administrator hash even when release metadata omits it'
$rejected=$false;try{Approved-DownloadHash $pinURL ('b'*64)|Out-Null}catch{$rejected=$_.Exception.Message -match 'conflicts with administrator policy'}
Assert $rejected 'Remote release metadata cannot replace the administrator artifact hash'
$rejected=$false;try{Download ($pinURL+'-unapproved') $pinHash 'not-written'}catch{$rejected=$_.Exception.Message -match 'Administrator policy does not pin'}
Assert $rejected 'An unpinned component is blocked before a network request'
$inputData=$oldInputData

$archiveRoot=Join-Path $root 'archive-fixture'
foreach($url in @('https://github.com/hufrea/byedpi/releases/download/v-test/component.zip','https://github.com/hufrea/byedpi/releases/download/v-test/..%2F..%2Foutside.zip')){
    $target=Component-ArchivePath $archiveRoot $url
    Assert ((Under $target $archiveRoot) -and [IO.Path]::GetFileName($target) -match '^asset-[a-f0-9]{32}\.zip$') 'Component metadata cannot select the staging filename or escape its directory'
}


# Scheduled-task inspection remains read-only, bounded and language-independent.
$previousTaskNative=(Get-Command Native).ScriptBlock
try {
    $script:taskQueryCalls=[Collections.Generic.List[object]]::new()
    function Native([string]$program,[string[]]$arguments=@(),[int[]]$codes=@(0),[switch]$Secret,[int]$Timeout=600) {
        $script:taskQueryCalls.Add(@{program=$program;arguments=@($arguments);codes=@($codes);secret=[bool]$Secret;timeout=$Timeout})
        if($script:taskQueryMode -eq 'denied'){throw 'PRIVATE_TASK_QUERY_DETAIL'}
        if($script:taskQueryMode -eq 'timeout'){throw 'Timed out: PRIVATE_TASK_QUERY_DETAIL'}
        $exit=if($script:taskQueryMode -eq 'absent'){-2147024894}elseif($script:taskQueryMode -eq 'unexpected'){1}else{0}
        return @{exitCode=$exit;outputComplete=($script:taskQueryMode -ne 'incomplete');stdout='PRIVATE_TASK_QUERY_DETAIL';stderr='PRIVATE_TASK_QUERY_DETAIL'}
    }
    foreach($mode in @('present','absent','denied','timeout','unexpected','incomplete')) {
        $script:taskQueryMode=$mode
        $inspection=Get-RefreshTaskInspection
        if($mode -eq 'present'){Assert ($inspection.present -eq $true -and $null -eq $inspection.error) 'Task inspection reports a successful query as present'}
        elseif($mode -eq 'absent'){Assert ($inspection.present -eq $false -and $null -eq $inspection.error) 'Task inspection reports only the file-not-found HRESULT as absent'}
        else{Assert ($null -eq $inspection.present -and -not [string]::IsNullOrWhiteSpace($inspection.error)) ($mode+' task inspection remains explicitly unknown')}
        Assert (($inspection|ConvertTo-Json) -notmatch 'PRIVATE_TASK_QUERY_DETAIL') 'Task inspection omits command output and private exception details'
    }
    foreach($call in $script:taskQueryCalls) {
        Assert ($call.program -eq (Join-Path $env:SystemRoot 'System32\schtasks.exe')) 'Task inspection uses the absolute trusted native utility'
        Assert (($call.arguments -join '|') -eq '/Query|/TN|\AccessWeaver-WireSock-Refresh|/FO|CSV|/NH|/HRESULT') 'Task inspection queries only the fixed local task with HRESULT result codes'
        Assert ($call.timeout -eq 5 -and $call.secret -and ($call.codes -join ',') -eq '0,-2147024894') 'Task inspection bounds execution and suppresses query output'
    }
}finally{Set-Item Function:Native $previousTaskNative}
