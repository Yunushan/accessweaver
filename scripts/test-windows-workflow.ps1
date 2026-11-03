# Local filesystem and pure-function contract tests. No services, drivers,
# application installs or network settings are changed by this test script.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
foreach($file in @('test-windows-vendor-preflight.ps1','test-windows-integration.ps1','build-windows-installer.ps1','test-windows-installer.ps1','test-windows-installer-contracts.ps1','windows-installer-common.ps1','build-windows-fixtures.ps1','test-windows-apps.ps1','test-windows-wiresock.ps1','test-windows-reboot.ps1','test-windows-storage.ps1','test-windows-uiaccess.ps1','vmware-test-bootstrap.ps1','vmware-reboot-resume.ps1')){$tokens=$null;$issues=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$tokens,[ref]$issues);if($issues.Count){throw ($issues|Out-String)}}
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
    function Get-AuthenticodeSignature {param($LiteralPath);$script:prerequisiteCalls.Add(@{kind='signature';path=$LiteralPath});return @{Status=$script:prerequisiteSignature}}
    function Read-RemoteJSON {param($Headers,$Uri);$script:prerequisiteCalls.Add(@{kind='release';url=$Uri});return @{assets=$script:prerequisiteAssets}}
    function Download {param($url,$hash,$destination,[switch]$Signed);$script:prerequisiteCalls.Add(@{kind='download';url=$url;hash=$hash});Copy-Item -LiteralPath $script:prerequisiteDownloadFixture -Destination $destination -Force}
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
        Assert ($launch.Count -eq 1 -and $launch[0].arguments[1].EndsWith('.'+$platform+'.msi',[StringComparison]::OrdinalIgnoreCase) -and $launch[0].program -eq 'msiexec.exe' -and ($launch[0].codes -join ',') -eq '0,3010,1641') ($architecture+' bundle selects only its platform and preserves reboot exit codes')
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
    $rejected=$false;try{Prerequisite-Plan 'unknown'|Out-Null}catch{$rejected=$_.Exception.Message -eq 'Unknown prerequisite component'}
    Assert $rejected 'Unknown prerequisite names cannot fall back to Visual C runtime installation'
} finally {
    foreach($name in $prerequisiteFunctions.Keys){if($null -eq $prerequisiteFunctions[$name]){Remove-Item ('Function:'+$name)}else{Set-Item ('Function:'+$name) $prerequisiteFunctions[$name]}}
    $inputData=$previousPrerequisiteInput;$r=$previousPrerequisiteRequest
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
    $assetNames=@{proxifyre='ProxiFyre.exe';wgcf='wgcf.exe';dnscrypt='dnscrypt-proxy.exe'}
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
} finally {
    foreach($name in $componentFunctions.Keys){Set-Item ('Function:'+$name) $componentFunctions[$name]}
    Remove-Item Function:Write-InertPE
    $inputData=$previousComponentInput;$r=$previousComponentRequest;$root=$previousComponentRoot;$assetNames=$previousAssetNames
}

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
[IO.File]::AppendAllText($source,"PostUp = arbitrary-command`n")
$rejected=$false;try{Make-Config|Out-Null}catch{$rejected=$true}
Assert $rejected 'WireGuard command hooks rejected'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=Join-Path $root 'traversal.zip';$zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
$entry=$zip.CreateEntry('../escape.txt');$writer=[IO.StreamWriter]::new($entry.Open());$writer.Write('bad');$writer.Dispose();$zip.Dispose()
$rejected=$false;try{Expand-Safe $archive (Join-Path $root 'extracted')}catch{$rejected=$true}
Assert $rejected 'Archive traversal rejected before extraction'
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

# Mock OS cmdlets to exercise DNS snapshot/restore semantics without changing
# the host's real DNS, services, registry or network adapters.
$script:dnsCalls=[Collections.Generic.List[object]]::new()
$script:dohCalls=[Collections.Generic.List[object]]::new()
function Get-NetAdapter { [pscustomobject]@{Status='Up';InterfaceDescription='Fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000001}';ifIndex=77} }
function Get-ItemProperty {param($LiteralPath,$Name,$ErrorAction);[pscustomobject]@{NameServer=$(if($LiteralPath -match 'Tcpip6') {''}else{'192.0.2.53'})} }
function Get-DnsClientServerAddress {param($InterfaceIndex,$AddressFamily);[pscustomobject]@{InterfaceIndex=$InterfaceIndex;AddressFamily=$AddressFamily;ServerAddresses=@($(if($AddressFamily -eq 'IPv4'){'192.0.2.53'}else{'2001:db8::53'}))} }
function Set-DnsClientServerAddress { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,$InterfaceIndex,[string[]]$ServerAddresses,[switch]$ResetServerAddresses);process{$script:dnsCalls.Add(@{family=$InputObject.AddressFamily;index=$InterfaceIndex;servers=@($ServerAddresses);reset=[bool]$ResetServerAddresses})} }
function Get-DnsClientDohServerAddress {param($ServerAddress,$ErrorAction);if(-not $ServerAddress){[pscustomobject]@{ServerAddress='8.8.8.8';DohTemplate='https://original.invalid/dns-query';AllowFallbackToUdp=$true;AutoUpgrade=$false}} }
function Add-DnsClientDohServerAddress {param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);$script:dohCalls.Add(@{action='add';address=$ServerAddress;template=$DohTemplate;fallback=$AllowFallbackToUdp})}
function Set-DnsClientDohServerAddress {param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);$script:dohCalls.Add(@{action='set';address=$ServerAddress;template=$DohTemplate;fallback=$AllowFallbackToUdp})}
function Remove-DnsClientDohServerAddress {param($ServerAddress,$ErrorAction);$script:dohCalls.Add(@{action='remove';address=$ServerAddress})}
function Get-Service {param($Name,$ErrorAction);return $null}
function Clear-DnsClientCache {}
function Resolve-DnsName {param($Name,[switch]$DnsOnly,[switch]$QuickTimeout,$ErrorAction);return [pscustomobject]@{Name='example.com'}}
Configure-DNS 'doh'
$dnsSnapshot=Join-Path $root 'profiles\dns-original.json'
Assert (Test-Path -LiteralPath $dnsSnapshot) 'DNS snapshot persisted before changes'
Assert ($script:dnsCalls[0].servers.Count -eq 4) 'DNS configuration covers IPv4 and IPv6 providers'
Assert (@($script:dohCalls | Where-Object {$_.action -eq 'add' -and $_.fallback -eq $false}).Count -eq 4) 'Native DoH configuration disables plaintext fallback'
Restore-DNS
Assert (@($script:dnsCalls|Where-Object {$_.family -eq 'IPv4' -and $_.servers -contains '192.0.2.53'}).Count -eq 1) 'Original static IPv4 DNS is restored'
Assert (@($script:dnsCalls|Where-Object {$_.family -eq 'IPv6' -and $_.reset}).Count -eq 1) 'Original DHCP IPv6 DNS is restored independently'
Assert (@($script:dohCalls|Where-Object {$_.action -eq 'set' -and $_.template -eq 'https://original.invalid/dns-query'}).Count -eq 1) 'Original DoH metadata is restored'
Assert (-not (Test-Path -LiteralPath $dnsSnapshot)) 'DNS snapshot removed only after successful recovery'
Write-Output 'DNS workflow contracts completed using mock OS cmdlets.'

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
