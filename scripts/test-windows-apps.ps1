# Run only in a clean disposable Windows guest, as its ordinary desktop user.
# Add -InteractiveCommunications with the approved controller digest to record
# two-way text and voice checks with an authorized peer and disposable accounts.
# Example: .\test-windows-apps.ps1 -DisposableVM -Executable APPROVED_CONTROLLER
#          -ExpectedSHA256 APPROVED_CONTROLLER_DIGEST -InteractiveCommunications
# A failed exchange can be recorded by pressing Enter, allowing cleanup to run.
# Keep account names, message contents, recordings and screenshots out of the results.
[CmdletBinding()]
param(
    [string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',
    [switch]$SkipSplitCord,
    [switch]$DisposableVM,
    [switch]$InteractiveCommunications,
    [string]$ResultsDirectory='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$ExpectedSHA256=''
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Test-FixtureAppProcess([string]$Path,[int]$Session,$Processes,[string]$ProcessName,
        [switch]$AllSessions,[string]$CleanupVariant){
    $processNames=@($ProcessName)
    $cleanupNames=@()
    $directory=if($CleanupVariant -ceq 'splitcord'){
        $cleanupNames=@('crashpad_handler')
        [IO.Path]::GetDirectoryName($Path)
    }elseif($CleanupVariant -cin @('discord','discord-ptb')){
        $folder=if($CleanupVariant -ceq 'discord'){'Discord'}else{'DiscordPTB'}
        $cleanupNames=@($folder,'Update','crashpad_handler')
        Join-Path $env:LOCALAPPDATA $folder
    }
    if($directory){$directory=[IO.Path]::GetFullPath($directory).TrimEnd([char]92)+[char]92}
    $processNames+=@($cleanupNames)
    $seen=$false
    $complete=$true
    foreach($process in $Processes){
        try {
            if($ProcessName){
                $name=$process.ProcessName
                if([string]::IsNullOrWhiteSpace($name)){$complete=$false;continue}
                if($name -notin $processNames){continue}
            }
            $exited=$process.HasExited
            if($exited -isnot [bool]){$complete=$false;continue}
            if($exited){continue}
            if(-not $AllSessions){
                $observedSession=$process.SessionId
                if($observedSession -isnot [int] -or $observedSession -lt 0){$complete=$false;continue}
                if($observedSession -ne $Session){continue}
            }
            $image=$process.Path
            if([string]::IsNullOrWhiteSpace($image)){$complete=$false;continue}
            $exited=$process.HasExited
            if($exited -isnot [bool]){$complete=$false;continue}
            if($exited){continue}
            if($image -ieq $Path -or ($directory -and
                [IO.Path]::GetFileNameWithoutExtension($image) -in $cleanupNames -and
                [IO.Path]::GetExtension($image) -ieq '.exe' -and
                [IO.Path]::GetFullPath($image).StartsWith($directory,[StringComparison]::OrdinalIgnoreCase))){
                $seen=$true
            }
        } catch {
            # An inaccessible live process cannot establish absence.
            $complete=$false
        } finally {
            if($process -is [IDisposable]){
                try {$process.Dispose()}catch{$complete=$false}
            }
        }
    }
    if($seen){return $true}
    if($complete){return $false}
    return $null
}

function Get-FixtureAppImage($Applications,[string]$Variant){
    $names=@{discord='Discord.exe';'discord-ptb'='DiscordPTB.exe';splitcord='SplitCord-Turkey.exe'}
    if($Variant -cnotin @('discord','discord-ptb','splitcord')){throw 'Unsupported application'}
    $property=$Applications.PSObject.Properties[$Variant]
    if($null -eq $property){throw 'Incomplete application discovery'}
    $path=$property.Value
    if($null -eq $path){return}
    if($path -isnot [string] -or $path.Length -gt 4096 -or
       $path -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|\x00-\x1f]+\z' -or
       [IO.Path]::GetFullPath($path) -ine $path -or
       [IO.Path]::GetFileName($path) -ine $names[$Variant]){
        throw 'Unexpected application discovery identity'
    }
    return $path
}

function Find-FixtureLiveImage([string]$Path,[switch]$AllSessions,[string]$CleanupVariant){
    $name=[IO.Path]::GetFileNameWithoutExtension($Path)
    # Full enumeration distinguishes a genuinely empty match from a lookup error.
    return (Test-FixtureAppProcess $Path $session @(Get-Process -ErrorAction Stop) $name -AllSessions:$AllSessions -CleanupVariant $CleanupVariant)
}

function Assert-FixtureLiveImage([string]$Path,[bool]$Expected,[switch]$AllSessions,[string]$CleanupVariant){
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        $observed=Find-FixtureLiveImage $Path -AllSessions:$AllSessions -CleanupVariant $CleanupVariant
        if($observed -is [bool] -and $observed -eq $Expected){return}
        Start-Sleep -Milliseconds 250
    } while($timer.Elapsed.TotalSeconds -lt 10)
    if($AllSessions){throw 'Application process exit could not be confirmed across Windows sessions'}
    throw 'Application process state was not confirmed in this desktop session'
}

function Assert-FixtureCommunicationImage([string]$Variant,[string]$Image,[string]$ExpectedDigest){
    if((Get-FixtureAppImage (Inspect-Apps) $Variant) -ine $Image -or
       (Get-FileHash -LiteralPath $Image -Algorithm SHA256 -ErrorAction Stop).Hash -ine $ExpectedDigest){
        throw 'Application identity changed during communication verification'
    }
    Assert-FixtureLiveImage $Image $true
}

function Test-FixtureCommunication([string]$Variant,[string]$Image,[string]$Kind,[string]$ExpectedDigest) {
    if($Variant -cnotin @('discord','discord-ptb','splitcord') -or $Kind -cnotin @('text','voice')){
        throw 'Unknown application communication check'
    }
    if($ExpectedDigest -notmatch '\A[a-f0-9]{64}\z'){throw 'Expected an installed application digest'}
    Assert-FixtureCommunicationImage $Variant $Image $ExpectedDigest
    if($Kind -ceq 'text'){
        $prompt="In $Variant, use an authorized disposable account and peer in a private test channel. Send a synthetic message and verify a reply. Type PASS only after both directions work"
    }else{
        $prompt="In $Variant, use the authorized test voice channel. Confirm that both participants hear and understand a spoken test phrase. Type PASS only after both directions work"
    }
    $answer=Read-Host $prompt
    if($answer -cne 'PASS'){throw 'Operator did not confirm two-way communication'}
    Assert-FixtureCommunicationImage $Variant $Image $ExpectedDigest
}

function Check-FixtureCommunications([string]$Variant,[string]$StartCheck){
    if(-not $InteractiveCommunications){return}
    $launch=@($checks | Where-Object {$_.name -ceq $StartCheck})
    foreach($kind in @('text','voice')){
        Check ('communications-'+$Variant+'-'+$kind) {
            if(-not (Test-FixtureAppChecks $launch @($StartCheck)) -or
               -not $installedImages.ContainsKey($Variant) -or -not $installedDigests.ContainsKey($Variant)){
                throw 'Application install and fresh start must pass before communication verification'
            }
            $script:appEvidenceStage='interactive-communication'
            Test-FixtureCommunication $Variant $installedImages[$Variant] $kind $installedDigests[$Variant]
        }
    }
}

function Test-FixtureAppChecks([object[]]$Checks,[string[]]$Expected) {
    if($Checks.Count -ne $Expected.Count){return $false}
    $remaining=[Collections.Generic.HashSet[string]]::new($Expected,[StringComparer]::Ordinal)
    foreach($check in $Checks){
        if($check.name -isnot [string] -or -not $remaining.Remove($check.name) -or
           $check.passed -isnot [bool] -or -not $check.passed){return $false}
    }
    return $remaining.Count -eq 0
}

function Get-FixtureSplitCordServiceState {
    $service=[ServiceProcess.ServiceController]::new('SplitCordDpiService')
    try {
        # Invoke the getter explicitly so PowerShell preserves its exception
        # instead of substituting a null value during property access.
        try {return [ServiceProcess.ServiceController].GetProperty('Status').GetValue($service).ToString()}
        catch {
            # Only SCM's explicit "service does not exist" proves absence.
            $errorSource=$_.Exception.GetBaseException()
            if($errorSource -is [ComponentModel.Win32Exception] -and $errorSource.NativeErrorCode -eq 1060){return 'Absent'}
            throw 'SplitCord service state could not be inspected'
        }
    } finally {$service.Dispose()}
}

function Assert-FixtureSplitCordServiceState([ValidateSet('Absent','Running')][string]$Expected,[string]$Image) {
    if((Get-FixtureSplitCordServiceState) -cne $Expected){throw 'SplitCord service did not match the expected state'}
    if($Expected -ceq 'Absent'){return}
    if(-not $Image -or -not [IO.Path]::IsPathRooted($Image)){
        throw 'SplitCord service verification requires the installed client path'
    }
    $binary=Join-Path (Split-Path -Parent $Image) 'resources\service-installer\SplitCordService.exe'
    if(-not (Test-Path -LiteralPath $binary -PathType Leaf -ErrorAction Stop)){
        throw 'SplitCord service executable could not be verified'
    }
    $services=@(Get-CimInstance -ClassName Win32_Service -Filter "Name='SplitCordDpiService'" -ErrorAction Stop)
    if($services.Count -ne 1 -or $services[0].Name -ine 'SplitCordDpiService' -or
       $services[0].State -cne 'Running' -or $services[0].PathName -isnot [string] -or
       ($services[0].PathName -ine $binary -and $services[0].PathName -ine ('"'+$binary+'"'))){
        throw 'Running SplitCord service could not be bound to the installed client'
    }
}

function Remove-FixtureApp([string]$Variant,[switch]$Cleanup){
    $current=Get-FixtureAppImage (Inspect-Apps) $Variant
    $previous=$installedImages[$Variant]
    $script:appEvidenceStage='removal-baseline'
    if(-not $Cleanup){
        if(-not $previous -or -not $current -or $current -ine $previous -or
            -not (Test-Path -LiteralPath $current -PathType Leaf -ErrorAction Stop)){
            throw 'Recorded application installation could not be verified before removal'
        }
    }
    if($current -or $Cleanup){
        $data=Invoke-AppWorkflow @{action='app-remove';engine=$Variant}
        if($data.application -cne $Variant -or $data.removed -isnot [bool] -or (-not $Cleanup -and -not $data.removed)){
            throw 'Application workflow did not verify the requested removal'
        }
    }
    $remaining=Get-FixtureAppImage (Inspect-Apps) $Variant
    $script:appEvidenceStage='removal-readback'
    if($remaining){throw 'Application remains discoverable after removal'}
    foreach($image in @($previous,$current) | Where-Object {$_} | Select-Object -Unique){
        Assert-FixtureLiveImage $image $false -AllSessions -CleanupVariant $Variant
        if(Test-Path -LiteralPath $image -ErrorAction Stop){throw 'Previously discovered executable remains after removal'}
    }
    if($Variant -ceq 'splitcord'){
        $script:appEvidenceStage='service-readback'
        Assert-FixtureSplitCordServiceState 'Absent'
    }
}
function Start-FixtureApp([string]$Variant){
    if(-not $installedImages.ContainsKey($Variant)){throw 'Application install prerequisite failed'}
    $image=$installedImages[$Variant]
    $script:appEvidenceStage='process-baseline'
    $alreadyRunning=Find-FixtureLiveImage $image
    if($alreadyRunning -isnot [bool]){throw 'Application process baseline could not be verified'}
    if($alreadyRunning){
        if([Console]::IsInputRedirected){throw 'A fresh launch requires a stopped application'}
        [void](Read-Host "Quit $Variant from its tray menu, then press Enter to verify it has stopped")
        Assert-FixtureLiveImage $image $false
    }
    $data=Invoke-AppWorkflow @{action='app-start';engine=$Variant}
    $script:appEvidenceStage='process-readback'
    if($data.application -cne $Variant -or $data.alreadyRunning -isnot [bool] -or $data.alreadyRunning){
        throw 'The application workflow did not confirm a fresh start'
    }
    Assert-FixtureLiveImage $image $true
}

if($InteractiveCommunications -and (-not $ExpectedSHA256 -or [Console]::IsInputRedirected)){
    throw 'Interactive communications checks require the approved controller digest and an interactive desktop console'
}
if($env:OS -cne 'Windows_NT' -or ($env:USERNAME -ne 'WDAGUtilityAccount' -and
   (-not $DisposableVM -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware'))){
    throw 'Explicitly disposable Windows guest required'
}
$current=[Diagnostics.Process]::GetCurrentProcess()
try {$session=$current.SessionId} finally {$current.Dispose()}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if($identity.IsSystem -or ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $session -eq 0){
        throw 'Run this fixture in an unelevated PowerShell window in the disposable desktop account'
    }
} finally {$identity.Dispose()}

$Executable=[IO.Path]::GetFullPath($Executable)
$controller=Get-Item -LiteralPath $Executable -Force
if($controller.PSIsContainer -or ($controller.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
   $controller.Length -le 0 -or $controller.Length -gt 128MB){
    throw 'Expected a bounded ordinary controller executable'
}
$guard=[IO.File]::Open($Executable,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$previousHome=$env:ACCESSWEAVER_HOME
try {
    $digest=(Get-FileHash -InputStream $guard -Algorithm SHA256).Hash.ToLowerInvariant()
    if($ExpectedSHA256 -and $digest -ine $ExpectedSHA256){throw 'Controller differs from the approved candidate'}
    $runID=[guid]::NewGuid().ToString('N')
    $results=if($ResultsDirectory){[IO.Path]::GetFullPath($ResultsDirectory)}else{Join-Path $env:LOCALAPPDATA 'AccessWeaver-App-Test-Results'}
    $run=Join-Path $results $runID
    [void][IO.Directory]::CreateDirectory($run)
    $env:ACCESSWEAVER_HOME=Join-Path $run 'controller-state'
    $encoding=[Text.UTF8Encoding]::new($false)
    $variants=@('discord','discord-ptb')
    if(-not $SkipSplitCord){$variants+=@('splitcord')}
    $expectedChecks=@(
        'discord-install','discord-start','combined-repair-refused-with-state-preserved',
        'discord-reinstall','discord-start-after-reinstall','discord-remove','discord-install-for-ptb-clean',
        'ptb-install-with-stable','ptb-start-with-stable','ptb-remove-with-stable','ptb-clean-install','ptb-start','ptb-remove'
    )
    if(-not $SkipSplitCord){$expectedChecks+=@('splitcord-install','splitcord-start','splitcord-remove')}
    foreach($variant in $variants){
        $expectedChecks+=@('cleanup-'+$variant)
        if($InteractiveCommunications){$expectedChecks+=@("communications-$variant-text","communications-$variant-voice")}
    }
    $attempted=[Collections.Generic.List[string]]::new()
    $installedImages=@{}
    $installedDigests=@{}
    $checks=[Collections.Generic.List[object]]::new()
    $script:appEvidenceStage='baseline'
    $report=[ordered]@{
        schemaVersion=9;runID=$runID;controllerSHA256=$digest;approvedDigestMatched=[bool]$ExpectedSHA256;
        fixtureSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();
        architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant();
        checks=$null;baselineClear=$false;splitCordIncluded=(-not $SkipSplitCord);
        communicationMethod=$(if($InteractiveCommunications){'operator-observed-two-way'}else{'not-requested'});
        textExercised=$false;voiceExercised=$false;combinedRepairExecuted=$false;passed=$false
    }

    function Invoke-FixtureCLI([string[]]$Arguments){
        $old=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $output=@(& $Executable @Arguments 2>&1)
            $code=$LASTEXITCODE
        } finally {$ErrorActionPreference=$old}
        $text=$output -join "`n"
        if($text.Length -gt 1048576){throw 'Application fixture output exceeds the inspection limit'}
        return @{exitCode=$code;text=$text}
    }
    function Invoke-AppWorkflow([hashtable]$Request,[switch]$ExpectRepairRefusal){
        $script:appEvidenceStage='workflow'
        $path=Join-Path $run ('request-'+[guid]::NewGuid().ToString('N')+'.json')
        try {
            [IO.File]::WriteAllText($path,($Request|ConvertTo-Json -Compress),$encoding)
            $response=Invoke-FixtureCLI @('system','apply',$path,'--confirm')
            if($ExpectRepairRefusal){
                if($response.exitCode -eq 0 -or $response.text -cnotmatch 'privilege-separated broker'){
                    throw 'Combined repair did not return the expected refusal'
                }
                return
            }
            if($response.exitCode -ne 0){throw 'Application workflow failed'}
            $job=ConvertFrom-Json -InputObject $response.text
            if($job.action -cne $Request.action -or $job.state -cne 'succeeded' -or
                $job.result.ok -isnot [bool] -or -not $job.result.ok){
                throw 'Application workflow did not reach success'
            }
            return $job.result.data
        } finally {[IO.File]::Delete($path)}
    }
    function Inspect-Apps {
        $script:appEvidenceStage='discovery'
        $response=Invoke-FixtureCLI @('system','discover')
        if($response.exitCode -ne 0){throw 'Application discovery failed'}
        $job=ConvertFrom-Json -InputObject $response.text
        if($job.action -cne 'discover' -or $job.state -cne 'succeeded' -or
           $job.result.ok -isnot [bool] -or -not $job.result.ok -or $null -eq $job.result.data.applications -or
           (-not $SkipSplitCord -and @($job.result.data.conflicts) -ccontains 'SplitCord installation could not be identified safely')){
            throw 'Application discovery could not verify the inventory'
        }
        return $job.result.data.applications
    }
    function Install-FixtureApp([string]$Variant,[switch]$Clean){
        $installedDigests.Remove($Variant)
        if(-not $attempted.Contains($Variant)){$attempted.Add($Variant)}
        $request=@{action='app-install';engine=$Variant}
        if($Clean){$request.clean=$true}
        $data=Invoke-AppWorkflow $request
        $image=Get-FixtureAppImage (Inspect-Apps) $Variant
        if($image){$installedImages[$Variant]=$image}
        $script:appEvidenceStage='install-readback'
        if($data.application -cne $Variant -or $data.installed -isnot [bool] -or -not $data.installed -or
           $data.previouslyInstalled -isnot [bool] -or $data.previouslyInstalled -or -not $image -or
           -not (Test-Path -LiteralPath $image -PathType Leaf)){
            throw 'New application installation could not be verified'
        }
        if($Variant -ceq 'splitcord'){
            $script:appEvidenceStage='service-readback'
            Assert-FixtureSplitCordServiceState 'Running' $image
        }
        if($InteractiveCommunications){
            $script:appEvidenceStage='install-readback'
            $installedDigests[$Variant]=(Get-FileHash -LiteralPath $image -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    }
    function Assert-FixtureStablePeer([string]$Image,[string]$Digest){
        $observed=Get-FixtureAppImage (Inspect-Apps) 'discord'
        $script:appEvidenceStage='stable-peer-readback'
        if(-not $Image -or -not $Digest -or $observed -ine $Image -or
           (Get-FileHash -LiteralPath $Image -Algorithm SHA256 -ErrorAction Stop).Hash -cne $Digest){
            throw 'Standard PTB lifecycle did not preserve the stable Discord executable'
        }
    }
    function Check([string]$Name,[scriptblock]$Body){
        $script:appEvidenceStage='prerequisite'
        try {
            $null=& $Body
            $checks.Add(@{name=$Name;passed=$true})
        } catch {$checks.Add(@{name=$Name;passed=$false;stage=$script:appEvidenceStage})}
    }

    try {
        $apps=Inspect-Apps
        foreach($variant in $variants){
            if(Get-FixtureAppImage $apps $variant){throw 'The disposable desktop baseline already contains a tested application'}
        }
        if(-not $SkipSplitCord){
            $script:appEvidenceStage='service-baseline'
            Assert-FixtureSplitCordServiceState 'Absent'
        }
        $report.baselineClear=$true
        Check 'discord-install' {Install-FixtureApp 'discord'}
        Check 'discord-start' {Start-FixtureApp 'discord'}
        Check 'combined-repair-refused-with-state-preserved' {
            if(-not $installedImages.ContainsKey('discord')){throw 'Stable Discord install prerequisite failed'}
            $before=Get-FixtureAppImage (Inspect-Apps) 'discord'
            if(-not $before){throw 'Stable Discord is absent'}
            $beforeHash=(Get-FileHash -LiteralPath $before -Algorithm SHA256).Hash
            $script:appEvidenceStage='process-baseline'
            $beforeRunning=Find-FixtureLiveImage $before
            if($beforeRunning -isnot [bool]){throw 'Application process baseline could not be verified'}
            Invoke-AppWorkflow @{action='app-repair';engine='discord'} -ExpectRepairRefusal
            $currentImage=Get-FixtureAppImage (Inspect-Apps) 'discord'
            $script:appEvidenceStage='repair-readback'
            $afterRunning=Find-FixtureLiveImage $before
            if($currentImage -ine $before -or
               (Get-FileHash -LiteralPath $before -Algorithm SHA256).Hash -cne $beforeHash -or
               $afterRunning -isnot [bool] -or $afterRunning -ne $beforeRunning){
                throw 'Combined repair refusal changed the observed Discord state'
            }
        }
        Check 'discord-reinstall' {
            $installedDigests.Remove('discord')
            if(-not $installedImages.ContainsKey('discord')){throw 'Stable Discord install prerequisite failed'}
            $data=Invoke-AppWorkflow @{action='app-reinstall';engine='discord'}
            $image=Get-FixtureAppImage (Inspect-Apps) 'discord'
            if($data.application -cne 'discord' -or $data.reinstalled -isnot [bool] -or -not $data.reinstalled -or -not $image -or
               -not (Test-Path -LiteralPath $image -PathType Leaf)){throw 'Stable Discord replacement was not confirmed'}
            $installedImages['discord']=$image
            if($InteractiveCommunications){
                $installedDigests['discord']=(Get-FileHash -LiteralPath $image -Algorithm SHA256 -ErrorAction Stop).Hash
            }
        }
        Check 'discord-start-after-reinstall' {Start-FixtureApp 'discord'}
        Check-FixtureCommunications 'discord' 'discord-start-after-reinstall'
        Check 'discord-remove' {Remove-FixtureApp 'discord'}
        Check 'discord-install-for-ptb-clean' {
            if(Get-FixtureAppImage (Inspect-Apps) 'discord'){throw 'Stable Discord removal prerequisite failed'}
            Install-FixtureApp 'discord'
        }
        $stablePeer=@{}
        Check 'ptb-install-with-stable' {
            $image=$installedImages['discord']
            if(-not $image -or (Get-FixtureAppImage (Inspect-Apps) 'discord') -ine $image){
                throw 'Standard PTB coexistence requires an installed stable client'
            }
            $digest=(Get-FileHash -LiteralPath $image -Algorithm SHA256 -ErrorAction Stop).Hash
            Install-FixtureApp 'discord-ptb'
            Assert-FixtureStablePeer $image $digest
            $stablePeer.image=$image
            $stablePeer.digest=$digest
        }
        Check 'ptb-start-with-stable' {
            if(-not $stablePeer.image){throw 'Standard PTB install prerequisite failed'}
            Start-FixtureApp 'discord-ptb'
            Assert-FixtureStablePeer $stablePeer.image $stablePeer.digest
        }
        Check 'ptb-remove-with-stable' {
            if(-not $stablePeer.image){throw 'Standard PTB install prerequisite failed'}
            Remove-FixtureApp 'discord-ptb'
            Assert-FixtureStablePeer $stablePeer.image $stablePeer.digest
            $stablePeer.removalVerified=$true
        }
        Check 'ptb-clean-install' {
            if(-not $stablePeer.removalVerified){throw 'Standard PTB cleanup prerequisite failed'}
            Assert-FixtureStablePeer $stablePeer.image $stablePeer.digest
            $previousPTB=$installedImages['discord-ptb']
            if((Get-FixtureAppImage (Inspect-Apps) 'discord-ptb') -or
               (Test-Path -LiteralPath $previousPTB -ErrorAction Stop)){
                throw 'Standard PTB reappeared before clean-mode setup'
            }
            Assert-FixtureLiveImage $previousPTB $false -AllSessions -CleanupVariant 'discord-ptb'
            Install-FixtureApp 'discord-ptb' -Clean
            $prior=$installedImages['discord']
            $stable=Get-FixtureAppImage (Inspect-Apps) 'discord'
            $script:appEvidenceStage='clean-mode-readback'
            if($stable -or (Test-Path -LiteralPath $prior)){
                throw 'Clean PTB installation left the stable executable'
            }
            Assert-FixtureLiveImage $prior $false -AllSessions -CleanupVariant 'discord'
        }
        Check 'ptb-start' {Start-FixtureApp 'discord-ptb'}
        Check-FixtureCommunications 'discord-ptb' 'ptb-start'
        Check 'ptb-remove' {Remove-FixtureApp 'discord-ptb'}
        if(-not $SkipSplitCord){
            Check 'splitcord-install' {Install-FixtureApp 'splitcord'}
            Check 'splitcord-start' {Start-FixtureApp 'splitcord'}
            Check-FixtureCommunications 'splitcord' 'splitcord-start'
            Check 'splitcord-remove' {Remove-FixtureApp 'splitcord'}
        }
    } finally {
        foreach($variant in $attempted){
            Check ('cleanup-'+$variant) {Remove-FixtureApp $variant -Cleanup}
        }
        $report.checks=@($checks.ToArray())
        if($InteractiveCommunications){
            $textChecks=@($report.checks | Where-Object {$_.name -clike 'communications-*-text'})
            $voiceChecks=@($report.checks | Where-Object {$_.name -clike 'communications-*-voice'})
            $report.textExercised=Test-FixtureAppChecks $textChecks @($variants | ForEach-Object {"communications-$_-text"})
            $report.voiceExercised=Test-FixtureAppChecks $voiceChecks @($variants | ForEach-Object {"communications-$_-voice"})
        }
        $report.passed=$report.baselineClear -and (Test-FixtureAppChecks $report.checks $expectedChecks)
        [IO.File]::WriteAllText((Join-Path $run 'applications.json'),($report|ConvertTo-Json -Depth 5),$encoding)
    }
    if(-not $report.passed){throw 'Application acceptance failed. Review the per-run applications.json result.'}
    $report|ConvertTo-Json -Depth 5
} finally {
    $env:ACCESSWEAVER_HOME=$previousHome
    $guard.Dispose()
}
