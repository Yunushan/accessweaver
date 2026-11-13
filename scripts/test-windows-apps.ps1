# Run only in a clean disposable Windows guest, as its ordinary desktop user.
[CmdletBinding()]
param(
    [string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',
    [switch]$SkipSplitCord,
    [switch]$DisposableVM,
    [string]$ResultsDirectory='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$ExpectedSHA256=''
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Test-FixtureAppProcess([string]$Path,[int]$Session,$Processes){
    $seen=$false
    foreach($process in $Processes){
        try {
            if($process.Path -ieq $Path -and $process.SessionId -eq $Session -and
               $process.HasExited -is [bool] -and -not $process.HasExited){
                $seen=$true
            }
        } catch {
            # A process can exit during inspection.
        } finally {
            if($process -is [IDisposable]){$process.Dispose()}
        }
    }
    return $seen
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

function Find-FixtureLiveImage([string]$Path){
    $name=[IO.Path]::GetFileNameWithoutExtension($Path)
    return (Test-FixtureAppProcess $Path $session @(Get-Process -Name $name -ErrorAction SilentlyContinue))
}

function Assert-FixtureLiveImage([string]$Path,[bool]$Expected){
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        if((Find-FixtureLiveImage $Path) -eq $Expected){return}
        Start-Sleep -Milliseconds 250
    } while($timer.Elapsed.TotalSeconds -lt 10)
    throw 'Application process state was not confirmed in this desktop session'
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
    $attempted=[Collections.Generic.List[string]]::new()
    $installedImages=@{}
    $checks=[Collections.Generic.List[object]]::new()
    $script:appEvidenceStage='baseline'
    $report=[ordered]@{
        schemaVersion=2;runID=$runID;controllerSHA256=$digest;approvedDigestMatched=[bool]$ExpectedSHA256;
        fixtureSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();
        architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant();
        checks=$null;baselineClear=$false;splitCordIncluded=(-not $SkipSplitCord);
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
            if($job.state -cne 'succeeded'){throw 'Application workflow did not reach success'}
            return $job.result.data
        } finally {[IO.File]::Delete($path)}
    }
    function Inspect-Apps {
        $script:appEvidenceStage='discovery'
        $response=Invoke-FixtureCLI @('system','discover')
        if($response.exitCode -ne 0){throw 'Application discovery failed'}
        $job=ConvertFrom-Json -InputObject $response.text
        if($job.state -cne 'succeeded' -or $null -eq $job.result.data.applications -or
           @($job.result.data.conflicts) -ccontains 'SplitCord installation could not be identified safely'){
            throw 'Application discovery could not verify the inventory'
        }
        return $job.result.data.applications
    }
    function Install-FixtureApp([string]$Variant,[switch]$Clean){
        $attempted.Add($Variant)
        $request=@{action='app-install';engine=$Variant}
        if($Clean){$request.clean=$true}
        $data=Invoke-AppWorkflow $request
        $image=Get-FixtureAppImage (Inspect-Apps) $Variant
        if($image){$installedImages[$Variant]=$image}
        $script:appEvidenceStage='install-readback'
        if($data.installed -ne $true -or $data.previouslyInstalled -ne $false -or -not $image -or
           -not (Test-Path -LiteralPath $image -PathType Leaf)){
            throw 'New application installation could not be verified'
        }
    }
    function Start-FixtureApp([string]$Variant){
        if(-not $installedImages.ContainsKey($Variant)){throw 'Application install prerequisite failed'}
        $image=$installedImages[$Variant]
        $alreadyRunning=Find-FixtureLiveImage $image
        [void](Invoke-AppWorkflow @{action='app-start';engine=$Variant})
        $script:appEvidenceStage='process-readback'
        Assert-FixtureLiveImage $image $true
        return $alreadyRunning
    }
    function Remove-FixtureApp([string]$Variant){
        $current=Get-FixtureAppImage (Inspect-Apps) $Variant
        if($current){$installedImages[$Variant]=$current}
        if($current){[void](Invoke-AppWorkflow @{action='app-remove';engine=$Variant})}
        $remaining=Get-FixtureAppImage (Inspect-Apps) $Variant
        $script:appEvidenceStage='removal-readback'
        if($remaining){throw 'Application remains discoverable after removal'}
        if($installedImages.ContainsKey($Variant)){
            $image=$installedImages[$Variant]
            Assert-FixtureLiveImage $image $false
            if(Test-Path -LiteralPath $image){throw 'Previously discovered executable remains after removal'}
        }
    }
    function Check([string]$Name,[scriptblock]$Body){
        $script:appEvidenceStage='prerequisite'
        try {
            $observation=& $Body
            $entry=@{name=$Name;passed=$true}
            if($observation -is [bool]){$entry.alreadyRunning=$observation}
            $checks.Add($entry)
        } catch {$checks.Add(@{name=$Name;passed=$false;stage=$script:appEvidenceStage})}
    }

    try {
        $apps=Inspect-Apps
        foreach($variant in $variants){
            if(Get-FixtureAppImage $apps $variant){throw 'The disposable desktop baseline already contains a tested application'}
        }
        $report.baselineClear=$true
        Check 'discord-install' {Install-FixtureApp 'discord'}
        Check 'discord-start' {Start-FixtureApp 'discord'}
        Check 'combined-repair-refused-with-state-preserved' {
            if(-not $installedImages.ContainsKey('discord')){throw 'Stable Discord install prerequisite failed'}
            $before=Get-FixtureAppImage (Inspect-Apps) 'discord'
            if(-not $before){throw 'Stable Discord is absent'}
            $beforeHash=(Get-FileHash -LiteralPath $before -Algorithm SHA256).Hash
            $beforeRunning=Find-FixtureLiveImage $before
            Invoke-AppWorkflow @{action='app-repair';engine='discord'} -ExpectRepairRefusal
            $currentImage=Get-FixtureAppImage (Inspect-Apps) 'discord'
            $script:appEvidenceStage='repair-readback'
            if($currentImage -ine $before -or
               (Get-FileHash -LiteralPath $before -Algorithm SHA256).Hash -cne $beforeHash -or
               (Find-FixtureLiveImage $before) -ne $beforeRunning){
                throw 'Combined repair refusal changed the observed Discord state'
            }
        }
        Check 'ptb-clean-install' {
            if(-not $installedImages.ContainsKey('discord') -or
               -not (Get-FixtureAppImage (Inspect-Apps) 'discord')){throw 'Clean mode requires an installed stable client'}
            Install-FixtureApp 'discord-ptb' -Clean
            $prior=$installedImages['discord']
            $stable=Get-FixtureAppImage (Inspect-Apps) 'discord'
            $script:appEvidenceStage='clean-mode-readback'
            if($stable -or (Test-Path -LiteralPath $prior)){
                throw 'Clean PTB installation left the stable executable'
            }
            Assert-FixtureLiveImage $prior $false
        }
        Check 'ptb-start' {Start-FixtureApp 'discord-ptb'}
        Check 'ptb-remove' {
            if(-not $installedImages.ContainsKey('discord-ptb')){throw 'PTB install prerequisite failed'}
            Remove-FixtureApp 'discord-ptb'
        }
        if(-not $SkipSplitCord){
            Check 'splitcord-install' {Install-FixtureApp 'splitcord'}
            Check 'splitcord-start' {Start-FixtureApp 'splitcord'}
            Check 'splitcord-remove' {
                if(-not $installedImages.ContainsKey('splitcord')){throw 'SplitCord install prerequisite failed'}
                Remove-FixtureApp 'splitcord'
            }
        }
    } finally {
        foreach($variant in $attempted){
            Check ('cleanup-'+$variant) {Remove-FixtureApp $variant}
        }
        $report.checks=@($checks.ToArray())
        $report.passed=$report.baselineClear -and -not @($report.checks|Where-Object {-not $_.passed}).Count
        [IO.File]::WriteAllText((Join-Path $run 'applications.json'),($report|ConvertTo-Json -Depth 5),$encoding)
    }
    if(-not $report.passed){throw 'Application acceptance failed. Review the per-run applications.json result.'}
    $report|ConvertTo-Json -Depth 5
} finally {
    $env:ACCESSWEAVER_HOME=$previousHome
    $guard.Dispose()
}
