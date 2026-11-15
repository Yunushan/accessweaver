# Run only in a clean disposable Windows guest, as its ordinary desktop user.
# SplitCord setup and removal require a separate elevated CLI in that guest.
# Use -SkipSplitCord for a Discord/PTB-only run.
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
    [switch]$StagedDiscordRepair,
    [ValidateSet('stage','detach','reapply','cleanup')][string]$DiscordProxyAction,
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$DesktopAccountSHA256='',
    [string]$ResultsDirectory='',
    [ValidateSet('app-install','app-remove')][string]$SplitCordAction,
    [ValidatePattern('\A[a-f0-9]{32}\z')][string]$HandoffID,
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
            $name=$null
            if($ProcessName){
                $name=$process.ProcessName
                if([string]::IsNullOrWhiteSpace($name)){$complete=$false;continue}
                if($name -notin $processNames){continue}
            }
            $exited=$null
            try {$exited=$process.HasExited}catch{}
            if($exited -is [bool] -and $exited){continue}
            if(-not $AllSessions){
                $observedSession=$process.SessionId
                if($observedSession -isnot [int] -or $observedSession -lt 0){$complete=$false;continue}
                if($observedSession -ne $Session){continue}
            }
            $image=$null
            try {$image=$process.Path}catch{}
            if([string]::IsNullOrWhiteSpace($image)){
                if($CleanupVariant -cin @('discord','discord-ptb') -and $name -in @('Update','crashpad_handler')){
                    $serviceSession=$process.SessionId
                    if($serviceSession -is [int] -and $serviceSession -eq 0){continue}
                }
                $complete=$false
                continue
            }
            if($exited -isnot [bool]){$complete=$false;continue}
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
    if($Variant -ceq 'splitcord'){
        $script:appEvidenceStage='service-readback'
        Assert-FixtureSplitCordServiceState 'Running' $Image
        $script:appEvidenceStage='interactive-communication'
    }
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

function Get-FixtureBaselineFailureStage([string]$Stage,[Exception]$Failure){
    if($Stage -ceq 'discovery'){
        for($cause=$Failure;$null -ne $cause;$cause=$cause.InnerException){
            if($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -eq 4551){
                return 'controller-launch-policy'
            }
        }
    }
    return $Stage
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
    $services=@(Get-CimInstance -ClassName Win32_Service -Filter "Name='SplitCordDpiService'" -ErrorAction Stop)
    if($services.Count -ne 1 -or $services[0].Name -ine 'SplitCordDpiService' -or
       $services[0].State -cne 'Running' -or $services[0].PathName -isnot [string] -or
       ($services[0].PathName -ine $binary -and $services[0].PathName -ine ('"'+$binary+'"'))){
        throw 'Running SplitCord service could not be bound to the installed client'
    }
    $serviceImage=Get-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
    if($null -eq $serviceImage -or $serviceImage.PSIsContainer -or
       ($serviceImage.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'SplitCord service executable could not be verified'
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
    $images=@(@($previous,$current) | Where-Object {$_} | Select-Object -Unique)
    foreach($image in $images){
        Assert-FixtureLiveImage $image $false -AllSessions -CleanupVariant $Variant
        if(Test-Path -LiteralPath $image -ErrorAction Stop){throw 'Previously discovered executable remains after removal'}
    }
    if($Variant -ceq 'splitcord'){
        $script:appEvidenceStage='service-readback'
        Assert-FixtureSplitCordServiceState 'Absent'
    }else{
        Assert-FixtureDiscordUpdaterAbsent $Variant -CheckProcesses:($images.Count -eq 0)
    }
}
function Assert-FixtureDiscordUpdaterAbsent([string]$Variant,[switch]$CheckProcesses){
    $folder=if($Variant -ceq 'discord'){'Discord'}else{'DiscordPTB'}
    $path=Join-Path (Join-Path $env:LOCALAPPDATA $folder) 'Update.exe'
    if(Test-Path -LiteralPath $path -ErrorAction Stop){throw 'Discord updater remains on disk'}
    if($CheckProcesses){Assert-FixtureLiveImage $path $false -AllSessions -CleanupVariant $Variant}
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
    if($Variant -ceq 'splitcord'){
        $script:appEvidenceStage='service-readback'
        Assert-FixtureSplitCordServiceState 'Running' $image
    }
}

function New-SplitCordHandoff([string]$JSON,[string]$ID,[string]$Action,[string]$Digest){
    if(-not $JSON -or $JSON.Length -gt 1MB){throw 'SplitCord machine workflow output exceeds the inspection limit'}
    $job=ConvertFrom-Json -InputObject $JSON -ErrorAction Stop
    $field=if($Action -ceq 'app-install'){'installed'}else{'removed'}
    if($job -isnot [pscustomobject] -or $job.action -cne $Action -or $job.state -cne 'succeeded' -or
        $job.result.ok -isnot [bool] -or -not $job.result.ok -or @($job.result.finalizationFailures).Count -ne 0 -or
        $job.result.data.application -cne 'splitcord' -or $job.result.data.$field -isnot [bool] -or
        ($Action -ceq 'app-install' -and (-not $job.result.data.installed -or
            $job.result.data.previouslyInstalled -isnot [bool]))){
        throw 'SplitCord machine workflow did not verify the requested operation'
    }
    $receipt=@{id=$ID;action=$Action;controllerSHA256=$Digest;changed=$job.result.data.$field}
    if($Action -ceq 'app-install'){$receipt.previouslyInstalled=$job.result.data.previouslyInstalled}
    $receipt | ConvertTo-Json -Compress
}

function Read-SplitCordHandoff([string]$Receipt,[string]$ID,[string]$Action,[string]$Digest){
    if(-not $Receipt -or $Receipt.Length -gt 512 -or $Receipt -cnotmatch '\A\{'){
        throw 'SplitCord machine receipt is unavailable'
    }
    $record=ConvertFrom-Json -InputObject $Receipt -ErrorAction Stop
    $keys=@('id','action','controllerSHA256','changed')
    if($Action -ceq 'app-install'){$keys+=@('previouslyInstalled')}
    if($record -isnot [pscustomobject] -or @($record.PSObject.Properties).Count -ne $keys.Count -or
        @($record.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or
        $record.id -isnot [string] -or $record.id -cne $ID -or
        $record.action -isnot [string] -or $record.action -cne $Action -or
        $record.controllerSHA256 -isnot [string] -or $record.controllerSHA256 -cne $Digest -or
        $record.changed -isnot [bool] -or ($Action -ceq 'app-install' -and (-not $record.changed -or $record.previouslyInstalled -isnot [bool]))){
        throw 'SplitCord machine receipt does not match the current request'
    }
    if($Action -ceq 'app-install'){
        return @{application='splitcord';installed=$record.changed;previouslyInstalled=$record.previouslyInstalled}
    }
    return @{application='splitcord';removed=$record.changed}
}

function Get-DiscordProxyRequest([string]$Phase) {
    switch -CaseSensitive ($Phase){
        {$_ -cin @('stage','reapply')} {return @{action='install';engine='byedpi';mode='dll';dns='unchanged'}}
        'detach' {return @{action='remove';engine='drover'}}
        'cleanup' {return @{action='remove';engine='byedpi'}}
        default {throw 'Unknown staged repair phase'}
    }
}
function New-DiscordProxyReceipt([string]$JSON,[string]$ID,[string]$Phase,[string]$Digest) {
    $request=Get-DiscordProxyRequest $Phase
    if(-not $JSON -or $JSON.Length -gt 1MB){throw 'Discord proxy workflow output exceeds the inspection limit'}
    $job=ConvertFrom-Json -InputObject $JSON -ErrorAction Stop
    if($job -isnot [pscustomobject] -or $job.action -cne $request.action -or $job.state -cne 'succeeded' -or
        $job.result.ok -isnot [bool] -or -not $job.result.ok -or @($job.result.finalizationFailures).Count -ne 0 -or
        ($request.action -ceq 'install' -and $job.result.data.installed -cne 'byedpi')){
        throw 'Discord proxy workflow did not verify the requested operation'
    }
    if($Phase -ceq 'reapply' -and @($job.result.events | Where-Object {
        $_ -is [string] -and $_.EndsWith(' Reused the running managed ByeDPI service for Discord',[StringComparison]::Ordinal)
    }).Count -ne 1){throw 'Discord proxy reapplication did not confirm service reuse'}
    @{id=$ID;phase=$Phase;controllerSHA256=$Digest} | ConvertTo-Json -Compress
}
function Assert-DiscordProxyReceipt([string]$Receipt,[string]$ID,[string]$Phase,[string]$Digest) {
    if(-not $Receipt -or $Receipt.Length -gt 512 -or $Receipt -cnotmatch '\A\{'){throw 'Discord proxy receipt is unavailable'}
    $record=ConvertFrom-Json -InputObject $Receipt -ErrorAction Stop
    if($record -isnot [pscustomobject] -or @($record.PSObject.Properties).Count -ne 3 -or
        $record.id -isnot [string] -or $record.id -cne $ID -or
        $record.phase -isnot [string] -or $record.phase -cne $Phase -or
        $record.controllerSHA256 -isnot [string] -or $record.controllerSHA256 -cne $Digest){
        throw 'Discord proxy receipt does not match the current request'
    }
}
function Get-FixtureDiscordProxy([ValidateSet('byedpi','proxifyre')][string]$Engine='byedpi') {
    $name='AccessWeaver-'+$Engine
    $rows=@(Get-CimInstance -ClassName Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction Stop)
    if($rows.Count -eq 0){return}
    if($rows.Count -ne 1 -or $rows[0].Name -cne $name -or $rows[0].State -cne 'Running' -or
        $rows[0].StartMode -cne 'Auto' -or $rows[0].ProcessId -le 0 -or
        $rows[0].PathName -isnot [string] -or [string]::IsNullOrWhiteSpace($rows[0].PathName)){
        throw 'Managed proxy registration or running process could not be verified'
    }
    $id=[uint32]$rows[0].ProcessId
    $processes=@(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId='+$id) -Property ProcessId,CreationDate -ErrorAction Stop)
    if($processes.Count -ne 1 -or $processes[0].ProcessId -ne $id -or $processes[0].CreationDate -isnot [datetime]){
        throw 'Managed proxy process identity could not be verified'
    }
    return ('{0}:{1}:{2}' -f $id,$processes[0].CreationDate.Ticks,$rows[0].PathName)
}
function Get-FixtureDroverFiles([string]$Image) {
    if(-not $Image){throw 'Stable Discord is absent during proxy verification'}
    $base=Join-Path $env:LOCALAPPDATA 'Discord'
    $rootItem=Get-Item -LiteralPath $base -Force -ErrorAction Stop
    if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'Discord root is not an ordinary directory'
    }
    $directories=@(Get-ChildItem -LiteralPath $base -Directory -Filter 'app-*' -Force -ErrorAction Stop |
        Select-Object -First 257 | Sort-Object FullName)
    if($directories.Count -gt 256){throw 'Discord version inventory exceeds the inspection limit'}
    $observed=$false
    foreach($directory in $directories){
        if($directory.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Discord version directory is redirected'}
        $app=Join-Path $directory.FullName 'Discord.exe'
        if(-not (Test-Path -LiteralPath $app -ErrorAction Stop)){continue}
        if($app -ieq $Image){$observed=$true}
        $record=[ordered]@{image=$app}
        foreach($name in @('Discord.exe','version.dll','drover.ini')){
            $path=Join-Path $directory.FullName $name
            $hash=$null
            if(Test-Path -LiteralPath $path -ErrorAction Stop){
                $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $item.Length -gt 512MB -or ($name -ceq 'Discord.exe' -and $item.Length -le 0)){
                    throw 'Discord proxy fixture encountered an unsafe file'
                }
                $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
            }
            if($name -ceq 'Discord.exe' -and -not $hash){throw 'Discord executable disappeared during proxy verification'}
            $record[$name]=$hash
        }
        [pscustomobject]$record
    }
    if(-not $observed){throw 'Observed Discord client is missing from the version inventory'}
}
function Assert-FixtureDroverApplied([object[]]$Baseline,[object[]]$Observed,[object]$Expected) {
    if($Observed.Count -eq 0 -or $Observed.Count -ne $Baseline.Count){throw 'Discord version inventory changed during proxy application'}
    for($i=0;$i -lt $Observed.Count;$i++){
        $before=$Baseline[$i];$after=$Observed[$i]
        if($after.image -ine $before.image -or $after.'Discord.exe' -cne $before.'Discord.exe' -or
            -not $after.'version.dll' -or -not $after.'drover.ini' -or
            $after.'version.dll' -ceq $before.'version.dll' -or $after.'drover.ini' -ceq $before.'drover.ini' -or
            $after.'version.dll' -cne $Expected.'version.dll' -or $after.'drover.ini' -cne $Expected.'drover.ini'){
            throw 'Discord proxy files did not match the expected deployment'
        }
    }
}

function Assert-FixtureDroverRestored([object[]]$Baseline,[object[]]$Observed) {
    if((ConvertTo-Json -InputObject $Observed -Compress) -cne (ConvertTo-Json -InputObject $Baseline -Compress)){
        throw 'Original Discord files were not restored'
    }
}
function Test-FixtureDiscordDroverLoaded([string]$Image,[int]$Session,[object[]]$Processes) {
    $expected=Join-Path (Split-Path -Parent $Image) 'version.dll'
    $loaded=$false
    foreach($process in $Processes){
        try {
            if($process.SessionId -ne $Session -or $process.Path -ine $Image -or $process.HasExited -cne $false){continue}
            foreach($module in $process.Modules){
                if($module.FileName -ieq $expected -and $process.HasExited -ceq $false){$loaded=$true;break}
            }
        }catch{
            # A process can exit during module enumeration. Require a positive observation.
        }finally{
            if($process -is [IDisposable]){$process.Dispose()}
        }
    }
    return $loaded
}

$machineHandoff=[bool]($SplitCordAction -or $DiscordProxyAction)
if(($SplitCordAction -and $DiscordProxyAction) -or [bool]$DiscordProxyAction -ne [bool]$DesktopAccountSHA256 -or
    $machineHandoff -ne [bool]$HandoffID -or ($machineHandoff -and
    (-not $ExpectedSHA256 -or -not $PSBoundParameters.ContainsKey('Executable') -or -not $DisposableVM -or
        $InteractiveCommunications -or $SkipSplitCord -or $StagedDiscordRepair -or $ResultsDirectory))){
    throw 'Machine handoff requires a fixed action, request ID, explicit approved controller path and digest, and disposable guest'
}
if(-not $machineHandoff -and ($StagedDiscordRepair -or $InteractiveCommunications -or -not $SkipSplitCord) -and
    (-not $ExpectedSHA256 -or [Console]::IsInputRedirected)){
    throw 'Machine maintenance and communications checks require the approved controller digest and an interactive desktop console'
}
if($env:OS -cne 'Windows_NT' -or ($env:USERNAME -ne 'WDAGUtilityAccount' -and
   (-not $DisposableVM -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware'))){
    throw 'Explicitly disposable Windows guest required'
}
$current=[Diagnostics.Process]::GetCurrentProcess()
try {$session=$current.SessionId} finally {$current.Dispose()}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $elevated=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($identity.IsSystem -or $session -eq 0 -or $elevated -ne $machineHandoff){
        throw 'Use an unelevated desktop shell for the fixture and a separate administrator shell for machine handoffs'
    }
    if($StagedDiscordRepair -or $DiscordProxyAction){
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$accountDigest=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity.User.Value))).Replace('-','').ToLowerInvariant()}
        finally {$sha.Dispose()}
        if($DiscordProxyAction -and $accountDigest -ine $DesktopAccountSHA256){
            throw 'Staged Discord repair requires elevation under the fixture desktop account'
        }
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
    if($guard.Length -le 0 -or $guard.Length -gt 128MB){throw 'Expected a bounded ordinary controller executable'}
    $controllerDigest=(Get-FileHash -InputStream $guard -Algorithm SHA256).Hash.ToLowerInvariant()
    if($ExpectedSHA256 -and $controllerDigest -ine $ExpectedSHA256){throw 'Controller differs from the approved candidate'}
    if($machineHandoff){
        $operation=if($SplitCordAction){
            $SplitCordAction=$SplitCordAction.ToLowerInvariant()
            @{action=$SplitCordAction;engine='splitcord'}
        }else{
            $DiscordProxyAction=$DiscordProxyAction.ToLowerInvariant()
            if($DiscordProxyAction -ceq 'stage'){
                $manifest=Join-Path $env:ProgramData 'AccessWeaver\profiles\drover-owned.json'
                if((Get-FixtureDiscordProxy) -or (Get-FixtureDiscordProxy 'proxifyre') -or
                    (Test-Path -LiteralPath $manifest -ErrorAction Stop)){
                    throw 'Staged repair requires a clean managed proxy baseline'
                }
            }
            Get-DiscordProxyRequest $DiscordProxyAction
        }
        $request=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('AccessWeaver-App-Handoff-'+$HandoffID+'.json')
        $data=[Text.Encoding]::UTF8.GetBytes(($operation | ConvertTo-Json -Compress))
        $requestStream=[IO.File]::Open($request,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try {
            try {$requestStream.Write($data,0,$data.Length)} finally {$requestStream.Dispose()}
            $output=@(& $Executable system apply $request --confirm)
            if($LASTEXITCODE -ne 0){throw 'Application fixture machine workflow failed'}
            if($SplitCordAction){
                New-SplitCordHandoff ($output -join "`n") $HandoffID $SplitCordAction $controllerDigest
            }else{
                New-DiscordProxyReceipt ($output -join "`n") $HandoffID $DiscordProxyAction $controllerDigest
            }
        } finally {[IO.File]::Delete($request)}
        return
    }
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
    $repair=@{}
    $repairChecks=@('discord-proxy-stage','discord-proxy-detach','discord-proxy-reapply','discord-proxy-cleanup')
    if($StagedDiscordRepair){$expectedChecks+=$repairChecks}
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
        schemaVersion=12;runID=$runID;controllerSHA256=$controllerDigest;approvedDigestMatched=[bool]$ExpectedSHA256;
        fixtureSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();
        architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant();
        checks=$null;baselineClear=$false;baselineFailureStage=$null;splitCordIncluded=(-not $SkipSplitCord);
        communicationMethod=$(if($InteractiveCommunications){'operator-observed-two-way'}else{'not-requested'});
        textExercised=$false;voiceExercised=$false;combinedRepairExecuted=$false;
        stagedDiscordRepairRequested=[bool]$StagedDiscordRepair;stagedDiscordRepairExercised=$false;passed=$false
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
            $requestJSON=$Request|ConvertTo-Json -Compress
            if($Request.engine -ceq 'splitcord' -and $Request.action -cin @('app-install','app-remove')){
                $script:appEvidenceStage='operator-machine-workflow'
                $id=[guid]::NewGuid().ToString('N')
                Write-Host 'In the separate administrator shell, run the reviewed fixture and approved controller from protected storage.'
                Write-Host ("Use -DisposableVM -SplitCordAction "+$Request.action+" -HandoffID "+$id+" -ExpectedSHA256 "+$controllerDigest)
                $receipt=Read-Host 'Paste the single-line SplitCord receipt. Press Enter to record failure'
                return (Read-SplitCordHandoff $receipt $id $Request.action $controllerDigest)
            }else{
                [IO.File]::WriteAllText($path,$requestJSON,$encoding)
                $response=Invoke-FixtureCLI @('system','apply',$path,'--confirm')
            }
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
    function Invoke-DiscordProxyWorkflow([string]$Phase){
        $script:appEvidenceStage='operator-machine-workflow'
        $id=[guid]::NewGuid().ToString('N')
        Write-Host 'In the elevated shell for this desktop account, use the reviewed fixture and approved controller from protected storage.'
        Write-Host ("Use -DisposableVM -DiscordProxyAction "+$Phase+" -HandoffID "+$id+" -DesktopAccountSHA256 "+$accountDigest+" -ExpectedSHA256 "+$controllerDigest)
        $receipt=Read-Host 'Paste the single-line Discord proxy receipt. Press Enter to record failure'
        Assert-DiscordProxyReceipt $receipt $id $Phase $controllerDigest
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
            $script:appEvidenceStage='application-baseline'
            if(Get-FixtureAppImage $apps $variant){throw 'The disposable desktop baseline already contains a tested application'}
            if($variant -cin @('discord','discord-ptb')){
                $script:appEvidenceStage='updater-baseline'
                Assert-FixtureDiscordUpdaterAbsent $variant -CheckProcesses
            }
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
        if($StagedDiscordRepair){
            Check 'discord-proxy-stage' {
                $script:appEvidenceStage='proxy-baseline'
                $repair.baseline=@(Get-FixtureDroverFiles (Get-FixtureAppImage (Inspect-Apps) 'discord'))
                $repair.attempted=$true
                Invoke-DiscordProxyWorkflow 'stage'
                $repair.stageConfirmed=$true
                $script:appEvidenceStage='proxy-readback'
                $repair.proxy=Get-FixtureDiscordProxy
                if(-not $repair.proxy){throw 'Initial proxy registration is missing'}
                $deployed=@(Get-FixtureDroverFiles (Get-FixtureAppImage (Inspect-Apps) 'discord'))
                Assert-FixtureDroverApplied $repair.baseline $deployed $deployed[0]
                $repair.assets=$deployed[0]
            }
            Check 'discord-proxy-detach' {
                if(-not $repair.assets){throw 'Initial Discord proxy deployment was not verified'}
                Invoke-DiscordProxyWorkflow 'detach'
                $script:appEvidenceStage='proxy-readback'
                if((Get-FixtureDiscordProxy) -cne $repair.proxy){throw 'Proxy changed when removing the Discord DLL'}
                $observed=@(Get-FixtureDroverFiles (Get-FixtureAppImage (Inspect-Apps) 'discord'))
                Assert-FixtureDroverRestored $repair.baseline $observed
                $repair.detached=$true
            }
        }
        Check 'discord-reinstall' {
            if($StagedDiscordRepair -and -not $repair.detached){throw 'Discord proxy detach prerequisite failed'}
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
            $repair.reinstalled=$true
        }
        if($StagedDiscordRepair){
            Check 'discord-proxy-reapply' {
                if(-not $repair.reinstalled){throw 'Discord replacement was not verified'}
                $script:appEvidenceStage='proxy-readback'
                if((Get-FixtureDiscordProxy) -cne $repair.proxy){throw 'Proxy changed during desktop reinstall'}
                $repair.baseline=@(Get-FixtureDroverFiles (Get-FixtureAppImage (Inspect-Apps) 'discord'))
                Invoke-DiscordProxyWorkflow 'reapply'
                $script:appEvidenceStage='proxy-readback'
                if((Get-FixtureDiscordProxy) -cne $repair.proxy){throw 'Proxy changed during DLL reapplication'}
                $deployed=@(Get-FixtureDroverFiles (Get-FixtureAppImage (Inspect-Apps) 'discord'))
                Assert-FixtureDroverApplied $repair.baseline $deployed $repair.assets
                $repair.reapplied=$true
            }
        }
        Check 'discord-start-after-reinstall' {
            if($StagedDiscordRepair -and -not $repair.reapplied){throw 'Staged proxy repair prerequisite failed'}
            Start-FixtureApp 'discord'
            if($StagedDiscordRepair){
                $script:appEvidenceStage='proxy-module-readback'
                $image=$installedImages['discord']
                $wait=[Diagnostics.Stopwatch]::StartNew()
                do {
                    $loaded=Test-FixtureDiscordDroverLoaded $image $session @([Diagnostics.Process]::GetProcessesByName('Discord'))
                    if(-not $loaded){Start-Sleep -Milliseconds 250}
                }while(-not $loaded -and $wait.Elapsed.TotalSeconds -lt 10)
                if(-not $loaded){throw 'Discord did not load the staged proxy DLL'}
                $deployed=@(Get-FixtureDroverFiles (Get-FixtureAppImage (Inspect-Apps) 'discord'))
                $script:appEvidenceStage='proxy-module-readback'
                Assert-FixtureDroverApplied $repair.baseline $deployed $repair.assets
                if((Get-FixtureDiscordProxy) -cne $repair.proxy){throw 'Proxy changed during desktop launch'}
            }
        }
        Check-FixtureCommunications 'discord' 'discord-start-after-reinstall'
        if($StagedDiscordRepair){
            Check 'discord-proxy-cleanup' {
                if(-not $repair.stageConfirmed){throw 'Initial proxy ownership was not confirmed for cleanup'}
                $script:appEvidenceStage='proxy-readback'
                if($repair.proxy -and (Get-FixtureDiscordProxy) -cne $repair.proxy){
                    throw 'Retain the disposable guest for review of the changed proxy registration'
                }
                Invoke-DiscordProxyWorkflow 'cleanup'
                $script:appEvidenceStage='proxy-readback'
                if((Get-FixtureDiscordProxy) -or (Get-FixtureDiscordProxy 'proxifyre')){throw 'Discord proxy remains registered after cleanup'}
                $observed=@(Get-FixtureDroverFiles (Get-FixtureAppImage (Inspect-Apps) 'discord'))
                Assert-FixtureDroverRestored $repair.baseline $observed
                $repair.cleanupVerified=$true
            }
            if($repair.attempted -and -not $repair.cleanupVerified){throw 'Retain the disposable guest for staged repair cleanup'}
        }
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
            Assert-FixtureDiscordUpdaterAbsent 'discord'
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
    } catch {
        if(-not $report.baselineClear){
            $report.baselineFailureStage=Get-FixtureBaselineFailureStage $script:appEvidenceStage $_.Exception
        }
        throw
    } finally {
        foreach($variant in $attempted){
            Check ('cleanup-'+$variant) {
                if($variant -ceq 'discord' -and $repair.attempted -and -not $repair.cleanupVerified){
                    throw 'Keep the Discord installation until staged repair cleanup can be verified'
                }
                Remove-FixtureApp $variant -Cleanup
            }
        }
        $report.checks=@($checks.ToArray())
        if($StagedDiscordRepair){
            $expectedRepair=$repairChecks+@('discord-reinstall','discord-start-after-reinstall')
            $report.stagedDiscordRepairExercised=Test-FixtureAppChecks @($report.checks | Where-Object {$_.name -cin $expectedRepair}) $expectedRepair
        }
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
