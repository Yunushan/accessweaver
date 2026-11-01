# Destructive application tests: disposable guest and its test account only.
param([string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',[switch]$SkipSplitCord,[switch]$DisposableVM,[string]$ResultsDirectory='')
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -and (-not $DisposableVM -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware')){throw 'Explicitly disposable Windows guest required'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.IsSystem -or ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'Run application tests in an unelevated PowerShell window in the disposable desktop account'}
$env:ACCESSWEAVER_HOME=Join-Path $env:LOCALAPPDATA 'AccessWeaver-App-Test-State'
$results=if($ResultsDirectory){[IO.Path]::GetFullPath($ResultsDirectory)}else{Join-Path $env:LOCALAPPDATA 'AccessWeaver-App-Test-Results'}
[void](New-Item -ItemType Directory -Force -Path $results)
$checks=[Collections.Generic.List[object]]::new()
function Check([string]$name,[scriptblock]$body){try{& $body;$checks.Add(@{name=$name;passed=$true})}catch{$checks.Add(@{name=$name;passed=$false;error=$_.Exception.Message;stack=$_.ScriptStackTrace})};[IO.File]::WriteAllText((Join-Path $results 'applications.json'),(ConvertTo-Json -InputObject @($checks.ToArray()) -Depth 8))}
function Invoke-AppWorkflow([hashtable]$request){
    $id=$request.action+'-'+$request.engine+'-'+[guid]::NewGuid().ToString('N');$path=Join-Path $results ($id+'.json');[IO.File]::WriteAllText($path,($request|ConvertTo-Json -Depth 5))
    $old=$ErrorActionPreference;$ErrorActionPreference='Continue';try{$output=& $Executable system apply $path --confirm 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
    $output|Out-File (Join-Path $results ($id+'.output.txt'))
    if($code -ne 0){throw ($output -join "`n")};return (($output -join "`n")|ConvertFrom-Json)
}
function Inspect-Apps {$output=& $Executable system discover;if($LASTEXITCODE -ne 0){throw 'Discovery failed'};return (($output -join "`n")|ConvertFrom-Json).result.data.applications}
try{
    Check 'official stable Discord installation and discovery' {[void](Invoke-AppWorkflow @{action='app-install';engine='discord'});if(-not (Inspect-Apps).discord){throw 'Stable Discord missing'}}
    Check 'start installed Discord' {[void](Invoke-AppWorkflow @{action='app-start';engine='discord'});Start-Sleep -Seconds 3;if(-not (Get-Process Discord -ErrorAction SilentlyContinue)){throw 'Discord process missing'}}
    Check 'combined repair blocked without touching stable Discord' {
        $before=(Inspect-Apps).discord
        $rejected=$false;try{[void](Invoke-AppWorkflow @{action='app-repair';engine='discord'})}catch{$rejected=$_.Exception.Message -match 'privilege-separated'}
        if(-not $rejected -or (Inspect-Apps).discord -ne $before){throw 'Combined repair was not safely rejected'}
    }
    Check 'clean PTB installation removes stable Discord' {
        [void](Invoke-AppWorkflow @{action='app-install';engine='discord-ptb';clean=$true});$apps=Inspect-Apps
        if($apps.discord -or -not $apps.'discord-ptb'){throw 'Clean PTB application state incorrect'}
    }
    Check 'PTB start and removal' {[void](Invoke-AppWorkflow @{action='app-start';engine='discord-ptb'});[void](Invoke-AppWorkflow @{action='app-remove';engine='discord-ptb'});if((Inspect-Apps).'discord-ptb'){throw 'PTB remains installed'}}
    if(-not $SkipSplitCord){Check 'SplitCord official installation, start and removal' {
        [void](Invoke-AppWorkflow @{action='app-install';engine='splitcord'});if(-not (Inspect-Apps).splitcord){throw 'SplitCord missing'}
        [void](Invoke-AppWorkflow @{action='app-start';engine='splitcord'});[void](Invoke-AppWorkflow @{action='app-remove';engine='splitcord'})
        if((Inspect-Apps).splitcord){throw 'SplitCord remains installed'}
    }}
}finally{
    Check 'application-test cleanup' {foreach($variant in @('discord','discord-ptb','splitcord')){[void](Invoke-AppWorkflow @{action='app-remove';engine=$variant})}}
    [IO.File]::WriteAllText((Join-Path $results 'applications-completed.txt'),[DateTime]::UtcNow.ToString('o'))
}
if(@($checks | Where-Object {-not $_.passed}).Count){throw 'Application acceptance failed; inspect applications.json'}
