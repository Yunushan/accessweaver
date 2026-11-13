# Run manually as Administrator inside AccessWeaver-Clean-Windows-Test only.
# The control file selects fixed test stages; it never supplies shell commands.
$ErrorActionPreference='Stop'
$share='\\vmware-host\Shared Folders\AccessWeaver-Test'
$outputShare='\\vmware-host\Shared Folders\AccessWeaver-Results'
$local='C:\AccessWeaver-Test';$results='C:\AccessWeaver-Results'
$tools=Join-Path $env:ProgramFiles 'VMware\VMware Tools\vmtoolsd.exe'
if(-not (Test-Path $tools)){throw 'VMware Tools must be installed inside the disposable test VM'}
$marker=& $tools --cmd 'info-get guestinfo.accessweaverParity'
if($LASTEXITCODE -ne 0 -or ($marker -join '').Trim() -ne 'AccessWeaver-Clean-Windows-Test'){throw 'VM identity marker does not match the disposable AccessWeaver test VM'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this test launcher as Administrator inside the guest'}
[void](New-Item -ItemType Directory -Force -Path $local,$results,$outputShare)
$env:ACCESSWEAVER_TEST_VM='1';$env:ACCESSWEAVER_HOME='C:\AccessWeaver-Test-State'
$status=@{state='ready';stage='';id='';computer=$env:COMPUTERNAME;user=$env:USERNAME;startedAt=[DateTime]::UtcNow.ToString('o')}
function Publish-TestStatus {
    $status.updatedAt=[DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $outputShare 'controller.json'),($status|ConvertTo-Json -Depth 8))
}
function Copy-TestTree([string]$source,[string]$destination) {
    [void](New-Item -ItemType Directory -Force -Path $destination)
    & robocopy.exe $source $destination /E /R:2 /W:1 /NFL /NDL /NJH /NJS | Out-Null
    if($LASTEXITCODE -gt 7){throw ('Test file copy failed: '+$LASTEXITCODE)}
}
function Copy-TestInputs([string]$executable) {
    if($executable -notmatch '^accessweaver[a-zA-Z0-9-]*\.exe$'){throw 'Unsupported controller filename'}
    if(-not (Test-Path -LiteralPath (Join-Path $share 'dns-acceptance-state.ps1'))){throw 'DNS acceptance state helper must be staged with the candidate scripts'}
    foreach($name in @($executable,'setup.exe','wgpeer.exe','probe-selected.exe','probe-direct.exe','test-windows-integration.ps1','dns-acceptance-state.ps1','test-windows-apps.ps1','test-windows-wiresock.ps1','test-windows-reboot.ps1','vmware-reboot-resume.ps1')){
        $source=Join-Path $share $name;if(Test-Path $source){Copy-Item -LiteralPath $source -Destination (Join-Path $local $name) -Force}
    }
    foreach($name in @('components','fixture-licenses')){$source=Join-Path $share $name;if(Test-Path $source){Copy-TestTree $source (Join-Path $local $name)}}
    if(-not (Test-Path (Join-Path $local $executable))){throw 'Test controller was not staged'}
}
function Publish-TestResults {Copy-TestTree $results $outputShare}
Publish-TestStatus
Write-Host 'Disposable VM test controller ready. Close this window to stop it. No passwords are collected.'
$deadline=[DateTime]::UtcNow.AddHours(2);$last=''
try{
    while([DateTime]::UtcNow -lt $deadline){
        $control=Join-Path $share 'control.json'
        if(-not (Test-Path $control)){Start-Sleep -Seconds 2;continue}
        try{$request=Get-Content -LiteralPath $control -Raw|ConvertFrom-Json}catch{Start-Sleep -Seconds 2;continue}
        if(-not $request.id -or $request.id -eq $last){Start-Sleep -Seconds 2;continue}
        if($request.id -notmatch '^[a-zA-Z0-9-]{1,64}$'){throw 'Invalid test-stage identifier'}
        $last=$request.id;$status.id=$last;$status.stage=$request.stage;$status.state='running';$status.Remove('error');Publish-TestStatus
        try{
            if($request.stage -eq 'exit'){break}
            if($request.stage -notin @('system','apps','wiresock','reboot-prepare')){throw 'Unknown test stage'}
            $executable=if($request.executable){[string]$request.executable}else{'accessweaver.exe'}
            Copy-TestInputs $executable;$binary=Join-Path $local $executable
            switch($request.stage){
                'system' {& (Join-Path $local 'test-windows-integration.ps1') -Executable $executable -Extended}
                'apps' {throw 'Application tests require an unelevated desktop window. Run test-windows-apps.ps1 -DisposableVM there and collect its LocalAppData\AccessWeaver-App-Test-Results separately.'}
                'wiresock' {& (Join-Path $local 'test-windows-wiresock.ps1') -Executable $binary -DisposableVM -RemoveVendor}
                'reboot-prepare' {
                    $taskName='AccessWeaver-Parity-Reboot-Verify'
                    if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){
                        throw 'A DNS reboot verification task is already registered'
                    }
                    $method=if($request.dns){[string]$request.dns}else{'auto'}
                    if($method -cnotin @('auto','doh','dnscrypt')){throw 'Unknown DNS reboot method'}
                    & (Join-Path $local 'test-windows-reboot.ps1') -Phase Prepare -Executable $binary -DNS $method
                    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\AccessWeaver-Test\vmware-reboot-resume.ps1 -ExecutableName '+$executable
                    $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $arguments
                    $trigger=New-ScheduledTaskTrigger -AtStartup;$trigger.Delay='PT30S'
                    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval ([TimeSpan]::FromMinutes(1))
                    [void](Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest)
                }
            }
            $status.state='completed'
            if($request.stage -ne 'reboot-prepare'){Publish-TestResults}
        }catch{
            $status.state='failed';$status.error=$_.Exception.Message
            if($request.stage -ne 'reboot-prepare'){try{Publish-TestResults}catch{}}
        }
        Publish-TestStatus
        if($request.stage -eq 'reboot-prepare'){return}
    }
}finally{
    if($status.stage -ne 'reboot-prepare'){$status.state='stopped';Publish-TestStatus}
}
