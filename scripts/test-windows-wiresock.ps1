# Local traffic tests use generated keys and a userspace peer, without a WARP account.
param([string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',[switch]$DisposableVM,[switch]$RemoveVendor)
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -and (-not $DisposableVM -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware')){throw 'Explicitly disposable Windows guest required'}
$env:ACCESSWEAVER_HOME='C:\AccessWeaver-Test-State';$results='C:\AccessWeaver-Results';$checks=[Collections.Generic.List[object]]::new()
[void](New-Item -ItemType Directory -Force -Path $results)
function Test-Check([string]$name,[scriptblock]$body){try{& $body;$checks.Add(@{name=$name;passed=$true})}catch{$checks.Add(@{name=$name;passed=$false;error=$_.Exception.Message})};[IO.File]::WriteAllText((Join-Path $results 'wiresock.json'),(ConvertTo-Json -InputObject @($checks.ToArray()) -Depth 8))}
function Invoke-VendorWorkflow([hashtable]$request){
    $id='wiresock-'+$request.action+'-'+[guid]::NewGuid().ToString('N');$path=Join-Path $results ($id+'.json');[IO.File]::WriteAllText($path,($request|ConvertTo-Json -Depth 5))
    $old=$ErrorActionPreference;$ErrorActionPreference='Continue';try{$output=& $Executable system apply $path --confirm 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
    $output|Out-File (Join-Path $results ($id+'.output.txt'));if($code -ne 0){throw ($output -join "`n")};return (($output -join "`n")|ConvertFrom-Json)
}
$bundle=Split-Path -Parent $Executable
$fixture=Join-Path $env:ACCESSWEAVER_HOME ('wireguard-fixture-'+[guid]::NewGuid().ToString('N'))
$config=Join-Path $fixture 'client.conf';$script:peerProcess=$null
$selected=Join-Path $bundle 'probe-selected.exe';$direct=Join-Path $bundle 'probe-direct.exe'
function Invoke-Probe([string]$program,[string[]]$arguments){$old=$ErrorActionPreference;$ErrorActionPreference='Continue';try{& $program $arguments 2>&1|Out-File (Join-Path $results 'wiresock-probes.log') -Append;return $LASTEXITCODE}finally{$ErrorActionPreference=$old}}
try{
    Test-Check 'signed WireSock installation, unique import and real peer connection' {
        $env:ACCESSWEAVER_TEST_VM='1'
        $script:peerProcess=Start-Process -FilePath (Join-Path $bundle 'wgpeer.exe') -ArgumentList @('serve',('"'+$fixture+'"')) -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $results 'wgpeer-errors.log')
        $deadline=[DateTime]::UtcNow.AddSeconds(15)
        while(-not (Test-Path (Join-Path $fixture 'ready.json')) -and -not $script:peerProcess.HasExited -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path $config)){throw 'Local WireGuard fixture did not become ready'}
        [void](Invoke-VendorWorkflow @{action='install';engine='wiresock';mode='alternative';configPath=$config;profileId='local-peer-test';applications=@('probe-selected.exe')})
        $record=Get-Content C:\ProgramData\AccessWeaver\profiles\wiresock-owned.json -Raw|ConvertFrom-Json
        if($record.profile -notmatch '^AccessWeaver-[a-f0-9]{32}$'){throw 'Managed import name is not unique'}
    }
    Test-Check 'per-application TCP and UDP through WireSock over IPv4 and IPv6' {
        foreach($probe in @(@('http','http://198.51.100.1:8080/'),@('udp','198.51.100.1:7000'),@('http','http://[fd42:6177::1]:8080/'),@('udp','[fd42:6177::1]:7000'))){
            $ok=$false;foreach($attempt in 1..3){if((Invoke-Probe $selected $probe) -eq 0){$ok=$true;break};Start-Sleep -Seconds 1}
            if(-not $ok){throw ('Selected process could not reach fixture: '+($probe -join ' '))}
        }
        if((Invoke-Probe $direct @('http','http://198.51.100.1:8080/')) -eq 0){throw 'Unselected process reached the private tunnel fixture'}
        Start-Sleep -Seconds 2
        $traffic=Get-Content (Join-Path $fixture 'traffic.json') -Raw|ConvertFrom-Json
        if([int64]$traffic.last_handshake_time_sec -le 0 -or [int64]$traffic.rx_bytes -le 0 -or [int64]$traffic.tx_bytes -le 0){throw 'Peer did not report a handshake and encrypted traffic'}
        $traffic|ConvertTo-Json|Out-File (Join-Path $results 'wireguard-peer-counters.json')
    }
    Test-Check 'periodic refresh task registration and execution' {
        [void](Invoke-VendorWorkflow @{action='refresh';enabled=$true})
        Start-ScheduledTask -TaskName 'AccessWeaver-WireSock-Refresh';Start-Sleep -Seconds 5
        $info=Get-ScheduledTaskInfo -TaskName 'AccessWeaver-WireSock-Refresh';if($info.LastTaskResult -ne 0){throw ('Refresh task result '+$info.LastTaskResult)}
        [void](Invoke-VendorWorkflow @{action='refresh';enabled=$false})
        if(Get-ScheduledTask 'AccessWeaver-WireSock-Refresh' -ErrorAction SilentlyContinue){throw 'Refresh task remains'}
    }
    Test-Check 'managed WireSock disconnect stops routed traffic' {[void](Invoke-VendorWorkflow @{action='disconnect'});if((Invoke-Probe $selected @('http','http://198.51.100.1:8080/')) -eq 0){throw 'Private tunnel fixture remained reachable after disconnect'}}
}finally{
    Test-Check 'managed WireSock profile removal' {[void](Invoke-VendorWorkflow @{action='remove';engine='wiresock'});if(Test-Path C:\ProgramData\AccessWeaver\profiles\wiresock-owned.json){throw 'Ownership record remains'}}
    if($RemoveVendor){Test-Check 'registered WireSock vendor uninstallation' {[void](Invoke-VendorWorkflow @{action='vendor-uninstall';engine='wiresock'})}}
    if($script:peerProcess -and -not $script:peerProcess.HasExited){$script:peerProcess.Kill();$script:peerProcess.WaitForExit()}
    [IO.File]::WriteAllText((Join-Path $results 'wiresock-completed.txt'),[DateTime]::UtcNow.ToString('o'))
}
