# Execute each phase inside the same disposable Windows guest. Reboot the guest
# between phases; this script never reboots or changes the host itself.
param([ValidateSet('Prepare','Verify')][string]$Phase,[string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',[ValidateSet('auto','doh','dnscrypt')][string]$DNS='auto')
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware'){throw 'Disposable guest required'}
if(-not (Test-Path 'C:\AccessWeaver-Test')){throw 'Test-only guest bundle required'}
$env:ACCESSWEAVER_HOME='C:\AccessWeaver-Test-State'
$results='C:\AccessWeaver-Results'
function Invoke-TestWorkflow([hashtable]$request){
    $path=Join-Path $results ('reboot-'+$request.action+'.request.json');[IO.File]::WriteAllText($path,($request|ConvertTo-Json -Depth 5))
    $output=& $Executable system apply $path --confirm
    $output|Out-File (Join-Path $results ('reboot-'+$request.action+'.output.json'))
    if($LASTEXITCODE -ne 0){throw ('Workflow failed: '+$request.action)}
}
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
if($Phase -eq 'Prepare'){
    Invoke-TestWorkflow @{action='remove-all'}
    $before=Get-DnsClientServerAddress|Select-Object InterfaceIndex,AddressFamily,ServerAddresses|ConvertTo-Json -Depth 6
    if($DNS -eq 'auto'){$DNS=if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){'doh'}else{'dnscrypt'}}
    Invoke-TestWorkflow @{action='install';engine='byedpi';mode='service';bundlePath='C:\AccessWeaver-Test\components'}
    Invoke-TestWorkflow @{action='dns';dns=$DNS;bundlePath='C:\AccessWeaver-Test\components'}
    [IO.File]::WriteAllText((Join-Path $results 'reboot-before.json'),(@{boot=$boot;dns=$before;method=$DNS}|ConvertTo-Json -Depth 8))
}else{
    $saved=Get-Content (Join-Path $results 'reboot-before.json') -Raw|ConvertFrom-Json
    $outcome=@{passed=$false;before=$saved.boot;after=$boot}
    try{
        if($saved.boot -eq $boot){throw 'Guest did not reboot'}
        if((Get-Service 'AccessWeaver-byedpi').Status -ne 'Running'){throw 'Automatic service did not start after reboot'}
        $client=[Net.Sockets.TcpClient]::new();try{$client.Connect('127.0.0.1',1080)}finally{$client.Dispose()}
        $dns=@(Get-DnsClientServerAddress -AddressFamily IPv4|ForEach-Object {$_.ServerAddresses})
        $expected=if($saved.method -eq 'dnscrypt'){'127.0.0.1'}else{'8.8.8.8'}
        if($dns -notcontains $expected){throw 'Selected DNS addresses did not persist'}
        [void](Resolve-DnsName example.com -DnsOnly -ErrorAction Stop)
        $outcome.passed=$true
    }catch{$outcome.error=$_.Exception.Message}
    finally{
        try{Invoke-TestWorkflow @{action='remove-all'};$after=Get-DnsClientServerAddress|Select-Object InterfaceIndex,AddressFamily,ServerAddresses|ConvertTo-Json -Depth 6;$outcome.restored=($saved.dns -eq $after);if(-not $outcome.restored){$outcome.passed=$false;$outcome.cleanupError='Original adapter DNS differs after restoration'}}catch{$outcome.cleanupError=$_.Exception.Message;$outcome.passed=$false}
        [IO.File]::WriteAllText((Join-Path $results 'reboot-results.json'),($outcome|ConvertTo-Json -Depth 8))
    }
}
