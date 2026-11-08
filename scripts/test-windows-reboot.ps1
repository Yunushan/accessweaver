# Execute each phase inside the same disposable Windows guest. Reboot the guest
# between phases; this script never reboots or changes the host itself.
param([ValidateSet('Prepare','Verify')][string]$Phase,[string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',[ValidateSet('auto','doh','dnscrypt')][string]$DNS='auto')
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware'){throw 'Disposable guest required'}
if(-not (Test-Path 'C:\AccessWeaver-Test')){throw 'Test-only guest bundle required'}
. (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
$binaryHash=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
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
    $before=Read-DNSAcceptanceState
    if($DNS -eq 'auto'){$DNS=if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){'doh'}else{'dnscrypt'}}
    [IO.File]::WriteAllText((Join-Path $results 'reboot-before.json'),(@{schemaVersion=2;binarySHA256=$binaryHash;boot=$boot;dns=$before;method=$DNS}|ConvertTo-Json -Depth 12))
    Invoke-TestWorkflow @{action='install';engine='byedpi';mode='service';bundlePath='C:\AccessWeaver-Test\components'}
    Invoke-TestWorkflow @{action='dns';dns=$DNS;bundlePath='C:\AccessWeaver-Test\components'}

}else{
    $saved=Get-Content (Join-Path $results 'reboot-before.json') -Raw|ConvertFrom-Json
    if($saved.schemaVersion -ne 2 -or $saved.binarySHA256 -cne $binaryHash -or $saved.method -cnotin @('doh','dnscrypt')){throw 'Reboot acceptance baseline schema or controller identity differs; prepare a new baseline'}
    [void](Get-DNSAcceptanceIndex $saved.dns)
    $outcome=@{schemaVersion=2;binarySHA256=$binaryHash;passed=$false;before=$saved.boot;after=$boot}
    try{
        if($saved.boot -eq $boot){throw 'Guest did not reboot'}
        if((Get-Service 'AccessWeaver-byedpi').Status -ne 'Running'){throw 'Automatic service did not start after reboot'}
        $client=[Net.Sockets.TcpClient]::new();try{$client.Connect('127.0.0.1',1080)}finally{$client.Dispose()}
        if($saved.method -ceq 'dnscrypt' -and (Get-Service 'AccessWeaver-dnscrypt' -ErrorAction Stop).Status -ne 'Running'){throw 'DNSCrypt service did not start after reboot'}
        Assert-DNSAcceptanceConfigured $saved.dns (Read-DNSAcceptanceState) $saved.method
        Clear-DnsClientCache -ErrorAction Stop
        [void](Resolve-DnsName example.com -DnsOnly -ErrorAction Stop)
        $outcome.passed=$true
    }catch{$outcome.error=$_.Exception.Message}
    finally{
        try{Invoke-TestWorkflow @{action='remove-all'};Assert-DNSAcceptanceRestored $saved.dns (Read-DNSAcceptanceState);$outcome.restored=$true}catch{$outcome.restored=$false;$outcome.cleanupError=$_.Exception.Message;$outcome.passed=$false}
        [IO.File]::WriteAllText((Join-Path $results 'reboot-results.json'),($outcome|ConvertTo-Json -Depth 8))
    }
}
