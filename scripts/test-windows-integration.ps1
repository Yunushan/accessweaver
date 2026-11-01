# Run only in a disposable guest. This script intentionally changes guest services and DNS.
[CmdletBinding()]
param([string]$Bundle='C:\AccessWeaver-Test', [string]$Results='C:\AccessWeaver-Results', [string]$Executable='accessweaver.exe', [switch]$Extended, [switch]$SkipDNSCrypt)
$ErrorActionPreference='Stop'
$computer=Get-CimInstance Win32_ComputerSystem
if($env:USERNAME -ne 'WDAGUtilityAccount' -and $computer.Model -notmatch 'Virtual|VMware') { throw 'Disposable Windows guest required' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Guest administrator token required'}
[void](New-Item -ItemType Directory -Force -Path $Results)
$env:ACCESSWEAVER_HOME='C:\AccessWeaver-Test-State'
$exe=Join-Path $Bundle $Executable
$binaryHash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$os=Get-CimInstance Win32_OperatingSystem
$tests=[Collections.Generic.List[object]]::new()
function Save-Results { [IO.File]::WriteAllText((Join-Path $Results 'integration.json'),(@{computer=$env:COMPUTERNAME;model=$computer.Model;os=$os.Caption;version=$os.Version;binarySHA256=$binaryHash;tests=@($tests.ToArray())}|ConvertTo-Json -Depth 12)) }
function Test-Step([string]$name,[scriptblock]$body) {
    try { & $body; $tests.Add(@{name=$name;passed=$true}) } catch { $tests.Add(@{name=$name;passed=$false;error=$_.Exception.Message;stack=$_.ScriptStackTrace}) }
    Save-Results
}
function Invoke-Workflow([hashtable]$request) {
    $name=$request.action+'-'+$request.engine+'-'+[guid]::NewGuid().ToString('N')
    $path=Join-Path $Results ($name+'.request.json');$request|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $path -Encoding UTF8
    $oldPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try{$output=& $exe system apply $path --confirm 2>&1}finally{$ErrorActionPreference=$oldPreference}
    $code=$LASTEXITCODE
    $output|Out-File -LiteralPath (Join-Path $Results ($name+'.output.txt')) -Encoding utf8
    if($code -ne 0){throw ('Workflow failed: '+($output -join "`n"))}
    return (($output -join "`n")|ConvertFrom-Json)
}
Save-Results
try {
    if(Test-Path -LiteralPath (Join-Path $Bundle 'setup.exe')){Test-Step 'registered application installation' {
        $installer=Start-Process -FilePath (Join-Path $Bundle 'setup.exe') -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG='+ (Join-Path $Results 'setup.log'))) -WindowStyle Hidden -PassThru -Wait
        if($installer.ExitCode -ne 0 -or -not (Test-Path 'C:\Program Files\AccessWeaver\unins000.exe')){throw ('Installer failed '+$installer.ExitCode)}
    }}
    Test-Step 'discovery' { $output=& $exe system discover; if($LASTEXITCODE -ne 0){throw 'Discovery failed'}; $output|Out-File (Join-Path $Results 'discovery.json') }
    Test-Step 'private WireSock configuration without registration' {
        $source=Join-Path $Results 'fixture.conf'
        "[Interface]`nPrivateKey = fixture-only`nAddress = 172.16.0.2/32`n[Peer]`nPublicKey = fixture-only`nEndpoint = example.invalid:2408`nAllowedIPs = 0.0.0.0/0`n"|Set-Content -LiteralPath $source
        $job=Invoke-Workflow @{action='config';engine='wiresock';profileId='integration';configPath=$source;applications=@('fixture.exe');browsers=$true}
        $generated=Get-Content -LiteralPath $job.result.data.configPath -Raw
        if($generated -notmatch 'fixture.exe' -or $generated -notmatch 'chrome.exe'){throw 'Application selection missing'}
    }
    Test-Step 'real ByeDPI automatic SCM service' {
        [void](Invoke-Workflow @{action='install';engine='byedpi';mode='service';bundlePath=(Join-Path $Bundle 'components')})
        $service=Get-Service 'AccessWeaver-byedpi'
        if($service.Status -ne 'Running'){throw 'SCM service not running'}
        $record=Get-CimInstance Win32_Service -Filter "Name='AccessWeaver-byedpi'"
        if($record.StartMode -ne 'Auto'){throw 'Service not automatic'}
        $client=[Net.Sockets.TcpClient]::new();try{$client.Connect('127.0.0.1',1080);$stream=$client.GetStream();$stream.ReadTimeout=5000;$stream.Write([byte[]]@(5,1,0),0,3);$reply=[byte[]]::new(2);$read=$stream.Read($reply,0,2);if($read -ne 2 -or $reply[0] -ne 5 -or $reply[1] -ne 0){throw 'SOCKS5 negotiation failed'}}finally{$client.Dispose()}
    }
    Test-Step 'real SOCKS HTTPS transfer' {
        & curl.exe --fail --silent --show-error --max-time 30 --socks5-hostname 127.0.0.1:1080 https://example.com/ -o (Join-Path $Results 'socks-response.html')
        if($LASTEXITCODE -ne 0){throw ('SOCKS HTTPS curl exit '+$LASTEXITCODE)}
    }
    Test-Step 'SCM stop and restart' {
        Stop-Service 'AccessWeaver-byedpi';(Get-Service 'AccessWeaver-byedpi').WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
        $client=[Net.Sockets.TcpClient]::new();try{$client.Connect('127.0.0.1',1080);throw 'Child listener remained after SCM stop'}catch [Net.Sockets.SocketException]{}finally{$client.Dispose()}
        Start-Service 'AccessWeaver-byedpi';(Get-Service 'AccessWeaver-byedpi').WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    }
    Test-Step 'native DoH configure and exact adapter restoration' {
        $before=Get-DnsClientServerAddress|Select-Object InterfaceIndex,AddressFamily,ServerAddresses|ConvertTo-Json -Depth 6
        $dohBefore=Get-DnsClientDohServerAddress|Sort-Object ServerAddress|Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade|ConvertTo-Json -Depth 4
        [void](Invoke-Workflow @{action='dns';dns='doh'})
        [void](Invoke-Workflow @{action='dns-restore'})
        $after=Get-DnsClientServerAddress|Select-Object InterfaceIndex,AddressFamily,ServerAddresses|ConvertTo-Json -Depth 6
        if($before -ne $after){throw 'Adapter DNS differs after restoration'}
        $dohAfter=Get-DnsClientDohServerAddress|Sort-Object ServerAddress|Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade|ConvertTo-Json -Depth 4
        if($dohBefore -ne $dohAfter){throw 'Native DoH metadata differs after restoration'}
    }
    if($Extended){
        if(-not $SkipDNSCrypt){Test-Step 'DNSCrypt service and resolver restoration' {
            $before=Get-DnsClientServerAddress|Select-Object InterfaceIndex,AddressFamily,ServerAddresses|ConvertTo-Json -Depth 6
            [void](Invoke-Workflow @{action='dns';dns='dnscrypt'})
            if((Get-Service 'AccessWeaver-dnscrypt').Status -ne 'Running'){throw 'DNSCrypt service not running'}
            [void](Invoke-Workflow @{action='dns-restore'})
            $after=Get-DnsClientServerAddress|Select-Object InterfaceIndex,AddressFamily,ServerAddresses|ConvertTo-Json -Depth 6
            if($before -ne $after){throw 'DNSCrypt DNS restoration differs'}
            [void](Invoke-Workflow @{action='remove';engine='dnscrypt'})
        }}else{$tests.Add(@{name='DNSCrypt service and resolver restoration';skipped=$true;reason='Default Windows resolver timeout remains under investigation; prior failure reports retained'});Save-Results}
        foreach($engine in @('goodbyedpi','zapret','zapret2')){
            Test-Step ($engine+' real packet service and live hostlist') {
                $arguments=switch($engine){'goodbyedpi'{@('-5')};'zapret'{@('--wf-tcp=443','--filter-tcp=443','--dpi-desync=fake','--dpi-desync-ttl=7')};'zapret2'{@('--wf-tcp-out=443','--filter-tcp=443','--payload=tls_client_hello','--lua-desync=multidisorder:pos=2:seqovl=1')}}
                [void](Invoke-Workflow @{action='install';engine=$engine;mode='service';bundlePath=(Join-Path $Bundle 'components');args=@($arguments);domains=@('example.invalid');enabled=$true})
                if((Get-Service ('AccessWeaver-'+$engine)).Status -ne 'Running'){throw 'Packet service not running'}
                [void](Invoke-Workflow @{action='hostlist';engine=$engine;domains=@('example.org');enabled=$true})
                [void](Invoke-Workflow @{action='hostlist';engine=$engine;enabled=$false})
                $active=Join-Path $env:ProgramData ('AccessWeaver\components\'+$engine+'\accessweaver-hostlist.txt')
                if([IO.File]::ReadAllText($active).Trim()){throw 'Hostlist disable did not empty active list'}
                [void](Invoke-Workflow @{action='hostlist';engine=$engine;enabled=$true})
                if((Get-Content -LiteralPath $active -Raw).Trim() -ne 'example.org'){throw 'Saved list not restored'}
                [void](Invoke-Workflow @{action='remove';engine=$engine})
            }
            # A failing method must not block the other packet-engine tests.
            try{[void](Invoke-Workflow @{action='remove';engine=$engine})}catch{}
        }
    }
} finally {
    Test-Step 'remove owned services and firewall rules' {
        [void](Invoke-Workflow @{action='remove-all'})
        if(Get-Service 'AccessWeaver-*' -ErrorAction SilentlyContinue){throw 'Owned service remains'}
        if(Get-NetFirewallRule -Name 'AccessWeaver-*' -ErrorAction SilentlyContinue){throw 'Owned firewall rules remain'}
        if(Get-CimInstance Win32_SystemDriver|Where-Object {$_.Name -like 'WinDivert*' -and $_.PathName -like '*\ProgramData\AccessWeaver\components\*'}){throw 'Managed WinDivert driver remains registered'}
    }
    if(Test-Path 'C:\Program Files\AccessWeaver\unins000.exe'){Test-Step 'registered application uninstallation' {
        [void](Invoke-Workflow @{action='uninstall'})
        $deadline=[DateTime]::UtcNow.AddSeconds(60)
        while((Test-Path 'C:\Program Files\AccessWeaver\accessweaver.exe') -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 500}
        if(Test-Path 'C:\Program Files\AccessWeaver\accessweaver.exe'){throw 'Workflow-launched registered uninstaller did not remove the application'}
    }}
    Save-Results
    [IO.File]::WriteAllText((Join-Path $Results 'completed.txt'),[DateTime]::UtcNow.ToString('o'))
}
