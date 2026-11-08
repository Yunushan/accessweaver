# Native changes require a fresh non-domain GitHub-hosted VM. Never run locally.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Binary,[Parameter(Mandatory=$true)][string]$BinarySHA256,[Parameter(Mandatory=$true)][string]$ReportPath,[string]$Method='doh',[string]$ScenarioKind='roundtrip')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Assert-NativeOrdinaryPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){
        if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Native fixture reparse boundary refused'}}
        $next=Split-Path -Parent $current;if($next -eq $current){break};$current=$next
    }
}
function New-NativeDNSCryptBundle([string]$PrivateRoot,[string]$Architecture) {
    $script:componentStage='architecture'
    $pin=switch -CaseSensitive ($Architecture){
        'amd64' {@{asset='win64';size=5062148;hash='9e498cb9bdbae57756db19ce516362ac307e9340a6996214964cfcc7c489abc3';machine=0x8664}}
        'arm64' {@{asset='winarm';size=4491141;hash='db327b3a75d5526038468bf7d825a3106704753086b44cb02ae6ef6c69a9a875';machine=0xaa64}}
        default {throw 'DNSCrypt native architecture refused'}
    }
    $script:componentStage='directory'
    $directory=Join-Path $PrivateRoot 'upstream-dnscrypt';[void][IO.Directory]::CreateDirectory($directory)
    $archive=Join-Path $directory 'upstream.zip';$url='https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.20/dnscrypt-proxy-'+$pin.asset+'-2.1.20.zip'
    $script:componentStage='modules'
    Add-Type -AssemblyName System.Net.Http;Add-Type -AssemblyName System.IO.Compression
    $script:componentStage='client'
    $client=[Net.Http.HttpClient]::new();$response=$null;$inputStream=$null;$output=$null;$zip=$null;$zipStream=$null
    try {
        $client.Timeout=[TimeSpan]::FromSeconds(90);$client.DefaultRequestHeaders.UserAgent.ParseAdd('AccessWeaver-native-DNS-acceptance')
        $script:componentStage='download-headers'
        $response=$client.GetAsync($url,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $status=[int]$response.StatusCode;$script:componentHTTPStatus=if($status -in @(200,400,401,403,404,408,429,500,502,503,504)){$status}else{-1}
        [void]$response.EnsureSuccessStatusCode()
        $script:componentStage='download-size'
        if($null -ne $response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -ne $pin.size){throw 'DNSCrypt upstream size differs'}
        $script:componentStage='download-body'
        $inputStream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();$output=[IO.FileStream]::new($archive,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $buffer=[byte[]]::new(32768);$total=0
        while(($count=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0){$total+=$count;$script:componentDownloadedBytes=[Math]::Min(8388609,$total);if($total -gt $pin.size){throw 'DNSCrypt upstream bound exceeded'};$output.Write($buffer,0,$count)}
        $output.Dispose();$output=$null
        $script:componentStage='archive-digest'
        if($total -ne $pin.size -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.hash){throw 'DNSCrypt upstream digest differs'}
        $script:componentStage='archive-open'
        $zipStream=[IO.File]::OpenRead($archive);$zip=[IO.Compression.ZipArchive]::new($zipStream,[IO.Compression.ZipArchiveMode]::Read,$true)
        $script:componentStage='archive-count';$script:componentArchiveEntries=[Math]::Min(257,$zip.Entries.Count)
        if($zip.Entries.Count -gt 256){throw 'DNSCrypt upstream entry bound exceeded'}
        # Copy exactly two fixed basenames; archive paths never become destinations.
        foreach($name in @('dnscrypt-proxy.exe','example-dnscrypt-proxy.toml')){
            $script:componentStage=if($name -ceq 'dnscrypt-proxy.exe'){'binary-select'}else{'example-select'}
            $entries=@($zip.Entries | Where-Object {$_.Name -ceq $name})
            $limit=if($name -ceq 'dnscrypt-proxy.exe'){32MB}else{256KB}
            if($entries.Count -ne 1 -or $entries[0].Length -le 0 -or $entries[0].Length -gt $limit){throw 'DNSCrypt upstream member shape differs'}
            $script:componentStage=if($name -ceq 'dnscrypt-proxy.exe'){'binary-copy'}else{'example-copy'}
            $source=$entries[0].Open();$target=$null
            try {
                $target=[IO.FileStream]::new((Join-Path $directory $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$written=0
                while(($count=$source.Read($buffer,0,$buffer.Length)) -gt 0){$written+=$count;if($written -gt $entries[0].Length){throw 'DNSCrypt member bound exceeded'};$target.Write($buffer,0,$count)}
                if($written -ne $entries[0].Length){throw 'DNSCrypt member incomplete'}
            }finally{if($null -ne $target){$target.Dispose()};$source.Dispose()}
        }
        $script:componentStage='pe-header'
        $binary=Join-Path $directory 'dnscrypt-proxy.exe';$reader=[IO.BinaryReader]::new([IO.File]::OpenRead($binary))
        try {
            if($reader.ReadUInt16() -ne 0x5a4d){throw 'DNSCrypt PE header differs'}
            $script:componentStage='pe-offset'
            $reader.BaseStream.Position=60;$offset=$reader.ReadUInt32()
            if($offset -lt 64 -or $offset -gt 1MB -or $offset -gt $reader.BaseStream.Length-6){throw 'DNSCrypt PE offset differs'}
            $script:componentStage='pe-machine'
            $reader.BaseStream.Position=$offset
            if($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne $pin.machine){throw 'DNSCrypt PE native machine differs'}
        }finally{$reader.Dispose()}
        $script:componentStage='binary-digest';$binaryHash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:componentStage='complete'
        return @{directory=$directory;version='2.1.20';archiveSHA256=$pin.hash;binarySHA256=$binaryHash}
    }finally{if($null -ne $zip){$zip.Dispose()};if($null -ne $zipStream){$zipStream.Dispose()};if($null -ne $output){$output.Dispose()};if($null -ne $inputStream){$inputStream.Dispose()};if($null -ne $response){$response.Dispose()};$client.Dispose()}
}
if(-not [IO.Path]::IsPathRooted($ReportPath)){throw 'Native report requires an absolute path'}
$ReportPath=[IO.Path]::GetFullPath($ReportPath);Assert-NativeOrdinaryPath $ReportPath
$reportParent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ReportPath)) -Force -ErrorAction Stop
if(-not $reportParent.PSIsContainer -or [IO.Directory]::GetFileSystemEntries($reportParent.FullName).Length -ne 0){throw 'Native report parent must be empty and ordinary'}
$reportCreated=$reportParent.CreationTimeUtc.Ticks;$project=Split-Path -Parent $PSScriptRoot
$sources=@('scripts/test-native-doh.ps1','scripts/native-doh-scenario.ps1','scripts/dns-acceptance-state.ps1','scripts/test-dns-acceptance-state.ps1','scripts/check-native-environment.cjs','.github/workflows/native-doh.yml','internal/workflow/windows.ps1','internal/workflow/manager.go','cmd/accessweaver/system.go','go.mod','go.sum')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$script:componentStage='not-started';$script:componentFailureCode='none';$script:componentHTTPStatus=0;$script:componentDownloadedBytes=0;$script:componentArchiveEntries=0
$script:cliCount=0;$script:joined=0;$script:overflow=$false;$script:captureFailed=$false;$script:diagnosticWaitExceeded=$false
$script:captureStage='not-started';$script:captureProgress=@{adapterTotal=0;adapterOrdinal=0;selected=$false};$script:configureExit=-1;$script:restoreExit=-1;$script:answers=0
$script:forwarderPeerClosures=0;$script:forwarderFailureCode='none';$script:rollbackSnapshotRemoved=$false;$script:rollbackServiceRemoved=$false;$script:resolverVerificationRejected=$false;$script:configureElapsedMilliseconds=0;$script:forwarder=$null;$script:forwarderRequests=0;$script:forwarderResponses=0;$script:forwarderFailed=$false;$script:configuredDuringRejectedApply=$false;$script:installedComponentVerified=$false;$script:rollbackBefore=$null;$rollbackScenario=$null;$script:baselineAnswers=0;$script:rollbackPoll=$null
$script:failureServiceStopped=$false;$script:resolverProcessExited=$false;$script:failedResolverObserved=$false;$script:restoredAnswers=0
$component=$null;$serviceRunning=$false;$serviceAutomatic=$false;$serviceRemoved=$false;$script:cleanupExit=-1
$adapterShapes=@();$probeOutcome='not-started';$environmentVerified=$false;$nativeProcessVerified=$false;$binaryVerified=$false;$snapshotRemoved=$false;$scenario=$null;$outcome='failed';$code='environment-guard'
try {
    if($ScenarioKind -cnotin @('roundtrip','service-loss','verification-failure') -or ($ScenarioKind -cin @('service-loss','verification-failure') -and $Method -cne 'dnscrypt') -or $Method -cnotin @('doh','dnscrypt')){throw 'Native DNS method refused'}
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:ACCESSWEAVER_EXPECT_GOOS -cne 'windows' -or $env:ACCESSWEAVER_EXPECT_GOARCH -cnotin @('amd64','arm64')){throw 'Hosted native Windows guard refused'}
    if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Stock Windows PowerShell5.1 required'}
    if($env:GITHUB_SHA -notmatch '^[a-f0-9]{40}$' -or $env:GO_VERSION -cne '1.27.3'){throw 'Native source or SDK identity missing'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Unexpected interop environment'}}
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if($computer.Model -notmatch 'Virtual|VMware' -or $computer.PartOfDomain -ne $false){throw 'Fresh non-domain virtual machine required'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Hosted administrator token required'}
    Add-Type -TypeDefinition '
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class AccessWeaverNativeDoHIdentity {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    public static bool Matches(string architecture) {
        using (Process process = Process.GetCurrentProcess()) {
            ushort machine, native;
            if (!IsWow64Process2(process.Handle, out machine, out native)) return false;
            return machine == 0 && native == (architecture == "amd64" ? 0x8664 : 0xaa64);
        }
    }
}
'
    if(-not [AccessWeaverNativeDoHIdentity]::Matches($env:ACCESSWEAVER_EXPECT_GOARCH)){throw 'Native PowerShell process architecture differs'}
    $nativeProcessVerified=$true
    $code='capability-guard'
    foreach($command in @('Get-NetAdapter','Get-DnsClientServerAddress','Set-DnsClientServerAddress','Get-DnsClientDohServerAddress','Set-DnsClientDohServerAddress','Add-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress','Clear-DnsClientCache','Resolve-DnsName')){if(-not (Get-Command $command -ErrorAction SilentlyContinue)){throw 'Required native DNS capability unavailable'}}
    $code='fresh-state-guard'
    $machineRoot=Join-Path $env:ProgramData 'AccessWeaver';Assert-NativeOrdinaryPath $machineRoot
    if(Test-Path -LiteralPath $machineRoot){throw 'Preexisting product machine state refused'}
    if(@(Get-Service -Name 'AccessWeaver*' -ErrorAction SilentlyContinue).Count -ne 0){throw 'Preexisting product services refused'}
    $code='binary-guard'
    $Binary=[IO.Path]::GetFullPath($Binary);Assert-NativeOrdinaryPath $Binary
    $binaryItem=Get-Item -LiteralPath $Binary -Force -ErrorAction Stop;$workspace=[IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\')+'\'
    if(-not $Binary.StartsWith($workspace,[StringComparison]::OrdinalIgnoreCase) -or $binaryItem.PSIsContainer -or $binaryItem.Length -le 0 -or $binaryItem.Length -gt 128MB -or $BinarySHA256 -notmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BinarySHA256){throw 'Source-built native binary identity refused'}
    $binaryVerified=$true
    $code='private-root-guard'
    $privateRoot=[IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'),('AccessWeaver-NativeDoH-'+[guid]::NewGuid().ToString('N')))
    Assert-NativeOrdinaryPath $privateRoot
    if(Test-Path -LiteralPath $privateRoot){throw 'Native fixture directory already exists'}
    [void][IO.Directory]::CreateDirectory($privateRoot)
    $security=[Security.AccessControl.DirectorySecurity]::new();$security.SetOwner($identity.User);$security.SetAccessRuleProtection($true,$false)
    foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $privateRoot -AclObject $security -ErrorAction Stop
    $controllerHome=Join-Path $privateRoot 'controller';[void][IO.Directory]::CreateDirectory($controllerHome);Assert-NativeOrdinaryPath $privateRoot
    $environmentVerified=$true;$code='component-stage'
    . (Join-Path $PSScriptRoot 'native-doh-scenario.ps1')
    if($Method -ceq 'dnscrypt'){try{$component=New-NativeDNSCryptBundle $privateRoot $env:ACCESSWEAVER_EXPECT_GOARCH}catch{$script:componentFailureCode=Get-NativeDNSComponentFailure $_.Exception $script:componentHTTPStatus;throw}}
    $code='native-scenario'
    . (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
    function Invoke-NativeDoHCLI([hashtable]$Request) {
        $valid=($Request.action -ceq 'dns' -and $Request.dns -ceq $Method -and $Request.Count -eq 2) -or ($Request.action -ceq 'dns-restore' -and $Request.Count -eq 1) -or ($Method -ceq 'dnscrypt' -and $Request.action -ceq 'remove' -and $Request.engine -ceq 'dnscrypt' -and $Request.Count -eq 2)
        if(-not $valid){throw 'Native fixture request refused'}
        if($Request.action -ceq 'dns' -and $Method -ceq 'dnscrypt'){$Request.bundlePath=$component.directory}
        $requestPath=Join-Path $privateRoot ($Request.action+'.request.json');[IO.File]::WriteAllText($requestPath,($Request|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        if((Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BinarySHA256){throw 'Native binary changed before dispatch'}
        $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Binary;$start.Arguments='system apply "'+$requestPath+'" --confirm';$start.WorkingDirectory=$privateRoot
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.EnvironmentVariables['ACCESSWEAVER_HOME']=$controllerHome
        $process=[Diagnostics.Process]::new();$process.StartInfo=$start
        try {
            if(-not $process.Start()){throw 'Native CLI did not start'}
            $script:cliCount++;$clock=[Diagnostics.Stopwatch]::StartNew();$captures=@()
            foreach($reader in @($process.StandardOutput,$process.StandardError)){
                $capture=@{reader=$reader;buffer=[char[]]::new(4096);done=$false;count=0;task=$null;suffix=''}
                try{$capture.task=$reader.ReadAsync($capture.buffer,0,$capture.buffer.Length)}catch{$capture.done=$true;$script:captureFailed=$true;$reader.Dispose()};$captures+=@($capture)
            }
            # Discard private output in bounded buffers. Join the actual process
            # and both streams before restoring, including after capture failure.
            while(-not $process.HasExited -or @($captures | Where-Object {-not $_.done}).Count -ne 0){
                foreach($capture in $captures){
                    if(-not $capture.done -and $capture.task.IsCompleted){
                        try{
                            $count=$capture.task.GetAwaiter().GetResult()
                            if($count -eq 0){$capture.done=$true}else{
                                $marker=Get-NativeDNSVerificationMarker $capture.suffix ([string]::new($capture.buffer,0,$count))
                                if($marker.matched){$script:resolverVerificationRejected=$true};$capture.suffix=$marker.suffix
                                $capture.count=[Math]::Min(1048577,$capture.count+$count);if($capture.count -gt 1048576){$script:overflow=$true}
                                $capture.task=$capture.reader.ReadAsync($capture.buffer,0,$capture.buffer.Length)
                            }
                        }catch{$capture.done=$true;$script:captureFailed=$true;$capture.reader.Dispose()}
                    }
                }
                if($Request.action -ceq 'dns' -and $null -ne $script:rollbackPoll){
                    try{[void](& $script:rollbackPoll)}catch{
                        $failureCode=Get-NativeDNSForwarderFailure $_.Exception
                        # A late UDP reply can meet a query socket already closed
                        # by the proxy. Count only this typed Winsock condition.
                        if($failureCode -ceq 'peer-closed' -and $script:forwarderPeerClosures -lt 512){$script:forwarderPeerClosures++}else{$script:forwarderFailed=$true;$script:forwarderFailureCode=$failureCode}
                    }
                }
                if($clock.Elapsed.TotalSeconds -ge 240 -and -not $script:diagnosticWaitExceeded){$script:diagnosticWaitExceeded=$true;Write-Host 'Native CLI diagnostic deadline exceeded; awaiting actual completion.'}
                $pending=[Threading.Tasks.Task[]]@($captures | Where-Object {-not $_.done} | ForEach-Object {$_.task})
                if($pending.Length){[void][Threading.Tasks.Task]::WaitAny($pending,10)}else{Start-Sleep -Milliseconds 10}
            }
            $process.WaitForExit();$script:joined++
            if($Request.action -ceq 'dns'){$script:configureExit=$process.ExitCode;$script:configureElapsedMilliseconds=[int64][Math]::Floor($clock.Elapsed.TotalMilliseconds)}elseif($Request.action -ceq 'dns-restore'){$script:restoreExit=$process.ExitCode}else{$script:cleanupExit=$process.ExitCode}
            if(($process.ExitCode -ne 0 -and -not ($Request.action -ceq 'dns' -and $ScenarioKind -ceq 'verification-failure')) -or $script:overflow -or $script:captureFailed -or $script:forwarderFailed){throw 'Native CLI or bounded capture failed'}
        } finally {$process.Dispose()}
    }
    function Get-NativeDoHAdapterShapes {
        $inventory=@(Get-NetAdapter -ErrorAction Stop)
        if($inventory.Count -gt 16){throw 'Native adapter shape bound exceeded'}
        $physical=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$physicalKnown=$true
        try{foreach($a in @(Get-NetAdapter -Physical -ErrorAction Stop)){[void]$physical.Add(([guid]$a.InterfaceGuid).ToString('D'))}}catch{$physicalKnown=$false}
        $rows=@();$ordinal=0
        foreach($a in $inventory){
            $ordinal++;$guid=([guid]$a.InterfaceGuid).ToString('D')
            $hardware=if($a.HardwareInterface -is [bool]){if($a.HardwareInterface){'true'}else{'false'}}else{'unknown'}
            $isPhysical=if($physicalKnown){if($physical.Contains($guid)){'true'}else{'false'}}else{'unknown'}
            $interfaceType=0;try{$n=[int]$a.InterfaceType;if($n -ge 0 -and $n -le 1024){$interfaceType=$n}}catch{}
            $row=@{ordinal=$ordinal;selected=($a.Status -eq 'Up' -and $a.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN');hardware=$hardware;physical=$isPhysical;interfaceType=$interfaceType}
            foreach($family in @('IPv4','IPv6')){
                $item=@{registry='unknown';nameServerKind='unknown';binding='unknown';addressRows=-1;unicastRows=-1;ipInterfaceRows=-1;ipConnected='unknown';ipDhcp='unknown'}
                $service=if($family -ceq 'IPv4'){'Tcpip'}else{'Tcpip6'}
                $component=if($family -ceq 'IPv4'){'ms_tcpip'}else{'ms_tcpip6'}
                $key=$null
                try{
                    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(('SYSTEM\CurrentControlSet\Services\'+$service+'\Parameters\Interfaces\{'+$guid+'}'))
                    if($null -eq $key){$item.registry='absent';$item.nameServerKind='absent'}else{
                        $item.registry='present';$names=@($key.GetValueNames())
                        if($names.Count -le 1024 -and $names -icontains 'NameServer'){
                            $kind=$key.GetValueKind('NameServer').ToString()
                            $item.nameServerKind=switch -CaseSensitive ($kind){'String' {'string'} 'ExpandString' {'expand-string'} 'MultiString' {'multi-string'} 'DWord' {'dword'} 'QWord' {'qword'} 'Binary' {'binary'} default {'unknown'}}
                        }elseif($names.Count -le 1024){$item.nameServerKind='absent'}
                    }
                }catch{}finally{if($null -ne $key){$key.Close()}}
                try{
                    $bindings=@(Get-NetAdapterBinding -Name ([Management.Automation.WildcardPattern]::Escape([string]$a.Name)) -ComponentID $component -ErrorAction Stop)
                    if($bindings.Count -eq 1 -and $bindings[0].Enabled -is [bool]){$item.binding=if($bindings[0].Enabled){'enabled'}else{'disabled'}}
                }catch{}
                try{$count=@(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily $family -ErrorAction Stop).Count;if($count -le 16){$item.addressRows=$count}}catch{if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){$item.addressRows=0}}
                try{$count=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily $family -Type Unicast -ErrorAction Stop).Count;if($count -le 16){$item.unicastRows=$count}}catch{if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){$item.unicastRows=0}}
                try{
                    $interfaces=@(Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily $family -ErrorAction Stop)
                    if($interfaces.Count -le 16){$item.ipInterfaceRows=$interfaces.Count}
                    if($interfaces.Count -eq 1){
                        if([string]$interfaces[0].ConnectionState -in @('Connected','Disconnected')){$item.ipConnected=([string]$interfaces[0].ConnectionState).ToLowerInvariant()}
                        if([string]$interfaces[0].Dhcp -in @('Enabled','Disabled')){$item.ipDhcp=([string]$interfaces[0].Dhcp).ToLowerInvariant()}
                    }
                }catch{if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){$item.ipInterfaceRows=0}}
                $row[$family.ToLowerInvariant()]=$item
            }
            $row.selected=($row.selected -and ($row.ipv4.addressRows -eq 1 -or $row.ipv6.addressRows -eq 1))
            $rows+=@($row)
        }
        return @($rows)
    }
    # Read-only shape metadata uses no adapter names/GUIDs, addresses or values.
    try{$adapterShapes=@(Get-NativeDoHAdapterShapes);$probeOutcome='complete'}catch{$probeOutcome='failed'}
    function Get-NativeDNSAnswerCount {
        Clear-DnsClientCache -ErrorAction Stop
        $answers=@(Resolve-DnsName 'example.com' -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
        $count=@($answers | Where-Object {$_.IPAddress -and ([Net.IPAddress]$_.IPAddress).AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork}).Count
        if($count -lt 1 -or $count -gt 64){throw 'Ordinary native DNS answer bounds failed'}
        return $count
    }
    if($ScenarioKind -ceq 'verification-failure'){
        $script:forwarder=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
        $port=([Net.IPEndPoint]$script:forwarder.Client.LocalEndPoint).Port
        $example=Join-Path $component.directory 'example-dnscrypt-proxy.toml';$text=[IO.File]::ReadAllText($example)
        if($text -match '(?m)^\s*forwarding_rules\s*='){throw 'Pinned example already defines forwarding'}
        [IO.File]::WriteAllText($example,('forwarding_rules = ''accessweaver-failure-forwarding.txt'''+"`n"+$text),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $component.directory 'accessweaver-failure-forwarding.txt'),('example.com 127.0.0.1:'+$port+"`n"),[Text.UTF8Encoding]::new($false))
        $script:rollbackPoll={
            if($script:forwarderFailed){return}
            # All bytes stay private and in memory. Only the fixed public domain
            # is answered; unrelated/malformed packets refuse qualification.
            if($script:forwarder.Available -gt 4096){throw 'Forwarded DNS packet bound exceeded'}
            if($script:forwarder.Available -gt 0){
                if($script:forwarderRequests -ge 512){throw 'Forwarded DNS request count exceeded'}
                $remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0);$packet=$script:forwarder.Receive([ref]$remote)
                if(-not [Net.IPAddress]::IsLoopback($remote.Address)){throw 'Non-loopback forwarder peer refused'}
                $reply=New-NativeDNSFailureResponse $packet;$script:forwarderRequests++
                $sent=$script:forwarder.Send($reply,$reply.Length,$remote)
                if($sent -ne $reply.Length){throw 'Forwarded DNS error response incomplete'}
                $script:forwarderResponses++
                if(-not $script:configuredDuringRejectedApply){
                    try{
                        Assert-DNSAcceptanceConfigured $script:rollbackBefore (Read-DNSAcceptanceState) 'dnscrypt'
                        $installed=Join-Path $machineRoot 'components\dnscrypt\dnscrypt-proxy.exe'
                        $script:installedComponentVerified=((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $component.binarySHA256)
                        $script:serviceRunning=((Get-Service -Name 'AccessWeaver-dnscrypt' -ErrorAction Stop).Status -eq 'Running')
                        $script:serviceAutomatic=((Get-CimInstance Win32_Service -Filter "Name='AccessWeaver-dnscrypt'" -ErrorAction Stop).StartMode -ceq 'Auto')
                        if($script:installedComponentVerified -and $script:serviceRunning -and $script:serviceAutomatic){$script:configuredDuringRejectedApply=$true}
                    }catch{}
                }
            }
        }
        $rollbackScenario=Invoke-NativeDNSRollbackScenario -Configure {
            Invoke-NativeDoHCLI @{action='dns';dns='dnscrypt'}
            return ($script:configureExit -ne 0)
        } -Capture {
            $current=Read-DNSAcceptanceState ([ref]$script:captureStage) ([ref]$script:captureProgress)
            if($null -eq $script:rollbackBefore){$script:rollbackBefore=$current}
            return $current
        } -Observe {return @{configured=$script:configuredDuringRejectedApply;forwarded=($script:forwarderResponses -gt 0 -and -not $script:forwarderFailed)}} -Resolve {
            $count=Get-NativeDNSAnswerCount
            if($script:cliCount -eq 0){$script:baselineAnswers=$count}else{$script:restoredAnswers=$count}
        } -EmergencyRestore {Invoke-NativeDoHCLI @{action='dns-restore'}}
        $script:rollbackSnapshotRemoved=-not (Test-Path -LiteralPath (Join-Path $machineRoot 'profiles\dns-original.json'))
        $script:rollbackServiceRemoved=(@(Get-Service -Name 'AccessWeaver-dnscrypt' -ErrorAction SilentlyContinue).Count -eq 0)
        $script:forwarder.Dispose();$script:forwarder=$null;$script:rollbackPoll=$null
    }else{
    $scenario=Invoke-NativeDoHScenario -Method $Method -ScenarioKind $ScenarioKind -Apply {param($request) Invoke-NativeDoHCLI $request} -Capture {Read-DNSAcceptanceState ([ref]$script:captureStage) ([ref]$script:captureProgress)} -Resolve {
        if($Method -ceq 'dnscrypt'){
            $script:serviceRunning=((Get-Service -Name 'AccessWeaver-dnscrypt' -ErrorAction Stop).Status -eq 'Running')
            $script:serviceAutomatic=((Get-CimInstance Win32_Service -Filter "Name='AccessWeaver-dnscrypt'" -ErrorAction Stop).StartMode -ceq 'Auto')
            if(-not $script:serviceRunning -or -not $script:serviceAutomatic){throw 'DNSCrypt service acceptance failed'}
        }
        $script:answers=Get-NativeDNSAnswerCount
    } -InduceFailure {
        # The fresh-state guard and successful real product configuration establish
        # ownership. Stop only this fixture's actual managed resolver service.
        Stop-Service -Name 'AccessWeaver-dnscrypt' -ErrorAction Stop
        (Get-Service -Name 'AccessWeaver-dnscrypt' -ErrorAction Stop).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
        $script:failureServiceStopped=((Get-Service -Name 'AccessWeaver-dnscrypt' -ErrorAction Stop).Status -eq 'Stopped')
        $installed=Join-Path $machineRoot 'components\dnscrypt\dnscrypt-proxy.exe'
        $processes=@(Get-CimInstance Win32_Process -Filter "Name='dnscrypt-proxy.exe'" -ErrorAction Stop)
        if(@($processes | Where-Object {[string]::IsNullOrWhiteSpace($_.ExecutablePath)}).Count -ne 0){throw 'Resolver process identity unavailable'}
        $script:resolverProcessExited=(@($processes | Where-Object {$_.ExecutablePath -eq $installed}).Count -eq 0)
        if(-not $script:failureServiceStopped -or -not $script:resolverProcessExited){throw 'Managed resolver did not stop completely'}
    } -ResolveFailed {
        Clear-DnsClientCache -ErrorAction Stop
        $failed=$false
        try{[void](Resolve-DnsName 'example.com' -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)}catch{$failed=$true}
        $script:failedResolverObserved=$failed
        if(-not $failed){throw 'Ordinary resolver unexpectedly succeeded after managed resolver loss'}
    } -ResolveRestored {$script:restoredAnswers=Get-NativeDNSAnswerCount}
    }
    if($Method -ceq 'dnscrypt'){
        # Remove through the actual product after the independent restore attempt.
        # Keep all private output under the same bounded, joined CLI boundary.
        try{Invoke-NativeDoHCLI @{action='remove';engine='dnscrypt'}}finally{$serviceRemoved=(@(Get-Service -Name 'AccessWeaver-dnscrypt' -ErrorAction SilentlyContinue).Count -eq 0)}
        $installed=Join-Path $machineRoot 'components\dnscrypt\dnscrypt-proxy.exe'
        if($ScenarioKind -cne 'verification-failure'){
            if((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant() -cne $component.binarySHA256){throw 'Installed DNSCrypt component identity differs'}
            $script:installedComponentVerified=$true
        }
    }
    $snapshotRemoved=-not (Test-Path -LiteralPath (Join-Path $machineRoot 'profiles\dns-original.json'))
    $scenarioPassed=($scenario.outcome -ceq 'passed' -and $snapshotRemoved -and $script:cliCount -eq $(if($Method -ceq 'dnscrypt'){3}else{2}) -and $script:joined -eq $script:cliCount -and ($Method -ceq 'doh' -or ($serviceRunning -and $serviceAutomatic -and $serviceRemoved -and $script:cleanupExit -eq 0)) -and -not $script:overflow -and -not $script:captureFailed)
    if($ScenarioKind -ceq 'service-loss'){$scenarioPassed=($scenarioPassed -and $scenario.failureInjected -and $scenario.failedResolverVerified -and $scenario.restoredResolverVerified -and $script:failureServiceStopped -and $script:resolverProcessExited -and $script:failedResolverObserved -and $script:restoredAnswers -ge 1)}
    if($ScenarioKind -ceq 'verification-failure'){$scenarioPassed=($rollbackScenario.outcome -ceq 'passed' -and -not $rollbackScenario.emergencyRestoreAttempted -and $script:rollbackSnapshotRemoved -and $script:rollbackServiceRemoved -and $script:configureExit -ne 0 -and $script:resolverVerificationRejected -and $script:configureElapsedMilliseconds -ge 90000 -and $script:restoreExit -eq -1 -and $script:cliCount -eq 2 -and $script:joined -eq 2 -and $snapshotRemoved -and $serviceRunning -and $serviceAutomatic -and $serviceRemoved -and $script:cleanupExit -eq 0 -and $script:installedComponentVerified -and $script:configuredDuringRejectedApply -and $script:forwarderResponses -gt 0 -and -not $script:forwarderFailed -and -not $script:overflow -and -not $script:captureFailed)}
    $code='post-validation';$integrityVerified=$true
    if((Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BinarySHA256){$integrityVerified=$false;$code='binary-changed'}
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){$integrityVerified=$false;$code='source-changed'}}
    if($integrityVerified){if($scenarioPassed){$outcome='passed';$code='none'}else{$code='native-roundtrip-failed'}}
} catch {$outcome='failed'}
finally {
    if($null -ne $script:forwarder){$script:forwarder.Dispose();$script:forwarder=$null}
    # Fixed metadata only: no exception, account, path, DNS value or raw output.
    $parent=Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop;Assert-NativeOrdinaryPath $ReportPath
    if($parent.CreationTimeUtc.Ticks -ne $reportCreated -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed native report parent retained'}
    $report=@{schemaVersion=1;sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;platform='windows';architecture=$env:ACCESSWEAVER_EXPECT_GOARCH;goVersion=$env:GO_VERSION;edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();binarySHA256=$BinarySHA256;outcome=$outcome;code=$code;environmentVerified=$environmentVerified;nativeProcessVerified=$nativeProcessVerified;binaryVerified=$binaryVerified;scenario=$scenario;rollbackScenario=$rollbackScenario;rollbackSnapshotRemoved=$script:rollbackSnapshotRemoved;rollbackServiceRemoved=$script:rollbackServiceRemoved;resolverVerificationRejected=$script:resolverVerificationRejected;configureElapsedMilliseconds=$script:configureElapsedMilliseconds;forwarderPeerClosures=$script:forwarderPeerClosures;forwarderFailureCode=$script:forwarderFailureCode;forwarderRequests=$script:forwarderRequests;forwarderResponses=$script:forwarderResponses;forwarderFailed=$script:forwarderFailed;configuredDuringRejectedApply=$script:configuredDuringRejectedApply;installedComponentVerified=$script:installedComponentVerified;baselineResolverAnswers=$script:baselineAnswers;probeOutcome=$probeOutcome;adapterShapes=@($adapterShapes);captureStage=$script:captureStage;captureProgress=$script:captureProgress;cliCount=$script:cliCount;processesJoined=$script:joined;configureExitCode=$script:configureExit;restoreExitCode=$script:restoreExit;outputOverflow=$script:overflow;captureFailed=$script:captureFailed;diagnosticWaitExceeded=$script:diagnosticWaitExceeded;ordinaryResolverAnswers=$script:answers;snapshotRemoved=$snapshotRemoved;method=$Method;scenarioKind=$ScenarioKind;failureServiceStopped=$script:failureServiceStopped;resolverProcessExited=$script:resolverProcessExited;failedResolverObserved=$script:failedResolverObserved;restoredResolverAnswers=$script:restoredAnswers;componentStage=$script:componentStage;componentFailureCode=$script:componentFailureCode;componentHTTPStatus=$script:componentHTTPStatus;componentDownloadedBytes=$script:componentDownloadedBytes;componentArchiveEntries=$script:componentArchiveEntries;componentVersion=$(if($component){$component.version}else{''});componentArchiveSHA256=$(if($component){$component.archiveSHA256}else{''});componentBinarySHA256=$(if($component){$component.binarySHA256}else{''});componentStaged=($null -ne $component);serviceRunning=$serviceRunning;serviceAutomatic=$serviceAutomatic;serviceRemoved=$serviceRemoved;cleanupExitCode=$script:cleanupExit;encryptedTrafficObserved=$false;rebootExercised=$false;dnscryptExercised=($Method -ceq 'dnscrypt' -and (($null -ne $scenario -and $scenario.configurationAttempted) -or ($null -ne $rollbackScenario -and $rollbackScenario.configurationAttempted)));nativeDnsQualified=$false;productionQualificationComplete=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 5 -Compress));if($bytes.Length -gt 16384){throw 'Native report exceeds fixed metadata bound'}
    $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
if($outcome -cne 'passed'){throw 'Native DNS round-trip acceptance failed; fixed metadata retained'}
