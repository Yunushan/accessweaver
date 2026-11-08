# Native changes require a fresh non-domain GitHub-hosted VM. Never run locally.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Binary,[Parameter(Mandatory=$true)][string]$BinarySHA256,[Parameter(Mandatory=$true)][string]$ReportPath)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Assert-NativeOrdinaryPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){
        if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Native fixture reparse boundary refused'}}
        $next=Split-Path -Parent $current;if($next -eq $current){break};$current=$next
    }
}
if(-not [IO.Path]::IsPathRooted($ReportPath)){throw 'Native report requires an absolute path'}
$ReportPath=[IO.Path]::GetFullPath($ReportPath);Assert-NativeOrdinaryPath $ReportPath
$reportParent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ReportPath)) -Force -ErrorAction Stop
if(-not $reportParent.PSIsContainer -or [IO.Directory]::GetFileSystemEntries($reportParent.FullName).Length -ne 0){throw 'Native report parent must be empty and ordinary'}
$reportCreated=$reportParent.CreationTimeUtc.Ticks;$project=Split-Path -Parent $PSScriptRoot
$sources=@('scripts/test-native-doh.ps1','scripts/native-doh-scenario.ps1','scripts/dns-acceptance-state.ps1','scripts/test-dns-acceptance-state.ps1','scripts/check-native-environment.cjs','.github/workflows/native-doh.yml','internal/workflow/windows.ps1','internal/workflow/manager.go','cmd/accessweaver/system.go','go.mod','go.sum')
$hashes=@{};foreach($file in $sources){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$script:cliCount=0;$script:joined=0;$script:overflow=$false;$script:captureFailed=$false;$script:diagnosticWaitExceeded=$false
$script:captureStage='not-started';$script:captureProgress=@{adapterTotal=0;adapterOrdinal=0;selected=$false};$script:configureExit=-1;$script:restoreExit=-1;$script:answers=0
$adapterShapes=@();$probeOutcome='not-started';$environmentVerified=$false;$nativeProcessVerified=$false;$binaryVerified=$false;$snapshotRemoved=$false;$scenario=$null;$outcome='failed';$code='environment-guard'
try {
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
    $environmentVerified=$true;$code='native-scenario'
    . (Join-Path $PSScriptRoot 'dns-acceptance-state.ps1')
    . (Join-Path $PSScriptRoot 'native-doh-scenario.ps1')
    function Invoke-NativeDoHCLI([hashtable]$Request) {
        if($Request.action -cnotin @('dns','dns-restore') -or ($Request.action -ceq 'dns' -and $Request.dns -cne 'doh')){throw 'Native fixture request refused'}
        $requestPath=Join-Path $privateRoot ($Request.action+'.request.json');[IO.File]::WriteAllText($requestPath,($Request|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        if((Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BinarySHA256){throw 'Native binary changed before dispatch'}
        $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Binary;$start.Arguments='system apply "'+$requestPath+'" --confirm';$start.WorkingDirectory=$privateRoot
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.EnvironmentVariables['ACCESSWEAVER_HOME']=$controllerHome
        $process=[Diagnostics.Process]::new();$process.StartInfo=$start
        try {
            if(-not $process.Start()){throw 'Native CLI did not start'}
            $script:cliCount++;$clock=[Diagnostics.Stopwatch]::StartNew();$captures=@()
            foreach($reader in @($process.StandardOutput,$process.StandardError)){
                $capture=@{reader=$reader;buffer=[char[]]::new(4096);done=$false;count=0;task=$null}
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
                                $capture.count=[Math]::Min(1048577,$capture.count+$count);if($capture.count -gt 1048576){$script:overflow=$true}
                                $capture.task=$capture.reader.ReadAsync($capture.buffer,0,$capture.buffer.Length)
                            }
                        }catch{$capture.done=$true;$script:captureFailed=$true;$capture.reader.Dispose()}
                    }
                }
                if($clock.Elapsed.TotalSeconds -ge 240 -and -not $script:diagnosticWaitExceeded){$script:diagnosticWaitExceeded=$true;Write-Host 'Native CLI diagnostic deadline exceeded; awaiting actual completion.'}
                $pending=[Threading.Tasks.Task[]]@($captures | Where-Object {-not $_.done} | ForEach-Object {$_.task})
                if($pending.Length){[void][Threading.Tasks.Task]::WaitAny($pending,10)}else{Start-Sleep -Milliseconds 10}
            }
            $process.WaitForExit();$script:joined++
            if($Request.action -ceq 'dns'){$script:configureExit=$process.ExitCode}else{$script:restoreExit=$process.ExitCode}
            if($process.ExitCode -ne 0 -or $script:overflow -or $script:captureFailed){throw 'Native CLI or bounded capture failed'}
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
                $item=@{registry='unknown';nameServerKind='unknown';binding='unknown';addressRows=-1}
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
                $row[$family.ToLowerInvariant()]=$item
            }
            $rows+=@($row)
        }
        return @($rows)
    }
    # Read-only shape metadata uses no adapter names/GUIDs, addresses or values.
    try{$adapterShapes=@(Get-NativeDoHAdapterShapes);$probeOutcome='complete'}catch{$probeOutcome='failed'}
    $scenario=Invoke-NativeDoHScenario -Apply {param($request) Invoke-NativeDoHCLI $request} -Capture {Read-DNSAcceptanceState ([ref]$script:captureStage) ([ref]$script:captureProgress)} -Resolve {
        Clear-DnsClientCache -ErrorAction Stop
        $answers=@(Resolve-DnsName 'example.com' -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
        $script:answers=@($answers | Where-Object {$_.IPAddress -and ([Net.IPAddress]$_.IPAddress).AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork}).Count
        if($script:answers -lt 1 -or $script:answers -gt 64){throw 'Ordinary native DNS answer bounds failed'}
    }
    $snapshotRemoved=-not (Test-Path -LiteralPath (Join-Path $machineRoot 'profiles\dns-original.json'))
    $scenarioPassed=($scenario.outcome -ceq 'passed' -and $snapshotRemoved -and $script:cliCount -eq 2 -and $script:joined -eq 2 -and -not $script:overflow -and -not $script:captureFailed)
    $code='post-validation';$integrityVerified=$true
    if((Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BinarySHA256){$integrityVerified=$false;$code='binary-changed'}
    foreach($file in $sources){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$file]){$integrityVerified=$false;$code='source-changed'}}
    if($integrityVerified){if($scenarioPassed){$outcome='passed';$code='none'}else{$code='native-roundtrip-failed'}}
} catch {$outcome='failed'}
finally {
    # Fixed metadata only: no exception, account, path, DNS value or raw output.
    $parent=Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop;Assert-NativeOrdinaryPath $ReportPath
    if($parent.CreationTimeUtc.Ticks -ne $reportCreated -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed native report parent retained'}
    $report=@{schemaVersion=1;sourceCommit=$env:GITHUB_SHA;sourceSHA256=$hashes;platform='windows';architecture=$env:ACCESSWEAVER_EXPECT_GOARCH;goVersion=$env:GO_VERSION;edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();binarySHA256=$BinarySHA256;outcome=$outcome;code=$code;environmentVerified=$environmentVerified;nativeProcessVerified=$nativeProcessVerified;binaryVerified=$binaryVerified;scenario=$scenario;probeOutcome=$probeOutcome;adapterShapes=@($adapterShapes);captureStage=$script:captureStage;captureProgress=$script:captureProgress;cliCount=$script:cliCount;processesJoined=$script:joined;configureExitCode=$script:configureExit;restoreExitCode=$script:restoreExit;outputOverflow=$script:overflow;captureFailed=$script:captureFailed;diagnosticWaitExceeded=$script:diagnosticWaitExceeded;ordinaryResolverAnswers=$script:answers;snapshotRemoved=$snapshotRemoved;encryptedTrafficObserved=$false;rebootExercised=$false;dnscryptExercised=$false;nativeDnsQualified=$false;productionQualificationComplete=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 5 -Compress));if($bytes.Length -gt 16384){throw 'Native report exceeds fixed metadata bound'}
    $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
if($outcome -cne 'passed'){throw 'Native DoH round-trip acceptance failed; fixed metadata retained'}
