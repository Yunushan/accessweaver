[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReportPath)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
   $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
   $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver' -or $env:ACCESSWEAVER_DNSCRYPT_PORT_PROBE -cne '1'){
    throw 'DNSCrypt port probe requires a disposable hosted Windows runner'
}
if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){
    throw 'Windows PowerShell 5.1 required'
}
$architecture=switch -CaseSensitive ($env:RUNNER_ARCH){
    'X64' {'amd64'}
    'ARM64' {'arm64'}
    default {throw 'Hosted Windows architecture required'}
}
Add-Type -TypeDefinition '
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class AccessWeaverDNSCryptPortNativeIdentity {
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
if(-not [AccessWeaverDNSCryptPortNativeIdentity]::Matches($architecture)){throw 'Native PowerShell process architecture differs'}
$computer=Get-CimInstance Win32_ComputerSystem -Property Model,PartOfDomain -ErrorAction Stop
if($computer.Model -notmatch 'Virtual|VMware' -or $computer.PartOfDomain -ne $false){throw 'Fresh non-domain virtual machine required'}
$project=Split-Path -Parent $PSScriptRoot
$source=$env:GITHUB_SHA
$head=@(& git -C $project rev-parse HEAD 2>$null)
if($LASTEXITCODE -ne 0 -or $head.Count -ne 1 -or $source -cnotmatch '\A[a-f0-9]{40}\z' -or $head[0] -cne $source){
    throw 'DNSCrypt port probe source identity differs'
}
$dirty=@(& git -C $project status --porcelain --untracked-files=no 2>$null)
if($LASTEXITCODE -ne 0 -or $dirty.Count){throw 'DNSCrypt port probe requires clean tracked source'}
$hashes=@{}
foreach($path in @('scripts/test-native-dnscrypt-port.ps1','.github/workflows/native-doh.yml')){
    $hashes[$path]=(Get-FileHash -LiteralPath (Join-Path $project $path) -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-FixtureUDP53 {
    $scopes=@{'0.0.0.0'='ipv4-wildcard';'127.0.0.1'='ipv4-loopback';'::'='ipv6-wildcard';'::1'='ipv6-loopback'}
    $query=@{Namespace='root/StandardCimv2';ClassName='MSFT_NetUDPEndpoint';Filter='LocalPort = 53'
        Property=@('LocalPort','LocalAddress','OwningProcess');ErrorAction='Stop';WarningAction='Stop'}
    $rows=@(Get-CimInstance @query | Select-Object -First 4097)
    if($rows.Count -gt 4096){throw 'UDP port inventory exceeds its limit'}
    foreach($row in $rows){
        $address=$null
        if($row.LocalPort -ne 53 -or $row.LocalAddress -isnot [string] -or
           -not [Net.IPAddress]::TryParse($row.LocalAddress,[ref]$address)){throw 'UDP port inventory differs'}
        if($address.IsIPv4MappedToIPv6){$address=$address.MapToIPv4()}
        $scope=$scopes[$address.ToString().Split('%')[0]]
        if($null -ne $scope){
            if($row.OwningProcess -isnot [uint32]){throw 'UDP port owner identity differs'}
            [pscustomobject]@{scope=$scope;owner=$row.OwningProcess}
        }
    }
}
function Read-FixtureUDP53Owner([uint32]$Owner) {
    try{
        $process=@(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $Owner" -Property ProcessId,CreationDate -ErrorAction Stop -WarningAction Stop |
            Select-Object -First 2)
        if($process.Count -ne 1 -or $process[0].ProcessId -ne $Owner -or $process[0].CreationDate -isnot [datetime]){return}
        $services=@(Get-CimInstance -ClassName Win32_Service -Filter "ProcessId = $Owner AND State = 'Running'" -Property ProcessId,State,Name -ErrorAction Stop -WarningAction Stop |
            Select-Object -First 33)
        if($services.Count -gt 32 -or @($services | Where-Object {
            $_.ProcessId -ne $Owner -or $_.State -cne 'Running' -or $_.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($_.Name)
        }).Count){return}
        return @{creation=$process[0].CreationDate.ToUniversalTime();services=@($services.Name | Sort-Object -CaseSensitive)}
    }catch{
        return
    }
}
function Get-FixtureUDP53OwnerCategory($Identity) {
    if($null -eq $Identity){return 'unavailable'}
    if($Identity.services.Count -eq 0){return 'no-running-service'}
    if($Identity.services.Count -ne 1){return 'shared-service-process'}
    switch ($Identity.services[0]){
        'SharedAccess' {return 'connection-sharing'}
        'Dnscache' {return 'dns-client'}
        'DNS' {return 'dns-server'}
        'hns' {return 'host-network'}
        'WinNat' {return 'nat'}
        default {return 'other-service'}
    }
}
function Test-FixtureExclusiveUDP53([Net.IPAddress]$Address) {
    $socket=$null
    try{
        $socket=[Net.Sockets.Socket]::new($Address.AddressFamily,[Net.Sockets.SocketType]::Dgram,[Net.Sockets.ProtocolType]::Udp)
        $socket.ExclusiveAddressUse=$true
        if($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$socket.DualMode=$false}
        $socket.Bind([Net.IPEndPoint]::new($Address,53))
        return 'bound'
    }catch{
        $cause=$_.Exception.GetBaseException()
        if($cause -is [Net.Sockets.SocketException]){
            switch ($cause.SocketErrorCode){
                'AddressAlreadyInUse' {return 'address-in-use'}
                'AccessDenied' {return 'access-denied'}
                'AddressFamilyNotSupported' {return 'family-unavailable'}
                'AddressNotAvailable' {return 'family-unavailable'}
            }
        }
        return 'unavailable'
    }finally{
        if($null -ne $socket){$socket.Dispose()}
    }
}

$report=[ordered]@{schemaVersion=1;sourceCommit=$source;sourceSHA256=$hashes;target=('windows/'+$architecture);
    stage='baseline';inventoryStable=$false;scopes=@();ipv4Bind='not-run';ipv6Bind='not-run';
    ipv4WildcardOwner='not-run';productionQualificationComplete=$false}
try{
    $before=@(Read-FixtureUDP53)
    $owners=@($before | Where-Object scope -CEQ 'ipv4-wildcard' | Select-Object -ExpandProperty owner -Unique)
    $ownerBefore=if($owners.Count -eq 1 -and $owners[0] -ne 0){Read-FixtureUDP53Owner $owners[0]}
    $report.stage='probe'
    $report.ipv4Bind=Test-FixtureExclusiveUDP53 ([Net.IPAddress]::Loopback)
    $report.ipv6Bind=Test-FixtureExclusiveUDP53 ([Net.IPAddress]::IPv6Loopback)
    $ownerAfter=if($null -ne $ownerBefore){Read-FixtureUDP53Owner $owners[0]}
    $after=@(Read-FixtureUDP53)
    $beforeKeys=@($before | ForEach-Object {$_.scope+'='+$_.owner} | Sort-Object)
    $afterKeys=@($after | ForEach-Object {$_.scope+'='+$_.owner} | Sort-Object)
    $report.inventoryStable=($beforeKeys -join ',') -ceq ($afterKeys -join ',')
    $report.scopes=@($before | Select-Object -ExpandProperty scope -Unique | Sort-Object)
    $report.ipv4WildcardOwner=if(-not $report.inventoryStable){'unstable'}
        elseif($owners.Count -eq 0){'none'}
        elseif($owners.Count -ne 1){'ambiguous'}
        elseif($null -eq $ownerBefore -or $null -eq $ownerAfter){'unavailable'}
        elseif($ownerBefore.creation -ne $ownerAfter.creation -or
            ($ownerBefore.services -join '|') -cne ($ownerAfter.services -join '|')){'unstable'}
        else{Get-FixtureUDP53OwnerCategory $ownerBefore}
    $report.stage='complete'
}catch{
    throw 'DNSCrypt port probe failed; fixed status retained'
}finally{
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 4 -Compress))
    if($bytes.Length -gt 4096){throw 'DNSCrypt port probe report exceeds its size limit'}
    $file=[IO.File]::Open($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$file.Write($bytes,0,$bytes.Length)}finally{$file.Dispose()}
}
