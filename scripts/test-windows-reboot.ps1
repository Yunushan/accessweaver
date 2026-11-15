# Prepare and verify on the same disposable Windows guest, with an external reboot between phases.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Verify')][string]$Phase,
    [Parameter(Mandatory)][ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$ExecutableSHA256,
    [Parameter(Mandatory)][ValidateScript({$_ -cmatch '\A[0-9a-f]{32}\z'})][string]$QualificationID,
    [Parameter(Mandatory)][ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$FixtureSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$OracleSHA256,
    [string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',
    [ValidateSet('auto','doh','dnscrypt')][string]$DNS='auto',
    [ValidateSet('any','dhcp-ipv4','static-ipv4','dhcp-ipv6','static-ipv6')][string]$RequiredOriginalMode='any'
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Assert-DNSRebootAdmission($Saved,$Current) {
    if($Saved.schemaVersion -ne 9 -or $Saved.architecture -isnot [string] -or
       $Saved.architecture -cnotin @('amd64','arm64') -or $Saved.architecture -cne $Current.architecture -or $Saved.method -isnot [string] -or
       $Saved.method -cnotin @('doh','dnscrypt') -or $Saved.method -cne $Current.method -or
       $Saved.requiredOriginalMode -isnot [string] -or $Saved.requiredOriginalMode -cne $Current.requiredOriginalMode -or
       $Saved.qualificationID -isnot [string] -or $Saved.qualificationID -cnotmatch '\A[a-f0-9]{32}\z' -or
       $Saved.qualificationID -cne $Current.qualificationID -or
       $Saved.guestID -cne $Current.guestID -or $Saved.binarySHA256 -cne $Current.binarySHA256 -or
       $Saved.oracleSHA256 -cne $Current.oracleSHA256 -or $Saved.fixtureSHA256 -cne $Current.fixtureSHA256 -or
       $Saved.snapshotSHA256 -cnotmatch '\A[A-F0-9]{64}\z' -or $Saved.snapshotSHA256 -cne $Current.snapshotSHA256 -or
       $Saved.copySHA256 -isnot [string] -or $Saved.copySHA256 -cnotmatch '\A[A-F0-9]{64}\z' -or
       $Saved.copySHA256 -cne $Current.copySHA256 -or
       $Saved.journalId -isnot [string] -or $Saved.journalId -cnotmatch '\Aworkflow-[a-f0-9]{32}\.json\z' -or
       $Saved.journalId -cne $Current.journalId -or $Saved.journalSHA256 -cnotmatch '\A[A-F0-9]{64}\z' -or
       $Saved.journalSHA256 -cne $Current.journalSHA256){
        throw 'DNS reboot candidate or recovery baseline differs'
    }
    $earlier=0L;$later=0L
    if($Saved.boot -cnotmatch '\A[0-9]{18}\z' -or $Current.boot -cnotmatch '\A[0-9]{18}\z' -or
       -not [long]::TryParse($Saved.boot,[ref]$earlier) -or -not [long]::TryParse($Current.boot,[ref]$later) -or
       $earlier -ge $later){
        throw 'A later boot on the prepared guest is required'
    }
}
function Save-DNSRebootRecord([string]$Path,$Record) {
    $data=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Record -Depth 16))
    if($data.Length -gt 1MB){throw 'DNS reboot record exceeds its size limit'}
    $staged=Join-Path (Split-Path -Parent $Path) ([guid]::NewGuid().ToString('N')+'.tmp')
    $stream=[IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        try {$stream.Write($data,0,$data.Length);$stream.Flush($true)} finally {$stream.Dispose()}
        [IO.File]::Move($staged,$Path)
    } finally {[IO.File]::Delete($staged)}
}
function Open-DNSRebootInput([string]$Path) {
    $entry=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($entry.PSIsContainer){throw 'Expected a bounded ordinary DNS reboot input'}
    for($currentPath=$Path;$currentPath;$currentPath=[IO.Path]::GetDirectoryName($currentPath)){
        $component=Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        if($component.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'DNS reboot input includes a reparse point'}
        if($currentPath -ieq [IO.Path]::GetPathRoot($currentPath)){break}
    }
    return [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
}
function Get-DNSRebootDigest([string]$Path,[long]$Maximum) {
    $stream=Open-DNSRebootInput $Path
    try {
        if($stream.Length -le 0 -or $stream.Length -gt $Maximum){throw 'DNS reboot input exceeds its size limit'}
        return (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
    } finally {$stream.Dispose()}
}
function Assert-DNSRebootControllerArchitecture([IO.Stream]$Stream,[string]$Architecture) {
    $machine=@{amd64=0x8664;arm64=0xaa64}[$Architecture]
    $reader=[IO.BinaryReader]::new($Stream,[Text.Encoding]::ASCII,$true)
    try {
        $Stream.Position=0
        if($null -eq $machine -or $Stream.Length -lt 90 -or $reader.ReadUInt16() -ne 0x5a4d){
            throw 'DNS reboot controller must be a native Windows executable'
        }
        $Stream.Position=60
        $offset=$reader.ReadInt32()
        if($offset -lt 64 -or $offset -gt ($Stream.Length-26)){
            throw 'DNS reboot controller PE header is outside the approved file'
        }
        $Stream.Position=$offset
        if($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne $machine){
            throw 'DNS reboot controller does not match the native guest architecture'
        }
        $Stream.Position=$offset+24
        if($reader.ReadUInt16() -ne 0x20b){throw 'DNS reboot controller must use the PE32+ format'}
    } finally {$reader.Dispose()}
}
function Open-ApprovedDNSRebootController([string]$Path,[string]$ExpectedSHA256,[string]$Architecture) {
    $stream=Open-DNSRebootInput $Path
    try {
        if($ExpectedSHA256 -cnotmatch '\A[A-Fa-f0-9]{64}\z' -or
            $stream.Length -le 0 -or $stream.Length -gt 128MB -or
            (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash -ine $ExpectedSHA256){
            throw 'Staged DNS reboot controller does not match the approved candidate'
        }
        Assert-DNSRebootControllerArchitecture $stream $Architecture
        return $stream
    } catch {
        $stream.Dispose()
        throw
    }
}
function Read-DNSRebootRecord([string]$Path,[int]$Maximum) {
    $stream=Open-DNSRebootInput $Path
    try {
        $length=$stream.Length
        if($length -le 0 -or $length -gt $Maximum){throw 'DNS reboot input exceeds its size limit'}
        $bytes=[byte[]]::new([int]$length)
        $offset=0
        while($offset -lt $bytes.Length){
            $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($count -eq 0){throw 'DNS reboot input was truncated'}
            $offset+=$count
        }
        if($stream.ReadByte() -ne -1){throw 'DNS reboot input grew during read'}
    } finally {$stream.Dispose()}

    $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    if($json.Length -gt 0 -and $json[0] -eq [char]0xfeff){$json=$json.Substring(1)}
    if($json -cnotmatch '\A[\x20\t\r\n]*\{' -or $json.IndexOf([char]0) -ge 0){
        throw 'Expected a DNS reboot JSON object'
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')} finally {$sha.Dispose()}
    return @{record=(ConvertFrom-Json -InputObject $json -ErrorAction Stop);sha256=$digest}
}

function Get-DNSRebootJournalID([string]$Path,[string]$LogDirectory) {
    if(-not [IO.Path]::IsPathRooted($Path)){throw 'Expected a protected DNS workflow journal'}
    $id=[IO.Path]::GetFileName($Path)
    if($id -cnotmatch '\Aworkflow-[a-f0-9]{32}\.json\z' -or $Path -ine [IO.Path]::Combine($LogDirectory,$id)){
        throw 'Expected a protected DNS workflow journal'
    }
    return $id
}
function Assert-DNSRebootJournal($Journal,[string]$SnapshotSHA256) {
    $undo=@($Journal.undo)
    $dns=@($undo | Where-Object {$_.kind -ceq 'dns'})
    if($Journal.action -cne 'dns' -or $Journal.state -cne 'succeeded' -or $dns.Count -ne 1 -or
        $dns[0].snapshotActive -isnot [bool] -or -not $dns[0].snapshotActive -or
        $dns[0].snapshotSHA256 -isnot [string] -or $dns[0].snapshotSHA256 -ine $SnapshotSHA256){
        throw 'Prepared DNS workflow journal does not bind the snapshot'
    }
}
$computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(@($computer).Count -ne 1 -or $computer.Model -notmatch 'Virtual|VMware' -or $computer.PartOfDomain -ne $false){
    throw 'Non-domain disposable Windows guest required'
}
$tools=Join-Path $env:ProgramFiles 'VMware\VMware Tools\vmtoolsd.exe'
if(-not (Test-Path -LiteralPath $tools -PathType Leaf)){throw 'Disposable VMware guest tools required'}
$marker=& $tools --cmd 'info-get guestinfo.accessweaverParity'
if($LASTEXITCODE -ne 0 -or ($marker -join '').Trim() -cne 'AccessWeaver-Clean-Windows-Test'){
    throw 'Disposable VMware guest identity marker required'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Elevated disposable guest required'
    }
} finally {$identity.Dispose()}
$Executable=[IO.Path]::GetFullPath($Executable)
if((Split-Path -Parent $Executable) -ine 'C:\AccessWeaver-Test' -or
   (Split-Path -Leaf $Executable) -notmatch '\Aaccessweaver[a-zA-Z0-9-]*\.exe\z'){
    throw 'Expected a staged guest test controller'
}
$oracle=Join-Path $PSScriptRoot 'dns-acceptance-state.ps1'
$guest=Get-CimInstance Win32_ComputerSystemProduct
$guestID=[guid]::Empty
if(@($guest).Count -ne 1 -or -not [guid]::TryParseExact([string]$guest.UUID,'D',[ref]$guestID) -or
   $guestID -eq [guid]::Empty -or $guestID.ToString('D') -ceq 'ffffffff-ffff-ffff-ffff-ffffffffffff'){
    throw 'Cannot bind the DNS reboot test to a guest'
}
$os=Get-CimInstance Win32_OperatingSystem
if(@($os).Count -ne 1 -or $os.LastBootUpTime -isnot [DateTime]){throw 'Cannot identify guest boot'}
$DNS=$DNS.ToLowerInvariant()
if($DNS -ceq 'auto'){$DNS=if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){'doh'}else{'dnscrypt'}}
$nativeArchitecture=@{X64='amd64';Arm64='arm64'}[[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()]
if(-not $nativeArchitecture -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.RuntimeInformation]::OSArchitecture){
    throw 'A native 64-bit Windows DNS reboot guest and shell are required'
}
$current=@{
    schemaVersion=9;architecture=$nativeArchitecture;method=$DNS;requiredOriginalMode=$RequiredOriginalMode.ToLowerInvariant();guestID=$guestID.ToString('D');qualificationID=$QualificationID;
    binarySHA256=$ExecutableSHA256.ToUpperInvariant();
    fixtureSHA256=(Get-DNSRebootDigest $PSCommandPath 1MB);
    boot=$os.LastBootUpTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
}
if($current.fixtureSHA256 -ine $FixtureSHA256){throw 'DNS reboot fixture differs from the approved source'}
$private=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AccessWeaver DNS reboot fixture'
$baseline=Join-Path $private 'prepared.json'
$machineRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AccessWeaver'
$snapshot=Join-Path $machineRoot 'profiles\dns-original.json'
$recoveryCopy=Join-Path $machineRoot 'profiles\dns-original.copy'
$logDirectory=Join-Path $machineRoot 'logs'
$report=Join-Path $private 'reboot-results.json'

function Invoke-TestWorkflow([hashtable]$Request) {
    $path=Join-Path $private ('request-'+[guid]::NewGuid().ToString('N')+'.json')
    try {
        Save-DNSRebootRecord $path $Request
        $old=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $output=@(& $Executable system apply $path --confirm 2>$null)
            $code=$LASTEXITCODE
        } finally {$ErrorActionPreference=$old}
        if($code -ne 0){throw 'DNS reboot workflow failed'}
        $text=$output -join "`n"
        if($text.Length -gt 1MB){throw 'DNS reboot workflow response exceeds its size limit'}
        $job=ConvertFrom-Json -InputObject $text -ErrorAction Stop
        if($job.state -cne 'succeeded' -or $job.action -cne $Request.action -or
            $job.result.ok -isnot [bool] -or -not $job.result.ok -or @($job.result.finalizationFailures).Count -ne 0){
            throw 'DNS reboot workflow did not return a successful job'
        }
        return $job.result
    } finally {[IO.File]::Delete($path)}
}
function Invoke-DNSRebootPreparation([scriptblock]$Prepare,[scriptblock]$Recover) {
    try {
        & $Prepare
    } catch {
        $preparationFailure=$_
        try {
            & $Recover
        } catch {
            throw [AggregateException]::new('DNS reboot preparation failed and guest restoration could not be verified',
                [Exception[]]@($preparationFailure.Exception,$_.Exception))
        }
        throw $preparationFailure
    }
}

function Get-DNSRebootCoverage([object]$Before,[string]$RequiredMode) {
    $original=Get-DNSAcceptanceIndex $Before
    $coverage=[ordered]@{'dhcp-ipv4'=0;'static-ipv4'=0;'dhcp-ipv6'=0;'static-ipv6'=0}
    foreach($record in $original.adapters.Values){
        if(-not $record.selected){continue}
        foreach($family in @('ipv4','ipv6')){
            $mode=$record.$family.mode
            if($mode -cne 'not-exposed'){$coverage[$mode+'-'+$family]++}
        }
    }
    if(-not ($coverage.Values -gt 0) -or
        ($RequiredMode -cne 'any' -and (-not $coverage.Contains($RequiredMode) -or $coverage[$RequiredMode] -le 0))){
        throw 'Active DNS adapters do not cover the required original mode'
    }
    return $coverage
}
function Assert-DNSRebootConfigured([object]$Before,[object]$After,[string]$Method) {
    $original=Get-DNSAcceptanceIndex $Before
    $observed=Get-DNSAcceptanceIndex $After
    $selected=@($original.adapters.Keys | Where-Object {$original.adapters[$_].selected})
    $active=@($observed.adapters.Keys | Where-Object {$observed.adapters[$_].selected})
    if($selected.Count -ne $active.Count){throw 'Active DNS adapter coverage changed after reboot'}
    foreach($guid in $active){
        if($guid -notin $selected){throw 'Active DNS adapter coverage changed after reboot'}
    }
    Assert-DNSAcceptanceConfigured $Before $After $Method
}
function Assert-RebootResolver([string]$Server='') {
    Clear-DnsClientCache -ErrorAction Stop
    $resolver=@{}
    if($Server){$resolver.Server=$Server}
    # Query both record types through the ordinary resolver. An AAAA answer
    # says nothing about the transport address family used for that lookup.
    $recordTypes=[ordered]@{A=[Net.Sockets.AddressFamily]::InterNetwork;AAAA=[Net.Sockets.AddressFamily]::InterNetworkV6}
    foreach($type in $recordTypes.Keys){
        $answers=@(Resolve-DnsName -Name 'example.com.' -DnsOnly -Type $type -NoHostsFile -QuickTimeout -ErrorAction Stop @resolver)
        $verified=$false
        foreach($answer in $answers){
            $address=$null
            if($answer.Type -eq $type -and $answer.Section -eq 'Answer' -and
               $answer.Name -is [string] -and $answer.Name.TrimEnd('.') -ieq 'example.com' -and
               $answer.IPAddress -is [string] -and [Net.IPAddress]::TryParse($answer.IPAddress,[ref]$address) -and
               $address.AddressFamily -eq $recordTypes[$type] -and -not $address.IsIPv4MappedToIPv6){
                $verified=$true
                break
            }
        }
        if(-not $verified){throw ('Ordinary Windows DNS returned no valid '+$type+' answer')}
    }
}
function Get-DNSRebootListenerOwner([string]$Engine,[string]$Root,[string]$ApprovedSHA256,
    [uint16]$Port,[string[]]$Addresses,[switch]$IncludeUDP) {
    $name='AccessWeaver-'+$Engine
    $rows=@(Get-CimInstance -ClassName Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction Stop)
    if($rows.Count -ne 1 -or $rows[0].Name -ine $name -or $rows[0].State -cne 'Running' -or
       $rows[0].StartMode -cne 'Auto' -or $rows[0].ProcessId -le 0){
        throw 'Expected automatic managed service is not running'
    }
    $serviceID=[uint32]$rows[0].ProcessId
    $directory=Join-Path $Root 'services'
    $hostPath=Join-Path $directory ('host-'+$ApprovedSHA256.ToLowerInvariant()+'.exe')
    $configPath=Join-Path $directory ($Engine+'.json')
    $expectedCommand='"'+$hostPath+'" service-host "'+$configPath+'"'
    $command=$rows[0].PathName
    if($command -isnot [string] -or -not $command.StartsWith($expectedCommand,[StringComparison]::OrdinalIgnoreCase) -or
       $command.Substring($expectedCommand.Length) -cnotmatch '\A --instance=[a-f0-9]{32}\z'){
        throw 'Service registration does not match the approved controller'
    }
    $hostProcess=@(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId="+$serviceID) -ErrorAction Stop)
    if($hostProcess.Count -ne 1 -or $hostProcess[0].ProcessId -ne $serviceID -or
       $hostProcess[0].ExecutablePath -ine $hostPath -or $hostProcess[0].CreationDate -isnot [datetime] -or
       (Get-DNSRebootDigest $hostPath 128MB) -ine $ApprovedSHA256){
        throw 'Running service host does not match the approved controller'
    }

    $config=(Read-DNSRebootRecord $configPath 1MB).record
    if($config.name -ine $name -or $config.binary -isnot [string] -or -not [IO.Path]::IsPathRooted($config.binary)){
        throw 'Managed service executable could not be identified'
    }
    $tcp=@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
    $udp=@()
    if($IncludeUDP){$udp=@(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction Stop)}
    $listeners=@()
    foreach($address in $Addresses){
        $atAddress=@($tcp | Where-Object {$_.LocalAddress -ceq $address})
        if($atAddress.Count -ne 1){throw 'Expected one managed TCP listener on each required loopback address'}
        $listeners+=$atAddress
        if($IncludeUDP){
            $atAddress=@($udp | Where-Object {$_.LocalAddress -ceq $address})
            if($atAddress.Count -ne 1){throw 'Expected one managed UDP listener on each required loopback address'}
            $listeners+=$atAddress
        }
    }
    if(@(($tcp+$udp) | Where-Object {$_.LocalAddress -cin @('0.0.0.0','::')}).Count -ne 0){throw 'Wildcard listener makes loopback ownership ambiguous'}
    if(@($listeners | Where-Object {$_.OwningProcess -le 0}).Count -ne 0){throw 'Loopback listener has no observable process owner'}
    $listenerIDs=@($listeners.OwningProcess | Select-Object -Unique)
    if($listenerIDs.Count -ne 1 -or $listenerIDs[0] -le 0){throw 'Loopback listeners do not have one managed owner'}
    $listenerID=[uint32]$listenerIDs[0]
    $child=@(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId="+$listenerID) -ErrorAction Stop)
    if($child.Count -ne 1 -or $child[0].ProcessId -ne $listenerID -or $child[0].ParentProcessId -ne $serviceID -or
       $child[0].ExecutablePath -ine $config.binary -or $child[0].CreationDate -isnot [datetime] -or
       $child[0].CreationDate -lt $hostProcess[0].CreationDate){
        throw 'Loopback listener does not belong to the expected managed service child'
    }
    return '{0}:{1}:{2}:{3}' -f $serviceID,$hostProcess[0].CreationDate.Ticks,$listenerID,$child[0].CreationDate.Ticks
}
function Assert-DNSRebootActiveResolver([System.Collections.IDictionary]$Coverage,[string]$Method,[string]$Root,[string]$ApprovedSHA256) {
    if($Method -ceq 'doh'){
        Assert-RebootResolver
        return
    }
    $addresses=@()
    if($Coverage['dhcp-ipv4'] + $Coverage['static-ipv4'] -gt 0){$addresses+='127.0.0.1'}
    if($Coverage['dhcp-ipv6'] + $Coverage['static-ipv6'] -gt 0){$addresses+='::1'}
    $owner=Get-DNSRebootListenerOwner 'dnscrypt' $Root $ApprovedSHA256 53 $addresses -IncludeUDP
    Assert-RebootResolver
    foreach($address in $addresses){Assert-RebootResolver -Server $address}
    if((Get-DNSRebootListenerOwner 'dnscrypt' $Root $ApprovedSHA256 53 $addresses -IncludeUDP) -cne $owner){
        throw 'DNSCrypt listener owner changed during resolver verification'
    }
}

function Wait-DNSRebootObservation([scriptblock]$Observe,[int]$TimeoutSeconds=60) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        try {[void](& $Observe);return}
        catch {
            if($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds){throw}
            Start-Sleep -Seconds 1
            if($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds){throw}
        }
    } while($true)
}
function Test-DNSRebootServicesRemoved {
    $remaining=$false
    $observed=0
    Get-Service -ErrorAction Stop | ForEach-Object {
        try {
            if([string]::IsNullOrWhiteSpace($_.ServiceName)){throw 'Service inventory returned an unknown identity'}
            $observed++
            if($_.ServiceName -like 'AccessWeaver-*'){$remaining=$true}
        } finally {
            if($_ -is [IDisposable]){$_.Dispose()}
        }
    }
    if(-not $observed){throw 'Service inventory returned no service identities'}
    return -not $remaining
}
function Invoke-DNSRebootSocksProbe {
    $client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $task=$client.ConnectAsync([Net.IPAddress]::Loopback,1080)
        if(-not $task.Wait(5000)){throw 'Expected loopback service did not respond'}
        $stream=$client.GetStream()
        $stream.ReadTimeout=5000
        $stream.WriteTimeout=5000
        $stream.Write([byte[]]@(5,1,0),0,3)
        if($stream.ReadByte() -ne 5 -or $stream.ReadByte() -ne 0){throw 'Expected SOCKS5 negotiation failed'}
    } finally {$client.Dispose()}
}
function Assert-RebootServices([string]$Method,[string]$Root,[string]$ApprovedSHA256) {
    if($Method -ceq 'dnscrypt'){
        $service=@(Get-CimInstance -ClassName Win32_Service -Filter "Name='AccessWeaver-dnscrypt'" -ErrorAction Stop)
        if($service.Count -ne 1 -or $service[0].Name -ine 'AccessWeaver-dnscrypt' -or
           $service[0].State -cne 'Running' -or $service[0].StartMode -cne 'Auto' -or $service[0].ProcessId -le 0){
            throw 'Expected automatic DNSCrypt service is not running'
        }
    }
    $owner=Get-DNSRebootListenerOwner 'byedpi' $Root $ApprovedSHA256 1080 @('127.0.0.1')
    Invoke-DNSRebootSocksProbe
    if((Get-DNSRebootListenerOwner 'byedpi' $Root $ApprovedSHA256 1080 @('127.0.0.1')) -cne $owner){
        throw 'ByeDPI listener owner changed during SOCKS5 verification'
    }
}

$previousHome=$env:ACCESSWEAVER_HOME
# Hold the approved executable through all dispatches. Windows read sharing
# permits execution while denying writes, renames and deletion of the file.
$controller=Open-ApprovedDNSRebootController $Executable $current.binarySHA256 $nativeArchitecture
try {
    $oracleStream=Open-DNSRebootInput $oracle
    try {
        if($oracleStream.Length -le 0 -or $oracleStream.Length -gt 1MB){throw 'DNS reboot oracle exceeds its size limit'}
        $current.oracleSHA256=(Get-FileHash -InputStream $oracleStream -Algorithm SHA256).Hash
        if($current.oracleSHA256 -ine $OracleSHA256){throw 'DNS reboot oracle differs from the approved source'}
        . $oracle
    } finally {$oracleStream.Dispose()}
    $env:ACCESSWEAVER_HOME=Join-Path $private 'controller-state'
    if($Phase -eq 'Prepare'){
        if((Test-Path -LiteralPath $private -ErrorAction Stop) -or
           (Test-Path -LiteralPath $machineRoot -ErrorAction Stop) -or -not (Test-DNSRebootServicesRemoved)){
            throw 'A fresh guest checkpoint and results directory are required'
        }
        $before=Read-DNSAcceptanceState
        $coverage=Get-DNSRebootCoverage $before $current.requiredOriginalMode
        Assert-RebootResolver
        [void][IO.Directory]::CreateDirectory($private)
        $security=[Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-32-544','S-1-5-18')){
            $principal=[Security.Principal.SecurityIdentifier]::new($sid)
            $rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $security.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $private -AclObject $security -ErrorAction Stop
        Save-DNSRebootRecord (Join-Path $private 'original.json') @{schemaVersion=7;dns=$before}
        Invoke-DNSRebootPreparation {
            [void](Invoke-TestWorkflow @{action='install';engine='byedpi';mode='service';bundlePath='C:\AccessWeaver-Test\components'})
            $applied=Invoke-TestWorkflow @{action='dns';dns=$DNS;bundlePath='C:\AccessWeaver-Test\components'}
            Assert-RebootServices $DNS $machineRoot $current.binarySHA256
            Assert-DNSRebootConfigured $before (Read-DNSAcceptanceState) $DNS
            Assert-DNSRebootActiveResolver $coverage $DNS $machineRoot $current.binarySHA256
            Assert-DNSRebootConfigured $before (Read-DNSAcceptanceState) $DNS
            $current.dns=$before
            $current.snapshotSHA256=Get-DNSRebootDigest $snapshot 8MB
            $current.copySHA256=Get-DNSRebootDigest $recoveryCopy (8MB+65)
            $current.journalId=Get-DNSRebootJournalID $applied.journal $logDirectory
            $journalPath=Join-Path $logDirectory $current.journalId
            $journal=Read-DNSRebootRecord $journalPath 8MB
            $current.journalSHA256=$journal.sha256
            Assert-DNSRebootJournal $journal.record $current.snapshotSHA256
            Save-DNSRebootRecord $baseline $current
        } {
            # Product removal restores and reads back DNS before removing services.
            [void](Invoke-TestWorkflow @{action='remove-all'})
            Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState)
            Assert-RebootResolver
            Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState)
            if((Test-Path -LiteralPath $snapshot -ErrorAction Stop) -or
               (Test-Path -LiteralPath $recoveryCopy -ErrorAction Stop) -or -not (Test-DNSRebootServicesRemoved)){
                throw 'DNS reboot preparation cleanup retained a snapshot or managed service'
            }
        }
        return
    }

    $saved=(Read-DNSRebootRecord $baseline 1MB).record
    if($saved.journalId -isnot [string] -or $saved.journalId -cnotmatch '\Aworkflow-[a-f0-9]{32}\.json\z'){
        throw 'Prepared DNS reboot journal name is invalid'
    }
    $current.journalId=$saved.journalId
    $journalPath=Join-Path $logDirectory $current.journalId
    $journal=Read-DNSRebootRecord $journalPath 8MB
    $current.journalSHA256=$journal.sha256
    $current.snapshotSHA256=Get-DNSRebootDigest $snapshot 8MB
    $current.copySHA256=Get-DNSRebootDigest $recoveryCopy (8MB+65)
    Assert-DNSRebootAdmission $saved $current
    Assert-DNSRebootJournal $journal.record $current.snapshotSHA256
    $coverage=Get-DNSRebootCoverage $saved.dns $saved.requiredOriginalMode
    if(Test-Path -LiteralPath $report){throw 'DNS reboot evidence already exists'}
    if(Test-Path -LiteralPath (Join-Path $private 'verification-started.json')){
        throw 'Interrupted DNS reboot verification requires a fresh checkpoint'
    }
    Save-DNSRebootRecord (Join-Path $private 'verification-started.json') @{schemaVersion=7}
    $heldSnapshot=Join-Path ([IO.Path]::GetDirectoryName($snapshot)) ('reboot-held-'+$saved.qualificationID+'.json')
    $primaryMoved=$false
    $outcome=[ordered]@{schemaVersion=12;qualificationID=$saved.qualificationID;method=$saved.method;architecture=$current.architecture;binarySHA256=$current.binarySHA256;
        requiredOriginalMode=$saved.requiredOriginalMode;originalModeCoverage=$coverage;
        fixtureSHA256=$current.fixtureSHA256;oracleSHA256=$current.oracleSHA256;
        rebootVerified=$true;servicesVerified=$false;configuredStateVerified=$false;
        resolverVerified=$false;journalBindingVerified=$true;primarySnapshotHeld=$false;journalRecoveryAccepted=$false;
        originalStateRestored=$false;originalResolverVerified=$false;snapshotRetired=$false;restorationReceiptVerified=$false;
        servicesRemoved=$false;passed=$false;stage='services';cleanupStage='not-started';teardownStage='not-started'}
    try {
        Wait-DNSRebootObservation {Assert-RebootServices $saved.method $machineRoot $current.binarySHA256}
        $outcome.servicesVerified=$true
        $outcome.stage='configured-state'
        Wait-DNSRebootObservation {Assert-DNSRebootConfigured $saved.dns (Read-DNSAcceptanceState) $saved.method}
        $outcome.configuredStateVerified=$true
        $outcome.stage='resolver'
        Wait-DNSRebootObservation {Assert-DNSRebootActiveResolver $coverage $saved.method $machineRoot $current.binarySHA256}
        $outcome.stage='configured-readback'
        $outcome.configuredStateVerified=$false
        Assert-DNSRebootConfigured $saved.dns (Read-DNSAcceptanceState) $saved.method
        $outcome.configuredStateVerified=$true
        $outcome.resolverVerified=$true
        $outcome.stage='complete'
    } catch {
        # Record only the source-defined stage.
    } finally {
        try {
            $outcome.cleanupStage='journal-binding'
            if((Get-DNSRebootDigest $journalPath 8MB) -cne $current.journalSHA256){
                throw 'Prepared DNS journal changed before recovery'
            }
            $outcome.cleanupStage='primary-hold'
            if((Get-DNSRebootDigest $snapshot 8MB) -cne $current.snapshotSHA256){
                throw 'Prepared DNS snapshot changed before recovery'
            }
            [IO.File]::Move($snapshot,$heldSnapshot)
            $primaryMoved=$true
            if((Test-Path -LiteralPath $snapshot -ErrorAction Stop) -or
               (Get-DNSRebootDigest $heldSnapshot 8MB) -cne $current.snapshotSHA256 -or
               (Get-DNSRebootDigest $recoveryCopy (8MB+65)) -cne $current.copySHA256){
                throw 'Prepared DNS snapshot hold or protected copy could not be verified'
            }
            $outcome.primarySnapshotHeld=$true
            $outcome.cleanupStage='journal-recovery'
            [void](Invoke-TestWorkflow @{action='recover';journalId=$saved.journalId})
            $outcome.journalRecoveryAccepted=$true
            $outcome.cleanupStage='original-state'
            Assert-DNSAcceptanceRestored $saved.dns (Read-DNSAcceptanceState)
            $outcome.originalStateRestored=$true
            $outcome.cleanupStage='original-resolver'
            Assert-RebootResolver
            # Verify that the probe still corresponds to the restored DNS state.
            Assert-DNSAcceptanceRestored $saved.dns (Read-DNSAcceptanceState)
            $outcome.originalResolverVerified=$true
            $outcome.cleanupStage='snapshot-retirement'
            $outcome.snapshotRetired=-not ((Test-Path -LiteralPath $snapshot -ErrorAction Stop) -or
                (Test-Path -LiteralPath $recoveryCopy -ErrorAction Stop))
            if(-not $outcome.snapshotRetired){throw 'Journal recovery retained active DNS recovery files'}
            $outcome.cleanupStage='restoration-receipt'
            $receipt=Join-Path ([IO.Path]::GetDirectoryName($snapshot)) ('dns-restored-'+$current.snapshotSHA256.ToLowerInvariant()+'.receipt')
            $expectedReceipt=[Text.Encoding]::ASCII.GetBytes($current.snapshotSHA256.ToUpperInvariant())
            $sha256=[Security.Cryptography.SHA256]::Create()
            try {$expectedReceiptSHA256=[BitConverter]::ToString($sha256.ComputeHash($expectedReceipt)).Replace('-','')}
            finally {$sha256.Dispose()}
            if((Get-DNSRebootDigest $receipt 64) -cne $expectedReceiptSHA256){
                throw 'DNS restoration receipt does not bind the retired snapshot'
            }
            $outcome.restorationReceiptVerified=$true
            $outcome.cleanupStage='held-snapshot-retirement'
            if((Get-DNSRebootDigest $heldSnapshot 8MB) -cne $current.snapshotSHA256){
                throw 'Held DNS snapshot changed after journal recovery'
            }
            [IO.File]::Delete($heldSnapshot)
            if(Test-Path -LiteralPath $heldSnapshot -ErrorAction Stop){throw 'Held DNS snapshot was not retired'}
            $outcome.cleanupStage='recovered'
        } catch {
            # Keep the first fixed recovery failure even if teardown later restores DNS.
            if($primaryMoved -and -not $outcome.journalRecoveryAccepted -and -not [IO.File]::Exists($snapshot)){
                try {
                    if((Get-DNSRebootDigest $heldSnapshot 8MB) -ceq $current.snapshotSHA256){
                        [IO.File]::Move($heldSnapshot,$snapshot)
                    }
                }catch{}
            }
        }
        try {
            $outcome.teardownStage='remove-all'
            [void](Invoke-TestWorkflow @{action='remove-all'})
            $outcome.teardownStage='original-state'
            Assert-DNSAcceptanceRestored $saved.dns (Read-DNSAcceptanceState)
            $outcome.teardownStage='original-resolver'
            Assert-RebootResolver
            Assert-DNSAcceptanceRestored $saved.dns (Read-DNSAcceptanceState)
            $outcome.teardownStage='snapshot-retirement'
            if((Test-Path -LiteralPath $snapshot -ErrorAction Stop) -or
               (Test-Path -LiteralPath $recoveryCopy -ErrorAction Stop)){throw 'Teardown retained active DNS recovery files'}
            $outcome.teardownStage='service-inventory'
            $outcome.servicesRemoved=Test-DNSRebootServicesRemoved
            $outcome.teardownStage=if($outcome.servicesRemoved){'complete'}else{'services-remain'}
        } catch {
            # Preserve the fixed teardown stage alongside the journal recovery result.
        }
        $outcome.passed=$outcome.stage -ceq 'complete' -and $outcome.cleanupStage -ceq 'recovered' -and
            $outcome.teardownStage -ceq 'complete'
        Save-DNSRebootRecord $report $outcome
    }
    if(-not $outcome.passed){throw 'DNS reboot acceptance failed; inspect the fixed guest result'}
} finally {
    try {$env:ACCESSWEAVER_HOME=$previousHome} finally {$controller.Dispose()}
}
