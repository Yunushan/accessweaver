# Prepare and verify on the same disposable Windows guest, with an external reboot between phases.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Verify')][string]$Phase,
    [string]$Executable='C:\AccessWeaver-Test\accessweaver.exe',
    [ValidateSet('auto','doh','dnscrypt')][string]$DNS='auto'
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Assert-DNSRebootAdmission($Saved,$Current) {
    if($Saved.schemaVersion -ne 5 -or $Saved.method -cnotin @('doh','dnscrypt') -or
       $Saved.qualificationID -isnot [string] -or $Saved.qualificationID -cnotmatch '\A[a-f0-9]{32}\z' -or
       $Saved.guestID -cne $Current.guestID -or $Saved.binarySHA256 -cne $Current.binarySHA256 -or
       $Saved.oracleSHA256 -cne $Current.oracleSHA256 -or $Saved.fixtureSHA256 -cne $Current.fixtureSHA256 -or
       $Saved.snapshotSHA256 -cnotmatch '\A[A-F0-9]{64}\z' -or $Saved.snapshotSHA256 -cne $Current.snapshotSHA256 -or
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
function Get-DNSRebootDigest([string]$Path,[long]$Maximum) {
    $entry=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($entry.PSIsContainer){throw 'Expected a bounded ordinary DNS reboot input'}
    for($currentPath=$Path;$currentPath;$currentPath=[IO.Path]::GetDirectoryName($currentPath)){
        $component=Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        if($component.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'DNS reboot input includes a reparse point'}
        if($currentPath -ieq [IO.Path]::GetPathRoot($currentPath)){break}
    }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt $Maximum){throw 'DNS reboot input exceeds its size limit'}
        return (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
    } finally {$stream.Dispose()}
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
$current=@{
    schemaVersion=5;guestID=$guestID.ToString('D');
    binarySHA256=(Get-DNSRebootDigest $Executable 128MB);oracleSHA256=(Get-DNSRebootDigest $oracle 1MB);
    fixtureSHA256=(Get-DNSRebootDigest $PSCommandPath 1MB);
    boot=$os.LastBootUpTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
}
. $oracle
$private=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AccessWeaver DNS reboot fixture'
$baseline=Join-Path $private 'prepared.json'
$machineRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AccessWeaver'
$snapshot=Join-Path $machineRoot 'profiles\dns-original.json'
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
function Assert-RebootResolver {
    Clear-DnsClientCache -ErrorAction Stop
    if(-not @(Resolve-DnsName example.com -DnsOnly -Type A -ErrorAction Stop | Where-Object {$_.Type -eq 'A' -and $_.IPAddress}).Count){
        throw 'Ordinary Windows DNS returned no IPv4 answer'
    }
}
function Assert-RebootServices([string]$Method) {
    foreach($name in @('AccessWeaver-byedpi','AccessWeaver-dnscrypt')){
        if($name -eq 'AccessWeaver-dnscrypt' -and $Method -ne 'dnscrypt'){continue}
        $service=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction Stop
        if(@($service).Count -ne 1 -or $service.State -cne 'Running' -or $service.StartMode -cne 'Auto'){
            throw 'Expected automatic service is not running'
        }
    }
    $client=[Net.Sockets.TcpClient]::new()
    try {
        $task=$client.ConnectAsync('127.0.0.1',1080)
        if(-not $task.Wait(5000)){throw 'Expected loopback service did not respond'}
        $stream=$client.GetStream()
        $stream.ReadTimeout=5000
        $stream.Write([byte[]]@(5,1,0),0,3)
        if($stream.ReadByte() -ne 5 -or $stream.ReadByte() -ne 0){throw 'Expected SOCKS5 negotiation failed'}
    } finally {$client.Dispose()}
}

$previousHome=$env:ACCESSWEAVER_HOME
try {
    $env:ACCESSWEAVER_HOME=Join-Path $private 'controller-state'
    if($Phase -eq 'Prepare'){
        if((Test-Path -LiteralPath $private) -or (Test-Path -LiteralPath $report) -or
           (Test-Path -LiteralPath $snapshot) -or @(Get-Service 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count){
            throw 'A fresh guest checkpoint and results directory are required'
        }
        $before=Read-DNSAcceptanceState
        Assert-RebootResolver
        if($DNS -eq 'auto'){$DNS=if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){'doh'}else{'dnscrypt'}}
        [void][IO.Directory]::CreateDirectory($private)
        $security=[Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-32-544','S-1-5-18')){
            $principal=[Security.Principal.SecurityIdentifier]::new($sid)
            $rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $security.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $private -AclObject $security -ErrorAction Stop
        Save-DNSRebootRecord (Join-Path $private 'original.json') @{schemaVersion=5;dns=$before}
        [void](Invoke-TestWorkflow @{action='install';engine='byedpi';mode='service';bundlePath='C:\AccessWeaver-Test\components'})
        $applied=Invoke-TestWorkflow @{action='dns';dns=$DNS;bundlePath='C:\AccessWeaver-Test\components'}
        Assert-RebootServices $DNS
        Assert-DNSAcceptanceConfigured $before (Read-DNSAcceptanceState) $DNS
        Assert-RebootResolver
        $current.qualificationID=[guid]::NewGuid().ToString('N')
        $current.method=$DNS
        $current.dns=$before
        $current.snapshotSHA256=Get-DNSRebootDigest $snapshot 8MB
        $current.journalId=Get-DNSRebootJournalID $applied.journal $logDirectory
        $journalPath=Join-Path $logDirectory $current.journalId
        $current.journalSHA256=Get-DNSRebootDigest $journalPath 8MB
        Assert-DNSRebootJournal (Get-Content -LiteralPath $journalPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) $current.snapshotSHA256
        Save-DNSRebootRecord $baseline $current
        return
    }

    [void](Get-DNSRebootDigest $baseline 1MB)
    $saved=Get-Content -LiteralPath $baseline -Raw -ErrorAction Stop | ConvertFrom-Json
    if($saved.journalId -isnot [string] -or $saved.journalId -cnotmatch '\Aworkflow-[a-f0-9]{32}\.json\z'){
        throw 'Prepared DNS reboot journal name is invalid'
    }
    $current.journalId=$saved.journalId
    $journalPath=Join-Path $logDirectory $current.journalId
    $current.journalSHA256=Get-DNSRebootDigest $journalPath 8MB
    $current.snapshotSHA256=Get-DNSRebootDigest $snapshot 8MB
    Assert-DNSRebootAdmission $saved $current
    Assert-DNSRebootJournal (Get-Content -LiteralPath $journalPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) $current.snapshotSHA256
    [void](Get-DNSAcceptanceIndex $saved.dns)
    if(Test-Path -LiteralPath $report){throw 'DNS reboot evidence already exists'}
    if(Test-Path -LiteralPath (Join-Path $private 'verification-started.json')){
        throw 'Interrupted DNS reboot verification requires a fresh checkpoint'
    }
    Save-DNSRebootRecord (Join-Path $private 'verification-started.json') @{schemaVersion=5}
    $outcome=[ordered]@{schemaVersion=5;qualificationID=$saved.qualificationID;method=$saved.method;binarySHA256=$current.binarySHA256;
        fixtureSHA256=$current.fixtureSHA256;oracleSHA256=$current.oracleSHA256;
        rebootVerified=$true;servicesVerified=$false;configuredStateVerified=$false;
        resolverVerified=$false;journalBindingVerified=$true;journalRecoveryAccepted=$false;
        originalStateRestored=$false;originalResolverVerified=$false;snapshotRetired=$false;
        servicesRemoved=$false;passed=$false;stage='services';cleanupStage='not-started'}
    try {
        Assert-RebootServices $saved.method
        $outcome.servicesVerified=$true
        $outcome.stage='configured-state'
        Assert-DNSAcceptanceConfigured $saved.dns (Read-DNSAcceptanceState) $saved.method
        $outcome.configuredStateVerified=$true
        $outcome.stage='resolver'
        Assert-RebootResolver
        $outcome.resolverVerified=$true
        $outcome.stage='complete'
    } catch {
        # Record only the source-defined stage.
    } finally {
        try {
            $outcome.cleanupStage='journal-recovery'
            [void](Invoke-TestWorkflow @{action='recover';journalId=$saved.journalId})
            $outcome.journalRecoveryAccepted=$true
            $outcome.cleanupStage='original-state'
            Assert-DNSAcceptanceRestored $saved.dns (Read-DNSAcceptanceState)
            $outcome.originalStateRestored=$true
            $outcome.cleanupStage='original-resolver'
            Assert-RebootResolver
            $outcome.originalResolverVerified=$true
            $outcome.cleanupStage='snapshot-retirement'
            $outcome.snapshotRetired=-not (Test-Path -LiteralPath $snapshot -ErrorAction Stop)
            if(-not $outcome.snapshotRetired){throw 'Journal recovery retained the active snapshot'}
            $outcome.cleanupStage='recovered'
        } catch {
            # Keep the first fixed recovery failure even if teardown later restores DNS.
        }
        try {
            [void](Invoke-TestWorkflow @{action='remove-all'})
            $outcome.servicesRemoved=-not @(Get-Service 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count
            Assert-DNSAcceptanceRestored $saved.dns (Read-DNSAcceptanceState)
            Assert-RebootResolver
            if($outcome.cleanupStage -ceq 'recovered' -and $outcome.servicesRemoved -and
                -not (Test-Path -LiteralPath $snapshot -ErrorAction Stop)){$outcome.cleanupStage='complete'}
        } catch {
            # A recovery result remains available even when later teardown fails.
        }
        $outcome.passed=$outcome.stage -ceq 'complete' -and $outcome.cleanupStage -ceq 'complete'
        Save-DNSRebootRecord $report $outcome
    }
    if(-not $outcome.passed){throw 'DNS reboot acceptance failed; inspect the fixed guest result'}
} finally {$env:ACCESSWEAVER_HOME=$previousHome}
