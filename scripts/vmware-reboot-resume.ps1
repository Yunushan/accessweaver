# Startup verifier installed only by the disposable VMware guest controller.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExecutableName)
$ErrorActionPreference='Stop'

function Read-DNSRebootReport([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'DNS reboot report must be an ordinary file'
    }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 16KB){throw 'DNS reboot report size refused'}
        $data=[byte[]]::new([int]$stream.Length)
        $offset=0
        while($offset -lt $data.Length){
            $read=$stream.Read($data,$offset,$data.Length-$offset)
            if($read -eq 0){throw 'DNS reboot report was truncated'}
            $offset+=$read
        }
        if($stream.ReadByte() -ne -1){throw 'DNS reboot report changed during read'}
        return ,$data
    } finally {$stream.Dispose()}
}
function Assert-DNSRebootPublicReport([byte[]]$Data) {
    $record=[Text.UTF8Encoding]::new($false,$true).GetString($Data) | ConvertFrom-Json -ErrorAction Stop
    $flags=@('rebootVerified','servicesVerified','configuredStateVerified','resolverVerified','journalBindingVerified',
        'journalRecoveryAccepted','originalStateRestored','originalResolverVerified','snapshotRetired','servicesRemoved','passed')
    $digests=@('binarySHA256','fixtureSHA256','oracleSHA256')
    $modes=@('dhcp-ipv4','static-ipv4','dhcp-ipv6','static-ipv6')
    $keys=@('schemaVersion','qualificationID','method','requiredOriginalMode','originalModeCoverage','stage','cleanupStage')+$flags+$digests
    if($record -isnot [pscustomobject] -or @($record.PSObject.Properties).Count -ne $keys.Count -or
        @($record.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or
        ($record.schemaVersion -isnot [int] -and $record.schemaVersion -isnot [long]) -or $record.schemaVersion -ne 6 -or
        $record.qualificationID -isnot [string] -or $record.qualificationID -cnotmatch '\A[a-f0-9]{32}\z' -or
        $record.method -isnot [string] -or $record.method -cnotin @('doh','dnscrypt') -or
        $record.stage -isnot [string] -or $record.cleanupStage -isnot [string] -or
        $record.stage -cnotin @('services','configured-state','resolver','complete') -or
        $record.cleanupStage -cnotin @('journal-recovery','original-state','original-resolver','snapshot-retirement','recovered','complete')){
        throw 'DNS reboot report schema refused'
    }
    $coverage=$record.originalModeCoverage
    if($coverage -isnot [pscustomobject] -or @($coverage.PSObject.Properties).Count -ne $modes.Count -or
        @($coverage.PSObject.Properties.Name | Where-Object {$_ -cnotin $modes}).Count -ne 0 -or
        $record.requiredOriginalMode -isnot [string] -or $record.requiredOriginalMode -cnotin (@('any')+$modes)){
        throw 'DNS reboot original mode coverage refused'
    }
    $covered=$false
    foreach($mode in $modes){
        $count=$coverage.$mode
        if(($count -isnot [int] -and $count -isnot [long]) -or $count -lt 0 -or $count -gt [int]::MaxValue){
            throw 'DNS reboot original mode count refused'
        }
        if($count -gt 0){$covered=$true}
    }
    if(-not $covered -or ($record.requiredOriginalMode -cne 'any' -and $coverage.($record.requiredOriginalMode) -eq 0)){
        throw 'DNS reboot required original mode is missing'
    }
    foreach($flag in $flags){if($record.$flag -isnot [bool]){throw 'DNS reboot report flag refused'}}
    foreach($digest in $digests){
        if($record.$digest -isnot [string] -or $record.$digest -cnotmatch '\A[A-F0-9]{64}\z'){throw 'DNS reboot report digest refused'}
    }
    if(-not $record.rebootVerified -or -not $record.journalBindingVerified -or
        $record.passed -ne ($record.stage -ceq 'complete' -and $record.cleanupStage -ceq 'complete') -or
        ($record.passed -and @($flags | Where-Object {-not $record.$_}).Count -ne 0)){
        throw 'DNS reboot report outcome is inconsistent'
    }
    return $record.passed
}
function Publish-DNSRebootPublicReport([string]$Destination,[byte[]]$Data) {
    if([IO.File]::Exists($Destination)){
        $existing=Read-DNSRebootReport $Destination
        if(-not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($existing,$Data)){
            throw 'Host DNS reboot result already contains different evidence'
        }
        return
    }
    $staged=Join-Path (Split-Path -Parent $Destination) ([guid]::NewGuid().ToString('N')+'.tmp')
    $stream=[IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        try {$stream.Write($Data,0,$Data.Length);$stream.Flush()} finally {$stream.Dispose()}
        [IO.File]::Move($staged,$Destination)
    } finally {[IO.File]::Delete($staged)}
}
function Complete-DNSRebootStartup([string]$Report,[string]$Destination,[scriptblock]$Verify,[scriptblock]$Retire) {
    if(-not [IO.File]::Exists($Report)){
        try{[void](& $Verify)}catch{
            # A failed acceptance can still have a complete fixed report.
            if(-not [IO.File]::Exists($Report)){throw}
        }
    }
    $data=Read-DNSRebootReport $Report
    $passed=Assert-DNSRebootPublicReport $data
    Publish-DNSRebootPublicReport $Destination $data
    [void](& $Retire)
    return $passed
}

if($ExecutableName -cnotmatch '\Aaccessweaver[a-zA-Z0-9-]*\.exe\z'){throw 'Unexpected test controller name'}
$tools=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'VMware\VMware Tools\vmtoolsd.exe'
if(-not (Test-Path -LiteralPath $tools -PathType Leaf)){throw 'Disposable VMware guest tools required'}
$marker=& $tools --cmd 'info-get guestinfo.accessweaverParity'
if($LASTEXITCODE -ne 0 -or ($marker -join '').Trim() -cne 'AccessWeaver-Clean-Windows-Test'){
    throw 'Disposable VMware guest identity marker required'
}
$private=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AccessWeaver DNS reboot fixture'
$report=Join-Path $private 'reboot-results.json'
$destination='\\vmware-host\Shared Folders\AccessWeaver-Results\reboot-results.json'
$binary=Join-Path 'C:\AccessWeaver-Test' $ExecutableName
$passed=Complete-DNSRebootStartup $report $destination {
    & C:\AccessWeaver-Test\test-windows-reboot.ps1 -Phase Verify -Executable $binary
} {
    Unregister-ScheduledTask -TaskName 'AccessWeaver-Parity-Reboot-Verify' -Confirm:$false -ErrorAction Stop
}
if(-not $passed){throw 'DNS reboot acceptance failed; fixed evidence published'}
