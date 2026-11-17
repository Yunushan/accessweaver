# Startup verifier installed only by the disposable VMware guest controller.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ExecutableName,
    [Parameter(Mandatory)][ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$ExecutableSHA256,
    [Parameter(Mandatory)][ValidateScript({$_ -cmatch '\A[0-9a-f]{32}\z'})][string]$QualificationID,
    [Parameter(Mandatory)][ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$FixtureSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$OracleSHA256,
    [Parameter(Mandatory)][ValidateSet('doh','dnscrypt')][string]$DNS,
    [Parameter(Mandatory)][ValidateSet('any','dhcp-ipv4','static-ipv4','dhcp-ipv6','static-ipv6')][string]$RequiredOriginalMode
)
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
function Assert-DNSRebootPublicReport([byte[]]$Data,[string]$ApprovedSHA256,[string]$ExpectedQualificationID,
    [string]$ExpectedMethod,[string]$ExpectedOriginalMode,[string]$ExpectedFixtureSHA256,[string]$ExpectedOracleSHA256,[string]$ExpectedArchitecture) {
    $record=[Text.UTF8Encoding]::new($false,$true).GetString($Data) | ConvertFrom-Json -ErrorAction Stop
    $flags=@('rebootVerified','servicesVerified','configuredStateVerified','resolverVerified','journalBindingVerified',
        'primarySnapshotHeld','journalRecoveryAccepted','originalStateRestored','originalResolverVerified','snapshotRetired','restorationReceiptVerified','servicesRemoved','passed')
    $digests=@('binarySHA256','fixtureSHA256','oracleSHA256')
    $modes=@('dhcp-ipv4','static-ipv4','dhcp-ipv6','static-ipv6')
    $stages=@('services','configured-state','resolver','configured-readback','complete')
    $cleanupStages=@('journal-binding','primary-hold','journal-recovery','original-state','original-resolver',
        'snapshot-retirement','restoration-receipt','held-snapshot-retirement','recovered')
    $teardownStages=@('remove-all','original-state','original-resolver','snapshot-retirement','service-inventory','services-remain','complete')
    $keys=@('schemaVersion','qualificationID','method','architecture','requiredOriginalMode','originalModeCoverage','stage','cleanupStage','teardownStage')+$flags+$digests
    if($record -isnot [pscustomobject] -or @($record.PSObject.Properties).Count -ne $keys.Count -or
        @($record.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or
        ($record.schemaVersion -isnot [int] -and $record.schemaVersion -isnot [long]) -or $record.schemaVersion -ne 12 -or
        $record.qualificationID -isnot [string] -or $record.qualificationID -cnotmatch '\A[a-f0-9]{32}\z' -or
        $record.method -isnot [string] -or $record.method -cnotin @('doh','dnscrypt') -or
        $record.architecture -isnot [string] -or $record.architecture -cnotin @('amd64','arm64') -or
        $record.architecture -cne $ExpectedArchitecture -or
        $record.stage -isnot [string] -or $record.cleanupStage -isnot [string] -or $record.teardownStage -isnot [string] -or
        $record.stage -cnotin $stages -or $record.cleanupStage -cnotin $cleanupStages -or $record.teardownStage -cnotin $teardownStages){
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
    if($record.binarySHA256 -ine $ApprovedSHA256){
        throw 'DNS reboot report does not match the approved controller'
    }
    if($record.fixtureSHA256 -ine $ExpectedFixtureSHA256 -or $record.oracleSHA256 -ine $ExpectedOracleSHA256){
        throw 'DNS reboot report does not match the approved fixture and oracle'
    }
    if($record.qualificationID -cne $ExpectedQualificationID){
        throw 'DNS reboot report does not match the scheduled qualification'
    }
    $stage=[Array]::IndexOf($stages,$record.stage)
    $cleanup=[Array]::IndexOf($cleanupStages,$record.cleanupStage)
    $teardownComplete=$record.teardownStage -ceq 'complete'
    if(-not $record.rebootVerified -or -not $record.journalBindingVerified -or
        $record.servicesVerified -ne ($stage -ge 1) -or $record.configuredStateVerified -ne ($record.stage -cin @('resolver','complete')) -or
        $record.resolverVerified -ne ($stage -eq 4) -or
        $record.primarySnapshotHeld -ne ($cleanup -ge 2) -or
        $record.journalRecoveryAccepted -ne ($cleanup -ge 3) -or $record.originalStateRestored -ne ($cleanup -ge 4) -or
        $record.originalResolverVerified -ne ($cleanup -ge 5) -or $record.snapshotRetired -ne ($cleanup -ge 6) -or
        $record.restorationReceiptVerified -ne ($cleanup -ge 7) -or
        $record.servicesRemoved -ne $teardownComplete -or
        $record.passed -ne ($stage -eq 4 -and $record.cleanupStage -ceq 'recovered' -and $teardownComplete)){
        throw 'DNS reboot report outcome is inconsistent'
    }
    if($record.method -cne $ExpectedMethod -or $record.requiredOriginalMode -cne $ExpectedOriginalMode){
        throw 'DNS reboot report does not match the scheduled method or original mode'
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
function Complete-DNSRebootStartup([string]$Report,[string]$ResultsDirectory,[scriptblock]$Verify,[scriptblock]$Retire,[string]$ApprovedSHA256,[string]$ExpectedQualificationID,
    [string]$ExpectedMethod,[string]$ExpectedOriginalMode,[string]$ExpectedFixtureSHA256,[string]$ExpectedOracleSHA256,[string]$ExpectedArchitecture) {
    if(-not [IO.File]::Exists($Report)){
        try{[void](& $Verify)}catch{
            # A failed acceptance can still have a complete fixed report.
            if(-not [IO.File]::Exists($Report)){throw}
        }
    }
    $data=Read-DNSRebootReport $Report
    $passed=Assert-DNSRebootPublicReport $data $ApprovedSHA256 $ExpectedQualificationID $ExpectedMethod $ExpectedOriginalMode $ExpectedFixtureSHA256 $ExpectedOracleSHA256 $ExpectedArchitecture
    $destination=Join-Path $ResultsDirectory ('reboot-results-'+$ExpectedQualificationID+'.json')
    Publish-DNSRebootPublicReport $destination $data
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
$resultsDirectory='\\vmware-host\Shared Folders\AccessWeaver-Results'
$binary=Join-Path 'C:\AccessWeaver-Test' $ExecutableName
$nativeArchitecture=@{X64='amd64';Arm64='arm64'}[[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()]
if(-not $nativeArchitecture -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.RuntimeInformation]::OSArchitecture){
    throw 'A native 64-bit Windows DNS reboot guest and shell are required'
}
$passed=Complete-DNSRebootStartup $report $resultsDirectory {
    $fixture='C:\AccessWeaver-Test\test-windows-reboot.ps1'
    $stream=[IO.File]::Open($fixture,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 1MB -or
            (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash -ine $FixtureSHA256){
            throw 'Staged DNS reboot fixture differs from the approved source'
        }
        & $fixture -Phase Verify -Executable $binary -ExecutableSHA256 $ExecutableSHA256 -QualificationID $QualificationID -DNS $DNS -RequiredOriginalMode $RequiredOriginalMode -FixtureSHA256 $FixtureSHA256 -OracleSHA256 $OracleSHA256
    } finally {$stream.Dispose()}
} {
    Unregister-ScheduledTask -TaskName 'AccessWeaver-Parity-Reboot-Verify' -Confirm:$false -ErrorAction Stop
} $ExecutableSHA256 $QualificationID ($DNS.ToLowerInvariant()) ($RequiredOriginalMode.ToLowerInvariant()) $FixtureSHA256 $OracleSHA256 $nativeArchitecture
if(-not $passed){throw 'DNS reboot acceptance failed; fixed evidence published'}
