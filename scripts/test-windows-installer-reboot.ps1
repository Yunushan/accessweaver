# Run inside the same disposable VMware guest before and after its external reboot.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Verify')][string]$Phase,
    [Parameter(Mandatory)][ValidatePattern('\A[a-f0-9]{32}\z')][string]$RunID,
    [Parameter(Mandatory)][ValidateSet('amd64','arm64')][string]$Architecture,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$SetupSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$PayloadSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$PublisherCertificateSHA256,
    [string]$PreviousVersion='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$PreviousPayloadSHA256='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$PreviousPayloadSBOMSHA256='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$PreviousPayloadPublisherCertificateSHA256='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$PreviousSetupSHA256='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$PreviousPublisherCertificateSHA256='',
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$PayloadPublisherCertificateSHA256='',
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$PayloadSBOMSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$BuildInfoSHA256,
    [ValidatePattern('\A(?:[a-fA-F0-9]{64})?\z')][string]$PreviousBuildInfoSHA256=''
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Assert-LaterGuestBoot([string]$Before,[string]$After){
    $previous=0L;$current=0L
    if($Before -cnotmatch '\A[0-9]{18}\z' -or $After -cnotmatch '\A[0-9]{18}\z' -or
       -not [long]::TryParse($Before,[ref]$previous) -or -not [long]::TryParse($After,[ref]$current) -or
       $current -le $previous){
        throw 'The guest boot did not advance'
    }
}
function Write-NewRebootEvidence([string]$Path,$Data){
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $bytes=$encoding.GetBytes(($Data|ConvertTo-Json -Depth 5 -Compress))
    if($bytes.Length -gt 8192){throw 'Installer reboot evidence exceeds the size limit'}
    $staged=Join-Path (Split-Path -Parent $Path) ([guid]::NewGuid().ToString('N')+'.tmp')
    $file=[IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        try {
            $file.Write($bytes,0,$bytes.Length)
            $file.Flush($true)
        } finally {$file.Dispose()}
        [IO.File]::Move($staged,$Path)
    } finally {[IO.File]::Delete($staged)}
}
function Get-RebootInstallMode([string]$Version,[string]$PayloadSHA256,[string]$PreviousVersion,[string]$PreviousPayloadSHA256,
        [string]$PreviousPayloadSBOMSHA256,[string]$PreviousPayloadPublisherSHA256){
    if(-not ($PreviousVersion -or $PreviousPayloadSHA256 -or $PreviousPayloadSBOMSHA256 -or $PreviousPayloadPublisherSHA256)){
        return 'clean'
    }
    if(-not $PreviousVersion -or $Version -ceq $PreviousVersion -or $PayloadSHA256 -ieq $PreviousPayloadSHA256){
        throw 'Upgrade qualification requires a distinct approved previous release'
    }
    foreach($pin in @($PreviousPayloadSHA256,$PreviousPayloadSBOMSHA256,$PreviousPayloadPublisherSHA256)){
        if($pin -notmatch '\A[a-fA-F0-9]{64}\z'){throw 'Upgrade qualification requires approved previous payload, SBOM and publisher digests'}
    }
    return 'upgrade'
}
function Test-RebootDowngradeInputs([string]$InstallMode,[string]$SetupSHA256,[string]$PreviousSetupSHA256,[string]$PreviousPublisherSHA256){
    if(-not $PreviousSetupSHA256 -and -not $PreviousPublisherSHA256){return $false}
    if($InstallMode -cne 'upgrade' -or $PreviousSetupSHA256 -notmatch '\A[a-fA-F0-9]{64}\z' -or
        $PreviousPublisherSHA256 -notmatch '\A[a-fA-F0-9]{64}\z' -or $PreviousSetupSHA256 -ieq $SetupSHA256){
        throw 'Downgrade qualification requires a distinct approved older setup and publisher identity'
    }
    return $true
}
function Assert-RebootUpgradeOrder($Comparison,[string]$PreviousVersion,[string]$Version){
    if($Comparison.currentVersion -cne $PreviousVersion -or $Comparison.version -cne $Version -or
        $Comparison.updateAvailable -isnot [bool] -or -not $Comparison.updateAvailable){
        throw 'The approved candidate is not newer than the installed baseline'
    }
}
function Assert-RebootIdentity($Record,$Expected){
    if(($Record.schemaVersion -isnot [int] -and $Record.schemaVersion -isnot [long]) -or $Record.schemaVersion -ne 11 -or
       $Record.runID -cne $Expected.runID -or $Record.architecture -cne $Expected.architecture -or
       $Record.installMode -cne $Expected.installMode -or $Record.previousVersion -cne $Expected.previousVersion -or
       $Record.previousPayloadSHA256 -cne $Expected.previousPayloadSHA256 -or
       $Record.previousPayloadSBOMSHA256 -cne $Expected.previousPayloadSBOMSHA256 -or
       $Record.previousPayloadPublisherSHA256 -cne $Expected.previousPayloadPublisherSHA256 -or
       $Record.previousBuildInfoSHA256 -isnot [string] -or
       $Record.previousBuildInfoSHA256 -cne $Expected.previousBuildInfoSHA256 -or
       ($Expected.installMode -ceq 'upgrade' -and $Record.previousBuildInfoSHA256 -cnotmatch '\A[a-f0-9]{64}\z') -or
       ($Expected.installMode -ceq 'clean' -and $Record.previousBuildInfoSHA256 -cne '') -or
       $Record.previousPayloadTrustVerified -isnot [bool] -or
       $Record.previousPayloadTrustVerified -ne ($Expected.installMode -ceq 'upgrade') -or
       $Record.previousSetupSHA256 -cne $Expected.previousSetupSHA256 -or
       $Record.previousPublisherSHA256 -cne $Expected.previousPublisherSHA256 -or
       $Record.userProfilePreservedThroughUpgrade -isnot [bool] -or
       $Record.userProfilePreservedThroughUpgrade -ne ($Expected.installMode -ceq 'upgrade') -or
       $Record.version -cne $Expected.version -or $Record.setupSHA256 -cne $Expected.setupSHA256 -or
       $Record.payloadSHA256 -cne $Expected.payloadSHA256 -or $Record.publisherSHA256 -cne $Expected.publisherSHA256 -or
       $Record.payloadSBOMSHA256 -cne $Expected.payloadSBOMSHA256 -or
       $Record.buildInfoSHA256 -isnot [string] -or $Record.buildInfoSHA256 -cnotmatch '\A[a-f0-9]{64}\z' -or
       $Record.buildInfoSHA256 -cne $Expected.buildInfoSHA256 -or
       $Record.payloadPublisherSHA256 -cne $Expected.payloadPublisherSHA256 -or
       $Record.guestID -cne $Expected.guestID -or $Record.userSID -cne $Expected.userSID -or
       $Record.detectorSHA256 -cne $Expected.detectorSHA256 -or $Record.fixtureSHA256 -cne $Expected.fixtureSHA256 -or
       $Record.commonSHA256 -cne $Expected.commonSHA256 -or $Record.publisherVerifierSHA256 -cne $Expected.publisherVerifierSHA256 -or
       $Record.uninstallerSHA256 -isnot [string] -or $Record.uninstallerSHA256 -cnotmatch '\A[a-f0-9]{64}\z' -or
       ($Record.setupExitCode -isnot [int] -and $Record.setupExitCode -isnot [long]) -or $Record.setupExitCode -notin @(0,3010) -or
       $Record.installedTreeSHA256 -isnot [string] -or $Record.installedTreeSHA256 -cnotmatch '\A[a-f0-9]{64}\z' -or
       $Record.registrationSHA256 -isnot [string] -or $Record.registrationSHA256 -cnotmatch '\A[a-f0-9]{64}\z' -or
       $Record.userProfileSHA256 -isnot [string] -or $Record.userProfileSHA256 -cnotmatch '\A[a-f0-9]{64}\z'){
        throw 'The independently approved candidate differs from the prepared reboot run'
    }
}
function Assert-RebootPath([string]$Path){
    $root=[IO.Path]::GetPathRoot($Path)
    $current=$root
    foreach($component in $Path.Substring($root.Length).Split('\')){
        $current=[IO.Path]::Combine($current,$component)
        $entry=Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reboot fixture path includes an alias'}
    }
}
function Get-RebootDigest([string]$Path,[switch]$AllowEmpty){
    Assert-RebootPath $Path
    $entry=Get-Item -LiteralPath $Path -Force
    if($entry.PSIsContainer){throw 'Expected an ordinary fixture file'}
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if(($file.Length -eq 0 -and -not $AllowEmpty) -or $file.Length -gt 512MB){throw 'Fixture file is outside the verification size limit'}
        return (Get-FileHash -InputStream $file -Algorithm SHA256).Hash.ToLowerInvariant()
    } finally {$file.Dispose()}
}
function Get-RebootMetadataDigest($Value){
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $Value -Depth 6 -Compress))
    $hash=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}
    finally {$hash.Dispose()}
}
function Get-RebootInstalledTreeDigest([string]$Directory){
    Assert-RebootPath $Directory
    $pending=[Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($Directory)
    $records=[Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    $total=0L
    while($pending.Count){
        $parent=$pending.Dequeue()
        foreach($path in [IO.Directory]::EnumerateFileSystemEntries($parent)){
            if($records.Count -ge 4096){throw 'Installed package contains too many entries'}
            $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Installed package contains an alias'}
            $relative=$path.Substring($Directory.Length+1)
            if($item.PSIsContainer){
                $records.Add($relative,[ordered]@{path=$relative;kind='directory'})
                $pending.Enqueue($path)
            }else{
                $total+=$item.Length
                if($total -gt 512MB){throw 'Installed package exceeds the fingerprint budget'}
                $records.Add($relative,[ordered]@{path=$relative;kind='file';size=$item.Length;sha256=(Get-RebootDigest $path -AllowEmpty)})
            }
        }
    }
    if(-not $records.Count){throw 'Installed package is empty'}
    return Get-RebootMetadataDigest @($records.Values)
}
function Get-RebootRegistrationFingerprint($Key){
    if($null -eq $Key -or $Key.SubKeyCount -ne 0 -or $Key.ValueCount -le 0 -or $Key.ValueCount -gt 256){
        throw 'Installed machine registration is missing or outside the fixture bounds'
    }
    $names=$Key.GetValueNames()
    if($names.Count -ne $Key.ValueCount){throw 'Machine registration changed during inspection'}
    [Array]::Sort($names,[StringComparer]::Ordinal)
    $records=foreach($name in $names){
        $kind=$Key.GetValueKind($name)
        $value=$Key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if($null -eq $value){throw 'Machine registration changed during inspection'}
        [ordered]@{name=$name;kind=$kind.ToString();value=$value}
    }
    return Get-RebootMetadataDigest @($records)
}
function Get-RebootRegistrationDigest {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey($registrationKey,$false)
        return Get-RebootRegistrationFingerprint $key
    } finally {
        if($null -ne $key){$key.Dispose()}
        $base.Dispose()
    }
}
function Assert-RebootInstalledState($Saved,[string]$TreeSHA256,[string]$RegistrationSHA256){
    if($Saved.installedTreeSHA256 -cne $TreeSHA256){throw 'Installed package tree changed across reboot'}
    if($Saved.registrationSHA256 -cne $RegistrationSHA256){throw 'Machine registration changed across reboot'}
}
function Assert-RebootPackageRemoved([string]$Directory){
    if(-not (Test-Path -LiteralPath $Directory -ErrorAction Stop)){return}
    Assert-RebootPath $Directory
    $entries=[IO.Directory]::EnumerateFileSystemEntries($Directory).GetEnumerator()
    try {
        if($entries.MoveNext()){throw 'Installed package files remain after uninstall'}
    } finally {$entries.Dispose()}
}
function Get-GuestBoot {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if(@($os).Count -ne 1 -or $os.LastBootUpTime -isnot [datetime]){throw 'Cannot establish the current guest boot'}
    return $os.LastBootUpTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
}
function Invoke-ApprovedInstaller([string]$Path,[string[]]$Arguments,[switch]$AllowRestartRequired,[int]$ExpectedExitCode=0,[string]$OutputPath,
    [string]$ApprovedSHA256,[string]$ApprovedPublisherSHA256){
    if($AllowRestartRequired -and $ExpectedExitCode -ne 0){throw 'Conflicting installer exit expectations'}
    $capture=@{}
    if($OutputPath){
        if(Test-Path -LiteralPath $OutputPath -ErrorAction Stop){throw 'Fixture output path already exists'}
        $capture.RedirectStandardOutput=$OutputPath
    }
    if([bool]$ApprovedSHA256 -ne [bool]$ApprovedPublisherSHA256){throw 'Both artifact and publisher digests are required'}
    $guard=$null
    try {
        if($ApprovedSHA256){
            Assert-RebootPath $Path
            $guard=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $null=@(& $publisher -Artifact $Path -ArtifactSHA256 $ApprovedSHA256 -PublisherCertificateSHA256 $ApprovedPublisherSHA256)
            if($LASTEXITCODE -ne 0){throw 'Installer publisher verification failed'}
        }
        $process=Start-Process -FilePath $Path -ArgumentList $Arguments -WindowStyle Hidden -PassThru @capture
    } finally {
        # Keep verified bytes bound through process creation. Release the read
        # handle before waiting so the uninstaller can remove its own files.
        if($null -ne $guard){$guard.Dispose()}
    }
    try {
        if(-not $process.WaitForExit(180000)){
            # Retain the process and its installer guard through the actual exit.
            $process.WaitForExit()
            throw 'Installer exceeded the guest fixture deadline'
        }
        $code=$process.ExitCode
        if($code -ne $ExpectedExitCode -and (-not $AllowRestartRequired -or $code -ne 3010)){
            throw 'Installer did not complete successfully'
        }
        return $code
    } finally {$process.Dispose()}
}
function Assert-RebootDowngradeLog([string]$Path){
    Assert-RebootPath $Path
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 1MB){throw 'Downgrade log exceeds fixture bounds'}
        $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,4096,$true)
        try {
            $marker='A newer AccessWeaver version is installed. Use a current or newer installer. This installer will not downgrade it.'
            while($null -ne ($line=$reader.ReadLine())){
                if($line -cmatch ('\A(?:[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?[ \t]+)?'+[regex]::Escape($marker)+'\s*\z')){return}
            }
        } finally {$reader.Dispose()}
    } finally {$stream.Dispose()}
    throw 'The older installer did not report the version-policy refusal'
}
function Save-RebootFixtureProfile([string]$Controller,[string]$UserStore,[string]$InputPath,[string]$ProfileID){
    $profile=[ordered]@{version=1;id=$ProfileID;name='Installer reboot preservation fixture';engine='byedpi';args=@()
        routing=@{includeDomains=@();excludeDomains=@();applications=@()}
        probe=@{host='example.invalid';port=443;tls=$true;timeoutSeconds=5}}
    Write-NewRebootEvidence $InputPath $profile
    $previousHome=$env:ACCESSWEAVER_HOME
    try {
        $env:ACCESSWEAVER_HOME=$UserStore
        [void](Invoke-ApprovedInstaller $Controller @('import',('"'+$InputPath+'"')))
    } finally {$env:ACCESSWEAVER_HOME=$previousHome}
}
function Assert-RebootUserProfile([string]$Path,[string]$Digest){
    if((Get-RebootDigest $Path) -cne $Digest){throw 'Saved user profile changed during installer lifecycle'}
}
function Assert-RebootProfileReadable([string]$Controller,[string]$ControllerSHA256,[string]$UserStore,[string]$ProfileID,[string]$OutputPath){
    Assert-RebootPath $Controller
    $previousHome=$env:ACCESSWEAVER_HOME
    $guard=[IO.File]::Open($Controller,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if((Get-FileHash -InputStream $guard -Algorithm SHA256).Hash -ine $ControllerSHA256){
            throw 'Installed controller differs from the approved payload'
        }
        $env:ACCESSWEAVER_HOME=$UserStore
        [void](Invoke-ApprovedInstaller $Controller @('show',$ProfileID) -OutputPath $OutputPath)
        Assert-RebootPath $OutputPath
        $stream=[IO.File]::Open($OutputPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if($stream.Length -le 0 -or $stream.Length -gt 8192){throw 'Saved profile readback is outside the fixture bounds'}
            $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$false,1024,$true)
            try {$record=ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop}
            finally {$reader.Dispose()}
        } finally {$stream.Dispose()}
        if($record -isnot [pscustomobject] -or $record.id -cne $ProfileID -or
           $record.name -cne 'Installer reboot preservation fixture' -or $record.engine -cne 'byedpi' -or $record.version -ne 1){
            throw 'Installed controller did not read the saved fixture profile'
        }
    } finally {
        $env:ACCESSWEAVER_HOME=$previousHome
        $guard.Dispose()
    }
}
function Assert-InstalledDetection([bool]$Detected,[string]$CandidateVersion=$Version,[string]$CandidateSHA256=$PayloadSHA256,[string]$UninstallerDigest='',[string]$CandidateSBOMSHA256=$PayloadSBOMSHA256,
        [string]$CandidateBuildInfoSHA256=$BuildInfoSHA256){
    $output=@(& $detector -Version $CandidateVersion -Architecture $Architecture -PayloadSHA256 $CandidateSHA256 -UninstallerSHA256 $UninstallerDigest -PayloadSBOMSHA256 $CandidateSBOMSHA256 -BuildInfoSHA256 $CandidateBuildInfoSHA256 2>&1)
    if($LASTEXITCODE -ne 0){throw 'Installed candidate detection could not complete'}
    if($Detected){
        if($output.Count -ne 1 -or $output[0] -cne 'AccessWeaver detected'){throw 'Approved installed payload was not detected'}
    } elseif($output.Count -ne 0){throw 'Unexpected approved installation already exists'}
}
function Assert-InstalledPublisher([string]$ArtifactSHA256=$PayloadSHA256,[string]$PublisherSHA256=$PayloadPublisherCertificateSHA256) {
    $null=@(& $publisher -Artifact $controller -ArtifactSHA256 $ArtifactSHA256 -PublisherCertificateSHA256 $PublisherSHA256)
    if($LASTEXITCODE -ne 0){throw 'Installed payload publisher verification failed'}
}
function Assert-RegistrationAbsent {
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        $registration=$null
        try {
            $registration=$base.OpenSubKey($registrationKey,$false)
            if($null -ne $registration){throw 'An AccessWeaver machine registration already exists'}
        } finally {
            if($null -ne $registration){$registration.Dispose()}
            $base.Dispose()
        }
    }
}

if($env:OS -cne 'Windows_NT' -or $Architecture -cnotin @('amd64','arm64') -or
   [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne @{amd64='X64';arm64='Arm64'}[$Architecture] -or
   -not [Environment]::Is64BitProcess -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VMware'){
    throw 'A matching native VMware guest is required'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if($identity.IsSystem -or -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'An elevated disposable guest token is required'
    }
    $userSID=$identity.User.Value
} finally {$identity.Dispose()}
$userAppData=[Environment]::GetFolderPath('ApplicationData')
if(-not [IO.Path]::IsPathRooted($userAppData)){throw 'Expected a local disposable guest user profile'}
Assert-RebootPath $userAppData
$userStore=Join-Path $userAppData 'AccessWeaver'
$profileID='installer-reboot-'+$RunID
$userProfile=Join-Path $userStore ('profiles\'+$profileID+'.json')
$programFiles=[Environment]::GetFolderPath('ProgramFiles')
$tools=Join-Path $programFiles 'VMware\VMware Tools\vmtoolsd.exe'
Assert-RebootPath $tools
$marker=@(& $tools --cmd 'info-get guestinfo.accessweaverParity' 2>$null)
if($LASTEXITCODE -ne 0 -or ($marker -join '').Trim() -cne 'AccessWeaver-Clean-Windows-Test'){
    throw 'The disposable VMware identity does not match'
}

$guestInfo=Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
$guestUUID=[guid]::Empty
if(@($guestInfo).Count -ne 1 -or -not [guid]::TryParseExact([string]$guestInfo.UUID,'D',[ref]$guestUUID) -or
   $guestUUID -eq [guid]::Empty -or $guestUUID.ToString('D') -ceq 'ffffffff-ffff-ffff-ffff-ffffffffffff'){
    throw 'Cannot bind the reboot fixture to this guest'
}
$common=Join-Path $PSScriptRoot 'windows-installer-common.ps1'
Assert-RebootPath $common
. $common
Assert-InstallerReleaseVersion $Version
$installMode=Get-RebootInstallMode $Version $PayloadSHA256 $PreviousVersion $PreviousPayloadSHA256 $PreviousPayloadSBOMSHA256 $PreviousPayloadPublisherCertificateSHA256
if(($installMode -ceq 'upgrade') -ne [bool]$PreviousBuildInfoSHA256){
    throw 'Upgrade qualification requires an approved prior build metadata digest'
}
if($installMode -ceq 'upgrade'){Assert-InstallerReleaseVersion $PreviousVersion}
$testDowngrade=Test-RebootDowngradeInputs $installMode $SetupSHA256 $PreviousSetupSHA256 $PreviousPublisherCertificateSHA256
$setup=Join-Path $PSScriptRoot 'setup.exe'
$detector=Join-Path $PSScriptRoot 'detect-windows-installer.ps1'
$publisher=Join-Path $PSScriptRoot 'verify-windows-installer-publisher.ps1'
$install=Join-Path $programFiles 'AccessWeaver'
$controller=Join-Path $install 'accessweaver.exe'
$uninstaller=Join-Path $install 'unins000.exe'
$registrationKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1'
$capsule=Join-Path $programFiles ('AccessWeaver reboot fixture '+$RunID)
$baseline=Join-Path $capsule 'prepared.json'
$report=Join-Path $capsule 'result.json'
if(-not $PayloadPublisherCertificateSHA256){$PayloadPublisherCertificateSHA256=$PublisherCertificateSHA256}
$expected=[ordered]@{schemaVersion=11;runID=$RunID;architecture=$Architecture;version=$Version;installMode=$installMode;
    previousVersion=$PreviousVersion;previousPayloadSHA256=$PreviousPayloadSHA256.ToLowerInvariant();
    previousPayloadSBOMSHA256=$PreviousPayloadSBOMSHA256.ToLowerInvariant();
    previousBuildInfoSHA256=$PreviousBuildInfoSHA256.ToLowerInvariant();
    previousPayloadPublisherSHA256=$PreviousPayloadPublisherCertificateSHA256.ToLowerInvariant();previousPayloadTrustVerified=$false;
    previousSetupSHA256=$PreviousSetupSHA256.ToLowerInvariant();previousPublisherSHA256=$PreviousPublisherCertificateSHA256.ToLowerInvariant();
    userProfilePreservedThroughUpgrade=$false;
    setupSHA256=$SetupSHA256.ToLowerInvariant();payloadSHA256=$PayloadSHA256.ToLowerInvariant();
    payloadSBOMSHA256=$PayloadSBOMSHA256.ToLowerInvariant();buildInfoSHA256=$BuildInfoSHA256.ToLowerInvariant();guestID=$guestUUID.ToString('D');
    publisherSHA256=$PublisherCertificateSHA256.ToLowerInvariant();
    payloadPublisherSHA256=$PayloadPublisherCertificateSHA256.ToLowerInvariant();userSID=$userSID;
    detectorSHA256=(Get-RebootDigest $detector);fixtureSHA256=(Get-RebootDigest $PSCommandPath);
    commonSHA256=(Get-RebootDigest $common);publisherVerifierSHA256=(Get-RebootDigest $publisher)}
$boot=Get-GuestBoot

if($Phase -ceq 'Prepare'){
    if($installMode -ceq 'clean'){
        Assert-RegistrationAbsent
        if(Test-Path -LiteralPath $install){throw 'Clean qualification requires an unused installation directory'}
    }
    $managed=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AccessWeaver'
    if((Test-Path -LiteralPath $capsule) -or (Test-Path -LiteralPath $userStore) -or
       (Test-Path -LiteralPath $managed) -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\AccessWeaver') -or
       @(Get-Service -Name 'AccessWeaver-*' -ErrorAction SilentlyContinue).Count){
        throw 'The reboot fixture requires an unused guest and run identifier'
    }
    Assert-RebootPath $programFiles
    [void][IO.Directory]::CreateDirectory($capsule)
    $pending=Join-Path $capsule 'started.json'
    Write-NewRebootEvidence $pending $expected
    $stage='publisher'
    try {
        $profileInput=Join-Path $capsule 'profile-input.json'
        if($installMode -ceq 'upgrade'){
            $stage='previous-installation'
            Assert-RebootPath $controller
            $guard=[IO.File]::Open($controller,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try {
                Assert-InstalledDetection $true $PreviousVersion $PreviousPayloadSHA256 -CandidateSBOMSHA256 $PreviousPayloadSBOMSHA256 -CandidateBuildInfoSHA256 $PreviousBuildInfoSHA256
                Assert-InstalledPublisher $PreviousPayloadSHA256 $PreviousPayloadPublisherCertificateSHA256
                $expected.previousPayloadTrustVerified=$true
                $comparison=@(& $controller system check-version $Version 2>$null) -join ""
                if($LASTEXITCODE -ne 0 -or $comparison.Length -gt 4096){throw 'Previous controller could not compare release versions'}
                Assert-RebootUpgradeOrder (ConvertFrom-Json -InputObject $comparison -ErrorAction Stop) $PreviousVersion $Version
                $stage='user-profile-before-upgrade'
                Save-RebootFixtureProfile $controller $userStore $profileInput $profileID
                $expected.userProfileSHA256=Get-RebootDigest $userProfile
            } finally {$guard.Dispose()}
        }
        $stage='publisher'
        Assert-RebootPath $setup
        $setupGuard=[IO.File]::Open($setup,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $null=@(& $publisher -Artifact $setup -ArtifactSHA256 $SetupSHA256 -PublisherCertificateSHA256 $PublisherCertificateSHA256)
            if($LASTEXITCODE -ne 0){throw 'Setup publisher verification failed'}
            $stage='install'
            $expected.setupExitCode=Invoke-ApprovedInstaller $setup @('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/RESTARTEXITCODE=3010','/NOICONS') -AllowRestartRequired
        } finally {$setupGuard.Dispose()}
        $stage='installed-before-reboot'
        Assert-InstalledDetection $true
        Assert-InstalledPublisher
        $expected.boot=$boot
        $expected.uninstallerSHA256=Get-RebootDigest $uninstaller
        $null=@(& $publisher -Artifact $uninstaller -ArtifactSHA256 $expected.uninstallerSHA256 -PublisherCertificateSHA256 $PublisherCertificateSHA256)
        if($LASTEXITCODE -ne 0){throw 'Installed uninstaller publisher verification failed'}
        Assert-InstalledDetection $true -UninstallerDigest $expected.uninstallerSHA256
        $expected.installedTreeSHA256=Get-RebootInstalledTreeDigest $install
        $expected.registrationSHA256=Get-RebootRegistrationDigest
        if($installMode -ceq 'upgrade'){
            $stage='user-profile-after-upgrade'
            Assert-RebootUserProfile $userProfile $expected.userProfileSHA256
            $expected.userProfilePreservedThroughUpgrade=$true
        }else{
            $stage='user-profile-prepare'
            Save-RebootFixtureProfile $controller $userStore $profileInput $profileID
            $expected.userProfileSHA256=Get-RebootDigest $userProfile
        }
        Write-NewRebootEvidence $baseline $expected
    } catch {
        Write-NewRebootEvidence $report @{schemaVersion=11;runID=$RunID;stage=$stage;passed=$false}
        throw 'Windows installer reboot preparation failed. Retain the disposable guest for review.'
    }
    Write-Output 'Prepared the approved installation. Reboot the disposable guest before verification.'
    return
}

Assert-RebootPath $baseline
if((Get-Item -LiteralPath $baseline).Length -gt 8192 -or (Test-Path -LiteralPath $report)){throw 'The prepared run is invalid or already consumed'}
$saved=Get-Content -LiteralPath $baseline -Raw|ConvertFrom-Json
Assert-RebootIdentity $saved $expected
Assert-LaterGuestBoot $saved.boot $boot
Write-NewRebootEvidence (Join-Path $capsule 'verification-started.json') @{schemaVersion=11;runID=$RunID}
$result=[ordered]@{schemaVersion=11;runID=$RunID;architecture=$Architecture;version=$Version;installMode=$installMode;
    previousVersion=$expected.previousVersion;previousPayloadSHA256=$expected.previousPayloadSHA256;
    previousPayloadSBOMSHA256=$expected.previousPayloadSBOMSHA256;previousPayloadPublisherSHA256=$expected.previousPayloadPublisherSHA256;
    previousBuildInfoSHA256=$expected.previousBuildInfoSHA256;
    previousPayloadTrustVerified=$saved.previousPayloadTrustVerified;
    previousSetupSHA256=$expected.previousSetupSHA256;previousPublisherSHA256=$expected.previousPublisherSHA256;
    downgradeRequested=$testDowngrade;downgradeRefused=$false;downgradeStatePreserved=$false;
    userProfilePreservedThroughUpgrade=$saved.userProfilePreservedThroughUpgrade;
    setupSHA256=$expected.setupSHA256;payloadSHA256=$expected.payloadSHA256;publisherSHA256=$expected.publisherSHA256;
    payloadPublisherSHA256=$expected.payloadPublisherSHA256;
    payloadSBOMSHA256=$expected.payloadSBOMSHA256;installedPayloadSBOMVerified=$false;installedPayloadPublisherVerified=$false;
    buildInfoSHA256=$expected.buildInfoSHA256;installedBuildInfoVerified=$false;
    detectorSHA256=$expected.detectorSHA256;fixtureSHA256=$expected.fixtureSHA256;
    commonSHA256=$expected.commonSHA256;publisherVerifierSHA256=$expected.publisherVerifierSHA256;
    uninstallerSHA256=$saved.uninstallerSHA256;installedTreeSHA256=$saved.installedTreeSHA256;registrationSHA256=$saved.registrationSHA256;
    installedTreeVerified=$false;registrationPreserved=$false;packageFilesRemoved=$false;
    userProfileVerifiedAfterReboot=$false;userProfileOpenedByInstalledController=$false;userProfilePreservedAfterUninstall=$false;setupExitCode=$saved.setupExitCode;setupRequestedRestart=($saved.setupExitCode -eq 3010);
    guestRebootVerified=$true;installedPayloadVerifiedBeforeRestart=$true;installedPayloadVerified=$false;uninstallerIdentityVerified=$false;
    registrationRemoved=$false;passed=$false;stage='installed-after-reboot'}
try {
    Assert-InstalledDetection $true -UninstallerDigest $saved.uninstallerSHA256
    $result.installedPayloadVerified=$true
    $result.installedPayloadSBOMVerified=$true
    $result.installedBuildInfoVerified=$true
    $result.stage='installed-publisher'
    Assert-InstalledPublisher
    $result.installedPayloadPublisherVerified=$true
    $result.stage='installed-state'
    Assert-RebootInstalledState $saved (Get-RebootInstalledTreeDigest $install) (Get-RebootRegistrationDigest)
    $result.installedTreeVerified=$true
    $result.registrationPreserved=$true
    $result.stage='user-profile-after-reboot'
    Assert-RebootUserProfile $userProfile $saved.userProfileSHA256
    $result.userProfileVerifiedAfterReboot=$true
    $result.stage='installed-controller-profile-read'
    Assert-RebootProfileReadable $controller $PayloadSHA256 $userStore $profileID (Join-Path $capsule 'profile-readback.json')
    Assert-RebootUserProfile $userProfile $saved.userProfileSHA256
    $result.userProfileOpenedByInstalledController=$true
    if($testDowngrade){
        $result.stage='downgrade-publisher'
        $olderSetup=Join-Path $PSScriptRoot 'previous-setup.exe'
        Assert-RebootPath $olderSetup
        $downgradeLog=Join-Path $capsule 'downgrade.log'
        if(Test-Path -LiteralPath $downgradeLog -ErrorAction Stop){throw 'Downgrade log already exists'}
        $olderGuard=[IO.File]::Open($olderSetup,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $null=@(& $publisher -Artifact $olderSetup -ArtifactSHA256 $PreviousSetupSHA256 -PublisherCertificateSHA256 $PreviousPublisherCertificateSHA256)
            if($LASTEXITCODE -ne 0){throw 'Older setup publisher verification failed'}
            $result.stage='downgrade-refusal'
            [void](Invoke-ApprovedInstaller $olderSetup @('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOICONS',('/LOG="'+$downgradeLog+'"')) -ExpectedExitCode 1)
        } finally {$olderGuard.Dispose()}
        Assert-RebootDowngradeLog $downgradeLog
        $result.downgradeRefused=$true
        $result.stage='downgrade-readback'
        Assert-InstalledDetection $true -UninstallerDigest $saved.uninstallerSHA256
        Assert-RebootInstalledState $saved (Get-RebootInstalledTreeDigest $install) (Get-RebootRegistrationDigest)
        Assert-RebootUserProfile $userProfile $saved.userProfileSHA256
        $result.downgradeStatePreserved=$true
    }
    $result.stage='uninstall'
    [void](Invoke-ApprovedInstaller $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -ApprovedSHA256 $saved.uninstallerSHA256 -ApprovedPublisherSHA256 $PublisherCertificateSHA256)
    $result.uninstallerIdentityVerified=$true
    $result.stage='removal-readback'
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    while((Test-Path -LiteralPath $uninstaller) -and $deadline.Elapsed.TotalSeconds -lt 20){Start-Sleep -Milliseconds 200}
    Assert-InstalledDetection $false
    Assert-RegistrationAbsent
    $result.registrationRemoved=$true
    Assert-RebootPackageRemoved $install
    $result.packageFilesRemoved=$true
    $result.stage='user-profile-after-uninstall'
    Assert-RebootUserProfile $userProfile $saved.userProfileSHA256
    $result.userProfilePreservedAfterUninstall=$true
    $result.passed=$true
    $result.stage='complete'
} catch {
    throw 'Windows installer reboot verification failed. Retain the disposable guest for review.'
} finally {
    Write-NewRebootEvidence $report $result
}
$result | ConvertTo-Json -Compress
