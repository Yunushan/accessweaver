# Run inside the same clean disposable VMware guest before and after its external reboot.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Verify')][string]$Phase,
    [Parameter(Mandatory)][ValidatePattern('\A[a-f0-9]{32}\z')][string]$RunID,
    [Parameter(Mandatory)][ValidateSet('amd64','arm64')][string]$Architecture,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$SetupSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$PayloadSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$PublisherCertificateSHA256
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
    $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $file.Write($bytes,0,$bytes.Length)
        $file.Flush($true)
    } finally {$file.Dispose()}
}
function Assert-RebootIdentity($Record,$Expected){
    if(($Record.schemaVersion -isnot [int] -and $Record.schemaVersion -isnot [long]) -or $Record.schemaVersion -ne 1 -or
       $Record.runID -cne $Expected.runID -or $Record.architecture -cne $Expected.architecture -or
       $Record.version -cne $Expected.version -or $Record.setupSHA256 -cne $Expected.setupSHA256 -or
       $Record.payloadSHA256 -cne $Expected.payloadSHA256 -or $Record.publisherSHA256 -cne $Expected.publisherSHA256 -or
       $Record.guestID -cne $Expected.guestID -or
       $Record.detectorSHA256 -cne $Expected.detectorSHA256 -or $Record.fixtureSHA256 -cne $Expected.fixtureSHA256 -or
       $Record.commonSHA256 -cne $Expected.commonSHA256 -or $Record.publisherVerifierSHA256 -cne $Expected.publisherVerifierSHA256 -or
       $Record.uninstallerSHA256 -cnotmatch '\A[a-f0-9]{64}\z'){
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
function Get-RebootDigest([string]$Path){
    Assert-RebootPath $Path
    $entry=Get-Item -LiteralPath $Path -Force
    if($entry.PSIsContainer){throw 'Expected an ordinary fixture file'}
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($file.Length -le 0 -or $file.Length -gt 512MB){throw 'Fixture file is outside the verification size limit'}
        return (Get-FileHash -InputStream $file -Algorithm SHA256).Hash.ToLowerInvariant()
    } finally {$file.Dispose()}
}
function Get-GuestBoot {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if(@($os).Count -ne 1 -or $os.LastBootUpTime -isnot [datetime]){throw 'Cannot establish the current guest boot'}
    return $os.LastBootUpTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
}
function Invoke-ApprovedInstaller([string]$Path,[string[]]$Arguments){
    $result=Start-Process -FilePath $Path -ArgumentList $Arguments -WindowStyle Hidden -PassThru
    try {
        if(-not $result.WaitForExit(180000)){throw 'Installer exceeded the guest fixture deadline'}
        if($result.ExitCode -ne 0){throw 'Installer did not complete successfully'}
    } finally {$result.Dispose()}
}
function Assert-InstalledDetection([bool]$Detected){
    $output=@(& $detector -Version $Version -Architecture $Architecture -PayloadSHA256 $PayloadSHA256 2>&1)
    if($LASTEXITCODE -ne 0){throw 'Installed candidate detection could not complete'}
    if($Detected){
        if($output.Count -ne 1 -or $output[0] -cne 'AccessWeaver detected'){throw 'Approved installed payload was not detected'}
    } elseif($output.Count -ne 0){throw 'Unexpected approved installation already exists'}
}
function Assert-RegistrationAbsent {
    $key='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1'
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        $registration=$null
        try {
            $registration=$base.OpenSubKey($key,$false)
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
    if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'An elevated disposable guest token is required'
    }
} finally {$identity.Dispose()}
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
$setup=Join-Path $PSScriptRoot 'setup.exe'
$detector=Join-Path $PSScriptRoot 'detect-windows-installer.ps1'
$publisher=Join-Path $PSScriptRoot 'verify-windows-installer-publisher.ps1'
$install=Join-Path $programFiles 'AccessWeaver'
$uninstaller=Join-Path $install 'unins000.exe'
$capsule=Join-Path $programFiles ('AccessWeaver reboot fixture '+$RunID)
$baseline=Join-Path $capsule 'prepared.json'
$report=Join-Path $capsule 'result.json'
$expected=[ordered]@{schemaVersion=1;runID=$RunID;architecture=$Architecture;version=$Version;
    setupSHA256=$SetupSHA256.ToLowerInvariant();payloadSHA256=$PayloadSHA256.ToLowerInvariant();guestID=$guestUUID.ToString('D');
    publisherSHA256=$PublisherCertificateSHA256.ToLowerInvariant();
    detectorSHA256=(Get-RebootDigest $detector);fixtureSHA256=(Get-RebootDigest $PSCommandPath);
    commonSHA256=(Get-RebootDigest $common);publisherVerifierSHA256=(Get-RebootDigest $publisher)}
$boot=Get-GuestBoot

if($Phase -ceq 'Prepare'){
    Assert-RegistrationAbsent
    $managed=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AccessWeaver'
    if((Test-Path -LiteralPath $capsule) -or (Test-Path -LiteralPath $install) -or
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
        Assert-RebootPath $setup
        $setupGuard=[IO.File]::Open($setup,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $null=@(& $publisher -Artifact $setup -ArtifactSHA256 $SetupSHA256 -PublisherCertificateSHA256 $PublisherCertificateSHA256)
            if($LASTEXITCODE -ne 0){throw 'Setup publisher verification failed'}
            $stage='install'
            Invoke-ApprovedInstaller $setup @('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/RESTARTEXITCODE=3010','/NOICONS')
        } finally {$setupGuard.Dispose()}
        $stage='installed-before-reboot'
        Assert-InstalledDetection $true
        $expected.boot=$boot
        $expected.uninstallerSHA256=Get-RebootDigest $uninstaller
        $null=@(& $publisher -Artifact $uninstaller -ArtifactSHA256 $expected.uninstallerSHA256 -PublisherCertificateSHA256 $PublisherCertificateSHA256)
        if($LASTEXITCODE -ne 0){throw 'Installed uninstaller publisher verification failed'}
        Write-NewRebootEvidence $baseline $expected
    } catch {
        Write-NewRebootEvidence $report @{schemaVersion=1;runID=$RunID;stage=$stage;passed=$false}
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
Write-NewRebootEvidence (Join-Path $capsule 'verification-started.json') @{schemaVersion=1;runID=$RunID}
$result=[ordered]@{schemaVersion=1;runID=$RunID;architecture=$Architecture;version=$Version;
    setupSHA256=$expected.setupSHA256;payloadSHA256=$expected.payloadSHA256;publisherSHA256=$expected.publisherSHA256;
    detectorSHA256=$expected.detectorSHA256;fixtureSHA256=$expected.fixtureSHA256;
    commonSHA256=$expected.commonSHA256;publisherVerifierSHA256=$expected.publisherVerifierSHA256;
    uninstallerSHA256=$saved.uninstallerSHA256;
    guestRebootVerified=$true;installedPayloadVerifiedBeforeRestart=$true;installedPayloadVerified=$false;uninstallerIdentityVerified=$false;
    registrationRemoved=$false;passed=$false;stage='installed-after-reboot'}
try {
    Assert-InstalledDetection $true
    $result.installedPayloadVerified=$true
    $result.stage='uninstaller-identity'
    if((Get-RebootDigest $uninstaller) -cne $saved.uninstallerSHA256){throw 'Installed uninstaller changed after preparation'}
    $null=@(& $publisher -Artifact $uninstaller -ArtifactSHA256 $saved.uninstallerSHA256 -PublisherCertificateSHA256 $PublisherCertificateSHA256)
    if($LASTEXITCODE -ne 0){throw 'Uninstaller publisher verification failed'}
    $result.uninstallerIdentityVerified=$true
    $result.stage='uninstall'
    Invoke-ApprovedInstaller $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
    $result.stage='removal-readback'
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    while((Test-Path -LiteralPath $uninstaller) -and $deadline.Elapsed.TotalSeconds -lt 20){Start-Sleep -Milliseconds 200}
    Assert-InstalledDetection $false
    Assert-RegistrationAbsent
    if((Test-Path -LiteralPath (Join-Path $install 'accessweaver.exe')) -or (Test-Path -LiteralPath $uninstaller)){
        throw 'Owned installed executable remains after uninstall'
    }
    $result.registrationRemoved=$true
    $result.passed=$true
    $result.stage='complete'
} catch {
    throw 'Windows installer reboot verification failed. Retain the disposable guest for review.'
} finally {
    Write-NewRebootEvidence $report $result
}
$result | ConvertTo-Json -Compress
