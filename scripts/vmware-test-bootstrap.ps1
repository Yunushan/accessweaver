# Run manually as Administrator inside AccessWeaver-Clean-Windows-Test only.
# The control file selects fixed test stages; it never supplies shell commands.
$ErrorActionPreference='Stop'
$share='\\vmware-host\Shared Folders\AccessWeaver-Test'
$outputShare='\\vmware-host\Shared Folders\AccessWeaver-Results'
$local='C:\AccessWeaver-Test';$results='C:\AccessWeaver-Results'
$taskName='AccessWeaver-Parity-Reboot-Verify'
$tools=Join-Path $env:ProgramFiles 'VMware\VMware Tools\vmtoolsd.exe'
if(-not (Test-Path $tools)){throw 'VMware Tools must be installed inside the disposable test VM'}
$marker=& $tools --cmd 'info-get guestinfo.accessweaverParity'
if($LASTEXITCODE -ne 0 -or ($marker -join '').Trim() -ne 'AccessWeaver-Clean-Windows-Test'){throw 'VM identity marker does not match the disposable AccessWeaver test VM'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this test launcher as Administrator inside the guest'}
[void](New-Item -ItemType Directory -Force -Path $local,$results,$outputShare)
$env:ACCESSWEAVER_TEST_VM='1';$env:ACCESSWEAVER_HOME='C:\AccessWeaver-Test-State'
$status=@{state='ready';stage='';id='';computer=$env:COMPUTERNAME;user=$env:USERNAME;startedAt=[DateTime]::UtcNow.ToString('o')}
function Publish-TestStatus {
    $status.updatedAt=[DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $outputShare 'controller.json'),($status|ConvertTo-Json -Depth 8))
}
function Copy-TestTree([string]$source,[string]$destination) {
    [void](New-Item -ItemType Directory -Force -Path $destination)
    & robocopy.exe $source $destination /E /R:2 /W:1 /NFL /NDL /NJH /NJS | Out-Null
    if($LASTEXITCODE -gt 7){throw ('Test file copy failed: '+$LASTEXITCODE)}
}
function Read-ApprovedDNSRebootResume {
    [CmdletBinding()]
    param([string]$Path,[string]$ExpectedSHA256)
    $ErrorActionPreference='Stop'
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'DNS startup verifier must be an ordinary file'
    }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $length=$stream.Length
        if($length -le 0 -or $length -gt 1MB){throw 'DNS startup verifier has an invalid size'}
        $reader=[IO.BinaryReader]::new($stream,[Text.Encoding]::UTF8,$true)
        try {$data=$reader.ReadBytes([int]$length)} finally {$reader.Dispose()}
        if($data.Length -ne $length -or $stream.ReadByte() -ne -1){
            throw 'DNS startup verifier changed during read'
        }
        $sha256=[Security.Cryptography.SHA256]::Create()
        try {$observed=[BitConverter]::ToString($sha256.ComputeHash($data)).Replace('-','')} finally {$sha256.Dispose()}
        if($observed -ine $ExpectedSHA256){throw 'DNS startup verifier differs from the approved source'}
        $source=[Text.UTF8Encoding]::new($false,$true).GetString($data).TrimStart([char]0xFEFF)
        return [scriptblock]::Create($source)
    } finally {$stream.Dispose()}
}
function New-DNSRebootStartupArguments {
    [CmdletBinding()]
    param(
        [string]$ResumePath,
        [ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$ResumeSHA256,
        [ValidatePattern('\Aaccessweaver[a-zA-Z0-9-]*\.exe\z')][string]$ExecutableName,
        [ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$ExecutableSHA256,
        [ValidatePattern('\A[0-9a-f]{32}\z')][string]$QualificationID,
        [ValidateSet('doh','dnscrypt')][string]$DNS,
        [ValidateSet('any','dhcp-ipv4','static-ipv4','dhcp-ipv6','static-ipv6')][string]$RequiredOriginalMode,
        [ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$FixtureSHA256,
        [ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string]$OracleSHA256
    )
    $quotedPath=$ResumePath.Replace("'","''")
    $reader=(Get-Command Read-ApprovedDNSRebootResume -CommandType Function -ErrorAction Stop).Definition
    $command=@"
`$ErrorActionPreference='Stop'
`$startup = & {
$reader
} '$quotedPath' '$ResumeSHA256'
& `$startup -ExecutableName '$ExecutableName' -ExecutableSHA256 '$ExecutableSHA256' -QualificationID '$QualificationID' -DNS '$DNS' -RequiredOriginalMode '$RequiredOriginalMode' -FixtureSHA256 '$FixtureSHA256' -OracleSHA256 '$OracleSHA256'
"@
    return ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command)))
}
function Copy-TestInputs([string]$executable,[switch]$DnsReboot) {
    if($executable -notmatch '^accessweaver[a-zA-Z0-9-]*\.exe$'){throw 'Unsupported controller filename'}
    $required=@($executable,'dns-acceptance-state.ps1')
    if($DnsReboot){$required+=@('test-windows-reboot.ps1','vmware-reboot-resume.ps1')}
    foreach($name in $required){
        $item=Get-Item -LiteralPath (Join-Path $share $name) -Force -ErrorAction Stop
        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
            throw 'Required test input must be an ordinary file'
        }
        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $local $name) -Force -ErrorAction Stop
    }
    foreach($name in @('setup.exe','wgpeer.exe','probe-selected.exe','probe-direct.exe','test-windows-integration.ps1','test-windows-apps.ps1','test-windows-wiresock.ps1','test-windows-reboot.ps1','vmware-reboot-resume.ps1')){
        if($name -cin $required){continue}
        $source=Join-Path $share $name
        if(Test-Path -LiteralPath $source -PathType Leaf){Copy-Item -LiteralPath $source -Destination (Join-Path $local $name) -Force}
    }
    foreach($name in @('components','fixture-licenses')){$source=Join-Path $share $name;if(Test-Path $source){Copy-TestTree $source (Join-Path $local $name)}}
    if(-not (Test-Path (Join-Path $local $executable))){throw 'Test controller was not staged'}
}
function Publish-TestResults {Copy-TestTree $results $outputShare}
Publish-TestStatus
Write-Host 'Disposable VM test controller ready. Close this window to stop it. No passwords are collected.'
$deadline=[DateTime]::UtcNow.AddHours(2);$last=''
try{
    while([DateTime]::UtcNow -lt $deadline){
        $control=Join-Path $share 'control.json'
        if(-not (Test-Path $control)){Start-Sleep -Seconds 2;continue}
        try{$request=Get-Content -LiteralPath $control -Raw|ConvertFrom-Json}catch{Start-Sleep -Seconds 2;continue}
        if(-not $request.id -or $request.id -eq $last){Start-Sleep -Seconds 2;continue}
        if($request.id -notmatch '^[a-zA-Z0-9-]{1,64}$'){throw 'Invalid test-stage identifier'}
        $last=$request.id;$status.id=$last;$status.stage=$request.stage;$status.state='running';$status.Remove('error');Publish-TestStatus
        try{
            if($request.stage -eq 'exit'){break}
            if($request.stage -notin @('system','apps','wiresock','reboot-prepare')){throw 'Unknown test stage'}
            $executable=if($request.executable){[string]$request.executable}else{'accessweaver.exe'}
            $tasks=Get-ScheduledTask -ErrorAction Stop
            if($tasks | Where-Object {$_.TaskPath -eq '\' -and $_.TaskName -eq $taskName}){
                throw 'A pending DNS reboot verification still owns the staged test inputs'
            }
            Copy-TestInputs $executable -DnsReboot:($request.stage -ceq 'reboot-prepare')
            $binary=Join-Path $local $executable
            switch($request.stage){
                'system' {& (Join-Path $local 'test-windows-integration.ps1') -Executable $executable -Extended}
                'apps' {throw 'Application tests require an unelevated desktop window. Run test-windows-apps.ps1 -DisposableVM there and collect its LocalAppData\AccessWeaver-App-Test-Results separately.'}
                'wiresock' {& (Join-Path $local 'test-windows-wiresock.ps1') -Executable $binary -DisposableVM -RemoveVendor}
                'reboot-prepare' {
                    $digest=$request.executableSHA256
                    if($digest -isnot [string] -or $digest -cnotmatch '\A[A-Fa-f0-9]{64}\z'){
                        throw 'Expected an independently approved reboot controller SHA-256'
                    }
                    $fixtureDigest=$request.fixtureSHA256
                    $oracleDigest=$request.oracleSHA256
                    $resumeDigest=$request.resumeSHA256
                    foreach($scriptDigest in @($fixtureDigest,$oracleDigest,$resumeDigest)){
                        if($scriptDigest -isnot [string] -or $scriptDigest -cnotmatch '\A[A-Fa-f0-9]{64}\z'){
                            throw 'Expected independently approved DNS reboot fixture, oracle and startup verifier SHA-256 values'
                        }
                    }
                    $fixturePath=Join-Path $local 'test-windows-reboot.ps1'
                    $resumePath=Join-Path $local 'vmware-reboot-resume.ps1'
                    [void](Read-ApprovedDNSRebootResume $resumePath $resumeDigest)
                    $method=if($request.dns){[string]$request.dns}else{'auto'}
                    if($method -cnotin @('auto','doh','dnscrypt')){throw 'Unknown DNS reboot method'}
                    if($method -ceq 'auto'){$method=if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){'doh'}else{'dnscrypt'}}
                    $originalMode=if($null -eq $request.dnsOriginalMode){'any'}else{$request.dnsOriginalMode}
                    if($originalMode -isnot [string] -or $originalMode -notin @('any','dhcp-ipv4','static-ipv4','dhcp-ipv6','static-ipv6')){
                        throw 'Unknown DNS reboot original adapter mode'
                    }
                    $originalMode=$originalMode.ToLowerInvariant()
                    $qualificationID=[guid]::NewGuid().ToString('N')
                    $startupInputs=@{
                        ResumePath=$resumePath;ResumeSHA256=$resumeDigest;ExecutableName=$executable;ExecutableSHA256=$digest
                        QualificationID=$qualificationID;DNS=$method;RequiredOriginalMode=$originalMode
                        FixtureSHA256=$fixtureDigest;OracleSHA256=$oracleDigest
                    }
                    $arguments=New-DNSRebootStartupArguments @startupInputs
                    $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $arguments
                    $trigger=New-ScheduledTaskTrigger -AtStartup;$trigger.Delay='PT30S'
                    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval ([TimeSpan]::FromMinutes(1))
                    [void](Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop)
                    try {
                        $stream=[IO.File]::Open($fixturePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                        try {
                            if($stream.Length -le 0 -or $stream.Length -gt 1MB -or
                                (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash -ine $fixtureDigest){
                                throw 'Staged DNS reboot fixture differs from the approved source'
                            }
                            & $fixturePath -Phase Prepare -Executable $binary -ExecutableSHA256 $digest -DNS $method -RequiredOriginalMode $originalMode -QualificationID $qualificationID -FixtureSHA256 $fixtureDigest -OracleSHA256 $oracleDigest
                        } finally {$stream.Dispose()}
                    } catch {
                        $preparationFailure=$_
                        try {
                            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                        } catch {
                            throw [AggregateException]::new('DNS reboot preparation failed and the startup task could not be retired',
                                [Exception[]]@($preparationFailure.Exception,$_.Exception))
                        }
                        throw $preparationFailure
                    }
                    $status.qualificationID=$qualificationID
                }
            }
            $status.state='completed'
            if($request.stage -ne 'reboot-prepare'){Publish-TestResults}
        }catch{
            $status.state='failed';$status.error=$_.Exception.Message
            if($request.stage -ne 'reboot-prepare'){try{Publish-TestResults}catch{}}
        }
        Publish-TestStatus
        if($request.stage -eq 'reboot-prepare'){return}
    }
}finally{
    if($status.stage -ne 'reboot-prepare'){$status.state='stopped';Publish-TestStatus}
}
