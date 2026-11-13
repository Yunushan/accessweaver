[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver' -or $env:ACCESSWEAVER_NATIVE_WIRESOCK_CHECK -cne '1'){
    throw 'Disposable hosted Windows WireSock qualification required'
}
if([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant() -cne @{amd64='x64';arm64='arm64'}[$Architecture]){
    throw 'Native Windows architecture mismatch'
}
$project=Split-Path -Parent $PSScriptRoot
$source=$env:GITHUB_SHA
if($source -cnotmatch '^[a-f0-9]{40}$' -or (git -C $project rev-parse HEAD).Trim() -cne $source -or $LASTEXITCODE -ne 0){throw 'Source identity mismatch'}
if((git -C $project status --porcelain --untracked-files=no)){throw 'Tracked source must be clean'}
$paths=@('internal/workflow/windows.ps1','go.mod','go.sum','scripts/fixtures/wgpeer/go.mod','scripts/fixtures/wgpeer/go.sum','scripts/fixtures/wgpeer/main.go','scripts/fixtures/wgpeer/cmd/probe/main.go','scripts/test-windows-native-wiresock.ps1','.github/workflows/windows-native-wiresock.yml')
$hashes=@{}
foreach($path in $paths){$hashes[$path]=(Get-FileHash -LiteralPath (Join-Path $project $path) -Algorithm SHA256).Hash.ToLowerInvariant()}
$checks=[ordered]@{
    cleanVendorBaseline=$false;fixtureBuilt=$false;peerReady=$false;installCompleted=$false;restartRequested=$false
    selectedTCP4=$false;selectedUDP4=$false;selectedTCP6=$false;selectedUDP6=$false
    directBlocked=$false;peerHandshake=$false;disconnectCompleted=$false;disconnectedTrafficBlocked=$false
    managedRemovalCompleted=$false;vendorRemovalCompleted=$false;peerExited=$false;fixtureRemoved=$false
}
$workflowOutcomes=[ordered]@{install='not-run';disconnect='not-run';remove='not-run';'vendor-uninstall'='not-run'}
$connectionState='not-checked'
$vendorCLI=[ordered]@{profileList='not-checked';directStatus='not-checked'}
$stage='baseline'
$bin=Join-Path $env:RUNNER_TEMP ('accessweaver-wiresock-'+[guid]::NewGuid().ToString('N'))
$controller=Join-Path $bin 'accessweaver.exe'
$peerBinary=Join-Path $bin 'wgpeer.exe'
$selected=Join-Path $bin 'probe-selected.exe'
$direct=Join-Path $bin 'probe-direct.exe'
$state=Join-Path $bin 'peer'
$owned=Join-Path $env:ProgramData 'AccessWeaver\profiles\wiresock-owned.json'
$peer=$null
$attempted=$false
$binarySHA256=@{}
function Invoke-PrivateNative([string]$program,[string[]]$arguments){
    $old=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $lines=@(& $program @arguments 2>$null)
        return @{exitCode=$LASTEXITCODE;stdout=($lines -join [Environment]::NewLine)}
    } finally {$ErrorActionPreference=$old}
}
function Get-WorkflowOutcome($run,$job) {
    if($job.result.rebootRequired -eq $true){return 'restart-required'}
    if($run.exitCode -eq 0 -and $job.state -ceq 'succeeded'){return 'succeeded'}
    if($null -eq $job){return 'no-job-json'}
    if($null -eq $job.result){return 'no-worker-result'}
    if($job.result.reportingFailure){return 'worker-reporting-failed'}
    # Map source-known messages in memory. Never retain the worker's text,
    # paths, exit codes, vendor output or result payload in the public report.
    $workerError=[string]$job.result.error
    switch -CaseSensitive -Regex ($workerError) {
        '^Downloaded component SHA-256 mismatch$' {return 'download-hash-mismatch'}
        '^Installer publisher signature could not be verified$' {return 'download-publisher-refused'}
        '^WireSock installer publisher signature could not be verified$' {return 'installer-publisher-refused'}
        '^WireSock installation did not produce a CLI$' {return 'installed-cli-missing'}
        '^Tool failed: wiresock-setup\.exe \(exit -?[0-9]{1,10}\)$' {return 'installer-exit-failure'}
        '^Timed out: wiresock-setup\.exe$' {return 'installer-timeout'}
        '^Vendor service missing: (WireSockAppService|WireSockConnectService); finish installation/reboot before connecting$' {return 'vendor-service-missing'}
        '^Vendor service (is not ready for setup: (WireSockAppService|WireSockConnectService)|state changed during setup; retry when it is stable)$' {return 'vendor-service-not-ready'}
        '^Tool failed: (wiresock-connect-cli|wiresock-client)\.exe \(exit -?[0-9]{1,10}\)$' {return 'vendor-cli-exit-failure'}
        '^Timed out: (wiresock-connect-cli|wiresock-client)\.exe$' {return 'vendor-cli-timeout'}
        '^Invalid WireGuard configuration$' {return 'config-invalid'}
        '^Use a separately elevated system apply CLI for machine changes\.' {return 'worker-not-elevated'}
        '^No supported registered WireSock product found; use Windows Apps settings for an unrecognized package$' {return 'uninstall-registration-missing'}
        '^Registered vendor uninstaller is outside protected installation storage$' {return 'uninstaller-location-refused'}
        '^Multiple registered WireSock products matched; select the intended product in Windows Apps settings$' {return 'uninstall-registration-ambiguous'}
        '^Registered WireSock MSI uninstall command does not match its product code$' {return 'uninstaller-msi-product-refused'}
        '^Vendor uninstaller publisher signature could not be verified$' {return 'uninstaller-publisher-refused'}
        '^Vendor (CLI remains installed|uninstall registration remains); inspect vendor uninstall logs$' {return 'vendor-removal-unconfirmed'}
        default {return 'other-workflow-failure'}
    }
}
function Get-FixedConnectionState([string]$text){
    if([string]::IsNullOrWhiteSpace($text)){return 'empty'}
    $states=@([regex]::Matches($text,'(?<![A-Za-z])(NotConnected|Connecting|Connected|Disconnecting|Disconnected)(?![A-Za-z])') | ForEach-Object {$_.Value} | Sort-Object -Unique)
    if($states.Count -eq 1){return $states[0]}
    if($states.Count -gt 1){return 'ambiguous'}
    return 'unrecognized'
}
function Invoke-TestWorkflow([hashtable]$request){
    $action=$request.action
    $workflowOutcomes[$action]='fixture-error'
    $path=Join-Path $bin ('request-'+[guid]::NewGuid().ToString('N')+'.json')
    try {
        [IO.File]::WriteAllText($path,($request|ConvertTo-Json -Depth 4 -Compress),[Text.UTF8Encoding]::new($false))
        $run=Invoke-PrivateNative $controller @('system','apply',$path,'--confirm')
        $job=$null
        if($run.stdout.Length -le 1048576){try {$job=ConvertFrom-Json -InputObject $run.stdout -ErrorAction Stop}catch{}}
        $outcome=Get-WorkflowOutcome $run $job
        $workflowOutcomes[$action]=$outcome
        if($action -ceq 'install' -and $outcome -ceq 'succeeded'){
            $script:connectionState=Get-FixedConnectionState ([string]$job.result.data.status)
        }
        return @{passed=($outcome -ceq 'succeeded');restart=($outcome -ceq 'restart-required')}
    } finally {[IO.File]::Delete($path)}
}
try {
    $cliPaths=@('WireSock Secure Connect\command-line\wiresock-connect-cli.exe','WireSock Secure Connect\bin\wiresock-client.exe','WireSock VPN Client\bin\wiresock-client.exe')
    foreach($path in $cliPaths){if(Test-Path -LiteralPath (Join-Path $env:ProgramFiles $path)){throw 'Expected an empty vendor baseline'}}
    if((Test-Path -LiteralPath $owned) -or @(Get-Service -Name @('WireSockAppService','WireSockConnectService','wiresock-client-service') -ErrorAction SilentlyContinue).Count){
        throw 'Expected an empty vendor baseline'
    }
    $checks.cleanVendorBaseline=$true
    $stage='build'
    [void][IO.Directory]::CreateDirectory($bin)
    $env:CGO_ENABLED='0'
    $env:GOOS='windows'
    $env:GOARCH=$Architecture
    $env:GOTOOLCHAIN='local'
    $env:ACCESSWEAVER_HOME=Join-Path $bin 'controller-state'
    foreach($build in @(
        @{root=$project;output=$controller;package='./cmd/accessweaver'},
        @{root=(Join-Path $project 'scripts/fixtures/wgpeer');output=$peerBinary;package='.'},
        @{root=(Join-Path $project 'scripts/fixtures/wgpeer');output=$selected;package='./cmd/probe'}
    )){
        $result=Invoke-PrivateNative (Get-Command go.exe -ErrorAction Stop).Source @('-C',$build.root,'build','-mod=readonly','-trimpath','-o',$build.output,$build.package)
        if($result.exitCode -ne 0){throw 'Native fixture build failed'}
        $binarySHA256[[IO.Path]::GetFileName($build.output)]=(Get-FileHash -LiteralPath $build.output -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    [IO.File]::Copy($selected,$direct)
    $checks.fixtureBuilt=$true
    $stage='peer'
    $env:ACCESSWEAVER_TEST_VM='1'
    $peer=Start-Process -FilePath $peerBinary -ArgumentList @('serve',('"'+$state+'"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $bin 'peer.stdout') -RedirectStandardError (Join-Path $bin 'peer.stderr')
    [void]$peer.Handle
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath (Join-Path $state 'ready.json')) -and -not $peer.HasExited -and $clock.Elapsed.TotalSeconds -lt 15){
        Start-Sleep -Milliseconds 100
    }
    $config=Join-Path $state 'client.conf'
    $checks.peerReady=(Test-Path -LiteralPath $config -PathType Leaf) -and -not $peer.HasExited
    if(-not $checks.peerReady){throw 'Local peer did not become ready'}
    $stage='install'
    $attempted=$true
    $installed=Invoke-TestWorkflow @{action='install';engine='wiresock';mode='alternative';dns='unchanged';configPath=$config;profileId='local-peer';applications=@('probe-selected.exe')}
    $checks.restartRequested=$installed.restart
    $checks.installCompleted=$installed.passed -and -not $installed.restart -and (Test-Path -LiteralPath $owned -PathType Leaf)
    if(-not $checks.installCompleted){throw 'WireSock installation and connection not confirmed'}
    # Query only the vendor CLI selected by the normal product installation.
    # The generated profile is compared in memory and never leaves the runner.
    $cli=Join-Path $env:ProgramFiles $cliPaths[0]
    if(Test-Path -LiteralPath $cli -PathType Leaf){
        $owner=Get-Item -LiteralPath $owned
        if($owner.Length -gt 0 -and $owner.Length -le 8192){
            $record=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($owner.FullName))
            if($record.profile -cmatch '^AccessWeaver-[a-f0-9]{32}$' -and $record.cli -ieq $cli){
                $list=Invoke-PrivateNative $cli @('list')
                $vendorCLI.profileList=if($list.exitCode -ne 0){'command-failed'}elseif([string]::IsNullOrWhiteSpace($list.stdout)){'empty'}elseif($list.stdout -cmatch ('(?<![a-zA-Z0-9-])'+[regex]::Escape($record.profile)+'(?![a-zA-Z0-9-])')){'profile-observed'}else{'profile-absent'}
                $status=Invoke-PrivateNative $cli @('status')
                $vendorCLI.directStatus=if($status.exitCode -ne 0){'command-failed'}else{Get-FixedConnectionState $status.stdout}
            }
        }
    }
    $stage='traffic'
    foreach($probe in @(
        @{name='selectedTCP4';args=@('http','http://198.51.100.1:8080/')},
        @{name='selectedUDP4';args=@('udp','198.51.100.1:7000')},
        @{name='selectedTCP6';args=@('http','http://[fd42:6177::1]:8080/')},
        @{name='selectedUDP6';args=@('udp','[fd42:6177::1]:7000')}
    )){
        for($i=0;$i -lt 3;$i++){
            if((Invoke-PrivateNative $selected $probe.args).exitCode -eq 0){$checks[$probe.name]=$true;break}
        }
    }
    $checks.directBlocked=(Invoke-PrivateNative $direct @('http','http://198.51.100.1:8080/')).exitCode -ne 0
    $clock.Restart()
    while($clock.Elapsed.TotalSeconds -lt 5){
        try {
            $counts=Get-Content -Raw -LiteralPath (Join-Path $state 'traffic.json') | ConvertFrom-Json
            if([long]$counts.last_handshake_time_sec -gt 0 -and [long]$counts.rx_bytes -gt 0 -and [long]$counts.tx_bytes -gt 0){$checks.peerHandshake=$true;break}
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    $stage='disconnect'
    $checks.disconnectCompleted=(Invoke-TestWorkflow @{action='disconnect';engine='wiresock'}).passed
    if($checks.disconnectCompleted){
        $checks.disconnectedTrafficBlocked=(Invoke-PrivateNative $selected @('http','http://198.51.100.1:8080/')).exitCode -ne 0
    }
    $stage='complete'
} catch {
    # Report only the fixed stage and checks, including when a vendor tool fails.
} finally {
    if($attempted){
        try {$checks.managedRemovalCompleted=(Invoke-TestWorkflow @{action='remove';engine='wiresock'}).passed -and -not (Test-Path -LiteralPath $owned)}catch{}
        try {
            $removed=Invoke-TestWorkflow @{action='vendor-uninstall';engine='wiresock'}
            $checks.vendorRemovalCompleted=$removed.passed -and -not $removed.restart
        } catch {}
    }
    if($peer){
        try {
            if(-not $peer.HasExited){$peer.Kill()}
            $checks.peerExited=$peer.WaitForExit(5000)
        } catch {} finally {$peer.Dispose()}
    }
    if([IO.Directory]::Exists($bin)){
        $resolved=[IO.Path]::GetFullPath($bin)
        $temp=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
        if((Split-Path -Parent $resolved) -ieq $temp -and (Split-Path -Leaf $resolved) -cmatch '^accessweaver-wiresock-[a-f0-9]{32}$'){
            try {Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop}catch{}
            $checks.fixtureRemoved=-not [IO.Directory]::Exists($resolved)
        }
    }
}
$report=@{schemaVersion=4;sourceCommit=$source;target=('windows/'+$Architecture);sourceSHA256=$hashes;binarySHA256=$binarySHA256;stage=$stage;checks=$checks;workflowOutcomes=$workflowOutcomes;connectionState=$connectionState;vendorCLI=$vendorCLI;productionQualificationComplete=$false}
$evidence=Join-Path $project 'build/native-wiresock'
[void][IO.Directory]::CreateDirectory($evidence)
[IO.File]::WriteAllText((Join-Path $evidence 'status.json'),($report|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
foreach($key in $checks.Keys){
    if($key -eq 'restartRequested'){if($checks[$key]){throw 'Native WireSock qualification requires another boot'}}
    elseif(-not $checks[$key]){throw 'Native WireSock qualification did not pass all fixed checks'}
}
