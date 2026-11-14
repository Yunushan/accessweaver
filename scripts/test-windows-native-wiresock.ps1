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
$paths=@('internal/workflow/windows.ps1','go.mod','go.sum','scripts/fixtures/wgpeer/go.mod','scripts/fixtures/wgpeer/go.sum','scripts/fixtures/wgpeer/main.go','scripts/fixtures/wgpeer/cmd/probe/main.go','scripts/test-windows-native-wiresock.ps1','scripts/test-windows-wiresock-evidence.ps1','.github/workflows/windows-native-wiresock.yml')
$hashes=@{}
foreach($path in $paths){$hashes[$path]=(Get-FileHash -LiteralPath (Join-Path $project $path) -Algorithm SHA256).Hash.ToLowerInvariant()}
$checks=[ordered]@{
    cleanVendorBaseline=$false;fixtureBuilt=$false;peerSelfTest=$false;peerReady=$false;installCompleted=$false;restartRequested=$false
    selectedTCP4=$false;selectedUDP4=$false;selectedTCP6=$false;selectedUDP6=$false
    unselectedTCP4Unreachable=$false;unselectedUDP4Unreachable=$false;unselectedTCP6Unreachable=$false;unselectedUDP6Unreachable=$false
    peerStatsReadable=$false;peerInitiationReceived=$false;peerHandshake=$false;peerReceivedBytes=$false;peerSentBytes=$false
    disconnectCompleted=$false
    disconnectedTCP4Unreachable=$false;disconnectedUDP4Unreachable=$false;disconnectedTCP6Unreachable=$false;disconnectedUDP6Unreachable=$false
    managedRemovalCompleted=$false;vendorRemovalCompleted=$false;peerExited=$false;fixtureRemoved=$false
}
$workflowOutcomes=[ordered]@{install='not-run';disconnect='not-run';remove='not-run';'vendor-uninstall'='not-run'}
$connectionState='not-checked'
$connectionRecovery=[ordered]@{
    observed=$false
    recordedRollback='not-observed'
    externalEffects='not-observed'
    ownership='not-checked'
    profileList='not-checked'
    statusBeforeRetry='not-checked'
    rollbackFailure='not-observed'
    journalReferenceValid=$false
    retryOutcome='not-run'
    profileListAfterRetry='not-checked'
}
$managedRemovalProfileList='not-checked'
$failedConnectionPeer=[ordered]@{observed=$false;statsReadable=$false;initiationReceived=$false;handshake=$false;receivedBytes=$false;sentBytes=$false}
$vendorCLI=[ordered]@{profileList='not-checked';directStatus='not-checked';profileExport='not-checked';keyPairRetained=$false;endpointRetained=$false;prefixesRetained=$false;selectedAppRetained=$false}
$uninstallRegistration=[ordered]@{observed=$false;total=0;visibleBundles=0;hiddenMSIs=0;other=0;hiddenMSIIdentity='not-checked'}
$cachedBundleTrust=[ordered]@{path='not-checked';signature='not-checked';publisher='not-checked';installerBytes='not-checked';engineBytes='not-checked'}
$stage='baseline'
$bin=Join-Path $env:RUNNER_TEMP ('accessweaver-wiresock-'+[guid]::NewGuid().ToString('N'))
$controller=Join-Path $bin 'accessweaver.exe'
$peerBinary=Join-Path $bin 'wgpeer.exe'
$selected=Join-Path $bin 'probe-selected.exe'
$direct=Join-Path $bin 'probe-direct.exe'
$state=Join-Path $bin 'peer'
$managedRoot=Join-Path $env:ProgramData 'AccessWeaver'
$owned=Join-Path $managedRoot 'profiles\wiresock-owned.json'
$installJournal=$null
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
function Test-ProbeRoundTrip([string]$program,[string[]]$arguments){
    $result=Invoke-PrivateNative $program $arguments
    return $result.exitCode -eq 0 -and $result.stdout -ceq 'PASS'
}
function Test-ProbeUnreachable([string]$program,[string[]]$arguments){
    $result=Invoke-PrivateNative $program $arguments
    return $result.exitCode -eq 1 -and $result.stdout -ceq 'NO_RESPONSE'
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
        '^WireSock disconnect command failed; the managed profile was retained$' {return 'disconnect-command-failed'}
        '^WireSock profile deletion command failed; the ownership record was retained$' {return 'profile-deletion-command-failed'}
        '^WireSock profile deletion could not be verified; the ownership record was retained$' {return 'profile-inventory-unverified'}
        '^WireSock profile inventory could not be verified before removal; the ownership record was retained$' {return 'profile-inventory-unverified'}
        '^WireSock removal could not confirm the only managed vendor profile; the ownership record was retained$' {return 'recovery-inventory-mismatch'}
        '^WireSock connection was not confirmed by vendor status$' {return 'connection-unconfirmed'}
        '^WireSock profile inventory could not be verified; retry before importing a profile$' {return 'profile-inventory-unverified'}
        '^A managed WireSock profile remains in the vendor inventory; recover the earlier workflow before retrying setup$' {return 'managed-profile-remains'}
        '^WireSock recovery journal differs from the current managed profile$' {return 'recovery-owner-mismatch'}
        '^WireSock recovery cannot confirm the journaled profile is the only managed vendor profile$' {return 'recovery-inventory-mismatch'}
        '^WireSock recovery cannot confirm the vendor is idle without an ownership record$' {return 'recovery-idle-unconfirmed'}
        '^Invalid WireGuard configuration$' {return 'config-invalid'}
        '^Use a separately elevated system apply CLI for machine changes\.' {return 'worker-not-elevated'}
        '^No supported registered WireSock product found; use Windows Apps settings for an unrecognized package$' {return 'uninstall-registration-missing'}
        '^Registered vendor uninstaller is outside protected installation storage$' {return 'uninstaller-location-refused'}
        '^Multiple registered WireSock products matched; select the intended product in Windows Apps settings$' {return 'uninstall-registration-ambiguous'}
        '^Registered WireSock MSI uninstall command does not match its product code$' {return 'uninstaller-msi-product-refused'}
        '^Vendor uninstaller publisher signature could not be verified$' {return 'uninstaller-publisher-refused'}
        '^Vendor (CLI remains installed|uninstall registration remains|services remain installed); inspect vendor uninstall logs$' {return 'vendor-removal-unconfirmed'}
        '^Vendor (service removal could not be verified|CLI removal could not be verified|uninstall registrations could not be verified|uninstall completed but the managed ownership record could not be retired)$' {return 'vendor-removal-unconfirmed'}
        default {return 'other-workflow-failure'}
    }
}
function Get-FixedConnectionState([string]$text){
    if($text.Length -gt 8192){return 'oversized'}
    if([string]::IsNullOrWhiteSpace($text)){return 'empty'}
    $states=@([regex]::Matches($text,'(?<![A-Za-z])(NotConnected|Connecting|Connected|Disconnecting|Disconnected)(?![A-Za-z])') | ForEach-Object {$_.Value} | Sort-Object -Unique)
    if($states.Count -eq 1){return $states[0]}
    if($states.Count -gt 1){return 'ambiguous'}
    return 'unrecognized'
}
function Get-FixtureVendorStatus([string]$cli){
    if(-not (Test-Path -LiteralPath $cli -PathType Leaf -ErrorAction Stop)){return 'not-checked'}
    $result=Invoke-PrivateNative $cli @('status')
    if($result.exitCode -ne 0){return 'command-failed'}
    return Get-FixedConnectionState $result.stdout
}
function Read-FixtureProfileValue([string]$text,[string]$name) {
    $directive=if($name -ceq 'AllowedApps'){'(?:#@ws:[ \t]*)?'}else{''}
    $pattern='(?im)^[ \t]*'+$directive+[regex]::Escape($name)+'[ \t]*=[ \t]*([^\r\n]+)'
    $fields=[regex]::Matches($text,$pattern)
    if($fields.Count -eq 1){return $fields[0].Groups[1].Value.Trim()}
}
function Observe-ImportedProfile([string]$cli,[string]$profile,[string]$config) {
    $export=Join-Path $bin 'wire-profile-export.conf'
    try {
        $result=Invoke-PrivateNative $cli @('export',$profile,$export)
        if($result.exitCode -ne 0){$vendorCLI.profileExport='command-failed';return}
        $item=Get-Item -LiteralPath $export -ErrorAction SilentlyContinue
        if(-not $item -or $item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 16384 -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
            $vendorCLI.profileExport='invalid-file';return
        }
        $expected=[IO.File]::ReadAllText($config)
        $observed=[IO.File]::ReadAllText($export)
        $vendorCLI.profileExport='read'
        $retained=@{}
        foreach($field in @('PrivateKey','PublicKey','Endpoint','Address','AllowedIPs')){
            $want=Read-FixtureProfileValue $expected $field
            $have=Read-FixtureProfileValue $observed $field
            if(-not $want -or -not $have){$retained[$field]=$false;continue}
            if($field -in @('Address','AllowedIPs')){
                $want=($want -split '\s*,\s*' | Sort-Object) -join ','
                $have=($have -split '\s*,\s*' | Sort-Object) -join ','
            }
            $retained[$field]=$want -ceq $have
        }
        $vendorCLI.keyPairRetained=$retained.PrivateKey -and $retained.PublicKey
        $vendorCLI.endpointRetained=$retained.Endpoint
        $vendorCLI.prefixesRetained=$retained.Address -and $retained.AllowedIPs
        $apps=(Read-FixtureProfileValue $observed 'AllowedApps') -split '\s*,\s*'
        $vendorCLI.selectedAppRetained=$apps -icontains 'probe-selected.exe' -and $apps -inotcontains 'probe-direct.exe'
    } catch {
        $vendorCLI.profileExport='read-failed'
        $vendorCLI.keyPairRetained=$false
        $vendorCLI.endpointRetained=$false
        $vendorCLI.prefixesRetained=$false
        $vendorCLI.selectedAppRetained=$false
    } finally {
        try {[IO.File]::Delete($export)}catch{}
    }
}
function Get-HiddenMSIIdentity($record){
    $key=[guid]::Empty
    if(-not [guid]::TryParseExact([string]$record.PSChildName,'B',[ref]$key) -or $key -eq [guid]::Empty){
        return 'invalid-product-key'
    }
    $rawCommand=[string]$record.UninstallString
    if([string]::IsNullOrWhiteSpace($rawCommand)){return 'command-missing'}
    if($rawCommand.Length -gt 4096){return 'command-unrecognized'}
    $command=[Environment]::ExpandEnvironmentVariables($rawCommand).Trim()
    if($command.Length -gt 4096){return 'command-unrecognized'}
    $program=[regex]::Escape((Join-Path $env:SystemRoot 'System32\msiexec.exe'))
    $pattern='(?i)^(?:msiexec(?:\.exe)?|"'+$program+'"|'+$program+')[ \t]+/[ix][ \t]*(\{[0-9a-f-]{36}\})(?=$|[ \t])'
    $identity=[regex]::Match($command,$pattern,[Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if(-not $identity.Success){return 'command-unrecognized'}
    $product=[guid]::Empty
    if(-not [guid]::TryParseExact($identity.Groups[1].Value,'B',[ref]$product) -or $product -ne $key){
        return 'product-mismatch'
    }
    if($identity.Length -ne $command.Length){return 'extra-command-arguments'}
    return 'product-matched'
}
function Get-NativeInstallerPins {
    # Read the committed product pin as data. The installer staging file is
    # removed by the worker before this fixture can observe the vendor cache.
    $tokens=$null
    $parseErrors=$null
    $workflowPath=Join-Path $project 'internal/workflow/windows.ps1'
    $ast=[System.Management.Automation.Language.Parser]::ParseFile($workflowPath,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw 'Installer plan source is invalid'}
    $plans=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'WireSock-InstallerPlan'},$true))
    if($plans.Count -ne 1){throw 'Installer plan unavailable'}
    $switches=@($plans[0].FindAll({param($node) $node -is [System.Management.Automation.Language.SwitchStatementAst]},$true))
    if($switches.Count -ne 1){throw 'Installer architecture plan unavailable'}
    $clauses=@($switches[0].Clauses | Where-Object {$_.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $_.Item1.Value -ceq $Architecture})
    if($clauses.Count -ne 1){throw 'Native installer architecture unavailable'}
    $tables=@($clauses[0].Item2.FindAll({param($node) $node -is [System.Management.Automation.Language.HashtableAst]},$true))
    if($tables.Count -ne 1){throw 'Native installer pin unavailable'}
    $plan=$tables[0].SafeGetValue()
    foreach($pin in @($plan.sha256,$plan.cachedEngineSHA256)){
        if($pin -isnot [string] -or $pin -cnotmatch '\A[a-f0-9]{64}\z'){throw 'Native installer pin unavailable'}
    }
    return $plan
}
function Observe-CachedBundleTrust($record) {
    $cachedBundleTrust.path='refused'
    $cachePath=$record.BundleCachePath
    if($cachePath -isnot [string] -or $cachePath.Length -gt 4096 -or $cachePath -notmatch '\A[A-Za-z]:\\[^:*?"<>|\x00-\x1f]+\.exe\z'){return}
    $cacheRoot=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Package Cache')).TrimEnd('\')+'\'
    $program=[IO.Path]::GetFullPath($cachePath)
    if(-not $program.StartsWith($cacheRoot,[StringComparison]::OrdinalIgnoreCase)){return}
    $current=$program
    while($current){
        $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){return}
        if($current -ieq $program -and ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 256MB)){return}
        $current=Split-Path -Parent $current
    }
    $cachedBundleTrust.path='verified'
    $cachedBundleTrust.signature='inspection-failed'
    $signature=Get-AuthenticodeSignature -LiteralPath $program -ErrorAction Stop
    $cachedBundleTrust.signature=switch([string]$signature.Status){
        'Valid' {'valid'}
        'NotSigned' {'unsigned'}
        'HashMismatch' {'hash-mismatch'}
        'NotTrusted' {'untrusted'}
        default {'other'}
    }
    $subject=$signature.SignerCertificate.Subject
    if($subject -is [string]){
        $cachedBundleTrust.publisher=if($subject -match 'NT Kernel|WireSock'){'matches'}else{'differs'}
    }else{$cachedBundleTrust.publisher='missing'}
    $pins=Get-NativeInstallerPins
    $cachedHash=(Get-FileHash -LiteralPath $program -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $cachedBundleTrust.installerBytes=if($cachedHash -ceq $pins.sha256){'match'}else{'differ'}
    $cachedBundleTrust.engineBytes=if($cachedHash -ceq $pins.cachedEngineSHA256){'match'}else{'differ'}
}
function Observe-VendorUninstallRegistration {
    # Compare registry properties in memory. Publish only counts and a fixed category, without
    # registration keys, paths, product codes, or command lines.
    $total=0;$visibleBundles=0;$hiddenMSIs=0;$other=0
    $identity='not-checked';$bundle=$null
    foreach($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
        if(-not (Test-Path -LiteralPath $base)){continue}
        foreach($entry in (Get-ChildItem -LiteralPath $base)){
            $record=Get-ItemProperty -LiteralPath $entry.PSPath
            if($record.DisplayName -cne 'WireSock Secure Connect'){continue}
            $total++
            if($total -gt 32){return}
            if($record.WindowsInstaller -eq 1 -and $record.SystemComponent -eq 1){
                $hiddenMSIs++
                if($hiddenMSIs -eq 1){$identity=Get-HiddenMSIIdentity $record}
            }
            elseif($record.WindowsInstaller -ne 1 -and $record.SystemComponent -ne 1 -and
                -not [string]::IsNullOrWhiteSpace($record.BundleCachePath) -and -not [string]::IsNullOrWhiteSpace($record.BundleProviderKey)){$visibleBundles++;$bundle=$record}
            else {$other++}
        }
    }
    $uninstallRegistration.observed=$true
    $uninstallRegistration.total=$total
    $uninstallRegistration.visibleBundles=$visibleBundles
    $uninstallRegistration.hiddenMSIs=$hiddenMSIs
    $uninstallRegistration.other=$other
    if($hiddenMSIs -eq 1){$uninstallRegistration.hiddenMSIIdentity=$identity}
    if($visibleBundles -eq 1){Observe-CachedBundleTrust $bundle}
}
function Read-PeerEvidence([string]$path){
    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
       $item.Length -le 0 -or $item.Length -gt 4096){
        throw 'Peer statistics are not a bounded ordinary file'
    }
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $buffer=[byte[]]::new(4097)
        $length=0
        while($length -lt $buffer.Length){
            $read=$stream.Read($buffer,$length,$buffer.Length-$length)
            if($read -eq 0){break}
            $length+=$read
        }
        if($length -le 0 -or $length -gt 4096){throw 'Peer statistics size changed'}
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($buffer,0,$length)
    } finally {$stream.Dispose()}
    $counts=ConvertFrom-Json -InputObject $text -ErrorAction Stop
    $observed=@{}
    foreach($field in @('last_handshake_time_sec','rx_bytes','tx_bytes')){
        $value=$counts.$field
        $parsed=0L
        if($value -isnot [string] -or $value -cnotmatch '\A[0-9]{1,19}\z' -or
           -not [long]::TryParse($value,[ref]$parsed)){throw 'Invalid peer statistic'}
        $observed[$field]=$parsed -gt 0
    }
    if($counts.initiation_received -isnot [bool]){throw 'Invalid peer initiation observation'}
    return @{initiationReceived=$counts.initiation_received;handshake=$observed.last_handshake_time_sec;receivedBytes=$observed.rx_bytes;sentBytes=$observed.tx_bytes}
}
function Observe-PeerEvidence([string]$path,[switch]$WaitForTraffic){
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $observed=$null
    do {
        try {
            $sample=Read-PeerEvidence $path
            if(-not $observed){
                $observed=$sample
            } else {
                foreach($field in @('initiationReceived','handshake','receivedBytes','sentBytes')){
                    $observed[$field]=$observed[$field] -or $sample[$field]
                }
            }
            if(-not $WaitForTraffic -or ($observed.initiationReceived -and $observed.handshake -and $observed.receivedBytes -and $observed.sentBytes)){break}
        }catch{}
        Start-Sleep -Milliseconds 100
    } while($timer.Elapsed.TotalSeconds -lt 5)
    return $observed
}
function Read-ManagedVendorProfileList([string]$cli){
    if(-not (Test-Path -LiteralPath $cli -PathType Leaf -ErrorAction Stop)){return @{status='not-checked';profiles=@()}}
    $list=Invoke-PrivateNative $cli @('list')
    if($list.exitCode -ne 0 -or $list.stdout.Length -gt 8192){return @{status='command-failed';profiles=@()}}
    if([string]::IsNullOrWhiteSpace($list.stdout)){return @{status='empty';profiles=@()}}
    $pattern='(?<![a-zA-Z0-9-])AccessWeaver-[a-f0-9]{32}(?![a-zA-Z0-9-])'
    $profiles=@([regex]::Matches($list.stdout,$pattern) | ForEach-Object {$_.Value} | Sort-Object -Unique)
    $status=if($profiles.Count){'managed-profile-observed'}else{'managed-profile-not-observed'}
    return @{status=$status;profiles=$profiles}
}
function Get-ManagedVendorProfileList([string]$cli){
    return (Read-ManagedVendorProfileList $cli).status
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
            $reported=[string]$job.result.data.status
            $script:connectionState=if($reported -ceq 'Unknown'){'unrecognized'}else{Get-FixedConnectionState $reported}
        }
        if($action -ceq 'install' -and $outcome -ceq 'connection-unconfirmed'){
            $connectionRecovery.observed=$true
            if($job.result.rollbackScope -ceq 'recorded-resources' -and $job.result.recordedRollbackComplete -is [bool]){
                $connectionRecovery.recordedRollback=if($job.result.recordedRollbackComplete){'complete'}else{'incomplete'}
            }
            if($connectionRecovery.recordedRollback -ceq 'incomplete'){
                $rollbackErrors=@($job.result.rollbackErrors)
                $connectionRecovery.rollbackFailure=if($rollbackErrors -ccontains 'WireSock disconnect command failed; the managed profile was retained'){
                    'disconnect-refused'
                }elseif($rollbackErrors -cmatch '^Tool failed: wiresock-connect-cli\.exe \(exit -?[0-9]{1,10}\)$'){
                    'vendor-cli-exit-failure'
                }else{'other'}
            }
            $connectionRecovery.externalEffects=if($job.result.externalEffectsPending -is [bool] -and $job.result.externalEffectsPending){'pending'}else{'not-reported'}
            $journal=$job.result.journal
            if($journal -is [string] -and $journal.Length -le 4096){
                $name=[IO.Path]::GetFileName($journal)
                if($name -cmatch '\Aworkflow-[a-f0-9]{32}\.json\z' -and
                    $journal -ieq (Join-Path (Join-Path $managedRoot 'logs') $name)){
                    $script:installJournal=$name
                    $connectionRecovery.journalReferenceValid=$true
                }
            }
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
    $selfTest=Join-Path $bin 'peer-self-test'
    $control=Invoke-PrivateNative $peerBinary @('self-test',$selfTest)
    if($control.exitCode -eq 0){
        $controlReport=Get-Item -LiteralPath (Join-Path $selfTest 'self-test.json')
        if($controlReport.Length -gt 0 -and $controlReport.Length -le 4096){
            $controlResult=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($controlReport.FullName))
            $checks.peerSelfTest=$controlResult.passed -eq $true -and $controlResult.tcpIPv4 -eq $true -and
                $controlResult.udpIPv4 -eq $true -and $controlResult.tcpIPv6 -eq $true -and $controlResult.udpIPv6 -eq $true -and
                $controlResult.peer.initiation_received -is [bool] -and $controlResult.peer.initiation_received -and
                [long]$controlResult.peer.last_handshake_time_sec -gt 0 -and
                [long]$controlResult.peer.rx_bytes -gt 0 -and [long]$controlResult.peer.tx_bytes -gt 0
        }
    }
    if(-not $checks.peerSelfTest){throw 'Local peer positive control failed'}
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
    $cli=Join-Path $env:ProgramFiles $cliPaths[0]
    if(-not $checks.installCompleted){
        if($connectionRecovery.observed){
            # Snapshot the independent peer before the fixture retries recovery.
            $failedConnectionPeer.observed=$true
            if(-not $peer.HasExited){
                $sample=Observe-PeerEvidence (Join-Path $state 'traffic.json') -WaitForTraffic
                if($sample -and -not $peer.HasExited){
                    $failedConnectionPeer.statsReadable=$true
                    $failedConnectionPeer.initiationReceived=$sample.initiationReceived
                    $failedConnectionPeer.handshake=$sample.handshake
                    $failedConnectionPeer.receivedBytes=$sample.receivedBytes
                    $failedConnectionPeer.sentBytes=$sample.sentBytes
                }
            }
            $connectionRecovery.ownership=if(Test-Path -LiteralPath $owned -ErrorAction Stop){'present'}else{'absent'}
            $inventory=Read-ManagedVendorProfileList $cli
            $connectionRecovery.profileList=$inventory.status
            $connectionRecovery.statusBeforeRetry=Get-FixtureVendorStatus $cli
            $vendorCLI.directStatus=$connectionRecovery.statusBeforeRetry
            # This run started from a clean disposable vendor baseline. Only a
            # unique managed name and bound journal permit the diagnostic export.
            if($connectionRecovery.journalReferenceValid -and $inventory.profiles.Count -eq 1){
                $vendorCLI.profileList='profile-observed'
                Observe-ImportedProfile $cli $inventory.profiles[0] $config
            }
            if($installJournal -and $connectionRecovery.recordedRollback -ceq 'incomplete'){
                try {[void](Invoke-TestWorkflow @{action='recover';journalId=$installJournal})}
                catch {}
                finally {
                    $connectionRecovery.retryOutcome=$workflowOutcomes['recover']
                    $workflowOutcomes.Remove('recover')
                }
                $connectionRecovery.profileListAfterRetry=Get-ManagedVendorProfileList $cli
            }
        }
        throw 'WireSock installation and connection not confirmed'
    }
    # Query only the vendor CLI selected by the normal product installation.
    # The generated profile is compared in memory and never leaves the runner.
    if(Test-Path -LiteralPath $cli -PathType Leaf){
        $owner=Get-Item -LiteralPath $owned
        if($owner.Length -gt 0 -and $owner.Length -le 8192){
            $record=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($owner.FullName))
            if($record.profile -cmatch '^AccessWeaver-[a-f0-9]{32}$' -and $record.cli -ieq $cli){
                $list=Invoke-PrivateNative $cli @('list')
                $vendorCLI.profileList=if($list.exitCode -ne 0){'command-failed'}elseif([string]::IsNullOrWhiteSpace($list.stdout)){'empty'}elseif($list.stdout -cmatch ('(?<![a-zA-Z0-9-])'+[regex]::Escape($record.profile)+'(?![a-zA-Z0-9-])')){'profile-observed'}else{'profile-absent'}
                $vendorCLI.directStatus=Get-FixtureVendorStatus $cli
                if($vendorCLI.profileList -ceq 'profile-observed'){Observe-ImportedProfile $cli $record.profile $config}
            }
        }
    }
    $stage='traffic'
    $probes=@(
        @{name='TCP4';args=@('http','http://198.51.100.1:8080/')},
        @{name='UDP4';args=@('udp','198.51.100.1:7000')},
        @{name='TCP6';args=@('http','http://[fd42:6177::1]:8080/')},
        @{name='UDP6';args=@('udp','[fd42:6177::1]:7000')}
    )
    foreach($probe in $probes){
        $selectedCheck='selected'+$probe.name
        for($i=0;$i -lt 3;$i++){
            if(Test-ProbeRoundTrip $selected $probe.args){$checks[$selectedCheck]=$true;break}
        }
        # Bracket the unselected probe with selected round trips so a stopped
        # tunnel cannot make the isolation check pass.
        if($checks[$selectedCheck] -and (Test-ProbeUnreachable $direct $probe.args)){
            $checks['unselected'+$probe.name+'Unreachable']=(Test-ProbeRoundTrip $selected $probe.args) -and -not $peer.HasExited
        }
    }
    $sample=Observe-PeerEvidence (Join-Path $state 'traffic.json') -WaitForTraffic
    if($sample -and -not $peer.HasExited){
        $checks.peerStatsReadable=$true
        $checks.peerInitiationReceived=$sample.initiationReceived
        $checks.peerHandshake=$sample.handshake
        $checks.peerReceivedBytes=$sample.receivedBytes
        $checks.peerSentBytes=$sample.sentBytes
    }
    $stage='disconnect'
    $checks.disconnectCompleted=(Invoke-TestWorkflow @{action='disconnect';engine='wiresock'}).passed
    if($checks.disconnectCompleted){
        foreach($probe in $probes){
            if($checks['selected'+$probe.name] -and -not $peer.HasExited){
                $checks['disconnected'+$probe.name+'Unreachable']=(Test-ProbeUnreachable $selected $probe.args) -and -not $peer.HasExited
            }
        }
    }
    $stage='complete'
} catch {
    # Report only the fixed stage and checks, including when a vendor tool fails.
} finally {
    if($attempted){
        try {
            $removed=Invoke-TestWorkflow @{action='remove';engine='wiresock'}
            $managedRemovalProfileList=Get-ManagedVendorProfileList $cli
            $checks.managedRemovalCompleted=$removed.passed -and -not (Test-Path -LiteralPath $owned -ErrorAction Stop) -and
                $managedRemovalProfileList -cin @('empty','managed-profile-not-observed')
        } catch {}
        try {
            try {Observe-VendorUninstallRegistration}catch{}
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
$report=@{schemaVersion=19;failedConnectionPeer=$failedConnectionPeer;sourceCommit=$source;target=('windows/'+$Architecture);sourceSHA256=$hashes;binarySHA256=$binarySHA256;stage=$stage;checks=$checks;workflowOutcomes=$workflowOutcomes;connectionState=$connectionState;connectionRecovery=$connectionRecovery;managedRemovalProfileList=$managedRemovalProfileList;vendorCLI=$vendorCLI;uninstallRegistration=$uninstallRegistration;cachedBundleTrust=$cachedBundleTrust;productionQualificationComplete=$false}
$evidence=Join-Path $project 'build/native-wiresock'
[void][IO.Directory]::CreateDirectory($evidence)
[IO.File]::WriteAllText((Join-Path $evidence 'status.json'),($report|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
if($vendorCLI.profileExport -cne 'read' -or -not $vendorCLI.keyPairRetained -or -not $vendorCLI.endpointRetained -or
    -not $vendorCLI.prefixesRetained -or -not $vendorCLI.selectedAppRetained){
    throw 'Native WireSock qualification did not verify imported profile fields'
}
foreach($key in $checks.Keys){
    if($key -eq 'restartRequested'){if($checks[$key]){throw 'Native WireSock qualification requires another boot'}}
    elseif(-not $checks[$key]){throw 'Native WireSock qualification did not pass all fixed checks'}
}
