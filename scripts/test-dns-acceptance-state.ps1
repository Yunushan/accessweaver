# Selected-function contracts only: no worker top level or real OS DNS/registry,
# service, network, process, account or installation operations are invoked.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell,[string]$ReportPath)
$ErrorActionPreference='Stop'
if($RequireWindowsPowerShell -and ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){throw 'Windows PowerShell 5.1 Desktop is required'}
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Management','Microsoft.PowerShell.Management.psd1')) -ErrorAction Stop
$PSModuleAutoLoadingPreference='None'
$reportParent=$null;$reportCreated=0
if($ReportPath){
    if(-not [IO.Path]::IsPathRooted($ReportPath)){throw 'Contract report needs an absolute owned path'}
    $ReportPath=[IO.Path]::GetFullPath($ReportPath)
    $reportParent=Microsoft.PowerShell.Management\Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ReportPath)) -Force -ErrorAction Stop
    if(-not $reportParent.PSIsContainer -or ($reportParent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($reportParent.FullName).Length -ne 0){throw 'Contract report needs an existing empty ordinary parent'}
    $reportCreated=$reportParent.CreationTimeUtc.Ticks
}
$project=Split-Path -Parent $PSScriptRoot
$sourcePath=Join-Path $PSScriptRoot 'dns-acceptance-state.ps1'
$sourceFiles=@('scripts/native-doh-scenario.ps1','scripts/test-native-doh.ps1','.github/workflows/native-doh.yml','scripts/dns-acceptance-state.ps1','scripts/test-dns-acceptance-state.ps1','scripts/test-windows-integration.ps1','scripts/test-windows-reboot.ps1','scripts/vmware-test-bootstrap.ps1','scripts/test-windows-workflow.ps1','.github/workflows/dns-recovery-contracts.yml')
$sourceHashes=@{};foreach($file in $sourceFiles){$sourceHashes[$file]=(Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Acceptance helper source did not parse'}
$definitions=@($ast.EndBlock.Statements)
$tokens=$null;$issues=$null;$coordinator=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-doh-scenario.ps1'),[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Native coordinator source did not parse'}
$definitions+=@($coordinator.EndBlock.Statements)
$selected=@('Invoke-NativeDoHScenario','Convert-DNSAcceptanceGuid','Convert-DNSAcceptanceAddress','Read-DNSAcceptanceState','Get-DNSAcceptanceIndex','Assert-DNSAcceptanceRestored','Assert-DNSAcceptanceConfigured','Invoke-DNSAcceptanceRoundTrip')
$allowed=$selected+@('Get-NetAdapter','Get-ItemProperty','Get-DnsClientServerAddress','Get-Command','Get-DnsClientDohServerAddress','Where-Object','Get-Service','Clear-DnsClientCache','Resolve-DnsName')
foreach($name in $selected){
    $nodes=@($definitions | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Acceptance helper function unavailable'}
    foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
        $commandName=$command.GetCommandName()
        $callback=(-not $commandName -and $command.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and $command.CommandElements[0] -is [Management.Automation.Language.VariableExpressionAst] -and $command.CommandElements[0].VariablePath.UserPath -cin @('Apply','Capture','Resolve'))
        if(-not $callback -and $commandName -notin $allowed){throw 'Acceptance helper command boundary refused'}
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$script:checks=0;$script:contractOutcome='failed';$script:contractCode='unexpected-contract-error'
$script:closedContractCodes=@('capture-stage-complete','capture-stage-refusal','native-coordinator-result','native-coordinator-cleanup','service-failure-restores','cleanup-failure-propagates','link-local-scope-follows-guid','none','unexpected-contract-error','unknown-test-code','expected-refusal','mixed-modes-captured','dhcp-lease-change-and-index-order-independent','guid-case-independent','read-inspection-refused','malformed-static-refused','invalid-saved-state-refused','legacy-state-refused','doh-capability-legacy-roundtrip','configured-method-positive','configured-method-negative','roundtrip-positive','resolver-failure-restores','operation-and-cleanup-errors-retained','capture-failure-no-operation','invalid-method-no-operation','native-harness-wiring')
function Assert-A([bool]$Value,[string]$Code){if(-not $Value){$script:contractCode=if($Code -in $script:closedContractCodes){$Code}else{'unknown-test-code'};throw ('Acceptance contract failed: '+$script:contractCode)};$script:checks++}
function Reject-A([scriptblock]$Operation){$failed=$false;try{& $Operation | Out-Null}catch{$failed=$true};Assert-A $failed 'expected-refusal'}
$script:g1='abcdef00-0000-0000-0000-000000000001';$script:g2='abcdef00-0000-0000-0000-000000000002'
function New-AData {
    return @{
        $script:g1=[pscustomobject]@{mode4='dhcp';mode6='static';servers4=@('198.51.100.53');servers6=@('2001:db8::53','2001:db8::54')}
        $script:g2=[pscustomobject]@{mode4='static';mode6='dhcp';servers4=@('192.0.2.53','192.0.2.54');servers6=@('2001:db8:2::53')}
    }
}
function Original-ADoh {return [pscustomobject]@{ServerAddress='192.0.2.90';DohTemplate='https://original.invalid/dns-query';AllowFallbackToUdp=$true;AutoUpgrade=$false}}
function New-ACase {
    $script:adapters=@([pscustomobject]@{InterfaceGuid=$script:g1;ifIndex=77;Status='Up';InterfaceDescription='Fixture adapter'},[pscustomobject]@{InterfaceGuid=$script:g2;ifIndex=88;Status='Down';InterfaceDescription='Second fixture adapter'})
    $script:data=New-AData;$script:doh=@((Original-ADoh));$script:available=$true;$script:registryFailure='';$script:dnsFailure='';$script:dohFailure=$false
    $script:resolveFailure=$false;$script:operationFailure=$false;$script:restoreFailure=$false;$script:serviceStatus='Running';$script:actions=[Collections.Generic.List[string]]::new();$script:dnsReads=0
}
function Clone-A([object]$Value){return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 14)}
function Get-NetAdapter {[CmdletBinding()]param();foreach($a in $script:adapters){[pscustomobject]@{InterfaceGuid=$a.InterfaceGuid;ifIndex=$a.ifIndex;Status=$a.Status;InterfaceDescription=$a.InterfaceDescription}}}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$LiteralPath)
    if($LiteralPath -notmatch '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\(Tcpip6?)\\Parameters\\Interfaces\\\{([a-f0-9-]{36})\}$'){throw 'Unexpected acceptance registry path'}
    $family=if($Matches[1] -ceq 'Tcpip'){'IPv4'}else{'IPv6'};$guid=$Matches[2]
    if(-not $script:data.ContainsKey($guid) -or $script:registryFailure -ceq $family){throw 'fixture-registry-inspection'}
    $mode=if($family -ceq 'IPv4'){$script:data[$guid].mode4}else{$script:data[$guid].mode6}
    if($mode -ceq 'dhcp'){return [pscustomobject]@{}}
    if($mode -ceq 'malformed'){return [pscustomobject]@{NameServer=42}}
    return [pscustomobject]@{NameServer='fixture-static-mode'}
}
function Get-DnsClientServerAddress {
    [CmdletBinding()]param($InterfaceIndex,$AddressFamily)
    $script:dnsReads++;if($script:dnsFailure -ceq 'empty'){return}
    $a=@($script:adapters | Where-Object {$_.ifIndex -eq $InterfaceIndex});if($a.Count -ne 1){throw 'fixture-address-identity'}
    $guid=([guid]$a[0].InterfaceGuid).ToString('D');$values=if($AddressFamily -ceq 'IPv4'){@($script:data[$guid].servers4)}else{@($script:data[$guid].servers6)}
    $result=[pscustomobject]@{ServerAddresses=@($values)}
    if($script:dnsFailure -ceq 'duplicate'){return @($result,$result)};return $result
}
function Get-Command {[CmdletBinding()]param([string]$Name);if($Name -cne 'Get-DnsClientDohServerAddress'){throw 'Unexpected acceptance command discovery'};if($script:available){return [pscustomobject]@{Name=$Name}}}
function Get-DnsClientDohServerAddress {[CmdletBinding()]param();if($script:dohFailure){throw 'fixture-doh-inspection'};return $script:doh}
function Get-Service {[CmdletBinding()]param($Name);if($Name -cne 'AccessWeaver-dnscrypt'){throw 'Unexpected acceptance service'};return [pscustomobject]@{Status=$script:serviceStatus}}
function Clear-DnsClientCache {[CmdletBinding()]param()}
function Resolve-DnsName {[CmdletBinding()]param($Name,[switch]$DnsOnly,[switch]$QuickTimeout);if($Name -cne 'example.com' -or -not $DnsOnly -or -not $QuickTimeout){throw 'Unexpected acceptance resolver boundary'};if($script:resolveFailure){throw 'fixture-resolver-failure'};return [pscustomobject]@{Name='example.com'}}
function Set-AConfigured([string]$Method) {
    $script:data[$script:g1].mode4='static';$script:data[$script:g1].mode6='static'
    $script:data[$script:g1].servers4=if($Method -ceq 'doh'){@('8.8.8.8','9.9.9.9')}else{@('127.0.0.1')}
    $script:data[$script:g1].servers6=if($Method -ceq 'doh'){@('2001:4860:4860::8888','2620:fe::fe')}else{@('::1')}
    if($Method -ceq 'doh'){
        foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
            $template=if($address -in @('8.8.8.8','2001:4860:4860::8888')){'https://dns.google/dns-query'}else{'https://dns.quad9.net/dns-query'}
            $script:doh+=@([pscustomobject]@{ServerAddress=$address;DohTemplate=$template;AllowFallbackToUdp=$false;AutoUpgrade=$true})
        }
    }
}
$script:applyFixture={param($request)
    $script:actions.Add($request.action)
    if($request.action -ceq 'dns'){
        if($script:operationFailure){throw 'fixture-operation-failure'};Set-AConfigured $request.dns
    } elseif($request.action -ceq 'dns-restore'){
        if($script:restoreFailure){throw 'fixture-restore-failure'};$script:data=New-AData;$script:doh=@((Original-ADoh))
    } else {throw 'Unexpected acceptance apply request'}
}
try {
    New-ACase;$before=Read-DNSAcceptanceState
    Assert-A ($before.adapters.Count -eq 2 -and $before.adapters[0].ipv4.mode -ceq 'dhcp' -and $before.adapters[0].ipv4.servers.Count -eq 0 -and $before.adapters[0].ipv6.mode -ceq 'static' -and $before.adapters[0].ipv6.servers.Count -eq 2 -and $before.doh.Count -eq 1) 'mixed-modes-captured'
    $script:adapters[0].ifIndex=101;$script:adapters[1].ifIndex=102;$script:adapters=@($script:adapters[1],$script:adapters[0]);$script:data[$script:g1].servers4=@('203.0.113.53')
    Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);Assert-A $true 'dhcp-lease-change-and-index-order-independent'
    $script:adapters[0].InterfaceGuid=$script:adapters[0].InterfaceGuid.ToUpperInvariant();Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);Assert-A $true 'guid-case-independent'
    New-ACase;$script:data[$script:g1].servers6=@('fe80::53%77');$before=Read-DNSAcceptanceState;$script:adapters[0].ifIndex=101;$script:data[$script:g1].servers6=@('fe80::53%101')
    Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);Assert-A ($before.adapters[0].ipv6.servers[0] -ceq 'fe80::53') 'link-local-scope-follows-guid'
    $script:data[$script:g1].servers6=@('fe80::53%77');Reject-A {Read-DNSAcceptanceState}
    foreach($failure in @('registry4','registry6','dns-empty','dns-duplicate','doh','doh-duplicate','doh-flags','duplicate-guid','invalid-guid','empty-inventory','malformed-mode')){
        New-ACase
        switch($failure){
            'registry4' {$script:registryFailure='IPv4'}
            'registry6' {$script:registryFailure='IPv6'}
            'dns-empty' {$script:dnsFailure='empty'}
            'dns-duplicate' {$script:dnsFailure='duplicate'}
            'doh' {$script:dohFailure=$true}
            'doh-duplicate' {$script:doh+=@($script:doh[0])}
            'doh-flags' {$script:doh[0].AutoUpgrade='true'}
            'duplicate-guid' {$script:adapters+=@($script:adapters[0])}
            'invalid-guid' {$script:adapters[0].InterfaceGuid='invalid'}
            'empty-inventory' {$script:adapters=@()}
            'malformed-mode' {$script:data[$script:g1].mode4='malformed'}
        }
        Reject-A {Read-DNSAcceptanceState};Assert-A ($script:actions.Count -eq 0) 'read-inspection-refused'
    }
    foreach($values in @(@(),@('not-an-ip'),@('192.0.2.53'))){
        New-ACase;$script:data[$script:g1].servers6=$values
        Reject-A {Read-DNSAcceptanceState};Assert-A ($script:actions.Count -eq 0) 'malformed-static-refused'
    }
    foreach($failure in @('version','mode','missing','extra','duplicate','dhcp-servers','static-empty','static-value','static-order','wrong-family','doh-duplicate','doh-flags','doh-template','doh-capability','doh-missing')){
        New-ACase;$before=Read-DNSAcceptanceState;$after=Clone-A $before
        switch($failure){
            'version' {$after.schemaVersion='1'}
            'mode' {$after.adapters[0].ipv4.mode='static';$after.adapters[0].ipv4.servers=@('198.51.100.53')}
            'missing' {$after.adapters=@($after.adapters[0])}
            'extra' {$other=Clone-A $after.adapters[0];$other.guid='abcdef00-0000-0000-0000-000000000003';$after.adapters+=@($other)}
            'duplicate' {$after.adapters+=@($after.adapters[0])}
            'dhcp-servers' {$after.adapters[0].ipv4.servers=@('198.51.100.53')}
            'static-empty' {$after.adapters[0].ipv6.servers=@()}
            'static-value' {$after.adapters[0].ipv6.servers=@('2001:db8::55','2001:db8::54')}
            'static-order' {$after.adapters[0].ipv6.servers=@('2001:db8::54','2001:db8::53')}
            'wrong-family' {$after.adapters[0].ipv6.servers=@('192.0.2.53')}
            'doh-duplicate' {$after.doh+=@($after.doh[0])}
            'doh-flags' {$after.doh[0].fallback=$false}
            'doh-template' {$after.doh[0].template='https://changed.invalid/dns-query'}
            'doh-capability' {$after.dohAvailable=$false;$after.doh=@()}
            'doh-missing' {$after.doh=@()}
        }
        Reject-A {Assert-DNSAcceptanceRestored $before $after};Assert-A ($script:actions.Count -eq 0) 'invalid-saved-state-refused'
    }
    Reject-A {Assert-DNSAcceptanceRestored 'legacy-index-json' 'legacy-index-json'};Assert-A $true 'legacy-state-refused'
    New-ACase;$script:available=$false;$script:doh=@();$before=Read-DNSAcceptanceState;Assert-DNSAcceptanceRestored $before (Clone-A $before);Assert-A $true 'doh-capability-legacy-roundtrip'
    foreach($method in @('doh','dnscrypt')){
        New-ACase;$before=Read-DNSAcceptanceState;Set-AConfigured $method;$current=Read-DNSAcceptanceState;Assert-DNSAcceptanceConfigured $before $current $method;Assert-A $true 'configured-method-positive'
        foreach($failure in @('mode','ipv6','server-order','missing-adapter','no-selected')){
            $bad=Clone-A $current;$original=Clone-A $before
            switch($failure){
                'mode' {$bad.adapters[0].ipv4.mode='dhcp';$bad.adapters[0].ipv4.servers=@()}
                'ipv6' {$bad.adapters[0].ipv6.servers=@('2001:db8::1')}
                'server-order' {$bad.adapters[0].ipv4.servers=@('9.9.9.9','8.8.8.8')}
                'missing-adapter' {$bad.adapters=@($bad.adapters[1])}
                'no-selected' {$original.adapters[0].selected=$false}
            }
            Reject-A {Assert-DNSAcceptanceConfigured $original $bad $method};Assert-A $true 'configured-method-negative'
        }
        New-ACase;Invoke-DNSAcceptanceRoundTrip $method $script:applyFixture
        Assert-A (($script:actions -join ',') -ceq 'dns,dns-restore') 'roundtrip-positive'
    }
    foreach($failure in @('fallback','upgrade','template','missing','capability')){
        New-ACase;$before=Read-DNSAcceptanceState;Set-AConfigured 'doh';$current=Read-DNSAcceptanceState
        switch($failure){
            'fallback' {$current.doh[1].fallback=$true}
            'upgrade' {$current.doh[1].upgrade=$false}
            'template' {$current.doh[1].template='https://changed.invalid/dns-query'}
            'missing' {$current.doh=@($current.doh[0])}
            'capability' {$current.dohAvailable=$false;$current.doh=@()}
        }
        Reject-A {Assert-DNSAcceptanceConfigured $before $current 'doh'};Assert-A $true 'configured-method-negative'
    }
    New-ACase;$before=Read-DNSAcceptanceState;$script:resolveFailure=$true
    Reject-A {Invoke-DNSAcceptanceRoundTrip 'doh' $script:applyFixture};Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);Assert-A (($script:actions -join ',') -ceq 'dns,dns-restore') 'resolver-failure-restores'
    New-ACase;$before=Read-DNSAcceptanceState;$script:serviceStatus='Stopped'
    Reject-A {Invoke-DNSAcceptanceRoundTrip 'dnscrypt' $script:applyFixture};Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);Assert-A (($script:actions -join ',') -ceq 'dns,dns-restore') 'service-failure-restores'
    New-ACase;$script:restoreFailure=$true;Reject-A {Invoke-DNSAcceptanceRoundTrip 'doh' $script:applyFixture};Assert-A (($script:actions -join ',') -ceq 'dns,dns-restore') 'cleanup-failure-propagates'
    New-ACase;$script:operationFailure=$true;$script:restoreFailure=$true;$aggregate=$null
    try{Invoke-DNSAcceptanceRoundTrip 'doh' $script:applyFixture}catch{$aggregate=$_.Exception;while($null -ne $aggregate -and $aggregate -isnot [AggregateException]){$aggregate=$aggregate.InnerException}}
    Assert-A ($null -ne $aggregate -and $aggregate.InnerExceptions.Count -eq 2 -and ($script:actions -join ',') -ceq 'dns,dns-restore') 'operation-and-cleanup-errors-retained'
    New-ACase;$script:registryFailure='IPv4';Reject-A {Invoke-DNSAcceptanceRoundTrip 'doh' $script:applyFixture};Assert-A ($script:actions.Count -eq 0) 'capture-failure-no-operation'
    New-ACase;Reject-A {Invoke-DNSAcceptanceRoundTrip 'invalid' $script:applyFixture};Assert-A ($script:actions.Count -eq 0 -and $script:dnsReads -eq 0) 'invalid-method-no-operation'
    New-ACase;$capturePhase='';[void](Read-DNSAcceptanceState ([ref]$capturePhase));Assert-A ($capturePhase -ceq 'complete') 'capture-stage-complete'
    New-ACase;$script:registryFailure='IPv6';$capturePhase='';$refused=$false
    try{[void](Read-DNSAcceptanceState ([ref]$capturePhase))}catch{$refused=$true}
    Assert-A ($refused -and $capturePhase -ceq 'registry-error-ipv6') 'capture-stage-refusal'
    foreach($failure in @('none','baseline','capability','selected','configuration','configured-state','ordinary-resolver','restoration','restored-state','dual')){
        New-ACase;$script:nativeBefore=Read-DNSAcceptanceState;Set-AConfigured 'doh';$script:nativeConfigured=Read-DNSAcceptanceState;$script:nativeAfter=Clone-A $script:nativeBefore
        $script:nativeActions=[Collections.Generic.List[string]]::new();$script:nativeFailure=$failure;$script:nativeResolves=0
        if($failure -ceq 'capability'){$script:nativeBefore.dohAvailable=$false;$script:nativeBefore.doh=@()}
        if($failure -ceq 'selected'){$script:nativeBefore.adapters[0].selected=$false}
        if($failure -ceq 'configured-state'){$script:nativeConfigured.adapters[0].ipv4.servers=@('192.0.2.53')}
        if($failure -ceq 'restoration'){$script:nativeAfter=Clone-A $script:nativeConfigured}
        if($failure -ceq 'restored-state'){$script:nativeAfter.adapters[0].ipv4.mode='static';$script:nativeAfter.adapters[0].ipv4.servers=@('198.51.100.53')}
        $result=Invoke-NativeDoHScenario -Apply {param($request)
            $script:nativeActions.Add($request.action)
            if(($request.action -ceq 'dns' -and $script:nativeFailure -cin @('configuration','dual')) -or ($request.action -ceq 'dns-restore' -and $script:nativeFailure -cin @('restoration','dual'))){throw 'fixture-native-boundary'}
        } -Capture {
            if($script:nativeActions.Count -eq 0){if($script:nativeFailure -ceq 'baseline'){throw 'fixture-native-baseline'};return $script:nativeBefore}
            if($script:nativeActions[$script:nativeActions.Count-1] -ceq 'dns'){return $script:nativeConfigured};return $script:nativeAfter
        } -Resolve {$script:nativeResolves++;if($script:nativeFailure -ceq 'ordinary-resolver'){throw 'fixture-native-resolver'}}
        $expectedOperation=if($failure -cin @('baseline','capability','selected')){'baseline'}elseif($failure -ceq 'dual'){'configuration'}elseif($failure -cin @('configuration','configured-state','ordinary-resolver')){$failure}else{'none'}
        $expectedRestoration=if($failure -ceq 'dual'){'restoration'}elseif($failure -ceq 'restoration'){'restoration'}else{'none'}
        $expectedVerification=if($failure -cin @('restoration','restored-state')){'restored-state'}else{'none'}
        Assert-A ($result.verificationCode -ceq $expectedVerification -and $result.operationCode -ceq $expectedOperation -and $result.restorationCode -ceq $expectedRestoration -and ($result.outcome -ceq 'passed') -eq ($failure -ceq 'none')) 'native-coordinator-result'
        if($expectedOperation -ceq 'baseline'){
            Assert-A ($script:nativeActions.Count -eq 0 -and -not $result.configurationAttempted -and -not $result.restorationAttempted) 'native-coordinator-cleanup'
        } else {
            Assert-A (($script:nativeActions -join ',') -ceq 'dns,dns-restore' -and $result.restorationAttempted -and $result.restoredStateVerified -eq ($expectedVerification -ceq 'none')) 'native-coordinator-cleanup'
        }
    }
    foreach($file in @('scripts/test-windows-integration.ps1','scripts/test-windows-reboot.ps1')){
        $tokens=$null;$issues=$null;$native=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project $file),[ref]$tokens,[ref]$issues)
        $calls=@($native.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
        $connected=if($file -like '*integration*'){@($calls | Where-Object {$_ -ceq 'Invoke-DNSAcceptanceRoundTrip'}).Count -eq 2}else{('Assert-DNSAcceptanceConfigured' -in $calls -and 'Assert-DNSAcceptanceRestored' -in $calls -and 'Get-DNSAcceptanceIndex' -in $calls)}
        Assert-A ($issues.Count -eq 0 -and $connected) 'native-harness-wiring'
    }
    foreach($file in $sourceFiles){if((Get-FileHash -LiteralPath (Join-Path $project $file) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sourceHashes[$file]){throw 'Acceptance source changed during contracts'}}
    $script:contractOutcome='passed';$script:contractCode='none'
    Write-Output ('DNS acceptance source contracts passed: '+$script:checks)
} finally {
    if($ReportPath){
        $parent=Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop
        if($parent.FullName -cne $reportParent.FullName -or $parent.CreationTimeUtc.Ticks -ne $reportCreated -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed acceptance report parent retained'}
        $commit=[string]$env:GITHUB_SHA
        if($commit -and $commit -notmatch '^[0-9a-f]{40}$'){throw 'Acceptance source identity invalid'}
        if($script:contractCode -notin $script:closedContractCodes){throw 'Acceptance report code invalid'}
        $report=@{schemaVersion=1;sourceCommit=$commit;sourceSHA256=$sourceHashes;edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();outcome=$script:contractOutcome;code=$script:contractCode;checks=$script:checks;realDnsChanged=$false;nativeDnsQualified=$false}
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $report -Compress -Depth 4))
        if($bytes.Length -gt 4096){throw 'Acceptance report exceeds fixed metadata limit'}
        $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
    }
}
