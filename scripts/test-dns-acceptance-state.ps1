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
$selected=@('Read-DNSAcceptanceRegistry','Get-DNSAcceptanceRegistryHash','Invoke-NativeDoHScenario','Invoke-NativeDNSRollbackScenario','New-NativeDNSFailureResponse','Get-NativeDNSVerificationMarker','Get-NativeDNSForwarderFailure','Convert-DNSAcceptanceGuid','Convert-DNSAcceptanceAddress','Read-DNSAcceptanceState','Get-DNSAcceptanceIndex','Assert-DNSAcceptanceRestored','Assert-DNSAcceptanceConfigured','Invoke-DNSAcceptanceRoundTrip')
$allowed=$selected+@('ConvertTo-Json','Get-NetAdapter','Get-ItemProperty','Get-DnsClientServerAddress','Get-Command','Get-DnsClientDohServerAddress','Where-Object','Get-Service','Clear-DnsClientCache','Resolve-DnsName')
foreach($name in $selected){
    $nodes=@($definitions | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Acceptance helper function unavailable'}
    foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
        $commandName=$command.GetCommandName()
        $callback=(-not $commandName -and $command.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and $command.CommandElements[0] -is [Management.Automation.Language.VariableExpressionAst] -and $command.CommandElements[0].VariablePath.UserPath -cin @('Apply','Capture','Resolve','InduceFailure','ResolveFailed','ResolveRestored','Configure','Observe','EmergencyRestore'))
        if(-not $callback -and $commandName -notin $allowed){throw 'Acceptance helper command boundary refused'}
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$script:checks=0;$script:contractOutcome='failed';$script:contractCode='unexpected-contract-error'
$script:closedContractCodes=@('forwarder-closed-error-map','rollback-native-result','rollback-native-flags','rollback-native-cleanup','rollback-native-order','rollback-native-preflight','fixed-dns-response','verification-marker-boundary','failure-native-result','failure-native-flags','failure-native-cleanup','failure-native-order','failure-native-preflight','roundtrip-does-not-inject','native-method-forwarded','native-invalid-method-no-effects','capture-identity-change-refused','unexposed-state-preserved','unexposed-state-not-selected','unexposed-access-refused','unexposed-registry-change-refused','single-family-configured-state','client-inventory-failure-phase','capture-stage-complete','capture-stage-refusal','native-coordinator-result','native-coordinator-cleanup','service-failure-restores','cleanup-failure-propagates','link-local-scope-follows-guid','none','unexpected-contract-error','unknown-test-code','expected-refusal','mixed-modes-captured','dhcp-lease-change-and-index-order-independent','guid-case-independent','read-inspection-refused','malformed-static-refused','invalid-saved-state-refused','legacy-state-refused','doh-capability-legacy-roundtrip','configured-method-positive','configured-method-negative','roundtrip-positive','resolver-failure-restores','operation-and-cleanup-errors-retained','capture-failure-no-operation','invalid-method-no-operation','native-harness-wiring')
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
    $script:renumberAfterInventory=$false;$script:exposure=@{};$script:registryAbsent=@{};$script:registryValues=@{};$script:data=New-AData;$script:doh=@((Original-ADoh));$script:available=$true;$script:registryFailure='';$script:dnsFailure='';$script:dohFailure=$false
    $script:resolveFailure=$false;$script:operationFailure=$false;$script:restoreFailure=$false;$script:serviceStatus='Running';$script:actions=[Collections.Generic.List[string]]::new();$script:dnsReads=0
}
function Clone-A([object]$Value){return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 14)}
function Get-NetAdapter {[CmdletBinding()]param();foreach($a in $script:adapters){[pscustomobject]@{InterfaceGuid=$a.InterfaceGuid;ifIndex=$a.ifIndex;Status=$a.Status;InterfaceDescription=$a.InterfaceDescription}}}
function Read-DNSAcceptanceRegistry([string]$Guid,[string]$Family) {
    if(-not $script:data.ContainsKey($Guid) -or $script:registryFailure -ceq $Family){throw 'fixture-registry-inspection'}
    $key=$Guid+'/'+$Family
    if($script:registryAbsent.ContainsKey($key) -and $script:registryAbsent[$key]){return @{present=$false;hasValue=$false;kind='absent';value=$null}}
    $mode=if($Family -ceq 'IPv4'){$script:data[$Guid].mode4}else{$script:data[$Guid].mode6}
    if($mode -ceq 'dhcp'){return @{present=$true;hasValue=$false;kind='absent';value=$null}}
    if($mode -ceq 'malformed'){return @{present=$true;hasValue=$true;kind='DWord';value=42}}
    return @{present=$true;hasValue=$true;kind='String';value=$(if($script:registryValues.ContainsKey($key)){$script:registryValues[$key]}else{'fixture-static-mode'})}
}
function Get-DnsClientServerAddress {
    [CmdletBinding()]param($InterfaceIndex,$AddressFamily)
    $script:dnsReads++
    if($script:dnsFailure -ceq 'failure'){throw 'fixture-client-inventory-failed'}
    if($script:dnsFailure -ceq 'empty'){return}
    foreach($a in $script:adapters){
        if($null -ne $InterfaceIndex -and $a.ifIndex -ne $InterfaceIndex){continue}
        $guid=([guid]$a.InterfaceGuid).ToString('D')
        foreach($family in @('IPv4','IPv6')){
            if($AddressFamily -and $family -cne $AddressFamily){continue}
            $key=$guid+'/'+$family
            if($script:exposure.ContainsKey($key) -and -not $script:exposure[$key]){continue}
            $values=if($family -ceq 'IPv4'){@($script:data[$guid].servers4)}else{@($script:data[$guid].servers6)}
            $result=[pscustomobject]@{InterfaceIndex=$a.ifIndex;AddressFamily=$(if($family -ceq 'IPv4'){2}else{23});ServerAddresses=@($values)}
            $result
            if($script:dnsFailure -ceq 'duplicate'){$result}
        }
    }
    if($null -eq $InterfaceIndex -and $script:renumberAfterInventory){$script:adapters[0].ifIndex=101;$script:renumberAfterInventory=$false}
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
    foreach($failure in @('registry4','registry6','dns-failure','dns-duplicate','doh','doh-duplicate','doh-flags','duplicate-guid','invalid-guid','empty-inventory','malformed-mode')){
        New-ACase
        switch($failure){
            'registry4' {$script:registryFailure='IPv4'}
            'registry6' {$script:registryFailure='IPv6'}
            'dns-failure' {$script:dnsFailure='failure'}
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
    New-ACase;$script:adapters[1].Status='Up';$script:exposure[$script:g2+'/IPv4']=$false;$script:exposure[$script:g2+'/IPv6']=$false;$script:registryAbsent[$script:g2+'/IPv4']=$true;$script:registryAbsent[$script:g2+'/IPv6']=$true
    $before=Read-DNSAcceptanceState
    Assert-A (-not $before.adapters[1].selected -and $before.adapters[1].ipv4.mode -ceq 'not-exposed' -and $before.adapters[1].ipv6.mode -ceq 'not-exposed' -and $before.adapters[1].ipv4.registryHash -match '^[a-f0-9]{64}$') 'unexposed-state-not-selected'
    Set-AConfigured 'doh';Assert-DNSAcceptanceConfigured $before (Read-DNSAcceptanceState) 'doh';$script:data=New-AData;$script:doh=@((Original-ADoh));Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);Assert-A $true 'unexposed-state-preserved'
    $script:registryFailure='IPv4';Reject-A {Read-DNSAcceptanceState};Assert-A ($script:actions.Count -eq 0) 'unexposed-access-refused'
    New-ACase;$script:exposure[$script:g2+'/IPv4']=$false;$before=Read-DNSAcceptanceState;$script:registryValues[$script:g2+'/IPv4']='changed dormant configuration'
    Reject-A {Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState)};Assert-A $true 'unexposed-registry-change-refused'
    foreach($family in @('IPv4','IPv6')){
        New-ACase;$other=if($family -ceq 'IPv4'){'IPv6'}else{'IPv4'};$script:exposure[$script:g1+'/'+$other]=$false;$before=Read-DNSAcceptanceState
        Set-AConfigured 'doh';if($other -ceq 'IPv4'){$script:data[$script:g1].mode4='dhcp'}
        Assert-DNSAcceptanceConfigured $before (Read-DNSAcceptanceState) 'doh';Assert-A $true 'single-family-configured-state'
    }
    New-ACase;$script:dnsFailure='failure';$capturePhase='';$refused=$false
    try{[void](Read-DNSAcceptanceState ([ref]$capturePhase))}catch{$refused=$true}
    Assert-A ($refused -and $capturePhase -ceq 'dns-inventory') 'client-inventory-failure-phase'
    New-ACase;$script:renumberAfterInventory=$true;Reject-A {Read-DNSAcceptanceState};Assert-A ($script:actions.Count -eq 0) 'capture-identity-change-refused'
    New-ACase;$capturePhase='';[void](Read-DNSAcceptanceState ([ref]$capturePhase));Assert-A ($capturePhase -ceq 'complete') 'capture-stage-complete'
    New-ACase;$script:registryFailure='IPv6';$capturePhase='';$refused=$false
    try{[void](Read-DNSAcceptanceState ([ref]$capturePhase))}catch{$refused=$true}
    Assert-A ($refused -and $capturePhase -ceq 'registry-error-ipv6') 'capture-stage-refusal'
    foreach($method in @('doh','dnscrypt')){
    foreach($failure in @('none','baseline','capability','selected','configuration','configured-state','ordinary-resolver','restoration','restored-state','dual')){
        New-ACase;$script:nativeBefore=Read-DNSAcceptanceState;Set-AConfigured $method;$script:nativeConfigured=Read-DNSAcceptanceState;$script:nativeAfter=Clone-A $script:nativeBefore
        $script:nativeActions=[Collections.Generic.List[string]]::new();$script:nativeFailure=$failure;$script:nativeResolves=0
        if($failure -ceq 'capability'){foreach($state in @($script:nativeBefore,$script:nativeConfigured,$script:nativeAfter)){$state.dohAvailable=$false;$state.doh=@()}}
        if($failure -ceq 'selected'){$script:nativeBefore.adapters[0].selected=$false}
        if($failure -ceq 'configured-state'){$script:nativeConfigured.adapters[0].ipv4.servers=@('192.0.2.53')}
        if($failure -ceq 'restoration'){$script:nativeAfter=Clone-A $script:nativeConfigured}
        if($failure -ceq 'restored-state'){$script:nativeAfter.adapters[0].ipv4.mode='static';$script:nativeAfter.adapters[0].ipv4.servers=@('198.51.100.53')}
        $result=Invoke-NativeDoHScenario -Method $method -Apply {param($request)
            if($request.action -ceq 'dns'){Assert-A ($request.dns -ceq $method) 'native-method-forwarded'}
            $script:nativeActions.Add($request.action)
            if(($request.action -ceq 'dns' -and $script:nativeFailure -cin @('configuration','dual')) -or ($request.action -ceq 'dns-restore' -and $script:nativeFailure -cin @('restoration','dual'))){throw 'fixture-native-boundary'}
        } -Capture {
            if($script:nativeActions.Count -eq 0){if($script:nativeFailure -ceq 'baseline'){throw 'fixture-native-baseline'};return $script:nativeBefore}
            if($script:nativeActions[$script:nativeActions.Count-1] -ceq 'dns'){return $script:nativeConfigured};return $script:nativeAfter
        } -Resolve {$script:nativeResolves++;if($script:nativeFailure -ceq 'ordinary-resolver'){throw 'fixture-native-resolver'}}
        Assert-A (-not $result.failureInjected -and -not $result.failedResolverVerified -and -not $result.restoredResolverVerified) 'roundtrip-does-not-inject'
        $expectedOperation=if($failure -cin @('baseline','selected') -or ($method -ceq 'doh' -and $failure -ceq 'capability')){'baseline'}elseif($failure -ceq 'dual'){'configuration'}elseif($failure -cin @('configuration','configured-state','ordinary-resolver')){$failure}else{'none'}
        $expectedRestoration=if($failure -ceq 'dual'){'restoration'}elseif($failure -ceq 'restoration'){'restoration'}else{'none'}
        $expectedVerification=if($failure -cin @('restoration','restored-state')){'restored-state'}else{'none'}
        Assert-A ($result.verificationCode -ceq $expectedVerification -and $result.operationCode -ceq $expectedOperation -and $result.restorationCode -ceq $expectedRestoration -and ($result.outcome -ceq 'passed') -eq ($failure -ceq 'none' -or ($method -ceq 'dnscrypt' -and $failure -ceq 'capability'))) 'native-coordinator-result'
        if($expectedOperation -ceq 'baseline'){
            Assert-A ($script:nativeActions.Count -eq 0 -and -not $result.configurationAttempted -and -not $result.restorationAttempted) 'native-coordinator-cleanup'
        } else {
            Assert-A (($script:nativeActions -join ',') -ceq 'dns,dns-restore' -and $result.restorationAttempted -and $result.restoredStateVerified -eq ($expectedVerification -ceq 'none')) 'native-coordinator-cleanup'
        }
    }
    }
    foreach($invalid in @('DOH','DNSCRYPT','','auto','unknown')){
        $script:nativeActions.Clear();$script:nativeResolves=0;$script:invalidCaptures=0
        $invalidResult=Invoke-NativeDoHScenario -Method $invalid -Apply {$script:nativeActions.Add('invalid')} -Capture {$script:invalidCaptures++;return $script:nativeBefore} -Resolve {$script:nativeResolves++}
        Assert-A ($invalidResult.operationCode -ceq 'baseline' -and $script:nativeActions.Count -eq 0 -and $script:invalidCaptures -eq 0 -and $script:nativeResolves -eq 0) 'native-invalid-method-no-effects'
    }
    foreach($failure in @('none','baseline','configuration','configured-state','ordinary-resolver','fault-injection','failed-resolver','restoration','restored-state','restored-resolver','dual')){
        New-ACase;$script:nativeBefore=Read-DNSAcceptanceState;Set-AConfigured 'dnscrypt';$script:nativeConfigured=Read-DNSAcceptanceState;$script:nativeAfter=Clone-A $script:nativeBefore
        $script:nativeFailure=$failure;$script:failureTrace=[Collections.Generic.List[string]]::new();$script:failureRestoreAttempted=$false
        if($failure -ceq 'configured-state'){$script:nativeConfigured.adapters[0].ipv4.servers=@('192.0.2.53')}
        if($failure -ceq 'restoration'){$script:nativeAfter=Clone-A $script:nativeConfigured}
        if($failure -ceq 'restored-state'){$script:nativeAfter.adapters[0].ipv4.mode='static';$script:nativeAfter.adapters[0].ipv4.servers=@('198.51.100.53')}
        $result=Invoke-NativeDoHScenario -Method 'dnscrypt' -ScenarioKind 'service-loss' -Apply {param($request)
            if($request.action -ceq 'dns'){
                $script:failureTrace.Add('configure')
                if($script:nativeFailure -cin @('configuration','dual')){throw 'fixture-failure-configuration'}
            }else{
                $script:failureTrace.Add('restore');$script:failureRestoreAttempted=$true
                if($script:nativeFailure -cin @('restoration','dual')){throw 'fixture-failure-restoration'}
            }
        } -Capture {
            $script:failureTrace.Add('capture')
            if($script:failureRestoreAttempted){return $script:nativeAfter}
            if('configure' -in $script:failureTrace){return $script:nativeConfigured}
            if($script:nativeFailure -ceq 'baseline'){throw 'fixture-failure-baseline'}
            return $script:nativeBefore
        } -Resolve {
            $script:failureTrace.Add('resolve')
            if($script:nativeFailure -ceq 'ordinary-resolver'){throw 'fixture-failure-query'}
        } -InduceFailure {
            $script:failureTrace.Add('inject')
            if($script:nativeFailure -ceq 'fault-injection'){throw 'fixture-failure-injection'}
        } -ResolveFailed {
            $script:failureTrace.Add('failed-query')
            if($script:nativeFailure -ceq 'failed-resolver'){throw 'fixture-failure-not-observed'}
        } -ResolveRestored {
            $script:failureTrace.Add('recovered-query')
            if($script:nativeFailure -ceq 'restored-resolver'){throw 'fixture-recovered-query-failed'}
        }
        $operation=if($failure -ceq 'dual'){'configuration'}elseif($failure -cin @('baseline','configuration','configured-state','ordinary-resolver','fault-injection','failed-resolver')){$failure}else{'none'}
        $restore=if($failure -cin @('restoration','dual')){'restoration'}else{'none'}
        $verify=if($failure -cin @('restoration','restored-state')){'restored-state'}elseif($failure -ceq 'restored-resolver'){'restored-resolver'}else{'none'}
        Assert-A (($result.outcome -ceq 'passed') -eq ($failure -ceq 'none') -and $result.operationCode -ceq $operation -and $result.restorationCode -ceq $restore -and $result.verificationCode -ceq $verify) 'failure-native-result'
        $injected=$failure -cin @('none','failed-resolver','restoration','restored-state','restored-resolver')
        $failedQuery=$failure -cin @('none','restoration','restored-state','restored-resolver')
        $recovered=$failure -cnotin @('baseline','restoration','restored-state','restored-resolver')
        Assert-A ($result.failureInjected -eq $injected -and $result.failedResolverVerified -eq $failedQuery -and $result.restoredResolverVerified -eq $recovered) 'failure-native-flags'
        Assert-A ($result.restorationAttempted -eq ($failure -cne 'baseline') -and @($script:failureTrace | Where-Object {$_ -ceq 'restore'}).Count -eq $(if($failure -ceq 'baseline'){0}else{1})) 'failure-native-cleanup'
        if($failure -ceq 'none'){Assert-A (($script:failureTrace -join ',') -ceq 'capture,configure,capture,resolve,inject,failed-query,restore,capture,recovered-query') 'failure-native-order'}
    }
    foreach($invalid in @('wrong-method','missing-injection','missing-failed-query','missing-recovered-query','unknown-kind','wrong-case-kind')){
        $script:invalidEffects=0
        $boundary={$script:invalidEffects++}
        $parameters=@{Method='dnscrypt';ScenarioKind='service-loss';Apply=$boundary;Capture=$boundary;Resolve=$boundary;InduceFailure=$boundary;ResolveFailed=$boundary;ResolveRestored=$boundary}
        switch -CaseSensitive ($invalid){
            'wrong-method' {$parameters.Method='doh'}
            'missing-injection' {$parameters.Remove('InduceFailure')}
            'missing-failed-query' {$parameters.Remove('ResolveFailed')}
            'missing-recovered-query' {$parameters.Remove('ResolveRestored')}
            'unknown-kind' {$parameters.ScenarioKind='unknown'}
            'wrong-case-kind' {$parameters.ScenarioKind='SERVICE-LOSS'}
        }
        $result=Invoke-NativeDoHScenario @parameters
        Assert-A ($result.operationCode -ceq 'baseline' -and $script:invalidEffects -eq 0 -and -not $result.configurationAttempted -and -not $result.restorationAttempted) 'failure-native-preflight'
    }
    # Synthetic DNS packets for the fixture's one public query name only.
    $packet=[byte[]]::new(29);$packet[0]=0x12;$packet[1]=0x34;$packet[2]=1;$packet[5]=1;$packet[12]=7;$packet[20]=3;$packet[26]=1;$packet[28]=1
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('example'),0,$packet,13,7);[Array]::Copy([Text.Encoding]::ASCII.GetBytes('com'),0,$packet,21,3)
    foreach($type in @(1,28,65)){
        $copy=[byte[]]$packet.Clone();$copy[26]=[byte]$type;$reply=New-NativeDNSFailureResponse $copy
        Assert-A ($reply -is [byte[]] -and $reply.Length -eq 29 -and $reply[0] -eq 0x12 -and $reply[1] -eq 0x34 -and $reply[2] -eq 0x81 -and $reply[3] -eq 0x82 -and $reply[26] -eq $type -and $reply[10] -eq 0 -and $reply[11] -eq 0 -and $copy[2] -eq 1 -and $copy[3] -eq 0) 'fixed-dns-response'
    }
    $edns=[byte[]]::new(40);[Array]::Copy($packet,$edns,29);$edns[11]=1;$edns[31]=41;$edns[32]=4;$edns[33]=0xd0
    $reply=New-NativeDNSFailureResponse $edns;Assert-A ($reply.Length -eq 29 -and $reply[11] -eq 0 -and $edns[11] -eq 1) 'fixed-dns-response'
    foreach($change in @(@{i=2;v=0x80},@{i=2;v=8},@{i=5;v=2},@{i=7;v=1},@{i=9;v=1},@{i=11;v=1},@{i=11;v=2},@{i=12;v=0xc0},@{i=13;v=120},@{i=20;v=2},@{i=24;v=1},@{i=25;v=1},@{i=26;v=255},@{i=28;v=2})){
        $bad=[byte[]]$packet.Clone();$bad[$change.i]=[byte]$change.v;Reject-A {New-NativeDNSFailureResponse $bad}
    }
    foreach($length in @(0,28,30,4097)){Reject-A {New-NativeDNSFailureResponse ([byte[]]::new($length))}}
    foreach($change in @(@{i=31;v=1},@{i=34;v=1},@{i=35;v=1},@{i=39;v=1})){$bad=[byte[]]$edns.Clone();$bad[$change.i]=[byte]$change.v;Reject-A {New-NativeDNSFailureResponse $bad}}
    $marker='Resolver verification failed; original DNS settings restored:'
    for($split=0;$split -le $marker.Length;$split++){
        $first=Get-NativeDNSVerificationMarker '' ('prefix'+$marker.Substring(0,$split));$second=Get-NativeDNSVerificationMarker $first.suffix ($marker.Substring($split)+'suffix')
        Assert-A ($first.matched -or $second.matched) 'verification-marker-boundary'
        Assert-A ($first.suffix.Length -lt $marker.Length -and $second.suffix.Length -lt $marker.Length) 'verification-marker-boundary'
    }
    Assert-A (-not (Get-NativeDNSVerificationMarker '' 'unrelated synthetic output').matched) 'verification-marker-boundary'
    Reject-A {Get-NativeDNSVerificationMarker ('x'*$marker.Length) ''};Reject-A {Get-NativeDNSVerificationMarker '' ('x'*4097)}
    foreach($failure in @('none','baseline','baseline-resolver','configuration','accepted','nonboolean','observation','missing-configured','missing-forwarded','malformed-observation','restored-state','restored-resolver','emergency-failure')){
        New-ACase;$script:nativeBefore=Read-DNSAcceptanceState;Set-AConfigured 'dnscrypt';$script:nativeConfigured=Read-DNSAcceptanceState;$script:nativeAfter=Clone-A $script:nativeBefore
        $script:nativeFailure=$failure;$script:rollbackTrace=[Collections.Generic.List[string]]::new();$script:rollbackConfigured=$false;$script:rollbackQueries=0
        if($failure -cin @('restored-state','emergency-failure')){$script:nativeAfter=Clone-A $script:nativeConfigured}
        $result=Invoke-NativeDNSRollbackScenario -Configure {
            $script:rollbackTrace.Add('configure');$script:rollbackConfigured=$true
            if($script:nativeFailure -ceq 'configuration'){throw 'fixture-configure-fault'}
            if($script:nativeFailure -ceq 'accepted'){return $false};if($script:nativeFailure -ceq 'nonboolean'){return 1};return $true
        } -Capture {
            $script:rollbackTrace.Add('capture')
            if($script:rollbackConfigured){return $script:nativeAfter}
            if($script:nativeFailure -ceq 'baseline'){throw 'fixture-baseline-fault'};return $script:nativeBefore
        } -Observe {
            $script:rollbackTrace.Add('observe')
            if($script:nativeFailure -ceq 'observation'){throw 'fixture-observation-fault'}
            if($script:nativeFailure -ceq 'malformed-observation'){return @{configured=1;forwarded=$true}}
            return @{configured=($script:nativeFailure -cne 'missing-configured');forwarded=($script:nativeFailure -cne 'missing-forwarded')}
        } -Resolve {
            $script:rollbackQueries++;$script:rollbackTrace.Add('resolve')
            if(($script:rollbackQueries -eq 1 -and $script:nativeFailure -ceq 'baseline-resolver') -or ($script:rollbackQueries -eq 2 -and $script:nativeFailure -ceq 'restored-resolver')){throw 'fixture-resolver-fault'}
        } -EmergencyRestore {
            $script:rollbackTrace.Add('emergency')
            if($script:nativeFailure -ceq 'emergency-failure'){throw 'fixture-emergency-fault'}
        }
        $operation=if($failure -cin @('baseline','baseline-resolver')){'baseline'}elseif($failure -cin @('configuration','accepted','nonboolean')){'configuration'}elseif($failure -cin @('observation','missing-configured','missing-forwarded','malformed-observation')){'effects-observation'}else{'none'}
        $recovery=if($failure -cin @('restored-state','emergency-failure')){'restored-state'}elseif($failure -ceq 'restored-resolver'){'restored-resolver'}else{'none'}
        Assert-A (($result.outcome -ceq 'passed') -eq ($failure -ceq 'none') -and $result.operationCode -ceq $operation -and $result.recoveryCode -ceq $recovery) 'rollback-native-result'
        $expectedEmergency=$failure -cin @('restored-state','emergency-failure')
        Assert-A ($result.emergencyRestoreAttempted -eq $expectedEmergency -and @($script:rollbackTrace | Where-Object {$_ -ceq 'emergency'}).Count -eq $(if($expectedEmergency){1}else{0})) 'rollback-native-cleanup'
        if($failure -ceq 'none'){
            Assert-A ($result.configurationRejected -and $result.configuredStateObserved -and $result.forwardedFailureObserved -and $result.originalStateRestored -and $result.restoredResolverPassed) 'rollback-native-flags'
            Assert-A (($script:rollbackTrace -join ',') -ceq 'capture,resolve,configure,observe,capture,resolve') 'rollback-native-order'
        }
    }
    foreach($missing in @('Configure','Capture','Observe','Resolve','EmergencyRestore')){
        $script:invalidEffects=0;$boundary={$script:invalidEffects++};$parameters=@{Configure=$boundary;Capture=$boundary;Observe=$boundary;Resolve=$boundary;EmergencyRestore=$boundary};$parameters.Remove($missing)
        $result=Invoke-NativeDNSRollbackScenario @parameters
        Assert-A ($result.operationCode -ceq 'baseline' -and $script:invalidEffects -eq 0 -and -not $result.configurationAttempted -and -not $result.emergencyRestoreAttempted) 'rollback-native-preflight'
    }
    $peer=[Net.Sockets.SocketException]::new(10054);$other=[Net.Sockets.SocketException]::new(10013)
    Assert-A ((Get-NativeDNSForwarderFailure $peer) -ceq 'peer-closed') 'forwarder-closed-error-map'
    Assert-A ((Get-NativeDNSForwarderFailure ([InvalidOperationException]::new('synthetic-wrapper',$peer))) -ceq 'peer-closed') 'forwarder-closed-error-map'
    Assert-A ((Get-NativeDNSForwarderFailure $other) -ceq 'socket-io') 'forwarder-closed-error-map'
    Assert-A ((Get-NativeDNSForwarderFailure ([InvalidOperationException]::new('unrecognized synthetic text'))) -ceq 'unexpected-io') 'forwarder-closed-error-map'
    foreach($pair in @(@('Forwarded DNS packet bound exceeded','packet-bound'),@('Forwarded DNS request count exceeded','request-bound'),@('Non-loopback forwarder peer refused','peer-bound'),@('Forwarded DNS error response incomplete','response-write'),@('Fixed DNS EDNS shape refused','packet-shape'))){
        Assert-A ((Get-NativeDNSForwarderFailure ([InvalidOperationException]::new($pair[0]))) -ceq $pair[1]) 'forwarder-closed-error-map'
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
