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
# PowerShell 5.1 Get-FileHash is a function that calls Test-Path. The
# deliberately closed Test-Path mock below must not intercept source hashing.
function Get-ASourceSHA256([string]$File) {
    $stream=[IO.File]::OpenRead($File);$algorithm=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
    finally{$algorithm.Dispose();$stream.Dispose()}
}
$sourceHashes=@{};foreach($file in $sourceFiles){$sourceHashes[$file]=Get-ASourceSHA256 (Join-Path $project $file)}
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Acceptance helper source did not parse'}
$definitions=@($ast.EndBlock.Statements)
$tokens=$null;$issues=$null;$coordinator=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'native-doh-scenario.ps1'),[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Native coordinator source did not parse'}
$definitions+=@($coordinator.EndBlock.Statements)
$selected=@('Get-NativeDNSStaticFailure','Invoke-NativeDNSStaticFixture','Read-DNSAcceptanceRegistry','Get-DNSAcceptanceRegistryHash','Invoke-NativeDoHScenario','Invoke-NativeDNSJournalScenario','Invoke-NativeDNSRollbackScenario','New-NativeDNSFailureResponse','Get-NativeDNSVerificationMarker','Get-NativeDNSForwarderFailure','Get-NativeDNSComponentFailure','Get-NativeDNSComponentRetry','Convert-DNSAcceptanceGuid','Convert-DNSAcceptanceAddress','Read-DNSAcceptanceState','Get-DNSAcceptanceIndex','Assert-DNSAcceptanceRestored','Assert-DNSAcceptanceConfigured','Invoke-DNSAcceptanceRoundTrip')
$allowed=$selected+@('ConvertTo-Json','Get-NetAdapter','Get-ItemProperty','Get-DnsClientServerAddress','Get-Command','Get-DnsClientDohServerAddress','Where-Object','Get-Service','Clear-DnsClientCache','Resolve-DnsName')
foreach($name in $selected){
    $nodes=@($definitions | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Acceptance helper function unavailable'}
    foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
        $commandName=$command.GetCommandName()
        $callback=(-not $commandName -and $command.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and $command.CommandElements[0] -is [Management.Automation.Language.VariableExpressionAst] -and $command.CommandElements[0].VariablePath.UserPath -cin @('Apply','Capture','Resolve','InduceFailure','ResolveFailed','ResolveRestored','ReadBinding','Configure','Observe','EmergencyRestore','Stage','Exercise','Unstage'))
        if(-not $callback -and $commandName -notin $allowed){throw 'Acceptance helper command boundary refused'}
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$script:checks=0;$script:contractOutcome='failed';$script:contractCode='unexpected-contract-error'
$script:closedContractCodes=@('static-stage-source','static-resolver-source-callback','static-closed-failure-map','static-fixture-result','static-fixture-cleanup','static-fixture-order','static-fixture-flags','static-fixture-preflight','component-retry-contract','component-closed-error-map','forwarder-closed-error-map','rollback-native-result','rollback-native-flags','rollback-native-cleanup','rollback-native-order','rollback-native-preflight','fixed-dns-response','journal-scenario-order','journal-scenario-result','journal-scenario-private-output','journal-refusal-marker','verification-marker-boundary','failure-native-result','failure-native-flags','failure-native-cleanup','failure-native-order','failure-native-preflight','roundtrip-does-not-inject','native-method-forwarded','native-invalid-method-no-effects','capture-identity-change-refused','unexposed-state-preserved','unexposed-state-not-selected','unexposed-access-refused','unexposed-registry-change-refused','single-family-configured-state','client-inventory-failure-phase','capture-stage-complete','capture-stage-refusal','native-coordinator-result','native-coordinator-cleanup','service-failure-restores','cleanup-failure-propagates','link-local-scope-follows-guid','none','unexpected-contract-error','unknown-test-code','expected-refusal','mixed-modes-captured','dhcp-lease-change-and-index-order-independent','guid-case-independent','read-inspection-refused','malformed-static-refused','invalid-saved-state-refused','legacy-state-refused','doh-capability-legacy-roundtrip','configured-method-positive','configured-method-negative','roundtrip-positive','resolver-failure-restores','operation-and-cleanup-errors-retained','capture-failure-no-operation','invalid-method-no-operation','native-harness-wiring')
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
    $script:staticStagingWrites=0;$script:staticWaitCalls=0;$script:staticPendingReads=0;$script:staticPendingShape='';$script:staticTeardownFault='';$script:resolveFailure=$false;$script:operationFailure=$false;$script:restoreFailure=$false;$script:serviceStatus='Running';$script:actions=[Collections.Generic.List[string]]::new();$script:dnsReads=0
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
    if($script:dnsFailure -ceq 'failure' -or ($script:staticTeardownFault -ceq 'verification-read' -and $null -eq $InterfaceIndex)){throw 'fixture-client-inventory-failed'}
    if($script:dnsFailure -ceq 'empty'){return}
    foreach($a in $script:adapters){
        if($null -ne $InterfaceIndex -and $a.ifIndex -ne $InterfaceIndex){continue}
        $guid=([guid]$a.InterfaceGuid).ToString('D')
        foreach($family in @('IPv4','IPv6')){
            if($AddressFamily -and $family -cne $AddressFamily){continue}
            $key=$guid+'/'+$family
            if($script:exposure.ContainsKey($key) -and -not $script:exposure[$key]){continue}
            $values=if($family -ceq 'IPv4'){@($script:data[$guid].servers4)}else{@($script:data[$guid].servers6)}
            if($null -eq $InterfaceIndex -and $guid -ceq $script:g1 -and $family -ceq 'IPv6' -and ($values -join ',') -ceq 'fe80::53,fe80::54' -and $script:staticPendingReads -gt 0){
                $script:staticPendingReads--;if($script:staticPendingShape -ceq 'empty'){$values=@()}else{$values=@($values[0])}
            }
            $result=[pscustomobject]@{InterfaceIndex=$a.ifIndex;AddressFamily=$(if($family -ceq 'IPv4'){2}else{23});ServerAddresses=@($values)}
            $result
            if($script:dnsFailure -ceq 'duplicate'){$result}
        }
    }
    if($null -eq $InterfaceIndex -and $script:renumberAfterInventory){$script:adapters[0].ifIndex=101;$script:renumberAfterInventory=$false}
}
function Get-Command {[CmdletBinding()]param([string]$Name);if($Name -cne 'Get-DnsClientDohServerAddress'){throw 'Unexpected acceptance command discovery'};if($script:available){return [pscustomobject]@{Name=$Name}}}
function Get-DnsClientDohServerAddress {[CmdletBinding()]param();if($script:dohFailure){throw 'fixture-doh-inspection'};return $script:doh}
function Get-Service {[CmdletBinding()]param($Name);if($Name -ceq 'MpsSvc'){return [pscustomobject]@{Status='Running'}};if($Name -cne 'AccessWeaver-dnscrypt'){throw 'Unexpected acceptance service'};return [pscustomobject]@{Status=$script:serviceStatus}}
function Clear-DnsClientCache {[CmdletBinding()]param()}
function Resolve-DnsName {[CmdletBinding()]param($Name,[switch]$DnsOnly,[switch]$QuickTimeout);if($Name -cne 'example.com' -or -not $DnsOnly -or -not $QuickTimeout){throw 'Unexpected acceptance resolver boundary'};if($script:resolveFailure){throw 'fixture-resolver-failure'};return [pscustomobject]@{Name='example.com'}}
function Set-AConfigured([string]$Method) {
    $script:data[$script:g1].mode4='static';$script:data[$script:g1].mode6='static'
    $script:data[$script:g1].servers4=if($Method -ceq 'doh'){@('8.8.8.8','9.9.9.9')}else{@('127.0.0.1')}
    $script:data[$script:g1].servers6=if($Method -ceq 'doh'){@('2001:4860:4860::8888','2620:fe::fe')}else{@('::1')}
    if($Method -ceq 'doh'){
        foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
            $template=switch -CaseSensitive ($address){'8.8.8.8'{'https://8.8.8.8/dns-query'}'9.9.9.9'{'https://9.9.9.9/dns-query'}'2001:4860:4860::8888'{'https://[2001:4860:4860::8888]/dns-query'}'2620:fe::fe'{'https://[2620:fe::fe]/dns-query'}default{throw 'Unexpected fixed DoH provider'}}
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
    # Each provider must reject its old hostname bootstrap and a foreign IP
    # authority. These mutations exercise the independent native readback oracle.
    foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
        $legacy=if($address -in @('8.8.8.8','2001:4860:4860::8888')){'https://dns.google/dns-query'}else{'https://dns.quad9.net/dns-query'}
        foreach($wrong in @($legacy,'https://192.0.2.90/dns-query')){
            New-ACase;$before=Read-DNSAcceptanceState;Set-AConfigured 'doh';$current=Read-DNSAcceptanceState
            @($current.doh | Where-Object {$_.address -ceq $address})[0].template=$wrong
            Reject-A {Assert-DNSAcceptanceConfigured $before $current 'doh'};Assert-A $true 'configured-method-negative'
        }
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
    foreach($failure in @('none','baseline','first-configuration','first-binding','second-configuration','second-binding','stale-journal','configured-state','current-journal','restored-state','restored-resolver')){
        New-ACase
        $script:journalBaseline=Read-DNSAcceptanceState
        Set-AConfigured 'doh'
        $script:journalConfigured=Read-DNSAcceptanceState
        $script:journalAfter=Clone-A $script:journalBaseline
        if($failure -ceq 'restored-state'){$script:journalAfter=Clone-A $script:journalConfigured}
        $script:journalTrace=[Collections.Generic.List[string]]::new()
        $script:journalConfigures=0;$script:journalQueries=0
        $first=@{journalId=('workflow-'+('a'*32)+'.json');digest=('c'*64)}
        $current=@{journalId=('workflow-'+('b'*32)+'.json');digest=('d'*64)}
        $result=Invoke-NativeDNSJournalScenario -Apply {
            param($request,[switch]$ExpectStaleJournal)
            $phase=switch -CaseSensitive ($request.action){
                'dns' {
                    if($request.dns -cne 'doh'){throw 'Unexpected DNS method'}
                    $script:journalConfigures++
                    if($script:journalConfigures -eq 1){'first-configuration'}else{'second-configuration'}
                }
                'recover' {
                    if($ExpectStaleJournal -and $request.journalId -ceq $first.journalId){'stale-journal'}
                    elseif(-not $ExpectStaleJournal -and $request.journalId -ceq $current.journalId){'current-journal'}
                    else{throw 'Unexpected journal identity'}
                }
                'dns-restore' {'emergency-restore'}
                default {throw 'Unexpected journal scenario action'}
            }
            $script:journalTrace.Add($phase)
            if($phase -ceq $failure){throw 'Fixture apply failed'}
        } -Capture {
            if($failure -ceq 'baseline'){throw 'Fixture baseline failed'}
            if($script:journalConfigures -eq 0 -or $script:journalTrace -contains 'emergency-restore'){return $script:journalBaseline}
            if($script:journalTrace -contains 'current-journal'){return $script:journalAfter}
            return $script:journalConfigured
        } -Resolve {
            $script:journalQueries++
            if($script:journalQueries -eq 2 -and $failure -ceq 'restored-resolver'){throw 'Fixture restored query failed'}
        } -ReadBinding {
            param($Previous,$KnownCurrent)
            if(-not $Previous){
                if($failure -ceq 'first-binding'){throw 'Fixture first binding failed'}
                return $first
            }
            if($Previous -cne $first.journalId){throw 'Unexpected previous journal'}
            if($failure -ceq 'second-binding'){return $first}
            if($KnownCurrent){
                if($KnownCurrent -cne $current.journalId){throw 'Unexpected current journal'}
                if($failure -ceq 'configured-state'){return $first}
            }
            return $current
        }
        $passed=($failure -ceq 'none')
        $emergency=($failure -cnotin @('none','baseline'))
        Assert-A (($result.outcome -ceq 'passed') -eq $passed -and $result.code -ceq $failure -and
            $result.emergencyRestoreAttempted -eq $emergency -and $result.emergencyRestoreAccepted -eq $emergency -and
            $result.emergencyStateVerified -eq $emergency) 'journal-scenario-result'
        if($passed){
            Assert-A (($script:journalTrace -join ',') -ceq 'first-configuration,second-configuration,stale-journal,current-journal' -and
                $script:journalQueries -eq 2 -and $result.firstBindingVerified -and $result.bindingRotated -and
                $result.staleJournalRejected -and $result.configuredStatePreserved -and $result.currentJournalRecovered -and
                $result.restoredStateVerified -and $result.restoredResolverVerified) 'journal-scenario-order'
        }elseif($emergency){
            Assert-A ($script:journalTrace[$script:journalTrace.Count-1] -ceq 'emergency-restore') 'journal-scenario-order'
        }else{
            Assert-A ($script:journalTrace.Count -eq 0 -and $script:journalQueries -eq 0) 'journal-scenario-order'
        }
        $report=Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $result -Compress
        Assert-A ($report -cnotmatch 'workflow-|[a-f0-9]{64}') 'journal-scenario-private-output'
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
    $staleMarker='DNS recovery journal does not match the active snapshot; review dns-restore'
    for($split=0;$split -le $staleMarker.Length;$split++){
        $first=Get-NativeDNSVerificationMarker '' $staleMarker.Substring(0,$split) -StaleJournal
        $second=Get-NativeDNSVerificationMarker $first.suffix $staleMarker.Substring($split) -StaleJournal
        Assert-A (($first.matched -or $second.matched) -and $second.suffix.Length -lt $staleMarker.Length) 'journal-refusal-marker'
    }
    Assert-A (-not (Get-NativeDNSVerificationMarker '' $staleMarker).matched -and
        -not (Get-NativeDNSVerificationMarker '' $marker -StaleJournal).matched) 'journal-refusal-marker'
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
    foreach($pair in @(@('No dual-family native static fixture adapter','no-family'),@('No active native link-local interface','no-link-local'),@('Static fixture adapter identity changed','adapter-changed'),@('Static fixture family changed','family-changed'))){Assert-A ((Get-NativeDNSStaticFailure ([InvalidOperationException]::new($pair[0]))) -ceq $pair[1]) 'static-closed-failure-map'}
    Assert-A ((Get-NativeDNSStaticFailure ([ArgumentException]::new('synthetic-private-value'))) -ceq 'argument') 'static-closed-failure-map'
    Assert-A ((Get-NativeDNSStaticFailure ([InvalidOperationException]::new('synthetic-wrapper',[InvalidCastException]::new('synthetic-private-value')))) -ceq 'cast') 'static-closed-failure-map'
    Assert-A ((Get-NativeDNSStaticFailure ([InvalidOperationException]::new('synthetic-private-value'))) -ceq 'unexpected') 'static-closed-failure-map'
    foreach($pair in @(@('DNS acceptance adapter inventory changed','state-inventory'),@('DNS acceptance original adapter is missing','state-adapter'),@('DNS acceptance original DHCP/static mode differs','state-mode'),@('DNS acceptance dormant registry state differs','state-dormant'),@('DNS acceptance original static server count differs','state-count'),@('DNS acceptance original static server order or value differs','state-order'),@('DNS acceptance original DoH capability or inventory differs','state-doh-inventory'),@('DNS acceptance original DoH entry is missing','state-doh-entry'),@('DNS acceptance original DoH metadata differs','state-doh-metadata'))){Assert-A ((Get-NativeDNSStaticFailure ([InvalidOperationException]::new($pair[0]))) -ceq $pair[1]) 'static-closed-failure-map'}
    foreach($pair in @(@('Static fixture firewall policy unavailable','firewall-policy'),@('Static fixture address is local','fixture-address-local'),@('Static fixture firewall identity collision','firewall-identity'),@('Static fixture firewall rule not active','firewall-active'),@('Static fixture firewall filters differ','firewall-filter'),@('Static fixture firewall ownership differs','firewall-owner'),@('Static fixture firewall removal incomplete','firewall-removal'),@('Static fixture firewall cleanup failed','firewall-cleanup'))){Assert-A ((Get-NativeDNSStaticFailure ([InvalidOperationException]::new($pair[0]))) -ceq $pair[1]) 'static-closed-failure-map'}
    # Actual independent-reader refusals must reach fixed public categories.
    foreach($failure in @('inventory','registry','scope','address','doh')){
        New-ACase
        $expectedCode=switch($failure){
            'inventory' {$script:adapters=@();'read-empty-inventory'}
            'registry' {$script:registryValues[($script:g1+'/IPv6')]=@('synthetic','array');'read-registry-mode'}
            'scope' {$script:data[$script:g1].servers6=@('fe80::53%99');'read-scope'}
            'address' {$script:data[$script:g1].servers6=@('synthetic-not-an-address');'read-address'}
            'doh' {$script:doh[0].DohTemplate='';'read-doh-metadata'}
        }
        $refused=$false;$actualCode='none'
        try{[void](Read-DNSAcceptanceState)}catch{$refused=$true;$actualCode=Get-NativeDNSStaticFailure $_.Exception}
        Assert-A ($refused -and $actualCode -ceq $expectedCode) 'static-closed-failure-map'
    }
    # Execute the actual driver resolver callback under the roundtrip coordinator.
    # Its ScenarioKind parameter shadows the caller's static-ipv6 mode. All file,
    # CIM, service and resolver boundaries below are closed source mocks.
    $tokens=$null;$issues=$null;$driver=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project 'scripts/test-native-doh.ps1'),[ref]$tokens,[ref]$issues)
    if($issues.Count){throw 'Native driver callback source did not parse'}
    $calls=@($driver.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Invoke-NativeDoHScenario'},$true));if($calls.Count -ne 1){throw 'Native driver coordinator call is ambiguous'}
    $resolver=$null
    for($i=0;$i -lt $calls[0].CommandElements.Count-1;$i++){
        $element=$calls[0].CommandElements[$i]
        if($element -is [Management.Automation.Language.CommandParameterAst] -and $element.ParameterName -ceq 'Resolve'){$resolver=$calls[0].CommandElements[$i+1]}
    }
    if($resolver -isnot [Management.Automation.Language.ScriptBlockExpressionAst]){throw 'Native driver resolver callback unavailable'}
    foreach($command in $resolver.ScriptBlock.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
        if($command.GetCommandName() -cnotin @('Get-Service','Get-CimInstance','Get-Content','Join-Path','ConvertFrom-Json','Where-Object','Convert-DNSAcceptanceGuid','Get-NativeDNSAnswerCount','Measure-DoHNetEventWire','Test-NativeConfiguredDNSReadback')){throw 'Native source resolver callback boundary refused'}
    }
    foreach($name in @('Get-NativeStaticIPv6Row','Wait-NativeStaticIPv6FixtureState','Set-NativeStaticIPv6Fixture','Remove-NativeStaticIPv6Fixture')){
        $nodes=@($driver.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));if($nodes.Count -ne 1){throw 'Static staging source is ambiguous'}
        foreach($command in $nodes[0].FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
            if($command.GetCommandName() -cnotin @('Get-NetAdapter','Where-Object','Convert-DNSAcceptanceGuid','Get-DnsClientServerAddress','Get-NativeStaticIPv6Row','Wait-NativeStaticIPv6FixtureState','Start-Sleep','Get-NetIPAddress','Set-DnsClientServerAddress','ConvertFrom-Json','ConvertTo-Json','Read-DNSAcceptanceState','Get-DNSAcceptanceIndex','Assert-DNSAcceptanceRestored','Get-NetFirewallProfile','Get-Service','Get-NetFirewallRule','New-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Remove-NetFirewallRule','Test-Path','Join-Path','Invoke-NativeDoHCLI')){throw 'Static staging source boundary refused'}
        }
        . ([scriptblock]::Create($nodes[0].Extent.Text))
    }
    $script:wire=$null
    function Measure-DoHNetEventWire {throw 'Native wire effects are forbidden in source resolver contracts'}
    function Test-NativeConfiguredDNSReadback {throw 'Native readback is forbidden in source resolver contracts'}
    $machineRoot=[IO.Path]::GetTempPath();$script:staticSnapshotPath=Join-Path $machineRoot 'profiles\dns-original.json'
    function Start-Sleep {[CmdletBinding()]param([int]$Milliseconds);if($Milliseconds -ne 250 -or $script:staticWaitCalls -ge 39){throw 'Unexpected source observation delay'};$script:staticWaitCalls++}
    function Get-NetIPAddress {[CmdletBinding()]param($InterfaceIndex,$AddressFamily,$Type);if(($null -ne $InterfaceIndex -and $InterfaceIndex -ne 77) -or $AddressFamily -cne 'IPv6' -or $Type -cne 'Unicast'){throw 'Unexpected source address inspection'};return [pscustomobject]@{IPAddress='fe80::a77%77';AddressState='Preferred'}}
    function Set-DnsClientServerAddress {
        [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[string[]]$ServerAddresses,[switch]$ResetServerAddresses)
        process {
            if($InputObject.InterfaceIndex -ne 77 -or $InputObject.AddressFamily -ne 23){throw 'Unexpected source static family write'}
            if(-not $ResetServerAddresses -and ($ServerAddresses -join ',') -ceq 'fe80::53,fe80::54'){
                if(-not $script:staticFirewallProtected -or $script:fixtureRules.Count -ne 2){throw 'Source staging needs verified containment'}
                $script:staticStagingWrites++
            }
            if($script:staticTeardownFault -ceq 'write-throw'){throw 'source-original-restore-failed'}
            if($script:staticTeardownFault -ceq 'write-noop'){return}
            $script:data[$script:g1].mode6=if($ResetServerAddresses){'dhcp'}else{'static'};$script:data[$script:g1].servers6=if($ResetServerAddresses){@()}else{@($ServerAddresses)}
            if(-not $ResetServerAddresses -and ($ServerAddresses -join ',') -ceq 'fe80::53,fe80::54' -and $script:staticStageFault -cin @('pending-empty','pending-count','permanent-empty','permanent-count')){
                $script:staticPendingReads=if($script:staticStageFault -like 'permanent-*'){40}else{2};$script:staticPendingShape=if($script:staticStageFault -like '*-empty'){'empty'}else{'count'}
            }
            if($script:staticStageFault -ceq 'family-set' -and $script:staticStageFaultPending){$script:staticStageFaultPending=$false;throw 'source-partial-family-set'}
        }
    }
    function Get-NetFirewallProfile {[CmdletBinding()]param($PolicyStore);if($PolicyStore -cne 'ActiveStore'){throw 'Unexpected source firewall store'};foreach($name in @('Domain','Private','Public')){[pscustomobject]@{Name=$name;Enabled=$(if($script:staticStageFault -ceq 'profile-disabled'){'False'}else{'True'});AllowLocalFirewallRules=$(if($script:staticStageFault -ceq 'local-rules-disabled'){'False'}else{'NotConfigured'});DisabledInterfaceAliases=@('NotConfigured')}}}
    function Get-NetFirewallRule {[CmdletBinding()]param($PolicyStore);if($PolicyStore -cnotin @('ActiveStore','PersistentStore')){throw 'Unexpected source firewall store'};foreach($entry in $script:fixtureRules.Values){$entry}}
    function New-NetFirewallRule {
        [CmdletBinding()]param($Name,$DisplayName,$Group,$Direction,$Action,$Enabled,$Profile,$Protocol,$RemotePort,[string[]]$RemoteAddress,$PolicyStore)
        if($Name -cnotmatch '^AccessWeaver-NativeStatic-[a-f0-9]{32}$' -or $script:fixtureRules.ContainsKey($Name) -or $PolicyStore -cne 'PersistentStore' -or $Profile -cne 'Any' -or $Protocol -cnotin @('UDP','TCP') -or [string]$RemotePort -cne '53' -or ($RemoteAddress -join ',') -cne 'fe80::53,fe80::54'){throw 'Unexpected source firewall mutation'}
        $script:fixtureRules[$Name]=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Group=$Group;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile;Protocol=$Protocol;RemotePort=[string]$RemotePort;RemoteAddress=@($RemoteAddress)}
        if($script:staticStageFault -ceq 'create-second' -and $script:fixtureRules.Count -eq 2){throw 'source-partial-firewall-create'}
    }
    function Get-NetFirewallPortFilter {
        [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
        process {if(-not $script:fixtureRules.ContainsKey($InputObject.Name)){throw 'Unexpected source firewall inspection'};[pscustomobject]@{Protocol=$InputObject.Protocol;RemotePort=$(if($script:staticStageFault -ceq 'active-filter'){'54'}else{$InputObject.RemotePort})}}
    }
    function Get-NetFirewallAddressFilter {
        [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
        process {if(-not $script:fixtureRules.ContainsKey($InputObject.Name)){throw 'Unexpected source firewall inspection'};[pscustomobject]@{RemoteAddress=$(if($script:staticStageFault -ceq 'active-address'){@('fe80::53','fe80::53')}elseif($script:staticStageFault -ceq 'cidr'){@($InputObject.RemoteAddress | ForEach-Object {$_+'/128'})}else{@($InputObject.RemoteAddress)})}}
    }
    function Remove-NetFirewallRule {[CmdletBinding()]param($Name,$PolicyStore);if($PolicyStore -cne 'PersistentStore' -or -not $script:fixtureRules.ContainsKey($Name)){throw 'Unexpected source firewall retirement'};$script:fixtureRules.Remove($Name)}
    function Test-Path {[CmdletBinding()]param($LiteralPath);if($LiteralPath -cne $script:staticSnapshotPath){throw 'Unexpected source snapshot inspection'};return $false}
    function Invoke-NativeDoHCLI {throw 'Product execution forbidden in source staging fixture'}
    foreach($failure in @('none','cidr','pending-empty','pending-count','permanent-empty','permanent-count','create-second','active-filter','active-address','family-set','profile-disabled','local-rules-disabled')){
        New-ACase;$before=Read-DNSAcceptanceState;$script:staticPlan=$null;$script:fixtureRules=@{};$script:staticStageFault=$failure;$script:staticStageFaultPending=$true;$script:staticFirewallProtected=$false;$script:staticFirewallRemoved=$false;$stagePassed=$false
        try{$stagePassed=Set-NativeStaticIPv6Fixture $before}catch{}
        Assert-A ($stagePassed -is [bool] -and $stagePassed -eq ($failure -cin @('none','cidr','pending-empty','pending-count'))) 'static-stage-source'
        if($failure -cin @('none','cidr','pending-empty','pending-count')){Assert-A ($script:staticFirewallProtected -and $script:staticObservation.captured -and $script:staticObservation.mode -ceq 'static' -and $script:staticObservation.count -eq 2 -and $script:staticObservation.firstMatches -and $script:staticObservation.secondMatches) 'static-stage-source'}
        Assert-A ($script:staticStagingWrites -eq $(if($failure -cin @('none','cidr','pending-empty','pending-count','permanent-empty','permanent-count','family-set')){1}else{0})) 'static-stage-source'
        Assert-A ($script:staticWaitCalls -eq $(if($failure -like 'pending-*'){2}elseif($failure -like 'permanent-*'){39}else{0})) 'static-stage-source'
        $removed=$false;try{Remove-NativeStaticIPv6Fixture $before;Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState);$removed=$true}catch{}
        Assert-A ($removed -and $script:staticFirewallRemoved -eq ($failure -cnotin @('profile-disabled','local-rules-disabled')) -and $script:fixtureRules.Count -eq 0) 'static-stage-source'
    }
    # The true pre-fixture original can itself contain scoped link-local DNS.
    # Restore its canonical values on the GUID-bound row, without a setter zone.
    New-ACase;$script:data[$script:g1].servers6=@('fe80::70%77','fe80::71%77');$before=Read-DNSAcceptanceState
    $script:staticPlan=$null;$script:fixtureRules=@{};$script:staticStageFault='none';$script:staticStageFaultPending=$false;$script:staticFirewallProtected=$false;$script:staticFirewallRemoved=$false
    Assert-A (Set-NativeStaticIPv6Fixture $before) 'static-stage-source'
    Remove-NativeStaticIPv6Fixture $before
    Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState)
    Assert-A (($script:data[$script:g1].servers6 -join ',') -ceq 'fe80::70,fe80::71' -and $script:staticFirewallRemoved -and $script:fixtureRules.Count -eq 0) 'static-stage-source'
    # Persistent teardown faults must preserve both actual source-owned blocks.
    # No OS commands run: extraction above binds every dependency to these mocks.
    foreach($originalMode in @('static','dhcp')){
        foreach($failure in @('write-throw','write-noop','verification-read','other-family')){
            New-ACase;$script:data[$script:g1].mode6=$originalMode;$before=Read-DNSAcceptanceState
            $script:staticPlan=$null;$script:fixtureRules=@{};$script:staticStageFault='none';$script:staticStageFaultPending=$false;$script:staticFirewallProtected=$false;$script:staticFirewallRemoved=$false
            Assert-A (Set-NativeStaticIPv6Fixture $before) 'static-stage-source'
            $script:staticTeardownFault=$failure
            if($failure -ceq 'other-family'){$script:data[$script:g2].servers4=@('203.0.113.53')}
            $refused=$false;try{Remove-NativeStaticIPv6Fixture $before}catch{$refused=$true}
            Assert-A ($refused -and -not $script:staticFirewallRemoved -and $script:fixtureRules.Count -eq 2) 'static-stage-source'
            foreach($name in @($script:staticPlan.rules)){
                Assert-A ($script:fixtureRules.ContainsKey($name) -and $script:fixtureRules[$name].Action -ceq 'Block' -and $script:fixtureRules[$name].Enabled -ceq 'True') 'static-stage-source'
            }
            # Once the original can actually be verified, the same owned rules
            # can be retired. An earlier refusal must not lose their identities.
            $script:staticTeardownFault=''
            if($failure -ceq 'other-family'){$script:data[$script:g2].servers4=@('192.0.2.53','192.0.2.54')}
            Remove-NativeStaticIPv6Fixture $before
            Assert-DNSAcceptanceRestored $before (Read-DNSAcceptanceState)
            Assert-A ($script:staticFirewallRemoved -and $script:fixtureRules.Count -eq 0) 'static-stage-source'
        }
    }
    $body=$resolver.ScriptBlock.Extent.Text;$nativeResolve=[scriptblock]::Create($body.Substring(1,$body.Length-2))
    $machineRoot=[IO.Path]::GetTempPath();$script:staticSnapshotPath=Join-Path $machineRoot 'profiles\dns-original.json'
    function Get-Content {[CmdletBinding()]param($LiteralPath,[switch]$Raw);if($LiteralPath -cne $script:staticSnapshotPath -or -not $Raw){throw 'Unexpected source snapshot read'};return $script:staticSnapshotText}
    function Get-CimInstance {throw 'CIM access forbidden in source resolver callback'}
    function Get-NativeDNSAnswerCount {$script:sourceResolverCalls++;return 1}
    foreach($badSnapshot in @($false,$true)){
        New-ACase;$script:sourceResolverCalls=0;$script:staticSnapshotNormalized=$false;$script:staticPlan=@{guid=$script:g1;servers=@('fe80::53','::1')}
        $servers=if($badSnapshot){@('fe80::53%77','::1')}else{@('fe80::53','::1')}
        $script:staticSnapshotText=ConvertTo-Json -InputObject @{adapters=@(@{guid=$script:g1;dhcp6=$false;ipv6=$servers})} -Depth 5
        $result=Invoke-NativeDoHScenario -Method doh -ScenarioKind roundtrip -Capture {Read-DNSAcceptanceState} -Apply $script:applyFixture -Resolve $nativeResolve
        Assert-A (($result.outcome -ceq 'passed') -eq (-not $badSnapshot) -and $script:staticSnapshotNormalized -eq (-not $badSnapshot) -and $script:sourceResolverCalls -eq $(if($badSnapshot){0}else{1}) -and $result.restoredStateVerified) 'static-resolver-source-callback'
    }
    $script:staticPlan=$null
    foreach($failure in @('none','baseline','baseline-false','baseline-string','stage-throw','stage-false','stage-string','exercise-throw','exercise-false','exercise-string','unstage','state','cleanup-resolver','exercise-and-unstage')){
        New-ACase;$script:staticTrace=[Collections.Generic.List[string]]::new();$script:staticFailure=$failure;$script:staticResolveCalls=0
        $result=Invoke-NativeDNSStaticFixture -Capture {
            $script:staticTrace.Add('capture')
            if($script:staticFailure -ceq 'baseline'){throw 'fixture-baseline'}
            return (Read-DNSAcceptanceState)
        } -Resolve {
            $script:staticTrace.Add('resolve');$script:staticResolveCalls++
            if($script:staticResolveCalls -eq 1){
                if($script:staticFailure -ceq 'baseline-false'){return $false}
                if($script:staticFailure -ceq 'baseline-string'){return 'true'}
            }elseif($script:staticFailure -ceq 'cleanup-resolver'){return $false}
            return $true
        } -Stage {
            param($before)
            $script:staticTrace.Add('stage');$script:data[$script:g1].servers6=@('fe80::53','fe80::54')
            if($script:staticFailure -ceq 'stage-throw'){throw 'fixture-partial-stage'}
            if($script:staticFailure -ceq 'stage-false'){return $false}
            if($script:staticFailure -ceq 'stage-string'){return 'true'}
            return $true
        } -Exercise {
            $script:staticTrace.Add('exercise')
            if($script:staticFailure -cin @('exercise-throw','exercise-and-unstage')){throw 'fixture-exercise'}
            if($script:staticFailure -ceq 'exercise-false'){return $false}
            if($script:staticFailure -ceq 'exercise-string'){return 'true'}
            return $true
        } -Unstage {
            param($before)
            $script:staticTrace.Add('unstage')
            if($script:staticFailure -cin @('unstage','exercise-and-unstage')){throw 'fixture-unstage'}
            if($script:staticFailure -cne 'state'){$script:data[$script:g1].servers6=@('2001:db8::53','2001:db8::54')}
        }
        $baselineFailure=$failure -cin @('baseline','baseline-false','baseline-string')
        $operation=if($baselineFailure){'baseline'}elseif($failure -like 'stage-*'){'stage'}elseif($failure -like 'exercise-*'){'exercise'}else{'none'}
        $cleanup=if($failure -cin @('unstage','exercise-and-unstage')){'unstage'}elseif($failure -ceq 'state'){'state'}elseif($failure -ceq 'cleanup-resolver'){'resolver'}else{'none'}
        Assert-A (($result.outcome -ceq 'passed') -eq ($failure -ceq 'none') -and $result.operationCode -ceq $operation -and $result.cleanupCode -ceq $cleanup) 'static-fixture-result'
        Assert-A ($result.stagingAttempted -eq (-not $baselineFailure) -and $result.cleanupAttempted -eq (-not $baselineFailure) -and @($script:staticTrace | Where-Object {$_ -ceq 'unstage'}).Count -eq $(if($baselineFailure){0}else{1})) 'static-fixture-cleanup'
        if($failure -ceq 'none'){
            Assert-A ($result.baselineCaptured -and $result.baselineResolverPassed -and $result.stagingVerified -and $result.exerciseAttempted -and $result.exercisePassed -and $result.originalStateRestored -and $result.originalResolverPassed) 'static-fixture-flags'
            Assert-A (($script:staticTrace -join ',') -ceq 'capture,resolve,stage,exercise,unstage,capture,resolve') 'static-fixture-order'
        }
    }
    foreach($missing in @('Capture','Resolve','Stage','Exercise','Unstage')){
        $script:invalidEffects=0;$boundary={$script:invalidEffects++};$parameters=@{Capture=$boundary;Resolve=$boundary;Stage=$boundary;Exercise=$boundary;Unstage=$boundary};$parameters.Remove($missing)
        $result=Invoke-NativeDNSStaticFixture @parameters
        Assert-A ($result.operationCode -ceq 'baseline' -and $script:invalidEffects -eq 0 -and -not $result.stagingAttempted -and -not $result.cleanupAttempted) 'static-fixture-preflight'
    }
    $peer=[Net.Sockets.SocketException]::new(10054);$other=[Net.Sockets.SocketException]::new(10013)
    Assert-A ((Get-NativeDNSForwarderFailure $peer) -ceq 'peer-closed') 'forwarder-closed-error-map'
    Assert-A ((Get-NativeDNSForwarderFailure ([InvalidOperationException]::new('synthetic-wrapper',$peer))) -ceq 'peer-closed') 'forwarder-closed-error-map'
    Assert-A ((Get-NativeDNSForwarderFailure $other) -ceq 'socket-io') 'forwarder-closed-error-map'
    Assert-A ((Get-NativeDNSForwarderFailure ([InvalidOperationException]::new('unrecognized synthetic text'))) -ceq 'unexpected-io') 'forwarder-closed-error-map'
    foreach($pair in @(@('Forwarded DNS packet bound exceeded','packet-bound'),@('Forwarded DNS request count exceeded','request-bound'),@('Non-loopback forwarder peer refused','peer-bound'),@('Forwarded DNS error response incomplete','response-write'),@('Fixed DNS EDNS shape refused','packet-shape'))){
        Assert-A ((Get-NativeDNSForwarderFailure ([InvalidOperationException]::new($pair[0]))) -ceq $pair[1]) 'forwarder-closed-error-map'
    }
    foreach($status in @(400,401,403,404,408,429,500,502,503,504)){
        Assert-A ((Get-NativeDNSComponentFailure ([InvalidOperationException]::new('synthetic-unrecognized')) $status) -ceq ('http-'+$status)) 'component-closed-error-map'
    }
    Assert-A ((Get-NativeDNSComponentFailure ([InvalidOperationException]::new('synthetic-unrecognized')) -1) -ceq 'http-other') 'component-closed-error-map'
    foreach($pair in @(@('DNSCrypt native architecture refused','native-architecture'),@('DNSCrypt upstream size differs','upstream-size'),@('DNSCrypt upstream bound exceeded','upstream-bound'),@('DNSCrypt upstream digest differs','upstream-digest'),@('DNSCrypt upstream entry bound exceeded','archive-count'),@('DNSCrypt upstream member shape differs','member-shape'),@('DNSCrypt member bound exceeded','member-bound'),@('DNSCrypt member incomplete','member-incomplete'),@('DNSCrypt PE header differs','pe-header'),@('DNSCrypt PE offset differs','pe-offset'),@('DNSCrypt PE native machine differs','pe-machine'))){
        Assert-A ((Get-NativeDNSComponentFailure ([InvalidOperationException]::new($pair[0])) 200) -ceq $pair[1]) 'component-closed-error-map'
    }
    Assert-A ((Get-NativeDNSComponentFailure ([OperationCanceledException]::new('synthetic-private-timeout'))) -ceq 'timeout') 'component-closed-error-map'
    Assert-A ((Get-NativeDNSComponentFailure ([UnauthorizedAccessException]::new('synthetic-private-access'))) -ceq 'access') 'component-closed-error-map'
    Assert-A ((Get-NativeDNSComponentFailure ([IO.InvalidDataException]::new('synthetic-private-data'))) -ceq 'archive-data') 'component-closed-error-map'
    Assert-A ((Get-NativeDNSComponentFailure ([IO.IOException]::new('synthetic-private-io'))) -ceq 'io') 'component-closed-error-map'
    Assert-A ((Get-NativeDNSComponentFailure ([InvalidOperationException]::new('synthetic-private-unknown')) 599) -ceq 'unexpected') 'component-closed-error-map'
    Assert-A ((Get-NativeDNSComponentFailure ([InvalidOperationException]::new('synthetic-wrapper',[IO.IOException]::new('synthetic-private-io')))) -ceq 'io') 'component-closed-error-map'
    $nested=[IO.IOException]::new('synthetic-private-io');for($i=0;$i -lt 16;$i++){$nested=[InvalidOperationException]::new('synthetic-wrapper',$nested)}
    Assert-A ((Get-NativeDNSComponentFailure $nested) -ceq 'unexpected') 'component-closed-error-map'
    foreach($status in @(200,301,400,401,403,404,429,501,599)){Assert-A ((Get-NativeDNSComponentRetry $status 1 90000) -eq -1) 'component-retry-contract'}
    foreach($status in @(408,500,502,503,504)){
        $first=Get-NativeDNSComponentRetry $status 1 90000;$second=Get-NativeDNSComponentRetry $status 2 80000
        Assert-A ($first -gt 0 -and $first -lt 90000 -and $second -gt $first -and $second -lt 80000) 'component-retry-contract'
        Assert-A ((Get-NativeDNSComponentRetry $status 3 80000) -eq -1) 'component-retry-contract'
    }
    Assert-A ((Get-NativeDNSComponentRetry 504 1 20000 5000) -eq 5000) 'component-retry-contract'
    foreach($parameters in @(@(504,0,90000,0),@(504,4,90000,0),@(504,1,0,0),@(504,1,90001,0),@(504,1,1000,0),@(504,1,5000,5000),@(504,1,90000,-1))){Assert-A ((Get-NativeDNSComponentRetry @parameters) -eq -1) 'component-retry-contract'}
    foreach($file in @('scripts/test-windows-integration.ps1','scripts/test-windows-reboot.ps1')){
        $tokens=$null;$issues=$null;$native=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project $file),[ref]$tokens,[ref]$issues)
        $calls=@($native.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
        $connected=if($file -like '*integration*'){@($calls | Where-Object {$_ -ceq 'Invoke-DNSAcceptanceRoundTrip'}).Count -eq 2}else{('Assert-DNSAcceptanceConfigured' -in $calls -and 'Assert-DNSAcceptanceRestored' -in $calls -and 'Get-DNSAcceptanceIndex' -in $calls)}
        Assert-A ($issues.Count -eq 0 -and $connected) 'native-harness-wiring'
    }
    foreach($file in $sourceFiles){if((Get-ASourceSHA256 (Join-Path $project $file)) -cne $sourceHashes[$file]){throw 'Acceptance source changed during contracts'}}
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
