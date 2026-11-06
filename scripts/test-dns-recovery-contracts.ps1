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
$sourcePath=Join-Path $project 'internal/workflow/windows.ps1'
$sourceHash=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'DNS workflow source did not parse'}
$selected=@('Read-OriginalDNSNameServer','Configure-DNS','Restore-DNS')
$allowed=@('Read-OriginalDNSNameServer','Restore-DNS','Get-ItemProperty','Get-Command','Join-Path','Get-NetAdapter','Where-Object','ForEach-Object','Test-Path','Get-DnsClientServerAddress','Get-DnsClientDohServerAddress','Write-Atomic','ConvertTo-Json','Save-Journal','Ensure-Asset','Split-Path','Copy-Checked','Get-Content','Get-Service','Install-EngineService','Set-Service','Restart-Service','Stop-Service','Set-DnsClientDohServerAddress','Add-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress','Set-DnsClientServerAddress','Clear-DnsClientCache','Resolve-DnsName','Start-Sleep','Event','ConvertFrom-Json','Remove-Item')
foreach($name in $selected){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required DNS function is unavailable'}
    foreach($command in $nodes[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)){
        $commandName=$command.GetCommandName()
        if(-not $commandName -or $commandName -notin $allowed){throw 'DNS contract source contains an unapproved command boundary'}
    }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
if((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne $sourceHash){throw 'DNS source changed while selecting functions'}
$ownerPath=[IO.Path]::GetFullPath([IO.Path]::Combine([IO.Path]::GetTempPath(),('accessweaver-dns-contracts-'+[guid]::NewGuid().ToString('N'))))
$owner=[IO.Directory]::CreateDirectory($ownerPath)
$ownerCreated=$owner.CreationTimeUtc.Ticks
$script:checks=0;$script:caseNumber=0
$script:contractOutcome='failed';$script:contractCode='unexpected-contract-error'
$script:closedContractCodes=@('absent','absent-entry-idempotence-and-unrelated-preservation','accessweaver-dns-contracts-','add','all-providers-no-plaintext-fallback','ambiguous-adapter','bad-doh','bad-flags','capture-inspection-failure-not-empty','case','confirmed-absent-entry-not-removed-again','confirmed-absent-mode-is-dhcp','current-doh-query-before-effects','dns','doh','duplicate-doh','empty-adapters','empty-static','exact-original-doh-restored','expected-refusal','false','guid-recovery-uses-current-index','invalid-recovery-preflight','legacy-no-doh-recovery-supported','malformed-mode-not-empty','missing-adapter','no-false-restored-event','none','original-snapshot-retained','partial-removal-retains-needed-recovery','profiles','recovery-retry-completes-after-confirmed-inspection','registry-error-not-dhcp','remove','restore-inspection-before-effects','saved-doh-needs-capability','set','snapshot-before-native-effects','source-doh-inspection-failed','source-doh-mutation-failed','source-registry-inspection-failed','source-snapshot-removal-failed','source-snapshot-write-failed','true','unexpected-contract-error','unknown-test-code')
function Assert-DNS([bool]$Condition,[string]$Code){if(-not $Condition){$script:contractCode=if($Code -in $script:closedContractCodes){$Code}else{'unknown-test-code'};throw ('DNS contract failed: '+$script:contractCode)};$script:checks++}
function Reject-DNS([scriptblock]$Operation){$failed=$false;try{& $Operation | Out-Null}catch{$failed=$true};Assert-DNS $failed 'expected-refusal'}
function New-DNSCase {
    $script:caseNumber++
    $script:root=[IO.Path]::Combine($ownerPath,('case'+$script:caseNumber))
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($root,'profiles'))
    $script:snapshot=Join-Path $root 'profiles/dns-original.json'
    $script:present=@{'Get-DnsClientDohServerAddress'=$true;'Set-DnsClientDohServerAddress'=$true;'Add-DnsClientDohServerAddress'=$true;'Remove-DnsClientDohServerAddress'=$true}
    $script:adapters=@([pscustomobject]@{Status='Up';InterfaceDescription='Fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000001}';ifIndex=77})
    $script:mode4='192.0.2.53';$script:mode6='absent';$script:registryFailure='';$script:emptyDnsRead=$false;$script:failDohRead=0;$script:dohReads=0
    $script:failAction='';$script:failAddress='';$script:failDelete=$false;$script:failSnapshotWrite=$false
    $script:currentDoh=@{};$script:calls=[Collections.Generic.List[object]]::new();$script:events=[Collections.Generic.List[string]]::new()
    $script:undo=[Collections.Generic.List[object]]::new();$script:dnsTouched=$false;$script:dnsConfigured=$false;$script:journals=0
}
function Original-DNSFixture {
    return @{adapters=@(@{guid='{00000000-0000-0000-0000-000000000001}';index=77;ipv4=@('192.0.2.53');ipv6=@('2001:db8::53');dhcp4=$false;dhcp6=$true});doh=@()}
}
function Old-DohFixture {return [pscustomobject]@{ServerAddress='8.8.8.8';DohTemplate='https://original.invalid/dns-query';AllowFallbackToUdp=$true;AutoUpgrade=$false}}
function Write-DNSFixture([object]$Data){[IO.File]::WriteAllText($snapshot,(Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Data -Depth 12),[Text.UTF8Encoding]::new($false))}
function Assert-SnapshotRetained([string]$Hash){Assert-DNS ([IO.File]::Exists($snapshot) -and (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -ceq $Hash) 'original-snapshot-retained';Assert-DNS (-not ($script:events -contains 'Original DNS and DoH settings restored')) 'no-false-restored-event'}
function Snapshot-Hash {return (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash}
function Mutation-Count {return @($script:calls | Where-Object {$_.kind -in @('dns','add','set','remove')}).Count}
# Every OS/state-changing command reachable from the selected functions is a
# closed source fixture. Command discovery is mocked too; no module fallback.
function Get-Command {[CmdletBinding()]param([string[]]$Name);foreach($item in $Name){if(-not $script:present.ContainsKey($item)){throw 'Unexpected DNS command discovery'};if($script:present[$item]){[pscustomobject]@{Name=$item;CommandType='Function'}}}}
function Get-NetAdapter {[CmdletBinding()]param();return $script:adapters}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Name)
    if($LiteralPath -notmatch '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6?\\Parameters\\Interfaces\\'){throw 'Unexpected registry fixture path'}
    $family=if($LiteralPath -match 'Tcpip6'){'IPv6'}else{'IPv4'}
    if($script:registryFailure -eq $family){Write-Error 'source-registry-inspection-failed';return}
    $value=if($family -eq 'IPv4'){$script:mode4}else{$script:mode6}
    if($value -is [string] -and $value -ceq 'absent'){return [pscustomobject]@{}}
    return [pscustomobject]@{NameServer=$value}
}
function Get-DnsClientServerAddress {[CmdletBinding()]param($InterfaceIndex,$AddressFamily);if($script:emptyDnsRead){return};return [pscustomobject]@{InterfaceIndex=$InterfaceIndex;AddressFamily=$AddressFamily;ServerAddresses=@($(if($AddressFamily -eq 'IPv4'){'192.0.2.53'}else{'2001:db8::53'}))}}
function Set-DnsClientServerAddress {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,$InterfaceIndex,[string[]]$ServerAddresses,[switch]$ResetServerAddresses);process{$index=if($null -ne $InputObject){$InputObject.InterfaceIndex}else{$InterfaceIndex};$script:calls.Add(@{kind='dns';index=$index;family=$InputObject.AddressFamily;servers=@($ServerAddresses);reset=[bool]$ResetServerAddresses})}}
function Get-DnsClientDohServerAddress {
    [CmdletBinding()]param($ServerAddress)
    if(-not $script:present['Get-DnsClientDohServerAddress']){throw 'Unavailable DoH query invoked'}
    $script:dohReads++;if($script:failDohRead -eq $script:dohReads){Write-Error 'source-doh-inspection-failed';return}
    if($ServerAddress){throw 'Per-address absent/error inference is not allowed'}
    return @($script:currentDoh.Values)
}
function Set-DNSFixtureDoh([string]$Kind,[string]$Address,[string]$Template,[bool]$Fallback,[bool]$Upgrade) {
    $script:calls.Add(@{kind=$Kind;address=$Address})
    if($script:failAction -eq $Kind -and $script:failAddress -eq $Address){Write-Error 'source-doh-mutation-failed';return}
    if($Kind -eq 'remove'){if(-not $script:currentDoh.ContainsKey($Address)){throw 'Remove requires an existing DoH entry'};$script:currentDoh.Remove($Address);return}
    if($Kind -eq 'set' -and -not $script:currentDoh.ContainsKey($Address)){throw 'Set requires an existing DoH entry'}
    if($Kind -eq 'add' -and $script:currentDoh.ContainsKey($Address)){throw 'Add requires an absent DoH entry'}
    $script:currentDoh[$Address]=[pscustomobject]@{ServerAddress=$Address;DohTemplate=$Template;AllowFallbackToUdp=$Fallback;AutoUpgrade=$Upgrade}
}
function Add-DnsClientDohServerAddress {[CmdletBinding()]param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);Set-DNSFixtureDoh 'add' $ServerAddress $DohTemplate $AllowFallbackToUdp $AutoUpgrade}
function Set-DnsClientDohServerAddress {[CmdletBinding()]param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);Set-DNSFixtureDoh 'set' $ServerAddress $DohTemplate $AllowFallbackToUdp $AutoUpgrade}
function Remove-DnsClientDohServerAddress {[CmdletBinding()]param($ServerAddress);Set-DNSFixtureDoh 'remove' $ServerAddress '' $false $false}
function Assert-DNSFixturePath([string]$LiteralPath){if([IO.Path]::GetFullPath($LiteralPath) -cne [IO.Path]::GetFullPath($snapshot)){throw 'Unexpected fixture filesystem path'}}
function Write-Atomic {[CmdletBinding()]param($path,$text);Assert-DNSFixturePath $path;if($script:failSnapshotWrite){throw 'source-snapshot-write-failed'};[IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))}
function Get-Content {[CmdletBinding()]param($LiteralPath,[switch]$Raw);Assert-DNSFixturePath $LiteralPath;return Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -Raw -ErrorAction Stop}
function Remove-Item {[CmdletBinding()]param($LiteralPath);Assert-DNSFixturePath $LiteralPath;if($script:failDelete){Write-Error 'source-snapshot-removal-failed';return};Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -ErrorAction Stop}
function Save-Journal {$script:journals++}
function Event([string]$Text){$script:events.Add($Text)}
function Get-Service {[CmdletBinding()]param($Name);return $null}
function Clear-DnsClientCache {}
function Resolve-DnsName {[CmdletBinding()]param($Name,[switch]$DnsOnly,[switch]$QuickTimeout);return [pscustomobject]@{Name='example.com'}}
function Start-Sleep {throw 'Unexpected resolver wait'}
function Ensure-Asset {throw 'Native component access is forbidden in DNS contracts'}
function Copy-Checked {throw 'Native component copy is forbidden in DNS contracts'}
function Install-EngineService {throw 'Service installation is forbidden in DNS contracts'}
function Set-Service {throw 'Service changes are forbidden in DNS contracts'}
function Restart-Service {throw 'Service changes are forbidden in DNS contracts'}
function Stop-Service {throw 'Service changes are forbidden in DNS contracts'}
try {
    foreach($family in @('IPv4','IPv6')){
        New-DNSCase;$script:registryFailure=$family
        Reject-DNS {Configure-DNS 'doh'}
        Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0 -and $script:journals -eq 0 -and -not $script:dnsTouched) 'registry-error-not-dhcp'
    }
    New-DNSCase;$script:mode4=42;Reject-DNS {Configure-DNS 'doh'};Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0) 'malformed-mode-not-empty'
    New-DNSCase;$script:failDohRead=1;Reject-DNS {Configure-DNS 'doh'};Assert-DNS (-not [IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0) 'capture-inspection-failure-not-empty'
    New-DNSCase;$script:failSnapshotWrite=$true;Reject-DNS {Configure-DNS 'doh'};Assert-DNS ((Mutation-Count) -eq 0 -and -not $script:dnsTouched -and $script:undo.Count -eq 0) 'snapshot-before-native-effects'
    New-DNSCase;$script:failDohRead=2;Reject-DNS {Configure-DNS 'doh'};Assert-DNS ([IO.File]::Exists($snapshot) -and (Mutation-Count) -eq 0) 'current-doh-query-before-effects'
    New-DNSCase;$script:mode4='absent';$script:currentDoh['8.8.8.8']=Old-DohFixture
    Configure-DNS 'doh'
    $saved=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshot))
    Assert-DNS ($saved.adapters[0].dhcp4 -and $saved.adapters[0].dhcp6) 'confirmed-absent-mode-is-dhcp'
    Assert-DNS ($script:currentDoh.Count -eq 4 -and @($script:currentDoh.Values | Where-Object {$_.AllowFallbackToUdp -ne $false -or $_.AutoUpgrade -ne $true}).Count -eq 0) 'all-providers-no-plaintext-fallback'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:failDohRead=1
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'restore-inspection-before-effects'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:emptyDnsRead=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'restore-inspection-before-effects'
    foreach($mode in @('empty-adapters','bad-flags','empty-static','missing-adapter','ambiguous-adapter','duplicate-doh','bad-doh')){
        New-DNSCase;$saved=Original-DNSFixture
        switch($mode){
            'empty-adapters' {$saved.adapters=@()}
            'bad-flags' {$saved.adapters[0].dhcp4='false'}
            'empty-static' {$saved.adapters[0].ipv4=@()}
            'missing-adapter' {$saved.adapters+=@{guid='{00000000-0000-0000-0000-000000000002}';index=88;ipv4=@('192.0.2.54');ipv6=@();dhcp4=$false;dhcp6=$true}}
            'ambiguous-adapter' {$script:adapters+=@($script:adapters[0])}
            'duplicate-doh' {$saved.doh=@((Old-DohFixture),(Old-DohFixture))}
            'bad-doh' {$item=Old-DohFixture;$item.AllowFallbackToUdp='true';$saved.doh=@($item)}
        }
        Write-DNSFixture $saved;$hash=Snapshot-Hash;Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'invalid-recovery-preflight'
    }
    foreach($kind in @('set','add','remove')){
        New-DNSCase;$saved=Original-DNSFixture
        if($kind -ne 'remove'){$saved.doh=@((Old-DohFixture))}
        if($kind -ne 'add'){$script:currentDoh['8.8.8.8']=[pscustomobject]@{ServerAddress='8.8.8.8';DohTemplate='https://changed.invalid/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true}}
        Write-DNSFixture $saved;$hash=Snapshot-Hash;$script:failAction=$kind;$script:failAddress='8.8.8.8'
        Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
        $script:failAction='';Restore-DNS
        Assert-DNS (-not [IO.File]::Exists($snapshot)) 'recovery-retry-completes-after-confirmed-inspection'
        if($kind -ne 'remove'){Assert-DNS ($script:currentDoh['8.8.8.8'].DohTemplate -ceq 'https://original.invalid/dns-query' -and $script:currentDoh['8.8.8.8'].AllowFallbackToUdp -and -not $script:currentDoh['8.8.8.8'].AutoUpgrade) 'exact-original-doh-restored'}
    }
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash
    foreach($address in @('8.8.8.8','9.9.9.9')){$script:currentDoh[$address]=[pscustomobject]@{ServerAddress=$address;DohTemplate='https://changed.invalid/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true}}
    $script:failAction='remove';$script:failAddress='9.9.9.9'
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    Assert-DNS (-not $script:currentDoh.ContainsKey('8.8.8.8') -and $script:currentDoh.ContainsKey('9.9.9.9')) 'partial-removal-retains-needed-recovery'
    $script:failAction='';Restore-DNS
    Assert-DNS (@($script:calls | Where-Object {$_.kind -eq 'remove' -and $_.address -eq '8.8.8.8'}).Count -eq 1 -and -not [IO.File]::Exists($snapshot)) 'confirmed-absent-entry-not-removed-again'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:adapters[0].ifIndex=101
    $script:currentDoh['192.0.2.90']=[pscustomobject]@{ServerAddress='192.0.2.90';DohTemplate='https://unrelated.invalid/dns-query';AllowFallbackToUdp=$true;AutoUpgrade=$false}
    Restore-DNS
    Assert-DNS (@($script:calls | Where-Object {$_.kind -eq 'dns' -and $_.index -ne 101}).Count -eq 0) 'guid-recovery-uses-current-index'
    Assert-DNS ($script:currentDoh.ContainsKey('192.0.2.90') -and @($script:calls | Where-Object {$_.kind -eq 'remove'}).Count -eq 0) 'absent-entry-idempotence-and-unrelated-preservation'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$hash=Snapshot-Hash;$script:failDelete=$true
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash
    New-DNSCase;$saved=Original-DNSFixture;$saved.doh=@((Old-DohFixture));Write-DNSFixture $saved;$hash=Snapshot-Hash;$script:present['Get-DnsClientDohServerAddress']=$false
    Reject-DNS {Restore-DNS};Assert-SnapshotRetained $hash;Assert-DNS ((Mutation-Count) -eq 0) 'saved-doh-needs-capability'
    New-DNSCase;Write-DNSFixture (Original-DNSFixture);$script:present['Get-DnsClientDohServerAddress']=$false;Restore-DNS
    Assert-DNS (-not [IO.File]::Exists($snapshot)) 'legacy-no-doh-recovery-supported'
    if((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne $sourceHash){throw 'DNS workflow source changed during contracts'}
    $script:contractOutcome='passed';$script:contractCode='none'
    Write-Output ('DNS contracts passed: '+$script:checks+'; PowerShell '+$PSVersionTable.PSVersion.ToString()+' '+$PSVersionTable.PSEdition+'; source '+$sourceHash.ToLowerInvariant())
} finally {
    # One shell owns cleanup. Resolve and verify the explicitly created fixture
    # root before any recursive delete; do not cross to cmd/batch for deletion.
    $current=Microsoft.PowerShell.Management\Get-Item -LiteralPath $ownerPath -Force -ErrorAction Stop
    if([IO.Path]::GetFullPath($current.FullName) -cne $ownerPath -or $current.CreationTimeUtc.Ticks -ne $ownerCreated -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed DNS fixture root retained'}
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $ownerPath -Recurse -Force -ErrorAction Stop
    if($ReportPath){
        $parent=Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportParent.FullName -Force -ErrorAction Stop
        if($parent.FullName -cne $reportParent.FullName -or $parent.CreationTimeUtc.Ticks -ne $reportCreated -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($parent.FullName).Length -ne 0){throw 'Changed contract report parent retained'}
        $commit=[string]$env:GITHUB_SHA
        if($commit -and $commit -notmatch '^[0-9a-f]{40}$'){throw 'Contract source identity is invalid'}
        if($PSVersionTable.PSEdition -notin @('Core','Desktop') -or $script:contractCode -notin $script:closedContractCodes){throw 'Contract output metadata is invalid'}
        $report=@{schemaVersion=1;sourceCommit=$commit;workflowSHA256=$sourceHash.ToLowerInvariant();fixtureSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();outcome=$script:contractOutcome;code=$script:contractCode;checks=$script:checks;realDnsChanged=$false;nativeDnsQualified=$false}
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $report -Compress))
        if($bytes.Length -gt 4096){throw 'Contract output exceeds fixed metadata limit'}
        $stream=[IO.FileStream]::new($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
    }
}
