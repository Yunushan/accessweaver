# Synthetic state diagnostics only. No installer, service, firewall or DNS call.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-state.ps1')
function Assert-State([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
$baseline='{"services":[],"firewall":[{"Name":"private-rule-name","Enabled":1,"Direction":1,"Action":2}],"dns":[{"InterfaceIndex":5,"AddressFamily":2,"ServerAddresses":["192.0.2.99","192.0.2.100"]}]}'
$same=Compare-InstallerState $baseline $baseline
Assert-State $same.exactMatch 'Equal snapshots were not exact'
Assert-State ($same.domains.firewall.changed -eq 0 -and $same.domains.dns.serializedEqual) 'Equal snapshots produced changed rows'
$dns=$baseline.Replace('192.0.2.99','198.51.100.77');$delta=Compare-InstallerState $baseline $dns
Assert-State (-not $delta.exactMatch -and $delta.domains.dns.changed -eq 1 -and $delta.domains.firewall.serializedEqual) 'DNS change was not isolated'
Assert-State ($delta.domains.dns.changes[0].fields -contains 'ServerAddresses') 'DNS changed field was lost'
$public=$delta | ConvertTo-Json -Depth 16
foreach($private in @('private-rule-name','192.0.2.99','192.0.2.100','198.51.100.77')){Assert-State (-not $public.Contains($private)) 'Raw private state escaped diagnostics'}
$firewall=$baseline.Replace('"Enabled":1','"Enabled":2');$delta=Compare-InstallerState $baseline $firewall
Assert-State ($delta.domains.firewall.changed -eq 1 -and $delta.domains.firewall.changes[0].fields -contains 'Enabled' -and $delta.domains.dns.serializedEqual) 'Firewall change was not isolated'
$reordered=$baseline.Replace('"Name":"private-rule-name","Enabled":1','"Enabled":1,"Name":"private-rule-name"');$delta=Compare-InstallerState $baseline $reordered
Assert-State (-not $delta.exactMatch -and $delta.domains.firewall.rowSerializationChanges -eq 1 -and $delta.domains.firewall.changed -eq 0) 'Representation drift was confused with field mutation'
$empty='{"services":[],"firewall":[],"dns":[]}';$delta=Compare-InstallerState $baseline $empty
Assert-State ($delta.domains.firewall.removed -eq 1 -and $delta.domains.dns.removed -eq 1) 'Removed rows were not counted'
$reverse=Compare-InstallerState $empty $baseline
Assert-State ($reverse.domains.firewall.added -eq 1 -and $reverse.domains.dns.added -eq 1) 'Added rows were not counted'
$bad='{"services":[],"firewall":[{"Name":"same"},{"Name":"same"}],"dns":[]}'
$rejected=$false;try{$null=Compare-InstallerState $bad $empty}catch{$rejected=$true};Assert-State $rejected 'Duplicate row identity was accepted'
Write-Output 'Synthetic exact-state difference, privacy and representation diagnostics passed.'
