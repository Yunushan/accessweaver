# Definitions only. Read-only adapter binding and closed metadata reduction.
function Get-NativeOffloadRaw([object]$Row,[string]$Name) {
    $property=$Row.CimInstanceProperties[$Name];if($null -eq $property){throw 'Offload property'};return ,$property.Value
}
function Read-NativeOffloadBinding([object[]]$Routes,[object[]]$Adapters,[object[]]$Settings) {
    if($Routes.Count -ne 2 -or $Adapters.Count -gt 32 -or $Settings.Count -gt 32){throw 'Offload bound'}
    $index=$null;$seen=@{}
    foreach($row in $Routes){$class=$row.CimClass.CimClassName;if($class -cnotin @('MSFT_NetIPAddress','MSFT_NetRoute') -or $seen.ContainsKey($class)){throw 'Offload route'};$seen[$class]=$true;$value=Get-NativeOffloadRaw $row 'InterfaceIndex';if($value -isnot [uint32] -or $value -eq 0 -or ($null -ne $index -and $index -ne $value)){throw 'Offload route'};$index=$value}
    $selectedRows=[Collections.Generic.List[object]]::new()
    foreach($row in $Adapters){if($row.CimClass.CimClassName -cne 'MSFT_NetAdapter'){throw 'Offload adapter'};if((Get-NativeOffloadRaw $row 'InterfaceIndex') -eq $index){$selectedRows.Add($row)}}
    if($selectedRows.Count -ne 1){throw 'Offload adapter'};$adapter=$selectedRows[0]
    $name=Get-NativeOffloadRaw $adapter 'Name';$description=Get-NativeOffloadRaw $adapter 'InterfaceDescription';$guidValue=Get-NativeOffloadRaw $adapter 'InterfaceGuid';$guid=[guid]::Empty
    if($name -isnot [string] -or $name.Length -lt 1 -or $name.Length -gt 1024 -or $description -isnot [string] -or $description.Length -lt 1 -or $description.Length -gt 1024 -or -not [guid]::TryParse([string]$guidValue,[ref]$guid) -or $guid -eq [guid]::Empty){throw 'Offload adapter'}
    $selectedRows.Clear()
    foreach($row in $Settings){if($row.CimClass.CimClassName -cne 'MSFT_NetAdapterLsoSettingData'){throw 'Offload setting'};if([string]::Equals([string](Get-NativeOffloadRaw $row 'Name'),$name,[StringComparison]::Ordinal) -and [string]::Equals([string](Get-NativeOffloadRaw $row 'InterfaceDescription'),$description,[StringComparison]::Ordinal)){$selectedRows.Add($row)}}
    if($selectedRows.Count -ne 1){throw 'Offload setting'};$setting=$selectedRows[0];$instance=Get-NativeOffloadRaw $setting 'InstanceID';$version=Get-NativeOffloadRaw $setting 'MaximumLsoVersionSupported'
    if($instance -isnot [string] -or $instance.Length -lt 1 -or $instance.Length -gt 4096 -or $version -isnot [uint32] -or $version -gt 2){throw 'Offload property'}
    $r=@{index=$index;guid=$guid.ToString('D');name=$name;description=$description;instance=$instance;maximumVersion=[int]$version}
    foreach($field in @('V1IPv4Enabled','IPv4Enabled','IPv6Enabled')){$value=Get-NativeOffloadRaw $setting $field;if($value -isnot [bool]){throw 'Offload property'};$r[$field]=$value};return $r
}
function Test-NativeOffloadBindingEqual([object]$Before,[object]$After) {
    foreach($key in @('index','guid','name','description','instance','maximumVersion','V1IPv4Enabled','IPv4Enabled','IPv6Enabled')){if($Before[$key] -is [string]){if($After[$key] -isnot [string] -or -not [string]::Equals($Before[$key],$After[$key],[StringComparison]::Ordinal)){return $false}}elseif($Before[$key] -ne $After[$key]){return $false}};return $true
}
function New-NativeOffloadEvidence([string]$Code='not-inspected') {
    return @{code=$Code;routeMatched=$false;adapterMatched=$false;settingMatched=$false;getCapability=$false;setCapability=$false;noRestartCapability=$false;ipv4Enabled=$null;ipv6Enabled=$null;v1Ipv4Enabled=$null;maximumVersion=-1;routeStable=$false;identityStable=$false;settingsChanged=$false}
}
function Get-NativeOffloadEvidence([string]$Text) {
    $bad=New-NativeOffloadEvidence 'invalid';if($Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $flags=@('routeMatched','adapterMatched','settingMatched','getCapability','setCapability','noRestartCapability','routeStable','identityStable','settingsChanged');$keys=@('code','ipv4Enabled','ipv6Enabled','v1Ipv4Enabled','maximumVersion')+$flags
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 14 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.code -cnotin @('none','environment','metadata','read','route','adapter','setting','property','bound','drift') -or $v.maximumVersion -isnot [int] -or $v.maximumVersion -lt -1 -or $v.maximumVersion -gt 2){return $bad}
    foreach($key in $flags){if($v.$key -isnot [bool]){return $bad}};if($v.settingsChanged){return $bad}
    foreach($key in @('ipv4Enabled','ipv6Enabled','v1Ipv4Enabled')){if($null -ne $v.$key -and $v.$key -isnot [bool]){return $bad}}
    if($v.code -ceq 'none'){foreach($key in $flags){if($key -cne 'settingsChanged' -and -not $v.$key){return $bad}};foreach($key in @('ipv4Enabled','ipv6Enabled','v1Ipv4Enabled')){if($v.$key -isnot [bool]){return $bad}};if($v.maximumVersion -lt 0){return $bad}}
    $r=New-NativeOffloadEvidence $v.code;foreach($key in $keys){$r[$key]=$v.$key};return $r
}
