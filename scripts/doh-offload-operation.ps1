# Exact-owner general offload operations. Fresh disposable hosted process only.
[CmdletBinding()]param([Parameter(Mandatory=$true)][ValidateSet('prepare','stage','restore','verify')][string]$Operation,[Parameter(Mandatory=$true)][string]$PrivateRoot,[int]$Ordinal=-1,[string]$ExpectedDigest='')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$stage='environment';$lock=$null;$digestOut=''
$r=@{schemaVersion=1;operation=$Operation;code='environment';adapters=0;matchedMask=0;unroutedMask=0;ordinal=$Ordinal;identityVerified=$false;readbackVerified=$false;changed=$false;restartRequested=$false;restartReturned=$false;restored=$false;topologyVerified=$false}
try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$'){throw 'Hosted offload operation required'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop offload boundary'}}
    foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','CimCmdlets','NetAdapter','NetTCPIP')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop};$PSModuleAutoLoadingPreference='None'
    foreach($name in @('native-offload-state.ps1','native-doh-route-state.ps1','native-ipv6-route-table.ps1','native-doh-offload-plan.ps1')){. (Join-Path $PSScriptRoot $name)};$r=New-NativeDoHOffloadEvidence $Operation;$r.ordinal=$Ordinal
    $stage='path';$root=[IO.Path]::GetFullPath($PrivateRoot);$local=[Environment]::GetFolderPath('LocalApplicationData')
    if(-not $root.Equals($PrivateRoot,[StringComparison]::Ordinal) -or [IO.Path]::GetFileName($root) -cnotmatch '^AccessWeaver-NetEventControl-[a-f0-9]{32}$' -or -not [IO.Path]::GetDirectoryName($root).Equals($local,[StringComparison]::OrdinalIgnoreCase)){throw 'Private offload root'}
    $current=$root;while($current){if(([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Private offload reparse'};$next=[IO.Path]::GetDirectoryName($current);if($next -eq $current){break};$current=$next}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$security=Get-Acl -LiteralPath $root -ErrorAction Stop
    if(-not $security.AreAccessRulesProtected -or $security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $identity.User.Value){throw 'Private offload owner'}
    foreach($rule in $security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -cnotin @($identity.User.Value,'S-1-5-18','S-1-5-32-544')){throw 'Private offload ACL'}}
    $file=Join-Path $root 'capture-doh-offload-plan.json'
    function Read-PrivateDoHInventory {
        $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object -First 33);$settings=@(Get-NetAdapterLso -Name '*' -IncludeHidden -ErrorAction Stop | Select-Object -First 33)
        if($adapters.Count -gt 32 -or $settings.Count -gt 32){throw 'DoH offload inventory'};foreach($row in @($adapters)+@($settings)){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'DoH offload inventory'}};return @{adapters=$adapters;settings=$settings}
    }
    function Read-PrivateDoHTopology {
        $views=[Collections.Generic.List[object]]::new();$v4=[Collections.Generic.List[object]]::new();$v6=[Collections.Generic.List[object]]::new()
        foreach($pass in @(0,1)){
            $inventory=Read-PrivateDoHInventory;$view=[Collections.Generic.List[object]]::new()
            foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
                $o=@{code='empty';category=-1;cimStatus=-1;hresult=0;binding=$null};$rows=@();$ok=$true
                try{$rows=@(Find-NetRoute -RemoteIPAddress $address -ErrorAction Stop | Select-Object -First 3)}catch{$ok=$false;$o.code='read-refused';$o.category=[int]$_.CategoryInfo.Category;$failure=$_.Exception;for($depth=0;$null -ne $failure -and $depth -lt 16;$depth++){$o.hresult=[int]$failure.HResult;if($failure -is [Microsoft.Management.Infrastructure.CimException]){$n=[int]$failure.NativeErrorCode;if($n -ge 0 -and $n -le 65535){$o.cimStatus=$n}};$failure=$failure.InnerException}}
                if($ok -and $rows.Count -gt 0){try{foreach($row in $rows){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'DoH offload route'}};$o.binding=Read-NativeOffloadBinding $rows $inventory.adapters $inventory.settings;$o.code='matched'}catch{$o.code='binding-refused';$o.binding=$null}};$view.Add($o)
            };$views.Add(@($view.ToArray()))
            foreach($family in @('IPv4','IPv6')){$rows=@(Get-NetRoute -AddressFamily $family -PolicyStore ActiveStore -ErrorAction Stop | Select-Object -First 257);foreach($row in $rows){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'DoH offload table'}};$snapshot=Read-NativeIPRouteTable $rows $family;if($family -ceq 'IPv4'){$v4.Add($snapshot)}else{$v6.Add($snapshot)}}
        }
        $observations=[Collections.Generic.List[object]]::new();foreach($i in @(0,1,2,3)){$observations.Add(@{mask=@(1,2,4,8)[$i];first=$views[0][$i];second=$views[1][$i]})}
        $t4=ConvertTo-NativeIPv6RouteTableEvidence $v4[0] $v4[1];$t6=ConvertTo-NativeIPv6RouteTableEvidence $v6[0] $v6[1];return (New-NativeDoHOffloadPlan @($observations.ToArray()) $t4 $t6)
    }
    function Get-PrivateDoHDigest([byte[]]$Bytes) {$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
    function Wait-PrivateDoHState([object]$Entry,[string]$Mode) {
        for($attempt=0;$attempt -lt 4;$attempt++){
            try{$inventory=Read-PrivateDoHInventory;$binding=Read-NativeOffloadOwnerSnapshot $inventory.adapters $inventory.settings $Entry.binding.guid;if(Test-NativeDoHOffloadState $Entry $binding $Mode){return @{inventory=$inventory;binding=$binding}}}catch{}
            if($attempt -lt 3){Start-Sleep -Milliseconds 500}
        };throw 'DoH offload readback'
    }
    $stage='plan'
    if($Operation -ceq 'prepare'){
        if($Ordinal -ne -1 -or $ExpectedDigest){throw 'DoH offload plan'};$stage='route';$plan=Read-PrivateDoHTopology;$stage='output';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($plan | ConvertTo-Json -Depth 6 -Compress));if($bytes.Length -gt 65536){throw 'DoH offload plan'}
        $stream=[IO.FileStream]::new($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()};$digestOut=Get-PrivateDoHDigest $bytes;$r.identityVerified=$true;$r.readbackVerified=$true;$r.topologyVerified=$true
    }else{
        if($ExpectedDigest -cnotmatch '^[a-f0-9]{64}$' -or (([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'DoH offload plan'}
        $lock=[IO.FileStream]::new($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);if($lock.Length -lt 1 -or $lock.Length -gt 65536){throw 'DoH offload plan'};$bytes=[byte[]]::new([int]$lock.Length);$at=0;while($at -lt $bytes.Length){$n=$lock.Read($bytes,$at,$bytes.Length-$at);if($n -le 0){throw 'DoH offload plan'};$at+=$n};if($lock.ReadByte() -ne -1 -or (Get-PrivateDoHDigest $bytes) -cne $ExpectedDigest){throw 'DoH offload plan'}
        $plan=Read-NativeDoHOffloadPlan (([Text.UTF8Encoding]::new($false,$true).GetString($bytes)) | ConvertFrom-Json -ErrorAction Stop)
        if($Operation -ceq 'verify'){
            if($Ordinal -ne -1){throw 'DoH offload plan'};$stage='route';$fresh=Read-PrivateDoHTopology;if(-not (Test-NativeDoHOffloadTopology $plan $fresh)){throw 'DoH offload identity'};$r.identityVerified=$true
            foreach($entry in $plan.adapters){$found=$null;foreach($current in $fresh.adapters){if($current.binding.guid -ceq $entry.binding.guid){$found=$current.binding;break}};if($null -eq $found -or -not (Test-NativeDoHOffloadState $entry $found 'stage')){throw 'DoH offload state'}};$r.readbackVerified=$true;$r.topologyVerified=$true
        }else{
            if($Ordinal -lt 0 -or $Ordinal -ge $plan.adapters.Count){throw 'DoH offload plan'};$entry=$plan.adapters[$Ordinal];$stage='identity';$view=Wait-PrivateDoHState $entry $(if($Operation -ceq 'stage'){'restore'}else{'recover'});$r.identityVerified=$true;$current=$view.binding
            if($Operation -ceq 'stage'){
                $stage='route';$i=0;foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){$bit=@(1,2,4,8)[$i];$i++;if(($entry.endpointMask -band $bit) -eq 0){continue};$rows=@(Find-NetRoute -RemoteIPAddress $address -ErrorAction Stop | Select-Object -First 3);foreach($row in $rows){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'DoH offload route'}};$route=Read-NativeOffloadBinding $rows $view.inventory.adapters $view.inventory.settings;if(-not (Test-NativeOffloadBindingEqual $current $route)){throw 'DoH offload identity'}}
            }
            $v4=if($Operation -ceq 'stage' -and ($entry.familyMask -band 1) -ne 0){$false}else{$entry.binding.IPv4Enabled};$v6=if($Operation -ceq 'stage' -and ($entry.familyMask -band 2) -ne 0){$false}else{$entry.binding.IPv6Enabled}
            if($current.IPv4Enabled -ne $v4 -or $current.IPv6Enabled -ne $v6){$setting=Select-NativeOffloadSetting $current $view.inventory.settings;$stage='apply';$r.restartRequested=$true;[void](Set-NetAdapterLso -InputObject $setting -V1IPv4Enabled $entry.binding.V1IPv4Enabled -IPv4Enabled $v4 -IPv6Enabled $v6 -NoRestart:$false -Confirm:$false -ErrorAction Stop);$r.restartReturned=$true;$r.changed=$true}
            $stage='readback';[void](Wait-PrivateDoHState $entry $(if($Operation -ceq 'stage'){'stage'}else{'restore'}));$r.readbackVerified=$true;$r.restored=($Operation -ceq 'restore')
        }
    }
    $r.adapters=$plan.adapters.Count;$r.matchedMask=$plan.matchedMask;$r.unroutedMask=$plan.unroutedMask;$r.code='none'
}catch{
    $failure=$_.Exception;for($depth=0;$null -ne $failure -and $depth -lt 16;$depth++){$mapped=switch -CaseSensitive ($failure.Message){'DoH offload plan'{'plan'}'DoH offload route'{'route'}'DoH offload table'{'table'}'DoH offload inventory'{'inventory'}'DoH offload identity'{'identity'}'DoH offload state'{'state'}'DoH offload capability'{'capability'}'DoH offload readback'{'readback'}'IPv6 route bound'{'table-bound'}'IPv6 route class'{'table-class'}'IPv6 route family'{'table-family'}'IPv6 route store'{'table-store'}'IPv6 route index'{'table-index'}'IPv6 route prefix'{'table-prefix'}'IPv6 route next-hop'{'table-next-hop'}'IPv6 route metric'{'table-metric'}default{''}};if($mapped){$stage=$mapped;break};$failure=$failure.InnerException};$r.code=$stage;$digestOut=''
}finally{if($null -ne $lock){$lock.Dispose()}}
# Private IPC: the journal digest is consumed only by the parent, never copied to public evidence.
[Console]::Out.WriteLine((@{summary=$r;digest=$digestOut} | ConvertTo-Json -Depth 4 -Compress))
