# Reversible, exact-owner capture instrumentation. Fresh disposable hosted VM only.
[CmdletBinding()]param([Parameter(Mandatory=$true)][ValidateSet('stage','restore')][string]$Operation,[Parameter(Mandatory=$true)][string]$PrivateRoot)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
$r=@{schemaVersion=1;operation=$Operation;code='environment';identityVerified=$false;changeRequired=$false;changeAttempted=$false;changed=$false;readbackVerified=$false;restored=$false;originalIPv4=$null;currentIPv4=$null;preservedOthers=$false};$stage='environment'
try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$'){throw 'Fresh hosted stock operation required'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop offload boundary'}}
    foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','CimCmdlets','NetAdapter','NetTCPIP')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop};$PSModuleAutoLoadingPreference='None'
    . (Join-Path $PSScriptRoot 'native-offload-state.ps1');$r=New-NativeOffloadChangeEvidence $Operation
    $stage='path-canonical';$root=[IO.Path]::GetFullPath($PrivateRoot);$local=[Environment]::GetFolderPath('LocalApplicationData')
    if(-not $root.Equals($PrivateRoot,[StringComparison]::Ordinal) -or [IO.Path]::GetFileName($root) -cnotmatch '^AccessWeaver-NetEventControl-[a-f0-9]{32}$' -or -not [IO.Path]::GetDirectoryName($root).Equals($local,[StringComparison]::OrdinalIgnoreCase)){throw 'Offload private path'}
    $stage='path-ancestry';$current=$root;while($current){if(([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Offload reparse path'};$next=[IO.Path]::GetDirectoryName($current);if($next -eq $current){break};$current=$next}
    $stage='path-acl';$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$security=Get-Acl -LiteralPath $root -ErrorAction Stop
    if(-not $security.AreAccessRulesProtected -or $security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $identity.User.Value){throw 'Offload root owner'}
    foreach($rule in $security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -cnotin @($identity.User.Value,'S-1-5-18','S-1-5-32-544')){throw 'Offload root access'}}
    $planPath=Join-Path $root 'capture-offload-plan.json'
    function Read-PrivateOffloadInventory([bool]$Route) {
        $routes=@();if($Route){$routes=@(Find-NetRoute -RemoteIPAddress '8.8.8.8' -ErrorAction Stop | Select-Object -First 3)}
        $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object -First 33);$settings=@(Get-NetAdapterLso -Name '*' -IncludeHidden -ErrorAction Stop | Select-Object -First 33)
        foreach($row in @($routes)+@($adapters)+@($settings)){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Offload native row'}}
        return @{routes=$routes;adapters=$adapters;settings=$settings}
    }
    $stage='read'
    if($Operation -ceq 'stage'){
        $inventory=Read-PrivateOffloadInventory $true;$before=Read-NativeOffloadBinding $inventory.routes $inventory.adapters $inventory.settings
        $inventory=Read-PrivateOffloadInventory $true;$check=Read-NativeOffloadBinding $inventory.routes $inventory.adapters $inventory.settings
        if(-not (Test-NativeOffloadBindingEqual $before $check)){$stage='identity';throw 'Offload preflight drift'}
        if($before.maximumVersion -ne 2){$stage='state';throw 'Offload LSOv2 unsupported'}
        $r.originalIPv4=$before.IPv4Enabled;$r.changeRequired=$before.IPv4Enabled;$r.identityVerified=$true
        $plan=@{schemaVersion=1;binding=$before;changeAttempted=$before.IPv4Enabled};$stage='output'
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($plan | ConvertTo-Json -Depth 3 -Compress));if($bytes.Length -gt 16384){throw 'Offload plan bound'}
        $stream=[IO.FileStream]::new($planPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        $r.changeAttempted=$before.IPv4Enabled
        if($before.IPv4Enabled){$setting=Select-NativeOffloadSetting $check $inventory.settings;$stage='apply';[void](Set-NetAdapterLso -InputObject $setting -IPv4Enabled $false -NoRestart -Confirm:$false -ErrorAction Stop);$r.changed=$true}
        $stage='read';$inventory=Read-PrivateOffloadInventory $true;$after=Read-NativeOffloadBinding $inventory.routes $inventory.adapters $inventory.settings
        if(-not (Test-NativeOffloadOwner $before $after) -or $before.index -ne $after.index -or -not [string]::Equals($before.name,$after.name,[StringComparison]::Ordinal)){$stage='identity';throw 'Offload owner drift'}
        $r.preservedOthers=Test-NativeOffloadOtherSettings $before $after;$r.currentIPv4=$after.IPv4Enabled
        if(-not $r.preservedOthers -or $after.IPv4Enabled){$stage='state';throw 'Offload stage readback'};$r.readbackVerified=$true;$r.code='none'
    }else{
        $stage='plan'
        if(-not [IO.File]::Exists($planPath)){$r.code='not-staged';$r.restored=$true}else{
            if(([IO.File]::GetAttributes($planPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Offload plan reparse'}
            $stream=[IO.FileStream]::new($planPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{if($stream.Length -le 0 -or $stream.Length -gt 16384){throw 'Offload plan size'};$text=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true)).ReadToEnd();$plan=$text | ConvertFrom-Json -ErrorAction Stop}finally{$stream.Dispose()}
            if($plan -isnot [pscustomobject] -or @($plan.PSObject.Properties).Count -ne 3 -or $plan.schemaVersion -isnot [int] -or $plan.schemaVersion -ne 1 -or $plan.changeAttempted -isnot [bool] -or $plan.binding -isnot [pscustomobject] -or @($plan.binding.PSObject.Properties).Count -ne 9){throw 'Offload plan shape'}
            $before=@{};foreach($key in @('index','guid','name','description','instance','maximumVersion','V1IPv4Enabled','IPv4Enabled','IPv6Enabled')){if($null -eq $plan.binding.PSObject.Properties[$key]){throw 'Offload plan field'};$before[$key]=$plan.binding.$key}
            foreach($key in @('V1IPv4Enabled','IPv4Enabled','IPv6Enabled')){if($before[$key] -isnot [bool]){throw 'Offload plan state'}}
            $guid=[guid]::Empty;if($before.guid -isnot [string] -or -not [guid]::TryParse($before.guid,[ref]$guid) -or $guid -eq [guid]::Empty -or $before.index -isnot [int] -or $before.index -le 0 -or $before.maximumVersion -isnot [int] -or $before.maximumVersion -ne 2 -or $plan.changeAttempted -ne $before.IPv4Enabled){throw 'Offload plan identity'}
            foreach($key in @('name','description','instance')){if($before[$key] -isnot [string] -or $before[$key].Length -lt 1 -or $before[$key].Length -gt 4096){throw 'Offload plan text'}}
            $r.originalIPv4=$before.IPv4Enabled;$r.changeRequired=$before.IPv4Enabled;$r.changeAttempted=$plan.changeAttempted
            $stage='read';$inventory=Read-PrivateOffloadInventory $false;$check=Read-NativeOffloadOwnerSnapshot $inventory.adapters $inventory.settings $before.guid
            if(-not (Test-NativeOffloadOwner $before $check)){$stage='identity';throw 'Offload restore owner'};$r.identityVerified=$true
            if(-not (Test-NativeOffloadOtherSettings $before $check)){$stage='state';throw 'Offload foreign state drift'}
            if($check.IPv4Enabled -ne $before.IPv4Enabled){$setting=Select-NativeOffloadSetting $check $inventory.settings;$stage='apply';[void](Set-NetAdapterLso -InputObject $setting -V1IPv4Enabled $before.V1IPv4Enabled -IPv4Enabled $before.IPv4Enabled -IPv6Enabled $before.IPv6Enabled -NoRestart -Confirm:$false -ErrorAction Stop);$r.changed=$true}
            $stage='read';$inventory=Read-PrivateOffloadInventory $false;$after=Read-NativeOffloadOwnerSnapshot $inventory.adapters $inventory.settings $before.guid
            if(-not (Test-NativeOffloadOwner $before $after)){$stage='identity';throw 'Offload final owner drift'}
            $r.currentIPv4=$after.IPv4Enabled;$r.preservedOthers=Test-NativeOffloadOtherSettings $before $after
            if(-not $r.preservedOthers -or $after.IPv4Enabled -ne $before.IPv4Enabled){$stage='state';throw 'Offload restoration readback'};$r.readbackVerified=$true;$r.restored=$true;$r.code='none'
        }
    }
}catch{$r.code=$stage}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
