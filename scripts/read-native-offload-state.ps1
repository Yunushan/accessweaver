# READ ONLY. No setter/start/restart command is invoked, and no identifiers leave.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
$r=@{code='environment';routeMatched=$false;adapterMatched=$false;settingMatched=$false;getCapability=$false;setCapability=$false;noRestartCapability=$false;ipv4Enabled=$null;ipv6Enabled=$null;v1Ipv4Enabled=$null;maximumVersion=-1;routeStable=$false;identityStable=$false;settingsChanged=$false};$stage='environment'
try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$'){throw 'Fresh hosted stock reader required'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop offload boundary'}}
    foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets','NetAdapter','NetTCPIP')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop};$PSModuleAutoLoadingPreference='None'
    . (Join-Path $PSScriptRoot 'native-offload-state.ps1');$r=New-NativeOffloadEvidence 'metadata';$stage='metadata'
    foreach($spec in @(@{name='Find-NetRoute';parameters=@('RemoteIPAddress')},@{name='Get-NetAdapter';parameters=@('IncludeHidden')},@{name='Get-NetAdapterLso';parameters=@('Name','IncludeHidden')},@{name='Set-NetAdapterLso';parameters=@('InputObject','IPv4Enabled','IPv6Enabled','V1IPv4Enabled','NoRestart','Confirm')})){
        $command=Get-Command -Name $spec.name -ErrorAction Stop;foreach($parameter in $spec.parameters){if(-not $command.Parameters.ContainsKey($parameter)){throw 'Offload command metadata'}}
    };$r.getCapability=$true;$r.setCapability=$true;$r.noRestartCapability=$true
    function Read-PrivateOffloadBinding {
        $routes=@(Find-NetRoute -RemoteIPAddress '8.8.8.8' -ErrorAction Stop | Select-Object -First 3)
        $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object -First 33)
        $settings=@(Get-NetAdapterLso -Name '*' -IncludeHidden -ErrorAction Stop | Select-Object -First 33)
        foreach($row in @($routes)+@($adapters)+@($settings)){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Offload property'}}
        return (Read-NativeOffloadBinding $routes $adapters $settings)
    }
    $stage='read';$before=Read-PrivateOffloadBinding;$r.routeMatched=$true;$r.adapterMatched=$true;$r.settingMatched=$true
    $after=Read-PrivateOffloadBinding;$r.routeStable=($before.index -eq $after.index);$r.identityStable=Test-NativeOffloadBindingEqual $before $after
    if(-not $r.routeStable -or -not $r.identityStable){$stage='drift';throw 'Offload binding drift'}
    $r.ipv4Enabled=$after.IPv4Enabled;$r.ipv6Enabled=$after.IPv6Enabled;$r.v1Ipv4Enabled=$after.V1IPv4Enabled;$r.maximumVersion=$after.maximumVersion;$r.code='none'
}catch{
    $r.code=$stage
    $failure=$_.Exception;for($depth=0;$depth -lt 8 -and $null -ne $failure;$depth++){$mapped=switch -CaseSensitive ($failure.Message){'Offload route'{'route'}'Offload adapter'{'adapter'}'Offload setting'{'setting'}'Offload property'{'property'}'Offload bound'{'bound'}default{''}};if($mapped){$r.code=$mapped;break};$failure=$failure.InnerException}
}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
