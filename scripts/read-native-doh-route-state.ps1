# Read-only four-endpoint route/adapter/LSO discovery. Fresh hosted stock process only.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$stage='environment'
$r=@{schemaVersion=1;code='environment';matchedMask=0;sameAdapterMask=0;adapterCount=0;allConsistent=$false;allRoutesMatched=$false;records=@()}
try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$'){throw 'Hosted route probe required'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop route boundary'}}
    foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets','NetAdapter','NetTCPIP')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop};$PSModuleAutoLoadingPreference='None'
    . (Join-Path $PSScriptRoot 'native-offload-state.ps1');. (Join-Path $PSScriptRoot 'native-doh-route-state.ps1');$stage='metadata'
    foreach($spec in @(@{name='Find-NetRoute';parameters=@('RemoteIPAddress')},@{name='Get-NetAdapter';parameters=@('IncludeHidden')},@{name='Get-NetAdapterLso';parameters=@('Name','IncludeHidden')})){$command=Get-Command $spec.name -ErrorAction Stop;foreach($name in $spec.parameters){if(-not $command.Parameters.ContainsKey($name)){throw 'Route capability'}}}
    $views=[Collections.Generic.List[object]]::new()
    foreach($pass in @(0,1)){
        $stage='inventory';$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object -First 33);$settings=@(Get-NetAdapterLso -Name '*' -IncludeHidden -ErrorAction Stop | Select-Object -First 33)
        if($adapters.Count -gt 32 -or $settings.Count -gt 32){throw 'Route inventory bound'};foreach($row in @($adapters)+@($settings)){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Route inventory type'}}
        $view=[Collections.Generic.List[object]]::new();$stage='read'
        foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
            $observation=@{code='empty';category=-1;cimStatus=-1;hresult=0;binding=$null};$routes=@();$read=$true
            try{$routes=@(Find-NetRoute -RemoteIPAddress $address -ErrorAction Stop | Select-Object -First 3)}catch{
                $read=$false;$observation.code='read-refused';$observation.category=[int]$_.CategoryInfo.Category;$failure=$_.Exception
                for($depth=0;$null -ne $failure -and $depth -lt 16;$depth++){$observation.hresult=[int]$failure.HResult;if($failure -is [Microsoft.Management.Infrastructure.CimException]){$value=[int]$failure.NativeErrorCode;if($value -ge 0 -and $value -le 65535){$observation.cimStatus=$value}};$failure=$failure.InnerException}
            }
            if($read -and $routes.Count -gt 0){
                try{foreach($row in $routes){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Route row type'}};$observation.binding=Read-NativeOffloadBinding $routes $adapters $settings;$observation.code='matched'}catch{$observation.code='binding-refused';$observation.binding=$null}
            };$view.Add($observation)
        };$views.Add(@($view.ToArray()))
    }
    $observations=[Collections.Generic.List[object]]::new();foreach($ordinal in @(0,1,2,3)){$observations.Add(@{mask=@(1,2,4,8)[$ordinal];first=$views[0][$ordinal];second=$views[1][$ordinal]})}
    $r=ConvertTo-NativeDoHRouteEvidence @($observations.ToArray())
}catch{$r=@{schemaVersion=1;code=$stage;matchedMask=0;sameAdapterMask=0;adapterCount=0;allConsistent=$false;allRoutesMatched=$false;records=@()}}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Depth 4 -Compress))
