# Read-only complete bounded active IPv6 table check; private prefix/next-hop values never emitted.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$stage='environment'
$r=@{schemaVersion=1;code='environment';firstRows=-1;secondRows=-1;firstGoogleMatches=-1;secondGoogleMatches=-1;firstQuad9Matches=-1;secondQuad9Matches=-1;consistent=$false;noEndpointRoutes=$false}
try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$'){throw 'Hosted table probe required'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop table boundary'}}
    foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets','NetTCPIP')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop};$PSModuleAutoLoadingPreference='None'
    . (Join-Path $PSScriptRoot 'native-offload-state.ps1');. (Join-Path $PSScriptRoot 'native-ipv6-route-table.ps1');$stage='metadata';$command=Get-Command 'Get-NetRoute' -ErrorAction Stop;foreach($name in @('AddressFamily','PolicyStore')){if(-not $command.Parameters.ContainsKey($name)){throw 'IPv6 route capability'}}
    $views=[Collections.Generic.List[object]]::new();$stage='read'
    foreach($pass in @(0,1)){$rows=@(Get-NetRoute -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop | Select-Object -First 257);foreach($row in $rows){if($row -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'IPv6 route class'}};$views.Add((Read-NativeIPv6RouteTable $rows))}
    $r=ConvertTo-NativeIPv6RouteTableEvidence $views[0] $views[1]
}catch{
    $failure=$_.Exception;for($depth=0;$null -ne $failure -and $depth -lt 16;$depth++){$mapped=switch -CaseSensitive ($failure.Message){'IPv6 route bound'{'bound'}'IPv6 route class'{'class'}'IPv6 route family'{'family'}'IPv6 route store'{'store'}'IPv6 route index'{'index'}'IPv6 route prefix'{'prefix'}'IPv6 route next-hop'{'next-hop'}'IPv6 route metric'{'metric'}default{''}};if($mapped){$stage=$mapped;break};$failure=$failure.InnerException};$r=@{schemaVersion=1;code=$stage;firstRows=-1;secondRows=-1;firstGoogleMatches=-1;secondGoogleMatches=-1;firstQuad9Matches=-1;secondQuad9Matches=-1;consistent=$false;noEndpointRoutes=$false}
}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
