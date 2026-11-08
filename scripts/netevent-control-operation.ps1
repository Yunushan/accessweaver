# Guarded native boundary. Only the exact six operation names are admitted.
[CmdletBinding()]param([Parameter(Mandatory=$true)][ValidateSet('preflight','create','provider','start','stop','remove')][string]$Operation,[Parameter(Mandatory=$true)][string]$PlanBase64)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Fresh hosted stock boundary required'}
foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop boundary refused'}}
foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop}
$PSModuleAutoLoadingPreference='None'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','NetEventPacketCapture','NetEventPacketCapture.psd1')) -ErrorAction Stop
function Assert-NativeOrdinaryPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){
        if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Native fixture reparse boundary refused'}}
        $next=Split-Path -Parent $current;if($next -eq $current){break};$current=$next
    }
}
. (Join-Path $PSScriptRoot 'native-netevent-control.ps1')
$r=@{code='operation';sessionGuid='';state='unknown';sessionVerified=$false;providerVerified=$false;emptyBefore=$false;emptyAfter=$false}
try{
    if($PlanBase64.Length -gt 8192){throw 'NetEvent plan'}
    $plan=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PlanBase64)) | ConvertFrom-Json -ErrorAction Stop
    if(@($plan.PSObject.Properties).Count -ne 4 -or @($plan.PSObject.Properties.Name | Where-Object {$_ -cnotin @('name','file','guid','originalVerified')}).Count -ne 0){throw 'NetEvent plan'}
    $file=[IO.Path]::GetFullPath($plan.file);$parent=[IO.Path]::GetDirectoryName($file);$local=[Environment]::GetFolderPath('LocalApplicationData')
    if([IO.Path]::GetFileName($parent) -cnotmatch '^AccessWeaver-NetEventControl-[a-f0-9]{32}$' -or -not [IO.Path]::GetDirectoryName($parent).Equals($local,[StringComparison]::OrdinalIgnoreCase) -or -not $file.Equals($plan.file,[StringComparison]::Ordinal)){throw 'NetEvent plan'}
    Assert-NativeOrdinaryPath $parent;Assert-NativeOrdinaryPath $file
    $r=Invoke-NativeNetEventOperation $Operation $plan
}catch{
    for($e=$_.Exception;$null -ne $e;$e=$e.InnerException){
        $code=switch -CaseSensitive ($e.Message){'NetEvent plan'{'plan'}'NetEvent enum'{'enum'}'NetEvent session'{'session'}'NetEvent identity'{'identity'}'NetEvent configuration'{'configuration'}'NetEvent state'{'state'}'NetEvent provider'{'provider'}'NetEvent filters'{'filters'}'NetEvent inventory'{'inventory'}'NetEvent original'{'original'}default{''}}
        if($code){$r.code=$code;break}
    }
}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
