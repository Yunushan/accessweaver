# READ-ONLY metadata producer. Fresh hosted stock Windows PowerShell only.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Hosted stock metadata reader required'}
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
$r=@{code='unavailable';stockShell=$true;sessionCommandsListed=$false;providerCommandsListed=$false;privateFileParametersListed=$false;packetFilterParametersListed=$false;sessionReadbackParametersListed=$false;providerReadbackParametersListed=$false;sessionInventory='not-inspected';providerInventory='not-inspected'}
function Test-TraceCapabilityParameters([string]$Name,[string[]]$Names){
    $c=Get-Command -Name $Name -ErrorAction Stop
    foreach($name in $Names){if(-not $c.Parameters.ContainsKey($name)){return $false}};return $true
}
try{
    Import-Module ([IO.Path]::Combine($PSHOME,'Modules','CimCmdlets','CimCmdlets.psd1')) -ErrorAction Stop
    $PSModuleAutoLoadingPreference='None'
    Import-Module ([IO.Path]::Combine($PSHOME,'Modules','NetEventPacketCapture','NetEventPacketCapture.psd1')) -ErrorAction Stop
    $r.privateFileParametersListed=Test-TraceCapabilityParameters 'New-NetEventSession' @('Name','CaptureMode','LocalFilePath','MaxFileSize')
    $r.sessionCommandsListed=$true
    foreach($name in @('New-NetEventSession','Start-NetEventSession','Stop-NetEventSession','Remove-NetEventSession')){if(-not (Test-TraceCapabilityParameters $name @('Name'))){$r.sessionCommandsListed=$false}}
    $r.providerCommandsListed=(Test-TraceCapabilityParameters 'Add-NetEventPacketCaptureProvider' @('SessionName')) -and (Test-TraceCapabilityParameters 'Remove-NetEventPacketCaptureProvider' @('SessionName'))
    $r.packetFilterParametersListed=Test-TraceCapabilityParameters 'Add-NetEventPacketCaptureProvider' @('SessionName','IpAddresses','IpProtocols','TruncationLength','CaptureType','Level')
    $r.sessionReadbackParametersListed=Test-TraceCapabilityParameters 'Get-NetEventSession' @('Name')
    $r.providerReadbackParametersListed=Test-TraceCapabilityParameters 'Get-NetEventPacketCaptureProvider' @('SessionName')
    try{$items=@(Get-NetEventSession -ErrorAction Stop | Select-Object -First 9);$r.sessionInventory=if($items.Count -eq 0){'empty'}elseif($items.Count -le 8){'present'}else{'bound'}}catch{$r.sessionInventory=if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){'empty'}else{'unknown'}}
    try{$items=@(Get-NetEventPacketCaptureProvider -ErrorAction Stop | Select-Object -First 9);$r.providerInventory=if($items.Count -eq 0){'empty'}elseif($items.Count -le 8){'present'}else{'bound'}}catch{$r.providerInventory=if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){'empty'}else{'unknown'}}
    $r.code='complete'
}catch{$r.code='unavailable'}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
