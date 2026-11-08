# Metadata-only ETL reader. Native execution is restricted to fresh hosted VMs.
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$CapturePath)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8){throw 'Hosted native stock header reader required'}
foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop header boundary refused'}}
foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop}
$PSModuleAutoLoadingPreference='None'
function Assert-NativeOrdinaryPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){
        if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Native fixture reparse boundary refused'}}
        $next=Split-Path -Parent $current;if($next -eq $current){break};$current=$next
    }
}
$r=@{code='unavailable';eventsLost=-1;buffersLost=-1;bufferSize=-1;buffersWritten=-1;maximumFileSize=-1;pointerSize=-1;logFileMode=-1;finalized=$false;closed=$false;nativeCode=-1};$stream=$null
try{
    $file=[IO.Path]::GetFullPath($CapturePath);$parent=[IO.Path]::GetDirectoryName($file);$local=[Environment]::GetFolderPath('LocalApplicationData')
    if([IO.Path]::GetFileName($file) -cne 'capture.etl' -or [IO.Path]::GetFileName($parent) -cnotmatch '^AccessWeaver-NetEventControl-[a-f0-9]{32}$' -or -not [IO.Path]::GetDirectoryName($parent).Equals($local,[StringComparison]::OrdinalIgnoreCase)){throw 'Private header path required'}
    Assert-NativeOrdinaryPath $file
    $stream=[IO.FileStream]::new($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($stream.Length -le 0 -or $stream.Length -ge 16MB){throw 'Private header file bound'}
    Add-Type -Path (Join-Path $PSScriptRoot 'native-etl-header.cs') -ErrorAction Stop
    $value=[AccessWeaverPrivateEtlHeader]::Read($file)
    $r=@{code=$value.Code;eventsLost=$value.EventsLost;buffersLost=$value.BuffersLost;bufferSize=$value.BufferSize;buffersWritten=$value.BuffersWritten;maximumFileSize=$value.MaximumFileSize;pointerSize=$value.PointerSize;logFileMode=$value.LogFileMode;finalized=$value.Finalized;closed=$value.Closed;nativeCode=$value.NativeCode}
}catch{$r.code='unavailable'}finally{if($null -ne $stream){$stream.Dispose()}}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
