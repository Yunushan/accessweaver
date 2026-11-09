# Guarded private ETL header phase map. No packet properties or event text are read.
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$CapturePath,[Parameter(Mandatory=$true)][ValidateRange(1,4096)][int]$ExpectedFragments,[Parameter(Mandatory=$true)][ValidateRange(1,16777215)][long]$ExpectedCaptureBytes,[Parameter(Mandatory=$true)][long]$BoundaryUtcTicks)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
$r=@{schemaVersion=1;code='environment';records=0;frames=0;privateMapWritten=$false};$stage='environment';$stream=$null;$reader=$null;$output=$null
try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$' -or $env:ACCESSWEAVER_EXPECT_GOOS -cne 'windows' -or $env:ACCESSWEAVER_EXPECT_GOARCH -cnotin @('amd64','arm64')){throw 'Hosted private header guard'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop phase boundary'}}
    foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop};$PSModuleAutoLoadingPreference='None'
    $stage='boundary';if($BoundaryUtcTicks -le 0 -or $BoundaryUtcTicks -gt [DateTime]::MaxValue.Ticks){throw 'Phase boundary ticks'}
    $stage='path';$file=[IO.Path]::GetFullPath($CapturePath);$parent=[IO.Path]::GetDirectoryName($file);$local=[Environment]::GetFolderPath('LocalApplicationData')
    if(-not $file.Equals($CapturePath,[StringComparison]::Ordinal) -or [IO.Path]::GetFileName($file) -cne 'capture.etl' -or [IO.Path]::GetFileName($parent) -cnotmatch '^AccessWeaver-NetEventControl-[a-f0-9]{32}$' -or -not [IO.Path]::GetDirectoryName($parent).Equals($local,[StringComparison]::OrdinalIgnoreCase)){throw 'Private phase path'}
    foreach($checked in @($file,(Join-Path $parent 'frames.json'))){$current=$checked;while($current){if(([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Private phase reparse'};$next=[IO.Path]::GetDirectoryName($current);if($next -eq $current){break};$current=$next}}
    $stream=[IO.FileStream]::new($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);if($stream.Length -ne $ExpectedCaptureBytes -or $stream.Length -ge 16MB){throw 'Private phase file bound'}
    $stage='read';$query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($file,[Diagnostics.Eventing.Reader.PathType]::FilePath);$query.ReverseDirection=$false;$query.TolerateQueryErrors=$false
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=16;$clock=[Diagnostics.Stopwatch]::StartNew();$phases=[Collections.Generic.List[int]]::new()
    while($true){
        if($r.records -ge 4096 -or $clock.Elapsed.TotalSeconds -ge 3){$stage='bound';throw 'Private phase record bound'}
        $stage='read';$record=$reader.ReadEvent([TimeSpan]::FromMilliseconds(250));if($null -eq $record){break}
        try{
            $r.records++
            if($record.ProviderId -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef' -or $record.Id -ne 1001){continue}
            $stage='timestamp';if($record.Version -ne 0 -or $record.TimeCreated -isnot [DateTime] -or $record.TimeCreated.Kind -eq [DateTimeKind]::Unspecified){throw 'Private phase timestamp'}
            $ticks=$record.TimeCreated.ToUniversalTime().Ticks;$phase=if($ticks -lt $BoundaryUtcTicks){0}elseif($ticks -eq $BoundaryUtcTicks){1}else{2}
            if($phases.Count -ge $ExpectedFragments){$stage='bound';throw 'Private phase frame bound'};$phases.Add($phase);$r.frames=$phases.Count
        }finally{$record.Dispose()}
    }
    if($r.frames -ne $ExpectedFragments -or $stream.Length -ne $ExpectedCaptureBytes){$stage='bound';throw 'Private phase enumeration changed'}
    $stage='source';$frames=Join-Path $parent 'frames.json';$frameInfo=Get-Item -LiteralPath $frames -Force -ErrorAction Stop;if($frameInfo.PSIsContainer -or $frameInfo.Length -le 0 -or $frameInfo.Length -gt 16MB){throw 'Private phase source bound'}
    $digest=(Get-FileHash -LiteralPath $frames -Algorithm SHA256).Hash.ToLowerInvariant()
    $stage='output';$bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{schemaVersion=1;records=$r.records;sourceFramesSHA256=$digest;phases=@($phases.ToArray())} | ConvertTo-Json -Depth 3 -Compress));if($bytes.Length -gt 65536){throw 'Private phase output bound'}
    $output=[IO.FileStream]::new((Join-Path $parent 'frame-phases.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$output.Write($bytes,0,$bytes.Length);$output.Flush($true);$output.Dispose();$output=$null;$r.privateMapWritten=$true;$r.code='none'
}catch{$r.code=$stage}finally{if($null -ne $output){$output.Dispose()};if($null -ne $reader){$reader.Dispose()};if($null -ne $stream){$stream.Dispose()}}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
