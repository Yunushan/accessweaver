# Fresh-host private extraction only. stdout is a closed metadata projection.
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$CapturePath,[Parameter(Mandatory=$true)][ValidateRange(1,4096)][int]$ExpectedFragments,[Parameter(Mandatory=$true)][ValidateRange(1,16777215)][long]$ExpectedCaptureBytes)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
$r=@{code='environment';records=0;frames=0;bytesWritten=0;payloadRead=$false};$stage='environment';$stream=$null;$reader=$null;$selector=$null;$provider=$null;$output=$null
try{
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$' -or $env:ACCESSWEAVER_EXPECT_GOOS -cne 'windows' -or $env:ACCESSWEAVER_EXPECT_GOARCH -cnotin @('amd64','arm64')){throw 'Hosted private extraction guard'}
    foreach($name in @('ACCESSWEAVER_HISTORY_INTEROP','ACCESSWEAVER_RECONCILIATION_INTEROP','ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP','ACCESSWEAVER_SUPPORT_INTEROP')){if($null -ne [Environment]::GetEnvironmentVariable($name,'Process')){throw 'Interop extraction boundary'}}
    foreach($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1'))) -ErrorAction Stop};$PSModuleAutoLoadingPreference='None'
    . (Join-Path $PSScriptRoot 'native-netevent-control.ps1')
    $stage='path';$file=[IO.Path]::GetFullPath($CapturePath);$parent=[IO.Path]::GetDirectoryName($file);$local=[Environment]::GetFolderPath('LocalApplicationData')
    if(-not $file.Equals($CapturePath,[StringComparison]::Ordinal) -or [IO.Path]::GetFileName($file) -cne 'capture.etl' -or [IO.Path]::GetFileName($parent) -cnotmatch '^AccessWeaver-NetEventControl-[a-f0-9]{32}$' -or -not [IO.Path]::GetDirectoryName($parent).Equals($local,[StringComparison]::OrdinalIgnoreCase)){throw 'Private extraction path'}
    $current=$file;while($current){if(([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Private extraction reparse'};$next=[IO.Path]::GetDirectoryName($current);if($next -eq $current){break};$current=$next}
    $stream=[IO.FileStream]::new($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);if($stream.Length -ne $ExpectedCaptureBytes -or $stream.Length -ge 16MB){throw 'Private extraction file bound'}
    $stage='source-schema';$provider=[Diagnostics.Eventing.Reader.ProviderMetadata]::new('Microsoft-Windows-NDIS-PacketCapture');if($provider.Id -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef'){throw 'Private provider schema'}
    $signature='';$definitions=0;$matches=0
    foreach($definition in $provider.Events){if(++$definitions -gt 64){throw 'Private provider schema bound'};if($definition.Id -eq 1001 -and $definition.Version -eq 0){$matches++;if((Get-NativeNDISCatalogClass 1001 0 ([int]$definition.Level.Value) $definition.Template) -cne 'fragment'){throw 'Private fragment schema'};$signature=Get-NativeNDISTemplateSignature $definition.Template}}
    if($matches -ne 1){throw 'Private fragment schema ambiguity'}
    $modern=$signature.EndsWith('|GftFlowEntryId:win:UInt64:|GftOffloadInformation:win:UInt64:',[StringComparison]::Ordinal)
    $names=@('FragmentSize','Fragment');if($modern){$names+=@('GftFlowEntryId','GftOffloadInformation')}
    $paths=[Collections.Generic.List[string]]::new();foreach($name in $names){$paths.Add("Event/EventData/Data[@Name='$name']")};$selector=[Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($paths)
    $stage='read';$query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($file,[Diagnostics.Eventing.Reader.PathType]::FilePath);$query.ReverseDirection=$false;$query.TolerateQueryErrors=$false
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=16;$clock=[Diagnostics.Stopwatch]::StartNew();$rows=[Collections.Generic.List[object]]::new();$projectedBytes=0
    while($true){
        if($r.records -ge 4096 -or $clock.Elapsed.TotalSeconds -ge 3){$stage='bound';throw 'Private extraction record bound'}
        $stage='read';$record=$reader.ReadEvent([TimeSpan]::FromMilliseconds(250));if($null -eq $record){break}
        try{
            $r.records++
            if($record.ProviderId -ne [guid]'2ed6006e-4729-4609-b423-3ee7bcd678ef' -or $record.Id -ne 1001){continue}
            $stage='record';$r.payloadRead=$true;$values=$record.GetPropertyValues($selector)
            try{$row=ConvertTo-NativeNDISPrivateRecord $record.ProviderId $record.Id $record.Version $record.Keywords $values $modern}catch{if($_.Exception.Message -ceq 'NDIS private record offload'){$stage='offload'};throw}
            $projectedBytes+=$row.fragment.Length+512;if($projectedBytes -gt 16MB -or $rows.Count -ge $ExpectedFragments){$stage='bound';throw 'Private extraction byte bound'}
            $rows.Add($row);$r.frames=$rows.Count
        }finally{$record.Dispose()}
    }
    if($r.frames -ne $ExpectedFragments -or $stream.Length -ne $ExpectedCaptureBytes){$stage='bound';throw 'Private extraction count changed'}
    $stage='output';$bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{schemaVersion=1;records=@($rows.ToArray())} | ConvertTo-Json -Depth 4 -Compress));if($bytes.Length -gt 16MB){throw 'Private extraction output bound'}
    $output=[IO.FileStream]::new((Join-Path $parent 'frames.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$output.Write($bytes,0,$bytes.Length);$output.Flush();$output.Dispose();$output=$null;$r.bytesWritten=$bytes.Length;$r.code='none'
}catch{$r.code=$stage}finally{if($null -ne $output){$output.Dispose()};if($null -ne $reader){$reader.Dispose()};if($null -ne $selector){$selector.Dispose()};if($null -ne $provider){$provider.Dispose()};if($null -ne $stream){$stream.Dispose()}}
[Console]::Out.WriteLine(($r | ConvertTo-Json -Compress))
