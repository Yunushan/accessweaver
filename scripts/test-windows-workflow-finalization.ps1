# Selected source functions and inert fake owners only. No native worker,
# installer, mutex, network, service, account or machine configuration runs.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell,[string]$InteropDirectory)
$ErrorActionPreference='Stop'
if($RequireWindowsPowerShell -and ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop')){throw 'Windows PowerShell 5.1 Desktop is required'}
$finalizerProject=Split-Path -Parent $PSScriptRoot
$finalizerSource=Join-Path $finalizerProject 'internal\workflow\windows.ps1'
$finalizerSHA=(Get-FileHash -LiteralPath $finalizerSource -Algorithm SHA256).Hash.ToLowerInvariant()
$finalizerTokens=$null;$finalizerErrors=$null
$finalizerAst=[Management.Automation.Language.Parser]::ParseFile($finalizerSource,[ref]$finalizerTokens,[ref]$finalizerErrors)
if($finalizerErrors.Count){throw 'Finalizer source did not parse'}
$finalizerFunctions=@('Under','Assert-WorkflowUninstallACL','Get-WorkflowUninstallPath','Discover','Assert-NoPendingWorkflowInstallation','Open-WorkflowUninstallBinding','Invoke-WorkflowUninstall','Invoke-WorkflowDeferredUninstaller','Complete-WorkflowFinalization','Assert-WorkflowResultDepth','Assert-WorkflowResultToken','Get-WorkflowResultFailureCode','Throw-WorkflowResultFailure','ConvertTo-WorkflowResultBytes','New-WorkflowResultStream','Write-WorkflowResultStream','Move-WorkflowResultFile','Write-WorkflowResultBytes','New-WorkflowResultFailureReport','Publish-WorkflowResult')
foreach($name in $finalizerFunctions){
    $nodes=@($finalizerAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required finalizer source function unavailable'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
if((Get-FileHash -LiteralPath $finalizerSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $finalizerSHA){throw 'Finalizer source changed during selection'}
$script:finalizerChecks=0
$finalizerToken='0123456789abcdef0123456789abcdef0123456789abcdef'
function Assert-Finalizer([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:finalizerChecks++}
& {
    $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $users=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    foreach($case in @(
        @{acl=[Security.AccessControl.FileSecurity]::new();kind=[Security.AccessControl.FileSystemAccessRule];read=[Security.AccessControl.FileSystemRights]::ReadAndExecute;write=[Security.AccessControl.FileSystemRights]::Write},
        @{acl=[Security.AccessControl.RegistrySecurity]::new();kind=[Security.AccessControl.RegistryAccessRule];read=[Security.AccessControl.RegistryRights]::ReadKey;write=[Security.AccessControl.RegistryRights]::SetValue}
    )){
        $case.acl.SetOwner($admin)
        $case.acl.AddAccessRule($case.kind::new($admin,$case.write,'Allow'))
        $case.acl.AddAccessRule($case.kind::new($users,$case.read,'Allow'))
        Assert-WorkflowUninstallACL $case.acl ([int]$case.write)
        $case.acl.AddAccessRule($case.kind::new($users,$case.write,'Allow'))
        $refused=$false
        try {Assert-WorkflowUninstallACL $case.acl ([int]$case.write)}catch{$refused=$true}
        Assert-Finalizer $refused 'An ordinary writable file or registration passed inspection'
    }
}
& {
    $assetNames=@{}
    $root=$finalizerProject
    function Get-ServiceInspection {return @{services=@();error=$null}}
    function Find-App {return $null}
    function Get-Process {param($Name,$ErrorAction) return $null}
    function Get-RefreshTaskInspection {return @{present=$false;error=$null}}
    function WireSock-CLI {return $null}
    function Test-Path {param($LiteralPath) return $false}
    function Get-WorkflowInstallerRecoveryState {return $observed}
    foreach($observed in @('clear','pending','unavailable')){
        $report=Discover
        Assert-Finalizer ($report.installerRecovery -ceq $observed -and $report.dnsSnapshot -eq $false) 'Discovery lost Setup state or an independent observation'
        $expected=if($observed -ceq 'pending'){'*retry with the same or a newer approved installer in the original directory.'}
            elseif($observed -ceq 'unavailable'){'*Ask an administrator to verify it before uninstalling.'}
        if($expected){
            Assert-Finalizer ($report.conflicts.Count -eq 1 -and $report.conflicts[0] -clike $expected) 'Discovery omitted fixed recovery guidance'
        } else {
            Assert-Finalizer ($report.conflicts.Count -eq 0) 'Cleared Setup state reported a recovery conflict'
        }
    }
}
& {
    $folder=[Environment]::GetFolderPath('ProgramFiles')
    $installed=Join-Path $folder 'Fixture vendor\AccessWeaver'
    $uninstaller=Join-Path $installed 'unins005.exe'
    $approved=@{DisplayVersion='1.2.3';InstallLocation=$installed+'\';
        UninstallString=('"'+$uninstaller+'" /LOG');QuietUninstallString=('"'+$uninstaller+'" /SILENT /LOG')}
    Assert-Finalizer ((Get-WorkflowUninstallPath $approved $folder) -ceq $uninstaller) 'Registered nested Program Files path was not accepted'
    foreach($invalid in @(
        @{InstallLocation=$folder+'-else\AccessWeaver'},
        @{InstallLocation=$installed+'\..\Other'},
        @{InstallLocation=$installed+'.'},
        @{UninstallString=('"'+$uninstaller+'" /SILENT')},
        @{QuietUninstallString=('"'+$uninstaller+'" /SILENT /LOG /NORESTART')},
        @{UninstallString=('"'+(Join-Path $folder 'unins005.exe')+'"')}
    )){
        $record=$approved.Clone()
        foreach($key in $invalid.Keys){$record[$key]=$invalid[$key]}
        $failed=$false
        try {$null=Get-WorkflowUninstallPath $record $folder}catch{$failed=$true}
        Assert-Finalizer $failed 'Untrusted registration path or command was accepted'
    }

    $realOpenBinding=(Get-Command Open-WorkflowUninstallBinding).ScriptBlock
    $state=@{launches=0;restores=0;stream=$null;binding=$null;failOpen=$false;failLaunch=$false;
        busy=$false;held=$false;failRestore=$false;installerRecovery='clear';registrationReads=0}
    function Enter-WorkflowUninstallLifecycle {
        if($state.busy){throw 'Inert lifecycle contention'}
        Assert-Finalizer (-not $state.held) 'Lifecycle acquired twice'
        $state.held=$true
        $owner=[pscustomobject]@{State=$state}
        $owner | Add-Member ScriptMethod ReleaseMutex {$this.State.held=$false}
        $owner | Add-Member ScriptMethod Dispose {if($this.State.held){throw 'Lifecycle disposed while owned'}}
        return $owner
    }
    function Get-WorkflowInstallerRecoveryState {return $state.installerRecovery}
    function Read-WorkflowUninstallRegistration {
        $state.registrationReads++
        return $null
    }
    function Open-WorkflowUninstallBinding {
        if($state.failOpen){throw 'Inert inspection failure'}
        if($state.installerRecovery -cne 'clear'){return (& $realOpenBinding)}
        if($null -eq $state.binding){return $null}
        $result=$state.binding.Clone()
        $state.stream=[IO.MemoryStream]::new()
        $result.stream=$state.stream
        return $result
    }
    function Start-Process {
        param($FilePath,$WorkingDirectory,$ArgumentList,$WindowStyle)
        Assert-Finalizer ($FilePath -ceq $uninstaller -and $WorkingDirectory -ceq $installed -and
            $WindowStyle -ceq 'Hidden' -and ($ArgumentList -join ',') -ceq '/VERYSILENT,/SUPPRESSMSGBOXES,/NORESTART' -and
            $state.stream.CanRead) 'Deferred launch lost its fixed command or executable guard'
        $state.launches++
        if($state.failLaunch){throw 'Inert launch failure'}
    }
    function Remove-All {
        Assert-Finalizer ($null -eq $state.stream -or -not $state.stream.CanRead) 'Initial executable guard was not closed before restoration'
        Assert-Finalizer $state.held 'Uninstall restoration ran outside the lifecycle lock'
        if($state.failRestore){throw 'Inert cleanup failure'}
        $state.restores++
    }
    try {
        $null=Invoke-WorkflowUninstall
        Assert-Finalizer ($state.restores -eq 1 -and $null -eq $script:pendingUninstaller -and -not $state.held) 'Portable restoration scheduled an uninstall or retained the lifecycle lock'
        foreach($fault in @('busy','failRestore')){
            $state[$fault]=$true
            $failed=$false
            try {$null=Invoke-WorkflowUninstall}catch{$failed=$true}
            Assert-Finalizer ($failed -and $state.restores -eq 1 -and -not $state.held -and
                $null -eq $script:pendingUninstaller -and $state.registrationReads -eq 0) 'Uninstall crossed a failed lifecycle boundary'
            $state[$fault]=$false
        }
        $state.failOpen=$true
        $failed=$false
        try {$null=Invoke-WorkflowUninstall}catch{$failed=$true}
        Assert-Finalizer ($failed -and $state.restores -eq 1) 'Failed initial registration inspection allowed restoration'
        $state.failOpen=$false
        $state.binding=@{path=$uninstaller;sha256=('a'*64);registration=$approved}
        $null=Invoke-WorkflowUninstall
        $binding=$script:pendingUninstaller
        Assert-Finalizer ($null -ne $binding -and -not $binding.ContainsKey('stream')) 'Deferred state retained a live file handle'
        Invoke-WorkflowDeferredUninstaller $binding
        Assert-Finalizer ($state.launches -eq 1 -and -not $state.stream.CanRead) 'Successful launch did not release the executable guard'
        foreach($observed in @('pending','unavailable')){
            $state.installerRecovery=$observed
            $refusal=if($observed -ceq 'pending'){'An AccessWeaver installation is incomplete.*'}
                else{'AccessWeaver Setup recovery state could not be read.*'}
            $failed=$false
            try {$null=Invoke-WorkflowUninstall}catch{$failed=$_.Exception.Message -clike $refusal}
            Assert-Finalizer ($failed -and $state.restores -eq 2 -and -not $state.held -and $state.registrationReads -eq 0) 'Uninstall crossed a failed Setup recovery boundary'
            $failed=$false
            try {Invoke-WorkflowDeferredUninstaller $binding}catch{$failed=$_.Exception.Message -clike $refusal}
            Assert-Finalizer ($failed -and $state.launches -eq 1 -and $state.registrationReads -eq 0) 'Deferred launch crossed a failed Setup recovery boundary'
        }
        $state.installerRecovery='clear'
        foreach($change in @('digest','registration','launch-error')){
            $state.binding=$binding.Clone()
            switch($change){
                'digest' {$state.binding.sha256=('b'*64)}
                'registration' {$state.binding.registration=$approved.Clone();$state.binding.registration.DisplayVersion='1.2.4'}
                'launch-error' {$state.failLaunch=$true}
            }
            $failed=$false
            try {Invoke-WorkflowDeferredUninstaller $binding}catch{$failed=$true}
            Assert-Finalizer ($failed -and -not $state.stream.CanRead) 'Changed identity or failed launch lost its failure or leaked a file guard'
        }
        Assert-Finalizer ($state.launches -eq 2) 'An identity mismatch reached the process launcher'
    } finally {$script:pendingUninstaller=$null}
}
Add-Type -TypeDefinition @"
using System;
using System.IO;
namespace AccessWeaverFinalizerFixture {
 public sealed class Owner {
  public int Releases,Disposals;
  public bool FailRelease,FailDispose;
  public void ReleaseMutex(){Releases++;if(FailRelease)throw new IOException("PRIVATE_MUTEX_RELEASE");}
  public void Dispose(){Disposals++;if(FailDispose)throw new IOException("PRIVATE_MUTEX_DISPOSE");}
 }
}
"@
function Reset-Finalizer([string[]]$Faults=@()){
    $script:finalizerFaults=$Faults
    $script:finalizerCalls=[Collections.Generic.List[string]]::new()
    $script:finalizerPublication=$null
    $script:events=[Collections.Generic.List[string]]::new();$script:events.Add('source fixture event')
    $script:journalPath='source-fixture-journal';$script:journalState='succeeded';$script:rebootRequired=$true
    $script:externalEffectsPending=$false;$script:pendingUninstaller='source-fixture-uninstaller'
    $script:mutex=[AccessWeaverFinalizerFixture.Owner]::new();$script:ownsMutex=$true
    $script:mutex.FailRelease=$Faults -contains 'mutex-release';$script:mutex.FailDispose=$Faults -contains 'mutex-dispose'
}
function Save-Journal {
    $script:finalizerCalls.Add('journal')
    if($script:finalizerFaults -contains 'journal-save'){throw 'PRIVATE_FINAL_JOURNAL'}
}
function Invoke-WorkflowDeferredUninstaller([string]$Path){
    Assert-Finalizer ($null -eq $script:mutex -and -not $script:ownsMutex) 'Deferred handoff preceded observed mutex cleanup'
    $script:finalizerCalls.Add('handoff')
    if($script:finalizerFaults -contains 'uninstaller-start'){throw 'PRIVATE_FINAL_HANDOFF'}
}
$finalizerRealPublisher=${function:Publish-WorkflowResult}
function Publish-WorkflowResult([string]$Path,[Collections.IDictionary]$Result,[string]$ResultToken){
    $script:finalizerCalls.Add('publish');$script:finalizerPublication=$Result.Clone()
    if($script:finalizerFaults -contains 'publish'){throw 'PRIVATE_FINAL_PUBLICATION'}
    return -not ($script:finalizerFaults -contains 'fallback')
}
foreach($faults in @(@(),@('journal-save'),@('mutex-release'),@('mutex-dispose'),@('uninstaller-start'),@('journal-save','mutex-release','mutex-dispose'))){
    Reset-Finalizer $faults
    $owner=$script:mutex
    $result=@{ok=$true;data=@{fixture='preserved'};events=@();journal=$null;rebootRequired=$false}
    Complete-WorkflowFinalization $result 'source-path' $finalizerToken
    Assert-Finalizer ($owner.Releases -eq 1 -and $owner.Disposals -eq 1) 'Finalizer did not attempt every owner stage once'
    Assert-Finalizer ($script:finalizerCalls[0] -ceq 'journal' -and $script:finalizerCalls[$script:finalizerCalls.Count-1] -ceq 'publish') 'Publication did not follow journal and cleanup attempts'
    Assert-Finalizer ($null -ne $script:finalizerPublication) 'Finalization skipped result publication'
    Assert-Finalizer ($result.journal -ceq 'source-fixture-journal' -and $result.rebootRequired -and $result.events.Count -eq 1) 'Finalization lost bounded recovery context'
    Assert-Finalizer (@($result.finalizationFailures).Count -eq $faults.Count) 'Finalization lost a known failure code'
    foreach($fault in $faults){Assert-Finalizer (@($result.finalizationFailures) -ccontains $fault) 'Finalization omitted a typed stage failure'}
    $cleanupFault=@($faults|Where-Object {$_ -cne 'uninstaller-start'}).Count -gt 0
    Assert-Finalizer (($script:finalizerCalls -contains 'handoff') -eq (-not $cleanupFault)) 'Uninstaller ran after unconfirmed cleanup or was not attempted when eligible'
    Assert-Finalizer ($result.ok -eq ($faults.Count -eq 0)) 'Finalization turned an uncertain outcome into success'
    Assert-Finalizer ($result.externalEffectsPending -eq (-not $cleanupFault)) 'Deferred launch uncertainty was not preserved'
    if($faults.Count){Assert-Finalizer ($result.error -notmatch 'PRIVATE_') 'Finalizer exposed a private cleanup cause in its public summary'}
}
Reset-Finalizer @('journal-save','mutex-release','mutex-dispose')
$failed=@{ok=$false;error='original operation failure';data=$null}
Complete-WorkflowFinalization $failed 'source-path' $finalizerToken
Assert-Finalizer ($failed.error -ceq 'original operation failure') 'Finalizer replaced the original failure'
Assert-Finalizer (-not ($script:finalizerCalls -contains 'handoff')) 'Failed operation launched deferred work'
Reset-Finalizer @('publish')
$publication=@{ok=$true;data=$null};$owner=$script:mutex;$publicationError=$false
try{Complete-WorkflowFinalization $publication 'source-path' $finalizerToken}catch{$publicationError=$true}
Assert-Finalizer ($publicationError -and -not $publication.ok -and $owner.Disposals -eq 1) 'Publication error erased cleanup or retained a successful flag'
Reset-Finalizer @('fallback')
$fallback=@{ok=$true;data=$null}
Complete-WorkflowFinalization $fallback 'source-path' $finalizerToken
Assert-Finalizer (-not $fallback.ok) 'Serialization fallback became successful finalization'
# Failed cleanup prevents the intentional detached launch; successful launch is
# still informational pending external completion, not a native wait claim.
Reset-Finalizer @()
$script:mutex=$null;$script:ownsMutex=$false;$script:pendingUninstaller=$null;$script:externalEffectsPending=$true
$native=@{ok=$true;data=$null}
Complete-WorkflowFinalization $native 'source-path' $finalizerToken
Assert-Finalizer ($native.ok -and $native.externalEffectsPending) 'Known worker completion cleared unverified external effects'

if($InteropDirectory){
    $destination=Get-Item -LiteralPath $InteropDirectory -Force
    if(-not $destination.PSIsContainer -or ($destination.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($destination.FullName).Length -ne 0){throw 'Finalizer interop requires an existing empty ordinary directory'}
    $created=$destination.CreationTimeUtc.Ticks
    $cases=@()
    foreach($case in @(@{name='cleanup.json';faults=@('journal-save','mutex-release','mutex-dispose');large=$false},@{name='handoff.json';faults=@('uninstaller-start');large=$false},@{name='fallback.json';faults=@('journal-save','mutex-release','mutex-dispose');large=$true})){
        Reset-Finalizer $case.faults;$script:externalEffectsPending=$true
        $report=@{ok=$true;data=$(if($case.large){'x'*65536}else{@{fixture='retained'}})}
        $current=Get-Item -LiteralPath $destination.FullName -Force
        if(-not $current.PSIsContainer -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $current.CreationTimeUtc.Ticks -ne $created){throw 'Finalizer interop directory changed'}
        # Keep the real selected producer and all actual counter/encoding/
        # staged-publication behavior in this composed path.
        $script:finalizerInteropMaximum=if($case.large){2048}else{32768}
        function Publish-WorkflowResult([string]$Path,[Collections.IDictionary]$Result,[string]$ResultToken){
            return (& $finalizerRealPublisher $Path $Result $ResultToken $script:finalizerInteropMaximum)
        }
        Complete-WorkflowFinalization $report (Join-Path $destination.FullName $case.name) $finalizerToken
        $cases+=@{name=$case.name;reportingFailure=$(if($case.large){'result-too-large'}else{''});finalizationFailures=@($case.faults);externalEffectsPending=$true}
    }
    $manifest=@{schemaVersion=1;sourceSHA256=$finalizerSHA;resultToken=$finalizerToken;cases=$cases}|ConvertTo-Json -Depth 5
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($manifest)
    $file=[IO.FileStream]::new((Join-Path $destination.FullName 'manifest.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
if((Get-FileHash -LiteralPath $finalizerSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $finalizerSHA){throw 'Finalizer source changed during verification'}
Write-Output ('PASS workflow finalization source contracts ('+$script:finalizerChecks+' checks; native worker not executed)')
