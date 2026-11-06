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
$finalizerFunctions=@('Complete-WorkflowFinalization','Assert-WorkflowResultDepth','Assert-WorkflowResultToken','Get-WorkflowResultFailureCode','Throw-WorkflowResultFailure','ConvertTo-WorkflowResultBytes','New-WorkflowResultStream','Write-WorkflowResultStream','Move-WorkflowResultFile','Write-WorkflowResultBytes','New-WorkflowResultFailureReport','Publish-WorkflowResult')
foreach($name in $finalizerFunctions){
    $nodes=@($finalizerAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required finalizer source function unavailable'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
if((Get-FileHash -LiteralPath $finalizerSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $finalizerSHA){throw 'Finalizer source changed during selection'}
$script:finalizerChecks=0
$finalizerToken='0123456789abcdef0123456789abcdef0123456789abcdef'
function Assert-Finalizer([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:finalizerChecks++}
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
