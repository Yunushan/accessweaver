# Pure selected-function result-writer contracts. No worker top level, network,
# native process, product executable, service or host configuration is invoked.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell,[string]$InteropDirectory)
$ErrorActionPreference='Stop'
if($RequireWindowsPowerShell -and ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop')){throw 'Windows PowerShell 5.1 Desktop is required'}
if($InteropDirectory){
    $resultInteropInitial=Get-Item -LiteralPath $InteropDirectory -Force
    if(-not $resultInteropInitial.PSIsContainer -or ($resultInteropInitial.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($resultInteropInitial.FullName).Length -ne 0){throw 'Interop fixture requires an existing empty ordinary directory'}
    $resultInteropInitialCreated=$resultInteropInitial.CreationTimeUtc.Ticks
}
$resultProject=Split-Path -Parent $PSScriptRoot
$resultWorkflowPath=Join-Path $resultProject 'internal\workflow\windows.ps1'
$resultWorkflowHash=(Get-FileHash -LiteralPath $resultWorkflowPath -Algorithm SHA256).Hash.ToLowerInvariant()
$resultTokens=$null;$resultParseErrors=$null
$resultAst=[Management.Automation.Language.Parser]::ParseFile($resultWorkflowPath,[ref]$resultTokens,[ref]$resultParseErrors)
if($resultParseErrors.Count){throw 'Workflow result source did not parse'}
$resultNames=@('Assert-WorkflowResultDepth','Assert-WorkflowResultToken','Get-WorkflowResultFailureCode','Throw-WorkflowResultFailure','ConvertTo-WorkflowResultBytes','New-WorkflowResultStream','Write-WorkflowResultStream','Move-WorkflowResultFile','Write-WorkflowResultBytes','New-WorkflowResultFailureReport','Publish-WorkflowResult')
foreach($resultName in $resultNames){
    $resultNodes=@($resultAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $resultName})
    if($resultNodes.Count -ne 1){throw 'Required workflow result function is unavailable'}
    . ([scriptblock]::Create($resultNodes[0].Extent.Text))
}
if((Get-FileHash -LiteralPath $resultWorkflowPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $resultWorkflowHash){throw 'Workflow source changed while selecting result helpers'}
$script:resultFixtureChecks=0
$resultFixtureToken=('abcdef0123456789'*3)
function Assert-ResultFixture([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:resultFixtureChecks++}
function Reject-ResultFixture([scriptblock]$Operation){
    $resultFailure=$null
    try{& $Operation|Out-Null}catch{$resultFailure=$_.Exception}
    Assert-ResultFixture ($null -ne $resultFailure) 'Expected workflow result refusal did not occur'
    return $resultFailure
}
function New-ResultFixture([object]$Data){return @{ok=$true;data=$Data;events=@();rebootRequired=$false;journal=$null}}
function Read-ResultFixtureBytes([byte[]]$Bytes){
    $resultText=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
    return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $resultText)
}
function New-ResultFixtureDepth([int]$Aggregates){
    $resultValue='retained-leaf'
    for($resultIndex=0;$resultIndex -lt $Aggregates;$resultIndex++){$resultValue=@{next=$resultValue}}
    return $resultValue
}
Add-Type -TypeDefinition @"
using System;
using System.IO;
namespace AccessWeaverResultFixture {
 public sealed class Output {
  private MemoryStream memory=new MemoryStream();
  public bool FailWrite,FailFlush,FailClose,Discard;
  public int Writes,Flushes,Closes;
  public long AttemptedBytes;
  public byte[] Bytes { get { return memory.ToArray(); } }
  public void Write(byte[] data,int offset,int count) {
   Writes++;AttemptedBytes+=count;
   if(FailWrite) { if(count>0) memory.Write(data,offset,Math.Min(3,count));throw new IOException("PRIVATE_RESULT_WRITE_FIXTURE"); }
   if(!Discard) memory.Write(data,offset,count);
  }
  public void Flush(bool durable) {
   Flushes++;
   if(FailFlush) throw new IOException("PRIVATE_RESULT_FLUSH_FIXTURE");
  }
  public void Dispose() {
   Closes++;
   if(FailClose) throw new IOException("PRIVATE_RESULT_CLOSE_FIXTURE");
   memory.Dispose();
  }
 }
}
"@

# Measure the actual serialized UTF-8 envelope, never just UTF-16 character
# length. Controls expand in JSON while a supplementary scalar is four bytes.
$resultControlText=-join ([char[]](0..31))
$resultNonAscii=([string][char]0x00e9)+([string][char]0x0416)+([string][char]0x2122)
$resultSupplementary=[char]::ConvertFromUtf32(0x1f680)
foreach($resultTextCase in @('plain ASCII',$resultControlText,$resultNonAscii,$resultSupplementary,('quoted"slash\'+$resultNonAscii+$resultControlText+$resultSupplementary))){
    $resultValue=New-ResultFixture @{text=$resultTextCase;items=@(1,$false,$null,@{name='retained'})}
    $resultBytes=ConvertTo-WorkflowResultBytes $resultValue $resultFixtureToken
    Assert-ResultFixture ($resultBytes -is [byte[]]) 'Result converter did not return one owned byte array'
    $resultDecoded=Read-ResultFixtureBytes $resultBytes
    Assert-ResultFixture ($resultDecoded.data.text -ceq $resultTextCase -and $resultDecoded.data.items.Count -eq 4 -and $resultDecoded.data.items[3].name -ceq 'retained') 'Normal result JSON shape or Unicode content changed'
    Assert-ResultFixture ($resultDecoded.reportVersion -eq 1 -and $resultDecoded.resultToken -ceq $resultFixtureToken) 'Result envelope lost its version or request token'
    $resultJsonText=[Text.UTF8Encoding]::new($false,$true).GetString($resultBytes)
    Assert-ResultFixture ([Text.UTF8Encoding]::new($false,$true).GetByteCount($resultJsonText) -eq $resultBytes.Length -and -not ($resultBytes.Length -ge 3 -and $resultBytes[0] -eq 239 -and $resultBytes[1] -eq 187 -and $resultBytes[2] -eq 191)) 'Result bytes are not exact strict UTF-8 without a BOM'
    $resultExact=ConvertTo-WorkflowResultBytes $resultValue $resultFixtureToken -MaximumBytes $resultBytes.Length
    Assert-ResultFixture ([Convert]::ToBase64String($resultExact) -ceq [Convert]::ToBase64String($resultBytes)) 'Exact serialized UTF-8 boundary was not preserved'
    $resultFailure=Reject-ResultFixture {ConvertTo-WorkflowResultBytes $resultValue $resultFixtureToken -MaximumBytes ($resultBytes.Length-1)}
    Assert-ResultFixture ((Get-WorkflowResultFailureCode $resultFailure) -ceq 'result-too-large') 'One-byte oversized envelope did not report the closed byte-limit failure'
    $resultOutput=[AccessWeaverResultFixture.Output]::new()
    Write-WorkflowResultStream $resultOutput $resultBytes -MaximumBytes $resultBytes.Length
    Assert-ResultFixture ($resultOutput.Writes -eq 1 -and $resultOutput.AttemptedBytes -eq $resultBytes.Length -and $resultOutput.Flushes -eq 1 -and [Convert]::ToBase64String($resultOutput.Bytes) -ceq [Convert]::ToBase64String($resultBytes)) 'Exact-boundary result stream lost or changed bytes'
    $resultOutput.Dispose()
    $resultOutput=[AccessWeaverResultFixture.Output]::new()
    try{
        $null=Reject-ResultFixture {Write-WorkflowResultStream $resultOutput $resultBytes -MaximumBytes ($resultBytes.Length-1)}
        Assert-ResultFixture ($resultOutput.Writes -eq 0 -and $resultOutput.AttemptedBytes -eq 0 -and $resultOutput.Flushes -eq 0 -and $resultOutput.Bytes.Length -eq 0) 'Over-budget envelope reached a destination write'
    }finally{$resultOutput.Dispose()}
}
foreach($resultInvalidToken in @('','a',('a'*47),('a'*49),('A'*48),(('a'*48)+[char]10),(('a'*47)+[char]0x00e9))){
    $null=Reject-ResultFixture {ConvertTo-WorkflowResultBytes (New-ResultFixture @{}) $resultInvalidToken}
}
$resultMetadata=New-ResultFixture @{value='expected'}
$resultMetadata.reportVersion=999;$resultMetadata.resultToken=('0'*48)
$resultDecoded=Read-ResultFixtureBytes (ConvertTo-WorkflowResultBytes $resultMetadata $resultFixtureToken)
Assert-ResultFixture ($resultDecoded.reportVersion -eq 1 -and $resultDecoded.resultToken -ceq $resultFixtureToken) 'Result payload replaced the current request correlation envelope'
$resultAtDepth=New-ResultFixture (New-ResultFixtureDepth 16)
$resultDepthBytes=ConvertTo-WorkflowResultBytes $resultAtDepth $resultFixtureToken
$resultDepthDecoded=Read-ResultFixtureBytes $resultDepthBytes
$resultDepthLeaf=$resultDepthDecoded.data
for($resultIndex=0;$resultIndex -lt 16;$resultIndex++){$resultDepthLeaf=$resultDepthLeaf.next}
Assert-ResultFixture ($resultDepthLeaf -ceq 'retained-leaf') 'Depth-sixteen aggregate or its primitive leaf was truncated'
$resultFailure=Reject-ResultFixture {ConvertTo-WorkflowResultBytes (New-ResultFixture (New-ResultFixtureDepth 17)) $resultFixtureToken}
Assert-ResultFixture ((Get-WorkflowResultFailureCode $resultFailure) -ceq 'result-depth') 'Over-depth aggregate was silently serialized as a valid-looking partial result'

$script:resultOriginalNew=(Get-Command New-WorkflowResultStream).ScriptBlock
$script:resultOriginalMove=(Get-Command Move-WorkflowResultFile).ScriptBlock
$resultFixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-result-source-'+[guid]::NewGuid().ToString('N'))
if([IO.Directory]::Exists($resultFixtureRoot)){throw 'Fresh result fixture path already exists'}
$resultFixtureRootItem=[IO.Directory]::CreateDirectory($resultFixtureRoot)
$resultFixtureRootCreated=$resultFixtureRootItem.CreationTimeUtc.Ticks
$resultFixtureOwned=[Collections.Generic.List[string]]::new()
try{
try{
    $resultDestination=Join-Path $resultFixtureRoot 'result.json'
    $resultOldBytes=ConvertTo-WorkflowResultBytes (New-ResultFixture @{old='retained'}) ('0'*48)
    [IO.File]::WriteAllBytes($resultDestination,$resultOldBytes);$resultFixtureOwned.Add($resultDestination)
    # Replace only physical I/O adapters in this private test process. The real
    # writer and publisher still enforce byte admission and own close ordering.
    . {
        function New-WorkflowResultStream([string]$Path){
            $script:resultFaultFactories++
            $script:resultFaultStage=$Path
            if($script:resultFaultMode -eq 'create'){throw [IO.IOException]::new('PRIVATE_RESULT_CREATE_FIXTURE')}
            return $script:resultFaultOutput
        }
        function Move-WorkflowResultFile([string]$Source,[string]$Destination){
            $script:resultFaultMoves++
            if($script:resultFaultOutput.Closes -ne 1 -or $script:resultFaultOutput.Flushes -ne 1){$script:resultFaultOrder=$true}
            if($script:resultFaultMode -eq 'move'){throw [IO.IOException]::new('PRIVATE_RESULT_MOVE_FIXTURE')}
            # Pure composition: no fake promotion writes a valid-looking target.
        }
        foreach($resultFaultCase in @('none','create','write','flush','close','move')){
            $script:resultFaultMode=$resultFaultCase
            $script:resultFaultFactories=0;$script:resultFaultMoves=0;$script:resultFaultOrder=$false
            $script:resultFaultOutput=[AccessWeaverResultFixture.Output]::new()
            $script:resultFaultOutput.FailWrite=$resultFaultCase -eq 'write'
            $script:resultFaultOutput.FailFlush=$resultFaultCase -eq 'flush'
            $script:resultFaultOutput.FailClose=$resultFaultCase -eq 'close'
            try{
                if($resultFaultCase -eq 'none'){
                    $resultPublished=Publish-WorkflowResult $resultDestination (New-ResultFixture @{text='complete'}) $resultFixtureToken
                    Assert-ResultFixture ($resultPublished -is [bool] -and $resultPublished) 'Normal result composition did not report normal publication'
                }else{
                    $resultFailure=Reject-ResultFixture {Publish-WorkflowResult $resultDestination (New-ResultFixture @{text='complete'}) $resultFixtureToken}
                    Assert-ResultFixture ($resultFailure.Message -ceq 'Workflow result publication failed; preserve staging and recovery evidence' -and $resultFailure.Message -cnotmatch 'PRIVATE_RESULT_') 'Storage failure leaked private detail or became a successful fallback'
                }
                Assert-ResultFixture ($script:resultFaultFactories -eq 1 -and -not $script:resultFaultOrder) 'Storage failure retried publication or moved before checked close'
                $resultExpectedMoves=if($resultFaultCase -in @('none','move')){1}else{0}
                $resultExpectedCloses=if($resultFaultCase -eq 'create'){0}else{1}
                Assert-ResultFixture ($script:resultFaultMoves -eq $resultExpectedMoves -and $script:resultFaultOutput.Closes -eq $resultExpectedCloses) 'Publication admitted an unexpected move or repeated an uncertain close'
                Assert-ResultFixture ([Convert]::ToBase64String([IO.File]::ReadAllBytes($resultDestination)) -ceq [Convert]::ToBase64String($resultOldBytes)) 'Failed I/O composition changed the preexisting result destination'
                if($resultFaultCase -eq 'write'){Assert-ResultFixture ($script:resultFaultOutput.Bytes.Length -eq 3) 'Synthetic failed write did not retain its exact partial staging bytes'}
            }finally{$script:resultFaultOutput.FailClose=$false;$script:resultFaultOutput.Dispose()}
        }
        $script:resultFaultFactories=0;$script:resultFaultMoves=0
        $resultSmallBytes=ConvertTo-WorkflowResultBytes (New-ResultFixture @{value='small'}) $resultFixtureToken
        $null=Reject-ResultFixture {Write-WorkflowResultBytes $resultDestination $resultSmallBytes -MaximumBytes ($resultSmallBytes.Length-1)}
        Assert-ResultFixture ($script:resultFaultFactories -eq 0 -and $script:resultFaultMoves -eq 0) 'Oversized result reached physical stream creation or promotion'
    }
}finally{
    Set-Item -LiteralPath Function:script:New-WorkflowResultStream -Value $script:resultOriginalNew
    Set-Item -LiteralPath Function:script:Move-WorkflowResultFile -Value $script:resultOriginalMove
    if([IO.File]::Exists($resultDestination)){[IO.File]::Delete($resultDestination)}
}

# Exercise the production default itself. The large spy discards admitted data;
# this tests byte admission, not a bound on serializer memory allocation.
$resultLargeValue=New-ResultFixture @{text=''}
$resultEmptyBytes=ConvertTo-WorkflowResultBytes $resultLargeValue $resultFixtureToken
$resultLargeCount=32MB-$resultEmptyBytes.Length
$resultLargeValue.data.text=[string]::new([char]'x',$resultLargeCount)
$resultLargeBytes=ConvertTo-WorkflowResultBytes $resultLargeValue $resultFixtureToken
Assert-ResultFixture ($resultLargeBytes.Length -eq 32MB) 'Default result serializer did not admit exactly32MiB of actual UTF-8 bytes'
$resultLargeOutput=[AccessWeaverResultFixture.Output]::new();$resultLargeOutput.Discard=$true
try{
    Write-WorkflowResultStream $resultLargeOutput $resultLargeBytes
    Assert-ResultFixture ($resultLargeOutput.AttemptedBytes -eq 32MB -and $resultLargeOutput.Writes -eq 1 -and $resultLargeOutput.Flushes -eq 1) 'Default writer did not admit the exact32MiB boundary'
}finally{$resultLargeOutput.Dispose()}
$resultLargeValue.data.text=[string]::new([char]'x',($resultLargeCount+1))
$resultFailure=Reject-ResultFixture {ConvertTo-WorkflowResultBytes $resultLargeValue $resultFixtureToken}
Assert-ResultFixture ((Get-WorkflowResultFailureCode $resultFailure) -ceq 'result-too-large') 'Default serializer accepted one byte beyond32MiB'
$resultLargeOutput=[AccessWeaverResultFixture.Output]::new();$resultLargeOutput.Discard=$true
try{
    $resultOverBytes=[byte[]]::new((32MB+1))
    $null=Reject-ResultFixture {Write-WorkflowResultStream $resultLargeOutput $resultOverBytes}
    Assert-ResultFixture ($resultLargeOutput.Writes -eq 0 -and $resultLargeOutput.AttemptedBytes -eq 0 -and $resultLargeOutput.Flushes -eq 0) 'Default over-limit bytes reached any write'
}finally{$resultLargeOutput.Dispose()}
$resultLargeValue=$null;$resultLargeBytes=$null;$resultOverBytes=$null

# A lone UTF-16 surrogate follows the actual serializer: escaped ASCII JSON is
# counted as emitted; an unpaired literal must fail strict UTF-8 before writing.
foreach($resultSurrogate in @([char]0xd800,[char]0xdc00)){
    $resultValue=New-ResultFixture @{text=[string]$resultSurrogate}
    $resultReference=@{};foreach($resultKey in $resultValue.Keys){$resultReference[$resultKey]=$resultValue[$resultKey]}
    $resultReference.reportVersion=1;$resultReference.resultToken=$resultFixtureToken
    $resultReferenceJson=Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $resultReference -Depth 16
    $resultReferenceValid=$true
    try{$resultReferenceCount=[Text.UTF8Encoding]::new($false,$true).GetByteCount($resultReferenceJson)}catch{$resultReferenceValid=$false}
    if($resultReferenceValid){
        $resultBytes=ConvertTo-WorkflowResultBytes $resultValue $resultFixtureToken
        Assert-ResultFixture ($resultBytes.Length -eq $resultReferenceCount) 'Escaped surrogate result did not count the serializer actual UTF-8 bytes'
    }else{
        $resultFailure=Reject-ResultFixture {ConvertTo-WorkflowResultBytes $resultValue $resultFixtureToken}
        Assert-ResultFixture ((Get-WorkflowResultFailureCode $resultFailure) -ceq 'result-encoding') 'Invalid literal surrogate reached result encoding'
    }
}

# Synthetic serializer failures are explicit scope-local cmdlet replacements.
# Every successful conversion still delegates the real depth16 JSON serializer.
$script:resultSerializerFault=''
function ConvertTo-Json {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)]$InputObject,[int]$Depth=2)
    process{
        if($script:resultSerializerFault -eq 'serialization'){$script:resultSerializerFault='';throw [InvalidOperationException]::new('PRIVATE_RESULT_SERIALIZER_FIXTURE')}
        if($script:resultSerializerFault -eq 'encoding'){$script:resultSerializerFault='';return [string][char]0xd800}
        return (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $InputObject -Depth $Depth -ErrorAction Stop -WarningAction Stop)
    }
}
foreach($resultReportCase in @(
    @{mode='normal';code=$null;maximum=8192;data=@{message='normal';nested=@{items=@(1,2,3)}}},
    @{mode='size';code='result-too-large';maximum=1024;data=@{payload=('PRIVATE_RESULT_PAYLOAD'+('x'*12000))}},
    @{mode='depth';code='result-depth';maximum=8192;data=(New-ResultFixtureDepth 17)},
    @{mode='serialization';code='result-serialization';maximum=8192;data=@{payload='PRIVATE_RESULT_PAYLOAD'}},
    @{mode='encoding';code='result-encoding';maximum=8192;data=@{payload='PRIVATE_RESULT_PAYLOAD'}}
)){
    $resultValue=New-ResultFixture $resultReportCase.data
    $resultValue.journal='fixture-recovery-journal.json';$resultValue.rebootRequired=$true
    $resultValue.error='PRIVATE_RESULT_ORIGINAL_ERROR'
    $script:resultSerializerFault=if($resultReportCase.mode -in @('serialization','encoding')){$resultReportCase.mode}else{''}
    $resultPublished=Publish-WorkflowResult $resultDestination $resultValue $resultFixtureToken -MaximumBytes $resultReportCase.maximum
    $resultStored=[IO.File]::ReadAllBytes($resultDestination)
    $resultDecoded=Read-ResultFixtureBytes $resultStored
    Assert-ResultFixture ($resultStored.Length -le $resultReportCase.maximum -and $resultDecoded.reportVersion -eq 1 -and $resultDecoded.resultToken -ceq $resultFixtureToken) 'Published result exceeded its byte cap or lost request correlation'
    if($null -eq $resultReportCase.code){
        Assert-ResultFixture ($resultPublished -is [bool] -and $resultPublished -and $resultDecoded.ok -eq $true -and $resultDecoded.data.nested.items.Count -eq 3) 'Normal result publication changed nested JSON shape'
    }else{
        Assert-ResultFixture ($resultPublished -is [bool] -and -not $resultPublished -and $resultValue.ok -eq $false -and $resultDecoded.ok -is [bool] -and -not $resultDecoded.ok) 'Reporting fallback retained a success-shaped outcome'
        Assert-ResultFixture ($resultDecoded.reportingFailure -ceq $resultReportCase.code -and $resultDecoded.error -ceq 'Workflow result reporting failed; inspect process.log and the recovery journal') 'Reporting fallback lost its closed failure category or fixed message'
        Assert-ResultFixture ($null -eq $resultDecoded.data -and $resultDecoded.events -is [array] -and $resultDecoded.events.Count -eq 0 -and $resultDecoded.rebootRequired -eq $true -and $resultDecoded.journal -ceq 'fixture-recovery-journal.json') 'Reporting fallback lost bounded recovery context or retained original payload'
        $resultPropertyNames=@($resultDecoded.PSObject.Properties.Name)
        $resultUnknownProperties=@($resultPropertyNames|Where-Object {$_ -cnotin @('data','error','events','journal','ok','rebootRequired','reportVersion','reportingFailure','resultToken')})
        Assert-ResultFixture ($resultPropertyNames.Count -eq 9 -and $resultUnknownProperties.Count -eq 0) 'Reporting fallback accepted unknown top-level properties'
        Assert-ResultFixture ([Text.Encoding]::UTF8.GetString($resultStored) -cnotmatch 'PRIVATE_RESULT_') 'Reporting fallback leaked private serializer or original payload detail'
    }
    Assert-ResultFixture ([IO.Directory]::GetFiles($resultFixtureRoot,'*.tmp').Length -eq 0) 'Confirmed normal or fallback publication retained staging'
    [IO.File]::Delete($resultDestination)
}

# Preserve whole paths only when they fit the recovery-context quota. Do not
# manufacture a truncated path or coerce a nonboolean reboot indication.
foreach($resultContextCase in @(
    @{journal=('j'*4096);expected=('j'*4096);reboot=$true;expectedReboot=$true},
    @{journal=('j'*4097);expected=$null;reboot=$true;expectedReboot=$true},
    @{journal=([string]::new([char]0x00e9,2048));expected=([string]::new([char]0x00e9,2048));reboot=$false;expectedReboot=$false},
    @{journal=(([string]::new([char]0x00e9,2048))+'a');expected=$null;reboot='true';expectedReboot=$false},
    @{journal=([string][char]0xd800);expected=$null;reboot=$true;expectedReboot=$true},
    @{journal=42;expected=$null;reboot=$null;expectedReboot=$false}
)){
    $resultValue=New-ResultFixture @{payload=('PRIVATE_RESULT_PAYLOAD'+('x'*20000))}
    $resultValue.journal=$resultContextCase.journal;$resultValue.rebootRequired=$resultContextCase.reboot
    $resultContextExpected='result-too-large'
    $resultContextReference=Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $resultValue -Depth 16
    try{[void][Text.UTF8Encoding]::new($false,$true).GetByteCount($resultContextReference)}catch{$resultContextExpected='result-encoding'}
    $resultPublished=Publish-WorkflowResult $resultDestination $resultValue $resultFixtureToken -MaximumBytes 8192
    $resultStored=[IO.File]::ReadAllBytes($resultDestination);$resultDecoded=Read-ResultFixtureBytes $resultStored
    Assert-ResultFixture (-not $resultPublished -and $resultDecoded.reportingFailure -ceq $resultContextExpected -and $resultStored.Length -le 8192) 'Recovery context bypassed the small fallback limit'
    Assert-ResultFixture ($resultDecoded.journal -ceq $resultContextCase.expected -and $resultDecoded.rebootRequired -is [bool] -and $resultDecoded.rebootRequired -eq $resultContextCase.expectedReboot) 'Fallback truncated recovery path bytes or coerced reboot context'
    [IO.File]::Delete($resultDestination)
}
# Context may fit4096bytes and still not fit the chosen report quota; omit the
# whole journal on that secondary bound, preserving the required failure fields.
$resultValue=New-ResultFixture @{payload=('x'*12000)};$resultValue.journal=('j'*4096)
$resultPublished=Publish-WorkflowResult $resultDestination $resultValue $resultFixtureToken -MaximumBytes 1024
$resultDecoded=Read-ResultFixtureBytes ([IO.File]::ReadAllBytes($resultDestination))
Assert-ResultFixture (-not $resultPublished -and $null -eq $resultDecoded.journal -and $resultDecoded.reportingFailure -ceq 'result-too-large') 'Fallback could not omit an otherwise valid path to meet its byte quota'
[IO.File]::Delete($resultDestination)
$resultFailure=Reject-ResultFixture {Publish-WorkflowResult $resultDestination (New-ResultFixture @{payload='PRIVATE_RESULT_PAYLOAD'}) $resultFixtureToken -MaximumBytes 1}
Assert-ResultFixture (-not [IO.File]::Exists($resultDestination) -and [IO.Directory]::GetFileSystemEntries($resultFixtureRoot).Length -eq 0) 'Unpublishable fallback wrote a partial result or staging file'

# Physical promotion refuses a preexisting valid OLD report. Keep its exact
# bytes; the new token must never turn that old report into this operation.
[IO.File]::WriteAllBytes($resultDestination,$resultOldBytes)
$resultFailure=Reject-ResultFixture {Publish-WorkflowResult $resultDestination (New-ResultFixture @{new='unpublished'}) $resultFixtureToken}
Assert-ResultFixture ($resultFailure.Message -ceq 'Workflow result publication failed; preserve staging and recovery evidence') 'Physical promotion failure retried as reporting fallback'
$resultStillOld=[IO.File]::ReadAllBytes($resultDestination)
Assert-ResultFixture ([Convert]::ToBase64String($resultStillOld) -ceq [Convert]::ToBase64String($resultOldBytes) -and (Read-ResultFixtureBytes $resultStillOld).resultToken -ceq ('0'*48)) 'Physical publication replaced or rebound the older destination'
$resultPreservedStages=[IO.Directory]::GetFiles($resultFixtureRoot,'*.tmp')
Assert-ResultFixture ($resultPreservedStages.Length -eq 1 -and (Read-ResultFixtureBytes ([IO.File]::ReadAllBytes($resultPreservedStages[0]))).resultToken -ceq $resultFixtureToken) 'Failed physical promotion deleted or adopted uncertain staging'

}finally{
    Set-Item -LiteralPath Function:script:New-WorkflowResultStream -Value $script:resultOriginalNew
    Set-Item -LiteralPath Function:script:Move-WorkflowResultFile -Value $script:resultOriginalMove
    $resultFresh=Get-Item -LiteralPath $resultFixtureRoot -Force
    if($resultFresh.CreationTimeUtc.Ticks -ne $resultFixtureRootCreated -or ($resultFresh.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed result fixture root was preserved'}
    foreach($resultOwned in Get-ChildItem -LiteralPath $resultFixtureRoot -Force){
        if($resultOwned.PSIsContainer -or ($resultOwned.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($resultOwned.Name -cne 'result.json' -and $resultOwned.Name -cnotmatch '^\.accessweaver-result-[a-f0-9]{32}\.tmp$')){throw 'Unknown result fixture content was preserved'}
        [IO.File]::Delete($resultOwned.FullName)
    }
    [IO.Directory]::Delete($resultFixtureRoot,$false)
}

if($InteropDirectory){
    # Optional cross-language SOURCE fixture only. The caller owns this empty
    # directory; fixed filenames are exclusively published and never replaced.
    $resultInteropItem=Get-Item -LiteralPath $InteropDirectory -Force
    if(-not $resultInteropItem.PSIsContainer -or $resultInteropItem.CreationTimeUtc.Ticks -ne $resultInteropInitialCreated -or ($resultInteropItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Directory]::GetFileSystemEntries($resultInteropItem.FullName).Length -ne 0){throw 'Interop fixture requires an existing empty ordinary directory'}
    if((Get-FileHash -LiteralPath $resultWorkflowPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $resultWorkflowHash){throw 'Workflow source changed before interop fixture publication'}
    $resultInteropCreated=$resultInteropItem.CreationTimeUtc.Ticks
    $resultInteropToken='0123456789abcdef0123456789abcdef0123456789abcdef'
    $resultInteropCases=@(
        @{name='normal.json';reportingFailure='';value=(New-ResultFixture @{message='interop-normal';items=@('a','b')})},
        @{name='too-large.json';reportingFailure='result-too-large';value=(New-ResultFixture @{payload=('inert-over-limit-'*300)})},
        @{name='too-deep.json';reportingFailure='result-depth';value=(New-ResultFixture (New-ResultFixtureDepth 17))}
    )
    $resultInteropManifestCases=@()
    foreach($resultInteropCase in $resultInteropCases){
        $resultInteropCurrent=Get-Item -LiteralPath $resultInteropItem.FullName -Force
        if($resultInteropCurrent.CreationTimeUtc.Ticks -ne $resultInteropCreated -or ($resultInteropCurrent.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed interop fixture directory was preserved'}
        $resultInteropCase.value.journal='fixture-recovery-journal.json';$resultInteropCase.value.rebootRequired=$true
        $resultInteropPath=Join-Path $resultInteropItem.FullName $resultInteropCase.name
        $resultInteropPublished=Publish-WorkflowResult $resultInteropPath $resultInteropCase.value $resultInteropToken -MaximumBytes 2048
        $resultInteropBytes=[IO.File]::ReadAllBytes($resultInteropPath)
        $resultInteropDecoded=Read-ResultFixtureBytes $resultInteropBytes
        Assert-ResultFixture ($resultInteropBytes.Length -le 2048 -and $resultInteropDecoded.reportVersion -eq 1 -and $resultInteropDecoded.resultToken -ceq $resultInteropToken) 'Interop source report lost its byte bound or correlation'
        Assert-ResultFixture ([string]$resultInteropDecoded.reportingFailure -ceq $resultInteropCase.reportingFailure -and $resultInteropPublished -eq ($resultInteropCase.reportingFailure -ceq '') -and $resultInteropDecoded.ok -eq ($resultInteropCase.reportingFailure -ceq '')) 'Interop source report did not match its closed case marker'
        $resultInteropManifestCases+=@{name=$resultInteropCase.name;reportingFailure=$resultInteropCase.reportingFailure}
    }
    $resultInteropManifest=@{schemaVersion=1;sourceSHA256=$resultWorkflowHash;resultToken=$resultInteropToken;cases=$resultInteropManifestCases}
    $resultInteropManifestJson=Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $resultInteropManifest -Depth 6
    $resultInteropManifestBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($resultInteropManifestJson)
    $resultInteropManifestPath=Join-Path $resultInteropItem.FullName 'manifest.json'
    $resultInteropManifestStream=[IO.FileStream]::new($resultInteropManifestPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$resultInteropManifestStream.Write($resultInteropManifestBytes,0,$resultInteropManifestBytes.Length);$resultInteropManifestStream.Flush($true)}finally{$resultInteropManifestStream.Dispose()}
    Assert-ResultFixture ([IO.Directory]::GetFileSystemEntries($resultInteropItem.FullName).Length -eq 4) 'Interop fixture contains unexpected output or staging'
}
Write-Output ('PASS workflow result source contracts ('+$script:resultFixtureChecks+' checks; native worker not executed)')
