# Selected production readers, inert streams and test-owned files only. No
# worker top-level, native tool, service, policy or machine configuration runs.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell,[switch]$RequirePowerShell7)
$ErrorActionPreference='Stop'
if($RequireWindowsPowerShell -and $RequirePowerShell7){throw 'Select one PowerShell fixture runtime'}
if($RequireWindowsPowerShell){
    if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop'){throw 'Windows PowerShell 5.1 Desktop is required'}
}else{
    if($PSVersionTable.PSVersion.Major -lt 7 -or $PSVersionTable.PSEdition -cne 'Core'){throw 'PowerShell 7 Core is required'}
}
$recoveryProject=Split-Path -Parent $PSScriptRoot
$recoverySource=Join-Path $recoveryProject 'internal\workflow\windows.ps1'
$recoverySHA=(Get-FileHash -LiteralPath $recoverySource -Algorithm SHA256).Hash.ToLowerInvariant()
$recoveryTokens=$null;$recoveryErrors=$null
$recoveryAst=[Management.Automation.Language.Parser]::ParseFile($recoverySource,[ref]$recoveryTokens,[ref]$recoveryErrors)
if($recoveryErrors.Count){throw 'Recovery source did not parse'}
$recoveryNames=@('Throw-WorkflowRecoveryJournalReadFailure','Read-WorkflowRecoveryJournalBytes','Read-WorkflowRecoveryJournalStream','Read-WorkflowRecoveryJournal','Recover-Operation','Under','No-Reparse')
foreach($name in $recoveryNames){
    $nodes=@($recoveryAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required recovery source function unavailable'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
if((Get-FileHash -LiteralPath $recoverySource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $recoverySHA){throw 'Recovery source changed during selection'}
$script:recoveryChecks=0
$script:recoveryParses=0
$script:recoveryObserved=$null
$recoveryMessage='Recovery journal could not be read safely; preserve the selected journal and recovery evidence'
function Assert-Recovery([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:recoveryChecks++}
function Assert-RecoveryFailure([scriptblock]$Action,[string]$Expected=$recoveryMessage){
    $caught=$null
    try {& $Action|Out-Null}catch {$caught=$_.Exception.Message}
    Assert-Recovery ($caught -ceq $Expected) 'Recovery refusal lost its fixed private message'
}
# This fixture exposes synthetic stream faults through the actual reader. It
# never substitutes a successful physical ownership observation.
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
namespace AccessWeaverRecoveryReaderFixture {
 public sealed class ObservedStream : Stream {
  readonly MemoryStream source;
  readonly string fault;
  public int Reads,LengthReads,Disposals,Writes;
  public long ReadBytes;
  public bool Eof,Closed;
  public ObservedStream(byte[] bytes,string mode){source=new MemoryStream(bytes,false);fault=mode;}
  public override bool CanRead {get{return fault!="not-readable";}}
  public override bool CanSeek {get{return fault!="not-seekable";}}
  public override bool CanWrite {get{return false;}}
  public override long Length {get{
   LengthReads++;
   if(fault=="initial-length" || fault=="final-length" && LengthReads>1)throw new IOException("PRIVATE_LENGTH_FAULT");
   if(fault=="negative-length")return -1;
   if(fault=="over-limit")return 8388609;
   if(fault=="declared-short")return source.Length-1;
   if(fault=="declared-long")return source.Length+1;
   if(fault=="late-extra")return source.Length-1;
   if(fault=="grow" && Reads>0)return source.Length+1;
   if(fault=="shrink" && Reads>0)return source.Length-1;
   return source.Length;
  }}
  public override long Position {get{
   if(fault=="initial-position" || fault=="final-position" && Reads>0)return source.Position+1;
   return source.Position;
  }set{source.Position=value;}}
  public override int Read(byte[] buffer,int offset,int count){
   Reads++;
   if(fault=="read" || fault=="read-close")throw new IOException("PRIVATE_READ_FAULT");
   if(fault=="early-eof"){Eof=true;return 0;}
   if(fault=="invalid-count")return count+1;
   if(fault=="negative-count")return -1;
   int n=source.Read(buffer,offset,count);ReadBytes+=n;if(n==0)Eof=true;return n;
  }
  public override void Flush(){throw new NotSupportedException();}
  public override void Write(byte[] buffer,int offset,int count){Writes++;throw new NotSupportedException();}
  public override void SetLength(long value){throw new NotSupportedException();}
  public override long Seek(long offset,SeekOrigin origin){return source.Seek(offset,origin);}
  protected override void Dispose(bool disposing){
   Disposals++;Closed=true;if(disposing)source.Dispose();base.Dispose(disposing);
   if(fault=="close" || fault=="read-close")throw new IOException("PRIVATE_CLOSE_FAULT");
  }
  public static byte[] PaddedJson(int size){
   byte[] prefix=Encoding.UTF8.GetBytes("{\"undo\":[],\"events\":[]}");
   if(size<prefix.Length)throw new ArgumentOutOfRangeException();
   byte[] bytes=new byte[size];Array.Copy(prefix,bytes,prefix.Length);
   for(int i=prefix.Length;i<bytes.Length;i++)bytes[i]=32;
   return bytes;
  }
 }
}
"@
# Count real parser calls and prove none can begin before the owned Dispose.
$script:recoveryRealConvert=Get-Command 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -CommandType Cmdlet
function ConvertFrom-Json {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)][string]$InputObject)
    process {
        $script:recoveryParses=$script:recoveryParses+1
        if($script:recoveryObserved -and ($script:recoveryObserved.Disposals -ne 1 -or -not $script:recoveryObserved.Closed)){throw 'PRIVATE_PARSE_PRECEDED_CLOSE'}
        & $script:recoveryRealConvert -InputObject $InputObject -ErrorAction Stop
    }
}
$small=[Text.Encoding]::UTF8.GetBytes('{"undo":[],"events":[]}')
foreach($fault in @('not-readable','not-seekable','initial-position','negative-length','over-limit','initial-length','final-length','declared-short','declared-long','grow','shrink','final-position','read','early-eof','invalid-count','negative-count','close','read-close')){
    $stream=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new($small,$fault)
    $script:recoveryObserved=$stream;$before=$script:recoveryParses
    Assert-RecoveryFailure {Read-WorkflowRecoveryJournalStream $stream}
    Assert-Recovery ($stream.Disposals -eq 1 -and $stream.Closed -and $stream.Writes -eq 0) 'Faulted reader abandoned or wrote its source'
    Assert-Recovery ($script:recoveryParses -eq $before) 'Faulted or unclosed reader parsed a partial frame'
    if($fault -in @('not-readable','not-seekable','initial-position','negative-length','over-limit','initial-length')){Assert-Recovery ($stream.Reads -eq 0) 'Invalid initial metadata reached a payload read'}
}
foreach($size in @((8MB-1),8MB)){
    $stream=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new([AccessWeaverRecoveryReaderFixture.ObservedStream]::PaddedJson($size),'')
    $script:recoveryObserved=$stream;$before=$script:recoveryParses
    $parsed=Read-WorkflowRecoveryJournalStream $stream
    Assert-Recovery ($parsed -and @($parsed.undo).Count -eq 0) 'Complete boundary journal was not parsed'
    Assert-Recovery ($stream.ReadBytes -eq $size -and $stream.Eof -and $stream.Disposals -eq 1 -and $stream.Writes -eq 0) 'Boundary journal did not reach EOF and one checked Close'
    Assert-Recovery ($script:recoveryParses -eq $before+1) 'Boundary journal parser call count changed'
}
$extra=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new([AccessWeaverRecoveryReaderFixture.ObservedStream]::PaddedJson(8MB+1),'late-extra')
$script:recoveryObserved=$extra;$before=$script:recoveryParses
Assert-RecoveryFailure {Read-WorkflowRecoveryJournalStream $extra}
Assert-Recovery ($extra.ReadBytes -eq 8MB+1 -and $extra.Disposals -eq 1 -and $script:recoveryParses -eq $before) 'Late extra byte bypassed actual cap or parser admission'
foreach($bytes in @([byte[]]@(0xc3,0x28),[byte[]]@(0xff,0xfe,0x7b,0),[byte[]]@(0),[byte[]]::new(0),[Text.Encoding]::UTF8.GetBytes('{"PRIVATE_PAYLOAD":'))){
    $stream=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new($bytes,'')
    $script:recoveryObserved=$stream
    Assert-RecoveryFailure {Read-WorkflowRecoveryJournalStream $stream}
    Assert-Recovery ($stream.Eof -and $stream.Disposals -eq 1) 'Rejected encoding or JSON bypassed source closure'
}
# Raw NUL must be refused by framing before the permissive JSON parser. These
# frames still reach actual EOF and one checked owned Dispose first.
$rawNulFrames=@(
    [byte[]]@(0),
    [byte[]](@(0)+@($small)),
    [byte[]](@($small)+@(0)),
    [byte[]](@([Text.Encoding]::UTF8.GetBytes('{"undo":'))+@(0)+@([Text.Encoding]::UTF8.GetBytes('[],"events":[]}'))),
    [byte[]](@([Text.Encoding]::UTF8.GetBytes('{"undo":[],"events":["'))+@(0)+@([Text.Encoding]::UTF8.GetBytes('"]}')))
)
foreach($rawNulFrame in $rawNulFrames){
    $stream=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new($rawNulFrame,'')
    $script:recoveryObserved=$stream;$before=$script:recoveryParses
    Assert-RecoveryFailure {Read-WorkflowRecoveryJournalStream $stream}
    Assert-Recovery ($stream.Eof -and $stream.Disposals -eq 1 -and $stream.Closed -and $stream.Writes -eq 0) 'Raw NUL framing refusal bypassed EOF or owned Close'
    Assert-Recovery ($script:recoveryParses -eq $before) 'Raw NUL frame reached JSON parsing'
}
# This has six literal ASCII escape characters, not a raw NUL byte. The real
# parser must retain its valid decoded U+0000 string value.
$escapedNul=[Text.Encoding]::UTF8.GetBytes('{"undo":[],"events":["\u0000"]}')
$stream=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new($escapedNul,'')
$script:recoveryObserved=$stream;$before=$script:recoveryParses
$parsed=Read-WorkflowRecoveryJournalStream $stream
$decodedNul=[string]$parsed.events[0]
Assert-Recovery ($decodedNul.Length -eq 1 -and [int][char]$decodedNul[0] -eq 0) 'Valid escaped NUL data was rejected or changed'
Assert-Recovery ($script:recoveryParses -eq $before+1 -and $stream.Eof -and $stream.Disposals -eq 1 -and $stream.Closed -and $stream.Writes -eq 0) 'Escaped NUL data bypassed actual parser or owned Close'
$unicode=[Text.Encoding]::UTF8.GetBytes(('{"undo":[],"events":["'+[char]0x03bb+[char]0x4e2d+'"]}'))
$withBom=[byte[]](@(0xef,0xbb,0xbf)+@($unicode))
$stream=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new($withBom,'')
$script:recoveryObserved=$stream
$parsed=Read-WorkflowRecoveryJournalStream $stream
Assert-Recovery ($parsed.events[0] -ceq ([string][char]0x03bb+[char]0x4e2d)) 'Strict UTF8 or one legacy BOM changed decoded data'
$doubleBom=[byte[]](@(0xef,0xbb,0xbf)+@($withBom))
$stream=[AccessWeaverRecoveryReaderFixture.ObservedStream]::new($doubleBom,'')
$script:recoveryObserved=$stream;$before=$script:recoveryParses
Assert-RecoveryFailure {Read-WorkflowRecoveryJournalStream $stream}
Assert-Recovery ($script:recoveryParses -eq $before -and $stream.Disposals -eq 1) 'Multiple BOMs reached JSON parsing'
$script:recoveryObserved=$null
# Fresh fixture only. Never recursively remove or repair unknown objects; a
# failed assertion retains the whole fixture for source-test review.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-recovery-reader-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $fixture -ErrorAction Stop)
$fixtureInfo=Get-Item -LiteralPath $fixture -Force
$registered=[Collections.Generic.List[object]]::new()
$fixtureComplete=$false
function New-RecoveryFixtureFile([string]$Path,[byte[]]$Bytes){
    $owned=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$owned.Write($Bytes,0,$Bytes.Length);$owned.Flush($true)}finally {$owned.Dispose()}
    $info=Get-Item -LiteralPath $Path -Force
    $registered.Add(@{path=$Path;length=[long]$Bytes.Length;created=$info.CreationTimeUtc;sha=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash})
}
function Assert-RecoveryFixtureUnchanged {
    $now=Get-Item -LiteralPath $fixture -Force
    Assert-Recovery ($now.PSIsContainer -and -not ($now.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $now.CreationTimeUtc -eq $fixtureInfo.CreationTimeUtc) 'Fixture root identity changed'
    foreach($entry in $registered){
        $info=Get-Item -LiteralPath $entry.path -Force
        Assert-Recovery (-not $info.PSIsContainer -and -not ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $info.Length -eq $entry.length -and $info.CreationTimeUtc -eq $entry.created -and (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash -ceq $entry.sha) 'Selected journal or unknown staging changed'
    }
}
try {
    $physical=Join-Path $fixture 'selected.json'
    New-RecoveryFixtureFile $physical $unicode
    New-RecoveryFixtureFile ($physical+'.tmp') ([byte[]]@(1,2,3))
    New-RecoveryFixtureFile ($physical+'.tmp.old') ([byte[]]@(4,5,6))
    $parsed=Read-WorkflowRecoveryJournal $physical
    Assert-Recovery ($parsed.events[0] -ceq ([string][char]0x03bb+[char]0x4e2d)) 'Physical readonly reader changed journal bytes'
    $reopen=[IO.File]::Open($physical,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    $reopen.Dispose()
    Assert-RecoveryFixtureUnchanged
    foreach($case in @('exact','oversized','invalid')){
        $path=Join-Path $fixture ($case+'.json')
        $bytes=if($case -eq 'exact'){,[AccessWeaverRecoveryReaderFixture.ObservedStream]::PaddedJson(8MB)}elseif($case -eq 'oversized'){,[AccessWeaverRecoveryReaderFixture.ObservedStream]::PaddedJson(8MB+1)}else{,[byte[]]@(0xff,0xfe,0,0)}
        New-RecoveryFixtureFile $path $bytes
        if($case -eq 'exact'){$parsed=Read-WorkflowRecoveryJournal $path;Assert-Recovery ($parsed -and @($parsed.undo).Count -eq 0) 'Physical exact boundary journal was refused'}else{Assert-RecoveryFailure {Read-WorkflowRecoveryJournal $path}}
        $reopen=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);$reopen.Dispose()
    }
    Assert-RecoveryFailure {Read-WorkflowRecoveryJournal (Join-Path $fixture 'absent.json')}
    $logs=Join-Path $fixture 'logs';[void](New-Item -ItemType Directory -Path $logs -ErrorAction Stop)
    $script:root=$fixture
    $script:undo=[Collections.Generic.List[object]]::new()
    $script:readerRollbackCalls=0;$script:readerSaveCalls=0;$script:readerEventCalls=0
    function Save-Journal {$script:readerSaveCalls++}
    function Rollback {$script:readerRollbackCalls++;return @()}
    function Event([string]$Text){$script:readerEventCalls++}
    foreach($case in @('bad-utf8','oversized','bad-json','bad-service','valid')){
        $script:r=@{journalId=('workflow-'+[guid]::NewGuid().ToString('N')+'.json')}
        $selected=Join-Path $logs $r.journalId
        $bytes=if($case -eq 'bad-utf8'){,[byte[]]@(0xc3,0x28)}elseif($case -eq 'oversized'){,[AccessWeaverRecoveryReaderFixture.ObservedStream]::PaddedJson(8MB+1)}elseif($case -eq 'bad-json'){,[Text.Encoding]::UTF8.GetBytes('{"PRIVATE_RECOVERY_BODY":')}elseif($case -eq 'bad-service'){,[Text.Encoding]::UTF8.GetBytes('{"undo":[{"kind":"service","name":"unowned-fixture-service"}],"events":[]}')}else{,[Text.Encoding]::UTF8.GetBytes('{"undo":[{"kind":"dns"}],"events":[]}')}
        New-RecoveryFixtureFile $selected $bytes
        New-RecoveryFixtureFile ($selected+'.tmp') ([byte[]]@(7,8,9))
        $sentinel=@{kind='source-sentinel'};$script:undo.Clear();$script:undo.Add($sentinel)
        $rollbackBefore=$script:readerRollbackCalls;$saveBefore=$script:readerSaveCalls;$eventBefore=$script:readerEventCalls
        if($case -eq 'valid'){
            Recover-Operation
            Assert-Recovery ($script:undo.Count -eq 1 -and $script:undo[0].kind -ceq 'dns' -and $script:readerRollbackCalls -eq $rollbackBefore+1 -and $script:readerSaveCalls -eq $saveBefore+1 -and $script:readerEventCalls -eq $eventBefore+1) 'Valid selected record bypassed the real recovery adoption path'
        }else{
            $expected=if($case -eq 'bad-service'){'Recovery journal contains an unmanaged service'}else{$recoveryMessage}
            Assert-RecoveryFailure {Recover-Operation} $expected
            Assert-Recovery ($script:undo.Count -eq 1 -and [object]::ReferenceEquals($script:undo[0],$sentinel) -and $script:readerRollbackCalls -eq $rollbackBefore -and $script:readerSaveCalls -eq $saveBefore -and $script:readerEventCalls -eq $eventBefore) 'Refused journal changed undo or dispatched recovery'
        }
        Assert-RecoveryFixtureUnchanged
    }
    if((Get-FileHash -LiteralPath $recoverySource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $recoverySHA){throw 'Recovery source changed during contracts'}
    Assert-RecoveryFixtureUnchanged
    $fixtureComplete=$true
}finally {
    if($fixtureComplete){
        try {
            Assert-RecoveryFixtureUnchanged
            foreach($entry in $registered){[IO.File]::Delete($entry.path)}
            [IO.Directory]::Delete((Join-Path $fixture 'logs'),$false)
            [IO.Directory]::Delete($fixture,$false)
        }catch {throw 'Recovery fixture cleanup could not be confirmed; preserve test evidence'}
    }
}
Write-Output ('Workflow recovery reader source contracts passed: '+$script:recoveryChecks)
