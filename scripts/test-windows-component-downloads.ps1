# Selected-function source contracts only. No worker top level, network, curl,
# product executable, service, machine policy or host setting is invoked.
# Native HTTP/curl and Windows pipe qualification remain separate hosted work.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop'
Write-Output 'STAGE-ENTRY-PASS'
if($RequireWindowsPowerShell -and ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop')){throw 'Windows PowerShell 5.1 Desktop is required'}
$downloadProject=Split-Path -Parent $PSScriptRoot
$downloadTokens=$null;$downloadParseErrors=$null
$downloadAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $downloadProject 'internal\workflow\windows.ps1'),[ref]$downloadTokens,[ref]$downloadParseErrors)
if($downloadParseErrors.Count){throw 'Component download source did not parse'}
Write-Output 'STAGE-SOURCE-PARSE-PASS'
$downloadNames=@('Throw-ComponentDownloadFailure','New-ComponentDownloadBudget','Get-ComponentDownloadRemaining','Wait-ComponentDownloadTask','Write-ComponentDownloadChunk','Receive-ComponentDownloadStream','Assert-ComponentDownloadLength','Test-ComponentDownloadTerminal','Save-ComponentDownloadAttempt','Invoke-ComponentDownloadDotNet','Set-ComponentDownloadHeaders','Invoke-ComponentDownloadCurl','New-ComponentDownloadCurlStart','New-ComponentDownloadCurlProcess','Wait-ComponentDownloadProcessExit','Native-Argument','Quote-Arg','Require-DownloadPermission','Approved-DownloadHash','Allowed-Download','Read-RemoteJSON','Resolve-ComponentDownloadRedirect','New-ComponentDownloadRequest','Invoke-ComponentDownloadCurlOnce','Test-InstallerPublisher','Download')
$downloadDefinitionIndex=0
foreach($downloadName in $downloadNames){
    $downloadNodes=@($downloadAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $downloadName})
    if($downloadNodes.Count -ne 1){throw 'Required component download function is unavailable'}
    . ([scriptblock]::Create($downloadNodes[0].Extent.Text))
    $downloadDefinitionIndex++
    if($downloadDefinitionIndex -in @(5,10,15,20,25)){Write-Output ('STAGE-DEFINITION-'+$downloadDefinitionIndex+'-PASS')}
}
Write-Output 'STAGE-DEFINITIONS-PASS'
# These types allocate only tiny buffers. Length is deliberately independent of
# actual data, so the actual-byte guard cannot rely on a declared stream size.
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
namespace AccessWeaverDownloadFixture {
 public sealed class Input : Stream {
  public long Total;
  public long Declared;
  public int Chunk;
  public int Reads;
  public long ReadBytes;
  public bool Stalled;
  public bool Closed;
  public long FailAfter = -1;
  public TaskCompletionSource<int> Pending;
  public Input(long total, int chunk, long declared) { Total=total;Chunk=chunk;Declared=declared; }
  public override bool CanRead { get { return true; } }
  public override bool CanSeek { get { return false; } }
  public override bool CanWrite { get { return false; } }
  public override long Length { get { return Declared; } }
  public override long Position { get { return ReadBytes; } set { throw new NotSupportedException(); } }
  public override int Read(byte[] b,int offset,int count) {
   Reads++;
   if(FailAfter>=0 && ReadBytes>=FailAfter) throw new IOException("synthetic source transport failure");
   int n=(int)Math.Min(Math.Min((long)count,Chunk),Total-ReadBytes);
   for(int i=0;i<n;i++) b[offset+i]=(byte)((ReadBytes+i)%251);
   ReadBytes+=n;return n;
  }
  public override Task<int> ReadAsync(byte[] b,int offset,int count,CancellationToken cancellation) {
   if(Stalled) { Reads++;Pending=new TaskCompletionSource<int>();return Pending.Task; }
   try { return Task.FromResult(Read(b,offset,count)); }
   catch(Exception e) { var failed=new TaskCompletionSource<int>();failed.SetException(e);return failed.Task; }
  }
  protected override void Dispose(bool disposing) {
   Closed=true;
   if(Pending!=null) Pending.TrySetException(new ObjectDisposedException("synthetic source stream"));
   base.Dispose(disposing);
  }
  public override void Flush() { }
  public override long Seek(long o,SeekOrigin origin) { throw new NotSupportedException(); }
  public override void SetLength(long n) { throw new NotSupportedException(); }
  public override void Write(byte[] b,int o,int n) { throw new NotSupportedException(); }
 }
 public sealed class Output : MemoryStream {
  public long AttemptedBytes;
  public int Writes;
  public bool FailWrite;
  public bool Stalled;
  public bool Closed;
  public TaskCompletionSource<int> Pending;
  protected override void Dispose(bool disposing) { Closed=true;if(Pending!=null) Pending.TrySetException(new ObjectDisposedException("synthetic destination stream"));base.Dispose(disposing); }
  public override Task WriteAsync(byte[] b,int offset,int count,CancellationToken cancellation) {
   if(Stalled) { Writes++;AttemptedBytes+=count;Pending=new TaskCompletionSource<int>();return Pending.Task; }
   try { Write(b,offset,count);return Task.FromResult(0); }
   catch(Exception e) { var failed=new TaskCompletionSource<int>();failed.SetException(e);return failed.Task; }
  }
  public override void Write(byte[] b,int offset,int count) {
   Writes++;AttemptedBytes+=count;
   if(FailWrite) throw new IOException("synthetic destination failure");
   base.Write(b,offset,count);
  }
 }
}
"@
$script:downloadFixtureChecks=0
function Assert-DownloadFixture([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:downloadFixtureChecks++}
function Reject-DownloadFixture([scriptblock]$Operation){
    $downloadFailure=$null
    try{& $Operation|Out-Null}catch{$downloadFailure=$_.Exception}
    Assert-DownloadFixture ($null -ne $downloadFailure) 'Expected component download refusal did not occur'
    return $downloadFailure
}
function New-DownloadFixtureBytes([int]$Count){
    $downloadBytes=[byte[]]::new($Count)
    for($downloadIndex=0;$downloadIndex -lt $Count;$downloadIndex++){$downloadBytes[$downloadIndex]=[byte]($downloadIndex%251)}
    return ,$downloadBytes
}
function Get-DownloadFixtureHash([byte[]]$Bytes){
    $downloadHasher=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($downloadHasher.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$downloadHasher.Dispose()}
}

# These are stream/framing contracts, not native HTTP chunk decoding evidence.
$downloadBudget=New-ComponentDownloadBudget
Assert-DownloadFixture ($downloadBudget.MaximumBytes -eq (2147483648L+32MB) -and $downloadBudget.TimeoutMilliseconds -eq 600000 -and $downloadBudget.Written -eq 0) 'Production download budget changed unexpectedly'
$downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
$downloadOutput=[AccessWeaverDownloadFixture.Output]::new()
try{
    $downloadBytes=New-DownloadFixtureBytes 32
    Write-ComponentDownloadChunk $downloadOutput $downloadBytes 8 $downloadBudget
    Write-ComponentDownloadChunk $downloadOutput $downloadBytes 24 $downloadBudget
    Assert-DownloadFixture ($downloadOutput.Length -eq 32 -and $downloadOutput.AttemptedBytes -eq 32 -and $downloadBudget.Written -eq 32) 'Exact stream boundary was not accepted'
    $null=Reject-DownloadFixture {Write-ComponentDownloadChunk $downloadOutput $downloadBytes 1 $downloadBudget}
    Assert-DownloadFixture ($downloadOutput.AttemptedBytes -eq 32 -and $downloadOutput.Writes -eq 2 -and $downloadBudget.Written -eq 32) 'Overflow reached the destination Write call'
}finally{$downloadOutput.Dispose()}
foreach($downloadInvalidCount in @(-1,33)){
    $downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
    $downloadOutput=[AccessWeaverDownloadFixture.Output]::new()
    try{
        $null=Reject-DownloadFixture {Write-ComponentDownloadChunk $downloadOutput (New-DownloadFixtureBytes 32) $downloadInvalidCount $downloadBudget}
        Assert-DownloadFixture ($downloadOutput.AttemptedBytes -eq 0 -and $downloadBudget.Written -eq 0) 'Invalid byte count reached the destination'
    }finally{$downloadOutput.Dispose()}
}
foreach($downloadStreamCase in @(
    @{total=0;chunk=1;declared=0;accept=$true},
    @{total=32;chunk=32;declared=32;accept=$true},
    @{total=32;chunk=1;declared=-1;accept=$true},
    @{total=32;chunk=7;declared=-1;accept=$true},
    @{total=33;chunk=1;declared=-1;accept=$false},
    @{total=33;chunk=33;declared=-1;accept=$false},
    @{total=32;chunk=4;declared=31;accept=$false},
    @{total=31;chunk=4;declared=32;accept=$false}
)){
    $downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
    $downloadInput=[AccessWeaverDownloadFixture.Input]::new($downloadStreamCase.total,$downloadStreamCase.chunk,$downloadStreamCase.declared)
    $downloadOutput=[AccessWeaverDownloadFixture.Output]::new()
    try{
        $downloadOperation={
            Assert-ComponentDownloadLength $downloadStreamCase.declared $downloadBudget
            Receive-ComponentDownloadStream $downloadInput $downloadOutput $downloadBudget
            Assert-ComponentDownloadLength $downloadStreamCase.declared $downloadBudget $downloadOutput.Length
        }
        if($downloadStreamCase.accept){& $downloadOperation}else{$null=Reject-DownloadFixture $downloadOperation}
        Assert-DownloadFixture ($downloadOutput.AttemptedBytes -le 32 -and $downloadOutput.Length -le 32 -and $downloadBudget.Written -eq $downloadOutput.Length) 'Stream framing wrote beyond its byte budget'
        if($downloadStreamCase.accept){Assert-DownloadFixture ($downloadOutput.Length -eq $downloadStreamCase.total) 'Accepted stream lost bytes'}
        if($downloadStreamCase.total -eq 33 -and $downloadStreamCase.chunk -eq 33){Assert-DownloadFixture ($downloadOutput.Writes -eq 0) 'An oversized first chunk was partly written before refusal'}
    }finally{$downloadInput.Dispose();$downloadOutput.Dispose()}
}
$downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
$downloadInput=[AccessWeaverDownloadFixture.Input]::new(33,1,33)
$downloadOutput=[AccessWeaverDownloadFixture.Output]::new()
try{
    $null=Reject-DownloadFixture {Assert-ComponentDownloadLength 33 $downloadBudget;Receive-ComponentDownloadStream $downloadInput $downloadOutput $downloadBudget}
    Assert-DownloadFixture ($downloadInput.Reads -eq 0 -and $downloadOutput.AttemptedBytes -eq 0) 'Declared oversize was not refused before reading'
}finally{$downloadInput.Dispose();$downloadOutput.Dispose()}
$downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
$downloadInput=[AccessWeaverDownloadFixture.Input]::new(32,4,-1);$downloadInput.FailAfter=4
$downloadOutput=[AccessWeaverDownloadFixture.Output]::new()
try{
    $null=Reject-DownloadFixture {Receive-ComponentDownloadStream $downloadInput $downloadOutput $downloadBudget}
    Assert-DownloadFixture ($downloadOutput.AttemptedBytes -eq 4 -and $downloadBudget.Written -eq 4) 'Read failure lost the exact partial byte count'
}finally{$downloadInput.Dispose();$downloadOutput.Dispose()}
$downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
$downloadOutput=[AccessWeaverDownloadFixture.Output]::new();$downloadOutput.FailWrite=$true
try{
    $downloadFailure=Reject-DownloadFixture {Write-ComponentDownloadChunk $downloadOutput (New-DownloadFixtureBytes 4) 4 $downloadBudget}
    Assert-DownloadFixture (Test-ComponentDownloadTerminal $downloadFailure) 'Destination storage error allowed a transport retry'
    Assert-DownloadFixture ($downloadBudget.Written -eq 4 -and $downloadOutput.Length -eq 0 -and $downloadOutput.Writes -eq 1) 'Failed storage write did not retain its conservative admission charge'
}finally{$downloadOutput.Dispose()}
# Disposing this synthetic stalled source resolves its exact pending task. The
# assertion requires completion, so a timeout that abandons the task cannot pass.
$downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 40
$downloadInput=[AccessWeaverDownloadFixture.Input]::new(1,1,-1);$downloadInput.Stalled=$true
$downloadOutput=[AccessWeaverDownloadFixture.Output]::new()
try{
    $downloadFailure=Reject-DownloadFixture {Receive-ComponentDownloadStream $downloadInput $downloadOutput $downloadBudget}
    Assert-DownloadFixture (Test-ComponentDownloadTerminal $downloadFailure) 'Stalled stream did not retain terminal deadline refusal'
    Assert-DownloadFixture ($downloadInput.Closed -and $null -ne $downloadInput.Pending -and $downloadInput.Pending.Task.IsCompleted -and $downloadOutput.AttemptedBytes -eq 0) 'Deadline abandoned a pending read or destination bytes'
}finally{$downloadInput.Dispose();$downloadOutput.Dispose()}
$downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 40
$downloadPending=[Threading.Tasks.TaskCompletionSource[int]]::new()
$script:downloadAborts=0
$downloadFailure=Reject-DownloadFixture {Wait-ComponentDownloadTask $downloadPending.Task $downloadBudget {$script:downloadAborts++;[void]$downloadPending.TrySetException([IO.IOException]::new('synthetic aborted task'))}}
Assert-DownloadFixture ((Test-ComponentDownloadTerminal $downloadFailure) -and $script:downloadAborts -eq 1 -and $downloadPending.Task.IsCompleted) 'Shared deadline did not abort and join the exact pending task'

# The destination stall also retains its exact pending async buffer until join.
$downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 40
$downloadOutput=[AccessWeaverDownloadFixture.Output]::new();$downloadOutput.Stalled=$true
try{
    $downloadFailure=Reject-DownloadFixture {Write-ComponentDownloadChunk $downloadOutput (New-DownloadFixtureBytes 4) 4 $downloadBudget}
    Assert-DownloadFixture ((Test-ComponentDownloadTerminal $downloadFailure) -and $downloadOutput.Closed -and $downloadOutput.Pending.Task.IsCompleted -and $downloadBudget.Written -eq 4) 'Deadline abandoned the admitted destination write or its buffer'
}finally{$downloadOutput.Dispose()}

Write-Output 'STAGE-STREAM-PASS'
# Capture real pure helpers before scope-local transport replacements. The
# orchestration still calls the real exclusive-file attempt and real byte copier.
$script:downloadOriginalApproval=(Get-Command Approved-DownloadHash).ScriptBlock
$script:downloadOriginalAllowed=(Get-Command Allowed-Download).ScriptBlock
$script:downloadOriginalBudget=(Get-Command New-ComponentDownloadBudget).ScriptBlock
$script:downloadOriginalDotNet=(Get-Command Invoke-ComponentDownloadDotNet).ScriptBlock
$script:downloadOriginalCurl=(Get-Command Invoke-ComponentDownloadCurl).ScriptBlock
$script:downloadFixtureState=$null
function New-ComponentDownloadBudget([long]$MaximumBytes=(2147483648L+32MB),[int]$TimeoutMilliseconds=600000){
    if($null -eq $script:downloadFixtureState){return (& $script:downloadOriginalBudget -MaximumBytes $MaximumBytes -TimeoutMilliseconds $TimeoutMilliseconds)}
    $script:downloadFixtureState.Budgets++
    $downloadFixtureBudget=& $script:downloadOriginalBudget -MaximumBytes $script:downloadFixtureState.Limit -TimeoutMilliseconds $script:downloadFixtureState.Timeout
    $script:downloadFixtureState.Budget=$downloadFixtureBudget
    return $downloadFixtureBudget
}
function Approved-DownloadHash([string]$url,[string]$hash){$script:downloadFixtureState.Approvals++;return $hash}
function Allowed-Download([string]$url){$script:downloadFixtureState.Allowed++}
function Copy-Checked([string]$source,[string]$destination){
    $script:downloadFixtureState.Promotions++
    if($script:downloadFixtureState.Mode -eq 'promotion-failure'){throw 'synthetic promotion failure'}
    [IO.File]::Copy($source,$destination,$false)
}
function Event([string]$message){$script:downloadFixtureState.Events++}
function Get-AuthenticodeSignature([string]$LiteralPath){
    $script:downloadFixtureState.Signatures++
    if($script:downloadFixtureState.Mode -eq 'signature-error'){throw 'synthetic signature inspection failure'}
    if($script:downloadFixtureState.Mode -eq 'signature-invalid'){return [pscustomobject]@{Status='NotSigned';SignerCertificate=$null}}
    if($script:downloadFixtureState.Mode -eq 'publisher-invalid'){return [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='fixture unapproved publisher'}}}
    return [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='Microsoft fixture publisher'}}
}
function Invoke-DownloadFixtureTransport([string]$Kind,[IO.Stream]$Output,$Budget,[bool]$Proxy){
    $downloadFixtureState=$script:downloadFixtureState
    $downloadFixtureState.Calls.Add($Kind)
    Assert-DownloadFixture ([object]::ReferenceEquals($Budget,$downloadFixtureState.Budget)) 'Fallback replaced the shared deadline budget'
    Assert-DownloadFixture ($Output.Length -eq 0 -and $Budget.Written -eq 0) 'Attempt reused a partial file or stale per-attempt byte charge'
    $downloadFixtureState.Paths.Add($Output.Name)
    $downloadFixtureState.Proxies.Add($Proxy)
    if($Kind -eq 'curl'){
        Assert-DownloadFixture ($downloadFixtureState.Paths.Count -eq 1 -or $downloadFixtureState.Paths[0] -eq $Output.Name) 'Fallback switched away from the guarded staging path'
    }
    if($downloadFixtureState.Mode -eq 'overflow'){
        $downloadFixtureInput=[AccessWeaverDownloadFixture.Input]::new(33,33,-1)
        try{Receive-ComponentDownloadStream $downloadFixtureInput $Output $Budget}finally{$downloadFixtureInput.Dispose()}
        throw 'Oversized fixture unexpectedly completed'
    }
    if($downloadFixtureState.Mode -eq 'storage-failure'){Throw-ComponentDownloadFailure 'storage'}
    if($downloadFixtureState.Mode -eq 'cleanup-failure'){
        $downloadFixturePath=$Output.Name
        $Output.Dispose()
        $downloadFixtureState.Held=[IO.FileStream]::new($downloadFixturePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        Throw-ComponentDownloadFailure 'transport'
    }
    if($Kind -eq 'dotnet' -and $downloadFixtureState.Mode -in @('fallback','deadline','both-fail')){
        Write-ComponentDownloadChunk $Output (New-DownloadFixtureBytes 5) 5 $Budget
        if($downloadFixtureState.Mode -eq 'deadline'){
            while($Budget.Clock.ElapsedMilliseconds -lt $Budget.TimeoutMilliseconds){[Threading.Thread]::Sleep(1)}
        }
        Throw-ComponentDownloadFailure 'transport'
    }
    if($Kind -eq 'curl' -and $downloadFixtureState.Mode -eq 'both-fail'){Throw-ComponentDownloadFailure 'transport'}
    $downloadFixtureInput=[AccessWeaverDownloadFixture.Input]::new(32,7,-1)
    try{Receive-ComponentDownloadStream $downloadFixtureInput $Output $Budget}finally{$downloadFixtureInput.Dispose()}
}
function Invoke-ComponentDownloadDotNet([string]$Url,[IO.Stream]$Output,$Budget,[hashtable]$Headers=@{}){Invoke-DownloadFixtureTransport 'dotnet' $Output $Budget $false}
function Invoke-ComponentDownloadCurl([string]$Url,[IO.Stream]$Output,$Budget,[switch]$Proxy){Invoke-DownloadFixtureTransport 'curl' $Output $Budget ([bool]$Proxy)}
$downloadFixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-component-source-'+[guid]::NewGuid().ToString('N'))
if(Test-Path -LiteralPath $downloadFixtureRoot){throw 'Fresh download fixture path already exists'}
$downloadFixtureRootItem=[IO.Directory]::CreateDirectory($downloadFixtureRoot)
$downloadFixtureRootCreated=$downloadFixtureRootItem.CreationTimeUtc.Ticks
$root=$downloadFixtureRoot
$downloadFixtureDirectory=[IO.Directory]::CreateDirectory((Join-Path $root 'downloads'))
try{
    foreach($downloadCase in @(
        @{mode='success';accept=$true;signed=$false;proxy=$false;calls='dotnet';promotions=1},
        @{mode='success';accept=$true;signed=$true;proxy=$false;calls='dotnet';promotions=1},
        @{mode='fallback';accept=$true;signed=$false;proxy=$false;calls='dotnet,curl';promotions=1},
        @{mode='success';accept=$true;signed=$false;proxy=$true;calls='curl';promotions=1},
        @{mode='overflow';accept=$false;signed=$false;proxy=$false;calls='dotnet';promotions=0},
        @{mode='deadline';accept=$false;signed=$false;proxy=$false;calls='dotnet';promotions=0},
        @{mode='both-fail';accept=$false;signed=$false;proxy=$false;calls='dotnet,curl';promotions=0},
        @{mode='storage-failure';accept=$false;signed=$false;proxy=$false;calls='dotnet';promotions=0},
        @{mode='cleanup-failure';accept=$false;signed=$false;proxy=$false;calls='dotnet';promotions=0},
        @{mode='hash-mismatch';accept=$false;signed=$false;proxy=$false;calls='dotnet';promotions=0},
        @{mode='signature-invalid';accept=$false;signed=$true;proxy=$false;calls='dotnet';promotions=0},
        @{mode='publisher-invalid';accept=$false;signed=$true;proxy=$false;calls='dotnet';promotions=0},
        @{mode='publisher-other-category';accept=$false;signed=$true;proxy=$false;calls='dotnet';promotions=0},
        @{mode='signature-error';accept=$false;signed=$true;proxy=$false;calls='dotnet';promotions=0},
        @{mode='promotion-failure';accept=$false;signed=$false;proxy=$false;calls='dotnet';promotions=1}
    )){
        $script:downloadFixtureState=@{Mode=$downloadCase.mode;Limit=32L;Timeout=$(if($downloadCase.mode -eq 'deadline'){80}else{2000});Budgets=0;Budget=$null;Approvals=0;Allowed=0;Promotions=0;Signatures=0;Events=0;Calls=[Collections.Generic.List[string]]::new();Paths=[Collections.Generic.List[string]]::new();Proxies=[Collections.Generic.List[bool]]::new();Held=$null}
        $script:repairProxyReady=$downloadCase.proxy
        $downloadDestination=Join-Path $root 'verified.bin'
        $downloadExpectedHash=Get-DownloadFixtureHash (New-DownloadFixtureBytes 32)
        if($downloadCase.mode -eq 'hash-mismatch'){$downloadExpectedHash='a'*64}
        try{
            $downloadAction={if($downloadCase.signed){$fixturePublisher=if($downloadCase.mode -eq 'publisher-other-category'){'discord'}else{'microsoft'};Download 'https://github.com/hufrea/byedpi/releases/download/fixture/component.zip' $downloadExpectedHash $downloadDestination -Signed -Publisher $fixturePublisher}else{Download 'https://github.com/hufrea/byedpi/releases/download/fixture/component.zip' $downloadExpectedHash $downloadDestination}}
            if($downloadCase.accept){& $downloadAction}else{$null=Reject-DownloadFixture $downloadAction}
            Assert-DownloadFixture (($script:downloadFixtureState.Calls -join ',') -ceq $downloadCase.calls) 'Download attempted an unexpected transport or retry'
            Assert-DownloadFixture ($script:downloadFixtureState.Budgets -eq 1 -and $script:downloadFixtureState.Approvals -eq 1 -and $script:downloadFixtureState.Allowed -eq 1) 'Download repeated policy admission or reset its deadline'
            Assert-DownloadFixture ($script:downloadFixtureState.Promotions -eq $downloadCase.promotions) 'Unverified or incomplete download reached promotion'
            Assert-DownloadFixture ((Test-Path -LiteralPath $downloadDestination) -eq $downloadCase.accept) 'Download published an unverified destination'
            Assert-DownloadFixture ($script:downloadFixtureState.Events -eq [int]$downloadCase.accept) 'Download reported success before verified promotion'
            if($downloadCase.accept){Assert-DownloadFixture ((Get-FileHash -LiteralPath $downloadDestination -Algorithm SHA256).Hash.ToLowerInvariant() -ceq (Get-DownloadFixtureHash (New-DownloadFixtureBytes 32))) 'Promoted bytes differ from the verified source'}
            if($downloadCase.proxy){Assert-DownloadFixture ($script:downloadFixtureState.Proxies.Count -eq 1 -and $script:downloadFixtureState.Proxies[0]) 'Repair proxy did not remain confined to the curl transport'}
            if($downloadCase.mode -eq 'cleanup-failure'){
                Assert-DownloadFixture ((Get-ChildItem -LiteralPath $downloadFixtureDirectory.FullName -File).Count -eq 1) 'Unconfirmed cleanup was hidden as a successful retry'
            }else{Assert-DownloadFixture ((Get-ChildItem -LiteralPath $downloadFixtureDirectory.FullName -File).Count -eq 0) 'Failed or verified staging file was retained'}
        }finally{
            if($script:downloadFixtureState.Held){$script:downloadFixtureState.Held.Dispose()}
            foreach($downloadOwnedPath in $script:downloadFixtureState.Paths){if([IO.File]::Exists($downloadOwnedPath)){[IO.File]::Delete($downloadOwnedPath)}}
            if([IO.File]::Exists($downloadDestination)){[IO.File]::Delete($downloadDestination)}
        }
    }
    $downloadExisting=Join-Path $root 'exclusive.bin'
    $downloadSentinel=New-DownloadFixtureBytes 3
    [IO.File]::WriteAllBytes($downloadExisting,$downloadSentinel)
    try{
        $downloadBudget=& $script:downloadOriginalBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
        $downloadCallsBefore=$script:downloadFixtureState.Calls.Count
        $downloadFailure=Reject-DownloadFixture {Save-ComponentDownloadAttempt 'https://github.com/hufrea/byedpi/releases/download/fixture/component.zip' $downloadExisting $downloadBudget}
        Assert-DownloadFixture ((Test-ComponentDownloadTerminal $downloadFailure) -and $script:downloadFixtureState.Calls.Count -eq $downloadCallsBefore -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($downloadExisting)) -ceq [Convert]::ToBase64String($downloadSentinel)) 'Exclusive attempt modified or deleted a preexisting file'
    }finally{[IO.File]::Delete($downloadExisting)}
}finally{
    $script:downloadFixtureState=$null
    $downloadFreshRoot=Get-Item -LiteralPath $downloadFixtureRoot -Force
    if($downloadFreshRoot.CreationTimeUtc.Ticks -ne $downloadFixtureRootCreated -or ($downloadFreshRoot.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed download fixture root was preserved'}
    # No recursive deletion: preserve unknown content rather than adopting it.
    [IO.Directory]::Delete($downloadFixtureDirectory.FullName,$false)
    [IO.Directory]::Delete($downloadFixtureRoot,$false)
}

Write-Output 'STAGE-COMPOSITION-PASS'
# A late response is still owned by the pending task until Abort resolves and
# the actual task is joined. No native HTTP response is constructed here.
$downloadBudget=& $script:downloadOriginalBudget -MaximumBytes 32 -TimeoutMilliseconds 30
$downloadLate=[Threading.Tasks.TaskCompletionSource[object]]::new()
$downloadLateResponse=[IO.MemoryStream]::new()
$downloadFailure=Reject-DownloadFixture {Wait-ComponentDownloadTask $downloadLate.Task $downloadBudget {[void]$downloadLate.TrySetResult($downloadLateResponse)}}
Assert-DownloadFixture ((Test-ComponentDownloadTerminal $downloadFailure) -and $downloadLate.Task.IsCompleted -and -not $downloadLateResponse.CanRead) 'Expired successful response was abandoned instead of disposed after actual task completion'
Add-Type -TypeDefinition @"
using System.Net;
namespace AccessWeaverDownloadFixture {
 public sealed class Response : WebResponse {
  public bool Closed;
  public override void Close() { Closed=true;base.Close(); }
 }
}
"@
$downloadBudget=& $script:downloadOriginalBudget -MaximumBytes 32 -TimeoutMilliseconds 30
$downloadLate=[Threading.Tasks.TaskCompletionSource[object]]::new()
$downloadLateErrorResponse=[AccessWeaverDownloadFixture.Response]::new()
$downloadLateWebError=[Net.WebException]::new('synthetic error response',$null,[Net.WebExceptionStatus]::ProtocolError,$downloadLateErrorResponse)
$downloadFailure=Reject-DownloadFixture {Wait-ComponentDownloadTask $downloadLate.Task $downloadBudget {[void]$downloadLate.TrySetException($downloadLateWebError)}}
Assert-DownloadFixture ((Test-ComponentDownloadTerminal $downloadFailure) -and $downloadLate.Task.IsCompleted -and $downloadLateErrorResponse.Closed) 'Expired faulted response was abandoned instead of closed after actual task completion'

# Metadata uses its actual production eight-MiB budget; overflow is generated
# in small chunks and remains entirely in memory. Parse calls are observed so
# invalid UTF-8, incomplete transports and cap failures cannot pass via JSON error.
Set-Item -LiteralPath Function:\New-ComponentDownloadBudget -Value $script:downloadOriginalBudget
$script:downloadMetadataState=$null
function ConvertFrom-Json([string]$InputObject){
    $script:downloadMetadataState.Parses++
    $downloadParsed=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject
    return ,$downloadParsed
}
function Invoke-ComponentDownloadDotNet([string]$Url,[IO.Stream]$Output,$Budget,[hashtable]$Headers=@{}){
    $downloadMetadata=$script:downloadMetadataState
    $downloadMetadata.Calls++
    $downloadMetadata.Output=$Output
    $downloadMetadata.Budget=$Budget
    Assert-DownloadFixture ($Budget.MaximumBytes -eq 8MB -and $Budget.TimeoutMilliseconds -eq 60000) 'Metadata did not use its independent bounded budget'
    Assert-DownloadFixture ($Headers['User-Agent'] -ceq 'AccessWeaver-source-fixture' -and $Headers['Accept'] -ceq 'application/json') 'Metadata dropped caller headers before transport'
    $downloadDeclared=-1L
    if($downloadMetadata.Mode -eq 'declared-oversize'){$downloadDeclared=8MB+1}
    if($downloadMetadata.Mode -eq 'misdeclared'){$downloadDeclared=2}
    Assert-ComponentDownloadLength $downloadDeclared $Budget
    if($downloadMetadata.Mode -eq 'unknown-overflow'){
        $downloadSource=[AccessWeaverDownloadFixture.Input]::new((8MB+1),65536,-1)
        try{Receive-ComponentDownloadStream $downloadSource $Output $Budget}finally{$downloadSource.Dispose()}
        throw 'Oversized metadata unexpectedly completed'
    }
    if($downloadMetadata.Mode -eq 'transport-failure'){
        Write-ComponentDownloadChunk $Output ([Text.Encoding]::UTF8.GetBytes('{')) 1 $Budget
        Throw-ComponentDownloadFailure 'transport'
    }
    $downloadMetadataSource=[IO.MemoryStream]::new($downloadMetadata.Bytes,$false)
    try{Receive-ComponentDownloadStream $downloadMetadataSource $Output $Budget}finally{$downloadMetadataSource.Dispose()}
    Assert-ComponentDownloadLength $downloadDeclared $Budget $Budget.Written
}
$inputData=@{managedPolicy=$false;allowDownloads=$true}
foreach($downloadMetadataCase in @(
    @{mode='object';json='{"name":"fixture"}';accept=$true;parses=1},
    @{mode='array';json='[{"n":1},{"n":2}]';accept=$true;parses=1},
    @{mode='empty-array';json='[]';accept=$true;parses=1},
    @{mode='one-array';json='[{"n":1}]';accept=$true;parses=1},
    @{mode='null';json='null';accept=$true;parses=1},
    @{mode='bom';json='{"name":"fixture"}';accept=$true;parses=1},
    @{mode='invalid-utf8';json='';accept=$false;parses=0},
    @{mode='invalid-json';json='[PRIVATE_METADATA_FIXTURE';accept=$false;parses=1},
    @{mode='envelope-sibling';json='null,"other":1';accept=$false;parses=1},
    @{mode='envelope-duplicate';json='null,"value":{"name":"override"}';accept=$false;parses=1},
    @{mode='transport-failure';json='';accept=$false;parses=0},
    @{mode='declared-oversize';json='';accept=$false;parses=0},
    @{mode='unknown-overflow';json='';accept=$false;parses=0},
    @{mode='misdeclared';json='{"name":"fixture"}';accept=$false;parses=0}
)){
    $downloadMetadataBytes=[Text.Encoding]::UTF8.GetBytes($downloadMetadataCase.json)
    if($downloadMetadataCase.mode -eq 'bom'){$downloadMetadataBytes=[byte[]](@(239,187,191)+$downloadMetadataBytes)}
    if($downloadMetadataCase.mode -eq 'invalid-utf8'){$downloadMetadataBytes=[byte[]]@(195,40)}
    $script:downloadMetadataState=@{Mode=$downloadMetadataCase.mode;Bytes=$downloadMetadataBytes;Calls=0;Parses=0;Output=$null;Budget=$null}
    $downloadMetadataAction={Read-RemoteJSON 'https://api.github.com/repos/hufrea/byedpi/releases' @{'User-Agent'='AccessWeaver-source-fixture';Accept='application/json'}}
    if($downloadMetadataCase.accept){$downloadMetadataResult=& $downloadMetadataAction}else{$downloadMetadataFailure=Reject-DownloadFixture $downloadMetadataAction}
    Assert-DownloadFixture ($script:downloadMetadataState.Calls -eq 1 -and (($downloadMetadataCase.parses -eq 0 -and $script:downloadMetadataState.Parses -eq 0) -or ($downloadMetadataCase.parses -gt 0 -and $script:downloadMetadataState.Parses -ge 1))) 'Metadata parsed failed or unbounded transport content'
    Assert-DownloadFixture (-not $script:downloadMetadataState.Output.CanRead -and $script:downloadMetadataState.Budget.Written -le 8MB) 'Metadata retained its private response buffer or exceeded its byte cap'
    if($downloadMetadataCase.mode -in @('object','bom')){Assert-DownloadFixture ($downloadMetadataResult.name -ceq 'fixture') 'Metadata object semantics changed'}
    if($downloadMetadataCase.mode -eq 'array'){Assert-DownloadFixture ($downloadMetadataResult -is [array] -and $downloadMetadataResult.Count -eq 2 -and $downloadMetadataResult[0].n -eq 1 -and $downloadMetadataResult[1].n -eq 2) 'Metadata array semantics changed'}
    if($downloadMetadataCase.mode -eq 'empty-array'){Assert-DownloadFixture ($downloadMetadataResult -is [array] -and $downloadMetadataResult.Count -eq 0) 'Metadata empty array collapsed to null'}
    if($downloadMetadataCase.mode -eq 'one-array'){Assert-DownloadFixture ($downloadMetadataResult -is [array] -and $downloadMetadataResult.Count -eq 1 -and $downloadMetadataResult[0].n -eq 1) 'Metadata single array collapsed to an object'}
    if($downloadMetadataCase.mode -eq 'null'){Assert-DownloadFixture ($null -eq $downloadMetadataResult) 'Metadata null semantics changed'}
    if($downloadMetadataCase.mode -in @('invalid-json','invalid-utf8','envelope-sibling','envelope-duplicate')){Assert-DownloadFixture ($downloadMetadataFailure.Message -ceq 'Component download response was incomplete or unsupported' -and $downloadMetadataFailure.Message.Length -le 128 -and $downloadMetadataFailure.Message -cnotmatch 'PRIVATE_METADATA_FIXTURE') 'Metadata parse failure exposed upstream body or decoder detail'}
    if($downloadMetadataCase.mode -eq 'declared-oversize'){Assert-DownloadFixture ($script:downloadMetadataState.Budget.Written -eq 0) 'Declared oversized metadata was consumed'}
}
$script:downloadMetadataState=@{Mode='policy-denied';Calls=0;Parses=0}
$inputData=@{managedPolicy=$true;allowDownloads=$false}
$null=Reject-DownloadFixture {Read-RemoteJSON 'https://api.github.com/repos/hufrea/byedpi/releases' @{}}
Assert-DownloadFixture ($script:downloadMetadataState.Calls -eq 0 -and $script:downloadMetadataState.Parses -eq 0) 'Managed metadata denial happened after remote access or parsing'

# Download policy uses the real approval function and refuses before budget,
# transport, staging or destination promotion can be admitted.
& {
    Set-Item -LiteralPath Function:\Approved-DownloadHash -Value $script:downloadOriginalApproval
    $inputData=@{managedPolicy=$true;allowDownloads=$false;downloads=@(@{url='https://github.com/hufrea/byedpi/releases/download/fixture/component.zip';sha256=('a'*64)})}
    $script:downloadMetadataState=@{Calls=0;Parses=0}
    $downloadPolicyFailure=Reject-DownloadFixture {Download 'https://github.com/hufrea/byedpi/releases/download/fixture/component.zip' ('a'*64) 'not-created-by-policy-refusal.bin'}
    Assert-DownloadFixture ($downloadPolicyFailure.Message -ceq 'Administrator policy disables remote component and release requests') 'Download permission refusal was replaced by a different admission failure'
    Assert-DownloadFixture ($script:downloadMetadataState.Calls -eq 0 -and $script:downloadMetadataState.Parses -eq 0) 'Download policy denial reached transport'
}

Write-Output 'STAGE-METADATA-PASS'
# Redirect policy is evaluated with synthetic URI strings only.
foreach($redirectCase in @(
    @{origin='https://github.com/hufrea/byedpi/releases/download/v1/a.zip';location='https://release-assets.githubusercontent.com/fixture';accept=$true},
    @{origin='https://discord.com/api/downloads/fixture';location='https://stable.dl2.discordapp.net/fixture';accept=$true},
    @{origin='https://aka.ms/fixture';location='https://download.visualstudio.microsoft.com/fixture';accept=$true},
    @{origin='https://api.github.com/repos/fixture';location='/repositories/123/releases';accept=$true},
    @{origin='https://github.com/hufrea/byedpi/releases/download/v1/a.zip';location='https://127.0.0.1/private';accept=$false},
    @{origin='https://github.com/hufrea/byedpi/releases/download/v1/a.zip';location='https://release-assets.githubusercontent.com.example.invalid/a';accept=$false},
    @{origin='https://github.com/hufrea/byedpi/releases/download/v1/a.zip';location='https://user@release-assets.githubusercontent.com/a';accept=$false},
    @{origin='https://github.com/hufrea/byedpi/releases/download/v1/a.zip';location='https://release-assets.githubusercontent.com:444/a';accept=$false},
    @{origin='https://github.com/hufrea/byedpi/releases/download/v1/a.zip';location='http://release-assets.githubusercontent.com/a';accept=$false},
    @{origin='https://discord.com/api/downloads/fixture';location='https://download.visualstudio.microsoft.com/a';accept=$false}
)){
    $redirectAccepted=$true;try{$null=Resolve-ComponentDownloadRedirect $redirectCase.origin $redirectCase.origin $redirectCase.location}catch{$redirectAccepted=$false}
    Assert-DownloadFixture ($redirectAccepted -eq $redirectCase.accept) 'Origin-specific redirect policy accepted or rejected an unexpected target'
}
& {
    function Allowed-Download([string]$url){& $script:downloadOriginalAllowed $url}
    $origin='https://github.com/hufrea/byedpi/releases/download/v1/a.zip'
    $failure=Reject-DownloadFixture {Resolve-ComponentDownloadRedirect $origin $origin 'https://github.com/unrelated/project/releases/download/v1/a.zip'}
    Assert-DownloadFixture (Test-ComponentDownloadTerminal $failure) 'Redirect to an unapproved GitHub release must be terminal'
    $failure=Reject-DownloadFixture {Allowed-Download 'https://github.com:444/hufrea/byedpi/releases/download/v1/a.zip'}
    Assert-DownloadFixture ($null -ne $failure) 'Initial component URL must not use a nonstandard port'
}
Write-Output 'STAGE-REDIRECT-POLICY-PASS'
# The real .NET redirect loop uses inert WebResponse objects and a fake factory.
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
namespace AccessWeaverDownloadFixture {
 public sealed class HopResponse : WebResponse {
  public int StatusCode; private WebHeaderCollection headers = new WebHeaderCollection();
  public override WebHeaderCollection Headers { get { return headers; } }
  public bool Closed; public byte[] Bytes;
  public HopResponse(int status,string location,byte[] bytes) { StatusCode=status;Bytes=bytes;if(location!=null)Headers["Location"]=location; }
  public override long ContentLength { get { return Bytes.Length; } set { throw new NotSupportedException(); } }
  public override Stream GetResponseStream() { return new MemoryStream(Bytes,false); }
  public override void Close() { Closed=true;base.Close(); }
 }
 public sealed class HopRequest {
  public string Method; public bool AllowAutoRedirect; public int Timeout,ReadWriteTimeout; public HopResponse Response;
  public HopRequest(HopResponse response) { Response=response; }
  public Task<WebResponse> GetResponseAsync() { return Task.FromResult<WebResponse>(Response); }
  public void Abort() { }
 }
}
"@
& {
    function New-ComponentDownloadRequest([uri]$Uri) {$script:dotNetHopCalls++;return $script:dotNetHopQueue.Dequeue()}
    $origin='https://github.com/hufrea/byedpi/releases/download/fixture/component.zip'
    $script:dotNetHopCalls=0;$script:dotNetHopQueue=[Collections.Generic.Queue[object]]::new()
    $first=[AccessWeaverDownloadFixture.HopResponse]::new(302,'https://release-assets.githubusercontent.com/fixture',[byte[]]@())
    $second=[AccessWeaverDownloadFixture.HopResponse]::new(200,$null,(New-DownloadFixtureBytes 32))
    $script:dotNetHopQueue.Enqueue([AccessWeaverDownloadFixture.HopRequest]::new($first));$script:dotNetHopQueue.Enqueue([AccessWeaverDownloadFixture.HopRequest]::new($second))
    $budget=& $script:downloadOriginalBudget -MaximumBytes 64 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
    try {
        & $script:downloadOriginalDotNet $origin $out $budget
        Assert-DownloadFixture ($script:dotNetHopCalls -eq 2 -and $first.Closed -and $second.Closed -and $budget.Written -eq 32 -and $out.Length -eq 32) 'Allowed .NET redirect must retain its budget and close both responses'
    } finally {$out.Dispose()}
    $script:dotNetHopCalls=0;$script:dotNetHopQueue=[Collections.Generic.Queue[object]]::new()
    $blocked=[AccessWeaverDownloadFixture.HopResponse]::new(302,'https://127.0.0.1/private',[byte[]]@());$script:dotNetHopQueue.Enqueue([AccessWeaverDownloadFixture.HopRequest]::new($blocked))
    $budget=& $script:downloadOriginalBudget -MaximumBytes 64 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
    try {
        $failure=Reject-DownloadFixture {& $script:downloadOriginalDotNet $origin $out $budget}
        Assert-DownloadFixture ((Test-ComponentDownloadTerminal $failure) -and $script:dotNetHopCalls -eq 1 -and $blocked.Closed -and $out.Length -eq 0) 'Disallowed .NET redirect must not open another request'
    } finally {$out.Dispose()}
    $script:dotNetHopCalls=0;$script:dotNetHopQueue=[Collections.Generic.Queue[object]]::new();$loopResponses=@()
    for($i=0;$i -lt 6;$i++){
        $response=[AccessWeaverDownloadFixture.HopResponse]::new(302,'https://release-assets.githubusercontent.com/fixture',[byte[]]@());$loopResponses+=@($response);$script:dotNetHopQueue.Enqueue([AccessWeaverDownloadFixture.HopRequest]::new($response))
    }
    $budget=& $script:downloadOriginalBudget -MaximumBytes 64 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
    try {
        $failure=Reject-DownloadFixture {& $script:downloadOriginalDotNet $origin $out $budget}
        Assert-DownloadFixture ((Test-ComponentDownloadTerminal $failure) -and $script:dotNetHopCalls -eq 6 -and @($loopResponses | Where-Object {-not $_.Closed}).Count -eq 0) 'The .NET redirect limit must close every response'
    } finally {$out.Dispose()}
}
Write-Output 'STAGE-DOTNET-HOPS-PASS'
# Only the actual reusable StartInfo builder runs. Test-Path is scoped to this
# pure construction block; no curl image is opened, executed or downloaded.
& {
    $downloadExpectedCurl=Join-Path $env:SystemRoot 'System32\curl.exe'
    function Test-Path {param([string]$LiteralPath) if($LiteralPath -cne $downloadExpectedCurl){throw 'Curl builder checked an unexpected executable path'};return $true}
    $downloadOldCulture=[Threading.Thread]::CurrentThread.CurrentCulture
    try{
        [Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('fr-FR')
        foreach($downloadProxy in @($false,$true)){
            $downloadBudget=New-ComponentDownloadBudget -MaximumBytes 32 -TimeoutMilliseconds 5000
            $downloadStart=New-ComponentDownloadCurlStart 'https://github.com/hufrea/byedpi/releases/download/fixture/file.zip' $downloadBudget -Proxy:$downloadProxy
            Assert-DownloadFixture ($downloadStart.FileName -ceq $downloadExpectedCurl -and $downloadStart.WorkingDirectory -ceq (Split-Path -Parent $downloadExpectedCurl)) 'Curl executable was not bound to the system directory'
            Assert-DownloadFixture ($downloadStart.Arguments -cmatch '^--disable --globoff ' -and $downloadStart.Arguments -cmatch '--output -(?: |$)' -and $downloadStart.Arguments -cmatch '--proto =https' -and $downloadStart.Arguments -cmatch '--write-out' -and $downloadStart.Arguments -cnotmatch '--location') 'Curl must stream one HTTPS hop with fixed status metadata'
            Assert-DownloadFixture ($downloadStart.Arguments -cmatch '--max-time [0-9]+\.[0-9]{3}(?: |$)' -and $downloadStart.Arguments -cnotmatch '--max-time [^ ]*,') 'Curl deadline formatting depends on host culture'
            Assert-DownloadFixture ((($downloadStart.Arguments -cmatch '--socks5-hostname 127\.0\.0\.1:1080(?: |$)') -eq $downloadProxy)) 'Curl unexpectedly admitted or dropped the explicit repair proxy'
            Assert-DownloadFixture (-not $downloadStart.UseShellExecute -and $downloadStart.CreateNoWindow -and $downloadStart.RedirectStandardInput -and $downloadStart.RedirectStandardOutput -and $downloadStart.RedirectStandardError) 'Curl process redirection no longer supports bounded binary transfer'
        }
    }finally{[Threading.Thread]::CurrentThread.CurrentCulture=$downloadOldCulture}
}

# This fake has no operating-system process identity. The actual curl runner
# executes against its instance methods; only the private physical factory is
# replaced. Failures model Wait observation, not a native Windows fault.
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
namespace AccessWeaverDownloadFixture {
 public sealed class ReadPipe : MemoryStream {
  public bool Closed;
  public List<Task> Reads=new List<Task>();
  public ReadPipe(byte[] data) : base(data,false) { }
  public override Task<int> ReadAsync(byte[] b,int offset,int count,CancellationToken cancellation) {
   Task<int> task=Task.FromResult(base.Read(b,offset,count));Reads.Add(task);return task;
  }
  protected override void Dispose(bool disposing) { Closed=true;base.Dispose(disposing); }
  public bool Completed() { foreach(Task read in Reads) if(!read.IsCompleted) return false;return true; }
 }
 public sealed class Reader {
  public ReadPipe BaseStream;
  public Reader(byte[] data) { BaseStream=new ReadPipe(data); }
 }
 public sealed class InputPipe {
  public bool Closed;
  public void Close() { Closed=true; }
 }
 public sealed class Process {
  public ProcessStartInfo StartInfo;
  public InputPipe StandardInput=new InputPipe();
  public Reader StandardOutput;
  public Reader StandardError;
  public IntPtr Handle=new IntPtr(321);
  public bool HasExited=true;
  public int ExitCode=0;
  public int Starts,Waits,Kills,Disposals,FailedWaits,ConfirmedWaits;
  public int FailFrom=1,FailCount;
  public bool DisposedDuringFailure,UnjoinedFinalWait,DisposedBeforeConfirmation;
  public List<string> Order=new List<string>();
  public Process(byte[] output) : this(output,System.Text.Encoding.UTF8.GetBytes("AWC1 200\n\n")) { }
  public Process(byte[] output, byte[] metadata) { StandardOutput=new Reader(output);StandardError=new Reader(metadata); }
  public bool Start() { Starts++;Order.Add("start");return true; }
  public void WaitForExit() {
   Waits++;Order.Add("wait");
   if(Waits>1 && (!StandardOutput.BaseStream.Closed || !StandardError.BaseStream.Closed || !StandardOutput.BaseStream.Completed() || !StandardError.BaseStream.Completed())) UnjoinedFinalWait=true;
   if(Waits>=FailFrom && Waits<FailFrom+FailCount) {
    FailedWaits++;DisposedDuringFailure=DisposedDuringFailure || Disposals!=0;
    throw new IOException("synthetic process wait observation failure");
   }
   ConfirmedWaits++;
  }
  public void Kill() { Kills++;HasExited=true;Order.Add("kill"); }
  public void Dispose() {
   Disposals++;Order.Add("dispose");
   if(ConfirmedWaits==0 || !StandardOutput.BaseStream.Completed() || !StandardError.BaseStream.Completed()) DisposedBeforeConfirmation=true;
  }
 }
}
"@
& {
    $downloadExpectedCurl=Join-Path $env:SystemRoot 'System32\curl.exe'
    function Test-Path {param([string]$LiteralPath) if($LiteralPath -cne $downloadExpectedCurl){throw 'Virtual curl runner checked an unexpected executable path'};return $true}
    function New-ComponentDownloadCurlProcess([Diagnostics.ProcessStartInfo]$StartInfo){
        $script:downloadCurlFactoryCalls++
        $script:downloadCurlProcess.StartInfo=$StartInfo
        return $script:downloadCurlProcess
    }
    foreach($downloadWaitCase in @(
        @{from=1;failures=0;waits=2},
        @{from=1;failures=1;waits=2},
        @{from=1;failures=2;waits=3},
        @{from=2;failures=2;waits=4}
    )){
        $script:downloadCurlFactoryCalls=0
        $script:downloadCurlProcess=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 32))
        $script:downloadCurlProcess.FailFrom=$downloadWaitCase.from
        $script:downloadCurlProcess.FailCount=$downloadWaitCase.failures
        $downloadBudget=& $script:downloadOriginalBudget -MaximumBytes 32 -TimeoutMilliseconds 2000
        $downloadOutput=[AccessWeaverDownloadFixture.Output]::new()
        try{
            if($downloadWaitCase.failures -eq 0){& $script:downloadOriginalCurl 'https://github.com/hufrea/byedpi/releases/download/fixture/component.zip' $downloadOutput $downloadBudget}
            else{
                $downloadFailure=Reject-DownloadFixture {& $script:downloadOriginalCurl 'https://github.com/hufrea/byedpi/releases/download/fixture/component.zip' $downloadOutput $downloadBudget}
                Assert-DownloadFixture ((Test-ComponentDownloadTerminal $downloadFailure) -and $downloadFailure.Message -ceq 'Component download cleanup encountered a failure') 'Reconciled Wait failure was erased or exposed private native detail'
            }
            Assert-DownloadFixture ($script:downloadCurlFactoryCalls -eq 1 -and $script:downloadCurlProcess.Starts -eq 1 -and $script:downloadCurlProcess.Waits -eq $downloadWaitCase.waits -and $script:downloadCurlProcess.FailedWaits -eq $downloadWaitCase.failures) 'Curl Wait retry changed process generation or repeated its launch'
            Assert-DownloadFixture ($script:downloadCurlProcess.Kills -eq 0 -and $script:downloadCurlProcess.Disposals -eq 1 -and -not $script:downloadCurlProcess.DisposedDuringFailure -and -not $script:downloadCurlProcess.DisposedBeforeConfirmation) 'Unconfirmed curl observation released its process owner or retried a signal'
            Assert-DownloadFixture (-not $script:downloadCurlProcess.UnjoinedFinalWait -and $script:downloadCurlProcess.StandardInput.Closed -and $script:downloadCurlProcess.StandardOutput.BaseStream.Closed -and $script:downloadCurlProcess.StandardError.BaseStream.Closed) 'Curl final Wait did not retain and join its redirected pipes'
            Assert-DownloadFixture ($script:downloadCurlProcess.Order[$script:downloadCurlProcess.Order.Count-1] -ceq 'dispose' -and $downloadOutput.AttemptedBytes -eq 32 -and $downloadBudget.Written -eq 32) 'Curl disposed before final observation or changed binary stdout bytes'
        }finally{$downloadOutput.Dispose()}
    }
    # One full real Download/SaveAttempt composition proves that reconciled
    # observation failure deletes the owned partial and prevents promotion.
    $downloadCurlRoot=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-curl-source-'+[guid]::NewGuid().ToString('N'))
    if([IO.Directory]::Exists($downloadCurlRoot)){throw 'Fresh virtual curl fixture path already exists'}
    $downloadCurlRootItem=[IO.Directory]::CreateDirectory($downloadCurlRoot)
    $downloadCurlRootCreated=$downloadCurlRootItem.CreationTimeUtc.Ticks
    $downloadCurlStage=[IO.Directory]::CreateDirectory((Join-Path $downloadCurlRoot 'downloads'))
    $script:root=$downloadCurlRoot
    $script:inputData=@{managedPolicy=$false;allowDownloads=$true}
    $script:downloadFixtureState=@{Mode='virtual-curl-wait';Approvals=0;Allowed=0;Promotions=0;Events=0}
    $script:repairProxyReady=$true
    $script:downloadCurlFactoryCalls=0
    $script:downloadCurlProcess=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 32))
    $script:downloadCurlProcess.FailCount=2
    Set-Item -LiteralPath Function:script:New-ComponentDownloadCurlProcess -Value (Get-Command New-ComponentDownloadCurlProcess).ScriptBlock
    Set-Item -LiteralPath Function:script:Invoke-ComponentDownloadCurl -Value $script:downloadOriginalCurl
    try{
        $downloadCurlDestination=Join-Path $root 'unpublished.bin'
        $downloadFailure=Reject-DownloadFixture {Download 'https://github.com/hufrea/byedpi/releases/download/fixture/component.zip' (Get-DownloadFixtureHash (New-DownloadFixtureBytes 32)) $downloadCurlDestination}
        Assert-DownloadFixture ((Test-ComponentDownloadTerminal $downloadFailure) -and $downloadFailure.Message -ceq 'Component download cleanup encountered a failure') 'Download lost the reconciled curl ownership failure'
        Assert-DownloadFixture ($script:downloadCurlFactoryCalls -eq 1 -and $script:downloadCurlProcess.Disposals -eq 1 -and $script:downloadCurlProcess.ConfirmedWaits -eq 1 -and -not $script:downloadCurlProcess.DisposedDuringFailure -and -not $script:downloadCurlProcess.UnjoinedFinalWait) 'Download returned before its same-object curl Wait reconciled'
        Assert-DownloadFixture ($script:downloadFixtureState.Promotions -eq 0 -and $script:downloadFixtureState.Events -eq 0 -and -not [IO.File]::Exists($downloadCurlDestination) -and [IO.Directory]::GetFileSystemEntries($downloadCurlStage.FullName).Length -eq 0) 'Reconciled curl Wait failure promoted bytes or retained a failed partial'
    }finally{
        $script:downloadFixtureState=$null
        $downloadCurlFresh=Get-Item -LiteralPath $downloadCurlRoot -Force
        if($downloadCurlFresh.CreationTimeUtc.Ticks -ne $downloadCurlRootCreated -or ($downloadCurlFresh.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed virtual curl fixture root was preserved'}
        [IO.Directory]::Delete($downloadCurlStage.FullName,$false)
        [IO.Directory]::Delete($downloadCurlRoot,$false)
    }
}
Write-Output 'STAGE-CURL-OWNER-PASS'
# Real hop orchestration against in-memory fake processes: no network or curl.
& {
    $downloadExpectedCurl=Join-Path $env:SystemRoot 'System32\curl.exe'
    function Test-Path {param([string]$LiteralPath) if($LiteralPath -cne $downloadExpectedCurl){throw 'Virtual curl checked an unexpected executable path'};return $true}
    function New-ComponentDownloadCurlProcess([Diagnostics.ProcessStartInfo]$StartInfo){
        $script:redirectFactoryCalls++;$p=$script:redirectQueue.Dequeue();$p.StartInfo=$StartInfo;return $p
    }
    $origin='https://github.com/hufrea/byedpi/releases/download/fixture/component.zip'
    $script:redirectFactoryCalls=0;$script:redirectQueue=[Collections.Generic.Queue[object]]::new()
    $first=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 4),[Text.Encoding]::UTF8.GetBytes("AWC1 302`nhttps://release-assets.githubusercontent.com/fixture`n"))
    $second=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 32))
    $script:redirectQueue.Enqueue($first);$script:redirectQueue.Enqueue($second)
    $budget=& $script:downloadOriginalBudget -MaximumBytes 64 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
    try {
        & $script:downloadOriginalCurl $origin $out $budget
        Assert-DownloadFixture ($script:redirectFactoryCalls -eq 2 -and $budget.Written -eq 36 -and $out.Length -eq 32) 'Allowed redirects must keep a cumulative budget and replace intermediate bodies'
        Assert-DownloadFixture ((Get-DownloadFixtureHash ($out.ToArray())) -ceq (Get-DownloadFixtureHash (New-DownloadFixtureBytes 32)) -and $first.Disposals -eq 1 -and $second.Disposals -eq 1) 'Redirect transfer changed final bytes or lost a process owner'
    } finally {$out.Dispose()}
    $script:redirectFactoryCalls=0;$script:redirectQueue=[Collections.Generic.Queue[object]]::new()
    $blocked=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 4),[Text.Encoding]::UTF8.GetBytes("AWC1 302`nhttps://127.0.0.1/private`n"));$script:redirectQueue.Enqueue($blocked)
    $budget=& $script:downloadOriginalBudget -MaximumBytes 64 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
    try {
        $failure=Reject-DownloadFixture {& $script:downloadOriginalCurl $origin $out $budget}
        Assert-DownloadFixture ((Test-ComponentDownloadTerminal $failure) -and $script:redirectFactoryCalls -eq 1 -and $blocked.Disposals -eq 1) 'Disallowed redirect reached another process or lost its owner'
    } finally {$out.Dispose()}
    $script:redirectFactoryCalls=0;$script:redirectQueue=[Collections.Generic.Queue[object]]::new();$loopProcesses=@()
    for($i=0;$i -lt 6;$i++){
        $p=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 1),[Text.Encoding]::UTF8.GetBytes("AWC1 302`nhttps://release-assets.githubusercontent.com/fixture`n"));$script:redirectQueue.Enqueue($p);$loopProcesses+=@($p)
    }
    $budget=& $script:downloadOriginalBudget -MaximumBytes 64 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
    try {
        $failure=Reject-DownloadFixture {& $script:downloadOriginalCurl $origin $out $budget}
        Assert-DownloadFixture ((Test-ComponentDownloadTerminal $failure) -and $script:redirectFactoryCalls -eq 6 -and @($loopProcesses | Where-Object {$_.Disposals -ne 1}).Count -eq 0) 'Redirect limit must retain and dispose every owned process'
    } finally {$out.Dispose()}
    $script:redirectFactoryCalls=0;$script:redirectQueue=[Collections.Generic.Queue[object]]::new()
    $first=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 4),[Text.Encoding]::UTF8.GetBytes("AWC1 302`nhttps://release-assets.githubusercontent.com/fixture`n"));$second=[AccessWeaverDownloadFixture.Process]::new((New-DownloadFixtureBytes 32));$script:redirectQueue.Enqueue($first);$script:redirectQueue.Enqueue($second)
    $budget=& $script:downloadOriginalBudget -MaximumBytes 35 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
    try {
        $failure=Reject-DownloadFixture {& $script:downloadOriginalCurl $origin $out $budget}
        Assert-DownloadFixture ((Test-ComponentDownloadTerminal $failure) -and $script:redirectFactoryCalls -eq 2 -and $budget.Written -eq 4 -and $first.Disposals -eq 1 -and $second.Disposals -eq 1) 'Redirect bodies must count toward the shared byte budget'
    } finally {$out.Dispose()}
    foreach($metadata in @("AWC1 302`n`n","AWC1 200`nhttps://example.invalid/private`n",'PRIVATE_FIXTURE',('X'*16385))){
        $script:redirectFactoryCalls=0;$script:redirectQueue=[Collections.Generic.Queue[object]]::new()
        $fake=[AccessWeaverDownloadFixture.Process]::new([byte[]]@(),[Text.Encoding]::UTF8.GetBytes($metadata));$script:redirectQueue.Enqueue($fake)
        $budget=& $script:downloadOriginalBudget -MaximumBytes 64 -TimeoutMilliseconds 2000;$out=[AccessWeaverDownloadFixture.Output]::new()
        try {
            $failure=Reject-DownloadFixture {& $script:downloadOriginalCurl $origin $out $budget}
            Assert-DownloadFixture ((Test-ComponentDownloadTerminal $failure) -and $script:redirectFactoryCalls -eq 1 -and $fake.Disposals -eq 1 -and $failure.Message -cnotmatch 'PRIVATE_FIXTURE') 'Invalid curl status metadata must fail privately and retain the process owner'
        } finally {$out.Dispose()}
    }
}
Write-Output 'STAGE-CURL-HOPS-PASS'
# This constructs a managed request object only. No request is sent, no DNS or
# proxy method runs, and no response or network stream is obtained. Unlike the
# metadata transport spy, this exercises the actual restricted-header mapper.
foreach($downloadHeaderCase in @(
    @{'User-Agent'='AccessWeaver-source-fixture';Accept='application/json';'X-Fixture'='bounded-source'},
    @{'uSeR-aGeNt'='AccessWeaver-source-fixture';aCcEpT='application/json';'X-Fixture'='bounded-source'}
)){
    $downloadRequest=[Net.HttpWebRequest]::CreateHttp('https://example.invalid/accessweaver-source-header-test')
    Set-ComponentDownloadHeaders $downloadRequest $downloadHeaderCase
    Assert-DownloadFixture ($downloadRequest.UserAgent -ceq 'AccessWeaver-source-fixture') 'Restricted User-Agent header was not assigned through the request property'
    Assert-DownloadFixture ($downloadRequest.Accept -ceq 'application/json') 'Restricted Accept header was not assigned through the request property'
    Assert-DownloadFixture ($downloadRequest.Headers['X-Fixture'] -ceq 'bounded-source') 'Unrestricted request header was not preserved'
}
Write-Output ('PASS component download source contracts ('+$script:downloadFixtureChecks+' checks; native transport not executed)')
