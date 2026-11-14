param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::WriteLine('Workflow phase: initialize')
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-initialize {0}' -f $script:workflowClock.ElapsedMilliseconds))}
# Import required JSON and OS cmdlets from this stock shell's module directory.
# Avoid command discovery across unrelated modules on each fresh workflow process.
Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-utility-ready {0}' -f $script:workflowClock.ElapsedMilliseconds))}
Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')) -ErrorAction Stop
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-management-ready {0}' -f $script:workflowClock.ElapsedMilliseconds))}
$inputData = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
$r = $inputData.request
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-request-decoded {0}' -f $script:workflowClock.ElapsedMilliseconds))}
# Local inventory and folder selection have no HTTP requests to configure.
if($r.action -notin @('discover','choose-folder')){[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-network-ready {0}' -f $script:workflowClock.ElapsedMilliseconds))}
$script:root = Join-Path $env:ProgramData 'AccessWeaver'
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-root-ready {0}' -f $script:workflowClock.ElapsedMilliseconds))}
$script:undo = [Collections.Generic.List[object]]::new()
$script:events = [Collections.Generic.List[string]]::new()
$script:journalPath = $null
$script:rebootRequired = $false
$script:dnsConfigured = $false
$script:mutex = $null
$script:ownsMutex = $false
$script:journalState = 'running'
$script:pendingUninstaller = $null
$script:externalEffectsPending = $false
$script:repairProxyReady = $false
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-state-ready {0}' -f $script:workflowClock.ElapsedMilliseconds))}

function Event([string]$text) { $script:events.Add(([DateTime]::UtcNow.ToString('o')+' '+$text)); [Console]::WriteLine($text); Save-Journal }
function Save-Journal {
    if($script:journalPath){
        $text=@{action=$r.action;engine=$r.engine;state=$script:journalState;externalEffectsPending=[bool]$script:externalEffectsPending;undo=@($script:undo.ToArray());events=@($script:events.ToArray())} | ConvertTo-Json -Depth 12
        Publish-WorkflowFile $script:journalPath ([Text.UTF8Encoding]::new($false).GetBytes($text))
    }
}
function Under([string]$path,[string]$parent) { $p=[IO.Path]::GetFullPath($path);$b=[IO.Path]::GetFullPath($parent).TrimEnd('\')+'\';return $p.StartsWith($b,[StringComparison]::OrdinalIgnoreCase) }
function No-Reparse([string]$path) {
    $current=[IO.Path]::GetFullPath($path)
    while ($current) { if ((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse points are not supported in installation paths' };$next=Split-Path -Parent $current;if ($next -eq $current) {break};$current=$next }
}
function Require-Admin {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use a separately elevated system apply CLI for machine changes. Keep the dashboard and user application operations unelevated.' }
}
function Require-DesktopUser {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if($identity.IsSystem -or ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'Application operations require the signed-in desktop user without administrator rights'}
}
function Enter-ApplicationWorkflow {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$user=$identity.User} finally {$identity.Dispose()}
    $security=[Security.AccessControl.MutexSecurity]::new()
    $security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new($user,'FullControl','Allow'))
    $name='Global\AccessWeaver-DesktopApplications-'+$user.Value
    $created=$false
    try {
        if($PSVersionTable.PSEdition -ceq 'Desktop'){
            $owner=[Threading.Mutex]::new($true,$name,[ref]$created,$security)
        }else{
            $owner=[Threading.MutexAcl]::Create($true,$name,[ref]$created,$security)
        }
    } catch {
        throw 'AccessWeaver could not verify application workflow ownership for this Windows user'
    }
    if(-not $created){
        $owner.Dispose()
        throw 'An AccessWeaver application workflow is already active for this Windows user'
    }
    $script:mutex=$owner
    $script:ownsMutex=$true
}
function Initialize-Operation {
    # Check before machine-storage initialization, DNS changes, discovery or
    # process execution. A combined repair cannot cross this boundary safely.
    if($r.action -eq 'app-repair'){throw 'Combined Discord repair is unavailable until a privilege-separated broker is implemented'}
    if($r.action -in @('app-install','app-remove','app-start','app-reinstall')){
        Require-DesktopUser
        if($r.dns -and $r.dns -ne 'unchanged'){throw 'Configure system DNS separately from user application operations'}
        Enter-ApplicationWorkflow
        $script:root=Join-Path (Split-Path -Parent $inputData.resultPath) 'application'
        $directories=if($r.action -eq 'app-start'){@('logs')}else{@('downloads','backups','logs')}
        foreach($dir in $directories){
            $path=Join-Path $root $dir
            No-Reparse $path
            [void](New-Item -ItemType Directory -Force -Path $path)
        }
        $script:journalPath=Join-Path $root 'logs\application.json'
        Save-Journal
    }elseif($r.action -notin @('discover','updates','choose-folder')){Initialize-Changes}
}
function Quote-Arg([string]$text) { return '"'+[regex]::Replace([regex]::Replace($text,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"' }
function Native-Argument([string]$text) {
    # Some vendor CLIs parse the raw command line instead of the decoded argv.
    # Keep simple verbs/switches bare; complex values retain literal escaping.
    if($text -cmatch '\A[A-Za-z0-9_./:=\\-]+\z'){return $text}
    return (Quote-Arg $text)
}
function New-ToolCapture([IO.StreamReader]$reader) {
    $buffer=[char[]]::new(4096)
    return @{reader=$reader;buffer=$buffer;text=[Text.StringBuilder]::new();done=$false;task=$reader.ReadAsync($buffer,0,$buffer.Length)}
}
function Receive-ToolCapture($capture) {
    # Service both pipes fairly. Completed reads never retain more than four
    # million UTF-16 characters per pipe; overflow fails rather than truncates.
    for($reads=0;$reads -lt 64 -and -not $capture.done -and $capture.task.IsCompleted;$reads++) {
        $count=$capture.task.GetAwaiter().GetResult()
        if($count -eq 0){$capture.done=$true;break}
        if($capture.text.Length+$count -gt 4MB){throw 'Tool output exceeded the 4 Mi-character per-stream capture limit; inspect the recovery journal'}
        [void]$capture.text.Append($capture.buffer,0,$count)
        $capture.task=$capture.reader.ReadAsync($capture.buffer,0,$capture.buffer.Length)
    }
}
function Wait-ToolCapture($stdout,$stderr) {
    $pending=[Threading.Tasks.Task[]]@(@($stdout,$stderr)|Where-Object {-not $_.done}|ForEach-Object {$_.task})
    if($pending.Length){[void][Threading.Tasks.Task]::WaitAny($pending,10)}else{Start-Sleep -Milliseconds 10}
}
# The cleanup utility needs its own deadline: the original tool's timeout has
# already expired when this path runs. Always retain the owned parent for fallback.
function Stop-ToolTreeWithHelper([Diagnostics.Process]$process,[Diagnostics.Process]$helper,[ValidateRange(1,5000)][int]$TimeoutMilliseconds=5000) {
    $started=$false;$failure=$null
    try {
        [void]$helper.Start();$started=$true;$helper.StandardInput.Close()
        $stdout=New-ToolCapture $helper.StandardOutput;$stderr=New-ToolCapture $helper.StandardError
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while(-not $helper.HasExited){
            Receive-ToolCapture $stdout;Receive-ToolCapture $stderr
            if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw 'Termination helper exceeded its cleanup deadline'}
            Wait-ToolCapture $stdout $stderr
        }
        if($helper.ExitCode -ne 0){throw 'Termination helper returned a failure exit code'}
    } catch {$failure=$_.Exception.Message}
    finally {
        try {
            if($started -and -not $helper.HasExited){
                $helper.Kill()
                if(-not $helper.WaitForExit(1000)){$failure='Termination helper could not be stopped'}
            }
        } catch {$failure='Termination helper cleanup could not be confirmed'}
        # Kill only the process object we started. Stopping the parent is still
        # required when tree cleanup fails, but cannot confirm descendant cleanup.
        try {
            if(-not $process.HasExited){$process.Kill()}
            if(-not $process.WaitForExit(2000)){$failure='Owned tool process could not be stopped'}
        } catch {$failure='Owned tool process cleanup could not be confirmed'}
    }
    if($failure){throw ('Tool process tree cleanup is unconfirmed: '+$failure+'; inspect the recovery journal')}
}
function Stop-ToolTree([Diagnostics.Process]$process) {
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=[IO.Path]::Combine($env:SystemRoot,'System32\taskkill.exe')
    $start.Arguments='/PID '+$process.Id+' /T /F'
    $start.WorkingDirectory=[IO.Path]::GetDirectoryName($start.FileName)
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $helper=[Diagnostics.Process]::new();$helper.StartInfo=$start
    try {Stop-ToolTreeWithHelper $process $helper} finally {$helper.Dispose()}
}
function Run-Tool([string]$program,[string[]]$arguments=@(),[int[]]$codes=@(0),[switch]$Secret,[int]$Timeout=600,[string]$WorkingDirectory,[hashtable]$ChildEnvironment,[IO.FileStream]$StartGuard) {
    if($Timeout -lt 1 -or $Timeout -gt 86400){throw 'Tool timeout must be between 1 and 86400 seconds'}
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$program;$start.Arguments=(@($arguments | ForEach-Object {Native-Argument $_}) -join ' ')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
    $start.WorkingDirectory=Split-Path -Parent $program
    if (-not [IO.Path]::IsPathRooted($program)) {$start.WorkingDirectory=$root}
    if($WorkingDirectory){$start.WorkingDirectory=$WorkingDirectory}
    if($null -ne $ChildEnvironment){
        $start.EnvironmentVariables.Clear()
        foreach($name in $ChildEnvironment.Keys){
            $start.EnvironmentVariables[[string]$name]=[string]$ChildEnvironment[$name]
        }
    }
    $p=[Diagnostics.Process]::new();$p.StartInfo=$start;$started=$false
    # Fixed diagnostics only: never include the task output, arguments or path.
    $traceTask=([IO.Path]::GetFileName($program) -ieq 'schtasks.exe')
    $traceClock=[Diagnostics.Stopwatch]::StartNew()
    function Trace-TaskQueryStage([ValidateSet('start','started','capture-ready','exited','timed-out','drained','cleanup','tree-helper-returned','disposed')][string]$Phase) {
        if($traceTask){[Console]::WriteLine(('Task query timing ms: {0} {1}' -f $Phase,$traceClock.ElapsedMilliseconds))}
    }
    try {
        Trace-TaskQueryStage 'start'
        # A consumed vendor tool exit cannot certify every external side effect.
        if($r.action -notin @('discover','updates','choose-folder')){$script:externalEffectsPending=$true}
        try {
            if(-not $p.Start()){throw 'Tool process did not start'}
            $started=$true
        } finally {
            # Uninstallers may delete their own files. Protect the verified
            # executable through process creation, then release it.
            if($null -ne $StartGuard){$StartGuard.Dispose()}
        }
        $p.StandardInput.Close()
        Trace-TaskQueryStage 'started'
        $stdout=New-ToolCapture $p.StandardOutput;$stderr=New-ToolCapture $p.StandardError
        Trace-TaskQueryStage 'capture-ready'
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while($true){
            Receive-ToolCapture $stdout;Receive-ToolCapture $stderr
            if($p.HasExited){Trace-TaskQueryStage 'exited';break}
            if($clock.Elapsed.TotalSeconds -ge $Timeout){Trace-TaskQueryStage 'timed-out';throw ('Timed out: '+[IO.Path]::GetFileName($program))}
            Wait-ToolCapture $stdout $stderr
        }
        # GUI children can inherit output handles. Drain for at most two seconds
        # after the original tool exits, then report incomplete capture explicitly.
        $drain=[Diagnostics.Stopwatch]::StartNew()
        while(-not ($stdout.done -and $stderr.done) -and $drain.Elapsed.TotalSeconds -lt 2){
            Receive-ToolCapture $stdout;Receive-ToolCapture $stderr
            if(-not ($stdout.done -and $stderr.done)){Wait-ToolCapture $stdout $stderr}
        }
        Trace-TaskQueryStage 'drained'
        $out=$stdout.text.ToString();$errorText=$stderr.text.ToString()
        $complete=$stdout.done -and $stderr.done
        if (-not $Secret) {if ($out) {[Console]::WriteLine($out)};if($errorText){[Console]::WriteLine($errorText)}}
        if(-not $complete){[Console]::WriteLine('Tool exited with inherited output pipes still open; capture is incomplete')}
        if ($codes -notcontains $p.ExitCode) {throw ('Tool failed: '+[IO.Path]::GetFileName($program)+' (exit '+$p.ExitCode+')')}
        if ($p.ExitCode -eq 3010 -or $p.ExitCode -eq 1641) {$script:rebootRequired=$true}
        return @{stdout=$out;stderr=$errorText;exitCode=$p.ExitCode;outputComplete=$complete}
    } finally {
        try {
            Trace-TaskQueryStage 'cleanup'
            if($started -and -not $p.HasExited){
                Stop-ToolTree $p
                Trace-TaskQueryStage 'tree-helper-returned'
                if(-not $p.WaitForExit(2000)){throw ('Tool process '+$p.Id+' could not be stopped; inspect the recovery journal')}
            }
        } finally {$p.Dispose();Trace-TaskQueryStage 'disposed'}
    }
}
function Native([string]$program,[string[]]$arguments=@(),[int[]]$codes=@(0),[switch]$Secret,[int]$Timeout=600,[string]$WorkingDirectory,[hashtable]$ChildEnvironment,[IO.FileStream]$StartGuard) {
    # Keep native output separate from the returned record, even for multi-line tools.
    $all=@(Run-Tool $program $arguments $codes -Secret:$Secret -Timeout $Timeout -WorkingDirectory $WorkingDirectory -ChildEnvironment $ChildEnvironment -StartGuard $StartGuard)
    return $all[-1]
}
function Private-DirectorySecurity {
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) { $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow');[void]$acl.AddAccessRule($rule) }
    return $acl
}
function Trusted-SecurityDescriptor($acl) {
    $trusted=@('S-1-5-18','S-1-5-32-544')
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){return $false}
    # A null/empty DACL or a nonprivileged allow ACE is not private storage.
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if(-not $rules.Count){return $false}
    foreach($rule in $rules){if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted){return $false}}
    return $true
}
function Assert-TrustedItem([string]$path) {
    No-Reparse $path
    if(-not (Trusted-SecurityDescriptor (Get-Acl -LiteralPath $path))){throw ('Untrusted existing machine-storage ownership or permissions; retain the files for administrator review: '+$path)}
}
function Protect-Dir([string]$path) {
    No-Reparse $path
    if(-not (Test-Path -LiteralPath $path)){
        $acl=Private-DirectorySecurity
        # The .NET Framework overload creates with the descriptor, rather than
        # opening a public directory and tightening it afterward. A concurrent
        # preexisting object is still checked below before anything is used.
        if([IO.Directory].GetMethod('CreateDirectory',[type[]]@([string],[Security.AccessControl.DirectorySecurity]))){[void][IO.Directory]::CreateDirectory($path,$acl)}
        else{[void][IO.FileSystemAclExtensions]::CreateDirectory($acl,$path)}
    }
    if(-not (Get-Item -LiteralPath $path -Force).PSIsContainer){throw 'Machine storage must be a directory'}
    Assert-TrustedItem $path
}
function Assert-TrustedTree([string]$path) {
    $pending=[Collections.Generic.Stack[string]]::new();$pending.Push($path);$count=0
    while($pending.Count){
        $directory=$pending.Pop();Assert-TrustedItem $directory
        foreach($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop){
            if(++$count -gt 100000){throw 'Machine storage exceeds the validation limit; administrator retention review is required'}
            No-Reparse $item.FullName
            # Preserved user cache is inert recovery data, not trusted executable
            # storage. Keep its original user ownership for exact restoration.
            if($directory -eq (Join-Path $root 'backups') -and $item.PSIsContainer -and $item.Name -match '^discord-cache-[a-f0-9]{32}$'){continue}
            Assert-TrustedItem $item.FullName
            if($item.PSIsContainer){$pending.Push($item.FullName)}
        }
    }
}
function Initialize-Changes {
    Require-Admin
    $security=[Security.AccessControl.MutexSecurity]::new()
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){$security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))}
    $created=$false;$script:mutex=[Threading.Mutex]::new($false,'Global\AccessWeaver-SystemWorkflows',[ref]$created,$security)
    try{$script:ownsMutex=$script:mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$script:ownsMutex=$true}
    if(-not $script:ownsMutex){throw 'Another AccessWeaver system workflow is already running'}
    Protect-Dir $root
    Assert-TrustedTree $root
    foreach ($dir in @('components','services','logs','backups','profiles','downloads','temp')) {Protect-Dir (Join-Path $root $dir)}
    $env:TEMP=Join-Path $root 'temp';$env:TMP=$env:TEMP
    $script:journalPath=Join-Path $root ('logs\workflow-'+[guid]::NewGuid().ToString('N')+'.json');Save-Journal
}
function Get-WorkflowFileHash([string]$path) {
    No-Reparse $path
    try {$attributes=[IO.File]::GetAttributes($path)}
    catch [IO.FileNotFoundException] {return}
    catch [IO.DirectoryNotFoundException] {return}
    if($attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)){
        throw 'Workflow requires an ordinary file'
    }
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Copy-WorkflowFileToNewPath([string]$source,[string]$target,[string]$expectedHash) {
    No-Reparse $source
    No-Reparse $target
    $ownsTarget=$false
    try {
        $inputStream=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $output=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $ownsTarget=$true
            try {
                $inputStream.CopyTo($output)
                $output.Flush($true)
            } finally {$output.Dispose()}
        } finally {$inputStream.Dispose()}
        if((Get-WorkflowFileHash $target) -ine $expectedHash){
            throw 'Copied workflow file does not match the recorded digest'
        }
    } catch {
        if($ownsTarget){
            No-Reparse $target
            [IO.File]::Delete($target)
        }
        throw
    }
}
function Backup-File([string]$path) {
    $existing=$script:undo | Where-Object {$_.kind -eq 'file' -and $_.path -eq $path}
    if($existing){return $existing}
    $backup=$null;$originalHash=Get-WorkflowFileHash $path
    if($originalHash){
        $backup=Join-Path $root ('backups\'+[guid]::NewGuid().ToString('N'))
        Copy-WorkflowFileToNewPath $path $backup $originalHash
    }
    $entry=@{kind='file';path=$path;backup=$backup;originalHash=$originalHash}
    $script:undo.Add($entry)
    Save-Journal
    return $entry
}
function Publish-WorkflowFile([string]$path,[byte[]]$bytes,[switch]$Recorded,[string]$BeforeHash) {
    No-Reparse $path
    $parent=Split-Path -Parent $path
    $staged=Join-Path $parent ([guid]::NewGuid().ToString('N')+'.tmp')
    $stream=[IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        try {
            $stream.Write($bytes,0,$bytes.Length)
            $stream.Flush($true)
        } finally {$stream.Dispose()}
        $digest=Get-WorkflowBytesSHA256 $bytes
        if($Recorded){
            Publish-RecordedWorkflowFile $staged $path $digest
        }else{
            if(-not $PSBoundParameters.ContainsKey('BeforeHash')){$BeforeHash=Get-WorkflowFileHash $path}
            Publish-StagedWorkflowFile $staged $path $digest $BeforeHash
        }
    } finally {
        if([IO.File]::Exists($staged)){
            No-Reparse $staged
            [IO.File]::Delete($staged)
        }
    }
}
function Write-Atomic([string]$path,[string]$text) {
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($text)
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path))
    Publish-WorkflowFile $path $bytes -Recorded
}
function Get-WorkflowBytesSHA256([byte[]]$bytes) {
    $sha256=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace('-','')}
    finally {$sha256.Dispose()}
}
function Copy-Checked([string]$source,[string]$destination,[string]$expectedHash) {
    No-Reparse $source
    No-Reparse $destination
    $parent=Split-Path -Parent $destination
    [void](New-Item -ItemType Directory -Force -Path $parent)
    $staged=Join-Path $parent ('.accessweaver-copy-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $inputStream=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $ownsStage=$false
    try {
        if(-not $expectedHash){$expectedHash=(Get-FileHash -InputStream $inputStream -Algorithm SHA256).Hash}
        $stageFile=[IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $ownsStage=$true
        $stageFile.Dispose()
        # Windows file copy retains source streams, including Zone.Identifier.
        [IO.File]::Copy($source,$staged,$true)
        if((Get-WorkflowFileHash $staged) -ine $expectedHash){throw 'Copied component does not match the expected digest'}
        Publish-RecordedWorkflowFile $staged $destination $expectedHash
    } finally {
        try {$inputStream.Dispose()}
        finally {
            if($ownsStage -and (Test-Path -LiteralPath $staged -ErrorAction Stop)){
                No-Reparse $staged
                Remove-Item -LiteralPath $staged -Force -ErrorAction Stop
            }
        }
    }
}
function Copy-Tree([string]$source,[string]$destination,[switch]$Disposable) {
    No-Reparse $source
    foreach($item in Get-ChildItem -LiteralPath $source -Recurse -Force){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Component contains a reparse point'}
        if($item.PSIsContainer -and -not $Disposable){continue}
        $relative=$item.FullName.Substring($source.TrimEnd('\').Length).TrimStart('\')
        $target=Join-Path $destination $relative
        if(-not (Under $target $destination)){throw 'Invalid component path'}
        if($Disposable){
            if($item.PSIsContainer){
                [void][IO.Directory]::CreateDirectory($target)
            }else{
                No-Reparse $item.FullName
                [void][IO.Directory]::CreateDirectory((Split-Path -Parent $target))
                [IO.File]::Copy($item.FullName,$target,$false)
            }
        }else{
            Copy-Checked $item.FullName $target
        }
    }
}
function Require-DownloadPermission {
    if ($inputData.managedPolicy -and $inputData.allowDownloads -ne $true) {throw 'Administrator policy disables remote component and release requests'}
}
function Approved-DownloadHash([string]$url,[string]$hash) {
    Require-DownloadPermission
    if (-not $inputData.managedPolicy) {return $hash}
    $approved=@($inputData.downloads | Where-Object {[string]::Equals($_.url,$url,[StringComparison]::Ordinal)})
    if($approved.Count -ne 1 -or $approved[0].sha256 -notmatch '^[a-f0-9]{64}$'){throw 'Administrator policy does not pin this component URL and SHA-256'}
    if($hash -and $hash -ne $approved[0].sha256){throw 'Remote metadata SHA-256 conflicts with administrator policy'}
    return ([string]$approved[0].sha256).ToLowerInvariant()
}
function Read-RemoteJSON([string]$Uri,[hashtable]$Headers) {
    Require-DownloadPermission
    $memory=[IO.MemoryStream]::new()
    try {
        $budget=New-ComponentDownloadBudget -MaximumBytes 8MB -TimeoutMilliseconds 60000
        Invoke-ComponentDownloadDotNet $Uri $memory $budget $Headers
        [void](Get-ComponentDownloadRemaining $budget)
        try {
            $bytes=$memory.ToArray()
            try {$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)}finally {if($bytes){[Array]::Clear($bytes,0,$bytes.Length)}}
            if($text.Length -gt 0 -and $text[0] -eq [char]0xfeff){$text=$text.Substring(1)}
            # Validate the original single JSON value before wrapping: invalid
            # sibling text must never become valid envelope properties.
            ConvertFrom-Json -InputObject $text -ErrorAction Stop | Out-Null
            [void](Get-ComponentDownloadRemaining $budget)
            # A fixed envelope preserves [], one-item arrays and null on both
            # PS5.1 and PS7, whose pipeline enumeration otherwise differs.
            $envelope=ConvertFrom-Json -InputObject ('{"value":'+$text+'}')
        }catch {if(Test-ComponentDownloadTerminal $_){throw};Throw-ComponentDownloadFailure 'protocol'}
        [void](Get-ComponentDownloadRemaining $budget)
        return ,$envelope.value
    }finally {$memory.Dispose()}
}
function Test-AccessWeaverReleaseAssets($release,[string]$architecture) {
    $assets=$release.assets
    if($assets -isnot [array] -or $assets.Count -gt 100){return $false}
    $archive='accessweaver-'+$release.tag_name+'-windows-'+$architecture+'.zip'
    $required=@($archive,'BUILD-MANIFEST.json','SHA256SUMS.txt','BUILD-PROVENANCE.sigstore.json')
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($asset in $assets){
        if($asset.name -isnot [string] -or $asset.name -cnotin $required){continue}
        if(-not $seen.Add($asset.name) -or $asset.state -cne 'uploaded' -or
            $asset.digest -isnot [string] -or $asset.digest -cnotmatch '\Asha256:[0-9a-f]{64}\z'){
            return $false
        }
    }
    return $seen.Count -eq $required.Count
}
function Check-AccessWeaverUpdates {
    $architecture=[string]$inputData.nativeArchitecture
    if($architecture -cnotin @('amd64','arm64')){throw 'Native Windows architecture is unavailable or unsupported for release discovery'}
    $allReleases=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri 'https://api.github.com/repos/Yunushan/accessweaver/releases?per_page=30'
    if($allReleases -isnot [array] -or $allReleases.Count -gt 30){throw 'AccessWeaver release metadata did not contain a valid release list'}
    $releases=@($allReleases | Where-Object {
        $_.draft -is [bool] -and -not $_.draft -and $_.prerelease -is [bool] -and $_.tag_name -is [string] -and $_.tag_name.Length -le 256 -and
        $_.tag_name -cmatch '\Av?[0-9][0-9A-Za-z.+-]*\z' -and
        (-not $_.prerelease -or $_.tag_name -cmatch '^[^+]+-[^+]+') -and
        (Test-AccessWeaverReleaseAssets $_ $architecture)
    })
    if(-not $releases.Count){throw 'No published AccessWeaver releases include a Windows archive and verification files for this architecture'}
    $comparison=Native $inputData.controller (@('system','check-version','--follow-channel')+@($releases|ForEach-Object {$_.tag_name})) -Secret
    $invalidComparison='AccessWeaver release comparison returned an invalid result'
    if($comparison.outputComplete -ne $true -or $comparison.stdout -isnot [string] -or $comparison.stdout.Length -gt 4096){throw $invalidComparison}
    try {$check=ConvertFrom-Json -InputObject $comparison.stdout -ErrorAction Stop}catch{throw $invalidComparison}
    if($check -isnot [pscustomobject] -or $check.version -isnot [string] -or
        $check.currentVersion -isnot [string] -or -not $check.currentVersion -or $check.updateAvailable -isnot [bool]){
        throw $invalidComparison
    }
    if($check.version -ceq '' -and $check.updateAvailable -eq $false){
        return @{version='';currentVersion=$check.currentVersion;updateAvailable=$false;url=$null;publishedAt=$null}
    }
    $release=$releases|Where-Object {$_.tag_name -ceq $check.version}|Select-Object -First 1
    if(-not $release){throw 'Selected AccessWeaver release was not in the reviewed metadata'}
    $url='https://github.com/Yunushan/accessweaver/releases/tag/'+[uri]::EscapeDataString($check.version)
    @{version=$check.version;currentVersion=$check.currentVersion;updateAvailable=$check.updateAvailable;url=$url;publishedAt=$release.published_at}
}
function Allowed-Download([string]$url) {
    $uri=[uri]$url
    if ($uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort -or $uri.UserInfo -or $uri.Fragment) {throw 'Downloads must use an official HTTPS URL'}
    $repos=@('hufrea/byedpi','wiresock/proxifyre','wiresock/ndisapi','ViRb3/wgcf','bol-van/zapret-win-bundle','bol-van/zapret2','ValdikSS/GoodbyeDPI','DNSCrypt/dnscrypt-proxy','cagritaskn/SplitCord-Turkey','cagritaskn/SplitWire-Turkey','hdrover/discord-drover')
    if ($uri.Host -eq 'github.com') {foreach ($repo in $repos) {if ($uri.AbsolutePath.StartsWith('/'+$repo+'/releases/download/',[StringComparison]::OrdinalIgnoreCase)){return}}}
    if ($uri.Host -in @('www.wiresock.net','wiresock.net','discord.com','dl.discordapp.net','download.discordapp.net','aka.ms','download.visualstudio.microsoft.com')) {return}
    throw 'URL is not an allowlisted component download source'
}
# Check each redirect before opening it. This is an origin-specific host policy,
# not an IP-address, DNS-rebinding, certificate-pinning or proxy guarantee.
function Resolve-ComponentDownloadRedirect([string]$origin,[string]$current,[string]$location) {
    if([string]::IsNullOrWhiteSpace($location) -or $location.Length -gt 8192){Throw-ComponentDownloadFailure 'protocol'}
    try {$first=[uri]$origin;$base=[uri]$current;$next=[uri]::new($base,$location)}catch{Throw-ComponentDownloadFailure 'protocol'}
    foreach($item in @($first,$base,$next)){
        if(-not $item.IsAbsoluteUri -or $item.Scheme -cne 'https' -or -not $item.IsDefaultPort -or $item.UserInfo -or $item.Fragment){Throw-ComponentDownloadFailure 'protocol'}
    }
    $hostName=$first.DnsSafeHost.ToLowerInvariant();$target=$next.DnsSafeHost.ToLowerInvariant()
    $allowed=switch($hostName){
        'api.github.com' {@('api.github.com')}
        'github.com' {@('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com','objects-origin.githubusercontent.com','github-releases.githubusercontent.com')}
        {$_ -in @('discord.com','dl.discordapp.net','download.discordapp.net')} {@('discord.com','dl.discordapp.net','download.discordapp.net','stable.dl2.discordapp.net','ptb.dl2.discordapp.net')}
        {$_ -in @('wiresock.net','www.wiresock.net')} {@('wiresock.net','www.wiresock.net')}
        {$_ -in @('aka.ms','download.visualstudio.microsoft.com')} {@('aka.ms','go.microsoft.com','download.visualstudio.microsoft.com','download.microsoft.com','download.visualstudio.com')}
        default {@()}
    }
    if($target -notin @($allowed)){Throw-ComponentDownloadFailure 'protocol'}
    if($target -ceq 'github.com'){try{Allowed-Download $next.AbsoluteUri}catch{Throw-ComponentDownloadFailure 'protocol'}}
    return $next.AbsoluteUri
}
function Throw-ComponentDownloadFailure([string]$Code) {
    $messages=@{
        limit='Component download exceeds its byte limit'
        deadline='Component download exceeded its shared deadline'
        storage='Component download staging write or close failed'
        cleanup='Component download cleanup could not be confirmed'
        'cleanup-observation'='Component download cleanup encountered a failure'
        protocol='Component download response was incomplete or unsupported'
        transport='Component download transport failed'
    }
    if(-not $messages.ContainsKey($Code)){$Code='protocol'}
    $failure=[InvalidOperationException]::new($messages[$Code])
    $failure.Data['AccessWeaverComponentDownloadTerminal']=($Code -ne 'transport')
    throw $failure
}
function Test-ComponentDownloadTerminal($Failure) {
    $exception=$Failure.Exception
    if(-not $exception -and $Failure -is [Exception]){$exception=$Failure}
    while($exception){
        if($exception.Data['AccessWeaverComponentDownloadTerminal'] -eq $true){return $true}
        $exception=$exception.InnerException
    }
    return $false
}
function New-ComponentDownloadBudget([long]$MaximumBytes=(2147483648L+32MB),[int]$TimeoutMilliseconds=600000) {
    if($MaximumBytes -lt 0 -or $MaximumBytes -gt (2147483648L+32MB) -or $TimeoutMilliseconds -lt 1 -or $TimeoutMilliseconds -gt 600000){throw 'Invalid component download budget'}
    return @{Clock=[Diagnostics.Stopwatch]::StartNew();MaximumBytes=$MaximumBytes;TimeoutMilliseconds=$TimeoutMilliseconds;Written=0L}
}
function Get-ComponentDownloadRemaining($Budget) {
    $remaining=[long]$Budget.TimeoutMilliseconds-$Budget.Clock.ElapsedMilliseconds
    if($remaining -le 0){Throw-ComponentDownloadFailure 'deadline'}
    return [int]$remaining
}
function Wait-ComponentDownloadTask([Threading.Tasks.Task]$Task,$Budget,[scriptblock]$Abort) {
    $expired=$false
    if(-not $Task.IsCompleted){
        $remaining=[long]$Budget.TimeoutMilliseconds-$Budget.Clock.ElapsedMilliseconds
        # WaitAny wakes when I/O completes without throwing a task fault.
        # GetResult below preserves the original success or failure.
        $expired=$remaining -le 0 -or [Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]@($Task),[int]$remaining) -eq -1
    }
    if($expired){
        # Abort cancels the underlying operation; it does not substitute for
        # observing its completion. Never release/reuse an in-flight buffer.
        $cleanupFailed=$false
        try {& $Abort}catch {$cleanupFailed=$true}
        try {
            $late=$Task.GetAwaiter().GetResult()
            if($late -is [IDisposable]){try {$late.Dispose()}catch {$cleanupFailed=$true}}
        }catch {
            $exception=$_.Exception
            while($exception){
                if($exception -is [Net.WebException] -and $exception.Response){try {$exception.Response.Close()}catch {$cleanupFailed=$true}}
                $exception=$exception.InnerException
            }
        }
        if($cleanupFailed){Throw-ComponentDownloadFailure 'cleanup'}
        Throw-ComponentDownloadFailure 'deadline'
    }
    return $Task.GetAwaiter().GetResult()
}
function Write-ComponentDownloadChunk([IO.Stream]$Output,[byte[]]$Buffer,[int]$Count,$Budget) {
    [void](Get-ComponentDownloadRemaining $Budget)
    if($Count -lt 0 -or $Count -gt $Buffer.Length){Throw-ComponentDownloadFailure 'protocol'}
    if([long]$Count -gt $Budget.MaximumBytes-$Budget.Written){Throw-ComponentDownloadFailure 'limit'}
    if($Count -eq 0){return}
    # Charge BEFORE admitting the write, independently of headers/framing.
    $Budget.Written+=[long]$Count
    try {
        $task=$Output.WriteAsync($Buffer,0,$Count)
        [void](Wait-ComponentDownloadTask $task $Budget {$Output.Dispose()})
    }catch {
        if(Test-ComponentDownloadTerminal $_){throw}
        Throw-ComponentDownloadFailure 'storage'
    }
}
function Receive-ComponentDownloadStream([IO.Stream]$Source,[IO.Stream]$Output,$Budget) {
    $buffer=[byte[]]::new(65536)
    while($true){
        [void](Get-ComponentDownloadRemaining $Budget)
        $task=$Source.ReadAsync($buffer,0,$buffer.Length)
        $count=Wait-ComponentDownloadTask $task $Budget {$Source.Dispose()}
        if($count -eq 0){break}
        Write-ComponentDownloadChunk $Output $buffer $count $Budget
    }
}
function Assert-ComponentDownloadLength([long]$Declared,$Budget,[long]$Actual=-1) {
    if($Declared -gt $Budget.MaximumBytes){Throw-ComponentDownloadFailure 'limit'}
    if($Declared -lt -1 -or ($Actual -ge 0 -and $Declared -ge 0 -and $Actual -ne $Declared)){Throw-ComponentDownloadFailure 'protocol'}
}
function Set-ComponentDownloadHeaders($Request,[hashtable]$Headers) {
    foreach($key in $Headers.Keys){
        if([string]::Equals($key,'User-Agent',[StringComparison]::OrdinalIgnoreCase)){
            $Request.UserAgent=[string]$Headers[$key]
        }elseif([string]::Equals($key,'Accept',[StringComparison]::OrdinalIgnoreCase)){
            $Request.Accept=[string]$Headers[$key]
        }else{
            $Request.Headers[[string]$key]=[string]$Headers[$key]
        }
    }
}
function New-ComponentDownloadRequest([uri]$Uri) {
    return [Net.HttpWebRequest]::CreateHttp($Uri)
}
function Invoke-ComponentDownloadDotNet([string]$Url,[IO.Stream]$Output,$Budget,[hashtable]$Headers=@{}) {
    $current=[uri]$Url
    for($redirects=0;$redirects -le 5;$redirects++){
        if($current.Scheme -ne 'https' -or $current.UserInfo -or $current.Fragment){Throw-ComponentDownloadFailure 'protocol'}
        $request=$null;$response=$null;$stream=$null;$pending=$null;$cleanupFailed=$false
        try {
            $remaining=Get-ComponentDownloadRemaining $Budget
            $request=New-ComponentDownloadRequest $current
            $request.Method='GET';$request.AllowAutoRedirect=$false
            Set-ComponentDownloadHeaders $request $Headers
            $request.Timeout=$remaining;$request.ReadWriteTimeout=$remaining
            $pending=$request.GetResponseAsync()
            $response=Wait-ComponentDownloadTask $pending $Budget {$request.Abort()}
            $pending=$null
            [void](Get-ComponentDownloadRemaining $Budget)
            $status=[int]$response.StatusCode
            if($status -in @(301,302,303,307,308)){
                if($redirects -eq 5 -or -not $response.Headers['Location']){Throw-ComponentDownloadFailure 'protocol'}
                $current=[uri](Resolve-ComponentDownloadRedirect $Url $current.AbsoluteUri ([string]$response.Headers['Location']))
                continue
            }
            if($status -ne 200){Throw-ComponentDownloadFailure 'protocol'}
            Assert-ComponentDownloadLength $response.ContentLength $Budget
            $stream=$response.GetResponseStream()
            Receive-ComponentDownloadStream $stream $Output $Budget
            Assert-ComponentDownloadLength $response.ContentLength $Budget $Budget.Written
            [void](Get-ComponentDownloadRemaining $Budget)
            return
        }catch {
            # Error responses also own a response stream. Never retain a native
            # response merely because GetResponseAsync completed with an error.
            $exception=$_.Exception
            while($exception){
                if($exception -is [Net.WebException] -and $exception.Response){try {$exception.Response.Close()}catch {$cleanupFailed=$true}}
                $exception=$exception.InnerException
            }
            if(Test-ComponentDownloadTerminal $_){throw}
            Throw-ComponentDownloadFailure 'transport'
        }finally {
            # Wait-ComponentDownloadTask joins after Abort before returning.
            if($stream){try {$stream.Dispose()}catch {$cleanupFailed=$true}}
            if($response){try {$response.Close()}catch {$cleanupFailed=$true}}
            if($cleanupFailed){Throw-ComponentDownloadFailure 'cleanup'}
        }
    }
    Throw-ComponentDownloadFailure 'protocol'
}
function New-ComponentDownloadCurlStart([string]$Url,$Budget,[switch]$Proxy) {
    $curl=Join-Path $env:SystemRoot 'System32\curl.exe'
    if(-not (Test-Path -LiteralPath $curl)){Throw-ComponentDownloadFailure 'transport'}
    $seconds=([double](Get-ComponentDownloadRemaining $Budget)/1000).ToString('0.000',[Globalization.CultureInfo]::InvariantCulture)
    $arguments=@('--disable','--globoff','--fail','--proto','=https','--connect-timeout','30','--max-time',$seconds,'--silent','--output','-','--write-out','%{stderr}AWC1 %{http_code}\n%{redirect_url}\n')
    if($Proxy){
        # NO_PROXY can override an explicitly selected proxy unless the list
        # is cleared on curl's command line.
        $arguments+=@('--socks5-hostname','127.0.0.1:1080','--noproxy','')
    }
    $arguments+=@($Url)
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$curl
    $start.Arguments=(@($arguments|ForEach-Object {Native-Argument $_}) -join ' ')
    $start.WorkingDirectory=Split-Path -Parent $curl
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    # Curl builds that support these variables can write TLS secrets or
    # connection diagnostics to paths inherited from the caller.
    $start.EnvironmentVariables.Remove('SSLKEYLOGFILE')
    $start.EnvironmentVariables.Remove('QLOGDIR')
    return $start
}
function New-ComponentDownloadCurlProcess([Diagnostics.ProcessStartInfo]$StartInfo) {
    $process=[Diagnostics.Process]::new()
    $process.StartInfo=$StartInfo
    return $process
}
function Wait-ComponentDownloadProcessExit($Process) {
    $waitFailed=$false
    while($true){
        try {[void]$Process.WaitForExit();return $waitFailed}catch {
            # Reobserve only this same cached process object. A failed native
            # wait cannot release its owner/staging scope or admit another kill.
            if(-not $waitFailed){
                try {[Console]::Error.WriteLine('Component download cleanup is unconfirmed; waiting for the owned process.')}catch {}
            }
            $waitFailed=$true
            [Threading.Thread]::Sleep(200)
        }
    }
}
function Invoke-ComponentDownloadCurlOnce([string]$Url,[IO.Stream]$Output,$Budget,[switch]$Proxy) {
    $start=New-ComponentDownloadCurlStart $Url $Budget -Proxy:$Proxy
    $process=New-ComponentDownloadCurlProcess $start
    $started=$false;$heldHandle=[IntPtr]::Zero;$stdout=$null;$stderr=$null
    $readOut=$null;$readErr=$null;$failure=$null;$cleanupFailed=$false;$waitFault=$false;$hop=$null
    $metadata=[IO.MemoryStream]::new()
    try {
        [void](Get-ComponentDownloadRemaining $Budget)
        [void]$process.Start();$started=$true
        # Process.Handle pins this accepted Windows process object across every
        # exit query, helper operation and actual Wait. No PID reopening/kills.
        $heldHandle=$process.Handle
        if($heldHandle -eq [IntPtr]::Zero){Throw-ComponentDownloadFailure 'cleanup'}
        $process.StandardInput.Close()
        $stdout=$process.StandardOutput.BaseStream;$stderr=$process.StandardError.BaseStream
        $outBuffer=[byte[]]::new(65536);$errBuffer=[byte[]]::new(4096)
        $readOut=$stdout.ReadAsync($outBuffer,0,$outBuffer.Length)
        $readErr=$stderr.ReadAsync($errBuffer,0,$errBuffer.Length)
        $outDone=$false;$errDone=$false
        while(-not ($outDone -and $errDone -and $process.HasExited)){
            [void](Get-ComponentDownloadRemaining $Budget)
            if(-not $outDone -and $readOut.IsCompleted){
                $count=$readOut.GetAwaiter().GetResult();$readOut=$null
                if($count -eq 0){$outDone=$true}else{
                    Write-ComponentDownloadChunk $Output $outBuffer $count $Budget
                    $readOut=$stdout.ReadAsync($outBuffer,0,$outBuffer.Length)
                }
            }
            if(-not $errDone -and $readErr.IsCompleted){
                $count=$readErr.GetAwaiter().GetResult();$readErr=$null
                # Curl writes only the fixed status/redirect record to stderr.
                # Keep it bounded and private; never emit a redirect URL.
                if($count -eq 0){$errDone=$true}else{
                    if($count -gt 16384-$metadata.Length){Throw-ComponentDownloadFailure 'protocol'}
                    $metadata.Write($errBuffer,0,$count)
                    $readErr=$stderr.ReadAsync($errBuffer,0,$errBuffer.Length)
                }
            }
            $pending=@()
            if($null -ne $readOut){$pending+=@($readOut)}
            if($null -ne $readErr){$pending+=@($readErr)}
            if($pending.Count){
                $remaining=Get-ComponentDownloadRemaining $Budget
                if([Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$pending,$remaining) -eq -1){
                    Throw-ComponentDownloadFailure 'deadline'
                }
            }elseif(-not $process.HasExited){
                # Both pipes have reached EOF. Only the owned process remains.
                [Threading.Thread]::Sleep([Math]::Min(10,(Get-ComponentDownloadRemaining $Budget)))
            }
        }
        try {$process.WaitForExit()}catch {$waitFault=$true;throw}
        if($process.ExitCode -ne 0){Throw-ComponentDownloadFailure 'transport'}
        [void](Get-ComponentDownloadRemaining $Budget)
        $metadataBytes=$metadata.ToArray()
        try {$text=[Text.UTF8Encoding]::new($false,$true).GetString($metadataBytes)}finally{[Array]::Clear($metadataBytes,0,$metadataBytes.Length)}
        if($text -cnotmatch '^AWC1 ([0-9]{3})\r?\n([^\r\n]*)\r?\n$'){Throw-ComponentDownloadFailure 'protocol'}
        $status=[int]$matches[1];$location=[string]$matches[2]
        if(($status -eq 200 -and $location) -or ($status -notin @(200,301,302,303,307,308)) -or ($status -ne 200 -and -not $location)){Throw-ComponentDownloadFailure 'protocol'}
        $hop=@{status=$status;location=$location}
    }catch {$failure=$_}finally {
        if($started){
            # A failed transfer cannot release an accepted curl or pending pipe
            # read. Keep its exact cached handle until Kill/Wait and I/O join.
            if($failure){
                if($heldHandle -eq [IntPtr]::Zero){$cleanupFailed=$true}else{
                    try {if(-not $process.HasExited){$process.Kill()}}catch {$cleanupFailed=$true}
                }
            }
            if($stdout){try {$stdout.Dispose()}catch {$cleanupFailed=$true}}
            if($stderr){try {$stderr.Dispose()}catch {$cleanupFailed=$true}}
            foreach($pendingRead in @($readOut,$readErr)){
                if($pendingRead){try {$pendingRead.GetAwaiter().GetResult()|Out-Null}catch {if(-not $failure){$cleanupFailed=$true}}}
            }
            $finalWaitFault=Wait-ComponentDownloadProcessExit $process
            $waitFault=$waitFault -or $finalWaitFault
        }
        try {$process.Dispose()}catch {$cleanupFailed=$true}
        try {[Array]::Clear($metadata.GetBuffer(),0,[int]$metadata.Length);$metadata.Dispose()}catch {$cleanupFailed=$true}
    }
    if($cleanupFailed){Throw-ComponentDownloadFailure 'cleanup'}
    if($waitFault){Throw-ComponentDownloadFailure 'cleanup-observation'}
    if($failure){if(Test-ComponentDownloadTerminal $failure){throw $failure};Throw-ComponentDownloadFailure 'transport'}
    return $hop
}
function Invoke-ComponentDownloadCurl([string]$Url,[IO.Stream]$Output,$Budget,[switch]$Proxy) {
    $current=$Url
    for($redirects=0;$redirects -le 5;$redirects++){
        $hop=Invoke-ComponentDownloadCurlOnce $current $Output $Budget -Proxy:$Proxy
        if($hop.status -eq 200){return}
        if($redirects -eq 5){Throw-ComponentDownloadFailure 'protocol'}
        $current=Resolve-ComponentDownloadRedirect $Url $current $hop.location
        try {$Output.SetLength(0);$Output.Position=0}catch{Throw-ComponentDownloadFailure 'storage'}
    }
    Throw-ComponentDownloadFailure 'protocol'
}
function Save-ComponentDownloadAttempt([string]$Url,[string]$Path,$Budget,[switch]$Curl,[switch]$Proxy) {
    $output=$null;$owned=$false;$complete=$false;$failure=$null;$cleanupFailed=$false
    try {
        [void](Get-ComponentDownloadRemaining $Budget)
        try {$output=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,65536,[IO.FileOptions]::Asynchronous)}catch {Throw-ComponentDownloadFailure 'storage'}
        $owned=$true;$Budget.Written=0L
        if($Curl){Invoke-ComponentDownloadCurl $Url $output $Budget -Proxy:$Proxy}else{Invoke-ComponentDownloadDotNet $Url $output $Budget}
        [void](Get-ComponentDownloadRemaining $Budget)
        try {$output.Flush($true)}catch {Throw-ComponentDownloadFailure 'storage'}
        [void](Get-ComponentDownloadRemaining $Budget)
        try {$output.Dispose();$output=$null}catch {Throw-ComponentDownloadFailure 'storage'}
        $complete=$true
    }catch {$failure=$_
    }finally {
        if($output){try {$output.Dispose()}catch {$cleanupFailed=$true}}
        if($owned -and -not $complete){try {[IO.File]::Delete($Path)}catch {$cleanupFailed=$true}}
    }
    if($cleanupFailed){Throw-ComponentDownloadFailure 'cleanup'}
    if($failure){throw $failure}
}
function Test-InstallerPublisher([string]$publisher,$signature,[string]$verifiedSHA256,[string]$nativeArchitecture) {
    if($null -eq $signature -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -isnot [string]){return $false}
    switch($publisher){
        'discord' {return $signature.SignerCertificate.Subject -match 'Discord'}
        'microsoft' {return $signature.SignerCertificate.Subject -match 'Microsoft'}
        'wiresock' {
            # Only an exact vendor-published payload pin can identify the
            # release when Windows trusts its signer but the name has changed.
            if($verifiedSHA256 -and $nativeArchitecture -cin @('amd64','arm64') -and
                $verifiedSHA256 -ceq (WireSock-InstallerPlan $nativeArchitecture).sha256){return $true}
            return $signature.SignerCertificate.Subject -match 'NT Kernel|WireSock'
        }
        default {return $false}
    }
}
function Download([string]$url,[string]$hash,[string]$destination,[switch]$Signed,[string]$Publisher='',[switch]$ReturnVerifiedHash) {
    if($Signed -and $Publisher -notin @('discord','microsoft','wiresock')){throw 'A signed installer requires an expected publisher category'}
    $hash=Approved-DownloadHash $url $hash
    Allowed-Download $url
    if (-not $Signed -and $hash -notmatch '^[a-fA-F0-9]{64}$'){throw 'A SHA-256 from the release asset digest or an independently verified source is required'}
    $extension=if($Signed){'.exe'}else{[IO.Path]::GetExtension(([uri]$url).AbsolutePath)}
    $temp=Join-Path $root ('downloads\'+[guid]::NewGuid().ToString('N')+$extension)
    $budget=New-ComponentDownloadBudget
    $owned=$false
    $lockedSource=$null
    try {
        if($script:repairProxyReady){
            Save-ComponentDownloadAttempt $url $temp $budget -Curl -Proxy
        }else{
            try {Save-ComponentDownloadAttempt $url $temp $budget}catch {
                if(Test-ComponentDownloadTerminal $_){throw}
                [void](Get-ComponentDownloadRemaining $budget)
                # Fresh exclusive staging after confirmed primary-partial removal;
                # fallback shares the original clock, never a new timeout.
                Save-ComponentDownloadAttempt $url $temp $budget -Curl
            }
        }
        $owned=$true
        [void](Get-ComponentDownloadRemaining $budget)
        No-Reparse $temp
        $lockedSource=[IO.File]::Open($temp,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $verifiedSHA256=(Get-FileHash -InputStream $lockedSource -Algorithm SHA256).Hash.ToLowerInvariant()
        if($hash -and $verifiedSHA256 -ne $hash){throw 'Downloaded component SHA-256 mismatch'}
        if($Signed){
            $signature=Get-AuthenticodeSignature -LiteralPath $temp
            if(-not (Test-InstallerPublisher $Publisher $signature $verifiedSHA256 $inputData.nativeArchitecture)){throw 'Installer publisher signature could not be verified'}
        }
        [void](Get-ComponentDownloadRemaining $budget)
        Copy-Checked $temp $destination $verifiedSHA256
    }finally {
        if($lockedSource){$lockedSource.Dispose()}
        if($owned){try {[IO.File]::Delete($temp)}catch {Throw-ComponentDownloadFailure 'cleanup'}}
    }
    Event ('Verified download: '+[IO.Path]::GetFileName($destination))
    if($ReturnVerifiedHash){return $verifiedSHA256}
}
function Read-ComponentZip64Fields([byte[]]$Extra,[long[]]$Values) {
    $offset=0
    while($Extra.Length-$offset -ge 4){
        $tag=[BitConverter]::ToUInt16($Extra,$offset)
        $length=[BitConverter]::ToUInt16($Extra,$offset+2)
        $offset+=4
        if($length -gt $Extra.Length-$offset){break}
        if($tag -eq 1){
            $end=$offset+$length
            for($field=0;$field -lt $Values.Length;$field++){
                if($Values[$field] -ne 4294967295L){continue}
                if($end-$offset -lt 8){throw 'Component ZIP64 member metadata is incomplete'}
                $value=[BitConverter]::ToUInt64($Extra,$offset)
                if($value -gt [long]::MaxValue){throw 'Component ZIP64 member metadata exceeds its bounds'}
                $Values[$field]=[long]$value
                $offset+=8
            }
            return
        }
        $offset+=$length
    }
    throw 'Component ZIP64 member metadata is missing or invalid'
}
function Assert-ComponentZipLocalMember([IO.BinaryReader]$Reader,[long]$DirectoryOffset,[byte[]]$Header,[byte[]]$Name,[byte[]]$Extra) {
    $stream=$Reader.BaseStream
    $flags=[BitConverter]::ToUInt16($Header,8)
    $method=[BitConverter]::ToUInt16($Header,10)
    $crc=[BitConverter]::ToUInt32($Header,16)
    $disk=[BitConverter]::ToUInt16($Header,34)
    if($disk -ne 0){throw 'Multi-volume component archive members are unsupported'}
    $values=[long[]]@([BitConverter]::ToUInt32($Header,24),[BitConverter]::ToUInt32($Header,20),[BitConverter]::ToUInt32($Header,42))
    $zip64Sizes=$values[0] -eq 4294967295L -or $values[1] -eq 4294967295L
    if($values -contains 4294967295L){Read-ComponentZip64Fields $Extra $values}
    $expanded=$values[0];$compressed=$values[1];$localOffset=$values[2]
    if($DirectoryOffset-$localOffset -lt 30){throw 'Component archive local member header exceeds its bounds'}
    $stream.Position=$localOffset
    $local=$Reader.ReadBytes(30)
    if([BitConverter]::ToUInt32($local,0) -ne 0x04034b50 -or
        [BitConverter]::ToUInt16($local,6) -ne $flags -or [BitConverter]::ToUInt16($local,8) -ne $method){
        throw 'Component archive local and central headers disagree'
    }
    $nameLength=[BitConverter]::ToUInt16($local,26)
    $extraLength=[BitConverter]::ToUInt16($local,28)
    $dataOffset=$stream.Position+$nameLength+$extraLength
    if($nameLength -ne $Name.Length -or $dataOffset -gt $DirectoryOffset -or $compressed -gt $DirectoryOffset-$dataOffset){
        throw 'Component archive local member data exceeds its bounds'
    }
    $localName=$Reader.ReadBytes($nameLength)
    if([Convert]::ToBase64String($localName) -cne [Convert]::ToBase64String($Name)){
        throw 'Component archive local and central member names disagree'
    }
    $localSizes=[long[]]@([BitConverter]::ToUInt32($local,22),[BitConverter]::ToUInt32($local,18))
    $localZip64=$localSizes -contains 4294967295L
    if(($flags -band 8) -eq 0){
        if($localZip64){Read-ComponentZip64Fields ($Reader.ReadBytes($extraLength)) $localSizes}
        if($localSizes[0] -ne $expanded -or $localSizes[1] -ne $compressed -or [BitConverter]::ToUInt32($local,14) -ne $crc){
            throw 'Component archive local and central member sizes or CRC disagree'
        }
        return
    }

    # A streaming writer can leave zero sizes in the local header. Its data
    # descriptor supplies the independent sizes and CRC, with an optional signature.
    $stream.Position=$dataOffset+$compressed
    $descriptor=$Reader.ReadBytes([int][Math]::Min(24,$DirectoryOffset-$stream.Position))
    $wide=$zip64Sizes -or $localZip64
    $descriptorSize=if($wide){20}else{12}
    foreach($start in @(0,4)){
        if($descriptor.Length -lt $start+$descriptorSize){continue}
        if($start -eq 4 -and [BitConverter]::ToUInt32($descriptor,0) -ne 0x08074b50){continue}
        if([BitConverter]::ToUInt32($descriptor,$start) -ne $crc){continue}
        if($wide){
            $describedCompressed=[BitConverter]::ToUInt64($descriptor,$start+4)
            $describedExpanded=[BitConverter]::ToUInt64($descriptor,$start+12)
        }else{
            $describedCompressed=[BitConverter]::ToUInt32($descriptor,$start+4)
            $describedExpanded=[BitConverter]::ToUInt32($descriptor,$start+8)
        }
        if($describedCompressed -eq $compressed -and $describedExpanded -eq $expanded){return}
    }
    throw 'Component archive data descriptor disagrees with its central header'
}
function Assert-ComponentZipBudget([IO.Stream]$stream) {
    # Bound central-directory parsing before ZipArchive materializes its entries.
    if(-not $stream.CanSeek -or $stream.Length -lt 22 -or $stream.Length -gt (2147483648L+32MB)){throw 'Component archive has an unsupported compressed size'}
    $reader=[IO.BinaryReader]::new($stream,[Text.Encoding]::UTF8,$true)
    try {
        $tailLength=[int][Math]::Min(65557,$stream.Length);[void]$stream.Seek(-$tailLength,[IO.SeekOrigin]::End)
        $tail=$reader.ReadBytes($tailLength);$position=-1
        for($i=$tail.Length-22;$i -ge 0;$i--){
            if([BitConverter]::ToUInt32($tail,$i) -eq 0x06054b50){$position=$i;break}
        }
        if($position -lt 0 -or [BitConverter]::ToUInt16($tail,$position+20) -ne $tail.Length-$position-22){throw 'Component archive end record is invalid'}
        $footer=$stream.Length-$tailLength+$position
        if([BitConverter]::ToUInt16($tail,$position+4) -ne 0 -or [BitConverter]::ToUInt16($tail,$position+6) -ne 0){throw 'Multi-volume component archives are unsupported'}
        $diskCount=[long][BitConverter]::ToUInt16($tail,$position+8);$count=[long][BitConverter]::ToUInt16($tail,$position+10)
        $size=[long][BitConverter]::ToUInt32($tail,$position+12);$offset=[long][BitConverter]::ToUInt32($tail,$position+16)
        $zip64=$false
        if($footer -ge 20){[void]$stream.Seek($footer-20,[IO.SeekOrigin]::Begin);$locator=$reader.ReadBytes(20);$zip64=[BitConverter]::ToUInt32($locator,0) -eq 0x07064b50}
        if($zip64){
            if([BitConverter]::ToUInt32($locator,4) -ne 0 -or [BitConverter]::ToUInt32($locator,16) -ne 1){throw 'Multi-volume ZIP64 component archives are unsupported'}
            $recordOffset=[BitConverter]::ToUInt64($locator,8)
            if($recordOffset -gt $footer-76){throw 'Component ZIP64 end record is out of bounds'}
            [void]$stream.Seek([long]$recordOffset,[IO.SeekOrigin]::Begin);$record=$reader.ReadBytes(56)
            if($record.Length -ne 56 -or [BitConverter]::ToUInt32($record,0) -ne 0x06064b50){throw 'Component ZIP64 end record is invalid'}
            $recordLength=[BitConverter]::ToUInt64($record,4)
            if($recordLength -lt 44 -or $recordLength -gt 1MB -or $recordOffset+12+$recordLength -ne $footer-20){throw 'Component ZIP64 end record has an invalid size'}
            if([BitConverter]::ToUInt32($record,16) -ne 0 -or [BitConverter]::ToUInt32($record,20) -ne 0){throw 'Multi-volume ZIP64 component archives are unsupported'}
            $values=@([BitConverter]::ToUInt64($record,24),[BitConverter]::ToUInt64($record,32),[BitConverter]::ToUInt64($record,40),[BitConverter]::ToUInt64($record,48))
            if($values[0] -gt 4096 -or $values[1] -gt 4096){throw 'Component archive exceeds the 4096-entry limit'}
            if($values[2] -gt 16MB -or $values[3] -gt $stream.Length){throw 'Component archive central directory exceeds its bounds'}
            if(($diskCount -ne 65535 -and $diskCount -ne $values[0]) -or ($count -ne 65535 -and $count -ne $values[1]) -or ($size -ne 4294967295L -and $size -ne $values[2]) -or ($offset -ne 4294967295L -and $offset -ne $values[3])){throw 'Component ZIP64 end records disagree'}
            $diskCount=[long]$values[0];$count=[long]$values[1];$size=[long]$values[2];$offset=[long]$values[3];$footer=[long]$recordOffset
        }
        if($count -gt 4096 -or $diskCount -ne $count){throw 'Component archive exceeds the 4096-entry limit or has inconsistent counts'}
        if($size -gt 16MB -or $offset -gt $footer -or $size -gt $footer-$offset){throw 'Component archive central directory exceeds its bounds'}
        $end=$offset+$size
        if($end -ne $footer){
            # Some writers exclude the optional signature from directory size.
            if($footer-$end -lt 6 -or $footer-$end -gt 65541 -or $size+$footer-$end -gt 16MB){throw 'Component archive has unexpected data after its central directory'}
            [void]$stream.Seek($end,[IO.SeekOrigin]::Begin)
            if($reader.ReadUInt32() -ne 0x05054b50 -or $reader.ReadUInt16() -ne $footer-$stream.Position){throw 'Component archive central signature is invalid'}
        }
        [void]$stream.Seek($offset,[IO.SeekOrigin]::Begin)
        for($i=0;$i -lt $count;$i++){
            if($end-$stream.Position -lt 46){throw 'Component archive central directory is incomplete'}
            $header=$reader.ReadBytes(46)
            if($header.Length -ne 46 -or [BitConverter]::ToUInt32($header,0) -ne 0x02014b50){throw 'Component archive central directory entry is invalid'}
            $nameLength=[BitConverter]::ToUInt16($header,28);$extra=[BitConverter]::ToUInt16($header,30);$comment=[BitConverter]::ToUInt16($header,32)
            $skip=[long]$nameLength+$extra+$comment
            if($nameLength -eq 0 -or $skip -gt $end-$stream.Position){throw 'Component archive central directory entry exceeds its bounds'}
            $name=$reader.ReadBytes($nameLength)
            $extraFields=$reader.ReadBytes($extra)
            $nextHeader=$stream.Position+$comment
            Assert-ComponentZipLocalMember $reader $offset $header $name $extraFields
            $stream.Position=$nextHeader
        }
        if($stream.Position -ne $end){
            # Optional PKWARE central-directory digital signature; no extra entries.
            if($end-$stream.Position -lt 6 -or $reader.ReadUInt32() -ne 0x05054b50){throw 'Component archive contains unexpected central directory data'}
            $length=$reader.ReadUInt16()
            if($length -ne $end-$stream.Position){throw 'Component archive central signature is out of bounds'}
            [void]$stream.Seek($length,[IO.SeekOrigin]::Current)
        }
    } finally {$reader.Dispose();[void]$stream.Seek(0,[IO.SeekOrigin]::Begin)}
}
function Component-ArchivePlan($zip,[string]$destination) {
    if($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt 4096){throw 'Component archive must contain between 1 and 4096 entries'}
    $base=[IO.Path]::GetFullPath($destination).TrimEnd('\');No-Reparse $base
    $baseParent=Split-Path -Parent $base
    if(-not [IO.Directory]::Exists($base) -and (-not $baseParent -or -not [IO.Directory]::Exists($baseParent))){throw 'Component archive destination parent must already exist'}
    # Include the extraction root and every implicit parent in the same finite
    # object budget. Explicit entries keep their separate duplicate-path check.
    $paths=[Collections.Generic.Dictionary[string,bool]]::new([StringComparer]::OrdinalIgnoreCase)
    $objects=[Collections.Generic.Dictionary[string,bool]]::new([StringComparer]::OrdinalIgnoreCase)
    $plan=[Collections.Generic.List[object]]::new();$total=0L
    $objects.Add($base,$true);$plan.Add(@{entry=$null;target=$base;directory=$true})
    foreach($entry in $zip.Entries){
        if($entry.Length -gt 2147483648L-$total){throw 'Component archive exceeds 2 GiB'};$total+=$entry.Length
        $name=$entry.FullName.Replace('\','/')
        $mode=($entry.ExternalAttributes -shr 16) -band 0xf000
        if($mode -notin @(0,0x4000,0x8000) -or ($entry.ExternalAttributes -band 0x400)){throw 'Component archive contains an unsupported file type'}
        $directory=$name.EndsWith('/') -or $mode -eq 0x4000 -or ($entry.ExternalAttributes -band 0x10)
        if($directory -and $entry.Length -ne 0){throw 'Component archive directory contains file data'}
        if(-not $name -or $name.StartsWith('/') -or $name.Contains('//') -or $name -match '[:<>\"|?*\x00-\x1f]'){throw 'Component archive contains an invalid Windows path'}
        $relative=$name.TrimEnd('/');$parts=@($relative.Split('/'))
        if($parts.Count -gt 32){throw 'Component archive exceeds the 32-level path-depth limit'}
        foreach($part in $parts){
            $stem=($part -split '[.]',2)[0].TrimEnd(' ')
            if(-not $part -or $part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $stem -match '^(CON|PRN|AUX|NUL|CLOCK[$]|CONIN[$]|CONOUT[$]|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])$'){throw 'Component archive contains an ambiguous Windows path'}
        }
        $target=[IO.Path]::GetFullPath((Join-Path $base $relative))
        if(-not (Under $target $base) -or $paths.ContainsKey($target)){throw 'Component archive contains an escaping or duplicate path'}
        $paths.Add($target,[bool]$directory)
        $current=$base
        for($partIndex=0;$partIndex -lt $parts.Count;$partIndex++){
            $current=[IO.Path]::GetFullPath((Join-Path $current $parts[$partIndex]))
            $isDirectory=($partIndex -lt $parts.Count-1) -or [bool]$directory
            if($objects.ContainsKey($current)){
                if($objects[$current] -ne $isDirectory){throw 'Component archive file conflicts with a directory path'}
            }else{
                if($objects.Count -ge 8192){throw 'Component archive exceeds the 8192-object filesystem limit'}
                $objects.Add($current,$isDirectory)
                $plan.Add(@{entry=$(if($isDirectory){$null}else{$entry});target=$current;directory=$isDirectory})
            }
        }
    }
    # Preflight all planned objects before creating even the destination root.
    # Parent-first plan order also prevents CreateDirectory from introducing
    # uncounted implicit parents during extraction.
    foreach($item in $plan){
        No-Reparse $item.target
        if((Test-Path -LiteralPath $item.target) -and [bool](Get-Item -LiteralPath $item.target -Force).PSIsContainer -ne $item.directory){throw 'Component archive conflicts with an existing file or directory'}
    }
    return $plan.ToArray()
}
function Replace-StagedWorkflowFile([string]$staged,[string]$target) {
    [IO.File]::Replace($staged,$target,[NullString]::Value)
}
function Publish-StagedWorkflowFile([string]$staged,[string]$target,[string]$expectedHash,[string]$beforeHash) {
    foreach($delay in @(50,100,200,0)){
        $stagedHash=Get-WorkflowFileHash $staged
        $targetHash=Get-WorkflowFileHash $target
        if(-not $targetHash){$targetHash=''}
        if($stagedHash -ine $expectedHash -or $targetHash -ine $beforeHash){
            throw 'Workflow files changed before replacement'
        }
        if(-not $beforeHash){
            [IO.File]::Move($staged,$target)
            break
        }
        try {
            Replace-StagedWorkflowFile $staged $target
            break
        }catch {
            $cause=$_.Exception
            while($cause.InnerException){$cause=$cause.InnerException}
            # ERROR_SHARING_VIOLATION and ERROR_UNABLE_TO_REMOVE_REPLACED
            # retain both names. Move failures can leave partially changed state.
            if($delay -eq 0 -or $cause -isnot [IO.IOException] -or
               $cause.HResult -notin @(-2147024864,-2147023721)){throw}
        }
        Start-Sleep -Milliseconds $delay
    }
    if((Get-WorkflowFileHash $target) -ine $expectedHash -or (Get-WorkflowFileHash $staged)){
        throw 'Workflow file publication could not be verified'
    }
}
function Publish-RecordedWorkflowFile([string]$staged,[string]$target,[string]$hash) {
    $record=Backup-File $target
    $beforeHash=if($record.expectedHash){$record.expectedHash}else{$record.originalHash}
    # Either journaled digest can be present after an interruption.
    $record.pendingHash=$hash
    Save-Journal
    Publish-StagedWorkflowFile $staged $target $hash $beforeHash
    $record.expectedHash=$hash
    $record.Remove('pendingHash')
    Save-Journal
}
function Expand-Safe([string]$archive,[string]$destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    No-Reparse $archive
    $inputStream=[IO.File]::Open($archive,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $zip=$null
    try {
        Assert-ComponentZipBudget $inputStream
        $zip=[IO.Compression.ZipArchive]::new($inputStream,[IO.Compression.ZipArchiveMode]::Read,$true)
        $plan=@(Component-ArchivePlan $zip $destination);$total=0L;$buffer=[byte[]]::new(65536)
        if(@($plan | Where-Object {$_.target -ieq $inputStream.Name}).Count){throw 'Component archive cannot replace its own container'}
        foreach($item in $plan){
            if($item.directory){[void][IO.Directory]::CreateDirectory($item.target);continue}
            $parent=Split-Path -Parent $item.target;No-Reparse $parent
            $temporary=Join-Path $parent ('.accessweaver-extract-'+[guid]::NewGuid().ToString('N')+'.tmp')
            $source=$null;$output=$null;$hasher=$null;$ownsTemporary=$false
            try {
                $source=$item.entry.Open();$output=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$ownsTemporary=$true
                $hasher=[Security.Cryptography.SHA256]::Create();$written=0L
                while(($count=$source.Read($buffer,0,$buffer.Length)) -gt 0){
                    if($count -gt $item.entry.Length-$written -or $count -gt 2147483648L-$total){throw 'Component archive stream exceeds its declared size or 2 GiB budget'}
                    $output.Write($buffer,0,$count);[void]$hasher.TransformBlock($buffer,0,$count,$buffer,0);$written+=$count;$total+=$count
                }
                if($written -ne $item.entry.Length){throw 'Component archive stream is incomplete'}
                [void]$hasher.TransformFinalBlock([byte[]]::new(0),0,0);$hash=[BitConverter]::ToString($hasher.Hash).Replace('-','')
                $output.Flush($true);$output.Dispose();$output=$null
                Publish-RecordedWorkflowFile $temporary $item.target $hash
            } finally {
                if($hasher){$hasher.Dispose()};if($output){$output.Dispose()};if($source){$source.Dispose()}
                if($ownsTemporary -and (Test-Path -LiteralPath $temporary)){No-Reparse $temporary;Remove-Item -LiteralPath $temporary -Force}
            }
        }
    } finally {if($zip){$zip.Dispose()};$inputStream.Dispose()}
}
$assetNames=@{byedpi='ciadpi.exe';proxifyre='ProxiFyre.exe';wgcf='wgcf.exe';zapret='winws.exe';zapret2='winws2.exe';goodbyedpi='goodbyedpi.exe';dnscrypt='dnscrypt-proxy.exe';drover='version.dll'}
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-catalog-ready {0}' -f $script:workflowClock.ElapsedMilliseconds))}
# These upstreams publish separate native Windows builds. Other integrations
# retain their existing behavior and still require independent ARM64 work.
function Component-ArchitecturePlan([string]$engine) {
    if($engine -notin @('proxifyre','wgcf','dnscrypt')){throw 'Unknown native component'}
    $architecture=[string]$inputData.nativeArchitecture
    if($architecture -notin @('amd64','arm64')){throw 'Native Windows architecture is unavailable or unsupported; component selection was not attempted'}
    $machine=if($architecture -eq 'arm64'){0xaa64}else{0x8664}
    $pattern=switch($engine){
        'proxifyre' {'^ProxiFyre-v[0-9]+(?:[.][0-9]+){1,3}-'+$(if($architecture -eq 'arm64'){'ARM64'}else{'x64'})+'[.]zip$'}
        'wgcf' {'^wgcf_[0-9]+(?:[.][0-9]+){1,3}_windows_'+$architecture+'[.]exe$'}
        'dnscrypt' {'^dnscrypt-proxy-'+$(if($architecture -eq 'arm64'){'winarm'}else{'win64'})+'-[0-9]+(?:[.][0-9]+){1,3}[.]zip$'}
    }
    return @{machine=$machine;assetPattern=$pattern}
}
function Get-PEMachine([string]$path) {
    No-Reparse $path
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $reader=$null
    try {
        if($stream.Length -lt 64 -or $stream.Length -gt 128MB){return 0}
        $reader=[IO.BinaryReader]::new($stream)
        $header=$reader.ReadBytes(64)
        if($header.Length -ne 64 -or $header[0] -ne 0x4d -or $header[1] -ne 0x5a){return 0}
        $offset=[BitConverter]::ToUInt32($header,60)
        if($offset -lt 64 -or $offset -gt 1MB -or $offset -gt $stream.Length-6){return 0}
        [void]$stream.Seek($offset,[IO.SeekOrigin]::Begin)
        $coff=$reader.ReadBytes(6)
        if($coff.Length -ne 6 -or $coff[0] -ne 0x50 -or $coff[1] -ne 0x45 -or $coff[2] -ne 0 -or $coff[3] -ne 0){return 0}
        return [BitConverter]::ToUInt16($coff,4)
    } finally {if($null -ne $reader){$reader.Dispose()}else{$stream.Dispose()}}
}
function Find-Source([string]$engine,[string[]]$SourceRoots) {
    $name=$assetNames[$engine];if (-not $name){throw 'Unknown component'}
    $native=$engine -in @('proxifyre','wgcf','dnscrypt')
    if($native -and $inputData.nativeArchitecture -notin @('amd64','arm64')){return $null}
    $plan=if($native){Component-ArchitecturePlan $engine}else{$null}
    if(-not $PSBoundParameters.ContainsKey('SourceRoots')){
        $SourceRoots=@((Join-Path $root ('components\'+$engine)))
        if ($r.bundlePath) {$SourceRoots+=[IO.Path]::GetFullPath($r.bundlePath)}
        $SourceRoots+=@((Join-Path $env:ProgramFiles 'SplitWire-Turkey\res'),(Join-Path $env:ProgramFiles 'SplitWire-Turkey\Prerequisites'))
    }
    foreach ($base in $SourceRoots) {
        if(-not (Test-Path -LiteralPath $base)){continue}
        No-Reparse $base
        if($native){
            $compatible=Get-ChildItem -LiteralPath $base -Recurse -Filter $name -File | Where-Object {(Get-PEMachine $_.FullName) -eq $plan.machine} | Select-Object -First 1
            if($compatible){return $compatible.FullName}
            continue
        }
        if($engine -in @('zapret','zapret2')){
            $folder=if($engine -eq 'zapret2'){'zapret-winws2'}else{'zapret-winws'}
            $preferred=Get-ChildItem -LiteralPath $base -Directory -Recurse -Filter $folder | Select-Object -First 1
            if($preferred -and (Test-Path -LiteralPath (Join-Path $preferred.FullName $name))){return (Join-Path $preferred.FullName $name)}
        }
        $match=Get-ChildItem -LiteralPath $base -Recurse -Filter $name -File | Where-Object {$_.FullName -notmatch '\\x86\\|\\32\\|\\arm64\\|\\win7\\'} | Select-Object -First 1
        if($match){return $match.FullName}
    }
    return $null
}
function Component-ArchivePath([string]$directory,[string]$url) {
    $extension=[IO.Path]::GetExtension(([uri]$url).AbsolutePath).ToLowerInvariant()
    if($extension -notin @('.zip','.exe')){throw 'Unsupported component archive extension'}
    $target=Join-Path $directory ('asset-'+[guid]::NewGuid().ToString('N')+$extension)
    if(-not (Under $target $directory)){throw 'Invalid component archive destination'}
    return $target
}
function Get-ZapretLuaBundle([string]$directory,[string[]]$ExpectedSHA256) {
    $lua=Join-Path $directory 'lua'
    # Match upstream blockcheck's initialization order.
    $paths=@((Join-Path $lua 'zapret-lib.lua'),(Join-Path $lua 'zapret-antidpi.lua'))
    for($i=0;$i -lt $paths.Count;$i++){
        $digest=Get-WorkflowFileHash $paths[$i]
        if($ExpectedSHA256 -and $digest -ine $ExpectedSHA256[$i]){
            throw 'Zapret2 Lua libraries differ from the completed strategy scan'
        }
        if(-not $digest){throw 'Zapret2 requires its matching upstream Lua asset bundle'}
        @{path=$paths[$i];sha256=$digest}
    }
}
function Ensure-Asset([string]$engine,[string]$ExpectedSHA256,[string[]]$ExpectedLuaSHA256) {
    $plan=if($engine -in @('proxifyre','wgcf','dnscrypt')){Component-ArchitecturePlan $engine}else{$null}
    $source=if($ExpectedSHA256 -and $r.bundlePath){Find-Source $engine -SourceRoots @($r.bundlePath)}else{Find-Source $engine}
    if($ExpectedSHA256 -and (-not $source -or (Get-WorkflowFileHash $source) -ine $ExpectedSHA256)){
        throw 'The selected engine executable differs from the completed strategy scan'
    }
    if($ExpectedLuaSHA256){Get-ZapretLuaBundle (Split-Path -Parent $source) $ExpectedLuaSHA256 | Out-Null}
    if (-not $source) {
        $repos=@{byedpi='hufrea/byedpi';proxifyre='wiresock/proxifyre';wgcf='ViRb3/wgcf';zapret='cagritaskn/SplitWire-Turkey';zapret2='cagritaskn/SplitWire-Turkey';goodbyedpi='ValdikSS/GoodbyeDPI';dnscrypt='DNSCrypt/dnscrypt-proxy';drover='hdrover/discord-drover'}
        $patterns=@{byedpi='x86_64-w64.*zip$';proxifyre='x64\.zip$';wgcf='windows_amd64.exe$';zapret='ZIP.*Windows.*zip$';zapret2='ZIP.*Windows.*zip$';goodbyedpi='goodbyedpi.*zip$';dnscrypt='win64.*zip$';drover='drover.*zip$'}
        if($plan){$patterns[$engine]=$plan.assetPattern}
        if(-not $repos[$engine]){throw ('Supply an official component bundle for '+$engine)}
        $release=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri ('https://api.github.com/repos/'+$repos[$engine]+'/releases/latest')
        $candidates=@($release.assets | Where-Object {$_.name -match $patterns[$engine]})
        if($plan -and $candidates.Count -ne 1){throw ('Exactly one native Windows asset is required for '+$engine)}
        $asset=$candidates | Select-Object -First 1
        if(-not $asset){throw ('No compatible Windows asset found for '+$engine)}
        $hash=([string]$asset.digest) -replace '^sha256:',''
        if(-not $hash -and $r.sha256){$hash=$r.sha256}
        $dir=Join-Path $root ('components\'+$engine);Protect-Dir $dir;$archive=Component-ArchivePath $dir $asset.browser_download_url
        Download $asset.browser_download_url $hash $archive
        if($archive.EndsWith('.zip')){Expand-Safe $archive $dir}elseif($engine -eq 'wgcf'){Copy-Checked $archive (Join-Path $dir 'wgcf.exe')}
        $source=Find-Source $engine
        if(-not $source){throw ('Downloaded component does not contain '+$assetNames[$engine])}
    }
    $destination=Join-Path $root ('components\'+$engine)
    if((Split-Path -Parent $source).TrimEnd('\') -ne $destination.TrimEnd('\')) {
        Protect-Dir $destination
        if($engine -eq 'wgcf'){Copy-Checked $source (Join-Path $destination 'wgcf.exe');$source=Join-Path $destination 'wgcf.exe'}
        else {Copy-Tree (Split-Path -Parent $source) $destination;$source=Join-Path $destination ([IO.Path]::GetFileName($source))}
    }
    if([IO.Path]::GetFileName($source) -ne $assetNames[$engine]){$canonical=Join-Path $destination $assetNames[$engine];Copy-Checked $source $canonical;$source=$canonical}
    if($plan -and (Get-PEMachine $source) -ne $plan.machine){throw 'Staged component does not match the native Windows architecture'}
    $actualSHA256=Get-WorkflowFileHash $source
    if($ExpectedSHA256 -and $actualSHA256 -ine $ExpectedSHA256){
        throw 'The staged engine executable differs from the completed strategy scan'
    }
    Event ('Component ready: '+$engine+'; SHA256 '+$actualSHA256)
    return $source
}
function Get-WireSockCLIPaths {
    Join-Path $env:ProgramFiles 'WireSock Secure Connect\command-line\wiresock-connect-cli.exe'
    Join-Path $env:ProgramFiles 'WireSock Secure Connect\bin\wiresock-client.exe'
    Join-Path $env:ProgramFiles 'WireSock VPN Client\bin\wiresock-client.exe'
}
function WireSock-CLI {
    foreach($path in Get-WireSockCLIPaths){
        if(Test-Path -LiteralPath $path -PathType Leaf){No-Reparse $path;return $path}
    }
    return $null
}
function Read-OwnedWireSockProfile([string]$path) {
    $refusal='WireSock ownership record is invalid or its vendor CLI is unavailable'
    $stream=$null
    try {
        No-Reparse $path
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -le 0 -or $stream.Length -gt 8192){throw $refusal}
        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$false)
        try {
            $text=$reader.ReadToEnd().Trim()
            if(-not $text.StartsWith('{') -or -not $text.EndsWith('}')){throw $refusal}
            $record=ConvertFrom-Json -InputObject $text -ErrorAction Stop
        } finally {$reader.Dispose()}
        if($record -isnot [pscustomobject] -or $record.cli -isnot [string] -or $record.profile -isnot [string] -or [string]::IsNullOrWhiteSpace($record.profile)){
            throw $refusal
        }
        $legacyProperty=$record.PSObject.Properties['legacy']
        if($legacyProperty -and $legacyProperty.Value -isnot [bool]){throw $refusal}
        $legacy=$record.legacy -eq $true
        $paths=@(Get-WireSockCLIPaths)
        $allowed=if($legacy){@($paths[1],$paths[2])}else{@($paths[0])}
        if($record.cli -notin $allowed){throw $refusal}
        if(-not $legacy -and $record.profile -cnotmatch '^AccessWeaver-[a-f0-9]{32}$'){throw $refusal}
        No-Reparse $record.cli
        if(-not (Test-Path -LiteralPath $record.cli -PathType Leaf)){throw $refusal}
        return @{cli=$record.cli;profile=$record.profile;legacy=$legacy}
    } catch {
        throw $refusal
    } finally {
        if($stream){$stream.Dispose()}
    }
}
function Copy-BundledInstaller([IO.FileInfo]$installer,[ref]$OwnedPath) {
    # Use the same protected bytes for signature validation and execution.
    No-Reparse $installer.FullName
    $directory=Join-Path $root 'downloads'
    No-Reparse $directory
    $candidate=Join-Path $directory ([guid]::NewGuid().ToString('N')+'-'+$installer.Name)
    $source=[IO.File]::Open($installer.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($source.Length -le 0 -or $source.Length -gt (2147483648L+32MB)){
            throw 'Bundled installer exceeds the supported size or is empty'
        }
        $target=[IO.File]::Open($candidate,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $OwnedPath.Value=$candidate
        try {$source.CopyTo($target)}finally{$target.Dispose()}
    } finally {$source.Dispose()}
}
function WireSock-InstallerPlan([string]$architecture) {
    switch($architecture){
        'amd64' {
            return @{
                pattern='wiresock-secure-connect-x64-*.exe'
                url='https://wiresock.net/_api/download-release.php?product=wiresock-secure-connect&platform=windows_x64&version=3.8.1.1'
                sha256='bd5a7eba32177b1022eda42d233b6b7848ea38604a63b0205666b4060b89a375'
                cachedEngineSHA256='f7c8e620f44efab8c85eac96eee781875df816b483e9ff584dfbc5eb48349902'
            }
        }
        'arm64' {
            return @{
                pattern='wiresock-secure-connect-arm64-*.exe'
                url='https://wiresock.net/_api/download-release.php?platform=windows_arm64&product=wiresock-secure-connect&version=3.8.1.1'
                sha256='74af4720a702eeff2d0586c0694f9527f604e2dd3f8ea568dca196dd69f6f06d'
                cachedEngineSHA256='b6afed7d78c9aad39747027d3d2e37c0429dd25861b17b926904614adda8a869'
            }
        }
        default {throw 'Native Windows architecture is unavailable or unsupported for WireSock installation'}
    }
}
function Install-WireSock {
    if($r.downloadUrl -and ($r.downloadUrl -cnotmatch '^https://' -or ([string]$r.sha256).Length -ne 64 -or $r.sha256 -notmatch '^[a-fA-F0-9]{64}$')){throw 'Custom WireSock installer requires an HTTPS URL and SHA-256'}
    if($script:rebootRequired){throw 'Restart Windows before continuing WireSock setup'}
    $cli=WireSock-CLI;if($cli){return $cli}
    $plan=WireSock-InstallerPlan $inputData.nativeArchitecture
    $installer=$null
    $bundleRoots=@($r.bundlePath)
    if(-not $inputData.managedPolicy){$bundleRoots+=@(Join-Path $env:ProgramFiles 'SplitWire-Turkey\res')}
    foreach($base in $bundleRoots){
        if($base -and (Test-Path -LiteralPath $base -PathType Container)){
            No-Reparse $base
            $installer=Get-ChildItem -LiteralPath $base -Recurse -Filter $plan.pattern -File | Sort-Object Name -Descending | Select-Object -First 1
            if($installer){break}
        }
    }
    $bundleInstaller=$installer
    if(-not $installer){
        $url=$plan.url
        $hash=$plan.sha256
        if($r.downloadUrl){$url=$r.downloadUrl;$hash=$r.sha256}
        $target=Join-Path $root 'downloads\wiresock-setup.exe'
        Download $url $hash $target -Signed -Publisher wiresock
        $installer=Get-Item -LiteralPath $target
    }
    $staged=$null
    try {
        $installerPath=$installer.FullName
        if($bundleInstaller){
            Copy-BundledInstaller $installer ([ref]$staged)
            $installerPath=$staged
        }
        No-Reparse $installerPath
        $sig=Get-AuthenticodeSignature -LiteralPath $installerPath
        $installerSHA256=(Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if(-not (Test-InstallerPublisher 'wiresock' $sig $installerSHA256 $inputData.nativeArchitecture)){throw 'WireSock installer publisher signature could not be verified'}
        [void](Native $installerPath @('/install','/quiet','/norestart') @(0,3010,1641))
    } finally {
        if($staged){[IO.File]::Delete($staged)}
    }
    if($script:rebootRequired){throw 'Restart Windows after WireSock installation, then retry setup'}
    $cli=WireSock-CLI
    if(-not $cli){throw 'WireSock installation did not produce a CLI'}
    return $cli
}
function Application-Names {
    $names=@('Discord.exe','DiscordPTB.exe','SplitCord-Turkey.exe','Update.exe','RobloxPlayerBeta.exe','RobloxPlayerInstaller.exe')
    if($r.applications){$names+=@($r.applications)}
    if($r.browsers){$names+=@('chrome.exe','firefox.exe','opera.exe','operagx.exe','brave.exe','vivaldi.exe','msedge.exe','zen.exe','chromium.exe','librewolf.exe')}
    return @($names | Select-Object -Unique)
}
function Make-Config {
    $id='AccessWeaver-'+$(if($r.profileId){$r.profileId}else{'default'})
    $output=Join-Path $root ('profiles\'+$id+'.conf')
    if($r.configPath){No-Reparse $r.configPath;$config=Get-Content -LiteralPath $r.configPath -Raw}
    else {
        $wgcf=Ensure-Asset 'wgcf';$wgdir=Split-Path -Parent $wgcf
        # Never reuse or copy another application's private account file.
        if(-not (Test-Path -LiteralPath (Join-Path $wgdir 'wgcf-account.toml'))) {if(-not $r.acceptCloudflareTerms){throw 'Accept Cloudflare terms before registering a new account, or provide an existing configPath'};[void](Native $wgcf @('register','--accept-tos') -Secret)}
        [void](Native $wgcf @('generate') -Secret)
        $config=Get-Content -LiteralPath (Join-Path $wgdir 'wgcf-profile.conf') -Raw
    }
    if($config -match '(?im)^\s*(PreUp|PostUp|PreDown|PostDown)\s*='){throw 'Tunnel command hooks are not accepted'}
    $peerHeader='(?i)^[ \t]*\[Peer\][ \t]*(?:[#;][^\r\n]*)?(?:\r?\n|$)'
    $sections=[regex]::Split($config,'(?m)(?=^[ \t]*\[[^\]\r\n]+\])')
    if(-not ($sections -match $peerHeader) -or $config -notmatch '(?im)^\s*PrivateKey\s*='){throw 'Invalid WireGuard configuration'}
    $selection='AllowedApps = '+((Application-Names) -join ', ')
    $config=($sections | ForEach-Object {
        # WireSock parses application rules in each peer, including #@ws: directives.
        $section=[regex]::Replace($_,'(?im)^[ \t]*(?:#@ws:[ \t]*)?(?:AllowedApps|DisallowedApps)[ \t]*=[^\r\n]*(?:\r?\n|$)','')
        if($section -match $peerHeader){$section=$section.TrimEnd()+"`r`n"+$selection+"`r`n"}
        $section
    }) -join ''
    Write-Atomic $output $config
    Event ('Private tunnel configuration generated: '+$id)
    return $output
}
function Start-WireSockServices {
    $services=[Collections.Generic.List[object]]::new()
    try {
        foreach($name in @('WireSockAppService','WireSockConnectService')){
            $service=Get-Service -Name $name -ErrorAction SilentlyContinue
            if(-not $service){throw ('Vendor service missing: '+$name+'; finish installation/reboot before connecting')}
            $services.Add($service)
            if($service.Status -notin @('Running','Stopped')){
                throw ('Vendor service is not ready for setup: '+$name)
            }
        }
        foreach($service in $services){
            $service.Refresh()
            if($service.Status -eq 'Running'){continue}
            if($service.Status -ne 'Stopped'){throw 'Vendor service state changed during setup; retry when it is stable'}
            # These services belong to the vendor and may be shared with
            # other clients. Record the effect without claiming ownership.
            $script:externalEffectsPending=$true
            Start-Service -InputObject $service -ErrorAction Stop
            $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
        }
    } finally {
        foreach($service in $services){
            if($service -is [IDisposable]){$service.Dispose()}
        }
    }
}
function Get-WireSockReportedState($status) {
    if($status.outputComplete -ne $true -or $status.stdout -isnot [string] -or $status.stdout.Length -gt 8192){return 'Unknown'}
    # Accept one state from a standalone line or an explicit status field.
    # Never persist the address, profile name, or other vendor output.
    $pattern='(?m)^[ \t]*(?:(?i:(?:Connection[ \t]+)?Status)[ \t]*:[ \t]*)?(NotConnected|Connecting|Connected|Disconnecting|Disconnected)[ \t]*\r?$'
    $states=[regex]::Matches($status.stdout,$pattern)
    if($states.Count -ne 1){return 'Unknown'}
    return $states[0].Groups[1].Value
}
function Get-ManagedWireSockProfiles([string]$cli) {
    $failure='WireSock profile inventory could not be verified; retry before importing a profile'
    try {$inventory=Native $cli @('list') -Secret -Timeout 15}catch{throw $failure}
    if($inventory.outputComplete -ne $true -or $inventory.stdout -isnot [string] -or $inventory.stdout.Length -gt 8192){
        throw $failure
    }
    $pattern='(?<![a-zA-Z0-9-])AccessWeaver-[a-f0-9]{32}(?![a-zA-Z0-9-])'
    [regex]::Matches($inventory.stdout,$pattern) | ForEach-Object {$_.Value} | Sort-Object -Unique
}
function Connect-WireSock([string]$config) {
    if(Test-Path -LiteralPath (Join-Path $root 'profiles\wiresock-owned.json')){throw 'Remove the current managed WireSock method before importing another profile'}
    $cli=Install-WireSock
    if([IO.Path]::GetFileName($cli) -eq 'wiresock-connect-cli.exe') {
        Start-WireSockServices
        if(@(Get-ManagedWireSockProfiles $cli).Count){
            throw 'A managed WireSock profile remains in the vendor inventory; recover the earlier workflow before retrying setup'
        }
        # A unique vendor profile prevents replacement of an independently
        # imported profile with the same user-selected configuration name.
        $profile='AccessWeaver-'+[guid]::NewGuid().ToString('N')
        $importConfig=Join-Path $root ('profiles\'+$profile+'.conf')
        if(Test-Path -LiteralPath $importConfig){throw 'WireSock import staging path already exists'}
        $recovery=@{kind='wiresock';cli=$cli;profile=$profile;importOnly=$true}
        try {
            Copy-Checked $config $importConfig
            $script:undo.Add($recovery);Save-Journal
            [void](Native $cli @('import',$importConfig) -Secret)
        } finally {
            # The vendor derives its profile name from this file during import.
            # Keep the generated config for recovery, but retire this extra copy.
            No-Reparse $importConfig
            if([IO.File]::Exists($importConfig)){[IO.File]::Delete($importConfig)}
        }
        $recovery.importOnly=$false
        try {Save-Journal}catch{$recovery.importOnly=$true;throw}
        [void](Native $cli @('connect',$profile,'-exit') -Secret)
        $status=Get-WireSockReportedState (Native $cli @('status') -Secret -Timeout 15)
        if($status -cne 'Connected'){throw 'WireSock connection was not confirmed by vendor status'}
        Write-Atomic (Join-Path $root 'profiles\wiresock-owned.json') (@{profile=$profile;cli=$cli} | ConvertTo-Json)
        Event 'WireSock reports Connected; verify traffic independently'
        return $status
    }
    if(Get-Service 'wiresock-client-service' -ErrorAction SilentlyContinue){throw 'An existing SDK WireSock service is installed; remove it through its owner before using managed setup'}
    $script:undo.Add(@{kind='wiresock';cli=$cli;legacy=$true});Save-Journal
    [void](Native $cli @('install','-start-type','2','-config',$config,'-log-level','error') -Secret)
    Start-Service -Name 'wiresock-client-service';(Get-Service 'wiresock-client-service').WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    Write-Atomic (Join-Path $root 'profiles\wiresock-owned.json') (@{profile=[IO.Path]::GetFileNameWithoutExtension($config);cli=$cli;legacy=$true}|ConvertTo-Json)
    return 'Vendor service running; tunnel traffic requires independent verification'
}
function Confirm-WireSockDisconnected([string]$cli) {
    $refusal='WireSock disconnect command failed; the managed profile was retained'
    try {
        [void](Native $cli @('disconnect') -Secret)
        return
    } catch {
        # A consumed nonzero exit can mean the tunnel is already idle. A
        # timeout or uncertain process cleanup keeps the recovery entry intact.
        $program=[regex]::Escape([IO.Path]::GetFileName($cli))
        if($_.Exception.Message -cnotmatch ('\ATool failed: '+$program+' \(exit -?[0-9]{1,10}\)\z')){throw $refusal}
    }
    $state='Unknown'
    try {$state=Get-WireSockReportedState (Native $cli @('status') -Secret -Timeout 15)}catch{}
    if($state -cnotin @('NotConnected','Disconnected')){throw $refusal}
}
function Remove-ModernWireSockProfile([string]$cli,[string]$profile,[switch]$Disconnect,[switch]$RequireIdle) {
    try {$profiles=@(Get-ManagedWireSockProfiles $cli)}
    catch {throw 'WireSock profile inventory could not be verified before removal; the ownership record was retained'}
    if($profiles -cnotcontains $profile){
        if(($Disconnect -or $RequireIdle) -and $profiles.Count){
            throw 'WireSock removal could not confirm the only managed vendor profile; the ownership record was retained'
        }
        return
    }
    if(($Disconnect -or $RequireIdle) -and $profiles.Count -ne 1){
        throw 'WireSock removal could not confirm the only managed vendor profile; the ownership record was retained'
    }
    if($Disconnect){Confirm-WireSockDisconnected $cli}
    if($RequireIdle){
        $status=Get-WireSockReportedState (Native $cli @('status') -Secret -Timeout 15)
        if($status -cnotin @('NotConnected','Disconnected')){
            throw 'WireSock recovery cannot confirm the vendor is idle without an ownership record'
        }
    }
    try {[void](Native $cli @('delete',$profile) -Secret)}
    catch {throw 'WireSock profile deletion command failed; the ownership record was retained'}
    try {$remaining=@(Get-ManagedWireSockProfiles $cli)}
    catch {throw 'WireSock profile deletion could not be verified; the ownership record was retained'}
    if($remaining -ccontains $profile -or (($Disconnect -or $RequireIdle) -and $remaining.Count)){
        throw 'WireSock profile deletion could not be verified; the ownership record was retained'
    }
}
function Disconnect-OwnedWireSock($record) {
    if($record.legacy){
        $script:externalEffectsPending=$true
        Stop-Service 'wiresock-client-service' -ErrorAction Stop
    }else{
        Confirm-WireSockDisconnected $record.cli
    }
    Event 'Managed WireSock connection disconnected'
}
function Disconnect-WireSock {
    $owned=Join-Path $root 'profiles\wiresock-owned.json'
    if(-not (Test-Path -LiteralPath $owned)){throw 'No AccessWeaver-owned WireSock profile recorded'}
    $record=Read-OwnedWireSockProfile $owned
    Remove-WireSockRefreshTask
    Disconnect-OwnedWireSock $record
}
function Install-EngineService([string]$engine,[string]$binary,[string[]]$arguments) {
    $serviceName='AccessWeaver-'+$engine
    $existing=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if($existing){throw ('Service already exists; remove this managed method before reinstalling: '+$serviceName)}
    $controllerHash=(Get-FileHash -LiteralPath $inputData.controller -Algorithm SHA256).Hash.ToLowerInvariant()
    $controller=Join-Path $root ('services\host-'+$controllerHash+'.exe')
    if(Test-Path -LiteralPath $controller){
        Assert-TrustedItem $controller
    }else{Copy-Checked $inputData.controller $controller $controllerHash}
    if((Get-FileHash -LiteralPath $controller -Algorithm SHA256).Hash -ne $controllerHash){throw 'Existing service-host content does not match its trusted controller digest; retain it for administrator review'}
    $file=Join-Path $root ('services\'+$engine+'.json')
    Write-Atomic $file (@{name=$serviceName;binary=$binary;args=@($arguments);directory=(Split-Path -Parent $binary);logPath=(Join-Path $root ('logs\'+$engine+'.log'))}|ConvertTo-Json -Depth 5)
    $instance=[guid]::NewGuid().ToString('N')
    $binPath=(Quote-Arg $controller)+' service-host '+(Quote-Arg $file)+' --instance='+$instance
    $serviceOptions=@{Name=$serviceName;BinaryPathName=$binPath;StartupType='Automatic';DisplayName=('AccessWeaver '+$engine)}
    if($engine -eq 'proxifyre'){$serviceOptions.DependsOn=@('NDISRD')}
    $entry=@{kind='service';name=$serviceName;commandSHA256=(Get-ManagedServiceCommandDigest $binPath)}
    Write-Atomic (Join-Path $root ('services\'+$engine+'.registration')) $entry.commandSHA256
    $script:undo.Add($entry)
    Save-Journal
    $created=New-Service @serviceOptions
    if($created -is [IDisposable]){$created.Dispose()}
    if((Assert-RecordedServiceBinding $entry) -ne 0){throw 'New managed service registration could not be verified'}
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    Start-Sleep -Milliseconds 500
    if((Get-Service $serviceName).Status -ne 'Running'){throw ('Engine exited during startup: '+$engine)}
    Event ('Installed and started '+$serviceName)
}
function Get-ManagedFirewallRule([string]$Name,[string]$Instance,[switch]$Journal) {
    $match=[regex]::Match($Name,'\AAccessWeaver-(byedpi|proxifyre)-(Inbound|Outbound)\z')
    if(-not $match.Success){throw 'Unrecognized managed firewall rule name'}
    if($Instance -and $Instance -cnotmatch '\A[a-f0-9]{32}\z'){throw 'Invalid managed firewall recovery identity'}
    $engine=$match.Groups[1].Value;$direction=$match.Groups[2].Value
    $warnings=@()
    $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable warnings | Where-Object {
        $_.Name -ieq $Name -or $_.Name -ilike ($Name+'-*')
    })
    if($warnings.Count){throw 'Managed firewall rule inventory could not be verified'}
    if(-not $rules.Count){return}
    if($rules.Count -ne 1){throw 'Managed firewall rule identity is ambiguous'}
    $rule=$rules[0]
    $program=Join-Path $root ('components\'+$engine+'\'+$assetNames[$engine])
    $filter=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -PolicyStore PersistentStore -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable warnings)
    if($warnings.Count){throw 'Managed firewall application filter could not be verified'}
    $marker=[string]$rule.Description
    $legacy=$rule.Name -ceq $Name -and -not $marker
    $modern=$marker -cmatch '\AAccessWeaver managed rule [a-f0-9]{32}\z' -and
        $rule.Name -ceq ($Name+'-'+$marker.Substring($marker.Length-32))
    if($rule.DisplayName -cne $Name -or [string]$rule.Direction -cne $direction -or [string]$rule.Action -cne 'Allow' -or
        [string]$rule.Profile -cne 'Any' -or [string]$rule.Enabled -cne 'True' -or
        $filter.Count -ne 1 -or $filter[0].Program -ine $program -or
        (-not $legacy -and -not $modern)){
        throw 'Managed firewall rule differs from its expected local configuration'
    }
    if(($Journal -or $Instance) -and (-not $Instance -or $marker -cne ('AccessWeaver managed rule '+$Instance))){
        throw 'Managed firewall rule does not match the recovery journal'
    }
    return $rule
}
function Remove-ManagedFirewallRule([string]$Name,[string]$Instance,[switch]$Journal) {
    $rule=Get-ManagedFirewallRule $Name $Instance -Journal:$Journal
    if($null -eq $rule){return}
    $script:externalEffectsPending=$true
    Remove-NetFirewallRule -InputObject $rule -Confirm:$false -ErrorAction Stop
    if($null -ne (Get-ManagedFirewallRule $Name $Instance -Journal:$Journal)){
        throw 'Managed firewall rule removal could not be verified'
    }
}
function Firewall([string]$engine,[string]$binary) {
    if($engine -cnotin @('byedpi','proxifyre') -or
       $binary -ine (Join-Path $root ('components\'+$engine+'\'+$assetNames[$engine]))){
        throw 'Managed firewall rule requires the installed component path'
    }
    foreach($direction in @('Inbound','Outbound')){
        $name='AccessWeaver-'+$engine+'-'+$direction
        if($null -ne (Get-ManagedFirewallRule $name)){continue}
        $instance=[guid]::NewGuid().ToString('N')
        $script:undo.Add(@{kind='firewall';name=$name;instance=$instance})
        Save-Journal
        $script:externalEffectsPending=$true
        [void](New-NetFirewallRule -Name ($name+'-'+$instance) -DisplayName $name -Description ('AccessWeaver managed rule '+$instance) -Program $binary -Direction $direction -Action Allow -Profile Any -PolicyStore PersistentStore -ErrorAction Stop)
        if($null -eq (Get-ManagedFirewallRule $name $instance)){throw 'New managed firewall rule could not be verified'}
    }
}
function Test-ProxiFyreRuntimeRegistered {
    $runtime=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -Name Installed -ErrorAction SilentlyContinue
    return $runtime.Installed -eq 1
}
function Test-ProxiFyrePacketFilterRegistered {
    $found=$false
    Get-DriverServiceControllers -ErrorAction Stop | ForEach-Object {
        $driver=$_
        try {
            if($driver.ServiceName -ieq 'NDISRD'){$found=$true}
        } finally {
            if($driver -is [IDisposable]){$driver.Dispose()}
        }
    }
    return $found
}
function Assert-PrerequisiteRegistered([string]$component) {
    switch($component){
        'vcredist' {
            if(-not (Test-ProxiFyreRuntimeRegistered)){throw 'Visual C++ runtime installation did not register the required runtime'}
        }
        'ndisapi' {
            if(-not (Test-ProxiFyrePacketFilterRegistered)){throw 'Windows Packet Filter installation did not register the required driver'}
        }
        default {throw 'Unknown prerequisite component'}
    }
}
function Setup-ProxiFyre([string]$proxy) {
    if($script:rebootRequired){throw 'Restart Windows before continuing ProxiFyre setup'}
    if(-not (Test-ProxiFyreRuntimeRegistered)){
        Install-Prerequisite 'vcredist'
        if($script:rebootRequired){throw 'Restart Windows after Visual C++ runtime installation, then retry ProxiFyre setup'}
        Assert-PrerequisiteRegistered 'vcredist'
    }
    if(-not (Test-ProxiFyrePacketFilterRegistered)){
        Install-Prerequisite 'ndisapi'
        if($script:rebootRequired){throw 'Restart Windows after Windows Packet Filter installation, then retry ProxiFyre setup'}
        Assert-PrerequisiteRegistered 'ndisapi'
    }
    $binary=Ensure-Asset 'proxifyre';$dir=Split-Path -Parent $binary
    Protect-Dir (Join-Path $dir 'logs')
    Write-Atomic (Join-Path $dir 'app-config.json') (@{proxies=@(@{appNames=@(Application-Names);socks5ProxyEndpoint=$proxy;supportedProtocols=@('TCP','UDP')})}|ConvertTo-Json -Depth 8)
    # Topshelf's native service name belongs to the vendor. Run its console
    # command under our own SCM host so an existing vendor service is untouched.
    Install-EngineService 'proxifyre' $binary @('run')
    Firewall 'proxifyre' $binary
    Event 'Per-application TCP/UDP proxifier service started'
}
function Prerequisite-Plan([string]$component) {
    if($component -eq 'vcredist'){return @{pattern='VC_redist.x64.exe';assetPattern='^VC_redist[.]x64[.]exe$';platform=$null}}
    if($component -ne 'ndisapi'){throw 'Unknown prerequisite component'}
    $platform=switch($inputData.nativeArchitecture){'amd64' {'x64'} 'arm64' {'Arm64'} default {throw 'Native Windows architecture is unavailable or unsupported; driver installation was not attempted'}}
    return @{pattern=('Windows.Packet.Filter.*.'+$platform+'.msi');assetPattern=('^Windows[.]Packet[.]Filter[.][0-9]+(?:[.][0-9]+){2,3}[.]'+$platform+'[.]msi$');platform=$platform}
}
function Get-MSIPlatform([string]$path) {
    $installer=$null;$database=$null;$summary=$null
    try {
        $installer=New-Object -ComObject WindowsInstaller.Installer
        $database=$installer.OpenDatabase([IO.Path]::GetFullPath($path),0)
        $summary=$database.SummaryInformation(0)
        return (([string]$summary.Property(7)).Split(';')[0])
    } finally {
        foreach($object in @($summary,$database,$installer)){if($null -ne $object){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)}}
    }
}
function Install-Prerequisite([string]$component) {
    # Resolve the kernel's architecture before any bundle lookup or download.
    $plan=Prerequisite-Plan $component
    $installer=$null
    $bundleRoots=@($r.bundlePath)
    if(-not $inputData.managedPolicy){
        $bundleRoots+=@(Join-Path $env:ProgramFiles 'SplitWire-Turkey\Prerequisites')
    }
    foreach($base in $bundleRoots) {
        if($base -and (Test-Path -LiteralPath $base)){
            $candidateInstallers=@(Get-ChildItem -LiteralPath $base -Recurse -Filter $plan.pattern -File | Where-Object {$_.Name -match $plan.assetPattern})
            if($candidateInstallers.Count -gt 1){throw 'Multiple compatible prerequisite installers found; supply one reviewed installer'}
            if($candidateInstallers.Count -eq 1){$installer=$candidateInstallers[0];break}
        }
    }
    $bundleInstaller=$installer
    if(-not $installer){
        if($component -eq 'ndisapi'){
            $release=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri 'https://api.github.com/repos/wiresock/ndisapi/releases/latest'
            $assets=@($release.assets | Where-Object {$_.name -match $plan.assetPattern})
            if($assets.Count -ne 1){throw 'Exactly one architecture-compatible Windows Packet Filter installer is required'}
            $asset=$assets[0];$destination=Join-Path $root 'downloads\packet-filter.msi'
            Download $asset.browser_download_url (([string]$asset.digest)-replace '^sha256:','') $destination;$installer=Get-Item -LiteralPath $destination
        }else{$destination=Join-Path $root 'downloads\VC_redist.x64.exe';Download 'https://aka.ms/vs/17/release/vc_redist.x64.exe' '' $destination -Signed -Publisher microsoft;$installer=Get-Item -LiteralPath $destination}
    }
    $installerPath=$installer.FullName
    $staged=$null
    try {
        if($bundleInstaller){
            Copy-BundledInstaller $installer ([ref]$staged)
            $installerPath=$staged
        }
        No-Reparse $installerPath
        $signature=Get-AuthenticodeSignature -LiteralPath $installerPath
        if($signature.Status -ne 'Valid'){throw 'Prerequisite signature is invalid'}
        if($component -eq 'vcredist' -and -not (Test-InstallerPublisher 'microsoft' $signature)){
            throw 'Visual C++ runtime publisher signature could not be verified'
        }
        if($component -eq 'ndisapi' -and (Get-MSIPlatform $installerPath) -ine $plan.platform){
            throw 'Windows Packet Filter MSI platform does not match the native OS architecture'
        }
        if($component -eq 'ndisapi'){
            [void](Native (Join-Path $env:SystemRoot 'System32\msiexec.exe') @('/i',$installerPath,'/qn','/norestart') @(0,3010,1641))
        }else{
            [void](Native $installerPath @('/install','/quiet','/norestart') @(0,3010,1641))
        }
    } finally {
        if($staged){[IO.File]::Delete($staged)}
    }
    if($script:rebootRequired){
        Event ('Prerequisite installer requires a Windows restart: '+$component)
    }else{
        Event ('Prerequisite installer exited successfully: '+$component)
    }
}
function Discord-Directories([string]$variant='discord') {
    $folder=if($variant -eq 'discord-ptb'){'DiscordPTB'}else{'Discord'}
    $base=Join-Path $env:LOCALAPPDATA $folder
    if(-not (Test-Path -LiteralPath $base)){return @()}
    $candidates=@(foreach($item in Get-ChildItem -LiteralPath $base -Directory -Filter 'app-*'){
        if(-not (Test-Path -LiteralPath (Join-Path $item.FullName ($folder+'.exe')) -PathType Leaf)){continue}
        [version]$parsed=$null;$hasVersion=[version]::TryParse($item.Name.Substring(4),[ref]$parsed)
        if(-not $hasVersion){$parsed=[version]'0.0'}
        [pscustomobject]@{path=$item.FullName;hasVersion=$hasVersion;version=$parsed;modified=$item.LastWriteTimeUtc;name=$item.Name}
    })
    return @($candidates | Sort-Object @{Expression='hasVersion';Descending=$true},@{Expression='version';Descending=$true},@{Expression='modified';Descending=$true},@{Expression='name';Descending=$false} | ForEach-Object {$_.path})
}
function Install-Drover {
    $manifest=Join-Path $root 'profiles\drover-owned.json'
    No-Reparse $manifest
    if(Test-Path -LiteralPath $manifest -ErrorAction Stop){throw 'Restore the existing managed drover installation before replacing it'}
    $dirs=@(Discord-Directories)
    if($dirs.Count -eq 0 -or $dirs.Count -gt 256){throw 'Expected a bounded stable Discord installation inventory'}
    $dll=Ensure-Asset 'drover'
    $ini=Join-Path (Split-Path -Parent $dll) 'drover.ini'
    if(-not (Test-Path -LiteralPath $ini)){Write-Atomic $ini "[drover]`r`nproxy = socks5://127.0.0.1:1080`r`n"}

    $sources=@{'version.dll'=$dll;'drover.ini'=$ini}
    $hashes=@{}
    foreach($name in $sources.Keys){
        Assert-TrustedItem $sources[$name]
        $hashes[$name]=Get-DroverFileHash $sources[$name]
        if(-not $hashes[$name]){throw 'Drover input is missing'}
    }
    $deploymentID=[guid]::NewGuid().ToString('N')
    $records=@(foreach($dir in $dirs){
        $appSHA256=Get-DroverFileHash (Join-Path $dir 'Discord.exe')
        if(-not $appSHA256){throw 'Stable Discord executable disappeared before Drover deployment'}
        foreach($name in @('version.dll','drover.ini')){
            $target=Join-Path $dir $name
            $original=Get-DroverFileHash $target
            $backup=$null
            if($original){
                $backup=Join-Path $root ('backups\'+[guid]::NewGuid().ToString('N'))
                [IO.File]::Copy($target,$backup,$false)
            }else{
                # Force JSON null in Windows PowerShell for a missing original.
                $original=$null
            }
            [pscustomobject]@{deploymentID=$deploymentID;applicationSHA256=$appSHA256;path=$target;backup=$backup;originalHash=$original;installedHash=$hashes[$name]}
        }
    })
    foreach($item in @(Get-DroverRestorePlan $records)){
        if(-not $item.directoryExists -or $item.current -ine $item.original){throw 'Discord files changed before Drover deployment'}
    }
    $payload=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $records -Depth 5))
    if($payload.Length -gt 1MB){throw 'Drover ownership record exceeds its size limit'}
    $sha256=[Security.Cryptography.SHA256]::Create()
    try {$digest=[BitConverter]::ToString($sha256.ComputeHash($payload)).Replace('-','')} finally {$sha256.Dispose()}
    $script:undo.Add(@{kind='drover';manifestSHA256=$digest})
    Save-Journal
    $staged=Join-Path (Split-Path -Parent $manifest) ([guid]::NewGuid().ToString('N')+'.tmp')
    $stream=[IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        try {$stream.Write($payload,0,$payload.Length);$stream.Flush($true)} finally {$stream.Dispose()}
        [IO.File]::Move($staged,$manifest)
    } finally {
        if([IO.File]::Exists($staged)){[IO.File]::Delete($staged)}
    }

    Stop-AppProcesses 'discord'
    foreach($item in $records){
        $name=Split-Path -Leaf $item.path
        Set-DroverFile $sources[$name] $item.path $item.originalHash $item.installedHash $item.applicationSHA256
    }
    foreach($item in @(Get-DroverRestorePlan $records)){
        if(-not $item.directoryExists -or $item.current -ine $item.installedHash){throw 'Installed Drover file could not be verified'}
    }
    Event 'Discord drover files installed with original-file backups'
}
function Assert-DroverApplication([string]$directory,[string]$expected) {
    if($expected -and (Get-DroverFileHash (Join-Path $directory 'Discord.exe')) -ine $expected){
        throw 'The Discord executable changed; retain Drover recovery for administrator review'
    }
}
function Set-DroverFile([string]$source,[string]$target,[string]$before,[string]$expected,[string]$applicationSHA256) {
    if((Get-DroverFileHash $source) -ine $expected){throw 'Drover source changed before publication'}
    $directory=Split-Path -Parent $target
    No-Reparse $target
    Assert-DroverApplication $directory $applicationSHA256
    $staged=Join-Path $directory ('accessweaver-drover-'+[guid]::NewGuid().ToString('N')+'.tmp')
    [IO.File]::Copy($source,$staged,$false)
    try {
        if((Get-DroverFileHash $staged) -ine $expected){throw 'Staged Drover bytes changed before publication'}
        $current=Get-DroverFileHash $target
        if(($before -and $current -ine $before) -or (-not $before -and $current)){throw 'Drover file changed before publication'}
        Assert-DroverApplication $directory $applicationSHA256
        $script:externalEffectsPending=$true
        if($before){[IO.File]::Replace($staged,$target,[NullString]::Value)}
        else{[IO.File]::Move($staged,$target)}
    } finally {
        if([IO.File]::Exists($staged)){[IO.File]::Delete($staged)}
    }
}
function Get-DroverFileHash([string]$path) {
    No-Reparse $path
    if(-not (Test-Path -LiteralPath $path -ErrorAction Stop)){return}
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if($file.PSIsContainer -or $file.Length -gt 128MB){throw 'Drover recovery requires a bounded ordinary file'}
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Get-DroverRestorePlan($records) {
    $discord=Join-Path $env:LOCALAPPDATA 'Discord'
    $backups=Join-Path $root 'backups'
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($item in $records){
        $path=$item.path
        if($path -isnot [string] -or $path.Length -gt 4096 -or
           $path -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|\x00-\x1f]+\z' -or
           [IO.Path]::GetFullPath($path) -ine $path -or -not $seen.Add($path) -or
           $item.installedHash -isnot [string] -or $item.installedHash -notmatch '\A[a-fA-F0-9]{64}\z'){
            throw 'Invalid or duplicate Drover recovery entry'
        }
        $directory=Split-Path -Parent $path
        if((Split-Path -Parent $directory) -ine $discord -or (Split-Path -Leaf $directory) -notlike 'app-*' -or
           (Split-Path -Leaf $path) -notin @('version.dll','drover.ini')){
            throw 'Drover recovery target is outside the stable Discord installation'
        }
        No-Reparse $path
        $directoryExists=Test-Path -LiteralPath $directory -PathType Container -ErrorAction Stop
        if(-not $directoryExists -and (Test-Path -LiteralPath $directory -ErrorAction Stop)){
            throw 'The previous Discord version path is no longer a directory'
        }
        $applicationSHA256=$item.applicationSHA256
        if($null -ne $item.deploymentID -or $null -ne $applicationSHA256){
            if($item.deploymentID -isnot [string] -or $item.deploymentID -cnotmatch '\A[a-f0-9]{32}\z' -or
               $applicationSHA256 -isnot [string] -or $applicationSHA256 -notmatch '\A[a-fA-F0-9]{64}\z'){
                throw 'Invalid Drover application identity'
            }
            if($directoryExists){Assert-DroverApplication $directory $applicationSHA256}
        }
        $original=$null
        if($null -ne $item.backup){
            if($item.backup -isnot [string] -or (Split-Path -Parent $item.backup) -ine $backups -or
               (Split-Path -Leaf $item.backup) -cnotmatch '\A[a-f0-9]{32}\z'){
                throw 'Invalid Drover recovery backup path'
            }
            Assert-TrustedItem $item.backup
            $original=Get-DroverFileHash $item.backup
            if(-not $original -or ($null -ne $item.originalHash -and $item.originalHash -ine $original)){
                throw 'Original Drover backup is missing or changed'
            }
        }elseif($null -ne $item.originalHash){
            # Windows PowerShell 5.1 serialized an absent original file hash
            # from earlier installers as an empty object in identity-bound records.
            $legacyAbsentHash=$applicationSHA256 -and $item.originalHash -is [pscustomobject] -and
                @($item.originalHash.PSObject.Properties).Count -eq 0
            if(-not $legacyAbsentHash){throw 'Original Drover backup is missing'}
        }
        $current=Get-DroverFileHash $path
        if($current -ine $original -and $current -ine $item.installedHash -and $directoryExists){
            throw 'Drover file changed after installation; manual review required'
        }
        [pscustomobject]@{path=$path;backup=$item.backup;current=$current;original=$original;installedHash=$item.installedHash;applicationSHA256=$applicationSHA256;directoryExists=$directoryExists}
    }
}
function Restore-Drover([string]$ExpectedManifestSHA256) {
    $manifest=Join-Path $root 'profiles\drover-owned.json'
    No-Reparse $manifest
    if(-not (Test-Path -LiteralPath $manifest -ErrorAction Stop)){return}
    Assert-TrustedItem $manifest
    $entry=Get-Item -LiteralPath $manifest -Force -ErrorAction Stop
    if($entry.PSIsContainer -or $entry.Length -le 0 -or $entry.Length -gt 1MB){throw 'Invalid Drover ownership record'}
    $manifestHash=Get-DroverFileHash $manifest
    if($ExpectedManifestSHA256 -and $manifestHash -ine $ExpectedManifestSHA256){throw 'Drover recovery journal differs from the current ownership record'}
    $manifestJSON=Get-Content -LiteralPath $manifest -Raw -ErrorAction Stop
    # Windows PowerShell emits the whole decoded array as one pipeline object.
    # Evaluate the JSON command before normalizing its records to an array.
    $records=@((ConvertFrom-Json -InputObject $manifestJSON -ErrorAction Stop))
    if((Get-DroverFileHash $manifest) -cne $manifestHash){throw 'Drover ownership record changed during inspection'}
    if($records.Count -eq 0 -or $records.Count -gt 512){throw 'Invalid Drover ownership record'}
    # Refuse known conflicts before stopping Discord or changing any file.
    $plan=@(Get-DroverRestorePlan $records)
    if(@($plan | Where-Object {$_.directoryExists -and $_.current -ine $_.original}).Count){
        Stop-AppProcesses 'discord'
        $plan=@(Get-DroverRestorePlan $records)
    }
    foreach($item in $plan){
        if(-not $item.directoryExists){continue}
        Assert-DroverApplication (Split-Path -Parent $item.path) $item.applicationSHA256
        if((Get-DroverFileHash $item.path) -ine $item.current){throw 'Drover file changed during restoration'}
        if($item.current -ine $item.original){
            $script:externalEffectsPending=$true
            if($item.backup){
                if((Get-DroverFileHash $item.backup) -ine $item.original){throw 'Original Drover backup changed during restoration'}
                Set-DroverFile $item.backup $item.path $item.current $item.original $item.applicationSHA256
            }else{
                Remove-Item -LiteralPath $item.path -ErrorAction Stop
            }
        }
    }
    foreach($item in @(Get-DroverRestorePlan $records)){
        if($item.directoryExists -and $item.current -ine $item.original){throw 'Drover restoration could not be verified'}
    }
    # Completed restorations may be retried after a partial failure, using
    # the original backup hash to recognize files that are already restored.
    if((Get-DroverFileHash $manifest) -cne $manifestHash){throw 'Drover ownership record changed during restoration'}
    $script:externalEffectsPending=$true
    Remove-Item -LiteralPath $manifest -ErrorAction Stop
    if(Test-Path -LiteralPath $manifest -ErrorAction Stop){throw 'Drover ownership record could not be retired'}
    Event 'Original Discord files restored; backups for retired versions were retained'
}
function Save-Hostlist {
    if($r.engine -notin @('zapret','zapret2','goodbyedpi')){throw 'Live hostlists support Zapret, Zapret2 and GoodbyeDPI'}
    $dir=Join-Path $root ('components\'+$r.engine);$backup=Join-Path $dir 'accessweaver-hostlist.saved.txt';$active=Join-Path $dir 'accessweaver-hostlist.txt'
    if($null -ne $r.domains){Write-Atomic $backup ((@($r.domains | ForEach-Object {$_.ToLowerInvariant()}) -join "`n")+"`n")}
    if(-not (Test-Path -LiteralPath $backup)){Write-Atomic $backup ''}
    $text=if($r.enabled){Get-Content -LiteralPath $backup -Raw}else{''};Write-Atomic $active $text
    Event 'Hostlist saved; Zapret reload behavior is version-dependent; GoodbyeDPI requires service restart'
    if($r.engine -eq 'goodbyedpi' -and (Get-Service 'AccessWeaver-goodbyedpi' -ErrorAction SilentlyContinue)){
        $serviceConfig=Join-Path $root 'services\goodbyedpi.json';$config=Get-Content -LiteralPath $serviceConfig -Raw|ConvertFrom-Json;$arguments=@();$oldArgs=@($config.args)
        for($i=0;$i -lt $oldArgs.Count;$i++){if($oldArgs[$i] -eq '--blacklist'){$i++;continue};if($oldArgs[$i] -like '--blacklist=*'){continue};$arguments+=@($oldArgs[$i])}
        if($r.enabled){$arguments+=@('--blacklist',$active)};$config.args=@($arguments);Write-Atomic $serviceConfig ($config|ConvertTo-Json -Depth 8)
        Restart-Service 'AccessWeaver-goodbyedpi';(Get-Service 'AccessWeaver-goodbyedpi').WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    }
}
function Read-OriginalDNSNameServer([string]$path) {
    # Read the key successfully before treating an absent NameServer as DHCP.
    # Access failures and malformed values are not evidence of an empty value.
    $items=@(Get-ItemProperty -LiteralPath $path -ErrorAction Stop)
    if($items.Count -ne 1 -or $null -eq $items[0]){throw 'Original DNS mode could not be inspected; no new DNS configuration was applied'}
    $property=$items[0].PSObject.Properties['NameServer']
    if($null -eq $property -or $null -eq $property.Value){return ''}
    if($property.Value -isnot [string]){throw 'Original DNS mode has an unsupported value; no new DNS configuration was applied'}
    return [string]$property.Value
}
function Get-DNSClientFamily([object]$Value) {
    switch([string]$Value){
        {$_ -in @('2','IPv4','InterNetwork')} {return 'IPv4'}
        {$_ -in @('23','IPv6','InterNetworkV6')} {return 'IPv6'}
        default {throw 'DNS client inventory has an unsupported address family'}
    }
}
function Read-DNSClientInventory {
    $rows=@(Get-DnsClientServerAddress -ErrorAction Stop)
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($row in $rows){
        $index=[uint32]0
        if($null -eq $row -or -not [uint32]::TryParse([string]$row.InterfaceIndex,[ref]$index) -or $index -eq 0){throw 'DNS client inventory has an invalid interface identity'}
        $family=Get-DNSClientFamily $row.AddressFamily
        if(-not $seen.Add(([string]$index)+'/'+$family)){throw 'DNS client inventory has duplicate interface families'}
    }
    return @($rows)
}
function Get-DNSClientRows([object[]]$Rows,[uint32]$Index,[string]$Family) {
    return @($Rows | Where-Object {$_.InterfaceIndex -eq $Index -and (Get-DNSClientFamily $_.AddressFamily) -eq $Family})
}
function Get-OriginalDNSBounds([object]$Record) {
    $has4=if($Record -is [Collections.IDictionary]){$Record.Contains('bound4')}else{$null -ne $Record.PSObject.Properties['bound4']}
    $has6=if($Record -is [Collections.IDictionary]){$Record.Contains('bound6')}else{$null -ne $Record.PSObject.Properties['bound6']}
    if($has4 -ne $has6){throw 'Original DNS family coverage is incomplete; retain the snapshot'}
    if(-not $has4){return @{bound4=$true;bound6=$true}}
    if($Record.bound4 -isnot [bool] -or $Record.bound6 -isnot [bool] -or (-not $Record.bound4 -and -not $Record.bound6)){throw 'Original DNS family coverage is invalid; retain the snapshot'}
    return @{bound4=$Record.bound4;bound6=$Record.bound6}
}
function Assert-OriginalDNSModes([object]$Record,[hashtable]$Bounds) {
    if($Record.dhcp4 -isnot [bool] -or $Record.dhcp6 -isnot [bool]){throw 'Original DNS snapshot has invalid address mode flags; retain the snapshot'}
    foreach($number in @('4','6')){
        $dhcp=$Record.('dhcp'+$number);$values=@($Record.('ipv'+$number))
        if(-not $Bounds['bound'+$number]){
            if($dhcp -or $values.Count -ne 0){throw 'Original DNS unexposed-family metadata is inconsistent; retain the snapshot'}
        } elseif(-not $dhcp -and ($values.Count -eq 0 -or @($values | Where-Object {$_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)}).Count -ne 0)){throw 'Original static DNS addresses are unavailable; retain the snapshot'}
    }
}
# Canonical link-local values stay zone-free in snapshots and setter strings.
# Legacy zones must identify their saved adapter; a fresh GUID-bound CIM row
# supplies the current interface when those values are applied.
function Get-StaticDNSServers([object[]]$Values,[string]$Family,[object]$OriginalIndex) {
    if($Family -cnotin @('IPv4','IPv6') -or $Values.Count -eq 0){throw 'Original static DNS family or addresses are invalid; retain the snapshot'}
    $addresses=@()
    foreach($value in $Values){
        if($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)){throw 'Original static DNS address is invalid; retain the snapshot'}
        if($value.Contains('%')){
            # Named zones can cause platform interface lookup during parsing.
            # Only numeric zone syntax is admitted at this pure boundary.
            $scope=[uint32]0
            if($value -cnotmatch '^[^%]+%[0-9]{1,10}$' -or -not [uint32]::TryParse($value.Substring($value.LastIndexOf('%')+1),[ref]$scope)){throw 'Original DNS scope syntax is unsupported; retain the snapshot'}
        }
        $address=$null
        if(-not [Net.IPAddress]::TryParse($value,[ref]$address) -or ($Family -ceq 'IPv4' -and $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) -or ($Family -ceq 'IPv6' -and $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6)){throw 'Original static DNS address family is invalid; retain the snapshot'}
        if($Family -ceq 'IPv6'){
            if($value.Contains('%')){
                $index=[uint32]0
                if($address.ScopeId -eq 0 -or -not $address.IsIPv6LinkLocal -or -not [uint32]::TryParse([string]$OriginalIndex,[ref]$index) -or $index -eq 0 -or $address.ScopeId -ne $index){throw 'Original IPv6 DNS scope cannot identify its saved adapter; retain the snapshot'}
            }
            if($address.IsIPv6LinkLocal){$address.ScopeId=0}
        }
        $addresses+=@($address.ToString())
    }
    return @($addresses)
}
function Read-DNSStaticOverride([object]$Adapter,[string]$Family) {
    $service=if($Family -eq 'IPv4'){'Tcpip'}else{'Tcpip6'}
    $path='HKLM:\SYSTEM\CurrentControlSet\Services\'+$service+'\Parameters\Interfaces\'+([guid]$Adapter.InterfaceGuid).ToString('B')
    $names=Read-OriginalDNSNameServer $path
    if([string]::IsNullOrWhiteSpace($names)){return}
    if($names.Length -gt 16384){throw 'Stored DNS server list exceeds its size limit'}
    Get-StaticDNSServers ($names.Trim() -split '[,\s]+') $Family $Adapter.ifIndex
}
function Read-OriginalDNSFamily([object]$Adapter,[string]$Family,[object[]]$Clients) {
    $inventory=@(Get-NetAdapter -ErrorAction Stop)
    $current=@($inventory | Where-Object {[string]$_.InterfaceGuid -eq [string]$Adapter.InterfaceGuid})
    if($current.Count -ne 1 -or $current[0].ifIndex -ne $Adapter.ifIndex -or
       @($inventory | Where-Object {$_.ifIndex -eq $Adapter.ifIndex}).Count -ne 1){
        throw 'An adapter changed during original DNS capture; no new DNS configuration was applied'
    }
    $rows=@(Get-DNSClientRows $Clients $Adapter.ifIndex $Family)
    if($rows.Count -ne 1){throw 'Original adapter DNS family could not be inspected; no new DNS configuration was applied'}
    $stored=@(Read-DNSStaticOverride $Adapter $Family)
    $values=@($rows[0].ServerAddresses)
    if($stored.Count){
        $values=@(Get-StaticDNSServers $values $Family $Adapter.ifIndex)
        if(($stored -join ',') -cne ($values -join ',')){throw 'Stored static DNS servers differ from the effective adapter settings'}
    }
    return @{dhcp=($stored.Count -eq 0);values=@($values)}
}
function Read-OriginalDNSAdapter([object]$Adapter,[object[]]$Clients) {
    $record=@{guid=[string]$Adapter.InterfaceGuid;index=$Adapter.ifIndex;ipv4=@();ipv6=@();dhcp4=$false;dhcp6=$false;bound4=$false;bound6=$false}
    foreach($number in @('4','6')){
        $family='IPv'+$number
        if(@(Get-DNSClientRows $Clients $Adapter.ifIndex $family).Count -eq 1){
            $original=Read-OriginalDNSFamily $Adapter $family $Clients
            $record['ipv'+$number]=@($original.values);$record['dhcp'+$number]=$original.dhcp;$record['bound'+$number]=$true
        }
    }
    [void](Get-OriginalDNSBounds $record)
    return $record
}
function Get-ActiveDNSAdapters([object[]]$Adapters,[object[]]$Clients) {
    $Adapters | Where-Object {
        $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN' -and
        (@(Get-DNSClientRows $Clients $_.ifIndex 'IPv4').Count -eq 1 -or @(Get-DNSClientRows $Clients $_.ifIndex 'IPv6').Count -eq 1)
    }
}
# Native setters can return successfully while effective adapter state lags or
# differs. Compare both effective settings and the stored static override.
function Assert-ConfiguredDNSServers([object[]]$Adapters,[object[]]$Records,[string[]]$Servers) {
    if($Adapters.Count -eq 0 -or $Servers.Count -eq 0){throw 'Configured DNS readback is incomplete'}
    $first=@(Get-NetAdapter -ErrorAction Stop);$clients=@(Read-DNSClientInventory);$last=@(Get-NetAdapter -ErrorAction Stop)
    $activeBefore=@(Get-ActiveDNSAdapters $first $clients)
    $activeAfter=@(Get-ActiveDNSAdapters $last $clients)
    if($activeBefore.Count -ne $Adapters.Count -or $activeAfter.Count -ne $Adapters.Count){
        throw 'Active DNS adapter coverage changed during readback'
    }
    foreach($adapter in $Adapters){
        $guid=[string]$adapter.InterfaceGuid
        $before=@($activeBefore | Where-Object {[string]$_.InterfaceGuid -eq $guid})
        $after=@($activeAfter | Where-Object {[string]$_.InterfaceGuid -eq $guid})
        $saved=@($Records | Where-Object {[string]$_.guid -eq $guid})
        if([string]::IsNullOrWhiteSpace($guid) -or $before.Count -ne 1 -or $after.Count -ne 1 -or $saved.Count -ne 1 -or
           $before[0].ifIndex -le 0 -or
           $before[0].ifIndex -ne $after[0].ifIndex -or
           @($first | Where-Object {$_.ifIndex -eq $before[0].ifIndex}).Count -ne 1 -or
           @($last | Where-Object {$_.ifIndex -eq $after[0].ifIndex}).Count -ne 1){
            throw 'Configured DNS adapter changed during readback'
        }
        $bounds=Get-OriginalDNSBounds $saved[0]
        foreach($number in @('4','6')){
            $family='IPv'+$number;$rows=@(Get-DNSClientRows $clients $before[0].ifIndex $family)
            if(($rows.Count -eq 1) -ne $bounds['bound'+$number]){throw 'Configured DNS family coverage changed during readback'}
            if(-not $bounds['bound'+$number]){continue}
            $wanted=@($Servers | Where-Object {($_.Contains(':')) -eq ($number -eq '6')})
            $expected=@(Get-StaticDNSServers $wanted $family $before[0].ifIndex)
            $actual=@(Get-StaticDNSServers @($rows[0].ServerAddresses) $family $before[0].ifIndex)
            if($actual.Count -ne $expected.Count){throw 'Configured DNS server count differs'}
            if(($actual -join ',') -cne ($expected -join ',')){throw 'Configured DNS servers differ'}
            $stored=@(Read-DNSStaticOverride $before[0] $family)
            if(($stored -join ',') -cne ($expected -join ',')){throw 'Stored DNS servers do not match the configured static addresses'}
        }
    }
}
function Test-DNSIPv4Answer([object[]]$Answers,[string]$Name) {
    foreach($answer in $Answers){
        $address=$null
        if($answer.Section -eq 'Answer' -and $answer.Type -eq 'A' -and
            $answer.Name -is [string] -and $answer.Name.TrimEnd('.') -ieq $Name -and
            $answer.IPAddress -is [string] -and [Net.IPAddress]::TryParse($answer.IPAddress,[ref]$address) -and
            $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){return $true}
    }
    return $false
}
function Wait-DNSCryptListeners([string[]]$Servers,[int]$TimeoutSeconds=30) {
    $pending=@($Servers)
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        $pending=@(foreach($server in $pending){
            $ready=$false
            try {
                Clear-DnsClientCache -ErrorAction Stop
                $answers=@(Resolve-DnsName -Name 'example.net.' -Server $server -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
                $ready=Test-DNSIPv4Answer $answers 'example.net'
            } catch {}
            if(-not $ready){$server}
        })
        if(-not $pending.Count){return}
        if($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds){break}
        Start-Sleep -Milliseconds 500
    } while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    throw 'DNSCrypt loopback readiness could not be verified before adapter configuration'
}
function Get-DNSClientMutationRow([string]$Guid,[string]$Family,[switch]$RequireUp) {
    $adapters=@(Get-NetAdapter -ErrorAction Stop)
    $target=@($adapters | Where-Object {[string]$_.InterfaceGuid -eq $Guid})
    if($target.Count -ne 1 -or $target[0].ifIndex -le 0 -or ($RequireUp -and $target[0].Status -ne 'Up')){
        throw 'A DNS adapter changed before the update; retain the recovery snapshot'
    }
    $index=$target[0].ifIndex
    if(@($adapters | Where-Object {$_.ifIndex -eq $index}).Count -ne 1){
        throw 'A DNS adapter index is ambiguous; retain the recovery snapshot'
    }
    $rows=@(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily $Family -ErrorAction Stop)
    if($rows.Count -ne 1 -or @(Get-DNSClientRows $rows $index $Family).Count -ne 1){
        throw 'The DNS adapter family changed before the update; retain the recovery snapshot'
    }
    $fresh=@(Get-NetAdapter -ErrorAction Stop)
    $current=@($fresh | Where-Object {$_.ifIndex -eq $index})
    if($current.Count -ne 1 -or [string]$current[0].InterfaceGuid -ne $Guid -or
       @($fresh | Where-Object {[string]$_.InterfaceGuid -eq $Guid}).Count -ne 1 -or
       ($RequireUp -and $current[0].Status -ne 'Up')){
        throw 'A DNS adapter changed before the update; retain the recovery snapshot'
    }
    return $rows[0]
}
function Test-DNSRecoveryOwnsDoh($Record) {
    $scope=$Record.PSObject.Properties['dohManaged']
    # Older snapshots did not record scope and may have changed global DoH.
    if($null -eq $scope){return $true}
    if($scope.Value -isnot [bool] -or (-not $scope.Value -and @($Record.doh | Where-Object {$null -ne $_}).Count)){
        throw 'Original DNS snapshot has invalid DoH recovery scope'
    }
    return $scope.Value
}
function Get-DNSDohProviders {
    # Literal authorities avoid plaintext resolution of the DoH bootstrap host.
    return @(
        @{ServerAddress='8.8.8.8';DohTemplate='https://8.8.8.8/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true},
        @{ServerAddress='9.9.9.9';DohTemplate='https://9.9.9.9/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true},
        @{ServerAddress='2001:4860:4860::8888';DohTemplate='https://[2001:4860:4860::8888]/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true},
        @{ServerAddress='2620:fe::fe';DohTemplate='https://[2620:fe::fe]/dns-query';AllowFallbackToUdp=$false;AutoUpgrade=$true}
    )
}
function Test-DNSRecoveryUsesDohOwnership($Record,[bool]$OwnsDoh) {
    $guard=$Record.PSObject.Properties['dohConditional']
    if($null -eq $guard){return $false}
    if($guard.Value -isnot [bool] -or -not $guard.Value -or -not $OwnsDoh){
        throw 'Original DNS snapshot has invalid DoH ownership metadata'
    }
    return $true
}
function Get-DNSOriginalDohEntry($Record,[string]$Address) {
    $entry=@($Record.doh | Where-Object {$_.ServerAddress -eq $Address})
    if($entry.Count -gt 1){throw 'Original DoH metadata is ambiguous; retain the original DNS snapshot'}
    if($entry.Count -eq 1 -and ($entry[0].DohTemplate -isnot [string] -or [string]::IsNullOrWhiteSpace($entry[0].DohTemplate) -or
        $entry[0].AllowFallbackToUdp -isnot [bool] -or $entry[0].AutoUpgrade -isnot [bool])){
        throw 'Original DoH metadata is incomplete; retain the DNS snapshot for manual recovery'
    }
    return $entry
}
function Assert-ConfiguredDNSDohPolicy([object[]]$Providers,[string]$FailureMessage) {
    $observed=@(Get-DnsClientDohServerAddress -ErrorAction Stop)
    foreach($provider in $Providers){
        $entry=@($observed | Where-Object {$_.ServerAddress -eq $provider.ServerAddress})
        if(-not (Test-DNSDohEntriesEqual $entry @($provider))){throw $FailureMessage}
    }
}
function Test-DNSCryptListenerNeeded([object[]]$Records) {
    try {
        $inventory=@(Get-NetAdapter -ErrorAction Stop)
        $clients=@(Read-DNSClientInventory)
        # Include down and excluded interfaces. Also check stored overrides for
        # previously managed families whose effective rows can lag or disappear.
        # Keep the service if restoring a saved static setting would need it.
        foreach($client in $clients){
            foreach($server in $client.ServerAddresses){
                $address=$null
                if(-not [Net.IPAddress]::TryParse([string]$server,[ref]$address) -or
                   $address.Equals([Net.IPAddress]::Loopback) -or $address.Equals([Net.IPAddress]::IPv6Loopback)){return $true}
            }
        }
        foreach($record in $Records){
            $matches=@($inventory | Where-Object {[string]$_.InterfaceGuid -eq $record.guid})
            if($matches.Count -ne 1){return $true}
            $adapter=$matches[0];$bounds=Get-OriginalDNSBounds $record
            foreach($number in @('4','6')){
                if(-not $bounds['bound'+$number]){continue}
                $family='IPv'+$number
                if(@(Get-DNSClientRows $clients $adapter.ifIndex $family).Count -ne 1){return $true}
                if(-not $record.('dhcp'+$number)){
                    $original=@(Get-StaticDNSServers @($record.('ipv'+$number)) $family $record.index)
                    if($original -contains '127.0.0.1' -or $original -contains '::1'){return $true}
                }
                $stored=@(Read-DNSStaticOverride $adapter $family)
                if($stored -contains '127.0.0.1' -or $stored -contains '::1'){return $true}
            }
        }
    } catch {
        return $true
    }
    return $false
}
function Configure-DNS([string]$method) {
    if($method -notin @('doh','dnscrypt')){throw 'Choose doh or dnscrypt'}
    if($method -eq 'doh'){foreach($command in @('Get-DnsClientDohServerAddress','Set-DnsClientDohServerAddress','Add-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress')){if(-not (Get-Command $command -ErrorAction SilentlyContinue)){throw 'This Windows version does not expose native DoH management; choose DNSCrypt instead'}}}
    $serviceName='AccessWeaver-dnscrypt'
    $existingResolver=Assert-ManagedServiceOwnership $serviceName
    $snapshot=Join-Path $root 'profiles\dns-original.json'
    $inventory=@(Get-NetAdapter -ErrorAction Stop)
    # A complete successful DNS-client query distinguishes non-IP adapters from
    # inspection failure. Up/hardware status alone does not expose DNS families.
    $clients=@(Read-DNSClientInventory)
    $adapters=@(Get-ActiveDNSAdapters $inventory $clients)
    if(-not $adapters.Count){throw 'No active adapter exposes a DNS client family'}
    $originalSnapshot=Read-DNSRecoverySnapshot
    $hadSnapshot=$null -ne $originalSnapshot
    $original=if($hadSnapshot){$originalSnapshot.record}else{[pscustomobject]@{adapters=@();doh=@();dohManaged=$false}}
    $ownsDoh=Test-DNSRecoveryOwnsDoh $original
    $guardDoh=Test-DNSRecoveryUsesDohOwnership $original $ownsDoh
    if($hadSnapshot -and ($null -eq $original.adapters -or @($original.adapters).Count -eq 0)){throw 'Original DNS snapshot has no adapter records; no new DNS configuration was applied'}
    $records=@($original.adapters);$known=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($record in $records){
        if($null -eq $record -or $record.guid -isnot [string] -or [string]::IsNullOrWhiteSpace($record.guid) -or -not $known.Add($record.guid)){throw 'Original DNS adapter identities are invalid or duplicated; no new DNS configuration was applied'}
        $matches=@($inventory | Where-Object {[string]$_.InterfaceGuid -eq $record.guid})
        if($matches.Count -ne 1){throw 'An original network adapter is missing or ambiguous; no new DNS configuration was applied'}
        $bounds=Get-OriginalDNSBounds $record;Assert-OriginalDNSModes $record $bounds
        foreach($number in @('4','6')){
            if($bounds['bound'+$number]){
                if(-not $record.('dhcp'+$number)){[void](Get-StaticDNSServers @($record.('ipv'+$number)) ('IPv'+$number) $record.index)}
                if(@(Get-DNSClientRows $clients $matches[0].ifIndex ('IPv'+$number)).Count -ne 1){throw 'An owned DNS family is unavailable; retain the snapshot before further configuration'}
            }
        }
    }
    $newOriginals=@()
    # Extend adapter/family coverage before effects. Preserve every first original
    # and the first global DoH metadata, including across family activation.
    foreach($adapter in $adapters){
        $guid=[string]$adapter.InterfaceGuid;$matches=@($inventory | Where-Object {[string]$_.InterfaceGuid -eq $guid})
        if([string]::IsNullOrWhiteSpace($guid) -or $matches.Count -ne 1){throw 'Selected DNS adapter identities are unavailable or ambiguous; no new DNS configuration was applied'}
        if(-not $known.Contains($guid)){
            $record=Read-OriginalDNSAdapter $adapter $clients
            $records+=@($record);[void]$known.Add($guid)
            $newOriginals+=@(@{adapter=$adapter;record=$record;bounds=(Get-OriginalDNSBounds $record)})
        } else {
            $record=@($records | Where-Object {$_.guid -eq $guid})[0];$bounds=Get-OriginalDNSBounds $record
            $added=@{bound4=$false;bound6=$false}
            foreach($number in @('4','6')){
                if(-not $bounds['bound'+$number] -and @(Get-DNSClientRows $clients $adapter.ifIndex ('IPv'+$number)).Count -eq 1){
                    $captured=Read-OriginalDNSFamily $adapter ('IPv'+$number) $clients
                    $record.('ipv'+$number)=@($captured.values);$record.('dhcp'+$number)=$captured.dhcp;$record.('bound'+$number)=$true
                    $added['bound'+$number]=$true
                }
            }
            if($added.bound4 -or $added.bound6){$newOriginals+=@(@{adapter=$adapter;record=$record;bounds=$added})}
        }
    }
    if($method -eq 'doh'){
        $providers=@(Get-DNSDohProviders)
        $baseline=@(Get-DnsClientDohServerAddress -ErrorAction Stop |
            Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade)
        if(-not $ownsDoh){
            $original.doh=@($baseline | Where-Object {$_.ServerAddress -in $providers.ServerAddress})
            $original.dohManaged=$true
            $original | Add-Member -NotePropertyName dohConditional -NotePropertyValue $true
            $guardDoh=$true
        }
        foreach($provider in $providers){
            $address=$provider.ServerAddress
            $old=@(Get-DNSOriginalDohEntry $original $address)
            $current=@($baseline | Where-Object {$_.ServerAddress -eq $address})
            if($current.Count -gt 1){throw 'Current DoH configuration is ambiguous; retain the original DNS snapshot'}
            if($guardDoh -and -not (Test-DNSDohEntriesEqual $current $old) -and -not (Test-DNSDohEntriesEqual $current @($provider))){
                throw 'Managed DoH policy has changed independently; review it before configuration'
            }
        }
    }
    if($newOriginals.Count){
        $freshClients=@(Read-DNSClientInventory)
        foreach($originals in $newOriginals){
            foreach($number in @('4','6')){
                if(-not $originals.bounds['bound'+$number]){continue}
                $record=$originals.record
                $current=Read-OriginalDNSFamily $originals.adapter ('IPv'+$number) $freshClients
                # DHCP lease addresses can change. Restoration applies the DHCP mode.
                if($current.dhcp -ne $record.('dhcp'+$number) -or
                   (-not $current.dhcp -and ($current.values -join ',') -cne ($record.('ipv'+$number) -join ','))){
                    throw 'Original DNS settings changed during capture; no new DNS configuration was applied'
                }
            }
        }
    }
    # A new configuration supersedes older journals, even if the originals
    # are identical. DNS alone owns retirement of the published snapshot.
    $original | Add-Member -NotePropertyName recoveryID -NotePropertyValue ([guid]::NewGuid().ToString('N')) -Force
    $original.adapters=@($records)
    $encoded=$original|ConvertTo-Json -Depth 10
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($encoded)
    if($bytes.Length -gt 8MB){throw 'DNS recovery snapshot exceeds its size limit'}
    $snapshotSHA256=Get-WorkflowBytesSHA256 $bytes
    $dnsUndo=$script:undo | Where-Object {$_.kind -ceq 'dns'} | Select-Object -First 1
    if(-not $dnsUndo){
        $dnsUndo=@{kind='dns'}
        $script:undo.Add($dnsUndo)
    }
    $dnsUndo.snapshotSHA256=$snapshotSHA256
    $dnsUndo.snapshotActive=$false
    # The previous journal keeps its binding until the snapshot is replaced.
    Save-Journal
    Assert-DNSRecoverySnapshotUnchanged $originalSnapshot.sha256
    Publish-WorkflowFile $snapshot $bytes -BeforeHash $originalSnapshot.sha256
    if(-not (Confirm-DNSRecoverySnapshot $snapshotSHA256)){throw 'DNS recovery snapshot could not be published'}
    $dnsUndo.snapshotActive=$true
    Save-Journal
    if($method -eq 'dnscrypt') {
        if($existingResolver -and (Assert-RecordedServiceBinding $existingResolver) -ne 0){
            throw 'Existing DNSCrypt service disappeared before reconfiguration'
        }
        $binary=Ensure-Asset 'dnscrypt';$config=Join-Path (Split-Path -Parent $binary) 'dnscrypt-proxy.toml'
        if(-not (Test-Path -LiteralPath $config)){$example=Join-Path (Split-Path -Parent $binary) 'example-dnscrypt-proxy.toml';if(Test-Path -LiteralPath $example){Copy-Checked $example $config}else{throw 'Official DNSCrypt resolver configuration is missing'}}
        $text=Get-Content -LiteralPath $config -Raw;if($text -notmatch '(?m)^listen_addresses\s*='){throw 'DNSCrypt configuration is missing its top-level listen_addresses setting'};$text=[regex]::Replace($text,'(?m)^listen_addresses\s*=.*$',"listen_addresses = ['127.0.0.1:53', '[::1]:53']")
        if($text -notmatch '(?m)^server_names\s*='){$text="server_names = ['google', 'cloudflare', 'quad9-dnscrypt-ip4-nofilter-pri']`r`n"+$text}
        Write-Atomic $config $text
        if($existingResolver){
            if((Assert-RecordedServiceBinding $existingResolver) -ne 0){throw 'Existing DNSCrypt service disappeared before restart'}
            Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
            Restart-Service -Name $serviceName -ErrorAction Stop
            $service=Get-Service -Name $serviceName -ErrorAction Stop
            try {$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))}
            finally {if($service -is [IDisposable]){$service.Dispose()}}
        }else{Install-EngineService 'dnscrypt' $binary @('-config',$config)}
        $servers=@('127.0.0.1','::1')
        $listeners=@(foreach($number in @('4','6')){
            foreach($adapter in $adapters){
                $record=@($records | Where-Object {$_.guid -eq [string]$adapter.InterfaceGuid})[0]
                $bounds=Get-OriginalDNSBounds $record
                if($bounds['bound'+$number]){
                    if($number -eq '4'){$servers[0]}else{$servers[1]}
                    break
                }
            }
        })
        Wait-DNSCryptListeners $listeners
    } elseif($method -eq 'doh') {
        foreach($provider in $providers){
            $address=$provider.ServerAddress
            $expected=@($baseline | Where-Object {$_.ServerAddress -eq $address})
            $current=@(Get-DnsClientDohServerAddress -ErrorAction Stop | Where-Object {$_.ServerAddress -eq $address})
            if(-not (Test-DNSDohEntriesEqual $current $expected)){
                throw 'DoH policy changed during configuration; review current policy and retain the recovery snapshot'
            }
            if(Test-DNSDohEntriesEqual $current @($provider)){continue}
            $script:externalEffectsPending=$true
            if($current.Count -eq 1){
                Set-DnsClientDohServerAddress -ServerAddress $address -DohTemplate $provider.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
            }else{
                Add-DnsClientDohServerAddress -ServerAddress $address -DohTemplate $provider.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
            }
        }
        # Require verified policy before switching adapter resolvers.
        Assert-ConfiguredDNSDohPolicy $providers 'Configured DoH policy could not be verified; retain the original DNS snapshot'
        $servers=@($providers | ForEach-Object {$_.ServerAddress})
    } else {throw 'Choose doh or dnscrypt'}
    foreach($adapter in $adapters){
        $record=@($records | Where-Object {$_.guid -eq [string]$adapter.InterfaceGuid})[0];$bounds=Get-OriginalDNSBounds $record
        foreach($number in @('4','6')){
            if(-not $bounds['bound'+$number]){continue}
            $familyServers=@($servers | Where-Object {($_.Contains(':')) -eq ($number -eq '6')})
            $dns=Get-DNSClientMutationRow $record.guid ('IPv'+$number) -RequireUp
            $script:externalEffectsPending=$true
            $dns | Set-DnsClientServerAddress -ServerAddresses $familyServers -ErrorAction Stop
        }
    }
    # Observe eventual consistency without repeating a setter. Refuse success
    # and leave the original snapshot available if readback never converges.
    $adapterReadbackVerified=$false
    for($attempt=0;$attempt -lt 40;$attempt++){
        try{Assert-ConfiguredDNSServers $adapters $records $servers;$adapterReadbackVerified=$true;break}catch{if($attempt -lt 39){Start-Sleep -Milliseconds 250}}
    }
    if(-not $adapterReadbackVerified){throw 'Configured DNS servers could not be verified; retain the original DNS snapshot'}
    if($method -ceq 'doh'){
        Assert-ConfiguredDNSDohPolicy $providers 'Configured DoH policy changed after adapter configuration; retain the original DNS snapshot'
    }
    $ready=$false;$timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        try {
            Clear-DnsClientCache -ErrorAction Stop
            $answers=@(Resolve-DnsName -Name 'example.com.' -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
            if(Test-DNSIPv4Answer $answers 'example.com'){$ready=$true;break}
        }catch{}
        if($timer.Elapsed.TotalSeconds -ge 90){break}
        Start-Sleep -Seconds 2
    } while($timer.Elapsed.TotalSeconds -lt 90)
    if(-not $ready){
        if(-not (Confirm-DNSRecoverySnapshot $snapshotSHA256)){throw 'DNS recovery snapshot disappeared during verification'}
        Restore-DNS $snapshotSHA256
        throw 'Resolver verification failed; original DNS settings restored: the ordinary resolver did not return the expected DNS answer'
    }
    # A DNS answer could have come through settings that changed during the probe.
    Assert-ConfiguredDNSServers $adapters $records $servers
    if($method -ceq 'doh'){
        Assert-ConfiguredDNSDohPolicy $providers 'Configured DoH policy changed during resolver verification; retain the original DNS snapshot'
    }
    if($method -ceq 'doh' -and $existingResolver -and -not (Test-DNSCryptListenerNeeded $records)){
        # Keep the old listener available until the new adapter DNS is usable
        # and there is no remaining observed dependency on the loopback listener.
        if((Assert-RecordedServiceBinding $existingResolver) -ne 0){throw 'Existing DNSCrypt service disappeared during DoH configuration'}
        Stop-Service -Name $serviceName -ErrorAction Stop
        Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
    }
    Event ('Encrypted DNS configured: '+$method)
    $script:dnsConfigured=$true
}
function Test-DNSDohEntriesEqual([object[]]$Actual,[object[]]$Expected) {
    if($Actual.Count -ne $Expected.Count -or $Actual.Count -gt 1){return $false}
    if($Actual.Count -eq 0){return $true}
    $entry=$Actual[0];$reference=$Expected[0]
    return ([object]::Equals($entry.DohTemplate,$reference.DohTemplate) -and
        [object]::Equals($entry.AllowFallbackToUdp,$reference.AllowFallbackToUdp) -and
        [object]::Equals($entry.AutoUpgrade,$reference.AutoUpgrade))
}
# A successful setter is not proof of restored state. Keep the first originals
# until fresh GUID-bound DNS reads and managed DoH metadata match the snapshot.
function Assert-RestoredDNSState([object[]]$Plans,[object[]]$DohPlans,[bool]$DohAvailable) {
    $before=@(Get-NetAdapter -ErrorAction Stop)
    $clients=@(Read-DNSClientInventory)
    $after=@(Get-NetAdapter -ErrorAction Stop)
    foreach($plan in $Plans){
        $record=$plan.record
        $previous=@($before | Where-Object {[string]$_.InterfaceGuid -eq $record.guid})
        $matches=@($after | Where-Object {[string]$_.InterfaceGuid -eq $record.guid})
        if($previous.Count -ne 1 -or $matches.Count -ne 1 -or $previous[0].ifIndex -le 0 -or
           $previous[0].ifIndex -ne $matches[0].ifIndex -or
           @($before | Where-Object {$_.ifIndex -eq $previous[0].ifIndex}).Count -ne 1 -or
           @($after | Where-Object {$_.ifIndex -eq $matches[0].ifIndex}).Count -ne 1){
            throw 'An original adapter changed during restoration verification; retain the recovery snapshot'
        }
        foreach($number in @('4','6')){
            if(-not $plan.bounds['bound'+$number]){continue}
            $family='IPv'+$number
            $actual=Read-OriginalDNSFamily $matches[0] $family $clients
            if($actual.dhcp -ne $record.('dhcp'+$number)){throw 'Restored DNS mode could not be verified; retain the recovery snapshot'}
            if(-not $actual.dhcp){
                $expected=@(Get-StaticDNSServers @($record.('ipv'+$number)) $family $record.index)
                $values=@($actual.values)
                if($values.Count -ne $expected.Count){throw 'Restored static DNS count could not be verified; retain the recovery snapshot'}
                for($i=0;$i -lt $expected.Count;$i++){
                    if($values[$i] -cne $expected[$i]){throw 'Restored static DNS order or value could not be verified; retain the recovery snapshot'}
                }
            }
        }
    }
    if($DohAvailable){
        $observed=@(Get-DnsClientDohServerAddress -ErrorAction Stop)
        foreach($plan in $DohPlans){
            $current=@($observed | Where-Object {$_.ServerAddress -eq $plan.address})
            if(-not (Test-DNSDohEntriesEqual $current $plan.old)){throw 'Restored DoH policy could not be verified; retain the recovery snapshot'}
        }
    }
}
function Restore-DNS([string]$ExpectedSHA256) {
    $snapshot=Join-Path $root 'profiles\dns-original.json'
    $restoration=Read-DNSRecoverySnapshot
    if(-not $restoration){throw 'No original DNS snapshot exists; no settings were changed'}
    $snapshotSHA256=$restoration.sha256
    if($ExpectedSHA256 -and $snapshotSHA256 -ine $ExpectedSHA256){
        throw 'DNS recovery journal does not match the active snapshot; review dns-restore'
    }
    $saved=$restoration.record
    if($null -eq $saved.adapters -or @($saved.adapters).Count -eq 0){throw 'Original DNS snapshot has no adapter records; retain it for manual recovery'}
    # Inspect every original adapter and relevant DoH entry before changing any
    # settings. This is preflight, not a guarantee of an atomic OS transaction.
    $currentAdapters=@(Get-NetAdapter -ErrorAction Stop);$plans=@();$known=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($record in $saved.adapters){
        if($null -eq $record -or $record.guid -isnot [string] -or [string]::IsNullOrWhiteSpace($record.guid) -or -not $known.Add($record.guid)){throw 'Original DNS adapter identities are invalid or duplicated; retain the snapshot for manual recovery'}
        $bounds=Get-OriginalDNSBounds $record;Assert-OriginalDNSModes $record $bounds
        $matches=@($currentAdapters | Where-Object {[string]$_.InterfaceGuid -eq $record.guid})
        if($matches.Count -ne 1){throw 'An original network adapter is missing or ambiguous; retain the snapshot for later recovery'}
        foreach($number in @('4','6')){
            if($bounds['bound'+$number] -and -not $record.('dhcp'+$number)){[void](Get-StaticDNSServers @($record.('ipv'+$number)) ('IPv'+$number) $record.index)}
        }
        $plans+=@{record=$record;adapter=$matches[0];bounds=$bounds}
    }
    $clients=@(Read-DNSClientInventory)
    foreach($plan in $plans){foreach($number in @('4','6')){if($plan.bounds['bound'+$number] -and @(Get-DNSClientRows $clients $plan.adapter.ifIndex ('IPv'+$number)).Count -ne 1){throw 'An owned DNS family cannot be inspected; retain the recovery snapshot'}}}
    $ownsDoh=Test-DNSRecoveryOwnsDoh $saved
    $guardDoh=Test-DNSRecoveryUsesDohOwnership $saved $ownsDoh
    $dohAvailable=$ownsDoh -and [bool](Get-Command 'Get-DnsClientDohServerAddress' -ErrorAction SilentlyContinue)
    $currentDoh=@();$dohPlans=@()
    if($dohAvailable){
        foreach($command in @('Set-DnsClientDohServerAddress','Add-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress')){if(-not (Get-Command $command -ErrorAction SilentlyContinue)){throw 'DoH recovery commands are unavailable; retain the original DNS snapshot'}}
        $currentDoh=@(Get-DnsClientDohServerAddress -ErrorAction Stop)
        foreach($provider in Get-DNSDohProviders){
            $address=$provider.ServerAddress
            $old=@(Get-DNSOriginalDohEntry $saved $address)
            $current=@($currentDoh | Where-Object {$_.ServerAddress -eq $address})
            if($current.Count -gt 1){throw 'Current DoH recovery metadata is ambiguous; retain the original DNS snapshot'}
            if($guardDoh -and -not (Test-DNSDohEntriesEqual $current $old) -and -not (Test-DNSDohEntriesEqual $current @($provider))){
                throw 'Managed DoH policy has changed independently; review it and retain the recovery snapshot'
            }
            $observed=@($current | Select-Object DohTemplate,AllowFallbackToUdp,AutoUpgrade)
            $dohPlans+=@{address=$address;old=$old;current=$observed}
        }
    } elseif($guardDoh -or @($saved.doh | Where-Object {$null -ne $_}).Count -gt 0){throw 'Original DoH metadata cannot be restored on this host; retain the DNS snapshot'}
    Assert-DNSRecoverySnapshotUnchanged $snapshotSHA256
    foreach($plan in $plans){
        $record=$plan.record
        foreach($number in @('4','6')){
            if(-not $plan.bounds['bound'+$number]){continue}
            $dns=Get-DNSClientMutationRow $record.guid ('IPv'+$number)
            $script:externalEffectsPending=$true
            if($record.('dhcp'+$number)){
                $dns | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop
            }else{
                $dns | Set-DnsClientServerAddress -ServerAddresses @(Get-StaticDNSServers @($record.('ipv'+$number)) ('IPv'+$number) $record.index) -ErrorAction Stop
            }
        }
    }
    foreach($plan in $dohPlans){
        # An independent policy change can occur during adapter recovery or
        # during another provider's setter. Compare again before touching it.
        $current=@(Get-DnsClientDohServerAddress -ErrorAction Stop | Where-Object {$_.ServerAddress -eq $plan.address})
        if(-not (Test-DNSDohEntriesEqual $current $plan.current)){
            throw 'DoH policy changed during restoration; review current policy and retain the recovery snapshot'
        }
        if(Test-DNSDohEntriesEqual $current $plan.old){continue}
        if($plan.old.Count -eq 1){
            $old=$plan.old[0]
            if($current.Count -eq 1){Set-DnsClientDohServerAddress -ServerAddress $plan.address -DohTemplate $old.DohTemplate -AllowFallbackToUdp $old.AllowFallbackToUdp -AutoUpgrade $old.AutoUpgrade -ErrorAction Stop}
            else{Add-DnsClientDohServerAddress -ServerAddress $plan.address -DohTemplate $old.DohTemplate -AllowFallbackToUdp $old.AllowFallbackToUdp -AutoUpgrade $old.AutoUpgrade -ErrorAction Stop}
        } else {Remove-DnsClientDohServerAddress -ServerAddress $plan.address -ErrorAction Stop}
    }
    # A DNS client row can lag behind the setter after service or adapter
    # startup. Retry observations while preserving the original snapshot.
    for($attempt=0;$attempt -lt 40;$attempt++){
        try {
            Assert-RestoredDNSState $plans $dohPlans $dohAvailable
            break
        } catch {
            if($attempt -eq 39){throw}
            Start-Sleep -Milliseconds 250
        }
    }
    if(-not (Confirm-DNSRecoverySnapshot $snapshotSHA256)){throw 'Original DNS snapshot disappeared during restoration'}
    Save-DNSRecoveryReceipt $snapshotSHA256
    Assert-DNSRecoverySnapshotUnchanged $snapshotSHA256
    Remove-Item -LiteralPath $snapshot -ErrorAction Stop
    if(Get-DNSRecoverySnapshotDigest){throw 'Original DNS snapshot retirement could not be verified'}
    Event 'Original DNS and DoH settings restored'
}

function Remove-WireSockRefreshTask {
    $inspection=Get-RefreshTaskInspection
    if($inspection.present -eq $false){return}
    if($inspection.present -ne $true){throw 'WireSock reconnect task state could not be verified'}
    $task=@{TaskName='AccessWeaver-WireSock-Refresh';TaskPath='\';ErrorAction='Stop'}
    try {
        # Prevent new runs before stopping any active instance.
        $script:externalEffectsPending=$true
        Disable-ScheduledTask @task | Out-Null
        Stop-ScheduledTask @task | Out-Null
        Unregister-ScheduledTask @task -Confirm:$false
    } catch {
        throw 'WireSock reconnect task cleanup failed; retry before removing the profile'
    }
    if((Get-RefreshTaskInspection).present -ne $false){
        throw 'WireSock reconnect task removal could not be verified'
    }
}
function Refresh-Task {
    $name='AccessWeaver-WireSock-Refresh'
    if(-not $r.enabled){Remove-WireSockRefreshTask;Event 'Reconnect task removed';return}
    $recordPath=Join-Path $root 'profiles\wiresock-owned.json';if(-not (Test-Path -LiteralPath $recordPath)){throw 'Connect a managed WireSock profile first'}
    $record=Read-OwnedWireSockProfile $recordPath
    if($record.legacy){$command="Restart-Service -Name 'wiresock-client-service' -ErrorAction Stop";$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command));$action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)}
    else{$action=New-ScheduledTaskAction -Execute $record.cli -Argument ('connect '+(Quote-Arg $record.profile)+' -exit')}
    $trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5)) -RepetitionInterval (New-TimeSpan -Minutes 5)
    [void](Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -User $env:USERNAME -RunLevel Highest -Force)
    $script:undo.Add(@{kind='task';name=$name});Save-Journal;Event 'Reconnect task installed (every five minutes)'
}
function Invoke-ManagedServiceControl([string]$Operation,[string]$Name,[int[]]$Codes) {
    $program=Join-Path $env:SystemRoot 'System32\sc.exe'
    $result=Native $program @($Operation,$Name) $Codes -Secret -Timeout 5
    if($result.outputComplete -ne $true -or $result.exitCode -notin $Codes){
        throw 'Managed service control result could not be verified'
    }
    return $result.exitCode
}
function Get-ManagedServiceCommandDigest([string]$CommandLine) {
    if([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine.Length -gt 32767){throw 'Invalid managed service command'}
    return Get-WorkflowBytesSHA256 ([Text.Encoding]::Unicode.GetBytes($CommandLine))
}
function Read-ManagedServiceCommand([string]$Name) {
    $rows=@(Get-CimInstance -ClassName Win32_Service -Filter ("Name='"+$Name+"'") -ErrorAction Stop)
    if($rows.Count -ne 1 -or $rows[0].Name -ine $Name -or $rows[0].PathName -isnot [string]){
        throw 'Managed service registration could not be verified'
    }
    return $rows[0].PathName
}
function Assert-ManagedServiceOwnership([string]$Name) {
    if($Name -notmatch '\AAccessWeaver-(byedpi|proxifyre|zapret|zapret2|goodbyedpi|dnscrypt)\z'){
        throw 'Recovery journal contains an unmanaged service'
    }
    $state=Invoke-ManagedServiceControl 'query' $Name @(0,1060,1072)
    if($state -eq 1060){return}
    if($state -eq 1072){Wait-RecordedServiceAbsent $Name;return}

    $engine=$Name.Substring('AccessWeaver-'.Length)
    $directory=Join-Path $root 'services'
    $config=Join-Path $directory ($engine+'.json')
    $registration=Join-Path $directory ($engine+'.registration')
    $command=Read-ManagedServiceCommand $Name
    $match=[regex]::Match($command,'\A"[^"\r\n]+[\\/]host-([a-f0-9]{64})\.exe" service-host "[^"\r\n]+"( --instance=[a-f0-9]{32})?\z')
    if(-not $match.Success){throw 'Managed service command does not match the protected service host'}
    $hostHash=$match.Groups[1].Value
    $instance=$match.Groups[2].Value
    $hostPath=Join-Path $directory ('host-'+$hostHash+'.exe')
    $expected=(Quote-Arg $hostPath)+' service-host '+(Quote-Arg $config)+$instance
    if($command -cne $expected){throw 'Managed service command does not match the protected service host'}

    foreach($path in @($hostPath,$config)){
        Assert-TrustedItem $path
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if($item.PSIsContainer -or $item.Length -le 0){throw 'Managed service ownership file is invalid'}
    }
    if((Get-FileHash -LiteralPath $hostPath -Algorithm SHA256 -ErrorAction Stop).Hash -ine $hostHash){
        throw 'Managed service host content differs from its registered digest'
    }
    $digest=Get-ManagedServiceCommandDigest $command
    No-Reparse $registration
    if($instance -or (Test-Path -LiteralPath $registration -ErrorAction Stop)){
        Assert-TrustedItem $registration
        $record=Get-Item -LiteralPath $registration -Force -ErrorAction Stop
        if($record.PSIsContainer -or $record.Length -ne 64 -or [IO.File]::ReadAllText($registration) -cne $digest){
            throw 'Managed service command differs from its ownership record'
        }
    }
    return @{name=$Name;commandSHA256=$digest}
}
function Assert-RecordedServiceBinding($Entry) {
    $name=$Entry.name
    if($name -isnot [string] -or $name -notmatch '\AAccessWeaver-(byedpi|proxifyre|zapret|zapret2|goodbyedpi|dnscrypt)\z'){
        throw 'Recovery journal contains an unmanaged service'
    }
    $digest=$Entry.commandSHA256
    if($null -ne $digest -and ($digest -isnot [string] -or $digest -cnotmatch '\A[A-F0-9]{64}\z')){
        throw 'Recovery journal contains an invalid service command digest'
    }
    $state=Invoke-ManagedServiceControl 'query' $name @(0,1060,1072)
    if($state -eq 1060){return $state}
    if(-not $digest){throw 'Recovery journal has no service binding; use explicit managed removal'}
    if($state -eq 1072){
        Wait-RecordedServiceAbsent $name
        return 1060
    }
    if((Get-ManagedServiceCommandDigest (Read-ManagedServiceCommand $name)) -cne $digest){
        throw 'Recovery journal does not match the current managed service'
    }
    return $state
}
function Wait-RecordedServiceStopped([string]$Name) {
    $service=[ServiceProcess.ServiceController]::new($Name)
    try {$service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))}
    finally {$service.Dispose()}
}
function Wait-RecordedServiceAbsent([string]$Name) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    do {
        if((Invoke-ManagedServiceControl 'query' $Name @(0,1060,1072)) -eq 1060){return}
        Start-Sleep -Milliseconds 250
    }while($clock.Elapsed.TotalSeconds -lt 5)
    throw 'Managed service removal is pending; release open service handles and retry'
}
function Remove-RecordedService([string]$Name,$Entry) {
    if($Name -notmatch '\AAccessWeaver-(byedpi|proxifyre|zapret|zapret2|goodbyedpi|dnscrypt)\z'){
        throw 'Recovery journal contains an unmanaged service'
    }
    if($null -eq $Entry -or $Entry.name -cne $Name){throw 'Managed service removal has no verified binding'}
    $state=Assert-RecordedServiceBinding $Entry
    if($state -eq 1060){return}
    if($state -eq 0){
        $stopped=Invoke-ManagedServiceControl 'stop' $Name @(0,1060,1062,1072)
        if($stopped -eq 0){Wait-RecordedServiceStopped $Name}
        if($stopped -in @(0,1062)){[void](Invoke-ManagedServiceControl 'delete' $Name @(0,1060,1072))}
    }
    Wait-RecordedServiceAbsent $Name
}
function Remove-Method([string]$engine,[switch]$OwnedOnly) {
    if($engine -eq 'wiresock'){
        $recordPath=Join-Path $root 'profiles\wiresock-owned.json'
        $owned=$null
        if(Test-Path -LiteralPath $recordPath -ErrorAction Stop){$owned=Read-OwnedWireSockProfile $recordPath}
        Remove-WireSockRefreshTask
        if($owned){
            if($owned.legacy){
                Disconnect-OwnedWireSock $owned
                [void](Native $owned.cli @('uninstall') -Secret)
            }else{
                Remove-ModernWireSockProfile $owned.cli $owned.profile -Disconnect
            }
            Remove-Item -LiteralPath $recordPath -ErrorAction Stop
            if(Test-Path -LiteralPath $recordPath -ErrorAction Stop){throw 'WireSock ownership record removal could not be verified'}
        }
        return
    }
    if($engine -eq 'drover'){Restore-Drover;return}
    if($engine -eq 'windivert'){
        foreach($dependent in @('AccessWeaver-zapret','AccessWeaver-zapret2','AccessWeaver-goodbyedpi')){if((Get-Service $dependent -ErrorAction SilentlyContinue).Status -eq 'Running'){throw 'Remove packet-engine services before WinDivert'}}
        foreach($driver in @(Get-CimInstance Win32_SystemDriver|Where-Object {$_.Name -match '^WinDivert[a-zA-Z0-9]*$'})){
            $path=([string]$driver.PathName).Trim('"') -replace '^\\\?\?\\',''
            if([string]::IsNullOrWhiteSpace($path)){if($OwnedOnly){continue};throw 'Cannot verify WinDivert driver ownership without its binary path'}
            if(-not (Under $path (Join-Path $root 'components'))){if($OwnedOnly){continue};throw 'WinDivert is owned by another application; remove it through that application after checking its dependents'}
            No-Reparse $path
            # WinDivert can unregister itself when its final handle closes.
            [void](Native (Join-Path $env:SystemRoot 'System32\sc.exe') @('stop',$driver.Name) @(0,1060,1062));[void](Native (Join-Path $env:SystemRoot 'System32\sc.exe') @('delete',$driver.Name) @(0,1060));Event ('Removed managed WinDivert driver: '+$driver.Name)
        };return
    }
    $name='AccessWeaver-'+$engine
    $entry=Assert-ManagedServiceOwnership $name
    $firewallNames=@()
    if($engine -cin @('byedpi','proxifyre')){
        $firewallNames=@($name+'-Inbound';$name+'-Outbound')
        foreach($ruleName in $firewallNames){[void](Get-ManagedFirewallRule $ruleName)}
    }
    if($engine -eq 'byedpi'){Remove-Method 'proxifyre';Restore-Drover}
    if($engine -eq 'dnscrypt' -and (Test-Path -LiteralPath (Join-Path $root 'profiles\dns-original.json'))){Restore-DNS}
    if($entry){Remove-RecordedService $name -Entry $entry}
    foreach($ruleName in $firewallNames){Remove-ManagedFirewallRule $ruleName}
    Event ('Managed method removed: '+$engine)
}
function Remove-All {
    # Keep every managed resource available until adapter DNS and DoH policy
    # have been restored and independently read back by Restore-DNS.
    $snapshot=Join-Path $root 'profiles\dns-original.json'
    if(Test-Path -LiteralPath $snapshot -ErrorAction Stop){Restore-DNS}
    foreach($engine in @('proxifyre','byedpi','zapret','zapret2','goodbyedpi','wiresock')){Remove-Method $engine}
    Remove-Method 'windivert' -OwnedOnly
    Remove-Method 'dnscrypt';Restore-Drover
}
function Get-WireSockMsiProductCode($record,[string]$program,[switch]$BundleOwnsUninstall) {
    $failure='Registered WireSock MSI uninstall command does not match its product code'
    $key=[guid]::Empty
    if(-not [guid]::TryParseExact([string]$record.PSChildName,'B',[ref]$key) -or $key -eq [guid]::Empty){
        throw $failure
    }
    # A hidden package can omit its command because the verified bundle
    # owns removal. Its registry key still identifies the readback record.
    if($BundleOwnsUninstall -and [string]::IsNullOrWhiteSpace([string]$record.UninstallString)){
        return $key.ToString('B')
    }
    $command=[Environment]::ExpandEnvironmentVariables([string]$record.UninstallString).Trim()
    $escapedProgram=[regex]::Escape($program)
    $msiCommand='(?i)^(?:msiexec(?:\.exe)?|"'+$escapedProgram+'"|'+$escapedProgram+')[ \t]+/[ix][ \t]*(\{[0-9a-f-]{36}\})$'
    $identity=[regex]::Match($command,$msiCommand,[Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $product=[guid]::Empty
    if(-not $identity.Success -or -not [guid]::TryParseExact($identity.Groups[1].Value,'B',[ref]$product) -or
        $product -ne $key){
        throw $failure
    }
    return $product.ToString('B')
}
function Test-WireSockServicesPresent([string[]]$names) {
    $present=$false
    try {
        Get-Service -ErrorAction Stop | ForEach-Object {
            try {if($_.ServiceName -in $names){$present=$true}}
            finally {if($_ -is [IDisposable]){$_.Dispose()}}
        }
    } catch {throw 'Vendor service removal could not be verified'}
    return $present
}
function Get-WireSockUninstallRegistrations([string[]]$names) {
    foreach($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
        if(-not (Test-Path -LiteralPath $base -ErrorAction Stop)){continue}
        foreach($entry in Get-ChildItem -LiteralPath $base -ErrorAction Stop){
            $record=Get-ItemProperty -LiteralPath $entry.PSPath -ErrorAction Stop
            if($record.DisplayName -in $names){$record}
        }
    }
}
function Uninstall-WireSockProduct {
    $cli=WireSock-CLI
    $knownPaths=@(Get-WireSockCLIPaths)
    $legacy=$cli -and $cli -ieq $knownPaths[2]
    $names=if($legacy){@('WireSock VPN Client','WireSock VPN Client for Windows')}else{@('WireSock Secure Connect')}
    $paths=if($legacy){@($knownPaths[2])}else{@($knownPaths[0],$knownPaths[1])}
    $serviceNames=if($legacy){@('wiresock-client-service')}else{@('WireSockAppService','WireSockConnectService')}
    $registrationFailure='Vendor uninstall registrations could not be verified'
    try {$records=@(Get-WireSockUninstallRegistrations $names)}catch{throw $registrationFailure}
    if($records.Count -eq 0){throw 'No supported registered WireSock product found; use Windows Apps settings for an unrecognized package'}
    $msiexec=Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $record=$records[0]
    $paired=$records.Count -gt 1
    if($paired){
        # A modern vendor bundle can register a hidden MSI as well as its
        # public uninstall entry. Only the bundle can manage its package chain.
        $bundles=@($records | Where-Object {$_.WindowsInstaller -ne 1 -and $_.SystemComponent -ne 1 -and
            -not [string]::IsNullOrWhiteSpace($_.BundleCachePath) -and -not [string]::IsNullOrWhiteSpace($_.BundleProviderKey)})
        $hiddenMSIs=@($records | Where-Object {$_.WindowsInstaller -eq 1 -and $_.SystemComponent -eq 1})
        if($legacy -or $records.Count -ne 2 -or $bundles.Count -ne 1 -or $hiddenMSIs.Count -ne 1){
            throw 'Multiple registered WireSock products matched; select the intended product in Windows Apps settings'
        }
        $record=$bundles[0]
        [void](Get-WireSockMsiProductCode $hiddenMSIs[0] $msiexec -BundleOwnsUninstall)
    }
    $packageCache=Join-Path $env:ProgramData 'Package Cache'
    $command=[Environment]::ExpandEnvironmentVariables([string]$record.UninstallString).Trim()
    if($record.WindowsInstaller -eq 1){
        $program=$msiexec
        $product=Get-WireSockMsiProductCode $record $program
        $arguments=@('/x',$product,'/qn','/norestart')
        $codes=@(0,1605,3010,1641)
    }else{
        $program=$null
        if($command -match '^"([^"]+\.exe)"(?:[ \t]|$)'){$program=$matches[1]}
        elseif($command -match '^([^"]+?\.exe)(?:[ \t]|$)'){$program=$matches[1]}
        if($program -notmatch '^[A-Za-z]:\\[^:*?"<>|]+\.exe$' -or
            (-not (Under $program $env:ProgramFiles) -and -not (Under $program $packageCache))){
            throw 'Registered vendor uninstaller is outside protected installation storage'
        }
        if($paired -and ($program -ine $record.BundleCachePath -or -not (Under $program $packageCache))){
            throw 'Registered vendor uninstaller is outside protected installation storage'
        }
        No-Reparse $program
        $signature=Get-AuthenticodeSignature -LiteralPath $program
        $digest=(Get-FileHash -LiteralPath $program -Algorithm SHA256).Hash.ToLowerInvariant()
        if(-not (Test-InstallerPublisher 'wiresock' $signature $digest $inputData.nativeArchitecture)){
            # Burn restores the inner signature when it caches the engine.
            # Use its exact release-derived hash only for the validated pair.
            $architecture=$inputData.nativeArchitecture
            if(-not $paired -or $architecture -cnotin @('amd64','arm64') -or
                $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
                $digest -cne (WireSock-InstallerPlan $architecture).cachedEngineSHA256){
                throw 'Vendor uninstaller publisher signature could not be verified'
            }
        }
        $arguments=@('/uninstall','/quiet','/norestart')
        $codes=@(0,3010,1641)
    }
    Remove-WireSockRefreshTask
    try{Remove-Method 'wiresock'}catch{Event 'Managed profile cleanup could not complete; continuing with the explicitly requested vendor uninstall'}
    [void](Native $program $arguments $codes -Timeout 900)
    if($script:rebootRequired){
        Event ('Vendor uninstall requires a Windows restart: '+$record.DisplayName)
        return @{product=$record.DisplayName;rebootRequired=$true}
    }
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    do {
        $cliPresent=$false
        try {
            foreach($path in $paths){
                if(Test-Path -LiteralPath $path -ErrorAction Stop){$cliPresent=$true}
            }
        } catch {throw 'Vendor CLI removal could not be verified'}
        $servicesPresent=Test-WireSockServicesPresent $serviceNames
        $registrationPresent=$false
        try {
            foreach($entry in $records){
                if(Test-Path -LiteralPath $entry.PSPath -ErrorAction Stop){$registrationPresent=$true}
            }
            # A replacement registration can use a different key. Check both
            # views again after the originally selected registrations disappear.
            if(-not $registrationPresent){
                $registrationPresent=@(Get-WireSockUninstallRegistrations $names).Count -gt 0
            }
        } catch {throw $registrationFailure}
        if(-not ($cliPresent -or $registrationPresent -or $servicesPresent) -or $deadline.Elapsed.TotalSeconds -ge 30){break}
        Start-Sleep -Milliseconds 500
    } while($true)
    if($cliPresent){throw 'Vendor CLI remains installed; inspect vendor uninstall logs'}
    if($registrationPresent){throw 'Vendor uninstall registration remains; inspect vendor uninstall logs'}
    if($servicesPresent){throw 'Vendor services remain installed; inspect vendor uninstall logs'}
    $owned=Join-Path $root 'profiles\wiresock-owned.json'
    try {
        if(Test-Path -LiteralPath $owned){Remove-Item -LiteralPath $owned -ErrorAction Stop}
        if(Test-Path -LiteralPath $owned){throw 'Ownership record still present'}
    } catch {throw 'Vendor uninstall completed but the managed ownership record could not be retired'}
    Event ('Vendor uninstall completed: '+$record.DisplayName)
    return @{product=$record.DisplayName;rebootRequired=$false}
}
function Packet-Arguments([string]$engine,[string[]]$arguments) {
    if($engine -in @('zapret','zapret2') -and -not @($arguments|Where-Object {$_ -match '^--wf-(tcp|udp|raw)(-out|-in)?(=|$)'}).Count){
        $capture=if($engine -eq 'zapret2'){@('--wf-tcp-out=80,443','--wf-udp-out=443,50000-50100')}else{@('--wf-tcp=80,443','--wf-udp=443,50000-50100')}
        return @($capture)+@($arguments)
    }
    return @($arguments)
}
function Assert-ByeDPIArguments([string[]]$arguments) {
    $reserved=@('--ip','--port','--daemon','--daemonize','--service','--transparent')
    foreach($arg in $arguments){
        $arg=[string]$arg
        $name=($arg -split '=',2)[0]
        $blocked=$arg -eq '--' -or $arg.StartsWith('@',[StringComparison]::Ordinal) -or $arg -cmatch '^-[a-zA-Z].+' -or $name -cin @('-i','-p','-D','-E')
        foreach($option in $reserved){if($name.StartsWith('--',[StringComparison]::Ordinal) -and $option.StartsWith($name,[StringComparison]::Ordinal)){$blocked=$true}}
        if($blocked){throw 'Managed ByeDPI installation reserves listener/process options; use full strategy option names without option terminators or argument files'}
    }
}
function Install-Method([string]$ScannedEngineSHA256,[string[]]$ScannedLuaSHA256) {
    if($r.engine -eq 'byedpi'){Assert-ByeDPIArguments @($r.args)}
    if(($r.engine -eq 'wiresock' -and $r.mode -eq 'standard') -or ($r.engine -eq 'byedpi' -and $r.mode -eq 'dll')){if(-not @(Discord-Directories).Count){throw 'Install stable Discord before selecting the Discord DLL setup mode'}}
    if($r.engine -ne 'dnscrypt' -and $r.dns -and $r.dns -ne 'unchanged' -and -not $script:dnsConfigured){Configure-DNS $r.dns}
    switch($r.engine) {
        'wiresock' {$config=Make-Config;$status=Connect-WireSock $config;if($r.mode -eq 'standard'){$byedpi=Ensure-Asset 'byedpi';Install-EngineService 'byedpi' $byedpi @('--ip','127.0.0.1','--port','1080','--split','2');Firewall 'byedpi' $byedpi;Install-Drover};if($r.refresh){$r | Add-Member -NotePropertyName enabled -NotePropertyValue $true -Force;Refresh-Task};return @{configPath=$config;status=$status}}
        'byedpi' {$binary=Ensure-Asset 'byedpi';$arguments=@('--ip','127.0.0.1','--port','1080');if($r.args){$arguments+=@($r.args)}else{$arguments+=@('--split','2')};if($r.mode -eq 'once'){Event 'One-shot ByeDPI running; cancel this workflow to stop it';[void](Native $binary $arguments -Timeout 86400)}else{Install-EngineService 'byedpi' $binary $arguments;Firewall 'byedpi' $binary;if($r.mode -eq 'dll'){Install-Drover}elseif($r.mode -ne 'service'){Setup-ProxiFyre '127.0.0.1:1080'}}}
        {$_ -in @('zapret','zapret2','goodbyedpi')} {
            foreach($name in @('zapret','zapret2','goodbyedpi')){if($name -ne $r.engine -and (Get-Service ('AccessWeaver-'+$name) -ErrorAction SilentlyContinue).Status -eq 'Running'){throw 'Stop other packet engines before installing this method'}}
            if($ScannedEngineSHA256 -and (Get-Service -Name ('AccessWeaver-'+$r.engine) -ErrorAction SilentlyContinue)){
                throw 'Remove the existing managed engine service before installing a scanned strategy'
            }
            if($ScannedEngineSHA256 -and $r.engine -eq 'zapret2' -and @($ScannedLuaSHA256).Count -ne 2){
                throw 'Zapret2 scan did not verify both Lua libraries'
            }
            $binary=Ensure-Asset $r.engine $ScannedEngineSHA256 $ScannedLuaSHA256
            $arguments=@($r.args)
            if(-not $arguments.Count){if($r.engine -eq 'goodbyedpi'){$arguments=@('-5')}else{throw 'Select a tested preset or supply strategy arguments'}}
            $arguments=@(Packet-Arguments $r.engine $arguments)
            if($r.engine -eq 'zapret2' -and ($ScannedLuaSHA256 -or -not @($arguments | Where-Object {$_ -match '^--lua-init(=|$)'}).Count)){
                $initializers=@(Get-ZapretLuaBundle (Split-Path -Parent $binary) $ScannedLuaSHA256 | ForEach-Object {'--lua-init=@'+$_.path})
                $arguments=$initializers+$arguments
            }
            $list=Join-Path (Split-Path -Parent $binary) 'accessweaver-hostlist.txt'
            if($r.engine -eq 'goodbyedpi' -and -not $r.domains -and -not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $binary) 'accessweaver-hostlist.saved.txt'))){$r|Add-Member -NotePropertyName domains -NotePropertyValue @('discord.com','discord.gg','discordapp.com','discordapp.net','discord.media','roblox.com','wattpad.com') -Force}
            Save-Hostlist
            if($r.engine -eq 'goodbyedpi'){if($r.enabled){$arguments+=@('--blacklist',$list)}}else{$filter='--hostlist-exclude='+$list;$expanded=@();foreach($arg in $arguments){if($arg -eq '--new'){$expanded+=@($filter)};$expanded+=@($arg)};$arguments=$expanded+@($filter)}
            if($r.mode -eq 'once'){Event 'One-shot engine started; cancel the running workflow to stop it';[void](Native $binary $arguments -Timeout 86400)}else{Install-EngineService $r.engine $binary $arguments}
        }
        'dnscrypt' {Configure-DNS 'dnscrypt'}
        {$_ -in @('ndisapi','vcredist')} {
            Install-Prerequisite $r.engine
            if($script:rebootRequired){return @{prerequisite=$r.engine;rebootRequired=$true}}
            Assert-PrerequisiteRegistered $r.engine
        }
        default {throw 'Unsupported install component'}
    }
    return @{installed=$r.engine}
}
function Find-SplitCordApp {
    # electron-builder derives this NSIS key from the vendor app ID com.splitcord.turkey.
    $installKey='30120f3b-3e88-5c75-afec-3de1a3155a97'
    $registered=@(foreach($registry in @('HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node')){
        $key=Join-Path $registry $installKey
        if(-not (Test-Path -LiteralPath $key -ErrorAction Stop)){continue}
        $location=(Get-ItemProperty -LiteralPath $key -ErrorAction Stop).InstallLocation
        if($location -isnot [string] -or $location.Length -gt 4096 -or
            $location -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|\x00-\x1f]+\z'){continue}
        $app=Join-Path ([IO.Path]::GetFullPath($location)) 'SplitCord-Turkey.exe'
        No-Reparse $app
        if(Test-Path -LiteralPath $app -PathType Leaf -ErrorAction Stop){$app}
    })
    $registered=@($registered | Sort-Object -Unique)
    if($registered.Count -gt 1){throw 'Multiple registered SplitCord installations matched'}
    if($registered.Count -eq 1){return $registered[0]}

    $bases=@((Join-Path $env:LOCALAPPDATA 'Programs'),$env:ProgramFiles,${env:ProgramFiles(x86)})
    foreach($base in @($bases | Where-Object {$_} | Select-Object -Unique)){
        $directory=Join-Path $base 'SplitCord-Turkey'
        No-Reparse $directory
        if(Test-Path -LiteralPath $directory -PathType Container -ErrorAction Stop){
            $files=@(Get-ChildItem -LiteralPath $directory -Recurse -Filter 'SplitCord-Turkey.exe' -File -ErrorAction Stop)
            if($files.Count -gt 1){throw 'Multiple SplitCord executables matched in the installation directory'}
            if($files.Count -eq 1){No-Reparse $files[0].FullName;return $files[0].FullName}
        }
    }
    return $null
}
function Find-App([string]$variant) {
    if($variant -in @('discord','discord-ptb')){$dirs=@(Discord-Directories $variant);if($dirs.Count){return (Join-Path $dirs[0] $(if($variant -eq 'discord'){'Discord.exe'}else{'DiscordPTB.exe'}))};return $null}
    if($variant -eq 'splitcord'){return Find-SplitCordApp}
    throw 'Unknown application variant'
}
function Wait-App([string]$variant,[bool]$installed,[int]$seconds=120,[string]$previousImage) {
    $deadline=[DateTime]::UtcNow.AddSeconds($seconds)
    do {
        $app=Find-App $variant
        if($installed -and $app){
            No-Reparse $app
            if(Test-Path -LiteralPath $app -PathType Leaf -ErrorAction Stop){return $app}
        }elseif(-not $installed -and -not $app -and
                 (-not $previousImage -or -not (Test-Path -LiteralPath $previousImage -ErrorAction Stop))){return}
        Start-Sleep -Milliseconds 500
    }while([DateTime]::UtcNow -lt $deadline)
    throw 'Application installation state did not reach the expected result; inspect installer logs'
}
function Get-SplitCordInstaller {
    $repository='https://github.com/cagritaskn/SplitCord-Turkey'
    $release=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri 'https://api.github.com/repos/cagritaskn/SplitCord-Turkey/releases/latest'
    $tag=$release.tag_name
    if($release.draft -ne $false -or $release.draft -isnot [bool] -or
        $release.prerelease -ne $false -or $release.prerelease -isnot [bool] -or
        $tag -isnot [string] -or $tag.Length -gt 64 -or $tag -cnotmatch '\Av?[0-9]+\.[0-9]+\.[0-9]+\z' -or
        $release.assets -isnot [array] -or $release.assets.Count -gt 100){
        throw 'SplitCord release metadata is invalid'
    }
    $name='SplitCord-Turkey-Setup-'+$tag.TrimStart('v')+'.exe'
    $assets=@($release.assets | Where-Object {$_.name -is [string] -and $_.name -ceq $name})
    if($assets.Count -ne 1 -or $assets[0].state -cne 'uploaded'){throw 'Expected one uploaded SplitCord installer for the selected release'}
    $asset=$assets[0]
    $url=$repository+'/releases/download/'+$tag+'/'+$name
    if($asset.browser_download_url -isnot [string] -or $asset.browser_download_url -cne $url){throw 'SplitCord installer URL does not match the selected release'}
    $hash=[string]$r.sha256
    if($null -ne $asset.digest -and $asset.digest -cne ''){
        if($asset.digest -isnot [string] -or $asset.digest -cnotmatch '\Asha256:[a-fA-F0-9]{64}\z'){throw 'SplitCord installer digest is invalid'}
        $digest=$asset.digest.Substring(7)
        if($hash -and $hash -ine $digest){throw 'SplitCord installer digest conflicts with the requested SHA-256'}
        $hash=$digest
    }
    if($hash -notmatch '\A[a-fA-F0-9]{64}\z'){throw 'SplitCord installer requires a published or explicitly supplied SHA-256'}
    return @{url=$url;hash=$hash}
}
function Wait-SplitCordService([string]$App,[int]$Seconds=20) {
    $name='SplitCordDpiService'
    $binary=if($App){Join-Path (Split-Path -Parent $App) 'resources\service-installer\SplitCordService.exe'}
    if($binary){
        No-Reparse $binary
        if(-not (Test-Path -LiteralPath $binary -PathType Leaf -ErrorAction Stop)){throw 'SplitCord service executable is missing'}
    }
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    do {
        # The shared native runner marks tool calls as potential effects.
        # This operation only queries the SCM, including on an absent-client retry.
        $previousEffects=$script:externalEffectsPending
        try {$state=Invoke-ManagedServiceControl 'query' $name @(0,1060,1072)}
        finally {$script:externalEffectsPending=$previousEffects}
        if(-not $binary -and $state -eq 1060){return}
        if($binary -and $state -eq 0){
            $command=Read-ManagedServiceCommand $name
            if($command -ine $binary -and $command -ine ('"'+$binary+'"')){
                throw 'SplitCord service registration differs from the installed application'
            }
            $service=Get-Service -Name $name -ErrorAction Stop
            try {if($service.Status -eq 'Running'){return}}
            finally {$service.Dispose()}
        }
        if($deadline.Elapsed.TotalSeconds -ge $Seconds){break}
        Start-Sleep -Milliseconds 250
    } while($true)
    if($binary){throw 'SplitCord service did not reach Running'}
    throw 'SplitCord service removal could not be verified'
}
function Save-ApplicationEffectBoundary {
    # Persist the attempt before allowing an irreversible desktop action.
    $previous=$script:externalEffectsPending
    $script:externalEffectsPending=$true
    try {Save-Journal}catch {
        $script:externalEffectsPending=$previous
        throw
    }
}
function Install-App([string]$variant,[switch]$Reinstall) {
    Require-DesktopUser
    if($Reinstall -and ($variant -cne 'discord' -or $r.clean -or $r.downloadUrl -or $r.sha256 -or $r.configPath -or $r.bundlePath)){
        throw 'Discord reinstall uses the official signed installer and fixed desktop-user inputs'
    }
    $originalApp=$null;$originalAppDigest=$null
    if($Reinstall){
        $originalApp=Find-App $variant
        if(-not $originalApp){throw 'Stable Discord is not installed; use Install Discord instead'}
        $originalAppDigest=Get-AppExecutableDigest $originalApp
    }
    if($variant -notin @('discord','discord-ptb','splitcord')){throw 'Choose Discord, Discord PTB or SplitCord'}
    if($variant -eq 'splitcord'){
        $installer=Get-SplitCordInstaller
        $file=Join-Path $root 'downloads\splitcord-setup.exe'
        $verifiedHash=Download $installer.url $installer.hash $file -ReturnVerifiedHash
    }else {
        $architecture=[string]$inputData.nativeArchitecture
        if($architecture -cnotin @('amd64','arm64')){throw 'Native Windows architecture is unavailable or unsupported for Discord installation'}
        $channel=if($variant -eq 'discord-ptb'){'ptb'}else{'stable'}
        $installerArch=if($channel -eq 'stable' -and $architecture -eq 'arm64'){'arm64'}else{'x64'}
        $url='https://discord.com/api/downloads/distributions/app/installers/latest?channel='+$channel+'&platform=win&arch='+$installerArch
        $file=Join-Path $root ('downloads\'+$variant+'-setup.exe')
        $verifiedHash=Download $url '' $file -Signed -Publisher discord -ReturnVerifiedHash
    }
    $cleanPTB=$r.clean -and $variant -eq 'discord-ptb'
    $stableBeforeSetup=$null;$stableBeforeSetupDigest=$null;$ptbBeforeSetupDigest=$null
    # Hold the verified download through any preparatory removal and process creation.
    No-Reparse $file
    try {$lockedInstaller=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}
    catch {throw 'Staged application installer could not be opened for verification'}
    try {
        $stagedHash=(Get-FileHash -InputStream $lockedInstaller -Algorithm SHA256).Hash
        if($verifiedHash -isnot [string] -or $stagedHash -ine $verifiedHash){throw 'Staged application installer differs from the verified download'}
        $existingApp=Find-App $variant
        $previouslyInstalled=[bool]$existingApp
        if($Reinstall){
            if($existingApp -ine $originalApp){throw 'Stable Discord changed before reinstall; review the current installation'}
            [void](Remove-App $variant $originalApp $originalAppDigest)
        }
        if($cleanPTB){
            $stableBeforeSetup=Find-App 'discord'
            if($stableBeforeSetup){
                $stableBeforeSetupDigest=Get-AppExecutableDigest $stableBeforeSetup
                if($existingApp){$ptbBeforeSetupDigest=Get-AppExecutableDigest $existingApp}
            }
        }
        $installerArgs=if($variant -eq 'splitcord'){@('/S')}else{@('-s')}
        if($Reinstall -and ((Find-App $variant) -or (Test-Path -LiteralPath $originalApp -ErrorAction Stop))){
            throw 'Stable Discord reappeared before replacement setup; review the current installation'
        }
        Save-ApplicationEffectBoundary
        [void](Native $file $installerArgs -Timeout 900 -StartGuard $lockedInstaller)
    } finally {$lockedInstaller.Dispose()}
    $installedApp=Wait-App $variant $true 180
    $installedDigest=Get-AppExecutableDigest $installedApp
    if($variant -eq 'splitcord'){
        Wait-SplitCordService $installedApp
        if((Find-App $variant) -ine $installedApp -or (Get-AppExecutableDigest $installedApp) -ine $installedDigest){
            throw 'SplitCord changed during service verification'
        }
    }
    if($cleanPTB){
        # A previously installed PTB executable alone cannot confirm replacement.
        if($ptbBeforeSetupDigest -and $existingApp -ieq $installedApp -and $ptbBeforeSetupDigest -ieq $installedDigest){
            throw 'Discord PTB setup did not replace the existing executable; stable Discord was preserved'
        }
        if($stableBeforeSetup){[void](Remove-App 'discord' $stableBeforeSetup $stableBeforeSetupDigest)}
        elseif(Find-App 'discord'){throw 'Stable Discord appeared during PTB setup; review the current installation'}
        $confirmedApp=Wait-App $variant $true 30
        if($confirmedApp -ine $installedApp -or (Get-AppExecutableDigest $confirmedApp) -ine $installedDigest){
            throw 'Discord PTB changed during stable client cleanup; review the current installation'
        }
    }
    if($Reinstall){
        $confirmedApp=Find-App $variant
        if($confirmedApp -ine $installedApp -or (Get-AppExecutableDigest $confirmedApp) -ine $installedDigest){
            throw 'Stable Discord changed during replacement verification'
        }
        Event 'Stable Discord reinstalled in the desktop session'
        return @{application=$variant;installed=$true;previouslyInstalled=$true;reinstalled=$true}
    }
    if($previouslyInstalled){Event ('Application was already present before setup: '+$variant)}
    else{Event ('Application installed: '+$variant)}
    return @{application=$variant;installed=$true;previouslyInstalled=$previouslyInstalled}
}
function Get-AppUninstaller([string]$variant,[string]$app) {
    if($variant -in @('discord','discord-ptb')){
        $folder=if($variant -eq 'discord'){'Discord'}else{'DiscordPTB'}
        $path=Join-Path $env:LOCALAPPDATA ($folder+'\Update.exe')
        $arguments=@('--uninstall','-s')
        $timeout=300
    }else{
        $directory=Split-Path -Parent $app
        $candidates=@(Get-ChildItem -LiteralPath $directory -Filter 'Uninstall*.exe' -File -ErrorAction Stop)
        if($candidates.Count -ne 1){throw 'Expected exactly one SplitCord uninstaller'}
        $path=$candidates[0].FullName
        $arguments=@('/S')
        $timeout=600
    }
    No-Reparse $path
    if(-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)){throw 'Application uninstaller not found'}
    return @{path=$path;arguments=$arguments;timeout=$timeout}
}
function Get-AppExecutableDigest([string]$path) {
    No-Reparse $path
    $file=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($file.Length -le 0 -or $file.Length -gt 512MB){throw 'Application executable exceeds inspection limits'}
        return (Get-FileHash -InputStream $file -Algorithm SHA256 -ErrorAction Stop).Hash
    } finally {$file.Dispose()}
}
function Remove-App([string]$variant,[string]$expectedApp,[string]$expectedAppDigest) {
    Require-DesktopUser
    $app=Find-App $variant
    if($expectedApp -and $app -ine $expectedApp){throw 'Application installation changed before removal'}
    if(-not $app){
        if($variant -eq 'splitcord'){Wait-SplitCordService '' 0}
        return $false
    }
    $appDigest=Get-AppExecutableDigest $app
    if($expectedAppDigest -and $appDigest -ine $expectedAppDigest){throw 'Application installation changed before removal'}
    $uninstaller=Get-AppUninstaller $variant $app
    $digest=Get-AppExecutableDigest $uninstaller.path
    Stop-AppProcesses $variant $app
    if((Find-App $variant) -ine $app -or (Get-AppExecutableDigest $app) -ine $appDigest){
        throw 'Application installation changed before uninstall launch'
    }
    $confirmed=Get-AppUninstaller $variant $app
    if($confirmed.path -ine $uninstaller.path){throw 'Application uninstaller changed before launch'}
    $guard=[IO.File]::Open($confirmed.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($guard.Length -le 0 -or $guard.Length -gt 512MB -or
            (Get-FileHash -InputStream $guard -Algorithm SHA256 -ErrorAction Stop).Hash -cne $digest){
            throw 'Application uninstaller changed before launch'
        }
        $base=Get-AppProcessBase $variant
        $names=@(Get-AppProcessNames $base $app)
        if(-not (Test-AppProcessesExited $base $app $names)){
            throw 'Application process exit could not be verified before uninstall; close the client and retry'
        }
        Save-ApplicationEffectBoundary
        [void](Native $confirmed.path $confirmed.arguments -Timeout $confirmed.timeout -StartGuard $guard)
    } finally {$guard.Dispose()}
    Wait-App $variant $false 60 $app
    if($variant -eq 'splitcord'){Wait-SplitCordService ''}
    Wait-AppProcessesExited $variant $app
    if((Find-App $variant) -or (Test-Path -LiteralPath $app -ErrorAction Stop)){
        throw 'Application installation reappeared during uninstall verification'
    }
    Event ('Application uninstalled: '+$variant)
    return $true
}
function Get-AppProcessBase([string]$variant) {
    if($variant -in @('discord','discord-ptb')){
        $folder=if($variant -eq 'discord'){'Discord'}else{'DiscordPTB'}
        $base=Join-Path $env:LOCALAPPDATA $folder
        No-Reparse $base
        return $base
    }
}
function Test-AppImagePath([string]$path,[string]$base,[string]$app) {
    if(-not $path){return $false}
    if($base){
        return (Under $path $base) -and ([IO.Path]::GetFileName($path) -in @('Discord.exe','DiscordPTB.exe','Update.exe','crashpad_handler.exe'))
    }
    return [bool]($app -and $path -ieq $app)
}
function Get-AppProcessMatch($process,[string]$base,[string]$app,[string[]]$names) {
    $image=$null
    try {$image=$process.Path}catch{}
    if($image -is [string] -and -not [string]::IsNullOrWhiteSpace($image)){
        return (Test-AppImagePath $image $base $app)
    }
    $name=$null
    try {$name=$process.ProcessName}catch{}
    if($name -is [string] -and -not [string]::IsNullOrWhiteSpace($name) -and $name -notin $names){
        return $false
    }
    try {
        $exited=$process.HasExited
        if($exited -is [bool] -and $exited){return $false}
    }catch{}
    # A potentially matching process without a readable image remains unresolved.
    return $null
}
function Get-AppProcessNames([string]$base,[string]$app) {
    if($base){return @('Discord','DiscordPTB','Update','crashpad_handler')}
    if($app){return [IO.Path]::GetFileNameWithoutExtension($app)}
}
function Test-AppProcessesExited([string]$base,[string]$app,[string[]]$names) {
    $processes=@(Get-Process -ErrorAction Stop)
    try {
        foreach($process in $processes){
            $match=Get-AppProcessMatch $process $base $app $names
            if($null -eq $match){return $false}
            if(-not $match){continue}
            $exited=$null
            try {$exited=$process.HasExited}catch{}
            if($exited -isnot [bool] -or -not $exited){return $false}
        }
        return $true
    } finally {
        foreach($process in $processes){
            if($process -is [IDisposable]){$process.Dispose()}
        }
    }
}
function Wait-AppProcessesExited([string]$variant,[string]$app,[int]$seconds=10) {
    $base=Get-AppProcessBase $variant
    $names=@(Get-AppProcessNames $base $app)
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        if(Test-AppProcessesExited $base $app $names){return}
        if($timer.Elapsed.TotalSeconds -ge $seconds){break}
        Start-Sleep -Milliseconds 250
    } while($true)
    throw 'Application process exit could not be verified after uninstall'
}
function Stop-AppProcesses([string]$variant,[string]$app) {
    $base=Get-AppProcessBase $variant
    if(-not $base -and -not $app){$app=Find-App $variant}
    $names=@(Get-AppProcessNames $base $app)
    if(-not $names.Count){return}
    $current=[Diagnostics.Process]::GetCurrentProcess()
    try {$sessionId=$current.SessionId} finally {$current.Dispose()}
    $matching=[Collections.Generic.List[object]]::new()
    $processes=@(Get-Process -ErrorAction Stop)
    try {
        # Check all observed matches before stopping a client. A shared install
        # may still be in use by a disconnected or concurrent desktop session.
        foreach($process in $processes){
            $match=Get-AppProcessMatch $process $base $app $names
            if($null -eq $match){throw 'A possible application process executable could not be verified'}
            if(-not $match){continue}
            $matching.Add($process)
            $processSession=$null
            try {$processSession=$process.SessionId}catch{}
            if($processSession -isnot [int] -or $processSession -lt 0){throw 'A matching application process session could not be verified'}
            if($processSession -ne $sessionId){throw 'A matching application is running in another Windows session'}
        }
        if($matching.Count -gt 0 -and $r.action -in @('app-install','app-remove','app-reinstall')){
            Save-ApplicationEffectBoundary
        }
        foreach($process in $matching){
            # Terminating a user application is an external effect even if a
            # later stop or uninstall fails; it cannot be rolled back here.
            $script:externalEffectsPending=$true
            try {
                # Cache the native handle on this Process instance. Stop and
                # wait use that instance rather than reopening a numeric PID.
                if($process.Handle -eq [IntPtr]::Zero){throw 'Application process handle is unavailable'}
                $process.Kill()
                if(-not $process.WaitForExit(5000)){throw 'Application exit was not observed'}
            } catch {
                $exited=$null
                try {$exited=$process.HasExited}catch{}
                if($exited -isnot [bool] -or -not $exited){throw 'A matching application process could not be stopped; the operation was not continued'}
            }
        }
    } finally {
        foreach($process in $processes){$process.Dispose()}
    }
}
function Test-AppProcessInSession([string]$path,[int]$sessionId,$processes,[datetime]$StartedAfter=[datetime]::MinValue) {
    $name=[IO.Path]::GetFileNameWithoutExtension($path)
    $running=$false
    $complete=$true
    foreach($process in $processes){
        try {
            if($running){continue}
            $processName=$process.ProcessName
            if($processName -isnot [string] -or [string]::IsNullOrWhiteSpace($processName)){$complete=$false;continue}
            if($processName -ine $name){continue}
            $exited=$process.HasExited
            if($exited -isnot [bool]){$complete=$false;continue}
            if($exited){continue}
            $session=$process.SessionId
            if($session -isnot [int] -or $session -lt 0){$complete=$false;continue}
            if($session -ne $sessionId){continue}
            $image=$process.Path
            if($image -isnot [string] -or [string]::IsNullOrWhiteSpace($image)){$complete=$false;continue}
            if($image -ine $path){continue}
            if($StartedAfter -ne [datetime]::MinValue){
                $started=$process.StartTime
                if($started -isnot [datetime]){$complete=$false;continue}
                if($started.ToUniversalTime() -lt $StartedAfter){continue}
            }
            $exited=$process.HasExited
            if($exited -isnot [bool]){$complete=$false;continue}
            if(-not $exited){$running=$true}
        } catch {
            # Only a confirmed exit can clear an observation failure.
            try {$exited=$process.HasExited}catch{$exited=$null}
            if($exited -isnot [bool] -or -not $exited){$complete=$false}
        } finally {
            if($process -is [IDisposable]){$process.Dispose()}
        }
    }
    if($running){return $true}
    if($complete){return $false}
    return $null
}
function Start-App([string]$variant) {
    Require-DesktopUser
    $app=Find-App $variant;if(-not $app){throw 'Application is not installed'};No-Reparse $app
    $guard=[IO.File]::Open($app,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($guard.Length -le 0 -or $guard.Length -gt 512MB){throw 'Application executable exceeds inspection limits'}
        $current=[Diagnostics.Process]::GetCurrentProcess()
        try {$sessionId=$current.SessionId} finally {$current.Dispose()}
        if($sessionId -eq 0){throw 'Start user applications from the signed-in Windows desktop, not the SYSTEM session'}
        $baseline=Test-AppProcessInSession $app $sessionId @(Get-Process -ErrorAction Stop)
        if($baseline -isnot [bool]){throw 'Application process state could not be inspected before launch'}
        if((Find-App $variant) -ine $app){throw 'Application installation changed before launch'}
        No-Reparse $app
        if($baseline){
            Event 'Application was already running in the desktop session'
            return @{application=$variant;alreadyRunning=$true}
        }
        # Explorer brokers the launch asynchronously in the desktop session.
        # Keep the selected executable open until process observation finishes.
        Save-ApplicationEffectBoundary
        $handoffTime=[DateTime]::UtcNow
        Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList @((Quote-Arg $app)) -WindowStyle Hidden
        $wait=[Diagnostics.Stopwatch]::StartNew()
        do {
            $processes=@(Get-Process -ErrorAction Stop)
            if(Test-AppProcessInSession $app $sessionId $processes $handoffTime){
                if((Find-App $variant) -ine $app){throw 'Application installation changed during launch verification'}
                No-Reparse $app
                Event 'Application process is running in the desktop session'
                return @{application=$variant;alreadyRunning=$false}
            }
            Start-Sleep -Milliseconds 500
        } while($wait.Elapsed.TotalSeconds -lt 10)
        throw 'Application launch could not be verified; inspect its desktop and logs'
    } finally {$guard.Dispose()}
}
function Start-RepairProxy {
    $binary=Ensure-Asset 'byedpi';$name='AccessWeaver-byedpi';$service=Get-Service $name -ErrorAction SilentlyContinue
    if($service){
        $recordPath=Join-Path $root 'services\byedpi.json';if(-not (Test-Path -LiteralPath $recordPath)){throw 'Existing ByeDPI service has no ownership record'}
        $record=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json
        if($record.name -ne $name -or $record.binary -ne $binary){throw 'Existing ByeDPI service configuration differs; remove it before repair'}
        if($service.Status -ne 'Running'){
            $digest=Get-ManagedServiceCommandDigest (Read-ManagedServiceCommand $name)
            $script:undo.Add(@{kind='started-service';name=$name;commandSHA256=$digest})
            Save-Journal
            Start-Service $name
            $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
        }
    }else{Install-EngineService 'byedpi' $binary @('--ip','127.0.0.1','--port','1080','--split','2')}
    Firewall 'byedpi' $binary;$script:repairProxyReady=$true
}
function Preserve-DiscordCache {
    $cache=[IO.Path]::GetFullPath((Join-Path $env:APPDATA 'discord'))
    if(-not (Test-Path -LiteralPath $cache)){return}
    $destination=[IO.Path]::GetFullPath((Join-Path $root ('backups\discord-cache-'+[guid]::NewGuid().ToString('N'))))
    if(-not (Under $cache $env:APPDATA) -or -not (Under $destination (Join-Path $root 'backups'))){throw 'Invalid cache backup path'}
    No-Reparse $cache;No-Reparse $destination
    $script:undo.Add(@{kind='cache';path=$cache;backup=$destination});Save-Journal
    Move-Item -LiteralPath $cache -Destination $destination
    Event 'Discord cache preserved in protected backup storage'
}
function ConvertTo-ScanCygwinPath([string]$Path) {
    if($Path -notmatch '^([A-Za-z]):\\(.+)$'){throw 'Windows blockcheck requires a local drive path'}
    return '/cygdrive/'+$matches[1].ToLowerInvariant()+'/'+($matches[2] -replace '\\','/')
}
function Find-WindowsScanTools([string]$Base,[string]$Pattern) {
    No-Reparse $Base
    $scripts=@(Get-ChildItem -LiteralPath $Base -Recurse -Filter $Pattern -File -ErrorAction Stop | Select-Object -First 2)
    if($scripts.Count -gt 1){throw 'Windows blockcheck bundle contains multiple matching scripts'}
    if($scripts.Count -eq 0){return $null}
    $runtimes=@(Get-ChildItem -LiteralPath $Base -Recurse -Filter 'bash.exe' -File -ErrorAction Stop | Select-Object -First 2)
    if($runtimes.Count -gt 1){throw 'Windows blockcheck bundle contains multiple Bash runtimes'}
    if($runtimes.Count -eq 0){return $null}
    No-Reparse $scripts[0].FullName
    No-Reparse $runtimes[0].FullName
    return @{check=$scripts[0];bash=$runtimes[0]}
}
function Scan-Strategies {
    if($r.engine -notin @('zapret','zapret2')){throw 'Strategy scans require Zapret or Zapret2'}
    $scanParent=[IO.Path]::GetFullPath((Join-Path $root 'temp'))
    $managed=[bool]$inputData.managedPolicy
    $explicitBundle=[bool]$r.bundlePath
    $candidate=Join-Path $scanParent ('scan-'+$r.engine+'-'+[guid]::NewGuid().ToString('N'))
    if($managed -and -not $explicitBundle){throw 'Managed strategy scans require an approved Windows blockcheck bundle'}
    if($explicitBundle){
        if(-not (Test-Path -LiteralPath $r.bundlePath -PathType Container -ErrorAction Stop)){
            throw 'The selected Windows blockcheck bundle directory is unavailable'
        }
        $bundle=[IO.Path]::GetFullPath($r.bundlePath)
        No-Reparse $bundle
        if(Under $candidate $bundle){throw 'Strategy scan staging must be outside the selected bundle'}
    }
    if(Test-Path -LiteralPath $candidate -ErrorAction Stop){throw 'Strategy scan staging path already exists'}
    Protect-Dir $candidate
    try {
        if($explicitBundle){
            # Preserve the bundle layout without mixing cached files into the run.
            Copy-Tree $bundle $candidate -Disposable
            $search=@($candidate)
        }else{
            $binary=Ensure-Asset $r.engine;$dir=Split-Path -Parent $binary
            $search=@((Split-Path -Parent $dir),(Join-Path $env:ProgramFiles 'SplitWire-Turkey\res\zapret')) | Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Container -ErrorAction Stop)}
        }
        $pattern=if($r.engine -eq 'zapret2'){'blockcheck2.sh'}else{'blockcheck.sh'}
        $tools=$null
        foreach($base in $search){
            $tools=Find-WindowsScanTools $base $pattern
            if($tools){break}
        }
        if(-not $tools){throw 'Supply the official Windows blockcheck bundle, including its Cygwin bash runtime'}
        $check=$tools.check
        $bash=$tools.bash
        if(-not (Under $check.FullName $root) -or -not (Under $bash.FullName $root)){
            if(Under $candidate $base){throw 'Strategy scan staging must be outside the discovered bundle'}
            # Copy the discovered tree together so the original relative layout is preserved.
            Copy-Tree $base $candidate -Disposable
            $tools=Find-WindowsScanTools $candidate $pattern
            if(-not $tools){throw 'Copied blockcheck bundle is incomplete'}
            $check=$tools.check
            $bash=$tools.bash
        }
        if($r.engine -eq 'zapret2' -and $inputData.ispHook){
            $hook=Join-Path $check.Directory.FullName 'blockcheck2.d\standard\00-accessweaver-isp.sh'
            if(Under $hook $candidate){
                No-Reparse $hook
                [void][IO.Directory]::CreateDirectory((Split-Path -Parent $hook))
                [IO.File]::WriteAllText($hook,$inputData.ispHook,[Text.UTF8Encoding]::new($false))
            }else{
                Write-Atomic $hook $inputData.ispHook
            }
        }
        $level=if($r.scan){$r.scan}else{'standard'};$scope=@{quick='quick';standard='standard';full='force'}[$level]
        $domains=if($r.targets){$r.targets -join ' '}else{'discord.com discord.gg'}
        if($explicitBundle -or (Under $check.FullName $candidate)){
            $binary=Find-Source $r.engine -SourceRoots @($candidate)
        }
        if(-not $binary){throw 'Windows blockcheck bundle lacks the selected engine'}
        $engineSHA256=Get-WorkflowFileHash $binary
        if(-not $engineSHA256){throw 'Windows blockcheck engine executable could not be verified'}
        $luaSHA256=@()
        if($r.engine -eq 'zapret2'){
            $luaSHA256=@(Get-ZapretLuaBundle $check.Directory.FullName | ForEach-Object {$_.sha256})
        }
        $arguments=@('--noprofile','--norc',(ConvertTo-ScanCygwinPath $check.FullName))
        $privateState=Join-Path $candidate ('state-'+[guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($privateState)
        $system=Join-Path $env:SystemRoot 'System32'
        $childEnvironment=@{
            SystemRoot=$env:SystemRoot
            WINDIR=$env:SystemRoot
            SystemDrive=[IO.Path]::GetPathRoot($env:SystemRoot).TrimEnd('\')
            ComSpec=(Join-Path $system 'cmd.exe')
            PATH=($bash.Directory.FullName+';'+$system)
            HOME=$privateState
            TEMP=$privateState
            TMP=$privateState
            BATCH='1'
            SCANLEVEL=$scope
            DOMAINS=$domains
        }
        $engineVariable=if($r.engine -eq 'zapret2'){'WINWS2'}else{'WINWS'}
        $childEnvironment[$engineVariable]=ConvertTo-ScanCygwinPath $binary
        $result=Native $bash.FullName $arguments -Timeout 4200 -WorkingDirectory $check.Directory.FullName -ChildEnvironment $childEnvironment
        if((Get-WorkflowFileHash $binary) -ine $engineSHA256){
            throw 'Windows blockcheck engine executable changed during the scan'
        }
        if($luaSHA256){Get-ZapretLuaBundle $check.Directory.FullName $luaSHA256 | Out-Null}
        if($null -eq $result -or $result.outputComplete -isnot [bool] -or -not $result.outputComplete -or
           $result.stdout -isnot [string] -or [string]::IsNullOrWhiteSpace($result.stdout)){
            throw 'Scan output was incomplete; no strategy was selected'
        }
        $report=Join-Path $root ('logs\'+$r.engine+'-blockcheck.txt')
        # The latest complete scan is diagnostic evidence for selection and rollback.
        Publish-WorkflowFile $report ([Text.UTF8Encoding]::new($false).GetBytes($result.stdout))
        return @{scanLevel=$level;output=$result.stdout;reportPath=$report;engineSHA256=$engineSHA256;luaSHA256=$luaSHA256;note='Review detected strategies before installing. A scan result is not a guarantee for UDP voice.'}
    } finally {
        $resolved=[IO.Path]::GetFullPath($candidate)
        if((Split-Path -Parent $resolved) -ine $scanParent -or (Split-Path -Leaf $resolved) -cnotmatch '^scan-zapret2?-[a-f0-9]{32}$'){
            throw 'Refusing unexpected strategy scan cleanup path'
        }
        Assert-TrustedTree $resolved
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
    }
}
function Auto-Install {
    if($r.dns -and $r.dns -ne 'unchanged' -and -not $script:dnsConfigured){Configure-DNS $r.dns}
    $scan=Scan-Strategies
    $selectionArgs=@('system','parse-scan',$scan.reportPath,$r.engine)
    $requireCommon=-not $r.targets -or @($r.targets).Count -gt 1
    if($requireCommon){$selectionArgs+=@('--require-common')}
    $selectionResult=Native $inputData.controller $selectionArgs @(0,1) -Secret
    if($null -eq $selectionResult -or $selectionResult.outputComplete -isnot [bool] -or -not $selectionResult.outputComplete){
        throw 'Scan strategy selection output was incomplete; no strategy was installed'
    }
    if($selectionResult.exitCode -eq 1){
        throw 'No usable strategy was selected. Review the scan report before installing manually.'
    }
    $selectionJSON=$selectionResult.stdout
    if($selectionResult.exitCode -ne 0 -or $selectionJSON -isnot [string] -or $selectionJSON.Length -gt 1MB -or
       -not $selectionJSON.TrimStart().StartsWith('{')){
        throw 'Scan strategy selection returned an invalid result'
    }
    try {$selected=ConvertFrom-Json -InputObject $selectionJSON -ErrorAction Stop}
    catch {throw 'Scan strategy selection returned an invalid result'}
    if($selected -isnot [pscustomobject] -or @($selected.PSObject.Properties).Count -ne 3 -or
       $selected.protocol -isnot [string] -or $selected.protocol -cnotin @('http','https','quic') -or
       $selected.common -isnot [bool] -or ($requireCommon -and -not $selected.common) -or
       $selected.args -isnot [array] -or $selected.args.Count -lt 1 -or $selected.args.Count -gt 125){
        throw 'Scan strategy selection returned an invalid result'
    }
    foreach($argument in $selected.args){
        if($argument -isnot [string] -or $argument -match '[\x00\r\n]' -or
           [Text.Encoding]::UTF8.GetByteCount($argument) -gt 4096){
            throw 'Scan strategy selection returned an invalid result'
        }
        $name=($argument -split '=',2)[0]
        if($r.engine -eq 'zapret2' -and $name.StartsWith('--',[StringComparison]::Ordinal) -and
           '--lua-init'.StartsWith($name,[StringComparison]::Ordinal)){
            throw 'Scan strategy selection returned an invalid result'
        }
    }
    $capture=if($r.engine -eq 'zapret2'){@('--wf-tcp-out=80,443','--wf-udp-out=443,50000-65535')}else{@('--wf-tcp=80,443','--wf-udp=443,50000-65535')}
    $filter=if($selected.protocol -eq 'quic'){'--filter-udp=443'}elseif($selected.protocol -eq 'http'){'--filter-tcp=80'}else{'--filter-tcp=443'}
    $r | Add-Member -NotePropertyName args -NotePropertyValue @($capture+@($filter)+@($selected.args)) -Force
    $r | Add-Member -NotePropertyName mode -NotePropertyValue 'service' -Force
    $installed=Install-Method -ScannedEngineSHA256 $scan.engineSHA256 -ScannedLuaSHA256 $scan.luaSHA256
    return @{installed=$installed;selectedStrategy=$selected;scanReport=$scan.reportPath;engineSHA256=$scan.engineSHA256;note='Only the protocol and scan targets in the report were tested. UDP voice and other networks require separate verification.'}
}
function Get-RefreshTaskInspection {
    # The executor supplies a canonical SystemRoot and a trusted native PATH.
    # Avoid an unbounded ScheduledTasks/WMI module query during discovery.
    $program=Join-Path $env:SystemRoot 'System32\schtasks.exe'
    try {
        $query=Native $program @('/Query','/TN','\AccessWeaver-WireSock-Refresh','/FO','CSV','/NH','/HRESULT') @(0,-2147024894) -Secret -Timeout 5
        if($query.outputComplete -ne $true){return @{present=$null;error='Scheduled task query output was incomplete; status is unknown'}}
        if($query.exitCode -eq 0){return @{present=$true;error=$null}}
        # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), independently of UI language.
        if($query.exitCode -eq -2147024894){return @{present=$false;error=$null}}
    }catch{}
    return @{present=$null;error='Scheduled task inspection failed; status is unknown'}
}
function Get-DriverServiceControllers {
    [CmdletBinding()]param()
    # Get-Service without a name excludes device drivers. Enumerate them through
    # the stock Framework API instead of losing WinDivert/NDISRD discovery.
    [ServiceProcess.ServiceController]::GetDevices()
}
function Get-ServiceInspection {
    $inspection=@{services=[Collections.Generic.List[object]]::new();error=$null}
    $incomplete='Some services could not be inspected; service inventory is incomplete'
    $names=@('WireSockAppService','WireSockConnectService','wiresock-client-service','ByeDPI','ProxiFyreService','WinDivert','WinDivert14','NDISRD','zapret','zapret2','GoodbyeDPI','dnscrypt-proxy','CloudflareWARP')
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($provider in @('Get-Service','Get-DriverServiceControllers')){
        $queryErrors=@()
        try {
            # These two fixed providers cover ordinary services and device drivers.
            # Preserve successful snapshots even if either provider reports errors.
            & $provider -ErrorAction SilentlyContinue -ErrorVariable queryErrors | ForEach-Object {
                $controller=$_
                try {
                    $serviceName=[string]$controller.ServiceName
                    if([string]::IsNullOrWhiteSpace($serviceName)){throw 'Incomplete service properties'}
                    if($serviceName.StartsWith('AccessWeaver-',[StringComparison]::OrdinalIgnoreCase) -or $serviceName -in $names){
                        $status=[string]$controller.Status
                        if([string]::IsNullOrWhiteSpace($status)){throw 'Incomplete service properties'}
                        if($seen.Add($serviceName)){[void]$inspection.services.Add(@{name=$serviceName;status=$status;owned=$serviceName.StartsWith('AccessWeaver-')})}
                    }
                } catch {$inspection.error=$incomplete}
                finally {
                    if($controller -is [IDisposable]){try{$controller.Dispose()}catch{$inspection.error=$incomplete}}
                }
            }
        } catch {$inspection.error=$incomplete}
        if($queryErrors.Count){$inspection.error=$incomplete}
    }
    return @{services=@($inspection.services.ToArray());error=$inspection.error}
}
function Discover {
    $discoveryClock=[Diagnostics.Stopwatch]::StartNew()
    [Console]::WriteLine('Discovery phase: services')
    [Console]::WriteLine(('Discovery timing ms: services {0}' -f $discoveryClock.ElapsedMilliseconds))
    $serviceInspection=Get-ServiceInspection;$services=@($serviceInspection.services);$serviceError=$serviceInspection.error
    [Console]::WriteLine('Discovery phase: components')
    [Console]::WriteLine(('Discovery timing ms: components {0}' -f $discoveryClock.ElapsedMilliseconds))
    $assets=@{};foreach($engine in $assetNames.Keys){$assets[$engine]=Find-Source $engine}
    [Console]::WriteLine('Discovery phase: applications')
    [Console]::WriteLine(('Discovery timing ms: applications {0}' -f $discoveryClock.ElapsedMilliseconds))
    $apps=@{};foreach($variant in @('discord','discord-ptb')){$apps[$variant]=Find-App $variant}
    $appInspectionError=$null
    try {$apps.splitcord=Find-App 'splitcord'}
    catch {$apps.splitcord=$null;$appInspectionError='SplitCord installation could not be identified safely'}
    [Console]::WriteLine('Discovery phase: conflicts')
    [Console]::WriteLine(('Discovery timing ms: conflicts {0}' -f $discoveryClock.ElapsedMilliseconds))
    $conflicts=@();if($appInspectionError){$conflicts+=@($appInspectionError)};$kaspersky=Get-Process -Name 'avp','avpui' -ErrorAction SilentlyContinue;if($kaspersky){$conflicts+=@('Kaspersky is running; WinDivert compatibility must be checked')};if(($services|Where-Object {$_.name -eq 'CloudflareWARP' -and $_.status -eq 'Running'})){$conflicts+=@('Cloudflare WARP is running; check routing conflicts')}
    $installerRecovery=Get-AccessWeaverInstallerRecoveryState
    switch ($installerRecovery) {
        'pending' {$conflicts+='AccessWeaver Setup is incomplete. After Setup exits, retry with the same or a newer approved installer in the original directory.'}
        'unavailable' {$conflicts+='AccessWeaver Setup recovery state could not be read. Ask an administrator to verify it before uninstalling.'}
    }
    [Console]::WriteLine('Discovery phase: refresh-task')
    [Console]::WriteLine(('Discovery timing ms: refresh-task {0}' -f $discoveryClock.ElapsedMilliseconds))
    $task=Get-RefreshTaskInspection
    [Console]::WriteLine('Discovery phase: final-paths')
    [Console]::WriteLine(('Discovery timing ms: final-paths {0}' -f $discoveryClock.ElapsedMilliseconds))
    $cli=WireSock-CLI;$dnsSnapshot=[bool](Test-Path -LiteralPath (Join-Path $root 'profiles\dns-original.json'))
    [Console]::WriteLine('Discovery phase: complete')
    [Console]::WriteLine(('Discovery timing ms: complete {0}' -f $discoveryClock.ElapsedMilliseconds))
    return @{services=@($services);serviceInspectionError=$serviceError;components=$assets;applications=$apps;wiresockCLI=$cli;conflicts=@($conflicts);managedRoot=$root;refreshTask=$task.present;refreshTaskInspectionError=$task.error;dnsSnapshot=$dnsSnapshot;installerRecovery=$installerRecovery}
}
function Restore-RecordedWorkflowFile($item) {
    $path=$item.path
    $currentHash=Get-WorkflowFileHash $path
    $pending=$item.pendingHash
    if($null -ne $pending -and ($pending -isnot [string] -or $pending -notmatch '\A[a-fA-F0-9]{64}\z')){
        throw 'Recovery journal contains an invalid pending file digest'
    }
    if($currentHash -and $currentHash -ine $item.originalHash -and
       $currentHash -ine $item.expectedHash -and $currentHash -ine $pending){
        throw ('File changed outside this operation; review before restoring: '+$path)
    }
    if($currentHash -and $currentHash -ieq $item.originalHash){return}

    if(-not $item.backup){
        if(-not $currentHash){return}
        Remove-Item -LiteralPath $path -ErrorAction Stop
        if(Get-WorkflowFileHash $path){throw 'Recovery could not verify removal of a file created by the operation'}
        return
    }
    if(-not (Under $item.backup (Join-Path $root 'backups'))){throw 'Recovery backup is outside protected storage'}
    if(-not $item.originalHash -or (Get-WorkflowFileHash $item.backup) -ine $item.originalHash){
        throw 'Recovery backup content does not match the recorded original digest'
    }

    $staged=Join-Path (Split-Path -Parent $path) ('.accessweaver-restore-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $ownsStage=$false
    try {
        Copy-WorkflowFileToNewPath $item.backup $staged $item.originalHash
        $ownsStage=$true
        Publish-StagedWorkflowFile $staged $path $item.originalHash $currentHash
        $ownsStage=$false
    } finally {
        if($ownsStage){
            No-Reparse $staged
            [IO.File]::Delete($staged)
        }
    }
}
function Rollback([string]$OwnerlessWireSockProfile) {
    foreach($entry in $script:undo){
        if($entry.kind -in @('service','started-service')){
            try {[void](Assert-RecordedServiceBinding $entry)}catch{return $_.Exception.Message}
        }
    }
    # Adapter DNS can still depend on the DNSCrypt service and on files shared
    # with other managed engines. Keep all recorded resources until DNS is safe.
    $dnsEntries=@($script:undo | Where-Object {$_.kind -ceq 'dns'})
    if($dnsEntries.Count -gt 1){return 'DNS recovery journal contains duplicate DNS entries'}
    if($dnsEntries.Count -eq 1){
        try {
            if(Confirm-DNSRecoveryEntry $dnsEntries[0]){Restore-DNS $dnsEntries[0].snapshotSHA256}
        } catch {return $_.Exception.Message}
    }
    $rollbackErrors=@()
    $wireSock=@($script:undo | Where-Object {$_.kind -ceq 'wiresock' -and -not $_.legacy})
    $ownershipPath=Join-Path $root 'profiles\wiresock-owned.json'
    $ownershipFile=$null
    if($wireSock.Count -eq 1){
        $records=@($script:undo | Where-Object {$_.kind -ceq 'file' -and $_.path -ieq $ownershipPath})
        if($records.Count -gt 1){return 'Recovery journal contains duplicate WireSock ownership records'}
        if($records.Count -eq 1){$ownershipFile=$records[0]}
    }
    for($i=$script:undo.Count-1;$i -ge 0;$i--){$item=$script:undo[$i];try{switch($item.kind){
        'service' {Remove-RecordedService $item.name -Entry $item}
        'started-service' {
            if((Assert-RecordedServiceBinding $item) -eq 0){Stop-Service -Name $item.name -ErrorAction Stop}
        }
        'firewall' {Remove-ManagedFirewallRule $item.name $item.instance -Journal}
        'task' {
            if($item.name -ne 'AccessWeaver-WireSock-Refresh'){throw 'Recovery journal contains an unmanaged task'}
            Remove-WireSockRefreshTask
        }
        'dns' {continue}
        'wiresock' {
            if($item.legacy){
                Stop-Service 'wiresock-client-service' -ErrorAction SilentlyContinue
                [void](Native $item.cli @('uninstall') -Secret)
            }else{
                $connectAttempted=$item.importOnly -isnot [bool] -or -not $item.importOnly
                $requireIdle=$connectAttempted -and $item.profile -ceq $OwnerlessWireSockProfile
                Remove-ModernWireSockProfile $item.cli $item.profile -Disconnect:($connectAttempted -and -not $requireIdle) -RequireIdle:$requireIdle
                if($ownershipFile){Restore-RecordedWorkflowFile $ownershipFile}
            }
        }
        'drover' {Restore-Drover $item.manifestSHA256}
        'cache' {if(-not (Under $item.path $env:APPDATA) -or -not (Under $item.backup (Join-Path $root 'backups'))){throw 'Invalid cache recovery path'};No-Reparse $item.path;No-Reparse $item.backup;if(Test-Path -LiteralPath $item.backup){if(Test-Path -LiteralPath $item.path){throw 'Discord created new cache; original cache backup retained for manual review'};Move-Item -LiteralPath $item.backup -Destination $item.path}}
        'file' {
            if($item.path -ieq (Join-Path $root 'profiles\dns-original.json') -or ($ownershipFile -and $item.path -ieq $ownershipPath)){continue}
            Restore-RecordedWorkflowFile $item
        }
    }}catch{
        $rollbackErrors+=@($_.Exception.Message)
        # Keep earlier files when a service, rule or profile still needs cleanup.
        if($item.kind -in @('service','firewall','wiresock')){break}
    }}
    return $rollbackErrors
}
# A recovery read never writes the selected journal or adopts a partial frame.
# This input cap is separate from producer bounds and whole-store accounting.
function Throw-WorkflowRecoveryJournalReadFailure {
    throw [IO.InvalidDataException]::new('Recovery journal could not be read safely; preserve the selected journal and recovery evidence')
}
function Read-WorkflowRecoveryJournalBytes([IO.Stream]$Source,[ValidateRange(1,8388608)][int]$Maximum=8MB) {
    $memory=$null
    try {
        if($null -eq $Source -or -not $Source.CanRead -or -not $Source.CanSeek -or $Source.Position -ne 0){Throw-WorkflowRecoveryJournalReadFailure}
        # PowerShell can return null when a property getter throws. Check the
        # raw value before a numeric cast can turn missing metadata into zero.
        $initial=$Source.Length
        if($initial -isnot [long] -or $initial -lt 0 -or $initial -gt $maximum){Throw-WorkflowRecoveryJournalReadFailure}
        $memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(65536);$actual=0L
        while($true){
            # At the boundary only one extra byte is admitted from the source;
            # it is rejected before any accumulator write or JSON parsing.
            $readSize=[int][Math]::Min([long]$buffer.Length,$maximum-$actual+1L)
            $count=$Source.Read($buffer,0,$readSize)
            if($count -lt 0 -or $count -gt $readSize){Throw-WorkflowRecoveryJournalReadFailure}
            if($count -eq 0){break}
            if($count -gt $maximum-$actual -or $count -gt $initial-$actual){Throw-WorkflowRecoveryJournalReadFailure}
            $memory.Write($buffer,0,$count);$actual+=$count
        }
        if($actual -ne $initial -or [long]$Source.Length -ne $initial -or [long]$Source.Position -ne $actual){Throw-WorkflowRecoveryJournalReadFailure}
        return ,$memory.ToArray()
    }catch {Throw-WorkflowRecoveryJournalReadFailure}
    finally {if($memory){$memory.Dispose()}}
}
# This helper takes ownership of exactly Source. Parsing cannot run until the
# actual read and its one checked Dispose have both completed successfully.
function Read-WorkflowRecoveryJournalStream([IO.Stream]$Source) {
    $bytes=$null;$failed=$false
    try {$bytes=Read-WorkflowRecoveryJournalBytes $Source}catch {$failed=$true}
    finally {
        if($null -eq $Source){$failed=$true}
        else {try {$Source.Dispose()}catch {$failed=$true}}
    }
    if($failed){Throw-WorkflowRecoveryJournalReadFailure}
    try {
        $text=[Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$bytes)
        # Accept one legacy UTF-8 BOM; never fall back to UTF-16 or a locale.
        if($text.Length -gt 0 -and $text[0] -eq [char]0xfeff){$text=$text.Substring(1)}
        if([string]::IsNullOrWhiteSpace($text) -or ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff)){Throw-WorkflowRecoveryJournalReadFailure}
        # Json.NET accepts raw NUL as ignorable input. It is not a valid JSON
        # frame character; escaped JSON \u0000 remains valid data after parsing.
        if($text.IndexOf([char]0) -ge 0){Throw-WorkflowRecoveryJournalReadFailure}
        $saved=$text|ConvertFrom-Json -ErrorAction Stop
        return ,$saved
    }catch {Throw-WorkflowRecoveryJournalReadFailure}
}
function Read-WorkflowRecoveryJournal([string]$Path) {
    try {$source=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}
    catch {Throw-WorkflowRecoveryJournalReadFailure}
    return ,(Read-WorkflowRecoveryJournalStream $source)
}
# A legacy journal has no binding. Administrators can still explicitly
# restore the currently active snapshot through dns-restore.
function Confirm-DNSRecoverySnapshot($ExpectedSHA256) {
    if($null -ne $ExpectedSHA256 -and
       ($ExpectedSHA256 -isnot [string] -or $ExpectedSHA256 -notmatch '\A[a-fA-F0-9]{64}\z')){
        throw 'DNS recovery journal contains an invalid snapshot digest'
    }
    $actual=Get-DNSRecoverySnapshotDigest
    if(-not $actual){return $false}
    if(-not $ExpectedSHA256 -or $actual -ine $ExpectedSHA256){
        throw 'DNS recovery journal does not match the active snapshot; review dns-restore'
    }
    return $true
}
function Read-DNSRecoveryFileBytes([string]$Path,[int]$Maximum) {
    No-Reparse $Path
    try {$attributes=[IO.File]::GetAttributes($Path)}
    catch [IO.FileNotFoundException] {return}
    catch [IO.DirectoryNotFoundException] {return}
    if($attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)){
        throw 'DNS recovery requires a bounded ordinary file'
    }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {return ,(Read-WorkflowRecoveryJournalBytes $stream $Maximum)}
    finally {$stream.Dispose()}
}
function Read-DNSRecoverySnapshot {
    $path=Join-Path $root 'profiles\dns-original.json'
    try {
        $bytes=Read-DNSRecoveryFileBytes $path 8MB
        if($null -eq $bytes){return}
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        if($text.Length -gt 0 -and $text[0] -eq [char]0xfeff){$text=$text.Substring(1)}
        if([string]::IsNullOrWhiteSpace($text) -or $text.IndexOf([char]0) -ge 0){throw 'Invalid DNS snapshot encoding'}
        $record=ConvertFrom-Json -InputObject $text -ErrorAction Stop
        if($record -isnot [pscustomobject]){throw 'Invalid DNS snapshot frame'}
        return @{record=$record;sha256=(Get-WorkflowBytesSHA256 $bytes)}
    } catch {throw 'Original DNS snapshot could not be read safely; retain it for review'}
}
function Assert-DNSRecoverySnapshotUnchanged([string]$ExpectedSHA256) {
    $observed=Get-DNSRecoverySnapshotDigest
    if(($ExpectedSHA256 -and $observed -ine $ExpectedSHA256) -or (-not $ExpectedSHA256 -and $observed)){
        throw 'Original DNS snapshot changed during preflight; retain it for review'
    }
}
function Get-DNSRecoverySnapshotDigest {
    $path=Join-Path $root 'profiles\dns-original.json'
    $bytes=Read-DNSRecoveryFileBytes $path 8MB
    if($null -eq $bytes){return}
    if($bytes.Length -eq 0){throw 'DNS recovery snapshot is not a bounded ordinary file'}
    return Get-WorkflowBytesSHA256 $bytes
}
function Get-DNSRecoveryReceiptPath([string]$SHA256) {
    if($SHA256 -notmatch '\A[a-fA-F0-9]{64}\z'){throw 'Invalid DNS recovery receipt digest'}
    return Join-Path $root ('profiles\dns-restored-'+$SHA256.ToLowerInvariant()+'.receipt')
}
function Save-DNSRecoveryReceipt([string]$SHA256) {
    $path=Get-DNSRecoveryReceiptPath $SHA256
    Publish-WorkflowFile $path ([Text.Encoding]::ASCII.GetBytes($SHA256.ToUpperInvariant()))
}
function Confirm-DNSRecoveryEntry($Entry) {
    if($null -ne $Entry.snapshotActive -and $Entry.snapshotActive -isnot [bool]){
        throw 'DNS recovery journal contains an invalid snapshot phase'
    }
    $digest=$Entry.snapshotSHA256
    if(Confirm-DNSRecoverySnapshot $digest){return $true}
    # Legacy entries lack a digest and continue to require explicit dns-restore
    # whenever an active snapshot exists. Bound entries require their receipt.
    if(-not $digest -or ($Entry.snapshotActive -is [bool] -and -not $Entry.snapshotActive)){return $false}
    $path=Get-DNSRecoveryReceiptPath $digest
    $bytes=$null
    try {$bytes=Read-DNSRecoveryFileBytes $path 64}catch{}
    if($null -eq $bytes -or $bytes.Length -ne 64 -or
       [Text.Encoding]::ASCII.GetString($bytes) -cne $digest.ToUpperInvariant()){
        throw 'DNS recovery snapshot is missing without a verified restoration receipt'
    }
    # Receipt inspection may overlap a snapshot publication. If an active
    # snapshot now exists it must pass the journal binding before cleanup.
    return (Confirm-DNSRecoverySnapshot $digest)
}
function Recover-Operation {
    if($r.journalId -notmatch '^workflow-[a-fA-F0-9]{32}\.json$'){throw 'Invalid recovery journal name'}
    $journal=Join-Path $root ('logs\'+$r.journalId);No-Reparse $journal;$saved=Read-WorkflowRecoveryJournal $journal
    $wireSockEntries=@($saved.undo | Where-Object {$_.kind -ceq 'wiresock'})
    if($wireSockEntries.Count -gt 1){throw 'Recovery journal contains duplicate WireSock entries'}
    $ownerlessWireSockProfile=''
    foreach($entry in @($saved.undo)){
        switch($entry.kind){
            'file' {if($entry.path -ieq (Join-Path $root 'profiles\dns-original.json')){[void](Confirm-DNSRecoverySnapshot $null);continue};$allowed=(Under $entry.path $root);if(-not $allowed){$allowed=(Under $entry.path (Join-Path $env:LOCALAPPDATA 'Discord')) -and ([IO.Path]::GetFileName($entry.path) -in @('version.dll','drover.ini'))};if(-not $allowed){throw 'Recovery journal contains an unmanaged file path'};if($entry.backup -and -not (Under $entry.backup (Join-Path $root 'backups'))){throw 'Recovery backup is outside protected storage'}}
            'service' {[void](Assert-RecordedServiceBinding $entry)}
            'started-service' {
                if($entry.name -ne 'AccessWeaver-byedpi'){throw 'Recovery journal contains an unmanaged restarted service'}
                [void](Assert-RecordedServiceBinding $entry)
            }
            'firewall' {[void](Get-ManagedFirewallRule $entry.name $entry.instance -Journal)}
            'task' {if($entry.name -ne 'AccessWeaver-WireSock-Refresh'){throw 'Recovery journal contains an unmanaged task'}}
            'dns' {[void](Confirm-DNSRecoveryEntry $entry)}
            'wiresock' {
                if($entry.cli -ne (WireSock-CLI) -or (-not $entry.legacy -and $entry.profile -notmatch '^AccessWeaver-[a-f0-9]{32}$')){
                    throw 'Recovery journal contains an unmanaged WireSock profile'
                }
                $phase=$entry.PSObject.Properties['importOnly']
                if($phase -and ($phase.Value -isnot [bool] -or $entry.legacy)){
                    throw 'Recovery journal contains an invalid WireSock phase'
                }
                if(-not $entry.legacy -and (-not $phase -or -not $phase.Value)){
                    # Disconnect is global. A stale journal must not use it
                    # when another managed profile may now own the tunnel.
                    $owned=Join-Path $root 'profiles\wiresock-owned.json'
                    $hasOwner=Test-Path -LiteralPath $owned -ErrorAction Stop
                    if($hasOwner){
                        $current=Read-OwnedWireSockProfile $owned
                        if($current.legacy -or $current.cli -ine $entry.cli -or $current.profile -cne $entry.profile){
                            throw 'WireSock recovery journal differs from the current managed profile'
                        }
                    }
                    $profiles=@(Get-ManagedWireSockProfiles $entry.cli)
                    if($profiles.Count -gt 0 -and ($profiles.Count -ne 1 -or $profiles[0] -cne $entry.profile)){
                        throw 'WireSock recovery cannot confirm the journaled profile is the only managed vendor profile'
                    }
                    if(-not $hasOwner){
                        # A vendor profile can exist while another profile is
                        # connected. Without an owner, only retry named deletion
                        # after a complete status query confirms the tunnel is idle.
                        if($profiles.Count){
                            $status=Get-WireSockReportedState (Native $entry.cli @('status') -Secret -Timeout 15)
                            if($status -cnotin @('NotConnected','Disconnected')){
                                throw 'WireSock recovery cannot confirm the vendor is idle without an ownership record'
                            }
                        }
                        $ownerlessWireSockProfile=$entry.profile
                    }
                }
            }
            'drover' {
                if($entry.manifestSHA256 -isnot [string] -or $entry.manifestSHA256 -notmatch '\A[a-fA-F0-9]{64}\z'){
                    throw 'Recovery journal contains an invalid Drover ownership digest'
                }
                $currentDrover=Get-DroverFileHash (Join-Path $root 'profiles\drover-owned.json')
                if($currentDrover -and $currentDrover -ine $entry.manifestSHA256){
                    throw 'Drover recovery journal differs from the current ownership record'
                }
            }
            'cache' {if($entry.path -ne (Join-Path $env:APPDATA 'discord') -or -not (Under $entry.backup (Join-Path $root 'backups'))){throw 'Recovery journal contains an unmanaged cache path'}}
            default {throw 'Unknown recovery journal operation'}
        }
    }
    $script:undo.Clear();foreach($entry in @($saved.undo)){$script:undo.Add($entry)};Save-Journal
    $errors=@(Rollback -OwnerlessWireSockProfile $ownerlessWireSockProfile);if($errors.Count){throw ($errors -join '; ')}
    Event 'Selected operation recovered'
}
function Throw-WorkflowResultFailure([string]$Code) {
    $known=@('result-too-large','result-serialization','result-depth','result-encoding')
    if($Code -cnotin $known){$Code='result-serialization'}
    $failure=[InvalidOperationException]::new('Workflow result reporting failed; inspect process.log and the recovery journal')
    $failure.Data['AccessWeaverWorkflowResultFailure']=$Code
    throw $failure
}
function Get-WorkflowResultFailureCode($Failure) {
    $exception=$Failure.Exception
    if(-not $exception -and $Failure -is [Exception]){$exception=$Failure}
    while($exception){
        $code=$exception.Data['AccessWeaverWorkflowResultFailure']
        if($code -cin @('result-too-large','result-serialization','result-depth','result-encoding')){return [string]$code}
        $exception=$exception.InnerException
    }
    return 'result-serialization'
}
function Assert-WorkflowResultToken([string]$ResultToken) {
    if($ResultToken -cnotmatch '\A[a-f0-9]{48}\z'){throw 'Workflow result report binding is unavailable'}
}
function Assert-WorkflowResultDepth($Value,[int]$Depth=0) {
    if($null -eq $Value -or $Value -is [DBNull]){return}
    $type=$Value.GetType()
    # Serializer scalar types remain scalar even below the aggregate depth.
    if($type.IsPrimitive -or $type.IsEnum -or $Value -is [string] -or $Value -is [decimal] -or $Value -is [DateTime] -or $Value -is [DateTimeOffset] -or $Value -is [Guid] -or $Value -is [uri] -or $type.FullName -eq 'System.Numerics.BigInteger'){return}
    if($Depth -gt 16){Throw-WorkflowResultFailure 'result-depth'}
    if($Value -is [Collections.IDictionary]){
        foreach($entry in $Value.GetEnumerator()){Assert-WorkflowResultDepth $entry.Value ($Depth+1)}
    }elseif($Value -is [Collections.IEnumerable]){
        foreach($entry in $Value){Assert-WorkflowResultDepth $entry ($Depth+1)}
    }else{
        foreach($property in $Value.PSObject.Properties){
            if($property.IsGettable){Assert-WorkflowResultDepth $property.Value ($Depth+1)}
        }
    }
}
function ConvertTo-WorkflowResultBytes([Collections.IDictionary]$Result,[string]$ResultToken,[int]$MaximumBytes=32MB) {
    Assert-WorkflowResultToken $ResultToken
    if($MaximumBytes -lt 1 -or $MaximumBytes -gt 32MB){throw 'Invalid workflow result byte limit'}
    $report=@{}
    try {
        foreach($key in $Result.Keys){
            if($key -isnot [string]){Throw-WorkflowResultFailure 'result-serialization'}
            if($key -ine 'reportVersion' -and $key -ine 'resultToken'){$report[$key]=$Result[$key]}
        }
        $report.reportVersion=1;$report.resultToken=$ResultToken
        # PS5.1 silently stringifies aggregates deeper than -Depth. Preflight
        # complements newer shells' warnings without rewriting JSON semantics.
        Assert-WorkflowResultDepth $report
        $json=ConvertTo-Json -InputObject $report -Depth 16 -ErrorAction Stop -WarningAction Stop
    }catch {Throw-WorkflowResultFailure (Get-WorkflowResultFailureCode $_)}
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    try {$length=$utf8.GetByteCount($json)}catch {Throw-WorkflowResultFailure 'result-encoding'}
    if($length -gt $MaximumBytes){Throw-WorkflowResultFailure 'result-too-large'}
    try {$bytes=$utf8.GetBytes($json)}catch {Throw-WorkflowResultFailure 'result-encoding'}
    return ,$bytes
}
function New-WorkflowResultStream([string]$Path) {
    return [IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
}
function Write-WorkflowResultStream($Stream,[byte[]]$Bytes,[int]$MaximumBytes=32MB) {
    if($MaximumBytes -lt 1 -or $MaximumBytes -gt 32MB){throw 'Invalid workflow result byte limit'}
    if($null -eq $Bytes -or $Bytes.Length -gt $MaximumBytes){Throw-WorkflowResultFailure 'result-too-large'}
    # The complete UTF-8 byte count is checked before the first data write.
    [void]$Stream.Write($Bytes,0,$Bytes.Length)
    [void]$Stream.Flush($true)
}
function Move-WorkflowResultFile([string]$Source,[string]$Destination) {
    # The two-argument Move refuses every preexisting destination; no replace.
    [IO.File]::Move($Source,$Destination)
}
function Write-WorkflowResultBytes([string]$Path,[byte[]]$Bytes,[int]$MaximumBytes=32MB) {
    if($MaximumBytes -lt 1 -or $MaximumBytes -gt 32MB){throw 'Invalid workflow result byte limit'}
    if($null -eq $Bytes -or $Bytes.Length -gt $MaximumBytes){Throw-WorkflowResultFailure 'result-too-large'}
    $temporary=Join-Path (Split-Path -Parent $Path) ('.accessweaver-result-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $stream=$null;$closeAttempted=$false;$failed=$false
    try {
        $stream=New-WorkflowResultStream $temporary
        Write-WorkflowResultStream $stream $Bytes $MaximumBytes
        $closeAttempted=$true
        [void]$stream.Dispose();$stream=$null
        Move-WorkflowResultFile $temporary $Path
    }catch {$failed=$true}finally {
        if($stream -and -not $closeAttempted){
            $closeAttempted=$true
            try {[void]$stream.Dispose()}catch {$failed=$true}
        }
        # Never delete uncertain staging or an unknown/preexisting destination.
        # The caller's token cannot turn an older result into this operation.
    }
    if($failed){throw 'Workflow result publication failed; preserve staging and recovery evidence'}
}
function New-WorkflowResultFailureReport([Collections.IDictionary]$Result,[string]$ResultToken,[string]$Code) {
    Assert-WorkflowResultToken $ResultToken
    if($Code -cnotin @('result-too-large','result-serialization','result-depth','result-encoding')){$Code='result-serialization'}
    $journal=$null
    if($Result['journal'] -is [string]){
        try {
            if([Text.UTF8Encoding]::new($false,$true).GetByteCount($Result['journal']) -le 4096){$journal=$Result['journal']}
        }catch {}
    }
    $reboot=$Result['rebootRequired'] -is [bool] -and $Result['rebootRequired']
    $fallback=@{reportVersion=1;resultToken=$ResultToken;ok=$false;error='Workflow result reporting failed; inspect process.log and the recovery journal';reportingFailure=$Code;events=@();data=$null;rebootRequired=[bool]$reboot;journal=$journal}
    $cleanup=@($Result['finalizationFailures'])
    if($cleanup.Count -gt 0 -and $cleanup.Count -le 4){
        $known=$true
        foreach($failure in $cleanup){if($failure -isnot [string] -or $failure -cnotin @('journal-save','mutex-release','mutex-dispose','uninstaller-start')){$known=$false}}
        if($known){$fallback.finalizationFailures=$cleanup}
    }
    if($Result['externalEffectsPending'] -is [bool] -and $Result['externalEffectsPending']){$fallback.externalEffectsPending=$true}
    return $fallback
}
function Publish-WorkflowResult([string]$Path,[Collections.IDictionary]$Result,[string]$ResultToken,[int]$MaximumBytes=32MB) {
    Assert-WorkflowResultToken $ResultToken
    $normal=$true
    try {$bytes=ConvertTo-WorkflowResultBytes $Result $ResultToken $MaximumBytes}catch {
        $normal=$false;$Result['ok']=$false
        $fallback=New-WorkflowResultFailureReport $Result $ResultToken (Get-WorkflowResultFailureCode $_)
        try {$bytes=ConvertTo-WorkflowResultBytes $fallback $ResultToken $MaximumBytes}catch {
            if((Get-WorkflowResultFailureCode $_) -cne 'result-too-large' -or $null -eq $fallback.journal){throw}
            # Preserve context when it fits, otherwise omit the whole path.
            $fallback.journal=$null
            $bytes=ConvertTo-WorkflowResultBytes $fallback $ResultToken $MaximumBytes
        }
    }
    Write-WorkflowResultBytes $Path $bytes $MaximumBytes
    return $normal
}
function Read-WorkflowUninstallRegistration {
    $path='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1'
    $record=$null
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        $key=$null
        try {
            $key=$base.OpenSubKey($path,$false)
            if($null -eq $key){continue}
            if($view -ne [Microsoft.Win32.RegistryView]::Registry64){throw 'Unexpected alternate AccessWeaver machine registration'}
            $writes=[int][Security.AccessControl.RegistryRights]'SetValue,CreateSubKey,CreateLink,Delete,ChangePermissions,TakeOwnership'
            Assert-WorkflowUninstallACL ($key.GetAccessControl()) $writes
            $record=@{}
            foreach($name in @('DisplayVersion','InstallLocation','UninstallString','QuietUninstallString')){
                $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 300 -or
                    $key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::String){
                    throw 'AccessWeaver uninstall registration is incomplete'
                }
                $record[$name]=$value
            }
        } finally {
            if($null -ne $key){$key.Dispose()}
            $base.Dispose()
        }
    }
    return $record
}
function Get-WorkflowUninstallPath($Registration,[string]$ProgramFiles) {
    $directory=$Registration.InstallLocation.TrimEnd('\')
    if($directory -cnotmatch '\A[A-Za-z]:\\[^:*?"<>|\x00-\x1f]+\z' -or
        $directory.Length -gt 259 -or [IO.Path]::GetFullPath($directory) -cne $directory -or
        -not (Under $directory $ProgramFiles)){
        throw 'Registered AccessWeaver installation must be a local Program Files directory'
    }
    foreach($part in $directory.Substring($ProgramFiles.Length+1).Split('\')){
        if(-not $part -or $part.EndsWith('.') -or $part.EndsWith(' ')){
            throw 'Registered AccessWeaver installation directory is ambiguous'
        }
    }
    $command=[regex]::Match($Registration.UninstallString,'\A"(?<file>[^"\r\n]+\\unins[0-9]{3}\.exe)"(?<log> /LOG)?\z',
        [Text.RegularExpressions.RegexOptions]'IgnoreCase,CultureInvariant')
    if(-not $command.Success){throw 'Registered AccessWeaver uninstall command is invalid'}
    $file=$command.Groups['file'].Value
    $expected=Join-Path $directory ([IO.Path]::GetFileName($file))
    $quiet='"'+$expected+'" /SILENT'+$command.Groups['log'].Value
    if($file -ine $expected -or $Registration.QuietUninstallString -ine $quiet){
        throw 'Registered AccessWeaver uninstall commands do not identify the installed uninstaller'
    }
    return $expected
}
function Assert-WorkflowUninstallACL($Acl,[int]$WriteRights) {
    # TrustedInstaller, SYSTEM and Administrators may manage the package.
    # Ordinary read/execute ACEs are expected in Program Files.
    $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){
        throw 'Registered AccessWeaver installation ownership could not be verified'
    }
    $writes=$WriteRights -bor 0x50000000
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if(-not $rules.Count){throw 'Registered AccessWeaver installation access could not be verified'}
    foreach($rule in $rules){
        if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            (([int]$rule.FileSystemRights -bor [int]$rule.RegistryRights) -band $writes)){
            throw 'Registered AccessWeaver installation is writable by an untrusted principal'
        }
    }
}
function Assert-WorkflowUninstallProtection([string]$Path) {
    No-Reparse $Path
    $writes=[int][Security.AccessControl.FileSystemRights]'Write,DeleteSubdirectoriesAndFiles,Delete,ChangePermissions,TakeOwnership'
    Assert-WorkflowUninstallACL (Get-Acl -LiteralPath $Path -ErrorAction Stop) $writes
}
function Assert-NoAccessWeaverSetup {
    if(-not ('AccessWeaver.InstallerSetupMutex' -as [type])){
        Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace AccessWeaver
{
    public static class InstallerSetupMutex
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr OpenMutexW(uint access, bool inherit, string name);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static bool IsAbsent(string name)
        {
            // Inspect existence without waiting or creating another mutex.
            IntPtr handle = OpenMutexW(0x00100000, false, name); // SYNCHRONIZE
            if (handle == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == 2; // ERROR_FILE_NOT_FOUND

            if (!CloseHandle(handle))
                throw new InvalidOperationException("Could not close the AccessWeaver Setup mutex handle");
            return false;
        }
    }
}
'@
    }
    if(-not [AccessWeaver.InstallerSetupMutex]::IsAbsent('Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092')){
        throw 'AccessWeaver Setup is active or its mutex could not be inspected'
    }
}

function Get-AccessWeaverInstallerRecoveryState {
    # The detector ships standalone. Its source fixture checks both copies.
    try {
        if(-not ('AccessWeaver.InstallerRecoveryRegistry' -as [type])){
            Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace AccessWeaver
{
    public static class InstallerRecoveryRegistry
    {
        private static readonly IntPtr LocalMachine = new IntPtr(unchecked((int)0x80000002));
        private const uint QueryFlags = 0x1001ffff; // RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY | RRF_RT_ANY

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int RegGetValueW(IntPtr key, string subKey, string value,
            uint flags, IntPtr type, IntPtr data, out uint size);

        public static int QueryStatus()
        {
            uint size;
            return RegGetValueW(LocalMachine, @"SOFTWARE\AccessWeaver\Installer", "PendingInstall",
                QueryFlags, IntPtr.Zero, IntPtr.Zero, out size);
        }
    }
}
'@
        }
        # Only explicit key/path or value absence permits uninstall or detection.
        switch ([AccessWeaver.InstallerRecoveryRegistry]::QueryStatus()) {
            0 {return 'pending'}
            2 {return 'clear'} # ERROR_FILE_NOT_FOUND
            3 {return 'clear'} # ERROR_PATH_NOT_FOUND
            default {return 'unavailable'}
        }
    } catch {
        return 'unavailable'
    }
}

function Assert-NoPendingWorkflowInstallation {
    $state=Get-AccessWeaverInstallerRecoveryState
    if($state -ceq 'pending'){
        throw 'An AccessWeaver installation is incomplete. Retry the approved installer before uninstalling.'
    }
    if($state -cne 'clear'){
        throw 'AccessWeaver Setup recovery state could not be read. Ask an administrator to verify it before uninstalling.'
    }
}
function Enter-WorkflowUninstallLifecycle {
    # Never wait on an existing object or consume its abandonment signal.
    $created=$false
    $mutex=[Threading.Mutex]::new($true,'Global\AccessWeaver-Lifecycle-B13D4677-4660-4E63-B3DB-03077ACBB092',[ref]$created)
    if(-not $created){
        $mutex.Dispose()
        throw 'An AccessWeaver installation or removal is active. Retry after it finishes.'
    }
    return $mutex
}
function Open-WorkflowUninstallBinding([string]$Architecture=$inputData.nativeArchitecture) {
    Assert-NoAccessWeaverSetup
    Assert-NoPendingWorkflowInstallation
    $registration=Read-WorkflowUninstallRegistration
    if($null -eq $registration){return $null}
    $programFiles=[Environment]::GetFolderPath('ProgramFiles').TrimEnd('\')
    $path=Get-WorkflowUninstallPath $registration $programFiles
    $directory=[IO.Path]::GetDirectoryName($path)
    $payload=Join-Path $directory 'accessweaver.exe'
    for($parent=$directory;;$parent=[IO.Path]::GetDirectoryName($parent)){
        Assert-WorkflowUninstallProtection $parent
        if($parent -ieq $programFiles){break}
    }
    Assert-WorkflowUninstallProtection $payload
    Assert-WorkflowUninstallProtection $path
    $machine=switch($Architecture){'amd64' {0x8664} 'arm64' {0xaa64} default {throw 'Native Windows architecture is unavailable'}}
    if((Get-PEMachine $payload) -ne $machine -or (Get-PEMachine $path) -ne 0x014c){
        throw 'Registered AccessWeaver payload or uninstaller architecture could not be verified'
    }
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 512MB){throw 'Registered AccessWeaver uninstaller exceeds the inspection limit'}
        $digest=(Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
        $confirmed=Read-WorkflowUninstallRegistration
        foreach($name in $registration.Keys){
            if($null -eq $confirmed -or $confirmed[$name] -cne $registration[$name]){
                throw 'AccessWeaver uninstall registration changed during inspection'
            }
        }
        return @{path=$path;sha256=$digest;registration=$registration;stream=$stream}
    } catch {
        $stream.Dispose()
        throw
    }
}
function Invoke-WorkflowDeferredUninstaller($Binding) {
    $current=Open-WorkflowUninstallBinding
    if($null -eq $current){throw 'AccessWeaver uninstall registration disappeared before handoff'}
    try {
        if($current.path -cne $Binding.path -or $current.sha256 -cne $Binding.sha256){
            throw 'Registered AccessWeaver uninstaller changed before handoff'
        }
        foreach($name in $Binding.registration.Keys){
            if($current.registration[$name] -cne $Binding.registration[$name]){
                throw 'AccessWeaver uninstall registration changed before handoff'
            }
        }
        # The file inspection can overlap a new Setup or recovery marker.
        Assert-NoPendingWorkflowInstallation
        Assert-NoAccessWeaverSetup
        # Keep the confirmed executable open through detached process creation.
        Start-Process -FilePath $current.path -WorkingDirectory ([IO.Path]::GetDirectoryName($current.path)) -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -WindowStyle Hidden
    } finally {$current.stream.Dispose()}
}
function Invoke-WorkflowUninstall {
    $lifecycle=Enter-WorkflowUninstallLifecycle
    try {
        $binding=Open-WorkflowUninstallBinding
        if($null -ne $binding){
            $binding.stream.Dispose()
            $binding.Remove('stream')
        }
        Assert-NoPendingWorkflowInstallation
        Assert-NoAccessWeaverSetup
        Remove-All
    } finally {
        try {$lifecycle.ReleaseMutex()}
        finally {$lifecycle.Dispose()}
    }
    $script:pendingUninstaller=$binding
    if($binding){
        return @{message='Owned system changes restored; registered uninstaller will start after releasing the workflow lock. Close AccessWeaver if requested. Recovery logs and vendor products are retained.'}
    }
    return @{message='Owned system changes restored. Stop the portable core before deleting its folder. Recovery logs and vendor products are retained.'}
}
function Complete-WorkflowFinalization([Collections.IDictionary]$Result,[string]$Path,[string]$ResultToken) {
    $failures=[Collections.Generic.List[string]]::new()
    $handoffPlanned=$Result['ok'] -is [bool] -and $Result['ok'] -and $null -ne $script:pendingUninstaller
    if($handoffPlanned){$script:externalEffectsPending=$true}
    # Every owned cleanup stage is attempted independently. A failed journal
    # save must not skip mutex release/disposal or bounded result publication.
    try {Save-Journal}catch {[void]$failures.Add('journal-save')}
    if($script:mutex){
        if($script:ownsMutex){
            try {$script:mutex.ReleaseMutex();$script:ownsMutex=$false}catch {[void]$failures.Add('mutex-release')}
        }
        try {$script:mutex.Dispose();$script:mutex=$null}catch {[void]$failures.Add('mutex-dispose')}
    }
    if($handoffPlanned -and $failures.Count -eq 0){
        # Mark before the attempt: a launch exception cannot prove that no
        # detached process was accepted. Never rewrite the machine journal
        # after releasing the mutex or retry an uncertain native handoff.
        $Result['uninstallerHandoff']='attempted'
        try {Invoke-WorkflowDeferredUninstaller $script:pendingUninstaller;$Result['uninstallerHandoff']='started'}catch {
            $Result['uninstallerHandoff']='unconfirmed';[void]$failures.Add('uninstaller-start')
        }
    }
    if($failures.Count){
        $Result['ok']=$false;$script:journalState='failed'
        if(-not $Result.Contains('error') -or -not $Result['error']){$Result['error']='Workflow finalization is unconfirmed; inspect the retained result and recovery journal'}
    }
    $Result['finalizationFailures']=@($failures.ToArray())
    $Result['externalEffectsPending']=[bool]$script:externalEffectsPending
    $Result['events']=@($script:events.ToArray());$Result['rebootRequired']=[bool]$script:rebootRequired;$Result['journal']=$script:journalPath
    try {
        if(-not (Publish-WorkflowResult $Path $Result $ResultToken)){$Result['ok']=$false}
    }catch {$Result['ok']=$false;throw}
}
$result=@{ok=$false;events=@();data=$null;rebootRequired=$false;journal=$null}
try {
    [Console]::WriteLine('Workflow phase: dispatch')
    if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-dispatch {0}' -f $script:workflowClock.ElapsedMilliseconds))}
    Initialize-Operation
    if($r.action -eq 'scan' -and $r.dns -and $r.dns -ne 'unchanged'){Configure-DNS $r.dns}
    $data=switch($r.action) {
        'discover' {Discover}
        'choose-folder' {Add-Type -AssemblyName System.Windows.Forms;$dialog=[Windows.Forms.FolderBrowserDialog]::new();try{$dialog.Description='Select an application folder for AccessWeaver';$selection=$dialog.ShowDialog();@{folder=$(if($selection -eq 'OK'){$dialog.SelectedPath}else{''})}}finally{$dialog.Dispose()}}
        'updates' {Check-AccessWeaverUpdates}
        'download' {if(-not $r.engine -or -not $r.downloadUrl){throw 'Choose a component, official URL and SHA-256'};$dir=Join-Path $root ('components\'+$r.engine);Protect-Dir $dir;$destination=Join-Path $dir ([IO.Path]::GetFileName(([uri]$r.downloadUrl).AbsolutePath));Download $r.downloadUrl $r.sha256 $destination;if($destination.EndsWith('.zip')){Expand-Safe $destination $dir};@{path=$destination}}
        'install' {Install-Method}
        'config' {@{configPath=(Make-Config)}}
        'connect' {$config=if($r.configPath){Make-Config}else{Join-Path $root ('profiles\AccessWeaver-'+$(if($r.profileId){$r.profileId}else{'default'})+'.conf')};@{status=(Connect-WireSock $config)}}
        'disconnect' {Disconnect-WireSock}
        'scan' {Scan-Strategies}
        'auto-install' {Auto-Install}
        'hostlist' {Save-Hostlist}
        'dns' {Configure-DNS $r.dns}
        'dns-restore' {Restore-DNS}
        'refresh' {Refresh-Task}
        'remove' {Remove-Method $r.engine}
        'vendor-uninstall' {Uninstall-WireSockProduct}
        'remove-all' {Remove-All}
        'app-install' {Install-App $r.engine}
        'app-reinstall' {Install-App $r.engine -Reinstall}
        'app-remove' {@{application=$r.engine;removed=(Remove-App $r.engine)}}
        'app-start' {Start-App $r.engine}
        'app-repair' {Stop-AppProcesses 'discord';Restore-Drover;[void](Remove-App 'discord');Preserve-DiscordCache;Start-RepairProxy;Install-App 'discord';Install-Drover;@{repaired='discord';proxy='127.0.0.1:1080'}}
        'uninstall' {Invoke-WorkflowUninstall}
        'recover' {Recover-Operation}
        default {throw 'Unknown action'}
    }
    $result.ok=$true;$result.data=$data
    $script:journalState='succeeded'
} catch {
    $result.error=$_.Exception.Message
    $script:journalState='failed'
    if($r.action -in @('install','auto-install','connect','config','download','dns','refresh','scan','app-install','app-reinstall','app-repair')){
        $result.rollbackScope='recorded-resources';$result.recordedRollbackComplete=$false
        $result.rollbackErrors=@(Rollback)
        if(-not $result.rollbackErrors.Count){
            $result.recordedRollbackComplete=$true
            $script:journalState=if($script:externalEffectsPending){'recovery-attempted'}else{'rolled-back'}
        }
    }
    Write-Output ('Workflow failed: '+$result.error)
} finally {
    Complete-WorkflowFinalization $result $inputData.resultPath $inputData.resultToken
}
if(-not $result.ok){exit 1}
