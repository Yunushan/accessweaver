# Exercise the real scheduler only in a disposable, native GitHub-hosted VM.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver' -or $env:ACCESSWEAVER_NATIVE_REFRESH_CHECK -cne '1'){
    throw 'Disposable hosted Windows refresh qualification required'
}
$actual=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if($actual -cne @{amd64='x64';arm64='arm64'}[$Architecture]){throw 'Native architecture mismatch'}
if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){
    throw 'Stock Windows PowerShell 5.1 required'
}
$project=Split-Path -Parent $PSScriptRoot
$source=$env:GITHUB_SHA
if($source -cnotmatch '^[a-f0-9]{40}$' -or (git -C $project rev-parse HEAD).Trim() -cne $source -or $LASTEXITCODE -ne 0){throw 'Source identity mismatch'}
if((git -C $project status --porcelain --untracked-files=no)){throw 'Tracked source must be clean'}
$paths=@('internal/workflow/windows.ps1','scripts/test-windows-native-refresh-cleanup.ps1','.github/workflows/windows-native-refresh-cleanup.yml')
$hashes=@{}
foreach($path in $paths){$hashes[$path]=(Get-FileHash -LiteralPath (Join-Path $project $path) -Algorithm SHA256).Hash.ToLowerInvariant()}
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project $paths[0]),[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Product source parse failed'}
$names=@('Quote-Arg','Native-Argument','New-ToolCapture','Receive-ToolCapture','Wait-ToolCapture','Stop-ToolTreeWithHelper','Stop-ToolTree','Run-Tool','Native','Get-WorkflowBytesSHA256','Get-WireSockRefreshActionDigest','Get-WireSockRefreshTaskDefinition','Test-WireSockRefreshTaskUndo','Register-WireSockRefreshTask','Get-RefreshTaskInspection','Remove-WireSockRefreshTask')
foreach($name in $names){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required scheduler function unavailable'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$report=@{
    schemaVersion=2;sourceCommit=$source;target=('windows/'+$Architecture);sourceSHA256=$hashes
    originalTaskAbsent=$false;createOnlyVerified=$false;staleJournalRefused=$false;guardedCleanupVerified=$false
    fixtureRegistered=$false;runningInstanceObserved=$false
    cleanupReturned=$false;fixtureProcessExited=$false;taskAbsent=$false;repeatCleanupPassed=$false
    cleanupConfirmed=$false;vendorCodeExecuted=$false;productionQualificationComplete=$false
}
$task=@{TaskName='AccessWeaver-WireSock-Refresh';TaskPath='\';ErrorAction='Stop'}
$directory=Join-Path $env:RUNNER_TEMP ('accessweaver-refresh-'+[guid]::NewGuid().ToString('N'))
$marker=Join-Path $directory 'pid.txt'
$ownsTask=$false
$creationEntry=$null
$process=$null
$r=[pscustomobject]@{action='remove'}
try {
    if((Get-RefreshTaskInspection).present -ne $false){throw 'Expected absent fixture task before registration'}
    $report.originalTaskAbsent=$true
    [void][IO.Directory]::CreateDirectory($directory)
    # Verify create-only and readback on the product path. Retire this inert
    # task before the five-minute trigger. The separate SYSTEM task below
    # supplies deterministic running-instance cleanup coverage.
    $commandPath=Join-Path $env:SystemRoot 'System32\cmd.exe'
    $arguments='/d /c exit 0'
    $creationEntry=@{name=$task.TaskName;instance=[guid]::NewGuid().ToString('N');
        actionSHA256=(Get-WireSockRefreshActionDigest $commandPath $arguments '')}
    Register-WireSockRefreshTask $commandPath $arguments $creationEntry.instance
    if(-not (Test-WireSockRefreshTaskUndo $creationEntry -RequireReady)){throw 'Product creation was not observed'}
    $foreignInstance=[guid]::NewGuid().ToString('N')
    $duplicateRefused=$false
    try{Register-WireSockRefreshTask $commandPath $arguments $foreignInstance}
    catch{$duplicateRefused=$_.Exception.Message -like 'WireSock reconnect task creation failed*'}
    $report.createOnlyVerified=$duplicateRefused -and (Test-WireSockRefreshTaskUndo $creationEntry -RequireReady)
    $stale=@{name=$creationEntry.name;instance=$foreignInstance;actionSHA256=$creationEntry.actionSHA256}
    $staleRefused=$false
    try{Remove-WireSockRefreshTask -JournalEntry $stale}
    catch{$staleRefused=$_.Exception.Message -ceq 'WireSock reconnect task differs from the recovery journal'}
    $report.staleJournalRefused=$staleRefused -and (Test-WireSockRefreshTaskUndo $creationEntry -RequireReady)
    Remove-WireSockRefreshTask -JournalEntry $creationEntry
    $report.guardedCleanupVerified=(Get-RefreshTaskInspection).present -eq $false
    if(-not ($report.createOnlyVerified -and $report.staleJournalRefused -and $report.guardedCleanupVerified)){
        throw 'Product task registration or guarded cleanup could not be verified'
    }
    $creationEntry=$null
    $stock=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $literal=$marker.Replace("'","''")
    $command="[IO.File]::WriteAllText('$literal',[string]"+'$PID); Start-Sleep -Seconds 120'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute $stock -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(3))
    Register-ScheduledTask @task -Action $action -Principal $principal -Settings $settings | Out-Null
    $ownsTask=$true
    $report.fixtureRegistered=(Get-RefreshTaskInspection).present -eq $true
    if(-not $report.fixtureRegistered){throw 'Fixture task registration not confirmed'}
    Start-ScheduledTask @task
    $clock=[Diagnostics.Stopwatch]::StartNew()
    do {
        if((Get-ScheduledTask @task).State -eq 'Running' -and [IO.File]::Exists($marker)){
            $text=[IO.File]::ReadAllText($marker)
            if($text -cmatch '^[1-9][0-9]{0,9}$'){
                $process=[Diagnostics.Process]::GetProcessById([int]$text)
                [void]$process.Handle
                $report.runningInstanceObserved=-not $process.HasExited
                if($report.runningInstanceObserved){break}
                $process.Dispose()
                $process=$null
            }
        }
        Start-Sleep -Milliseconds 100
    } while($clock.Elapsed.TotalSeconds -lt 20)
    if(-not $report.runningInstanceObserved){throw 'Fixture task did not reach running state'}
    Remove-WireSockRefreshTask
    $report.cleanupReturned=$true
    $report.fixtureProcessExited=$process.WaitForExit(5000)
    $report.taskAbsent=(Get-RefreshTaskInspection).present -eq $false
    Remove-WireSockRefreshTask
    $report.repeatCleanupPassed=(Get-RefreshTaskInspection).present -eq $false
} catch {
    # Persist only fixed flags, including on failure.
} finally {
    if($creationEntry){try {Remove-WireSockRefreshTask -JournalEntry $creationEntry}catch{}}
    if($ownsTask){
        try {
            if((Get-RefreshTaskInspection).present -eq $true){
                Disable-ScheduledTask @task | Out-Null
                Stop-ScheduledTask @task | Out-Null
                Unregister-ScheduledTask @task -Confirm:$false
            }
            $report.cleanupConfirmed=(Get-RefreshTaskInspection).present -eq $false -and ($null -eq $process -or $process.WaitForExit(5000))
        }catch{}
    }
    if($process){$process.Dispose()}
    if([IO.File]::Exists($marker)){[IO.File]::Delete($marker)}
    if([IO.Directory]::Exists($directory)){[IO.Directory]::Delete($directory)}
}
$evidence=Join-Path $project 'build/native-refresh-cleanup'
[void][IO.Directory]::CreateDirectory($evidence)
[IO.File]::WriteAllText((Join-Path $evidence 'status.json'),($report | ConvertTo-Json -Depth 4 -Compress),[Text.UTF8Encoding]::new($false))
foreach($key in @('originalTaskAbsent','createOnlyVerified','staleJournalRefused','guardedCleanupVerified','fixtureRegistered','runningInstanceObserved','cleanupReturned','fixtureProcessExited','taskAbsent','repeatCleanupPassed','cleanupConfirmed')){
    if(-not $report[$key]){throw 'Native refresh cleanup did not pass all fixed checks'}
}
