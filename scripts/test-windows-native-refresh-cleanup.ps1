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
$names=@('Quote-Arg','Native-Argument','New-ToolCapture','Receive-ToolCapture','Wait-ToolCapture','Stop-ToolTreeWithHelper','Stop-ToolTree','Run-Tool','Native','Get-RefreshTaskInspection','Remove-WireSockRefreshTask')
foreach($name in $names){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required scheduler function unavailable'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$report=@{
    schemaVersion=1;sourceCommit=$source;target=('windows/'+$Architecture);sourceSHA256=$hashes
    originalTaskAbsent=$false;fixtureRegistered=$false;runningInstanceObserved=$false
    cleanupReturned=$false;fixtureProcessExited=$false;taskAbsent=$false;repeatCleanupPassed=$false
    cleanupConfirmed=$false;vendorCodeExecuted=$false;productionQualificationComplete=$false
}
$task=@{TaskName='AccessWeaver-WireSock-Refresh';TaskPath='\';ErrorAction='Stop'}
$directory=Join-Path $env:RUNNER_TEMP ('accessweaver-refresh-'+[guid]::NewGuid().ToString('N'))
$marker=Join-Path $directory 'pid.txt'
$ownsTask=$false
$process=$null
$r=[pscustomobject]@{action='remove'}
try {
    if((Get-RefreshTaskInspection).present -ne $false){throw 'Expected absent fixture task before registration'}
    $report.originalTaskAbsent=$true
    [void][IO.Directory]::CreateDirectory($directory)
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
foreach($key in @('originalTaskAbsent','fixtureRegistered','runningInstanceObserved','cleanupReturned','fixtureProcessExited','taskAbsent','repeatCleanupPassed','cleanupConfirmed')){
    if(-not $report[$key]){throw 'Native refresh cleanup did not pass all fixed checks'}
}
