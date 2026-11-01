# Run only inside an explicitly disposable elevated Windows guest.
param([string]$Executable='C:\AccessWeaver-Test\accessweaver-security.exe',[switch]$DisposableVM)
$ErrorActionPreference='Stop'
if(-not $DisposableVM -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware'){throw 'Explicit disposable Windows guest required'}
$results='C:\AccessWeaver-Results\uiaccess';[void](New-Item -ItemType Directory -Force -Path $results)
$state=Join-Path 'C:\AccessWeaver-Test-State' ('denied-ui-'+[guid]::NewGuid().ToString('N'))
$env:ACCESSWEAVER_HOME=$state;$env:ACCESSWEAVER_NO_BROWSER='1'
$start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable;$start.Arguments='ui';$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
$process=[Diagnostics.Process]::new();$process.StartInfo=$start;[void]$process.Start()
$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
$exited=$process.WaitForExit(15000)
if(-not $exited){$process.Kill();$process.WaitForExit()}
$output=$stdout.Result+$stderr.Result
$result=@{passed=($exited -and $process.ExitCode -ne 0 -and $output.Contains('normal desktop user') -and -not (Test-Path $state));exitCode=$process.ExitCode;exited=$exited;stateCreated=(Test-Path $state);output=$output;binarySHA256=(Get-FileHash $Executable -Algorithm SHA256).Hash}
$result|ConvertTo-Json -Depth 5|Set-Content (Join-Path $results 'elevated-refusal.json') -Encoding UTF8
if(-not $result.passed){exit 1}
