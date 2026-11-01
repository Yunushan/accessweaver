# Native filesystem tests only, inside an explicitly disposable Windows guest.
[CmdletBinding()]
param([string]$Workflow='C:\AccessWeaver-Test\workflow-storage.ps1',[string]$Executable='C:\AccessWeaver-Test\accessweaver-storage.exe',[switch]$DisposableVM)
$ErrorActionPreference='Stop'
if(-not $DisposableVM -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual|VMware'){throw 'Explicit disposable Windows guest required'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Guest administrator token required'}
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Workflow,[ref]$tokens,[ref]$issues)
if($issues.Count){throw ($issues|Out-String)}
foreach($node in $ast.EndBlock.Statements){if($node -is [Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($node.Extent.Text))}}
$results='C:\AccessWeaver-Results\storage-security';[void](New-Item -ItemType Directory -Force -Path $results)
$base=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('AccessWeaver-Storage-Test-'+[guid]::NewGuid().ToString('N'))
$checks=[Collections.Generic.List[object]]::new()
$script:undo=[Collections.Generic.List[object]]::new();$script:events=[Collections.Generic.List[string]]::new();$script:journalPath=$null
function Check([string]$name,[scriptblock]$body){try{& $body;$checks.Add(@{name=$name;passed=$true})}catch{$checks.Add(@{name=$name;passed=$false;error=$_.Exception.Message})};@{binarySHA256=(Get-FileHash $Executable -Algorithm SHA256).Hash;workflowSHA256=(Get-FileHash $Workflow -Algorithm SHA256).Hash;fixture=$base;tests=@($checks.ToArray())}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Reject([scriptblock]$body,[string]$expected){$message=$null;try{& $body}catch{$message=$_.Exception.Message};if(-not $message -or $message -notlike ('*'+$expected+'*')){throw ('Expected rejection '+$expected+'; got '+$message)}}
Check 'private directories are created with trusted ownership and DACL' {
    $root=Join-Path $base 'private';Protect-Dir $root;Assert-TrustedTree $root
    if(-not (Trusted-SecurityDescriptor (Get-Acl $root))){throw 'Created directory is not private'}
}
Check 'unprivileged preexisting owner is rejected without adopting contents' {
    $root=Join-Path $base 'poisoned';[void](New-Item -ItemType Directory -Force -Path $root)
    $acl=Get-Acl $root;$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'));Set-Acl -LiteralPath $root -AclObject $acl
    [IO.File]::WriteAllText((Join-Path $root 'inert.txt'),'never executable')
    Reject {Protect-Dir $root} 'Untrusted existing machine-storage'
    if((Get-Acl $root).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-545'){throw 'Untrusted owner was silently changed'}
}
Check 'a writable preexisting descendant is rejected before consumption' {
    $root=Join-Path $base 'descendant';Protect-Dir $root;$components=Join-Path $root 'components';Protect-Dir $components
    $item=Join-Path $components 'inert.txt';[IO.File]::WriteAllText($item,'inert fixture')
    $acl=Get-Acl $item;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Modify','Allow'));Set-Acl -LiteralPath $item -AclObject $acl
    Reject {Assert-TrustedTree $root} 'Untrusted existing machine-storage'
}
Check 'a corrupt hash-named service host is rejected before SCM calls' {
    $root=Join-Path $base 'host';Protect-Dir $root;Protect-Dir (Join-Path $root 'services')
    $inputData=@{controller=$Executable};$r=@{action='install';engine='byedpi'}
    $hash=(Get-FileHash $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $root ('services\host-'+$hash+'.exe')),'inert; never executed')
    function Get-Service {param($Name,$ErrorAction);return $null}
    function New-Service {throw 'Unexpected SCM creation reached'}
    Reject {Install-EngineService 'byedpi' (Join-Path $root 'components\byedpi\ciadpi.exe') @()} 'service-host content does not match'
}
if(@($checks|Where-Object {-not $_.passed}).Count){exit 1}
