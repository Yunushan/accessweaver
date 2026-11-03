# Local filesystem and pure-function contract tests. No services, drivers,
# application installs or network settings are changed by this test script.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
foreach($file in @('test-windows-integration.ps1','build-windows-installer.ps1','test-windows-installer.ps1','test-windows-installer-contracts.ps1','windows-installer-common.ps1','build-windows-fixtures.ps1','test-windows-apps.ps1','test-windows-wiresock.ps1','test-windows-reboot.ps1','test-windows-storage.ps1','test-windows-uiaccess.ps1','vmware-test-bootstrap.ps1','vmware-reboot-resume.ps1')){$tokens=$null;$issues=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$tokens,[ref]$issues);if($issues.Count){throw ($issues|Out-String)}}
$tokens=$null;$parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $projectRoot 'internal\workflow\windows.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors|Out-String)}
foreach($node in $ast.EndBlock.Statements){if($node -is [System.Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($node.Extent.Text))}}
$testRoot=Join-Path $projectRoot ('build\workflow-tests-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Force -Path $testRoot)
$root=$testRoot;$script:undo=[Collections.Generic.List[object]]::new();$script:events=[Collections.Generic.List[string]]::new();$script:journalPath=$null
[void](New-Item -ItemType Directory -Force -Path (Join-Path $testRoot 'backups'))
function Assert([bool]$condition,[string]$message){if(-not $condition){throw $message};Write-Output ('PASS '+$message)}
# Evaluate only the isolated process-local TLS setup, with no HTTP operations.
$tlsStatements=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('[Net.ServicePointManager]::SecurityProtocol')})
Assert ($tlsStatements.Count -eq 1) 'HTTP TLS setup is conditional rather than an eager global initializer'
$tlsSetup=[scriptblock]::Create($tlsStatements[0].Extent.Text)
$previousTLS=[Net.ServicePointManager]::SecurityProtocol;$previousRequest=$r
try {
    foreach($action in @('discover','choose-folder','updates','download','install')) {
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::SystemDefault
        $r=[pscustomobject]@{action=$action}
        & $tlsSetup
        $expected=if($action -in @('discover','choose-folder')){[Net.SecurityProtocolType]::SystemDefault}else{[Net.SecurityProtocolType]::Tls12}
        Assert ([Net.ServicePointManager]::SecurityProtocol -eq $expected) ('Process-local TLS setup preserves the contract for '+$action)
    }
} finally {[Net.ServicePointManager]::SecurityProtocol=$previousTLS;$r=$previousRequest}
# Exercise both direct helper calls and the dispatcher before any real OS work.
$desktopGuard=(Get-Command Require-DesktopUser).ScriptBlock
$machineInitializer=(Get-Command Initialize-Changes).ScriptBlock
try{
    function Require-DesktopUser {throw 'blocked desktop token fixture'}
    foreach($helper in @('Install-App','Remove-App','Start-App')){
        $rejected=$false;try{& $helper 'discord'}catch{$rejected=$_.Exception.Message -eq 'blocked desktop token fixture'}
        Assert $rejected ($helper+' rejects an unsafe token before discovery or execution')
    }
    $script:machineInitializationCount=0
    function Initialize-Changes {$script:machineInitializationCount++}
    $r=[pscustomobject]@{action='app-repair'}
    $rejected=$false;try{Initialize-Operation}catch{$rejected=$_.Exception.Message -match 'privilege-separated'}
    Assert ($rejected -and $script:machineInitializationCount -eq 0) 'Combined repair blocked before privileged initialization'
    $inputData=[pscustomobject]@{resultPath=(Join-Path $testRoot 'user-job\result.json')}
    foreach($action in @('app-install','app-remove','app-start')){
        $r=[pscustomobject]@{action=$action;dns='unchanged'}
        $rejected=$false;try{Initialize-Operation}catch{$rejected=$_.Exception.Message -eq 'blocked desktop token fixture'}
        Assert ($rejected -and -not (Test-Path (Join-Path $testRoot 'user-job'))) ($action+' checks the token before staging files')
    }
    function Require-DesktopUser {}
    $r=[pscustomobject]@{action='app-install';dns='doh'}
    $rejected=$false;try{Initialize-Operation}catch{$rejected=$_.Exception.Message -match 'DNS separately'}
    Assert ($rejected -and -not (Test-Path (Join-Path $testRoot 'user-job'))) 'User application dispatch rejects system DNS changes before staging'
    $r=[pscustomobject]@{action='app-install';dns='unchanged'}
    Initialize-Operation
    Assert ($root -eq (Join-Path $testRoot 'user-job\application') -and $script:machineInitializationCount -eq 0 -and (Test-Path -LiteralPath $script:journalPath)) 'User application staging and journal avoid machine storage'
}finally{
    Set-Item Function:Require-DesktopUser $desktopGuard
    Set-Item Function:Initialize-Changes $machineInitializer
    $root=$testRoot;$script:journalPath=$null
}
$descriptor=Private-DirectorySecurity
Assert (Trusted-SecurityDescriptor $descriptor) 'Administrator-owned private storage descriptor accepted'
$descriptor.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
Assert (-not (Trusted-SecurityDescriptor $descriptor)) 'Unprivileged owner rejected even with a private DACL'
$descriptor=Private-DirectorySecurity
$descriptor.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Read','Allow'))
Assert (-not (Trusted-SecurityDescriptor $descriptor)) 'Explicit nonprivileged descendant access rejected'
Assert (Under (Join-Path $root 'components\file') $root) 'Contained paths accepted'
Assert (-not (Under (Join-Path $root '..\escape') $root)) 'Parent path escape rejected'
Assert (-not (Under ($root+'-sibling\file') $root)) 'Sibling prefix rejected'
Assert ((Quote-Arg 'with spaces') -eq '"with spaces"') 'Windows argument quoting preserves spaces'
Assert ((Quote-Arg '') -eq '""') 'Empty Windows argument preserved'
$node=(Get-Command node -ErrorAction Stop).Source
$native=Native $node @('-e','process.stdout.write(JSON.stringify(process.argv.slice(1)))','with spaces','','trailing\','quote"inside')
$nativeArgs=$native.stdout|ConvertFrom-Json
Assert ($nativeArgs.Count -eq 4 -and $nativeArgs[0] -eq 'with spaces' -and $nativeArgs[1] -eq '' -and $nativeArgs[2] -eq 'trailing\' -and $nativeArgs[3] -eq 'quote"inside') 'Native processes receive literal Windows arguments without shell evaluation'
Assert $native.outputComplete 'Ordinary native output reaches EOF'
$clock=[Diagnostics.Stopwatch]::StartNew()
[void](Native $node @('-e','require("child_process").spawn(process.execPath,["-e","setTimeout(()=>{},12000)"],{stdio:"inherit"});process.exit(0)'))
Assert ($clock.Elapsed.TotalSeconds -lt 10) 'Exited installer does not wait for a GUI child holding inherited output pipes'
# Real disposable children exercise cleanup independently of OS utility success.
# The failed/timed-out helper must stop the held parent and retain uncertainty.
foreach($mode in @('success','start-failure','failure','timeout')){
    $parent=[Diagnostics.Process]::new();$helper=[Diagnostics.Process]::new()
    $parent.StartInfo=[Diagnostics.ProcessStartInfo]::new()
    $parent.StartInfo.FileName=$node;$parent.StartInfo.Arguments='-e '+(Quote-Arg 'setTimeout(()=>{},60000)')
    $parent.StartInfo.UseShellExecute=$false;$parent.StartInfo.CreateNoWindow=$true
    $helper.StartInfo=[Diagnostics.ProcessStartInfo]::new()
    $helper.StartInfo.FileName=$node;$helper.StartInfo.UseShellExecute=$false;$helper.StartInfo.CreateNoWindow=$true
    $helper.StartInfo.RedirectStandardInput=$true;$helper.StartInfo.RedirectStandardOutput=$true;$helper.StartInfo.RedirectStandardError=$true
    try {
        [void]$parent.Start()
        $code=switch($mode){
            'success' {'process.kill('+ $parent.Id +');'}
            'failure' {'process.exit(23)'}
            'timeout' {'process.stdout.write("x".repeat(1024*1024));process.stderr.write("y".repeat(1024*1024));setTimeout(()=>{},60000)'}
        }
        $helper.StartInfo.Arguments='-e '+(Quote-Arg $code)
        if($mode -eq 'start-failure'){$helper.StartInfo.FileName=Join-Path $testRoot 'nonexistent-termination-helper.exe'}
        $clock=[Diagnostics.Stopwatch]::StartNew();$rejected=$false
        try{Stop-ToolTreeWithHelper $parent $helper -TimeoutMilliseconds 2000}catch{
            if($_.Exception.Message -notmatch 'tree cleanup is unconfirmed'){throw}
            $rejected=$true
        }
        Assert ($rejected -eq ($mode -ne 'success')) ('Tree cleanup preserves helper outcome: '+$mode)
        Assert ($clock.Elapsed.TotalSeconds -lt 8 -and $parent.HasExited -and ($mode -eq 'start-failure' -or $helper.HasExited)) ('Tree cleanup is bounded and stops both owned processes: '+$mode)
    } finally {
        foreach($child in @($helper,$parent)){
            try{if(-not $child.HasExited){$child.Kill();[void]$child.WaitForExit(2000)}}catch{}finally{$child.Dispose()}
        }
    }
}
$native=Native $node @('-e','process.stdout.write("out");process.stderr.write("err")') -Secret
Assert ($native.stdout -eq 'out' -and $native.stderr -eq 'err' -and $native.outputComplete) 'Both native output streams are drained completely'
foreach($stream in @('stdout','stderr')){
    $clock=[Diagnostics.Stopwatch]::StartNew();$rejected=$false
    $pidFile=Join-Path $testRoot ($stream+'-overflow.pid')
    try{Native $node @('-e',('require("fs").writeFileSync(process.argv[1],String(process.pid));process.'+$stream+'.write("x".repeat(5*1024*1024));setTimeout(()=>{},60000)'),$pidFile) -Timeout 15 -Secret|Out-Null}catch{$rejected=$_.Exception.Message -match 'capture limit'}
    Assert ($rejected -and $clock.Elapsed.TotalSeconds -lt 12) ($stream+' overflow stops the tool promptly and fails without retaining truncated success')
    $toolPid=[int][IO.File]::ReadAllText($pidFile)
    Assert (-not (Get-Process -Id $toolPid -ErrorAction SilentlyContinue)) ($stream+' overflow leaves no running fixture tool')
}
$native=Native $node @('-e','process.stdout.write("x".repeat(4*1024*1024));process.stderr.write("y".repeat(4*1024*1024))') -Secret
Assert ($native.stdout.Length -eq 4MB -and $native.stderr.Length -eq 4MB -and $native.outputComplete) 'Both streams accept their exact capture limit without truncation or deadlock'
$rejected=$false;try{Native $node @('-e','setTimeout(()=>{},60000)') -Timeout 1 -Secret|Out-Null}catch{$rejected=$_.Exception.Message -match 'Timed out'}
Assert $rejected 'A silent native tool still observes its timeout'
$rejected=$false;try{Native $node @('-e','process.exit(23)') -Secret|Out-Null}catch{$rejected=$_.Exception.Message -match 'exit 23'}
Assert $rejected 'Native failure exit codes are preserved'
[void](Native $node @('-e','process.exit(0)') -Timeout 86400 -Secret)
Assert $true 'One-shot tool timeout remains accepted without waiting for the deadline'
foreach($arg in @('--i=0.0.0.0','--po=9999','--dae','--service','--trans','-Ui0.0.0.0','-D','--','@options.txt')){
    $rejected=$false;try{Assert-ByeDPIArguments @($arg)}catch{$rejected=$_.Exception.Message -match 'reserves listener/process'}
    Assert $rejected ('Reserved installer argument rejected: '+$arg)
}
Assert-ByeDPIArguments @('--split','2','--disorder','--comment','ordinary text','','--comment','')
Assert $true 'Full strategy options and values remain accepted'
$originalConfigureDNS=(Get-Command Configure-DNS).ScriptBlock
try{
    function Configure-DNS {throw 'DNS must not run before argument validation'}
    $r=[pscustomobject]@{engine='byedpi';args=@('--i=0.0.0.0');dns='doh'}
    $rejected=$false;try{Install-Method}catch{$rejected=$_.Exception.Message -match 'reserves listener/process'}
    Assert $rejected 'Direct installer rejects reserved arguments before DNS or component changes'
}finally{Set-Item Function:Configure-DNS $originalConfigureDNS}
$r=[pscustomobject]@{applications=@('custom.exe','C:\Apps\Custom');browsers=$true}
$apps=@(Application-Names)
Assert ($apps -contains 'custom.exe' -and $apps -contains 'chrome.exe' -and $apps -contains 'Discord.exe') 'Default, custom and browser application rules compiled'
$packet=@(Packet-Arguments 'zapret2' @('--payload=tls_client_hello','--lua-desync=multidisorder:pos=2'))
Assert ($packet -contains '--wf-tcp-out=80,443') 'Strategy-only ISP presets receive a Windows packet capture filter'
$packet=@(Packet-Arguments 'zapret2' @('--wf-tcp-out=80','--lua-desync=oob:urp=0'))
Assert (@($packet|Where-Object {$_ -like '--wf-tcp*'}).Count -eq 1 -and $packet[0] -eq '--wf-tcp-out=80') 'An explicitly selected capture filter is preserved'
foreach($url in @('http://github.com/hufrea/byedpi/releases/download/v1/file.zip','https://evil.invalid/tool.exe','https://github.com/attacker/byedpi/releases/download/v1/file.zip','https://github.com/hufrea/byedpi/blob/main/tool.exe')){$rejected=$false;try{Allowed-Download $url}catch{$rejected=$true};Assert $rejected ('Unapproved URL rejected: '+$url)}
Allowed-Download 'https://github.com/hufrea/byedpi/releases/download/v0.17.3/byedpi.zip'
Assert $true 'Official release URL accepted'
$file=Join-Path $root 'managed.txt';[IO.File]::WriteAllText($file,'original')
Write-Atomic $file 'replacement';Write-Atomic $file 'replacement again'
Assert ((Get-Content -LiteralPath $file -Raw) -eq 'replacement again') 'Atomic replacement works for an existing file'
Assert ($script:undo.Count -eq 1) 'Original file backed up only once per transaction'
$newFile=Join-Path $root 'new.txt';Write-Atomic $newFile 'new'
$errors=@(Rollback)
Assert ($errors.Count -eq 0) 'Rollback completed without errors'
Assert ((Get-Content -LiteralPath $file -Raw) -eq 'original') 'Rollback restores original bytes'
Assert (-not (Test-Path -LiteralPath $newFile)) 'Rollback removes newly created files'
$script:undo.Clear();Write-Atomic $file 'installed';[IO.File]::WriteAllText($file,'changed outside operation')
$conflicts=@(Rollback)
Assert ($conflicts.Count -eq 1 -and (Get-Content -LiteralPath $file -Raw) -eq 'changed outside operation') 'Recovery refuses to overwrite independently changed files'
$script:undo.Clear();Write-Atomic $file 'installed with backup'
$backup=$script:undo[0].backup;[IO.File]::WriteAllText($backup,'corrupted recovery data')
$conflicts=@(Rollback)
Assert ($conflicts.Count -eq 1 -and (Get-Content -LiteralPath $file -Raw) -eq 'installed with backup') 'Recovery refuses a backup whose bytes differ from the recorded original digest'
$script:undo.Clear()
$source=Join-Path $root 'source.conf';[IO.File]::WriteAllText($source,"[Interface]`nPrivateKey = fixture-only`n[Peer]`nPublicKey = fixture-only`nEndpoint = example.invalid:2408`nAllowedApps = old.exe`n")
[void](New-Item -ItemType Directory -Force -Path (Join-Path $root 'profiles'))
$r=[pscustomobject]@{profileId='test-profile';configPath=$source;applications=@('custom.exe');browsers=$false}
$config=Make-Config;$text=Get-Content -LiteralPath $config -Raw
Assert ($text -match 'custom.exe' -and $text -notmatch 'old.exe') 'WireSock application policy replaces original selection in a private generated copy'
Assert ((Get-Content -LiteralPath $source -Raw) -match 'old.exe') 'Original WireGuard config remains unchanged'
[IO.File]::AppendAllText($source,"PostUp = arbitrary-command`n")
$rejected=$false;try{Make-Config|Out-Null}catch{$rejected=$true}
Assert $rejected 'WireGuard command hooks rejected'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=Join-Path $root 'traversal.zip';$zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
$entry=$zip.CreateEntry('../escape.txt');$writer=[IO.StreamWriter]::new($entry.Open());$writer.Write('bad');$writer.Dispose();$zip.Dispose()
$rejected=$false;try{Expand-Safe $archive (Join-Path $root 'extracted')}catch{$rejected=$true}
Assert $rejected 'Archive traversal rejected before extraction'
$previousAppData=$env:APPDATA
try{
    $env:APPDATA=Join-Path $testRoot 'fake-appdata';$cache=Join-Path $env:APPDATA 'discord';[void](New-Item -ItemType Directory -Force -Path $cache)
    [IO.File]::WriteAllText((Join-Path $cache 'cache.txt'),'original session fixture')
    $script:undo.Clear();Preserve-DiscordCache;$recovery=@(Rollback)
    Assert ($recovery.Count -eq 0 -and [IO.File]::ReadAllText((Join-Path $cache 'cache.txt')) -eq 'original session fixture') 'Failed repair can restore the preserved original cache'
    $script:undo.Clear();Preserve-DiscordCache;[void](New-Item -ItemType Directory -Path $cache);[IO.File]::WriteAllText((Join-Path $cache 'cache.txt'),'new session fixture')
    $recovery=@(Rollback)
    Assert ($recovery.Count -eq 1 -and [IO.File]::ReadAllText((Join-Path $cache 'cache.txt')) -eq 'new session fixture') 'Repair recovery preserves newly created cache and retains the original backup'
}finally{$env:APPDATA=$previousAppData;$script:undo.Clear()}
Write-Output 'Windows workflow contract tests completed. Test artifacts are under build/.'

# Mock OS cmdlets to exercise DNS snapshot/restore semantics without changing
# the host's real DNS, services, registry or network adapters.
$script:dnsCalls=[Collections.Generic.List[object]]::new()
$script:dohCalls=[Collections.Generic.List[object]]::new()
function Get-NetAdapter { [pscustomobject]@{Status='Up';InterfaceDescription='Fixture adapter';InterfaceGuid='{00000000-0000-0000-0000-000000000001}';ifIndex=77} }
function Get-ItemProperty {param($LiteralPath,$Name,$ErrorAction);[pscustomobject]@{NameServer=$(if($LiteralPath -match 'Tcpip6') {''}else{'192.0.2.53'})} }
function Get-DnsClientServerAddress {param($InterfaceIndex,$AddressFamily);[pscustomobject]@{InterfaceIndex=$InterfaceIndex;AddressFamily=$AddressFamily;ServerAddresses=@($(if($AddressFamily -eq 'IPv4'){'192.0.2.53'}else{'2001:db8::53'}))} }
function Set-DnsClientServerAddress { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,$InterfaceIndex,[string[]]$ServerAddresses,[switch]$ResetServerAddresses);process{$script:dnsCalls.Add(@{family=$InputObject.AddressFamily;index=$InterfaceIndex;servers=@($ServerAddresses);reset=[bool]$ResetServerAddresses})} }
function Get-DnsClientDohServerAddress {param($ServerAddress,$ErrorAction);if(-not $ServerAddress){[pscustomobject]@{ServerAddress='8.8.8.8';DohTemplate='https://original.invalid/dns-query';AllowFallbackToUdp=$true;AutoUpgrade=$false}} }
function Add-DnsClientDohServerAddress {param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);$script:dohCalls.Add(@{action='add';address=$ServerAddress;template=$DohTemplate;fallback=$AllowFallbackToUdp})}
function Set-DnsClientDohServerAddress {param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);$script:dohCalls.Add(@{action='set';address=$ServerAddress;template=$DohTemplate;fallback=$AllowFallbackToUdp})}
function Remove-DnsClientDohServerAddress {param($ServerAddress,$ErrorAction);$script:dohCalls.Add(@{action='remove';address=$ServerAddress})}
function Get-Service {param($Name,$ErrorAction);return $null}
function Clear-DnsClientCache {}
function Resolve-DnsName {param($Name,[switch]$DnsOnly,[switch]$QuickTimeout,$ErrorAction);return [pscustomobject]@{Name='example.com'}}
Configure-DNS 'doh'
$dnsSnapshot=Join-Path $root 'profiles\dns-original.json'
Assert (Test-Path -LiteralPath $dnsSnapshot) 'DNS snapshot persisted before changes'
Assert ($script:dnsCalls[0].servers.Count -eq 4) 'DNS configuration covers IPv4 and IPv6 providers'
Assert (@($script:dohCalls | Where-Object {$_.action -eq 'add' -and $_.fallback -eq $false}).Count -eq 4) 'Native DoH configuration disables plaintext fallback'
Restore-DNS
Assert (@($script:dnsCalls|Where-Object {$_.family -eq 'IPv4' -and $_.servers -contains '192.0.2.53'}).Count -eq 1) 'Original static IPv4 DNS is restored'
Assert (@($script:dnsCalls|Where-Object {$_.family -eq 'IPv6' -and $_.reset}).Count -eq 1) 'Original DHCP IPv6 DNS is restored independently'
Assert (@($script:dohCalls|Where-Object {$_.action -eq 'set' -and $_.template -eq 'https://original.invalid/dns-query'}).Count -eq 1) 'Original DoH metadata is restored'
Assert (-not (Test-Path -LiteralPath $dnsSnapshot)) 'DNS snapshot removed only after successful recovery'
Write-Output 'DNS workflow contracts completed using mock OS cmdlets.'

$oldInputData=$inputData
$inputData=[pscustomobject]@{managedPolicy=$true;allowDownloads=$false}
foreach($operation in @('release','download')){
    $rejected=$false
    try{if($operation -eq 'release'){Read-RemoteJSON -Uri 'https://invalid.invalid/not-called' -Headers @{}}else{Download 'https://invalid.invalid/not-called' '' 'not-written'}}catch{$rejected=$_.Exception.Message -match 'Administrator policy'}
    Assert $rejected ('Managed '+$operation+' blocked before any network or file operation')
}
$inputData=[pscustomobject]@{managedPolicy=$true;allowDownloads=$true}
Require-DownloadPermission
Assert $true 'Explicit managed download permission accepted without performing a request'
$inputData=[pscustomobject]@{managedPolicy=$false;allowDownloads=$false}
Require-DownloadPermission
Assert $true 'Unmanaged download behavior preserved'
$inputData=$oldInputData

$pinURL='https://github.com/hufrea/byedpi/releases/download/v-test/fixture.zip'
$pinHash=('a'*64)
$inputData=[pscustomobject]@{managedPolicy=$true;allowDownloads=$true;downloads=@(@{url=$pinURL;sha256=$pinHash})}
Assert ((Approved-DownloadHash $pinURL '') -eq $pinHash) 'Managed download uses administrator hash even when release metadata omits it'
$rejected=$false;try{Approved-DownloadHash $pinURL ('b'*64)|Out-Null}catch{$rejected=$_.Exception.Message -match 'conflicts with administrator policy'}
Assert $rejected 'Remote release metadata cannot replace the administrator artifact hash'
$rejected=$false;try{Download ($pinURL+'-unapproved') $pinHash 'not-written'}catch{$rejected=$_.Exception.Message -match 'Administrator policy does not pin'}
Assert $rejected 'An unpinned component is blocked before a network request'
$inputData=$oldInputData

$archiveRoot=Join-Path $root 'archive-fixture'
foreach($url in @('https://github.com/hufrea/byedpi/releases/download/v-test/component.zip','https://github.com/hufrea/byedpi/releases/download/v-test/..%2F..%2Foutside.zip')){
    $target=Component-ArchivePath $archiveRoot $url
    Assert ((Under $target $archiveRoot) -and [IO.Path]::GetFileName($target) -match '^asset-[a-f0-9]{32}\.zip$') 'Component metadata cannot select the staging filename or escape its directory'
}


# Scheduled-task inspection remains read-only, bounded and language-independent.
$previousTaskNative=(Get-Command Native).ScriptBlock
try {
    $script:taskQueryCalls=[Collections.Generic.List[object]]::new()
    function Native([string]$program,[string[]]$arguments=@(),[int[]]$codes=@(0),[switch]$Secret,[int]$Timeout=600) {
        $script:taskQueryCalls.Add(@{program=$program;arguments=@($arguments);codes=@($codes);secret=[bool]$Secret;timeout=$Timeout})
        if($script:taskQueryMode -eq 'denied'){throw 'PRIVATE_TASK_QUERY_DETAIL'}
        if($script:taskQueryMode -eq 'timeout'){throw 'Timed out: PRIVATE_TASK_QUERY_DETAIL'}
        $exit=if($script:taskQueryMode -eq 'absent'){-2147024894}elseif($script:taskQueryMode -eq 'unexpected'){1}else{0}
        return @{exitCode=$exit;outputComplete=($script:taskQueryMode -ne 'incomplete');stdout='PRIVATE_TASK_QUERY_DETAIL';stderr='PRIVATE_TASK_QUERY_DETAIL'}
    }
    foreach($mode in @('present','absent','denied','timeout','unexpected','incomplete')) {
        $script:taskQueryMode=$mode
        $inspection=Get-RefreshTaskInspection
        if($mode -eq 'present'){Assert ($inspection.present -eq $true -and $null -eq $inspection.error) 'Task inspection reports a successful query as present'}
        elseif($mode -eq 'absent'){Assert ($inspection.present -eq $false -and $null -eq $inspection.error) 'Task inspection reports only the file-not-found HRESULT as absent'}
        else{Assert ($null -eq $inspection.present -and -not [string]::IsNullOrWhiteSpace($inspection.error)) ($mode+' task inspection remains explicitly unknown')}
        Assert (($inspection|ConvertTo-Json) -notmatch 'PRIVATE_TASK_QUERY_DETAIL') 'Task inspection omits command output and private exception details'
    }
    foreach($call in $script:taskQueryCalls) {
        Assert ($call.program -eq (Join-Path $env:SystemRoot 'System32\schtasks.exe')) 'Task inspection uses the absolute trusted native utility'
        Assert (($call.arguments -join '|') -eq '/Query|/TN|\AccessWeaver-WireSock-Refresh|/FO|CSV|/NH|/HRESULT') 'Task inspection queries only the fixed local task with HRESULT result codes'
        Assert ($call.timeout -eq 5 -and $call.secret -and ($call.codes -join ',') -eq '0,-2147024894') 'Task inspection bounds execution and suppresses query output'
    }
}finally{Set-Item Function:Native $previousTaskNative}
