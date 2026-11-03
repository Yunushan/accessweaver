param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::WriteLine('Workflow phase: initialize')
if($script:workflowClock){[Console]::WriteLine(('Workflow timing ms: shell-initialize {0}' -f $script:workflowClock.ElapsedMilliseconds))}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$inputData = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
$r = $inputData.request
$script:root = Join-Path $env:ProgramData 'AccessWeaver'
$script:undo = [Collections.Generic.List[object]]::new()
$script:events = [Collections.Generic.List[string]]::new()
$script:journalPath = $null
$script:rebootRequired = $false
$script:dnsTouched = $false
$script:dnsConfigured = $false
$script:mutex = $null
$script:ownsMutex = $false
$script:journalState = 'running'
$script:pendingUninstaller = $null
$script:repairProxyReady = $false

function Event([string]$text) { $script:events.Add(([DateTime]::UtcNow.ToString('o')+' '+$text)); [Console]::WriteLine($text); Save-Journal }
function Save-Journal { if ($script:journalPath) { $text=@{action=$r.action;engine=$r.engine;state=$script:journalState;undo=@($script:undo.ToArray());events=@($script:events.ToArray())} | ConvertTo-Json -Depth 12;$temp=$script:journalPath+'.tmp';[IO.File]::WriteAllText($temp,$text,[Text.UTF8Encoding]::new($false));if(Test-Path -LiteralPath $script:journalPath){$old=$temp+'.old';[IO.File]::Replace($temp,$script:journalPath,$old);Remove-Item -LiteralPath $old}else{[IO.File]::Move($temp,$script:journalPath)} } }
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
function Initialize-Operation {
    # Check before machine-storage initialization, DNS changes, discovery or
    # process execution. A combined repair cannot cross this boundary safely.
    if($r.action -eq 'app-repair'){throw 'Combined Discord repair is unavailable until a privilege-separated broker is implemented'}
    if($r.action -in @('app-install','app-remove','app-start')){
        Require-DesktopUser
        if($r.dns -and $r.dns -ne 'unchanged'){throw 'Configure system DNS separately from user application operations'}
        if($r.action -ne 'app-start'){
            $script:root=Join-Path (Split-Path -Parent $inputData.resultPath) 'application'
            No-Reparse $root
            foreach($dir in @('downloads','backups','logs')){[void](New-Item -ItemType Directory -Force -Path (Join-Path $root $dir))}
            $script:journalPath=Join-Path $root 'logs\application.json';Save-Journal
        }
    }elseif($r.action -notin @('discover','updates','choose-folder')){Initialize-Changes}
}
function Quote-Arg([string]$text) { return '"'+[regex]::Replace([regex]::Replace($text,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"' }
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
function Run-Tool([string]$program,[string[]]$arguments=@(),[int[]]$codes=@(0),[switch]$Secret,[int]$Timeout=600) {
    if($Timeout -lt 1 -or $Timeout -gt 86400){throw 'Tool timeout must be between 1 and 86400 seconds'}
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$program;$start.Arguments=(@($arguments | ForEach-Object {Quote-Arg $_}) -join ' ')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
    $start.WorkingDirectory=Split-Path -Parent $program
    if (-not [IO.Path]::IsPathRooted($program)) {$start.WorkingDirectory=$root}
    $p=[Diagnostics.Process]::new();$p.StartInfo=$start;$started=$false
    # Fixed diagnostics only: never include the task output, arguments or path.
    $traceTask=([IO.Path]::GetFileName($program) -ieq 'schtasks.exe')
    $traceClock=[Diagnostics.Stopwatch]::StartNew()
    function Trace-TaskQueryStage([ValidateSet('start','started','capture-ready','exited','timed-out','drained','cleanup','tree-helper-returned','disposed')][string]$Phase) {
        if($traceTask){[Console]::WriteLine(('Task query timing ms: {0} {1}' -f $Phase,$traceClock.ElapsedMilliseconds))}
    }
    try {
        Trace-TaskQueryStage 'start'
        [void]$p.Start();$started=$true;$p.StandardInput.Close()
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
                & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $p.Id /T /F | Out-Null
                Trace-TaskQueryStage 'tree-helper-returned'
                if(-not $p.WaitForExit(2000)){throw ('Tool process '+$p.Id+' could not be stopped; inspect the recovery journal')}
            }
        } finally {$p.Dispose();Trace-TaskQueryStage 'disposed'}
    }
}
function Native([string]$program,[string[]]$arguments=@(),[int[]]$codes=@(0),[switch]$Secret,[int]$Timeout=600) {
    # Keep native output separate from the returned record, even for multi-line tools.
    $all=@(Run-Tool $program $arguments $codes -Secret:$Secret -Timeout $Timeout)
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
function Backup-File([string]$path) {
    No-Reparse $path
    $existing=$script:undo | Where-Object {$_.kind -eq 'file' -and $_.path -eq $path}
    if ($existing) {return}
    $backup=$null;$originalHash=$null
    if (Test-Path -LiteralPath $path) {if ((Get-Item -LiteralPath $path).PSIsContainer){throw 'Expected a regular file'};$originalHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;$backup=Join-Path $root ('backups\'+[guid]::NewGuid().ToString('N'));Copy-Item -LiteralPath $path -Destination $backup}
    $script:undo.Add(@{kind='file';path=$path;backup=$backup;originalHash=$originalHash});Save-Journal
}
function Expected-Hash([string]$path,[string]$hash){$entry=$script:undo|Where-Object {$_.kind -eq 'file' -and $_.path -eq $path}|Select-Object -First 1;$entry.expectedHash=$hash;Save-Journal}
function Write-Atomic([string]$path,[string]$text) {
    Backup-File $path
    $hasher=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($hasher.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($text))).Replace('-','')}finally{$hasher.Dispose()};Expected-Hash $path $hash
    $parent=Split-Path -Parent $path;[void](New-Item -ItemType Directory -Force -Path $parent)
    $tmp=Join-Path $parent ([guid]::NewGuid().ToString('N')+'.tmp')
    [IO.File]::WriteAllText($tmp,$text,[Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $path) {$replaceBackup=$tmp+'.old';[IO.File]::Replace($tmp,$path,$replaceBackup);Remove-Item -LiteralPath $replaceBackup}else{[IO.File]::Move($tmp,$path)}
}
function Copy-Checked([string]$source,[string]$destination) {No-Reparse $source;Backup-File $destination;Expected-Hash $destination (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash;[void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination));Copy-Item -LiteralPath $source -Destination $destination -Force}
function Copy-Tree([string]$source,[string]$destination) {
    No-Reparse $source
    foreach ($item in Get-ChildItem -LiteralPath $source -Recurse -Force) {if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Component contains a reparse point'};if (-not $item.PSIsContainer) {$relative=$item.FullName.Substring($source.TrimEnd('\').Length).TrimStart('\');$target=Join-Path $destination $relative;if (-not (Under $target $destination)){throw 'Invalid component path'};Copy-Checked $item.FullName $target}}
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
    Invoke-RestMethod -Uri $Uri -Headers $Headers
}
function Allowed-Download([string]$url) {
    $uri=[uri]$url
    if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Fragment) {throw 'Downloads must use an official HTTPS URL'}
    $repos=@('hufrea/byedpi','wiresock/proxifyre','wiresock/ndisapi','ViRb3/wgcf','bol-van/zapret-win-bundle','bol-van/zapret2','ValdikSS/GoodbyeDPI','DNSCrypt/dnscrypt-proxy','cagritaskn/SplitCord-Turkey','cagritaskn/SplitWire-Turkey','hdrover/discord-drover')
    if ($uri.Host -eq 'github.com') {foreach ($repo in $repos) {if ($uri.AbsolutePath.StartsWith('/'+$repo+'/releases/download/',[StringComparison]::OrdinalIgnoreCase)){return}}}
    if ($uri.Host -in @('www.wiresock.net','wiresock.net','discord.com','dl.discordapp.net','download.discordapp.net','aka.ms','download.visualstudio.microsoft.com')) {return}
    throw 'URL is not an allowlisted component download source'
}
function Download([string]$url,[string]$hash,[string]$destination,[switch]$Signed) {
    $hash=Approved-DownloadHash $url $hash
    Allowed-Download $url
    if (-not $Signed -and $hash -notmatch '^[a-fA-F0-9]{64}$'){throw 'A SHA-256 from the release asset digest or an independently verified source is required'}
    $extension=if($Signed){'.exe'}else{[IO.Path]::GetExtension(([uri]$url).AbsolutePath)}
    $temp=Join-Path $root ('downloads\'+[guid]::NewGuid().ToString('N')+$extension)
    $curl=Join-Path $env:SystemRoot 'System32\curl.exe'
    $curlArgs=@('--fail','--location','--max-redirs','5','--proto','=https','--proto-redir','=https','--connect-timeout','30','--max-time','600','--output',$temp)
    if($script:repairProxyReady){
        if(-not (Test-Path -LiteralPath $curl)){throw 'Windows curl is required for the repair proxy download'}
        [void](Native $curl ($curlArgs+@('--socks5-hostname','127.0.0.1:1080',$url)) -Timeout 650)
    }else{try{Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $temp}catch{
        # Modern Windows curl uses the OS TLS implementation and can reach
        # endpoints that reject the older .NET Framework HTTP stack.
        if(-not (Test-Path -LiteralPath $curl)){throw}
        [void](Native $curl ($curlArgs+@($url)) -Timeout 650)
    }}
    if ($hash -and (Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash -ne $hash) {Remove-Item -LiteralPath $temp;throw 'Downloaded component SHA-256 mismatch'}
    if ($Signed) {$signature=Get-AuthenticodeSignature -LiteralPath $temp;if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Discord|Microsoft|NT Kernel|WireSock'){throw 'Installer publisher signature could not be verified'}}
    Copy-Checked $temp $destination;Remove-Item -LiteralPath $temp
    Event ('Verified download: '+[IO.Path]::GetFileName($destination))
}
function Expand-Safe([string]$archive,[string]$destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip=[IO.Compression.ZipFile]::OpenRead($archive)
    try { $total=0L;foreach($entry in $zip.Entries){$total+=$entry.Length;if($total -gt 2147483648){throw 'Component archive exceeds 2 GiB'};$target=Join-Path $destination $entry.FullName;if(-not (Under $target $destination)){throw 'Archive path escapes component storage'};if($entry.FullName.EndsWith('/')){continue};[void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target));Backup-File $target;$stream=$entry.Open();$hasher=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-','')}finally{$stream.Dispose();$hasher.Dispose()};Expected-Hash $target $hash;[IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$target,$true)} } finally {$zip.Dispose()}
}
$assetNames=@{byedpi='ciadpi.exe';proxifyre='ProxiFyre.exe';wgcf='wgcf.exe';zapret='winws.exe';zapret2='winws2.exe';goodbyedpi='goodbyedpi.exe';dnscrypt='dnscrypt-proxy.exe';drover='version.dll'}
function Find-Source([string]$engine) {
    $name=$assetNames[$engine];if (-not $name){throw 'Unknown component'}
    $roots=@((Join-Path $root ('components\'+$engine)))
    if ($r.bundlePath) {$roots+=[IO.Path]::GetFullPath($r.bundlePath)}
    $roots+=@((Join-Path $env:ProgramFiles 'SplitWire-Turkey\res'),(Join-Path $env:ProgramFiles 'SplitWire-Turkey\Prerequisites'))
    foreach ($base in $roots) {if(Test-Path -LiteralPath $base){No-Reparse $base;if($engine -in @('zapret','zapret2')){$folder=if($engine -eq 'zapret2'){'zapret-winws2'}else{'zapret-winws'};$preferred=Get-ChildItem -LiteralPath $base -Directory -Recurse -Filter $folder|Select-Object -First 1;if($preferred -and (Test-Path -LiteralPath (Join-Path $preferred.FullName 'winws.exe'))){return (Join-Path $preferred.FullName 'winws.exe')}};$match=Get-ChildItem -LiteralPath $base -Recurse -Filter $name -File | Where-Object {$_.FullName -notmatch '\\x86\\|\\32\\|\\arm64\\|\\win7\\'} | Select-Object -First 1;if ($match){return $match.FullName}}}
    return $null
}
function Component-ArchivePath([string]$directory,[string]$url) {
    $extension=[IO.Path]::GetExtension(([uri]$url).AbsolutePath).ToLowerInvariant()
    if($extension -notin @('.zip','.exe')){throw 'Unsupported component archive extension'}
    $target=Join-Path $directory ('asset-'+[guid]::NewGuid().ToString('N')+$extension)
    if(-not (Under $target $directory)){throw 'Invalid component archive destination'}
    return $target
}
function Ensure-Asset([string]$engine) {
    $source=Find-Source $engine
    if (-not $source) {
        $repos=@{byedpi='hufrea/byedpi';proxifyre='wiresock/proxifyre';wgcf='ViRb3/wgcf';zapret='cagritaskn/SplitWire-Turkey';zapret2='cagritaskn/SplitWire-Turkey';goodbyedpi='ValdikSS/GoodbyeDPI';dnscrypt='DNSCrypt/dnscrypt-proxy';drover='hdrover/discord-drover'}
        $patterns=@{byedpi='x86_64-w64.*zip$';proxifyre='x64\.zip$';wgcf='windows_amd64.exe$';zapret='ZIP.*Windows.*zip$';zapret2='ZIP.*Windows.*zip$';goodbyedpi='goodbyedpi.*zip$';dnscrypt='win64.*zip$';drover='drover.*zip$'}
        if(-not $repos[$engine]){throw ('Supply an official component bundle for '+$engine)}
        $release=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri ('https://api.github.com/repos/'+$repos[$engine]+'/releases/latest')
        $asset=$release.assets | Where-Object {$_.name -match $patterns[$engine]} | Select-Object -First 1
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
    Event ('Component ready: '+$engine+'; SHA256 '+(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash)
    return $source
}
function WireSock-CLI {
    foreach($path in @((Join-Path $env:ProgramFiles 'WireSock Secure Connect\command-line\wiresock-connect-cli.exe'),(Join-Path $env:ProgramFiles 'WireSock Secure Connect\bin\wiresock-client.exe'),(Join-Path $env:ProgramFiles 'WireSock VPN Client\bin\wiresock-client.exe'))) {if(Test-Path -LiteralPath $path){return $path}}
    return $null
}
function Install-WireSock {
    $cli=WireSock-CLI;if($cli){return $cli}
    $installer=$null
    foreach($base in @($r.bundlePath,(Join-Path $env:ProgramFiles 'SplitWire-Turkey\res'))) {if($base -and (Test-Path -LiteralPath $base)){$installer=Get-ChildItem -LiteralPath $base -Recurse -Filter 'wiresock-secure-connect-x64-*.exe' | Sort-Object Name -Descending | Select-Object -First 1;if($installer){break}}}
    if(-not $installer){$url=$r.downloadUrl;$hash=$r.sha256;if(-not $url){$url='https://wiresock.net/_api/download-release.php?product=wiresock-secure-connect&platform=windows_x64&version=3.8.1.1';$hash='bd5a7eba32177b1022eda42d233b6b7848ea38604a63b0205666b4060b89a375'};$target=Join-Path $root 'downloads\wiresock-setup.exe';Download $url $hash $target -Signed;$installer=Get-Item -LiteralPath $target}
    $sig=Get-AuthenticodeSignature -LiteralPath $installer.FullName;if($sig.Status -ne 'Valid'){throw 'WireSock installer signature is invalid'}
    [void](Native $installer.FullName @('/install','/quiet','/norestart') @(0,3010,1641))
    $cli=WireSock-CLI;if(-not $cli){throw 'WireSock installation did not produce a CLI; reboot may be required'}
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
    if($config -notmatch '(?im)^\s*\[Peer\]' -or $config -notmatch '(?im)^\s*PrivateKey\s*='){throw 'Invalid WireGuard configuration'}
    $config=[regex]::Replace($config,'(?im)^\s*(AllowedApps|DisallowedApps)\s*=.*\r?\n?','')
    $config=$config.TrimEnd()+"`r`nAllowedApps = "+((Application-Names) -join ', ')+"`r`n"
    Write-Atomic $output $config
    Event ('Private tunnel configuration generated: '+$id)
    return $output
}
function Connect-WireSock([string]$config) {
    if(Test-Path -LiteralPath (Join-Path $root 'profiles\wiresock-owned.json')){throw 'Remove the current managed WireSock method before importing another profile'}
    $cli=Install-WireSock
    if([IO.Path]::GetFileName($cli) -eq 'wiresock-connect-cli.exe') {
        $services=@('WireSockAppService','WireSockConnectService');foreach($name in $services){$service=Get-Service -Name $name -ErrorAction SilentlyContinue;if(-not $service){throw ('Vendor service missing: '+$name+'; finish installation/reboot before connecting')};Start-Service -Name $name;$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))}
        # A unique vendor profile prevents replacement of an independently
        # imported profile with the same user-selected configuration name.
        $profile='AccessWeaver-'+[guid]::NewGuid().ToString('N')
        $importConfig=Join-Path $root ('profiles\'+$profile+'.conf');Copy-Checked $config $importConfig
        $script:undo.Add(@{kind='wiresock';cli=$cli;profile=$profile});Save-Journal
        [void](Native $cli @('import',$importConfig) -Secret)
        [void](Native $cli @('connect',$profile,'-exit') -Secret)
        $status=Native $cli @('status') -Secret
        Write-Atomic (Join-Path $root 'profiles\wiresock-owned.json') (@{profile=$profile;cli=$cli} | ConvertTo-Json)
        Event 'WireSock connect command completed; inspect status and traffic verification separately'
        return $status.stdout
    }
    if(Get-Service 'wiresock-client-service' -ErrorAction SilentlyContinue){throw 'An existing SDK WireSock service is installed; remove it through its owner before using managed setup'}
    $script:undo.Add(@{kind='wiresock';cli=$cli;legacy=$true});Save-Journal
    [void](Native $cli @('install','-start-type','2','-config',$config,'-log-level','error') -Secret)
    Start-Service -Name 'wiresock-client-service';(Get-Service 'wiresock-client-service').WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    Write-Atomic (Join-Path $root 'profiles\wiresock-owned.json') (@{profile=[IO.Path]::GetFileNameWithoutExtension($config);cli=$cli;legacy=$true}|ConvertTo-Json)
    return 'Vendor service running; tunnel traffic requires independent verification'
}
function Disconnect-WireSock {
    $owned=Join-Path $root 'profiles\wiresock-owned.json'
    if(-not (Test-Path -LiteralPath $owned)){throw 'No AccessWeaver-owned WireSock profile recorded'}
    $record=Get-Content -LiteralPath $owned -Raw | ConvertFrom-Json
    if($record.legacy){Stop-Service 'wiresock-client-service' -ErrorAction Stop}else{[void](Native $record.cli @('disconnect') -Secret)}
    Event 'Managed WireSock connection disconnected'
}
function Install-EngineService([string]$engine,[string]$binary,[string[]]$arguments) {
    $serviceName='AccessWeaver-'+$engine
    $existing=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if($existing){throw ('Service already exists; remove this managed method before reinstalling: '+$serviceName)}
    $controllerHash=(Get-FileHash -LiteralPath $inputData.controller -Algorithm SHA256).Hash.ToLowerInvariant()
    $controller=Join-Path $root ('services\host-'+$controllerHash+'.exe')
    if(Test-Path -LiteralPath $controller){
        Assert-TrustedItem $controller
    }else{Copy-Checked $inputData.controller $controller}
    if((Get-FileHash -LiteralPath $controller -Algorithm SHA256).Hash -ne $controllerHash){throw 'Existing service-host content does not match its trusted controller digest; retain it for administrator review'}
    $file=Join-Path $root ('services\'+$engine+'.json')
    Write-Atomic $file (@{name=$serviceName;binary=$binary;args=@($arguments);directory=(Split-Path -Parent $binary);logPath=(Join-Path $root ('logs\'+$engine+'.log'))}|ConvertTo-Json -Depth 5)
    $binPath=(Quote-Arg $controller)+' service-host '+(Quote-Arg $file)
    $serviceOptions=@{Name=$serviceName;BinaryPathName=$binPath;StartupType='Automatic';DisplayName=('AccessWeaver '+$engine)}
    if($engine -eq 'proxifyre'){$serviceOptions.DependsOn=@('NDISRD')}
    [void](New-Service @serviceOptions)
    $script:undo.Add(@{kind='service';name=$serviceName});Save-Journal
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    Start-Sleep -Milliseconds 500
    if((Get-Service $serviceName).Status -ne 'Running'){throw ('Engine exited during startup: '+$engine)}
    Event ('Installed and started '+$serviceName)
}
function Firewall([string]$engine,[string]$binary) {
    foreach($direction in @('Inbound','Outbound')){$name='AccessWeaver-'+$engine+'-'+$direction;if(-not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)){[void](New-NetFirewallRule -Name $name -DisplayName $name -Program $binary -Direction $direction -Action Allow -Profile Any);$script:undo.Add(@{kind='firewall';name=$name});Save-Journal}}
}
function Setup-ProxiFyre([string]$proxy) {
    if((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -Name Installed -ErrorAction SilentlyContinue).Installed -ne 1){Install-Prerequisite 'vcredist'}
    if(-not (Get-Service -Name 'NDISRD' -ErrorAction SilentlyContinue)){Install-Prerequisite 'ndisapi'}
    $binary=Ensure-Asset 'proxifyre';$dir=Split-Path -Parent $binary
    Protect-Dir (Join-Path $dir 'logs')
    Write-Atomic (Join-Path $dir 'app-config.json') (@{proxies=@(@{appNames=@(Application-Names);socks5ProxyEndpoint=$proxy;supportedProtocols=@('TCP','UDP')})}|ConvertTo-Json -Depth 8)
    # Topshelf's native service name belongs to the vendor. Run its console
    # command under our own SCM host so an existing vendor service is untouched.
    Install-EngineService 'proxifyre' $binary @('run')
    Firewall 'proxifyre' $binary
    Event 'Per-application TCP/UDP proxifier service started'
}
function Install-Prerequisite([string]$component) {
    $pattern=if($component -eq 'ndisapi'){'Windows.Packet.Filter.*.x64.msi'}else{'VC_redist.x64.exe'}
    $installer=$null
    foreach($base in @($r.bundlePath,(Join-Path $env:ProgramFiles 'SplitWire-Turkey\Prerequisites'))) {if($base -and (Test-Path -LiteralPath $base)){$installer=Get-ChildItem -LiteralPath $base -Recurse -Filter $pattern -File | Select-Object -First 1;if($installer){break}}}
    if(-not $installer){
        if($component -eq 'ndisapi'){$release=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri 'https://api.github.com/repos/wiresock/ndisapi/releases/latest';$asset=$release.assets|Where-Object {$_.name -match '\.x64\.msi$'}|Select-Object -First 1;if(-not $asset){throw 'Official Windows Packet Filter x64 installer not found'};$destination=Join-Path $root 'downloads\packet-filter.msi';Download $asset.browser_download_url (([string]$asset.digest)-replace '^sha256:','') $destination;$installer=Get-Item -LiteralPath $destination}
        else{$destination=Join-Path $root 'downloads\VC_redist.x64.exe';Download 'https://aka.ms/vs/17/release/vc_redist.x64.exe' '' $destination -Signed;$installer=Get-Item -LiteralPath $destination}
    }
    if((Get-AuthenticodeSignature -LiteralPath $installer.FullName).Status -ne 'Valid'){throw 'Prerequisite signature is invalid'}
    if($installer.Extension -eq '.msi'){[void](Native 'msiexec.exe' @('/i',$installer.FullName,'/qn','/norestart') @(0,3010,1641))}else{[void](Native $installer.FullName @('/install','/quiet','/norestart') @(0,3010,1641))}
    Event ('Prerequisite installed: '+$component)
}
function Discord-Directories([string]$variant='discord') {
    $folder=if($variant -eq 'discord-ptb'){'DiscordPTB'}else{'Discord'}
    $base=Join-Path $env:LOCALAPPDATA $folder
    if(-not (Test-Path -LiteralPath $base)){return @()}
    return @(Get-ChildItem -LiteralPath $base -Directory -Filter 'app-*' | Where-Object {Test-Path -LiteralPath (Join-Path $_.FullName ($folder+'.exe'))} | Sort-Object LastWriteTime -Descending | ForEach-Object {$_.FullName})
}
function Install-Drover {
    $dll=Ensure-Asset 'drover';$ini=Join-Path (Split-Path -Parent $dll) 'drover.ini'
    if(-not (Test-Path -LiteralPath $ini)){Write-Atomic $ini "[drover]`r`nproxy = socks5://127.0.0.1:1080`r`n"}
    $dirs=@(Discord-Directories);if(-not $dirs.Count){throw 'Install Discord before applying drover'}
    Stop-AppProcesses 'discord'
    $manifest=Join-Path $root 'profiles\drover-owned.json';$records=@()
    if(Test-Path -LiteralPath $manifest){throw 'Restore the existing managed drover installation before replacing it'}
    foreach($dir in $dirs){foreach($name in @('version.dll','drover.ini')){$target=Join-Path $dir $name;Copy-Checked $(if($name -eq 'version.dll'){$dll}else{$ini}) $target;$entry=$script:undo | Where-Object {$_.kind -eq 'file' -and $_.path -eq $target} | Select-Object -Last 1;$records+=@{path=$target;backup=$entry.backup;installedHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash}}}
    Write-Atomic $manifest (ConvertTo-Json -InputObject @($records) -Depth 5);Event 'Discord drover files installed with original-file backups'
}
function Restore-Drover {
    $manifest=Join-Path $root 'profiles\drover-owned.json';if(-not (Test-Path -LiteralPath $manifest)){return}
    Stop-AppProcesses 'discord'
    $records=Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    foreach($item in $records){if(-not (Under $item.path $env:LOCALAPPDATA)){throw 'Invalid drover recovery path'};No-Reparse $item.path;if(-not (Test-Path -LiteralPath (Split-Path -Parent $item.path))){Event 'An old Discord version folder is gone; its original backup is retained';continue};if(Test-Path -LiteralPath $item.path){if((Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash -ne $item.installedHash){throw 'Drover file changed after installation; manual review required'}};if($item.backup){Copy-Item -LiteralPath $item.backup -Destination $item.path -Force}else{Remove-Item -LiteralPath $item.path -ErrorAction SilentlyContinue}}
    Remove-Item -LiteralPath $manifest;Event 'Original Discord files restored'
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
function Configure-DNS([string]$method) {
    if($method -eq 'doh'){foreach($command in @('Get-DnsClientDohServerAddress','Set-DnsClientDohServerAddress','Add-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress')){if(-not (Get-Command $command -ErrorAction SilentlyContinue)){throw 'This Windows version does not expose native DoH management; choose DNSCrypt instead'}}}
    $snapshot=Join-Path $root 'profiles\dns-original.json'
    $adapters=@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'WireSock|WireGuard|TAP|TUN'})
    if(-not $adapters.Count){throw 'No active physical network adapter found'}
    if(-not (Test-Path -LiteralPath $snapshot)){
        $records=@();foreach($adapter in $adapters){$reg='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+$adapter.InterfaceGuid;$names=(Get-ItemProperty -LiteralPath $reg -Name NameServer -ErrorAction SilentlyContinue).NameServer;$reg6='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\'+$adapter.InterfaceGuid;$names6=(Get-ItemProperty -LiteralPath $reg6 -Name NameServer -ErrorAction SilentlyContinue).NameServer;$records+=@{guid=[string]$adapter.InterfaceGuid;index=$adapter.ifIndex;ipv4=@((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses);ipv6=@((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6).ServerAddresses);dhcp4=[string]::IsNullOrWhiteSpace($names);dhcp6=[string]::IsNullOrWhiteSpace($names6)}}
        $dohSettings=@();if(Get-Command 'Get-DnsClientDohServerAddress' -ErrorAction SilentlyContinue){$dohSettings=@(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)}
        Write-Atomic $snapshot (@{adapters=@($records);doh=$dohSettings}|ConvertTo-Json -Depth 10)
    }
    $script:dnsTouched=$true
    $script:undo.Add(@{kind='dns'});Save-Journal
    if($method -eq 'dnscrypt') {
        $binary=Ensure-Asset 'dnscrypt';$config=Join-Path (Split-Path -Parent $binary) 'dnscrypt-proxy.toml'
        if(-not (Test-Path -LiteralPath $config)){$example=Join-Path (Split-Path -Parent $binary) 'example-dnscrypt-proxy.toml';if(Test-Path -LiteralPath $example){Copy-Checked $example $config}else{throw 'Official DNSCrypt resolver configuration is missing'}}
        $text=Get-Content -LiteralPath $config -Raw;if($text -notmatch '(?m)^listen_addresses\s*='){throw 'DNSCrypt configuration is missing its top-level listen_addresses setting'};$text=[regex]::Replace($text,'(?m)^listen_addresses\s*=.*$',"listen_addresses = ['127.0.0.1:53', '[::1]:53']")
        if($text -notmatch '(?m)^server_names\s*='){$text="server_names = ['google', 'cloudflare', 'quad9-dnscrypt-ip4-nofilter-pri']`r`n"+$text}
        Write-Atomic $config $text
        if(-not (Get-Service 'AccessWeaver-dnscrypt' -ErrorAction SilentlyContinue)){Install-EngineService 'dnscrypt' $binary @('-config',$config)}else{Set-Service 'AccessWeaver-dnscrypt' -StartupType Automatic;Restart-Service 'AccessWeaver-dnscrypt';(Get-Service 'AccessWeaver-dnscrypt').WaitForStatus('Running',[TimeSpan]::FromSeconds(20))}
        $servers=@('127.0.0.1','::1')
    } elseif($method -eq 'doh') {
        if(Get-Service 'AccessWeaver-dnscrypt' -ErrorAction SilentlyContinue){Stop-Service 'AccessWeaver-dnscrypt';Set-Service 'AccessWeaver-dnscrypt' -StartupType Manual}
        $providers=@(@{address='8.8.8.8';url='https://dns.google/dns-query'},@{address='9.9.9.9';url='https://dns.quad9.net/dns-query'},@{address='2001:4860:4860::8888';url='https://dns.google/dns-query'},@{address='2620:fe::fe';url='https://dns.quad9.net/dns-query'})
        foreach($provider in $providers){if(Get-DnsClientDohServerAddress -ServerAddress $provider.address -ErrorAction SilentlyContinue){Set-DnsClientDohServerAddress -ServerAddress $provider.address -DohTemplate $provider.url -AllowFallbackToUdp $false -AutoUpgrade $true}else{Add-DnsClientDohServerAddress -ServerAddress $provider.address -DohTemplate $provider.url -AllowFallbackToUdp $false -AutoUpgrade $true}}
        $servers=@($providers | ForEach-Object {$_.address})
    } else {throw 'Choose doh or dnscrypt'}
    foreach($adapter in $adapters){Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $servers}
    $ready=$false;$deadline=[DateTime]::UtcNow.AddSeconds(90)
    $lastResolverError=''
    do{try{Clear-DnsClientCache;[void](Resolve-DnsName 'example.com' -DnsOnly -QuickTimeout -ErrorAction Stop);$ready=$true;break}catch{$lastResolverError=$_.Exception.Message;Start-Sleep -Seconds 2}}while([DateTime]::UtcNow -lt $deadline)
    if(-not $ready){Restore-DNS;throw ('Resolver verification failed; original DNS settings restored: '+$lastResolverError)}
    Event ('Encrypted DNS configured: '+$method)
    $script:dnsConfigured=$true
}
function Restore-DNS {
    $snapshot=Join-Path $root 'profiles\dns-original.json';if(-not (Test-Path -LiteralPath $snapshot)){throw 'No original DNS snapshot exists; no settings were changed'}
    $saved=Get-Content -LiteralPath $snapshot -Raw | ConvertFrom-Json
    foreach($record in $saved.adapters){$adapter=Get-NetAdapter | Where-Object {[string]$_.InterfaceGuid -eq $record.guid};if(-not $adapter){throw 'An original network adapter is missing; retain the snapshot for later recovery'}
        foreach($family in @('IPv4','IPv6')){$dhcp=if($family -eq 'IPv4'){$record.dhcp4}else{$record.dhcp6};$values=if($family -eq 'IPv4'){@($record.ipv4)}else{@($record.ipv6)};$dns=Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family;if($dhcp){$dns | Set-DnsClientServerAddress -ResetServerAddresses}else{$dns | Set-DnsClientServerAddress -ServerAddresses $values}}
    }
    if(Get-Command 'Get-DnsClientDohServerAddress' -ErrorAction SilentlyContinue){foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){$old=$saved.doh | Where-Object {$_.ServerAddress -eq $address};if($old){Set-DnsClientDohServerAddress -ServerAddress $address -DohTemplate $old.DohTemplate -AllowFallbackToUdp $old.AllowFallbackToUdp -AutoUpgrade $old.AutoUpgrade}else{Remove-DnsClientDohServerAddress -ServerAddress $address -ErrorAction SilentlyContinue}}}
    Remove-Item -LiteralPath $snapshot;Event 'Original DNS and DoH settings restored'
}
function Refresh-Task {
    $name='AccessWeaver-WireSock-Refresh'
    if(-not $r.enabled){Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue;Event 'Reconnect task removed';return}
    $recordPath=Join-Path $root 'profiles\wiresock-owned.json';if(-not (Test-Path -LiteralPath $recordPath)){throw 'Connect a managed WireSock profile first'}
    $record=Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    if($record.legacy){$command="Restart-Service -Name 'wiresock-client-service' -ErrorAction Stop";$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command));$action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)}
    else{$action=New-ScheduledTaskAction -Execute $record.cli -Argument ('connect '+(Quote-Arg $record.profile)+' -exit')}
    $trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5)) -RepetitionInterval (New-TimeSpan -Minutes 5)
    [void](Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -User $env:USERNAME -RunLevel Highest -Force)
    $script:undo.Add(@{kind='task';name=$name});Save-Journal;Event 'Reconnect task installed (every five minutes)'
}
function Remove-Method([string]$engine,[switch]$OwnedOnly) {
    if($engine -eq 'wiresock') {if(Test-Path -LiteralPath (Join-Path $root 'profiles\wiresock-owned.json')){Disconnect-WireSock;$owned=Get-Content -LiteralPath (Join-Path $root 'profiles\wiresock-owned.json') -Raw | ConvertFrom-Json;if($owned.legacy){[void](Native $owned.cli @('uninstall'))}else{[void](Native $owned.cli @('delete',$owned.profile) -Secret)};Remove-Item -LiteralPath (Join-Path $root 'profiles\wiresock-owned.json')};Unregister-ScheduledTask -TaskName 'AccessWeaver-WireSock-Refresh' -Confirm:$false -ErrorAction SilentlyContinue;return}
    if($engine -eq 'drover'){Restore-Drover;return}
    if($engine -eq 'windivert'){
        foreach($dependent in @('AccessWeaver-zapret','AccessWeaver-zapret2','AccessWeaver-goodbyedpi')){if((Get-Service $dependent -ErrorAction SilentlyContinue).Status -eq 'Running'){throw 'Remove packet-engine services before WinDivert'}}
        foreach($driver in @(Get-CimInstance Win32_SystemDriver|Where-Object {$_.Name -match '^WinDivert[a-zA-Z0-9]*$'})){
            $path=([string]$driver.PathName).Trim('"') -replace '^\\\?\?\\',''
            if([string]::IsNullOrWhiteSpace($path)){if($OwnedOnly){continue};throw 'Cannot verify WinDivert driver ownership without its binary path'}
            if(-not (Under $path (Join-Path $root 'components'))){if($OwnedOnly){continue};throw 'WinDivert is owned by another application; remove it through that application after checking its dependents'}
            No-Reparse $path
            # WinDivert can unregister itself when its final handle closes.
            [void](Native 'sc.exe' @('stop',$driver.Name) @(0,1060,1062));[void](Native 'sc.exe' @('delete',$driver.Name) @(0,1060));Event ('Removed managed WinDivert driver: '+$driver.Name)
        };return
    }
    if($engine -eq 'byedpi'){Remove-Method 'proxifyre';Restore-Drover}
    if($engine -eq 'dnscrypt' -and (Test-Path -LiteralPath (Join-Path $root 'profiles\dns-original.json'))){Restore-DNS}
    $name='AccessWeaver-'+$engine;$service=Get-Service -Name $name -ErrorAction SilentlyContinue
    if($service){if(-not (Test-Path -LiteralPath (Join-Path $root ('services\'+$engine+'.json'))) -and $engine -ne 'proxifyre'){throw 'Missing service ownership record; refusing deletion'};if($service.Status -ne 'Stopped'){Stop-Service -Name $name;$service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))};[void](Native 'sc.exe' @('delete',$name));for($i=0;$i -lt 20;$i++){if(-not (Get-Service $name -ErrorAction SilentlyContinue)){break};Start-Sleep -Milliseconds 250};if(Get-Service $name -ErrorAction SilentlyContinue){throw 'Service is marked for deletion; close Services and retry after reboot'}}
    foreach($direction in @('Inbound','Outbound')){Remove-NetFirewallRule -Name ('AccessWeaver-'+$engine+'-'+$direction) -ErrorAction SilentlyContinue}
    Event ('Managed method removed: '+$engine)
}
function Remove-All {
    foreach($engine in @('proxifyre','byedpi','zapret','zapret2','goodbyedpi','wiresock')){Remove-Method $engine}
    Remove-Method 'windivert' -OwnedOnly
    if(Test-Path -LiteralPath (Join-Path $root 'profiles\dns-original.json')){Restore-DNS}
    Remove-Method 'dnscrypt';Restore-Drover
}
function Uninstall-WireSockProduct {
    $cli=WireSock-CLI
    $names=if($cli -and [IO.Path]::GetFileName($cli) -eq 'wiresock-client.exe'){@('WireSock VPN Client','WireSock VPN Client for Windows')}else{@('WireSock Secure Connect')}
    $records=@();foreach($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
        if(Test-Path -LiteralPath $base){$records+=@(Get-ChildItem -LiteralPath $base|ForEach-Object {Get-ItemProperty -LiteralPath $_.PSPath}|Where-Object {$_.DisplayName -in $names})}
    }
    $record=$records|Select-Object -First 1;if(-not $record){throw 'No supported registered WireSock product found; use Windows Apps settings for an unrecognized package'}
    Unregister-ScheduledTask -TaskName 'AccessWeaver-WireSock-Refresh' -Confirm:$false -ErrorAction SilentlyContinue
    try{Remove-Method 'wiresock'}catch{Event 'Managed profile cleanup could not complete; continuing with the explicitly requested vendor uninstall'}
    $command=[Environment]::ExpandEnvironmentVariables([string]$record.UninstallString)
    if($command -match '(?i)msiexec(?:\.exe)?' -and $command -match '(\{[0-9a-fA-F-]{36}\})'){
        $product=[guid]$matches[1]
        [void](Native (Join-Path $env:SystemRoot 'System32\msiexec.exe') @('/x',$product.ToString('B'),'/qn','/norestart') @(0,1605,3010,1641) -Timeout 900)
    }else{
        $program=$null;if($command -match '^"([^"]+\.exe)"'){$program=$matches[1]}elseif($command -match '^(.+?\.exe)(?:\s|$)'){$program=$matches[1]}
        if(-not $program -or (-not (Under $program $env:ProgramFiles) -and -not (Under $program (Join-Path $env:ProgramData 'Package Cache')))){throw 'Registered vendor uninstaller is outside protected installation storage'}
        No-Reparse $program;$signature=Get-AuthenticodeSignature -LiteralPath $program
        if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'NT Kernel|WireSock'){throw 'Vendor uninstaller publisher signature could not be verified'}
        [void](Native $program @('/uninstall','/quiet','/norestart') @(0,3010,1641) -Timeout 900)
    }
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while($cli -and (Test-Path -LiteralPath $cli) -and -not $script:rebootRequired -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 500}
    if($cli -and (Test-Path -LiteralPath $cli) -and -not $script:rebootRequired){throw 'Vendor CLI remains installed; inspect vendor uninstall logs'}
    if((Test-Path -LiteralPath $record.PSPath) -and -not $script:rebootRequired){throw 'Vendor uninstall registration remains; inspect vendor uninstall logs'}
    Remove-Item -LiteralPath (Join-Path $root 'profiles\wiresock-owned.json') -ErrorAction SilentlyContinue
    Event ('Vendor uninstall completed: '+$record.DisplayName)
    return @{product=$record.DisplayName;rebootRequired=$script:rebootRequired}
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
function Install-Method {
    if($r.engine -eq 'byedpi'){Assert-ByeDPIArguments @($r.args)}
    if(($r.engine -eq 'wiresock' -and $r.mode -eq 'standard') -or ($r.engine -eq 'byedpi' -and $r.mode -eq 'dll')){if(-not @(Discord-Directories).Count){throw 'Install stable Discord before selecting the Discord DLL setup mode'}}
    if($r.engine -ne 'dnscrypt' -and $r.dns -and $r.dns -ne 'unchanged' -and -not $script:dnsConfigured){Configure-DNS $r.dns}
    switch($r.engine) {
        'wiresock' {$config=Make-Config;$status=Connect-WireSock $config;if($r.mode -eq 'standard'){$byedpi=Ensure-Asset 'byedpi';Install-EngineService 'byedpi' $byedpi @('--ip','127.0.0.1','--port','1080','--split','2');Firewall 'byedpi' $byedpi;Install-Drover};if($r.refresh){$r | Add-Member -NotePropertyName enabled -NotePropertyValue $true -Force;Refresh-Task};return @{configPath=$config;status=$status}}
        'byedpi' {$binary=Ensure-Asset 'byedpi';$arguments=@('--ip','127.0.0.1','--port','1080');if($r.args){$arguments+=@($r.args)}else{$arguments+=@('--split','2')};if($r.mode -eq 'once'){Event 'One-shot ByeDPI running; cancel this workflow to stop it';[void](Native $binary $arguments -Timeout 86400)}else{Install-EngineService 'byedpi' $binary $arguments;Firewall 'byedpi' $binary;if($r.mode -eq 'dll'){Install-Drover}elseif($r.mode -ne 'service'){Setup-ProxiFyre '127.0.0.1:1080'}}}
        {$_ -in @('zapret','zapret2','goodbyedpi')} {
            foreach($name in @('zapret','zapret2','goodbyedpi')){if($name -ne $r.engine -and (Get-Service ('AccessWeaver-'+$name) -ErrorAction SilentlyContinue).Status -eq 'Running'){throw 'Stop other packet engines before installing this method'}}
            $binary=Ensure-Asset $r.engine;$arguments=@($r.args)
            if(-not $arguments.Count){if($r.engine -eq 'goodbyedpi'){$arguments=@('-5')}else{throw 'Select a tested preset or supply strategy arguments'}}
            $arguments=@(Packet-Arguments $r.engine $arguments)
            if($r.engine -eq 'zapret2' -and -not @($arguments | Where-Object {$_ -match '^--lua-init(=|$)'}).Count){$lua=Join-Path (Split-Path -Parent $binary) 'lua';foreach($name in @('zapret-lib.lua','zapret-antidpi.lua')){$asset=Join-Path $lua $name;if(-not (Test-Path -LiteralPath $asset)){throw 'Zapret2 requires its matching upstream Lua asset bundle'};$arguments=@('--lua-init=@'+$asset)+$arguments}}
            $list=Join-Path (Split-Path -Parent $binary) 'accessweaver-hostlist.txt'
            if($r.engine -eq 'goodbyedpi' -and -not $r.domains -and -not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $binary) 'accessweaver-hostlist.saved.txt'))){$r|Add-Member -NotePropertyName domains -NotePropertyValue @('discord.com','discord.gg','discordapp.com','discordapp.net','discord.media','roblox.com','wattpad.com') -Force}
            Save-Hostlist
            if($r.engine -eq 'goodbyedpi'){if($r.enabled){$arguments+=@('--blacklist',$list)}}else{$filter='--hostlist-exclude='+$list;$expanded=@();foreach($arg in $arguments){if($arg -eq '--new'){$expanded+=@($filter)};$expanded+=@($arg)};$arguments=$expanded+@($filter)}
            if($r.mode -eq 'once'){Event 'One-shot engine started; cancel the running workflow to stop it';[void](Native $binary $arguments -Timeout 86400)}else{Install-EngineService $r.engine $binary $arguments}
        }
        'dnscrypt' {Configure-DNS 'dnscrypt'}
        'ndisapi' {Install-Prerequisite 'ndisapi'}
        'vcredist' {Install-Prerequisite 'vcredist'}
        default {throw 'Unsupported install component'}
    }
    return @{installed=$r.engine}
}
function Find-App([string]$variant) {
    if($variant -in @('discord','discord-ptb')){$dirs=@(Discord-Directories $variant);if($dirs.Count){return (Join-Path $dirs[0] $(if($variant -eq 'discord'){'Discord.exe'}else{'DiscordPTB.exe'}))};return $null}
    if($variant -eq 'splitcord'){foreach($base in @((Join-Path $env:LOCALAPPDATA 'Programs\SplitCord-Turkey'),(Join-Path $env:ProgramFiles 'SplitCord-Turkey'))){if(Test-Path -LiteralPath $base){$file=Get-ChildItem -LiteralPath $base -Recurse -Filter 'SplitCord-Turkey.exe' -File|Select-Object -First 1;if($file){return $file.FullName}}};return $null}
    throw 'Unknown application variant'
}
function Wait-App([string]$variant,[bool]$installed,[int]$seconds=120) {
    $deadline=[DateTime]::UtcNow.AddSeconds($seconds)
    do{if([bool](Find-App $variant) -eq $installed){return};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $deadline)
    throw 'Application installation state did not reach the expected result; inspect installer logs'
}
function Install-App([string]$variant) {
    Require-DesktopUser
    if($variant -notin @('discord','discord-ptb','splitcord')){throw 'Choose Discord, Discord PTB or SplitCord'}
    if($r.clean -and $variant -eq 'discord-ptb' -and (Find-App 'discord')){Remove-App 'discord'}
    if($variant -eq 'splitcord'){$release=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri 'https://api.github.com/repos/cagritaskn/SplitCord-Turkey/releases/latest';$asset=$release.assets | Where-Object {$_.name -match '(Setup|Install).*exe'}|Select-Object -First 1;if(-not $asset){throw 'Official SplitCord installer not found'};$url=$asset.browser_download_url;$hash=([string]$asset.digest)-replace '^sha256:','';if(-not $hash){$hash=$r.sha256};$file=Join-Path $root 'downloads\splitcord-setup.exe';Download $url $hash $file}
    else{$url='https://discord.com/api/downloads/distributions/app/installers/latest?channel='+$(if($variant -eq 'discord-ptb'){'ptb'}else{'stable'})+'&platform=win&arch=x64';$file=Join-Path $root ('downloads\'+$variant+'-setup.exe');Download $url '' $file -Signed}
    $installerArgs=if($variant -eq 'splitcord'){@('/S')}else{@('-s')}
    [void](Native $file $installerArgs -Timeout 900)
    Wait-App $variant $true 180
    Event ('Application installed: '+$variant)
}
function Remove-App([string]$variant) {
    Require-DesktopUser
    $app=Find-App $variant;if(-not $app){return}
    Stop-AppProcesses $variant
    if($variant -in @('discord','discord-ptb')){$folder=if($variant -eq 'discord'){'Discord'}else{'DiscordPTB'};$update=Join-Path $env:LOCALAPPDATA ($folder+'\Update.exe');No-Reparse $update;[void](Native $update @('--uninstall','-s') -Timeout 300)}
    else{$directory=Split-Path -Parent $app;$uninstaller=Get-ChildItem -LiteralPath $directory -Filter 'Uninstall*.exe' -File|Select-Object -First 1;if(-not $uninstaller){throw 'SplitCord uninstaller not found'};[void](Native $uninstaller.FullName @('/S'))}
    Wait-App $variant $false 60
    Event ('Application uninstalled: '+$variant)
}
function Stop-AppProcesses([string]$variant) {
    $base=$null;$app=$null
    if($variant -in @('discord','discord-ptb')){$base=Join-Path $env:LOCALAPPDATA $(if($variant -eq 'discord'){'Discord'}else{'DiscordPTB'});No-Reparse $base}else{$app=Find-App $variant}
    foreach($process in Get-Process -ErrorAction SilentlyContinue){try{
        $path=$process.Path;if(-not $path){continue}
        $match=if($base){(Under $path $base) -and ([IO.Path]::GetFileName($path) -in @('Discord.exe','DiscordPTB.exe','Update.exe','crashpad_handler.exe'))}else{$app -and $path -eq $app}
        if($match){Stop-Process -Id $process.Id -ErrorAction Stop}
    }catch{}}
}
function Start-App([string]$variant) {
    Require-DesktopUser
    $app=Find-App $variant;if(-not $app){throw 'Application is not installed'};No-Reparse $app
    if([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'Start user applications from the signed-in Windows desktop, not the SYSTEM session'}
    # Explorer brokers the launch in the signed-in desktop user's context.
    Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList @((Quote-Arg $app)) -WindowStyle Hidden
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    do{foreach($process in Get-Process -ErrorAction SilentlyContinue){try{if($process.Path -eq $app){Event 'Application process is running in the desktop session';return}}catch{}};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $deadline)
    throw 'Application launch could not be verified; inspect its desktop and logs'
}
function Start-RepairProxy {
    $binary=Ensure-Asset 'byedpi';$name='AccessWeaver-byedpi';$service=Get-Service $name -ErrorAction SilentlyContinue
    if($service){
        $recordPath=Join-Path $root 'services\byedpi.json';if(-not (Test-Path -LiteralPath $recordPath)){throw 'Existing ByeDPI service has no ownership record'}
        $record=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json
        if($record.name -ne $name -or $record.binary -ne $binary){throw 'Existing ByeDPI service configuration differs; remove it before repair'}
        if($service.Status -ne 'Running'){$script:undo.Add(@{kind='started-service';name=$name});Save-Journal;Start-Service $name;$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))}
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
function Scan-Strategies {
    if($r.engine -notin @('zapret','zapret2')){throw 'Strategy scans require Zapret or Zapret2'}
    $binary=Ensure-Asset $r.engine;$dir=Split-Path -Parent $binary
    $search=@($r.bundlePath,(Split-Path -Parent $dir),(Join-Path $env:ProgramFiles 'SplitWire-Turkey\res\zapret')) | Where-Object {$_ -and (Test-Path -LiteralPath $_)}
    $check=$null;$bash=$null
    foreach($base in $search){$pattern=if($r.engine -eq 'zapret2'){'blockcheck2.sh'}else{'blockcheck.sh'};$check=Get-ChildItem -LiteralPath $base -Recurse -Filter $pattern -File|Select-Object -First 1;if($check){$bash=Get-ChildItem -LiteralPath $base -Recurse -Filter 'bash.exe' -File|Select-Object -First 1;if($bash){break}}}
    if(-not $check -or -not $bash){throw 'Supply the official Windows blockcheck bundle, including its Cygwin bash runtime'}
    if(-not (Under $check.FullName $root)){$scanDir=Join-Path $root ('components\scan-'+$r.engine);Protect-Dir $scanDir;Copy-Tree $check.Directory.FullName $scanDir;$check=Get-Item -LiteralPath (Join-Path $scanDir $check.Name)}
    if(-not (Under $bash.FullName $root)){$runtimeDir=Join-Path $root 'components\cygwin';Protect-Dir $runtimeDir;$bashRoot=Split-Path -Parent $bash.Directory.FullName;Copy-Tree $bashRoot $runtimeDir;$bash=Get-Item -LiteralPath (Join-Path $runtimeDir 'bin\bash.exe')}
    if($r.engine -eq 'zapret2' -and $inputData.ispHook){Write-Atomic (Join-Path $check.Directory.FullName 'blockcheck2.d\standard\00-accessweaver-isp.sh') $inputData.ispHook}
    $level=if($r.scan){$r.scan}else{'standard'};$scope=@{quick='quick';standard='standard';full='force'}[$level]
    $old=[Environment]::GetEnvironmentVariable('SCANLEVEL');$oldDomains=[Environment]::GetEnvironmentVariable('DOMAINS')
    $oldBatch=[Environment]::GetEnvironmentVariable('BATCH');$oldPath=$env:PATH
    try{$env:BATCH='1';$env:PATH=$bash.Directory.FullName+';'+$env:PATH;$env:SCANLEVEL=$scope;$env:DOMAINS=if($r.targets){@($r.targets)-join ' '}else{'discord.com discord.gg'};$unixPath=$check.FullName -replace '\\','/';if($unixPath -match '^([A-Za-z]):/(.*)$'){$unixPath='/cygdrive/'+$matches[1].ToLowerInvariant()+'/'+$matches[2]};$result=Native $bash.FullName @('--noprofile','--norc',$unixPath) -Timeout 4200;$report=Join-Path $root ('logs\'+$r.engine+'-blockcheck.txt');Write-Atomic $report $result.stdout;return @{scanLevel=$level;output=$result.stdout;reportPath=$report;note='Review detected strategies before installing. A scan result is not a guarantee for UDP voice.'}}finally{[Environment]::SetEnvironmentVariable('SCANLEVEL',$old);[Environment]::SetEnvironmentVariable('DOMAINS',$oldDomains);[Environment]::SetEnvironmentVariable('BATCH',$oldBatch);$env:PATH=$oldPath}
}
function Auto-Install {
    if($r.dns -and $r.dns -ne 'unchanged' -and -not $script:dnsConfigured){Configure-DNS $r.dns}
    $scan=Scan-Strategies
    $selectionResult=Native $inputData.controller @('system','parse-scan',$scan.reportPath,$r.engine)
    $selected=$selectionResult.stdout|ConvertFrom-Json
    $capture=if($r.engine -eq 'zapret2'){@('--wf-tcp-out=80,443','--wf-udp-out=443,50000-65535')}else{@('--wf-tcp=80,443','--wf-udp=443,50000-65535')}
    $filter=if($selected.protocol -eq 'quic'){'--filter-udp=443'}elseif($selected.protocol -eq 'http'){'--filter-tcp=80'}else{'--filter-tcp=443'}
    $r | Add-Member -NotePropertyName args -NotePropertyValue @($capture+@($filter)+@($selected.args)) -Force
    $r | Add-Member -NotePropertyName mode -NotePropertyValue 'service' -Force
    $installed=Install-Method
    return @{installed=$installed;selectedStrategy=$selected;scanReport=$scan.reportPath;note='Only the protocol and scan targets in the report were tested. UDP voice and other networks require separate verification.'}
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
function Discover {
    $discoveryClock=[Diagnostics.Stopwatch]::StartNew()
    [Console]::WriteLine('Discovery phase: services')
    [Console]::WriteLine(('Discovery timing ms: services {0}' -f $discoveryClock.ElapsedMilliseconds))
    $serviceError=$null;$services=@();try{foreach($name in @('AccessWeaver-*','WireSockAppService','WireSockConnectService','wiresock-client-service','ByeDPI','ProxiFyreService','WinDivert','WinDivert14','NDISRD','zapret','zapret2','GoodbyeDPI','dnscrypt-proxy','CloudflareWARP')){foreach($svc in @(Get-Service -Name $name -ErrorAction SilentlyContinue)){$services+=@{name=$svc.Name;status=[string]$svc.Status;owned=$svc.Name.StartsWith('AccessWeaver-')}}}}catch{$serviceError=$_.Exception.Message}
    [Console]::WriteLine('Discovery phase: components')
    [Console]::WriteLine(('Discovery timing ms: components {0}' -f $discoveryClock.ElapsedMilliseconds))
    $assets=@{};foreach($engine in $assetNames.Keys){$assets[$engine]=Find-Source $engine}
    [Console]::WriteLine('Discovery phase: applications')
    [Console]::WriteLine(('Discovery timing ms: applications {0}' -f $discoveryClock.ElapsedMilliseconds))
    $apps=@{};foreach($variant in @('discord','discord-ptb','splitcord')){$apps[$variant]=Find-App $variant}
    [Console]::WriteLine('Discovery phase: conflicts')
    [Console]::WriteLine(('Discovery timing ms: conflicts {0}' -f $discoveryClock.ElapsedMilliseconds))
    $conflicts=@();$kaspersky=Get-Process -Name 'avp','avpui' -ErrorAction SilentlyContinue;if($kaspersky){$conflicts+=@('Kaspersky is running; WinDivert compatibility must be checked')};if(($services|Where-Object {$_.name -eq 'CloudflareWARP' -and $_.status -eq 'Running'})){$conflicts+=@('Cloudflare WARP is running; check routing conflicts')}
    [Console]::WriteLine('Discovery phase: refresh-task')
    [Console]::WriteLine(('Discovery timing ms: refresh-task {0}' -f $discoveryClock.ElapsedMilliseconds))
    $task=Get-RefreshTaskInspection
    [Console]::WriteLine('Discovery phase: final-paths')
    [Console]::WriteLine(('Discovery timing ms: final-paths {0}' -f $discoveryClock.ElapsedMilliseconds))
    $cli=WireSock-CLI;$dnsSnapshot=[bool](Test-Path -LiteralPath (Join-Path $root 'profiles\dns-original.json'))
    [Console]::WriteLine('Discovery phase: complete')
    [Console]::WriteLine(('Discovery timing ms: complete {0}' -f $discoveryClock.ElapsedMilliseconds))
    return @{services=@($services);serviceInspectionError=$serviceError;components=$assets;applications=$apps;wiresockCLI=$cli;conflicts=@($conflicts);managedRoot=$root;refreshTask=$task.present;refreshTaskInspectionError=$task.error;dnsSnapshot=$dnsSnapshot}
}
function Rollback {
    $rollbackErrors=@()
    for($i=$script:undo.Count-1;$i -ge 0;$i--){$item=$script:undo[$i];try{switch($item.kind){
        'service' {Stop-Service -Name $item.name -Force -ErrorAction SilentlyContinue;[void](Native 'sc.exe' @('delete',$item.name) @(0,1060))}
        'started-service' {Stop-Service -Name $item.name -ErrorAction Stop}
        'firewall' {Remove-NetFirewallRule -Name $item.name -ErrorAction SilentlyContinue}
        'task' {Unregister-ScheduledTask -TaskName $item.name -Confirm:$false -ErrorAction SilentlyContinue}
        'dns' {if(Test-Path -LiteralPath (Join-Path $root 'profiles\dns-original.json')){Restore-DNS}}
        'wiresock' {if($item.legacy){Stop-Service 'wiresock-client-service' -ErrorAction SilentlyContinue;[void](Native $item.cli @('uninstall') -Secret)}else{[void](Native $item.cli @('disconnect') -Secret);[void](Native $item.cli @('delete',$item.profile) -Secret)}}
        'cache' {if(-not (Under $item.path $env:APPDATA) -or -not (Under $item.backup (Join-Path $root 'backups'))){throw 'Invalid cache recovery path'};No-Reparse $item.path;No-Reparse $item.backup;if(Test-Path -LiteralPath $item.backup){if(Test-Path -LiteralPath $item.path){throw 'Discord created new cache; original cache backup retained for manual review'};Move-Item -LiteralPath $item.backup -Destination $item.path}}
        'file' {No-Reparse $item.path;if(Test-Path -LiteralPath $item.path){$currentHash=(Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash;if($currentHash -eq $item.originalHash){continue};if(-not $item.expectedHash -or $currentHash -ne $item.expectedHash){throw ('File changed outside this operation; review before restoring: '+$item.path)}};if($item.backup){if(-not (Under $item.backup (Join-Path $root 'backups'))){throw 'Recovery backup is outside protected storage'};No-Reparse $item.backup;if(-not $item.originalHash -or (Get-FileHash -LiteralPath $item.backup -Algorithm SHA256).Hash -ne $item.originalHash){throw 'Recovery backup content does not match the recorded original digest'};Copy-Item -LiteralPath $item.backup -Destination $item.path -Force}else{Remove-Item -LiteralPath $item.path -ErrorAction SilentlyContinue}}
    }}catch{$rollbackErrors+=@($_.Exception.Message)}}
    return $rollbackErrors
}
function Recover-Operation {
    if($r.journalId -notmatch '^workflow-[a-fA-F0-9]{32}\.json$'){throw 'Invalid recovery journal name'}
    $journal=Join-Path $root ('logs\'+$r.journalId);No-Reparse $journal;$saved=Get-Content -LiteralPath $journal -Raw|ConvertFrom-Json
    foreach($entry in @($saved.undo)){
        switch($entry.kind){
            'file' {$allowed=(Under $entry.path $root);if(-not $allowed){$allowed=(Under $entry.path (Join-Path $env:LOCALAPPDATA 'Discord')) -and ([IO.Path]::GetFileName($entry.path) -in @('version.dll','drover.ini'))};if(-not $allowed){throw 'Recovery journal contains an unmanaged file path'};if($entry.backup -and -not (Under $entry.backup (Join-Path $root 'backups'))){throw 'Recovery backup is outside protected storage'}}
            'service' {if($entry.name -notmatch '^AccessWeaver-(byedpi|proxifyre|zapret|zapret2|goodbyedpi|dnscrypt)$'){throw 'Recovery journal contains an unmanaged service'}}
            'started-service' {if($entry.name -ne 'AccessWeaver-byedpi'){throw 'Recovery journal contains an unmanaged restarted service'}}
            'firewall' {if($entry.name -notmatch '^AccessWeaver-[a-z]+-(Inbound|Outbound)$'){throw 'Recovery journal contains an unmanaged firewall rule'}}
            'task' {if($entry.name -ne 'AccessWeaver-WireSock-Refresh'){throw 'Recovery journal contains an unmanaged task'}}
            'dns' { }
            'wiresock' {if($entry.cli -ne (WireSock-CLI) -or (-not $entry.legacy -and $entry.profile -notmatch '^AccessWeaver-[a-f0-9]{32}$')){throw 'Recovery journal contains an unmanaged WireSock profile'}}
            'cache' {if($entry.path -ne (Join-Path $env:APPDATA 'discord') -or -not (Under $entry.backup (Join-Path $root 'backups'))){throw 'Recovery journal contains an unmanaged cache path'}}
            default {throw 'Unknown recovery journal operation'}
        }
    }
    $script:undo.Clear();foreach($entry in @($saved.undo)){$script:undo.Add($entry)};Save-Journal
    $errors=@(Rollback);if($errors.Count){throw ($errors -join '; ')}
    Event 'Selected operation recovered'
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
        'updates' {$allReleases=Read-RemoteJSON -Headers @{'User-Agent'='AccessWeaver'} -Uri 'https://api.github.com/repos/Yunushan/accessweaver/releases?per_page=30';$releases=@($allReleases | Where-Object {-not $_.draft});if(-not $releases.Count){throw 'No published AccessWeaver releases found'};$comparison=Native $inputData.controller (@('system','check-version')+@($releases|ForEach-Object {$_.tag_name}));$check=$comparison.stdout|ConvertFrom-Json;$release=$releases|Where-Object {$_.tag_name -eq $check.version}|Select-Object -First 1;@{version=$check.version;currentVersion=$check.currentVersion;updateAvailable=$check.updateAvailable;url=$release.html_url;publishedAt=$release.published_at}}
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
        'app-remove' {Remove-App $r.engine}
        'app-start' {Start-App $r.engine}
        'app-repair' {Stop-AppProcesses 'discord';Restore-Drover;Remove-App 'discord';Preserve-DiscordCache;Start-RepairProxy;Install-App 'discord';Install-Drover;@{repaired='discord';proxy='127.0.0.1:1080'}}
        'uninstall' {Remove-All;$uninstaller=Join-Path $env:ProgramFiles 'AccessWeaver\unins000.exe';if(Test-Path -LiteralPath $uninstaller){No-Reparse $uninstaller;$script:pendingUninstaller=$uninstaller;@{message='Owned system changes restored; registered uninstaller will start after releasing the workflow lock. Close AccessWeaver if requested. Recovery logs and vendor products are retained.'}}else{@{message='Owned system changes restored. Stop the portable core before deleting its folder. Recovery logs and vendor products are retained.'}}}
        'recover' {Recover-Operation}
        default {throw 'Unknown action'}
    }
    $result.ok=$true;$result.data=$data
    $script:journalState='succeeded'
} catch {
    $result.error=$_.Exception.Message
    $script:journalState='failed'
    if($script:dnsTouched -and (Test-Path -LiteralPath (Join-Path $root 'profiles\dns-original.json'))){try{Restore-DNS}catch{$result.dnsRecoveryError=$_.Exception.Message}}
    if($r.action -in @('install','auto-install','connect','config','download','dns','refresh','scan','app-install','app-repair')){$result.rollbackErrors=@(Rollback);if(-not $result.rollbackErrors.Count){$script:journalState='rolled-back'}}
    Write-Output ('Workflow failed: '+$result.error)
} finally {
    Save-Journal
    if($script:mutex){if($script:ownsMutex){$script:mutex.ReleaseMutex()};$script:mutex.Dispose()}
    if($result.ok -and $script:pendingUninstaller){try{Start-Process -FilePath $script:pendingUninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -WindowStyle Hidden}catch{$result.ok=$false;$result.error=$_.Exception.Message;$script:journalState='failed';Save-Journal}}
    $result.events=@($script:events.ToArray());$result.rebootRequired=$script:rebootRequired;$result.journal=$script:journalPath
    [IO.File]::WriteAllText($inputData.resultPath,($result|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))
}
if(-not $result.ok){exit 1}
