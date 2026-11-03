# Execute pinned upstream help/version commands only on disposable hosted Windows.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:OS -ne 'Windows_NT' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:ACCESSWEAVER_DISPOSABLE_WINDOWS_VENDOR_PREFLIGHT -ne '1' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver'){throw 'Vendor execution requires explicit disposable hosted Windows opt-in'}
$source=$env:GITHUB_SHA;$sourceRef=$env:GITHUB_REF;$run=$env:GITHUB_RUN_ID
if($source -notmatch '^[a-f0-9]{40}$' -or $sourceRef -notmatch '^refs/(heads/[A-Za-z0-9_./-]+|pull/[0-9]+/merge)$' -or $run -notmatch '^[0-9]+$'){throw 'Missing source-bound hosted context'}
$hostArch=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if(@{amd64='x64';arm64='arm64'}[$Architecture] -cne $hostArch){throw 'Vendor probe requires the matching native Windows host'}
$project=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if((git -C $project rev-parse HEAD).Trim() -cne $source -or $LASTEXITCODE -ne 0){throw 'Checkout source differs from hosted context'}
if((git -C $project status --porcelain --untracked-files=no)){throw 'Tracked checkout is not clean'}
$workflow=Join-Path $project 'internal\workflow\windows.ps1'
$workflowHash=(Get-FileHash -LiteralPath $workflow -Algorithm SHA256).Hash.ToLowerInvariant()
$pinsPath=Join-Path $PSScriptRoot 'vendor-windows-pins.json'
$pinsHash=(Get-FileHash -LiteralPath $pinsPath -Algorithm SHA256).Hash.ToLowerInvariant()
$pins=Get-Content -LiteralPath $pinsPath -Raw | ConvertFrom-Json
if($pins.schemaVersion -ne 1){throw 'Unknown vendor pin schema'}
$selected=$pins.targets.$Architecture
Add-Type -AssemblyName System.IO.Compression.FileSystem
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($workflow,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Workflow parse failed'}
$functions=@('No-Reparse','Under','Quote-Arg','Native-Argument','New-ToolCapture','Receive-ToolCapture','Wait-ToolCapture','Stop-ToolTreeWithHelper','Stop-ToolTree','Run-Tool','Native','Assert-ComponentZipBudget','Component-ArchivePlan','Expand-Safe','Backup-File','Expected-Hash','Save-Journal','Get-PEMachine','Component-ArchitecturePlan','Find-Source','Get-DriverServiceControllers','Get-ServiceInspection')
foreach($name in $functions){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Required workflow helper missing or duplicated'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Require([bool]$ok,[string]$message){if(-not $ok){throw $message}}
function Receive-PinnedAsset($pin,[string]$path){
    Require ($pin.url -match '^https://github[.]com/(wiresock/proxifyre|ViRb3/wgcf|DNSCrypt/dnscrypt-proxy)/releases/download/[^/]+/[^/]+$' -and $pin.sha256 -cmatch '^[a-f0-9]{64}$' -and $pin.bytes -gt 0 -and $pin.bytes -le 32MB) 'Invalid bounded upstream pin'
    $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false
    $client=[Net.Http.HttpClient]::new($handler);$cancel=[Threading.CancellationTokenSource]::new(90000);$response=$null;$stream=$null;$file=$null
    try {
        $url=[uri]$pin.url
        for($redirects=0;$redirects -le 5;$redirects++){
            Require ($url.Scheme -ceq 'https' -and -not $url.UserInfo -and -not $url.Fragment) 'Download redirect must preserve HTTPS'
            if($response){$response.Dispose();$response=$null}
            $response=$client.GetAsync($url,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
            if([int]$response.StatusCode -in @(301,302,303,307,308)){
                Require ($null -ne $response.Headers.Location) 'Missing redirect location'
                $url=[uri]::new($url,$response.Headers.Location);continue
            }
            break
        }
        Require ($response.IsSuccessStatusCode -and ($null -eq $response.Content.Headers.ContentLength -or $response.Content.Headers.ContentLength -eq $pin.bytes)) 'Unexpected upstream response'
        $stream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $buffer=[byte[]]::new(65536);$total=0L
        while(($count=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){
            $total+=$count;Require ($total -le $pin.bytes) 'Asset exceeds its pinned size'
            $file.Write($buffer,0,$count)
        }
        Require ($total -eq $pin.bytes) 'Asset is incomplete'
    } finally {if($file){$file.Dispose()};if($stream){$stream.Dispose()};if($response){$response.Dispose()};$cancel.Dispose();$client.Dispose()}
    Require ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $pin.sha256) 'Asset SHA-256 differs from its pin'
}
function Public-VendorFailureMessages([string]$text){
    $tokenIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$identity=$tokenIdentity.Name} finally {$tokenIdentity.Dispose()}
    $machine=[Environment]::MachineName
    $messages=@()
    foreach($line in ($text -split '\r?\n')){
        if($line -notmatch '(?i)exception|error|failed|could not|unable|invalid|not found|unknown|terminated'){continue}
        $safe=$line.Replace($identity,'<account>').Replace($machine,'<machine>')
        $safe=$safe -replace '(?i)[A-Z]:[\\/].*$','<path>' -replace '\\\\.*$','<path>'
        $safe=$safe -replace '(?i)[A-Za-z0-9_-]*(token|secret|password|credential|account|key|authorization|bearer)[A-Za-z0-9_-]*.*$','<redacted>'
        $safe=$safe -replace '\bS-[0-9]+(?:-[0-9]+){2,}\b','<sid>'
        $safe=$safe -replace '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}','<id>'
        $safe=($safe -replace '[^\x20-\x7e]',' ').Trim()
        if($safe.Length -gt 160){$safe=$safe.Substring(0,160)}
        if($safe){$messages+=,$safe};if($messages.Count -ge 4){break}
    }
    return $messages
}
function Service-Snapshot {
    $inspection=Get-ServiceInspection;Require ($null -eq $inspection.error) 'Relevant service inspection is incomplete'
    return (ConvertTo-Json -InputObject @($inspection.services | Sort-Object name) -Depth 4 -Compress)
}
function Invoke-PrivateStartup([string]$binary,[string[]]$arguments,[string]$profile){
    $system=[Environment]::SystemDirectory;$windows=Split-Path -Parent $system
    $saved=@{};foreach($entry in Get-ChildItem Env:){$saved[$entry.Name]=$entry.Value}
    $allowed=@{SystemRoot=$windows;WINDIR=$windows;SystemDrive=[IO.Path]::GetPathRoot($system).TrimEnd('\');ComSpec=(Join-Path $system 'cmd.exe');PATH=($system+';'+$windows);TEMP=$profile;TMP=$profile;USERPROFILE=$profile;APPDATA=$profile;LOCALAPPDATA=$profile}
    try {
        foreach($entry in Get-ChildItem Env:){[Environment]::SetEnvironmentVariable($entry.Name,$null,'Process')}
        foreach($name in $allowed.Keys){[Environment]::SetEnvironmentVariable($name,$allowed[$name],'Process')}
        return (Native $binary $arguments ((0..255)+@(1067,-532462766,-1073741515,-1073741701)) -Secret -Timeout 30)
    } finally {
        foreach($entry in Get-ChildItem Env:){[Environment]::SetEnvironmentVariable($entry.Name,$null,'Process')}
        foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
    }
}
$temporary=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\');No-Reparse $temporary
$capsule=Join-Path $temporary ('accessweaver-vendor-preflight-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($capsule)
$script:undo=[Collections.Generic.List[object]]::new();$script:journalPath=$null
$root=Join-Path $capsule 'managed';$r=[pscustomobject]@{bundlePath=(Join-Path $capsule 'payloads')}
$inputData=[pscustomobject]@{nativeArchitecture=$Architecture}
$assetNames=@{proxifyre='ProxiFyre.exe';wgcf='wgcf.exe';dnscrypt='dnscrypt-proxy.exe'}
$repositories=@{proxifyre='wiresock/proxifyre';wgcf='ViRb3/wgcf';dnscrypt='DNSCrypt/dnscrypt-proxy'}
$failures=@();$records=@();$failure=$false;$cleaned=$false;$stage='service-baseline';$failureType=$null;$failureInnerType=$null;$startupDiagnostic=$null
try {
    $before=Service-Snapshot
    foreach($engine in @('proxifyre','wgcf','dnscrypt')){
        $startupDiagnostic=$null
        try {
        $stage='download-'+$engine;$pin=$selected.$engine;$plan=Component-ArchitecturePlan $engine
        Require ($pin.url.StartsWith(('https://github.com/'+$repositories[$engine]+'/releases/download/'),[StringComparison]::Ordinal) -and $pin.asset -match $plan.assetPattern -and ([uri]$pin.url).AbsolutePath.EndsWith('/'+$pin.asset) -and $pin.binarySHA256 -cmatch '^[a-f0-9]{64}$') 'Native asset pin does not match the component plan'
        $asset=Join-Path $capsule $pin.asset;Receive-PinnedAsset $pin $asset
        $destination=Join-Path $r.bundlePath $engine;[void][IO.Directory]::CreateDirectory($destination)
        if($pin.member){
            Expand-Safe $asset $destination
            $binary=Join-Path $destination $pin.member;Require (Under $binary $destination) 'Pinned member escapes payload'
        }else{$binary=Join-Path $destination 'wgcf.exe';[IO.File]::Copy($asset,$binary,$false)}
        $binary=[IO.Path]::GetFullPath($binary)
        $stage='identity-'+$engine
        Require ((Get-PEMachine $binary) -eq $plan.machine -and (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $pin.binarySHA256) 'Real executable identity differs from the native pin'
        Require ((Find-Source $engine) -ieq $binary) 'Product discovery did not select the real native executable'
        $arguments=switch($engine){'proxifyre' {@('help')} 'wgcf' {@('--help')} 'dnscrypt' {@('-version')}}
        $profile=Join-Path $capsule ('profile-'+$engine);[void][IO.Directory]::CreateDirectory($profile)
        $stage='process-'+$engine;$clock=[Diagnostics.Stopwatch]::StartNew();$result=Invoke-PrivateStartup $binary $arguments $profile;$clock.Stop();$elapsed=$clock.ElapsedMilliseconds
        $stage='result-'+$engine
        $startupDiagnostic=@{engine=$engine;exitCode=$result.exitCode;outputComplete=$result.outputComplete;stdoutCharacters=$result.stdout.Length;stderrCharacters=$result.stderr.Length;loaderFailureClass='none'}
        $startupDiagnostic.outputTags=@(foreach($tag in @('FileNotFoundException','BadImageFormatException','UnauthorizedAccessException','ArgumentNullException','TypeInitializationException','TypeLoadException','Win32Exception','NDISRD','NLog','Topshelf','ProxiFyre.Configuration')){if(($result.stdout+$result.stderr).Contains($tag)){$tag}})
        $startupDiagnostic.mixedModeDependencyMarker=(($result.stdout+$result.stderr) -match 'socksify|Socksifier|mixed.mode')
        $startupDiagnostic.configurationDependencyMarker=(($result.stdout+$result.stderr) -match 'ProxiFyre[.]Configuration')
        if($result.exitCode -ne 0){$startupDiagnostic.sanitizedFailureMessages=@(Public-VendorFailureMessages ($result.stdout+[Environment]::NewLine+$result.stderr))}
        if($result.stderr -match 'could not establish its secure native dependency loading policy'){$startupDiagnostic.loaderFailureClass='native-loader-policy'}
        elseif(($result.stdout+$result.stderr) -match 'Could not load file or assembly|FileNotFoundException|BadImageFormatException'){$startupDiagnostic.loaderFailureClass='assembly-load'}
        elseif(($result.stdout+$result.stderr) -match 'You must install|framework.*not found|MSVCP|VCRUNTIME'){$startupDiagnostic.loaderFailureClass='runtime-missing'}
        elseif(($result.stdout+$result.stderr) -match 'administrator privileges|Administrator console'){$startupDiagnostic.loaderFailureClass='privilege-denial'}
        Require ($result.exitCode -eq 0 -and $result.outputComplete -and $elapsed -le 30000) 'Vendor startup did not complete within its bound'
        $matched=switch($engine){'proxifyre' {$result.stdout -match '(?i)help' -and $result.stdout -match '(?i)install' -and $result.stdout -match '(?i)uninstall'} 'wgcf' {$result.stdout -match 'wgcf is a utility' -and $result.stdout -match 'Available Commands:'} 'dnscrypt' {$result.stdout.Trim() -ceq $pin.version}}
        $stage='output-'+$engine
        $startupDiagnostic.helpMarker=($result.stdout -match '(?i)help');$startupDiagnostic.installMarker=($result.stdout -match '(?i)install');$startupDiagnostic.uninstallMarker=($result.stdout -match '(?i)uninstall')
        Require $matched 'Vendor startup output does not match the pinned command contract'
        Require ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $pin.binarySHA256) 'Executable changed during startup'
        $records+=@{engine=$engine;version=$pin.version;asset=$pin.asset;assetSHA256=$pin.sha256;binarySHA256=$pin.binarySHA256;coffMachine=$plan.machine;discoverySelectedPinnedExecutable=$true;helpOrVersionPassed=$true;exitCode=$result.exitCode;outputComplete=$result.outputComplete;elapsedMilliseconds=$elapsed;deadlineMilliseconds=30000;childEnvironmentSanitized=$true}
        } catch {
            $failure=$true;$failureType=$_.Exception.GetType().FullName;$failureInnerType=$null
            if($_.Exception.InnerException){$failureInnerType=$_.Exception.InnerException.GetType().FullName}
            if($_.Exception.Message -match '^Tool failed: (ProxiFyre|wgcf|dnscrypt-proxy)[.]exe [(]exit (-?[0-9]+)[)]$'){$startupDiagnostic=@{toolExitCode=[int]$Matches[2]}}
            $failures+=@{stage=$stage;exceptionType=$failureType;innerExceptionType=$failureInnerType;startup=$startupDiagnostic}
        }
    }
    $stage='service-comparison';Require ((Service-Snapshot) -ceq $before) 'Relevant service state changed during help/version probes'
} catch {
    $failure=$true;$failureType=$_.Exception.GetType().FullName
    if($_.Exception.InnerException){$failureInnerType=$_.Exception.InnerException.GetType().FullName}
    if($_.Exception.Message -match '^Tool failed: (ProxiFyre|wgcf|dnscrypt-proxy)[.]exe [(]exit (-?[0-9]+)[)]$'){$startupDiagnostic=@{toolExitCode=[int]$Matches[2]}}
    $failures+=@{stage=$stage;exceptionType=$failureType;innerExceptionType=$failureInnerType;startup=$startupDiagnostic}
}
finally {
    $resolved=[IO.Path]::GetFullPath($capsule)
    Require ((Split-Path -Parent $resolved) -ieq $temporary -and (Split-Path -Leaf $resolved) -match '^accessweaver-vendor-preflight-[a-f0-9]{32}$') 'Refusing unexpected capsule cleanup target'
    No-Reparse $resolved
    Require (@(Get-ChildItem -LiteralPath $resolved -Force -Recurse -Attributes ReparsePoint).Count -eq 0) 'Refusing capsule cleanup with reparse entries'
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $cleaned=-not (Test-Path -LiteralPath $resolved)
}
if($failure){
    $diagnostic=@{failures=$failures;successfulComponents=@($records.engine);ownedCapsuleRemoved=$cleaned;productionQualificationComplete=$false}
    Write-Output ('Fixed vendor startup failure: '+($diagnostic|ConvertTo-Json -Depth 6 -Compress))
}
Require (-not $failure -and $cleaned -and $records.Count -eq 3) ('Vendor startup preflight failed at '+$stage+'; no production qualification is established')
$report=@{schemaVersion=1;sourceCommit=$source;sourceRef=$sourceRef;runID=$run;target=('windows/'+$Architecture);hostArchitecture=$hostArch;workflowScriptSHA256=$workflowHash;pinsSHA256=$pinsHash;components=$records;relevantServiceStateUnchanged=$true;ownedCapsuleRemoved=$cleaned;commandsRequestedServiceOrDriverChanges=$false;networkIsolationVerified=$false;vendorRoutingQualified=$false;productionQualificationComplete=$false}
$directory=Join-Path $project 'build\vendor-startup-checks';No-Reparse $directory;[void][IO.Directory]::CreateDirectory($directory)
$path=Join-Path $directory ('vendor-startup-windows-'+$Architecture+'.json')
$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 6));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
Write-Output ('PASS three pinned native vendor help/version probes on windows/'+$Architecture)
