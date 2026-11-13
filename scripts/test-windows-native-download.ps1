# Hosted-only qualification of the product's actual download transports.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:OS -cne 'Windows_NT' -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver' -or $env:ACCESSWEAVER_NATIVE_DOWNLOAD_CHECK -cne '1'){throw 'Disposable hosted Windows qualification required'}
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop'){throw 'Stock Windows PowerShell 5.1 required'}
$expectedHost=@{amd64='x64';arm64='arm64'}[$Architecture]
if([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant() -cne $expectedHost){throw 'Native matching architecture required'}
$project=Split-Path -Parent $PSScriptRoot
$source=$env:GITHUB_SHA
if($source -cnotmatch '^[a-f0-9]{40}$' -or (git -C $project rev-parse HEAD).Trim() -cne $source -or $LASTEXITCODE -ne 0){throw 'Source identity mismatch'}
if((git -C $project status --porcelain --untracked-files=no)){throw 'Tracked source must be clean'}
$paths=@('internal/workflow/windows.ps1','scripts/vendor-windows-pins.json','scripts/test-windows-native-download.ps1','.github/workflows/windows-native-download.yml')
$hashes=@{};foreach($path in $paths){$hashes[$path]=(Get-FileHash -LiteralPath (Join-Path $project $path) -Algorithm SHA256).Hash.ToLowerInvariant()}
$pins=Get-Content -Raw -LiteralPath (Join-Path $project $paths[1]) | ConvertFrom-Json
if($pins.schemaVersion -ne 1){throw 'Unknown pin schema'}
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project $paths[0]),[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Product source parse failed'}
$names=@('Quote-Arg','Native-Argument','Allowed-Download','Resolve-ComponentDownloadRedirect','Throw-ComponentDownloadFailure','Test-ComponentDownloadTerminal','New-ComponentDownloadBudget','Get-ComponentDownloadRemaining','Wait-ComponentDownloadTask','Write-ComponentDownloadChunk','Receive-ComponentDownloadStream','Assert-ComponentDownloadLength','Set-ComponentDownloadHeaders','New-ComponentDownloadRequest','Invoke-ComponentDownloadDotNet','New-ComponentDownloadCurlStart','New-ComponentDownloadCurlProcess','Wait-ComponentDownloadProcessExit','Invoke-ComponentDownloadCurlOnce', 'Invoke-ComponentDownloadCurl','WireSock-InstallerPlan')
foreach($name in $names){$nodes=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name});if($nodes.Count -ne 1){throw 'Product transport function unavailable'};. ([scriptblock]::Create($nodes[0].Extent.Text))}
$cases=@();$failed=$false
$wirePlan=WireSock-InstallerPlan $Architecture
$sourceText=[IO.File]::ReadAllText((Join-Path $project $paths[0]))
foreach($engine in @('proxifyre','dnscrypt','wiresock')){
    if($engine -ceq 'wiresock'){$pin=@{url=$wirePlan.url;sha256=$wirePlan.sha256;bytes=0};$maximum=64MB}
    else {
        $pin=$pins.targets.$Architecture.$engine
        if($pin.url -cnotmatch '^https://github[.]com/(wiresock/proxifyre|DNSCrypt/dnscrypt-proxy)/releases/download/[^/]+/[^/]+$' -or $pin.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $pin.bytes -le 0 -or $pin.bytes -gt 8MB){throw 'Unexpected pinned asset'}
        $maximum=[long]$pin.bytes+1MB
    }
    foreach($transport in @('dotnet','curl')){
        $passed=$false;$output=[IO.MemoryStream]::new();$sha256=[Security.Cryptography.SHA256]::Create()
        try {
            Allowed-Download $pin.url
            $budget=New-ComponentDownloadBudget -MaximumBytes $maximum -TimeoutMilliseconds 90000
            if($transport -ceq 'dotnet'){Invoke-ComponentDownloadDotNet $pin.url $output $budget}
            else {Invoke-ComponentDownloadCurl $pin.url $output $budget}
            if($output.Length -le 0 -or ($pin.bytes -gt 0 -and $output.Length -ne $pin.bytes)){throw 'Asset length mismatch'}
            $output.Position=0;$digest=([BitConverter]::ToString($sha256.ComputeHash($output))).Replace('-','').ToLowerInvariant()
            if($digest -cne $pin.sha256){throw 'Asset hash mismatch'}
            $passed=$true
        } catch {$failed=$true} finally {$sha256.Dispose();$output.Dispose()}
        $cases+=@{engine=$engine;transport=$transport;passed=$passed}
    }
}
# Dynamic signed-installer routes have no source pin. Compare independent
# product transport downloads in memory only by digest; never execute them or
# export installer bytes, URLs, certificate contents or computed digests.
$discordPrefix='https://discord.com/api/downloads/distributions/app/installers/latest?channel='
$microsoftUrl='https://aka.ms/vs/17/release/vc_redist.x64.exe'
if(-not $sourceText.Contains($discordPrefix) -or -not $sourceText.Contains($microsoftUrl)){throw 'Product installer routes changed'}
foreach($route in @(
    @{engine='discord-stable';url=($discordPrefix+'stable&platform=win&arch=x64')},
    @{engine='discord-ptb';url=($discordPrefix+'ptb&platform=win&arch=x64')},
    @{engine='microsoft-vc';url=$microsoftUrl}
)){
    $routeCases=@();$routeDigests=@()
    foreach($transport in @('dotnet','curl')){
        $passed=$false;$cleaned=$false;$output=$null;$owned=$false
        $budget=$null
        $stage='admission'
        $failureStage='none'
        $terminalFailure=$false
        $budgetExpired=$false
        $admittedMiB=0
        $path=Join-Path $env:RUNNER_TEMP ('accessweaver-native-download-'+[guid]::NewGuid().ToString('N')+'.tmp')
        try {
            Allowed-Download $route.url
            $output=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$owned=$true
            $stage='transfer'
            $budget=New-ComponentDownloadBudget -MaximumBytes 256MB -TimeoutMilliseconds 120000
            if($transport -ceq 'dotnet'){Invoke-ComponentDownloadDotNet $route.url $output $budget}
            else {Invoke-ComponentDownloadCurl $route.url $output $budget}
            $stage='digest'
            if($output.Length -le 0){throw 'Empty installer'}
            $output.Position=0;$sha256=[Security.Cryptography.SHA256]::Create()
            try {$digest=([BitConverter]::ToString($sha256.ComputeHash($output))).Replace('-','').ToLowerInvariant()}finally{$sha256.Dispose()}
            $routeDigests+=@($digest);$passed=$true
        } catch {
            $failed=$true
            $failureStage=$stage
            $terminalFailure=Test-ComponentDownloadTerminal $_
        } finally {
            if($budget){
                $budgetExpired=$budget.Clock.ElapsedMilliseconds -ge $budget.TimeoutMilliseconds
                $admittedMiB=[int][Math]::Floor($budget.Written / 1MB)
            }
            if($output){try {$output.Dispose()}catch {$passed=$false;$failed=$true;$failureStage='cleanup'}}
            if($owned){try {[IO.File]::Delete($path);$cleaned=-not [IO.File]::Exists($path)}catch {$cleaned=$false}}
            else {$cleaned=$true}
            if(-not $cleaned){$passed=$false;$failed=$true;$failureStage='cleanup'}
        }
        $routeCases+=@{
            engine=$route.engine
            transport=$transport
            passed=$passed
            temporaryFileRemoved=$cleaned
            failureStage=$failureStage
            terminalFailure=$terminalFailure
            budgetExpired=$budgetExpired
            admittedMiB=$admittedMiB
        }
    }
    $same=($routeDigests.Count -eq 2 -and $routeDigests[0] -ceq $routeDigests[1])
    if(-not $same){$failed=$true}
    foreach($case in $routeCases){$case['independentDownloadsMatch']=$same;$cases+=@($case)}
}
# Hold a local listener without forwarding. With a bypass list of "*", curl
# must still reach this listener and fail without receiving any asset bytes.
$proxyObserved=$false
$proxyFailedClosed=$false
$previousNoProxy=$env:NO_PROXY
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,1080)
$accept=$null
$output=[IO.MemoryStream]::new()
try {
    $listener.ExclusiveAddressUse=$true
    $listener.Start()
    $accept=$listener.AcceptTcpClientAsync()
    $env:NO_PROXY='*'
    $proxyBudget=New-ComponentDownloadBudget -MaximumBytes 8MB -TimeoutMilliseconds 5000
    try {
        Invoke-ComponentDownloadCurl $pins.targets.$Architecture.proxifyre.url $output $proxyBudget -Proxy
    } catch {
        $proxyObserved=$accept.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion
        $proxyFailedClosed=$proxyObserved -and $output.Length -eq 0
    }
} catch {
    $failed=$true
} finally {
    $env:NO_PROXY=$previousNoProxy
    $listener.Stop()
    if($accept){
        try {
            $client=$accept.GetAwaiter().GetResult()
            $client.Dispose()
        } catch {}
    }
    $output.Dispose()
}
if(-not $proxyFailedClosed){$failed=$true}
$report=@{schemaVersion=3;proxyConnectionObserved=$proxyObserved;proxyBypassRejected=$proxyFailedClosed;sourceCommit=$source;target=('windows/'+$Architecture);sourceSHA256=$hashes;cases=$cases;vendorDownloadsAttempted=$true;vendorCodeExecuted=$false;proxyPathQualified=$false;allVendorRoutesQualified=$false;productionQualificationComplete=$false}
$directory=Join-Path $project 'build/native-download-checks';[void][IO.Directory]::CreateDirectory($directory)
[IO.File]::WriteAllText((Join-Path $directory ('native-download-'+$Architecture+'.json')),($report|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
if($failed){throw 'One or more fixed native download checks failed'}
Write-Output 'PASS fixed pinned native download checks'
