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
$names=@('Quote-Arg','Native-Argument','Allowed-Download','Resolve-ComponentDownloadRedirect','Throw-ComponentDownloadFailure','Test-ComponentDownloadTerminal','New-ComponentDownloadBudget','Get-ComponentDownloadRemaining','Wait-ComponentDownloadTask','Write-ComponentDownloadChunk','Receive-ComponentDownloadStream','Assert-ComponentDownloadLength','Set-ComponentDownloadHeaders','New-ComponentDownloadRequest','Invoke-ComponentDownloadDotNet','New-ComponentDownloadCurlStart','New-ComponentDownloadCurlProcess','Wait-ComponentDownloadProcessExit','Invoke-ComponentDownloadCurlOnce','Invoke-ComponentDownloadCurl')
foreach($name in $names){$nodes=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name});if($nodes.Count -ne 1){throw 'Product transport function unavailable'};. ([scriptblock]::Create($nodes[0].Extent.Text))}
$cases=@();$failed=$false
foreach($engine in @('proxifyre','dnscrypt')){
    $pin=$pins.targets.$Architecture.$engine
    if($pin.url -cnotmatch '^https://github[.]com/(wiresock/proxifyre|DNSCrypt/dnscrypt-proxy)/releases/download/[^/]+/[^/]+$' -or $pin.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $pin.bytes -le 0 -or $pin.bytes -gt 8MB){throw 'Unexpected pinned asset'}
    foreach($transport in @('dotnet','curl')){
        $passed=$false;$output=[IO.MemoryStream]::new();$sha256=[Security.Cryptography.SHA256]::Create()
        try {
            Allowed-Download $pin.url
            $budget=New-ComponentDownloadBudget -MaximumBytes ([long]$pin.bytes+1MB) -TimeoutMilliseconds 90000
            if($transport -ceq 'dotnet'){Invoke-ComponentDownloadDotNet $pin.url $output $budget}
            else {Invoke-ComponentDownloadCurl $pin.url $output $budget}
            if($output.Length -ne $pin.bytes){throw 'Asset length mismatch'}
            $output.Position=0;$digest=([BitConverter]::ToString($sha256.ComputeHash($output))).Replace('-','').ToLowerInvariant()
            if($digest -cne $pin.sha256){throw 'Asset hash mismatch'}
            $passed=$true
        } catch {$failed=$true} finally {$sha256.Dispose();$output.Dispose()}
        $cases+=@{engine=$engine;transport=$transport;passed=$passed}
    }
}
$report=@{schemaVersion=1;sourceCommit=$source;target=('windows/'+$Architecture);sourceSHA256=$hashes;cases=$cases;realVendorAssetsDownloaded=$true;vendorCodeExecuted=$false;proxyPathQualified=$false;allVendorRoutesQualified=$false;productionQualificationComplete=$false}
$directory=Join-Path $project 'build/native-download-checks';[void][IO.Directory]::CreateDirectory($directory)
[IO.File]::WriteAllText((Join-Path $directory ('native-download-'+$Architecture+'.json')),($report|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
if($failed){throw 'One or more fixed native download checks failed'}
Write-Output 'PASS fixed pinned native download checks'
