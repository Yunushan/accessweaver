# Run the real NetSecurity operations with an inert program path on a disposable Windows runner.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
if($env:OS -cne 'Windows_NT' -or $env:GITHUB_ACTIONS -cne 'true' -or
   $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
   $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver' -or $env:ACCESSWEAVER_DISPOSABLE_FIREWALL_TEST -cne '1'){
    throw 'Native firewall test requires a disposable hosted Windows runner'
}
if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){
    throw 'Native firewall test requires Windows PowerShell 5.1'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try{$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
if(-not $admin){throw 'Native firewall test requires a hosted administrator token'}
$project=Split-Path -Parent $PSScriptRoot
$head=@(& git -C $project rev-parse HEAD 2>$null)
if($LASTEXITCODE -ne 0 -or $head.Count -ne 1 -or $env:GITHUB_SHA -cnotmatch '\A[a-f0-9]{40}\z' -or $head[0] -cne $env:GITHUB_SHA){
    throw 'Native firewall test source identity differs'
}
$dirty=@(& git -C $project status --porcelain --untracked-files=no 2>$null)
if($LASTEXITCODE -ne 0 -or $dirty.Count){throw 'Native firewall test requires clean tracked source'}
$workflow=Join-Path $project 'internal\workflow\windows.ps1'
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($workflow,[ref]$tokens,[ref]$issues)
if($issues.Count){throw 'Native firewall test could not parse the workflow'}
foreach($name in @('Get-ManagedFirewallRule','Remove-ManagedFirewallRule','Firewall')){
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name})
    if($nodes.Count -ne 1){throw 'Native firewall test dependency differs'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Get-FixtureRule([string]$Name){
    $warnings=@()
    $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -WarningAction SilentlyContinue -WarningVariable warnings -ErrorAction Stop | Where-Object Name -CEQ $Name)
    if($warnings.Count -or $rules.Count -gt 1){throw 'Fixture rule inventory incomplete'}
    return $rules
}

$assetNames=@{byedpi='ciadpi.exe'}
$root=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-firewall-'+[guid]::NewGuid().ToString('N'))
$program=Join-Path $root 'components\byedpi\ciadpi.exe'
$script:undo=[Collections.Generic.List[object]]::new()
$script:savedRules=[Collections.Generic.List[object]]::new()
# The source-only suite exercises persistence. Keep identities here for native fixture cleanup.
function Save-Journal {$script:savedRules.Add($script:undo[$script:undo.Count-1])}
$names=@('AccessWeaver-byedpi-Inbound','AccessWeaver-byedpi-Outbound')
$step='preflight'
try{
    foreach($name in $names){
        if($null -ne (Get-ManagedFirewallRule $name)){throw 'Existing rule'}
    }
    $step='create and reuse'
    Firewall 'byedpi' $program
    Firewall 'byedpi' $program
    if($script:savedRules.Count -ne 2){throw 'Unexpected creation count'}
    $original=@($script:savedRules.ToArray())
    foreach($entry in $original){
        $rule=Get-ManagedFirewallRule $entry.name $entry.instance -Journal
        if($rule -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Rule readback differs'}
    }

    $step='remove and retry'
    foreach($entry in $original){
        Remove-ManagedFirewallRule $entry.name $entry.instance -Journal
        Remove-ManagedFirewallRule $entry.name $entry.instance -Journal
    }

    $step='refuse stale journal'
    Firewall 'byedpi' $program
    if($script:savedRules.Count -ne 4){throw 'Unexpected replacement count'}
    for($i=0;$i -lt $original.Count;$i++){
        $entry=$original[$i]
        $replacement=$script:savedRules[$i+$original.Count]
        $refused=$false
        try{Remove-ManagedFirewallRule $entry.name $entry.instance -Journal}catch{
            $refused=$_.Exception.Message -ceq 'Managed firewall rule does not match the recovery journal'
        }
        if(-not $refused -or $null -eq (Get-ManagedFirewallRule $replacement.name $replacement.instance -Journal)){
            throw 'Replacement rule did not survive stale recovery'
        }
    }
    $step='explicit cleanup'
    foreach($name in $names){Remove-ManagedFirewallRule $name}
    foreach($name in $names){
        if($null -ne (Get-ManagedFirewallRule $name)){throw 'Rule remains'}
    }
}catch{
    throw ('Native firewall ownership check failed during '+$step)
}finally{
    $cleanupFailed=$false
    foreach($entry in $script:savedRules){
        try{
            $nativeName=$entry.name+'-'+$entry.instance
            $rule=Get-FixtureRule $nativeName
            if($null -eq $rule){continue}
            if($rule.Description -cne ('AccessWeaver managed rule '+$entry.instance)){throw 'Fixture marker differs'}
            Remove-NetFirewallRule -InputObject $rule -Confirm:$false -ErrorAction Stop
            if($null -ne (Get-FixtureRule $nativeName)){throw 'Fixture rule remains'}
        }catch{$cleanupFailed=$true}
    }
    if($cleanupFailed){throw 'Native firewall fixture cleanup could not be verified'}
}
Write-Output 'Native firewall ownership, stale-journal refusal and cleanup passed.'
