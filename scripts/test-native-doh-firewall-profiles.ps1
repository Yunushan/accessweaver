[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReportPath)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
   $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
   $env:GITHUB_REPOSITORY -cne 'Yunushan/accessweaver' -or $env:ACCESSWEAVER_DOH_PROFILE_TEST -cne '1'){
    throw 'DoH firewall profile comparison requires a disposable hosted Windows runner'
}
if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){
    throw 'Windows PowerShell 5.1 required'
}
$architecture=switch -CaseSensitive ($env:RUNNER_ARCH){
    'X64' {'amd64'}
    'ARM64' {'arm64'}
    default {throw 'Hosted Windows architecture required'}
}
Add-Type -TypeDefinition '
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class AccessWeaverFirewallProfileNativeIdentity {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    public static bool Matches(string architecture) {
        using (Process process = Process.GetCurrentProcess()) {
            ushort machine, native;
            if (!IsWow64Process2(process.Handle, out machine, out native)) return false;
            return machine == 0 && native == (architecture == "amd64" ? 0x8664 : 0xaa64);
        }
    }
}
'
if(-not [AccessWeaverFirewallProfileNativeIdentity]::Matches($architecture)){throw 'Native PowerShell process architecture differs'}
$computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if($computer.Model -notmatch 'Virtual|VMware' -or $computer.PartOfDomain -ne $false){throw 'Fresh non-domain virtual machine required'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try{$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
if(-not $admin){throw 'Hosted administrator token required'}
$project=Split-Path -Parent $PSScriptRoot
$source=$env:GITHUB_SHA
$head=@(& git -C $project rev-parse HEAD 2>$null)
if($LASTEXITCODE -ne 0 -or $head.Count -ne 1 -or $source -cnotmatch '\A[a-f0-9]{40}\z' -or $head[0] -cne $source){
    throw 'DoH firewall profile comparison source identity differs'
}
$dirty=@(& git -C $project status --porcelain --untracked-files=no 2>$null)
if($LASTEXITCODE -ne 0 -or $dirty.Count){throw 'DoH firewall profile comparison requires clean tracked source'}
$hashes=@{}
foreach($path in @('scripts/test-native-doh-firewall-profiles.ps1','.github/workflows/native-doh-wire.yml')){
    $hashes[$path]=(Get-FileHash -LiteralPath (Join-Path $project $path) -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-FixtureProfileMask {
    $policy=New-Object -ComObject HNetCfg.FwPolicy2
    try{
        $mask=$policy.CurrentProfileTypes
        if($mask -isnot [int] -or $mask -lt 1 -or $mask -gt 7){throw 'Current firewall profile mask unavailable'}
        return $mask
    }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy)}
}
function Get-FixtureRule([string]$Name,[ValidateSet('PersistentStore','ActiveStore')][string]$Store) {
    $rules=@(Get-NetFirewallRule -PolicyStore $Store -TracePolicyStore:($Store -ceq 'ActiveStore') -WarningAction Stop -ErrorAction Stop |
        Where-Object Name -IEQ $Name)
    if($rules.Count -gt 1 -or ($rules.Count -eq 1 -and $rules[0].Name -cne $Name)){throw 'Ambiguous fixture firewall rule'}
    return $rules
}
function Get-FixtureStatus([string]$Name,[string]$Marker,[int]$ActiveMask) {
    $rule=Get-FixtureRule $Name 'ActiveStore'
    if($rule -isnot [Microsoft.Management.Infrastructure.CimInstance] -or $rule.Description -cne $Marker -or
       [string]$rule.PolicyStoreSourceType -cne 'Local' -or [string]$rule.Direction -cne 'Outbound' -or
       [string]$rule.Action -cne 'Block' -or [string]$rule.Enabled -cne 'True'){
        throw 'Fixture firewall readback differs'
    }
    $profiles=$rule.PSBase.CimInstanceProperties['Profiles']
    $status=$rule.PSBase.CimInstanceProperties['EnforcementStatus']
    if($null -eq $profiles -or $profiles.CimType -ne [Microsoft.Management.Infrastructure.CimType]::UInt16 -or
       $profiles.Value -isnot [uint16] -or $profiles.Value -gt 7 -or $null -eq $status -or
       $status.CimType -ne [Microsoft.Management.Infrastructure.CimType]::UInt16Array -or
       $status.Value -isnot [uint16[]] -or $status.Value.Length -eq 0 -or $status.Value.Length -gt 32 -or
       @($status.Value | Where-Object {$_ -gt 23}).Count){
        throw 'Fixture firewall status has an unsupported representation'
    }
    if((Get-FixtureProfileMask) -ne $ActiveMask){throw 'Active firewall profiles changed during the comparison'}
    return @{profileMask=[int]$profiles.Value;enforcement=@($status.Value | Sort-Object)}
}
function Remove-FixtureRule([string]$Name,[string]$Marker) {
    $owned=Get-FixtureRule $Name 'PersistentStore'
    if($owned){
        if($owned.Description -cne $Marker){throw 'Fixture firewall ownership changed'}
        Remove-NetFirewallRule -InputObject $owned -Confirm:$false -WarningAction Stop -ErrorAction Stop
    }
    if((Get-FixtureRule $Name 'PersistentStore') -or (Get-FixtureRule $Name 'ActiveStore')){
        throw 'Fixture firewall rule remains'
    }
}

$report=[ordered]@{schemaVersion=1;sourceCommit=$source;sourceSHA256=$hashes;target=('windows/'+$architecture);status='profile-read';
    activeProfileMask=0;cases=@();cleanupVerified=$true;productionQualificationComplete=$false}
$nonce=[guid]::NewGuid().ToString('N')
$marker='AccessWeaver DoH firewall profile comparison '+$nonce
$profileOptions=[ordered]@{Any='Any';ExplicitAll='Domain,Private,Public';Domain='Domain';Private='Private';Public='Public'}
try{
    $report.activeProfileMask=Get-FixtureProfileMask
    $report.status='comparison'
    foreach($protocol in @('TCP','UDP')){
        foreach($option in $profileOptions.Keys){
            $name='AccessWeaver-DoH-ProfileFixture-'+$nonce+'-'+$protocol+'-'+$option
            $case=[ordered]@{protocol=$protocol;profile=$option;stage='preflight';first=$null;second=$null;cleanupVerified=$false}
            $report.cases+=@($case)
            $creationAttempted=$false
            try{
                if((Get-FixtureRule $name 'PersistentStore') -or (Get-FixtureRule $name 'ActiveStore')){throw 'Fixture identity already exists'}
                $case.stage='create'
                # Documentation destinations keep the temporary rule out of ordinary DNS traffic.
                $rule=@{Name=$name;DisplayName='AccessWeaver DoH firewall profile comparison';Description=$marker
                    PolicyStore='PersistentStore';Direction='Outbound';Action='Block';Enabled='True'
                    Profile=$profileOptions[$option];Protocol=$protocol;RemotePort=53
                    RemoteAddress=@('192.0.2.1','2001:db8::1');Service='Dnscache';WarningAction='Stop';ErrorAction='Stop'}
                $creationAttempted=$true
                [void](New-NetFirewallRule @rule)
                $case.stage='first-read'
                $case.first=Get-FixtureStatus $name $marker $report.activeProfileMask
                Start-Sleep -Seconds 2
                $case.stage='second-read'
                $case.second=Get-FixtureStatus $name $marker $report.activeProfileMask
                $case.stage='complete'
            }catch{
                # The report records fixed stage names. Provider messages can contain runner data.
            }finally{
                try{
                    if($creationAttempted){Remove-FixtureRule $name $marker}
                    $case.cleanupVerified=$true
                }catch{$report.cleanupVerified=$false}
            }
            if(-not $report.cleanupVerified){throw 'DoH firewall profile comparison cleanup failed'}
        }
    }
    if(@($report.cases | Where-Object stage -CNE 'complete').Count){throw 'DoH firewall profile comparison has incomplete cases'}
    $report.status='complete'
}catch{
    throw 'DoH firewall profile comparison failed; fixed status retained'
}finally{
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 6 -Compress))
    if($bytes.Length -gt 16384){throw 'DoH firewall profile comparison report exceeds its size limit'}
    $file=[IO.File]::Open($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$file.Write($bytes,0,$bytes.Length)}finally{$file.Dispose()}
}
