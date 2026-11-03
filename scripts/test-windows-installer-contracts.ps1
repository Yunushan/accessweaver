# Pure target/identity contracts and synthetic PE headers. Nothing is executed.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-common.ps1')
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Reject([scriptblock]$Action,[string]$Message){$rejected=$false;try{& $Action}catch{$rejected=$true};Assert $rejected $Message}
foreach($value in @('0.1.0-alpha','1.0.0','1.2.3-alpha.2+build.001','999999999999999999999.0.0','1.2.3--',('1.2.3-'+('a'*250)))){
    Assert-InstallerReleaseVersion $value
}
foreach($value in @('','v1.2.3','01.2.3','1.02.3','1.2.03','1.2','1.2.3.4','1.2.3-','1.2.3-alpha.01','1.2.3+','1.2.3+a..b','1.2.3-..',('1.2.3'+[char]10),('1.2.3-'+('a'*251)))){
    Reject {Assert-InstallerReleaseVersion $value} 'Invalid installer release version was accepted'
}
foreach($arch in @('amd64','arm64')){
    Assert ((Resolve-InstallerTarget 'windows' $arch '') -ceq $arch) 'Default target must follow the SDK host'
    Assert ((Resolve-InstallerTarget 'windows' $arch $arch) -ceq $arch) 'Explicit matching target rejected'
}
foreach($case in @(@('linux','amd64','amd64'),@('windows','386','amd64'),@('windows','amd64','arm64'),@('windows','arm64','amd64'),@('windows','arm64','ARM64'),@('windows','amd64','386'))){
    Reject {Resolve-InstallerTarget $case[0] $case[1] $case[2]} 'Unsupported or cross-host target was accepted'
}
$project=Split-Path -Parent $PSScriptRoot
$fixture=Join-Path $project ('build\installer-contracts-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $fixture)
function Header([int]$Machine){
    $memory=[IO.MemoryStream]::new()
    $writer=[IO.BinaryWriter]::new($memory)
    try {
        $memory.SetLength(256)
        $writer.Write([uint16]0x5a4d)
        $memory.Position=0x3c;$writer.Write([uint32]128)
        $memory.Position=128;$writer.Write([uint32]0x4550);$writer.Write([uint16]$Machine)
        return ,$memory.ToArray()
    } finally {$writer.Dispose()}
}
try {
    $payload=Join-Path $fixture 'payload.dat'
    foreach($arch in @('amd64','arm64')){
        $machine=if($arch -ceq 'amd64'){0x8664}else{0xaa64}
        [IO.File]::WriteAllBytes($payload,(Header $machine))
        $expected=@{version='0.1.0-alpha';commit=('a'*40);sourceState='clean';builtAt='2026-11-02T00:00:00Z';goVersion='go1.27.3';platform='windows';arch=$arch}
        $identity=[pscustomobject]$expected
        Assert-InstallerPayloadIdentity $payload $identity $expected
        foreach($key in @('version','commit','sourceState','builtAt','goVersion','platform','arch')){
            $changed=@{};foreach($name in $expected.Keys){$changed[$name]=$expected[$name]};$changed[$key]='wrong'
            Reject {Assert-InstallerPayloadIdentity $payload ([pscustomobject]$changed) $expected} ('Changed '+$key+' accepted')
            $missing=@{};foreach($name in $expected.Keys){if($name -ne $key){$missing[$name]=$expected[$name]}}
            Reject {Assert-InstallerPayloadIdentity $payload ([pscustomobject]$missing) $expected} ('Missing '+$key+' accepted')
        }
        [IO.File]::WriteAllBytes($payload,(Header $(if($arch -ceq 'amd64'){0xaa64}else{0x8664})))
        Reject {Assert-InstallerPayloadIdentity $payload $identity $expected} 'Mislabeled PE machine accepted'
    }
    foreach($machine in @(0x014c,0,0xffff)){
        [IO.File]::WriteAllBytes($payload,(Header $machine))
        Reject {Assert-InstallerPEArchitecture $payload 'arm64'} 'Unsupported or 32-bit payload accepted'
    }
    foreach($kind in @('short','dos','offset-before','offset-after','truncated-pe','signature')){
        $bytes=Header 0xaa64
        switch($kind){
            'short' {$bytes=[byte[]]@(0,1,2)}
            'dos' {$bytes[0]=0}
            'offset-before' {[Array]::Copy([BitConverter]::GetBytes([uint32]1),0,$bytes,0x3c,4)}
            'offset-after' {[Array]::Copy([BitConverter]::GetBytes([uint32]::MaxValue),0,$bytes,0x3c,4)}
            'truncated-pe' {[Array]::Copy([BitConverter]::GetBytes([uint32]($bytes.Length-5)),0,$bytes,0x3c,4)}
            'signature' {$bytes[128]=0}
        }
        [IO.File]::WriteAllBytes($payload,$bytes)
        Reject {Read-InstallerPEMachine $payload} ('Invalid '+$kind+' header accepted')
    }
    $setupPath=Join-Path $fixture 'preprocessed.iss'
    foreach($arch in @('amd64','arm64')){
        $architecture=if($arch -ceq 'arm64'){'arm64'}else{'x64compatible'}
        $script="[Setup]`nSetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092`nAllowNoIcons=yes`nArchitecturesAllowed=$architecture`nArchitecturesInstallIn64BitMode=$architecture`nOutputBaseFilename=accessweaver-0.1.0-alpha-windows-$arch-setup`n[Code]`n"
        [IO.File]::WriteAllText($setupPath,$script)
        $values=Assert-InstallerSetupScript $setupPath $arch '0.1.0-alpha'
        Assert ($values.ArchitecturesAllowed -ceq $architecture) 'Valid preprocessed architecture rejected'
        foreach($kind in @('mutex','missing-mutex','icons','missing-icons','allowed','install-mode','filename','duplicate','wrong-section')){
            $changed=switch($kind){
                'mutex' {$script.Replace('SetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092','SetupMutex=OtherProduct')}
                'missing-mutex' {$script.Replace(('SetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092'+"`n"),'')}
                'icons' {$script.Replace('AllowNoIcons=yes','AllowNoIcons=no')}
                'missing-icons' {$script.Replace(('AllowNoIcons=yes'+"`n"),'')}
                'allowed' {$script.Replace(('ArchitecturesAllowed='+$architecture),'ArchitecturesAllowed=win64')}
                'install-mode' {$script.Replace(('ArchitecturesInstallIn64BitMode='+$architecture),'ArchitecturesInstallIn64BitMode=x86compatible')}
                'filename' {$script.Replace(('windows-'+$arch),'windows-386')}
                'duplicate' {$script.Replace('[Code]',('ArchitecturesAllowed='+$architecture+"`n[Code]"))}
                'wrong-section' {$script.Replace('[Setup]','[Code]')}
            }
            [IO.File]::WriteAllText($setupPath,$changed)
            Reject {Assert-InstallerSetupScript $setupPath $arch '0.1.0-alpha'} ('Invalid '+$kind+' directive accepted')
        }
    }
    Write-Output 'Installer target/identity/PE/preprocessed-script contracts passed; no executable or installer was run.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    $intended=[IO.Path]::GetFullPath((Join-Path $project 'build'))+[IO.Path]::DirectorySeparatorChar
    if(-not $resolved.StartsWith($intended,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^installer-contracts-[a-f0-9]{32}$'){throw 'Unsafe installer fixture cleanup target'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

& (Join-Path $PSScriptRoot 'test-windows-installer-state.ps1')
