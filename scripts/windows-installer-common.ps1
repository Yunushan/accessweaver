# Build-time checks only. These helpers never install software or change the OS.
function Resolve-InstallerTarget([string]$HostOS, [string]$HostArch, [string]$TargetArch) {
    if($HostOS -cne 'windows' -or $HostArch -cnotin @('amd64','arm64')){throw 'Installer verification requires a Windows amd64 or arm64 Go SDK'}
    if(-not $TargetArch){$TargetArch=$HostArch}
    if($TargetArch -cnotin @('amd64','arm64') -or $TargetArch -cne $HostArch){throw 'Installer payload target must match the Go SDK host architecture so its identity can be executed'}
    return $TargetArch
}

function Read-InstallerPEMachine([string]$Path) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $reader=[IO.BinaryReader]::new($stream)
    try {
        if($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d){throw 'Installer input has no DOS executable header'}
        $stream.Position=0x3c
        $offset=$reader.ReadUInt32()
        if($offset -lt 64 -or $offset -gt ($stream.Length-6)){throw 'Installer input has an invalid PE header offset'}
        $stream.Position=$offset
        if($reader.ReadUInt32() -ne 0x00004550){throw 'Installer input has no PE signature'}
        return $reader.ReadUInt16()
    } finally { $reader.Dispose() }
}

function Assert-InstallerPayloadIdentity([string]$Binary, [object]$Identity, [hashtable]$Expected) {
    $arch=$Expected.arch
    if($Expected.platform -cne 'windows' -or $arch -cnotin @('amd64','arm64')){throw 'Invalid expected installer payload target'}
    Assert-InstallerPEArchitecture $Binary $arch
    foreach($key in @('version','commit','sourceState','builtAt','goVersion','platform','arch')){
        if(-not $Expected.ContainsKey($key) -or -not $Expected[$key] -or [string]$Identity.$key -cne [string]$Expected[$key]){throw ('Installer payload build identity mismatch: '+$key)}
    }
}

function Assert-InstallerPEArchitecture([string]$Binary, [string]$Arch) {
    if($Arch -cnotin @('amd64','arm64')){throw 'Invalid expected installer payload architecture'}
    $machine=Read-InstallerPEMachine $Binary
    $expectedMachine=if($Arch -ceq 'arm64'){0xaa64}else{0x8664}
    if($machine -ne $expectedMachine){throw 'Installer payload PE machine does not match its requested architecture'}
}

function Assert-InstallerSetupScript([string]$Path, [string]$TargetArch, [string]$Version) {
    if($TargetArch -cnotin @('amd64','arm64')){throw 'Invalid installer script target'}
    if((Get-Item -LiteralPath $Path).Length -gt 1MB){throw 'Preprocessed installer script exceeds evidence limit'}
    $architecture=if($TargetArch -ceq 'arm64'){'arm64'}else{'x64compatible'}
    $expected=@{ArchitecturesAllowed=$architecture;ArchitecturesInstallIn64BitMode=$architecture;OutputBaseFilename=('accessweaver-'+$Version+'-windows-'+$TargetArch+'-setup')}
    $actual=@{};$section=''
    foreach($line in [IO.File]::ReadAllLines($Path)){
        if($line -match '^\s*\[([^]]+)\]\s*$'){$section=$matches[1];continue}
        if($section -ieq 'Setup' -and $line -match '^\s*([^=;]+?)\s*=(.*)$'){
            $name=$matches[1].Trim();$value=$matches[2].Trim()
            if($expected.ContainsKey($name)){
                if($actual.ContainsKey($name)){throw 'Duplicate architecture/output directive in preprocessed installer'}
                $actual[$name]=$value
            }
        }
    }
    foreach($key in $expected.Keys){if($actual[$key] -cne $expected[$key]){throw ('Preprocessed installer directive mismatch: '+$key)}}
    return $actual
}
