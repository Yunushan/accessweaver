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
$signer='C:\Release Tools\Sign.exe'
$shell='C:\Program Files\PowerShell\7\pwsh.exe'
$callback='C:\AccessWeaver\scripts\sign-windows-installer-artifact.ps1'
$arguments=@(Get-InstallerSigningArguments $signer ('a'*64) $shell $callback)
Assert ($arguments.Count -eq 2 -and $arguments[0] -ceq '/DOrganizationSigning=1' -and
    $arguments[1] -ceq '/SaccessweaverOrganization=$qC:\Program Files\PowerShell\7\pwsh.exe$q -NoProfile -NonInteractive -File $qC:\AccessWeaver\scripts\sign-windows-installer-artifact.ps1$q -Artifact $f') 'Signing callback arguments differ'
Assert (@(Get-InstallerSigningArguments '' '' '' '').Count -eq 0) 'Unsigned compilation acquired a signing argument'
Reject {Get-InstallerSigningArguments $signer '' $shell $callback} 'Signing without a publisher pin was accepted'
Reject {Get-InstallerSigningArguments 'signer.exe' ('a'*64) $shell $callback} 'A relative signer path was accepted'
Reject {Get-InstallerSigningArguments $signer ('a'*64) $shell 'C:\untrusted$q.ps1'} 'An Inno command escape was accepted'

$payloadSigner='C:\Release Tools\Sign Payload.exe'
$setupPin='a'*64;$payloadPin='b'*64
$defaultPayload=Get-InstallerPayloadSigning $signer $setupPin '' ''
Assert ($defaultPayload.signer -ceq $signer -and $defaultPayload.publisher -ceq $setupPin) 'Payload signing lost the default setup identity'
$distinctPayload=Get-InstallerPayloadSigning $signer $setupPin $payloadSigner $payloadPin
Assert ($distinctPayload.signer -ceq $payloadSigner -and $distinctPayload.publisher -ceq $payloadPin) 'Payload signing did not retain the independent identity'
Reject {Get-InstallerPayloadSigning '' '' $payloadSigner $payloadPin} 'Payload signing accepted absent setup configuration'
Reject {Get-InstallerPayloadSigning $signer $setupPin '' $payloadPin} 'Payload signing accepted absent signer'
Reject {Get-InstallerPayloadSigning $signer $setupPin $payloadSigner ''} 'Payload signing accepted absent publisher pin'
Reject {Get-InstallerPayloadSigning $signer $setupPin $payloadSigner 'invalid'} 'Payload signing accepted invalid publisher pin'

$previousSigner=$env:ACCESSWEAVER_BUILD_SIGNER;$previousPublisher=$env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256
try {
    $env:ACCESSWEAVER_BUILD_SIGNER='inert prior signer';$env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256='inert prior publisher'
    $observed=@(Invoke-InstallerSigningContext $distinctPayload.signer $distinctPayload.publisher {
        "$env:ACCESSWEAVER_BUILD_SIGNER | $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256"
    })
    Assert ($observed.Count -eq 1 -and $observed[0] -ceq "$payloadSigner | $payloadPin") 'Payload callback did not receive the isolated signing context'
    $failed=$false
    try {
        Invoke-InstallerSigningContext $signer $setupPin {
            Assert ($env:ACCESSWEAVER_BUILD_SIGNER -ceq $signer -and
                $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256 -ceq $setupPin) 'Setup callback inherited payload credentials'
            throw 'Synthetic setup compiler refusal'
        }
    } catch {$failed=$_.Exception.Message -ceq 'Synthetic setup compiler refusal'}
    Assert ($failed -and $env:ACCESSWEAVER_BUILD_SIGNER -ceq 'inert prior signer' -and
        $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256 -ceq 'inert prior publisher') 'Signing context was not restored after failure'
} finally {
    $env:ACCESSWEAVER_BUILD_SIGNER=$previousSigner
    $env:ACCESSWEAVER_BUILD_PUBLISHER_SHA256=$previousPublisher
}

$publisherBytes=[byte[]]@(1,2,3)
$publisherPin='039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81'
$signature=@{
    Status='Valid'
    SignatureType='Authenticode'
    SignerCertificate=@{RawData=$publisherBytes}
    TimeStamperCertificate=@{}
}
Assert-WindowsPublisherSignature $signature $publisherPin
Reject {Assert-WindowsPublisherSignature $signature ('f'*64)} 'An unapproved publisher certificate was accepted'
Reject {Assert-WindowsPublisherSignature $signature ('1'*40)} 'A SHA-1 thumbprint was accepted as a SHA-256 pin'
foreach($case in @(
    @{key='Status';value='NotTrusted'},
    @{key='SignatureType';value='Catalog'},
    @{key='TimeStamperCertificate';value=$null},
    @{key='SignerCertificate';value=$null},
    @{key='SignerCertificate';value=@{RawData=[byte[]]@()}}
)){
    $untrusted=$signature.Clone()
    $untrusted[$case.key]=$case.value
    Reject {Assert-WindowsPublisherSignature $untrusted $publisherPin} 'An incomplete or untrusted Windows signature was accepted'
}
$project=Split-Path -Parent $PSScriptRoot
$installerSource=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer.iss'))
$initialize=[regex]::Match($installerSource,'(?ms)^function InitializeUninstall: Boolean;.*?^end;').Value
$prepare=[regex]::Match($installerSource,'(?ms)^function PrepareToInstall\(.*?^end;').Value
$copy=[regex]::Match($installerSource,'(?ms)^procedure CurStepChanged\(.*?^end;').Value
$uninstallPreflight=[regex]::Match($installerSource,'(?ms)^function AWUninstallPreflight: String;.*?^end;').Value
Assert ($prepare -cmatch "(?s)AWInstallationPathPreflight\(ExpandConstant\('\{app\}'\), True\).*AWPayloadReplacementPreflight") 'Setup must check the destination before probing the payload'
Assert ($copy -cmatch '(?s)AWInstallationPathPreflight\(Destination, True\).*AWPayloadReplacementPreflight\(Destination\).*RaiseException\(Failure\).*RegWriteStringValue') 'Setup must recheck the destination and release files before recording pending installation'
$replacement=[regex]::Match($installerSource,'(?ms)^function AWPayloadReplacementPreflight\([^;\r\n]+\): String;\r?\nbegin.*?^end;').Value
foreach($name in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
    Assert ($replacement.Contains("AWCanReplaceInstalledFile(Destination + '\$name')")) 'Setup must check each release subject before replacement'
}
Assert ($uninstallPreflight -cmatch "AWInstallationPathPreflight\(ExpandConstant\('\{app\}'\), False\)") 'Uninstall must require an existing ordinary directory before restoration'
$uninstallRegistration=[regex]::Match($installerSource,'(?ms)^function AWUninstallDirectoryPreflight\(.*?^end;').Value
Assert ($uninstallRegistration -cmatch "AWOrdinal\(Version, '\{#ReleaseVersion\}'\) <> 0") 'Uninstall must match the exact release version in the machine registration'
$completion=[regex]::Match($installerSource,'(?ms)^function AWVerifyCompletedInstall\(.*?^end;').Value
Assert ($copy -cmatch "(?s)ssDone.*if not AWVerifyCompletedInstall.*Pending installation record retained\..*end else if not RegDeleteValue") 'Setup must verify completion before clearing the pending install record'
foreach($name in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
    Assert ($completion.Contains("Destination, '$name',")) 'Setup completion must verify each staged release subject'
}
Assert ($completion -cmatch '(?s)AWReadRegistration\(\$0100, True.*AWReadRegistration\(\$0200, False.*not Found64 or Found32') 'Setup completion must verify its unique machine registration'
$uninstallStep=[regex]::Match($installerSource,'(?ms)^procedure CurUninstallStepChanged\(CurUninstallStep: TUninstallStep\);.*?^end;').Value
Assert ($initialize.Contains('AWUninstallPreflight') -and -not $initialize.Contains('AWRunBoundedRestoration')) 'Uninstall initialization must validate without restoring machine state'
Assert ($uninstallStep -cmatch '(?s)if CurUninstallStep <> usUninstall then Exit;.*Failure := AWUninstallPreflight;.*AWRunBoundedRestoration.*then Exit;.*\bAbort;\s*end;') 'Uninstall must restore only after confirmation and abort deletion on failure'
Assert ($uninstallStep -cmatch "(?s)AWOpenVerifiedInstalledFile\(Executable, '\{#PayloadDigest\}', \{#PayloadBytes\}\).*if Payload = nil then.*else begin\s+try.*AWRunBoundedRestoration\(Executable.*finally\s+Payload\.Free;") 'Uninstall must hold the verified release controller through restoration'
Assert ([regex]::Matches($installerSource,'\bAWRunBoundedRestoration\(').Count -eq 1) 'Restoration has another installer entry point'
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
    $original=Join-Path $fixture 'unsigned.exe'
    $signed=Join-Path $fixture 'signed.exe'
    # A minimal PE header plus arbitrary overlay bytes makes it possible to
    # verify the signing-only comparison without a signing key or executable.
    foreach($format in @(@{magic=0x10b;size=224;directories=96},@{magic=0x20b;size=240;directories=112})){
        $sourceBytes=[byte[]]::new(4099)
        $sourceBytes[0]=0x4d;$sourceBytes[1]=0x5a;$sourceBytes[60]=128
        $sourceBytes[128]=0x50;$sourceBytes[129]=0x45
        [Array]::Copy([BitConverter]::GetBytes([uint16]$format.size),0,$sourceBytes,148,2)
        [Array]::Copy([BitConverter]::GetBytes([uint16]$format.magic),0,$sourceBytes,152,2)
        $sourceBytes[152+$format.directories-4]=16
        $sourceBytes[4098]=73
        [IO.File]::WriteAllBytes($original,$sourceBytes)
        $signedBytes=[byte[]]::new(4120)
        [Array]::Copy($sourceBytes,$signedBytes,$sourceBytes.Length)
        $signedBytes[216]=19
        $cert=152+$format.directories+32
        [Array]::Copy([BitConverter]::GetBytes([uint32]4104),0,$signedBytes,$cert,4)
        $signedBytes[$cert+4]=16
        $signedBytes[4104]=16;$signedBytes[4109]=2;$signedBytes[4110]=2
        [IO.File]::WriteAllBytes($signed,$signedBytes)
        Assert-InstallerSigningOnlyChange $original $signed
        foreach($index in @(200,2048,4098,4099,$cert,$cert+4)){
            $mutated=$signedBytes.Clone()
            $mutated[$index]=$mutated[$index] -bxor 1
            [IO.File]::WriteAllBytes($signed,$mutated)
            Reject {Assert-InstallerSigningOnlyChange $original $signed} 'A signer changed a non-signature byte or supplied an invalid table'
        }
        [IO.File]::WriteAllBytes($signed,[byte[]]($signedBytes+@(1)))
        Reject {Assert-InstallerSigningOnlyChange $original $signed} 'Trailing bytes outside the certificate table were accepted'
    }
    $setupPath=Join-Path $fixture 'preprocessed.iss'
    foreach($arch in @('amd64','arm64')){
        $architecture=if($arch -ceq 'arm64'){'arm64'}else{'x64os'}
        $script="[Setup]`nSetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092`nAllowNoIcons=yes`nArchitecturesAllowed=$architecture`nArchitecturesInstallIn64BitMode=$architecture`nOutputBaseFilename=accessweaver-0.1.0-alpha-windows-$arch-setup`n[Code]`n"
        [IO.File]::WriteAllText($setupPath,$script)
        $values=Assert-InstallerSetupScript $setupPath $arch '0.1.0-alpha'
        Assert ($values.ArchitecturesAllowed -ceq $architecture) 'Valid preprocessed architecture rejected'
        Reject {Assert-InstallerSetupScript $setupPath $arch '0.1.0-alpha' -OrganizationSigning} 'Signed compilation accepted missing directives'
        $signedDirectives=@('SignTool=accessweaverOrganization','SignedUninstaller=yes','[Code]') -join [Environment]::NewLine
        $signedScript=$script.Replace('[Code]',$signedDirectives)
        [IO.File]::WriteAllText($setupPath,$signedScript)
        $signedValues=Assert-InstallerSetupScript $setupPath $arch '0.1.0-alpha' -OrganizationSigning
        Assert ($signedValues.SignedUninstaller -ceq 'yes') 'Signed installer did not require a signed uninstaller'

        foreach($kind in @('mutex','missing-mutex','icons','missing-icons','allowed','install-mode','filename','duplicate','wrong-section')){
            $changed=switch($kind){
                'mutex' {$script.Replace('SetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092','SetupMutex=OtherProduct')}
                'missing-mutex' {$script.Replace(('SetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092'+"`n"),'')}
                'icons' {$script.Replace('AllowNoIcons=yes','AllowNoIcons=no')}
                'missing-icons' {$script.Replace(('AllowNoIcons=yes'+"`n"),'')}
                'allowed' {$script.Replace(('ArchitecturesAllowed='+$architecture),'ArchitecturesAllowed=x64compatible')}
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
