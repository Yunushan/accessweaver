# Target and identity contracts, synthetic PE headers, and inert native path guards.
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

Assert ((Get-InstallerBuildTimestamp '0') -ceq '1970-01-01T00:00:00Z') 'Installer build epoch zero did not round-trip'
Assert ((Get-InstallerBuildTimestamp '4294967295') -ceq '2106-02-07T06:28:15Z') 'Installer maximum build epoch did not round-trip'
foreach($epoch in @('','-1','4294967296','00000000000','1 ',('1'+[char]10))){
    Reject {Get-InstallerBuildTimestamp $epoch} 'Installer accepted an invalid release build epoch'
}
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
$publisherVerifier=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'verify-windows-installer-publisher.ps1'))
$publisherHelper=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer-common.ps1'))
Assert ($publisherVerifier.Contains('Get-WindowsPublisherArtifactSHA256 $Artifact $PublisherCertificateSHA256 $ArtifactSHA256')) 'Publisher receipt must use the guarded verifier and the approved artifact pin'
Assert ($publisherHelper -cmatch '(?s)VolumeRoot\(\$parents\[0\]\).*Open\(\$current,\$true\).*Open\(\$lockedPath,\$false\).*Get-FileHash -InputStream \$file.*Get-AuthenticodeSignature -LiteralPath \$lockedPath.*finally.*\$file\.Dispose\(\).*\$parents\[\$i\]\.Dispose\(\)') 'Publisher verification must hash the held handle and authenticate the same guarded volume path'
if($env:OS -ceq 'Windows_NT'){
    Initialize-WindowsPublisherFileAccess
    $fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('accessweaver-publisher-'+[Guid]::NewGuid().ToString('N'))
    $fixtureDirectory=Join-Path $fixtureRoot 'artifact'
    $relocated=Join-Path $fixtureRoot 'relocated'
    $alias=Join-Path $fixtureRoot 'alias'
    $artifact=Join-Path $fixtureDirectory 'inert.exe'
    [void][IO.Directory]::CreateDirectory($fixtureDirectory)
    $directoryGuard=$null
    $volumeGuard=$null
    $fileGuard=$null
    try {
        [IO.File]::WriteAllText($artifact,'inert authenticode path fixture')
        [IO.Directory]::Move($fixtureDirectory,$relocated)
        [IO.Directory]::Move($relocated,$fixtureDirectory)
        [void](New-Item -ItemType Junction -Path $alias -Target $fixtureDirectory)
        Reject {([AccessWeaver.PublisherFileAccess]::Open($alias,$true)).Dispose()} 'Publisher parent guard followed a junction'

        $drive=[IO.Path]::GetPathRoot($artifact)
        $volumeGuard=[AccessWeaver.PublisherFileAccess]::Open($drive,$true)
        $volume=[AccessWeaver.PublisherFileAccess]::VolumeRoot($volumeGuard)
        $protectedDirectory=$volume+$fixtureDirectory.Substring($drive.Length)
        $protectedArtifact=$volume+$artifact.Substring($drive.Length)
        $directoryGuard=[AccessWeaver.PublisherFileAccess]::Open($protectedDirectory,$true)
        Reject {[IO.Directory]::Move($fixtureDirectory,$relocated)} 'The held publisher directory was renamed'
        $fileGuard=[AccessWeaver.PublisherFileAccess]::Open($protectedArtifact,$false)
        Reject {([IO.File]::OpenWrite($artifact)).Dispose()} 'The held publisher artifact could be opened for writing'
    } finally {
        if($null -ne $fileGuard){$fileGuard.Dispose()}
        if($null -ne $directoryGuard){$directoryGuard.Dispose()}
        if($null -ne $volumeGuard){$volumeGuard.Dispose()}
        if([IO.Directory]::Exists($relocated)){[IO.Directory]::Move($relocated,$fixtureDirectory)}
        [IO.File]::Delete($artifact)
        if([IO.Directory]::Exists($alias)){[IO.Directory]::Delete($alias)}
        [IO.Directory]::Delete($fixtureDirectory)
        [IO.Directory]::Delete($fixtureRoot)
    }
}
$project=Split-Path -Parent $PSScriptRoot
$setupScript=Join-Path $PSScriptRoot 'windows-installer.iss'
$signingCallback=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'sign-windows-installer-artifact.ps1'))
Assert ($signingCallback -cmatch '(?s)Assert-InstallerSigningStreamOnlyChange \$original \$signed.*Get-FileHash -InputStream \$signed.*Get-WindowsPublisherArtifactSHA256 \$candidate \$publisher \$expectedSignedSHA256.*Complete-InstallerSigning \$absolute \$originalSHA256 \$candidate \$signedSHA256') 'Signing callback must bind the compared and publisher-verified bytes through replacement'
$installerSource=[IO.File]::ReadAllText($setupScript)
$initialize=[regex]::Match($installerSource,'(?ms)^function InitializeUninstall: Boolean;.*?^end;').Value
$prepare=[regex]::Match($installerSource,'(?ms)^function PrepareToInstall\(.*?^end;').Value
$copy=[regex]::Match($installerSource,'(?ms)^procedure CurStepChanged\(.*?^end;').Value
$uninstallPreflight=[regex]::Match($installerSource,'(?ms)^function AWUninstallPreflight: String;.*?^end;').Value
Assert ($prepare -cmatch "(?s)AWInstallationPathPreflight\(ExpandConstant\('\{app\}'\), True\).*AWPayloadReplacementPreflight") 'Setup must check the destination before probing the payload'
Assert ($copy -cmatch '(?s)AWInstallationPathPreflight\(Destination, True\).*AWPayloadReplacementPreflight\(Destination\).*RaiseException\(Failure\).*AWWriteLifecycleString') 'Setup must recheck the destination and release files before recording pending installation'
$replaceProbe=[regex]::Match($installerSource,'(?ms)^function AWCanReplaceInstalledFile\(.*?^end;').Value
Assert ($replaceProbe.Contains('AWOpenReplaceProbe(Path, $00010080, $00000007, 0, 3, $00200000, 0)') -and
    $replaceProbe -cmatch '(?s)AWGetFileInfo\(Handle, Info\).*Info.Attributes and \(\$00000400 or \$00000010 or \$00000001\).*Info.Links = 1.*finally.*AWCloseNativeHandle') 'Setup must refuse read-only, aliased or redirected files before replacement'
$installerBuild=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'build-windows-installer.ps1'))
Assert ($installerBuild -cmatch '(?s)stage-docs.*Assert-InstallerPackageDirectories \$stage \$setupScript.*& \$Compiler') 'Installer build must check the staged directory tree before compiling it'
Assert ($installerBuild -cmatch '(?s)Assert-InstallerSetupScript \$preprocessed.*Assert-InstallerPackageDirectories \$stage \$setupScript \$preprocessed') 'Installer build must verify coverage for each staged file in the compiled script'
Assert ($installerBuild -cmatch '(?s)Get-WindowsPublisherArtifactSHA256 \$payload \$payloadSigning\.publisher.*\$identity=& \$payload.*Get-WindowsPublisherArtifactSHA256 \$artifact \$PublisherCertificateSHA256.*\$artifactHash\.Hash -ine \$verifiedInstaller.*Get-WindowsPublisherArtifactSHA256 \$evidencePayload \$payloadSigning\.publisher \$signedPayloadSHA256.*Assert-InstallerSBOMSubject.*\$verifiedInstaller.*Assert-InstallerSBOMSubject.*\$verifiedPayload.*installerSHA256=\$verifiedInstaller.*payloadSHA256=\$verifiedPayload') 'Signed build receipt must bind setup and copied payload to verified digests and SBOM subjects'
$copyGuard=[regex]::Match($installerSource,'(?ms)^procedure AWCheckPackageCopyDestination;.*?^end;').Value
Assert ($installerSource -cmatch '(?m)^Source: .*; BeforeInstall: AWCheckPackageCopyDestination\s*$' -and
    $copyGuard -cmatch '(?s)CurrentFilename.*ExpandConstant\(Destination\).*AWInstallationPathPreflight\(ExtractFileDir\(Destination\), True\).*AWCanReplaceInstalledFile\(Destination\).*Log\(Failure\).*Abort;') 'Every package file must recheck its destination immediately before copying'
$replacement=[regex]::Match($installerSource,'(?ms)^function AWPayloadReplacementPreflight\([^;\r\n]+\): String;\r?\nbegin.*?^end;').Value
$packageDirectories=[regex]::Match($installerSource,'(?ms)^function AWCheckPackageDirectories\(.*?^end;').Value
foreach($directory in @('licenses','docs','docs\assets','docs\qualification')){
    Assert ($packageDirectories.Contains("AWCheckPackageDirectory(Destination + '\$directory', Hold, Held)")) 'Setup must check each packaged subdirectory'
}
Assert ($replacement -cmatch '(?s)AWPackageDirectoryPreflight\(Destination\).*if Result <> '''' then Exit') 'Setup must refuse a redirected package subdirectory before replacement'
foreach($name in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
    Assert ($replacement.Contains("AWCanReplaceInstalledFile(Destination + '\$name')")) 'Setup must check each release subject before replacement'
}
Assert ($uninstallPreflight -cmatch "AWInstallationPathPreflight\(ExpandConstant\('\{app\}'\), False\)") 'Uninstall must require an existing ordinary directory before restoration'
Assert ($uninstallPreflight -cmatch "AWPackageDirectoryPreflight\(ExpandConstant\('\{app\}'\)\)") 'Uninstall must refuse redirected package directories before restoration and deletion'
$uninstallRegistration=[regex]::Match($installerSource,'(?ms)^function AWUninstallDirectoryPreflight\(.*?^end;').Value
Assert ($uninstallRegistration -cmatch "AWOrdinal\(Version, '\{#ReleaseVersion\}'\) <> 0") 'Uninstall must match the exact release version in the machine registration'
Assert ($uninstallRegistration.Contains("AWReadRegistration(`$0100, True, ExpandConstant('{uninstallexe}'),")) 'Native uninstall must verify that both machine registration commands bind its original executable'
$completion=[regex]::Match($installerSource,'(?ms)^function AWVerifyCompletedInstall\(.*?^end;').Value
Assert ($completion -cmatch '(?s)AWLockInstallationDirectory\(Destination, Held\).*AWCheckPackageDirectories\(Destination, True, Held\).*AWVerifyInstalledFile') 'Setup completion must hold protected package directories before verifying files'
$heldPackageFile=[regex]::Match($installerSource,'(?ms)^function AWVerifyAndHoldPackageFile\(.*?^end;').Value
Assert ($completion -cmatch '(?s)AWCheckPackageDirectories\(Destination, True, Held\).*AWStagedVerify = True.*AWEmitStagedDirectoryChecks.*AWReadRegistration') 'Setup must verify all staged identities under the package directory guards'
Assert ($heldPackageFile -cmatch '(?s)AWVerifyInstalledFile\(Path, Digest, Size, True, Handle\).*if Result then begin.*Held\[Count\] := Handle.*\$FFFFFFFF.*finally.*AWCloseNativeHandle\(Handle\)') 'Successful shipped file checks must retain the handle for marker retirement and failed checks must close it'
$verifiedFile=[regex]::Match($installerSource,'(?ms)^function AWVerifyInstalledFileDigests\(.*?^end;').Value
$retirement=[regex]::Match($installerSource,'(?ms)^procedure AWCompleteInstallation\(.*?^end;').Value
$directoryLock=[regex]::Match($installerSource,'(?ms)^function AWLockInstallationDirectory\(.*?^end;').Value
$retireMarker=[regex]::Match($installerSource,'(?ms)^function AWRetirePendingInstall\(.*?^end;').Value
Assert ($retireMarker -cmatch '(?s)not AWLifecycleOwned or not AWPendingInstallMatches\(Destination\).*not AWDeleteLifecycleValue\(AWPendingInstall, True, Flushed\).*if Flushed then begin.*Result := AWPendingInstallAbsent') 'Setup must retire only its owned marker and verify its absence after flushing'
Assert ($retireMarker -cmatch '(?s)if not AWPendingInstallAbsent then begin.*Setup did not replace it.*Exit;.*AWWriteLifecycleString\(AWPendingInstall, AWPendingInstallValue\(Destination\), True\).*not AWPendingInstallMatches\(Destination\)') 'Setup must restore and verify its exact original marker only after explicit absence'
$lifecycleWrite=[regex]::Match($installerSource,'(?ms)^function AWWriteLifecycleString\(.*?^end;').Value
$lifecycleDelete=[regex]::Match($installerSource,'(?ms)^function AWDeleteLifecycleValue\(.*?^end;').Value
Assert ($lifecycleWrite -cmatch '(?s)AWOpenLifecycleRegistry\(\x240002, True, Key\).*AWSetLifecycleStringNative\(Key, Name.*Flush then Result := AWFlushRegistryKey\(Key\).*AWCloseRegistrationKey\(Key\)' -and
    $lifecycleDelete -cmatch '(?s)AWOpenLifecycleRegistry\(\x240002, False, Key\).*AWDeleteLifecycleValueNative\(Key, Name\).*AWRegistrationQueryValue\(Key, Name.*Flush then Flushed := AWFlushRegistryKey\(Key\).*AWCloseRegistrationKey\(Key\)') 'Recovery changes and flushes must use the same no-follow registry key'
$pendingValue=[regex]::Match($installerSource,'(?ms)^function AWPendingInstallValue\(.*?^end;').Value
Assert ($pendingValue -cmatch "(?s)Result := '\{#ReleaseVersion\}\|' \+ Destination;.*if AWPendingApprovalPin <> '' then Result := Result \+ '\|' \+ AWPendingApprovalPin") 'Original and restored pending markers must bind the same release, destination, and optional approval'
$absence=[regex]::Match($installerSource,'(?ms)^function AWPendingInstallAbsent:.*?^end;').Value
Assert ($absence -cmatch "\(AWReadPendingVersion\(Version, Directory, ApprovalPin\) = ''\) and \(Version = ''\)") 'Only a successful registry read with explicit absence can release the recovery guard'
Assert ($copy -cmatch "(?s)ssInstall.*AWRegistrationPreflight\(Destination\).*AWWriteLifecycleString.*AWPendingInstallMatches\(Destination\).*ssPostInstall.*ssDone.*AWCompleteInstallation") 'Setup must recheck registration and bind the pending record before copy'
Assert ($retirement -cmatch "(?s)AWVerifyCompletedInstall.*Pending installation record retained\..*else if AWRetirePendingInstall\(Destination\).*AWPendingRetirementFailed := False.*finally.*AWCloseNativeHandle\(UninstallData\).*AWCloseNativeHandle\(Uninstaller\).*AWCloseNativeHandle\(SBOM\).*AWCloseNativeHandle\(BuildInfo\).*AWCloseNativeHandle\(Executable\).*AWCloseNativeHandle\(Held\[I\]\)") 'Setup must hold the verified subjects and directories through pending record retirement'
Assert ($directoryLock.Contains('AWOpenReplaceProbe(Copy(Target, 1, I - 1), 1, 3, 0, 3, $02200000, 0)') -and $directoryLock.Contains('AWGetFileInfo(Handle, Info)')) 'Directory guards must enforce sharing and inspect each native handle'
Assert ($verifiedFile.Contains('AWOpenReplaceProbe(Path, $80000000, 1, 0, 3, $00200000, 0)') -and $verifiedFile -cmatch '(?s)AWGetFileInfo\(Held, Info\).*SingleLink and \(Info\.Links <> 1\).*THandleStream\.Create\(Held\).*Payload\.Size <> Size.*GetSHA256OfStream\(Payload\)') 'Installed files must be inspected and hashed through the held no-follow handles'
foreach($name in @('accessweaver.exe','BUILD-INFO.json','SBOM.cdx.json')){
    Assert ($completion.Contains("Destination + '\$name',")) 'Setup completion must verify each staged release subject'
}
Assert ($completion -cmatch '(?s)AWReadRegistration\(\$0100, True.*AWReadRegistration\(\$0200, False.*Found64 and not Found32') 'Setup completion must verify its unique machine registration'
$runtimeNoticeRelative='\licenses\Inno-Setup-License.txt'
Assert ($installerSource.Contains('#elif Defined(RequireInnoRuntimeNotice) || Defined(OrganizationSigning)') -and
    $replacement.Contains("AWCanReplaceInstalledFile(Destination + '$runtimeNoticeRelative')") -and
    $completion.Contains("AWVerifyInstalledFile(Destination + '$runtimeNoticeRelative', '{#InnoRuntimeNoticeDigest}', {#InnoRuntimeNoticeBytes}, True, RuntimeNotice)") -and
    $retirement -cmatch '(?s)AWVerifyCompletedInstall\([^;]+RuntimeNotice.*AWRetirePendingInstall.*finally.*AWCloseNativeHandle\(RuntimeNotice\)') 'Release Setup must require the notice and hold its verified bytes through pending record retirement'
$detectorSource=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'detect-windows-installer.ps1'))
foreach($subject in @(@{name='accessweaver.exe';limit='128MB';handle='Executable'},
    @{name='BUILD-INFO.json';limit='64KB';handle='BuildInfo'},@{name='SBOM.cdx.json';limit='4MB';handle='SBOM'})){
    $name=$subject.name;$limit=$subject.limit;$handle=$subject.handle
    Assert ($detectorSource.Contains("::OpenFile((Join-Path `$directory '$name'),$limit,`$true)")) ('Managed detection must require a single-link '+$name)
    Assert ($completion -cmatch ("AWVerifyInstalledFile\(Destination \+ '\\"+[regex]::Escape($name)+"', [^,]+, [^,]+, True, $handle\)")) ('Setup must hold a single-link '+$name)
}
Assert ($detectorSource -cmatch '(?s)Get-FileHash -InputStream \$sbom.*Read-AccessWeaverPayloadNotices \$sbom.*OpenFile\(\(Join-Path \$licenseDirectory \$notice\.Key\),1MB,\$true\).*\$noticeFiles\.Add\(\$file\).*Get-FileHash -InputStream \$file.*\$noticeFiles\[\$i\]\.Dispose\(\)') 'Managed detection must hold and hash the notice files named by its authenticated SBOM'
& {
    $issues=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($detectorSource,[ref]$null,[ref]$issues)
    $nodes=@($ast.EndBlock.Statements | Where-Object {$_.Name -ceq 'Read-AccessWeaverPayloadNotices'})
    Assert ($issues.Count -eq 0 -and $nodes.Count -eq 1) 'Managed detection notice parser is available'
    . ([scriptblock]::Create($nodes[0].Extent.Text))
    function Read-NoticeFixture([string]$RootEvidence,[string]$ComponentEvidence) {
        $name='accessweaver:license-evidence'
        $document=@{
            bomFormat='CycloneDX';specVersion='1.6'
            metadata=@{component=@{type='application';properties=@(@{name=$name;value=$RootEvidence})}}
            components=@(@{type='library';properties=@(@{name=$name;value=$ComponentEvidence})},@{type='file'})
        }
        $json=ConvertTo-Json -InputObject $document -Depth 10 -Compress
        $stream=[IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($json))
        try {return ,(Read-AccessWeaverPayloadNotices $stream)}
        finally {$stream.Dispose()}
    }
    function NoticeRecord([string]$Path,[string]$Digest) {
        ConvertTo-Json -InputObject @(@{path=$Path;sha256=$Digest}) -Compress
    }
    $pin='a'*64
    $valid=NoticeRecord 'licenses/Go-runtime-LICENSE' $pin
    $compatible=NoticeRecord 'licenses/go-runtime-license' $pin
    $notices=Read-NoticeFixture $valid $compatible
    Assert ($notices.Count -eq 1 -and $notices['Go-runtime-LICENSE'] -ceq $pin) 'Matching notice references are hashed once under Windows filename rules'
    foreach($invalid in @(
        '[]',
        '{"path":"licenses/notice.txt","sha256":"invalid"}',
        (NoticeRecord 'licenses/../notice.txt' $pin),
        (NoticeRecord 'licenses/notice.' $pin),
        (NoticeRecord 'licenses/nUl.txt' $pin),
        (NoticeRecord ('licenses/notice'+[char]0x212a+'.txt') $pin),
        (NoticeRecord 'licenses/notice.txt:alternate' $pin),
        (NoticeRecord 'licenses/go-runtime-license' ('b'*64))
    )){
        $refused=$false
        try {$null=Read-NoticeFixture $valid $invalid}catch{$refused=$_.Exception.Message -like 'Installed SBOM notice*'}
        Assert $refused 'Managed detection refuses malformed, unsafe or contradictory notice references'
    }
}
$registrySource=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer-registry.iss'))
$uninstallSubject=[regex]::Match($installerSource,'(?ms)^function AWOpenUninstallSubject\(.*?^end;').Value
Assert ($completion.Contains("ExpandConstant('{uninstallexe}')") -and
    $completion.Contains('AWOpenUninstallSubject(UninstallerPath, Uninstaller)') -and
    $completion.Contains("AWOpenUninstallSubject(ChangeFileExt(UninstallerPath, '.dat'), UninstallData)") -and
    $completion.Contains('AWReadRegistration($0100, True, UninstallerPath,')) 'Setup must hold the compiler-selected uninstaller and its data while checking registration'
Assert ($uninstallSubject.Contains('AWOpenReplaceProbe(Path, $80000000, 1, 0, 3, $00200000, 0)') -and
    $uninstallSubject -cmatch '(?s)AWGetFileInfo.*Info.Attributes.*Info.Links = 1.*Info.SizeLow > 0') 'Uninstall files must be ordinary bounded single-link files held without write or delete sharing'
Assert ($installerSource -cmatch '(?m)^UninstallLogging=no\r?$' -and
    $registrySource -cmatch "(?s)'UninstallString', \x2430000002, 300, Command.*'QuietUninstallString', \x2430000002, 300, QuietCommand.*AWOrdinal\(Command, Expected\).*AWOrdinal\(QuietCommand, Expected \+ ' /SILENT'\)") 'Setup must bind both uninstall commands to the installed uninstaller'
$approvedUpgrade=[regex]::Match($installerSource,'(?ms)^function AWApprovedUpgradePreflight\(.*?^end;').Value
Assert ($prepare.Contains("AWApprovedUpgradePreflight(ExpandConstant('{app}'), ApprovalPin)") -and
    $copy -cmatch '(?s)AWApprovedUpgradePreflight\(Destination, AWPendingApprovalPin\).*RaiseException\(Failure\).*AWWriteLifecycleString\(AWPendingInstall, AWPendingInstallValue\(Destination\), True\)') 'Managed upgrades must recheck the baseline before pending record publication'
Assert ($approvedUpgrade -cmatch '(?s)ParamCount.*if Present then Exit.*AWCompare.*Ordering <= 0.*AWLockInstallationDirectory.*AWVerifyInstalledFile.*PayloadPin.*AWVerifyInstalledFile.*SBOMPin.*AWVerifyInstalledFile.*BuildPin.*AWOrdinal\(Version, Installed\)') 'Managed upgrade baseline must verify one strict prior version and all three installed pins'
$fingerprint=[regex]::Match($installerSource,'(?ms)^function AWStagedPayloadDigest:.*?^end;').Value
Assert ($fingerprint -cmatch '(?s)AWEmitStagedDirectoryChecks.*AWOrdinal\(Entries\[J - 1\], Entry\).*Entries\[J\] := Entry.*GetSHA256OfString\(Utf8Encode\(Entries.Text\)\)' -and
    $installerSource.Contains("Entries.Add('{#AWStagedLiteral}|{#FileSize(AWStagedPath)}|{#GetSHA256OfFile(AWStagedPath)}');") -and
    $approvedUpgrade -cmatch '(?s)\{#TargetArch\}.*AWStagedPayloadDigest.*GetSHA256OfString.*PendingPin = ApprovalPin.*AWOrdinal\(PendingVersion.*AWIsInstallationDirectory\(Destination, PendingDirectory\).*resumed from its pending installation record') 'Managed retry must match the committed approval, entire staged payload and destination'
$tempRecovery=[regex]::Match($installerSource,'(?ms)^function AWPrepareManagedTempRecovery\(.*?^end;').Value
$tempRemoval=[regex]::Match($installerSource,'(?ms)^function AWRemoveTemporaryUninstaller\(.*?^end;').Value
Assert ($tempRecovery -cmatch '(?s)GetSHA256OfString\(AWPendingInstallValue\(Destination\)\).*AWPendingInstallAbsent.*AWWriteLifecycleString.*not AWPendingInstallMatches.*AWReadLifecycleString.*not AWSetupTempName.*Baseline.IndexOf\(Current\[I\]\) < 0') 'Managed temporary cleanup must restrict recovery to new names from the bound original attempt'
Assert ($tempRemoval -cmatch '(?s)AWOpenReplaceProbe\(Path, \x2480010000, 1, 0, 3, \x2400200000, 0\).*Info.Links <> 1.*Subject.Size <> ExpectedSize.*GetSHA256OfStream\(Subject\) <> Identity.*AWOnlyDefaultDataStream\(Handle\).*AWSetFileDisposition\(Handle, 4, DeleteFile, 1\).*AWCloseNativeHandle\(Handle\).*AWPathAttributes\(Path\).*Code = 2.*Code = 3') 'Temporary uninstaller removal must verify the exact stream through the no-follow delete handle and confirm absence'
Assert ($tempRemoval -cmatch '(?s)CanDelete := Handle <> \x24FFFFFFFF.*if not CanDelete.*AWOpenReplaceProbe\(Path, \x2480000000, 1, 0, 3, \x2400200000, 0\).*GetSHA256OfStream\(Subject\) <> Identity.*AWOnlyDefaultDataStream\(Handle\).*if not CanDelete then begin Result := False; Exit; end;.*AWSetFileDisposition\(Handle, 4, DeleteFile, 1\)') 'Only an identified default-stream temporary uninstaller may block cleanup when the delete handle is unavailable'
Assert ($copy -cmatch '(?s)AWPrepareManagedTempRecovery\(Destination\).*AWWriteLifecycleString\(AWPendingInstall' -and
    $retirement -cmatch '(?s)AWVerifyCompletedInstall.*AWCleanupManagedTemporaryUninstallers\(Destination, Uninstaller\).*AWRetirePendingInstall') 'Setup must persist the baseline before copy and retire verified temporary uninstallers before clearing recovery'
$resumeFile=[regex]::Match($installerSource,'(?ms)^function AWVerifyUpgradeResumeFile\(.*?^end;').Value
Assert ($resumeFile -cmatch '(?s)AWPathAttributes.*Code = 2.*Code = 3.*AWVerifyInstalledFileDigests\(Path, BeforeDigest, AfterDigest, -MaximumSize, True, Held\)') 'Managed retry must admit only a missing file or verified old or new bytes'
Assert ($approvedUpgrade -cmatch '(?s)PendingPin = ApprovalPin.*AWVerifyUpgradeResumeFile.*PayloadPin.*AWVerifyUpgradeResumeFile.*SBOMPin.*AWVerifyUpgradeResumeFile.*BuildPin.*AWReadRegistration.*if Found32 then Exit.*AWOrdinal\(Version, Installed\).*AWOrdinal.*resumed from its pending installation record') 'Managed retry must check all present releases and the registered version before resuming'
$lifecycleHarness=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'test-windows-installer-lifecycle.ps1'))
Assert ($lifecycleHarness -cmatch "(?s)foreach\(\x24name in @\(.*?'Initialize-AccessWeaverInstallerRecoveryRegistry','Get-AccessWeaverInstallerRecoveryState'.*?\)\)\{") 'Native lifecycle controller binding must import the recovery registry initializer and reader together'
$legacyPublication=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-installer-registry-publication.iss'))
Assert ($approvedUpgrade -cmatch '(?s)Length\(Approval\) = 324.*AWLegacyApproval.Uninstaller := Copy\(Approval, 196, 64\).*AWLegacyApproval.UninstallData := Copy\(Approval, 261, 64\).*AWSha256Pin\(AWLegacyApproval.Uninstaller\).*AWSha256Pin\(AWLegacyApproval.UninstallData\).*Argument := Version \+ '','' \+ Approval') 'Legacy approval must validate and bind both prior uninstaller file hashes'
Assert ($installerSource -cmatch '(?s)CreateUninstallRegKey=no.*UninstallLogMode=overwrite' -and
    $installerSource -cmatch '(?s)AWPrepareOwnedProductRegistration\(Destination, LegacyHeld\).*AWWriteLifecycleString\(AWPendingInstall, AWPendingInstallValue\(Destination\), True\).*AWRetireApprovedLegacyRegistration\(Destination\).*finally.*AWCloseNativeHandle\(LegacyHeld\[I\]\)') 'Legacy retirement must replace the old uninstall log and retain approved files until durable retirement'
Assert ($legacyPublication -cmatch '(?s)AWLockInstallationDirectory\(Destination, Held\).*AWLegacyApproval.Payload.*AWLegacyApproval.SBOM.*AWLegacyApproval.BuildInfo.*AWLegacyApproval.Uninstaller.*AWLegacyApproval.UninstallData' -and
    $legacyPublication -cmatch '(?s)function AWRetireApprovedLegacyRegistration.*AWPendingInstallMatches.*AWStageLegacyRegistrationRetirement.*AWRegistryTransactionFinish.*AWProductRegistrationAbsent.*SetArrayLength\(AWPriorRegistration, 0\)') 'Legacy retirement must bind all prior files and commit verified absence before creating a protected registration'
$uninstallStep=[regex]::Match($installerSource,'(?ms)^procedure CurUninstallStepChanged\(CurUninstallStep: TUninstallStep\);.*?^end;').Value
Assert ($initialize.Contains('AWUninstallPreflight') -and -not $initialize.Contains('AWRunBoundedRestoration')) 'Uninstall initialization must validate without restoring machine state'
Assert ($uninstallStep -cmatch '(?s)if CurUninstallStep <> usUninstall then Exit;.*Failure := AWUninstallPreflight;.*AWRunBoundedRestoration.*#else\s+Exit;\s+#endif.*\bAbort;\s*end;') 'Uninstall must restore only after confirmation and abort deletion on failure'
Assert ($uninstallStep -cmatch "(?s)AWLockInstallationDirectory\(Destination, Held\).*AWVerifyInstalledFile\(Executable, '\{#PayloadDigest\}', \{#PayloadBytes\}, True, Controller\).*if Verified then begin.*AWUninstallPreflight.*AWRunBoundedRestoration\(Executable.*finally.*AWCloseNativeHandle\(Controller\).*AWCloseNativeHandle\(Held\[I\]\)") 'Uninstall must hold the verified release controller and directory handles through restoration'
Assert ($uninstallStep -cmatch "(?s)Restored := AWRunBoundedRestoration.*else begin\s+Failure := AWUninstallPreflight;.*finally.*if AWCloseNativeHandle\(Controller\) = 0 then HandlesClosed := False;.*if AWCloseNativeHandle\(Held\[I\]\) = 0 then HandlesClosed := False;.*if Restored and HandlesClosed and \(Failure = ''\) then begin\s+#ifdef ProtectedRegistrationQualification\s+AWOwnedRemovalStarted := AWBeginOwnedRemoval") 'Uninstall must recheck registration and confirm handle cleanup before deletion'
$beginOwnedRemoval=[regex]::Match($installerSource,'(?ms)^function AWBeginOwnedRemoval\(.*?^end;').Value
Assert ($beginOwnedRemoval -cmatch '(?s)AWLifecycleOwned and AWPendingInstallAbsent.*AWWriteLifecycleString\(AWPendingInstall, AWPendingInstallValue\(Destination\), True\).*AWRetirePublishedRegistration') 'Protected uninstall must flush its repair record before retiring registration'
Assert ($uninstallStep -cmatch "(?s)CurUninstallStep = usPostUninstall.*AWOwnedRemovalStarted.*AWVerifyOwnedRemoval.*AWRetirePendingInstall.*AWBeginOwnedRemoval.*if not AWOwnedRemovalStarted.*end else Exit;") 'Protected uninstall must refuse unverified registration retirement and clear recovery only after verified removal'
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
    $layout=Join-Path $fixture 'staged-layout'
    foreach($directory in @('licenses','docs\assets','docs\qualification')){
        [void][IO.Directory]::CreateDirectory((Join-Path $layout $directory))
    }
    Assert-InstallerPackageDirectories $layout $setupScript

    $stagedDocument=Join-Path $layout "docs\qualification\fixture's report.json"
    [IO.File]::WriteAllText($stagedDocument,'{}')
    $compiled=Join-Path $fixture 'preprocessed-package.iss'
    $nl=[Environment]::NewLine
    $header=@('[Files]','Source: "C:\Fixture\*"; DestDir: "{app}"; BeforeInstall: AWCheckPackageCopyDestination',
        '[Code]','function AWPayloadReplacementPreflight(const Destination: String): String;','begin') -join $nl
    $fingerprintHeader=@('end;','function AWStagedPayloadDigest: String;','begin') -join $nl
    $completionHeader=@($fingerprintHeader,'end;','function AWVerifyCompletedInstall(const Destination: String): Boolean;','begin') -join $nl
    [IO.File]::WriteAllText($compiled,$header+$nl+$completionHeader+$nl+'end;'+$nl)
    Reject {Assert-InstallerPackageDirectories $layout $setupScript $compiled} 'Compiled installer without the nested file preflight was accepted'
    $probe="  if not AWCanReplaceInstalledFile(Destination + '\docs\qualification\fixture''s report.json') then Exit;"
    $compiledPrefix=$header+$nl+$probe+$nl+$completionHeader+$nl
    [IO.File]::WriteAllText($compiled,$compiledPrefix+'end;'+$nl)
    Reject {Assert-InstallerPackageDirectories $layout $setupScript $compiled} 'Compiled installer without the nested completion check was accepted'
    $digest=(Get-FileHash -LiteralPath $stagedDocument -Algorithm SHA256).Hash.ToLowerInvariant()
    $verify="  if not AWVerifyAndHoldPackageFile(Destination + '\docs\qualification\fixture''s report.json', '$digest', 2, Held) then Exit;"
    [IO.File]::WriteAllText($compiled,$compiledPrefix+$verify.Replace($digest,('f'*64))+$nl+'end;'+$nl)
    Reject {Assert-InstallerPackageDirectories $layout $setupScript $compiled} 'Compiled installer with a mismatched staged file digest was accepted'
    [IO.File]::WriteAllText($compiled,$compiledPrefix+$verify.Replace(', 2,',', 3,')+$nl+'end;'+$nl)
    Reject {Assert-InstallerPackageDirectories $layout $setupScript $compiled} 'Compiled installer with a mismatched staged file length was accepted'
    $completedWithFingerprint=$compiledPrefix+$verify+$nl+'end;'+$nl
    [IO.File]::WriteAllText($compiled,$completedWithFingerprint)
    $refused=$false
    try {Assert-InstallerPackageDirectories $layout $setupScript $compiled}catch{
        $refused=$_.Exception.Message -like 'Compiled installer omitted the staged file from the upgrade fingerprint:*'
    }
    Assert $refused 'Compiled installer without the nested upgrade fingerprint entry was accepted'
    $fingerprintEntry="  Entries.Add('docs\qualification\fixture''s report.json|2|$digest');"
    [IO.File]::WriteAllText($compiled,$completedWithFingerprint.Replace($fingerprintHeader,$fingerprintHeader+$nl+$fingerprintEntry))
    $verifiedFingerprint=''
    Assert-InstallerPackageDirectories $layout $setupScript $compiled ([ref]$verifiedFingerprint)
    Assert ($verifiedFingerprint -cmatch '\A[a-f0-9]{64}\z') 'Installer validation did not export its compiled payload fingerprint'
    $fingerprintVector=@(
        ("  Entries.Add('docs\assets\a.txt|9|"+('0'*64)+"');"),
        ("  Entries.Add('docs\assets\B.txt|0|"+('f'*64)+"');")
    ) -join $nl
    Assert ((Get-InstallerCompiledPayloadFingerprint $fingerprintVector) -ceq '3d04356a3fe4532832d311d4cfd0ce8dc89f84eec2b89e04b75ed3b84c024630') 'Compiled fingerprint must match Setup ordinal ordering and CRLF bytes'
    $localizedFixture="  Entries.Add('docs\qualification\"+[char]0x130+"stanbul.md|4|"+('a'*64)+"');"
    Assert ((Get-InstallerCompiledPayloadFingerprint $localizedFixture) -ceq '280f5d3166a0ec511eaf280d3d3a0b9230de59912bb6e1eef69c1db938b36a03') 'Localized staged paths must be fingerprinted as UTF-8'
    [IO.File]::WriteAllText($compiled,([IO.File]::ReadAllText($compiled).Replace('; BeforeInstall: AWCheckPackageCopyDestination','')))
    Reject {Assert-InstallerPackageDirectories $layout $setupScript $compiled} 'Compiled installer without a per-file copy guard was accepted'
    $uncovered=Join-Path $layout 'docs\qualification\new'
    [void][IO.Directory]::CreateDirectory($uncovered)
    Reject {Assert-InstallerPackageDirectories $layout $setupScript} 'Unprotected staged documentation directory was accepted'
    [IO.Directory]::Delete($uncovered,$false)
    $alias=Join-Path $layout 'docs\assets'
    $aliasTarget=Join-Path $fixture 'alias-target'
    [void][IO.Directory]::CreateDirectory($aliasTarget)
    [IO.Directory]::Delete($alias,$false)
    [void](New-Item -ItemType Junction -Path $alias -Target $aliasTarget -ErrorAction Stop)
    try {Reject {Assert-InstallerPackageDirectories $layout $setupScript} 'Redirected staged documentation directory was accepted'}
    finally {[IO.Directory]::Delete($alias,$false)}

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
    function Assert-InstallerSigningOnlyChange([string]$Original,[string]$Signed) {
        $source=[IO.File]::Open($Original,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $target=[IO.File]::Open($Signed,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try {
                Assert-InstallerSigningStreamOnlyChange $source $target
                Assert ($source.CanRead -and $target.CanRead) 'Signing comparison closed caller-owned file handles'
            }
            finally {$target.Dispose()}
        } finally {$source.Dispose()}
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
    $subjectPath=Join-Path $fixture 'subject.cdx.json'
    $subject=[ordered]@{bomFormat='CycloneDX';specVersion='1.6';metadata=@{component=@{
        type='application';hashes=@(@{alg='SHA-256';content=('a'*64)})
    }}}
    [IO.File]::WriteAllText($subjectPath,($subject|ConvertTo-Json -Depth 10))
    Assert-InstallerSBOMSubject $subjectPath ('a'*64)
    Reject {Assert-InstallerSBOMSubject $subjectPath ('b'*64)} 'An SBOM for a different artifact matched the signed build'
    $subject.metadata.component.hashes+=@{alg='SHA-256';content=('a'*64)}
    [IO.File]::WriteAllText($subjectPath,($subject|ConvertTo-Json -Depth 10))
    Reject {Assert-InstallerSBOMSubject $subjectPath ('a'*64)} 'The signed build accepted an ambiguous SBOM subject digest'
    [IO.File]::WriteAllText($subjectPath,'{"notAnSBOM":true}')
    Reject {Assert-InstallerSBOMSubject $subjectPath ('a'*64)} 'The signed build accepted invalid subject metadata'

    $handoffOriginal=Join-Path $fixture 'handoff-original.exe'
    $handoffSigned=Join-Path $fixture 'handoff-signed.exe'
    [IO.File]::WriteAllText($handoffOriginal,'fixture unsigned')
    [IO.File]::WriteAllText($handoffSigned,'fixture approved signed')
    $originalDigest=(Get-FileHash -LiteralPath $handoffOriginal -Algorithm SHA256).Hash
    $signedDigest=(Get-FileHash -LiteralPath $handoffSigned -Algorithm SHA256).Hash

    [IO.File]::WriteAllText($handoffSigned,'fixture replacement signed bytes')
    Reject {Complete-InstallerSigning $handoffOriginal $originalDigest $handoffSigned $signedDigest} 'A changed signed file was handed back'
    Assert ((Get-FileHash -LiteralPath $handoffOriginal -Algorithm SHA256).Hash -ceq $originalDigest) 'Rejected signed bytes replaced the original'
    [IO.File]::WriteAllText($handoffSigned,'fixture approved signed')
    [IO.File]::WriteAllText($handoffOriginal,'fixture changed unsigned')
    Reject {Complete-InstallerSigning $handoffOriginal $originalDigest $handoffSigned $signedDigest} 'A changed original was replaced'
    Assert ([IO.File]::ReadAllText($handoffOriginal) -ceq 'fixture changed unsigned') 'Rejected replacement overwrote the changed original'
    [IO.File]::WriteAllText($handoffOriginal,'fixture unsigned')

    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        $held=[IO.File]::Open($handoffOriginal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            Reject {Complete-InstallerSigning $handoffOriginal $originalDigest $handoffSigned $signedDigest} 'A locked original was replaced'
        } finally {$held.Dispose()}
        Assert ((Get-FileHash -LiteralPath $handoffOriginal -Algorithm SHA256).Hash -ceq $originalDigest) 'Failed replacement changed the locked original'
    }
    Complete-InstallerSigning $handoffOriginal $originalDigest $handoffSigned $signedDigest
    Assert ((Get-FileHash -LiteralPath $handoffOriginal -Algorithm SHA256).Hash -ceq $signedDigest) 'Verified replacement bytes were not handed back'
    Assert (-not (Test-Path -LiteralPath $handoffSigned)) 'Signing left the consumed file in staging'

    [IO.File]::WriteAllText($handoffOriginal,'fixture unsigned')
    [IO.File]::WriteAllText($handoffSigned,'fixture approved signed')
    & {
        $verifyDigest=${function:Assert-InstallerSigningDigest}
        function Assert-InstallerSigningDigest([string]$Path,[string]$ExpectedSHA256) {
            if($Path -ceq $handoffOriginal -and $ExpectedSHA256 -ceq $signedDigest){
                [IO.File]::WriteAllText($Path,'fixture changed after replacement')
            }
            & $verifyDigest $Path $ExpectedSHA256
        }
        Reject {Complete-InstallerSigning $handoffOriginal $originalDigest $handoffSigned $signedDigest} 'Changed replacement bytes were returned as verified'
        Assert ([IO.File]::ReadAllText($handoffOriginal) -ceq 'fixture changed after replacement') 'The post-replacement guard was not exercised'
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
