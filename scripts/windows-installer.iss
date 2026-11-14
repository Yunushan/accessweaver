#ifndef BuildRoot
  #error BuildRoot must name the staged release directory
#endif
#ifndef ReleaseVersion
  #define ReleaseVersion "0.1.0"
#endif
#ifndef TargetArch
  #error TargetArch must identify the verified staged payload
#endif
#if TargetArch == "amd64"
  #define InstallArchitecture "x64os"
#elif TargetArch == "arm64"
  #define InstallArchitecture "arm64"
#else
  #error TargetArch must be amd64 or arm64
#endif
#define PayloadPath BuildRoot + "\accessweaver.exe"
#define BuildInfoPath BuildRoot + "\BUILD-INFO.json"
#define PayloadSBOMPath BuildRoot + "\SBOM.cdx.json"
#define PayloadBytes FileSize(PayloadPath)
#define BuildInfoBytes FileSize(BuildInfoPath)
#define PayloadSBOMBytes FileSize(PayloadSBOMPath)
#if PayloadBytes <= 0 || BuildInfoBytes <= 0 || PayloadSBOMBytes <= 0
  #error The installer requires the staged executable, build identity and SBOM
#endif
#define PayloadDigest GetSHA256OfFile(PayloadPath)
#define BuildInfoDigest GetSHA256OfFile(BuildInfoPath)
#define PayloadSBOMDigest GetSHA256OfFile(PayloadSBOMPath)

[Setup]
#ifdef OrganizationSigning
SignTool=accessweaverOrganization
SignedUninstaller=yes
SignedUninstallerDir={#BuildRoot}\..\signed-uninstallers
#endif
AppId={{B13D4677-4660-4E63-B3DB-03077ACBB092}
AppName=AccessWeaver
AppVersion={#ReleaseVersion}
AppPublisher=AccessWeaver contributors
AppPublisherURL=https://github.com/Yunushan/accessweaver
DefaultDirName={autopf}\AccessWeaver
DefaultGroupName=AccessWeaver
AllowNoIcons=yes
ArchitecturesAllowed={#InstallArchitecture}
ArchitecturesInstallIn64BitMode={#InstallArchitecture}
PrivilegesRequired=admin
LicenseFile={#BuildRoot}\LICENSE
#ifdef OrganizationSigning
OutputDir={#BuildRoot}\..\signed
#else
OutputDir={#BuildRoot}\..
#endif
OutputBaseFilename=accessweaver-{#ReleaseVersion}-windows-{#TargetArch}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\accessweaver.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
SetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092
[Files]
Source: "{#BuildRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\AccessWeaver"; Filename: "{app}\accessweaver.exe"; Parameters: "ui"
[Code]
#include "windows-installer-lock.iss"
#include "windows-installer-version.iss"

#include "windows-installer-registry.iss"
#include "windows-installer-restore.iss"

const
  AWLifecycleRegistry = 'SOFTWARE\AccessWeaver\Installer';
  AWPendingInstall = 'PendingInstall';
  AWOpenReadDenyWrite = $0020; { fmOpenRead or fmShareDenyWrite }

var AWInstallFinished, AWPendingRetirementFailed: Boolean;

function AWFlushRegistryKey(Key: LongWord): LongWord;
  external 'RegFlushKey@advapi32.dll stdcall';

function AWReadPendingVersion(var Version, Directory: String): String;
var Key, Status, Kind, Bytes: LongWord;
    Buffer, RecordValue: String; Units, Separator: Integer;
begin
  Result := ''; Version := ''; Directory := '';
  Status := AWOpenRegistrationKey($80000002, AWLifecycleRegistry, 0, $0101, Key);
  if (Status = 2) or (Status = 3) then Exit;
  Result := 'Cannot verify the AccessWeaver pending installation record.';
  if Status <> 0 then Exit;
  try
    SetLength(Buffer, 518); Bytes := 1036; Kind := 0;
    Status := AWGetRegistrationValue(Key, '', AWPendingInstall, $30000002, Kind, Buffer, Bytes);
    if Status = 2 then begin Result := ''; Exit; end;
    if (Status <> 0) or (Kind <> 1) or (Bytes < 4) or (Bytes > 1036) or ((Bytes mod 2) <> 0) then Exit;
    Units := Bytes div 2;
    if Buffer[Units] <> #0 then Exit;
    RecordValue := Copy(Buffer, 1, Units - 1);
    Separator := Pos('|', RecordValue);
    if (Pos(#0, RecordValue) <> 0) or (Separator < 2) or (Separator > 257) then Exit;
    Version := Copy(RecordValue, 1, Separator - 1);
    Directory := Copy(RecordValue, Separator + 1, Length(RecordValue));
    if (Directory <> '') and (Length(Directory) <= 260) and (Pos('|', Directory) = 0) then Result := '';
  finally
    AWCloseRegistrationKey(Key);
  end;
end;

function AWFlushLifecycleRecord: Boolean;
var Key: LongWord;
begin
  Result := False;
  if AWOpenRegistrationKey($80000002, AWLifecycleRegistry, 0, $0101, Key) <> 0 then Exit;
  try
    Result := AWFlushRegistryKey(Key) = 0;
  finally
    AWCloseRegistrationKey(Key);
  end;
end;

function AWCompareDestination(const Left: String; LeftLength: Integer;
  const Right: String; RightLength, IgnoreCase: Integer): Integer;
  external 'CompareStringOrdinal@kernel32.dll stdcall';

function AWIsInstallationDirectory(const Destination, Registered: String): Boolean;
var Target, Location: String;
begin
  Target := RemoveBackslashUnlessRoot(Destination);
  Location := RemoveBackslashUnlessRoot(Registered);
  Result := (Target <> '') and (Location <> '') and
    (AWCompareDestination(Target, Length(Target), Location, Length(Location), 1) = 2);
end;

function AWPendingSetupPreflight(const Destination: String): String;
var Version, Directory: String; Ordering: Integer;
begin
  Result := AWReadPendingVersion(Version, Directory);
  if (Result <> '') or (Version = '') then Exit;
  if not AWCompare('{#ReleaseVersion}', Version, Ordering) then
    Result := 'The AccessWeaver pending installation version is invalid.'
  else if Ordering < 0 then
    Result := 'An AccessWeaver installation is incomplete. Retry with the same or a newer approved installer.'
  else if (Destination <> '') and not AWIsInstallationDirectory(Destination, Directory) then
    Result := 'Retry the approved installer in the original AccessWeaver installation directory.';
end;

function AWPathAttributes(const Path: String): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';
function AWDriveType(const Root: String): LongWord;
  external 'GetDriveTypeW@kernel32.dll stdcall';

function AWInstallationPathPreflight(const Directory: String; AllowMissing: Boolean): String;
var Target, Root, Part: String; Attributes, Code: LongWord; Start, I: Integer;
begin
  Result := 'AccessWeaver requires a local installation directory without junctions or symbolic links.';
  Target := RemoveBackslashUnlessRoot(Directory);
  if (Length(Target) < 4) or (Length(Target) > 259) or PathHasInvalidCharacters(Target, True) then Exit;
  if (Target[2] <> ':') or (Target[3] <> '\') or (Pos('/', Target) <> 0) then Exit;
  Root := Copy(Target, 1, 3);
  if AWDriveType(Root) <> 3 then Exit; { DRIVE_FIXED }
  { Check lexical components before probing any path. }
  Target := Target + '\';
  Start := 4;
  for I := 4 to Length(Target) do begin
    if Target[I] = '\' then begin
      Part := Copy(Target, Start, I - Start);
      if Part = '' then Exit;
      if (Part[Length(Part)] = '.') or (Part[Length(Part)] = ' ') then Exit;
      Start := I + 1;
    end;
  end;
  { Check from root to leaf so a parent junction is never accepted as a directory. }
  for I := 4 to Length(Target) do begin
    if Target[I] = '\' then begin
      Attributes := AWPathAttributes(Copy(Target, 1, I - 1));
      if Attributes = $FFFFFFFF then begin
        Code := DLLGetLastError;
        if not AllowMissing or ((Code <> 2) and (Code <> 3)) then Exit;
      end else if ((Attributes and $00000400) <> 0) or ((Attributes and $00000010) = 0) then Exit;
    end;
  end;
  Result := '';
end;

function AWInstalledFileMatches(const Directory, Name, Digest: String; Size: Int64): Boolean;
var Path: String; Attributes: LongWord; Payload: TFileStream;
begin
  Result := False;
  Path := Directory + '\' + Name;
  Attributes := AWPathAttributes(Path);
  if (Attributes = $FFFFFFFF) or ((Attributes and ($00000400 or $00000010)) <> 0) then Exit;
  Payload := TFileStream.Create(Path, AWOpenReadDenyWrite);
  try
    if Payload.Size <> Size then Exit;
    Result := CompareText(GetSHA256OfStream(Payload), Digest) = 0;
  finally
    Payload.Free;
  end;
end;

function AWVerifyCompletedInstall(const Destination: String): Boolean;
var Found64, Found32: Boolean; Version, Location, Version32, Location32: String;
begin
  Result := False;
  try
    if AWInstallationPathPreflight(Destination, False) <> '' then Exit;
    if AWReadRegistration($0100, True, Found64, Version, Location) <> '' then Exit;
    if AWReadRegistration($0200, False, Found32, Version32, Location32) <> '' then Exit;
    if not Found64 or Found32 or (Version <> '{#ReleaseVersion}') or
      not AWIsInstallationDirectory(Destination, Location) then Exit;
    if not AWInstalledFileMatches(Destination, 'accessweaver.exe', '{#PayloadDigest}', {#PayloadBytes}) then Exit;
    if not AWInstalledFileMatches(Destination, 'BUILD-INFO.json', '{#BuildInfoDigest}', {#BuildInfoBytes}) then Exit;
    Result := AWInstalledFileMatches(Destination, 'SBOM.cdx.json', '{#PayloadSBOMDigest}', {#PayloadSBOMBytes});
  except
    Result := False;
  end;
end;

function AWOpenReplaceProbe(const Path: String; Access, Sharing, Security,
  Disposition, Flags, Template: LongWord): LongWord;
  external 'CreateFileW@kernel32.dll stdcall';

function AWCanReplaceInstalledFile(const Path: String): Boolean;
var Attributes, Handle, Code: LongWord;
begin
  Result := False;
  Attributes := AWPathAttributes(Path);
  if Attributes = $FFFFFFFF then begin
    Code := DLLGetLastError;
    Result := (Code = 2) or (Code = 3);
    Exit;
  end;
  if (Attributes and ($00000400 or $00000010)) <> 0 then Exit;
  { Probe DELETE access without writing, truncating or deleting. }
  Handle := AWOpenReplaceProbe(Path, $00010000, $00000007, 0, 3, $00200000, 0);
  if Handle = $FFFFFFFF then Exit;
  Result := AWCloseNativeHandle(Handle) <> 0;
end;

function AWPayloadReplacementPreflight(const Destination: String): String;
begin
  Result := '';
  if not AWCanReplaceInstalledFile(Destination + '\accessweaver.exe') then
    Result := 'The AccessWeaver executable cannot be replaced. Close it and release any file locks before retrying setup.'
  else if not AWCanReplaceInstalledFile(Destination + '\BUILD-INFO.json') then
    Result := 'The AccessWeaver BUILD-INFO.json cannot be replaced. Release any file locks before retrying setup.'
  else if not AWCanReplaceInstalledFile(Destination + '\SBOM.cdx.json') then
    Result := 'The AccessWeaver SBOM.cdx.json cannot be replaced. Release any file locks before retrying setup.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Failure, Destination: String;
begin
  if CurStep = ssInstall then begin
    if not AWLifecycleOwned then RaiseException('The AccessWeaver installation lock is not held.');
    Destination := ExpandConstant('{app}');
    if (Destination = '') or (Length(Destination) > 260) or (Pos('|', Destination) <> 0) or
      (Length('{#ReleaseVersion}') > 256) then
      RaiseException('Cannot record the AccessWeaver installation destination.');
    Failure := AWPendingSetupPreflight(Destination);
    if Failure = '' then Failure := AWInstallationPathPreflight(Destination, True);
    if Failure = '' then Failure := AWPayloadReplacementPreflight(Destination);
    if Failure <> '' then RaiseException(Failure);
    if not RegWriteStringValue(HKLM64, AWLifecycleRegistry, AWPendingInstall, '{#ReleaseVersion}|' + Destination) or
      not AWFlushLifecycleRecord then
      RaiseException('Cannot persist the AccessWeaver pending installation record.');
  end else if CurStep = ssPostInstall then begin
    AWInstallFinished := True;
  end else if (CurStep = ssDone) and AWInstallFinished then begin
    if not AWVerifyCompletedInstall(ExpandConstant('{app}')) then begin
      AWPendingRetirementFailed := True;
      Log('AccessWeaver installed payload or registration verification failed. Pending installation record retained.');
    end else if not RegDeleteValue(HKLM64, AWLifecycleRegistry, AWPendingInstall) or not AWFlushLifecycleRecord then begin
      AWPendingRetirementFailed := True;
      Log('Cannot retire the AccessWeaver pending installation record.');
    end else
      Log('AccessWeaver installed payload and registration verified. Pending installation record retired.');
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := 0;
  if AWPendingRetirementFailed then Result := 1603;
end;

function AWRegistrationPreflight(const Destination: String): String;
var Found64, Found32, ReadLocation: Boolean;
    Version64, Version32, Location64, Location32, Installed, Location: String;
    Ordering: Integer;
begin
  ReadLocation := Destination <> '';
  Result := AWReadRegistration($0100, ReadLocation, Found64, Version64, Location64);
  if Result <> '' then Exit;
  Result := AWReadRegistration($0200, ReadLocation, Found32, Version32, Location32);
  if Result <> '' then Exit;
  if Found64 and Found32 then begin
    Result := 'Multiple machine installations of AccessWeaver are registered. Review them before retrying.'; Exit;
  end;
  if not AWCompare('{#ReleaseVersion}', '{#ReleaseVersion}', Ordering) then begin
    Result := 'This installer has invalid release version metadata.'; Exit;
  end;
  if not Found64 and not Found32 then Exit;
  if Found64 then begin Installed := Version64; Location := Location64; end
  else begin Installed := Version32; Location := Location32; end;
  if not AWCompare('{#ReleaseVersion}', Installed, Ordering) then begin
    Result := 'The installed AccessWeaver version is invalid. Review the installation and recovery records before retrying.'; Exit;
  end;
  if Ordering < 0 then begin
    Result := 'A newer AccessWeaver version is installed. Use a current or newer installer. This installer will not downgrade it.'; Exit;
  end;
  if ReadLocation and not AWIsInstallationDirectory(Destination, Location) then
    Result := 'Upgrade or reinstall AccessWeaver in its registered installation directory.';
end;

function AWUninstallDirectoryPreflight(const Destination: String): String;
var Found64, Found32: Boolean;
    Version, Location, OtherVersion, OtherLocation: String;
begin
  Result := AWReadRegistration($0100, True, Found64, Version, Location);
  if Result <> '' then Exit;
  Result := AWReadRegistration($0200, False, Found32, OtherVersion, OtherLocation);
  if Result <> '' then Exit;
  if not Found64 or Found32 or not AWIsInstallationDirectory(Destination, Location) then
    Result := 'This uninstaller does not match the active AccessWeaver installation directory. Use the registered uninstaller.'
  else if AWOrdinal(Version, '{#ReleaseVersion}') <> 0 then
    Result := 'This uninstaller version does not match the active AccessWeaver registration. Use the registered uninstaller.';
end;

function InitializeSetup: Boolean;
var Failure: String;
begin
  Failure := AWAcquireLifecycle;
  if Failure = '' then Failure := AWPendingSetupPreflight('');
  if Failure = '' then Failure := AWRegistrationPreflight('');
  Result := Failure = '';
  if not Result then begin
    AWReleaseLifecycle;
    Log(Failure);
    if not WizardSilent then SuppressibleMsgBox(Failure, mbCriticalError, MB_OK, IDOK);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  { Recheck after wizard interaction, while the product SetupMutex remains held. }
  if not AWLifecycleOwned then Result := 'The AccessWeaver installation lock is not held. Retry setup.'
  else begin
    Result := AWRegistrationPreflight(ExpandConstant('{app}'));
    if Result = '' then Result := AWPendingSetupPreflight(ExpandConstant('{app}'));
    if Result = '' then Result := AWInstallationPathPreflight(ExpandConstant('{app}'), True);
    if Result = '' then Result := AWPayloadReplacementPreflight(ExpandConstant('{app}'));
  end;
end;

procedure DeinitializeSetup;
begin
  AWReleaseLifecycle;
end;

procedure DeinitializeUninstall;
begin
  AWReleaseLifecycle;
end;

function AWUninstallPreflight: String;
var PendingVersion, PendingDirectory: String;
begin
  if not AWLifecycleOwned then begin
    Result := 'The AccessWeaver installation lock is not held. Retry uninstalling.'; Exit;
  end;
  Result := AWReadPendingVersion(PendingVersion, PendingDirectory);
  if (Result = '') and (PendingVersion <> '') then
    Result := 'An AccessWeaver installation is incomplete. Retry the approved installer before uninstalling.';
  if Result = '' then Result := AWUninstallDirectoryPreflight(ExpandConstant('{app}'));
  if Result = '' then Result := AWInstallationPathPreflight(ExpandConstant('{app}'), False);
end;

function InitializeUninstall: Boolean;
var Failure: String;
begin
  { Respect an already active older setup, as well as corrected lifecycle owners. }
  if CheckForMutexes('Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092') then
    Failure := 'An AccessWeaver setup is active. Wait for it to finish before uninstalling.'
  else Failure := AWAcquireLifecycle;
  if Failure = '' then Failure := AWUninstallPreflight;
  Result := Failure = '';
  if not Result then begin
    AWReleaseLifecycle;
    Log(Failure);
    if not UninstallSilent then SuppressibleMsgBox(Failure, mbCriticalError, MB_OK, IDOK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var ResultCode: LongWord; Failure: String;
begin
  if CurUninstallStep <> usUninstall then Exit;
  { Inno reaches this step after confirmation and app-mutex checks, before
    processing its deletion log. Keep lifecycle ownership until deinitialization. }
  Failure := AWUninstallPreflight;
  if Failure <> '' then begin
    Log(Failure);
    if not UninstallSilent then SuppressibleMsgBox(Failure, mbCriticalError, MB_OK, IDOK);
    Abort;
  end;
  Log('AccessWeaver system restoration starts at the uninstall step.');
  if AWRunBoundedRestoration(ExpandConstant('{app}\accessweaver.exe'),
    'system installer-restore --confirm',
    ExpandConstant('{app}'), AWRestorationDeadlineMilliseconds, ResultCode, Failure) then Exit;

  Log(Failure);
  Log('AccessWeaver system restoration failed; process result/error code: ' + IntToStr(ResultCode));
  if not UninstallSilent then
    MsgBox('AccessWeaver could not restore its system changes. Review the recovery journal in ProgramData\AccessWeaver\logs, then retry uninstalling.', mbError, MB_OK);
  Abort;
end;

#ifdef EvidenceOutput
  #expr SaveToFile(EvidenceOutput)
#endif
