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
UninstallLogging=no
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

var AWInstallFinished, AWPendingRetirementFailed: Boolean;
    AWPendingApprovalPin: String;

function AWFlushRegistryKey(Key: LongWord): LongWord;
  external 'RegFlushKey@advapi32.dll stdcall';

function AWSha256Pin(const Value: String): Boolean;
var I: Integer;
begin
  Result := False;
  if Length(Value) <> 64 then Exit;
  for I := 1 to Length(Value) do
    if (Value[I] < '0') or (Value[I] > '9') then
      if (Value[I] < 'a') or (Value[I] > 'f') then Exit;
  Result := True;
end;

function AWReadPendingVersion(var Version, Directory, ApprovalPin: String): String;
var Key, Status, Kind, Bytes: LongWord;
    Buffer, RecordValue: String; Units, Separator: Integer;
begin
  Result := ''; Version := ''; Directory := ''; ApprovalPin := '';
  Status := AWOpenRegistrationKey($80000002, AWLifecycleRegistry, 0, $0101, Key);
  if (Status = 2) or (Status = 3) then Exit;
  Result := 'Cannot verify the AccessWeaver pending installation record.';
  if Status <> 0 then Exit;
  try
    { Version, directory, optional approval pin, separators and terminator. }
    SetLength(Buffer, 583); Bytes := 1166; Kind := 0;
    Status := AWGetRegistrationValue(Key, '', AWPendingInstall, $30000002, Kind, Buffer, Bytes);
    if Status = 2 then begin Result := ''; Exit; end;
    if (Status <> 0) or (Kind <> 1) or (Bytes < 4) or (Bytes > 1166) or ((Bytes mod 2) <> 0) then Exit;
    Units := Bytes div 2;
    if Buffer[Units] <> #0 then Exit;
    RecordValue := Copy(Buffer, 1, Units - 1);
    Separator := Pos('|', RecordValue);
    if (Pos(#0, RecordValue) <> 0) or (Separator < 2) or (Separator > 257) then Exit;
    Version := Copy(RecordValue, 1, Separator - 1);
    Directory := Copy(RecordValue, Separator + 1, Length(RecordValue));
    Separator := Pos('|', Directory);
    if Separator <> 0 then begin
      ApprovalPin := Copy(Directory, Separator + 1, Length(Directory));
      if not AWSha256Pin(ApprovalPin) then Exit;
      SetLength(Directory, Separator - 1);
    end;
    if (Directory <> '') and (Length(Directory) <= 260) then Result := '';
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

function AWPendingInstallMatches(const Destination: String): Boolean;
var Version, Directory, ApprovalPin: String;
begin
  Result := False;
  if AWReadPendingVersion(Version, Directory, ApprovalPin) <> '' then Exit;
  Result := (AWOrdinal(Version, '{#ReleaseVersion}') = 0) and
    (AWOrdinal(Directory, Destination) = 0) and (ApprovalPin = AWPendingApprovalPin);
end;

function AWPendingSetupPreflight(const Destination: String): String;
var Version, Directory, ApprovalPin: String; Ordering: Integer;
begin
  Result := AWReadPendingVersion(Version, Directory, ApprovalPin);
  if (Result <> '') or (Version = '') then Exit;
  if not AWCompare('{#ReleaseVersion}', Version, Ordering) then
    Result := 'The AccessWeaver pending installation version is invalid.'
  else if Ordering < 0 then
    Result := 'An AccessWeaver installation is incomplete. Retry with the same or a newer approved installer.'
  else if (ApprovalPin <> '') and (AWOrdinal('{#ReleaseVersion}', Version) <> 0) then
    Result := 'Finish the incomplete AccessWeaver managed upgrade with its original approved installer.'
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

function AWOpenReplaceProbe(const Path: String; Access, Sharing, Security,
  Disposition, Flags, Template: LongWord): LongWord;
  external 'CreateFileW@kernel32.dll stdcall';

type
  AWFileInfo = record
    Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
    VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow: LongWord;
  end;
  AWDirectoryHandles = array of LongWord;

function AWGetFileInfo(Handle: LongWord; var Info: AWFileInfo): Integer;
  external 'GetFileInformationByHandle@kernel32.dll stdcall';

function AWLockInstallationDirectory(const Directory: String; var Held: AWDirectoryHandles): Boolean;
var Target: String; I, Count: Integer; Handle: LongWord; Info: AWFileInfo;
begin
  Result := False;
  if AWInstallationPathPreflight(Directory, False) <> '' then Exit;
  Target := RemoveBackslashUnlessRoot(Directory) + '\';
  for I := 4 to Length(Target) do begin
    if Target[I] = '\' then begin
      { Open each component in order, with OPEN_REPARSE_POINT and
        BACKUP_SEMANTICS. Request FILE_LIST_DIRECTORY so sharing checks
        apply, and withhold delete sharing to prevent rename. }
      Handle := AWOpenReplaceProbe(Copy(Target, 1, I - 1), 1, 3, 0, 3, $02200000, 0);
      if Handle = $FFFFFFFF then Exit;
      Count := GetArrayLength(Held);
      SetArrayLength(Held, Count + 1);
      Held[Count] := Handle;
      if AWGetFileInfo(Handle, Info) = 0 then Exit;
      if (Info.Attributes and ($00000400 or $00000010)) <> $00000010 then Exit;
    end;
  end;
  Result := True;
end;

function AWVerifyInstalledFile(const Path, Digest: String; Size: Int64;
  SingleLink: Boolean; var Held: LongWord): Boolean;
var Info: AWFileInfo; Payload: THandleStream;
begin
  Result := False;
  { GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, OPEN_REPARSE_POINT. }
  Held := AWOpenReplaceProbe(Path, $80000000, 1, 0, 3, $00200000, 0);
  if Held = $FFFFFFFF then Exit;
  if AWGetFileInfo(Held, Info) = 0 then Exit;
  if (Info.Attributes and ($00000400 or $00000010)) <> 0 then Exit;
  if SingleLink and (Info.Links <> 1) then Exit;
  Payload := THandleStream.Create(Held);
  try
    if Size >= 0 then begin
      if Payload.Size <> Size then Exit;
    end else if (Payload.Size <= 0) or (Payload.Size > -Size) then Exit;
    Result := CompareText(GetSHA256OfStream(Payload), Digest) = 0;
  finally
    { THandleStream borrows the native handle. The caller closes it. }
    Payload.Free;
  end;
end;

function AWVerifyCompletedInstall(const Destination: String; var Held: AWDirectoryHandles;
  var Executable, BuildInfo, SBOM, Uninstaller: LongWord): Boolean;
var Found64, Found32: Boolean;
    Version, Location, Version32, Location32, UninstallerPath: String;
    Info: AWFileInfo;
begin
  Result := False;
  if not AWLockInstallationDirectory(Destination, Held) then Exit;
  if not AWVerifyInstalledFile(Destination + '\accessweaver.exe', '{#PayloadDigest}', {#PayloadBytes}, True, Executable) then Exit;
  if not AWVerifyInstalledFile(Destination + '\BUILD-INFO.json', '{#BuildInfoDigest}', {#BuildInfoBytes}, False, BuildInfo) then Exit;
  if not AWVerifyInstalledFile(Destination + '\SBOM.cdx.json', '{#PayloadSBOMDigest}', {#PayloadSBOMBytes}, False, SBOM) then Exit;
  UninstallerPath := ExpandConstant('{uninstallexe}');
  if not AWIsInstallationDirectory(Destination, ExtractFileDir(UninstallerPath)) then Exit;
  Uninstaller := AWOpenReplaceProbe(UninstallerPath, $80000000, 1, 0, 3, $00200000, 0);
  if Uninstaller = $FFFFFFFF then Exit;
  if AWGetFileInfo(Uninstaller, Info) = 0 then Exit;
  if ((Info.Attributes and ($00000400 or $00000010)) <> 0) or (Info.Links <> 1) or
     (Info.SizeHigh <> 0) or (Info.SizeLow = 0) or (Info.SizeLow > 536870912) then Exit;
  if AWReadRegistration($0100, True, UninstallerPath, Found64, Version, Location) <> '' then Exit;
  if AWReadRegistration($0200, False, '', Found32, Version32, Location32) <> '' then Exit;
  Result := Found64 and not Found32 and (Version = '{#ReleaseVersion}') and
    AWIsInstallationDirectory(Destination, Location);
end;

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

function AWRegistrationPreflight(const Destination: String): String;
var Found64, Found32, ReadLocation: Boolean;
    Version64, Version32, Location64, Location32, Installed, Location: String;
    Ordering: Integer;
begin
  ReadLocation := Destination <> '';
  Result := AWReadRegistration($0100, ReadLocation, '', Found64, Version64, Location64);
  if Result <> '' then Exit;
  Result := AWReadRegistration($0200, ReadLocation, '', Found32, Version32, Location32);
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

const AWUpgradeFromPrefix = '/AWUpgradeFrom=';

function AWApprovedUpgradePreflight(const Destination: String; var ApprovalPin: String): String;
var I, Ordering: Integer; Argument, Approval, Version, PayloadPin, SBOMPin, BuildPin,
    Installed, Location, OtherVersion, OtherLocation, PendingVersion, PendingDirectory, PendingPin: String;
    Present, Found64, Found32: Boolean;
    Held: AWDirectoryHandles; Executable, BuildInfo, SBOM: LongWord;
begin
  ApprovalPin := '';
  Result := AWReadPendingVersion(PendingVersion, PendingDirectory, PendingPin);
  if Result <> '' then Exit;
  Result := 'Invalid AccessWeaver managed upgrade approval.';
  Present := False;
  for I := 1 to ParamCount do begin
    Argument := ParamStr(I);
    if CompareText(Copy(Argument, 1, Length(AWUpgradeFromPrefix)), AWUpgradeFromPrefix) = 0 then begin
      if Present then Exit;
      Present := True;
      Approval := Copy(Argument, Length(AWUpgradeFromPrefix) + 1, Length(Argument));
    end else if CompareText(Argument, '/AWUpgradeFrom') = 0 then Exit;
  end;
  if not Present then begin
    if PendingPin = '' then Result := ''
    else Result := 'Finish the incomplete AccessWeaver managed upgrade with its original approved installer and baseline argument.';
    Exit;
  end;
  if Length(Approval) > 451 then Exit;
  { Commas cannot occur in the four fields. AWCompare validates SemVer. }
  I := Pos(',', Approval);
  if I = 0 then Exit;
  Version := Copy(Approval, 1, I - 1);
  Delete(Approval, 1, I);
  if not AWCompare('{#ReleaseVersion}', Version, Ordering) or (Ordering <= 0) then Exit;
  if (Length(Approval) <> 194) or (Approval[65] <> ',') or (Approval[130] <> ',') then Exit;
  PayloadPin := Copy(Approval, 1, 64);
  SBOMPin := Copy(Approval, 66, 64);
  BuildPin := Copy(Approval, 131, 64);
  if not AWSha256Pin(PayloadPin) or not AWSha256Pin(SBOMPin) or not AWSha256Pin(BuildPin) then Exit;

  { The pin binds the validated argument and package contents to this attempt.
    The separate record fields bind its exact new version and destination. }
  Argument := Version + ',' + Approval + '|{#TargetArch}|{#PayloadDigest}|{#PayloadSBOMDigest}|{#BuildInfoDigest}';
  ApprovalPin := Lowercase(GetSHA256OfString(Argument));
  if PendingPin <> '' then begin
    Result := 'Finish the incomplete AccessWeaver managed upgrade with its original approved installer and baseline argument.';
    if (PendingPin = ApprovalPin) and (AWOrdinal(PendingVersion, '{#ReleaseVersion}') = 0) and
        AWIsInstallationDirectory(Destination, PendingDirectory) then begin
      Result := '';
      Log('AccessWeaver approved upgrade resumed from its pending installation record.');
    end;
    Exit;
  end;

  Result := 'The installed AccessWeaver release differs from the approved upgrade baseline.';
  Executable := $FFFFFFFF; BuildInfo := $FFFFFFFF; SBOM := $FFFFFFFF;
  try
    try
      if not AWLockInstallationDirectory(Destination, Held) then Exit;
      if not AWVerifyInstalledFile(Destination + '\accessweaver.exe', PayloadPin, -134217728, True, Executable) then Exit;
      if not AWVerifyInstalledFile(Destination + '\SBOM.cdx.json', SBOMPin, -4194304, True, SBOM) then Exit;
      if not AWVerifyInstalledFile(Destination + '\BUILD-INFO.json', BuildPin, -65536, True, BuildInfo) then Exit;
      if AWReadRegistration($0100, True, '', Found64, Installed, Location) <> '' then Exit;
      if AWReadRegistration($0200, False, '', Found32, OtherVersion, OtherLocation) <> '' then Exit;
      if Found64 and not Found32 and (AWOrdinal(Version, Installed) = 0) and
          AWIsInstallationDirectory(Destination, Location) then begin
        Result := '';
        Log('AccessWeaver approved upgrade baseline verified.');
      end;
    except
      { An incomplete or inaccessible baseline cannot authorize replacement. }
    end;
  finally
    if SBOM <> $FFFFFFFF then AWCloseNativeHandle(SBOM);
    if BuildInfo <> $FFFFFFFF then AWCloseNativeHandle(BuildInfo);
    if Executable <> $FFFFFFFF then AWCloseNativeHandle(Executable);
    for I := GetArrayLength(Held) - 1 downto 0 do AWCloseNativeHandle(Held[I]);
  end;
end;

procedure AWCompleteInstallation(const Destination: String);
var Held: AWDirectoryHandles; Executable, BuildInfo, SBOM, Uninstaller: LongWord; I: Integer;
    Verified: Boolean;
begin
  Executable := $FFFFFFFF; BuildInfo := $FFFFFFFF; SBOM := $FFFFFFFF; Uninstaller := $FFFFFFFF;
  try
    try
      Verified := AWVerifyCompletedInstall(Destination, Held, Executable, BuildInfo, SBOM, Uninstaller);
    except
      Verified := False;
    end;
    AWPendingRetirementFailed := True;
    if not Verified then
      Log('AccessWeaver installed payload or registration verification failed. Pending installation record retained.')
    else if not AWPendingInstallMatches(Destination) then
      Log('AccessWeaver pending installation record changed or could not be verified. Setup did not clear it.')
    else if not RegDeleteValue(HKLM64, AWLifecycleRegistry, AWPendingInstall) or not AWFlushLifecycleRecord then
      Log('Cannot retire the AccessWeaver pending installation record.')
    else begin
      AWPendingRetirementFailed := False;
      Log('AccessWeaver installed payload and registration verified. Pending installation record retired.');
    end;
  finally
    if Uninstaller <> $FFFFFFFF then AWCloseNativeHandle(Uninstaller);
    if SBOM <> $FFFFFFFF then AWCloseNativeHandle(SBOM);
    if BuildInfo <> $FFFFFFFF then AWCloseNativeHandle(BuildInfo);
    if Executable <> $FFFFFFFF then AWCloseNativeHandle(Executable);
    for I := GetArrayLength(Held) - 1 downto 0 do
      AWCloseNativeHandle(Held[I]);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Failure, Destination, RecordValue: String;
begin
  if CurStep = ssInstall then begin
    if not AWLifecycleOwned then RaiseException('The AccessWeaver installation lock is not held.');
    Destination := ExpandConstant('{app}');
    if (Destination = '') or (Length(Destination) > 260) or (Pos('|', Destination) <> 0) or
      (Length('{#ReleaseVersion}') > 256) then
      RaiseException('Cannot record the AccessWeaver installation destination.');
    Failure := AWRegistrationPreflight(Destination);
    if Failure = '' then Failure := AWPendingSetupPreflight(Destination);
    if Failure = '' then Failure := AWInstallationPathPreflight(Destination, True);
    if Failure = '' then Failure := AWPayloadReplacementPreflight(Destination);
    if Failure = '' then Failure := AWApprovedUpgradePreflight(Destination, AWPendingApprovalPin);
    if Failure <> '' then RaiseException(Failure);
    RecordValue := '{#ReleaseVersion}|' + Destination;
    if AWPendingApprovalPin <> '' then RecordValue := RecordValue + '|' + AWPendingApprovalPin;
    if not RegWriteStringValue(HKLM64, AWLifecycleRegistry, AWPendingInstall, RecordValue) or
      not AWFlushLifecycleRecord then
      RaiseException('Cannot persist the AccessWeaver pending installation record.');
    if not AWPendingInstallMatches(Destination) then
      RaiseException('Cannot verify the AccessWeaver pending installation record after writing it.');
  end else if CurStep = ssPostInstall then begin
    AWInstallFinished := True;
  end else if (CurStep = ssDone) and AWInstallFinished then
    AWCompleteInstallation(ExpandConstant('{app}'));
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := 0;
  if AWPendingRetirementFailed then Result := 1603;
end;

function AWUninstallDirectoryPreflight(const Destination: String): String;
var Found64, Found32: Boolean;
    Version, Location, OtherVersion, OtherLocation: String;
begin
  Result := AWReadRegistration($0100, True, '', Found64, Version, Location);
  if Result <> '' then Exit;
  Result := AWReadRegistration($0200, False, '', Found32, OtherVersion, OtherLocation);
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
var ApprovalPin: String;
begin
  { Recheck after wizard interaction, while the product SetupMutex remains held. }
  if not AWLifecycleOwned then Result := 'The AccessWeaver installation lock is not held. Retry setup.'
  else begin
    Result := AWRegistrationPreflight(ExpandConstant('{app}'));
    if Result = '' then Result := AWPendingSetupPreflight(ExpandConstant('{app}'));
    if Result = '' then Result := AWInstallationPathPreflight(ExpandConstant('{app}'), True);
    if Result = '' then Result := AWPayloadReplacementPreflight(ExpandConstant('{app}'));
    if Result = '' then Result := AWApprovedUpgradePreflight(ExpandConstant('{app}'), ApprovalPin);
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
var PendingVersion, PendingDirectory, PendingPin: String;
begin
  if not AWLifecycleOwned then begin
    Result := 'The AccessWeaver installation lock is not held. Retry uninstalling.'; Exit;
  end;
  Result := AWReadPendingVersion(PendingVersion, PendingDirectory, PendingPin);
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
var ResultCode, Controller: LongWord; Failure, Executable, Destination: String;
    Held: AWDirectoryHandles; I: Integer;
    Verified, Restored, HandlesClosed: Boolean;
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
  Destination := ExpandConstant('{app}');
  Executable := Destination + '\accessweaver.exe';
  Controller := $FFFFFFFF;
  Restored := False; HandlesClosed := True;
  Failure := 'Cannot verify the installed AccessWeaver restoration controller. Repair the installation with its approved installer.';
  try
    Verified := False;
    try
      if AWLockInstallationDirectory(Destination, Held) then
        Verified := AWVerifyInstalledFile(Executable, '{#PayloadDigest}', {#PayloadBytes}, True, Controller);
    except
      Verified := False;
    end;
    if Verified then begin
      Failure := AWUninstallPreflight;
      if Failure = '' then begin
        Log('AccessWeaver system restoration starts at the uninstall step.');
        Restored := AWRunBoundedRestoration(Executable, 'system installer-restore --confirm',
          Destination, AWRestorationDeadlineMilliseconds, ResultCode, Failure);
        if not Restored then
          Log('AccessWeaver system restoration failed; process result/error code: ' + IntToStr(ResultCode))
        else begin
          Failure := AWUninstallPreflight;
          if Failure <> '' then
            Log('AccessWeaver installation registration or pending state changed during restoration.');
        end;
      end;
    end;
  finally
    if Controller <> $FFFFFFFF then
      if AWCloseNativeHandle(Controller) = 0 then HandlesClosed := False;
    for I := GetArrayLength(Held) - 1 downto 0 do
      if AWCloseNativeHandle(Held[I]) = 0 then HandlesClosed := False;
  end;
  if not HandlesClosed then begin
    if Failure <> '' then Log(Failure);
    Failure := 'AccessWeaver restoration file handle cleanup could not be confirmed.';
  end;
  if Restored and HandlesClosed and (Failure = '') then Exit;
  Log(Failure);
  if not UninstallSilent then
    MsgBox('AccessWeaver could not restore its system changes. Review the recovery journal in ProgramData\AccessWeaver\logs, then retry uninstalling.', mbError, MB_OK);
  Abort;
end;

#ifdef EvidenceOutput
  #expr SaveToFile(EvidenceOutput)
#endif
