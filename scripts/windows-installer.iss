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
#ifdef RetiredPayloadInclude
  #if !Defined(ProtectedRegistrationQualification) || !Defined(RetiredPayloadIncludeSHA256)
    #error The retirement plan requires protected registration and a pinned include
  #endif
  #if GetSHA256OfFile(RetiredPayloadInclude) != RetiredPayloadIncludeSHA256
    #error The compiled retirement plan differs from the pinned plan
  #endif
  #define RetiredPayloadRecordHandle FileOpen(BuildRoot + "\docs\windows-retired-payload.sha256")
  #if !RetiredPayloadRecordHandle
    #error The retirement plan has no staged fingerprint record
  #endif
  #if FileRead(RetiredPayloadRecordHandle) != "retirement-plan-sha256=" + RetiredPayloadIncludeSHA256
    #error The staged fingerprint record does not bind the retirement plan
  #endif
  #call FileClose(RetiredPayloadRecordHandle)
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
#define InnoRuntimeNoticePath BuildRoot + "\licenses\Inno-Setup-License.txt"
#if FileExists(InnoRuntimeNoticePath)
  #define InnoRuntimeNoticeBytes FileSize(InnoRuntimeNoticePath)
  #if InnoRuntimeNoticeBytes <= 0 || InnoRuntimeNoticeBytes > 1048576
    #error The staged Inno Setup runtime notice must contain between one byte and 1 MiB
  #endif
  #define InnoRuntimeNoticeDigest GetSHA256OfFile(InnoRuntimeNoticePath)
#elif Defined(RequireInnoRuntimeNotice) || Defined(OrganizationSigning)
  #error The staged Inno Setup runtime notice is required
#endif

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
#ifdef ProtectedRegistrationQualification
DefaultDirName={code:AWProtectedDefaultDirectory}
#else
DefaultDirName={autopf}\AccessWeaver
#endif
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
#ifdef ProtectedRegistrationQualification
CreateUninstallRegKey=no
; A legacy Inno log contains a path-based deletion of the registration.
UninstallLogMode=overwrite
#endif
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UninstallLogging=no
SetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092
[Files]
Source: "{#BuildRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; BeforeInstall: AWCheckPackageCopyDestination
[Icons]
Name: "{group}\AccessWeaver"; Filename: "{app}\accessweaver.exe"; Parameters: "ui"
[Code]
#include "windows-installer-lock.iss"
#include "windows-installer-version.iss"

#include "windows-installer-registry.iss"
#include "windows-installer-restore.iss"

const
  AWPendingInstall = 'PendingInstall';
  AWLegacyRetirementMarker = 'legacy-retirement';

var AWInstallFinished, AWPendingRetirementFailed, AWPendingLegacyRetirement: Boolean;
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

function AWReadPendingVersion(var Version, Directory, ApprovalPin: String; var LegacyRetirement: Boolean): String;
var Key, Status, Kind, Bytes: LongWord;
    Buffer, RecordValue: String; Units, Separator: Integer;
begin
  Result := ''; Version := ''; Directory := ''; ApprovalPin := ''; LegacyRetirement := False;
  Status := AWOpenLifecycleRegistry($0001, False, Key);
  if (Status = 2) or (Status = 3) then Exit;
  Result := 'Cannot verify the AccessWeaver pending installation record.';
  if Status <> 0 then Exit;
  try
    { Version, directory, optional approval pin and legacy retirement phase. }
    SetLength(Buffer, 601); Bytes := 1202; Kind := 0;
    Status := AWGetRegistrationValue(Key, '', AWPendingInstall, $30000002, Kind, Buffer, Bytes);
    if Status = 2 then begin Result := ''; Exit; end;
    if (Status <> 0) or (Kind <> 1) or (Bytes < 4) or (Bytes > 1202) or ((Bytes mod 2) <> 0) then Exit;
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
      SetLength(Directory, Separator - 1);
      Separator := Pos('|', ApprovalPin);
      if Separator <> 0 then begin
        if AWOrdinal(Copy(ApprovalPin, Separator + 1, Length(ApprovalPin)), AWLegacyRetirementMarker) <> 0 then Exit;
        LegacyRetirement := True;
        SetLength(ApprovalPin, Separator - 1);
      end;
      if not AWSha256Pin(ApprovalPin) then Exit;
    end;
    if (Directory <> '') and (Length(Directory) <= 260) then Result := '';
  finally
    if AWCloseRegistrationKey(Key) <> 0 then
      Result := 'Cannot verify the AccessWeaver pending installation record.';
  end;
end;

#ifdef ProtectedRegistrationQualification
function AWProtectedDefaultDirectory(Param: String): String;
var Version, Directory, ApprovalPin: String; LegacyRetirement: Boolean;
begin
  Result := ExpandConstant('{autopf}\AccessWeaver');
  if (AWReadPendingVersion(Version, Directory, ApprovalPin, LegacyRetirement) = '') and
     LegacyRetirement then Result := Directory;
end;
#endif

function AWSetLifecycleStringNative(Key: LongWord; const Name: String;
  Reserved, Kind: LongWord; const Data: String; Bytes: LongWord): LongWord;
  external 'RegSetValueExW@advapi32.dll stdcall';

function AWDeleteLifecycleValueNative(Key: LongWord; const Name: String): LongWord;
  external 'RegDeleteValueW@advapi32.dll stdcall';

function AWWriteLifecycleString(const Name, Value: String; Flush: Boolean): Boolean;
var Key: LongWord;
begin
  Result := False;
  if not AWLifecycleOwned or (Length(Value) > 10000) or (Pos(#0, Value) <> 0) then Exit;
  if AWOpenLifecycleRegistry($0002, True, Key) <> 0 then Exit;
  try
    Result := AWSetLifecycleStringNative(Key, Name, 0, 1, Value, (Length(Value) + 1) * 2) = 0;
    if Result and Flush then Result := AWFlushRegistryKey(Key) = 0;
  finally
    if AWCloseRegistrationKey(Key) <> 0 then Result := False;
  end;
end;

function AWReadLifecycleString(const Name: String; Maximum: LongWord; var Value: String): Boolean;
var Key: LongWord;
begin
  Result := False; Value := '';
  if AWOpenLifecycleRegistry($0001, False, Key) <> 0 then Exit;
  try
    Result := AWReadRegistrationString(Key, Name, $30000002, Maximum, Value);
  finally
    if AWCloseRegistrationKey(Key) <> 0 then Result := False;
  end;
end;

function AWDeleteLifecycleValue(const Name: String; Flush: Boolean; var Flushed: Boolean): Boolean;
var Key, Kind, Bytes: LongWord;
begin
  Result := False; Flushed := False;
  if not AWLifecycleOwned or (AWOpenLifecycleRegistry($0002, False, Key) <> 0) then Exit;
  try
    Result := AWDeleteLifecycleValueNative(Key, Name) = 0;
    Kind := 0; Bytes := 0;
    if Result then Result := AWRegistrationQueryValue(Key, Name, 0, Kind, 0, Bytes) = 2;
    if Result and Flush then Flushed := AWFlushRegistryKey(Key) = 0;
  finally
    if AWCloseRegistrationKey(Key) <> 0 then begin
      Flushed := False;
      { A confirmed pending deletion with uncertain cleanup follows the same
        guarded restoration path as a failed retirement flush. }
      if not Flush then Result := False;
    end;
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
var Version, Directory, ApprovalPin: String; LegacyRetirement: Boolean;
begin
  Result := False;
  if AWReadPendingVersion(Version, Directory, ApprovalPin, LegacyRetirement) <> '' then Exit;
  Result := (AWOrdinal(Version, '{#ReleaseVersion}') = 0) and
    (AWOrdinal(Directory, Destination) = 0) and (ApprovalPin = AWPendingApprovalPin) and
    (LegacyRetirement = AWPendingLegacyRetirement);
end;

#ifdef ProtectedRegistrationQualification
#include "windows-installer-registry-owned.iss"
#include "windows-installer-registry-transaction.iss"
#include "windows-installer-registry-legacy.iss"
#endif

function AWPendingInstallValue(const Destination: String): String;
begin
  Result := '{#ReleaseVersion}|' + Destination;
  if AWPendingApprovalPin <> '' then Result := Result + '|' + AWPendingApprovalPin;
  if AWPendingLegacyRetirement then Result := Result + '|' + AWLegacyRetirementMarker;
end;

function AWPendingInstallAbsent: Boolean;
var Version, Directory, ApprovalPin: String; LegacyRetirement: Boolean;
begin
  Result := (AWReadPendingVersion(Version, Directory, ApprovalPin, LegacyRetirement) = '') and (Version = '');
end;

function AWRetirePendingInstall(const Destination: String): Boolean;
var Flushed: Boolean;
begin
  Result := False;
  if not AWLifecycleOwned or not AWPendingInstallMatches(Destination) then begin
    Log('AccessWeaver pending installation record changed or could not be verified. Setup did not clear it.');
    Exit;
  end;
  if not AWDeleteLifecycleValue(AWPendingInstall, True, Flushed) then begin
    Log('Cannot delete the AccessWeaver pending installation record.');
    Exit;
  end;
  if Flushed then begin
    Result := AWPendingInstallAbsent;
    if not Result then Log('AccessWeaver could not verify absence of the pending installation record after retirement.');
    Exit;
  end;

  { The lifecycle lock keeps other AccessWeaver installers and the detector
    out until retirement succeeds or the original recovery record is restored. }
  Log('Cannot flush retirement of the AccessWeaver pending installation record.');
  if not AWPendingInstallAbsent then begin
    Log('AccessWeaver pending installation record changed or could not be verified. Setup did not replace it.');
    Exit;
  end;
  if not AWWriteLifecycleString(AWPendingInstall, AWPendingInstallValue(Destination), True) then begin
    Log('Cannot restore the AccessWeaver pending installation record after the failed flush.');
    Exit;
  end;
  if not AWPendingInstallMatches(Destination) then begin
    Log('Cannot verify the restored AccessWeaver pending installation record.');
    Exit;
  end;
  Log('AccessWeaver pending installation record restored after retirement flush failed.');
end;

function AWPendingSetupPreflight(const Destination: String): String;
var Version, Directory, ApprovalPin: String; Ordering: Integer; LegacyRetirement: Boolean;
begin
  Result := AWReadPendingVersion(Version, Directory, ApprovalPin, LegacyRetirement);
#ifndef ProtectedRegistrationQualification
  if (Result = '') and LegacyRetirement then
    Result := 'Finish the incomplete AccessWeaver migration with its original approved installer.';
#endif
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
  AWNativeHandles = array of LongWord;

function AWGetFileInfo(Handle: LongWord; var Info: AWFileInfo): Integer;
  external 'GetFileInformationByHandle@kernel32.dll stdcall';

function AWLockInstallationDirectory(const Directory: String; var Held: AWNativeHandles): Boolean;
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

function AWVerifyInstalledFileDigests(const Path, Digest, AlternateDigest: String; Size: Int64;
  SingleLink: Boolean; var Held: LongWord): Boolean;
var Info: AWFileInfo; Payload: THandleStream; Actual: String;
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
    Actual := GetSHA256OfStream(Payload);
    Result := (CompareText(Actual, Digest) = 0) or
      ((AlternateDigest <> '') and (CompareText(Actual, AlternateDigest) = 0));
  finally
    { THandleStream borrows the native handle. The caller closes it. }
    Payload.Free;
  end;
end;

function AWVerifyInstalledFile(const Path, Digest: String; Size: Int64;
  SingleLink: Boolean; var Held: LongWord): Boolean;
begin
  Result := AWVerifyInstalledFileDigests(Path, Digest, '', Size, SingleLink, Held);
end;

function AWVerifyUpgradeResumeFile(const Path, BeforeDigest, AfterDigest: String;
  MaximumSize: Int64; var Held: LongWord): Boolean;
var Attributes, Code: LongWord;
begin
  Attributes := AWPathAttributes(Path);
  if Attributes = $FFFFFFFF then begin
    Code := DLLGetLastError;
    Result := (Code = 2) or (Code = 3);
  end else
    Result := AWVerifyInstalledFileDigests(Path, BeforeDigest, AfterDigest, -MaximumSize, True, Held);
end;

function AWOpenUninstallSubject(const Path: String; var Held: LongWord): Boolean;
var Info: AWFileInfo;
begin
  Result := False;
  Held := AWOpenReplaceProbe(Path, $80000000, 1, 0, 3, $00200000, 0);
  if Held = $FFFFFFFF then Exit;
  if AWGetFileInfo(Held, Info) = 0 then Exit;
  Result := ((Info.Attributes and ($00000400 or $00000010)) = 0) and (Info.Links = 1) and
    (Info.SizeHigh = 0) and (Info.SizeLow > 0) and (Info.SizeLow <= 536870912);
end;

{ Inno Setup can leave its staged temporary uninstaller in the application
  directory after interruption. Keep a baseline tied to this managed attempt. }
const AWManagedTempBaseline = 'PendingTemporaryFileBaseline';

var AWManagedTempCandidates: TStringList;

function AWSetupTempName(const Name: String): Boolean;
var I: Integer; C: Char;
begin
  Result := False;
  if (Length(Name) <> 17) or (CompareText(Copy(Name, 1, 3), 'is-') <> 0) or
     (CompareText(Copy(Name, 14, 4), '.tmp') <> 0) then Exit;
  for I := 4 to 13 do begin
    C := Name[I];
    if not (((C >= '0') and (C <= '9')) or ((C >= 'a') and (C <= 'z')) or
            ((C >= 'A') and (C <= 'Z'))) then Exit;
  end;
  Result := True;
end;

function AWCollectSetupTempNames(const Destination: String; Names: TStringList): Boolean;
var Search: TFindRec; Held: AWNativeHandles; I: Integer;
begin
  Result := False;
  try
    if not AWLockInstallationDirectory(Destination, Held) then Exit;
    { A managed baseline already has files. Failure to enumerate cannot
      establish that previously existing temporary names are absent. }
    if not FindFirst(AddBackslash(Destination) + '*', Search) then Exit;
    try
      repeat
        if AWSetupTempName(Search.Name) then Names.Add(Search.Name);
        if Names.Count > 512 then Exit;
      until not FindNext(Search);
      Result := True;
    finally
      FindClose(Search);
    end;
  finally
    for I := GetArrayLength(Held) - 1 downto 0 do AWCloseNativeHandle(Held[I]);
  end;
end;

function AWPrepareManagedTempRecovery(const Destination: String): Boolean;
var Baseline, Current: TStringList; Value, Binding: String; I: Integer;
begin
  Result := True;
  if AWPendingApprovalPin = '' then Exit;
  Binding := GetSHA256OfString(AWPendingInstallValue(Destination)) + '|';
  Current := TStringList.Create;
  try
    if AWPendingInstallAbsent then begin
      Value := '';
      if AWCollectSetupTempNames(Destination, Current) then Value := Binding + Current.Text;
      if Length(Value) > 10000 then Value := '';
      Result := AWWriteLifecycleString(AWManagedTempBaseline, Value, False);
      Exit;
    end;
    if not AWPendingInstallMatches(Destination) then begin Result := False; Exit; end;
    if not AWReadLifecycleString(AWManagedTempBaseline, 10000, Value) then Exit;
    if (Length(Value) > 10000) or (Copy(Value, 1, Length(Binding)) <> Binding) then Exit;
    Baseline := TStringList.Create;
    try
      Baseline.Text := Copy(Value, Length(Binding) + 1, Length(Value));
      for I := 0 to Baseline.Count - 1 do
        if not AWSetupTempName(Baseline[I]) then Exit;
      if not AWCollectSetupTempNames(Destination, Current) then Exit;
      AWManagedTempCandidates := TStringList.Create;
      for I := 0 to Current.Count - 1 do
        if Baseline.IndexOf(Current[I]) < 0 then AWManagedTempCandidates.Add(Current[I]);
    finally
      Baseline.Free;
    end;
  finally
    Current.Free;
  end;
end;

type AWFileStreamInfo = record
  NextEntryOffset, NameBytes: LongWord;
  StreamSize, AllocationSize: Int64;
  Name: array[0..31] of Word;
end;

function AWQueryFileStreams(Handle, InfoClass: LongWord; var Info: AWFileStreamInfo;
  Bytes: LongWord): Integer;
  external 'GetFileInformationByHandleEx@kernel32.dll stdcall';

function AWOnlyDefaultDataStream(Handle: LongWord; var Inspected: Boolean): Boolean;
var Info: AWFileStreamInfo; I: Integer; DefaultName: String; Code: LongWord;
begin
  Result := False;
  if AWQueryFileStreams(Handle, 7, Info, SizeOf(Info)) = 0 then begin
    Code := DLLGetLastError;
    { This fixed buffer has space for the default data stream. A larger
      enumeration cannot prove the file contains only that stream. }
    Inspected := (Code = 122) or (Code = 234);
    Exit;
  end;
  Inspected := True;
  DefaultName := '::$DATA';
  if (Info.NextEntryOffset <> 0) or (Info.NameBytes <> 2 * Length(DefaultName)) then Exit;
  for I := 1 to Length(DefaultName) do
    if Info.Name[I - 1] <> Ord(DefaultName[I]) then Exit;
  Result := True;
end;

function AWSetFileDisposition(Handle, InfoClass: LongWord; var DeleteFile: Byte;
  Bytes: LongWord): Integer;
  external 'SetFileInformationByHandle@kernel32.dll stdcall';

function AWRemoveMatchingInstallationFile(const Path, Identity: String; ExpectedSize: Int64;
  RequireInspection: Boolean): Boolean;
var Handle, Code: LongWord; Info: AWFileInfo; Subject: THandleStream; DeleteFile: Byte;
    CanDelete, Deleted, StreamsInspected: Boolean;
begin
  Result := True;
  Deleted := False;
  { GENERIC_READ | DELETE, FILE_SHARE_READ, OPEN_EXISTING, OPEN_REPARSE_POINT. }
  Handle := AWOpenReplaceProbe(Path, $80010000, 1, 0, 3, $00200000, 0);
  CanDelete := Handle <> $FFFFFFFF;
  if not CanDelete then begin
    { A reader can deny DELETE while still allowing us to identify the file.
      Preserve unrelated files without delaying managed recovery. }
    Handle := AWOpenReplaceProbe(Path, $80000000, 1, 0, 3, $00200000, 0);
    if Handle = $FFFFFFFF then begin
      Code := DLLGetLastError;
      Result := not RequireInspection or (Code = 2) or (Code = 3);
      Exit;
    end;
  end;
  try
    if AWGetFileInfo(Handle, Info) = 0 then begin
      Result := not RequireInspection;
      Exit;
    end;
    if ((Info.Attributes and ($00000400 or $00000010)) <> 0) or (Info.Links <> 1) then Exit;
    Subject := THandleStream.Create(Handle);
    try
      if Subject.Size <> ExpectedSize then Exit;
      if GetSHA256OfStream(Subject) <> Identity then Exit;
    finally
      Subject.Free;
    end;
    if not AWOnlyDefaultDataStream(Handle, StreamsInspected) then begin
      Result := StreamsInspected or not RequireInspection;
      Exit;
    end;
    if not CanDelete then begin Result := False; Exit; end;
    DeleteFile := 1;
    Deleted := AWSetFileDisposition(Handle, 4, DeleteFile, 1) <> 0;
    Result := Deleted;
  finally
    if AWCloseNativeHandle(Handle) = 0 then Result := False;
  end;
  if Deleted and Result then begin
    Result := False;
    if AWPathAttributes(Path) = $FFFFFFFF then begin
      Code := DLLGetLastError;
      Result := (Code = 2) or (Code = 3);
    end;
  end;
end;

function AWCleanupManagedTemporaryUninstallers(const Destination: String; Uninstaller: LongWord): Boolean;
var Subject: THandleStream; Identity: String; UninstallerSize: Int64; I: Integer;
begin
  Result := True;
  if AWManagedTempCandidates = nil then Exit;
  if AWManagedTempCandidates.Count = 0 then Exit;
  Result := False;
  if not AWPendingInstallMatches(Destination) then Exit;
  { The verified registered uninstaller and all installation directories are
    held by the caller. Use its exact bytes to identify staged copies. }
  try
    Subject := THandleStream.Create(Uninstaller);
    try
      UninstallerSize := Subject.Size;
      Identity := GetSHA256OfStream(Subject);
    finally
      Subject.Free;
    end;
    for I := 0 to AWManagedTempCandidates.Count - 1 do
      if not AWRemoveMatchingInstallationFile(AddBackslash(Destination) + AWManagedTempCandidates[I],
        Identity, UninstallerSize, False) then Exit;
    Result := True;
  except
    Result := False;
  end;
end;

function AWCheckPackageDirectory(const Path: String; Hold: Boolean; var Held: AWNativeHandles): String;
var Attributes, Code: LongWord;
begin
  Result := AWInstallationPathPreflight(Path, True);
  if (Result <> '') or not Hold then Exit;
  Attributes := AWPathAttributes(Path);
  if Attributes = $FFFFFFFF then begin
    Code := DLLGetLastError;
    if (Code = 2) or (Code = 3) then Exit;
  end else if AWLockInstallationDirectory(Path, Held) then Exit;
  Result := 'The AccessWeaver package directory could not be verified.';
end;

function AWCheckPackageDirectories(const Destination: String; Hold: Boolean; var Held: AWNativeHandles): String;
begin
  Result := AWCheckPackageDirectory(Destination + '\licenses', Hold, Held);
  if Result = '' then Result := AWCheckPackageDirectory(Destination + '\docs', Hold, Held);
  if Result = '' then Result := AWCheckPackageDirectory(Destination + '\docs\assets', Hold, Held);
  if Result = '' then Result := AWCheckPackageDirectory(Destination + '\docs\qualification', Hold, Held);
end;

function AWPackageDirectoryPreflight(const Destination: String): String;
var Unused: AWNativeHandles;
begin
  Result := AWCheckPackageDirectories(Destination, False, Unused);
end;

function AWVerifyAndHoldPackageFile(const Path, Digest: String; Size: Int64; var Held: AWNativeHandles): Boolean;
var Handle: LongWord; Count: Integer;
begin
  Handle := $FFFFFFFF;
  try
    Result := AWVerifyInstalledFile(Path, Digest, Size, True, Handle);
    if Result then begin
      Count := GetArrayLength(Held);
      SetArrayLength(Held, Count + 1);
      Held[Count] := Handle;
      Handle := $FFFFFFFF;
    end;
  finally
    if Handle <> $FFFFFFFF then AWCloseNativeHandle(Handle);
  end;
end;

{ Generate replacement and completion checks for the staged files in every package
  directory. The build admits only the directories checked by Setup. }
#dim AWStagedDirectories[5] { "", "licenses", "docs", "docs\assets", "docs\qualification" }
#define AWStagedDirectoryIndex
#define AWStagedPrefix
#define AWStagedFind
#define AWStagedResult
#define AWStagedVerify False
#define AWStagedFingerprint False
#define AWStagedRemoval False
#sub AWEmitStagedFileCheck
  #define AWStagedRelative AWStagedPrefix + FindGetFileName(AWStagedFind)
  #define AWStagedName LowerCase(AWStagedRelative)
  #define AWStagedLiteral StringChange(AWStagedRelative, "'", "''")
  #define AWStagedPath AddBackslash(BuildRoot) + AWStagedRelative
  #if AWStagedFingerprint
    Entries.Add('{#AWStagedLiteral}|{#FileSize(AWStagedPath)}|{#GetSHA256OfFile(AWStagedPath)}');
  #elif AWStagedRemoval
    if not AWInstalledPathAbsent(Destination + '\{#AWStagedLiteral}') then Exit;
  #elif AWStagedName != "accessweaver.exe" && AWStagedName != "build-info.json" && AWStagedName != "sbom.cdx.json" && AWStagedName != "licenses\inno-setup-license.txt"
    #if AWStagedVerify
      if not AWVerifyAndHoldPackageFile(Destination + '\{#AWStagedLiteral}', '{#GetSHA256OfFile(AWStagedPath)}', {#FileSize(AWStagedPath)}, Held) then Exit;
    #else
      if not AWCanReplaceInstalledFile(Destination + '\{#AWStagedLiteral}') then begin
        Result := AWPackageFileReplacementFailure('{#AWStagedLiteral}');
        Exit;
      end;
    #endif
  #endif
#endsub
#sub AWEmitStagedDirectoryChecks
  #expr AWStagedPrefix = AWStagedDirectories[AWStagedDirectoryIndex] == "" ? "" : AddBackslash(AWStagedDirectories[AWStagedDirectoryIndex])
  #for {AWStagedFind = AWStagedResult = FindFirst(AddBackslash(BuildRoot) + AWStagedPrefix + "*", faReadOnly | faHidden | faSysFile | faArchive); AWStagedResult; AWStagedResult = FindNext(AWStagedFind)} AWEmitStagedFileCheck
  #if AWStagedFind
    #call FindClose(AWStagedFind)
  #endif
#endsub

#ifdef ProtectedRegistrationQualification
#include "windows-installer-registry-publication.iss"
#endif

#ifdef RetiredPayloadInclude
function AWRetirePackageFile(const Path, Digest: String; Size: Int64): Boolean;
var Parent: String; Held: AWNativeHandles; Attributes, Code: LongWord; I: Integer;
begin
  Result := False;
  Parent := ExtractFileDir(Path);
  Attributes := AWPathAttributes(Parent);
  if Attributes = $FFFFFFFF then begin
    Code := DLLGetLastError;
    Result := (Code = 2) or (Code = 3);
    Exit;
  end;
  try
    if not AWLockInstallationDirectory(Parent, Held) then Exit;
    Attributes := AWPathAttributes(Path);
    if (Attributes <> $FFFFFFFF) and ((Attributes and ($00000400 or $00000010)) <> 0) then begin
      Result := True;
      Exit;
    end;
    Result := AWRemoveMatchingInstallationFile(Path, Digest, Size, True);
  finally
    for I := GetArrayLength(Held) - 1 downto 0 do
      if AWCloseNativeHandle(Held[I]) = 0 then Result := False;
  end;
end;

#include RetiredPayloadInclude

function AWCleanupRetiredPackageFiles(const Destination: String): Boolean;
begin
  Result := True;
  if not AWPendingLegacyRetirement then Exit;
  Result := False;
  if not AWPendingInstallMatches(Destination) or not AWRetiredPayloadMatchesApproval then Exit;
  try
    Result := AWRetireApprovedPackageFiles(Destination);
  except
    Result := False;
  end;
end;
#endif

function AWVerifyCompletedInstall(const Destination: String; var Held: AWNativeHandles;
  var Executable, BuildInfo, SBOM, RuntimeNotice, Uninstaller, UninstallData: LongWord): Boolean;
var Found64, Found32: Boolean;
    Version, Location, Version32, Location32, UninstallerPath: String;
begin
  Result := False;
  if not AWLockInstallationDirectory(Destination, Held) then Exit;
  if AWCheckPackageDirectories(Destination, True, Held) <> '' then Exit;
  if not AWVerifyInstalledFile(Destination + '\accessweaver.exe', '{#PayloadDigest}', {#PayloadBytes}, True, Executable) then Exit;
  if not AWVerifyInstalledFile(Destination + '\BUILD-INFO.json', '{#BuildInfoDigest}', {#BuildInfoBytes}, True, BuildInfo) then Exit;
  if not AWVerifyInstalledFile(Destination + '\SBOM.cdx.json', '{#PayloadSBOMDigest}', {#PayloadSBOMBytes}, True, SBOM) then Exit;
#ifdef InnoRuntimeNoticeDigest
  if not AWVerifyInstalledFile(Destination + '\licenses\Inno-Setup-License.txt', '{#InnoRuntimeNoticeDigest}', {#InnoRuntimeNoticeBytes}, True, RuntimeNotice) then Exit;
#endif
  #expr AWStagedVerify = True
  #for {AWStagedDirectoryIndex = 0; AWStagedDirectoryIndex < DimOf(AWStagedDirectories); AWStagedDirectoryIndex++} AWEmitStagedDirectoryChecks
  #expr AWStagedVerify = False
  UninstallerPath := ExpandConstant('{uninstallexe}');
  if not AWIsInstallationDirectory(Destination, ExtractFileDir(UninstallerPath)) then Exit;
  if not AWOpenUninstallSubject(UninstallerPath, Uninstaller) then Exit;
  if not AWOpenUninstallSubject(ChangeFileExt(UninstallerPath, '.dat'), UninstallData) then Exit;
#ifdef ProtectedRegistrationQualification
  if not AWPublishOwnedProductRegistration(Destination, UninstallerPath) then Exit;
#endif
  if AWReadRegistration($0100, True, UninstallerPath, Found64, Version, Location) <> '' then Exit;
  if AWReadRegistration($0200, False, '', Found32, Version32, Location32) <> '' then Exit;
  Result := Found64 and not Found32 and (Version = '{#ReleaseVersion}') and
    AWIsInstallationDirectory(Destination, Location);
end;

function AWCanReplaceInstalledFile(const Path: String): Boolean;
var Attributes, Handle, Code: LongWord; Info: AWFileInfo;
begin
  Result := False;
  Attributes := AWPathAttributes(Path);
  if Attributes = $FFFFFFFF then begin
    Code := DLLGetLastError;
    Result := (Code = 2) or (Code = 3);
    Exit;
  end;
  { Setup can prompt instead of replacing a read-only file. Refuse it before
    recording a pending installation, even when DELETE access is granted. }
  if (Attributes and ($00000400 or $00000010 or $00000001)) <> 0 then Exit;
  { Probe DELETE and FILE_READ_ATTRIBUTES without writing, truncating or deleting. }
  Handle := AWOpenReplaceProbe(Path, $00010080, $00000007, 0, 3, $00200000, 0);
  if Handle = $FFFFFFFF then Exit;
  try
    Result := (AWGetFileInfo(Handle, Info) <> 0) and
      ((Info.Attributes and ($00000400 or $00000010 or $00000001)) = 0) and (Info.Links = 1);
  finally
    if AWCloseNativeHandle(Handle) = 0 then Result := False;
  end;
end;

function AWPackageFileReplacementFailure(const Relative: String): String;
begin
  Result := 'The shipped AccessWeaver file cannot be replaced: ' + Relative +
    '. Release any file locks and check its file attributes before retrying setup.';
end;

function AWPayloadReplacementPreflight(const Destination: String): String;
begin
  Result := AWPackageDirectoryPreflight(Destination);
  if Result <> '' then Exit;
  if not AWCanReplaceInstalledFile(Destination + '\accessweaver.exe') then
    Result := 'The AccessWeaver executable cannot be replaced. Close it, release any file locks and check its file attributes before retrying setup.'
  else if not AWCanReplaceInstalledFile(Destination + '\BUILD-INFO.json') then
    Result := 'The AccessWeaver BUILD-INFO.json cannot be replaced. Release any file locks and check its file attributes before retrying setup.'
  else if not AWCanReplaceInstalledFile(Destination + '\SBOM.cdx.json') then
    Result := 'The AccessWeaver SBOM.cdx.json cannot be replaced. Release any file locks and check its file attributes before retrying setup.';
#ifdef InnoRuntimeNoticeDigest
  if (Result = '') and not AWCanReplaceInstalledFile(Destination + '\licenses\Inno-Setup-License.txt') then
    Result := 'The Inno Setup runtime notice cannot be replaced. Release any file locks and check its file attributes before retrying setup.';
#endif
  if Result <> '' then Exit;
  #for {AWStagedDirectoryIndex = 0; AWStagedDirectoryIndex < DimOf(AWStagedDirectories); AWStagedDirectoryIndex++} AWEmitStagedDirectoryChecks
end;

procedure AWCheckPackageCopyDestination;
var Destination, Failure: String;
begin
  Destination := CurrentFilename;
  if Copy(Destination, 1, 1) = '{' then Destination := ExpandConstant(Destination);
  if Copy(Destination, 1, 4) = '\\?\' then Delete(Destination, 1, 4);
  Failure := AWInstallationPathPreflight(ExtractFileDir(Destination), True);
  if Failure = '' then
    if not AWCanReplaceInstalledFile(Destination) then
      Failure := 'An AccessWeaver package file destination cannot be safely replaced. Setup recovery is required.';
  if Failure <> '' then begin
    Log(Failure);
    if not WizardSilent then SuppressibleMsgBox(Failure, mbCriticalError, MB_OK, IDOK);
    Abort;
  end;
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

function AWStagedPayloadDigest: String;
var Entries: TStringList; I, J: Integer; Entry: String;
begin
  Entries := TStringList.Create;
  try
    #expr AWStagedFingerprint = True
    #for {AWStagedDirectoryIndex = 0; AWStagedDirectoryIndex < DimOf(AWStagedDirectories); AWStagedDirectoryIndex++} AWEmitStagedDirectoryChecks
    #expr AWStagedFingerprint = False
    { Use the same order across build enumeration and Windows user locales. }
    for I := 1 to Entries.Count - 1 do begin
      Entry := Entries[I];
      J := I;
      while J > 0 do begin
        if AWOrdinal(Entries[J - 1], Entry) <= 0 then Break;
        Entries[J] := Entries[J - 1];
        J := J - 1;
      end;
      Entries[J] := Entry;
    end;
    Result := GetSHA256OfString(Utf8Encode(Entries.Text));
  finally
    Entries.Free;
  end;
end;

function AWApprovedUpgradePreflight(const Destination: String; var ApprovalPin: String): String;
var I, Ordering: Integer; Argument, Approval, Version, PayloadPin, SBOMPin, BuildPin,
    Installed, Location, OtherVersion, OtherLocation, PendingVersion, PendingDirectory, PendingPin: String;
    Present, Found64, Found32, PendingLegacyRetirement: Boolean;
    Held: AWNativeHandles; Executable, BuildInfo, SBOM: LongWord;
begin
  ApprovalPin := '';
#ifdef ProtectedRegistrationQualification
  AWLegacyApproval.Version := '';
#endif
  AWPendingLegacyRetirement := False;
  Result := AWReadPendingVersion(PendingVersion, PendingDirectory, PendingPin, PendingLegacyRetirement);
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
#ifdef ProtectedRegistrationQualification
  if Length(Approval) > 581 then Exit;
#else
  if Length(Approval) > 451 then Exit;
#endif
  { Commas delimit the approved version and file digests. AWCompare validates SemVer. }
  I := Pos(',', Approval);
  if I = 0 then Exit;
  Version := Copy(Approval, 1, I - 1);
  Delete(Approval, 1, I);
  if not AWCompare('{#ReleaseVersion}', Version, Ordering) or (Ordering <= 0) then Exit;
#ifdef ProtectedRegistrationQualification
  if (Length(Approval) <> 194) and (Length(Approval) <> 324) then Exit;
#else
  if Length(Approval) <> 194 then Exit;
#endif
  if (Approval[65] <> ',') or (Approval[130] <> ',') then Exit;
  PayloadPin := Copy(Approval, 1, 64);
  SBOMPin := Copy(Approval, 66, 64);
  BuildPin := Copy(Approval, 131, 64);
  if not AWSha256Pin(PayloadPin) or not AWSha256Pin(SBOMPin) or not AWSha256Pin(BuildPin) then Exit;
#ifdef ProtectedRegistrationQualification
  if Length(Approval) = 324 then begin
    if (Approval[195] <> ',') or (Approval[260] <> ',') then Exit;
    AWLegacyApproval.Uninstaller := Copy(Approval, 196, 64);
    AWLegacyApproval.UninstallData := Copy(Approval, 261, 64);
    if not AWSha256Pin(AWLegacyApproval.Uninstaller) or not AWSha256Pin(AWLegacyApproval.UninstallData) then Exit;
    AWLegacyApproval.Version := Version;
    AWLegacyApproval.Payload := PayloadPin;
    AWLegacyApproval.SBOM := SBOMPin;
    AWLegacyApproval.BuildInfo := BuildPin;
#ifdef RetiredPayloadInclude
    if not AWRetiredPayloadMatchesApproval then begin
      Result := 'The managed upgrade approval does not match this installer''s prior package retirement plan.';
      Exit;
    end;
#endif
  end;
#endif

  { The pin binds the baseline argument and all staged payload files.
    The separate record fields bind its exact new version and destination. }
  Argument := Version + ',' + Approval + '|{#TargetArch}|' + AWStagedPayloadDigest;
  ApprovalPin := Lowercase(GetSHA256OfString(Argument));
  if PendingPin <> '' then begin
    Result := 'Finish the incomplete AccessWeaver managed upgrade with its original approved installer and baseline argument.';
    if (PendingPin = ApprovalPin) and (AWOrdinal(PendingVersion, '{#ReleaseVersion}') = 0) and
        AWIsInstallationDirectory(Destination, PendingDirectory) then begin
      Result := 'The interrupted AccessWeaver upgrade contains files or registration outside the approved releases.';
      Executable := $FFFFFFFF; BuildInfo := $FFFFFFFF; SBOM := $FFFFFFFF;
      try
        try
          if not AWLockInstallationDirectory(Destination, Held) then Exit;
          if not AWVerifyUpgradeResumeFile(Destination + '\accessweaver.exe', PayloadPin, '{#PayloadDigest}', 134217728, Executable) then Exit;
          if not AWVerifyUpgradeResumeFile(Destination + '\SBOM.cdx.json', SBOMPin, '{#PayloadSBOMDigest}', 4194304, SBOM) then Exit;
          if not AWVerifyUpgradeResumeFile(Destination + '\BUILD-INFO.json', BuildPin, '{#BuildInfoDigest}', 65536, BuildInfo) then Exit;
          if AWReadRegistration($0100, True, '', Found64, Installed, Location) <> '' then Exit;
          if AWReadRegistration($0200, False, '', Found32, OtherVersion, OtherLocation) <> '' then Exit;
          if Found32 then Exit;
          if Found64 and (not AWIsInstallationDirectory(Destination, Location) or
             ((AWOrdinal(Version, Installed) <> 0) and (AWOrdinal('{#ReleaseVersion}', Installed) <> 0))) then Exit;
          AWPendingLegacyRetirement := PendingLegacyRetirement;
          Result := '';
          Log('AccessWeaver approved upgrade resumed from its pending installation record.');
        except
          { Retain the pending installation record if its files cannot be verified. }
        end;
      finally
        if SBOM <> $FFFFFFFF then AWCloseNativeHandle(SBOM);
        if BuildInfo <> $FFFFFFFF then AWCloseNativeHandle(BuildInfo);
        if Executable <> $FFFFFFFF then AWCloseNativeHandle(Executable);
        for I := GetArrayLength(Held) - 1 downto 0 do AWCloseNativeHandle(Held[I]);
      end;
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
var Held: AWNativeHandles; Executable, BuildInfo, SBOM, RuntimeNotice, Uninstaller, UninstallData: LongWord; I: Integer;
    Verified, BaselineFlushed: Boolean;
begin
  Executable := $FFFFFFFF; BuildInfo := $FFFFFFFF; SBOM := $FFFFFFFF;
  RuntimeNotice := $FFFFFFFF; Uninstaller := $FFFFFFFF; UninstallData := $FFFFFFFF;
  try
    try
      Verified := AWVerifyCompletedInstall(Destination, Held, Executable, BuildInfo, SBOM, RuntimeNotice, Uninstaller, UninstallData);
    except
      Verified := False;
    end;
    AWPendingRetirementFailed := True;
    if not Verified then
      Log('AccessWeaver installed payload or registration verification failed. Pending installation record retained.')
#ifdef RetiredPayloadInclude
    else if not AWCleanupRetiredPackageFiles(Destination) then
      Log('AccessWeaver could not retire a verified prior package file. Pending installation record retained.')
#endif
    else if not AWCleanupManagedTemporaryUninstallers(Destination, Uninstaller) then
      Log('AccessWeaver could not retire a verified temporary uninstaller. Pending installation record retained.')
    else if AWRetirePendingInstall(Destination) then begin
      AWPendingRetirementFailed := False;
      if AWPendingApprovalPin <> '' then AWDeleteLifecycleValue(AWManagedTempBaseline, False, BaselineFlushed);
      Log('AccessWeaver installed payload and registration verified. Pending installation record retired.');
    end;
  finally
    if UninstallData <> $FFFFFFFF then AWCloseNativeHandle(UninstallData);
    if Uninstaller <> $FFFFFFFF then AWCloseNativeHandle(Uninstaller);
    if RuntimeNotice <> $FFFFFFFF then AWCloseNativeHandle(RuntimeNotice);
    if SBOM <> $FFFFFFFF then AWCloseNativeHandle(SBOM);
    if BuildInfo <> $FFFFFFFF then AWCloseNativeHandle(BuildInfo);
    if Executable <> $FFFFFFFF then AWCloseNativeHandle(Executable);
    for I := GetArrayLength(Held) - 1 downto 0 do
      AWCloseNativeHandle(Held[I]);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Failure, Destination: String;
#ifdef ProtectedRegistrationQualification
    LegacyHeld: AWNativeHandles; LegacyClosed: Boolean; I: Integer;
#endif
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
#ifdef ProtectedRegistrationQualification
    LegacyClosed := True;
    try
      if not AWPrepareOwnedProductRegistration(Destination, LegacyHeld) then begin
        Log('AccessWeaver protected registration or legacy approval refused.');
        RaiseException('Cannot verify AccessWeaver registration. Migration requires the approved prior installer files and registration.');
      end;
      if AWLegacyPriorInventory <> '' then AWPendingLegacyRetirement := True;
#endif
      if not AWPrepareManagedTempRecovery(Destination) then
        RaiseException('Cannot persist the AccessWeaver temporary file baseline.');
      if not AWWriteLifecycleString(AWPendingInstall, AWPendingInstallValue(Destination), True) then
        RaiseException('Cannot persist the AccessWeaver pending installation record.');
      if not AWPendingInstallMatches(Destination) then
        RaiseException('Cannot verify the AccessWeaver pending installation record after writing it.');
#ifdef ProtectedRegistrationQualification
      if not AWRetireApprovedLegacyRegistration(Destination) then
        RaiseException('Cannot retire the approved legacy AccessWeaver registration. Retry the matching approved installer.');
    finally
      for I := GetArrayLength(LegacyHeld) - 1 downto 0 do
        if AWCloseNativeHandle(LegacyHeld[I]) = 0 then LegacyClosed := False;
    end;
    if not LegacyClosed then
      RaiseException('Cannot release the approved legacy installation files.');
#endif
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
  Result := AWReadRegistration($0100, True, ExpandConstant('{uninstallexe}'), Found64, Version, Location);
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
  if AWManagedTempCandidates <> nil then AWManagedTempCandidates.Free;
  AWReleaseLifecycle;
end;

procedure DeinitializeUninstall;
begin
  AWReleaseLifecycle;
end;

function AWUninstallPreflight: String;
var PendingVersion, PendingDirectory, PendingPin: String; PendingLegacyRetirement: Boolean;
begin
  if not AWLifecycleOwned then begin
    Result := 'The AccessWeaver installation lock is not held. Retry uninstalling.'; Exit;
  end;
  Result := AWReadPendingVersion(PendingVersion, PendingDirectory, PendingPin, PendingLegacyRetirement);
  if (Result = '') and (PendingVersion <> '') then
    Result := 'An AccessWeaver installation is incomplete. Retry the approved installer before uninstalling.';
  if Result = '' then Result := AWUninstallDirectoryPreflight(ExpandConstant('{app}'));
  if Result = '' then Result := AWInstallationPathPreflight(ExpandConstant('{app}'), False);
  if Result = '' then Result := AWPackageDirectoryPreflight(ExpandConstant('{app}'));
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

#ifdef ProtectedRegistrationQualification
var AWOwnedRemovalStarted: Boolean;

function AWInstalledPathAbsent(const Path: String): Boolean;
var Code: LongWord;
begin
  Result := False;
  if AWPathAttributes(Path) <> $FFFFFFFF then Exit;
  Code := DLLGetLastError;
  Result := (Code = 2) or (Code = 3);
end;

function AWVerifyOwnedRemoval(const Destination, Uninstaller: String): Boolean;
begin
  Result := False;
  if (AWInstallationPathPreflight(Destination, True) <> '') or
     (AWPackageDirectoryPreflight(Destination) <> '') then Exit;
  #expr AWStagedRemoval = True
  #for {AWStagedDirectoryIndex = 0; AWStagedDirectoryIndex < DimOf(AWStagedDirectories); AWStagedDirectoryIndex++} AWEmitStagedDirectoryChecks
  #expr AWStagedRemoval = False
  Result := AWInstalledPathAbsent(Uninstaller) and
    AWInstalledPathAbsent(ChangeFileExt(Uninstaller, '.dat')) and
    AWInstalledPathAbsent(ChangeFileExt(Uninstaller, '.msg')) and
    AWProductRegistrationAbsent($0100) and AWProductRegistrationAbsent($0200);
end;

function AWBeginOwnedRemoval(const Destination, Uninstaller: String): Boolean;
begin
  { Once the entry is retired, a stopped or incomplete removal can be
    recovered by running the approved Setup in the recorded directory. }
  Result := AWLifecycleOwned and AWPendingInstallAbsent and
    AWWriteLifecycleString(AWPendingInstall, AWPendingInstallValue(Destination), True) and
    AWRetirePublishedRegistration(Destination, Uninstaller);
end;
#endif

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var ResultCode, Controller: LongWord; Failure, Executable, Destination: String;
    Held: AWNativeHandles; I: Integer;
    Verified, Restored, HandlesClosed: Boolean;
begin
#ifdef ProtectedRegistrationQualification
  if (CurUninstallStep = usPostUninstall) and AWOwnedRemovalStarted then begin
    Destination := ExpandConstant('{app}');
    if AWVerifyOwnedRemoval(Destination, ExpandConstant('{uninstallexe}')) and
       AWRetirePendingInstall(Destination) then
      Log('AccessWeaver protected removal and registration absence verified.')
    else
      Log('AccessWeaver could not verify protected removal. Use the approved installer to recover.');
  end;
#endif
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
  if Restored and HandlesClosed and (Failure = '') then begin
#ifdef ProtectedRegistrationQualification
    AWOwnedRemovalStarted := AWBeginOwnedRemoval(Destination, ExpandConstant('{uninstallexe}'));
    if not AWOwnedRemovalStarted then begin
      Failure := 'Cannot retire the protected AccessWeaver registration. Use the approved installer to recover.';
    end else Exit;
#else
    Exit;
#endif
  end;
  Log(Failure);
  if not UninstallSilent then
    MsgBox('AccessWeaver could not restore its system changes. Review the recovery journal in ProgramData\AccessWeaver\logs, then retry uninstalling.', mbError, MB_OK);
  Abort;
end;

#ifdef EvidenceOutput
  #expr SaveToFile(EvidenceOutput)
#endif
