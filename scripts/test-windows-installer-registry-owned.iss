#ifndef EvidenceRoot
  #error EvidenceRoot is required
#endif
#ifndef SourceCommit
  #error SourceCommit is required
#endif
#ifndef RunID
  #error RunID is required
#endif
#ifndef RunAttempt
  #error RunAttempt is required
#endif
#ifndef TargetArch
  #error TargetArch is required
#endif
#define FixtureRootName "AccessWeaverRegistryContract-" + RunID + "-" + RunAttempt + "-" + TargetArch
[Setup]
AppId=AccessWeaverRegistryOwnershipContract
AppName=AccessWeaver registry ownership contract
AppVersion=1.0.0
CreateAppDir=no
Uninstallable=no
CreateUninstallRegKey=no
PrivilegesRequired=admin
DefaultDirName={tmp}\AccessWeaverRegistryOwnershipContract
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
CloseApplications=no
RestartApplications=no
OutputDir={#EvidenceRoot}
OutputBaseFilename=registry-owned-contracts-{#TargetArch}
[Code]
#include "windows-installer-registry-owned.iss"
const AWFixtureTag = 'AWReg-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      AWFixtureOtherTag = 'AWReg-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      AWFixtureParentSDDL = 'O:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;BU)';
var AWFixtureOwned: array of LongWord;
    AWFixturePassed, AWFixtureCleanup: Boolean;
    AWFixtureCases: String; AWFixtureCaseCount: Integer;

function AWFixtureDeleteHeld(Key: LongWord): LongWord;
  external 'NtDeleteKey@ntdll.dll stdcall';
function AWFixtureWriteDWORD(Key: LongWord; const Name: String; Reserved, Kind: LongWord;
  var Data: LongWord; Bytes: LongWord): LongWord;
  external 'RegSetValueExW@advapi32.dll stdcall';
function AWFixtureWriteText(Key: LongWord; const Name: String; Reserved, Kind: LongWord;
  const Data: String; Bytes: LongWord): LongWord;
  external 'RegSetValueExW@advapi32.dll stdcall';
function AWFixtureReadDWORD(Key: LongWord; const Name: String; Reserved: LongWord;
  var Kind, Data, Bytes: LongWord): LongWord;
  external 'RegQueryValueExW@advapi32.dll stdcall';
function AWFixtureHandleFlags(Handle: LongWord; var Flags: LongWord): Integer;
  external 'GetHandleInformation@kernel32.dll stdcall';

function AWFixtureBool(Value: Boolean): String;
begin if Value then Result := 'true' else Result := 'false'; end;

procedure AWFixtureCase(const ID: String; Passed: Boolean);
begin
  if AWFixtureCaseCount <> 0 then AWFixtureCases := AWFixtureCases + ',';
  AWFixtureCases := AWFixtureCases + '{"id":"' + ID +
    '","executed":true,"passed":' + AWFixtureBool(Passed) + '}';
  AWFixtureCaseCount := AWFixtureCaseCount + 1;
  AWFixturePassed := AWFixturePassed and Passed;
end;

procedure AWFixtureRemember(Key: LongWord);
var Count: Integer;
begin
  Count := GetArrayLength(AWFixtureOwned);
  SetArrayLength(AWFixtureOwned, Count + 1);
  AWFixtureOwned[Count] := Key;
end;

function AWFixtureRaw(Parent: LongWord; const Name, SDDL: String;
  Options: LongWord; var Key: LongWord): Boolean;
var Descriptor, Bytes, Disposition: LongWord; Attributes: AWOwnedRegistrySecurity;
begin
  Result := False; Key := 0; Descriptor := 0; Bytes := 0; Disposition := 0;
  try
    if AWOwnedRegistryParseSD(SDDL, 1, Descriptor, Bytes) = 0 then Exit;
    Attributes.Length := 12; Attributes.Descriptor := Descriptor; Attributes.Inherit := 0;
    if AWOwnedRegistryCreateNative(Parent, Name, 0, AWFixtureTag,
       Options or AWOwnedRegistryOpenLink, AWOwnedRegistryAccess,
       Attributes, Key, Disposition) <> 0 then Exit;
    if (Disposition <> 1) or (Key = 0) then begin AWOwnedRegistryClose(Key); Exit; end;
    AWFixtureRemember(Key); Result := True;
  finally
    if not AWOwnedRegistryFree(Descriptor) then Result := False;
  end;
end;

function AWFixtureNew(Parent: LongWord; const Name: String; var Key: LongWord): Boolean;
var Created: Boolean;
begin
  Result := AWCreateOwnedRegistryChild(Parent, Name, AWFixtureTag, Key, Created);
  if Created and (Key <> 0) then AWFixtureRemember(Key);
end;

function AWFixtureSentinel(Key: LongWord): Boolean;
var Kind, Data, Bytes: LongWord;
begin
  Kind := 0; Data := 0; Bytes := 4;
  Result := (AWFixtureReadDWORD(Key, 'sentinel', 0, Kind, Data, Bytes) = 0) and
    (Kind = 4) and (Bytes = 4) and (Data = 73);
end;

procedure AWFixtureCasesRun(Root: LongWord);
var Fresh, BadACL, Target, Link, MissingLink, Opened, Flags, Value, Status: LongWord;
    Created, OK: Boolean; NativeTarget: String;
begin
  Fresh := 0; Opened := 0; Target := 0; BadACL := 0; Link := 0; MissingLink := 0;
  OK := AWFixtureNew(Root, 'fresh', Fresh);
  AWFixtureCase('protected-child-created', OK);
  AWFixtureCase('creation-descriptor-exact', (Fresh <> 0) and AWOwnedRegistryDescriptor(Fresh));
  Flags := $FFFFFFFF;
  AWFixtureCase('handle-not-inheritable', (AWFixtureHandleFlags(Fresh, Flags) <> 0) and ((Flags and 1) = 0));
  AWFixtureCase('atomic-class-roundtrip', AWOwnedRegistryHeld(Fresh, AWFixtureTag));
  Value := 73; OK := AWFixtureWriteDWORD(Fresh, 'sentinel', 0, 4, Value, 4) = 0;
  Created := False;
  OK := OK and not AWCreateOwnedRegistryChild(Root, 'fresh', AWFixtureTag, Opened, Created) and
    not Created and (Opened = 0) and AWFixtureSentinel(Fresh);
  AWFixtureCase('existing-not-adopted-or-mutated', OK);
  OK := AWOpenOwnedRegistryChild(Root, 'fresh', AWFixtureTag, Opened);
  OK := AWOwnedRegistryClose(Opened) and OK;
  AWFixtureCase('owned-partial-retry-opens', OK);
  OK := not AWOpenOwnedRegistryChild(Root, 'fresh', AWFixtureOtherTag, Opened) and (Opened = 0);
  AWFixtureCase('wrong-class-refused', OK and AWFixtureSentinel(Fresh));
  OK := AWFixtureRaw(Root, 'bad-acl', AWFixtureParentSDDL, 0, BadACL);
  OK := OK and not AWOpenOwnedRegistryChild(Root, 'bad-acl', AWFixtureTag, Opened) and (Opened = 0);
  AWFixtureCase('foreign-writer-descriptor-refused', OK);
  Created := False;
  OK := not AWCreateOwnedRegistryChild(Root, 'nested\unexpected', AWFixtureTag, Opened, Created);
  AWFixtureCase('nested-name-refused', OK and not Created and (Opened = 0));
  OK := not AWCreateOwnedRegistryChild(Root, 'invalid-tag', 'not-an-owned-tag', Opened, Created);
  AWFixtureCase('invalid-tag-refused', OK and not Created and (Opened = 0));
  OK := AWFixtureNew(Root, 'target', Target);
  Value := 73; OK := OK and (AWFixtureWriteDWORD(Target, 'sentinel', 0, 4, Value, 4) = 0);
  NativeTarget := '\REGISTRY\MACHINE\SOFTWARE\{#FixtureRootName}\target';
  OK := OK and AWFixtureRaw(Root, 'link', AWOwnedRegistrySDDL, 2, Link);
  OK := OK and (AWFixtureWriteText(Link, 'SymbolicLinkValue', 0, 6, NativeTarget, Length(NativeTarget) * 2) = 0);
  OK := OK and not AWOpenOwnedRegistryChild(Root, 'link', AWFixtureTag, Opened) and (Opened = 0);
  AWFixtureCase('link-to-existing-target-refused', OK);
  OK := not AWCreateOwnedRegistryChild(Root, 'link', AWFixtureTag, Opened, Created);
  AWFixtureCase('create-does-not-adopt-link', OK and not Created and (Opened = 0) and AWFixtureSentinel(Target));
  NativeTarget := '\REGISTRY\MACHINE\SOFTWARE\{#FixtureRootName}\missing';
  OK := AWFixtureRaw(Root, 'missing-link', AWOwnedRegistrySDDL, 2, MissingLink);
  OK := OK and (AWFixtureWriteText(MissingLink, 'SymbolicLinkValue', 0, 6, NativeTarget, Length(NativeTarget) * 2) = 0);
  OK := OK and not AWOpenOwnedRegistryChild(Root, 'missing-link', AWFixtureTag, Opened) and (Opened = 0);
  AWFixtureCase('link-to-missing-target-refused', OK);
  OK := not AWCreateOwnedRegistryChild(Root, 'missing-link', AWFixtureTag, Opened, Created);
  Status := AWOwnedRegistryOpenNative(Root, 'missing', AWOwnedRegistryOpenLink, $00020119, Opened);
  if Status = 0 then AWOwnedRegistryClose(Opened);
  AWFixtureCase('missing-link-target-not-created', OK and not Created and (Status = 2));
  AWFixtureCase('existing-link-target-preserved', AWFixtureSentinel(Target));
end;

function InitializeSetup: Boolean;
var Software, Root, Probe: LongWord; I: Integer; RecordText: String; RootCreated: Boolean;
begin
  Result := False;
  { Independent binary gate: running this executable on the user's computer
    without the exact hosted opt-in has no registry effects. }
  if (GetEnv('GITHUB_ACTIONS') <> 'true') or
     (GetEnv('RUNNER_ENVIRONMENT') <> 'github-hosted') or
     (GetEnv('GITHUB_REPOSITORY') <> 'Yunushan/accessweaver') or
     (GetEnv('ACCESSWEAVER_DISPOSABLE_WINDOWS_INSTALLER_REGISTRY_TEST') <> '1') or
     (GetEnv('GITHUB_SHA') <> '{#SourceCommit}') or
     (GetEnv('GITHUB_RUN_ID') <> '{#RunID}') or
     (GetEnv('GITHUB_RUN_ATTEMPT') <> '{#RunAttempt}') or not IsWin64 then Exit;
  AWFixturePassed := True; AWFixtureCleanup := True; AWFixtureCases := ''; AWFixtureCaseCount := 0;
  Software := 0; Root := 0; Probe := 0; RootCreated := False;
  try
    if AWOwnedRegistryOpenNative($80000002, 'SOFTWARE', 0, $00020104, Software) = 0 then
      RootCreated := AWFixtureRaw(Software, '{#FixtureRootName}', AWFixtureParentSDDL, 0, Root);
    AWFixtureCase('new-owned-fixture-parent', RootCreated);
    if RootCreated then AWFixtureCasesRun(Root);
  finally
    { Every deletion uses an exact handle returned by a confirmed NEW creation.
      No recursive traversal, path-based link deletion, or adoption for cleanup. }
    for I := GetArrayLength(AWFixtureOwned) - 1 downto 0 do begin
      if AWFixtureDeleteHeld(AWFixtureOwned[I]) <> 0 then AWFixtureCleanup := False;
      if not AWOwnedRegistryClose(AWFixtureOwned[I]) then AWFixtureCleanup := False;
    end;
    if RootCreated then begin
      if AWOwnedRegistryOpenNative(Software, '{#FixtureRootName}', AWOwnedRegistryOpenLink,
           $00020119, Probe) <> 2 then AWFixtureCleanup := False;
      if not AWOwnedRegistryClose(Probe) then AWFixtureCleanup := False;
    end;
    if not AWOwnedRegistryClose(Software) then AWFixtureCleanup := False;
    if AWOwnedRegistryCleanupUncertain then AWFixtureCleanup := False;
    AWFixtureCase('exact-owned-cleanup', AWFixtureCleanup and RootCreated);
  end;
  RecordText := '{"schemaVersion":1,"sourceCommit":"{#SourceCommit}","runID":"{#RunID}",' +
    '"runAttempt":"{#RunAttempt}","architecture":"{#TargetArch}","compilerVersion":"6.7.1",' +
    '"scope":"disposable-protected-registry-ownership-contract","cases":[' + AWFixtureCases + '],' +
    '"cleanupComplete":' + AWFixtureBool(AWFixtureCleanup) + ',"passed":' +
    AWFixtureBool(AWFixturePassed and (AWFixtureCaseCount = 17)) +
    ',"productionRegistrationChanged":false,"productionQualificationComplete":false}' + #10;
  Result := SaveStringToFile('{#EvidenceRoot}\registry-owned-{#TargetArch}.json', RecordText, False);
end;
