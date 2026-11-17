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
#ifndef ExpectedCaseCount
  #error ExpectedCaseCount is required
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
#include "windows-installer-version.iss"
#include "windows-installer-registry.iss"
#include "windows-installer-registry-transaction.iss"
const AWFixtureTag = 'AWReg-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      AWFixtureOtherTag = 'AWReg-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      AWFixtureParentSDDL = 'O:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;BU)';
var AWFixtureOwned: array of LongWord;
    AWFixturePassed, AWFixtureCleanup: Boolean;
    AWFixtureCases, AWFixtureDescriptorResult, AWFixtureCleanupResult: String; AWFixtureCaseCount: Integer;

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

procedure AWFixtureCloseRetired(var Key: LongWord);
var I: Integer;
begin
  for I := 0 to GetArrayLength(AWFixtureOwned) - 1 do
    if AWFixtureOwned[I] = Key then begin
      AWFixtureOwned[I] := 0;
      if not AWOwnedRegistryClose(Key) then AWFixtureCleanup := False;
      Exit;
    end;
  AWFixtureCleanup := False;
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

function AWFixtureCreateRefused(Root: LongWord; const Name: String): Boolean;
var Key: LongWord; Created, Accepted: Boolean;
begin
  Accepted := AWCreateOwnedRegistryChild(Root, Name, AWFixtureTag, Key, Created);
  { Even a mistakenly created key belongs to this creation attempt. Retain the
    handle for exact cleanup and keep the refusal test failed. }
  if Created and (Key <> 0) then AWFixtureRemember(Key);
  Result := not Accepted and not Created and (Key = 0);
end;

procedure AWFixtureCasesRun(Root: LongWord);
var Fresh, BadACL, Unprotected, Target, Link, MissingLink, Opened, Flags, Value, Status: LongWord;
    Created, OK, LinkReady, MissingLinkReady: Boolean; NativeTarget: String;
begin
  Fresh := 0; Opened := 0; Target := 0; BadACL := 0; Unprotected := 0; Link := 0; MissingLink := 0;
  OK := AWFixtureNew(Root, 'fresh', Fresh);
  AWFixtureCase('protected-child-created', OK);
  if Fresh <> 0 then AWFixtureDescriptorResult := AWOwnedRegistryDescriptorStatus(Fresh);
  AWFixtureCase('creation-descriptor-exact', AWFixtureDescriptorResult = 'pass');
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
  OK := AWFixtureRaw(Root, 'bad-acl', 'O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)', 0, BadACL);
  OK := OK and (AWOwnedRegistryDescriptorStatus(BadACL) = 'descriptor-aces') and
    not AWOpenOwnedRegistryChild(Root, 'bad-acl', AWFixtureTag, Opened) and (Opened = 0);
  AWFixtureCase('foreign-writer-descriptor-refused', OK);
  OK := AWFixtureRaw(Root, 'unprotected', 'O:BAD:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)', 0, Unprotected);
  OK := OK and (AWOwnedRegistryDescriptorStatus(Unprotected) = 'descriptor-protection') and
    not AWOpenOwnedRegistryChild(Root, 'unprotected', AWFixtureTag, Opened) and (Opened = 0);
  AWFixtureCase('unprotected-descriptor-refused', OK);
  Created := False;
  OK := not AWCreateOwnedRegistryChild(Root, 'nested\unexpected', AWFixtureTag, Opened, Created);
  AWFixtureCase('nested-name-refused', OK and not Created and (Opened = 0));
  OK := not AWCreateOwnedRegistryChild(Root, 'invalid-tag', 'not-an-owned-tag', Opened, Created);
  AWFixtureCase('invalid-tag-refused', OK and not Created and (Opened = 0));
  OK := AWFixtureNew(Root, 'target', Target);
  Value := 73; OK := OK and (AWFixtureWriteDWORD(Target, 'sentinel', 0, 4, Value, 4) = 0);
  NativeTarget := '\REGISTRY\MACHINE\SOFTWARE\{#FixtureRootName}\target';
  LinkReady := AWFixtureRaw(Root, 'link', AWOwnedRegistrySDDL, 2, Link);
  LinkReady := LinkReady and (AWFixtureWriteText(Link, 'SymbolicLinkValue', 0, 6, NativeTarget, Length(NativeTarget) * 2) = 0);
  AWFixtureCase('link-to-existing-target-refused', OK and LinkReady and
    not AWOpenOwnedRegistryChild(Root, 'link', AWFixtureTag, Opened) and (Opened = 0));
  if not AWOwnedRegistryClose(Opened) then AWFixtureCleanup := False;
  AWFixtureCase('create-does-not-adopt-link', LinkReady and AWFixtureCreateRefused(Root, 'link') and
    AWFixtureSentinel(Target));
  NativeTarget := '\REGISTRY\MACHINE\SOFTWARE\{#FixtureRootName}\missing';
  MissingLinkReady := AWFixtureRaw(Root, 'missing-link', AWOwnedRegistrySDDL, 2, MissingLink);
  MissingLinkReady := MissingLinkReady and (AWFixtureWriteText(MissingLink, 'SymbolicLinkValue', 0, 6, NativeTarget, Length(NativeTarget) * 2) = 0);
  AWFixtureCase('link-to-missing-target-refused', MissingLinkReady and
    not AWOpenOwnedRegistryChild(Root, 'missing-link', AWFixtureTag, Opened) and (Opened = 0));
  if not AWOwnedRegistryClose(Opened) then AWFixtureCleanup := False;
  OK := MissingLinkReady and AWFixtureCreateRefused(Root, 'missing-link');
  Status := AWOwnedRegistryOpenNative(Root, 'missing', AWOwnedRegistryOpenLink, $00020119, Opened);
  if not AWOwnedRegistryClose(Opened) then AWFixtureCleanup := False;
  AWFixtureCase('missing-link-target-not-created', OK and (Status = 2));
  AWFixtureCase('existing-link-target-preserved', AWFixtureSentinel(Target));
  Status := AWOpenRegistrationComponent(Root, 'target', $0100, Opened);
  AWFixtureCase('registration-reader-opens-real-key', (Status = 0) and AWFixtureSentinel(Opened));
  if not AWOwnedRegistryClose(Opened) then AWFixtureCleanup := False;
  Status := AWOpenRegistrationComponent(Root, 'link', $0100, Opened);
  AWFixtureCase('registration-reader-refuses-existing-link', LinkReady and
    (Status = AWRegistrationUnsafe) and (Opened = 0));
  if not AWOwnedRegistryClose(Opened) then AWFixtureCleanup := False;
  Status := AWOpenRegistrationComponent(Root, 'missing-link', $0100, Opened);
  AWFixtureCase('registration-reader-refuses-dangling-link', MissingLinkReady and
    (Status = AWRegistrationUnsafe) and (Opened = 0));
  if not AWOwnedRegistryClose(Opened) then AWFixtureCleanup := False;
  Status := AWOpenRegistrationComponent(Root, 'not-present', $0100, Opened);
  AWFixtureCase('registration-reader-distinguishes-absence', (Status = 2) and (Opened = 0));
  if not AWOwnedRegistryClose(Opened) then AWFixtureCleanup := False;

end;


function AWFixtureNoKey(Parent: LongWord; const Name: String): Boolean;
var Key, Status: LongWord;
begin
  Key := 0;
  Status := AWOwnedRegistryOpenNative(Parent, Name, AWOwnedRegistryOpenLink, $00020119, Key);
  Result := AWOwnedRegistryClose(Key) and (Status = 2);
end;

const AWFixtureDirectory = 'C:\Fixture Folder\AccessWeaver';
      AWFixtureUninstaller = 'C:\Fixture Folder\AccessWeaver\unins000.exe';

function AWFixtureWriteRegistration(Key: LongWord; const Version: String): Boolean;
var Fields: AWRegistryTextValues;
begin
  Result := AWRegistryProductValues(Version, AWFixtureDirectory, AWFixtureUninstaller, Fields) and
    AWRegistryStageProductValues(Key, Fields);
end;

function AWFixtureRegistrationMatches(Key: LongWord; const Version: String): Boolean;
var Fields: AWRegistryTextValues;
begin
  Result := AWOwnedRegistryHeld(Key, AWFixtureTag) and
    AWRegistryProductValues(Version, AWFixtureDirectory, AWFixtureUninstaller, Fields) and
    AWRegistryProductValuesMatch(Key, Fields);
end;

function AWFixtureRemovalCommandsMatch(Key: LongWord): Boolean;
var Location, Command, Quiet: String;
begin
  Result := AWReadRegistrationString(Key, 'InstallLocation', $30000002, 261, Location) and
    (AWOrdinal(Location, 'C:\Fixture Folder\AccessWeaver\') = 0) and
    AWReadRegistrationString(Key, 'UninstallString', $30000002, 300, Command) and
    (AWOrdinal(Command, '"C:\Fixture Folder\AccessWeaver\unins000.exe"') = 0) and
    AWReadRegistrationString(Key, 'QuietUninstallString', $30000002, 300, Quiet) and
    (AWOrdinal(Quiet, '"C:\Fixture Folder\AccessWeaver\unins000.exe" /SILENT') = 0);
end;

procedure AWFixtureRetirementCases(Root: LongWord; var Prior: LongWord);
var Tx, Unused, Link, Value: LongWord;
    WrongFields, Fields: AWRegistryTextValues; Ready, LinkReady, Staged, Finished, Absent: Boolean;
    NativeTarget: String;
begin
  Tx := 0; Unused := 0; Link := 0;
  Ready := (Prior <> 0) and AWFixtureRegistrationMatches(Prior, '2.0.0') and
    AWRegistryProductValues('2.0.0', AWFixtureDirectory, AWFixtureUninstaller, Fields) and
    AWRegistryProductValues('1.0.0', AWFixtureDirectory, AWFixtureUninstaller, WrongFields);
  Staged := False;
  try
    if Ready and AWRegistryTransactionBegin(Tx) then
      Staged := not AWRegistryStageProductRetirement(Root, Tx, 'published', AWFixtureTag, WrongFields);
  finally
    Finished := AWRegistryTransactionFinish(Tx, Unused, False);
  end;
  AWFixtureCase('retirement-refuses-different-version', Staged and Finished and
    AWFixtureRegistrationMatches(Prior, '2.0.0'));

  NativeTarget := '\REGISTRY\MACHINE\SOFTWARE\{#FixtureRootName}\published';
  LinkReady := AWFixtureRaw(Root, 'registration-link', AWOwnedRegistrySDDL, 2, Link) and
    (AWFixtureWriteText(Link, 'SymbolicLinkValue', 0, 6, NativeTarget, Length(NativeTarget) * 2) = 0);
  Staged := False;
  try
    if Ready and LinkReady and AWRegistryTransactionBegin(Tx) then
      Staged := not AWRegistryStageProductRetirement(Root, Tx, 'registration-link', AWFixtureTag, Fields);
  finally
    Finished := AWRegistryTransactionFinish(Tx, Unused, False);
  end;
  AWFixtureCase('retirement-refuses-link-to-registration', Staged and Finished and
    AWFixtureRegistrationMatches(Prior, '2.0.0'));

  Staged := False;
  try
    if Ready and AWRegistryTransactionBegin(Tx) then
      Staged := AWRegistryStageProductRetirement(Root, Tx, 'published', AWFixtureTag, Fields);
    AWFixtureCase('staged-retirement-keeps-committed-record', Staged and
      AWFixtureRegistrationMatches(Prior, '2.0.0'));
  finally
    Finished := AWRegistryTransactionFinish(Tx, Unused, False);
  end;
  AWFixtureCase('abandoned-retirement-keeps-committed-record', Staged and Finished and
    AWFixtureRegistrationMatches(Prior, '2.0.0'));

  Staged := False;
  try
    if Ready and AWRegistryTransactionBegin(Tx) then
      Staged := AWRegistryStageProductRetirement(Root, Tx, 'published', AWFixtureTag, Fields);
  finally
    Finished := AWRegistryTransactionFinish(Tx, Unused, Staged);
  end;
  Absent := Staged and Finished and AWFixtureNoKey(Root, 'published');
  AWFixtureCase('committed-retirement-removes-exact-key', Absent);
  Value := 73;
  AWFixtureCase('retired-handle-cannot-write', Absent and
    (AWFixtureWriteDWORD(Prior, 'sentinel', 0, 4, Value, 4) = 1018));
  if Absent then AWFixtureCloseRetired(Prior);
end;

const AWFixtureLegacyDescriptor = 'O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)';

function AWFixtureLegacyMatches(Key: LongWord; const Prior: AWRegistryTextValues): Boolean;
var Kind, Bytes: LongWord;
begin
  Kind := 0; Bytes := 0;
  Result := (Key <> 0) and
    (AWOwnedRegistryQueryValue(Key, 'SymbolicLinkValue', 0, Kind, 0, Bytes) = 2) and
    (AWOwnedRegistryDescriptorStatus(Key) = 'descriptor-aces') and
    AWRegistryProductValuesMatch(Key, Prior);
end;

function AWFixtureLegacyVisible(Root: LongWord; const Prior: AWRegistryTextValues): Boolean;
var Key: LongWord;
begin
  Key := 0;
  Result := (AWOpenRegistrationComponent(Root, 'legacy', $00020119 or $0100, Key) = 0) and
    AWFixtureLegacyMatches(Key, Prior);
  if not AWOwnedRegistryClose(Key) then Result := False;
end;

function AWFixtureStageLegacyDelete(Root, Tx: LongWord; const Prior: AWRegistryTextValues): Boolean;
var Key: LongWord;
begin
  Result := False; Key := 0;
  if Tx = 0 then Exit;
  try
    if AWOwnedRegistryOpenInNative(Root, 'legacy', AWOwnedRegistryOpenLink,
       AWOwnedRegistryAccess, Key, Tx, 0) <> 0 then Exit;
    if AWFixtureLegacyMatches(Key, Prior) then Result := AWRegistryDeleteHeld(Key) = 0;
  finally
    if not AWOwnedRegistryClose(Key) then Result := False;
  end;
end;

function AWFixtureFlushKey(Key: LongWord): LongWord;
  external 'RegFlushKey@advapi32.dll stdcall';

const AWFixtureMigrationPin = 'approved-fixture-1.0.0-to-2.0.0';

function AWFixtureMigrationPending(Root: LongWord): Boolean;
var Key: LongWord; Actual: String;
begin
  Key := 0;
  Result := AWOpenOwnedRegistryChild(Root, 'migration-pending', AWFixtureTag, Key) and
    AWReadRegistrationString(Key, 'Candidate', $30000002, 64, Actual) and
    (AWOrdinal(Actual, AWFixtureMigrationPin) = 0);
  if not AWOwnedRegistryClose(Key) then Result := False;
end;

function AWFixtureStageLegacyRecovery(Root, Tx: LongWord;
  const Candidate: AWRegistryTextValues; var Key: LongWord): Boolean;
var Created: Boolean;
begin
  Result := False; Key := 0;
  if (Tx = 0) or not AWFixtureMigrationPending(Root) or not AWFixtureNoKey(Root, 'legacy') then Exit;
  Result := AWCreateOwnedRegistryChildIn(Root, Tx, 'legacy', AWFixtureOtherTag, Key, Created) and
    Created and AWRegistryStageProductValues(Key, Candidate) and AWFixtureNoKey(Root, 'legacy');
end;

procedure AWFixtureLegacyReplacementCases(Root: LongWord);
var Legacy, Replacement, Pending, Tx, Key, Value: LongWord; Prior, Candidate: AWRegistryTextValues;
    Ready, Staged, Finished, Retired, Opened: Boolean;
begin
  Legacy := 0; Replacement := 0; Pending := 0; Tx := 0; Key := 0;
  Value := 1;
  Ready := AWRegistryProductValues('1.0.0', AWFixtureDirectory, AWFixtureUninstaller, Prior) and
    AWRegistryProductValues('2.0.0', AWFixtureDirectory, AWFixtureUninstaller, Candidate) and
    AWFixtureRaw(Root, 'legacy', AWFixtureLegacyDescriptor, 0, Legacy) and
    AWRegistryStageProductValues(Legacy, Prior) and
    (AWFixtureWriteDWORD(Legacy, 'NoModify', 0, 4, Value, 4) = 0) and
    AWFixtureLegacyMatches(Legacy, Prior) and AWFixtureLegacyVisible(Root, Prior);
  AWFixtureCase('legacy-registration-held-with-writer', Ready);

  Staged := False;
  try
    if Ready and AWRegistryTransactionBegin(Tx) then
      Staged := AWFixtureStageLegacyDelete(Root, Tx, Prior);
    AWFixtureCase('staged-legacy-retirement-keeps-prior-visible', Staged and
      AWFixtureLegacyMatches(Legacy, Prior) and AWFixtureLegacyVisible(Root, Prior));
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, False);
  end;
  AWFixtureCase('abandoned-legacy-retirement-preserves-prior', Staged and Finished and
    AWFixtureLegacyMatches(Legacy, Prior) and AWFixtureLegacyVisible(Root, Prior));

  Ready := Ready and Finished and AWFixtureLegacyVisible(Root, Prior) and
    AWFixtureNew(Root, 'migration-pending', Pending) and
    AWRegistrySetString(Pending, 'Candidate', AWFixtureMigrationPin) and
    (AWFixtureFlushKey(Pending) = 0) and AWFixtureMigrationPending(Root);
  AWFixtureCase('legacy-retirement-bound-to-durable-pending-record', Ready);

  Staged := False;
  try
    if Ready and AWFixtureMigrationPending(Root) and AWRegistryTransactionBegin(Tx) then
      Staged := AWFixtureStageLegacyDelete(Root, Tx, Prior) and
        AWFixtureLegacyMatches(Legacy, Prior) and AWFixtureLegacyVisible(Root, Prior);
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, Staged);
  end;
  Retired := Staged and Finished and AWFixtureNoKey(Root, 'legacy');
  AWFixtureCase('retired-legacy-registration-leaves-recovery-record', Retired and
    AWFixtureMigrationPending(Root));

  { Recover with a new transaction after the first exact transaction has ended.
    Both the ordinary missing name and the protected marker must be observable. }
  Ready := Retired and AWFixtureMigrationPending(Root) and
    AWRegistrySetString(Pending, 'Candidate', 'different-fixture-candidate') and (AWFixtureFlushKey(Pending) = 0);
  Staged := False;
  try
    if Ready and AWRegistryTransactionBegin(Tx) then
      Staged := not AWFixtureStageLegacyRecovery(Root, Tx, Candidate, Key);
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, False);
  end;
  AWFixtureCase('legacy-recovery-refuses-unbound-pending-record', Staged and Finished and
    AWFixtureNoKey(Root, 'legacy'));

  Ready := Staged and Finished and AWRegistrySetString(Pending, 'Candidate', AWFixtureMigrationPin) and
    (AWFixtureFlushKey(Pending) = 0) and AWFixtureMigrationPending(Root);
  Staged := False;
  try
    if Ready and AWRegistryTransactionBegin(Tx) then
      Staged := AWFixtureStageLegacyRecovery(Root, Tx, Candidate, Key);
    AWFixtureCase('pending-legacy-recovery-stages-invisible-replacement', Staged);
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, Staged);
  end;
  Opened := Staged and Finished and AWOpenOwnedRegistryChild(Root, 'legacy', AWFixtureOtherTag, Replacement);
  if Opened then AWFixtureRemember(Replacement);
  AWFixtureCase('legacy-replacement-visible-protected-after-commit', Opened and
    AWRegistryProductValuesMatch(Replacement, Candidate) and AWFixtureMigrationPending(Root));
  Value := 73;
  AWFixtureCase('legacy-writer-cannot-change-replacement', Opened and
    (AWFixtureWriteDWORD(Legacy, 'sentinel', 0, 4, Value, 4) = 1018) and
    AWRegistryProductValuesMatch(Replacement, Candidate));
  if Retired then AWFixtureCloseRetired(Legacy);
end;

procedure AWFixtureTransactionCases(Root: LongWord);
var Tx, Key, Prior: LongWord; Created, Staged, Finished, Opened: Boolean;
begin
  Tx := 0; Key := 0; Prior := 0;
  Staged := False;
  try
    if AWRegistryTransactionBegin(Tx) then
      Staged := AWCreateOwnedRegistryChildIn(Root, Tx, 'abandoned', AWFixtureTag, Key, Created) and Created and
        AWFixtureWriteRegistration(Key, '1.0.0') and AWFixtureRegistrationMatches(Key, '1.0.0');
    AWFixtureCase('new-transacted-registration-staged', Staged and AWFixtureNoKey(Root, 'abandoned'));
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, False);
  end;
  AWFixtureCase('abandoned-registration-invisible', Staged and Finished and AWFixtureNoKey(Root, 'abandoned'));

  Staged := False; Finished := False;
  try
    if AWRegistryTransactionBegin(Tx) then
      Staged := AWCreateOwnedRegistryChildIn(Root, Tx, 'published', AWFixtureTag, Key, Created) and Created and
        AWFixtureWriteRegistration(Key, '1.0.0') and AWFixtureRegistrationMatches(Key, '1.0.0') and
        AWFixtureNoKey(Root, 'published');
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, Staged);
  end;
  Opened := Staged and Finished and AWOpenOwnedRegistryChild(Root, 'published', AWFixtureTag, Prior);
  if Opened then AWFixtureRemember(Prior);
  AWFixtureCase('complete-registration-visible-after-commit', Opened and
    AWFixtureRegistrationMatches(Prior, '1.0.0') and AWFixtureRemovalCommandsMatch(Prior));

  Staged := False; Finished := False;
  try
    if Opened and AWRegistryTransactionBegin(Tx) then
      Staged := AWOpenOwnedRegistryChildIn(Root, Tx, 'published', AWFixtureTag, Key) and
        AWFixtureRegistrationMatches(Key, '1.0.0') and AWFixtureWriteRegistration(Key, '2.0.0') and
        AWFixtureRegistrationMatches(Key, '2.0.0');
    AWFixtureCase('staged-upgrade-preserves-visible-prior', Staged and AWFixtureRegistrationMatches(Prior, '1.0.0'));
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, False);
  end;
  AWFixtureCase('abandoned-upgrade-preserves-prior', Staged and Finished and AWFixtureRegistrationMatches(Prior, '1.0.0'));

  Staged := False; Finished := False;
  try
    if Opened and AWRegistryTransactionBegin(Tx) then
      Staged := AWOpenOwnedRegistryChildIn(Root, Tx, 'published', AWFixtureTag, Key) and
        AWFixtureRegistrationMatches(Key, '1.0.0') and AWFixtureWriteRegistration(Key, '2.0.0') and
        AWFixtureRegistrationMatches(Key, '2.0.0') and AWFixtureRegistrationMatches(Prior, '1.0.0');
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, Staged);
  end;
  AWFixtureCase('complete-upgrade-visible-after-commit', Staged and Finished and AWFixtureRegistrationMatches(Prior, '2.0.0'));

  Staged := False;
  try
    if Opened and AWRegistryTransactionBegin(Tx) then
      Staged := AWOpenOwnedRegistryChildIn(Root, Tx, 'published', AWFixtureTag, Key) and
        AWFixtureRegistrationMatches(Key, '2.0.0') and
        AWRegistrySetString(Key, 'unexpected', 'inert') and
        not AWFixtureRegistrationMatches(Key, '2.0.0');
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, False);
  end;
  AWFixtureCase('unexpected-registration-value-refused', Staged and Finished and
    AWFixtureRegistrationMatches(Prior, '2.0.0'));

  Staged := False;
  try
    if Opened and AWRegistryTransactionBegin(Tx) then
      Staged := AWOpenOwnedRegistryChildIn(Root, Tx, 'published', AWFixtureTag, Key) and
        AWFixtureRegistrationMatches(Key, '2.0.0') and
        AWRegistrySetString(Key, 'NoModify', '1') and
        not AWFixtureRegistrationMatches(Key, '2.0.0');
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, False);
  end;
  AWFixtureCase('registration-value-type-mismatch-refused', Staged and Finished and
    AWFixtureRegistrationMatches(Prior, '2.0.0'));

  Staged := False; Finished := False;
  try
    if AWRegistryTransactionBegin(Tx) then
      Staged := not AWOpenOwnedRegistryChildIn(Root, Tx, 'link', AWFixtureTag, Key) and (Key = 0);
  finally
    Finished := AWRegistryTransactionFinish(Tx, Key, False);
  end;
  AWFixtureCase('transaction-rejects-existing-link', Staged and Finished);
  AWFixtureRetirementCases(Root, Prior);
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
  AWFixtureDescriptorResult := 'not-run'; AWFixtureCleanupResult := 'pass';
  Software := 0; Root := 0; Probe := 0; RootCreated := False;
  try
    if AWOwnedRegistryOpenNative($80000002, 'SOFTWARE', 0, $00020104, Software) = 0 then
      RootCreated := AWFixtureRaw(Software, '{#FixtureRootName}', AWFixtureParentSDDL, 0, Root);
    AWFixtureCase('new-owned-fixture-parent', RootCreated);
    if RootCreated then begin
      AWFixtureCasesRun(Root);
      AWFixtureTransactionCases(Root);
      AWFixtureLegacyReplacementCases(Root);
    end;
  finally
    { Every deletion uses an exact handle returned by a confirmed NEW creation.
      No recursive traversal, path-based link deletion, or adoption for cleanup. }
    for I := GetArrayLength(AWFixtureOwned) - 1 downto 0 do begin
      if AWFixtureOwned[I] <> 0 then begin
        if AWRegistryDeleteHeld(AWFixtureOwned[I]) <> 0 then begin
          if AWFixtureCleanupResult = 'pass' then AWFixtureCleanupResult := 'held-delete';
          AWFixtureCleanup := False;
        end;
        if not AWOwnedRegistryClose(AWFixtureOwned[I]) then AWFixtureCleanup := False;
      end;
    end;
    if RootCreated then begin
      if AWOwnedRegistryOpenNative(Software, '{#FixtureRootName}', AWOwnedRegistryOpenLink,
           $00020119, Probe) <> 2 then begin
        if AWFixtureCleanupResult = 'pass' then AWFixtureCleanupResult := 'root-present-or-unreadable';
        AWFixtureCleanup := False;
      end;
      if not AWOwnedRegistryClose(Probe) then AWFixtureCleanup := False;
    end;
    if not AWOwnedRegistryClose(Software) then AWFixtureCleanup := False;
    if AWOwnedRegistryCleanupUncertain then AWFixtureCleanup := False;
    AWFixtureCleanup := AWFixtureCleanup and RootCreated;
    if not AWFixtureCleanup and (AWFixtureCleanupResult = 'pass') then
      AWFixtureCleanupResult := 'fixture-or-handle-close';
    AWFixtureCase('exact-owned-cleanup', AWFixtureCleanup);
  end;
  RecordText := '{"schemaVersion":1,"sourceCommit":"{#SourceCommit}","runID":"{#RunID}",' +
    '"runAttempt":"{#RunAttempt}","architecture":"{#TargetArch}","compilerVersion":"6.7.1",' +
    '"scope":"disposable-protected-registry-ownership-contract","cases":[' + AWFixtureCases + '],' +
    '"descriptorResult":"' + AWFixtureDescriptorResult + '","cleanupResult":"' + AWFixtureCleanupResult + '",' +
    '"cleanupComplete":' + AWFixtureBool(AWFixtureCleanup) + ',"passed":' +
    AWFixtureBool(AWFixturePassed and (AWFixtureCaseCount = {#ExpectedCaseCount})) +
    ',"productionRegistrationChanged":false,"productionQualificationComplete":false}' + #10;
  Result := SaveStringToFile('{#EvidenceRoot}\registry-owned-{#TargetArch}.json', RecordText, False);
end;
