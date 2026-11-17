{
  Product registration is published and retired under the installation lock.
}
const AWProductRegistrationClass = 'AWReg-v1:8f826fa0456f2122e8b67448bcbda54b87254e164889106f8a66e76ca98b835c';

type AWLegacyUpgradeApproval = record
       Version, Payload, SBOM, BuildInfo, Uninstaller, UninstallData: String;
     end;

var AWPriorRegistration: AWRegistryTextValues;
    AWLegacyApproval: AWLegacyUpgradeApproval;
    AWLegacyPriorInventory: String;

function AWLegacyUninstallerName(const Path: String): Boolean;
var Name: String;
begin
  Name := ExtractFileName(Path);
  Result := (Length(Name) = 12) and (Copy(Name, 1, 5) = 'unins') and
    AWNumeric(Copy(Name, 6, 3)) and (Copy(Name, 9, 4) = '.exe');
end;

function AWVerifyLegacyUpgradeFiles(const Destination, Uninstaller: String;
  var Held: AWNativeHandles): Boolean;
begin
  Result := AWLockInstallationDirectory(Destination, Held) and
    AWVerifyAndHoldPackageFile(Destination + '\accessweaver.exe', AWLegacyApproval.Payload, -134217728, Held) and
    AWVerifyAndHoldPackageFile(Destination + '\SBOM.cdx.json', AWLegacyApproval.SBOM, -4194304, Held) and
    AWVerifyAndHoldPackageFile(Destination + '\BUILD-INFO.json', AWLegacyApproval.BuildInfo, -65536, Held) and
    AWVerifyAndHoldPackageFile(Uninstaller, AWLegacyApproval.Uninstaller, -536870912, Held) and
    AWVerifyAndHoldPackageFile(ChangeFileExt(Uninstaller, '.dat'), AWLegacyApproval.UninstallData, -536870912, Held);
end;

function AWPrepareOwnedProductRegistration(const Destination: String; var LegacyHeld: AWNativeHandles): Boolean;
var Parent, Key, Status: LongWord;
    Version, Location, Command, Uninstaller: String; OtherView: Boolean;
begin
  Result := False; Parent := 0; Key := 0;
  SetArrayLength(AWPriorRegistration, 0);
  AWLegacyPriorInventory := '';
  if AWReadRegistration($0200, False, '', OtherView, Version, Location) <> '' then Exit;
  if OtherView then Exit;
  if AWOpenMachineUninstallParent($0100, 0, Parent) <> 0 then Exit;
  try
    Status := AWOpenRegistrationComponent(Parent, AWMachineUninstallLeaf, $00020119, Key);
    if Status = 2 then begin Result := True; Exit; end;
    if Status <> 0 then Exit;
    if not AWReadRegistrationString(Key, 'DisplayVersion', $30000002, 256, Version) or
       not AWReadRegistrationString(Key, 'InstallLocation', $30000002, 261, Location) or
       not AWReadRegistrationString(Key, 'UninstallString', $30000002, 300, Command) then Exit;
    if not AWIsInstallationDirectory(Destination, Location) or
       (Length(Command) < 3) or (Command[1] <> '"') or (Command[Length(Command)] <> '"') then Exit;
    Uninstaller := Copy(Command, 2, Length(Command) - 2);
    if not AWRegistryProductValues(Version, RemoveBackslashUnlessRoot(Location),
      Uninstaller, AWPriorRegistration) then Exit;
    if AWOwnedRegistryHeld(Key, AWProductRegistrationClass) then begin
#ifdef RetiredPayloadInclude
      { This package overwrites a legacy log. Protected version changes use the
        ordinary Setup so the previous protected uninstall log remains intact. }
      if AWOrdinal(Version, '{#ReleaseVersion}') <> 0 then Exit;
#endif
      Result := AWRegistryProductValuesMatch(Key, AWPriorRegistration);
      Exit;
    end;
#ifdef RetiredPayloadInclude
    Result := (AWLegacyApproval.Version = Version) and AWLegacyUninstallerName(Uninstaller) and
      AWLegacyRegistrationInventory(Key, AWPriorRegistration, AWLegacyPriorInventory) and
      AWVerifyLegacyUpgradeFiles(Destination, Uninstaller, LegacyHeld);
#endif
  finally
    if not AWOwnedRegistryClose(Key) then Result := False;
    if not AWOwnedRegistryClose(Parent) then Result := False;
  end;
end;

function AWPublishOwnedProductRegistration(const Destination, Uninstaller: String): Boolean;
var Parent, Transaction, Key: LongWord;
    Candidate: AWRegistryTextValues;
    Staged, Finished, OtherView: Boolean;
    OtherVersion, OtherLocation: String;
begin
  Result := False; Parent := 0; Transaction := 0; Key := 0; Staged := False;
  if not AWLifecycleOwned or not AWPendingInstallMatches(Destination) then Exit;
  if AWReadRegistration($0200, False, '', OtherView, OtherVersion, OtherLocation) <> '' then Exit;
  if OtherView or not AWRegistryProductValues('{#ReleaseVersion}', Destination, Uninstaller, Candidate) then Exit;
  if AWOpenMachineUninstallParent($0100, $0004, Parent) <> 0 then Exit;
  try
    if not AWRegistryTransactionBegin(Transaction) then Exit;
    try
      Staged := AWRegistryStageProductRegistration(Parent, Transaction, AWMachineUninstallLeaf,
        AWProductRegistrationClass, AWPriorRegistration, Candidate, Key) and
        AWPendingInstallMatches(Destination);
    finally
      Finished := AWRegistryTransactionFinish(Transaction, Key, Staged);
    end;
    if not Staged or not Finished then Exit;
    if not AWOpenOwnedRegistryChild(Parent, AWMachineUninstallLeaf, AWProductRegistrationClass, Key) then Exit;
    Result := AWRegistryProductValuesMatch(Key, Candidate) and
      (AWFlushRegistryKey(Key) = 0) and AWPendingInstallMatches(Destination);
  finally
    if not AWOwnedRegistryClose(Key) then Result := False;
    if not AWOwnedRegistryClose(Parent) then Result := False;
  end;
end;


function AWProductRegistrationAbsent(View: LongWord): Boolean;
var Found: Boolean; Version, Location: String;
begin
  Result := (AWReadRegistration(View, False, '', Found, Version, Location) = '') and not Found;
end;

function AWRetireApprovedLegacyRegistration(const Destination: String): Boolean;
var Parent, Transaction, Unused: LongWord; Staged, Finished: Boolean;
begin
  Result := AWLegacyPriorInventory = '';
  if Result then Exit;
  Parent := 0; Transaction := 0; Unused := 0; Staged := False;
  if not AWLifecycleOwned or not AWPendingInstallMatches(Destination) then Exit;
  if not AWProductRegistrationAbsent($0200) then Exit;
  if AWOpenMachineUninstallParent($0100, 0, Parent) <> 0 then Exit;
  try
    if not AWRegistryTransactionBegin(Transaction) then Exit;
    try
      Staged := AWStageLegacyRegistrationRetirement(Parent, Transaction, AWMachineUninstallLeaf,
        AWPriorRegistration, AWLegacyPriorInventory) and AWPendingInstallMatches(Destination);
    finally
      Finished := AWRegistryTransactionFinish(Transaction, Unused, Staged);
    end;
    if not Staged or not Finished then Exit;
    Result := (AWFlushRegistryKey(Parent) = 0) and
      AWProductRegistrationAbsent($0100) and AWProductRegistrationAbsent($0200) and
      AWPendingInstallMatches(Destination);
    if Result then Log('AccessWeaver approved legacy registration retired.');
    if Result then SetArrayLength(AWPriorRegistration, 0);
  finally
    if not AWOwnedRegistryClose(Parent) then Result := False;
  end;
end;

function AWRetirePublishedRegistration(const Destination, Uninstaller: String): Boolean;
var Parent, Transaction, Key: LongWord;
    Fields: AWRegistryTextValues; Staged, Finished: Boolean;
begin
  Result := False; Parent := 0; Transaction := 0; Key := 0; Staged := False;
  if not AWLifecycleOwned or not AWPendingInstallMatches(Destination) then Exit;
  if not AWProductRegistrationAbsent($0200) then Exit;
  if not AWRegistryProductValues('{#ReleaseVersion}', Destination, Uninstaller, Fields) then Exit;
  if AWOpenMachineUninstallParent($0100, 0, Parent) <> 0 then Exit;
  try
    if not AWRegistryTransactionBegin(Transaction) then Exit;
    try
      Staged := AWRegistryStageProductRetirement(Parent, Transaction, AWMachineUninstallLeaf,
        AWProductRegistrationClass, Fields) and AWPendingInstallMatches(Destination);
    finally
      Finished := AWRegistryTransactionFinish(Transaction, Key, Staged);
    end;
    if not Staged or not Finished then Exit;
    Result := (AWFlushRegistryKey(Parent) = 0) and
      AWProductRegistrationAbsent($0100) and AWProductRegistrationAbsent($0200) and
      AWPendingInstallMatches(Destination);
  finally
    if not AWOwnedRegistryClose(Parent) then Result := False;
  end;
end;
