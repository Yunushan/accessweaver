{
  Included only by the protected-registration qualification build. The
  release builder requires a complete migration and removal path first.
}
const AWProductRegistrationClass = 'AWReg-v1:8f826fa0456f2122e8b67448bcbda54b87254e164889106f8a66e76ca98b835c';

var AWPriorRegistration: AWRegistryTextValues;

function AWPrepareOwnedProductRegistration(const Destination: String): Boolean;
var Parent, Key, Status: LongWord;
    Version, Location, Command: String; OtherView: Boolean;
begin
  Result := False; Parent := 0; Key := 0;
  SetArrayLength(AWPriorRegistration, 0);
  if AWReadRegistration($0200, False, '', OtherView, Version, Location) <> '' then Exit;
  if OtherView then Exit;
  if AWOpenMachineUninstallParent($0100, 0, Parent) <> 0 then Exit;
  try
    Status := AWOpenRegistrationComponent(Parent, AWMachineUninstallLeaf, $00020119, Key);
    if Status = 2 then begin Result := True; Exit; end;
    if (Status <> 0) or not AWOwnedRegistryHeld(Key, AWProductRegistrationClass) then Exit;
    if not AWReadRegistrationString(Key, 'DisplayVersion', $30000002, 256, Version) or
       not AWReadRegistrationString(Key, 'InstallLocation', $30000002, 261, Location) or
       not AWReadRegistrationString(Key, 'UninstallString', $30000002, 300, Command) then Exit;
    if not AWIsInstallationDirectory(Destination, Location) or
       (Length(Command) < 3) or (Command[1] <> '"') or (Command[Length(Command)] <> '"') then Exit;
    Result := AWRegistryProductValues(Version, RemoveBackslashUnlessRoot(Location),
      Copy(Command, 2, Length(Command) - 2), AWPriorRegistration) and
      AWRegistryProductValuesMatch(Key, AWPriorRegistration);
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
