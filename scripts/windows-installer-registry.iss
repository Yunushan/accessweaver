{ Fixed-key, fixed-buffer reads. The pinned Inno 6.7.1 runtime is x86. }
function AWOpenRegistrationKey(Parent: LongWord; const Subkey: String;
  Options, Access: LongWord; var Handle: LongWord): LongWord;
  external 'RegOpenKeyExW@advapi32.dll stdcall';
function AWGetRegistrationValue(Key: LongWord; const Subkey, Name: String;
  Flags: LongWord; var Kind: LongWord; Data: String; var Bytes: LongWord): LongWord;
  external 'RegGetValueW@advapi32.dll stdcall';
function AWCloseRegistrationKey(Key: LongWord): LongWord;
  external 'RegCloseKey@advapi32.dll stdcall';

const AWMachineUninstallLeaf = '{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1';
      AWRegistrationUnsafe = $FFFFFFFF;

function AWRegistrationQueryValue(Key: LongWord; const Name: String;
  Reserved: LongWord; var Kind: LongWord; Data: LongWord; var Bytes: LongWord): LongWord;
  external 'RegQueryValueExW@advapi32.dll stdcall';

function AWOpenRegistrationComponent(Parent: LongWord; const Name: String;
  Access: LongWord; var Key: LongWord): LongWord;
var Kind, Bytes: LongWord;
begin
  Key := 0;
  Result := AWRegistrationUnsafe;
  if (Parent = 0) or (Name = '') or (Pos('\', Name) <> 0) or (Pos(#0, Name) <> 0) then Exit;
  { OPEN_LINK binds the named object without resolving any symbolic target.
    Probe only the reserved name and refuse ambiguous query errors. }
  Result := AWOpenRegistrationKey(Parent, Name, $0008, Access or $0001, Key);
  if Result <> 0 then Exit;
  Kind := 0; Bytes := 0;
  if AWRegistrationQueryValue(Key, 'SymbolicLinkValue', 0, Kind, 0, Bytes) <> 2 then begin
    AWCloseRegistrationKey(Key);
    Key := 0;
    Result := AWRegistrationUnsafe;
  end;
end;

function AWRegistrationAncestor(Index: Integer): String;
begin
  case Index of
    0: Result := 'SOFTWARE';
    1: Result := 'Microsoft';
    2: Result := 'Windows';
    3: Result := 'CurrentVersion';
    4: Result := 'Uninstall';
  else
    Result := '';
  end;
end;

function AWOpenMachineUninstallParent(View: LongWord; var Key: LongWord): LongWord;
var Parent, Child, Status: LongWord; Index: Integer;
begin
  Key := 0;
  Result := AWRegistrationUnsafe;
  if (View <> $0100) and (View <> $0200) then Exit;
  Parent := $80000002;
  try
    for Index := 0 to 4 do begin
      Status := AWOpenRegistrationComponent(Parent, AWRegistrationAncestor(Index), $0008 or View, Child);
      if Status <> 0 then begin
        { Absence is meaningful only for the final Uninstall component. }
        if (Index = 4) and ((Status = 2) or (Status = 3)) then Result := 2;
        Exit;
      end;
      if Parent <> $80000002 then
        if AWCloseRegistrationKey(Parent) <> 0 then begin
          AWCloseRegistrationKey(Child);
          Parent := $80000002;
          Exit;
        end;
      Parent := Child;
    end;
    Key := Parent;
    Parent := $80000002;
    Result := 0;
  finally
    if Parent <> $80000002 then
      if AWCloseRegistrationKey(Parent) <> 0 then Result := AWRegistrationUnsafe;
  end;
end;

function AWReadRegistrationString(Key: LongWord; const Name: String;
  Flags, Maximum: LongWord; var Value: String): Boolean;
var Kind, Bytes, Status: LongWord;
    Buffer: String; Units: Integer;
begin
  Result := False; Value := '';
  SetLength(Buffer, Maximum + 1);
  Bytes := (Maximum + 1) * 2; Kind := 0;
  Status := AWGetRegistrationValue(Key, '', Name, Flags, Kind, Buffer, Bytes);
  if (Status <> 0) or (Bytes < 4) or (Bytes > (Maximum + 1) * 2) or ((Bytes mod 2) <> 0) then Exit;
  if (Kind <> 1) and ((Kind <> 2) or ((Flags and $4) = 0)) then Exit;
  Units := Bytes div 2;
  if Buffer[Units] <> #0 then Exit;
  Value := Copy(Buffer, 1, Units - 1);
  Result := Pos(#0, Value) = 0;
end;

function AWReadRegistration(const View: LongWord; const ReadLocation: Boolean;
  const ExpectedUninstaller: String; var Found: Boolean; var Version, Location: String): String;
var Uninstall, Product, Status: LongWord;
    Command, QuietCommand, Expected: String;
begin
  Result := ''; Found := False; Version := ''; Location := '';
  Uninstall := 0; Product := 0;
  try
    Status := AWOpenMachineUninstallParent(View, Uninstall);
    if Status = 2 then Exit;
    if Status <> 0 then begin
      Result := 'Cannot inspect machine installation registration. Review access and retry.'; Exit;
    end;
    Status := AWOpenRegistrationComponent(Uninstall, AWMachineUninstallLeaf, View, Product);
    if (Status = 2) or (Status = 3) then Exit;
    if Status <> 0 then begin
      Result := 'Cannot read the AccessWeaver installation registration. Review access and retry.'; Exit;
    end;
    Found := True;
    { Bound version bytes and keep REG_EXPAND_SZ literal. InstallLocation must
      be the REG_SZ directory that Setup recorded, including its trailing slash. }
    if not AWReadRegistrationString(Product, 'DisplayVersion', $30000006, 256, Version) then begin
      Result := 'The installed AccessWeaver version is unreadable, oversized or has an unsupported type. Review the installation before retrying.'; Exit;
    end;
    if ReadLocation and not AWReadRegistrationString(Product, 'InstallLocation', $30000002, 261, Location) then begin
      Result := 'Cannot verify the registered AccessWeaver installation directory. Review the installation before retrying.'; Exit;
    end;
    if ExpectedUninstaller <> '' then begin
      { Inno 6.7.1 writes these forms when UninstallLogging is disabled. }
      Expected := '"' + ExpectedUninstaller + '"';
      if not AWReadRegistrationString(Product, 'UninstallString', $30000002, 300, Command) or
         not AWReadRegistrationString(Product, 'QuietUninstallString', $30000002, 300, QuietCommand) or
         (AWOrdinal(Command, Expected) <> 0) or (AWOrdinal(QuietCommand, Expected + ' /SILENT') <> 0) then
        Result := 'The registered AccessWeaver uninstall commands do not match the installed uninstaller.';
    end;
  finally
    if Product <> 0 then
      if AWCloseRegistrationKey(Product) <> 0 then
        Result := 'Cannot release the AccessWeaver installation registration. Review access and retry.';
    if Uninstall <> 0 then
      if AWCloseRegistrationKey(Uninstall) <> 0 then
        Result := 'Cannot release machine installation registration. Review access and retry.';
  end;
end;
