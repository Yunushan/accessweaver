{ Fixed-key, fixed-buffer reads. The pinned Inno 6.7.1 runtime is x86. }
function AWOpenRegistrationKey(Parent: LongWord; const Subkey: String;
  Options, Access: LongWord; var Handle: LongWord): LongWord;
  external 'RegOpenKeyExW@advapi32.dll stdcall';
function AWGetRegistrationValue(Key: LongWord; const Subkey, Name: String;
  Flags: LongWord; var Kind: LongWord; Data: String; var Bytes: LongWord): LongWord;
  external 'RegGetValueW@advapi32.dll stdcall';
function AWCloseRegistrationKey(Key: LongWord): LongWord;
  external 'RegCloseKey@advapi32.dll stdcall';

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
  var Found: Boolean; var Version, Location: String): String;
var Parent, Uninstall, Product, Status: LongWord;
begin
  Result := ''; Found := False; Version := ''; Location := '';
  Parent := 0; Uninstall := 0; Product := 0;
  try
    { Preserve the readable-parent requirement without enumerating any names.
      Only the known Uninstall child and product leaf may be legitimately absent. }
    Status := AWOpenRegistrationKey($80000002,
      'SOFTWARE\Microsoft\Windows\CurrentVersion', 0, $0008 or View, Parent);
    if Status <> 0 then begin
      Result := 'Cannot inspect machine installation registration. Review access and retry.'; Exit;
    end;
    Status := AWOpenRegistrationKey(Parent, 'Uninstall', 0, $0008 or View, Uninstall);
    if (Status = 2) or (Status = 3) then Exit;
    if Status <> 0 then begin
      Result := 'Cannot inspect machine installation registration. Review access and retry.'; Exit;
    end;
    Status := AWOpenRegistrationKey(Uninstall,
      '{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1', 0, $0001 or View, Product);
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
    if ReadLocation and not AWReadRegistrationString(Product, 'InstallLocation', $30000002, 261, Location) then
      Result := 'Cannot verify the registered AccessWeaver installation directory. Review the installation before retrying.';
  finally
    if Product <> 0 then AWCloseRegistrationKey(Product);
    if Uninstall <> 0 then AWCloseRegistrationKey(Uninstall);
    if Parent <> 0 then AWCloseRegistrationKey(Parent);
  end;
end;
