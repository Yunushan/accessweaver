{ Fixed-key, fixed-buffer reads. The pinned Inno 6.7.1 runtime is x86. }
function AWOpenRegistrationKey(Parent: LongWord; const Subkey: String;
  Options, Access: LongWord; var Handle: LongWord): LongWord;
  external 'RegOpenKeyExW@advapi32.dll stdcall';
function AWGetRegistrationValue(Key: LongWord; const Subkey, Name: String;
  Flags: LongWord; var Kind: LongWord; Data: String; var Bytes: LongWord): LongWord;
  external 'RegGetValueW@advapi32.dll stdcall';
function AWCloseRegistrationKey(Key: LongWord): LongWord;
  external 'RegCloseKey@advapi32.dll stdcall';

function AWReadRegisteredVersion(const View: LongWord; var Found: Boolean; var Version: String): String;
var Parent, Uninstall, Product, Status, Kind, Bytes: LongWord;
    Buffer: String; Units: Integer;
begin
  Result := ''; Found := False; Version := '';
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
    { At most 256 UTF-16 code units plus one terminating NUL: 514 bytes.
      Restrict types to SZ/EXPAND_SZ; never expand machine environment references.
      Do not resize/retry from an untrusted required-size result. }
    SetLength(Buffer, 257);
    Bytes := 514; Kind := 0;
    Status := AWGetRegistrationValue(Product, '', 'DisplayVersion',
      $30000006, Kind, Buffer, Bytes);
    if (Status <> 0) or ((Kind <> 1) and (Kind <> 2)) or
      (Bytes < 2) or (Bytes > 514) or ((Bytes mod 2) <> 0) then begin
      Result := 'The installed AccessWeaver version is unreadable, oversized or has an unsupported type. Review the installation before retrying.'; Exit;
    end;
    Units := Bytes div 2;
    if Buffer[Units] <> #0 then begin
      Result := 'The installed AccessWeaver version has invalid termination.'; Exit;
    end;
    Version := Copy(Buffer, 1, Units - 1);
    if Pos(#0, Version) <> 0 then begin
      Result := 'The installed AccessWeaver version contains an embedded terminator.'; Exit;
    end;
  finally
    if Product <> 0 then AWCloseRegistrationKey(Product);
    if Uninstall <> 0 then AWCloseRegistrationKey(Uninstall);
    if Parent <> 0 then AWCloseRegistrationKey(Parent);
  end;
end;
