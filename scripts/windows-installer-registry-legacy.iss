{ The shipped Inno 6.7.1 scripts use an unclassified legacy leaf. A
  writable descriptor does not establish identity. Before migration, bind
  the entry to the independently approved files and compare this inventory
  again through the transacted handle. No legacy values are logged. }
function AWLegacyRegistrationText(Key: LongWord; const Name: String; Maximum: LongWord;
  Required: Boolean; var Count: LongWord; var Inventory: String): Boolean;
var Kind, Bytes, Status: LongWord; Units: Integer; Buffer, Value: String;
begin
  Result := False;
  SetLength(Buffer, Maximum + 1); Bytes := (Maximum + 1) * 2; Kind := 0;
  Status := AWGetRegistrationValue(Key, '', Name, $30000002, Kind, Buffer, Bytes);
  if Status = 2 then begin Result := not Required; Exit; end;
  if (Status <> 0) or (Kind <> 1) or (Bytes < 2) or (Bytes > (Maximum + 1) * 2) or
     ((Bytes mod 2) <> 0) then Exit;
  Units := Bytes div 2;
  if Buffer[Units] <> #0 then Exit;
  Value := Copy(Buffer, 1, Units - 1);
  if Pos(#0, Value) <> 0 then Exit;
  Count := Count + 1;
  Inventory := Inventory + Name + #0 + Value + #0;
  Result := True;
end;

function AWLegacyRegistrationDWORD(Key: LongWord; const Name: String; Required: Boolean;
  var Count: LongWord; var Inventory: String): Boolean;
var Kind, Data, Bytes, Status: LongWord;
begin
  Result := False; Kind := 0; Data := 0; Bytes := 4;
  Status := AWRegistryReadDWORDNative(Key, Name, 0, Kind, Data, Bytes);
  if Status = 2 then begin Result := not Required; Exit; end;
  if (Status <> 0) or (Kind <> 4) or (Bytes <> 4) then Exit;
  if (Name = 'Inno Setup: No Icons') and (Data <> 1) then Exit;
  Count := Count + 1;
  Inventory := Inventory + Name + #0 + IntToStr(Data) + #0;
  Result := True;
end;

function AWLegacyRegistrationInventory(Key: LongWord; const Fields: AWRegistryTextValues;
  var Inventory: String): Boolean;
var ClassBuffer, Compiler, Date: String;
    Characters, Children, Values, Count, Kind, Bytes: LongWord;
begin
  Result := False; Inventory := '';
  if (Key = 0) or (GetArrayLength(Fields) <> AWRegistryProductTextCount) then Exit;
  SetLength(ClassBuffer, 128); Characters := 128; Children := 0; Values := 0;
  if AWOwnedRegistryQueryInfo(Key, ClassBuffer, Characters, 0, Children, 0, 0,
    Values, 0, 0, 0, 0) <> 0 then Exit;
  if (Characters <> 0) or (Children <> 0) or (Values > 24) then Exit;
  Kind := 0; Bytes := 0;
  if AWOwnedRegistryQueryValue(Key, 'SymbolicLinkValue', 0, Kind, 0, Bytes) <> 2 then Exit;
  if not AWRegistryProductTextValuesMatch(Key, Fields) or
     not AWRegistryDWORDIsOne(Key, 'NoModify') or not AWRegistryDWORDIsOne(Key, 'NoRepair') then Exit;
  Count := AWRegistryProductTextCount + 2;
  if not AWReadRegistrationString(Key, 'Inno Setup: Setup Version', $30000002, 16, Compiler) or
     (Compiler <> '6.7.1') then Exit;
  if not AWReadRegistrationString(Key, 'InstallDate', $30000002, 8, Date) or
     (Length(Date) <> 8) or not AWNumeric(Date) then Exit;
  Count := Count + 2;
  Inventory := Compiler + #0 + Date + #0;
  Result :=
    AWLegacyRegistrationText(Key, 'Inno Setup: Icon Group', 260, True, Count, Inventory) and
    AWLegacyRegistrationText(Key, 'Inno Setup: User', 256, True, Count, Inventory) and
    AWLegacyRegistrationText(Key, 'Inno Setup: Language', 64, True, Count, Inventory) and
    AWLegacyRegistrationDWORD(Key, 'Inno Setup: No Icons', False, Count, Inventory) and
    AWLegacyRegistrationDWORD(Key, 'EstimatedSize', True, Count, Inventory) and
    AWLegacyRegistrationDWORD(Key, 'MajorVersion', False, Count, Inventory) and
    AWLegacyRegistrationDWORD(Key, 'MinorVersion', False, Count, Inventory) and
    AWLegacyRegistrationDWORD(Key, 'VersionMajor', False, Count, Inventory) and
    AWLegacyRegistrationDWORD(Key, 'VersionMinor', False, Count, Inventory) and
    (Count = Values);
end;

function AWStageLegacyRegistrationRetirement(Parent, Transaction: LongWord; const Name: String;
  const Fields: AWRegistryTextValues; const ExpectedInventory: String): Boolean;
var Key: LongWord; Inventory: String;
begin
  Result := False; Key := 0;
  if (Transaction = 0) or (ExpectedInventory = '') then Exit;
  try
    if AWOwnedRegistryOpenInNative(Parent, Name, AWOwnedRegistryOpenLink,
       $00030119 or $0100, Key, Transaction, 0) <> 0 then Exit;
    Result := AWLegacyRegistrationInventory(Key, Fields, Inventory) and
      (AWOrdinal(Inventory, ExpectedInventory) = 0) and (AWRegistryDeleteHeld(Key) = 0);
  finally
    if not AWOwnedRegistryClose(Key) then Result := False;
  end;
  if Result then Result := AWRegistryTransactedProductAbsent(Parent, Transaction, Name);
end;
