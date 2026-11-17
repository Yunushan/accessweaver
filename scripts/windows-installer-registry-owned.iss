{ Native registry ownership primitive for the pinned x86 Inno 6.7.1 runtime.
  Not yet wired into product registration. All children are single components
  of a caller-held parent. REG_OPTION_OPEN_LINK is used for both create/open,
  so an existing registry link must never redirect an operation to its target.
  A successful new creation returns an owned handle even if validation fails:
  the caller must close every nonzero output handle on every path. }

const AWOwnedRegistrySDDL = 'O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)';
      AWOwnedRegistryAccess = $000F013F; { KEY_ALL_ACCESS | WOW64_64KEY }
      AWOwnedRegistryOpenLink = $00000008;

type AWOwnedRegistrySecurity = record
       Length, Descriptor, Inherit: LongWord;
     end;

var AWOwnedRegistryCleanupUncertain: Boolean;

function AWOwnedRegistryCreateNative(Parent: LongWord; const Name: String;
  Reserved: LongWord; const ClassTag: String; Options, Access: LongWord;
  var Attributes: AWOwnedRegistrySecurity; var Key, Disposition: LongWord): LongWord;
  external 'RegCreateKeyExW@advapi32.dll stdcall';
function AWOwnedRegistryCreateInNative(Parent: LongWord; const Name: String;
  Reserved: LongWord; const ClassTag: String; Options, Access: LongWord;
  var Attributes: AWOwnedRegistrySecurity; var Key, Disposition: LongWord;
  Transaction, Extended: LongWord): LongWord;
  external 'RegCreateKeyTransactedW@advapi32.dll stdcall';
function AWOwnedRegistryOpenInNative(Parent: LongWord; const Name: String;
  Options, Access: LongWord; var Key: LongWord; Transaction, Extended: LongWord): LongWord;
  external 'RegOpenKeyTransactedW@advapi32.dll stdcall';
function AWOwnedRegistryOpenNative(Parent: LongWord; const Name: String;
  Options, Access: LongWord; var Key: LongWord): LongWord;
  external 'RegOpenKeyExW@advapi32.dll stdcall';
function AWOwnedRegistryCloseNative(Key: LongWord): LongWord;
  external 'RegCloseKey@advapi32.dll stdcall';
function AWOwnedRegistryQueryInfo(Key: LongWord; ClassText: String;
  var Characters: LongWord; Reserved: LongWord; var Children: LongWord;
  MaxChildName, MaxChildClass: LongWord; var Values: LongWord;
  MaxValueName, MaxValueBytes, SecurityBytes, LastWrite: LongWord): LongWord;
  external 'RegQueryInfoKeyW@advapi32.dll stdcall';
function AWOwnedRegistryQueryValue(Key: LongWord; const Name: String;
  Reserved: LongWord; var Kind: LongWord; Data: LongWord; var Bytes: LongWord): LongWord;
  external 'RegQueryValueExW@advapi32.dll stdcall';
function AWOwnedRegistryGetSecurity(Key, ObjectType, Information: LongWord;
  var Owner, Group, DACL, SACL, Descriptor: LongWord): LongWord;
  external 'GetSecurityInfo@advapi32.dll stdcall';
function AWOwnedRegistryParseSD(const Text: String; Revision: LongWord;
  var Descriptor, Bytes: LongWord): Integer;
  external 'ConvertStringSecurityDescriptorToSecurityDescriptorW@advapi32.dll stdcall';
function AWOwnedRegistryFormatSD(Descriptor, Revision, Information: LongWord;
  var Text, Characters: LongWord): Integer;
  external 'ConvertSecurityDescriptorToStringSecurityDescriptorW@advapi32.dll stdcall';
function AWOwnedRegistryCopyText(Destination: String; Source, Characters: LongWord): LongWord;
  external 'lstrcpynW@kernel32.dll stdcall';
function AWOwnedRegistryLocalFree(Memory: LongWord): LongWord;
  external 'LocalFree@kernel32.dll stdcall';

function AWOwnedRegistryFree(var Memory: LongWord): Boolean;
begin
  Result := True;
  if Memory = 0 then Exit;
  Result := AWOwnedRegistryLocalFree(Memory) = 0;
  Memory := 0;
  if not Result then AWOwnedRegistryCleanupUncertain := True;
end;

function AWOwnedRegistryClose(var Key: LongWord): Boolean;
begin
  Result := True;
  if Key = 0 then Exit;
  Result := AWOwnedRegistryCloseNative(Key) = 0;
  Key := 0;
  if not Result then AWOwnedRegistryCleanupUncertain := True;
end;

function AWOwnedRegistryChildName(const Name: String): Boolean;
var I: Integer;
begin
  Result := False;
  if (Length(Name) < 1) or (Length(Name) > 128) or (Name = '.') or (Name = '..') then Exit;
  for I := 1 to Length(Name) do
    if not (((Name[I] >= 'a') and (Name[I] <= 'z')) or
       ((Name[I] >= 'A') and (Name[I] <= 'Z')) or
       ((Name[I] >= '0') and (Name[I] <= '9')) or
       (Pos(Name[I], '{}._-') <> 0)) then Exit;
  Result := True;
end;

function AWOwnedRegistryClassTag(const Value: String): Boolean;
var I: Integer;
begin
  Result := False;
  if (Length(Value) <> 73) or (Copy(Value, 1, 9) <> 'AWReg-v1:') then Exit;
  for I := 10 to Length(Value) do
    if not (((Value[I] >= '0') and (Value[I] <= '9')) or
       ((Value[I] >= 'a') and (Value[I] <= 'f'))) then Exit;
  Result := True;
end;

function AWOwnedRegistrySDText(Descriptor: LongWord; var Text: String): Boolean;
var Memory, Characters: LongWord; Buffer: String;
begin
  Result := False; Text := ''; Memory := 0; Characters := 0;
  try
    if AWOwnedRegistryFormatSD(Descriptor, 1, $00000005, Memory, Characters) = 0 then Exit;
    if (Memory = 0) or (Characters < 2) or (Characters > 512) then Exit;
    SetLength(Buffer, Characters);
    if AWOwnedRegistryCopyText(Buffer, Memory, Characters) = 0 then Exit;
    if Buffer[Characters] <> #0 then Exit;
    Text := Copy(Buffer, 1, Characters - 1);
    Result := Pos(#0, Text) = 0;
  finally
    if not AWOwnedRegistryFree(Memory) then Result := False;
  end;
end;

function AWOwnedRegistryDescriptor(Key: LongWord): Boolean;
var Actual, Expected, Owner, Group, DACL, SACL, Bytes: LongWord;
    ActualText, ExpectedText: String;
begin
  Result := False; Actual := 0; Expected := 0; Bytes := 0;
  Owner := 0; Group := 0; DACL := 0; SACL := 0;
  try
    if AWOwnedRegistryGetSecurity(Key, 4, $00000005, Owner, Group, DACL, SACL, Actual) <> 0 then Exit;
    if (Owner = 0) or (DACL = 0) or (Actual = 0) then Exit;
    if AWOwnedRegistryParseSD(AWOwnedRegistrySDDL, 1, Expected, Bytes) = 0 then Exit;
    if Expected = 0 then Exit;
    { Both descriptors use the same native formatter: compare protected DACL,
      owner, exact principals/rights and ACE order without interpreting display
      names, expanding groups or accepting an inherited writer. }
    Result := AWOwnedRegistrySDText(Actual, ActualText) and
      AWOwnedRegistrySDText(Expected, ExpectedText) and (ActualText = ExpectedText);
  finally
    if not AWOwnedRegistryFree(Actual) then Result := False;
    if not AWOwnedRegistryFree(Expected) then Result := False;
  end;
end;

function AWOwnedRegistryHeld(Key: LongWord; const ClassTag: String): Boolean;
var Buffer: String; Characters, Children, Values, Kind, Bytes, Status: LongWord;
begin
  Result := False;
  if (Key = 0) or AWOwnedRegistryCleanupUncertain or not AWOwnedRegistryClassTag(ClassTag) then Exit;
  if not AWOwnedRegistryDescriptor(Key) then Exit;
  SetLength(Buffer, 128); Characters := 128; Children := 0; Values := 0;
  if AWOwnedRegistryQueryInfo(Key, Buffer, Characters, 0, Children, 0, 0,
       Values, 0, 0, 0, 0) <> 0 then Exit;
  if (Characters <> 73) or (Buffer[Characters + 1] <> #0) or
     (Copy(Buffer, 1, Characters) <> ClassTag) or (Children <> 0) or (Values > 32) then Exit;
  Kind := 0; Bytes := 0;
  Status := AWOwnedRegistryQueryValue(Key, 'SymbolicLinkValue', 0, Kind, 0, Bytes);
  { Any link value or ambiguous query fails, including malformed link data. }
  Result := (Status = 2) and not AWOwnedRegistryCleanupUncertain;
end;

function AWCreateOwnedRegistryChildIn(Parent, Transaction: LongWord; const Name, ClassTag: String;
  var Key: LongWord; var Created: Boolean): Boolean;
var Descriptor, Bytes, RawKey, Disposition, Status: LongWord; Attributes: AWOwnedRegistrySecurity;
begin
  Result := False; Key := 0; Created := False;
  Descriptor := 0; Bytes := 0; RawKey := 0; Disposition := 0;
  if (Parent = 0) or AWOwnedRegistryCleanupUncertain or
     not AWOwnedRegistryChildName(Name) or not AWOwnedRegistryClassTag(ClassTag) then Exit;
  try
    if AWOwnedRegistryParseSD(AWOwnedRegistrySDDL, 1, Descriptor, Bytes) = 0 then Exit;
    if Descriptor = 0 then Exit;
    Attributes.Length := 12; Attributes.Descriptor := Descriptor; Attributes.Inherit := 0;
    if Transaction = 0 then
      Status := AWOwnedRegistryCreateNative(Parent, Name, 0, ClassTag, AWOwnedRegistryOpenLink,
        AWOwnedRegistryAccess, Attributes, RawKey, Disposition)
    else
      Status := AWOwnedRegistryCreateInNative(Parent, Name, 0, ClassTag, AWOwnedRegistryOpenLink,
        AWOwnedRegistryAccess, Attributes, RawKey, Disposition, Transaction, 0);
    if Status <> 0 then Exit;
    if (RawKey = 0) or (Disposition <> 1) then Exit;
    Created := True; Key := RawKey; RawKey := 0;
    Result := AWOwnedRegistryHeld(Key, ClassTag);
  finally
    if not AWOwnedRegistryClose(RawKey) then Result := False;
    if not AWOwnedRegistryFree(Descriptor) then Result := False;
  end;
end;

function AWOpenOwnedRegistryChildIn(Parent, Transaction: LongWord; const Name, ClassTag: String;
  var Key: LongWord): Boolean;
var RawKey, Status: LongWord;
begin
  Result := False; Key := 0; RawKey := 0;
  if (Parent = 0) or AWOwnedRegistryCleanupUncertain or
     not AWOwnedRegistryChildName(Name) or not AWOwnedRegistryClassTag(ClassTag) then Exit;
  try
    if Transaction = 0 then
      Status := AWOwnedRegistryOpenNative(Parent, Name, AWOwnedRegistryOpenLink,
        AWOwnedRegistryAccess, RawKey)
    else
      Status := AWOwnedRegistryOpenInNative(Parent, Name, AWOwnedRegistryOpenLink,
        AWOwnedRegistryAccess, RawKey, Transaction, 0);
    if Status <> 0 then Exit;
    if not AWOwnedRegistryHeld(RawKey, ClassTag) then Exit;
    Key := RawKey; RawKey := 0; Result := True;
  finally
    if not AWOwnedRegistryClose(RawKey) then Result := False;
  end;
end;

function AWCreateOwnedRegistryChild(Parent: LongWord; const Name, ClassTag: String;
  var Key: LongWord; var Created: Boolean): Boolean;
begin
  Result := AWCreateOwnedRegistryChildIn(Parent, 0, Name, ClassTag, Key, Created);
end;

function AWOpenOwnedRegistryChild(Parent: LongWord; const Name, ClassTag: String;
  var Key: LongWord): Boolean;
begin
  Result := AWOpenOwnedRegistryChildIn(Parent, 0, Name, ClassTag, Key);
end;
