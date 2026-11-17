{ Short-lived local registration publication transaction. Closing the last
  uncommitted KTM handle rolls back. Never retry an uncertain commit or reuse
  a transacted key handle after the transaction ends. }

function AWRegistryTransactionCreate(Security, UOW, Options, Level, Flags,
  Milliseconds, Description: LongWord): LongWord;
  external 'CreateTransaction@ktmw32.dll stdcall';
function AWRegistryTransactionCommit(Transaction: LongWord): Integer;
  external 'CommitTransaction@ktmw32.dll stdcall';
function AWRegistryTransactionCloseNative(Transaction: LongWord): Integer;
  external 'CloseHandle@kernel32.dll stdcall';
function AWRegistrySetStringNative(Key: LongWord; const Name: String;
  Reserved, Kind: LongWord; const Data: String; Bytes: LongWord): LongWord;
  external 'RegSetValueExW@advapi32.dll stdcall';

function AWRegistrySetDWORDNative(Key: LongWord; const Name: String;
  Reserved, Kind: LongWord; var Data: LongWord; Bytes: LongWord): LongWord;
  external 'RegSetValueExW@advapi32.dll stdcall';
function AWRegistryReadDWORDNative(Key: LongWord; const Name: String;
  Reserved: LongWord; var Kind, Data, Bytes: LongWord): LongWord;
  external 'RegQueryValueExW@advapi32.dll stdcall';

function AWRegistryDeleteHeld(Key: LongWord): LongWord;
  external 'NtDeleteKey@ntdll.dll stdcall';

function AWRegistryTransactionBegin(var Transaction: LongWord): Boolean;
begin
  Transaction := 0;
  Result := False;
  if AWOwnedRegistryCleanupUncertain then Exit;
  { TRANSACTION_DO_NOT_PROMOTE, 15-second prepare deadline, noninheritable. }
  Transaction := AWRegistryTransactionCreate(0, 0, 1, 0, 0, 15000, 0);
  if Transaction = $FFFFFFFF then Transaction := 0;
  Result := Transaction <> 0;
end;

function AWRegistryTransactionClose(var Transaction: LongWord): Boolean;
begin
  Result := True;
  if Transaction = 0 then Exit;
  Result := AWRegistryTransactionCloseNative(Transaction) <> 0;
  Transaction := 0;
  if not Result then AWOwnedRegistryCleanupUncertain := True;
end;

function AWRegistryTransactionFinish(var Transaction, Key: LongWord;
  Publish: Boolean): Boolean;
var KeyClosed, TransactionClosed, Committed: Boolean;
begin
  KeyClosed := AWOwnedRegistryClose(Key);
  Committed := False;
  try
    if Publish and KeyClosed and (Transaction <> 0) and
       not AWOwnedRegistryCleanupUncertain then
      Committed := AWRegistryTransactionCommit(Transaction) <> 0;
  finally
    TransactionClosed := AWRegistryTransactionClose(Transaction);
  end;
  Result := KeyClosed and TransactionClosed and not AWOwnedRegistryCleanupUncertain and
    (Committed = Publish);
end;

const AWRegistryInnoAppPath = 'Inno Setup: App Path';

function AWRegistrySetString(Key: LongWord; const Name, Value: String): Boolean;
begin
  { The only supported product value whose name is not a child-key name. }
  Result := (Key <> 0) and ((Name = AWRegistryInnoAppPath) or AWOwnedRegistryChildName(Name)) and
    (Length(Value) > 0) and (Length(Value) <= 1024) and
    (Pos(#0, Value) = 0) and
    (AWRegistrySetStringNative(Key, Name, 0, 1, Value, (Length(Value) + 1) * 2) = 0);
end;

const AWRegistryProductTextCount = 9;

type AWRegistryTextValue = record
       Name, Value: String;
       Maximum: LongWord;
     end;
     AWRegistryTextValues = array of AWRegistryTextValue;

procedure AWRegistryTextField(var Field: AWRegistryTextValue; const Name, Value: String; Maximum: LongWord);
begin
  Field.Name := Name; Field.Value := Value; Field.Maximum := Maximum;
end;

function AWRegistryProductValues(const Version, Directory, Uninstaller: String;
  var Fields: AWRegistryTextValues): Boolean;
var Major, Minor, Patch, Pre, Location, Command: String; I: Integer;
begin
  Result := False;
  if not AWParse(Version, Major, Minor, Patch, Pre) then Exit;
  if (Length(Directory) < 4) or (Length(Directory) > 261) or
     (Length(Uninstaller) > 290) then Exit;
  if not (((Directory[1] >= 'A') and (Directory[1] <= 'Z')) or
          ((Directory[1] >= 'a') and (Directory[1] <= 'z'))) then Exit;
  if Copy(Directory, 2, 2) <> ':\' then Exit;
  for I := 1 to Length(Uninstaller) do
    if (Ord(Uninstaller[I]) < 32) or (Uninstaller[I] = '"') then Exit;
  Location := AddBackslash(Directory);
  if AWOrdinal(ExtractFilePath(Uninstaller), Location) <> 0 then Exit;
  if CompareText(ExtractFileExt(Uninstaller), '.exe') <> 0 then Exit;
  Command := '"' + Uninstaller + '"';
  SetArrayLength(Fields, AWRegistryProductTextCount);
  AWRegistryTextField(Fields[0], 'DisplayName', Copy('AccessWeaver version ' + Version, 1, 259), 259);
  AWRegistryTextField(Fields[1], 'DisplayVersion', Version, 256);
  AWRegistryTextField(Fields[2], 'InstallLocation', Location, 261);
  AWRegistryTextField(Fields[3], 'UninstallString', Command, 300);
  AWRegistryTextField(Fields[4], 'QuietUninstallString', Command + ' /SILENT', 300);
  AWRegistryTextField(Fields[5], 'DisplayIcon', Location + 'accessweaver.exe', 300);
  AWRegistryTextField(Fields[6], 'Publisher', 'AccessWeaver contributors', 64);
  AWRegistryTextField(Fields[7], 'URLInfoAbout', 'https://github.com/Yunushan/accessweaver', 128);
  AWRegistryTextField(Fields[8], AWRegistryInnoAppPath, RemoveBackslashUnlessRoot(Directory), 260);
  for I := 0 to GetArrayLength(Fields) - 1 do
    if Length(Fields[I].Value) > Fields[I].Maximum then Exit;
  Result := True;
end;

function AWRegistryDWORDIsOne(Key: LongWord; const Name: String): Boolean;
var Kind, Data, Bytes: LongWord;
begin
  Kind := 0; Data := 0; Bytes := 4;
  Result := (AWRegistryReadDWORDNative(Key, Name, 0, Kind, Data, Bytes) = 0) and
    (Kind = 4) and (Bytes = 4) and (Data = 1);
end;

function AWRegistryProductTextValuesMatch(Key: LongWord; const Fields: AWRegistryTextValues): Boolean;
var Actual: String; I: Integer;
begin
  Result := False;
  if (Key = 0) or (GetArrayLength(Fields) <> AWRegistryProductTextCount) then Exit;
  for I := 0 to GetArrayLength(Fields) - 1 do
    if not AWReadRegistrationString(Key, Fields[I].Name, $30000002, Fields[I].Maximum, Actual) or
       (AWOrdinal(Actual, Fields[I].Value) <> 0) then Exit;
  Result := True;
end;

function AWRegistryProductValuesMatch(Key: LongWord; const Fields: AWRegistryTextValues): Boolean;
var ClassBuffer: String;
    Characters, Children, Values: LongWord;
begin
  Result := False;
  if (Key = 0) or (GetArrayLength(Fields) <> AWRegistryProductTextCount) then Exit;
  SetLength(ClassBuffer, 128); Characters := 128; Children := 0; Values := 0;
  if AWOwnedRegistryQueryInfo(Key, ClassBuffer, Characters, 0, Children, 0, 0,
       Values, 0, 0, 0, 0) <> 0 then Exit;
  if (Children <> 0) or (Values <> AWRegistryProductTextCount + 2) then Exit;
  Result := AWRegistryProductTextValuesMatch(Key, Fields) and
    AWRegistryDWORDIsOne(Key, 'NoModify') and AWRegistryDWORDIsOne(Key, 'NoRepair');
end;

function AWRegistryStageProductValues(Key: LongWord; const Fields: AWRegistryTextValues): Boolean;
var I: Integer; One: LongWord;
begin
  Result := False;
  if (Key = 0) or (GetArrayLength(Fields) <> AWRegistryProductTextCount) then Exit;
  for I := 0 to GetArrayLength(Fields) - 1 do
    if not AWRegistrySetString(Key, Fields[I].Name, Fields[I].Value) then Exit;
  One := 1;
  Result := (AWRegistrySetDWORDNative(Key, 'NoModify', 0, 4, One, 4) = 0) and
    (AWRegistrySetDWORDNative(Key, 'NoRepair', 0, 4, One, 4) = 0) and
    AWRegistryProductValuesMatch(Key, Fields);
end;

{ Keep the pre-copy snapshot distinct from absence. Creation refuses any
  existing object. An update matches the exact previous fields inside KTM. }
function AWRegistryStageProductRegistration(Parent, Transaction: LongWord;
  const Name, ClassTag: String; const Prior, Candidate: AWRegistryTextValues;
  var Key: LongWord): Boolean;
var Created: Boolean;
begin
  Result := False; Key := 0;
  if Transaction = 0 then Exit;
  if GetArrayLength(Prior) = 0 then begin
    if not AWCreateOwnedRegistryChildIn(Parent, Transaction, Name, ClassTag, Key, Created) then Exit;
    if not Created then Exit;
  end else begin
    if not AWOpenOwnedRegistryChildIn(Parent, Transaction, Name, ClassTag, Key) then Exit;
    if not AWRegistryProductValuesMatch(Key, Prior) then Exit;
  end;
  Result := AWRegistryStageProductValues(Key, Candidate);
end;

function AWRegistryTransactedProductAbsent(Parent, Transaction: LongWord; const Name: String): Boolean;
var Key, Status: LongWord;
begin
  Key := 0;
  Status := AWOwnedRegistryOpenInNative(Parent, Name, AWOwnedRegistryOpenLink,
    $00020119 or $0100, Key, Transaction, 0);
  Result := (Status = 2) and (Key = 0);
  if not AWOwnedRegistryClose(Key) then Result := False;
end;

{ Stage removal only on the exact transacted handle. The caller must abort
  the transaction on any refusal, including unexpected post-delete readback. }
function AWRegistryStageProductRetirement(Parent, Transaction: LongWord;
  const Name, ClassTag: String; const Fields: AWRegistryTextValues): Boolean;
var Key: LongWord;
begin
  Result := False; Key := 0;
  if Transaction = 0 then Exit;
  if not AWOpenOwnedRegistryChildIn(Parent, Transaction, Name, ClassTag, Key) then Exit;
  try
    if AWRegistryProductValuesMatch(Key, Fields) then
      Result := AWRegistryDeleteHeld(Key) = 0;
  finally
    if not AWOwnedRegistryClose(Key) then Result := False;
  end;
  if Result then Result := AWRegistryTransactedProductAbsent(Parent, Transaction, Name);
end;
