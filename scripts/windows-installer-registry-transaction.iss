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

function AWRegistrySetString(Key: LongWord; const Name, Value: String): Boolean;
begin
  Result := (Key <> 0) and AWOwnedRegistryChildName(Name) and
    (Length(Value) > 0) and (Length(Value) <= 1024) and
    (Pos(#0, Value) = 0) and
    (AWRegistrySetStringNative(Key, Name, 0, 1, Value, (Length(Value) + 1) * 2) = 0);
end;
