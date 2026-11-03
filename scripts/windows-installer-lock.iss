{ Inno Setup 6.7.1's verified bootstrap is x86 on both payload targets.
  Native handles therefore use its 32-bit LongWord ABI. }
var AWLifecycleHandle: LongWord;
    AWLifecycleOwned: Boolean;

function AWCreateLifecycleMutex(Attributes: LongWord; const Name: String;
  Flags, Access: LongWord): LongWord;
  external 'CreateMutexExW@kernel32.dll stdcall';
function AWWaitLifecycleMutex(Handle, Milliseconds: LongWord): LongWord;
  external 'WaitForSingleObject@kernel32.dll stdcall';
function AWReleaseNativeMutex(Handle: LongWord): Integer;
  external 'ReleaseMutex@kernel32.dll stdcall';
function AWCloseNativeHandle(Handle: LongWord): Integer;
  external 'CloseHandle@kernel32.dll stdcall';

procedure AWReleaseLifecycle;
begin
  if AWLifecycleHandle <> 0 then begin
    if AWLifecycleOwned then begin
      if AWReleaseNativeMutex(AWLifecycleHandle) = 0 then
        Log('AccessWeaver lifecycle mutex release failed; process exit must complete before retrying.');
      AWLifecycleOwned := False;
    end;
    if AWCloseNativeHandle(AWLifecycleHandle) = 0 then
      Log('AccessWeaver lifecycle mutex handle cleanup failed.');
    AWLifecycleHandle := 0;
  end;
end;

function AWAcquireLifecycle: String;
var WaitResult: LongWord;
begin
  Result := '';
  if AWLifecycleOwned then Exit;
  { No initial owner: every contender uses the same atomic zero-time wait.
    The handle is non-inheritable; children must never retain lifecycle ownership. }
  AWLifecycleHandle := AWCreateLifecycleMutex(0,
    'Global\AccessWeaver-Lifecycle-B13D4677-4660-4E63-B3DB-03077ACBB092',
    0, $00100001); { SYNCHRONIZE | MUTEX_MODIFY_STATE }
  if AWLifecycleHandle = 0 then begin
    Result := 'Could not open the AccessWeaver installation lock. Check machine permissions and retry.'; Exit;
  end;
  WaitResult := AWWaitLifecycleMutex(AWLifecycleHandle, 0);
  if WaitResult = 0 then begin AWLifecycleOwned := True; Exit; end;
  if WaitResult = $00000080 then begin
    { Ownership was transferred, but persistent state has not been proven safe. }
    AWLifecycleOwned := True;
    Result := 'A previous AccessWeaver lifecycle operation ended unexpectedly. Review installation and recovery records before retrying.';
  end else if WaitResult = $00000102 then
    Result := 'Another AccessWeaver installation or removal is active. Wait for it to finish, then retry.'
  else Result := 'Could not acquire the AccessWeaver installation lock. Review machine state and retry.';
  AWReleaseLifecycle;
end;
