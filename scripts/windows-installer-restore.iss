{ The pinned Inno 6.7.1 engine is x86 on both payload targets.
  These Win32 records use explicit DWORD fields, including ABI padding. }
const AWRestorationDeadlineMilliseconds = 300000;
type
  TAWRestoreStartup = record
    Size, Reserved, Desktop, Title, X, Y, XSize, YSize, XChars, YChars, Fill, Flags, ShowAndReserved, Reserved2, StdIn, StdOut, StdErr: LongWord;
  end;
  TAWRestoreProcess = record
    Process, Thread, PID, TID: LongWord;
  end;
  TAWRestoreLimits = record
    ProcessTimeLo, ProcessTimeHi, JobTimeLo, JobTimeHi, Flags, MinimumWorkingSet, MaximumWorkingSet, ActiveProcessLimit, Affinity, PriorityClass, SchedulingClass, BasicPadding, ReadOpsLo, ReadOpsHi, WriteOpsLo, WriteOpsHi, OtherOpsLo, OtherOpsHi, ReadBytesLo, ReadBytesHi, WriteBytesLo, WriteBytesHi, OtherBytesLo, OtherBytesHi, ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory: LongWord;
  end;
  TAWRestoreAccounting = record
    UserTimeLo, UserTimeHi, KernelTimeLo, KernelTimeHi, PeriodUserLo, PeriodUserHi, PeriodKernelLo, PeriodKernelHi, PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses: LongWord;
  end;
  TAWRestoreMessage = record
    Window, Message, WParam, LParam, Time, X, Y, PrivateData: LongWord;
  end;

function AWCreateRestoreJob(Attributes, Name: LongWord): LongWord;
  external 'CreateJobObjectW@kernel32.dll stdcall';
function AWSetRestoreLimits(Job, Kind: LongWord; var Limits: TAWRestoreLimits; Bytes: LongWord): Integer;
  external 'SetInformationJobObject@kernel32.dll stdcall';
function AWQueryRestoreJob(Job, Kind: LongWord; var Accounting: TAWRestoreAccounting;
  Bytes: LongWord; var Returned: LongWord): Integer;
  external 'QueryInformationJobObject@kernel32.dll stdcall';
function AWCreateRestoreProcess(const Application: String; CommandLine: String;
  ProcessAttributes, ThreadAttributes: LongWord; Inherit: Integer;
  Flags, Environment: LongWord; const Directory: String;
  var Startup: TAWRestoreStartup; var Process: TAWRestoreProcess): Integer;
  external 'CreateProcessW@kernel32.dll stdcall';
function AWAssignRestoreJob(Job, Process: LongWord): Integer;
  external 'AssignProcessToJobObject@kernel32.dll stdcall';
function AWResumeRestoreThread(Thread: LongWord): LongWord;
  external 'ResumeThread@kernel32.dll stdcall';
function AWWaitRestoreProcess(Process, Milliseconds: LongWord): LongWord;
  external 'WaitForSingleObject@kernel32.dll stdcall';
function AWRestoreExitCode(Process: LongWord; var Code: LongWord): Integer;
  external 'GetExitCodeProcess@kernel32.dll stdcall';
function AWTerminateRestoreJob(Job, Code: LongWord): Integer;
  external 'TerminateJobObject@kernel32.dll stdcall';
function AWTerminateRestoreProcess(Process, Code: LongWord): Integer;
  external 'TerminateProcess@kernel32.dll stdcall';
function AWCloseRestoreHandle(Handle: LongWord): Integer;
  external 'CloseHandle@kernel32.dll stdcall';
function AWRestoreTicks: Int64;
  external 'GetTickCount64@kernel32.dll stdcall';
function AWRestoreLastError: LongWord;
  external 'GetLastError@kernel32.dll stdcall';
function AWPeekRestoreMessage(var Message: TAWRestoreMessage;
  Window, Minimum, Maximum, Remove: LongWord): Integer;
  external 'PeekMessageW@user32.dll stdcall';
function AWTranslateRestoreMessage(var Message: TAWRestoreMessage): Integer;
  external 'TranslateMessage@user32.dll stdcall';
function AWDispatchRestoreMessage(var Message: TAWRestoreMessage): LongInt;
  external 'DispatchMessageW@user32.dll stdcall';

function AWPumpRestoreMessages: Boolean;
var Message: TAWRestoreMessage; I: Integer;
begin
  Result := True;
  { A message flood must not starve the deadline check. }
  for I := 1 to 32 do begin
    if AWPeekRestoreMessage(Message, 0, 0, 0, 1) = 0 then Exit;
    if Message.Message = 18 then begin Result := False; Exit; end;
    AWTranslateRestoreMessage(Message);
    AWDispatchRestoreMessage(Message);
  end;
end;

function AWRunBoundedRestoration(const Executable, Parameters, Directory: String;
  const Milliseconds: LongWord; var Code: LongWord; var Failure: String): Boolean;
var Startup: TAWRestoreStartup; Process: TAWRestoreProcess;
    Limits: TAWRestoreLimits; Accounting: TAWRestoreAccounting;
    Job, Returned, WaitResult: LongWord; Assigned, RootExited, Completed: Boolean;
    Deadline, CleanupDeadline: Int64; CommandLine: String;
begin
  Result := False; Completed := False; Assigned := False; RootExited := False;
  Job := 0; Process.Process := 0; Process.Thread := 0; Process.PID := 0; Process.TID := 0;
  Code := 0; Failure := 'AccessWeaver system restoration could not start safely.';
  if (Milliseconds = 0) or (Milliseconds > AWRestorationDeadlineMilliseconds) then Exit;
  if (Executable = '') or (Pos('"', Executable) <> 0) then Exit;
  CommandLine := '"' + Executable + '" ' + Parameters;
  if Length(CommandLine) >= 32767 then Exit;
  Deadline := AWRestoreTicks + Milliseconds;
  Startup.Size := 68;
  Startup.Reserved := 0;
  Startup.Desktop := 0;
  Startup.Title := 0;
  Startup.X := 0;
  Startup.Y := 0;
  Startup.XSize := 0;
  Startup.YSize := 0;
  Startup.XChars := 0;
  Startup.YChars := 0;
  Startup.Fill := 0;
  Startup.Flags := 1;
  Startup.ShowAndReserved := 0;
  Startup.Reserved2 := 0;
  Startup.StdIn := 0;
  Startup.StdOut := 0;
  Startup.StdErr := 0;
  Limits.ProcessTimeLo := 0;
  Limits.ProcessTimeHi := 0;
  Limits.JobTimeLo := 0;
  Limits.JobTimeHi := 0;
  Limits.Flags := $00002000;
  Limits.MinimumWorkingSet := 0;
  Limits.MaximumWorkingSet := 0;
  Limits.ActiveProcessLimit := 0;
  Limits.Affinity := 0;
  Limits.PriorityClass := 0;
  Limits.SchedulingClass := 0;
  Limits.BasicPadding := 0;
  Limits.ReadOpsLo := 0;
  Limits.ReadOpsHi := 0;
  Limits.WriteOpsLo := 0;
  Limits.WriteOpsHi := 0;
  Limits.OtherOpsLo := 0;
  Limits.OtherOpsHi := 0;
  Limits.ReadBytesLo := 0;
  Limits.ReadBytesHi := 0;
  Limits.WriteBytesLo := 0;
  Limits.WriteBytesHi := 0;
  Limits.OtherBytesLo := 0;
  Limits.OtherBytesHi := 0;
  Limits.ProcessMemory := 0;
  Limits.JobMemory := 0;
  Limits.PeakProcessMemory := 0;
  Limits.PeakJobMemory := 0;
  try
    { Anonymous, non-inheritable job; never permit child breakaway. }
    Job := AWCreateRestoreJob(0, 0);
    if Job = 0 then begin Code := AWRestoreLastError; Exit; end;
    if AWSetRestoreLimits(Job, 9, Limits, 112) = 0 then begin Code := AWRestoreLastError; Exit; end;
    { Suspended until contained. A hidden new console provides valid standard
      console handles for the CLI without inheriting installer handles. }
    if AWCreateRestoreProcess(Executable, CommandLine, 0, 0, 0, $00000014,
      0, Directory, Startup, Process) = 0 then begin Code := AWRestoreLastError; Exit; end;
    if AWAssignRestoreJob(Job, Process.Process) = 0 then begin Code := AWRestoreLastError; Exit; end;
    Assigned := True;
    if AWResumeRestoreThread(Process.Thread) = $FFFFFFFF then begin Code := AWRestoreLastError; Exit; end;
    if AWCloseRestoreHandle(Process.Thread) = 0 then begin Code := AWRestoreLastError; Exit; end;
    Process.Thread := 0;
    Failure := 'AccessWeaver system restoration did not complete successfully.';
    while AWRestoreTicks < Deadline do begin
      if not AWPumpRestoreMessages then begin Failure := 'AccessWeaver system restoration was interrupted.'; Exit; end;
      if not RootExited then begin
        WaitResult := AWWaitRestoreProcess(Process.Process, 0);
        if WaitResult = 0 then begin
          if AWRestoreExitCode(Process.Process, Code) = 0 then begin Code := AWRestoreLastError; Exit; end;
          if AWCloseRestoreHandle(Process.Process) = 0 then begin Code := AWRestoreLastError; Exit; end;
          Process.Process := 0; RootExited := True;
          if Code <> 0 then Exit;
        end else if WaitResult <> $00000102 then begin Code := AWRestoreLastError; Exit; end;
      end;
      Returned := 0;
      if AWQueryRestoreJob(Job, 1, Accounting, 48, Returned) = 0 then begin Code := AWRestoreLastError; Exit; end;
      if Returned <> 48 then Exit;
      if RootExited and (Accounting.ActiveProcesses = 0) then begin
        Completed := True; Result := True; Failure := ''; Exit;
      end;
      Sleep(100);
    end;
    Code := 1460;
    Failure := 'AccessWeaver system restoration exceeded its five-minute deadline. Inspect the recovery journal before retrying.';
  finally
    { No failure path may allow file deletion. Terminate only the held owned
      process/job, never a process selected by an untrusted or reused PID. }
    if not Completed then begin
      CleanupDeadline := AWRestoreTicks + 5000;
      if Assigned then begin
        if AWTerminateRestoreJob(Job, 1460) = 0 then Log('AccessWeaver restoration job termination could not be confirmed.');
      end else if Process.Process <> 0 then begin
        if AWTerminateRestoreProcess(Process.Process, 1460) = 0 then Log('AccessWeaver suspended restoration process termination could not be confirmed.');
      end;
      if Process.Process <> 0 then begin
        if AWWaitRestoreProcess(Process.Process, 5000) <> 0 then Log('AccessWeaver restoration process exit could not be confirmed.');
        AWCloseRestoreHandle(Process.Process); Process.Process := 0;
      end;
      if Assigned then begin
        repeat
          Returned := 0;
          if AWQueryRestoreJob(Job, 1, Accounting, 48, Returned) = 0 then begin
            Log('AccessWeaver restoration process-group cleanup could not be inspected.'); Break;
          end;
          if (Returned = 48) and (Accounting.ActiveProcesses = 0) then Break;
          if AWRestoreTicks >= CleanupDeadline then begin
            Log('AccessWeaver restoration process-group exit could not be confirmed.'); Break;
          end;
          Sleep(50);
        until False;
      end;
    end;
    if Process.Thread <> 0 then AWCloseRestoreHandle(Process.Thread);
    if Process.Process <> 0 then AWCloseRestoreHandle(Process.Process);
    if Job <> 0 then begin
      { KILL_ON_JOB_CLOSE also covers unexpected owner termination. }
      if AWCloseRestoreHandle(Job) = 0 then begin
        Result := False;
        Failure := 'AccessWeaver restoration containment cleanup could not be confirmed.';
      end;
    end;
  end;
end;
