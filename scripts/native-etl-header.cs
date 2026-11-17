// Private ETL header inspection only. No ProcessTrace or event-payload access.
// Win64 layout follows EVENT_TRACE_LOGFILEW / TRACE_LOGFILE_HEADER in evntrace.h.
using System;
using System.Runtime.InteropServices;
public sealed class AccessWeaverEtlHeaderResult {
    public string Code = "unavailable";
    public long EventsLost=-1, BuffersLost=-1, BufferSize=-1, BuffersWritten=-1,
                MaximumFileSize=-1, PointerSize=-1, LogFileMode=-1;
    public bool Finalized=false, Closed=false;
    public int NativeCode=-1;
}
public static class AccessWeaverPrivateEtlHeader {
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void RecordCallback(IntPtr ignored);
    // On native AMD64/ARM64: EVENT_TRACE=88, TRACE_LOGFILE_HEADER=280,
    // header begins at 120; trailing native callback/context pointers align to 8.
    [StructLayout(LayoutKind.Explicit, Size=448)]
    private struct LogFile {
        [FieldOffset(0)] public IntPtr FileName;
        [FieldOffset(8)] public IntPtr LoggerName;
        [FieldOffset(28)] public uint ProcessTraceMode;
        [FieldOffset(120)] public uint HeaderBufferSize;
        [FieldOffset(136)] public long EndTime;
        [FieldOffset(148)] public uint MaximumFileSize;
        [FieldOffset(152)] public uint LogFileMode;
        [FieldOffset(156)] public uint BuffersWritten;
        [FieldOffset(164)] public uint PointerSize;
        [FieldOffset(168)] public uint EventsLost;
        [FieldOffset(396)] public uint BuffersLost;
        [FieldOffset(424)] public IntPtr EventRecordCallback;
    }
    [DllImport("sechost.dll", EntryPoint="OpenTraceW", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern ulong OpenTrace(ref LogFile file);
    [DllImport("sechost.dll", ExactSpelling=true)]
    private static extern uint CloseTrace(ulong handle);
    private static int BoundedCode(long value) { return value>=0 && value<=65535 ? (int)value : -1; }
    public static AccessWeaverEtlHeaderResult Read(string path) {
        AccessWeaverEtlHeaderResult r=new AccessWeaverEtlHeaderResult();
        if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(LogFile))!=448) { r.Code="layout"; return r; }
        IntPtr name=IntPtr.Zero; ulong handle=ulong.MaxValue;
        RecordCallback callback=delegate(IntPtr ignored) {};
        try {
            name=Marshal.StringToHGlobalUni(path);
            LogFile file=new LogFile(); file.FileName=name;
            file.ProcessTraceMode=0x10000000;
            file.EventRecordCallback=Marshal.GetFunctionPointerForDelegate(callback);
            handle=OpenTrace(ref file);
            if(handle==ulong.MaxValue) { r.Code="open-failed"; r.NativeCode=BoundedCode(Marshal.GetLastWin32Error()); return r; }
            r.EventsLost=file.EventsLost; r.BuffersLost=file.BuffersLost;
            r.BufferSize=file.HeaderBufferSize; r.BuffersWritten=file.BuffersWritten;
            r.MaximumFileSize=file.MaximumFileSize; r.PointerSize=file.PointerSize;
            r.LogFileMode=file.LogFileMode; r.Finalized=file.EndTime!=0;
            r.NativeCode=0; r.Code="parsed";
        } finally {
            if(handle!=ulong.MaxValue) {
                uint code=CloseTrace(handle); r.Closed=code==0;
                if(code!=0) { r.Code="close-failed"; r.NativeCode=BoundedCode(code); }
            }
            if(name!=IntPtr.Zero) Marshal.FreeHGlobal(name);
            GC.KeepAlive(callback);
        }
        return r;
    }
}
