using System;
using System.IO;
using System.Runtime.InteropServices;

// Hosted-only independent error oracle. Never resume a returned process and
// never inherit workflow credentials/handles into an unexpectedly valid image.
public sealed class RestorationLaunchProbeResult {
    public bool Started;
    public int NativeError;
    public bool UnexpectedProcessStopped;
}
public static class InstallerRestorationLaunch {
    [StructLayout(LayoutKind.Sequential)]
    private struct Startup {
        public uint Size;
        public IntPtr Reserved, Desktop, Title;
        public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
        public ushort Show,ReservedBytes;
        public IntPtr Reserved2,StdIn,StdOut,StdErr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo {
        public IntPtr Process,Thread;
        public uint PID,TID;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
    private static extern bool CreateProcessW(string application, System.Text.StringBuilder command,
        IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags,
        IntPtr environment, string directory, ref Startup startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern uint WaitForSingleObject(IntPtr process,uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static RestorationLaunchProbeResult Probe(string executable) {
        executable=Path.GetFullPath(executable);
        if(executable.IndexOf('"')>=0) throw new ArgumentException("Unexpected fixture path");
        var startup=new Startup();startup.Size=(uint)Marshal.SizeOf(typeof(Startup));startup.Flags=1;
        var process=new ProcessInfo();bool created=false;
        var environment=GCHandle.Alloc(new char[]{'\0','\0'},GCHandleType.Pinned);
        var result=new RestorationLaunchProbeResult();
        try {
            created=CreateProcessW(executable,new System.Text.StringBuilder("\""+executable+"\""),
                IntPtr.Zero,IntPtr.Zero,false,0x00000414,environment.AddrOfPinnedObject(),Path.GetDirectoryName(executable),ref startup,out process);
            // CLR SetLastError caching captures the actual call's error before
            // marshaling or other managed/native work can replace it.
            int error=Marshal.GetLastWin32Error();
            result.Started=created;result.NativeError=created?0:error;
        } finally {
            if(created) {
                try {
                    result.UnexpectedProcessStopped=TerminateProcess(process.Process,1) && WaitForSingleObject(process.Process,5000)==0;
                } finally {
                    CloseHandle(process.Thread);CloseHandle(process.Process);
                }
            }
            environment.Free();
        }
        return result;
    }
}
