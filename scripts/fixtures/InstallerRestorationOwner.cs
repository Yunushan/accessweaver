using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

// Disposable hosted observer only. It signals exactly one verified live
// uninstaller clone; the root/child handles deliberately lack terminate rights.
[DataContract]
public sealed class RestorationProcessIdentity {
    [DataMember(Name="pid", IsRequired=true)] public int PID;
    [DataMember(Name="created", IsRequired=true)] public ulong Created;
}
[DataContract]
public sealed class RestorationOwnerObservation {
    [DataMember(Name="mode", IsRequired=true)] public string Mode;
    [DataMember(Name="owner", IsRequired=true)] public RestorationProcessIdentity Owner;
    [DataMember(Name="root", IsRequired=true)] public RestorationProcessIdentity Root;
    [DataMember(Name="child", IsRequired=true)] public RestorationProcessIdentity Child;
}
public sealed class RestorationOwnerResult {
    public bool Passed;
    public string Stage = "awaiting-ready";
    public bool OwnerImageVerified;
    public bool RootAndChildImagesVerified;
    public bool CreationTimesVerified;
    public bool OnlyOwnerSignaled;
    public uint OwnerExitCode;
    public bool OwnerExitConfirmed;
    public bool RootExitConfirmed;
    public bool ChildExitConfirmed;
    public long CleanupMilliseconds;
}
public sealed class InstallerRestorationOwner : IDisposable {
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime { public uint Low, High; }
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern SafeWaitHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetProcessTimes(SafeWaitHandle process, out NativeFileTime created,
        out NativeFileTime exited, out NativeFileTime kernel, out NativeFileTime user);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
    private static extern bool QueryFullProcessImageNameW(SafeWaitHandle process, uint flags, StringBuilder path, ref uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetExitCodeProcess(SafeWaitHandle process, out uint code);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool TerminateProcess(SafeWaitHandle process, uint code);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern uint WaitForSingleObject(SafeWaitHandle process, uint milliseconds);

    private readonly string ready, core, coreHash, ownerHash, privateTemp;
    private readonly ManualResetEvent cancel = new ManualResetEvent(false);
    private readonly Thread thread;
    private readonly RestorationOwnerResult result = new RestorationOwnerResult();

    public InstallerRestorationOwner(string readyFile, string coreFile, string fixtureHash,
        string uninstallerHash, string tempDirectory) {
        ready=Path.GetFullPath(readyFile);core=Path.GetFullPath(coreFile);
        coreHash=fixtureHash;ownerHash=uninstallerHash;
        privateTemp=Path.GetFullPath(tempDirectory).TrimEnd('\\')+"\\";
        GuardPath(Path.GetDirectoryName(ready));GuardPath(core);GuardPath(tempDirectory);
        if(File.Exists(ready)) throw new InvalidOperationException("Observer destination already exists");
        thread=new Thread(Observe);thread.IsBackground=true;thread.Start();
    }
    private static void Require(bool valid) {
        if(!valid) throw new InvalidOperationException("Owned restoration observation failed");
    }
    private static void GuardPath(string path) {
        for(string item=Path.GetFullPath(path);!String.IsNullOrEmpty(item);item=Path.GetDirectoryName(item)) {
            Require((File.GetAttributes(item)&FileAttributes.ReparsePoint)==0);
        }
    }
    private static string Hash(string path) {
        GuardPath(path);
        using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete)) {
            Require(input.Length>0 && input.Length<=32*1024*1024);
            using(var hash=SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(input)).Replace("-","").ToLowerInvariant();
        }
    }
    private static SafeWaitHandle Open(RestorationProcessIdentity identity, bool terminate) {
        Require(identity!=null && identity.PID>0 && identity.Created>0);
        var handle=OpenProcess(0x00101000u|(terminate?1u:0u),false,(uint)identity.PID);
        if(handle==null || handle.IsInvalid) {if(handle!=null)handle.Dispose();throw new InvalidOperationException("Owned process could not be opened");}
        try {
            NativeFileTime created,exited,kernel,user;uint code;
            Require(GetProcessTimes(handle,out created,out exited,out kernel,out user));
            Require((((ulong)created.High<<32)|created.Low)==identity.Created);
            Require(GetExitCodeProcess(handle,out code) && code==259);
            return handle;
        } catch {handle.Dispose();throw;}
    }
    private static string Image(SafeWaitHandle handle) {
        var path=new StringBuilder(32768);uint size=32768;
        Require(QueryFullProcessImageNameW(handle,0,path,ref size) && size>0 && size<32768);
        return Path.GetFullPath(path.ToString());
    }
    private RestorationOwnerObservation ReadReady() {
        var deadline=Stopwatch.StartNew();
        while(deadline.ElapsedMilliseconds<20000 && !cancel.WaitOne(25)) {
            if(!File.Exists(ready)) continue;
            try {
                GuardPath(ready);
                using(var input=new FileStream(ready,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)) {
                    if(input.Length==0) continue;
                    Require(input.Length<=4096);
                    var serializer=new DataContractJsonSerializer(typeof(RestorationOwnerObservation));
                    return (RestorationOwnerObservation)serializer.ReadObject(input);
                }
            } catch(SerializationException) { /* Writer may still be completing its single bounded record. */ }
        }
        throw new TimeoutException("Owned restoration readiness was not observed");
    }
    private void Observe() {
        try {
            var data=ReadReady();
            result.Stage="identities";
            Require(data!=null && data.Mode=="owner-termination-with-child");
            Require(data.Owner!=null && data.Root!=null && data.Child!=null);
            Require(data.Owner.PID!=Process.GetCurrentProcess().Id && data.Owner.PID!=data.Root.PID && data.Owner.PID!=data.Child.PID && data.Root.PID!=data.Child.PID);
            Require(data.Owner.Created<=data.Root.Created && data.Root.Created<=data.Child.Created);
            using(var owner=Open(data.Owner,true))
            using(var root=Open(data.Root,false))
            using(var child=Open(data.Child,false)) {
                result.CreationTimesVerified=true;
                result.Stage="owner-image";
                string ownerImage=Image(owner);
                Require(ownerImage.StartsWith(privateTemp,StringComparison.OrdinalIgnoreCase) && String.Equals(Path.GetFileName(ownerImage),"_unins.tmp",StringComparison.OrdinalIgnoreCase));
                Require(Hash(ownerImage)==ownerHash);result.OwnerImageVerified=true;
                result.Stage="fixture-images";
                Require(String.Equals(Image(root),core,StringComparison.OrdinalIgnoreCase) && String.Equals(Image(child),core,StringComparison.OrdinalIgnoreCase));
                Require(Hash(core)==coreHash);result.RootAndChildImagesVerified=true;
                Require(!cancel.WaitOne(0));
                result.Stage="terminate-owner";
                Require(TerminateProcess(owner,167));result.OnlyOwnerSignaled=true;
                var cleanup=Stopwatch.StartNew();
                result.OwnerExitConfirmed=WaitForSingleObject(owner,5000)==0;
                uint code=0;
                Require(result.OwnerExitConfirmed && GetExitCodeProcess(owner,out code));result.OwnerExitCode=code;
                result.Stage="descendant-exit";
                result.RootExitConfirmed=WaitForSingleObject(root,5000)==0;
                result.ChildExitConfirmed=WaitForSingleObject(child,5000)==0;
                result.CleanupMilliseconds=cleanup.ElapsedMilliseconds;
                Require(code==167 && result.RootExitConfirmed && result.ChildExitConfirmed);
                result.Stage="complete";result.Passed=true;
            }
        } catch { /* Retain only the fixed stage and bounded public observations. */ }
    }
    public RestorationOwnerResult Complete() {
        if(!thread.Join(40000)) {cancel.Set();throw new TimeoutException("Owned restoration observer did not finish");}
        return result;
    }
    public void Dispose() {
        cancel.Set();
        if(thread.Join(5000)) cancel.Dispose();
    }
}
