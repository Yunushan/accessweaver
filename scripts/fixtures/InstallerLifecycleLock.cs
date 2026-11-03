using System;
using System.Threading;
// Hosted fixture only. Retain a handle after a thread exits owning the mutex,
// so the actual installer observes WAIT_ABANDONED rather than a new object.
public static class AccessWeaverLifecycleLockFixture {
    private static Mutex retained;
    public static void Abandon(string name) {
        if (retained != null) throw new InvalidOperationException("Fixture already exists");
        Exception failure = null;
        var thread = new Thread(() => {
            try {
                retained = new Mutex(false, name);
                if (!retained.WaitOne(0)) throw new InvalidOperationException("Fixture lock is busy");
                // Deliberately do not release ownership; thread exit abandons it.
            } catch (Exception error) { failure = error; }
        });
        thread.IsBackground = true;
        thread.Start();
        if (!thread.Join(10000)) throw new TimeoutException("Fixture owner did not terminate");
        if (failure != null) { Close(); throw new InvalidOperationException("Fixture failed", failure); }
    }
    public static void Close() {
        if (retained != null) { retained.Dispose(); retained = null; }
    }
}
