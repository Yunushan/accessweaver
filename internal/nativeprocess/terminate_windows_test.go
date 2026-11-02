//go:build windows

package nativeprocess

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeWindowsTerminationKillsOwnedTree(t *testing.T) {
	record := filepath.Join(t.TempDir(), "grandchild-pid")
	parent := exec.Command(os.Args[0], "-test.run=^TestNativeProcessHelper$", "--", "tree", record)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = parent.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = parent.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned tree fixture did not exit")
		}
	})
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(record); err == nil {
			pid, _ = strconv.Atoi(string(data))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("owned grandchild never became ready")
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.TerminateProcess(handle, 1); _ = windows.CloseHandle(handle) })
	_, unrelatedDone := sleepingProcess(t)
	if err := TerminateTree(parent.Process); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("owned parent survived native taskkill")
	}
	state, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("owned grandchild survived native taskkill: %d %v", state, err)
	}
	select {
	case <-unrelatedDone:
		t.Fatal("unrelated process terminated")
	default:
	}
}
