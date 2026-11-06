//go:build windows

package privatefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Only fresh test-owned files and the current process token are inspected. No
// account/profile/policy/service changes or external executables are involved.
func TestPrivateFileWindowsCreation(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	owner, err := historyExportProcessSID()
	if err != nil {
		t.Fatal("current process principal unavailable")
	}
	path := filepath.Join(t.TempDir(), "private-record.bin")
	file, err := Create(path)
	if err != nil {
		t.Fatal("private export creation failed")
	}
	closed := false
	defer func() {
		if !closed {
			if file.Close() != nil {
				t.Error("owned export handle close failed")
			}
		}
	}()
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || checkHistoryExportDescriptor(sd, owner) != nil {
		t.Fatal("created export did not retain exact protected user/SYSTEM grants")
	}
	var flags uint32
	getHandleInformation := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")
	ok, _, _ := getHandleInformation.Call(file.Fd(), uintptr(unsafe.Pointer(&flags)))
	runtime.KeepAlive(file)
	if ok == 0 || flags&windows.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("export handle was inheritable")
	}
	data := []byte("private source fixture bytes")
	if n, err := file.Write(data); err != nil || n != len(data) {
		t.Fatal("owned export write failed")
	}
	if file.Sync() != nil {
		t.Fatal("owned export sync failed")
	}
	closed = true
	if file.Close() != nil {
		t.Fatal("owned export close failed")
	}
	before, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, data) {
		t.Fatal("owned export bytes unavailable")
	}
	existing, err := Create(path)
	if existing != nil {
		_ = existing.Close()
		t.Fatal("existing destination was opened")
	}
	if err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatal("existing destination was not exclusively refused")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing destination bytes changed")
	}
}
