//go:build windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openPrivateAtTestDirectory(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, errors.Join(errPrivateCreateAt, windows.CloseHandle(handle))
	}
	return file, nil
}
func checkPrivateAtTestFile(t *testing.T, file *os.File) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	owner, err := historyExportProcessSID()
	if err != nil {
		t.Fatal("current fixture identity unavailable")
	}
	connection, err := file.SyscallConn()
	if err != nil {
		t.Fatal("owned child fixture unavailable")
	}
	var checkErr error
	err = connection.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		_, info, stateErr := privateAtWindowsState(handle, false)
		if stateErr != nil || info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow != 0 {
			checkErr = errPrivateCreateAt
			return
		}
		descriptor, descriptorErr := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if descriptorErr != nil || checkHistoryExportDescriptor(descriptor, owner) != nil {
			checkErr = errPrivateCreateAt
		}
	})
	if err != nil || checkErr != nil {
		t.Fatal("relative child DACL was not private before payload write")
	}
}

func TestPrivateFileCreateAtWindowsRejectsInheritedPublicReadBeforePayload(t *testing.T) {
	runtime.LockOSThread()
	owner, err := historyExportProcessSID()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal("fixture owner unavailable")
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;OICI;FA;;;" + owner + ")(A;OICI;FA;;;SY)(A;OICI;GRGX;;;WD)")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal("fixture descriptor unavailable")
	}
	path := filepath.Join(t.TempDir(), "inheritable-public-parent")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal("fixture parent name unavailable")
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	err = windows.CreateDirectory(name, &attrs)
	runtime.KeepAlive(descriptor)
	runtime.UnlockOSThread()
	if err != nil {
		t.Fatal("fresh public parent fixture unavailable")
	}
	parent := createAtTestParent(t, path)
	file, err := CreateAt(parent, "private.awbackup")
	if err != nil {
		t.Fatal("private child creation under public parent failed")
	}
	finishPrivateAtTestFile(t, file, []byte("inert private DACL fixture"))
}
