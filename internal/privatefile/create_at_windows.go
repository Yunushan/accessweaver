//go:build windows

package privatefile

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type privateAtWindowsID struct {
	Volume uint64
	FileID [16]byte
}

func privateAtWindowsState(handle windows.Handle, directory bool) (privateAtWindowsID, windows.ByHandleFileInformation, error) {
	var id privateAtWindowsID
	var info windows.ByHandleFileInformation
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return id, info, errors.Join(errPrivateCreateAt, err)
	}
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return id, info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return id, info, errPrivateCreateAt
	}
	if err = windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return id, info, err
	}
	if id.FileID == ([16]byte{}) {
		return id, info, errPrivateCreateAt
	}
	return id, info, nil
}

func privateAtWindowsOpen(parent windows.Handle, name string, access, share, disposition uint32, descriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	handle := windows.InvalidHandle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(objectName)
	runtime.KeepAlive(descriptor)
	if err != nil || handle == 0 || handle == windows.InvalidHandle || status.Status != 0 || (disposition == windows.FILE_CREATE && status.Information != 2) || (disposition == windows.FILE_OPEN && status.Information != 1) {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			err = errors.Join(err, os.ErrExist)
		}
		if handle != 0 && handle != windows.InvalidHandle {
			err = errors.Join(err, windows.CloseHandle(handle))
		}
		return windows.InvalidHandle, errors.Join(errPrivateCreateAt, err)
	}
	return handle, nil
}

// CreateAt creates relative to the actual borrowed directory, with a protected
// user+SYSTEM DACL supplied atomically. No parent pathname is reconstructed.
// Verification failure may retain a newly created empty file; it is never removed.
func CreateAt(parent *os.File, name string) (file *os.File, failure error) {
	if err := privateCreateAtParent(parent, name); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	owner, err := historyExportProcessSID()
	if err != nil {
		return nil, privateCreateAtFailure(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)")
	if err != nil || checkHistoryExportDescriptor(descriptor, owner) != nil {
		return nil, privateCreateAtFailure(errors.Join(errPrivateCreateAt, err))
	}
	connection, err := parent.SyscallConn()
	if err != nil {
		return nil, privateCreateAtFailure(err)
	}
	handle := windows.InvalidHandle
	defer func() {
		if handle != 0 && handle != windows.InvalidHandle {
			failure = privateCreateAtFailure(errors.Join(failure, windows.CloseHandle(handle)))
			file = nil
		}
	}()
	var operationErr error
	controlErr := connection.Control(func(parentFD uintptr) {
		parentHandle := windows.Handle(parentFD)
		before, _, err := privateAtWindowsState(parentHandle, true)
		if err != nil {
			operationErr = err
			return
		}
		handle, err = privateAtWindowsOpen(parentHandle, name, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0, windows.FILE_CREATE, descriptor)
		if err != nil {
			operationErr = err
			return
		}
		id, info, err := privateAtWindowsState(handle, false)
		if err != nil || info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow != 0 {
			operationErr = errors.Join(errPrivateCreateAt, err)
			return
		}
		observed, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || checkHistoryExportDescriptor(observed, owner) != nil {
			operationErr = errors.Join(errPrivateCreateAt, err)
			return
		}
		// Metadata-only lookup uses the same held parent and cannot traverse an alias.
		probe, err := privateAtWindowsOpen(parentHandle, name, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, nil)
		if err != nil {
			operationErr = err
			return
		}
		namedID, named, stateErr := privateAtWindowsState(probe, false)
		closeErr := windows.CloseHandle(probe)
		if stateErr != nil || closeErr != nil || namedID != id || named.NumberOfLinks != 1 || named.FileSizeHigh != 0 || named.FileSizeLow != 0 {
			operationErr = errors.Join(errPrivateCreateAt, stateErr, closeErr)
			return
		}
		after, _, err := privateAtWindowsState(parentHandle, true)
		if err != nil || before != after {
			operationErr = errors.Join(errPrivateCreateAt, err)
			return
		}
		currentOwner, err := historyExportProcessSID()
		if err != nil || currentOwner != owner {
			operationErr = errors.Join(errPrivateCreateAt, err)
		}
	})
	if controlErr != nil || operationErr != nil {
		return nil, privateCreateAtFailure(errors.Join(controlErr, operationErr))
	}
	file = os.NewFile(uintptr(handle), name)
	if file == nil {
		return nil, privateCreateAtFailure(nil)
	}
	handle = windows.InvalidHandle
	return file, nil
}
