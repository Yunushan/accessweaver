//go:build windows

package fileidentity

import (
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// OpenLocal acquires a read-only regular file through the local native namespace.
// Remote/device names, remote drive mappings and remote reparse targets refuse
// before a native open of their target. Local links retain FromPath semantics.
// The data handle is acquired relative to the retained parent, without following
// a substituted reparse point, and must match the inspected object identity.
// All metadata owners close successfully before the caller receives ownership.
// This admits a local file; it grants no permission or later pathname binding.
func OpenLocal(path string) (file *os.File, failure error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	handle := windows.InvalidHandle
	var owner windowsContext
	defer func() {
		if file == nil && handle != windows.InvalidHandle {
			if owner.close(handle) != nil {
				failure = ErrUnavailable
			}
		}
	}()
	_, err := inspectWindowsPath(path, true, func(context windowsContext, parent windows.Handle, name string, state State) error {
		owner = context
		var err error
		handle, err = context.openVerifiedRead(parent, name, state)
		return err
	})
	if err != nil {
		return nil, err
	}
	if handle == windows.InvalidHandle {
		return nil, ErrUnavailable
	}
	file = os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, ErrUnavailable
	}
	return file, nil
}

func (context windowsContext) openVerifiedRead(parent windows.Handle, name string, expected State) (result windows.Handle, failure error) {
	if expected.Kind != Regular {
		return windows.InvalidHandle, ErrUnavailable
	}
	handle, err := context.openAccess(parent, name, windows.FILE_GENERIC_READ)
	if err != nil {
		return windows.InvalidHandle, err
	}
	transferred := false
	defer func() {
		if !transferred && context.close(handle) != nil {
			result, failure = windows.InvalidHandle, ErrUnavailable
		}
	}()
	actual, err := context.state(handle)
	if err != nil || actual.Kind != Regular || actual.ID != expected.ID {
		return windows.InvalidHandle, ErrUnavailable
	}
	transferred = true
	return handle, nil
}
