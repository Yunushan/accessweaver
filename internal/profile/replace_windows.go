//go:build windows

package profile

import (
	"syscall"
	"unsafe"
)

// MoveFileExW allows atomic replacement of an existing profile on Windows.
// Unlike deleting the destination first, this avoids a missing-profile gap.
const moveFileReplaceExisting = 0x1
const moveFileWriteThrough = 0x8

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var moveFileEx = kernel32.NewProc("MoveFileExW")

func replaceFile(src, dst string) error {
	s, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	d, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	ok, _, callErr := moveFileEx.Call(uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(d)), moveFileReplaceExisting|moveFileWriteThrough)
	if ok != 0 {
		return nil
	}
	return callErr
}
