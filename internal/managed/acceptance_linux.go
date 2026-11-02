//go:build linux && (amd64 || arm64)

package managed

import (
	"os"
	"syscall"
	"unsafe"
)

// exchangeLinuxDirectories is the atomic namespace primitive for publishing a
// policy and its acceptance record together. The transaction must validate both
// directory handles/layouts/preimages and hold the protected writer lock first.
// No copy/delete fallback is safe when the filesystem rejects RENAME_EXCHANGE.
func exchangeLinuxDirectories(parent *os.File, staged, current string) error {
	old, err := syscall.BytePtrFromString(staged)
	if err != nil {
		return err
	}
	next, err := syscall.BytePtrFromString(current)
	if err != nil {
		return err
	}
	_, _, code := syscall.Syscall6(linuxRenameat2, parent.Fd(), uintptr(unsafe.Pointer(old)), parent.Fd(), uintptr(unsafe.Pointer(next)), 2, 0)
	if code != 0 {
		return code
	}
	return nil
}
