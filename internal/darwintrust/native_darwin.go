//go:build darwin && (amd64 || arm64)

package darwintrust

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// All symbols come from the fixed OS library. No caller/configuration selects a
// library, symbol, ABI or rename flags. Keep the handle for process life.
// Darwin SyscallN captures errno inside its maintained native trampoline before
// returning to Go; a later TLS read is unsafe even with LockOSThread because Go
// allocation/scheduling can use libc and change the same thread's errno.
type nativeAPI struct {
	library                                               uintptr
	aclGetFD                                              func(int32, int32) (uintptr, syscall.Errno)
	aclValid, aclFree, aclGetEntry, aclGetTag, aclGetMask uintptr
	aclInit, aclSetFD, aclGetFlags, aclAddFlag, rename    uintptr
}

var getNative = sync.OnceValues(loadNative)

func loadNative() (*nativeAPI, error) {
	handle, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("cannot load OS security APIs: %w", err)
	}
	api := &nativeAPI{library: handle}
	var getFD uintptr
	for _, symbol := range []struct {
		name   string
		target *uintptr
	}{
		{"acl_get_fd_np", &getFD}, {"acl_valid", &api.aclValid}, {"acl_free", &api.aclFree},
		{"acl_get_entry", &api.aclGetEntry}, {"acl_get_tag_type", &api.aclGetTag},
		{"acl_get_permset_mask_np", &api.aclGetMask}, {"acl_init", &api.aclInit},
		{"acl_set_fd_np", &api.aclSetFD}, {"acl_get_flagset_np", &api.aclGetFlags},
		{"acl_add_flag_np", &api.aclAddFlag}, {"renameatx_np", &api.rename},
	} {
		address, err := purego.Dlsym(handle, symbol.name)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("OS security API %s unavailable: %w", symbol.name, err), purego.Dlclose(handle))
		}
		*symbol.target = address
	}
	api.aclGetFD = func(fd, kind int32) (uintptr, syscall.Errno) {
		value, _, code := purego.SyscallN(getFD, uintptr(fd), uintptr(kind))
		// errno is a C int, even where a pointer-sized trampoline slot is used.
		return value, syscall.Errno(uint32(code))
	}
	return api, nil
}
func nativeError(operation string, code uintptr) error {
	errno := syscall.Errno(uint32(code))
	if errno == 0 {
		return fmt.Errorf("%s failed without an OS error", operation)
	}
	return fmt.Errorf("%s: %w", operation, errno)
}

const aclTypeExtended = 0x100
const aclAllow = 1
const aclDeny = 2

// Apple acl.h: read/list, execute/search, read attributes/xattrs/security and
// synchronize. Unknown or mutation rights on any allow ACE are not trusted.
const readOnlyACL = uint64(1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11 | 1<<20)

// Control pins the descriptor through native calls, including concurrent Close
// and finalizer activity. Error identity comes from each trampoline result.
func withNativeFD(file *os.File, operation func(*nativeAPI, int32) error) error {
	api, err := getNative()
	if err != nil {
		return err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	controlErr := raw.Control(func(fd uintptr) { result = operation(api, int32(fd)) })
	return errors.Join(result, controlErr)
}

// CheckReadOnlyACL rejects mutation/unknown allow rights on a held object.
// It permits read/search grants, so it is not a confidentiality check. Callers
// must separately verify ownership, POSIX permissions and object identity.
func CheckReadOnlyACL(file *os.File) error { return checkACL(file) }

func checkACL(file *os.File) error { return withNativeFD(file, checkACLWithRetry) }

// Only interrupted read-only inspections repeat. Persistent interruptions and
// all other errors remain blocking; writes/publication are not retried here.
func checkACLWithRetry(api *nativeAPI, fd int32) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = checkACLDescriptor(api, fd)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * time.Millisecond)
		}
	}
	return err
}
func checkACLDescriptor(api *nativeAPI, fd int32) (result error) {
	acl, code := api.aclGetFD(fd, aclTypeExtended)
	if acl == 0 {
		// Apple reports a missing FILESEC_ACL property as ENOENT on a held valid
		// descriptor. All POSIX/owner/type/link/local-APFS checks remain mandatory.
		if code == syscall.ENOENT {
			return nil
		}
		return nativeError("read extended ACL", uintptr(code))
	}
	defer func() {
		value, _, code := purego.SyscallN(api.aclFree, acl)
		if int32(value) != 0 {
			result = errors.Join(result, nativeError("free extended ACL", code))
		}
	}()
	value, _, errcode := purego.SyscallN(api.aclValid, acl)
	if int32(value) != 0 {
		return nativeError("validate extended ACL", errcode)
	}
	for index := 0; index <= 128; index++ {
		var entry uintptr
		value, _, code := purego.SyscallN(api.aclGetEntry, acl, uintptr(index), uintptr(unsafe.Pointer(&entry)))
		if int32(value) != 0 {
			// Apple's validated ACL getter reports the out-of-range entry as EINVAL.
			if syscall.Errno(uint32(code)) == syscall.EINVAL {
				return nil
			}
			return nativeError("read extended ACL entry", code)
		}
		if index == 128 {
			return errors.New("extended ACL exceeds 128 entries")
		}
		var tag int32
		value, _, code = purego.SyscallN(api.aclGetTag, entry, uintptr(unsafe.Pointer(&tag)))
		if int32(value) != 0 {
			return nativeError("read extended ACL tag", code)
		}
		if tag == aclDeny {
			continue
		}
		if tag != aclAllow {
			return errors.New("extended ACL has an unsupported entry type")
		}
		var mask uint64
		value, _, code = purego.SyscallN(api.aclGetMask, entry, uintptr(unsafe.Pointer(&mask)))
		if int32(value) != 0 {
			return nativeError("read extended ACL permissions", code)
		}
		if mask & ^readOnlyACL != 0 {
			return errors.New("extended ACL grants mutation or unknown permissions")
		}
	}
	return errors.New("extended ACL inspection did not terminate")
}

// ResetCreatedACL is only for new product objects created exclusively beneath
// a checked parent. Never change an existing administrator-owned object's ACL.
func ResetCreatedACL(file *os.File) error { return withNativeFD(file, resetCreatedDescriptorACL) }
func resetCreatedDescriptorACL(api *nativeAPI, fd int32) (result error) {
	acl, _, code := purego.SyscallN(api.aclInit, 0)
	if acl == 0 {
		return nativeError("create empty extended ACL", code)
	}
	defer func() {
		value, _, code := purego.SyscallN(api.aclFree, acl)
		if int32(value) != 0 {
			result = errors.Join(result, nativeError("free empty extended ACL", code))
		}
	}()
	// No-inherit prevents a publication rename restoring a removed read denial.
	var flags uintptr
	value, _, code := purego.SyscallN(api.aclGetFlags, acl, uintptr(unsafe.Pointer(&flags)))
	if int32(value) != 0 {
		return nativeError("read new ACL flags", code)
	}
	value, _, code = purego.SyscallN(api.aclAddFlag, flags, 1<<17)
	if int32(value) != 0 {
		return nativeError("disable new-object ACL inheritance", code)
	}
	value, _, code = purego.SyscallN(api.aclSetFD, uintptr(fd), acl, aclTypeExtended)
	if int32(value) != 0 {
		return nativeError("set new object extended ACL", code)
	}
	return nil
}

// RenameDirectories exposes only exclusive initial publication and atomic
// exchange. Its transaction caller must lock, check identities/preimages, sync
// and clean conservatively. There is no copy/delete fallback.
func RenameDirectories(parent *os.File, from, to string, exchange bool) error {
	if !validName(from) || !validName(to) || from == to {
		return errors.New("rename requires distinct single directory names")
	}
	flags := uintptr(unix.RENAME_EXCL)
	if exchange {
		flags = unix.RENAME_SWAP
	}
	fromPointer, err := unix.BytePtrFromString(from)
	if err != nil {
		return err
	}
	toPointer, err := unix.BytePtrFromString(to)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(fromPointer)
	defer runtime.KeepAlive(toPointer)
	return withNativeFD(parent, func(api *nativeAPI, fd int32) error {
		// Pointer conversions are direct SyscallN arguments. Its uintptrescapes
		// contract pins Go output/name allocations through the foreign call.
		value, _, code := purego.SyscallN(api.rename, uintptr(fd), uintptr(unsafe.Pointer(fromPointer)), uintptr(fd), uintptr(unsafe.Pointer(toPointer)), flags)
		if int32(value) != 0 {
			return nativeError("publish policy directory", code)
		}
		return nil
	})
}
