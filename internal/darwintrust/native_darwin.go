//go:build darwin && (amd64 || arm64)

package darwintrust

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// All symbols come from the fixed OS library. No caller or configuration can
// choose a library, symbol, ABI or rename flags. Keep the handle for process life.
type nativeAPI struct {
	library     uintptr
	errno       func() *int32
	aclGetFD    func(int32, int32) uintptr
	aclValid    func(uintptr) int32
	aclFree     func(uintptr) int32
	aclGetEntry func(uintptr, int32, *uintptr) int32
	aclGetTag   func(uintptr, *int32) int32
	aclGetMask  func(uintptr, *uint64) int32
	aclInit     func(int32) uintptr
	aclSetFD    func(int32, uintptr, int32) int32
	aclGetFlags func(uintptr, *uintptr) int32
	aclAddFlag  func(uintptr, int32) int32
	rename      func(int32, string, int32, string, uint32) int32
}

var getNative = sync.OnceValues(loadNative)

func loadNative() (*nativeAPI, error) {
	handle, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("cannot load OS security APIs: %w", err)
	}
	api := &nativeAPI{library: handle}
	for _, symbol := range []struct {
		name   string
		target any
	}{
		{"__error", &api.errno}, {"acl_get_fd_np", &api.aclGetFD},
		{"acl_valid", &api.aclValid}, {"acl_free", &api.aclFree},
		{"acl_get_entry", &api.aclGetEntry}, {"acl_get_tag_type", &api.aclGetTag},
		{"acl_get_permset_mask_np", &api.aclGetMask}, {"acl_init", &api.aclInit},
		{"acl_set_fd_np", &api.aclSetFD}, {"renameatx_np", &api.rename},
		{"acl_get_flagset_np", &api.aclGetFlags}, {"acl_add_flag_np", &api.aclAddFlag},
	} {
		address, err := purego.Dlsym(handle, symbol.name)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("OS security API %s unavailable: %w", symbol.name, err), purego.Dlclose(handle))
		}
		purego.RegisterFunc(symbol.target, address)
	}
	return api, nil
}

func (api *nativeAPI) lastError(operation string) error {
	// The caller holds its OS thread through the native call and errno read.
	code := syscall.Errno(*api.errno())
	if code == 0 {
		return fmt.Errorf("%s failed without an OS error", operation)
	}
	return fmt.Errorf("%s: %w", operation, code)
}

const aclTypeExtended = 0x100
const aclAllow = 1
const aclDeny = 2

// Apple acl.h: read/list, execute/search, read attributes/xattrs/security and
// synchronize. Unknown or mutation rights on any allow ACE are not trusted.
const readOnlyACL = uint64(1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11 | 1<<20)

func checkACL(file *os.File) (result error) {
	api, err := getNative()
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	acl := api.aclGetFD(int32(file.Fd()), aclTypeExtended)
	if acl == 0 {
		return api.lastError("read extended ACL")
	}
	defer func() {
		if api.aclFree(acl) != 0 {
			result = errors.Join(result, api.lastError("free extended ACL"))
		}
	}()
	if api.aclValid(acl) != 0 {
		return api.lastError("validate extended ACL")
	}
	for index := 0; index <= 128; index++ {
		var entry uintptr
		if api.aclGetEntry(acl, int32(index), &entry) != 0 {
			// On Apple's validated ACL object, an out-of-range entry is EINVAL.
			if syscall.Errno(*api.errno()) == syscall.EINVAL {
				return nil
			}
			return api.lastError("read extended ACL entry")
		}
		if index == 128 {
			return errors.New("extended ACL exceeds 128 entries")
		}
		var tag int32
		if api.aclGetTag(entry, &tag) != 0 {
			return api.lastError("read extended ACL tag")
		}
		if tag == aclDeny {
			continue
		}
		if tag != aclAllow {
			return errors.New("extended ACL has an unsupported entry type")
		}
		var mask uint64
		if api.aclGetMask(entry, &mask) != 0 {
			return api.lastError("read extended ACL permissions")
		}
		if mask & ^readOnlyACL != 0 {
			return errors.New("extended ACL grants mutation or unknown permissions")
		}
	}
	return errors.New("extended ACL inspection did not terminate")
}

// ResetCreatedACL is only for new product objects created exclusively beneath
// a checked parent. It must never change an existing administrator-owned object.
func ResetCreatedACL(file *os.File) (result error) {
	api, err := getNative()
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	acl := api.aclInit(0)
	if acl == 0 {
		return api.lastError("create empty extended ACL")
	}
	defer func() {
		if api.aclFree(acl) != 0 {
			result = errors.Join(result, api.lastError("free empty extended ACL"))
		}
	}()
	// Preserve the intended new-object ACL across a later publication rename;
	// parent inheritance must not reintroduce a removed read-deny entry.
	var flags uintptr
	if api.aclGetFlags(acl, &flags) != 0 {
		return api.lastError("read new ACL flags")
	}
	if api.aclAddFlag(flags, 1<<17) != 0 {
		return api.lastError("disable new-object ACL inheritance")
	}
	if api.aclSetFD(int32(file.Fd()), acl, aclTypeExtended) != 0 {
		return api.lastError("set new object extended ACL")
	}
	return nil
}

// RenameDirectories publishes a complete candidate. The caller must hold the
// writer lock and check identities, protection, allowed layouts and preimages.
// It never deletes objects or falls back to copying on unsupported filesystems.
func RenameDirectories(parent *os.File, from, to string, exchange bool) error {
	if !validName(from) || !validName(to) || from == to {
		return errors.New("rename requires distinct single directory names")
	}
	api, err := getNative()
	if err != nil {
		return err
	}
	flags := uint32(unix.RENAME_EXCL)
	if exchange {
		flags = unix.RENAME_SWAP
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if api.rename(int32(parent.Fd()), from, int32(parent.Fd()), to, flags) != 0 {
		return api.lastError("publish policy directory")
	}
	return nil
}
