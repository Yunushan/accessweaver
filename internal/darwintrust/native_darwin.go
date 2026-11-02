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

func (api *nativeAPI) lastError(operation string, errno *int32) error {
	// The caller holds its OS thread through the native call and errno read.
	code := syscall.Errno(*errno)
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

// Control pins the descriptor through the foreign call, including concurrent
// Close/finalizer activity. A locked OS thread also preserves errno identity.
func withNativeFD(file *os.File, operation func(*nativeAPI, int32, *int32) error) error {
	api, err := getNative()
	if err != nil {
		return err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	controlErr := raw.Control(func(fd uintptr) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// Resolve the thread-local errno address before the operation. No
		// second foreign call may intervene between failure and reading its code.
		errno := api.errno()
		if errno == nil {
			result = errors.New("native errno storage unavailable")
			return
		}
		result = operation(api, int32(fd), errno)
	})
	return errors.Join(result, controlErr)
}

func checkACL(file *os.File) error {
	return withNativeFD(file, func(api *nativeAPI, fd int32, errno *int32) error {
		return checkACLWithRetry(api, fd, errno)
	})
}

// Inspection can be interrupted by signals or a transient native metadata
// timeout. Retry the complete read at most three times; never interpret these
// errors as an absent ACL. Publication/ACL writes are not retried here.
func checkACLWithRetry(api *nativeAPI, fd int32, errno *int32) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = checkACLDescriptor(api, fd, errno)
		if !errors.Is(err, syscall.EINTR) && !errors.Is(err, syscall.ETIMEDOUT) {
			return err
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * time.Millisecond)
		}
	}
	return err
}

func checkACLDescriptor(api *nativeAPI, fd int32, errno *int32) (result error) {
	acl := api.aclGetFD(fd, aclTypeExtended)
	if acl == 0 {
		// Apple's descriptor API reports a missing FILESEC_ACL property as
		// ENOENT even while the file exists. Control holds a valid descriptor;
		// mode, owner, type, links and local APFS are checked separately.
		if syscall.Errno(*errno) == syscall.ENOENT {
			return nil
		}
		return api.lastError("read extended ACL", errno)
	}
	defer func() {
		if api.aclFree(acl) != 0 {
			result = errors.Join(result, api.lastError("free extended ACL", errno))
		}
	}()
	if api.aclValid(acl) != 0 {
		return api.lastError("validate extended ACL", errno)
	}
	for index := 0; index <= 128; index++ {
		var entry uintptr
		if api.aclGetEntry(acl, int32(index), &entry) != 0 {
			// On Apple's validated ACL object, an out-of-range entry is EINVAL.
			if syscall.Errno(*errno) == syscall.EINVAL {
				return nil
			}
			return api.lastError("read extended ACL entry", errno)
		}
		if index == 128 {
			return errors.New("extended ACL exceeds 128 entries")
		}
		var tag int32
		if api.aclGetTag(entry, &tag) != 0 {
			return api.lastError("read extended ACL tag", errno)
		}
		if tag == aclDeny {
			continue
		}
		if tag != aclAllow {
			return errors.New("extended ACL has an unsupported entry type")
		}
		var mask uint64
		if api.aclGetMask(entry, &mask) != 0 {
			return api.lastError("read extended ACL permissions", errno)
		}
		if mask & ^readOnlyACL != 0 {
			return errors.New("extended ACL grants mutation or unknown permissions")
		}
	}
	return errors.New("extended ACL inspection did not terminate")
}

// ResetCreatedACL is only for new product objects created exclusively beneath
// a checked parent. It must never change an existing administrator-owned object.
func ResetCreatedACL(file *os.File) error {
	return withNativeFD(file, resetCreatedDescriptorACL)
}

func resetCreatedDescriptorACL(api *nativeAPI, fd int32, errno *int32) (result error) {
	acl := api.aclInit(0)
	if acl == 0 {
		return api.lastError("create empty extended ACL", errno)
	}
	defer func() {
		if api.aclFree(acl) != 0 {
			result = errors.Join(result, api.lastError("free empty extended ACL", errno))
		}
	}()
	// Preserve the intended new-object ACL across a later publication rename;
	// parent inheritance must not reintroduce a removed read-deny entry.
	var flags uintptr
	if api.aclGetFlags(acl, &flags) != 0 {
		return api.lastError("read new ACL flags", errno)
	}
	if api.aclAddFlag(flags, 1<<17) != 0 {
		return api.lastError("disable new-object ACL inheritance", errno)
	}
	if api.aclSetFD(fd, acl, aclTypeExtended) != 0 {
		return api.lastError("set new object extended ACL", errno)
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
	flags := uint32(unix.RENAME_EXCL)
	if exchange {
		flags = unix.RENAME_SWAP
	}
	return withNativeFD(parent, func(api *nativeAPI, fd int32, errno *int32) error {
		if api.rename(fd, from, fd, to, flags) != 0 {
			return api.lastError("publish policy directory", errno)
		}
		return nil
	})
}
