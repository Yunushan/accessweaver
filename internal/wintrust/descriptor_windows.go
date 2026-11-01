//go:build windows

package wintrust

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var securityDLL = syscall.NewLazyDLL("advapi32.dll")
var getSecurityInfo = securityDLL.NewProc("GetSecurityInfo")
var isValidACL = securityDLL.NewProc("IsValidAcl")
var getSecurityACE = securityDLL.NewProc("GetAce")

type nativeACL struct {
	Revision, Reserved     byte
	Size, Count, Reserved2 uint16
}
type nativeACE struct {
	Kind, Flags byte
	Size        uint16
	Mask        uint32
}

const RegistryMutationRights uint32 = 0x40000000 | 0x10000000 | 0x10000 | 0x40000 | 0x80000 | 0x2 | 0x4 | 0x20

func TrustedSID(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

// Restrict writable authority to SYSTEM, Administrators and TrustedInstaller.
// Unsupported ACE forms fail closed rather than guessing their effective rights.
func CheckDescriptor(owner, acl unsafe.Pointer, mutationMask uint32) error {
	if owner == nil || acl == nil {
		return errors.New("machine authority requires an owner and a non-null DACL")
	}
	ownerSID, err := (*syscall.SID)(owner).String()
	if err != nil {
		return err
	}
	if !TrustedSID(ownerSID) {
		return errors.New("machine authority is not owned by a trusted administrator")
	}
	valid, _, _ := isValidACL.Call(uintptr(acl))
	if valid == 0 {
		return errors.New("invalid machine authority DACL")
	}
	count := (*nativeACL)(acl).Count
	for i := uint16(0); i < count; i++ {
		var raw unsafe.Pointer
		ok, _, callErr := getSecurityACE.Call(uintptr(acl), uintptr(i), uintptr(unsafe.Pointer(&raw)))
		if ok == 0 {
			return fmt.Errorf("cannot inspect machine authority ACE: %w", callErr)
		}
		ace := (*nativeACE)(raw)
		if ace.Flags&0x08 != 0 {
			continue
		} // inherit-only does not apply to this object
		if ace.Kind == 1 {
			continue
		} // ordinary deny ACE cannot grant mutation
		if ace.Kind != 0 || ace.Size < 16 {
			return errors.New("unsupported machine authority ACE")
		}
		sid, err := (*syscall.SID)(unsafe.Add(raw, 8)).String()
		if err != nil {
			return err
		}
		// CREATOR OWNER is an inheritance placeholder, not an ordinary token
		// principal. Windows' default SOFTWARE ACL contains it without IO.
		// The concrete owner of this object was already checked above.
		if sid == "S-1-3-0" && ace.Flags&0x03 != 0 {
			continue
		}
		if sid == "S-1-3-4" {
			continue
		} // OWNER RIGHTS refers only to that checked owner
		if ace.Mask&mutationMask != 0 && !TrustedSID(sid) {
			return errors.New("machine authority permits non-administrator mutation")
		}
	}
	return nil
}

func CheckHandle(handle syscall.Handle, objectType uint32, mutationMask uint32) error {
	var owner, acl, descriptor unsafe.Pointer
	code, _, _ := getSecurityInfo.Call(uintptr(handle), uintptr(objectType), 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if code != 0 {
		return syscall.Errno(code)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	return CheckDescriptor(owner, acl, mutationMask)
}
