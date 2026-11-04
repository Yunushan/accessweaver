//go:build windows

package audit

import (
	"encoding/binary"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsAuditSystemSID             = "S-1-5-18"
	windowsAuditOwnerRightsSID        = "S-1-3-4"
	windowsAuditFullControl    uint32 = 0x001f01ff
	// Match the replacement and mutation checks on other private Windows
	// storage. FILE_ADD_SUBDIRECTORY is deliberately absent: creating an
	// unrelated subdirectory cannot replace an already opened path component.
	windowsAuditAncestorMutation   uint32 = 0x500d0152
	windowsAuditGenericRights      uint32 = windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE | windows.GENERIC_ALL
	windowsAuditRelativeHeaderSize        = 20
)

var windowsAuditIsValidACL = windows.NewLazySystemDLL("advapi32.dll").NewProc("IsValidAcl")

// windowsAuditSecurityDescriptor is used only at exclusive creation. Existing
// objects are checked through their handles; these helpers never repair ACLs.
func windowsAuditSecurityDescriptor(owner string, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	if !windowsAuditCanonicalOwner(owner) {
		return nil, ErrJournalStorage
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;" + flags + ";FA;;;" + owner + ")(A;" + flags + ";FA;;;SY)")
	if err != nil || checkWindowsAuditDescriptor(sd, owner, true) != nil {
		return nil, ErrJournalStorage
	}
	return sd, nil
}

func checkWindowsAuditSecurity(handle windows.Handle, owner string, private bool) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrJournalStorage
	}
	return checkWindowsAuditDescriptor(sd, owner, private)
}

// GetSecurityInfo and SecurityDescriptorFromString return self-relative native
// descriptors copied onto the Go heap by x/sys. Validate the native descriptor
// before using its length, and keep that allocation alive through all native
// ACL/SID calls. The byte parser also has an explicit bound for malformed-data
// tests and never derives an ACE or SID pointer before checking its extent.
func checkWindowsAuditDescriptor(sd *windows.SECURITY_DESCRIPTOR, owner string, private bool) error {
	if sd == nil || !sd.IsValid() {
		return ErrJournalStorage
	}
	control, revision, err := sd.Control()
	if err != nil || revision != 1 || control&windows.SE_SELF_RELATIVE == 0 {
		return ErrJournalStorage
	}
	n := sd.Length()
	if n < windowsAuditRelativeHeaderSize || n > 1<<20 {
		return ErrJournalStorage
	}
	err = checkWindowsAuditDescriptorBytes(unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(n)), owner, private)
	runtime.KeepAlive(sd)
	return err
}

func windowsAuditCanonicalOwner(owner string) bool {
	// Creator/owner-rights SIDs are ACL placeholders, never executing identities.
	if owner == "" || strings.HasPrefix(owner, "S-1-3-") {
		return false
	}
	sid, err := windows.StringToSid(owner)
	return err == nil && sid != nil && sid.IsValid() && sid.String() == owner
}

func windowsAuditTrustedSID(sid, owner string) bool {
	return sid == owner || sid == windowsAuditSystemSID || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

func checkWindowsAuditDescriptorBytes(data []byte, owner string, private bool) error {
	if len(data) < windowsAuditRelativeHeaderSize || data[0] != 1 || data[1] != 0 || !windowsAuditCanonicalOwner(owner) {
		return ErrJournalStorage
	}
	control := windows.SECURITY_DESCRIPTOR_CONTROL(binary.LittleEndian.Uint16(data[2:4]))
	if control&(windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT) != windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT || (private && control&windows.SE_DACL_PROTECTED == 0) {
		return ErrJournalStorage
	}
	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	if ownerOffset < windowsAuditRelativeHeaderSize || ownerOffset&3 != 0 || uint64(ownerOffset) >= uint64(len(data)) {
		return ErrJournalStorage
	}
	actualOwner, ownerSize, ok := windowsAuditBoundedSID(data[int(ownerOffset):])
	if !ok || (private && actualOwner != owner) || (!private && !windowsAuditTrustedSID(actualOwner, owner)) {
		return ErrJournalStorage
	}
	// OWNER RIGHTS is resolved only below, after independently checking the
	// actual owner. It is deliberately absent from the trusted-owner list.
	if strings.HasPrefix(actualOwner, "S-1-3-") {
		return ErrJournalStorage
	}
	aclOffset := binary.LittleEndian.Uint32(data[16:20])
	if aclOffset < windowsAuditRelativeHeaderSize || aclOffset&3 != 0 || uint64(aclOffset)+8 > uint64(len(data)) {
		return ErrJournalStorage
	}
	acl := data[int(aclOffset):]
	aclSize := int(binary.LittleEndian.Uint16(acl[2:4]))
	if (acl[0] != 2 && acl[0] != 4) || acl[1] != 0 || binary.LittleEndian.Uint16(acl[6:8]) != 0 || aclSize < 8 || aclSize&3 != 0 || aclSize > len(acl) {
		return ErrJournalStorage
	}
	acl = acl[:aclSize]
	if int(ownerOffset) < int(aclOffset)+aclSize && int(aclOffset) < int(ownerOffset)+ownerSize {
		return ErrJournalStorage
	}
	count := int(binary.LittleEndian.Uint16(acl[4:6]))
	if count > (len(acl)-8)/16 {
		return ErrJournalStorage
	}
	cursor := 8
	var ownerRights uint32
	for i := 0; i < count; i++ {
		if cursor > len(acl)-4 {
			return ErrJournalStorage
		}
		size := int(binary.LittleEndian.Uint16(acl[cursor+2 : cursor+4]))
		if size < 16 || size&3 != 0 || size > len(acl)-cursor {
			return ErrJournalStorage
		}
		ace := acl[cursor : cursor+size]
		cursor += size
		kind, flags := ace[0], ace[1]
		if kind != windows.ACCESS_ALLOWED_ACE_TYPE && kind != windows.ACCESS_DENIED_ACE_TYPE {
			return ErrJournalStorage
		}
		const propagation = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		if flags & ^uint8(windows.VALID_INHERIT_FLAGS) != 0 || flags&(windows.INHERIT_ONLY_ACE|windows.NO_PROPAGATE_INHERIT_ACE) != 0 && flags&propagation == 0 {
			return ErrJournalStorage
		}
		// Private DACLs may propagate owner/SYSTEM grants, but may not depend on
		// an inherited or inherit-only grant. Reject deny entries as well: token
		// group membership could otherwise make an apparent owner grant unusable.
		if private && (flags & ^uint8(propagation) != 0 || kind != windows.ACCESS_ALLOWED_ACE_TYPE) {
			return ErrJournalStorage
		}
		mask := binary.LittleEndian.Uint32(ace[4:8])
		if mask & ^uint32(windowsAuditFullControl|windowsAuditGenericRights) != 0 {
			return ErrJournalStorage
		}
		principal, sidSize, ok := windowsAuditBoundedSID(ace[8:])
		if !ok || sidSize != len(ace)-8 {
			return ErrJournalStorage
		}
		if principal == windowsAuditOwnerRightsSID {
			principal = actualOwner
		}
		if private {
			if principal != owner && principal != windowsAuditSystemSID {
				return ErrJournalStorage
			}
			if principal == owner {
				ownerRights |= windowsAuditMapFileRights(mask)
			}
			continue
		}
		// These ordinary ACE forms have now been fully bounded and validated.
		// A deny cannot grant replacement rights; inherit-only grants do not
		// apply to this already opened parent. Effective grants are never skipped.
		if kind == windows.ACCESS_DENIED_ACE_TYPE || flags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if mask&windowsAuditAncestorMutation != 0 && !windowsAuditTrustedSID(principal, owner) {
			return ErrJournalStorage
		}
	}
	valid, _, _ := windowsAuditIsValidACL.Call(uintptr(unsafe.Pointer(&acl[0])))
	runtime.KeepAlive(data)
	if valid == 0 || (private && ownerRights&windowsAuditFullControl != windowsAuditFullControl) {
		return ErrJournalStorage
	}
	return nil
}

func windowsAuditBoundedSID(data []byte) (string, int, bool) {
	if len(data) < 8 || data[0] != 1 || data[1] > 15 {
		return "", 0, false
	}
	n := 8 + 4*int(data[1])
	if n > len(data) {
		return "", 0, false
	}
	sid := (*windows.SID)(unsafe.Pointer(&data[0]))
	if !sid.IsValid() {
		return "", 0, false
	}
	value := sid.String()
	runtime.KeepAlive(data)
	return value, n, value != ""
}

func windowsAuditMapFileRights(mask uint32) uint32 {
	if mask&windows.GENERIC_ALL != 0 {
		mask |= windowsAuditFullControl
	}
	if mask&windows.GENERIC_READ != 0 {
		mask |= windows.FILE_GENERIC_READ
	}
	if mask&windows.GENERIC_WRITE != 0 {
		mask |= windows.FILE_GENERIC_WRITE
	}
	if mask&windows.GENERIC_EXECUTE != 0 {
		mask |= windows.FILE_GENERIC_EXECUTE
	}
	return mask & ^windowsAuditGenericRights
}
