//go:build windows

package uiaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/privatefile"
)

var advapi = syscall.NewLazyDLL("advapi32.dll")
var convertSD = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var getNamedSecurity = advapi.NewProc("GetNamedSecurityInfoW")
var getACE = advapi.NewProc("GetAce")

func RequireUnelevated() error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	var elevated, size uint32
	if err = syscall.GetTokenInformation(token, 20, (*byte)(unsafe.Pointer(&elevated)), 4, &size); err != nil {
		return err
	}
	if elevated != 0 {
		return errors.New("run the dashboard as your normal desktop user; use separately authorized CLI elevation for administrative operations")
	}
	return nil
}

func currentSID() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String()
}

func trustedSID(sid, user string) bool {
	return sid == user || sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

func checkParents(path string) error {
	user, err := currentSID()
	if err != nil {
		return err
	}
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || attributes.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("dashboard session parent must be a real directory: %s", path)
		}
		name, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		var owner, acl, descriptor unsafe.Pointer
		code, _, _ := getNamedSecurity.Call(uintptr(unsafe.Pointer(name)), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&descriptor)))
		if code != 0 {
			return syscall.Errno(code)
		}
		err = checkDescriptor(owner, acl, user)
		_, _ = syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
		if err != nil {
			return fmt.Errorf("untrusted dashboard session parent %s: %w", path, err)
		}
		next := filepath.Dir(path)
		if next == path {
			return nil
		}
		path = next
	}
}

func checkDescriptor(owner, acl unsafe.Pointer, user string) error {
	if owner == nil || acl == nil {
		return errors.New("missing owner or private-access controls")
	}
	sid, err := (*syscall.SID)(owner).String()
	if err != nil || !trustedSID(sid, user) {
		return errors.New("owner is another user")
	}
	type aclHeader struct {
		Revision, Reserved     byte
		Size, Count, Reserved2 uint16
	}
	header := (*aclHeader)(acl)
	for i := uint16(0); i < header.Count; i++ {
		var ace unsafe.Pointer
		ok, _, callErr := getACE.Call(uintptr(acl), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 {
			return callErr
		}
		kind := *(*byte)(ace)
		flags := *(*byte)(unsafe.Add(ace, 1))
		if flags&8 != 0 {
			continue
		} // Inherit-only ACE does not apply to this parent.
		if kind == 1 {
			continue
		} // A deny ACE grants no replacement authority.
		if kind != 0 {
			return errors.New("unsupported parent access-control entry")
		}
		mask := *(*uint32)(unsafe.Add(ace, 4))
		// A private child cannot be substituted through another user's delete,
		// delete-child, ownership or DACL rights on an ancestor.
		if mask&0x500d0152 == 0 {
			continue
		}
		principal, err := (*syscall.SID)(unsafe.Add(ace, 8)).String()
		// OWNER RIGHTS denotes this object's owner, which was independently
		// validated above. It does not grant rights to an unrelated account.
		// Keep it out of trustedSID: it must never be accepted as an owner SID.
		if err != nil || (!trustedSID(principal, user) && principal != "S-1-3-4") {
			return errors.New("another principal can replace directory contents or change permissions")
		}
	}
	return nil
}

func createPrivateDirectory(path string) error {
	user, err := currentSID()
	if err != nil {
		return err
	}
	sddl, err := syscall.UTF16PtrFromString("O:" + user + "D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return err
	}
	var descriptor uintptr
	ok, _, callErr := convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		return callErr
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := syscall.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	return syscall.CreateDirectory(name, &attributes)
}

func createPrivateFile(path string) (*os.File, error) {
	return privatefile.Create(path)
}
