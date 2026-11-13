//go:build windows

package uiaccess

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOwnerRightsRequiresIndependentlyTrustedOwner(t *testing.T) {
	user, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	stranger := "S-1-5-21-100001-100002-100003-100004"
	for _, tc := range []struct{ name, owner, aces, message string }{
		{"current owner", user, "(A;;FA;;;S-1-3-4)", ""},
		{"system owner", "S-1-5-18", "(A;;FA;;;S-1-3-4)", ""},
		{"foreign owner", stranger, "(A;;FA;;;S-1-3-4)", "owner is another user"},
		{"owner rights is not an owner", "S-1-3-4", "(A;;FA;;;S-1-3-4)", "owner is another user"},
		{"everyone still denied", user, "(A;;FA;;;WD)", "another principal"},
		{"owner rights plus everyone", user, "(A;;FA;;;S-1-3-4)(A;;FA;;;WD)", "another principal"},
		{"owner rights plus foreign writer", user, "(A;;FA;;;S-1-3-4)(A;;FA;;;" + stranger + ")", "another principal"},
		{"read-only unrelated principal", user, "(A;;FA;;;S-1-3-4)(A;;FR;;;WD)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, err := syscall.UTF16PtrFromString("O:" + tc.owner + "D:" + tc.aces)
			if err != nil {
				t.Fatal(err)
			}
			var descriptor uintptr
			ok, _, callErr := convertSD.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
			if ok == 0 {
				t.Fatal(callErr)
			}
			defer syscall.LocalFree(syscall.Handle(descriptor))
			var owner, acl unsafe.Pointer
			var defaulted, present uint32
			ok, _, callErr = advapi.NewProc("GetSecurityDescriptorOwner").Call(descriptor, uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted)))
			if ok == 0 {
				t.Fatal(callErr)
			}
			ok, _, callErr = advapi.NewProc("GetSecurityDescriptorDacl").Call(descriptor, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted)))
			if ok == 0 || present == 0 {
				t.Fatal("missing test DACL", callErr)
			}
			err = checkDescriptor(owner, acl, user)
			if tc.message == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("wanted %q, got %v", tc.message, err)
			}
		})
	}
}

// Exercise the actual named-directory descriptor, not just a parsed SDDL blob.
func TestOwnerRightsParentDirectory(t *testing.T) {
	user, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "owner-rights")
	text, err := syscall.UTF16PtrFromString("O:" + user + "D:P(A;OICI;FA;;;S-1-3-4)(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	var descriptor uintptr
	ok, _, callErr := convertSD.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		t.Fatal(callErr)
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	name, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	attributes := syscall.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	if err := syscall.CreateDirectory(name, &attributes); err != nil {
		t.Fatal(err)
	}
	if err := checkParents(root); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsLauncherFileHasProtectedDACL(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "launcher")
	if err := createPrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "start.html")
	file, err := createPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("launcher file DACL is not protected", err)
	}
	owner, _, err := sd.Owner()
	user, sidErr := currentSID()
	if err != nil || sidErr != nil || owner == nil || owner.String() != user {
		t.Fatal("launcher file has an unexpected owner")
	}
	if other, err := createPrivateFile(path); !errors.Is(err, os.ErrExist) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("launcher file creation did not refuse an existing object", err)
	}
}
