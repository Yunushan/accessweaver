//go:build windows

package managed

import (
	"syscall"
	"testing"
	"unsafe"
)

func checkRegistrySDDL(t *testing.T, text string) error {
	t.Helper()
	convert := securityDLL.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	getOwner := securityDLL.NewProc("GetSecurityDescriptorOwner")
	getDACL := securityDLL.NewProc("GetSecurityDescriptorDacl")
	input, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor, owner, acl unsafe.Pointer
	ok, _, callErr := convert.Call(uintptr(unsafe.Pointer(input)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		t.Fatalf("invalid test descriptor: %v", callErr)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	var present, defaulted int32
	ok, _, callErr = getOwner.Call(uintptr(descriptor), uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 {
		t.Fatal(callErr)
	}
	ok, _, callErr = getDACL.Call(uintptr(descriptor), uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 {
		t.Fatal(callErr)
	}
	return checkMachineDescriptor(owner, acl, registryMutationRights)
}

func TestNativeMachineAuthorityDescriptors(t *testing.T) {
	for _, text := range []string{
		"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)",
		"O:SYG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;AU)",
		"O:BAG:BAD:P(D;;KW;;;BU)(A;;KA;;;BA)(A;;KR;;;BU)",
		"O:BAG:BAD:P(A;CIIO;KA;;;CO)(A;;KA;;;BA)(A;;KR;;;BU)",
		"O:SYG:SYD:P(A;CI;KA;;;CO)(A;;KA;;;SY)(A;;KR;;;BU)",
		"O:BAG:BAD:P(A;;KA;;;OW)(A;;KR;;;BU)",
	} {
		if err := checkRegistrySDDL(t, text); err != nil {
			t.Fatalf("protected administrator descriptor rejected: %v", err)
		}
	}
	for _, text := range []string{
		"O:BUG:BUD:P(A;;KA;;;BA)(A;;KR;;;BU)",
		"O:BUG:BUD:P(A;;KA;;;OW)(A;;KR;;;BU)",
		"O:BAG:BAD:NO_ACCESS_CONTROL",
		"O:BAG:BAD:P(A;;KA;;;BA)(A;;KW;;;BU)",
		"O:BAG:BAD:P(A;;KA;;;BA)(A;;WD;;;BU)",
		"O:BAG:BAD:P(A;;KA;;;BA)(A;;WO;;;AU)",
		"O:BAG:BAD:P(A;;KA;;;BA)(A;;SD;;;WD)",
		"O:BAG:BAD:P(A;;KA;;;BA)(A;;GW;;;BU)",
		"O:BAG:BAD:P(A;;KA;;;BA)(A;;0x4;;;BU)",
	} {
		if err := checkRegistrySDDL(t, text); err == nil {
			t.Fatalf("untrusted descriptor accepted: %s", text)
		}
	}
}

func TestNativeMachineReadDoesNotCreateRegistryState(t *testing.T) {
	// Read only. No test creates, changes or deletes HKLM keys on this host.
	_, _, err := readMachineInstallation()
	if err != nil {
		t.Fatalf("cannot inspect native managed source: %v", err)
	}
}
