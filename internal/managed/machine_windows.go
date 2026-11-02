//go:build windows

package managed

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/wintrust"
)

const machinePolicyKey = `SOFTWARE\Policies\AccessWeaver`
const machinePolicyValue = "Installation"

func machinePolicySupported() bool { return true }

const registryMutationRights = wintrust.RegistryMutationRights

var securityDLL = syscall.NewLazyDLL("advapi32.dll")

func checkMachineDescriptor(owner, acl unsafe.Pointer, mask uint32) error {
	return wintrust.CheckDescriptor(owner, acl, mask)
}
func checkMachineHandle(handle syscall.Handle, kind, mask uint32) error {
	return wintrust.CheckHandle(handle, kind, mask)
}

func openMachineKey(parent syscall.Handle, name string) (syscall.Handle, error) {
	path, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	err = syscall.RegOpenKeyEx(parent, path, 0, syscall.KEY_READ|syscall.KEY_WOW64_64KEY, &key)
	if err != nil {
		return 0, err
	}
	if err = checkMachineHandle(key, 4, registryMutationRights); err != nil {
		syscall.RegCloseKey(key)
		return 0, err
	}
	return key, nil
}

func readMachineInstallation() ([]byte, bool, error) {
	// Check each fixed ancestor before deciding an absent child is unmanaged.
	// Registry failures and weak protection never become an unmanaged fallback.
	parent := syscall.Handle(syscall.HKEY_LOCAL_MACHINE)
	for index, part := range strings.Split(machinePolicyKey, `\`) {
		key, err := openMachineKey(parent, part)
		if index > 0 && errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return nil, false, nil
		}
		if err != nil {
			return nil, true, err
		}
		defer syscall.RegCloseKey(key)
		parent = key
	}
	data, err := readInstallationValue(parent)
	return data, true, err
}

func readInstallationValue(key syscall.Handle) ([]byte, error) {
	name, _ := syscall.UTF16PtrFromString(machinePolicyValue)
	var kind, size uint32
	err := syscall.RegQueryValueEx(key, name, nil, &kind, nil, &size)
	if err != nil {
		return nil, err
	}
	if kind != syscall.REG_BINARY || size > MaxInstallationBytes {
		return nil, errors.New("machine installation source must be bounded REG_BINARY")
	}
	data := make([]byte, int(size))
	var pointer *byte
	if len(data) > 0 {
		pointer = &data[0]
	}
	// Query again even for an empty value: a missing, resized or retyped value
	// between queries must fail rather than being returned as an empty snapshot.
	err = syscall.RegQueryValueEx(key, name, nil, &kind, pointer, &size)
	if err != nil {
		return nil, err
	}
	if kind != syscall.REG_BINARY || size > uint32(len(data)) {
		return nil, errors.New("machine installation changed during reading")
	}
	return data[:size], nil
}
