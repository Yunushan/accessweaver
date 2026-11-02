//go:build windows

package managed

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const machineAcceptanceValue = "Acceptance"

func withMachinePolicyLeaf(read func(syscall.Handle) error) (bool, error) {
	parent := syscall.Handle(syscall.HKEY_LOCAL_MACHINE)
	for index, part := range strings.Split(machinePolicyKey, "\\") {
		key, err := openMachineKey(parent, part)
		if index > 0 && errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return false, nil
		}
		if err != nil {
			return true, err
		}
		defer syscall.RegCloseKey(key)
		parent = key
	}
	return true, read(parent)
}

func readAcceptanceValue(key syscall.Handle) ([]byte, bool, error) {
	name, _ := syscall.UTF16PtrFromString(machineAcceptanceValue)
	var kind, size uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &kind, nil, &size); err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if kind != syscall.REG_BINARY || size > maxAcceptanceBytes {
		return nil, true, errors.New("accepted policy state must be bounded REG_BINARY")
	}
	data := make([]byte, int(size))
	var pointer *byte
	if len(data) > 0 {
		pointer = &data[0]
	}
	if err := syscall.RegQueryValueEx(key, name, nil, &kind, pointer, &size); err != nil {
		return nil, true, err
	}
	if kind != syscall.REG_BINARY || size > uint32(len(data)) {
		return nil, true, errors.New("accepted policy state changed during reading")
	}
	return data[:size], true, nil
}

func readMachineAcceptance() ([]byte, bool, error) {
	var data []byte
	var valuePresent bool
	keyPresent, err := withMachinePolicyLeaf(func(key syscall.Handle) error {
		var err error
		data, valuePresent, err = readAcceptanceValue(key)
		return err
	})
	return data, keyPresent && valuePresent, err
}

func readMachineSnapshot() (machineSnapshot, error) {
	var snapshot machineSnapshot
	present, err := withMachinePolicyLeaf(func(key syscall.Handle) error {
		for attempt := 0; attempt < 3; attempt++ {
			before, beforePresent, err := readAcceptanceValue(key)
			if err != nil {
				return err
			}
			source, err := readInstallationValue(key)
			if err != nil {
				return err
			}
			after, afterPresent, err := readAcceptanceValue(key)
			if err != nil {
				return err
			}
			// Both values are committed in one transaction. A counter change brackets
			// a concurrent publication; retry rather than returning a mixed pair.
			if beforePresent == afterPresent && bytes.Equal(before, after) {
				snapshot.source = source
				snapshot.acceptance = after
				snapshot.acceptancePresent = afterPresent
				return nil
			}
		}
		return errors.New("machine policy changed repeatedly during reading")
	})
	snapshot.present = present
	return snapshot, err
}

func (tx *nativeInstallationTransaction) ReadAcceptance() ([]byte, bool, error) {
	if tx.newKey {
		return nil, false, nil
	}
	data, present, err := readAcceptanceValue(tx.keys[len(tx.keys)-1])
	if err != nil {
		return nil, present, err
	}
	// Reserve even absence in the private transaction before comparing committed
	// state. A successful mutation always replaces this reservation with a record.
	if err := tx.setAcceptanceValue(data); err != nil {
		return nil, present, err
	}
	committed, committedPresent, err := readMachineAcceptance()
	if err != nil {
		return nil, present, err
	}
	if committedPresent != present || !bytes.Equal(committed, data) {
		return nil, present, errors.New("accepted policy state changed during update")
	}
	return data, present, nil
}

func (tx *nativeInstallationTransaction) setAcceptanceValue(data []byte) error {
	if len(data) > maxAcceptanceBytes {
		return errors.New("accepted policy state exceeds size limit")
	}
	name, _ := syscall.UTF16PtrFromString(machineAcceptanceValue)
	var pointer unsafe.Pointer
	if len(data) > 0 {
		pointer = unsafe.Pointer(&data[0])
	}
	code, _, _ := securityDLL.NewProc("RegSetValueExW").Call(uintptr(tx.keys[len(tx.keys)-1]), uintptr(unsafe.Pointer(name)), 0, syscall.REG_BINARY, uintptr(pointer), uintptr(len(data)))
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func (tx *nativeInstallationTransaction) StageAccepted(source, record []byte) error {
	accepted, err := readAcceptance(record)
	if err != nil {
		return err
	}
	if err := accepted.checkSource(source); err != nil {
		return err
	}
	if err := tx.Stage(source); err != nil {
		return err
	}
	return tx.setAcceptanceValue(record)
}
