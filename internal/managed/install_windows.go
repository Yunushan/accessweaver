//go:build windows

package managed

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/nativepath"
)

func requirePolicyAdministrator() error {
	administrators, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	var member int32
	// NULL token checks the effective thread token, including impersonation.
	ok, _, callErr := securityDLL.NewProc("CheckTokenMembership").Call(0, uintptr(unsafe.Pointer(administrators)), uintptr(unsafe.Pointer(&member)))
	if ok == 0 {
		return fmt.Errorf("cannot inspect effective administrator token: %w", callErr)
	}
	if member == 0 {
		return fmt.Errorf("%w: policy installation requires a separately elevated administrator CLI", ErrDenied)
	}
	return nil
}

func applyMachinePolicy(data []byte, key ed25519.PublicKey, change policyChange) (InstallResult, error) {
	if err := requirePolicyAdministrator(); err != nil {
		return InstallResult{}, err
	}
	tx, err := beginMachineInstallation(change == changeInstall)
	if err != nil {
		return InstallResult{}, err
	}
	return commitInstallation(tx, data, key, change, time.Now)
}

type nativeInstallationTransaction struct {
	library     *syscall.DLL
	commit      *syscall.Proc
	transaction syscall.Handle
	keys        []syscall.Handle
	initial     bool
	newKey      bool
}

func beginMachineInstallation(initial bool) (*nativeInstallationTransaction, error) {
	// Resolve the transaction DLL from the OS directory, never the application
	// directory, current working directory or caller-controlled PATH.
	system, err := nativepath.SystemDirectory()
	if err != nil {
		return nil, err
	}
	library, err := syscall.LoadDLL(filepath.Join(system, "ktmw32.dll"))
	if err != nil {
		return nil, err
	}
	create, err := library.FindProc("CreateTransaction")
	if err != nil {
		library.Release()
		return nil, err
	}
	commit, err := library.FindProc("CommitTransaction")
	if err != nil {
		library.Release()
		return nil, err
	}
	// A local, bounded KTM transaction needs no shared mutex name or lock file.
	handle, _, callErr := create.Call(0, 0, 1, 0, 0, 15000, 0)
	if syscall.Handle(handle) == syscall.InvalidHandle || handle == 0 {
		library.Release()
		return nil, fmt.Errorf("cannot begin registry transaction: %w", callErr)
	}
	tx := &nativeInstallationTransaction{library: library, commit: commit, transaction: syscall.Handle(handle), initial: initial}
	fail := func(err error) (*nativeInstallationTransaction, error) { return nil, errors.Join(err, tx.Close()) }
	parent := syscall.Handle(syscall.HKEY_LOCAL_MACHINE)
	parts := strings.Split(machinePolicyKey, `\`)
	for index, part := range parts {
		name, _ := syscall.UTF16PtrFromString(part)
		access := uint32(syscall.KEY_READ | syscall.KEY_WOW64_64KEY)
		if index == len(parts)-1 {
			access |= syscall.KEY_SET_VALUE
		}
		var key syscall.Handle
		code, _, _ := securityDLL.NewProc("RegOpenKeyTransactedW").Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, uintptr(access), uintptr(unsafe.Pointer(&key)), uintptr(tx.transaction), 0)
		if code == uintptr(syscall.ERROR_FILE_NOT_FOUND) && initial && index > 0 {
			var created uint32
			var descriptor unsafe.Pointer
			sddl, _ := syscall.UTF16PtrFromString("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)")
			ok, _, err := securityDLL.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW").Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
			if ok == 0 {
				return fail(err)
			}
			attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
			code, _, _ = securityDLL.NewProc("RegCreateKeyTransactedW").Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(access), uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&created)), uintptr(tx.transaction), 0)
			syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
			if code == 0 && index == len(parts)-1 {
				tx.newKey = created == 1
			}
		}
		if code != 0 {
			return fail(fmt.Errorf("cannot open protected policy transaction: %w", syscall.Errno(code)))
		}
		tx.keys = append(tx.keys, key)
		if err := checkMachineHandle(key, 4, registryMutationRights); err != nil {
			return fail(err)
		}
		parent = key
	}
	return tx, nil
}

func (tx *nativeInstallationTransaction) Read() ([]byte, bool, error) {
	if tx.newKey {
		return nil, false, nil
	}
	data, err := readInstallationValue(tx.keys[len(tx.keys)-1])
	if err == nil && !tx.initial {
		err = tx.reservePrior(data)
	}
	return data, true, err
}

// Reserve the value for this writer, then compare with the committed native
// source. A reader that observed an older revision before another commit must
// abort, even if its later transacted write is otherwise permitted by the OS.
func (tx *nativeInstallationTransaction) reservePrior(data []byte) error {
	if err := tx.setInstallationValue(data); err != nil {
		return err
	}
	committed, present, err := readMachineInstallation()
	if err != nil {
		return err
	}
	if !present || !bytes.Equal(committed, data) {
		return errors.New("enrolled policy changed during update; inspect managed status and retry")
	}
	return nil
}

func (tx *nativeInstallationTransaction) Stage(data []byte) error {
	if len(data) == 0 || len(data) > MaxInstallationBytes {
		return errors.New("invalid installation size")
	}
	return tx.setInstallationValue(data)
}

// Write within the already protected native transaction. Read may reserve an
// existing empty value; Stage still requires a nonempty candidate.
func (tx *nativeInstallationTransaction) setInstallationValue(data []byte) error {
	if len(data) > MaxInstallationBytes {
		return errors.New("invalid installation size")
	}
	value, _ := syscall.UTF16PtrFromString(machinePolicyValue)
	var pointer unsafe.Pointer
	if len(data) > 0 {
		pointer = unsafe.Pointer(&data[0])
	}
	code, _, _ := securityDLL.NewProc("RegSetValueExW").Call(uintptr(tx.keys[len(tx.keys)-1]), uintptr(unsafe.Pointer(value)), 0, syscall.REG_BINARY, uintptr(pointer), uintptr(len(data)))
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}
func (tx *nativeInstallationTransaction) Commit() error {
	ok, _, callErr := tx.commit.Call(uintptr(tx.transaction))
	if ok == 0 {
		return callErr
	}
	return nil
}
func (tx *nativeInstallationTransaction) Close() error {
	var result error
	for index := len(tx.keys) - 1; index >= 0; index-- {
		result = errors.Join(result, syscall.RegCloseKey(tx.keys[index]))
	}
	tx.keys = nil
	if tx.transaction != 0 {
		// Closing an uncommitted last handle rolls the transaction back.
		result = errors.Join(result, syscall.CloseHandle(tx.transaction))
		tx.transaction = 0
	}
	if tx.library != nil {
		result = errors.Join(result, tx.library.Release())
		tx.library = nil
	}
	return result
}
