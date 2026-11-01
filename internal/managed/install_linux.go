//go:build linux && (amd64 || arm64)

package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
)

func applyMachinePolicy(data []byte, key ed25519.PublicKey, change policyChange) (InstallResult, error) {
	if os.Geteuid() != 0 {
		return InstallResult{}, fmt.Errorf("%w: machine policy changes require a separately elevated root CLI", ErrDenied)
	}
	parent, err := openLinuxPolicyParent()
	if err != nil {
		return InstallResult{}, err
	}
	tx, err := beginLinuxInstallation(parent, change == changeInstall, 0)
	if err != nil {
		return InstallResult{}, err
	}
	tx.persistent = true
	return commitInstallation(tx, data, key, change, time.Now)
}

type linuxInstallationTransaction struct {
	parent, dir, lock        *os.File
	owner                    uint32
	initial, committed       bool
	persistent               bool
	directoryName, stageName string
	prior                    []byte
}

func randomLinuxStage(prefix string) (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(data), nil
}

// Ownership of parent transfers to the transaction, including on failure. Only
// unit fixtures use a private temporary parent/non-root owner; runtime uses 0.
func beginLinuxInstallation(parent *os.File, initial bool, owner uint32) (*linuxInstallationTransaction, error) {
	tx := &linuxInstallationTransaction{parent: parent, owner: owner, initial: initial, directoryName: linuxPolicyDirectory}
	fail := func(err error) (*linuxInstallationTransaction, error) { return nil, errors.Join(err, tx.Close()) }
	fd, err := syscall.Openat(int(parent.Fd()), linuxPolicyLock, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fail(err)
	}
	tx.lock = os.NewFile(uintptr(fd), linuxPolicyLock)
	info, err := linuxtrust.Check(tx.lock, false, owner)
	if err != nil {
		return fail(err)
	}
	if info.Mode().Perm() != 0600 {
		return fail(errors.New("policy coordination file must be private mode 0600"))
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fail(err)
		}
		if !time.Now().Before(deadline) {
			return fail(errors.New("policy update is busy; inspect managed status and retry"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if initial {
		existing, err := linuxtrust.OpenDirectoryAt(parent, linuxPolicyDirectory, owner)
		if err == nil {
			existing.Close()
			return fail(errors.New("machine policy directory already exists; bootstrap cannot replace it"))
		}
		if !errors.Is(err, syscall.ENOENT) {
			return fail(err)
		}
		if err := cleanupLinuxInitialStages(parent, owner); err != nil {
			return fail(err)
		}
		name, err := randomLinuxStage(".accessweaver-install-")
		if err != nil {
			return fail(err)
		}
		if err := syscall.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
			return fail(err)
		}
		tx.directoryName = name
		tx.dir, err = linuxtrust.OpenDirectoryAt(parent, name, owner)
		if err != nil {
			return fail(err)
		}
		if err := linuxtrust.ResetCreatedACL(tx.dir, true); err != nil {
			return fail(err)
		}
	} else {
		tx.dir, err = linuxtrust.OpenDirectoryAt(parent, linuxPolicyDirectory, owner)
		if err != nil {
			return fail(err)
		}
		if err := cleanupLinuxUpdateStages(tx.dir, owner); err != nil {
			return fail(err)
		}
	}
	return tx, nil
}
func (tx *linuxInstallationTransaction) Read() ([]byte, bool, error) {
	if tx.initial {
		return nil, false, nil
	}
	data, err := readLinuxInstallation(tx.dir, tx.owner, tx.persistent)
	if err == nil {
		tx.prior = append([]byte(nil), data...)
	}
	return data, true, err
}
func (tx *linuxInstallationTransaction) Stage(data []byte) error {
	if len(data) == 0 || len(data) > MaxInstallationBytes {
		return errors.New("invalid installation size")
	}
	if tx.stageName != "" {
		return errors.New("policy candidate already staged")
	}
	name := linuxPolicyFile
	if !tx.initial {
		var err error
		name, err = randomLinuxStage(".installation-")
		if err != nil {
			return err
		}
	}
	fd, err := syscall.Openat(int(tx.dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	tx.stageName = name
	file := os.NewFile(uintptr(fd), name)
	_, writeErr := file.Write(data)
	aclErr := linuxtrust.ResetCreatedACL(file, false)
	modeErr := file.Chmod(0644)
	syncErr := file.Sync()
	return errors.Join(writeErr, aclErr, modeErr, syncErr, file.Close())
}
func renameNoReplace(parent *os.File, oldName, newName string) error {
	old, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	next, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, code := syscall.Syscall6(linuxRenameat2, parent.Fd(), uintptr(unsafe.Pointer(old)), parent.Fd(), uintptr(unsafe.Pointer(next)), 1, 0)
	if code != 0 {
		return code
	}
	return nil
}
func removeDirectoryAt(parent *os.File, name string) error {
	value, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, code := syscall.Syscall(syscall.SYS_UNLINKAT, parent.Fd(), uintptr(unsafe.Pointer(value)), 0x200)
	if code != 0 {
		return code
	}
	return nil
}
func (tx *linuxInstallationTransaction) Commit() error {
	if tx.stageName == "" {
		return errors.New("no staged installation")
	}
	if tx.initial {
		if err := tx.lock.Sync(); err != nil {
			return err
		}
		if err := tx.dir.Chmod(0755); err != nil {
			return err
		}
		if err := tx.dir.Sync(); err != nil {
			return err
		}
		if err := renameNoReplace(tx.parent, tx.directoryName, linuxPolicyDirectory); err != nil {
			return err
		}
		tx.committed = true
		return tx.parent.Sync()
	}
	// Direct administrator writes outside this lock must not be overwritten by
	// a candidate derived from stale key/revision metadata.
	current, err := linuxtrust.OpenDirectoryAt(tx.parent, linuxPolicyDirectory, tx.owner)
	if err != nil {
		return err
	}
	defer current.Close()
	before, err := tx.dir.Stat()
	if err != nil {
		return err
	}
	after, err := current.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return errors.New("policy directory changed during update")
	}
	data, err := readLinuxInstallation(current, tx.owner, tx.persistent)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, tx.prior) {
		return errors.New("enrolled policy changed during update; inspect managed status and retry")
	}
	if err := syscall.Renameat(int(tx.dir.Fd()), tx.stageName, int(tx.dir.Fd()), linuxPolicyFile); err != nil {
		return err
	}
	tx.committed = true
	return tx.dir.Sync()
}
func (tx *linuxInstallationTransaction) Published() bool { return tx.committed }

func (tx *linuxInstallationTransaction) Close() error {
	var result error
	if tx.dir != nil && !tx.committed {
		if tx.stageName != "" {
			result = errors.Join(result, syscall.Unlinkat(int(tx.dir.Fd()), tx.stageName))
		}
	}
	if tx.lock != nil {
		result = errors.Join(result, tx.lock.Close())
		tx.lock = nil
	}
	if tx.dir != nil {
		result = errors.Join(result, tx.dir.Close())
		tx.dir = nil
	}
	if tx.parent != nil {
		if tx.initial && !tx.committed && strings.HasPrefix(tx.directoryName, ".accessweaver-install-") {
			result = errors.Join(result, removeDirectoryAt(tx.parent, tx.directoryName))
		}
		result = errors.Join(result, tx.parent.Close())
		tx.parent = nil
	}
	return result
}

func linuxStageName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, prefix))
	return err == nil && strings.ToLower(name) == name
}
func scanLinuxStages(dir *os.File, prefix string, visit func(string) error) error {
	fd, err := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	scan := os.NewFile(uintptr(fd), dir.Name())
	defer scan.Close()
	seen, removed := 0, 0
	for {
		entries, readErr := scan.ReadDir(128)
		for _, entry := range entries {
			seen++
			if seen > 4096 {
				return errors.New("policy staging namespace exceeds inspection bound")
			}
			if !linuxStageName(entry.Name(), prefix) {
				continue
			}
			removed++
			if removed > 128 {
				return errors.New("policy staging cleanup reached 128 candidates; inspect and retry")
			}
			if err := visit(entry.Name()); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
func checkLinuxAbandonedFile(dir *os.File, name string, owner uint32) error {
	file, err := linuxtrust.OpenRegularAt(dir, name, owner)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if info.Size() > MaxInstallationBytes || (info.Mode().Perm() != 0600 && info.Mode().Perm() != 0644) {
		return errors.New("unexpected abandoned staging file; administrator inspection required")
	}
	return nil
}
func cleanupLinuxUpdateStages(dir *os.File, owner uint32) error {
	return scanLinuxStages(dir, ".installation-", func(name string) error {
		if err := checkLinuxAbandonedFile(dir, name, owner); err != nil {
			return err
		}
		return syscall.Unlinkat(int(dir.Fd()), name)
	})
}
func cleanupLinuxInitialStages(parent *os.File, owner uint32) error {
	return scanLinuxStages(parent, ".accessweaver-install-", func(name string) error {
		dir, err := linuxtrust.OpenDirectoryAt(parent, name, owner)
		if err != nil {
			return err
		}
		defer dir.Close()
		entries, err := dir.ReadDir(2)
		if err != nil && err != io.EOF {
			return err
		}
		if len(entries) > 1 || (len(entries) == 1 && entries[0].Name() != linuxPolicyFile) {
			return errors.New("unexpected bootstrap staging contents; administrator inspection required")
		}
		if len(entries) == 1 {
			if err := checkLinuxAbandonedFile(dir, linuxPolicyFile, owner); err != nil {
				return err
			}
			if err := syscall.Unlinkat(int(dir.Fd()), linuxPolicyFile); err != nil {
				return err
			}
		}
		return removeDirectoryAt(parent, name)
	})
}
