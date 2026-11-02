//go:build linux && (amd64 || arm64)

package managed

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
)

const linuxAcceptanceFile = "acceptance.json"
const linuxAcceptanceStagePrefix = ".accessweaver-policy-stage-"

func readLinuxAcceptanceAt(dir *os.File, owner uint32, persistent bool) ([]byte, bool, error) {
	file, err := linuxtrust.OpenRegularAt(dir, linuxAcceptanceFile, owner)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	defer file.Close()
	if persistent {
		if err := linuxtrust.CheckPersistent(file); err != nil {
			return nil, true, err
		}
	}
	before, err := file.Stat()
	if err != nil {
		return nil, true, err
	}
	if before.Size() < 0 || before.Size() > maxAcceptanceBytes {
		return nil, true, errors.New("accepted policy state exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAcceptanceBytes+1))
	if err != nil {
		return nil, true, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, true, err
	}
	if len(data) > maxAcceptanceBytes || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(data)) != after.Size() {
		return nil, true, errors.New("accepted policy state changed during reading")
	}
	return data, true, nil
}

func readLinuxPolicySnapshot(dir *os.File, owner uint32, persistent bool) (machineSnapshot, error) {
	snapshot := machineSnapshot{present: true}
	var err error
	snapshot.source, err = readLinuxInstallation(dir, owner, persistent)
	if err != nil {
		return snapshot, err
	}
	snapshot.acceptance, snapshot.acceptancePresent, err = readLinuxAcceptanceAt(dir, owner, persistent)
	return snapshot, err
}

func sameLinuxDirectory(parent *os.File, name string, expected *os.File, owner uint32) (bool, error) {
	current, err := linuxtrust.OpenDirectoryAt(parent, name, owner)
	if err != nil {
		return false, err
	}
	defer current.Close()
	old, err := expected.Stat()
	if err != nil {
		return false, err
	}
	now, err := current.Stat()
	if err != nil {
		return false, err
	}
	return os.SameFile(old, now), nil
}

func readMachineSnapshot() (machineSnapshot, error) {
	parent, err := openLinuxPolicyParent()
	if err != nil {
		return machineSnapshot{present: true}, err
	}
	defer parent.Close()
	return readLinuxSnapshotAt(parent, 0, true)
}

func readLinuxSnapshotAt(parent *os.File, owner uint32, persistent bool) (machineSnapshot, error) {
	for attempt := 0; attempt < 3; attempt++ {
		dir, err := linuxtrust.OpenDirectoryAt(parent, linuxPolicyDirectory, owner)
		if errors.Is(err, syscall.ENOENT) {
			return machineSnapshot{}, nil
		}
		if err != nil {
			return machineSnapshot{present: true}, err
		}
		snapshot, readErr := readLinuxPolicySnapshot(dir, owner, persistent)
		same, checkErr := sameLinuxDirectory(parent, linuxPolicyDirectory, dir, owner)
		closeErr := dir.Close()
		if checkErr != nil {
			return snapshot, errors.Join(readErr, checkErr, closeErr)
		}
		if !same {
			continue
		}
		return snapshot, errors.Join(readErr, closeErr)
	}
	return machineSnapshot{present: true}, errors.New("machine policy changed repeatedly during reading")
}

func (tx *linuxInstallationTransaction) ReadAcceptance() ([]byte, bool, error) {
	if tx.initial {
		return nil, false, nil
	}
	data, present, err := readLinuxAcceptanceAt(tx.dir, tx.owner, tx.persistent)
	if err == nil {
		tx.priorAcceptance = bytes.Clone(data)
		tx.priorAcceptancePresent = present
	}
	return data, present, err
}

type linuxPolicyPair struct {
	parent, dir, displaced       *os.File
	name                         string
	owner                        uint32
	persistent, published, ready bool
	candidate, cleanupExpected   machineSnapshot
}

func writeLinuxPolicyValue(dir *os.File, name string, data []byte) error {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	_, writeErr := file.Write(data)
	aclErr := linuxtrust.ResetCreatedACL(file, false)
	modeErr := file.Chmod(0644)
	syncErr := file.Sync()
	return errors.Join(writeErr, aclErr, modeErr, syncErr, file.Close())
}

func (tx *linuxInstallationTransaction) StageAccepted(source, record []byte) error {
	if tx.pair != nil || tx.stageName != "" {
		return errors.New("policy candidate already staged")
	}
	accepted, err := readAcceptance(record)
	if err != nil {
		return err
	}
	if err := accepted.checkSource(source); err != nil {
		return err
	}
	name, err := randomLinuxStage(linuxAcceptanceStagePrefix)
	if err != nil {
		return err
	}
	pair := &linuxPolicyPair{parent: tx.parent, name: name, owner: tx.owner, persistent: tx.persistent, candidate: machineSnapshot{source: bytes.Clone(source), acceptance: bytes.Clone(record), present: true, acceptancePresent: true}}
	if err := syscall.Mkdirat(int(tx.parent.Fd()), name, 0700); err != nil {
		return err
	}
	tx.pair = pair
	pair.dir, err = linuxtrust.OpenDirectoryAt(tx.parent, name, tx.owner)
	if err != nil {
		return err
	}
	if err := linuxtrust.ResetCreatedACL(pair.dir, true); err != nil {
		return err
	}
	if err := writeLinuxPolicyValue(pair.dir, linuxPolicyFile, source); err != nil {
		return err
	}
	if err := writeLinuxPolicyValue(pair.dir, linuxAcceptanceFile, record); err != nil {
		return err
	}
	pair.ready = true
	return nil
}

func policyPairEqual(a, b machineSnapshot) bool {
	return a.acceptancePresent == b.acceptancePresent && bytes.Equal(a.source, b.source) && bytes.Equal(a.acceptance, b.acceptance)
}

func linuxPairEntries(dir *os.File, owner uint32, persistent bool) ([]string, error) {
	fd, err := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	scan := os.NewFile(uintptr(fd), ".")
	entries, err := scan.ReadDir(3)
	closeErr := scan.Close()
	if err != nil && err != io.EOF {
		return nil, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > 2 {
		return nil, errors.New("policy directory contains unrelated objects; administrator inspection required")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		limit := int64(MaxInstallationBytes)
		switch entry.Name() {
		case linuxPolicyFile:
		case linuxAcceptanceFile:
			limit = maxAcceptanceBytes
		default:
			return nil, errors.New("policy directory contains unrelated objects; administrator inspection required")
		}
		file, err := linuxtrust.OpenRegularAt(dir, entry.Name(), owner)
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		var diskErr error
		if persistent {
			diskErr = linuxtrust.CheckPersistent(file)
		}
		closeErr := file.Close()
		if err := errors.Join(statErr, diskErr, closeErr); err != nil {
			return nil, err
		}
		if info.Size() > limit || (info.Mode().Perm() != 0600 && info.Mode().Perm() != 0644) {
			return nil, errors.New("unexpected policy staging object; administrator inspection required")
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

func (pair *linuxPolicyPair) commit(tx *linuxInstallationTransaction) error {
	if !pair.ready {
		return errors.New("policy pair is incomplete")
	}
	if _, err := linuxPairEntries(pair.dir, pair.owner, pair.persistent); err != nil {
		return err
	}
	staged, err := readLinuxPolicySnapshot(pair.dir, pair.owner, pair.persistent)
	if err != nil {
		return err
	}
	if !policyPairEqual(staged, pair.candidate) {
		return errors.New("policy pair changed during staging")
	}
	if err := tx.lock.Sync(); err != nil {
		return err
	}
	if err := pair.dir.Chmod(0755); err != nil {
		return err
	}
	if err := pair.dir.Sync(); err != nil {
		return err
	}
	if tx.initial {
		if err := renameNoReplace(pair.parent, pair.name, linuxPolicyDirectory); err != nil {
			return err
		}
		pair.published = true
		pair.name = ""
		tx.committed = true
		return pair.parent.Sync()
	}
	current, err := linuxtrust.OpenDirectoryAt(pair.parent, linuxPolicyDirectory, pair.owner)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			current.Close()
		}
	}()
	before, err := tx.dir.Stat()
	if err != nil {
		return err
	}
	now, err := current.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, now) {
		return errors.New("policy directory changed during update")
	}
	if _, err := linuxPairEntries(current, pair.owner, pair.persistent); err != nil {
		return err
	}
	actual, err := readLinuxPolicySnapshot(current, pair.owner, pair.persistent)
	if err != nil {
		return err
	}
	expected := machineSnapshot{source: tx.prior, acceptance: tx.priorAcceptance, acceptancePresent: tx.priorAcceptancePresent}
	if !policyPairEqual(actual, expected) {
		return errors.New("enrolled policy or accepted history changed during update")
	}
	if err := exchangeLinuxDirectories(pair.parent, pair.name, linuxPolicyDirectory); err != nil {
		return err
	}
	pair.published = true
	tx.committed = true
	pair.displaced = current
	pair.cleanupExpected = actual
	keep = true
	return pair.parent.Sync()
}

func removeLinuxPairDirectory(parent *os.File, name string, owner uint32, persistent bool, expected *machineSnapshot, identity *os.File) error {
	dir, err := linuxtrust.OpenDirectoryAt(parent, name, owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	if identity != nil {
		before, beforeErr := identity.Stat()
		current, currentErr := dir.Stat()
		if err := errors.Join(beforeErr, currentErr); err != nil {
			return err
		}
		if !os.SameFile(before, current) {
			return errors.New("policy staging directory changed; preserved for administrator inspection")
		}
	}
	names, err := linuxPairEntries(dir, owner, persistent)
	if err != nil {
		return err
	}
	if expected != nil {
		actual, err := readLinuxPolicySnapshot(dir, owner, persistent)
		if err != nil {
			return err
		}
		if !policyPairEqual(actual, *expected) {
			return errors.New("displaced policy data changed; preserved for administrator inspection")
		}
	}
	for _, leaf := range names {
		if err := syscall.Unlinkat(int(dir.Fd()), leaf); err != nil {
			return err
		}
	}
	if err := removeDirectoryAt(parent, name); err != nil {
		return err
	}
	return parent.Sync()
}

func (pair *linuxPolicyPair) close() error {
	var result error
	if pair.name != "" {
		var expected *machineSnapshot
		if pair.published {
			expected = &pair.cleanupExpected
		} else if pair.ready {
			expected = &pair.candidate
		}
		identity := pair.dir
		if pair.published {
			identity = pair.displaced
		}
		result = removeLinuxPairDirectory(pair.parent, pair.name, pair.owner, pair.persistent, expected, identity)
	}
	if pair.displaced != nil {
		result = errors.Join(result, pair.displaced.Close())
		pair.displaced = nil
	}
	if pair.dir != nil {
		result = errors.Join(result, pair.dir.Close())
		pair.dir = nil
	}
	return result
}

func cleanupLinuxAcceptanceStages(parent *os.File, owner uint32) error {
	return scanLinuxStages(parent, linuxAcceptanceStagePrefix, func(name string) error {
		dir, err := linuxtrust.OpenDirectoryAt(parent, name, owner)
		if err != nil {
			return err
		}
		names, err := linuxPairEntries(dir, owner, false)
		if err != nil {
			dir.Close()
			return err
		}
		var expected *machineSnapshot
		if len(names) == 2 {
			snapshot, readErr := readLinuxPolicySnapshot(dir, owner, false)
			if readErr != nil {
				dir.Close()
				return readErr
			}
			accepted, recordErr := readAcceptance(snapshot.acceptance)
			// A displaced damaged source or externally changed complete candidate is
			// retained. It is not safe to infer its original bytes after a process exit.
			if recordErr != nil || accepted.checkSource(snapshot.source) != nil {
				return dir.Close()
			}
			expected = &snapshot
		}
		removeErr := removeLinuxPairDirectory(parent, name, owner, false, expected, dir)
		return errors.Join(removeErr, dir.Close())
	})
}
