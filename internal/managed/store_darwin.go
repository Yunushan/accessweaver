//go:build darwin && (amd64 || arm64)

package managed

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// These are fixed product names; callers cannot select the machine authority.
const darwinPolicyDirectory = "AccessWeaver"
const darwinPolicyFile = "installation.json"
const darwinAcceptanceFile = "acceptance.json"
const darwinPolicyLock = ".accessweaver-policy.lock"
const darwinStagePrefix = ".accessweaver-policy-stage-"

// This internal constructor transfers parent ownership, including on failure.
// Only owned fixtures may supply a non-root owner. Runtime callers must open the
// fixed protected parent and use root.
type darwinInstallationTransaction struct {
	parent, current, lock      *os.File
	owner                      uint32
	initial, committed, closed bool
	readSource, readRecord     bool
	prior                      machineSnapshot
	pair                       *darwinPolicyPair
}

type darwinPolicyPair struct {
	name                       string
	dir, displaced             *os.File
	candidate, cleanupExpected machineSnapshot
	ready, published           bool
}

func beginDarwinInstallation(parent *os.File, initial bool, owner uint32) (*darwinInstallationTransaction, error) {
	tx := &darwinInstallationTransaction{parent: parent, initial: initial, owner: owner}
	fail := func(err error) (*darwinInstallationTransaction, error) { return nil, errors.Join(err, tx.Close()) }
	if _, err := darwintrust.Check(parent, true, owner); err != nil {
		return fail(err)
	}
	lock, err := darwintrust.CreateRegularAt(parent, darwinPolicyLock, owner)
	if errors.Is(err, unix.EEXIST) {
		lock, err = darwintrust.OpenRegularAt(parent, darwinPolicyLock, owner)
	}
	if err != nil {
		return fail(err)
	}
	tx.lock = lock
	info, err := lock.Stat()
	if err != nil {
		return fail(err)
	}
	if info.Mode().Perm() != 0600 || info.Size() != 0 {
		return fail(errors.New("policy coordination file must be empty and private mode 0600"))
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fail(err)
		}
		if !time.Now().Before(deadline) {
			return fail(errors.New("policy update is busy; inspect managed status and retry"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A replaced coordination file must not create a second writer namespace.
	actual, err := darwintrust.OpenRegularAt(parent, darwinPolicyLock, owner)
	if err != nil {
		return fail(err)
	}
	before, beforeErr := lock.Stat()
	after, afterErr := actual.Stat()
	closeErr := actual.Close()
	if err := errors.Join(beforeErr, afterErr, closeErr); err != nil {
		return fail(err)
	}
	if !os.SameFile(before, after) {
		return fail(errors.New("policy coordination file changed while acquiring lock"))
	}
	current, err := darwintrust.OpenDirectoryAt(parent, darwinPolicyDirectory, owner)
	if initial {
		if err == nil {
			current.Close()
			return fail(errors.New("machine policy directory already exists; bootstrap cannot replace it"))
		}
		if !errors.Is(err, unix.ENOENT) {
			return fail(err)
		}
	} else {
		if err != nil {
			return fail(err)
		}
		tx.current = current
	}
	return tx, nil
}

func readDarwinValue(dir *os.File, name string, owner uint32, limit int64) ([]byte, error) {
	file, err := darwintrust.OpenRegularAt(dir, name, owner)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("native policy record exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := darwintrust.Check(file, false, owner)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit || int64(len(data)) != after.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("native policy record changed during reading")
	}
	return data, nil
}

func readDarwinPolicyPair(dir *os.File, owner uint32) (machineSnapshot, error) {
	snapshot := machineSnapshot{present: true}
	var err error
	snapshot.source, err = readDarwinValue(dir, darwinPolicyFile, owner, MaxInstallationBytes)
	if err != nil {
		return snapshot, err
	}
	snapshot.acceptance, err = readDarwinValue(dir, darwinAcceptanceFile, owner, maxAcceptanceBytes)
	if err != nil {
		return snapshot, err
	}
	snapshot.acceptancePresent = true
	return snapshot, nil
}

func sameDarwinDirectory(parent *os.File, name string, expected *os.File, owner uint32) (bool, error) {
	current, err := darwintrust.OpenDirectoryAt(parent, name, owner)
	if err != nil {
		return false, err
	}
	before, beforeErr := expected.Stat()
	after, afterErr := current.Stat()
	if err := errors.Join(beforeErr, afterErr, current.Close()); err != nil {
		return false, err
	}
	return os.SameFile(before, after), nil
}

func readDarwinSnapshotAt(parent *os.File, owner uint32) (machineSnapshot, error) {
	for attempt := 0; attempt < 3; attempt++ {
		dir, err := darwintrust.OpenDirectoryAt(parent, darwinPolicyDirectory, owner)
		if errors.Is(err, unix.ENOENT) {
			return machineSnapshot{}, nil
		}
		if err != nil {
			return machineSnapshot{present: true}, err
		}
		snapshot, readErr := readDarwinPolicyPair(dir, owner)
		same, checkErr := sameDarwinDirectory(parent, darwinPolicyDirectory, dir, owner)
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

func (tx *darwinInstallationTransaction) Read() ([]byte, bool, error) {
	if tx.closed {
		return nil, false, errors.New("policy transaction is closed")
	}
	if tx.initial {
		tx.readSource = true
		return nil, false, nil
	}
	data, err := readDarwinValue(tx.current, darwinPolicyFile, tx.owner, MaxInstallationBytes)
	if err == nil {
		tx.prior.source = bytes.Clone(data)
		tx.prior.present = true
		tx.readSource = true
	}
	return data, true, err
}
func (tx *darwinInstallationTransaction) ReadAcceptance() ([]byte, bool, error) {
	if tx.closed {
		return nil, false, errors.New("policy transaction is closed")
	}
	if tx.initial {
		tx.readRecord = true
		return nil, false, nil
	}
	data, err := readDarwinValue(tx.current, darwinAcceptanceFile, tx.owner, maxAcceptanceBytes)
	// macOS has no legacy one-file enrollment. Missing history is never optional.
	if err != nil {
		return nil, false, err
	}
	tx.prior.acceptance = bytes.Clone(data)
	tx.prior.acceptancePresent = true
	tx.readRecord = true
	return data, true, nil
}
func (tx *darwinInstallationTransaction) Stage([]byte) error {
	return errors.New("macOS policy publication requires an accepted policy pair")
}

// Apple's fsync flushes the host cache; F_FULLFSYNC additionally requests the
// drive-cache flush needed for publication ordering. Refuse unsupported/error
// results instead of silently downgrading. Actual power-loss qualification is
// still separate from a successful native call on a hosted fixture.
func syncDarwinPolicyObject(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var syncErr error
	controlErr := raw.Control(func(fd uintptr) { _, syncErr = unix.FcntlInt(fd, unix.F_FULLFSYNC, 0) })
	if err := errors.Join(syncErr, controlErr); err != nil {
		return fmt.Errorf("full native policy sync: %w", err)
	}
	return nil
}

func writeDarwinValue(dir *os.File, name string, data []byte, owner uint32) error {
	file, err := darwintrust.CreateRegularAt(dir, name, owner)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	modeErr := file.Chmod(0644)
	syncErr := syncDarwinPolicyObject(file)
	return errors.Join(writeErr, modeErr, syncErr, file.Close())
}

func (tx *darwinInstallationTransaction) StageAccepted(source, record []byte) error {
	if tx.closed || tx.committed || tx.pair != nil {
		return errors.New("policy transaction cannot stage another candidate")
	}
	if !tx.readSource || !tx.readRecord {
		return errors.New("policy and accepted preimages must be read before staging")
	}
	accepted, err := readAcceptance(record)
	if err != nil {
		return err
	}
	if err := accepted.checkSource(source); err != nil {
		return err
	}
	installed, err := parseInstallation(source)
	if err != nil {
		return err
	}
	if installed.SchemaVersion != 2 {
		return errors.New("macOS native publication requires version-two paired storage")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	pair := &darwinPolicyPair{name: darwinStagePrefix + hex.EncodeToString(random), candidate: machineSnapshot{source: bytes.Clone(source), acceptance: bytes.Clone(record), present: true, acceptancePresent: true}}
	// A collision belongs to somebody else and never enters our cleanup path.
	// Native creation/ACL failure may leave a private reserved directory; without
	// a held verified identity it is preserved for administrator inspection.
	dir, err := darwintrust.CreateDirectoryAt(tx.parent, pair.name, tx.owner)
	if err != nil {
		return err
	}
	pair.dir = dir
	tx.pair = pair
	if err := writeDarwinValue(dir, darwinPolicyFile, source, tx.owner); err != nil {
		return err
	}
	if err := writeDarwinValue(dir, darwinAcceptanceFile, record, tx.owner); err != nil {
		return err
	}
	pair.ready = true
	return nil
}

func equalDarwinPair(a, b machineSnapshot) bool {
	return a.acceptancePresent == b.acceptancePresent && bytes.Equal(a.source, b.source) && bytes.Equal(a.acceptance, b.acceptance)
}

// Reopen "." for an independent enumeration offset; never consume an active
// reader's directory offset. Reject unrelated entries before any unlink.
func darwinPairEntries(dir *os.File, owner uint32) ([]string, error) {
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	scan := os.NewFile(uintptr(fd), dir.Name())
	entries, readErr := scan.ReadDir(3)
	closeErr := scan.Close()
	if readErr != nil && readErr != io.EOF {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > 2 {
		return nil, errors.New("policy directory contains unrelated objects; preserved for administrator inspection")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		var limit int64
		switch entry.Name() {
		case darwinPolicyFile:
			limit = MaxInstallationBytes
		case darwinAcceptanceFile:
			limit = maxAcceptanceBytes
		default:
			return nil, errors.New("policy directory contains unrelated objects; preserved for administrator inspection")
		}
		file, err := darwintrust.OpenRegularAt(dir, entry.Name(), owner)
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		if err := errors.Join(statErr, file.Close()); err != nil {
			return nil, err
		}
		if info.Size() < 0 || info.Size() > limit || (info.Mode().Perm() != 0600 && info.Mode().Perm() != 0644) {
			return nil, errors.New("unexpected policy staging object; preserved for administrator inspection")
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

func (tx *darwinInstallationTransaction) Commit() error {
	if tx.closed || tx.committed || tx.pair == nil || !tx.pair.ready {
		return errors.New("no complete unpublished policy pair")
	}
	pair := tx.pair
	same, err := sameDarwinDirectory(tx.parent, pair.name, pair.dir, tx.owner)
	if err != nil {
		return err
	}
	if !same {
		return errors.New("candidate directory changed during staging")
	}
	if _, err := darwinPairEntries(pair.dir, tx.owner); err != nil {
		return err
	}
	staged, err := readDarwinPolicyPair(pair.dir, tx.owner)
	if err != nil {
		return err
	}
	if !equalDarwinPair(staged, pair.candidate) {
		return errors.New("candidate policy pair changed during staging")
	}
	if err := pair.dir.Chmod(0755); err != nil {
		return err
	}
	if err := syncDarwinPolicyObject(pair.dir); err != nil {
		return err
	}
	if tx.initial {
		if err := darwintrust.RenameDirectories(tx.parent, pair.name, darwinPolicyDirectory, false); err != nil {
			return err
		}
		pair.name = ""
		pair.published = true
		tx.committed = true
		return syncDarwinPolicyObject(tx.parent)
	}
	same, err = sameDarwinDirectory(tx.parent, darwinPolicyDirectory, tx.current, tx.owner)
	if err != nil {
		return err
	}
	if !same {
		return errors.New("enrolled policy directory changed during update")
	}
	if _, err := darwinPairEntries(tx.current, tx.owner); err != nil {
		return err
	}
	actual, err := readDarwinPolicyPair(tx.current, tx.owner)
	if err != nil {
		return err
	}
	if !equalDarwinPair(actual, tx.prior) {
		return errors.New("enrolled policy or accepted history changed during update")
	}
	if err := darwintrust.RenameDirectories(tx.parent, pair.name, darwinPolicyDirectory, true); err != nil {
		return err
	}
	pair.published = true
	tx.committed = true
	pair.displaced = tx.current
	tx.current = nil
	pair.cleanupExpected = actual
	return syncDarwinPolicyObject(tx.parent)
}
func (tx *darwinInstallationTransaction) Published() bool { return tx.committed }

func (tx *darwinInstallationTransaction) cleanupPair() error {
	pair := tx.pair
	if pair == nil || pair.name == "" {
		return nil
	}
	identity := pair.dir
	expected := pair.candidate
	if pair.published {
		identity = pair.displaced
		expected = pair.cleanupExpected
	}
	same, err := sameDarwinDirectory(tx.parent, pair.name, identity, tx.owner)
	if err != nil {
		return err
	}
	if !same {
		return errors.New("staging directory identity changed; preserved for administrator inspection")
	}
	dir, err := darwintrust.OpenDirectoryAt(tx.parent, pair.name, tx.owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	names, err := darwinPairEntries(dir, tx.owner)
	if err != nil {
		return err
	}
	// Verify every existing leaf against its exact known bytes before deleting
	// anything. Partial failed writes or independent changes are retained.
	for _, name := range names {
		want := expected.source
		limit := int64(MaxInstallationBytes)
		if name == darwinAcceptanceFile {
			want = expected.acceptance
			limit = maxAcceptanceBytes
		}
		actual, err := readDarwinValue(dir, name, tx.owner, limit)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, want) {
			return errors.New("staged or displaced policy changed; preserved for administrator inspection")
		}
	}
	if pair.ready && len(names) != 2 {
		return errors.New("staged or displaced policy layout changed; preserved for administrator inspection")
	}
	for _, name := range names {
		if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(int(tx.parent.Fd()), pair.name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	pair.name = ""
	return syncDarwinPolicyObject(tx.parent)
}

func (tx *darwinInstallationTransaction) Close() error {
	if tx.closed {
		return nil
	}
	tx.closed = true
	var result error
	if tx.pair != nil {
		result = tx.cleanupPair()
		if tx.pair.displaced != nil {
			result = errors.Join(result, tx.pair.displaced.Close())
		}
		if tx.pair.dir != nil {
			result = errors.Join(result, tx.pair.dir.Close())
		}
	}
	if tx.current != nil {
		result = errors.Join(result, tx.current.Close())
	}
	// Keep the lock until publication, sync and conservative cleanup are done.
	if tx.lock != nil {
		result = errors.Join(result, tx.lock.Close())
	}
	if tx.parent != nil {
		result = errors.Join(result, tx.parent.Close())
	}
	return result
}
