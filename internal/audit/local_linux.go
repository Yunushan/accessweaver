//go:build linux && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
	"golang.org/x/sys/unix"
)

func LocalRecordingSupported() bool { return true }

// Open from / without following links or trusting writable/foreign ancestors.
// The final directory must already exist, be private, owned by the executing
// UID, and have persistent local storage. No path is created or repaired.
func openLocalAuditDirectory(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrJournalStorage
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrJournalStorage
	}
	current := os.NewFile(uintptr(fd), "audit-ancestor")
	owner := uint32(os.Geteuid())
	check := func(file *os.File, final bool) error {
		info, err := file.Stat()
		if err != nil {
			return ErrJournalStorage
		}
		native, ok := info.Sys().(*syscall.Stat_t)
		if !ok || native.Nlink == 0 || (native.Uid != 0 && native.Uid != owner) || (final && native.Uid != owner) {
			return ErrJournalStorage
		}
		checked, err := linuxtrust.Check(file, true, native.Uid)
		if err != nil || linuxtrust.CheckPersistent(file) != nil || (final && (checked.Mode().Perm() != 0700 || checked.Mode()&os.ModeSticky != 0)) {
			return ErrJournalStorage
		}
		return nil
	}
	if err := check(current, path == "/"); err != nil {
		current.Close()
		return nil, err
	}
	if path == "/" {
		return current, nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		fd, err := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := current.Close()
		if err != nil {
			return nil, ErrJournalStorage
		}
		next := os.NewFile(uintptr(fd), "audit-ancestor")
		if closeErr != nil || check(next, false) != nil {
			next.Close()
			return nil, ErrJournalStorage
		}
		current = next
	}
	if err := check(current, true); err != nil {
		current.Close()
		return nil, err
	}
	return current, nil
}

// InitializeLocalJournal creates a fresh random pseudonymization key and stream
// only in an existing empty protected directory. Keys are never returned or
// exported. Any partial initialization is preserved, never retried or replaced.
// Retain/authenticate the resulting genesis independently before using it.
func InitializeLocalJournal(directory string) (result Checkpoint, failure error) {
	dir, err := openLocalAuditDirectory(directory)
	if err != nil {
		return Checkpoint{}, err
	}
	defer func() {
		if dir.Close() != nil {
			result = Checkpoint{}
			failure = ErrJournalUncertain
		}
	}()
	names, err := dir.Readdirnames(1)
	if len(names) != 0 || !errors.Is(err, io.EOF) {
		return Checkpoint{}, ErrJournalStorage
	}
	var key [32]byte
	defer clear(key[:])
	if _, err := rand.Read(key[:]); err != nil {
		return Checkpoint{}, ErrProcessIdentity
	}
	producer, err := ProcessProducer(key)
	if err != nil {
		return Checkpoint{}, err
	}
	genesis, err := NewStream(producer)
	if err != nil {
		return Checkpoint{}, err
	}
	fd, err := unix.Openat(int(dir.Fd()), actorKeyName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return Checkpoint{}, ErrJournalStorage
	}
	file := os.NewFile(uintptr(fd), actorKeyName)
	payload := append([]byte(actorKeyPrefix), key[:]...)
	defer clear(payload)
	if linuxtrust.ResetCreatedACL(file, false) != nil || file.Chmod(0600) != nil {
		file.Close()
		return Checkpoint{}, ErrJournalUncertain
	}
	info, err := linuxtrust.Check(file, false, uint32(os.Geteuid()))
	if err != nil || info.Mode().Perm() != 0600 || linuxtrust.CheckPersistent(file) != nil {
		file.Close()
		return Checkpoint{}, ErrJournalUncertain
	}
	writeErr := commitJournalBytes(file, payload, 0)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || dir.Sync() != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	// Do not publish a genesis if the retained key differs from the exact key
	// used for its producer. Creation remains exclusive and never replaces data.
	retained, err := readLocalActorKey(dir, uint32(os.Geteuid()))
	same := retained == key
	clear(retained[:])
	if err != nil || !same {
		return Checkpoint{}, ErrJournalUncertain
	}
	journal, err := CreateLinuxJournal(dir, genesis)
	if err != nil {
		return Checkpoint{}, err
	}
	if journal.Close() != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	return genesis, nil
}

func readLocalActorKey(dir *os.File, owner uint32) (key [32]byte, failure error) {
	file, err := linuxtrust.OpenRegularAt(dir, actorKeyName, owner)
	if err != nil {
		return key, ErrJournalStorage
	}
	defer func() {
		if file.Close() != nil {
			clear(key[:])
			failure = ErrJournalStorage
		}
	}()
	before, err := file.Stat()
	if err != nil || before.Mode().Perm() != 0600 || before.Size() != int64(actorKeyFileBytes) || linuxtrust.CheckPersistent(file) != nil {
		return key, ErrJournalStorage
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(actorKeyFileBytes+1)))
	defer clear(data)
	if err != nil || len(data) != actorKeyFileBytes || !bytes.Equal(data[:len(actorKeyPrefix)], []byte(actorKeyPrefix)) {
		return key, ErrJournalStorage
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return key, ErrJournalStorage
	}
	named, err := linuxtrust.OpenRegularAt(dir, actorKeyName, owner)
	if err != nil {
		return key, ErrJournalStorage
	}
	info, statErr := named.Stat()
	closeErr := named.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(before, info) || info.Mode().Perm() != 0600 || info.Size() != before.Size() || !info.ModTime().Equal(before.ModTime()) {
		return key, ErrJournalStorage
	}
	copy(key[:], data[len(actorKeyPrefix):])
	if key == ([32]byte{}) {
		return key, ErrJournalStorage
	}
	return key, nil
}

type localLinuxJournal struct {
	mu          sync.Mutex
	journal     *LinuxJournal
	unavailable bool
}

// OpenLocalJournal checks the protected key/current OS/build producer against
// the independently supplied genesis, then verifies the exact retained head.
// It never adopts unknown records or enrolls a replacement producer implicitly.
func OpenLocalJournal(ctx context.Context, directory string, genesis, head Checkpoint) (result LocalJournal, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := openLocalAuditDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if dir.Close() != nil {
			if result != nil {
				_ = result.Close()
			}
			result = nil
			failure = ErrJournalStorage
		}
	}()
	key, err := readLocalActorKey(dir, uint32(os.Geteuid()))
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	producer, err := ProcessProducer(key)
	if err != nil || producer != genesis.Producer {
		return nil, ErrProcessIdentity
	}
	journal, err := OpenLinuxJournal(ctx, dir, genesis, head)
	if err != nil {
		return nil, err
	}
	return &localLinuxJournal{journal: journal}, nil
}
func (j *localLinuxJournal) Append(ctx context.Context, event Event) (Checkpoint, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.unavailable {
		return Checkpoint{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	key, err := readLocalActorKey(j.journal.dir, j.journal.owner)
	if err != nil {
		j.unavailable = true
		return Checkpoint{}, err
	}
	defer clear(key[:])
	producer, err := ProcessProducer(key)
	if err != nil || producer != j.journal.start.Producer {
		j.unavailable = true
		return Checkpoint{}, ErrProcessIdentity
	}
	return j.journal.Append(ctx, event)
}
func (j *localLinuxJournal) Snapshot(ctx context.Context) ([]byte, Checkpoint, Checkpoint, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.unavailable {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	return j.journal.Snapshot(ctx)
}
func (j *localLinuxJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.unavailable = true
	return j.journal.Close()
}
