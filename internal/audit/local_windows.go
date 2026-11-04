//go:build windows && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"runtime"
	"sync"
)

// The Windows implementation is kept behind native qualification. Public local
// recording remains unsupported until its full CLI and managed contracts pass.
// Every owner closes the journal before the borrowed directory. No failure
// repairs, replaces or deletes either file, including partial initialization.
func initializeWindowsLocalJournal(directory string) (result Checkpoint, failure error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dir, err := openWindowsAuditDirectory(directory)
	if err != nil {
		return Checkpoint{}, err
	}
	defer func() {
		principalErr := dir.checkPrincipalLocked()
		closeErr := dir.Close()
		if principalErr != nil || closeErr != nil {
			result, failure = Checkpoint{}, ErrJournalUncertain
		}
	}()
	if err := dir.requireEmpty(); err != nil {
		return Checkpoint{}, err
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
	file, err := dir.createRegular(actorKeyName)
	if err != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	payload := append([]byte(actorKeyPrefix), key[:]...)
	defer clear(payload)
	writeErr := commitJournalBytes(file, payload, 0)
	_, stateErr := dir.fileState(file, actorKeyName)
	closeErr := file.Close()
	if writeErr != nil || stateErr != nil || closeErr != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	retained, err := readWindowsLocalActorKey(dir)
	same := retained == key
	clear(retained[:])
	if err != nil || !same {
		return Checkpoint{}, ErrJournalUncertain
	}
	journal, err := createWindowsJournal(dir, genesis)
	if err != nil {
		return Checkpoint{}, err
	}
	closeErr = journal.Close()
	retained, err = readWindowsLocalActorKey(dir)
	same = retained == key
	clear(retained[:])
	if closeErr != nil || err != nil || !same || dir.checkBinding() != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	return genesis, nil
}

// readWindowsLocalActorKey requires exact private framing and a stable native
// file/name binding. It never creates a replacement key. Historical export does
// not call this function or require current producer metadata.
func readWindowsLocalActorKey(dir *windowsAuditDirectory) (key [32]byte, failure error) {
	if dir == nil {
		return key, ErrJournalStorage
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if dir.checkPrincipalLocked() != nil {
		return key, ErrProcessIdentity
	}
	file, err := dir.openRegular(actorKeyName, false)
	if err != nil {
		return key, err
	}
	defer func() {
		closeErr := file.Close()
		if dir.checkPrincipalLocked() != nil {
			clear(key[:])
			failure = ErrProcessIdentity
		} else if closeErr != nil {
			clear(key[:])
			failure = ErrJournalStorage
		}
	}()
	before, err := dir.fileState(file, actorKeyName)
	if err != nil || before.size != int64(actorKeyFileBytes) {
		return key, ErrJournalStorage
	}
	data := make([]byte, actorKeyFileBytes)
	defer clear(data)
	if n, err := file.ReadAt(data, 0); err != nil || n != len(data) || !bytes.Equal(data[:len(actorKeyPrefix)], []byte(actorKeyPrefix)) {
		return key, ErrJournalStorage
	}
	// A second exact read detects key changes even when a writer still holds a
	// handle and NTFS has not yet published its last-write timestamp.
	repeat := make([]byte, actorKeyFileBytes)
	defer clear(repeat)
	if n, err := file.ReadAt(repeat, 0); err != nil || n != len(repeat) || !bytes.Equal(data, repeat) {
		return key, ErrJournalStorage
	}
	after, err := dir.fileState(file, actorKeyName)
	if err != nil || after != before {
		return key, ErrJournalStorage
	}
	copy(key[:], data[len(actorKeyPrefix):])
	if key == ([32]byte{}) {
		return key, ErrJournalStorage
	}
	return key, nil
}

type localWindowsJournal struct {
	mu                  sync.Mutex
	dir                 *windowsAuditDirectory
	journal             *windowsJournal
	unavailable, closed bool
	closeErr            error
}

func openWindowsLocalJournal(ctx context.Context, directory string, genesis, head Checkpoint) (result LocalJournal, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if genesis.Sequence != 0 || validateCheckpoint(genesis) != nil || validateCheckpoint(head) != nil {
		return nil, ErrJournalStorage
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dir, err := openWindowsAuditDirectory(directory)
	if err != nil {
		return nil, err
	}
	local := &localWindowsJournal{dir: dir}
	defer func() {
		if dir.checkPrincipalLocked() != nil {
			result, failure = nil, ErrProcessIdentity
		}
		if result == nil && local.Close() != nil {
			failure = ErrJournalStorage
		}
	}()
	if err := local.checkProducer(genesis.Producer); err != nil {
		return nil, err
	}
	local.journal, err = openWindowsJournal(ctx, dir, genesis, head)
	if err != nil {
		return nil, err
	}
	if err := local.checkProducer(genesis.Producer); err != nil {
		return nil, err
	}
	return local, nil
}

func (j *localWindowsJournal) checkProducer(expected Producer) error {
	if j.dir == nil || j.dir.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	key, err := readWindowsLocalActorKey(j.dir)
	if err != nil {
		return err
	}
	defer clear(key[:])
	producer, err := ProcessProducer(key)
	if err != nil || producer != expected || j.dir.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	return nil
}

func (j *localWindowsJournal) Append(ctx context.Context, event Event) (Checkpoint, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.journal == nil || j.dir == nil {
		return Checkpoint{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := j.checkProducer(j.journal.start.Producer); err != nil {
		j.unavailable = true
		return Checkpoint{}, err
	}
	next, err := j.journal.Append(ctx, event)
	if err != nil {
		return Checkpoint{}, err
	}
	// A successful low-level write is not released to the caller if its key or
	// executing producer changed during that write. Preserve the resulting tail.
	if j.checkProducer(j.journal.start.Producer) != nil || j.dir.checkBinding() != nil {
		j.unavailable = true
		return Checkpoint{}, ErrJournalUncertain
	}
	return next, nil
}

func (j *localWindowsJournal) Snapshot(ctx context.Context) ([]byte, Checkpoint, Checkpoint, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.journal == nil || j.dir == nil {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := j.checkProducer(j.journal.start.Producer); err != nil {
		j.unavailable = true
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	data, start, head, err := j.journal.Snapshot(ctx)
	if err != nil {
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	if err := j.checkProducer(start.Producer); err != nil {
		clear(data)
		j.unavailable = true
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	return data, start, head, nil
}

func (j *localWindowsJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return j.closeErr
	}
	j.closed, j.unavailable = true, true
	// Never short-circuit cleanup when the first close fails.
	if j.journal != nil && j.journal.Close() != nil {
		j.closeErr = ErrJournalStorage
	}
	if j.dir != nil && j.dir.Close() != nil && j.closeErr == nil {
		j.closeErr = ErrJournalStorage
	}
	return j.closeErr
}

var _ LocalJournal = (*localWindowsJournal)(nil)
