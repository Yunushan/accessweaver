//go:build darwin && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"sync"
)

// The current-producer adapter owns dir and journal; journal borrows dir.
// A key is a pseudonymization
// secret, not a signature, account authentication or collector acknowledgment.
// Existing and uncertain objects are never repaired, replaced or deleted.
func initializeDarwinLocalJournal(directory string) (result Checkpoint, failure error) {
	dir, err := openDarwinAuditDirectory(directory)
	if err != nil {
		return Checkpoint{}, err
	}
	local := &localDarwinJournal{dir: dir}
	mutationAttempted := false
	defer func() {
		if err := local.Close(); err != nil {
			result = Checkpoint{}
			failure = darwinJournalReadError(err)
			if mutationAttempted {
				failure = ErrJournalUncertain
			}
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
	mutationAttempted = true
	if err := createDarwinLocalActorKey(dir, key); err != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	retained, err := readDarwinLocalActorKey(dir)
	same := retained == key
	clear(retained[:])
	if err != nil || !same || local.checkProducer(genesis.Producer) != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	local.journal, err = createDarwinJournal(dir, genesis)
	if err != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	if err := local.journal.Close(); err != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	retained, err = readDarwinLocalActorKey(dir)
	same = retained == key
	clear(retained[:])
	if err != nil || !same || local.checkProducer(genesis.Producer) != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	if err := dir.checkBinding(); err != nil {
		return Checkpoint{}, ErrJournalUncertain
	}
	return genesis, nil
}

// createDarwinLocalActorKey owns only a new exclusive key file. Its RW descriptor
// is prepared by the storage facade before any secret bytes, then its directory
// scope is reacquired and revalidated through write/full-sync/readback/close.
func createDarwinLocalActorKey(dir *darwinAuditDirectory, key [32]byte) (failure error) {
	defer clear(key[:])
	if dir == nil {
		return ErrJournalStorage
	}
	if key == ([32]byte{}) {
		return ErrProcessIdentity
	}
	file, err := dir.createRegular(actorKeyName)
	if err != nil {
		return err
	}
	dir.mu.Lock()
	defer dir.mu.Unlock()
	defer func() {
		closeErr := file.Close()
		bindingErr := dir.checkBindingLocked()
		principalErr := checkDarwinJournalPrincipalLocked(dir)
		if closeErr != nil || principalErr != nil || bindingErr != nil {
			failure = ErrJournalUncertain
		}
	}()
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return ErrProcessIdentity
	}
	if err := dir.checkBindingLocked(); err != nil {
		return darwinJournalReadError(err)
	}
	disk := &darwinJournalCommitter{file: file, parent: dir.dir}
	return writeDarwinLocalActorKeyLocked(dir, file, key, disk)
}

// Caller holds dir.mu and owns a still-empty, exclusively created private file.
// Production always supplies the real file+directory full-sync committer. This
// private core adds no public, global or environment-selected I/O override.
func writeDarwinLocalActorKeyLocked(dir *darwinAuditDirectory, file *os.File, key [32]byte, disk journalCommitter) (failure error) {
	defer clear(key[:])
	if dir == nil || file == nil || disk == nil {
		return ErrJournalStorage
	}
	if key == ([32]byte{}) {
		return ErrProcessIdentity
	}
	mutationAttempted := false
	defer func() {
		if checkDarwinJournalPrincipalLocked(dir) != nil {
			failure = ErrProcessIdentity
			if mutationAttempted {
				failure = ErrJournalUncertain
			}
		}
	}()
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return ErrProcessIdentity
	}
	before, err := dir.fileStateLocked(file, actorKeyName)
	if err != nil || before.size != 0 {
		return darwinJournalReadError(err)
	}
	var payload [actorKeyFileBytes]byte
	defer clear(payload[:])
	copy(payload[:], actorKeyPrefix)
	copy(payload[len(actorKeyPrefix):], key[:])
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return ErrProcessIdentity
	}
	mutationAttempted = true
	if commitJournalBytes(disk, payload[:], 0) != nil {
		return ErrJournalUncertain
	}
	retained, err := readDarwinLocalActorKeyLocked(dir, file)
	defer clear(retained[:])
	if err != nil || retained != key {
		return ErrJournalUncertain
	}
	after, err := dir.fileStateLocked(file, actorKeyName)
	if err != nil || after.id != before.id || after.size != int64(actorKeyFileBytes) {
		return ErrJournalUncertain
	}
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return ErrJournalUncertain
	}
	return nil
}

// No read path creates or resets a missing/changed key. The returned key is
// cleared again if any late scope/principal/descriptor-close check fails.
func readDarwinLocalActorKey(dir *darwinAuditDirectory) (key [32]byte, failure error) {
	if dir == nil {
		return key, ErrJournalStorage
	}
	file, err := dir.openRegular(actorKeyName, false)
	if err != nil {
		return key, err
	}
	dir.mu.Lock()
	defer dir.mu.Unlock()
	defer func() {
		closeErr := file.Close()
		bindingErr := dir.checkBindingLocked()
		if closeErr != nil || bindingErr != nil {
			clear(key[:])
			failure = ErrJournalStorage
		}
		if checkDarwinJournalPrincipalLocked(dir) != nil {
			clear(key[:])
			failure = ErrProcessIdentity
		}
	}()
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return key, ErrProcessIdentity
	}
	if err := dir.checkBindingLocked(); err != nil {
		return key, darwinJournalReadError(err)
	}
	return readDarwinLocalActorKeyLocked(dir, file)
}

// Caller owns file and holds dir.mu. All bytes, metadata and named bindings must
// agree on both exact reads. The caller closes file before releasing any key.
func readDarwinLocalActorKeyLocked(dir *darwinAuditDirectory, file *os.File) (key [32]byte, failure error) {
	if dir == nil || file == nil {
		return key, ErrJournalStorage
	}
	defer func() {
		if checkDarwinJournalPrincipalLocked(dir) != nil {
			failure = ErrProcessIdentity
		}
		if failure != nil {
			clear(key[:])
		}
	}()
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return key, ErrProcessIdentity
	}
	before, err := dir.fileStateLocked(file, actorKeyName)
	if err != nil || before.size != int64(actorKeyFileBytes) {
		return key, darwinJournalReadError(err)
	}
	var data, repeat [actorKeyFileBytes]byte
	defer clear(data[:])
	defer clear(repeat[:])
	if n, err := file.ReadAt(data[:], 0); err != nil || n != len(data) || !bytes.Equal(data[:len(actorKeyPrefix)], []byte(actorKeyPrefix)) {
		return key, ErrJournalStorage
	}
	if n, err := file.ReadAt(repeat[:], 0); err != nil || n != len(repeat) || !bytes.Equal(data[:], repeat[:]) {
		return key, ErrJournalStorage
	}
	after, err := dir.fileStateLocked(file, actorKeyName)
	if err != nil || after != before {
		return key, darwinJournalReadError(err)
	}
	copy(key[:], data[len(actorKeyPrefix):])
	if key == ([32]byte{}) {
		return key, ErrJournalStorage
	}
	return key, nil
}

type localDarwinJournal struct {
	mu                  sync.Mutex
	dir                 *darwinAuditDirectory
	journal             *darwinJournal
	unavailable, closed bool
	closeErr            error
}

func openDarwinLocalJournal(ctx context.Context, directory string, genesis, head Checkpoint) (result LocalJournal, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validDarwinJournalEndpoints(genesis, head) {
		return nil, ErrJournalStorage
	}
	dir, err := openDarwinAuditDirectory(directory)
	if err != nil {
		return nil, err
	}
	local := &localDarwinJournal{dir: dir}
	defer func() {
		if result == nil {
			if err := local.Close(); err != nil && failure == nil {
				failure = darwinJournalReadError(err)
			}
		}
	}()
	if err := local.checkProducer(genesis.Producer); err != nil {
		return nil, err
	}
	local.journal, err = openDarwinJournal(ctx, dir, genesis, head)
	if err != nil {
		return nil, err
	}
	if err := local.checkProducer(genesis.Producer); err != nil {
		return nil, err
	}
	return local, nil
}

// Called with adapter.mu for published adapters; it acquires only the key's
// directory scope, never journal.mu while holding dir.mu. Producer comes from
// the actual process/build and is compared in full with the enrolled claim.
func (local *localDarwinJournal) checkProducer(expected Producer) error {
	if local == nil || local.dir == nil {
		return ErrProcessIdentity
	}
	key, err := readDarwinLocalActorKey(local.dir)
	if err != nil {
		return err
	}
	defer clear(key[:])
	producer, err := ProcessProducer(key)
	if err != nil || producer != expected {
		return ErrProcessIdentity
	}
	return local.dir.checkBinding()
}

// Called only while adapter.mu is held and no raw journal method is in flight.
func (local *localDarwinJournal) poison() {
	local.unavailable = true
	if local.journal != nil {
		local.journal.mu.Lock()
		local.journal.unavailable = true
		local.journal.mu.Unlock()
	}
}

func (local *localDarwinJournal) Append(ctx context.Context, event Event) (Checkpoint, error) {
	if local == nil {
		return Checkpoint{}, ErrJournalUnavailable
	}
	local.mu.Lock()
	defer local.mu.Unlock()
	if local.closed || local.unavailable || local.journal == nil || local.dir == nil {
		return Checkpoint{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	if err := local.checkProducer(local.journal.start.Producer); err != nil {
		local.poison()
		return Checkpoint{}, err
	}
	local.journal.mu.Lock()
	previousHead, previousSize := local.journal.head, local.journal.size
	local.journal.mu.Unlock()
	next, err := local.journal.Append(ctx, event)
	if err != nil {
		if errors.Is(err, ErrJournalStorage) || errors.Is(err, ErrProcessIdentity) || errors.Is(err, ErrJournalUncertain) || errors.Is(err, ErrJournalUnavailable) {
			local.poison()
		}
		return Checkpoint{}, err
	}
	// Do not release a low-level checkpoint if its current key/process/build
	// binding changed. Restore only the adapter's acknowledged in-memory endpoint;
	// the already-written tail is preserved and both layers remain unavailable.
	if local.checkProducer(previousHead.Producer) != nil || local.dir.checkBinding() != nil {
		local.unavailable = true
		local.journal.mu.Lock()
		local.journal.unavailable = true
		local.journal.head, local.journal.size = previousHead, previousSize
		local.journal.mu.Unlock()
		return Checkpoint{}, ErrJournalUncertain
	}
	return next, nil
}

func (local *localDarwinJournal) Snapshot(ctx context.Context) (data []byte, start, head Checkpoint, failure error) {
	if local == nil {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	local.mu.Lock()
	defer local.mu.Unlock()
	if local.closed || local.unavailable || local.journal == nil || local.dir == nil {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	if err := local.checkProducer(local.journal.start.Producer); err != nil {
		local.poison()
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	data, start, head, err := local.journal.Snapshot(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			local.poison()
		}
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	if err := local.checkProducer(start.Producer); err != nil {
		clear(data)
		local.poison()
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	return data, start, head, nil
}

func (local *localDarwinJournal) Close() error {
	if local == nil {
		return nil
	}
	local.mu.Lock()
	defer local.mu.Unlock()
	if local.closed {
		return local.closeErr
	}
	local.closed, local.unavailable = true, true
	// Never short-circuit cleanup after an earlier failure.
	if local.journal != nil {
		if err := local.journal.Close(); err != nil {
			local.closeErr = darwinJournalReadError(err)
		}
	}
	if local.dir != nil {
		if err := local.dir.Close(); err != nil && local.closeErr == nil {
			local.closeErr = darwinJournalReadError(err)
		}
	}
	return local.closeErr
}

var _ LocalJournal = (*localDarwinJournal)(nil)
