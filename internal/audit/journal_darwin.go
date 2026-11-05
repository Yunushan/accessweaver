//go:build darwin && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// darwinJournal borrows dir and owns exactly one data file and its advisory
// exclusive flock until Close. Its caller must close the journal before dir.
// Lock order is journal.mu then dir.mu; both remain held throughout payload
// read/write, file+directory full sync and readback. No data descriptor is
// duplicated, no sidecar is used, and no native call is abandoned on timeout.
// Full-sync success is not physical power-loss qualification. No failure
// deletes, truncates, repairs, retries or adopts an unacknowledged tail.
// This unit neither reads actor-key contents nor authenticates Producer claims;
// current-key/build enrollment belongs to a separate future local adapter.
type darwinJournal struct {
	mu                  sync.Mutex
	dir                 *darwinAuditDirectory
	file                *os.File
	disk                journalCommitter
	start, head         Checkpoint
	size                int64
	unavailable, closed bool
	closeErr            error
}

// The real committer borrows both handles. Its owning journal holds both scope
// locks; only the journal closes file, and only the directory owner closes parent.
type darwinJournalCommitter struct{ file, parent *os.File }

func (disk *darwinJournalCommitter) WriteAt(data []byte, offset int64) (int, error) {
	if disk == nil || disk.file == nil {
		return 0, ErrJournalUncertain
	}
	return disk.file.WriteAt(data, offset)
}
func (disk *darwinJournalCommitter) Sync() error {
	if disk == nil || darwinFullSync(disk.file) != nil {
		return ErrJournalUncertain
	}
	if darwinFullSync(disk.parent) != nil {
		return ErrJournalUncertain
	}
	return nil
}

// No fsync-only or barrier fallback is permitted, including for a directory.
// A filesystem that refuses directory F_FULLFSYNC cannot qualify this contract.
func darwinFullSync(file *os.File) error {
	if file == nil || file.Sync() != nil {
		return ErrJournalUncertain
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return ErrJournalUncertain
	}
	var syncErr error
	controlErr := raw.Control(func(fd uintptr) { _, syncErr = unix.FcntlInt(fd, unix.F_FULLFSYNC, 0) })
	if syncErr != nil || controlErr != nil {
		return ErrJournalUncertain
	}
	return nil
}

// Advisory flock uses the actual data file. Final owning close releases it;
// no explicit unlock, waiting, retry, lock downgrade or duplicated owner exists.
func lockDarwinAuditJournal(file *os.File, exclusive bool) error {
	if file == nil {
		return ErrJournalStorage
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return ErrJournalStorage
	}
	flags := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		flags = unix.LOCK_EX | unix.LOCK_NB
	}
	var lockErr error
	controlErr := raw.Control(func(fd uintptr) { lockErr = unix.Flock(int(fd), flags) })
	if controlErr != nil {
		return ErrJournalStorage
	}
	if errors.Is(lockErr, unix.EWOULDBLOCK) || errors.Is(lockErr, unix.EAGAIN) {
		return ErrJournalBusy
	}
	if lockErr != nil {
		return ErrJournalStorage
	}
	return nil
}

// Caller holds dir.mu. The real/effective credential snapshot comes from the
// admitted storage scope, never account names or environment variables.
func checkDarwinJournalPrincipalLocked(dir *darwinAuditDirectory) error {
	if dir == nil || dir.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	return nil
}
func darwinJournalReadError(err error) error {
	if errors.Is(err, ErrProcessIdentity) {
		return ErrProcessIdentity
	}
	return darwinAuditStorageRejection(err)
}
func validDarwinJournalEndpoints(start, head Checkpoint) bool {
	return start.Sequence == 0 && validateCheckpoint(start) == nil && validateCheckpoint(head) == nil && start.StreamID == head.StreamID && start.Producer == head.Producer && head.Sequence <= MaxSegmentRecords
}

func createDarwinJournal(dir *darwinAuditDirectory, genesis Checkpoint) (result *darwinJournal, failure error) {
	if dir == nil || !validDarwinJournalEndpoints(genesis, genesis) {
		return nil, ErrJournalStorage
	}
	j := &darwinJournal{dir: dir}
	// Registered before the scope unlocks so failed construction closes only
	// after both locks have been released; Close follows the same lock order.
	defer func() {
		if result == nil {
			if err := j.Close(); err != nil && failure == nil {
				failure = err
			}
		}
	}()
	j.mu.Lock()
	defer j.mu.Unlock()
	file, err := dir.createRegular(journalName)
	if err != nil {
		return nil, err
	}
	j.file = file
	dir.mu.Lock()
	defer dir.mu.Unlock()
	// The facade above owns dir.mu for opening; revalidate after reacquiring it.
	// A concurrent dir.Close in that gap refuses before any payload is written.
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return nil, ErrProcessIdentity
	}
	if err := dir.checkBindingLocked(); err != nil {
		return nil, darwinJournalReadError(err)
	}
	j.disk = &darwinJournalCommitter{file: file, parent: dir.dir}
	if err := j.initializeLocked(genesis); err != nil {
		return nil, err
	}
	return j, nil
}

func openDarwinJournal(ctx context.Context, dir *darwinAuditDirectory, genesis, head Checkpoint) (result *darwinJournal, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dir == nil || !validDarwinJournalEndpoints(genesis, head) {
		return nil, ErrJournalStorage
	}
	j := &darwinJournal{dir: dir}
	defer func() {
		if result == nil {
			if err := j.Close(); err != nil && failure == nil {
				failure = err
			}
		}
	}()
	j.mu.Lock()
	defer j.mu.Unlock()
	file, err := dir.openRegular(journalName, true)
	if err != nil {
		return nil, err
	}
	j.file = file
	dir.mu.Lock()
	defer dir.mu.Unlock()
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return nil, ErrProcessIdentity
	}
	if err := dir.checkBindingLocked(); err != nil {
		return nil, darwinJournalReadError(err)
	}
	j.disk = &darwinJournalCommitter{file: file, parent: dir.dir}
	if err := j.reconcileLocked(ctx, genesis, head); err != nil {
		return nil, err
	}
	return j, nil
}

// These private initialization/reconciliation cores require journal.mu and
// dir.mu, an owned checked candidate file and a committer. Production constructors
// install only the real committer; there is no public or environment override.
func (j *darwinJournal) initializeLocked(genesis Checkpoint) (failure error) {
	if j == nil || j.dir == nil || j.file == nil || j.disk == nil || !validDarwinJournalEndpoints(genesis, genesis) {
		return ErrJournalStorage
	}
	if j.closed || j.unavailable {
		return ErrJournalUnavailable
	}
	previousStart, previousHead, previousSize := j.start, j.head, j.size
	mutationAttempted := false
	defer func() {
		if failure != nil {
			j.unavailable = true
		}
		if checkDarwinJournalPrincipalLocked(j.dir) != nil {
			j.unavailable = true
			failure = ErrProcessIdentity
			if mutationAttempted {
				j.start, j.head, j.size = previousStart, previousHead, previousSize
				failure = ErrJournalUncertain
			}
		}
	}()
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		return ErrProcessIdentity
	}
	if err := j.dir.checkBindingLocked(); err != nil {
		return darwinJournalReadError(err)
	}
	if err := lockDarwinAuditJournal(j.file, true); err != nil {
		return err
	}
	state, err := j.dir.fileStateLocked(j.file, journalName)
	if err != nil || state.size != 0 {
		return darwinJournalReadError(err)
	}
	data, err := EncodeCheckpoint(genesis)
	if err != nil {
		return ErrJournalStorage
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		return ErrProcessIdentity
	}
	mutationAttempted = true
	if commitJournalBytes(j.disk, data, 0) != nil {
		return ErrJournalUncertain
	}
	if _, err := readDarwinAuditJournalLocked(context.Background(), j.dir, j.file, genesis, genesis, int64(len(data))); err != nil {
		return ErrJournalUncertain
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		return ErrJournalUncertain
	}
	j.start, j.head, j.size = genesis, genesis, int64(len(data))
	return nil
}

// Only complete independently supplied endpoints may be reconciled. Sync may
// persist that exact existing stream; it never derives or edits its ending head.
func (j *darwinJournal) reconcileLocked(ctx context.Context, genesis, head Checkpoint) (failure error) {
	if j == nil || j.dir == nil || j.file == nil || j.disk == nil || !validDarwinJournalEndpoints(genesis, head) {
		return ErrJournalStorage
	}
	if j.closed || j.unavailable {
		return ErrJournalUnavailable
	}
	previousStart, previousHead, previousSize := j.start, j.head, j.size
	flushAttempted := false
	defer func() {
		if failure != nil && !errors.Is(failure, context.Canceled) && !errors.Is(failure, context.DeadlineExceeded) {
			j.unavailable = true
		}
		if checkDarwinJournalPrincipalLocked(j.dir) != nil {
			j.unavailable = true
			failure = ErrProcessIdentity
			if flushAttempted {
				j.start, j.head, j.size = previousStart, previousHead, previousSize
				failure = ErrJournalUncertain
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		return ErrProcessIdentity
	}
	if err := j.dir.checkBindingLocked(); err != nil {
		return darwinJournalReadError(err)
	}
	if err := lockDarwinAuditJournal(j.file, true); err != nil {
		return err
	}
	state, err := j.dir.fileStateLocked(j.file, journalName)
	if err != nil {
		return darwinJournalReadError(err)
	}
	if _, err := readDarwinAuditJournalLocked(ctx, j.dir, j.file, genesis, head, state.size); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		return ErrProcessIdentity
	}
	flushAttempted = true
	if j.disk.Sync() != nil {
		return ErrJournalUncertain
	}
	if _, err := readDarwinAuditJournalLocked(context.Background(), j.dir, j.file, genesis, head, state.size); err != nil {
		return ErrJournalUncertain
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		return ErrJournalUncertain
	}
	j.start, j.head, j.size = genesis, head, state.size
	return nil
}

// Caller holds dir.mu and a real EX/SH data lock. This bounded reader is also
// suitable for later historical export: it never reads the key or compares the
// enrolled Producer to the current build/principal. It still binds the executing
// storage principal on both sides of all I/O and returns event lines only.
func readDarwinAuditJournalLocked(ctx context.Context, dir *darwinAuditDirectory, file *os.File, start, head Checkpoint, size int64) (data []byte, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dir == nil || file == nil || !validDarwinJournalEndpoints(start, head) || size <= 0 || size > MaxJournalBytes {
		return nil, ErrJournalStorage
	}
	var raw []byte
	defer func() {
		if checkDarwinJournalPrincipalLocked(dir) != nil {
			data, failure = nil, ErrProcessIdentity
		}
		if failure != nil {
			clear(raw)
		}
	}()
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return nil, ErrProcessIdentity
	}
	before, err := dir.fileStateLocked(file, journalName)
	if err != nil || before.size != size {
		return nil, darwinJournalReadError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err = io.ReadAll(io.NewSectionReader(file, 0, MaxJournalBytes+1))
	if err != nil || int64(len(raw)) != size || len(raw) > MaxJournalBytes {
		return nil, ErrJournalStorage
	}
	first := bytes.IndexByte(raw, '\n') + 1
	if first <= 0 || first > MaxCheckpointBytes {
		return nil, ErrJournalStorage
	}
	actual, err := DecodeCheckpoint(raw[:first])
	if err != nil || actual != start {
		return nil, ErrJournalStorage
	}
	if _, err := VerifySegment(ctx, bytes.NewReader(raw[first:]), start, head); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrJournalStorage
	}
	after, err := dir.fileStateLocked(file, journalName)
	if err != nil || after != before {
		return nil, darwinJournalReadError(err)
	}
	return raw[first:], nil
}

func (j *darwinJournal) Append(ctx context.Context, event Event) (result Checkpoint, failure error) {
	if j == nil {
		return Checkpoint{}, ErrJournalUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.file == nil || j.dir == nil || j.disk == nil {
		return Checkpoint{}, ErrJournalUnavailable
	}
	j.dir.mu.Lock()
	defer j.dir.mu.Unlock()
	previousHead, previousSize := j.head, j.size
	mutationAttempted := false
	defer func() {
		if checkDarwinJournalPrincipalLocked(j.dir) != nil {
			j.unavailable = true
			result, failure = Checkpoint{}, ErrProcessIdentity
			if mutationAttempted {
				j.head, j.size = previousHead, previousSize
				failure = ErrJournalUncertain
			}
		}
	}()
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		j.unavailable = true
		return Checkpoint{}, ErrProcessIdentity
	}
	line, next, err := Append(j.head, event)
	if err != nil {
		return Checkpoint{}, err
	}
	if j.head.Sequence >= MaxSegmentRecords || j.size+int64(len(line)) > MaxJournalBytes {
		return Checkpoint{}, ErrJournalFull
	}
	if _, err := readDarwinAuditJournalLocked(ctx, j.dir, j.file, j.start, j.head, j.size); err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			j.unavailable = true
		}
		return Checkpoint{}, err
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		j.unavailable = true
		return Checkpoint{}, ErrProcessIdentity
	}
	mutationAttempted = true
	if commitJournalBytes(j.disk, line, j.size) != nil {
		j.unavailable = true
		return Checkpoint{}, ErrJournalUncertain
	}
	size := j.size + int64(len(line))
	if _, err := readDarwinAuditJournalLocked(context.Background(), j.dir, j.file, j.start, next, size); err != nil {
		j.unavailable = true
		return Checkpoint{}, ErrJournalUncertain
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		j.unavailable = true
		return Checkpoint{}, ErrJournalUncertain
	}
	j.head, j.size = next, size
	return next, nil
}

func (j *darwinJournal) Snapshot(ctx context.Context) (data []byte, start, head Checkpoint, failure error) {
	if j == nil {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.file == nil || j.dir == nil {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	j.dir.mu.Lock()
	defer j.dir.mu.Unlock()
	defer func() {
		if checkDarwinJournalPrincipalLocked(j.dir) != nil {
			j.unavailable = true
			clear(data)
			data, start, head, failure = nil, Checkpoint{}, Checkpoint{}, ErrProcessIdentity
		}
	}()
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		j.unavailable = true
		return nil, Checkpoint{}, Checkpoint{}, ErrProcessIdentity
	}
	data, err := readDarwinAuditJournalLocked(ctx, j.dir, j.file, j.start, j.head, j.size)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			j.unavailable = true
		}
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	return data, j.start, j.head, nil
}

// Close attempts the one owned data close even when the borrowed scope is bad.
// No explicit unlock or sync conceals a prior failure. The borrowed scope stays
// owned by its caller, and the first close result is returned on every repeat.
func (j *darwinJournal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return j.closeErr
	}
	j.closed = true
	if j.file == nil {
		return j.closeErr
	}
	if j.dir != nil {
		j.dir.mu.Lock()
		defer j.dir.mu.Unlock()
	}
	if checkDarwinJournalPrincipalLocked(j.dir) != nil {
		j.closeErr = ErrProcessIdentity
	} else if err := j.dir.checkBindingLocked(); err != nil {
		j.closeErr = darwinJournalReadError(err)
	}
	if j.file.Close() != nil && j.closeErr == nil {
		j.closeErr = ErrJournalStorage
	}
	j.file = nil
	if checkDarwinJournalPrincipalLocked(j.dir) != nil && j.closeErr == nil {
		j.closeErr = ErrProcessIdentity
	}
	return j.closeErr
}
