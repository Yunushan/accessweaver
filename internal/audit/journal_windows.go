//go:build windows && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// windowsJournal borrows dir and owns only file. Its synchronous, write-through
// native handle retains a byte-range lock until Close. Exact writes, file.Sync
// (FlushFileBuffers), and complete readback are prerequisites for a returned
// checkpoint. This requests file data/metadata persistence; power-loss behavior
// remains a separate native-host qualification, not a directory-flush claim.
// No failure path deletes, truncates, repairs, retries or adopts unknown bytes.
type windowsJournal struct {
	mu                  sync.Mutex
	dir                 *windowsAuditDirectory
	file                *os.File
	disk                journalCommitter
	start, head         Checkpoint
	size                int64
	unavailable, closed bool
	closeErr            error
}

func checkWindowsJournalPrincipal(dir *windowsAuditDirectory) error {
	if dir == nil || requireProcessTokenContext() != nil {
		return ErrProcessIdentity
	}
	principal, err := currentProcessPrincipal()
	if err != nil || principal != dir.principal || principal.kind != "sid" || principal.value != dir.owner {
		return ErrProcessIdentity
	}
	return nil
}

// lockWindowsAuditJournal uses the data handle, not a sidecar or a differently
// shared open. The extra byte includes the bounded reader's overflow sentinel.
// There is no explicit unlock: the final file close releases the lock.
func lockWindowsAuditJournal(file *os.File, exclusive bool) error {
	if file == nil {
		return ErrJournalStorage
	}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, uint32(MaxJournalBytes+1), 0, &overlapped)
	runtime.KeepAlive(file)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrJournalBusy
	}
	if err != nil {
		return ErrJournalStorage
	}
	return nil
}

func createWindowsJournal(dir *windowsAuditDirectory, genesis Checkpoint) (result *windowsJournal, failure error) {
	if dir == nil || genesis.Sequence != 0 || validateCheckpoint(genesis) != nil {
		return nil, ErrJournalStorage
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	j := &windowsJournal{dir: dir, start: genesis, head: genesis}
	mutationAttempted := false
	defer func() {
		if checkWindowsJournalPrincipal(dir) != nil {
			result, failure = nil, ErrProcessIdentity
			if mutationAttempted {
				failure = ErrJournalUncertain
			}
		}
		if result == nil {
			if err := j.Close(); failure == nil && err != nil {
				failure = err
			}
		}
	}()
	if err := checkWindowsJournalPrincipal(dir); err != nil {
		return nil, err
	}
	if err := dir.checkBinding(); err != nil {
		return nil, windowsJournalReadError(err)
	}
	mutationAttempted = true
	file, err := dir.createRegular(journalName)
	if err != nil {
		return nil, err
	}
	j.file, j.disk = file, file
	if err := lockWindowsAuditJournal(file, true); err != nil {
		return nil, err
	}
	state, err := dir.fileState(file, journalName)
	if err != nil || state.size != 0 {
		return nil, windowsJournalReadError(err)
	}
	if err := checkWindowsJournalPrincipal(dir); err != nil {
		return nil, ErrJournalUncertain
	}
	data, err := EncodeCheckpoint(genesis)
	if err != nil {
		return nil, ErrJournalStorage
	}
	if commitJournalBytes(j.disk, data, 0) != nil {
		return nil, ErrJournalUncertain
	}
	if _, err := readWindowsAuditJournal(context.Background(), dir, file, genesis, genesis, int64(len(data))); err != nil {
		return nil, ErrJournalUncertain
	}
	if checkWindowsJournalPrincipal(dir) != nil {
		return nil, ErrJournalUncertain
	}
	j.size = int64(len(data))
	return j, nil
}

// openWindowsJournal requires independently supplied complete endpoints. It may
// flush an explicitly reconciled complete tail, but never derives a head from it.
func openWindowsJournal(ctx context.Context, dir *windowsAuditDirectory, genesis, head Checkpoint) (result *windowsJournal, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dir == nil || genesis.Sequence != 0 || validateCheckpoint(genesis) != nil || validateCheckpoint(head) != nil || genesis.StreamID != head.StreamID || genesis.Producer != head.Producer || head.Sequence > MaxSegmentRecords {
		return nil, ErrJournalStorage
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	j := &windowsJournal{dir: dir, start: genesis, head: head}
	flushAttempted := false
	defer func() {
		if checkWindowsJournalPrincipal(dir) != nil {
			result, failure = nil, ErrProcessIdentity
			if flushAttempted {
				failure = ErrJournalUncertain
			}
		}
		if result == nil {
			if err := j.Close(); failure == nil && err != nil {
				failure = err
			}
		}
	}()
	if err := checkWindowsJournalPrincipal(dir); err != nil {
		return nil, err
	}
	file, err := dir.openRegular(journalName, true)
	if err != nil {
		return nil, err
	}
	j.file, j.disk = file, file
	if err := lockWindowsAuditJournal(file, true); err != nil {
		return nil, err
	}
	state, err := dir.fileState(file, journalName)
	if err != nil {
		return nil, windowsJournalReadError(err)
	}
	j.size = state.size
	if _, err := readWindowsAuditJournal(ctx, dir, file, genesis, head, j.size); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkWindowsJournalPrincipal(dir); err != nil {
		return nil, err
	}
	flushAttempted = true
	if file.Sync() != nil {
		return nil, ErrJournalUncertain
	}
	if _, err := readWindowsAuditJournal(context.Background(), dir, file, genesis, head, j.size); err != nil || checkWindowsJournalPrincipal(dir) != nil {
		return nil, ErrJournalUncertain
	}
	return j, nil
}

func windowsJournalReadError(err error) error {
	if errors.Is(err, ErrProcessIdentity) {
		return ErrProcessIdentity
	}
	return ErrJournalStorage
}

// readWindowsAuditJournal is also used by historical export under a shared
// byte-range lock. The caller pins its thread and checks identity on both sides.
// Size and candidate endpoints are explicit, so postwrite verification does not
// publish or temporarily replace the writer's previously acknowledged head.
func readWindowsAuditJournal(ctx context.Context, dir *windowsAuditDirectory, file *os.File, start, head Checkpoint, size int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dir == nil || file == nil || size <= 0 || size > MaxJournalBytes {
		return nil, ErrJournalStorage
	}
	before, err := dir.fileState(file, journalName)
	if err != nil || before.size != size {
		return nil, windowsJournalReadError(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(file, 0, MaxJournalBytes+1))
	if err != nil || int64(len(data)) != size || len(data) > MaxJournalBytes {
		return nil, ErrJournalStorage
	}

	first := bytes.IndexByte(data, '\n') + 1
	if first <= 0 || first > MaxCheckpointBytes {
		return nil, ErrJournalStorage
	}
	actualStart, err := DecodeCheckpoint(data[:first])
	if err != nil || actualStart != start {
		return nil, ErrJournalStorage
	}
	if _, err := VerifySegment(ctx, bytes.NewReader(data[first:]), start, head); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrJournalStorage
	}
	after, err := dir.fileState(file, journalName)
	if err != nil || before != after {
		return nil, windowsJournalReadError(err)
	}
	return data[first:], nil
}

func (j *windowsJournal) Append(ctx context.Context, event Event) (result Checkpoint, failure error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.file == nil || j.dir == nil {
		return Checkpoint{}, ErrJournalUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previousHead, previousSize := j.head, j.size
	mutationAttempted := false
	defer func() {
		if checkWindowsJournalPrincipal(j.dir) != nil {
			j.unavailable = true
			result, failure = Checkpoint{}, ErrProcessIdentity
			if mutationAttempted {
				j.head, j.size = previousHead, previousSize
				failure = ErrJournalUncertain
			}
		}
	}()
	if err := checkWindowsJournalPrincipal(j.dir); err != nil {
		j.unavailable = true
		return Checkpoint{}, err
	}
	line, next, err := Append(j.head, event)
	if err != nil {
		return Checkpoint{}, err
	}
	if j.head.Sequence >= MaxSegmentRecords || j.size+int64(len(line)) > MaxJournalBytes {
		return Checkpoint{}, ErrJournalFull
	}
	if _, err := readWindowsAuditJournal(ctx, j.dir, j.file, j.start, j.head, j.size); err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			j.unavailable = true
		}
		return Checkpoint{}, err
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	if err := checkWindowsJournalPrincipal(j.dir); err != nil {
		j.unavailable = true
		return Checkpoint{}, err
	}
	mutationAttempted = true
	if commitJournalBytes(j.disk, line, j.size) != nil {
		j.unavailable = true
		return Checkpoint{}, ErrJournalUncertain
	}
	size := j.size + int64(len(line))
	if _, err := readWindowsAuditJournal(context.Background(), j.dir, j.file, j.start, next, size); err != nil || checkWindowsJournalPrincipal(j.dir) != nil {
		j.unavailable = true
		return Checkpoint{}, ErrJournalUncertain
	}
	j.head, j.size = next, size
	return next, nil
}

func (j *windowsJournal) Snapshot(ctx context.Context) (data []byte, start, head Checkpoint, failure error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.file == nil || j.dir == nil {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() {
		if checkWindowsJournalPrincipal(j.dir) != nil {
			j.unavailable = true
			data, start, head, failure = nil, Checkpoint{}, Checkpoint{}, ErrProcessIdentity
		}
	}()
	if err := checkWindowsJournalPrincipal(j.dir); err != nil {
		j.unavailable = true
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	data, err := readWindowsAuditJournal(ctx, j.dir, j.file, j.start, j.head, j.size)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			j.unavailable = true
		}
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	return data, j.start, j.head, nil
}

// Close always attempts the owned file close, including when identity checks
// refuse. It never closes the borrowed directory or releases the lock early.
func (j *windowsJournal) Close() error {
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
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if checkWindowsJournalPrincipal(j.dir) != nil {
		j.closeErr = ErrProcessIdentity
	}
	if j.file.Close() != nil && j.closeErr == nil {
		j.closeErr = ErrJournalStorage
	}
	j.file = nil
	if checkWindowsJournalPrincipal(j.dir) != nil && j.closeErr == nil {
		j.closeErr = ErrProcessIdentity
	}
	return j.closeErr
}
