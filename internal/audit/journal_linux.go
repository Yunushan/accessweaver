//go:build linux && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
	"golang.org/x/sys/unix"
)

const journalName = "events.journal"
const MaxJournalBytes = MaxCheckpointBytes + MaxSegmentBytes

var (
	ErrJournalBusy        = errors.New("audit journal is locked by another writer")
	ErrJournalStorage     = errors.New("audit journal storage or retained checkpoints differ")
	ErrJournalUnavailable = errors.New("audit journal is closed or requires reconciliation")
	ErrJournalUncertain   = errors.New("audit journal write durability is uncertain; preserve storage and reconcile independently")
	ErrJournalFull        = errors.New("audit journal is full; independently acknowledged retention is required")
)

type journalCommitter interface {
	WriteAt([]byte, int64) (int, error)
	Sync() error
}

// LinuxJournal is a bounded, single-stream storage component, not a live event
// producer. It holds an exclusive OS lock until Close. It never rotates,
// truncates, repairs, deletes or silently adopts an unacknowledged tail.
//
// The caller supplies an already opened, trusted directory and must protect its
// ancestor bindings. The directory must belong to the effective UID, have mode
// 0700, and reside on a persistent filesystem accepted by linuxtrust. This API
// does not create a directory, establish actor identity or enroll checkpoints.
// Native filesystem calls can block; context cancellation is checked before a
// mutation, not used to abandon an in-flight write or fsync.
//
// Directory ownership is borrowed; an independent descriptor is retained. The
// journal is private mode 0600, has one hard link, and uses handle-relative I/O.
// Its first line is the genesis checkpoint, followed by canonical records.
// Root and same-UID processes can alter it; trusted external checkpoints remain
// essential. fsync is a durability request, not proof against hardware failure.
type LinuxJournal struct {
	mu                  sync.Mutex
	dir, file           *os.File
	disk                journalCommitter
	owner               uint32
	start, head         Checkpoint
	size                int64
	unavailable, closed bool
}

// CreateLinuxJournal exclusively creates a new journal for an enrolled genesis.
// Existing entries and failed initializations are preserved. On any error the
// caller must not dispatch work on the assumption that an intent was recorded.
func CreateLinuxJournal(parent *os.File, genesis Checkpoint) (*LinuxJournal, error) {
	if genesis.Sequence != 0 || validateCheckpoint(genesis) != nil {
		return nil, ErrJournalStorage
	}
	j, err := journalDirectory(parent)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*LinuxJournal, error) { _ = j.Close(); return nil, err }
	fd, err := unix.Openat(int(j.dir.Fd()), journalName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fail(ErrJournalStorage)
	}
	j.file = os.NewFile(uintptr(fd), journalName)
	j.disk = j.file
	if err := j.lock(); err != nil {
		return fail(err)
	}
	if linuxtrust.ResetCreatedACL(j.file, false) != nil || j.file.Chmod(0600) != nil || j.checkBinding() != nil {
		return fail(ErrJournalStorage)
	}
	data, _ := EncodeCheckpoint(genesis)
	if commitJournalBytes(j.disk, data, 0) != nil || j.dir.Sync() != nil || j.checkCommittedSize(int64(len(data))) != nil {
		return fail(ErrJournalUncertain)
	}
	j.start, j.head, j.size = genesis, genesis, int64(len(data))
	return j, nil
}

// OpenLinuxJournal requires the complete independently retained genesis and
// expected ending checkpoint. Extra complete records, partial records and lost
// records all refuse, without changing storage. A caller must reconcile an
// uncertain append independently before choosing different checkpoints.
func OpenLinuxJournal(ctx context.Context, parent *os.File, genesis, expectedHead Checkpoint) (*LinuxJournal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if genesis.Sequence != 0 || validateCheckpoint(genesis) != nil || validateCheckpoint(expectedHead) != nil {
		return nil, ErrJournalStorage
	}
	j, err := journalDirectory(parent)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*LinuxJournal, error) { _ = j.Close(); return nil, err }
	probe, err := linuxtrust.OpenRegularAt(j.dir, journalName, j.owner)
	if err != nil {
		return fail(ErrJournalStorage)
	}
	before, statErr := probe.Stat()
	closeErr := probe.Close()
	if statErr != nil || closeErr != nil {
		return fail(ErrJournalStorage)
	}
	fd, err := unix.Openat(int(j.dir.Fd()), journalName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(ErrJournalStorage)
	}
	j.file = os.NewFile(uintptr(fd), journalName)
	j.disk = j.file
	after, err := j.file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return fail(ErrJournalStorage)
	}
	if err := j.lock(); err != nil {
		return fail(err)
	}
	j.start, j.head, j.size = genesis, expectedHead, after.Size()
	if _, err := j.read(ctx); err != nil {
		return fail(err)
	}
	// Also persist an explicitly reconciled, complete record left by a prior
	// uncertain fsync or initialization. Never infer the checkpoint from that tail.
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if j.file.Sync() != nil || j.dir.Sync() != nil || j.checkCommittedSize(j.size) != nil {
		return fail(ErrJournalUncertain)
	}
	return j, nil
}

func journalDirectory(parent *os.File) (*LinuxJournal, error) {
	if parent == nil {
		return nil, ErrJournalStorage
	}
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	runtime.KeepAlive(parent)
	if err != nil {
		return nil, ErrJournalStorage
	}
	j := &LinuxJournal{dir: os.NewFile(uintptr(fd), "audit-directory"), owner: uint32(os.Geteuid())}
	info, err := linuxtrust.Check(j.dir, true, j.owner)
	if err != nil || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSticky != 0 || linuxtrust.CheckPersistent(j.dir) != nil {
		_ = j.Close()
		return nil, ErrJournalStorage
	}
	return j, nil
}
func (j *LinuxJournal) lock() error {
	err := unix.Flock(int(j.file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrJournalBusy
	}
	if err != nil {
		return ErrJournalStorage
	}
	return nil
}
func (j *LinuxJournal) checkBinding() error {
	directory, err := linuxtrust.Check(j.dir, true, j.owner)
	if err != nil || directory.Mode().Perm() != 0700 || directory.Mode()&os.ModeSticky != 0 || linuxtrust.CheckPersistent(j.dir) != nil {
		return ErrJournalStorage
	}
	opened, err := linuxtrust.Check(j.file, false, j.owner)
	if err != nil || opened.Mode().Perm() != 0600 || opened.Size() < 0 || opened.Size() > MaxJournalBytes || linuxtrust.CheckPersistent(j.file) != nil {
		return ErrJournalStorage
	}
	if directory.Sys().(*syscall.Stat_t).Dev != opened.Sys().(*syscall.Stat_t).Dev {
		return ErrJournalStorage
	}
	named, err := linuxtrust.OpenRegularAt(j.dir, journalName, j.owner)
	if err != nil {
		return ErrJournalStorage
	}
	info, statErr := named.Stat()
	closeErr := named.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(opened, info) {
		return ErrJournalStorage
	}
	return nil
}
func (j *LinuxJournal) read(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if j.checkBinding() != nil {
		return nil, ErrJournalStorage
	}
	before, err := j.file.Stat()
	if err != nil || before.Size() != j.size {
		return nil, ErrJournalStorage
	}
	data, err := io.ReadAll(io.NewSectionReader(j.file, 0, MaxJournalBytes+1))
	if err != nil || int64(len(data)) != j.size || len(data) > MaxJournalBytes {
		return nil, ErrJournalStorage
	}
	after, err := j.file.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || j.checkBinding() != nil {
		return nil, ErrJournalStorage
	}
	first := bytes.IndexByte(data, '\n') + 1
	if first <= 0 || first > MaxCheckpointBytes {
		return nil, ErrJournalStorage
	}
	start, err := DecodeCheckpoint(data[:first])
	if err != nil || start != j.start {
		return nil, ErrJournalStorage
	}
	if _, err := VerifySegment(ctx, bytes.NewReader(data[first:]), j.start, j.head); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrJournalStorage
	}
	return data[first:], nil
}
func (j *LinuxJournal) checkCommittedSize(expected int64) error {
	if j.checkBinding() != nil {
		return ErrJournalUncertain
	}
	info, err := j.file.Stat()
	if err != nil || info.Size() != expected {
		return ErrJournalUncertain
	}
	return nil
}
func commitJournalBytes(disk journalCommitter, data []byte, offset int64) error {
	n, err := disk.WriteAt(data, offset)
	if err != nil || n != len(data) {
		return ErrJournalUncertain
	}
	if disk.Sync() != nil {
		return ErrJournalUncertain
	}
	return nil
}

// Append returns a successor checkpoint only after an exact write and fsync.
// Write or sync failure poisons this handle, returns no checkpoint, and keeps
// every byte for reconciliation. An error does not prove the record is absent.
// Invalid events, cancellation before writing and capacity refusal do not write.
func (j *LinuxJournal) Append(ctx context.Context, event Event) (Checkpoint, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.file == nil || j.dir == nil {
		return Checkpoint{}, ErrJournalUnavailable
	}
	line, next, err := Append(j.head, event)
	if err != nil {
		return Checkpoint{}, err
	}
	if j.head.Sequence >= MaxSegmentRecords || j.size+int64(len(line)) > MaxJournalBytes {
		return Checkpoint{}, ErrJournalFull
	}
	if _, err := j.read(ctx); err != nil {
		if ctx.Err() == nil {
			j.unavailable = true
		}
		return Checkpoint{}, err
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	if commitJournalBytes(j.disk, line, j.size) != nil || j.checkCommittedSize(j.size+int64(len(line))) != nil {
		j.unavailable = true
		return Checkpoint{}, ErrJournalUncertain
	}
	j.head, j.size = next, j.size+int64(len(line))
	return next, nil
}

// Snapshot returns a bounded, fully verified copy and its endpoints. This does
// not authorize export, establish collector acknowledgment, or advance retention.
func (j *LinuxJournal) Snapshot(ctx context.Context) ([]byte, Checkpoint, Checkpoint, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.unavailable || j.file == nil || j.dir == nil {
		return nil, Checkpoint{}, Checkpoint{}, ErrJournalUnavailable
	}
	data, err := j.read(ctx)
	if err != nil {
		if ctx.Err() == nil {
			j.unavailable = true
		}
		return nil, Checkpoint{}, Checkpoint{}, err
	}
	return data, j.start, j.head, nil
}

// Close releases the lock and descriptors. It never removes journal storage.
func (j *LinuxJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	var failure error
	if j.file != nil {
		failure = j.file.Close()
	}
	if j.dir != nil {
		failure = errors.Join(failure, j.dir.Close())
	}
	if failure != nil {
		return ErrJournalStorage
	}
	return nil
}
