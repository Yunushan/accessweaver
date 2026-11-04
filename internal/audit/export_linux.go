//go:build linux && (amd64 || arm64)

package audit

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
	"golang.org/x/sys/unix"
)

// ExportLocalSegment writes canonical event lines only after a complete locked
// read-only snapshot verifies both independently trusted endpoints. It excludes
// the genesis line and never reads key bytes, syncs, appends, repairs or deletes.
// Historical producer metadata need not match this build. Export grants no
// authenticity, collector acknowledgment, retention or export-access record.
//
// Direct *os.File destinations are checked against source/key inode identities.
// An O_PATH probe inspects key identity without opening it for I/O. Callers must
// also protect their checkpoint inputs and must not supply wrappers/pipes that
// forward output into protected input/storage files. Stdout writes and native
// I/O can block; context is cooperative, not a whole-operation deadline.
func ExportLocalSegment(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) error {
	data, err := readLocalExport(ctx, directory, genesis, head, out)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := out.Write(data)
	if err != nil || n != len(data) {
		return ErrExportOutput
	}
	return nil
}
func readLocalExport(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) (data []byte, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if genesis.Sequence != 0 || validateCheckpoint(genesis) != nil || validateCheckpoint(head) != nil {
		return nil, ErrJournalStorage
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal, err := currentProcessPrincipal()
	if err != nil {
		return nil, ErrProcessIdentity
	}
	dir, err := openLocalAuditDirectory(directory)
	if err != nil {
		return nil, err
	}
	reader := &LinuxJournal{dir: dir, owner: uint32(os.Geteuid()), start: genesis, head: head}
	defer func() {
		if reader.Close() != nil {
			clear(data)
			data = nil
			failure = ErrJournalStorage
		}
	}()
	file, err := linuxtrust.OpenRegularAt(dir, journalName, reader.owner)
	if err != nil {
		return nil, ErrJournalStorage
	}
	reader.file = file // Never exposed as a mutable journal; disk remains nil.
	if err := unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrJournalBusy
		}
		return nil, ErrJournalStorage
	}
	info, err := file.Stat()
	if err != nil {
		return nil, ErrJournalStorage
	}
	reader.size = info.Size()
	if destination, ok := out.(*os.File); ok {
		output, err := destination.Stat()
		if err != nil {
			return nil, ErrExportOutput
		}
		if output.Mode().IsRegular() {
			if os.SameFile(info, output) {
				return nil, ErrExportDestination
			}
			// No key content is read or required for archived export. O_PATH makes a
			// FIFO/device/symlink identity probe nonblocking and side-effect-free.
			fd, err := unix.Openat(int(dir.Fd()), actorKeyName, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, ErrJournalStorage
			}
			if err == nil {
				probe := os.NewFile(uintptr(fd), "audit-key-identity")
				keyInfo, statErr := probe.Stat()
				closeErr := probe.Close()
				if statErr != nil || closeErr != nil {
					return nil, ErrJournalStorage
				}
				if os.SameFile(keyInfo, output) {
					return nil, ErrExportDestination
				}
			}
		}
	}
	data, err = reader.read(ctx)
	if err != nil {
		return nil, err
	}
	after, err := currentProcessPrincipal()
	if err != nil || after != principal {
		clear(data)
		return nil, ErrProcessIdentity
	}
	return data, nil
}
