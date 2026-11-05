//go:build darwin && (amd64 || arm64)

package audit

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Historical export uses independently retained endpoints and the executing
// storage principal, never current producer metadata or actor-key contents.
// Every source handle and shared lock closes before the first output byte.
// Callers must protect checkpoint inputs and must not wrap a writer that
// forwards output into protected storage. Native I/O and output may block;
// context cancellation is cooperative, not a whole-operation deadline.
func exportDarwinLocalSegment(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) error {
	if out == nil {
		return ErrExportOutput
	}
	data, err := readDarwinLocalExport(ctx, directory, genesis, head, out)
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

func readDarwinLocalExport(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) (data []byte, failure error) {
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
	defer func() {
		principalErr := dir.checkPrincipalLocked()
		closeErr := dir.Close()
		if principalErr != nil || dir.checkPrincipalLocked() != nil {
			clear(data)
			data, failure = nil, ErrProcessIdentity
		} else if closeErr != nil {
			clear(data)
			data, failure = nil, ErrJournalStorage
		}
	}()
	// The facade owns its own directory lock. Reacquire and validate the open
	// gap before any payload I/O; the inner defer closes the sole data handle
	// while the scope is still locked, before the outer scope close.
	file, err := dir.openRegular(journalName, false)
	if err != nil {
		return nil, err
	}
	dir.mu.Lock()
	defer dir.mu.Unlock()
	defer func() {
		principalErr := dir.checkPrincipalLocked()
		closeErr := file.Close()
		if principalErr != nil || dir.checkPrincipalLocked() != nil {
			clear(data)
			data, failure = nil, ErrProcessIdentity
		} else if closeErr != nil {
			clear(data)
			data, failure = nil, ErrJournalStorage
		}
	}()
	if checkDarwinJournalPrincipalLocked(dir) != nil {
		return nil, ErrProcessIdentity
	}
	state, err := dir.fileStateLocked(file, journalName)
	if err != nil {
		return nil, darwinJournalReadError(err)
	}
	if err := lockDarwinAuditJournal(file, false); err != nil {
		return nil, err
	}
	if err := checkDarwinExportDestinationLocked(dir, state.id, out); err != nil {
		return nil, err
	}
	data, err = readDarwinAuditJournalLocked(ctx, dir, file, genesis, head, state.size)
	if err != nil {
		return nil, err
	}
	if err := checkDarwinExportDestinationLocked(dir, state.id, out); err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

// Output may be a pipe or a file on another filesystem. Only descriptor
// identity is needed; storage admission checks do not apply to the destination.
func darwinAuditOutputIdentity(file *os.File) (identity darwinAuditIdentity, regular bool, failure error) {
	var stat unix.Stat_t
	if darwinAuditControl(file, func(fd int) error { return unix.Fstat(fd, &stat) }) != nil {
		return identity, false, ErrExportOutput
	}
	return darwinAuditIdentity{stat.Dev, stat.Ino}, stat.Mode&unix.S_IFMT == unix.S_IFREG, nil
}

// Caller holds dir.mu. Metadata-only nofollow lookup admits a missing key and
// never opens a key, symlink target or special file for payload I/O. Metadata
// lookup still has the documented filesystem hydration/automount limitations.
func darwinAuditExportKeyIdentityLocked(dir *darwinAuditDirectory) (identity darwinAuditIdentity, present bool, failure error) {
	if dir == nil || dir.checkPrincipalLocked() != nil {
		return identity, false, ErrProcessIdentity
	}
	if err := dir.checkBindingLocked(); err != nil {
		return identity, false, darwinJournalReadError(err)
	}
	var stat unix.Stat_t
	if err := darwinAuditControl(dir.dir, func(fd int) error {
		err := unix.Fstatat(fd, actorKeyName, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err == nil {
			present = true
		}
		return err
	}); err != nil {
		return identity, false, err
	}
	if dir.checkPrincipalLocked() != nil {
		return identity, false, ErrProcessIdentity
	}
	if err := dir.checkBindingLocked(); err != nil {
		return identity, false, darwinJournalReadError(err)
	}
	if present {
		identity = darwinAuditIdentity{stat.Dev, stat.Ino}
	}
	return identity, present, nil
}

func checkDarwinExportDestinationLocked(dir *darwinAuditDirectory, journalID darwinAuditIdentity, out io.Writer) error {
	destination, ok := out.(*os.File)
	if !ok {
		return nil
	}
	identity, regular, err := darwinAuditOutputIdentity(destination)
	if err != nil {
		return err
	}
	if !regular {
		return nil
	}
	if identity == journalID {
		return ErrExportDestination
	}
	keyID, present, err := darwinAuditExportKeyIdentityLocked(dir)
	if err != nil {
		return err
	}
	if present && identity == keyID {
		return ErrExportDestination
	}
	return nil
}
