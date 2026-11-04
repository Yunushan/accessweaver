//go:build windows && (amd64 || arm64)

package audit

import (
	"context"
	"io"
	"os"
	"runtime"
)

// exportWindowsLocalSegment keeps historical reads independent of current key
// contents and build metadata. All source handles and their shared byte lock
// close successfully before the first output byte. It never flushes or mutates
// archive storage. A caller must separately protect checkpoint inputs and must
// not wrap output writers that forward to protected storage.
func exportWindowsLocalSegment(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) error {
	if out == nil {
		return ErrExportOutput
	}
	data, err := readWindowsLocalExport(ctx, directory, genesis, head, out)
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

func readWindowsLocalExport(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) (data []byte, failure error) {
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
	var file *os.File
	defer func() {
		principalErr := dir.checkPrincipalLocked()
		var fileErr error
		if file != nil {
			fileErr = file.Close()
		}
		dirErr := dir.Close()
		if principalErr != nil || dir.checkPrincipalLocked() != nil {
			clear(data)
			data, failure = nil, ErrProcessIdentity
		} else if fileErr != nil || dirErr != nil {
			clear(data)
			data, failure = nil, ErrJournalStorage
		}
	}()
	file, err = dir.openRegular(journalName, false)
	if err != nil {
		return nil, err
	}
	if err := lockWindowsAuditJournal(file, false); err != nil {
		return nil, err
	}
	state, err := dir.fileState(file, journalName)
	if err != nil {
		return nil, err
	}
	checkDestination := func() error {
		destination, ok := out.(*os.File)
		if !ok {
			return nil
		}
		identity, regular, err := windowsAuditOutputIdentity(destination)
		if err != nil {
			return err
		}
		if !regular {
			return nil
		}
		if identity == state.id {
			return ErrExportDestination
		}
		keyID, present, err := dir.probeIdentity(actorKeyName)
		if err != nil {
			return err
		}
		if present && identity == keyID {
			return ErrExportDestination
		}
		return nil
	}
	if err := checkDestination(); err != nil {
		return nil, err
	}
	data, err = readWindowsAuditJournal(ctx, dir, file, genesis, head, state.size)
	if err != nil {
		return nil, err
	}
	if err := checkDestination(); err != nil {
		clear(data)
		return nil, err
	}
	if dir.checkPrincipalLocked() != nil {
		clear(data)
		return nil, ErrProcessIdentity
	}
	return data, nil
}
