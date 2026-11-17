package workflow

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Yunushan/accessweaver/internal/privatefile"
)

// Only fresh debug snapshots use this writer. It cannot replace an existing
// object, and never removes an uncertain stage on Write/Sync/Close failure.
type controllerSnapshotFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
	Stat() (os.FileInfo, error)
	Name() string
}
type controllerSnapshotHooks struct {
	open        func(string, string) (controllerSnapshotFile, error)
	afterClosed func(string, string) error
}

func writeControllerSnapshot(path string, data []byte, allowance int64) error {
	return writeControllerSnapshotObserved(path, data, allowance, nil)
}
func writeControllerSnapshotObserved(path string, data []byte, allowance int64, hooks *controllerSnapshotHooks) error {
	if allowance < 0 || int64(len(data)) > allowance {
		return ErrWorkflowStorageCapacity
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return workflowFailure(ErrWorkflowStoragePending, errors.Join(ErrWorkflowStoragePending, err))
	}
	var f controllerSnapshotFile
	var err error
	if hooks != nil && hooks.open != nil {
		f, err = hooks.open(filepath.Dir(path), ".workflow-controller-*.tmp")
	} else {
		f, err = privatefile.CreateTemp(filepath.Dir(path), ".workflow-controller-*.tmp")
	}
	if err != nil {
		return err
	}
	stage := f.Name()
	identity, err := f.Stat()
	if err != nil {
		return errors.Join(err, workflowFailure(ErrWorkflowCleanup, f.Close()))
	}
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
	}
	named, err := os.Lstat(stage)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(identity, named) || named.Size() != int64(len(data)) {
		return errors.Join(ErrWorkflowStoragePending, err)
	}
	if hooks != nil && hooks.afterClosed != nil {
		if err = hooks.afterClosed(stage, path); err != nil {
			return err
		}
	}
	observed, readErr := readWorkflowLifecycleFile(context.Background(), stage, int64(len(data)))
	now, nameErr := os.Lstat(stage)
	if readErr != nil || nameErr != nil || !now.Mode().IsRegular() || !os.SameFile(identity, now) || !bytes.Equal(observed, data) {
		return errors.Join(ErrWorkflowStoragePending, readErr, nameErr)
	}
	// No-replace publication. Both names are rechecked before removing the
	// source-owned closed stage; unknown replacements are always retained.
	if err = os.Link(stage, path); err != nil {
		return err
	}
	target, err := os.Lstat(path)
	current, sourceErr := os.Lstat(stage)
	if err != nil || sourceErr != nil || !target.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(identity, target) || !os.SameFile(identity, current) {
		return errors.Join(ErrWorkflowStoragePending, err, sourceErr)
	}
	return os.Remove(stage)
}
