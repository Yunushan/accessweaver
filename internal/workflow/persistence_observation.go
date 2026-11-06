package workflow

import (
	"bytes"
	"context"
	"errors"
	"github.com/Yunushan/accessweaver/internal/privatefile"
	"io"
	"os"
	"path/filepath"
)

type workflowPersistObservation struct {
	path, sha string
	closed    bool
}

// Every successful return follows actual Write, Sync and checked Close. Failed
// stages are retained; a fake persist hook cannot set the private observation.
func writeWorkflowDataFile(path string, b []byte) error {
	return writeWorkflowDataFileObserved(path, b, nil)
}

// The optional observer runs after actual Write/Sync/Close. It can refuse
// publication but cannot replace those physical operations or their errors.
func writeWorkflowDataFileObserved(path string, b []byte, beforePublish func(string, string) error) error {
	if len(b) > maxHistoryRecordBytes {
		return ErrWorkflowPersistence
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	var before os.FileInfo
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return ErrWorkflowPersistence
		}
		before = info
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := privatefile.CreateTemp(filepath.Dir(path), ".workflow-data-*.tmp")
	if err != nil {
		return err
	}
	stage := file.Name()
	identity, err := file.Stat()
	if err != nil {
		return errors.Join(err, workflowFailure(ErrWorkflowCleanup, file.Close()))
	}
	n, err := file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return errors.Join(err, workflowFailure(ErrWorkflowCleanup, file.Close()))
	}
	if err = file.Sync(); err != nil {
		return errors.Join(err, workflowFailure(ErrWorkflowCleanup, file.Close()))
	}
	if err = file.Close(); err != nil {
		return workflowFailure(ErrWorkflowCleanup, err)
	}
	now, err := os.Lstat(stage)
	if err != nil || !now.Mode().IsRegular() || !os.SameFile(identity, now) {
		return errors.Join(ErrWorkflowPersistence, err)
	}
	target, err := os.Lstat(path)
	if before == nil {
		if err == nil {
			return ErrWorkflowPersistence
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if err != nil || !os.SameFile(before, target) {
		return errors.Join(ErrWorkflowPersistence, err)
	}
	if beforePublish != nil {
		if err = beforePublish(stage, path); err != nil {
			return err
		}
		named, checkErr := os.Lstat(stage)
		if checkErr != nil || !named.Mode().IsRegular() || !os.SameFile(identity, named) {
			return errors.Join(ErrWorkflowPersistence, checkErr)
		}
		observed, checkErr := readWorkflowLifecycleFile(context.Background(), stage, int64(len(b)))
		if checkErr != nil || !bytes.Equal(observed, b) {
			return errors.Join(ErrWorkflowPersistence, checkErr)
		}
	}
	return replaceHistoryIndex(stage, path)
}
func (m *Manager) defaultPersist(path string, b []byte) error {
	err := writeWorkflowDataFile(path, b)
	if err == nil {
		m.mu.Lock()
		if probe := m.persistProbe; probe != nil && probe.path == path && probe.sha == workflowLifecycleHash(b) {
			probe.closed = true
		}
		m.mu.Unlock()
	}
	return err
}
