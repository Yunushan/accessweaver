package profile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ErrAtomicWriteUncertain describes an unconfirmed file update. A failed
// attempt can retain staged data or an already published destination. It does
// not authorize replay, rollback or deleting a name assumed to be temporary.
var ErrAtomicWriteUncertain = errors.New("file update could not be confirmed; staged data may remain; inspect the destination before another attempt")

type atomicWriteFailure struct{ cause error }

func (e *atomicWriteFailure) Error() string   { return ErrAtomicWriteUncertain.Error() }
func (e *atomicWriteFailure) Unwrap() []error { return []error{ErrAtomicWriteUncertain, e.cause} }

func atomicWriteUncertain(cause error) error { return &atomicWriteFailure{cause: cause} }

type atomicWriteStage interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type atomicWriteOperations struct {
	mkdirAll   func(string, os.FileMode) error
	createTemp func(string, string) (atomicWriteStage, error)
	replace    func(string, string) error
}

// AtomicWrite preserves its existing path, creation and replacement policy.
// Failed stages are retained: no pathname cleanup can prove that a reused name
// still belongs to this attempt. This is not private creation, a storage quota,
// a directory durability guarantee or descriptor-relative publication.
func AtomicWrite(file string, data []byte) error {
	return atomicWrite(file, data, atomicWriteOperations{
		mkdirAll: os.MkdirAll,
		createTemp: func(dir, pattern string) (atomicWriteStage, error) {
			file, err := os.CreateTemp(dir, pattern)
			if file == nil {
				return nil, err
			}
			return file, err
		},
		replace: replaceFile,
	})
}

// Operations are composed per call for real owned-file fault tests. Production
// always supplies the fixed physical operations above, without global, Store,
// environment or runtime backend selection.
func atomicWrite(file string, data []byte, ops atomicWriteOperations) (failure error) {
	dir := filepath.Dir(file)
	if err := ops.mkdirAll(dir, 0700); err != nil {
		return atomicWriteUncertain(err)
	}
	stage, createErr := ops.createTemp(dir, ".accessweaver-*")
	if stage == nil {
		if createErr == nil {
			createErr = errors.New("staged file creation returned no owned file")
		}
		return atomicWriteUncertain(createErr)
	}
	closed := false
	// Install cleanup even if a factory returns a partial owner with an error,
	// and before any stage operation can fail or panic. Never retry Close.
	defer func() {
		if !closed {
			closed = true
			closeErr := stage.Close()
			if closeErr != nil {
				failure = errors.Join(failure, closeErr)
			}
		}
		if failure != nil {
			failure = atomicWriteUncertain(failure)
		}
	}()
	if createErr != nil {
		return createErr
	}
	if err := stage.Chmod(0600); err != nil {
		return err
	}
	n, writeErr := stage.Write(data)
	if n != len(data) {
		return errors.Join(io.ErrShortWrite, writeErr)
	}
	if writeErr != nil {
		return writeErr
	}
	if err := stage.Sync(); err != nil {
		return err
	}
	closed = true
	if err := stage.Close(); err != nil {
		return err
	}
	// Publication starts only after confirmed source Close. Failure can race
	// with publication; retain evidence and never infer a rollback or absence.
	return ops.replace(stage.Name(), file)
}
