package workflow

import (
	"context"
	"errors"
	"fmt"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/privatefile"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Persisted ID is only an additional conflict detector. Authority always also
// requires genuine positive proof, managed review, exact root and content.
func reconciliationFileIdentity(file *os.File) (string, uint64, error) {
	state, err := fileidentity.FromFile(file)
	if err != nil {
		return "", 0, err
	}
	links, err := reconciliationLinkCount(file)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%016x:%x", state.ID.Volume, state.ID.FileID), links, nil
}

type closedLifecycleStage struct {
	Name     string `json:"name"`
	Identity string `json:"identity"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Links    uint64 `json:"links"`
}
type lifecycleWriteObservation struct {
	Err       error
	Known     bool
	Published bool
	Stage     *closedLifecycleStage
}
type ackObservation struct {
	Write             lifecycleWriteObservation
	TransactionClosed bool
}
type localExecutionObservation struct{ NeverCalled, NoNativeOwners, Invoked, Setup, Waited, Bound, OwnerClosed, OutputClosed, ReportValid, Finished bool }
type localExecutionObservationKey struct{}

func localExecutionFrom(ctx context.Context) *localExecutionObservation {
	observation, _ := ctx.Value(localExecutionObservationKey{}).(*localExecutionObservation)
	return observation
}

type localReleaseWitness struct {
	Receipt workflowLifecycleReceipt
	Done    <-chan struct{}
	Ack     ackObservation
}

func inspectLifecycleObject(path string) (object closedLifecycleStage, err error) {
	named, cause := os.Lstat(path)
	if cause != nil {
		return object, cause
	}
	if !named.Mode().IsRegular() || named.Size() < 0 || named.Size() > workflowLifecycleMaxReceiptBytes {
		return object, ErrLifecycleReconciliationConflict
	}
	file, cause := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if cause != nil {
		return object, cause
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			object = closedLifecycleStage{}
			err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
		}
	}()
	opened, cause := file.Stat()
	if cause != nil || !os.SameFile(named, opened) {
		return object, errors.Join(ErrLifecycleReconciliationConflict, cause)
	}
	identity, links, cause := reconciliationFileIdentity(file)
	if cause != nil {
		return object, cause
	}
	b, cause := io.ReadAll(io.LimitReader(file, workflowLifecycleMaxReceiptBytes+1))
	if cause != nil || len(b) > workflowLifecycleMaxReceiptBytes {
		return object, errors.Join(ErrLifecycleReconciliationConflict, cause)
	}
	after, cause := file.Stat()
	if cause != nil {
		return object, cause
	}
	current, cause := os.Lstat(path)
	if cause != nil || !current.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(after, current) || opened.Size() != after.Size() || opened.ModTime() != after.ModTime() || int64(len(b)) != after.Size() {
		return object, errors.Join(ErrLifecycleReconciliationConflict, cause)
	}
	return closedLifecycleStage{Name: filepath.Base(path), Identity: identity, Links: links, Size: int64(len(b)), SHA256: workflowLifecycleHash(b)}, nil
}
func sameLifecycleObject(a, b closedLifecycleStage) bool {
	return a.Name == b.Name && a.Identity == b.Identity && a.Size == b.Size && a.SHA256 == b.SHA256 && a.Links == b.Links
}
func physicalLifecyclePublish(stage, target, previous string) error {
	if previous == "" {
		return os.Link(stage, target)
	}
	old, err := readWorkflowLifecycleFile(context.Background(), target, workflowLifecycleMaxReceiptBytes)
	if err != nil || workflowLifecycleHash(old) != previous {
		return errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	return replaceHistoryIndex(stage, target)
}
func writeLifecycleObserved(path string, b []byte, previous string, publish func(string, string, string) error) (result lifecycleWriteObservation) {
	if len(b) > workflowLifecycleMaxReceiptBytes {
		result.Err = ErrWorkflowLifecycle
		return
	}
	if previous != "" {
		old, err := readWorkflowLifecycleFile(context.Background(), path, workflowLifecycleMaxReceiptBytes)
		if err != nil || workflowLifecycleHash(old) != previous {
			result.Err = errors.Join(ErrWorkflowLifecycle, err)
			return
		}
	}
	file, err := privatefile.CreateTemp(filepath.Dir(path), ".lifecycle-*.tmp")
	if err != nil {
		result.Err = err
		return
	}
	stage := file.Name()
	initial, statErr := file.Stat()
	closed := false
	closedOK := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		closeErr := file.Close()
		closedOK = closeErr == nil
		return workflowFailure(ErrWorkflowCleanup, closeErr)
	}
	defer func() {
		result.Err = errors.Join(result.Err, closeFile())
		if !closedOK || statErr != nil {
			return
		}
		named, cause := os.Lstat(stage)
		if errors.Is(cause, os.ErrNotExist) && result.Published {
			result.Known = true
			return
		}
		if cause != nil || !named.Mode().IsRegular() || !os.SameFile(initial, named) {
			return
		}
		object, cause := inspectLifecycleObject(stage)
		if cause != nil {
			result.Err = errors.Join(result.Err, cause)
			return
		}
		if object.Size != int64(len(b)) || object.SHA256 != workflowLifecycleHash(b) {
			result.Err = errors.Join(result.Err, ErrLifecycleReconciliationConflict)
			return
		}
		result.Stage = &object
		result.Known = true
	}()
	if statErr != nil {
		result.Err = statErr
		return
	}
	n, err := file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		result.Err = err
		return
	}
	if err = file.Sync(); err != nil {
		result.Err = err
		return
	}
	if err = closeFile(); err != nil {
		result.Err = err
		return
	}
	named, err := os.Lstat(stage)
	if err != nil || !os.SameFile(initial, named) {
		result.Err = errors.Join(ErrWorkflowLifecycle, err)
		return
	}
	if publish == nil {
		publish = physicalLifecyclePublish
	}
	if err = publish(stage, path, previous); err != nil {
		result.Err = err
		return
	}
	result.Published = true
	if previous != "" {
		result.Known = true
		return
	}
	named, err = os.Lstat(stage)
	if err != nil || !os.SameFile(initial, named) {
		result.Err = errors.Join(ErrWorkflowLifecycle, err)
		return
	}
	result.Err = os.Remove(stage)
	return
}
func (m *Manager) observedLifecycleWrite(path string, b []byte, previous string) lifecycleWriteObservation {
	if m.writeLifecycle != nil {
		return lifecycleWriteObservation{Err: m.writeLifecycle(path, b, previous)}
	}
	return writeLifecycleObserved(path, b, previous, m.publishLifecycle)
}
