package workflow

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/Yunushan/accessweaver/internal/filelock"
)

const (
	workflowActiveLockName      = ".workflow-active.lock"
	workflowTransactionLockName = ".workflow-store.lock"
)

// A successful acquisition has one owner and one observed Close. The physical
// implementation uses OS-owned persistent lock files; it never deletes them.
type workflowStoreLease interface{ Close() error }

func openWorkflowStoreLease(path string) (workflowStoreLease, error) {
	lease, err := filelock.TryAcquire(path)
	if err != nil {
		return nil, err
	}
	return lease, nil
}

type workflowStoreFailure struct{ cause error }

func (e *workflowStoreFailure) Error() string {
	if errors.Is(e.cause, filelock.ErrBusy) {
		return ErrWorkflowBusy.Error()
	}
	return ErrWorkflowStore.Error()
}
func (e *workflowStoreFailure) Unwrap() []error {
	causes := []error{ErrWorkflowStore, e.cause}
	if errors.Is(e.cause, filelock.ErrBusy) {
		causes = append(causes, ErrWorkflowBusy)
	}
	return causes
}
func workflowStoreError(cause error) error {
	if cause == nil {
		return nil
	}
	return &workflowStoreFailure{cause: cause}
}

// Call only outside Manager.mu. The active lease precedes the short transaction
// lease, and neither path is under the history directory's listing/count budget.
// Unsupported, inaccessible or replaced coordination files fail closed.
func (m *Manager) acquireWorkflowStoreLease(name string) (workflowStoreLease, error) {
	if err := os.MkdirAll(m.storeRoot, 0700); err != nil {
		return nil, workflowStoreError(err)
	}
	opener := m.openStoreLease
	if opener == nil {
		opener = openWorkflowStoreLease
	}
	lease, err := opener(filepath.Join(m.storeRoot, name))
	if err != nil {
		// Physical TryAcquire returns no lease on failure. A composed opener
		// must not lose an owner if it reports a failure with a lease as well.
		return nil, workflowStoreError(errors.Join(err, workflowFailure(ErrWorkflowCleanup, m.closeWorkflowStoreLease(lease))))
	}
	if lease == nil {
		return nil, workflowStoreError(errors.New("workflow lease unavailable"))
	}
	return lease, nil
}

// A failed Close is sticky: it cannot prove the reservation was released. Keep
// the lease reachable, poison this Manager against new admission, and publish
// the fixed category while retaining the original local cause for Is/As.
// Never retry Close, reopen a PID, unlink a lock file or infer release from age.
func (m *Manager) closeWorkflowStoreLease(lease workflowStoreLease) error {
	if lease == nil {
		return nil
	}
	err := workflowStoreError(lease.Close())
	if err != nil {
		m.mu.Lock()
		m.storeFailure = errors.Join(m.storeFailure, err)
		m.retainedStoreLeases = append(m.retainedStoreLeases, lease)
		m.mu.Unlock()
	}
	return err
}
