package nativeprocess

import (
	"errors"
	"os"
	"sync"
)

// ErrTreeOwnerUnavailable reports unavailable identity or unconfirmed cleanup.
// It never includes a PID, path or native error in its printable message.
var ErrTreeOwnerUnavailable = errors.New("process tree ownership or cleanup is unavailable")

var errTreeBinding = errors.New("process handle binding is invalid")

type treeOwnerFailure struct{ cause error }

func (e *treeOwnerFailure) Error() string { return ErrTreeOwnerUnavailable.Error() }
func (e *treeOwnerFailure) Unwrap() []error {
	return []error{ErrTreeOwnerUnavailable, e.cause}
}
func treeOwnerError(cause error) error {
	if cause == nil {
		return nil
	}
	return &treeOwnerFailure{cause: cause}
}

type treeBackend interface {
	withHandle(*os.Process, func(uintptr)) error
	duplicate(uintptr) (uintptr, error)
	processID(uintptr) (int, error)
	terminate(uintptr) error
	close(uintptr) error
	tree(uintptr, int) error
}

type treeOwnerPhase uint8

const (
	treePending treeOwnerPhase = iota
	treeBound
	treeFailed
	treeClosed
)

// TreeOwner reserves one successfully started process object's native identity
// before its sole consuming Go Wait. Construct it before Start; Bind immediately
// after Start succeeds and before Wait. Cancel may run before Bind and will wait
// for the binding decision. Failed Start must call Close to release that gate.
//
// The caller owns the actual Wait and output drain, including after Bind fails.
// Close must follow that completion; it also joins admitted cancellation helpers.
// A helper result never proves complete descendant cleanup or vendor rollback.
// A TreeOwner must not be copied, rebound or used for another process generation.
type TreeOwner struct {
	mu        sync.Mutex
	ready     chan struct{}
	backend   treeBackend
	phase     treeOwnerPhase
	handle    uintptr
	pid       int
	bindErr   error
	canceled  bool
	cancelErr error
	closeErr  error
}

func NewTreeOwner() *TreeOwner { return newTreeOwnerWithBackend(newTreeBackend()) }

// The backend is private, per-instance and fixed before Start. Production always
// uses the physical platform backend; there is no environment/profile selector.
func newTreeOwnerWithBackend(backend treeBackend) *TreeOwner {
	return &TreeOwner{ready: make(chan struct{}), backend: backend}
}

func validTreeHandle(handle uintptr) bool { return handle != 0 && handle != ^uintptr(0) }

// Bind duplicates only the original handle borrowed from Process.WithHandle.
// A duplicate/query/verification failure attempts exact-parent termination while
// that original handle is still borrowed; it never uses a numeric fallback.
// Any obtained duplicate stays owned until Close after the caller's actual Wait.
func (o *TreeOwner) Bind(process *os.Process) error {
	if o == nil || o.ready == nil {
		return ErrTreeOwnerUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != treePending {
		return ErrTreeOwnerUnavailable
	}
	var bindErr error
	if process == nil || process.Pid <= 0 || o.backend == nil {
		bindErr = errTreeBinding
	} else {
		expectedPID := process.Pid
		aborted := false
		handleErr := o.backend.withHandle(process, func(original uintptr) {
			if !validTreeHandle(original) {
				bindErr = errTreeBinding
				return
			}
			duplicate, err := o.backend.duplicate(original)
			if err != nil || !validTreeHandle(duplicate) {
				aborted = true
				bindErr = errors.Join(errTreeBinding, err, o.backend.terminate(original))
				return
			}
			o.handle = duplicate
			pid, err := o.backend.processID(duplicate)
			if err != nil || pid <= 0 || pid != expectedPID {
				aborted = true
				bindErr = errors.Join(errTreeBinding, err, o.backend.terminate(original))
				return
			}
			o.pid = pid
		})
		if handleErr != nil {
			bindErr = errors.Join(bindErr, handleErr)
			if !aborted && validTreeHandle(o.handle) {
				bindErr = errors.Join(bindErr, o.backend.terminate(o.handle))
			}
		}
		if !validTreeHandle(o.handle) || o.pid <= 0 {
			bindErr = errors.Join(bindErr, errTreeBinding)
		}
	}
	if bindErr != nil {
		o.phase = treeFailed
		o.bindErr = treeOwnerError(bindErr)
	} else {
		o.phase = treeBound
	}
	close(o.ready)
	return o.bindErr
}

// Cancel waits for binding, then admits at most one native helper under the same
// mutex that protects Close. Later calls return the first result without retries.
// Unavailable or changed handle identity forbids every raw numeric dispatch.
func (o *TreeOwner) Cancel() error {
	if o == nil || o.ready == nil {
		return ErrTreeOwnerUnavailable
	}
	<-o.ready
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != treeBound {
		if o.bindErr != nil {
			return o.bindErr
		}
		return ErrTreeOwnerUnavailable
	}
	if o.canceled {
		return o.cancelErr
	}
	o.canceled = true
	pid, err := o.backend.processID(o.handle)
	if err != nil || pid <= 0 || pid != o.pid {
		o.cancelErr = treeOwnerError(errors.Join(errTreeBinding, err))
		return o.cancelErr
	}
	o.cancelErr = treeOwnerError(o.backend.tree(o.handle, o.pid))
	return o.cancelErr
}

// Close resolves a pre-Start gate or closes the retained duplicate only after
// the caller has joined real Wait/output. It serializes with every admitted
// native operation and never retries a failed Close or native cancellation.
func (o *TreeOwner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase == treeClosed {
		return o.closeErr
	}
	if o.phase == treePending && o.ready != nil {
		close(o.ready)
	}
	o.phase = treeClosed
	if validTreeHandle(o.handle) {
		o.closeErr = treeOwnerError(o.backend.close(o.handle))
	}
	return o.closeErr
}
