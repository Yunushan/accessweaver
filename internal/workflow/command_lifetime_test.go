package workflow

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This seam checks command composition without allocating a native process owner.
type workflowTestCommandOwner struct {
	bind  func(*os.Process) error
	close func() error
}

func (o *workflowTestCommandOwner) Bind(p *os.Process) error { return o.bind(p) }
func (o *workflowTestCommandOwner) Close() error             { return o.close() }

func TestWorkflowCommandFailedStartClosesUnboundOwner(t *testing.T) {
	closeFailure := errors.New("PRIVATE_OWNER_CLOSE_FAILURE")
	binds, closes := 0, 0
	owner := &workflowTestCommandOwner{
		bind:  func(*os.Process) error { binds++; return nil },
		close: func() error { closes++; return closeFailure },
	}
	cmd := exec.Command(filepath.Join(t.TempDir(), "absent-source-helper"))
	initialFailure := cmd.Err // Windows can resolve a missing extension here.
	err := runWorkflowCommand(cmd, owner)
	preserved := initialFailure != nil && errors.Is(err, initialFailure)
	if initialFailure == nil {
		var startFailure *os.PathError
		preserved = errors.As(err, &startFailure) && errors.Is(startFailure, os.ErrNotExist)
	}
	if !preserved || !errors.Is(err, closeFailure) || !errors.Is(err, ErrWorkflowCleanup) {
		t.Fatal("failed start lost its original cause or owner-close uncertainty")
	}
	if binds != 0 || closes != 1 || cmd.Process != nil || cmd.ProcessState != nil {
		t.Fatal("failed start was treated as an accepted child")
	}
}

func TestWorkflowCommandInitializationFailureKeepsOriginalCause(t *testing.T) {
	startCause := errors.New("PRIVATE_INITIALIZATION_CAUSE")
	closeCause := errors.New("PRIVATE_INITIALIZATION_CLOSE_CAUSE")
	original := &os.PathError{Op: "PRIVATE_INITIALIZATION", Path: "PRIVATE_SOURCE", Err: startCause}
	binds, closes := 0, 0
	owner := &workflowTestCommandOwner{bind: func(*os.Process) error { binds++; return nil }, close: func() error { closes++; return closeCause }}
	cmd := exec.Command(filepath.Join(t.TempDir(), "absent-source-helper"))
	cmd.Err = original
	err := runWorkflowCommand(cmd, owner)
	var received *os.PathError
	if !errors.As(err, &received) || received != original || !errors.Is(err, startCause) || !errors.Is(err, closeCause) || !errors.Is(err, ErrWorkflowCleanup) {
		t.Fatal("initialization failure lost an original cause")
	}
	if binds != 0 || closes != 1 || cmd.Process != nil || cmd.ProcessState != nil {
		t.Fatal("initialization failure accepted a child or lost the unbound owner")
	}
}
