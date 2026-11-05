package workflow

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This seam checks command composition only; it performs no Windows native work.
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
	err := runWorkflowCommand(cmd, owner)
	var startFailure *os.PathError
	if !errors.As(err, &startFailure) || !errors.Is(err, closeFailure) || !errors.Is(err, ErrWorkflowCleanup) {
		t.Fatal("failed start lost its original cause or owner-close uncertainty")
	}
	if binds != 0 || closes != 1 || cmd.Process != nil || cmd.ProcessState != nil {
		t.Fatal("failed start was treated as an accepted child")
	}
}
