package workflow

import (
	"errors"
	"os"
	"os/exec"
)

// commandOwner binds an accepted child before its sole consuming wait. Close
// releases the reservation only after Wait has joined cancellation and output.
// The Windows owner handles a failed Bind using only a still-owned exact handle.
type commandOwner interface {
	Bind(*os.Process) error
	Close() error
}

func runWorkflowCommand(cmd *exec.Cmd, owner commandOwner) error {
	if owner == nil {
		return cmd.Run()
	}
	if err := cmd.Start(); err != nil {
		// No child was accepted. Closing still resolves a pre-start gate.
		return errors.Join(err, workflowFailure(ErrWorkflowCleanup, owner.Close()))
	}
	bindErr := owner.Bind(cmd.Process)
	// A binding failure cannot undo a successful Start. Retain the accepted
	// child and perform its real wait even when native cleanup is uncertain.
	waitErr := cmd.Wait()
	closeErr := owner.Close()
	return errors.Join(waitErr,
		workflowFailure(ErrWorkflowCleanup, bindErr),
		workflowFailure(ErrWorkflowCleanup, closeErr))
}
