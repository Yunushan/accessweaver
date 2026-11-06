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

type commandRunObservation struct{ Accepted, Waited, Bound, OwnerClosed bool }

func runWorkflowCommand(cmd *exec.Cmd, owner commandOwner) error {
	_, err := runWorkflowCommandObserved(cmd, owner)
	return err
}
func runWorkflowCommandObserved(cmd *exec.Cmd, owner commandOwner) (observation commandRunObservation, failure error) {
	if err := cmd.Start(); err != nil {
		if owner != nil {
			return observation, errors.Join(err, workflowFailure(ErrWorkflowCleanup, owner.Close()))
		}
		return observation, err
	}
	observation.Accepted = true
	var bindErr error
	if owner != nil {
		bindErr = owner.Bind(cmd.Process)
	}
	observation.Bound = bindErr == nil
	waitErr := cmd.Wait()
	observation.Waited = cmd.ProcessState != nil
	var closeErr error
	if owner != nil {
		closeErr = owner.Close()
	}
	observation.OwnerClosed = closeErr == nil
	return observation, errors.Join(waitErr, workflowFailure(ErrWorkflowCleanup, bindErr), workflowFailure(ErrWorkflowCleanup, closeErr))
}
