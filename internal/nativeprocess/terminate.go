// Package nativeprocess bounds native process-termination helpers.
package nativeprocess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type terminationCommand struct {
	executable        string
	args, environment []string
	directory         string
}

func killOwned(process *os.Process) error {
	if process == nil {
		return nil
	}
	err := process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// The command receives its own deadline, independently of the context whose
// cancellation triggered cleanup. A failed helper cannot prevent the fallback
// from terminating the held parent process. Failure still means tree cleanup
// is unconfirmed, even when that parent termination succeeds.
func terminateWithCommand(process *os.Process, spec terminationCommand, timeout time.Duration) error {
	if process == nil {
		return nil
	}
	return terminateCommand(spec, timeout, func() error { return killOwned(process) })
}

// The native owner supplies a fallback for its exact retained object handle.
// Keep the original helper deadline and output-drain policy unchanged.
func terminateCommand(spec terminationCommand, timeout time.Duration, fallback func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, spec.executable, spec.args...)
	cmd.Env, cmd.Dir = spec.environment, spec.directory
	cmd.WaitDelay = time.Second
	configureTerminator(cmd)
	if err := cmd.Run(); err != nil {
		helperErr := fmt.Errorf("terminate process tree: %w", errors.Join(err, ctx.Err()))
		return errors.Join(helperErr, fallback())
	}
	return nil
}
