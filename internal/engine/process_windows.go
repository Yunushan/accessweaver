//go:build windows

package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

// Preserve the existing Windows context/handle behavior. Unix group lifetime
// ownership is deliberately separate from Windows process-handle signaling.
func newEngineCommand(ctx context.Context, binary string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Cancel = func() error { return killProcess(cmd.Process) }
	return cmd
}
func processOwnershipLost(err error) bool { return errors.Is(err, ErrProcessOwnershipLost) }

func configureProcess(cmd *exec.Cmd)       {}
func interruptProcess(p *os.Process) error { return p.Kill() }
func killProcess(p *os.Process) error      { return p.Kill() }

type windowsProcessLifetime struct{ cmd *exec.Cmd }

func prepareProcessLifetime(cmd *exec.Cmd) (processLifetime, error) {
	return &windowsProcessLifetime{cmd}, nil
}
func (o *windowsProcessLifetime) dispatch(signal func(*os.Process) error) error {
	return signal(o.cmd.Process)
}
func (o *windowsProcessLifetime) wait(context.Context) (error, error) { return o.cmd.Wait(), nil }
func (o *windowsProcessLifetime) pendingError() error                 { return nil }
func (o *windowsProcessLifetime) faultSignal() <-chan struct{}        { return nil }
func (o *windowsProcessLifetime) retryCleanup() error                 { return ErrRunUnavailable }
func (o *windowsProcessLifetime) setFaultHandler(func(error))         {}
func (o *windowsProcessLifetime) abortStart() error                   { return nil }
