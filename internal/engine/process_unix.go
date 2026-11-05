//go:build !windows

package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func newEngineCommand(_ context.Context, binary string, args []string) *exec.Cmd {
	// No CommandContext watcher may issue a hidden Process.Kill during reap/I/O.
	return exec.Command(binary, args...)
}
func configureProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func processOwnershipLost(err error) bool {
	return errors.Is(err, ErrProcessOwnershipLost) || errors.Is(err, syscall.ECHILD)
}

func nativeGroupSignal(pgid int, signal syscall.Signal) error {
	if pgid <= 1 {
		return ErrProcessOwnershipLost
	}
	err := syscall.Kill(-pgid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

// Call only inside the launch owner's admitted dispatch. The supplied Process
// is an immutable PID view, not a second waitable/releasable process handle.
func interruptProcess(p *os.Process) error { return nativeGroupSignal(p.Pid, syscall.SIGTERM) }
func killProcess(p *os.Process) error      { return nativeGroupSignal(p.Pid, syscall.SIGKILL) }
