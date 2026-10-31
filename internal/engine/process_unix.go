//go:build !windows

package engine

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func groupSignal(p *os.Process, signal syscall.Signal) error {
	err := syscall.Kill(-p.Pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
func interruptProcess(p *os.Process) error { return groupSignal(p, syscall.SIGTERM) }
func killProcess(p *os.Process) error      { return groupSignal(p, syscall.SIGKILL) }
