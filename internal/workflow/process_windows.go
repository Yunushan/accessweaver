//go:build windows

package workflow

import (
	"os/exec"
	"strconv"
	"syscall"
)

func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return exec.Command("taskkill.exe", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
	}
}
