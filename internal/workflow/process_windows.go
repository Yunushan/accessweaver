//go:build windows

package workflow

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
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

func requireAdministrator() error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("cannot inspect administrator access: %w", err)
	}
	defer token.Close()
	var elevated, size uint32
	if err = syscall.GetTokenInformation(token, 20, (*byte)(unsafe.Pointer(&elevated)), 4, &size); err != nil {
		return fmt.Errorf("cannot inspect administrator access: %w", err)
	}
	if elevated == 0 {
		return errors.New("machine changes require a separately elevated system apply CLI; export the reviewed request and keep the dashboard unelevated")
	}
	return nil
}
