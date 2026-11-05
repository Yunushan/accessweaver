//go:build windows

package workflow

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/nativeprocess"
)

func configureCommand(cmd *exec.Cmd) commandOwner {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	owner := nativeprocess.NewTreeOwner()
	cmd.Cancel = owner.Cancel
	return owner
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
