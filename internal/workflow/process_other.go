//go:build !windows

package workflow

import (
	"errors"
	"os/exec"
)

func configureCommand(cmd *exec.Cmd) {}

func requireAdministrator() error {
	return errors.New("Windows system workflows require a Windows host")
}
