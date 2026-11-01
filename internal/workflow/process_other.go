//go:build !windows

package workflow

import "os/exec"

func configureCommand(cmd *exec.Cmd) {}
