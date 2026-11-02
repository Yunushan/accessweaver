//go:build !windows

package nativeprocess

import "os/exec"

func configureTerminator(cmd *exec.Cmd) {}
