//go:build windows

package engine

import (
	"os"
	"os/exec"
)

// The supported Windows adapters run in the foreground. Service wrappers are
// rejected. Go cannot send a console interrupt to arbitrary Windows children;
// stop therefore uses process termination. See engine setup/recovery notes.
func configureProcess(cmd *exec.Cmd)       {}
func interruptProcess(p *os.Process) error { return p.Kill() }
func killProcess(p *os.Process) error      { return p.Kill() }
