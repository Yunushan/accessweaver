//go:build windows

package nativeprocess

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/nativepath"
)

func configureTerminator(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

// TerminateTree uses the trusted Windows utility with a five-second deadline.
// If its setup or execution fails, the held parent process is also terminated;
// that fallback never turns an unconfirmed descendant cleanup into success.
func TerminateTree(process *os.Process) error {
	if process == nil {
		return nil
	}
	directory, err := nativepath.SystemDirectory()
	if err != nil {
		return errors.Join(fmt.Errorf("locate process termination utility: %w", err), killOwned(process))
	}
	environment, err := nativepath.UtilityEnvironment()
	if err != nil {
		return errors.Join(fmt.Errorf("prepare process termination utility: %w", err), killOwned(process))
	}
	return terminateWithCommand(process, terminationCommand{
		executable:  filepath.Join(directory, "taskkill.exe"),
		args:        []string{"/PID", strconv.Itoa(process.Pid), "/T", "/F"},
		environment: environment, directory: directory,
	}, 5*time.Second)
}
