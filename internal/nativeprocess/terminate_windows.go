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
	"golang.org/x/sys/windows"
)

func configureTerminator(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

type windowsTreeBackend struct{}

func newTreeBackend() treeBackend { return windowsTreeBackend{} }
func (windowsTreeBackend) withHandle(process *os.Process, f func(uintptr)) error {
	return process.WithHandle(f)
}
func (windowsTreeBackend) duplicate(original uintptr) (uintptr, error) {
	current, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var duplicate windows.Handle
	const rights = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE | windows.PROCESS_TERMINATE
	if err := windows.DuplicateHandle(current, windows.Handle(original), current, &duplicate, rights, false, 0); err != nil {
		return 0, err
	}
	return uintptr(duplicate), nil
}
func (windowsTreeBackend) processID(handle uintptr) (int, error) {
	pid, err := windows.GetProcessId(windows.Handle(handle))
	return int(pid), err
}
func (windowsTreeBackend) terminate(handle uintptr) error {
	return windows.TerminateProcess(windows.Handle(handle), 1)
}
func (windowsTreeBackend) close(handle uintptr) error {
	return windows.CloseHandle(windows.Handle(handle))
}
func (backend windowsTreeBackend) tree(handle uintptr, expectedPID int) error {
	// Derive the numeric utility argument only from the still-owned handle.
	// The owner mutex or legacy WithHandle scope retains it through all setup,
	// helper execution and exact-handle parent fallback.
	pid, err := backend.processID(handle)
	if err != nil || pid <= 0 || pid != expectedPID {
		return errors.Join(errTreeBinding, err)
	}
	fallback := func() error { return backend.terminate(handle) }
	directory, err := nativepath.SystemDirectory()
	if err != nil {
		return errors.Join(fmt.Errorf("locate process termination utility: %w", err), fallback())
	}
	environment, err := nativepath.UtilityEnvironment()
	if err != nil {
		return errors.Join(fmt.Errorf("prepare process termination utility: %w", err), fallback())
	}
	return terminateCommand(terminationCommand{
		executable:  filepath.Join(directory, "taskkill.exe"),
		args:        []string{"/PID", strconv.Itoa(pid), "/T", "/F"},
		environment: environment, directory: directory,
	}, 5*time.Second, fallback)
}

// TerminateTree is the legacy guarded entry. It never dispatches by Process.Pid:
// WithHandle retains the original object across setup, helper and fallback. A
// retired/unavailable handle is refused without reopening or probing its PID.
// New launchers should bind TreeOwner before Wait to retain late cleanup access.
func TerminateTree(process *os.Process) error {
	if process == nil {
		return nil
	}
	backend := windowsTreeBackend{}
	var result error
	err := backend.withHandle(process, func(handle uintptr) {
		pid, err := backend.processID(handle)
		if err != nil || pid <= 0 {
			result = errors.Join(errTreeBinding, err)
			return
		}
		result = backend.tree(handle, pid)
	})
	return treeOwnerError(errors.Join(err, result))
}
