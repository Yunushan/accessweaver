//go:build windows

package servicehost

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/logfile"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/nativepath"
	"github.com/Yunushan/accessweaver/internal/nativeprocess"
)

var advapi = syscall.NewLazyDLL("advapi32.dll")
var dispatcher = advapi.NewProc("StartServiceCtrlDispatcherW")
var register = advapi.NewProc("RegisterServiceCtrlHandlerExW")
var setStatus = advapi.NewProc("SetServiceStatus")

type serviceStatus struct{ Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint uint32 }
type tableEntry struct {
	Name     *uint16
	Callback uintptr
}

func Run(file string) error {
	if err := managed.NewGuard(nil).ServiceHost(); err != nil {
		return err
	}
	programData, err := nativepath.ProgramData()
	if err != nil {
		return err
	}
	root := filepath.Join(programData, "AccessWeaver")
	absolute, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	if !inside(absolute, filepath.Join(root, "services")) {
		return errors.New("service configuration must be in protected AccessWeaver service storage")
	}
	cfg, err := readLocalServiceConfig(absolute)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(cfg.Name, "AccessWeaver-") || !inside(cfg.Binary, filepath.Join(root, "components")) || !inside(cfg.Directory, filepath.Join(root, "components")) || !inside(cfg.LogPath, filepath.Join(root, "logs")) {
		return errors.New("service paths must be in protected AccessWeaver storage")
	}
	name, err := syscall.UTF16PtrFromString(cfg.Name)
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	var once sync.Once
	handler := syscall.NewCallback(func(control, event uint32, data, context uintptr) uintptr {
		if control == 1 || control == 5 {
			once.Do(func() { close(stop) })
		}
		return 0
	})
	entered, completed := make(chan struct{}), make(chan struct{})
	var serviceErr error // Published before completed closes.
	main := syscall.NewCallback(func(argc uint32, argv uintptr) uintptr {
		close(entered)
		defer close(completed)
		handle, _, registerErr := register.Call(uintptr(unsafe.Pointer(name)), handler, 0)
		if handle == 0 {
			serviceErr = fmt.Errorf("register service control handler: %w", registerErr)
			return 0
		}
		status := func(state, checkpoint, exit uint32) error {
			s := serviceStatus{Type: 0x10, State: state, Win32Exit: exit, Checkpoint: checkpoint}
			if state == serviceStateRunning {
				s.Accepted = 5
			}
			if state == serviceStateStartPending || state == serviceStateStopPending {
				s.WaitHint = 10000
			}
			ok, _, statusErr := setStatus.Call(handle, uintptr(unsafe.Pointer(&s)))
			if ok == 0 {
				return fmt.Errorf("report service status: %w", statusErr)
			}
			return nil
		}
		if err := status(serviceStateStartPending, 1, 0); err != nil {
			serviceErr = errors.Join(err, status(serviceStateStopped, 0, 1))
			return 0
		}
		log, err := logfile.Open(cfg.LogPath, 8<<20, 2)
		if err != nil {
			serviceErr = errors.Join(err, status(serviceStateStopped, 0, 1))
			return 0
		}
		cmd := exec.Command(cfg.Binary, cfg.Args...)
		cmd.Dir = cfg.Directory
		output := &serviceCommandOutput{writer: log}
		cmd.Stdout = output
		cmd.Stderr = output
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.WaitDelay = 2 * time.Second
		owner := nativeprocess.NewTreeOwner()
		// This is a plain Command: no context watcher can bypass this owner.
		// Bind duplicates the actual process handle before the sole Wait starts.
		result := runServiceChild(stop, serviceChildOperations{
			start:  cmd.Start,
			bind:   func() error { return owner.Bind(cmd.Process) },
			wait:   func() error { return waitServiceCommandOutput(cmd.Wait, output) },
			cancel: owner.Cancel,
			close:  owner.Close,
		}, status, log)
		serviceErr = result.err
		return 0
	})
	entries := []tableEntry{{name, main}, {nil, 0}}
	ok, _, callErr := dispatcher.Call(uintptr(unsafe.Pointer(&entries[0])))
	// STOPPED can release the dispatcher before the callback returns. Join its
	// final error publication; no callback-owned state may outlive Run.
	select {
	case <-entered:
		<-completed
	default:
	}
	if ok == 0 {
		return errors.Join(fmt.Errorf("connect service dispatcher: %w", callErr), serviceErr)
	}
	return serviceErr
}
func inside(file, root string) bool {
	a, e := filepath.Abs(file)
	if e != nil {
		return false
	}
	r, e := filepath.Abs(root)
	if e != nil {
		return false
	}
	rel, e := filepath.Rel(r, a)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// This binds the bounded read to a verified local regular-file handle. Local
// links may still resolve locally; this is not an ACL or containment proof.
func readLocalServiceConfig(path string) (Config, error) {
	file, err := fileidentity.OpenLocal(path)
	if err != nil {
		return Config{}, err
	}
	cfg, readErr := readConfig(file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
