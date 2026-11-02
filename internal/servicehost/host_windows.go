//go:build windows

package servicehost

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/logfile"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/nativepath"
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
	b, err := os.ReadFile(absolute)
	if err != nil {
		return err
	}
	var cfg Config
	if err = json.Unmarshal(b, &cfg); err != nil {
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
	var handle uintptr
	status := func(state, accepted, exit uint32) {
		s := serviceStatus{Type: 0x10, State: state, Accepted: accepted, Win32Exit: exit, WaitHint: 10000}
		setStatus.Call(handle, uintptr(unsafe.Pointer(&s)))
	}
	handler := syscall.NewCallback(func(control, event uint32, data, context uintptr) uintptr {
		if control == 1 || control == 5 {
			once.Do(func() { close(stop) })
		}
		return 0
	})
	main := syscall.NewCallback(func(argc uint32, argv uintptr) uintptr {
		handle, _, _ = register.Call(uintptr(unsafe.Pointer(name)), handler, 0)
		if handle == 0 {
			return 0
		}
		status(2, 0, 0)
		log, e := logfile.Open(cfg.LogPath, 8<<20, 2)
		if e != nil {
			status(1, 0, 1)
			return 0
		}
		defer log.Close()
		finish := func(exit uint32) {
			if log.Close() != nil {
				exit = 1
			}
			status(1, 0, exit)
		}
		cmd := exec.Command(cfg.Binary, cfg.Args...)
		cmd.Dir = cfg.Directory
		cmd.Stdout = log
		cmd.Stderr = log
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.WaitDelay = 2 * time.Second
		if e = cmd.Start(); e != nil {
			fmt.Fprintln(log, e)
			finish(1)
			return 0
		}
		status(4, 5, 0)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case e = <-done:
			if e != nil {
				fmt.Fprintln(log, e)
				finish(1)
			} else {
				finish(0)
			}
		case <-stop:
			status(3, 0, 0)
			_ = exec.Command("taskkill.exe", "/PID", fmt.Sprint(cmd.Process.Pid), "/T", "/F").Run()
			_ = cmd.Process.Kill()
			<-done
			finish(0)
		}
		return 0
	})
	entries := []tableEntry{{name, main}, {nil, 0}}
	ok, _, callErr := dispatcher.Call(uintptr(unsafe.Pointer(&entries[0])))
	if ok == 0 {
		return fmt.Errorf("connect service dispatcher: %w", callErr)
	}
	return nil
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
