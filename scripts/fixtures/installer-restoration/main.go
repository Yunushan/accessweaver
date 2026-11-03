//go:build windows

// Disposable hosted installer fixture only; never included in a product build.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

type processIdentity struct {
	PID     int    `json:"pid"`
	Created uint64 `json:"created"`
}

type observation struct {
	Mode  string          `json:"mode"`
	Root  processIdentity `json:"root"`
	Child processIdentity `json:"child"`
}

func identity(pid int) (processIdentity, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return processIdentity{}, err
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return processIdentity{}, err
	}
	return processIdentity{pid, uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}, nil
}

func writeNew(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func run() error {
	if len(os.Args) == 3 && os.Args[1] == "--owned-child" {
		own, err := identity(os.Getpid())
		if err != nil {
			return err
		}
		if err = writeNew(os.Args[2], own); err != nil {
			return err
		}
		time.Sleep(15 * time.Minute)
		return fmt.Errorf("fixture safety lifetime exceeded")
	}
	if len(os.Args) != 5 || os.Args[1] != "system" || os.Args[2] != "apply" || os.Args[4] != "--confirm" || filepath.Base(os.Args[3]) != "uninstall-system.json" {
		return fmt.Errorf("unexpected fixture invocation")
	}
	config := os.Getenv("ACCESSWEAVER_INSTALLER_RESTORE_FIXTURE")
	if config == "" {
		return fmt.Errorf("fixture requires an explicit private configuration")
	}
	f, err := os.Open(config)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		f.Close()
		return fmt.Errorf("invalid fixture configuration")
	}
	var input struct {
		Mode string `json:"mode"`
	}
	err = json.NewDecoder(f).Decode(&input)
	f.Close()
	if err != nil {
		return err
	}
	if input.Mode != "exit-failure-with-child" && input.Mode != "exit-success-with-child" && input.Mode != "hang-with-child" {
		return fmt.Errorf("unknown fixture mode")
	}
	own, err := identity(os.Getpid())
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	childMarker := config + ".child"
	child := exec.Command(executable, "--owned-child", childMarker)
	if err = child.Start(); err != nil {
		return err
	}
	// The fixture deliberately does not wait for/kill the child. The product's
	// job must retain and clean it even after a zero/nonzero parent exit.
	var childID processIdentity
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(childMarker)
		if readErr == nil && json.Unmarshal(data, &childID) == nil && childID.PID == child.Process.Pid {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if childID.PID != child.Process.Pid {
		return fmt.Errorf("owned child did not become ready")
	}
	if err = writeNew(config+".ready", observation{input.Mode, own, childID}); err != nil {
		return err
	}
	switch input.Mode {
	case "exit-failure-with-child":
		return fmt.Errorf("intentional fixture controller failure")
	case "exit-success-with-child":
		return nil
	default:
		time.Sleep(15 * time.Minute)
		return fmt.Errorf("fixture safety lifetime exceeded")
	}
}

func main() {
	if run() != nil {
		os.Exit(7)
	}
}
