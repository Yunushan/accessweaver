package nativeprocess

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Only tests invoke this subprocess protocol. There is no runtime environment
// switch or substitute path for the trusted Windows termination utility.
func TestNativeProcessHelper(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "--" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	args := os.Args[marker+1:]
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "sleep":
		time.Sleep(45 * time.Second)
	case "hang":
		if len(args) != 2 || os.WriteFile(args[1], []byte("started"), 0600) != nil {
			os.Exit(2)
		}
		time.Sleep(45 * time.Second)
	case "fail":
		os.Exit(7)
	case "tree":
		if len(args) != 2 {
			os.Exit(2)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestNativeProcessHelper$", "--", "sleep")
		if child.Start() != nil {
			os.Exit(2)
		}
		if os.WriteFile(args[1], []byte(strconv.Itoa(child.Process.Pid)), 0600) != nil {
			_ = child.Process.Kill()
			_ = child.Wait()
			os.Exit(2)
		}
		_ = child.Wait()
	default:
		os.Exit(2)
	}
}

func sleepingProcess(t *testing.T) (*exec.Cmd, <-chan struct{}) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNativeProcessHelper$", "--", "sleep")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned fixture did not exit")
		}
	})
	return cmd, done
}

func TestFailedTerminationStillKillsOwnedParent(t *testing.T) {
	for _, mode := range []string{"missing", "fail", "hang"} {
		t.Run(mode, func(t *testing.T) {
			child, done := sleepingProcess(t)
			_, unrelatedDone := sleepingProcess(t)
			ready := filepath.Join(t.TempDir(), "helper-started")
			spec := terminationCommand{executable: os.Args[0], args: []string{"-test.run=^TestNativeProcessHelper$", "--", mode}}
			if mode == "missing" {
				spec.executable = filepath.Join(t.TempDir(), "missing-helper")
			}
			if mode == "hang" {
				spec.args = append(spec.args, ready)
			}
			started := time.Now()
			err := terminateWithCommand(child.Process, spec, 2*time.Second)
			if err == nil {
				t.Fatal("unconfirmed tree cleanup reported success")
			}
			if time.Since(started) > 8*time.Second {
				t.Fatal("termination helper exceeded deadline and wait allowance")
			}
			switch mode {
			case "missing":
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			case "fail":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 {
					t.Fatal(err)
				}
			case "hang":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
				if data, e := os.ReadFile(ready); e != nil || string(data) != "started" {
					t.Fatalf("hung helper was not confirmed live: %q %v", data, e)
				}
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("fallback did not terminate owned parent")
			}
			select {
			case <-unrelatedDone:
				t.Fatal("unrelated process terminated")
			default:
			}
		})
	}
}

func TestNilProcessDoesNotLaunchTerminator(t *testing.T) {
	if err := terminateWithCommand(nil, terminationCommand{executable: "missing-helper"}, 0); err != nil {
		t.Fatal(err)
	}
}
