//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/profile"
)

type childReadyStandardOutput struct{ pidFile string }

func (w childReadyStandardOutput) Write(data []byte) (int, error) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.ReadFile(w.pidFile); err == nil {
			// This is the worker's actual standard-output descriptor, backed by
			// a pipe whose reader is closed before the worker starts.
			return os.Stdout.Write(data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, errors.New("inert child did not publish its PID")
}

func TestForegroundRunClosedPipeWorker(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_RUN_PIPE_WORKER") != "1" {
		t.Skip("source-test subprocess only")
	}
	signal.Reset(syscall.SIGPIPE)
	root := os.Getenv("ACCESSWEAVER_RUN_PIPE_ROOT")
	pidFile := filepath.Join(root, "child.pid")
	p := profile.New("closed-pipe-run", "Closed pipe run", "byedpi")
	p.Binary = filepath.Join(root, "ciadpi")
	p.Args = []string{"tracked-cli-wait"}
	manager := engine.NewManager(filepath.Join(root, "data"))
	err := runForegroundEngine(context.Background(), p, manager, childReadyStandardOutput{pidFile: pidFile})
	if !errors.Is(err, errEngineLaunchOutput) {
		t.Fatal("closed standard output did not return fixed launch-notice failure", err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 0 {
		t.Fatal("invalid inert child PID", err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("failed notice left owned child alive or unreaped", err)
	}
	if state := manager.Snapshot(); state.PID != 0 || state.State != "stopped" {
		t.Fatal("notice cleanup did not finish owned launch", state)
	}
	if err := os.WriteFile(filepath.Join(root, "reaped"), []byte("owned child reaped before restoring pipe behavior\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The scoped registration must already be restored. This subsequent write
	// must terminate this worker with SIGPIPE, after the cleanup proof exists.
	_, _ = os.Stdout.Write([]byte("scope restored\n"))
	os.Exit(81)
}

func TestForegroundRunClosedStandardPipeReapsChildAndRestoresScope(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ciadpi"), data, 0700); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	defer writer.Close()
	t.Cleanup(func() {
		data, err := os.ReadFile(filepath.Join(root, "child.pid"))
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(string(data))
		if err == nil && pid > 0 {
			// Only this source-test fixture's privately recorded owned group.
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestForegroundRunClosedPipeWorker$")
	command.Env = append(os.Environ(),
		"ACCESSWEAVER_RUN_PIPE_WORKER=1",
		"ACCESSWEAVER_RUN_PIPE_ROOT="+root,
		"ACCESSWEAVER_TRACKED_CLI_FIXTURE=1",
		"ACCESSWEAVER_TRACKED_CLI_PID="+filepath.Join(root, "child.pid"))
	command.Stdout = writer
	var stderr bytes.Buffer
	command.Stderr = &stderr
	runErr := command.Run()
	if ctx.Err() != nil {
		t.Fatal("closed-pipe worker timed out", ctx.Err(), stderr.String())
	}
	if proof, err := os.ReadFile(filepath.Join(root, "reaped")); err != nil || !strings.Contains(string(proof), "owned child reaped") {
		t.Fatal("worker exited before proving owned-child cleanup", err, stderr.String())
	}
	exit, ok := runErr.(*exec.ExitError)
	if !ok {
		t.Fatal("restored closed pipe did not terminate worker", fmt.Sprint(runErr), stderr.String())
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGPIPE {
		t.Fatal("foreground command leaked changed SIGPIPE behavior", runErr, stderr.String())
	}
}
