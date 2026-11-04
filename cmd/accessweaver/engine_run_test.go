package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// Only copied source-test executables enter this inert fixture. The managed
// native fixtures use a sanitized environment and retain their existing modes.
func init() {
	if os.Getenv("ACCESSWEAVER_TRACKED_CLI_FIXTURE") != "1" {
		return
	}
	for _, arg := range os.Args[1:] {
		switch arg {
		case "tracked-cli-exit-zero":
			os.Exit(0)
		case "tracked-cli-exit-fail":
			os.Exit(23)
		case "tracked-cli-wait":
			if err := os.WriteFile(os.Getenv("ACCESSWEAVER_TRACKED_CLI_PID"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				os.Exit(24)
			}
			for {
				time.Sleep(time.Hour)
			}
		}
	}
}

type foregroundRunFixture struct {
	done <-chan struct{}
	wait func(context.Context) (engine.RunResult, error)
}

func (r foregroundRunFixture) Done() <-chan struct{} { return r.done }

func (r foregroundRunFixture) Wait(ctx context.Context) (engine.RunResult, error) {
	return r.wait(ctx)
}

func TestForegroundEngineUsesExactTerminalResult(t *testing.T) {
	failure := errors.New("actual owned process failed")
	for _, tc := range []struct {
		reason             engine.RunReason
		waitErr, policyErr error
		wantErr            error
	}{
		{reason: engine.RunExited},
		{reason: engine.RunStopped, waitErr: failure},
		{reason: engine.RunFailed, waitErr: failure, wantErr: failure},
		{reason: engine.RunPolicyRevoked, waitErr: failure, policyErr: managed.ErrUnavailable, wantErr: managed.ErrUnavailable},
	} {
		t.Run(string(tc.reason), func(t *testing.T) {
			stops := 0
			run := foregroundRunFixture{wait: func(context.Context) (engine.RunResult, error) {
				return engine.RunResult{Reason: tc.reason, WaitErr: tc.waitErr, PolicyErr: tc.policyErr}, nil
			}}
			err := waitForegroundEngine(context.Background(), run, func() error { stops++; return nil })
			if !errors.Is(err, tc.wantErr) || stops != 0 {
				t.Fatal("foreground completion changed terminal error or signaled another process", err, stops)
			}
		})
	}
}

func TestForegroundEngineCancellationExplicitlyStopsOwnedProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopErr := errors.New("owned stop timed out")
	stops := 0
	run := foregroundRunFixture{wait: func(waitCtx context.Context) (engine.RunResult, error) {
		if waitCtx != ctx {
			t.Fatal("foreground wait lost caller cancellation")
		}
		return engine.RunResult{}, waitCtx.Err()
	}}
	err := waitForegroundEngine(ctx, run, func() error { stops++; return stopErr })
	if !errors.Is(err, stopErr) || stops != 1 {
		t.Fatal("foreground shutdown lost explicit owned Stop outcome", err, stops)
	}
	// A handle error unrelated to shutdown must not trigger process signaling.
	stops = 0
	run.wait = func(context.Context) (engine.RunResult, error) { return engine.RunResult{}, engine.ErrRunUnavailable }
	err = waitForegroundEngine(context.Background(), run, func() error { stops++; return nil })
	if !errors.Is(err, engine.ErrRunUnavailable) || stops != 0 {
		t.Fatal("invalid handle caused unrelated process stop", err, stops)
	}
}

func TestForegroundRunCLITracksImmediateInertProcessExit(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	name := "ciadpi"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(root, name)
	if err := os.WriteFile(bin, data, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACCESSWEAVER_HOME", filepath.Join(root, "profiles"))
	t.Setenv("ACCESSWEAVER_TRACKED_CLI_FIXTURE", "1")
	store, err := profile.NewStore(os.Getenv("ACCESSWEAVER_HOME"))
	if err != nil {
		t.Fatal(err)
	}
	p := profile.New("foreground-tracked", "Foreground tracked", "byedpi")
	p.Binary = bin
	for _, tc := range []struct {
		arg    string
		failed bool
	}{{"tracked-cli-exit-zero", false}, {"tracked-cli-exit-fail", true}} {
		p.Args = []string{tc.arg}
		if err := store.Save(p); err != nil {
			t.Fatal(err)
		}
		err := execute([]string{"run", p.ID})
		if tc.failed {
			if err == nil || !strings.Contains(err.Error(), "23") {
				t.Fatal("actual CLI hid immediate unexpected child exit", err)
			}
		} else if err != nil {
			t.Fatal("actual CLI failed an immediate normal child exit", err)
		}
	}
}

func TestForegroundEngineShutdownPreservesConcurrentTerminalFailure(t *testing.T) {
	for _, reason := range []engine.RunReason{engine.RunFailed, engine.RunPolicyRevoked} {
		t.Run(string(reason), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan struct{})
			close(done)
			actual := errors.New("owned process exited unexpectedly during shutdown")
			waits, stops := 0, 0
			run := foregroundRunFixture{done: done, wait: func(waitCtx context.Context) (engine.RunResult, error) {
				waits++
				if waits == 1 {
					return engine.RunResult{}, waitCtx.Err()
				}
				if waitCtx.Err() != nil {
					t.Fatal("published terminal observation reused canceled wait")
				}
				return engine.RunResult{Reason: reason, WaitErr: actual}, nil
			}}
			err := waitForegroundEngine(ctx, run, func() error { stops++; return nil })
			if !errors.Is(err, actual) || waits != 2 || stops != 1 {
				t.Fatal("successful stop masked concurrent actual failure", err, waits, stops)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waits := 0
	run := foregroundRunFixture{done: make(chan struct{}), wait: func(waitCtx context.Context) (engine.RunResult, error) {
		waits++
		return engine.RunResult{}, waitCtx.Err()
	}}
	if err := waitForegroundEngine(ctx, run, func() error { return nil }); err == nil || waits != 1 {
		t.Fatal("stop without terminal observation caused another unbounded wait", err, waits)
	}
}

type shortEngineNotice struct{ pidFile string }

func (w shortEngineNotice) Write(data []byte) (int, error) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.ReadFile(w.pidFile); err == nil {
			return len(data) - 1, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, errors.New("inert child did not start")
}

func TestForegroundRunShortNoticeStopsOwnedChild(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	name := "ciadpi"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(root, name)
	if err := os.WriteFile(bin, data, 0700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "child.pid")
	t.Setenv("ACCESSWEAVER_TRACKED_CLI_FIXTURE", "1")
	t.Setenv("ACCESSWEAVER_TRACKED_CLI_PID", pidFile)
	p := profile.New("short-notice", "Short notice", "byedpi")
	p.Binary = bin
	p.Args = []string{"tracked-cli-wait"}
	manager := engine.NewManager(filepath.Join(root, "data"))
	t.Cleanup(func() { _ = manager.Stop() })
	err = runForegroundEngine(context.Background(), p, manager, shortEngineNotice{pidFile: pidFile})
	if !errors.Is(err, errEngineLaunchOutput) {
		t.Fatal("short successful write was reported as a complete launch notice", err)
	}
	if _, err := os.ReadFile(pidFile); err != nil {
		t.Fatal("short notice test did not reach an actual running child", err)
	}
	if state := manager.Snapshot(); state.PID != 0 || state.State != "stopped" {
		t.Fatal("short notice left owned child running or unreaped", state)
	}
}
