package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
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
	lifecycle := errors.New("owned launch lifecycle uncertain")
	for _, tc := range []struct {
		name                             string
		reason                           engine.RunReason
		waitErr, policyErr, lifecycleErr error
		wantErr                          error
	}{
		{name: "exited", reason: engine.RunExited},
		{name: "stopped", reason: engine.RunStopped, waitErr: failure},
		{name: "failed", reason: engine.RunFailed, waitErr: failure, wantErr: failure},
		{name: "policy", reason: engine.RunPolicyRevoked, waitErr: failure, policyErr: managed.ErrUnavailable, wantErr: managed.ErrUnavailable},
		{name: "lifecycle-clean", reason: engine.RunExited, lifecycleErr: lifecycle, wantErr: lifecycle},
		{name: "lifecycle-stopped", reason: engine.RunStopped, lifecycleErr: lifecycle, wantErr: lifecycle},
		{name: "lifecycle-policy", reason: engine.RunPolicyRevoked, waitErr: failure, policyErr: managed.ErrUnavailable, lifecycleErr: lifecycle, wantErr: lifecycle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stops := 0
			done := make(chan struct{})
			close(done)
			run := foregroundRunFixture{done: done, wait: func(waitCtx context.Context) (engine.RunResult, error) {
				if waitCtx.Err() != nil {
					t.Error("terminal observation reused canceled context")
				}
				return engine.RunResult{Reason: tc.reason, WaitErr: tc.waitErr, PolicyErr: tc.policyErr, LifecycleErr: tc.lifecycleErr}, nil
			}}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := waitForegroundEngine(ctx, run, func() error { stops++; return nil })
			if tc.lifecycleErr != nil && ((tc.waitErr != nil && !errors.Is(err, tc.waitErr)) || (tc.policyErr != nil && !errors.Is(err, tc.policyErr))) {
				t.Fatal("lifecycle fault discarded actual wait or policy cause", err)
			}
			if !errors.Is(err, tc.wantErr) || stops != 0 {
				t.Fatal("foreground completion changed terminal error or signaled another process", err, stops)
			}
		})
	}
}

func TestForegroundEngineCancellationRetainsOwnedLaunchUntilDone(t *testing.T) {
	for _, stopFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop-returned-before-done", true: "stop-failed"}[stopFailure], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done, stopCalled := make(chan struct{}), make(chan struct{})
			actual, stopErr := errors.New("actual child failure"), errors.New("PRIVATE_STOP_FAULT")
			waits := 0
			run := foregroundRunFixture{done: done, wait: func(waitCtx context.Context) (engine.RunResult, error) {
				waits++
				if waitCtx.Err() != nil {
					t.Error("terminal wait was canceled")
				}
				return engine.RunResult{Reason: engine.RunFailed, WaitErr: actual}, nil
			}}
			feedback := &bytes.Buffer{}
			finished := make(chan error, 1)
			returned := make(chan struct{})
			cleanupForegroundFixture(t, done, returned)
			go func() {
				defer close(returned)
				finished <- observeForegroundEngine(ctx, run, func() error {
					close(stopCalled)
					if stopFailure {
						return stopErr
					}
					return nil
				}, feedback, false)
			}()
			cancel()
			select {
			case <-stopCalled:
			case <-time.After(5 * time.Second):
				t.Fatal("owned stop not requested")
			}
			select {
			case err := <-finished:
				t.Fatal("foreground abandoned a pending launch", err)
			case <-time.After(25 * time.Millisecond):
			}
			close(done)
			select {
			case err := <-finished:
				if !errors.Is(err, actual) || (stopFailure && !errors.Is(err, stopErr)) || waits != 1 {
					t.Fatal("actual outcome or stop error lost", err, waits)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("terminal launch was not drained")
			}
			if !strings.Contains(feedback.String(), "command remains active") || strings.Contains(feedback.String(), "PRIVATE") {
				t.Fatal("pending feedback missing or disclosed native error", feedback.String())
			}
		})
	}
	stops := 0
	if err := waitForegroundEngine(context.Background(), foregroundRunFixture{}, func() error { stops++; return nil }); !errors.Is(err, engine.ErrRunUnavailable) || stops != 0 {
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

type foregroundFaultFixture struct {
	foregroundRunFixture
	fault   <-chan struct{}
	pending func() error
}

func (r foregroundFaultFixture) Fault() <-chan struct{} { return r.fault }
func (r foregroundFaultFixture) PendingError() error    { return r.pending() }

type foregroundFeedbackReceipt struct{ written chan string }

func (w foregroundFeedbackReceipt) Write(data []byte) (int, error) {
	w.written <- string(data)
	return len(data), nil
}

func TestForegroundEnginePendingFaultRetainsOwnershipAndGivesFixedFeedback(t *testing.T) {
	done, fault := make(chan struct{}), make(chan struct{})
	actual := errors.New("PRIVATE_LIFECYCLE_FAULT")
	var pending atomic.Bool
	probed := make(chan struct{}, 1)
	run := foregroundFaultFixture{foregroundRunFixture: foregroundRunFixture{done: done, wait: func(context.Context) (engine.RunResult, error) {
		return engine.RunResult{Reason: engine.RunExited, LifecycleErr: actual}, nil
	}}, fault: fault, pending: func() error {
		if pending.Load() {
			return actual
		}
		select {
		case probed <- struct{}{}:
		default:
		}
		return nil
	}}
	feedback := foregroundFeedbackReceipt{written: make(chan string, 2)}
	finished := make(chan error, 1)
	returned := make(chan struct{})
	cleanupForegroundFixture(t, done, returned)
	go func() {
		defer close(returned)
		finished <- observeForegroundEngine(context.Background(), run, func() error { t.Error("pending fault caused an automatic stop retry"); return nil }, feedback, false)
	}()
	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		t.Fatal("foreground pending observation not entered")
	}
	pending.Store(true)
	close(fault)
	select {
	case text := <-feedback.written:
		if !strings.Contains(text, "command remains active") || strings.Contains(text, "PRIVATE") {
			t.Error("missing or private pending feedback", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending fault was silent")
	}
	select {
	case err := <-finished:
		t.Fatal("pending fault became terminal", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(done)
	select {
	case err := <-finished:
		if !errors.Is(err, actual) {
			t.Fatal("terminal lifecycle fault lost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal observation not drained")
	}
	select {
	case <-feedback.written:
		t.Fatal("same pending fault was reported repeatedly")
	default:
	}
}

func TestForegroundEngineNoticeFailureRetainsAcceptedLaunchAfterStopError(t *testing.T) {
	done, stopped := make(chan struct{}), make(chan struct{})
	stopErr := errors.New("PRIVATE_STOP_FAULT")
	run := foregroundRunFixture{done: done, wait: func(ctx context.Context) (engine.RunResult, error) {
		if ctx.Err() != nil {
			t.Error("notice failure canceled terminal observation")
		}
		return engine.RunResult{Reason: engine.RunStopped}, nil
	}}
	finished := make(chan error, 1)
	returned := make(chan struct{})
	cleanupForegroundFixture(t, done, returned)
	go func() {
		defer close(returned)
		finished <- finishAcceptedForegroundEngine(context.Background(), run, func() error { close(stopped); return stopErr }, shortForegroundNotice{}, io.Discard)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("notice failure did not request stop")
	}
	select {
	case err := <-finished:
		t.Fatal("notice failure abandoned accepted launch", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(done)
	select {
	case err := <-finished:
		if !errors.Is(err, errEngineLaunchOutput) || !errors.Is(err, stopErr) {
			t.Fatal("notice or stop error lost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notice failure did not drain launch")
	}
}

// Failed assertions must still release and join the deliberately pending run.
func cleanupForegroundFixture(t *testing.T, done chan struct{}, returned <-chan struct{}) {
	t.Helper()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			close(done)
		}
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Error("foreground fixture did not release")
		}
	})
}

type shortForegroundNotice struct{}

func (shortForegroundNotice) Write(data []byte) (int, error) { return len(data) - 1, nil }

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
