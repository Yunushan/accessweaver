package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// These extra modes belong only to the source-built inert test executable.
func init() {
	if os.Getenv("ACCESSWEAVER_FIXTURE") != "1" {
		return
	}
	for _, arg := range os.Args[1:] {
		switch arg {
		case "tracked-exit-zero":
			os.Exit(0)
		case "tracked-exit-fail":
			os.Exit(23)
		}
	}
}

func trackedFixture(t *testing.T) (profile.Profile, string) {
	t.Helper()
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
	t.Setenv("ACCESSWEAVER_FIXTURE", "1")
	t.Setenv("ACCESSWEAVER_FIXTURE_RECORD", filepath.Join(root, "ready.json"))
	p := profile.New("tracked-run", "Tracked run", "byedpi")
	p.Binary = bin
	return p, root
}

func waitTracked(t *testing.T, run *Run) RunResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	result, err := run.Wait(ctx)
	if err != nil {
		t.Fatal("owned launch did not publish its terminal result", err)
	}
	select {
	case <-run.Done():
	default:
		t.Fatal("result returned before completion was published")
	}
	return result
}

func waitTrackedReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(os.Getenv("ACCESSWEAVER_FIXTURE_RECORD")); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("inert child did not become ready")
}

func TestTrackedRunImmediateExitAndGenerationIsolation(t *testing.T) {
	p, root := trackedFixture(t)
	manager := NewManager(root)
	t.Cleanup(func() { _ = manager.Stop() })
	p.Args = []string{"tracked-exit-fail"}
	first, err := manager.StartTracked(p)
	if err != nil {
		t.Fatal(err)
	}
	copied := *first
	failed := waitTracked(t, first)
	if result := waitTracked(t, &copied); result != failed {
		t.Fatal("copied launch handle lost published result", result)
	}
	var exit *exec.ExitError
	if failed.Reason != RunFailed || !errors.As(failed.WaitErr, &exit) || exit.ExitCode() != 23 || failed.PolicyErr != nil {
		t.Fatalf("actual unexpected exit lost: %+v", failed)
	}
	p.Args = []string{"tracked-exit-zero"}
	second, err := manager.StartTracked(p)
	if err != nil {
		t.Fatal(err)
	}
	normal := waitTracked(t, second)
	if normal.Reason != RunExited || normal.WaitErr != nil || normal.PolicyErr != nil || first == second {
		t.Fatalf("immediate normal exit differs: %+v", normal)
	}
	p.Args = nil
	third, err := manager.StartTracked(p)
	if err != nil {
		t.Fatal(err)
	}
	waitTrackedReady(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	// Already published results are independent of a later launch or wait context.
	old, err := first.Wait(cancelled)
	if err != nil || old != failed {
		t.Fatal("old launch handle followed the next process or lost its result", old, err)
	}
	select {
	case <-third.Done():
		t.Fatal("new launch inherited old completion")
	default:
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	stopped := waitTracked(t, third)
	if stopped.Reason != RunStopped || stopped.PolicyErr != nil {
		t.Fatalf("accepted owned stop lost: %+v", stopped)
	}
	if state := manager.Snapshot(); state.State != "stopped" || state.PID != 0 || state.LastError != "" {
		t.Fatalf("snapshot does not mirror expected stop: %+v", state)
	}
}

func TestTrackedRunWaitCancellationDoesNotStopChild(t *testing.T) {
	p, root := trackedFixture(t)
	manager := NewManager(root)
	t.Cleanup(func() { _ = manager.Stop() })
	run, err := manager.StartTracked(p)
	if err != nil {
		t.Fatal(err)
	}
	waitTrackedReady(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := run.Wait(ctx); !errors.Is(err, context.Canceled) || result != (RunResult{}) {
		t.Fatal("canceled waiter returned a terminal result", result, err)
	}
	if state := manager.Snapshot(); state.State != "running" || state.PID == 0 {
		t.Fatal("wait cancellation signaled the process", state)
	}
	select {
	case <-run.Done():
		t.Fatal("canceled waiter published launch completion")
	default:
	}
	const waiters = 16
	results := make(chan RunResult, waiters)
	errorsSeen := make(chan error, waiters)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer waitCancel()
	for range waiters {
		go func() {
			result, err := run.Wait(waitCtx)
			results <- result
			errorsSeen <- err
		}()
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	for range waiters {
		result := <-results
		if err := <-errorsSeen; err != nil || result.Reason != RunStopped {
			t.Fatal("concurrent waiter did not receive published result", result, err)
		}
	}
}

func TestTrackedRunNilAndUnstartedHandles(t *testing.T) {
	for _, run := range []*Run{nil, {}} {
		if run.Done() != nil {
			t.Fatal("unstarted run unexpectedly signaled completion")
		}
		if _, err := run.Wait(context.Background()); !errors.Is(err, ErrRunUnavailable) {
			t.Fatal("unstarted wait did not fail promptly", err)
		}
	}
	p, root := trackedFixture(t)
	p.Binary = filepath.Join(root, "missing")
	run, err := NewManager(root).StartTracked(p)
	if err == nil || run != nil {
		t.Fatal("failed launch returned a usable handle", run, err)
	}
}

func TestTrackedRunPolicyRevocationRetainsActualWait(t *testing.T) {
	p, root := trackedFixture(t)
	var revoked atomic.Bool
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		if revoked.Load() {
			return nil, managed.ErrUnavailable
		}
		return nil, nil
	})
	manager := NewManagerWithGuard(root, guard)
	t.Cleanup(func() { _ = manager.Stop() })
	run, err := manager.StartTracked(p)
	if err != nil {
		t.Fatal(err)
	}
	waitTrackedReady(t)
	revoked.Store(true)
	result := waitTracked(t, run)
	if result.Reason != RunPolicyRevoked || !managed.IsPolicyError(result.PolicyErr) || result.WaitErr == nil {
		t.Fatalf("policy termination lost actual process or policy error: %+v", result)
	}
	if state := manager.Snapshot(); state.State != "error" || state.PID != 0 || state.LastError == "" {
		t.Fatalf("policy terminal result did not reach snapshot: %+v", state)
	}
}

func TestTrackedRunResolvesSignalsBeforePublishingImmediateExit(t *testing.T) {
	for _, outcome := range []string{"accepted", "failed", "already-done"} {
		t.Run(outcome, func(t *testing.T) {
			p, root := trackedFixture(t)
			manager := NewManager(root)
			t.Cleanup(func() { _ = manager.Stop() })
			waited := make(chan struct{})
			run, err := manager.startTracked(p, func() { close(waited) })
			if err != nil {
				t.Fatal(err)
			}
			waitTrackedReady(t)
			failure := errors.New("fixture signal refused")
			var signalErr error
			switch outcome {
			case "failed":
				signalErr = failure
			case "already-done":
				signalErr = os.ErrProcessDone
			}
			var earlyPublication bool
			interrupt := func(process *os.Process) error {
				if err := killProcess(process); err != nil {
					return err
				}
				select {
				case <-waited:
				case <-time.After(5 * time.Second):
					return errors.New("fixture process was not reaped")
				}
				// cmd.Wait has returned while the signal result is unresolved.
				select {
				case <-run.Done():
					earlyPublication = true
				default:
				}
				return signalErr
			}
			err = manager.stop(interrupt, func(*os.Process) error { return signalErr }, 3*time.Second, time.Second)
			if earlyPublication {
				t.Fatal("terminal result published before signal outcome resolved")
			}
			if outcome == "failed" && !errors.Is(err, failure) {
				t.Fatal("failed signal dispatch was hidden", err)
			}
			if outcome != "failed" && err != nil {
				t.Fatal(err)
			}
			result := waitTracked(t, run)
			wantReason, wantState := RunFailed, "error"
			if outcome == "accepted" {
				wantReason, wantState = RunStopped, "stopped"
			}
			if result.Reason != wantReason || result.WaitErr == nil || result.PolicyErr != nil {
				t.Fatalf("signal attempt replaced actual Wait or misclassified exit: %+v", result)
			}
			if state := manager.Snapshot(); state.State != wantState || state.PID != 0 || (state.LastError != "") != (wantState == "error") {
				t.Fatalf("snapshot did not mirror resolved terminal state: %+v", state)
			}
		})
	}
}

func TestTrackedRunFailedSignalRestoresRunningAndStopTimeoutRetainsOwnership(t *testing.T) {
	p, root := trackedFixture(t)
	manager := NewManager(root)
	t.Cleanup(func() { _ = manager.Stop() })
	run, err := manager.StartTracked(p)
	if err != nil {
		t.Fatal(err)
	}
	waitTrackedReady(t)
	failure := errors.New("fixture signal refused")
	refuse := func(*os.Process) error { return failure }
	if err := manager.stop(refuse, refuse, 0, 0); !errors.Is(err, failure) {
		t.Fatal("failed stop did not preserve signal error", err)
	}
	if state := manager.Snapshot(); state.State != "running" || state.PID == 0 {
		t.Fatal("failed stop falsely changed running state", state)
	}
	var interrupts, kills int
	if err := manager.stop(func(*os.Process) error { interrupts++; return nil }, func(*os.Process) error { kills++; return nil }, 0, 0); err == nil || !strings.Contains(err.Error(), "within timeout") {
		t.Fatal("bounded wait falsely completed an unresponsive process", err)
	}
	if interrupts != 1 || kills != 1 {
		t.Fatal("grace/force stop sequence changed", interrupts, kills)
	}
	select {
	case <-run.Done():
		t.Fatal("stop timeout published a terminal result")
	default:
	}
	if next, err := manager.StartTracked(p); err == nil || next != nil {
		t.Fatal("stop timeout released ownership and admitted another child", next, err)
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	if result := waitTracked(t, run); result.Reason != RunStopped {
		t.Fatal("owned process could not be stopped after timeout", result)
	}
}

func TestTrackedRunForcedSignalResolvesBeforePublishingExit(t *testing.T) {
	p, root := trackedFixture(t)
	manager := NewManager(root)
	t.Cleanup(func() { _ = manager.Stop() })
	waited := make(chan struct{})
	run, err := manager.startTracked(p, func() { close(waited) })
	if err != nil {
		t.Fatal(err)
	}
	waitTrackedReady(t)
	kills := 0
	var earlyPublication bool
	kill := func(process *os.Process) error {
		kills++
		if kills == 1 {
			// No initial signal was accepted, and the process remains alive.
			return os.ErrProcessDone
		}
		if err := killProcess(process); err != nil {
			return err
		}
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			return errors.New("fixture escalation did not reap process")
		}
		select {
		case <-run.Done():
			earlyPublication = true
		default:
		}
		return nil
	}
	if err := manager.stop(func(*os.Process) error { return os.ErrProcessDone }, kill, 0, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	result := waitTracked(t, run)
	if earlyPublication || kills != 2 || result.Reason != RunStopped || result.WaitErr == nil {
		t.Fatal("forced signal acceptance or actual exit lost", earlyPublication, kills, result)
	}
}
