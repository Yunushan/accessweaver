//go:build linux || darwin || freebsd || openbsd

package engine

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func shutdownAsync(manager *Manager) <-chan error {
	result := make(chan error, 1)
	go func() { result <- manager.Shutdown(context.Background()) }()
	return result
}
func shutdownAwait(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(9 * time.Second):
		t.Fatal("owned manager shutdown did not finish")
		return nil
	}
}
func shutdownCallerTimeout(t *testing.T, manager *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shutdown caller timeout fabricated owned completion")
	}
}
func shutdownState(t *testing.T, manager *Manager) *managerShutdown {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.shutdown == nil {
		t.Fatal("shared shutdown worker was not created")
	}
	return manager.shutdown
}
func shutdownOperationReleased(manager *Manager) <-chan struct{} {
	released := make(chan struct{})
	go func() { manager.opMu.Lock(); manager.opMu.Unlock(); close(released) }()
	return released
}

func TestUnixShutdownEmptyAndCompletedResultPrecedence(t *testing.T) {
	manager := NewManager(t.TempDir())
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal("empty manager shutdown failed")
	}
	shared := shutdownState(t, manager)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 4 {
		if err := manager.Shutdown(ctx); err != nil {
			t.Fatal("completed empty shutdown lost terminal precedence")
		}
		if shutdownState(t, manager) != shared {
			t.Fatal("repeated empty shutdown created another worker")
		}
	}
}

func TestUnixShutdownRepeatedCallersShareOneActualStop(t *testing.T) {
	f := newLifetimeFixture(t)
	var admissions atomic.Int64
	f.start("term", func(owner *ownedProcess) {
		owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
	}, nil)
	const callers = 12
	results := make(chan error, callers)
	for range callers {
		go func() { results <- f.manager.Shutdown(context.Background()) }()
	}
	f.read('t')
	for range callers {
		if err := shutdownAwait(t, results); err != nil {
			t.Fatal("shared graceful shutdown failed")
		}
	}
	result := lifetimeExit(t, f.run, RunStopped, 0)
	if result.LifecycleErr != nil || result.PolicyErr != nil || admissions.Load() != 2 {
		t.Fatal("repeated shutdown duplicated TERM or final owned cleanup")
	}
	shared := shutdownState(t, f.manager)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.manager.Shutdown(ctx); err != nil || shutdownState(t, f.manager) != shared || admissions.Load() != 2 {
		t.Fatal("completed shared shutdown repeated native stop")
	}
}

func TestUnixShutdownDrainsActualBlockedOutputAfterStopTimeout(t *testing.T) {
	f := newLifetimeFixture(t)
	writer := &lifetimeBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(writer.release) }) })
	f.output = writer
	beforeWait := make(chan struct{})
	var admissions atomic.Int64
	f.start("output", func(owner *ownedProcess) {
		owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
		owner.beforeWait = func() { close(beforeWait) }
	}, nil)
	lifetimeAwait(t, writer.entered, "shutdown fixture did not enter the actual output writer")
	background := shutdownAsync(f.manager)
	f.read('t') // The sole Stop is now inside its graceful wait, holding opMu.
	shared := shutdownState(t, f.manager)
	f.write('q')
	lifetimeAwait(t, beforeWait, "shutdown child did not retire its native signal owner")
	// This lock witness cannot pass until Stop releases its real operation lock.
	// The destination writer remains blocked throughout the ordinary stop budgets.
	lifetimeAwait(t, shutdownOperationReleased(f.manager), "shutdown retained operation lock while draining output")
	select {
	case <-f.run.Done():
		t.Fatal("blocked output was reported as drained")
	default:
	}
	select {
	case <-shared.done:
		t.Fatal("bounded Stop timeout fabricated shared shutdown completion")
	default:
	}
	before := admissions.Load()
	for range 3 {
		shutdownCallerTimeout(t, f.manager)
		if shutdownState(t, f.manager) != shared {
			t.Fatal("timed-out caller created another shutdown worker")
		}
	}
	if admissions.Load() != before {
		t.Fatal("timed-out shutdown callers repeated native dispatch")
	}
	select {
	case <-background:
		t.Fatal("background shutdown returned before actual output drain")
	default:
	}
	releaseOnce.Do(func() { close(writer.release) })
	terminal := shutdownAwait(t, background)
	if terminal == nil || !strings.Contains(terminal.Error(), "within timeout") {
		t.Fatal("late shutdown drain erased the original Stop timeout")
	}
	result := waitTracked(t, f.run)
	if !f.owner.cmd.ProcessState.Success() || result.LifecycleErr != nil || result.PolicyErr != nil || writer.bytes.Load() != int64(len("lifetime-output-marker\n")) {
		t.Fatal("late shutdown drain lost actual exit or output")
	}
	if result.WaitErr != nil && !errors.Is(result.WaitErr, exec.ErrWaitDelay) {
		t.Fatal("late shutdown drain changed its real I/O wait error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := f.manager.Shutdown(ctx); got != terminal {
		t.Fatal("repeated shutdown lost its single retained terminal error")
	}
	if admissions.Load() != before {
		t.Fatal("terminal shutdown repeated native dispatch")
	}
}

func TestUnixShutdownPendingCleanupRequiresExplicitSameRunRetry(t *testing.T) {
	f := newLifetimeFixture(t)
	var refuse atomic.Bool
	refuse.Store(true)
	var attempts atomic.Int64
	f.start("controlled", func(owner *ownedProcess) {
		real := owner.nativeSignal
		owner.nativeSignal = func(pgid int, sig syscall.Signal) error {
			attempts.Add(1)
			if refuse.Load() {
				return syscall.EPERM
			}
			return real(pgid, sig)
		}
	}, nil)
	t.Cleanup(func() { refuse.Store(false) })
	f.write('q')
	lifetimeAwait(t, f.run.Fault(), "shutdown cleanup fault was not published")
	if !errors.Is(f.run.PendingError(), ErrProcessCleanupPending) {
		t.Fatal("shutdown cleanup lost its fixed pending fault")
	}
	var shared *managerShutdown
	for range 3 {
		shutdownCallerTimeout(t, f.manager)
		current := shutdownState(t, f.manager)
		if shared == nil {
			shared = current
		} else if current != shared {
			t.Fatal("pending cleanup created another shutdown worker")
		}
	}
	lifetimeAwait(t, shutdownOperationReleased(f.manager), "pending shutdown held operation lock against explicit recovery")
	if attempts.Load() != 1 {
		t.Fatal("shutdown automatically retried native cleanup")
	}
	if !f.manager.Snapshot().LifecyclePending {
		t.Fatal("pending shutdown hid unresolved generation")
	}
	select {
	case <-shared.done:
		t.Fatal("pending fault fabricated shutdown completion")
	default:
	}
	select {
	case <-f.run.Done():
		t.Fatal("pending fault fabricated exact run completion")
	default:
	}
	if err := f.manager.RetryCleanup(&Run{}); !errors.Is(err, ErrRunUnavailable) {
		t.Fatal("shutdown retry accepted an unrelated generation")
	}
	refuse.Store(false)
	if err := f.manager.RetryCleanup(f.run); err != nil {
		t.Fatal("shutdown retained generation could not be explicitly recovered")
	}
	terminal := f.manager.Shutdown(context.Background())
	if !errors.Is(terminal, ErrProcessCleanupPending) || !errors.Is(terminal, ErrProcessLifecycle) {
		t.Fatal("shutdown recovery erased initial fault or terminal uncertainty")
	}
	result := lifetimeExit(t, f.run, RunFailed, 0)
	if !errors.Is(result.LifecycleErr, ErrProcessLifecycle) || attempts.Load() != 2 {
		t.Fatal("shutdown recovery changed actual zero exit or repeated cleanup")
	}
	if f.manager.Snapshot().LifecyclePending {
		t.Fatal("drained shutdown kept transient pending state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f.manager.Shutdown(ctx) != terminal || shutdownState(t, f.manager) != shared {
		t.Fatal("recovered shutdown did not share one immutable result")
	}
}

func TestUnixShutdownPropagatesLifecycleErrorWithoutChangingActualExitZero(t *testing.T) {
	f := newLifetimeFixture(t)
	f.start("controlled", func(owner *ownedProcess) {
		owner.observer = &lifetimeFaultObserver{base: owner.observer, closeErr: syscall.EIO}
	}, nil)
	background := shutdownAsync(f.manager)
	f.read('t') // Capture and Stop concern this still-active exact run.
	f.write('q')
	terminal := shutdownAwait(t, background)
	if !errors.Is(terminal, ErrProcessLifecycle) {
		t.Fatal("shutdown discarded terminal lifetime uncertainty")
	}
	result := lifetimeExit(t, f.run, RunFailed, 0)
	if result.WaitErr != nil || !errors.Is(result.LifecycleErr, ErrProcessLifecycle) {
		t.Fatal("shutdown rewrote the actual successful process wait")
	}
	if f.manager.Shutdown(context.Background()) != terminal {
		t.Fatal("terminal lifetime error was not shared")
	}
}

func TestUnixShutdownDoesNotImportInactiveHistoricalFailure(t *testing.T) {
	f := newLifetimeFixture(t)
	f.start("controlled", func(owner *ownedProcess) {
		owner.observer = &lifetimeFaultObserver{base: owner.observer, closeErr: syscall.EIO}
	}, nil)
	f.write('q')
	result := lifetimeExit(t, f.run, RunFailed, 0)
	if !errors.Is(result.LifecycleErr, ErrProcessLifecycle) {
		t.Fatal("historical fixture lifetime failure was not real")
	}
	if err := f.manager.Shutdown(context.Background()); err != nil {
		t.Fatal("empty shutdown imported an inactive historical run failure")
	}
}

func TestUnixShutdownDrainsRealAcceptedStartPublishedAfterClosing(t *testing.T) {
	f := newLifetimeFixture(t)
	entered, release, startReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.launchPending = true
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		select {
		case <-startReturned:
			f.launchPending = false
		case <-time.After(9 * time.Second):
			f.preserve = true
			t.Error("accepted Start fixture launcher did not finish; fixture preserved")
		}
	})
	var admissions atomic.Int64
	f.afterStart = func() { close(entered); <-release }
	go func() {
		defer close(startReturned)
		f.launch("term", func(owner *ownedProcess) {
			owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
		}, nil)
	}()
	lifetimeAwait(t, entered, "real accepted Start did not reach publication boundary")
	f.read('r') // The real image is executing before manager publication.
	stateRead := make(chan Snapshot, 1)
	go func() { stateRead <- f.manager.Snapshot() }()
	select {
	case <-stateRead:
	case <-time.After(time.Second):
		t.Fatal("accepted Start held manager state lock")
	}
	shutdownCallerTimeout(t, f.manager)
	shared := shutdownState(t, f.manager)
	if admissions.Load() != 0 {
		t.Fatal("shutdown signaled an unpublished generation outside start ownership")
	}
	select {
	case <-shared.done:
		t.Fatal("unpublished accepted Start was abandoned by shutdown")
	default:
	}
	once.Do(func() { close(release) })
	lifetimeAwait(t, startReturned, "accepted Start failed to publish after closing")
	if f.run == nil {
		t.Fatal("successful Start returned no accepted generation")
	}
	f.read('t')
	if err := f.manager.Shutdown(context.Background()); err != nil {
		t.Fatal("late accepted generation was not drained")
	}
	result := lifetimeExit(t, f.run, RunStopped, 0)
	if result.LifecycleErr != nil || result.PolicyErr != nil || admissions.Load() != 2 || shutdownState(t, f.manager) != shared {
		t.Fatal("late accepted generation lost shared exact shutdown ownership")
	}
	next, err := f.manager.StartTracked(f.p)
	if next != nil || err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Fatal("completed closing manager admitted another generation")
	}
}

func TestUnixShutdownRetainsCompletedGenerationPublishedAfterEntry(t *testing.T) {
	f := newLifetimeFixture(t)
	started, releaseStart, startReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	workerPaused, releaseWorker := make(chan struct{}), make(chan struct{})
	var startOnce, workerOnce sync.Once
	var shared *managerShutdown
	f.launchPending = true
	t.Cleanup(func() {
		startOnce.Do(func() { close(releaseStart) })
		workerOnce.Do(func() { close(releaseWorker) })
		select {
		case <-startReturned:
			f.launchPending = false
		case <-time.After(9 * time.Second):
			f.preserve = true
			t.Error("completed-generation launcher did not finish; fixture preserved")
			return
		}
		if shared != nil {
			select {
			case <-shared.done:
			case <-time.After(9 * time.Second):
				f.preserve = true
				t.Error("completed-generation shutdown did not finish; fixture preserved")
			}
		}
	})
	f.afterStart = func() { close(started); <-releaseStart }
	var admissions atomic.Int64
	go func() {
		defer close(startReturned)
		f.launch("controlled", func(owner *ownedProcess) {
			owner.observer = &lifetimeFaultObserver{base: owner.observer, closeErr: syscall.EIO}
			owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
		}, nil)
	}()
	lifetimeAwait(t, started, "completed-generation real Start did not reach publication barrier")
	f.read('r')
	// Configure before the first Shutdown. The native child is accepted but is
	// still unpublished; the worker may not serialize/capture until released.
	f.manager.beforeShutdownCapture = func() { close(workerPaused); <-releaseWorker }
	shutdownCallerTimeout(t, f.manager)
	lifetimeAwait(t, workerPaused, "shutdown worker did not reach generation capture barrier")
	shared = shutdownState(t, f.manager)
	startOnce.Do(func() { close(releaseStart) })
	lifetimeAwait(t, startReturned, "accepted generation did not publish while shutdown worker paused")
	if f.run == nil {
		t.Fatal("accepted completed generation lost its Run")
	}
	f.write('q')
	actual := lifetimeExit(t, f.run, RunFailed, 0)
	if !errors.Is(actual.LifecycleErr, ErrProcessLifecycle) || actual.WaitErr != nil {
		t.Fatal("completed generation fixture lost actual zero exit or uncertainty")
	}
	if f.manager.Snapshot().PID != 0 {
		t.Fatal("completed generation still advertised a live process")
	}
	before := admissions.Load()
	select {
	case <-shared.done:
		t.Fatal("paused shutdown worker fabricated generation accounting")
	default:
	}
	workerOnce.Do(func() { close(releaseWorker) })
	terminal := f.manager.Shutdown(context.Background())
	if !errors.Is(terminal, ErrProcessLifecycle) {
		t.Fatal("shutdown dropped a new generation completed before worker capture")
	}
	if admissions.Load() != before {
		t.Fatal("accounting for completed generation repeated a retired native signal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f.manager.Shutdown(ctx) != terminal || shutdownState(t, f.manager) != shared {
		t.Fatal("completed-generation shutdown did not retain one final result")
	}
}
