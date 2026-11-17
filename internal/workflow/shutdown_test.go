package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/managed"
)

// observeWorkflowNoNativeOwners is an explicit test-only fact for callbacks
// audited to create no native child, asynchronous output or retained native
// handle. It never stands in for observed command Wait/owner/output closure or
// the production persistence writer's separate observation.
func observeWorkflowNoNativeOwners(ctx context.Context) {
	if observation := localExecutionFrom(ctx); observation != nil {
		observation.NoNativeOwners = true
	}
}

// These fixtures use the actual reservation, validation and private persistence
// paths with controlled source callbacks. The platform label admits a reviewed
// plan only; no Windows executable or native workflow is ever invoked.
type workflowShutdownFixture struct {
	t        *testing.T
	manager  *Manager
	root     string
	rootInfo os.FileInfo
	releases []func()
	starts   []<-chan struct{}
	preserve bool
}

func newWorkflowShutdownFixture(t *testing.T) *workflowShutdownFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-workflow-shutdown-")
	if err != nil {
		t.Fatal("workflow fixture directory unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("workflow fixture directory binding unavailable")
	}
	f := &workflowShutdownFixture{t: t, root: root, rootInfo: info}
	f.manager = NewWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	f.manager.platform = "windows"
	f.manager.requireAdmin = func() error { return nil }
	f.manager.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		return json.RawMessage(`{"fixture":true}`), nil
	}
	t.Cleanup(f.close)
	return f
}
func (f *workflowShutdownFixture) barrier() (chan struct{}, func()) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f.releases = append(f.releases, unblock)
	return entered, func() { <-release }
}
func (f *workflowShutdownFixture) plan() Plan {
	f.t.Helper()
	p, err := f.manager.Preview(Request{Action: "discover"})
	if err != nil || !p.Ready {
		f.t.Fatal("workflow fixture preview failed")
	}
	return p
}
func (f *workflowShutdownFixture) start() Job {
	f.t.Helper()
	p := f.plan()
	job, err := f.manager.Start(p.ID)
	if err != nil {
		f.t.Fatal("workflow fixture admission failed")
	}
	return job
}
func (f *workflowShutdownFixture) startAsync(plan Plan) (<-chan error, <-chan struct{}) {
	result, done := make(chan error, 1), make(chan struct{})
	f.starts = append(f.starts, done)
	go func() { defer close(done); _, err := f.manager.Start(plan.ID); result <- err }()
	return result, done
}
func (f *workflowShutdownFixture) unblockAll() {
	for i := len(f.releases) - 1; i >= 0; i-- {
		f.releases[i]()
	}
}
func (f *workflowShutdownFixture) close() {
	f.manager.Cancel()
	f.unblockAll()
	for _, done := range f.starts {
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			f.preserve = true
			f.t.Error("workflow admission did not join; fixture preserved")
		}
	}
	if f.preserve {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = f.manager.Shutdown(ctx) // Expected typed failures are checked by each case.
	done := workflowShutdownDone(f.manager)
	if done != nil {
		select {
		case <-done:
		default:
			f.preserve = true
			f.t.Error("workflow completion unconfirmed; fixture preserved")
		}
	}
	if f.preserve {
		return
	}
	if done := workflowMaintenanceDone(f.manager); done != nil {
		select {
		case <-done:
		default:
			f.preserve = true
			f.t.Error("workflow maintenance completion unconfirmed; fixture preserved")
		}
	}
	if f.preserve {
		return
	}
	current, err := os.Lstat(f.root)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(f.rootInfo, current) {
		f.t.Error("workflow fixture root binding changed")
		return
	}
	if os.RemoveAll(f.root) != nil {
		f.t.Error("workflow fixture removal failed")
	}
}
func workflowMaintenanceDone(m *Manager) <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.maintenance != nil {
		return m.maintenance.done
	}
	return nil
}
func workflowShutdownDone(m *Manager) <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.done
}
func workflowShutdownAwait(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal(message)
	}
}
func workflowShutdownTimeout(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("workflow caller timeout fabricated completion")
	}
}
func workflowShutdownFinal(t *testing.T, m *Manager) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := m.Shutdown(ctx)
	if ctx.Err() != nil {
		t.Fatal("workflow shared shutdown did not finish")
	}
	return err
}

type workflowPrivateCause struct{ message string }

func (e *workflowPrivateCause) Error() string { return e.message }
func workflowShutdownPublic(t *testing.T, err error, private ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("workflow terminal failure was discarded")
	}
	text := err.Error()
	if len(text) > 512 {
		t.Fatal("workflow public shutdown error exceeded fixed stage bound")
	}
	for _, value := range private {
		if value != "" && strings.Contains(text, value) {
			t.Fatal("workflow public shutdown error exposed private cause")
		}
	}
}

func TestWorkflowShutdownRetainsTypedExecutionAndTerminalSaveFailures(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		name := "durable-failure"
		if failWrite {
			name = "terminal-save-failure"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			private := "PRIVATE_WORKFLOW_SOURCE_CAUSE"
			cause := &workflowPrivateCause{message: private + strings.Repeat("界", maxJobErrorBytes)}
			storage := errors.New("PRIVATE_WORKFLOW_PERSIST_CAUSE")
			result := json.RawMessage(`{"retained":"source-result"}`)
			m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
				observeWorkflowNoNativeOwners(ctx)
				return result, cause
			}
			writing, wait := f.barrier()
			var terminalWrites atomic.Int32
			realPersist := m.persist
			m.persist = func(path string, data []byte) error {
				var job Job
				if json.Unmarshal(data, &job) != nil {
					return errors.New("fixture persistence decode failed")
				}
				if job.State != "running" {
					terminalWrites.Add(1)
					close(writing)
					wait()
					if failWrite {
						return storage
					}
				}
				return realPersist(path, data)
			}
			job := f.start()
			workflowShutdownAwait(t, writing, "workflow did not reach terminal persistence")
			path := filepath.Join(m.root, job.ID+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("workflow running record unavailable")
			}
			workflowShutdownTimeout(t, m)
			done := workflowShutdownDone(m)
			select {
			case <-done:
				t.Fatal("terminal persistence was reported complete before return")
			default:
			}
			if err := m.TerminalError(job.ID); !errors.Is(err, ErrWorkflowOutcomeUnavailable) {
				t.Fatal("pending terminal write exposed a completed workflow error")
			}
			if snapshot := m.Snapshot(); snapshot.State != "running" || !snapshot.FinishedAt.IsZero() || len(snapshot.Result) != 0 {
				t.Fatal("unpersisted workflow terminal state was published")
			}
			f.unblockAll()
			terminal := workflowShutdownFinal(t, m)
			workflowShutdownPublic(t, terminal, private, storage.Error(), f.root)
			if !errors.Is(terminal, ErrWorkflowExecution) || !errors.Is(terminal, cause) {
				t.Fatal("workflow execution category or original cause lost")
			}
			var retained *workflowPrivateCause
			if !errors.As(terminal, &retained) || retained != cause {
				t.Fatal("workflow original typed execution cause lost")
			}
			if failWrite && (!errors.Is(terminal, ErrWorkflowPersistence) || !errors.Is(terminal, storage)) {
				t.Fatal("workflow terminal persistence category or cause lost")
			}
			workflowShutdownAwait(t, done, "workflow terminal outcome was not completed")
			if m.TerminalError(job.ID) != terminal {
				t.Fatal("terminal getter did not retain the same fixed typed outcome")
			}
			snapshot := m.Snapshot()
			if snapshot.State != "failed" || snapshot.FinishedAt.IsZero() || !bytes.Equal(snapshot.Result, result) || len(snapshot.Error) > maxJobErrorBytes || !utf8.ValidString(snapshot.Error) || !strings.Contains(snapshot.Error, "truncated") {
				t.Fatal("workflow result or bounded terminal display changed")
			}
			if terminalWrites.Load() != 1 {
				t.Fatal("workflow shutdown repeated terminal persistence")
			}
			if failWrite {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("failed final save repaired or replaced the running record")
				}
			} else {
				history, err := m.History()
				if err != nil || len(history) != 1 || history[0].State != "failed" || history[0].Error != snapshot.Error || !bytes.Equal(history[0].Result, result) {
					t.Fatal("workflow failure result did not remain durably readable")
				}
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if m.Shutdown(canceled) != terminal || terminalWrites.Load() != 1 {
				t.Fatal("repeated workflow shutdown did not share one completed result")
			}
		})
	}
}

func TestWorkflowShutdownCooperativeCancellationDoesNotHideOtherFailures(t *testing.T) {
	other := errors.New("PRIVATE_WORKFLOW_OTHER_FAILURE")
	lookalike := errors.New(context.Canceled.Error())
	cases := []struct {
		name    string
		failure func(context.Context) error
		clean   bool
		cause   error
	}{
		{"plain-cooperative", func(ctx context.Context) error { return ctx.Err() }, true, nil},
		{"joined-failure", func(ctx context.Context) error { return errors.Join(ctx.Err(), other) }, false, other},
		{"wrapped-cancellation", func(ctx context.Context) error { return fmt.Errorf("PRIVATE_WORKFLOW_WRAPPER: %w", ctx.Err()) }, false, context.Canceled},
		{"text-lookalike", func(context.Context) error { return lookalike }, false, lookalike},
		{"deadline-failure", func(context.Context) error { return context.DeadlineExceeded }, false, context.DeadlineExceeded},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			entered, wait := f.barrier()
			canceled := make(chan struct{})
			m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
				observeWorkflowNoNativeOwners(ctx)
				close(entered)
				<-ctx.Done()
				close(canceled)
				wait()
				return json.RawMessage(`{"cancel":"retained"}`), item.failure(ctx)
			}
			f.start()
			workflowShutdownAwait(t, entered, "workflow controlled execution did not start")
			workflowShutdownTimeout(t, m)
			workflowShutdownAwait(t, canceled, "workflow shutdown did not request cooperative cancellation")
			f.unblockAll()
			terminal := workflowShutdownFinal(t, m)
			if item.clean {
				if terminal != nil {
					t.Fatal("plain intentional cooperative cancellation became a shutdown failure")
				}
			} else {
				workflowShutdownPublic(t, terminal, "PRIVATE_WORKFLOW", f.root)
				if !errors.Is(terminal, ErrWorkflowExecution) || !errors.Is(terminal, item.cause) {
					t.Fatal("cooperative cancellation erased a distinct workflow failure")
				}
			}
			job := m.Snapshot()
			if job.State != "failed" || job.FinishedAt.IsZero() || job.Error == "" || string(job.Result) != `{"cancel":"retained"}` {
				t.Fatal("shutdown cancellation changed the original job outcome")
			}
			history, err := m.History()
			if err != nil || len(history) != 1 || history[0].State != "failed" || history[0].Error != job.Error {
				t.Fatal("canceled workflow outcome was not durable")
			}
		})
	}
}

func TestWorkflowShutdownResultValidationFailureSurvivesPlainCancellation(t *testing.T) {
	for _, value := range []struct {
		name   string
		result json.RawMessage
	}{{"invalid-json", json.RawMessage(`{"bad":`)}, {"oversized-result", json.RawMessage(strings.Repeat(" ", maxResultBytes+1))}} {
		t.Run(value.name, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			entered, wait := f.barrier()
			m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
				observeWorkflowNoNativeOwners(ctx)
				close(entered)
				<-ctx.Done()
				wait()
				return value.result, ctx.Err()
			}
			f.start()
			workflowShutdownAwait(t, entered, "workflow validation fixture did not execute")
			workflowShutdownTimeout(t, m)
			f.unblockAll()
			terminal := workflowShutdownFinal(t, m)
			if !errors.Is(terminal, ErrWorkflowResult) || !errors.Is(terminal, context.Canceled) {
				t.Fatal("result cofailure lost validation or original plain cancellation")
			}
			workflowShutdownPublic(t, terminal, f.root)
			job := m.Snapshot()
			if job.State != "failed" || job.FinishedAt.IsZero() || len(job.Result) != 0 || job.Error == "" || len(job.Error) > maxJobErrorBytes {
				t.Fatal("invalid result was retained or its failed outcome was lost")
			}
			history, err := m.History()
			if err != nil || len(history) != 1 || history[0].State != "failed" || len(history[0].Result) != 0 {
				t.Fatal("result refusal was not durably readable")
			}
		})
	}
}

func TestWorkflowShutdownReservedAdmissionRetainsWriteFailure(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		name := "cooperative-reservation"
		if failWrite {
			name = "admission-write-failure"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			writing, wait := f.barrier()
			cause := errors.New("PRIVATE_WORKFLOW_ADMISSION_WRITE")
			var executions atomic.Int32
			m.execute = func(context.Context, string, Request) (json.RawMessage, error) { executions.Add(1); return nil, nil }
			realPersist := m.persist
			m.persist = func(path string, data []byte) error {
				var job Job
				if json.Unmarshal(data, &job) != nil {
					return errors.New("fixture admission decode failed")
				}
				if job.State == "running" {
					close(writing)
					wait()
					if failWrite {
						return cause
					}
				}
				return realPersist(path, data)
			}
			start, startDone := f.startAsync(f.plan())
			workflowShutdownAwait(t, writing, "workflow reservation did not reach initial persistence")
			done := workflowShutdownDone(m)
			if done == nil {
				t.Fatal("admission did not reserve its completion")
			}
			workflowShutdownTimeout(t, m)
			if snapshot := m.Snapshot(); snapshot.State != "running" || !snapshot.FinishedAt.IsZero() {
				t.Fatal("reserved admission fabricated terminal state")
			}
			if executions.Load() != 0 {
				t.Fatal("execution preceded durable admission")
			}
			f.unblockAll()
			workflowShutdownAwait(t, startDone, "reserved admission did not return")
			startErr := <-start
			terminal := workflowShutdownFinal(t, m)
			if failWrite {
				if startErr != cause || !errors.Is(terminal, ErrWorkflowAdmission) || !errors.Is(terminal, ErrWorkflowPersistence) || !errors.Is(terminal, cause) || !errors.Is(terminal, context.Canceled) {
					t.Fatal("admission lost its original return or retained typed write failure")
				}
				workflowShutdownPublic(t, terminal, cause.Error(), f.root)
			} else if startErr != nil || terminal != nil {
				t.Fatal("reserved plain cancellation became a distinct failure")
			}
			workflowShutdownAwait(t, done, "reserved generation completion was not retained")
			if executions.Load() != 0 {
				t.Fatal("cancelled reserved admission executed a workflow")
			}
			job := m.Snapshot()
			if job.State != "failed" || job.FinishedAt.IsZero() || job.Error == "" {
				t.Fatal("reserved admission lost the original failed job outcome")
			}
		})
	}
}

func TestWorkflowShutdownConcurrentCallersRetainOneGeneration(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	entered, wait := f.barrier()
	cause := errors.New("PRIVATE_WORKFLOW_SHARED_FAILURE")
	var executions, cancelCalls atomic.Int32
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		executions.Add(1)
		close(entered)
		<-ctx.Done()
		wait()
		return json.RawMessage(`{"shared":true}`), errors.Join(ctx.Err(), cause)
	}
	f.start()
	workflowShutdownAwait(t, entered, "shared workflow execution did not begin")
	m.mu.Lock()
	originalCancel := m.cancel
	m.cancel = func() { cancelCalls.Add(1); originalCancel() }
	m.mu.Unlock()
	const callers = 12
	results := make(chan error, callers)
	for range callers {
		go func() { results <- m.Shutdown(context.Background()) }()
	}
	workflowShutdownTimeout(t, m)
	if cancelCalls.Load() != 1 || executions.Load() != 1 {
		t.Fatal("repeated shutdown duplicated cancellation or execution")
	}
	select {
	case <-workflowShutdownDone(m):
		t.Fatal("cancelled worker fabricated completion")
	default:
	}
	f.unblockAll()
	var terminal error
	for range callers {
		select {
		case got := <-results:
			if terminal == nil {
				terminal = got
			}
			if got != terminal {
				t.Fatal("workflow callers did not share one immutable terminal result")
			}
		case <-time.After(8 * time.Second):
			t.Fatal("workflow shared caller did not join")
		}
	}
	if !errors.Is(terminal, cause) || !errors.Is(terminal, ErrWorkflowExecution) || cancelCalls.Load() != 1 {
		t.Fatal("workflow shared outcome lost its cause or repeated cancellation")
	}
	workflowShutdownPublic(t, terminal, cause.Error(), f.root)
}

func TestWorkflowShutdownCapturesCurrentGenerationWithoutHistoricalFailure(t *testing.T) {
	for _, newGeneration := range []bool{false, true} {
		name := "inactive-history"
		if newGeneration {
			name = "new-active-generation"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			oldCause := errors.New("PRIVATE_OLD_WORKFLOW_FAILURE")
			newCause := errors.New("PRIVATE_NEW_WORKFLOW_FAILURE")
			entered, wait := f.barrier()
			var executions atomic.Int32
			m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
				observeWorkflowNoNativeOwners(ctx)
				if executions.Add(1) == 1 {
					return json.RawMessage(`{"old":true}`), oldCause
				}
				close(entered)
				<-ctx.Done()
				wait()
				return json.RawMessage(`{"new":true}`), errors.Join(ctx.Err(), newCause)
			}
			first := f.start()
			workflowShutdownAwait(t, workflowShutdownDone(m), "historical workflow did not complete")
			if m.Snapshot().State != "failed" {
				t.Fatal("historical fixture did not actually fail")
			}
			historical := m.TerminalError(first.ID)
			if !errors.Is(historical, ErrWorkflowExecution) || !errors.Is(historical, oldCause) {
				t.Fatal("current historical getter lost its typed terminal failure")
			}
			var second Job
			if newGeneration {
				second = f.start()
				workflowShutdownAwait(t, entered, "new workflow generation did not execute")
				workflowShutdownTimeout(t, m)
				f.unblockAll()
			}
			terminal := workflowShutdownFinal(t, m)
			if newGeneration {
				if !errors.Is(terminal, newCause) || errors.Is(terminal, oldCause) || !errors.Is(terminal, ErrWorkflowExecution) || second.ID == first.ID || m.Snapshot().ID != second.ID {
					t.Fatal("shutdown captured a stale workflow generation")
				}
			} else if terminal != nil || m.Snapshot().State != "failed" {
				t.Fatal("inactive historical failure contaminated empty shutdown")
			} else if m.TerminalError(first.ID) != historical {
				t.Fatal("empty shutdown erased the current terminal getter outcome")
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if m.Shutdown(canceled) != terminal {
				t.Fatal("completed workflow shutdown lost precedence over caller cancellation")
			}
		})
	}
}

func TestWorkflowShutdownBeforeReservationRejectsLatePolicyAdmission(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	entered, wait := f.barrier()
	var block atomic.Bool
	m.guard = managed.NewGuard(func() (*managed.Authority, error) {
		if block.CompareAndSwap(true, false) {
			close(entered)
			wait()
		}
		return nil, nil
	})
	plan := f.plan()
	block.Store(true)
	var executed atomic.Bool
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) { executed.Store(true); return nil, nil }
	result, startDone := f.startAsync(plan)
	workflowShutdownAwait(t, entered, "workflow did not reach pre-reservation policy admission")
	if err := workflowShutdownFinal(t, m); err != nil {
		t.Fatal("unreserved workflow fabricated an active shutdown outcome")
	}
	f.unblockAll()
	workflowShutdownAwait(t, startDone, "late workflow admission did not return")
	if err := <-result; err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Fatal("closing manager admitted a late workflow reservation")
	}
	if workflowShutdownDone(m) != nil || executed.Load() {
		t.Fatal("late policy admission reserved or executed a workflow")
	}
	if _, err := os.Lstat(m.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected workflow created job storage")
	}
	if workflowShutdownFinal(t, m) != nil {
		t.Fatal("rejected admission changed empty shared shutdown")
	}
}

func TestWorkflowShutdownPreservesPolicyCancellationCause(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	var revoked atomic.Bool
	m.guard = managed.NewGuard(func() (*managed.Authority, error) {
		if revoked.Load() {
			return nil, managed.ErrUnavailable
		}
		return nil, nil
	})
	entered, wait := f.barrier()
	causes := make(chan error, 1)
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		close(entered)
		<-ctx.Done()
		causes <- context.Cause(ctx)
		wait()
		return json.RawMessage(`{"policy":true}`), nil
	}
	f.start()
	workflowShutdownAwait(t, entered, "policy workflow fixture did not execute")
	revoked.Store(true)
	var cause error
	select {
	case cause = <-causes:
	case <-time.After(8 * time.Second):
		t.Fatal("workflow actual authorization did not revoke")
	}
	if !managed.IsPolicyError(cause) {
		t.Fatal("workflow policy fixture lost actual authorization cause")
	}
	workflowShutdownTimeout(t, m)
	f.unblockAll()
	terminal := workflowShutdownFinal(t, m)
	if !errors.Is(terminal, cause) || !errors.Is(terminal, ErrWorkflowExecution) {
		t.Fatal("intentional shutdown cancellation erased an earlier policy cause")
	}
	workflowShutdownPublic(t, terminal, f.root)
	if m.Snapshot().State != "failed" {
		t.Fatal("policy cancellation fabricated successful job state")
	}
}

// This error stands for the result selected by Cmd.Wait in a source-only
// composition test. Its ExitError is synthetic and no process is targeted.
type workflowSyntheticWaitFailure struct{ exit *exec.ExitError }

func (e *workflowSyntheticWaitFailure) Error() string { return "PRIVATE_SYNTHETIC_EXIT_DETAIL" }
func (e *workflowSyntheticWaitFailure) Unwrap() error { return e.exit }

func TestWorkflowShutdownNestedSyntheticCleanupWarningIsActionableAndPrivate(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	nativeCause := errors.New("PRIVATE_SYNTHETIC_NATIVE_CLEANUP")
	cmd := &exec.Cmd{Cancel: func() error { return nativeCause }}
	observation := captureCommandCancellation(cmd)
	if observation.failure() != nil {
		t.Fatal("uncalled cancellation callback fabricated cleanup uncertainty")
	}
	if cmd.Cancel() != nativeCause {
		t.Fatal("cancellation recorder changed synthetic callback return")
	}
	cleanup := observation.failure()
	if !errors.Is(cleanup, ErrWorkflowCleanup) || !errors.Is(cleanup, nativeCause) {
		t.Fatal("cancellation recorder lost synthetic cleanup failure")
	}
	exit := &exec.ExitError{}
	selected := &workflowSyntheticWaitFailure{exit: exit}
	entered, wait := f.barrier()
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		close(entered)
		<-ctx.Done()
		wait()
		return json.RawMessage(`{"synthetic":true}`), fmt.Errorf("PRIVATE_VENDOR_WRAPPER: %w", errors.Join(selected, cleanup))
	}
	f.start()
	workflowShutdownAwait(t, entered, "synthetic cleanup composition did not execute")
	workflowShutdownTimeout(t, m)
	f.unblockAll()
	terminal := workflowShutdownFinal(t, m)
	workflowShutdownPublic(t, terminal, "PRIVATE_", f.root)
	var retained *exec.ExitError
	if !errors.As(terminal, &retained) || retained != exit || !errors.Is(terminal, nativeCause) || !errors.Is(terminal, ErrWorkflowCleanup) || !errors.Is(terminal, ErrWorkflowExecution) {
		t.Fatal("workflow shutdown erased selected exit or recorded cleanup cofailure")
	}
	if strings.Count(terminal.Error(), ErrWorkflowCleanup.Error()) != 1 {
		t.Fatal("nested cleanup warning was hidden or duplicated by execution display")
	}
}

func TestWorkflowCancellationRecorderSourceCallbackContract(t *testing.T) {
	for _, item := range []struct {
		name    string
		failure error
	}{{"success", nil}, {"done-is-still-observed", os.ErrProcessDone}, {"failure", errors.New("PRIVATE_SOURCE_CANCEL_FAILURE")}} {
		t.Run(item.name, func(t *testing.T) {
			var calls atomic.Int32
			cmd := &exec.Cmd{Cancel: func() error { calls.Add(1); return item.failure }}
			observation := captureCommandCancellation(cmd)
			if cmd.Cancel() != item.failure || calls.Load() != 1 {
				t.Fatal("source cancellation callback behavior changed")
			}
			observed := observation.failure()
			if item.failure == nil {
				if observed != nil {
					t.Fatal("successful source cancellation fabricated uncertainty")
				}
			} else if !errors.Is(observed, ErrWorkflowCleanup) || !errors.Is(observed, item.failure) {
				t.Fatal("source cancellation error was erased")
			}
		})
	}
	cmd := &exec.Cmd{}
	observation := captureCommandCancellation(cmd)
	if cmd.Cancel != nil || observation.failure() != nil {
		t.Fatal("nil cancellation callback was replaced")
	}
}

func TestWorkflowShutdownPlainCancellationKeepsTerminalPersistenceCofailure(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	entered, wait := f.barrier()
	storage := errors.New("PRIVATE_CANCEL_PERSIST_FAILURE")
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		close(entered)
		<-ctx.Done()
		wait()
		return json.RawMessage(`{"cancel":true}`), ctx.Err()
	}
	realPersist := m.persist
	m.persist = func(path string, data []byte) error {
		var job Job
		if json.Unmarshal(data, &job) != nil {
			return errors.New("fixture record decode failed")
		}
		if job.State != "running" {
			return storage
		}
		return realPersist(path, data)
	}
	f.start()
	workflowShutdownAwait(t, entered, "cancel persistence fixture did not execute")
	workflowShutdownTimeout(t, m)
	f.unblockAll()
	terminal := workflowShutdownFinal(t, m)
	if !errors.Is(terminal, context.Canceled) || !errors.Is(terminal, ErrWorkflowPersistence) || !errors.Is(terminal, storage) {
		t.Fatal("plain cancellation erased terminal persistence cofailure")
	}
	workflowShutdownPublic(t, terminal, storage.Error(), f.root)
	if job := m.Snapshot(); job.State != "failed" || job.FinishedAt.IsZero() || string(job.Result) != `{"cancel":true}` {
		t.Fatal("cancel persistence cofailure changed job result or completion")
	}
}

func TestWorkflowAdmissionOwnContextCleanupDoesNotInventCancellation(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause := errors.New("PRIVATE_UNCANCELED_ADMISSION_WRITE_FAILURE")
	m.persist = func(string, []byte) error { return cause }
	plan := f.plan()
	if _, err := m.Start(plan.ID); err != cause {
		t.Fatal("uncanceled admission changed its original storage return")
	}
	m.mu.Lock()
	completion := m.completion
	m.mu.Unlock()
	if completion == nil {
		t.Fatal("failed admission lost its reserved generation")
	}
	workflowShutdownAwait(t, completion.done, "failed uncanceled admission did not complete")
	if !errors.Is(completion.err, ErrWorkflowAdmission) || !errors.Is(completion.err, ErrWorkflowPersistence) || !errors.Is(completion.err, cause) || errors.Is(completion.err, context.Canceled) {
		t.Fatal("admission own context cleanup invented an observed cancellation")
	}
	if workflowShutdownFinal(t, m) != nil {
		t.Fatal("inactive failed admission contaminated first shutdown")
	}
}

func TestWorkflowTerminalErrorRequiresExactCompletedCurrentGeneration(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	if err := m.TerminalError(""); err != ErrWorkflowOutcomeUnavailable {
		t.Fatal("empty workflow lookup fabricated an outcome")
	}
	firstEntered, secondEntered := make(chan struct{}), make(chan struct{})
	firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	releaseFirst := func() { firstOnce.Do(func() { close(firstRelease) }) }
	releaseSecond := func() { secondOnce.Do(func() { close(secondRelease) }) }
	f.releases = append(f.releases, releaseFirst, releaseSecond)
	contexts := make(chan context.Context, 2)
	cause := errors.New("PRIVATE_CURRENT_TERMINAL_FAILURE")
	var executions atomic.Int32
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		contexts <- ctx
		if executions.Add(1) == 1 {
			close(firstEntered)
			<-firstRelease
			return json.RawMessage(`{"first":true}`), cause
		}
		close(secondEntered)
		<-secondRelease
		return json.RawMessage(`{"second":true}`), nil
	}
	first := f.start()
	workflowShutdownAwait(t, firstEntered, "terminal lookup fixture did not execute first generation")
	firstContext := <-contexts
	lookup := make(chan error, 1)
	go func() { lookup <- m.TerminalError(first.ID) }()
	select {
	case err := <-lookup:
		if err != ErrWorkflowOutcomeUnavailable {
			t.Fatal("pending current lookup fabricated an outcome")
		}
	case <-time.After(time.Second):
		t.Fatal("terminal lookup waited for running workflow completion")
	}
	wrong := "PRIVATE_WRONG_WORKFLOW_ID"
	if err := m.TerminalError(wrong); err != ErrWorkflowOutcomeUnavailable || err.Error() != ErrWorkflowOutcomeUnavailable.Error() {
		t.Fatal("mismatched terminal lookup exposed input or returned another generation")
	}
	if firstContext.Err() != nil || executions.Load() != 1 || m.Snapshot().State != "running" {
		t.Fatal("terminal lookup canceled or replaced a running workflow")
	}
	firstDone := workflowShutdownDone(m)
	releaseFirst()
	workflowShutdownAwait(t, firstDone, "first lookup generation did not complete")
	original := m.TerminalError(first.ID)
	if !errors.Is(original, ErrWorkflowExecution) || !errors.Is(original, cause) {
		t.Fatal("completed current lookup lost typed phase or original cause")
	}
	workflowShutdownPublic(t, original, cause.Error(), f.root)
	if m.TerminalError(first.ID) != original {
		t.Fatal("completed lookup changed its immutable result")
	}
	// This actual second admission proves lookup did not close manager controls.
	second := f.start()
	workflowShutdownAwait(t, secondEntered, "terminal lookup closed later workflow admission")
	secondContext := <-contexts
	if m.TerminalError(first.ID) != ErrWorkflowOutcomeUnavailable || m.TerminalError(second.ID) != ErrWorkflowOutcomeUnavailable {
		t.Fatal("terminal lookup adopted past or unfinished generation")
	}
	if secondContext.Err() != nil || executions.Load() != 2 {
		t.Fatal("terminal lookup canceled a later workflow")
	}
	secondDone := workflowShutdownDone(m)
	releaseSecond()
	workflowShutdownAwait(t, secondDone, "second lookup generation did not complete")
	if m.TerminalError(second.ID) != nil || m.TerminalError(first.ID) != ErrWorkflowOutcomeUnavailable || m.TerminalError(wrong) != ErrWorkflowOutcomeUnavailable {
		t.Fatal("successful current lookup contaminated generation selection")
	}
	if workflowShutdownFinal(t, m) != nil || m.TerminalError(second.ID) != nil {
		t.Fatal("inactive clean generation changed shutdown or current lookup")
	}
}
