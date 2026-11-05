package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

type systemWaitFixture struct {
	mu       sync.Mutex
	job      workflow.Job
	shutdown func(context.Context) error
	terminal func(string) error
}

func (f *systemWaitFixture) Snapshot() workflow.Job             { f.mu.Lock(); defer f.mu.Unlock(); return f.job }
func (f *systemWaitFixture) Shutdown(ctx context.Context) error { return f.shutdown(ctx) }
func (f *systemWaitFixture) TerminalError(id string) error {
	if f.terminal != nil {
		return f.terminal(id)
	}
	return nil
}
func (f *systemWaitFixture) finish(job workflow.Job) { f.mu.Lock(); defer f.mu.Unlock(); f.job = job }

func TestSystemCancellationWaitsForRecordedOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entered, release, emitted := make(chan struct{}), make(chan struct{}), make(chan workflow.Job, 1)
	f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: "running"}}
	var enteredOnce sync.Once
	f.shutdown = func(ctx context.Context) error {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		f.finish(workflow.Job{ID: "fixture", State: "failed", FinishedAt: time.Now(), Error: "fixture cancellation recorded"})
		return nil
	}
	done := make(chan error, 1)
	returned := make(chan struct{})
	unblock := cleanupSystemWait(t, release, returned)
	go func() {
		defer close(returned)
		done <- waitSystemWorkflow(ctx, f, time.Second, func(j workflow.Job) error { emitted <- j; return nil })
	}()
	awaitSystemWait(t, entered, "workflow cancellation wait did not start")
	select {
	case <-done:
		t.Fatal("CLI returned before durable recording")
	case <-emitted:
		t.Fatal("CLI emitted a premature outcome")
	default:
	}
	unblock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CLI did not finish")
	}
	j := <-emitted
	if j.State != "failed" || j.FinishedAt.IsZero() || j.Error != "fixture cancellation recorded" {
		t.Fatalf("incorrect outcome: %+v", j)
	}
}

func TestSystemCancellationDiagnosticTimeoutRetainsActualWorkflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: "running"}}
	release, background, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := cleanupSystemWait(t, release, returned)
	var calls atomic.Int32
	f.shutdown = func(wait context.Context) error {
		if calls.Add(1) == 1 {
			<-wait.Done()
			return wait.Err()
		}
		if wait.Done() != nil || wait.Err() != nil {
			t.Error("workflow final join retained diagnostic deadline")
		}
		close(background)
		<-release
		f.finish(workflow.Job{ID: "fixture", State: "failed", FinishedAt: time.Now(), Error: "PRIVATE_JOB_DISPLAY"})
		return workflow.ErrWorkflowPersistence
	}
	feedback := foregroundFeedbackReceipt{written: make(chan string, 1)}
	emitted, finished := make(chan workflow.Job, 1), make(chan error, 1)
	go func() {
		defer close(returned)
		finished <- waitSystemWorkflowWithFeedback(ctx, f, 10*time.Millisecond, func(job workflow.Job) error { emitted <- job; return nil }, feedback)
	}()
	awaitSystemWait(t, background, "workflow was abandoned after diagnostic timeout")
	select {
	case text := <-feedback.written:
		if !strings.Contains(text, "keep this command active") || strings.Contains(text, "PRIVATE") {
			t.Error("workflow pending feedback missing or private")
		}
	default:
		t.Error("workflow pending feedback missing")
	}
	select {
	case err := <-finished:
		t.Fatal("workflow caller returned before actual completion", err)
	case <-emitted:
		t.Fatal("workflow emitted a running status as final")
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, workflow.ErrWorkflowPersistence) || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "PRIVATE_JOB_DISPLAY") {
			t.Fatal("workflow terminal failure lost or raw status substituted", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("workflow final completion not observed")
	}
	job := <-emitted
	if job.State != "failed" || job.FinishedAt.IsZero() || job.Error != "PRIVATE_JOB_DISPLAY" || calls.Load() != 2 {
		t.Fatal("workflow actual final snapshot or shared join changed")
	}
}

type failedSystemShutdownNotice struct {
	entered chan struct{}
	short   bool
}

func (w failedSystemShutdownNotice) Write(data []byte) (int, error) {
	close(w.entered)
	if w.short {
		return len(data) - 1, nil
	}
	return 0, errors.New("PRIVATE_NOTICE_ERROR")
}

func TestSystemCancellationNoticeFailureStillDrainsWorkflow(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-error", true: "short-write"}[short], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: "running"}}
			release, background, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			unblock := cleanupSystemWait(t, release, returned)
			var calls atomic.Int32
			f.shutdown = func(wait context.Context) error {
				if calls.Add(1) == 1 {
					<-wait.Done()
					return wait.Err()
				}
				close(background)
				<-release
				f.finish(workflow.Job{ID: "fixture", State: "succeeded", FinishedAt: time.Now()})
				return nil
			}
			feedback := failedSystemShutdownNotice{entered: make(chan struct{}), short: short}
			emitted, finished := make(chan workflow.Job, 1), make(chan error, 1)
			go func() {
				defer close(returned)
				finished <- cancelSystemWorkflowWithFeedback(ctx, f, 10*time.Millisecond, func(job workflow.Job) error { emitted <- job; return nil }, feedback)
			}()
			awaitSystemWait(t, feedback.entered, "workflow waiting notice not attempted")
			awaitSystemWait(t, background, "failed waiting notice abandoned owned workflow")
			select {
			case err := <-finished:
				t.Fatal("failed waiting notice returned before workflow completion", err)
			case <-emitted:
				t.Fatal("failed notice caused premature workflow snapshot")
			case <-time.After(25 * time.Millisecond):
			}
			unblock()
			select {
			case err := <-finished:
				if !errors.Is(err, errSystemShutdownOutput) || !errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "PRIVATE_NOTICE_ERROR") {
					t.Fatal("workflow notice error lost or exposed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("failed workflow notice did not drain")
			}
			if job := <-emitted; job.State != "succeeded" || job.FinishedAt.IsZero() || calls.Load() != 2 {
				t.Fatal("actual completed workflow status lost after notice failure")
			}
		})
	}
}

func TestSystemCancellationCompletedFailureDoesNotWarnOrUseRawDisplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: "failed", FinishedAt: time.Now(), Error: "PRIVATE_STATUS_DISPLAY"}, shutdown: func(context.Context) error { return workflow.ErrWorkflowExecution }}
	feedback := &bytes.Buffer{}
	err := cancelSystemWorkflowWithFeedback(ctx, f, time.Second, func(workflow.Job) error { return nil }, feedback)
	if !errors.Is(err, workflow.ErrWorkflowExecution) || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "PRIVATE_STATUS_DISPLAY") || feedback.Len() != 0 {
		t.Fatal("completed workflow error was replaced with raw display", err)
	}
}

func cleanupSystemWait(t *testing.T, release chan struct{}, returned <-chan struct{}) func() {
	t.Helper()
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Error("workflow CLI fixture did not drain")
		}
	})
	return unblock
}
func awaitSystemWait(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}

func TestSystemTerminalOutcomesAndOutputErrors(t *testing.T) {
	failed, writeErr := errors.New("fixture tool failure"), errors.New("fixture output failure")
	for _, tc := range []struct {
		state, message string
		outputErr      error
	}{
		{"succeeded", "", nil}, {"failed", failed.Error(), nil}, {"failed", failed.Error(), writeErr},
	} {
		f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: tc.state, Error: tc.message}, shutdown: func(context.Context) error { t.Fatal("completed job cancelled"); return nil }}
		called := 0
		err := waitSystemWorkflow(context.Background(), f, time.Second, func(j workflow.Job) error {
			called++
			if j.ID != "fixture" {
				t.Fatal("wrong job emitted")
			}
			return tc.outputErr
		})
		if called != 1 {
			t.Fatalf("output calls: %d", called)
		}
		if tc.state == "succeeded" && err != nil {
			t.Fatal(err)
		}
		if tc.state == "failed" && (err == nil || !strings.Contains(err.Error(), failed.Error())) {
			t.Fatalf("job failure lost: %v", err)
		}
		if tc.outputErr != nil && !errors.Is(err, writeErr) {
			t.Fatalf("output failure lost: %v", err)
		}
	}
}

func TestSystemCompletedWorkflowRetainsTypedFailureWithoutParsingDisplay(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal-completion", true: "completion-before-cancel-join"}[cancelled], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelled {
				cancel()
			}
			f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: "failed", FinishedAt: time.Now(), Error: "PRIVATE_WORKFLOW_JOB_DISPLAY"}, shutdown: func(context.Context) error { return nil }}
			f.terminal = func(id string) error {
				if id != "fixture" {
					t.Error("terminal outcome lookup used another workflow")
				}
				return workflow.ErrWorkflowCleanup
			}
			var emitted workflow.Job
			err := waitSystemWorkflowWithFeedback(ctx, f, time.Second, func(job workflow.Job) error { emitted = job; return nil }, &bytes.Buffer{})
			if !errors.Is(err, workflow.ErrWorkflowCleanup) || strings.Contains(err.Error(), "PRIVATE_WORKFLOW_JOB_DISPLAY") || emitted.Error != "PRIVATE_WORKFLOW_JOB_DISPLAY" {
				t.Fatal("typed workflow cleanup warning lost or display reparsed", err)
			}
		})
	}
}
