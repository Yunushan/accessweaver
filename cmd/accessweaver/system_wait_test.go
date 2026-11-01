package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

type systemWaitFixture struct {
	mu       sync.Mutex
	job      workflow.Job
	shutdown func(context.Context) error
}

func (f *systemWaitFixture) Snapshot() workflow.Job             { f.mu.Lock(); defer f.mu.Unlock(); return f.job }
func (f *systemWaitFixture) Shutdown(ctx context.Context) error { return f.shutdown(ctx) }
func (f *systemWaitFixture) finish(job workflow.Job)            { f.mu.Lock(); defer f.mu.Unlock(); f.job = job }

func TestSystemCancellationWaitsForRecordedOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entered, release, emitted := make(chan struct{}), make(chan struct{}), make(chan workflow.Job, 1)
	f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: "running"}}
	f.shutdown = func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		f.finish(workflow.Job{ID: "fixture", State: "failed", FinishedAt: time.Now(), Error: "fixture cancellation recorded"})
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- waitSystemWorkflow(ctx, f, time.Second, func(j workflow.Job) error { emitted <- j; return nil })
	}()
	<-entered
	select {
	case <-done:
		t.Fatal("CLI returned before durable recording")
	case <-emitted:
		t.Fatal("CLI emitted a premature outcome")
	default:
	}
	close(release)
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

func TestSystemCancellationTimeoutDoesNotInventTerminalState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &systemWaitFixture{job: workflow.Job{ID: "fixture", State: "running"}, shutdown: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
	var emitted workflow.Job
	err := waitSystemWorkflow(ctx, f, 10*time.Millisecond, func(j workflow.Job) error { emitted = j; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, context.Canceled) {
		t.Fatalf("timeout/cancellation lost: %v", err)
	}
	if emitted.State != "running" || !emitted.FinishedAt.IsZero() {
		t.Fatalf("unconfirmed terminal state emitted: %+v", emitted)
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
