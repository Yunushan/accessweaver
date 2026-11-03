package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestPendingAdmissionPersistenceKeepsControlsAvailable(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		name := "durable-running-record"
		if failWrite {
			name = "failed-running-record"
		}
		t.Run(name, func(t *testing.T) {
			m := New(t.TempDir())
			m.platform = "windows"
			writing, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			executed := make(chan struct{}, 1)
			m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
				executed <- struct{}{}
				return json.RawMessage(`{"ok":true}`), nil
			}
			m.persist = func(path string, data []byte) error {
				var job Job
				if err := json.Unmarshal(data, &job); err != nil {
					return err
				}
				if job.State == "running" {
					close(writing)
					<-release
					if failWrite {
						return errors.New("injected initial persistence failure")
					}
				}
				return profile.AtomicWrite(path, data)
			}
			plan, err := m.Preview(Request{Action: "discover"})
			if err != nil {
				t.Fatal(err)
			}
			started := make(chan error, 1)
			controlled := make(chan error, 1)
			go func() { _, err := m.Start(plan.ID); started <- err }()
			t.Cleanup(func() {
				unblock()
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Error("admission did not return after releasing storage")
				}
				select {
				case <-controlled:
				case <-time.After(5 * time.Second):
					t.Error("control probe did not return after releasing storage")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := m.Shutdown(ctx); err != nil {
					t.Error(err)
				}
			})
			select {
			case <-writing:
			case <-time.After(5 * time.Second):
				t.Fatal("initial write not reached")
			}
			go func() {
				snapshot := m.Snapshot()
				if snapshot.State != "running" || !snapshot.FinishedAt.IsZero() || len(snapshot.Result) != 0 {
					controlled <- errors.New("pending admission published a terminal result")
					return
				}
				if m.Summary().State != "running" {
					controlled <- errors.New("pending admission missing from summary")
					return
				}
				m.Cancel()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				if err := m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
					controlled <- errors.New("shutdown claimed completion before initial persistence returned")
					return
				}
				controlled <- nil
			}()
			select {
			case err := <-controlled:
				controlled <- err // Leave a completion for cleanup on every path.
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("initial persistence blocked workflow control operations")
			}
			select {
			case <-executed:
				t.Fatal("workflow executed before initial durability")
			default:
			}
			unblock()
			var startErr error
			select {
			case startErr = <-started:
				started <- startErr
			case <-time.After(5 * time.Second):
				t.Fatal("admission did not finish")
			}
			if failWrite && (startErr == nil || !strings.Contains(startErr.Error(), "injected initial persistence failure")) {
				t.Fatal("initial persistence error lost")
			}
			if !failWrite && startErr != nil {
				t.Fatal(startErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := m.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-executed:
				t.Fatal("cancelled admission executed a workflow")
			default:
			}
			job := m.Snapshot()
			if job.State != "failed" || job.FinishedAt.IsZero() || job.Error == "" {
				t.Fatal("failed admission outcome missing")
			}
			if failWrite {
				if !strings.Contains(job.Error, "injected initial persistence failure") {
					t.Fatal("initial write failure not visible")
				}
			} else {
				if !strings.Contains(job.Error, "context canceled") {
					t.Fatal("admission cancellation not visible")
				}
				history, err := m.History()
				if err != nil || len(history) != 1 || history[0].State != "failed" || history[0].Error != job.Error {
					t.Fatalf("cancelled admission not durable: %v", err)
				}
			}
			if _, err := m.Start(plan.ID); err == nil {
				t.Fatal("shutdown accepted another start")
			}
		})
	}
}
