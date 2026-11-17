package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// Both inputs satisfy the 32 MiB result contract, but formatting/HTML escaping
// used to expand their saved Job beyond the history reader's 64 MiB limit.
func TestCompletedResultsRemainReadableWithoutPersistenceExpansion(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		result json.RawMessage
	}{
		{"deep", json.RawMessage(strings.Repeat("[", 6000) + "0" + strings.Repeat("]", 6000))},
		{"unicode-separators", json.RawMessage(`"` + strings.Repeat("\u2028\u2029", 32<<10) + `"`)},
		{"maximum-result", json.RawMessage(`"` + strings.Repeat("\u2028", (maxResultBytes-2)/3) + `"`)},
		{"html", json.RawMessage(`"` + strings.Repeat("<", 11<<20) + `</script>&` + "\u2028\u2029" + `"`)},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			m := completedPersistenceFixture(t, fixture.result, nil)
			stored, err := os.ReadFile(filepath.Join(m.root, m.Snapshot().ID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(stored) > len(fixture.result)+4096 {
				t.Fatalf("saved result expanded from %d to %d bytes", len(fixture.result), len(stored))
			}
			if !json.Valid(stored) {
				t.Fatal("persisted job is not decodable JSON")
			}
			history, err := m.History()
			if err != nil || len(history) != 1 {
				t.Fatalf("completed result unreadable: %v", err)
			}
			job := history[0]
			if job.State != "succeeded" || job.FinishedAt.IsZero() || job.Error != "" || !bytes.Equal(job.Result, fixture.result) {
				t.Fatal("persisted result or terminal outcome changed")
			}
		})
	}
}

func TestOversizedWorkflowErrorIsBoundedAndOriginalResultRetained(t *testing.T) {
	const limit = 16 << 10
	for _, count := range []int{limit - 1, limit, limit + 1} {
		message := strings.Repeat("x", count)
		m := completedPersistenceFixture(t, json.RawMessage(`{"ok":false}`), errors.New(message))
		job := m.Snapshot()
		if len(job.Error) > limit {
			t.Fatalf("error has %d bytes", len(job.Error))
		}
		if count <= limit && job.Error != message {
			t.Fatal("in-budget error changed")
		}
		if count > limit && !strings.Contains(job.Error, "truncated") {
			t.Fatal("truncation was not reported")
		}
	}
	message := "original cause: " + strings.Repeat("界", 12<<10)
	result, err := json.Marshal(map[string]any{"ok": false, "error": message})
	if err != nil {
		t.Fatal(err)
	}
	m := completedPersistenceFixture(t, result, errors.New(message))
	job := m.Snapshot()
	if len(job.Error) > limit || !utf8.ValidString(job.Error) || !strings.HasPrefix(job.Error, "original cause:") || !strings.Contains(job.Error, "truncated") {
		t.Fatal("bounded Unicode error lost its cause or truncation notice")
	}
	history, err := m.History()
	if err != nil || len(history) != 1 {
		t.Fatalf("failed outcome unreadable: %v", err)
	}
	if history[0].State != "failed" || history[0].FinishedAt.IsZero() || history[0].Error != job.Error {
		t.Fatal("failed outcome not durable")
	}
	var retained struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(history[0].Result, &retained); err != nil || retained.Error != message {
		t.Fatal("original result error was truncated or changed")
	}
}

func completedPersistenceFixture(t *testing.T, result json.RawMessage, runErr error) *Manager {
	t.Helper()
	m := New(t.TempDir())
	m.platform = "windows"
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		return result, runErr
	}
	plan, err := m.Preview(Request{Action: "discover"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Start(plan.ID); err != nil {
		t.Fatal(err)
	}
	// This is a durability/round-trip assertion for inputs up to 32 MiB, not
	// a latency budget. CPU-emulated guest runs can exceed 15 seconds while
	// validating and saving that input. Keep a bounded wait within the package
	// deadline without reducing the input or omitting the read-back assertions.
	select {
	case <-m.done:
	case <-time.After(time.Minute):
		m.Cancel()
		t.Fatal("fixture job did not record its terminal outcome within one minute")
	}
	return m
}

func TestWorkflowPersistenceFailureRemainsVisibleWithOversizedCause(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		if err := os.Rename(m.root, m.root+"-retained"); err != nil {
			return nil, err
		}
		if err := os.WriteFile(m.root, nil, 0600); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"ok":false}`), errors.New(strings.Repeat("large cause ", 16<<10))
	}
	plan, err := m.Preview(Request{Action: "discover"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Start(plan.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.done:
	case <-time.After(15 * time.Second):
		m.Cancel()
		t.Fatal("fixture did not finish")
	}
	job := m.Snapshot()
	if job.State != "failed" || len(job.Error) > 16<<10 || !strings.HasPrefix(job.Error, "persist result:") || !strings.Contains(job.Error, "truncated") {
		t.Fatal("persistence failure hidden by oversized tool error")
	}
}

func TestTerminalPersistenceDoesNotBlockControlOrClaimCompletion(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		name := "success"
		if failWrite {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			m := New(t.TempDir())
			m.platform = "windows"
			m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
				observeWorkflowNoNativeOwners(ctx)
				return json.RawMessage(`{"ok":true}`), nil
			}
			writing, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			realPersist := m.persist
			m.persist = func(path string, data []byte) error {
				var record Job
				if err := json.Unmarshal(data, &record); err != nil {
					return err
				}
				if record.State != "running" {
					close(writing)
					<-release
					if failWrite {
						return errors.New("injected terminal persistence failure")
					}
				}
				return realPersist(path, data)
			}
			plan, err := m.Preview(Request{Action: "discover"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Start(plan.ID); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				unblock()
				select {
				case <-m.done:
				case <-time.After(5 * time.Second):
					t.Error("fixture worker did not exit after releasing persistence")
				}
			})
			select {
			case <-writing:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not reach terminal persistence")
			}
			control := make(chan error, 1)
			go func() {
				if snapshot := m.Snapshot(); snapshot.State != "running" || !snapshot.FinishedAt.IsZero() || len(snapshot.Result) != 0 {
					control <- errors.New("unfinished persistence published a terminal outcome")
					return
				}
				m.Cancel()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				if err := m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
					control <- errors.New("shutdown claimed completion before persistence finished")
					return
				}
				plan, err := m.Preview(Request{Action: "discover"})
				if err != nil {
					control <- err
					return
				}
				if _, err = m.Start(plan.ID); err == nil {
					control <- errors.New("shutdown accepted a new job while persistence was pending")
					return
				}
				control <- nil
			}()
			select {
			case err := <-control:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("terminal persistence blocked control operations")
			}
			select {
			case <-m.done:
				t.Fatal("worker completed before terminal persistence was released")
			default:
			}
			unblock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := m.Shutdown(ctx); failWrite {
				// Worker completion does not make a failed terminal write
				// durable. Preserve that typed failure in the shutdown result.
				if !errors.Is(err, ErrWorkflowPersistence) {
					t.Fatal("terminal persistence failure was erased by shutdown")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			job := m.Snapshot()
			if job.FinishedAt.IsZero() || string(job.Result) != `{"ok":true}` {
				t.Fatal("completed write lost the terminal result")
			}
			if failWrite {
				if job.State != "failed" || !strings.Contains(job.Error, "persist result: injected terminal persistence failure") {
					t.Fatal("failed persistence did not remain visible")
				}
			} else {
				history, err := m.History()
				if job.State != "succeeded" || err != nil || len(history) != 1 || history[0].State != "succeeded" || !bytes.Equal(history[0].Result, job.Result) {
					t.Fatalf("successful shutdown was not durable: %v", err)
				}
			}
		})
	}
}
