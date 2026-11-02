package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoundedWorkflowRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	want := `{"ok":true}`
	b, err := readWorkflowFile(path, int64(len(want)))
	if err != nil || string(b) != want {
		t.Fatalf("exact limit: %q %v", b, err)
	}
	if b, err = readWorkflowFile(path, int64(len(want)-1)); err == nil || b != nil {
		t.Fatal("oversized file retained")
	}
	// This exercises the streaming guard, independent of the initial size check.
	if b, err = readBounded(strings.NewReader(want), int64(len(want)-1)); err == nil || b != nil {
		t.Fatal("stream growing beyond limit retained")
	}
	if _, err = readWorkflowFile(filepath.Dir(path), 100); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err = readWorkflowFile(path+"-missing", 100); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
}

func TestWorkflowHistoryRejectsOversizedRecord(t *testing.T) {
	m := New(t.TempDir())
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(m.root, "old-job.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(maxHistoryRecordBytes + 1)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("fixture: %v %v", err, closeErr)
	}
	if _, err = m.History(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized history read: %v", err)
	}
}

func TestRejectedResultsRemainDurableAndSerializable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  json.RawMessage
		message string
	}{
		{"malformed", json.RawMessage(`{"ok":`), "invalid result JSON"},
		{"oversized", json.RawMessage(`"` + strings.Repeat("x", maxResultBytes) + `"`), "exceeds 32 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(t.TempDir())
			m.platform = "windows"
			m.requireAdmin = func() error { return nil }
			toolErr := errors.New("fixture tool failed")
			m.execute = func(context.Context, string, Request) (json.RawMessage, error) { return tc.result, toolErr }
			p, err := m.Preview(Request{Action: "discover"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Start(p.ID); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			// Wait for durable recording, rather than just the in-memory state.
			select {
			case <-m.done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			j := m.Snapshot()
			if j.State != "failed" || len(j.Result) != 0 || !strings.Contains(j.Error, tc.message) || !strings.Contains(j.Error, toolErr.Error()) {
				t.Fatalf("outcome: %+v", j)
			}
			if _, err = json.Marshal(j); err != nil {
				t.Fatalf("snapshot cannot be sent to API: %v", err)
			}
			history, err := m.History()
			if err != nil || len(history) != 1 || history[0].State != "failed" || history[0].FinishedAt.IsZero() || len(history[0].Result) != 0 {
				t.Fatalf("durable outcome: %+v %v", history, err)
			}
		})
	}
}

func TestSupportSummaryDoesNotExposeResultOrJobIdentity(t *testing.T) {
	m := New(t.TempDir())
	m.job = Job{ID: "PRIVATE_SUPPORT_FIXTURE", Action: "dns", State: "failed", Error: "PRIVATE_SUPPORT_FIXTURE", Result: json.RawMessage(`{"key":"PRIVATE_SUPPORT_FIXTURE"}`)}
	b, err := json.Marshal(m.Summary())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PRIVATE_SUPPORT_FIXTURE") {
		t.Fatal("private workflow data entered support summary")
	}
	if !m.Summary().ErrorPresent || !m.Summary().ResultPresent {
		t.Fatal("summary lost status information")
	}
}

func TestCanceledWorkflowExecutionDoesNotCreateState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "must-not-create")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := execute(ctx, directory, Request{Action: "discover"})
	if !errors.Is(err, context.Canceled) || len(result) != 0 {
		t.Fatalf("pre-canceled execution: %v", err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("pre-canceled execution created workflow state")
	}
}

type cancelingWorkflowReader struct {
	reader                 io.Reader
	cancel                 context.CancelFunc
	after, read, largest   int
	canceled               bool
	readsAfterCancellation int
}

func (r *cancelingWorkflowReader) Read(p []byte) (int, error) {
	if r.canceled {
		r.readsAfterCancellation++
	}
	if len(p) > r.largest {
		r.largest = len(p)
	}
	n, err := r.reader.Read(p)
	r.read += n
	if r.read >= r.after {
		r.cancel()
		r.canceled = true
	}
	return n, err
}

func TestBoundedWorkflowReadStopsOnCancellationWithoutPartialData(t *testing.T) {
	for _, after := range []int{0, 64 << 10} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &cancelingWorkflowReader{reader: strings.NewReader(strings.Repeat("x", 128<<10)), cancel: cancel, after: after}
		if after == 0 {
			cancel()
		}
		data, err := readBoundedContext(ctx, reader, 128<<10)
		cancel()
		if data != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled read retained partial data: %v", err)
		}
		if reader.read > after+(32<<10) || reader.largest > 32<<10 || reader.readsAfterCancellation != 0 {
			t.Fatalf("read beyond cancellation checkpoint: %+v", reader)
		}
		if after == 0 && reader.read != 0 {
			t.Fatal("pre-canceled reader was consumed")
		}
	}
	// Cancellation after a successful final read must also discard the result.
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelingWorkflowReader{reader: strings.NewReader("small"), cancel: cancel, after: 5}
	if data, err := readBoundedContext(ctx, reader, 5); data != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("final-read cancellation returned partial success")
	}
	cancel()
	data, err := readBoundedContext(context.Background(), strings.NewReader("small"), 5)
	if err != nil || string(data) != "small" {
		t.Fatalf("fresh reader did not recover: %v", err)
	}
}
