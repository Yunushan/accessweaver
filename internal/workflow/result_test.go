package workflow

import (
	"context"
	"encoding/json"
	"errors"
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
