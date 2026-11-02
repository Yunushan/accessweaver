package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryAggregateBoundaryPreservesEveryRecord(t *testing.T) {
	m := New(t.TempDir())
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	original := map[string][]byte{}
	var total int64
	for _, id := range []string{"c", "a", "b"} {
		record, err := json.Marshal(Job{ID: id, State: "succeeded", Result: json.RawMessage(`{"evidence":"retained"}`)})
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(m.root, id+".json")
		if err := os.WriteFile(name, record, 0600); err != nil {
			t.Fatal(err)
		}
		original[name] = record
		total += int64(len(record))
	}
	history, err := m.history(3, total)
	if err != nil || len(history) != 3 {
		t.Fatalf("exact aggregate limit: %d %v", len(history), err)
	}
	for i, id := range []string{"a", "b", "c"} {
		if history[i].ID != id {
			t.Fatal("history filename order changed")
		}
	}
	history, err = m.history(3, total-1)
	if err == nil || history != nil || !strings.Contains(err.Error(), "all records retained") {
		t.Fatalf("partial or oversized listing returned: %d %v", len(history), err)
	}
	for name, want := range original {
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("listing modified retained evidence")
		}
	}
}

func TestHistoryDirectoryLimitIncludesIgnoredEntries(t *testing.T) {
	m := New(t.TempDir())
	if err := os.MkdirAll(filepath.Join(m.root, "work-directory"), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 129; i++ {
		if err := os.WriteFile(filepath.Join(m.root, fmt.Sprintf("ignored-%03d.txt", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if history, err := m.history(130, 1); err != nil || len(history) != 0 {
		t.Fatalf("exact directory limit: %v", err)
	}
	history, err := m.history(129, 1)
	if history != nil || err == nil || !strings.Contains(err.Error(), "directory entries") {
		t.Fatalf("directory overflow: %v", err)
	}
	if files, err := os.ReadDir(m.root); err != nil || len(files) != 130 {
		t.Fatal("ignored retained entries changed")
	}
}

func TestHistoryMalformedRecordsStillConsumeByteBudget(t *testing.T) {
	m := New(t.TempDir())
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"a.json": "{", "b.json": `{"id":"b","state":"succeeded"}`} {
		if err := os.WriteFile(filepath.Join(m.root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	size := int64(len(`{"id":"b","state":"succeeded"}`))
	if history, err := m.history(2, size); err == nil || history != nil {
		t.Fatal("malformed record escaped aggregate byte limit")
	}
	history, err := m.history(2, size+1)
	if err != nil || len(history) != 1 || history[0].ID != "b" {
		t.Fatalf("legacy malformed-record handling changed: %v", err)
	}
}

func TestHistoryKeepsActiveJobAndMarksPreviousControllerInterrupted(t *testing.T) {
	m := New(t.TempDir())
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	m.job = Job{ID: "active", State: "running"}
	for _, id := range []string{"active", "previous"} {
		record, err := json.Marshal(Job{ID: id, State: "running"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m.root, id+".json"), record, 0600); err != nil {
			t.Fatal(err)
		}
	}
	history, err := m.History()
	if err != nil || len(history) != 2 {
		t.Fatalf("history: %v", err)
	}
	if history[0].State != "running" || history[1].State != "interrupted" || !strings.Contains(history[1].Error, "recovery journal") {
		t.Fatal("interrupted outcome lost")
	}
	persisted, err := os.ReadFile(filepath.Join(m.root, "previous.json"))
	if err != nil || bytes.Contains(persisted, []byte("interrupted")) {
		t.Fatal("listing rewrote the retained outcome")
	}
}

func TestHistoryContextHonorsEndedCallerAndPreservesRecords(t *testing.T) {
	m := New(t.TempDir())
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.root, "retained.json")
	original := []byte(`{"id":"retained","state":"succeeded","result":{"evidence":"kept"}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, end := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer end()
	for _, ctx := range []context.Context{canceled, expired} {
		jobs, err := m.HistoryContext(ctx)
		if jobs != nil || !errors.Is(err, ctx.Err()) {
			t.Fatalf("ended history returned records: %v", err)
		}
		if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, original) {
			t.Fatal("cancellation altered history")
		}
		// Cancellation must win even before opening a missing directory.
		missing := New(filepath.Join(t.TempDir(), "not-created"))
		if jobs, err := missing.HistoryContext(ctx); jobs != nil || !errors.Is(err, ctx.Err()) {
			t.Fatal("missing history hid cancellation")
		}
		if _, err := os.Stat(filepath.Dir(missing.root)); !os.IsNotExist(err) {
			t.Fatal("canceled history created state")
		}
	}
	jobs, err := m.HistoryContext(context.Background())
	if err != nil || len(jobs) != 1 || jobs[0].ID != "retained" {
		t.Fatalf("fresh history did not recover: %v", err)
	}
}
