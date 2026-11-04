package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
)

type recordedExportWriterFunc func([]byte) (int, error)

func (f recordedExportWriterFunc) Write(data []byte) (int, error) { return f(data) }

func recordedExportFixture(t *testing.T) (*recordedImportJournal, audit.Checkpoint, []byte) {
	t.Helper()
	j := newRecordedImportJournal(t)
	for _, outcome := range []string{"intent", "completed"} {
		if _, err := j.Append(context.Background(), audit.Event{OccurredAt: time.Now().UTC(), OperationID: strings.Repeat("b", 32), Action: "profile.write", Outcome: outcome}); err != nil {
			t.Fatal(err)
		}
	}
	j.calls = 0
	data, _, head, err := j.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return j, head, data
}

func TestRecordedExportOptionsRequireExactExplicitConsent(t *testing.T) {
	good := []string{"export-recorded", "--directory", "PRIVATE_DIRECTORY", "--from", "PRIVATE_FROM", "--to", "PRIVATE_TO", "--consent", "metadata-only"}
	if _, err := recordedExportPaths(good); err != nil {
		t.Fatal(err)
	}
	bad := [][]string{nil, {"export-recorded"}, good[:len(good)-2], append(append([]string{}, good...), "--root", "PRIVATE_ROOT"), append(append([]string{}, good...), "--to", "PRIVATE_DUPLICATE")}
	for _, consent := range []string{"Metadata-only", "PRIVATE_CONSENT", ""} {
		args := append([]string{}, good...)
		args[len(args)-1] = consent
		bad = append(bad, args)
	}
	for _, args := range bad {
		if err := auditRecordedExportCommand(args, io.Discard, io.Discard); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("unsafe consent/options", err)
		}
	}
	if !audit.LocalRecordingSupported() {
		if err := auditRecordedExportCommand(good, io.Discard, io.Discard); !errors.Is(err, audit.ErrLocalStorageUnsupported) {
			t.Fatal("unsupported native input was accessed", err)
		}
	}
}

func TestRecordedExportRequiresVerifiedSnapshotAndDurableObservedIntent(t *testing.T) {
	for _, mode := range []string{"intent-write", "intent-output", "short-observation", "pre-canceled", "cancel-before-write", "invalid-snapshot", "stale-head", "nil-events", "nil-observations"} {
		t.Run(mode, func(t *testing.T) {
			j, head, _ := recordedExportFixture(t)
			observations := &importCheckpointWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "intent-write":
				j.failAt = 1
			case "intent-output":
				observations.failAt = 1
			case "short-observation":
				observations.failAt = 1
				observations.short = true
			case "pre-canceled":
				cancel()
			case "cancel-before-write":
				observations.cancel = cancel
			case "invalid-snapshot":
				j.lines[0] = []byte("PRIVATE_MALFORMED\n")
			case "stale-head":
				head.SHA256 = strings.Repeat("f", 64)
			}
			calls := 0
			var events io.Writer = recordedExportWriterFunc(func([]byte) (int, error) { calls++; return 0, errors.New("PRIVATE_UNEXPECTED_EXPORT") })
			var checkpoints io.Writer = observations
			if mode == "nil-events" {
				events = nil
			}
			if mode == "nil-observations" {
				checkpoints = nil
			}
			err := executeRecordedExport(ctx, j, j.start, head, events, checkpoints)
			if err == nil || calls != 0 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unverified/unrecorded export dispatched", calls, err)
			}
			if mode == "intent-output" || mode == "short-observation" {
				if len(j.events) != 4 || j.events[3].Outcome != "refused" {
					t.Fatal("unobserved intent refusal lost")
				}
			}
			if mode == "cancel-before-write" {
				if len(j.events) != 4 || j.events[3].Outcome != "canceled" || !errors.Is(err, context.Canceled) {
					t.Fatal("pre-dispatch cancellation lost", err)
				}
			}
		})
	}
}

func TestRecordedExportReservesBothAccessRecordsAtCapacity(t *testing.T) {
	j := newRecordedImportJournal(t)
	for i := 0; i < audit.MaxSegmentRecords-1; i++ {
		if _, err := j.Append(context.Background(), audit.Event{OccurredAt: time.Now().UTC(), OperationID: strings.Repeat("a", 32), Action: "profile.write", Outcome: "intent"}); err != nil {
			t.Fatal(err)
		}
	}
	j.calls = 0
	events, observations := &bytes.Buffer{}, &bytes.Buffer{}
	if err := executeRecordedExport(context.Background(), j, j.start, j.head, events, observations); !errors.Is(err, audit.ErrRecorderUnavailable) || j.calls != 0 || events.Len() != 0 || observations.Len() != 0 {
		t.Fatal("export admitted without capacity for both access records", err)
	}
}

func TestRecordedExportWritesOnlyPriorSnapshotAndAccurateSynchronousOutcome(t *testing.T) {
	for _, mode := range []string{"complete", "cancel-during-write", "zero-error", "partial-error", "short-nil-error", "invalid-count", "panic", "result-write", "result-observation"} {
		t.Run(mode, func(t *testing.T) {
			j, head, snapshot := recordedExportFixture(t)
			observations := &importCheckpointWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "result-write" {
				j.failAt = 2
			}
			if mode == "result-observation" {
				observations.failAt = 2
			}
			calls := 0
			var received []byte
			out := recordedExportWriterFunc(func(data []byte) (int, error) {
				calls++
				if len(j.events) != 3 || j.events[2].Action != "audit.export" || j.events[2].Outcome != "intent" || observations.calls != 1 {
					t.Error("bytes preceded durable observed access intent")
				}
				if !bytes.Equal(data, snapshot) {
					t.Error("export included its own access or wrong segment")
				}
				switch mode {
				case "zero-error":
					return 0, errors.New("PRIVATE_WRITER_ERROR")
				case "partial-error":
					received = append([]byte{}, data[:len(data)/2]...)
					return len(received), errors.New("PRIVATE_PARTIAL_OUTPUT")
				case "short-nil-error":
					return len(data) - 1, nil
				case "invalid-count":
					return len(data) + 1, nil
				case "panic":
					panic("PRIVATE_WRITER_PANIC")
				case "cancel-during-write":
					cancel()
				}
				received = append([]byte{}, data...)
				return len(data), nil
			})
			err := executeRecordedExport(ctx, j, j.start, head, out, observations)
			success := mode == "complete" || mode == "cancel-during-write"
			if (err == nil) != success || calls != 1 {
				t.Fatal("write outcome differs", calls, err)
			}
			if !success && (!errors.Is(err, audit.ErrRecordedUncertain) || strings.Contains(err.Error(), "PRIVATE")) {
				t.Fatal("output uncertainty/private error mishandled", err)
			}
			if mode == "result-write" {
				if len(j.events) != 3 {
					t.Fatal("unknown outcome was invented")
				}
				return
			}
			if len(j.events) != 4 || j.events[2].OperationID != j.events[3].OperationID {
				t.Fatal("access pairing differs")
			}
			expected := "indeterminate"
			if success || mode == "result-observation" {
				expected = "completed"
			}
			if j.events[3].Outcome != expected {
				t.Fatal("inaccurate export completion", j.events[3])
			}
			if success {
				if !bytes.Equal(received, snapshot) {
					t.Fatal("canonical prior segment changed")
				}
				if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(received), j.start, head); err != nil {
					t.Fatal(err)
				}
			}
			if bytes.Contains(observations.Bytes(), []byte("PRIVATE")) || bytes.Contains(bytes.Join(j.lines, nil), []byte("PRIVATE")) {
				t.Fatal("writer error escaped audit metadata")
			}
		})
	}
}
