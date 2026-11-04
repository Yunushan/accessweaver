package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
)

type recordedImportJournal struct {
	start, head   audit.Checkpoint
	events        []audit.Event
	lines         [][]byte
	calls, failAt int
}

func newRecordedImportJournal(t *testing.T) *recordedImportJournal {
	t.Helper()
	args, files := auditCommandFixture(t)
	_ = args
	data, err := readAuditInput(context.Background(), files[0], audit.MaxCheckpointBytes)
	if err != nil {
		t.Fatal(err)
	}
	start, err := audit.DecodeCheckpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	return &recordedImportJournal{start: start, head: start}
}
func (j *recordedImportJournal) Append(ctx context.Context, e audit.Event) (audit.Checkpoint, error) {
	j.calls++
	if err := ctx.Err(); err != nil {
		return audit.Checkpoint{}, err
	}
	if j.calls == j.failAt {
		return audit.Checkpoint{}, errors.New("PRIVATE_DISK_FAILURE")
	}
	data, next, err := audit.Append(j.head, e)
	if err != nil {
		return audit.Checkpoint{}, err
	}
	j.events = append(j.events, e)
	j.lines = append(j.lines, data)
	j.head = next
	return next, nil
}
func (j *recordedImportJournal) Snapshot(context.Context) ([]byte, audit.Checkpoint, audit.Checkpoint, error) {
	return bytes.Join(j.lines, nil), j.start, j.head, nil
}
func (j *recordedImportJournal) Close() error { return nil }

type importCheckpointWriter struct {
	bytes.Buffer
	calls, failAt int
	short         bool
	cancel        context.CancelFunc
}

func (w *importCheckpointWriter) Write(data []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		if w.short {
			return 0, nil
		}
		return 0, errors.New("PRIVATE_OUTPUT_PATH")
	}
	n, err := w.Buffer.Write(data)
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
	return n, err
}
func TestRecordedImportNeverDispatchesWithoutDurableObservedIntentAndCapacity(t *testing.T) {
	for _, kind := range []string{"intent-write", "intent-output", "short-output", "capacity", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			j := newRecordedImportJournal(t)
			out := &importCheckpointWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "intent-write":
				j.failAt = 1
			case "intent-output":
				out.failAt = 1
			case "short-output":
				out.failAt = 1
				out.short = true
			case "capacity":
				j.head.Sequence = audit.MaxSegmentRecords - 1
			case "canceled":
				cancel()
			}
			dispatched := 0
			started, err := executeRecordedImport(ctx, j, j.start, j.head, out, func(context.Context) importOutcome {
				dispatched++
				return importOutcome{outcome: "completed", mutationStarted: true}
			})
			if err == nil || started || dispatched != 0 || out.Len() != 0 {
				t.Fatal("unrecorded/unobserved operation dispatched", started, dispatched, err)
			}
			if kind == "intent-output" || kind == "short-output" {
				if len(j.events) != 2 || j.events[1].Outcome != "refused" {
					t.Fatal("local observation refusal not preserved")
				}
			}
			if kind == "capacity" && j.calls != 0 {
				t.Fatal("capacity reserved only one event")
			}
		})
	}
}
func TestRecordedImportResultFailureAndOutputFailureRemainUncertain(t *testing.T) {
	for _, kind := range []string{"result-write", "result-output", "operation-error", "panic"} {
		t.Run(kind, func(t *testing.T) {
			j := newRecordedImportJournal(t)
			out := &importCheckpointWriter{}
			if kind == "result-write" {
				j.failAt = 2
			}
			if kind == "result-output" {
				out.failAt = 2
			}
			dispatched := 0
			started, err := executeRecordedImport(context.Background(), j, j.start, j.head, out, func(context.Context) importOutcome {
				dispatched++
				if kind == "panic" {
					panic("PRIVATE_PANIC_PAYLOAD")
				}
				if kind == "operation-error" {
					return importOutcome{outcome: "indeterminate", mutationStarted: true, failure: errors.New("PRIVATE_PROFILE_ERROR")}
				}
				return importOutcome{outcome: "completed", mutationStarted: true}
			})
			if !started || !errors.Is(err, errAuditImportUncertain) || dispatched != 1 {
				t.Fatal("post-mutation failure misreported or retried", started, dispatched, err)
			}
			if bytes.Contains(out.Bytes(), []byte("PRIVATE")) || bytes.Contains([]byte(err.Error()), []byte("PRIVATE")) {
				t.Fatal("private error escaped")
			}
			if kind == "panic" || kind == "operation-error" {
				if j.events[1].Outcome != "indeterminate" {
					t.Fatal("uncertain operation recorded complete")
				}
			}
			if kind == "result-write" && len(j.events) != 1 {
				t.Fatal("failed completion falsely recorded")
			}
		})
	}
}
func TestRecordedImportCancellationAfterIntentOrMutationRecordsActualOutcome(t *testing.T) {
	for _, when := range []string{"before-dispatch", "after-mutation"} {
		t.Run(when, func(t *testing.T) {
			j := newRecordedImportJournal(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := &importCheckpointWriter{}
			if when == "before-dispatch" {
				out.cancel = cancel
			}
			dispatched := 0
			started, err := executeRecordedImport(ctx, j, j.start, j.head, out, func(context.Context) importOutcome {
				dispatched++
				cancel()
				return importOutcome{outcome: "completed", mutationStarted: true}
			})
			if len(j.events) != 2 || j.events[0].OperationID != j.events[1].OperationID {
				t.Fatal("correlated outcome missing")
			}
			if when == "before-dispatch" {
				if started || dispatched != 0 || !errors.Is(err, errAuditImportRefused) || j.events[1].Outcome != "canceled" {
					t.Fatal("pre-dispatch cancellation ran import", err)
				}
			} else if !started || dispatched != 1 || err != nil || j.events[1].Outcome != "completed" {
				t.Fatal("actual mutation completion abandoned after cancellation", err)
			}
			checkpoints := bytes.Split(bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), []byte{'\n'})
			if len(checkpoints) != 2 {
				t.Fatal("missing canonical checkpoint observations")
			}
			for _, line := range checkpoints {
				if _, err := audit.DecodeCheckpoint(append(line, '\n')); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(bytes.Join(j.lines, nil)), j.start, j.head); err != nil {
				t.Fatal("recorded operation chain differs", err)
			}
		})
	}
}
func TestAuditRecordingArgumentsRefuseAmbiguityAndUnsupportedTargets(t *testing.T) {
	for _, args := range [][]string{nil, {"import"}, {"import", "--directory", "PRIVATE", "--from", "x", "--to", "y", "--to", "z"}, {"import", "--directory", "PRIVATE", "--from", "x", "--to", "y", "--token", "PRIVATE"}} {
		if _, err := auditPaths(args, "import", "--directory", "--from", "--to", "--profile"); err == nil || bytes.Contains([]byte(err.Error()), []byte("PRIVATE")) {
			t.Fatal("ambiguous recording options admitted or disclosed", err)
		}
	}
	if !audit.LocalRecordingSupported() {
		if err := auditInitializeCommand([]string{"initialize", "--directory", "PRIVATE_MISSING"}, io.Discard); !errors.Is(err, audit.ErrLocalStorageUnsupported) {
			t.Fatal(err)
		}
		if err := auditImportCommand([]string{"import", "--directory", "PRIVATE_MISSING", "--from", "PRIVATE_MISSING", "--to", "PRIVATE_MISSING", "--profile", "PRIVATE_MISSING"}, io.Discard); !errors.Is(err, audit.ErrLocalStorageUnsupported) {
			t.Fatal(err)
		}
	}
}
