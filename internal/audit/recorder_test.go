package audit

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recorderJournal struct {
	start, head           Checkpoint
	lines                 []byte
	events                []Event
	calls, failAt, closes int
}

func (j *recorderJournal) Append(ctx context.Context, e Event) (Checkpoint, error) {
	j.calls++
	if ctx.Err() != nil {
		return Checkpoint{}, ctx.Err()
	}
	if j.calls == j.failAt {
		return Checkpoint{}, errors.New("PRIVATE_STORAGE")
	}
	data, next, err := Append(j.head, e)
	if err != nil {
		return Checkpoint{}, err
	}
	j.lines = append(j.lines, data...)
	j.events = append(j.events, e)
	j.head = next
	return next, nil
}
func (j *recorderJournal) Snapshot(context.Context) ([]byte, Checkpoint, Checkpoint, error) {
	return bytes.Clone(j.lines), j.start, j.head, nil
}
func (j *recorderJournal) Close() error { j.closes++; return nil }
func recorderFixture(t *testing.T) (*recorderJournal, *Recorder, *bytes.Buffer) {
	t.Helper()
	start, err := NewStream(fixtureProducer())
	if err != nil {
		t.Fatal(err)
	}
	j := &recorderJournal{start: start, head: start}
	out := &bytes.Buffer{}
	r, err := NewRecorder(context.Background(), j, start, start, out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return j, r, out
}

type recorderWriter struct {
	failAt, calls int
	short         bool
	cancel        context.CancelFunc
	bytes.Buffer
}

func (w *recorderWriter) Write(data []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		if w.short {
			return 0, nil
		}
		return 0, errors.New("PRIVATE_OUTPUT")
	}
	n, err := w.Buffer.Write(data)
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
	return n, err
}
func TestRecorderRequiredIntentAndStickyOutputStorageFailures(t *testing.T) {
	for _, kind := range []string{"intent", "output", "short", "result", "result-output", "capacity", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			j, r, _ := recorderFixture(t)
			w := &recorderWriter{}
			r.output = w
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "intent":
				j.failAt = 1
			case "output":
				w.failAt = 1
			case "short":
				w.failAt = 1
				w.short = true
			case "result":
				j.failAt = 2
			case "result-output":
				w.failAt = 2
			case "capacity":
				r.head.Sequence = MaxSegmentRecords - 1
			case "canceled":
				cancel()
			}
			dispatched := 0
			op := func(context.Context) OperationResult {
				dispatched++
				if len(j.events) != 1 || j.events[0].Outcome != "intent" || w.calls != 1 {
					t.Error("dispatch preceded durable observed intent")
				}
				return OperationResult{Outcome: "completed"}
			}
			err := r.Execute(ctx, "profile.write", op)
			if err == nil || bytes.Contains([]byte(err.Error()), []byte("PRIVATE")) {
				t.Fatal("unsafe error", err)
			}
			want := 0
			if kind == "result" || kind == "result-output" {
				want = 1
			}
			if dispatched != want {
				t.Fatal("wrong dispatch count", dispatched)
			}
			if kind != "canceled" && kind != "capacity" {
				before := j.calls
				if r.Execute(context.Background(), "profile.write", op) == nil || j.calls != before || dispatched != want {
					t.Fatal("uncertain recorder was reused")
				}
			}
		})
	}
}
func TestRecorderActualChainResultAfterCancellationAndPanic(t *testing.T) {
	for _, kind := range []string{"success", "cancel-before", "cancel-after", "panic", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			j, r, _ := recorderFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel-before" {
				r.output = &recorderWriter{cancel: cancel}
			}
			called := 0
			err := r.Execute(ctx, "profile.delete", func(context.Context) OperationResult {
				called++
				switch kind {
				case "panic":
					panic("PRIVATE_PANIC")
				case "invalid":
					return OperationResult{Outcome: "accepted"}
				case "cancel-after":
					cancel()
				}
				return OperationResult{Outcome: "completed"}
			})
			want := "completed"
			if kind == "cancel-before" {
				want = "canceled"
				if called != 0 {
					t.Fatal("canceled work dispatched")
				}
			}
			if kind == "panic" || kind == "invalid" {
				want = "indeterminate"
			}
			if len(j.events) != 2 || j.events[1].Outcome != want || j.events[0].OperationID != j.events[1].OperationID {
				t.Fatal("wrong intent/result", j.events)
			}
			if (want == "completed") != (err == nil) {
				t.Fatal("wrong operation result", err)
			}
			if _, err := VerifySegment(context.Background(), bytes.NewReader(j.lines), j.start, j.head); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRecorderSerializedCancelableAdmissionAndCloseWait(t *testing.T) {
	j, r, _ := recorderFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Execute(context.Background(), "profile.write", func(context.Context) OperationResult {
			close(entered)
			<-release
			return OperationResult{Outcome: "completed"}
		})
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r.Execute(ctx, "profile.write", func(context.Context) OperationResult {
		t.Error("queued canceled work dispatched")
		return OperationResult{Outcome: "completed"}
	}) == nil {
		t.Fatal("canceled admitted")
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case <-closed:
		t.Fatal("closed journal during mutation")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if j.closes != 1 || r.Execute(context.Background(), "profile.write", nil) == nil {
		t.Fatal("closed recorder usable")
	}
}
func TestRecorderConcurrentCompletePairsAndBoundedCapacity(t *testing.T) {
	j, r, _ := recorderFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Execute(context.Background(), "profile.write", func(context.Context) OperationResult { return OperationResult{Outcome: "completed"} }); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(j.events) != 32 {
		t.Fatal("lost records")
	}
	for i := 0; i < len(j.events); i += 2 {
		if j.events[i].OperationID != j.events[i+1].OperationID || j.events[i].Outcome != "intent" || j.events[i+1].Outcome != "completed" {
			t.Fatal("interleaved operation pairs")
		}
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(j.lines), j.start, j.head); err != nil {
		t.Fatal(err)
	}
}

func TestRecorderProfileIntentAuthorityIsActionBoundAndRevoked(t *testing.T) {
	for _, action := range []string{"profile.write", "profile.import", "profile.delete"} {
		t.Run(action, func(t *testing.T) {
			_, r, _ := recorderFixture(t)
			var retained context.Context
			forged := context.WithValue(context.Background(), "profileIntent", true)
			if ProfileIntentActive(forged, "write") {
				t.Fatal("request-like context forged an intent")
			}
			err := r.Execute(context.Background(), action, func(ctx context.Context) OperationResult {
				retained = ctx
				if ProfileIntentActive(ctx, "write") != (action != "profile.delete") || ProfileIntentActive(ctx, "delete") != (action == "profile.delete") || ProfileIntentActive(ctx, "bulk") {
					t.Fatal("intent action binding differs")
				}
				return OperationResult{Outcome: "completed"}
			})
			if err != nil || retained == nil {
				t.Fatal("recorded callback failed", err)
			}
			if ProfileIntentActive(retained, "write") || ProfileIntentActive(retained, "delete") {
				t.Fatal("capability survived its callback")
			}
		})
	}
	_, r, _ := recorderFixture(t)
	var retained context.Context
	if err := r.Execute(context.Background(), "profile.write", func(ctx context.Context) OperationResult { retained = ctx; panic("PRIVATE") }); !errors.Is(err, ErrRecordedUncertain) {
		t.Fatal("panic not indeterminate", err)
	}
	if ProfileIntentActive(retained, "write") {
		t.Fatal("panic retained an active intent")
	}
}
