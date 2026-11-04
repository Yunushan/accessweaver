package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
)

type engineLifecycleJournal struct {
	mu                             sync.Mutex
	start, head                    audit.Checkpoint
	lines                          [][]byte
	events                         []audit.Event
	calls, closes, failAt, wrongAt int
	corrupt, snapshotFailure       bool
	onAppend                       func(context.Context, int, audit.Event)
	onSnapshot                     func(context.Context)
}

func newEngineLifecycleJournal(t *testing.T) *engineLifecycleJournal {
	t.Helper()
	start, err := audit.NewStream(audit.Producer{
		ActorClass: "user", ActorSHA256: strings.Repeat("a", 64),
		SourceCommit: "unknown", SourceState: "unknown", Target: "linux/amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &engineLifecycleJournal{start: start, head: start}
}
func (j *engineLifecycleJournal) Append(ctx context.Context, event audit.Event) (audit.Checkpoint, error) {
	j.mu.Lock()
	j.calls++
	call, hook := j.calls, j.onAppend
	j.mu.Unlock()
	if hook != nil {
		hook(ctx, call, event)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return audit.Checkpoint{}, err
	}
	if call == j.failAt {
		return audit.Checkpoint{}, errors.New("PRIVATE_STORAGE_FAILURE")
	}
	if j.head.Sequence >= audit.MaxSegmentRecords {
		return audit.Checkpoint{}, errors.New("full")
	}
	data, next, err := audit.Append(j.head, event)
	if err != nil {
		return audit.Checkpoint{}, err
	}
	j.lines = append(j.lines, data)
	j.events = append(j.events, event)
	j.head = next
	if call == j.wrongAt {
		next.SHA256 = strings.Repeat("f", 64)
	}
	return next, nil
}
func (j *engineLifecycleJournal) Snapshot(ctx context.Context) ([]byte, audit.Checkpoint, audit.Checkpoint, error) {
	j.mu.Lock()
	hook := j.onSnapshot
	j.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	data := bytes.Join(j.lines, nil)
	if j.corrupt {
		data = []byte("PRIVATE_CORRUPT_SNAPSHOT\n")
	}
	if j.snapshotFailure {
		return data, j.start, j.head, errors.New("PRIVATE_SNAPSHOT_FAILURE")
	}
	return data, j.start, j.head, ctx.Err()
}
func (j *engineLifecycleJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.closes++
	return nil
}
func (j *engineLifecycleJournal) view() ([]audit.Event, audit.Checkpoint, int, int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]audit.Event(nil), j.events...), j.head, j.calls, j.closes
}
func (j *engineLifecycleJournal) seed(t *testing.T, count int) {
	t.Helper()
	for range count {
		if _, err := j.Append(context.Background(), audit.Event{OccurredAt: time.Now().UTC(), OperationID: strings.Repeat("b", 32), Action: "profile.write", Outcome: "completed"}); err != nil {
			t.Fatal(err)
		}
	}
	j.calls = 0
}

type engineLifecycleRun struct {
	done    chan struct{}
	result  engine.RunResult
	waitErr error
	onWait  func(context.Context)
}

func (r *engineLifecycleRun) Done() <-chan struct{} { return r.done }
func (r *engineLifecycleRun) Wait(ctx context.Context) (engine.RunResult, error) {
	if r.onWait != nil {
		r.onWait(ctx)
	}
	select {
	case <-r.done:
		return r.result, r.waitErr
	default:
	}
	select {
	case <-r.done:
		return r.result, r.waitErr
	case <-ctx.Done():
		return engine.RunResult{}, ctx.Err()
	}
}
func completedEngineLifecycleRun(result engine.RunResult) *engineLifecycleRun {
	run := &engineLifecycleRun{done: make(chan struct{}), result: result}
	close(run.done)
	return run
}

type engineLifecycleWriter struct {
	mu            sync.Mutex
	data          bytes.Buffer
	calls, failAt int
	short         bool
	after         func(int)
}

func (w *engineLifecycleWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	w.calls++
	call, hook := w.calls, w.after
	n, err := 0, error(nil)
	if call == w.failAt {
		if w.short {
			n, _ = w.data.Write(data[:len(data)-1])
		} else {
			err = errors.New("PRIVATE_OUTPUT_FAILURE")
		}
	} else {
		n, err = w.data.Write(data)
	}
	w.mu.Unlock()
	if hook != nil {
		hook(call)
	}
	return n, err
}
func (w *engineLifecycleWriter) view() ([]byte, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.data.Bytes()...), w.calls
}
func assertEngineLifecycleEvents(t *testing.T, j *engineLifecycleJournal, want ...string) {
	t.Helper()
	events, _, _, closes := j.view()
	if closes != 0 {
		t.Fatal("borrowed producer closed its journal", closes)
	}
	if len(events) != len(want) {
		t.Fatal("wrong event count", events, want)
	}
	var id string
	for i, event := range events {
		if event.Action != "engine.start" || event.Outcome != want[i] || len(event.OperationID) != 32 || event.OccurredAt.Location() != time.UTC {
			t.Fatal("incorrect lifecycle metadata", event, want[i])
		}
		if i == 0 {
			id = event.OperationID
		}
		if event.OperationID != id {
			t.Fatal("lifecycle lost operation identity", events)
		}
		data, err := json.Marshal(event)
		if err != nil || bytes.Contains(data, []byte("PRIVATE")) {
			t.Fatal("private runtime data entered metadata", string(data), err)
		}
	}
}
func assertEngineCheckpointStream(t *testing.T, out *engineLifecycleWriter, count int) {
	t.Helper()
	data, calls := out.view()
	if calls != count {
		t.Fatal("checkpoint write count differs", calls, count)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != count {
		t.Fatal("mixed or partial checkpoint output", string(data))
	}
	for _, line := range lines {
		if _, err := audit.DecodeCheckpoint(append(line, '\n')); err != nil {
			t.Fatal("noncanonical checkpoint output", err)
		}
	}
}

func TestRecordedEngineLifecycleRequiresVerifiedObservedIntent(t *testing.T) {
	for _, mode := range []string{"snapshot-error", "corrupt", "stale", "non-genesis", "intent-append", "wrong-intent-successor", "intent-output", "short-intent-output", "canceled", "nil-journal", "nil-observations", "nil-notice", "nil-launch", "nil-stop", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			j := newEngineLifecycleJournal(t)
			out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			from, to := j.start, j.head
			var borrowed audit.LocalJournal = j
			var observations, information io.Writer = out, notice
			launches, stops := 0, 0
			launch := func() (foregroundEngineRun, error) {
				launches++
				return completedEngineLifecycleRun(engine.RunResult{Reason: engine.RunExited}), nil
			}
			stop := func() error { stops++; return nil }
			switch mode {
			case "snapshot-error":
				j.snapshotFailure = true
			case "corrupt":
				j.corrupt = true
			case "stale":
				to.SHA256 = strings.Repeat("f", 64)
			case "non-genesis":
				j.seed(t, 1)
				from, to = j.head, j.head
			case "intent-append":
				j.failAt = 1
			case "wrong-intent-successor":
				j.wrongAt = 1
			case "intent-output":
				out.failAt = 1
			case "short-intent-output":
				out.failAt, out.short = 1, true
			case "canceled":
				cancel()
			case "nil-journal":
				borrowed = nil
			case "nil-observations":
				observations = nil
			case "nil-notice":
				information = nil
			case "nil-launch":
				launch = nil
			case "nil-stop":
				stop = nil
			}
			var caller context.Context = ctx
			if mode == "nil-context" {
				caller = nil
			}
			err := executeRecordedEngine(caller, borrowed, from, to, observations, information, launch, stop)
			if !errors.Is(err, audit.ErrRecorderUnavailable) || launches != 0 || stops != 0 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unverified or unobserved dispatch", err, launches, stops)
			}
			if mode == "intent-output" || mode == "short-intent-output" {
				assertEngineLifecycleEvents(t, j, "intent", "refused")
				if _, calls := out.view(); calls != 1 {
					t.Fatal("failed observation was retried", calls)
				}
			}
		})
	}
}

func TestRecordedEngineLifecycleReservesExactlyThreeRecords(t *testing.T) {
	for _, slots := range []int{2, 3} {
		t.Run(string(rune('0'+slots)), func(t *testing.T) {
			j := newEngineLifecycleJournal(t)
			j.seed(t, audit.MaxSegmentRecords-slots)
			_, before, _, _ := j.view()
			launches := 0
			out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
			err := executeRecordedEngine(context.Background(), j, j.start, before, out, notice, func() (foregroundEngineRun, error) {
				launches++
				return completedEngineLifecycleRun(engine.RunResult{Reason: engine.RunExited}), nil
			}, func() error { t.Error("completed child was stopped"); return nil })
			events, after, calls, closes := j.view()
			if slots == 2 {
				if !errors.Is(err, audit.ErrRecorderUnavailable) || launches != 0 || calls != 0 || after != before {
					t.Fatal("insufficient terminal capacity admitted", err, launches, calls)
				}
			} else {
				if err != nil || launches != 1 || calls != 3 || after.Sequence != audit.MaxSegmentRecords {
					t.Fatal("exact capacity failed", err, launches, calls, after.Sequence)
				}
				tail := events[len(events)-3:]
				if tail[0].Outcome != "intent" || tail[1].Outcome != "accepted" || tail[2].Outcome != "completed" {
					t.Fatal("reserved terminal record lost", tail)
				}
				assertEngineCheckpointStream(t, out, 3)
			}
			if closes != 0 {
				t.Fatal("borrowed journal closed")
			}
		})
	}
}

func TestRecordedEngineLifecycleCancellationBeforeLaunchAndPreparationFailure(t *testing.T) {
	for _, mode := range []string{"cancel-after-intent", "startup-effect", "nil-handle", "zero-handle"} {
		t.Run(mode, func(t *testing.T) {
			j := newEngineLifecycleJournal(t)
			out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			launches, stops, effects := 0, 0, 0
			if mode == "cancel-after-intent" {
				out.after = func(call int) {
					if call == 1 {
						cancel()
					}
				}
			}
			err := executeRecordedEngine(ctx, j, j.start, j.head, out, notice, func() (foregroundEngineRun, error) {
				launches++
				switch mode {
				case "startup-effect":
					effects++
					return nil, errors.New("PRIVATE_GENERATED_INPUT_CHANGE")
				case "nil-handle":
					return nil, nil
				default:
					return (*engine.Run)(nil), nil
				}
			}, func() error { stops++; return nil })
			if mode == "cancel-after-intent" {
				if !errors.Is(err, context.Canceled) || launches != 0 || stops != 0 {
					t.Fatal("prelaunch cancellation dispatched", err, launches, stops)
				}
				assertEngineLifecycleEvents(t, j, "intent", "canceled")
			} else {
				if !errors.Is(err, audit.ErrRecordedUncertain) || launches != 1 || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("unknown startup effect was treated as clean refusal", err)
				}
				if mode == "startup-effect" && effects != 1 {
					t.Fatal("fixture did not model preparation effect")
				}
				assertEngineLifecycleEvents(t, j, "intent", "indeterminate")
			}
			assertEngineCheckpointStream(t, out, 2)
		})
	}
}

func TestRecordedEngineLifecycleActualTerminalMetadataAndImmediateExitOrder(t *testing.T) {
	privateExit := errors.New("PRIVATE_CHILD_WAIT")
	for _, tc := range []struct {
		name    string
		result  engine.RunResult
		outcome string
		want    error
	}{
		{"clean", engine.RunResult{Reason: engine.RunExited}, "completed", nil},
		{"failure", engine.RunResult{Reason: engine.RunFailed, WaitErr: privateExit}, "failed", privateExit},
		{"policy", engine.RunResult{Reason: engine.RunPolicyRevoked, WaitErr: privateExit, PolicyErr: managed.ErrUnavailable}, "failed", managed.ErrUnavailable},
		{"stopped-nonzero", engine.RunResult{Reason: engine.RunStopped, WaitErr: privateExit}, "failed", nil},
		{"stopped-clean", engine.RunResult{Reason: engine.RunStopped}, "completed", nil},
		{"missing-wait-error", engine.RunResult{Reason: engine.RunFailed}, "indeterminate", audit.ErrRecordedUncertain},
		{"inconsistent-clean", engine.RunResult{Reason: engine.RunExited, WaitErr: privateExit}, "indeterminate", audit.ErrRecordedUncertain},
		{"unknown", engine.RunResult{}, "indeterminate", audit.ErrRecordedUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newEngineLifecycleJournal(t)
			out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
			run := completedEngineLifecycleRun(tc.result)
			j.onAppend = func(ctx context.Context, call int, event audit.Event) {
				if call == 2 {
					select {
					case <-run.Done():
					default:
						t.Error("fixture was not terminal before accepted append")
					}
					if event.Outcome != "accepted" {
						t.Error("early terminal displaced acceptance")
					}
				}
			}
			err := executeRecordedEngine(context.Background(), j, j.start, j.head, out, notice, func() (foregroundEngineRun, error) {
				events, _, _, _ := j.view()
				if len(events) != 1 || events[0].Outcome != "intent" {
					t.Error("launch preceded durable intent")
				}
				if _, calls := out.view(); calls != 1 {
					t.Error("launch preceded complete intent observation")
				}
				return run, nil
			}, func() error { t.Error("immediate completed child received Stop"); return nil })
			if !errors.Is(err, tc.want) {
				t.Fatal("local terminal error lost", err, tc.want)
			}
			assertEngineLifecycleEvents(t, j, "intent", "accepted", tc.outcome)
			assertEngineCheckpointStream(t, out, 3)
			if data, calls := notice.view(); calls != 1 || !bytes.Contains(data, []byte("Process launched")) {
				t.Fatal("separate launch notice missing", calls, string(data))
			}
		})
	}
}

func TestRecordedEngineLifecyclePostAcceptanceFaultsDrainWithoutRetry(t *testing.T) {
	for _, mode := range []string{"accepted-append", "wrong-accepted-successor", "accepted-output", "short-accepted-output", "notice-output", "short-notice-output", "terminal-append", "terminal-output"} {
		t.Run(mode, func(t *testing.T) {
			j := newEngineLifecycleJournal(t)
			out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
			run := &engineLifecycleRun{done: make(chan struct{}), result: engine.RunResult{Reason: engine.RunStopped, WaitErr: errors.New("PRIVATE_SIGNAL_WAIT")}}
			stops := 0
			switch mode {
			case "accepted-append":
				j.failAt = 2
			case "wrong-accepted-successor":
				j.wrongAt = 2
			case "accepted-output":
				out.failAt = 2
			case "short-accepted-output":
				out.failAt, out.short = 2, true
			case "notice-output":
				notice.failAt = 1
			case "short-notice-output":
				notice.failAt, notice.short = 1, true
			case "terminal-append":
				j.failAt = 3
				close(run.done)
				run.result = engine.RunResult{Reason: engine.RunExited}
			case "terminal-output":
				out.failAt = 3
				close(run.done)
				run.result = engine.RunResult{Reason: engine.RunExited}
			}
			err := executeRecordedEngine(context.Background(), j, j.start, j.head, out, notice, func() (foregroundEngineRun, error) { return run, nil }, func() error {
				stops++
				close(run.done)
				return nil
			})
			if err == nil || errors.Is(err, audit.ErrRecorderUnavailable) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("post-effect failure became no-dispatch or disclosed fault", err)
			}
			events, _, calls, closes := j.view()
			if closes != 0 {
				t.Fatal("borrowed journal closed")
			}
			switch mode {
			case "accepted-append", "wrong-accepted-successor":
				if calls != 2 || stops != 1 {
					t.Fatal("uncertain accepted append retried or skipped owned cleanup", calls, stops)
				}
			case "terminal-append":
				if calls != 3 || stops != 0 || len(events) != 2 {
					t.Fatal("terminal uncertainty retried", calls, stops, events)
				}
			default:
				if calls != 3 || len(events) != 3 {
					t.Fatal("truthful terminal append missing", calls, events)
				}
				if mode != "terminal-output" && stops != 1 {
					t.Fatal("lost output did not stop child", stops)
				}
			}
			if mode == "accepted-output" || mode == "short-accepted-output" {
				if _, calls := out.view(); calls != 2 {
					t.Fatal("failed checkpoint channel retried", calls)
				}
				assertEngineLifecycleEvents(t, j, "intent", "accepted", "failed")
			}
			if mode == "notice-output" || mode == "short-notice-output" {
				if !errors.Is(err, errEngineLaunchOutput) || !errors.Is(err, audit.ErrRecordedUncertain) {
					t.Fatal("notice error or post-effect uncertainty lost", err)
				}
				assertEngineCheckpointStream(t, out, 3)
				assertEngineLifecycleEvents(t, j, "intent", "accepted", "failed")
			}
		})
	}
}

func TestRecordedEngineLifecycleStopFailureRetainsBorrowedOwnershipUntilActualDone(t *testing.T) {
	for _, stopFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop-returned-before-done", true: "stop-timeout"}[stopFailure], func(t *testing.T) {
			j := newEngineLifecycleJournal(t)
			out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waitEntered, stopReturned := make(chan struct{}), make(chan struct{})
			var once sync.Once
			run := &engineLifecycleRun{done: make(chan struct{}), onWait: func(waitCtx context.Context) {
				if waitCtx == ctx {
					once.Do(func() { close(waitEntered) })
				}
			}}
			stopErr := errors.New("PRIVATE_STOP_TIMEOUT")
			finished := make(chan error, 1)
			go func() {
				err := executeRecordedEngine(ctx, j, j.start, j.head, out, notice, func() (foregroundEngineRun, error) { return run, nil }, func() error {
					close(stopReturned)
					if stopFailure {
						return stopErr
					}
					return nil
				})
				// Model the outer owner's Close after the borrowed scope returns.
				_ = j.Close()
				finished <- err
			}()
			select {
			case <-waitEntered:
			case <-time.After(5 * time.Second):
				t.Fatal("live wait not reached")
			}
			cancel()
			select {
			case <-stopReturned:
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not request owned stop")
			}
			events, _, calls, closes := j.view()
			if len(events) != 2 || calls != 2 || closes != 0 {
				t.Fatal("Stop was mistaken for terminal proof", events, calls, closes)
			}
			select {
			case err := <-finished:
				t.Fatal("ownership escaped before actual Run completion", err)
			default:
			}
			// Only this actual observation permits terminal append and owner Close.
			actual := errors.New("PRIVATE_ACTUAL_EXIT")
			run.result = engine.RunResult{Reason: engine.RunFailed, WaitErr: actual}
			close(run.done)
			var err error
			select {
			case err = <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("observed terminal did not finish")
			}
			if !errors.Is(err, actual) || (stopFailure && (!errors.Is(err, audit.ErrRecordedUncertain) || !errors.Is(err, stopErr))) {
				t.Fatal("actual failure or Stop uncertainty lost", err)
			}
			events, _, calls, closes = j.view()
			if len(events) != 3 || events[2].Outcome != "failed" || calls != 3 || closes != 1 {
				t.Fatal("terminal/Close ownership order lost", events, calls, closes)
			}
		})
	}
}

func TestRecordedEngineLifecycleOutcomeContextsOutliveCanceledAdmission(t *testing.T) {
	j := newEngineLifecycleJournal(t)
	out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := completedEngineLifecycleRun(engine.RunResult{Reason: engine.RunStopped})
	j.onSnapshot = func(snapshotCtx context.Context) {
		if _, ok := snapshotCtx.Deadline(); !ok {
			t.Error("snapshot omitted admission budget")
		}
	}
	j.onAppend = func(appendCtx context.Context, call int, event audit.Event) {
		if _, ok := appendCtx.Deadline(); !ok {
			t.Error("append omitted cooperative budget")
		}
		if call > 1 && appendCtx.Err() != nil {
			t.Error("canceled wait suppressed actual outcome", event.Outcome, appendCtx.Err())
		}
	}
	stops := 0
	err := executeRecordedEngine(ctx, j, j.start, j.head, out, notice, func() (foregroundEngineRun, error) {
		cancel()
		return run, nil
	}, func() error { stops++; return nil })
	if err != nil || stops != 0 {
		t.Fatal("already terminal launch acquired a canceled outcome budget", err, stops)
	}
	assertEngineLifecycleEvents(t, j, "intent", "accepted", "completed")
	assertEngineCheckpointStream(t, out, 3)
}

func TestRecordedEngineLifecycleUnknownWaitCannotClaimTerminalCompletion(t *testing.T) {
	j := newEngineLifecycleJournal(t)
	out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
	run := completedEngineLifecycleRun(engine.RunResult{Reason: engine.RunExited})
	run.waitErr = errors.New("PRIVATE_INVALID_WAIT_RESULT")
	stops := 0
	err := executeRecordedEngine(context.Background(), j, j.start, j.head, out, notice, func() (foregroundEngineRun, error) {
		return run, nil
	}, func() error { stops++; return nil })
	if !errors.Is(err, audit.ErrRecordedUncertain) || stops != 1 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("unavailable terminal result became completed", err, stops)
	}
	assertEngineLifecycleEvents(t, j, "intent", "accepted", "indeterminate")
	assertEngineCheckpointStream(t, out, 3)
}

func TestRecordedEngineLifecycleMalformedLaunchStillDrainsObservableHandle(t *testing.T) {
	j := newEngineLifecycleJournal(t)
	out, notice := &engineLifecycleWriter{}, &engineLifecycleWriter{}
	run := &engineLifecycleRun{done: make(chan struct{}), result: engine.RunResult{Reason: engine.RunStopped}}
	stops := 0
	err := executeRecordedEngine(context.Background(), j, j.start, j.head, out, notice, func() (foregroundEngineRun, error) {
		// Real Manager.StartTracked never returns both; this private adapter
		// violation still supplies observable ownership and cannot escape it.
		return run, errors.New("PRIVATE_CONTRADICTORY_LAUNCH_RESULT")
	}, func() error { stops++; close(run.done); return nil })
	if !errors.Is(err, audit.ErrRecordedUncertain) || stops != 1 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("observable malformed launch escaped owned cleanup", err, stops)
	}
	assertEngineLifecycleEvents(t, j, "intent", "indeterminate")
	assertEngineCheckpointStream(t, out, 2)
}
