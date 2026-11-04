package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

var ErrRecorderUnavailable = errors.New("required audit unavailable; operation was not dispatched; preserve the journal and retained checkpoints")
var ErrRecordedUncertain = errors.New("operation or its audit result is uncertain; preserve the journal and inspect state before retrying")

// OperationResult is supplied by an in-process synchronous producer, never by
// request JSON. Refused/canceled require knowledge that no operation committed.
// An unknown result, panic or storage error must be indeterminate.
type OperationResult struct {
	Outcome string
	Err     error
}

// Recorder serializes one exclusively locked journal and its observation
// channel. Do not copy it. Keep the journal exclusive for the entire recorder
// scope. Close waits for an active callback before closing storage; a strictly
// synchronous borrowed scope may instead let its caller close the journal after
// Execute returns. Native I/O has no hard deadline.
// Output is not collector acknowledgment. A failed append/output poisons this
// recorder; it never retries, repairs, adopts an unknown tail or replaces it.
type Recorder struct {
	journal     LocalJournal
	output      io.Writer
	head        Checkpoint
	token       chan struct{}
	unavailable bool
	closed      bool
}

func NewRecorder(ctx context.Context, journal LocalJournal, from, to Checkpoint, out io.Writer) (*Recorder, error) {
	if journal == nil || out == nil || ctx.Err() != nil {
		return nil, ErrRecorderUnavailable
	}
	data, start, head, err := journal.Snapshot(ctx)
	clear(data)
	if err != nil || from != start || to != head || from.Sequence != 0 || validateCheckpoint(from) != nil || validateCheckpoint(to) != nil {
		return nil, ErrRecorderUnavailable
	}
	r := &Recorder{journal: journal, output: out, head: head, token: make(chan struct{}, 1)}
	r.token <- struct{}{}
	return r, nil
}

// Execute serializes complete intent/operation/result transactions. Callers
// must independently bound admission and must not recursively call Execute.
// Only the synchronous profile producers are connected by this version.
func (r *Recorder) Execute(ctx context.Context, action string, operation func(context.Context) OperationResult) error {
	if r == nil || r.token == nil || operation == nil || (action != "profile.write" && action != "profile.delete" && action != "profile.import") {
		return ErrRecorderUnavailable
	}
	if ctx.Err() != nil {
		return ErrRecorderUnavailable
	}
	select {
	case <-ctx.Done():
		return ErrRecorderUnavailable
	case <-r.token:
	}
	defer func() { r.token <- struct{}{} }()
	if ctx.Err() != nil || r.closed || r.unavailable || r.head.Sequence > MaxSegmentRecords-2 {
		return ErrRecorderUnavailable
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return ErrRecorderUnavailable
	}
	event := Event{OccurredAt: time.Now().UTC(), OperationID: hex.EncodeToString(id[:]), Action: action, Outcome: "intent"}
	intent, err := r.journal.Append(ctx, event)
	if err != nil {
		r.unavailable = true
		return ErrRecorderUnavailable
	}
	complete := func(outcome string) (Checkpoint, error) {
		resultCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		result := event
		result.OccurredAt = time.Now().UTC()
		result.Outcome = outcome
		return r.journal.Append(resultCtx, result)
	}
	if r.write(intent) != nil {
		_, _ = complete("refused")
		r.unavailable = true
		return ErrRecorderUnavailable
	}
	result := OperationResult{Outcome: "canceled", Err: context.Canceled}
	if ctx.Err() == nil {
		result = callWithProfileIntent(ctx, action, operation)
	}
	if (result.Outcome != "completed" && result.Outcome != "refused" && result.Outcome != "canceled" && result.Outcome != "indeterminate") || (result.Outcome == "completed" && result.Err != nil) || (result.Outcome != "completed" && result.Err == nil) {
		result = OperationResult{Outcome: "indeterminate", Err: ErrRecordedUncertain}
	}
	head, err := complete(result.Outcome)
	if err != nil {
		r.unavailable = true
		return ErrRecordedUncertain
	}
	r.head = head
	if r.write(head) != nil {
		r.unavailable = true
		return ErrRecordedUncertain
	}
	if result.Outcome == "indeterminate" {
		r.unavailable = true
		return ErrRecordedUncertain
	}
	return result.Err
}
func callRecordedOperation(ctx context.Context, operation func(context.Context) OperationResult) (result OperationResult) {
	result = OperationResult{Outcome: "indeterminate", Err: ErrRecordedUncertain}
	defer func() {
		if recover() != nil {
			result = OperationResult{Outcome: "indeterminate", Err: ErrRecordedUncertain}
		}
	}()
	return operation(ctx)
}
func (r *Recorder) write(checkpoint Checkpoint) error {
	data, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		return ErrRecorderUnavailable
	}
	n, err := r.output.Write(data)
	if err != nil || n != len(data) {
		return ErrRecorderUnavailable
	}
	return nil
}
func (r *Recorder) Close() error {
	if r == nil || r.token == nil {
		return nil
	}
	<-r.token
	defer func() { r.token <- struct{}{} }()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.journal.Close() != nil {
		return ErrRecordedUncertain
	}
	return nil
}
