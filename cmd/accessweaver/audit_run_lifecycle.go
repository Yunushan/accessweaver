package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
)

// executeRecordedEngine borrows one exclusively locked journal for the complete
// foreground lifecycle. Its caller retains journal and controller ownership
// until this function returns, then performs the sole owning Close. No journal
// reference or terminal callback escapes, and this function never closes it.
//
// launch/stop are trusted in-process adapters, never request-selected callbacks.
// An accepted launch must return a nonnil handle with nonnil Done; Manager's
// StartTracked guarantees this after process creation. Only pre-start failures
// refuse a launch; later lifecycle uncertainty belongs to the accepted Run. A
// pre-start error can still follow generated-file changes. Callback panics are not caught:
// a panic without an exact handle cannot be recovered as proof of cleanup.
//
// Native storage/output/signal operations have no hard deadline. In particular,
// Stop failure retains ownership while this foreground scope drains the exact
// Run; it must not detach a reaper or return while an observable Run is live.
func executeRecordedEngine(ctx context.Context, journal audit.LocalJournal, from, to audit.Checkpoint, observations, notice io.Writer, launch func() (foregroundEngineRun, error), stop func() error) error {
	if ctx == nil || journal == nil || observations == nil || notice == nil || launch == nil || stop == nil || ctx.Err() != nil {
		return audit.ErrRecorderUnavailable
	}
	admissionCtx, cancelAdmission := context.WithTimeout(ctx, 15*time.Second)
	defer cancelAdmission()
	data, start, head, snapshotErr := journal.Snapshot(admissionCtx)
	valid := snapshotErr == nil && start == from && head == to && from.Sequence == 0 && head.Sequence <= audit.MaxSegmentRecords-3
	if valid {
		_, snapshotErr = audit.VerifySegment(admissionCtx, bytes.NewReader(data), from, to)
		valid = snapshotErr == nil
	}
	clear(data) // Do not retain the complete private stream for the run lifetime.
	if !valid || admissionCtx.Err() != nil {
		return audit.ErrRecorderUnavailable
	}
	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return audit.ErrRecorderUnavailable
	}
	event := audit.Event{OperationID: hex.EncodeToString(randomID[:]), Action: "engine.start"}
	// The caller's exclusive lock and this one linear producer reserve all three
	// records. The storage's record and byte limits remain unchanged.
	appendEvent := func(appendCtx context.Context, outcome string) (audit.Checkpoint, error) {
		nextEvent := event
		nextEvent.OccurredAt = time.Now().UTC()
		nextEvent.Outcome = outcome
		_, expected, err := audit.Append(head, nextEvent)
		if err != nil {
			return audit.Checkpoint{}, audit.ErrRecordedUncertain
		}
		checkpoint, err := journal.Append(appendCtx, nextEvent)
		if err != nil || checkpoint != expected {
			// Never adopt an unexpected successor or retry an uncertain append.
			return audit.Checkpoint{}, audit.ErrRecordedUncertain
		}
		head = checkpoint
		return checkpoint, nil
	}
	appendResult := func(outcome string) (audit.Checkpoint, error) {
		resultCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return appendEvent(resultCtx, outcome)
	}
	intent, err := appendEvent(admissionCtx, "intent")
	if err != nil {
		return audit.ErrRecorderUnavailable
	}
	if writeAuditCheckpoint(observations, intent) != nil {
		_, _ = appendResult("refused")
		return audit.ErrRecorderUnavailable
	}
	if canceled := admissionCtx.Err(); canceled != nil {
		checkpoint, err := appendResult("canceled")
		if err != nil || writeAuditCheckpoint(observations, checkpoint) != nil {
			return audit.ErrRecordedUncertain
		}
		return canceled
	}
	cancelAdmission() // This budget must never become the live engine's lifetime.
	run, launchErr := launch()
	if launchErr != nil || run == nil || run.Done() == nil {
		// A missing handle is an adapter-contract violation, not proof of no
		// effects. A malformed adapter returning both a handle and error still
		// supplies observable ownership that must be drained before returning.
		if run != nil && run.Done() != nil {
			_, _, _ = stopAndDrainRecordedEngine(run, stop)
		} else if launchErr == nil {
			_ = stop() // Defensive only; a missing handle supplies no drain proof.
		}
		checkpoint, err := appendResult("indeterminate")
		if err == nil {
			_ = writeAuditCheckpoint(observations, checkpoint)
		}
		return audit.ErrRecordedUncertain
	}

	accepted, err := appendResult("accepted")
	if err != nil {
		_, stopErr, _ := stopAndDrainRecordedEngine(run, stop)
		// Storage continuity is unknown. Never append a guessed terminal tail.
		return errors.Join(audit.ErrRecordedUncertain, stopErr)
	}
	observationsHealthy := writeAuditCheckpoint(observations, accepted) == nil
	var operationErr error
	var result engine.RunResult
	var waitErr error
	if !observationsHealthy {
		operationErr = audit.ErrRecordedUncertain
		result, err, waitErr = stopAndDrainRecordedEngine(run, stop)
		if err != nil {
			operationErr = errors.Join(operationErr, err)
		}
	} else {
		const launchNotice = "Process launched. This does not guarantee functional routing or connection.\n"
		n, noticeErr := io.WriteString(notice, launchNotice)
		if noticeErr != nil || n != len(launchNotice) {
			operationErr = errors.Join(audit.ErrRecordedUncertain, errEngineLaunchOutput)
			result, err, waitErr = stopAndDrainRecordedEngine(run, stop)
			if err != nil {
				operationErr = errors.Join(operationErr, audit.ErrRecordedUncertain, err)
			}
		} else {
			result, waitErr = run.Wait(ctx)
			terminalPublished := false
			select {
			case <-run.Done():
				terminalPublished = true
			default:
			}
			if waitErr != nil || !terminalPublished {
				// A canceled wait does not stop a child. Explicitly stop it and
				// retain ownership even if Stop fails or its grace wait expires.
				if waitErr == nil || ctx.Err() == nil || !errors.Is(waitErr, ctx.Err()) {
					operationErr = audit.ErrRecordedUncertain
				}
				result, err, waitErr = stopAndDrainRecordedEngine(run, stop)
				if err != nil {
					operationErr = errors.Join(operationErr, audit.ErrRecordedUncertain, err)
				}
			}
		}
	}
	outcome, terminalErr := recordedEngineTerminal(result, waitErr)
	checkpoint, err := appendResult(outcome)
	if err != nil {
		return errors.Join(audit.ErrRecordedUncertain, operationErr)
	}
	if observationsHealthy && writeAuditCheckpoint(observations, checkpoint) != nil {
		return errors.Join(audit.ErrRecordedUncertain, operationErr)
	}
	return errors.Join(operationErr, terminalErr)
}

// Stop's error/timeout is not terminal proof. The exact handle remains owned
// until Done; this foreground wait is intentionally unbounded. The trusted Run
// then returns its cached result without context cancellation or another wait.
func stopAndDrainRecordedEngine(run foregroundEngineRun, stop func() error) (engine.RunResult, error, error) {
	stopErr := stop()
	<-run.Done()
	result, waitErr := run.Wait(context.Background())
	return result, stopErr, waitErr
}

// A stopped reason describes accepted signal dispatch, not its causal effect.
// Audit actual wait status, including a nonzero/signaled expected stop, while the
// local CLI can still treat that owned stop as successful. Never emit canceled
// or refused after acceptance, or serialize process/policy error text.
func recordedEngineTerminal(result engine.RunResult, waitErr error) (string, error) {
	if waitErr != nil || result.LifecycleErr != nil {
		return "indeterminate", audit.ErrRecordedUncertain
	}
	switch result.Reason {
	case engine.RunExited:
		if result.WaitErr == nil && result.PolicyErr == nil {
			return "completed", nil
		}
	case engine.RunFailed:
		if result.WaitErr != nil && result.PolicyErr == nil {
			return "failed", result.WaitErr
		}
	case engine.RunStopped:
		if result.PolicyErr == nil {
			if result.WaitErr != nil {
				return "failed", nil
			}
			return "completed", nil
		}
	case engine.RunPolicyRevoked:
		if managed.IsPolicyError(result.PolicyErr) {
			return "failed", errors.Join(result.PolicyErr, result.WaitErr)
		}
	}
	return "indeterminate", audit.ErrRecordedUncertain
}
