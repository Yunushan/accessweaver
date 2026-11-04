package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
)

func recordedExportPaths(args []string) (map[string]string, error) {
	paths, err := auditPaths(args, "export-recorded", "--directory", "--from", "--to", "--consent")
	if err != nil {
		return nil, err
	}
	if paths["--consent"] != "metadata-only" {
		return nil, errAuditExportConsent
	}
	return paths, nil
}

// The export is a snapshot ending at the supplied pre-access head. Its own
// intent/result are observed separately and appear only in a subsequent export.
// Stdout is event JSONL; stderr contains canonical checkpoint observations.
func auditRecordedExportCommand(args []string, out, observations io.Writer) (failure error) {
	paths, err := recordedExportPaths(args)
	if err != nil {
		return err
	}
	if !audit.LocalRecordingSupported() {
		return audit.ErrLocalStorageUnsupported
	}
	if out == nil || observations == nil {
		return audit.ErrRecorderUnavailable
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	inputCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	decode := func(path string) (audit.Checkpoint, error) {
		data, err := readAuditInput(inputCtx, path, audit.MaxCheckpointBytes)
		if err != nil {
			return audit.Checkpoint{}, err
		}
		return audit.DecodeCheckpoint(data)
	}
	from, err := decode(paths["--from"])
	if err != nil {
		return err
	}
	to, err := decode(paths["--to"])
	if err != nil {
		return err
	}
	required := []string{paths["--from"], paths["--to"], filepath.Join(paths["--directory"], "events.journal"), filepath.Join(paths["--directory"], ".actor-key")}
	if err := checkAuditUIOutputs(out, observations, required); err != nil {
		return audit.ErrExportDestination
	}
	// Also protect existing fixed machine authority when this explicit command is
	// separately run by an administrator. This grants no machine policy access.
	optional := []string{"/etc/accessweaver/installation.json", "/etc/accessweaver/acceptance.json", "/etc/.accessweaver-policy.lock"}
	for _, destination := range []io.Writer{out, observations} {
		if err := checkRecordedPolicyOutput(destination, required, optional); err != nil {
			return audit.ErrExportDestination
		}
	}
	journal, err := audit.OpenLocalJournal(inputCtx, paths["--directory"], from, to)
	if err != nil {
		return err
	}
	defer func() {
		if journal.Close() != nil {
			failure = audit.ErrRecordedUncertain
		}
	}()
	return executeRecordedExport(inputCtx, journal, from, to, out, observations)
}

// A synchronous borrowed recorder scope owns the already locked journal. It
// never dispatches an export without durable intent and a complete observation.
func executeRecordedExport(ctx context.Context, journal audit.LocalJournal, from, to audit.Checkpoint, out, observations io.Writer) error {
	if journal == nil || out == nil || observations == nil || ctx.Err() != nil {
		return audit.ErrRecorderUnavailable
	}
	data, start, head, err := journal.Snapshot(ctx)
	defer clear(data)
	if err != nil || start != from || head != to {
		return audit.ErrRecorderUnavailable
	}
	if _, err := audit.VerifySegment(ctx, bytes.NewReader(data), from, to); err != nil {
		return audit.ErrRecorderUnavailable
	}
	recorder, err := audit.NewRecorder(ctx, journal, from, to, observations)
	if err != nil {
		return audit.ErrRecorderUnavailable
	}
	return recorder.Execute(ctx, "audit.export", func(ctx context.Context) audit.OperationResult {
		if ctx.Err() != nil {
			return audit.OperationResult{Outcome: "canceled", Err: context.Canceled}
		}
		n, err := out.Write(data)
		// Even an error with n==0 cannot prove the writer forwarded no bytes.
		// Completion means a full local write, never recipient/collector receipt.
		if err != nil || n != len(data) {
			return audit.OperationResult{Outcome: "indeterminate", Err: audit.ErrRecordedUncertain}
		}
		return audit.OperationResult{Outcome: "completed"}
	})
}
