package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

var (
	errAuditImportAdmission = errors.New("required audit or checkpoint output unavailable; profile import was not started; preserve the journal before retrying")
	errAuditImportRefused   = errors.New("profile import refused; review its input, policy, controller and saved revision")
	errAuditImportUncertain = errors.New("profile import or its audit result is uncertain; preserve the journal and inspect profile state before retrying")
)

func auditPaths(args []string, action string, keys ...string) (map[string]string, error) {
	if len(args) != 1+2*len(keys) || args[0] != action {
		return nil, errors.New("invalid audit options; use audit help")
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	paths := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		if !allowed[args[i]] || paths[args[i]] != "" || args[i+1] == "" {
			return nil, errors.New("audit commands require unique nonempty named options")
		}
		paths[args[i]] = args[i+1]
	}
	return paths, nil
}
func writeAuditCheckpoint(out io.Writer, checkpoint audit.Checkpoint) error {
	data, err := audit.EncodeCheckpoint(checkpoint)
	if err != nil {
		return err
	}
	n, err := out.Write(data)
	if err != nil || n != len(data) {
		return errors.New("audit checkpoint output unavailable")
	}
	return nil
}
func auditInitializeCommand(args []string, out io.Writer) error {
	paths, err := auditPaths(args, "initialize", "--directory")
	if err != nil {
		return err
	}
	checkpoint, err := audit.InitializeLocalJournal(paths["--directory"])
	if err != nil {
		return err
	}
	if writeAuditCheckpoint(out, checkpoint) != nil {
		return errors.New("audit initialization output unavailable; preserve the initialized directory and recover its genesis independently")
	}
	return nil
}
func auditImportCommand(args []string, out io.Writer) (failure error) {
	paths, err := auditPaths(args, "import", "--directory", "--from", "--to", "--profile")
	if err != nil {
		return err
	}
	if !audit.LocalRecordingSupported() {
		return audit.ErrLocalStorageUnsupported
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	inputCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	readCheckpoint := func(path string) (audit.Checkpoint, error) {
		data, err := readAuditInput(inputCtx, path, audit.MaxCheckpointBytes)
		if err != nil {
			return audit.Checkpoint{}, err
		}
		return audit.DecodeCheckpoint(data)
	}
	from, err := readCheckpoint(paths["--from"])
	if err != nil {
		return err
	}
	to, err := readCheckpoint(paths["--to"])
	if err != nil {
		return err
	}
	data, err := readAuditInput(inputCtx, paths["--profile"], 1<<20)
	if err != nil {
		return err
	}
	defer clear(data)
	journal, err := audit.OpenLocalJournal(inputCtx, paths["--directory"], from, to)
	if err != nil {
		return err
	}
	started := false
	defer func() {
		if journal.Close() != nil {
			if started {
				failure = errAuditImportUncertain
			} else {
				failure = errAuditImportAdmission
			}
		}
	}()
	if err := inputCtx.Err(); err != nil {
		return err
	}
	cancel() // The read budget must not cancel an outcome after profile mutation.
	started, err = executeRecordedImport(ctx, journal, from, to, out, func(ctx context.Context) importOutcome { return importReviewedProfile(ctx, data) })
	return err
}

type importOutcome struct {
	outcome         string
	mutationStarted bool
	failure         error
}

// executeRecordedImport owns one exclusively locked journal for one synchronous
// operation. It reserves capacity for both records, publishes a durable intent
// checkpoint before mutation and attempts the result even after cancellation.
// Checkpoint output is an observation channel, not collector acknowledgment.
func executeRecordedImport(ctx context.Context, journal audit.LocalJournal, from, to audit.Checkpoint, out io.Writer, operation func(context.Context) importOutcome) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	existing, actualFrom, actualTo, err := journal.Snapshot(ctx)
	clear(existing)
	if err != nil || actualFrom != from || actualTo != to || to.Sequence > audit.MaxSegmentRecords-2 {
		return false, errAuditImportAdmission
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return false, errAuditImportAdmission
	}
	event := audit.Event{OccurredAt: time.Now().UTC(), OperationID: hex.EncodeToString(id[:]), Action: "profile.import", Outcome: "intent"}
	intent, err := journal.Append(ctx, event)
	if err != nil {
		return false, errAuditImportAdmission
	}
	complete := func(outcome string) (audit.Checkpoint, error) {
		resultCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		result := event
		result.OccurredAt = time.Now().UTC()
		result.Outcome = outcome
		return journal.Append(resultCtx, result)
	}
	if writeAuditCheckpoint(out, intent) != nil {
		// No mutation is dispatched. A failed observation channel gets no further
		// writes. Preserve a local refusal if storage still permits it.
		_, _ = complete("refused")
		return false, errAuditImportAdmission
	}
	result := importOutcome{outcome: "canceled", failure: errAuditImportRefused}
	if ctx.Err() == nil {
		result = callImportOperation(ctx, operation)
	}
	if result.outcome != "completed" && result.outcome != "refused" && result.outcome != "canceled" && result.outcome != "indeterminate" || (result.outcome == "completed" && result.failure != nil) {
		result = importOutcome{outcome: "indeterminate", mutationStarted: result.mutationStarted, failure: errAuditImportUncertain}
	}
	head, err := complete(result.outcome)
	if err != nil {
		return result.mutationStarted, errAuditImportUncertain
	}
	if writeAuditCheckpoint(out, head) != nil {
		if result.mutationStarted {
			return true, errAuditImportUncertain
		}
		return false, errAuditImportAdmission
	}
	if result.outcome == "indeterminate" {
		return result.mutationStarted, errAuditImportUncertain
	}
	if result.outcome != "completed" {
		return result.mutationStarted, errAuditImportRefused
	}
	return result.mutationStarted, nil
}
func callImportOperation(ctx context.Context, operation func(context.Context) importOutcome) (result importOutcome) {
	// An unexpected panic must leave a redacted indeterminate result, rather than
	// recording success or exposing the panic value through an audit diagnostic.
	result = importOutcome{outcome: "indeterminate", mutationStarted: true, failure: errAuditImportUncertain}
	defer func() {
		if recover() != nil {
			result = importOutcome{outcome: "indeterminate", mutationStarted: true, failure: errAuditImportUncertain}
		}
	}()
	return operation(ctx)
}
func importReviewedProfile(ctx context.Context, data []byte) importOutcome {
	refuse := func() importOutcome { return importOutcome{outcome: "refused", failure: errAuditImportRefused} }
	if ctx.Err() != nil {
		return importOutcome{outcome: "canceled", failure: errAuditImportRefused}
	}
	p, err := profile.Decode(bytes.NewReader(data))
	if err != nil {
		return refuse()
	}
	if managed.NewGuard(nil).ProfileChanges() != nil {
		return refuse()
	}
	root, err := profile.DefaultRoot()
	if err != nil {
		return refuse()
	}
	if override := os.Getenv("ACCESSWEAVER_HOME"); override != "" {
		root = override
	}
	// Directory creation is part of this already intent-recorded operation.
	store, err := profile.NewStore(root)
	if err != nil {
		return importOutcome{outcome: "indeterminate", mutationStarted: true, failure: errAuditImportUncertain}
	}
	controller, err := filelock.TryAcquire(filepath.Join(root, ".controller.lock"))
	if err != nil {
		return importOutcome{outcome: "refused", mutationStarted: true, failure: errAuditImportRefused}
	}
	err = store.SaveIfUnchangedContext(ctx, p)
	closeErr := controller.Close()
	if err == nil && closeErr == nil {
		return importOutcome{outcome: "completed", mutationStarted: true}
	}
	if errors.Is(err, profile.ErrConflict) || errors.Is(err, managed.ErrDenied) || errors.Is(err, profile.ErrStoreBusy) {
		return importOutcome{outcome: "refused", mutationStarted: true, failure: errAuditImportRefused}
	}
	return importOutcome{outcome: "indeterminate", mutationStarted: true, failure: errAuditImportUncertain}
}
