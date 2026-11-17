package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Yunushan/accessweaver/internal/managed"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The original generation is canceled after its physically published intent.
// No executor runs. The ACK fault occurs only after the actual stage writer
// has written, synced and closed; it is not an error-only proof surrogate.
func workflowReconciliationFixture(t *testing.T) (*workflowShutdownFixture, Job) {
	t.Helper()
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		t.Error("canceled generation executed")
		return nil, nil
	}
	m.publishLifecycle = func(stage, target, previous string) error {
		if strings.HasSuffix(target, ".ack.json") {
			return errors.New("closed ACK publication fixture fault")
		}
		err := physicalLifecyclePublish(stage, target, previous)
		if err == nil && strings.HasSuffix(target, ".intent.json") {
			m.Cancel()
		}
		return err
	}
	job := f.start()
	workflowLifecycleAwait(t, m)
	m.publishLifecycle = nil
	m.mu.Lock()
	witness := m.releaseWitness
	m.mu.Unlock()
	if witness == nil || !witness.Ack.Write.Known || witness.Ack.Write.Stage == nil || !witness.Ack.TransactionClosed {
		t.Fatal("actual original release witness missing")
	}
	return f, job
}
func workflowReconciliationPlan(t *testing.T, m *Manager) LifecycleReconciliationPlan {
	t.Helper()
	plan, err := m.PreviewLifecycleReconciliation(context.Background(), LifecycleReconciliationRequest{})
	if err != nil {
		t.Fatalf("live reconciliation preview: %v", err)
	}
	return plan
}
func TestWorkflowLifecycleReconciliationRealClosedStageAndReplay(t *testing.T) {
	f, job := workflowReconciliationFixture(t)
	m := f.manager
	before := map[string][]byte{}
	for _, path := range []string{filepath.Join(m.root, job.ID+".json"), m.lifecycleReceiptPath(job.ID, "intent"), m.lifecycleReceiptPath(job.ID, "seal")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = data
	}
	original := m.TerminalError(job.ID)
	if original == nil || m.Snapshot().State != "failed" {
		t.Fatal("original failed outcome not retained")
	}
	// A refused Start must never replace the retained original owner witness.
	denied := workflowStoreReviewedPlan(t, m)
	if _, err := m.Start(denied.ID); !errors.Is(err, ErrWorkflowLifecyclePending) {
		t.Fatal("unacknowledged generation admitted replacement")
	}
	plan := workflowReconciliationPlan(t, m)
	if len(plan.Objects) != 1 || !historyHex(plan.ReviewRevision, 64) || plan.Resume {
		t.Fatal("review material missing")
	}
	receipt, err := m.ApplyLifecycleReconciliation(context.Background(), plan.ID)
	if err != nil {
		t.Fatalf("reviewed apply: %v", err)
	}
	if receipt.State != "completed" || receipt.Generation != job.ID || !reflect.DeepEqual(plan.Objects, receipt.Quarantined) {
		t.Fatal("receipt did not bind reviewed objects")
	}
	replay, err := m.ApplyLifecycleReconciliation(context.Background(), plan.ID)
	if err != nil || !reflect.DeepEqual(receipt, replay) {
		t.Fatal("replay did not return original immutable receipt")
	}
	fresh := workflowLifecycleFreshManager(f)
	read, err := fresh.ReadLifecycleReconciliationReceipt(context.Background(), plan.OperationID)
	if err != nil || !reflect.DeepEqual(read, receipt) {
		t.Fatalf("cross-manager receipt: %v", err)
	}
	for path, data := range before {
		now, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, now) {
			t.Fatal("reconciliation changed original job/intent/seal")
		}
	}
	if m.Snapshot().State != "failed" {
		t.Fatal("reconciliation rewrote failed execution")
	}
	lifecycle, err := fresh.LifecycleStatus(context.Background())
	if err != nil || lifecycle.AdmissionBlocked {
		t.Fatal("known original release not acknowledged")
	}
	next := workflowStoreReviewedPlan(t, fresh)
	if _, err = fresh.Start(next.ID); err != nil {
		t.Fatalf("confirmed finite maintenance did not restore admission: %v", err)
	}
	workflowLifecycleAwait(t, fresh)
	if _, err = fresh.ReadLifecycleReconciliationReceipt(context.Background(), plan.OperationID); err != nil {
		t.Fatal("new generation invalidated old exact receipt")
	}
}
func TestWorkflowLifecycleReconciliationDurableResumeAfterCanceledAttempt(t *testing.T) {
	f, _ := workflowReconciliationFixture(t)
	m := f.manager
	plan := workflowReconciliationPlan(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		lease, err := openWorkflowStoreLease(path)
		if err == nil && filepath.Base(path) == workflowTransactionLockName {
			cancel()
		}
		return lease, err
	}
	_, err := m.ApplyLifecycleReconciliation(ctx, plan.ID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled accepted maintenance result: %v", err)
	}
	if _, err = m.ReadLifecycleReconciliationReceipt(context.Background(), plan.OperationID); !errors.Is(err, ErrLifecycleReconciliationUnavailable) {
		t.Fatal("finished incomplete attempt reported indefinitely running")
	}
	fresh := workflowLifecycleFreshManager(f)
	status, err := fresh.LifecycleReconciliationStatus(context.Background())
	if err != nil || status.State != "pending" || !status.ResumeAvailable {
		t.Fatalf("safe finite resume unavailable: %v", err)
	}
	resume, err := fresh.PreviewLifecycleReconciliation(context.Background(), LifecycleReconciliationRequest{OperationID: plan.OperationID})
	if err != nil || !resume.Resume {
		t.Fatalf("durable explicit resume preview: %v", err)
	}
	other := workflowLifecycleFreshManager(f)
	again, err := other.PreviewLifecycleReconciliation(context.Background(), LifecycleReconciliationRequest{OperationID: plan.OperationID})
	if err != nil || again.ReviewRevision != resume.ReviewRevision {
		t.Fatal("cross-CLI review revision changed without material change")
	}
	receipt, err := fresh.ApplyLifecycleReconciliation(context.Background(), resume.ID)
	if err != nil || !reflect.DeepEqual(receipt.Quarantined, plan.Objects) {
		t.Fatalf("durable positive-proof resume failed: %v", err)
	}
}
func TestWorkflowLifecycleReconciliationIdenticalBytesReplacementRefused(t *testing.T) {
	f, _ := workflowReconciliationFixture(t)
	m := f.manager
	plan := workflowReconciliationPlan(t, m)
	m.mu.Lock()
	object := *m.releaseWitness.Ack.Write.Stage
	m.mu.Unlock()
	path := filepath.Join(m.storeRoot, workflowLifecycleDirectory, object.Name)
	old := path + ".preserved"
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(old)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.ApplyLifecycleReconciliation(context.Background(), plan.ID); !errors.Is(err, ErrLifecycleReconciliationConflict) {
		t.Fatal("same-byte different native object adopted")
	}
	if now, err := os.ReadFile(path); err != nil || !bytes.Equal(now, data) {
		t.Fatal("unrecognized replacement changed")
	}
}
func TestWorkflowLifecycleReconciliationUnknownExecutorsAndWritersProduceNoProof(t *testing.T) {
	for _, kind := range []string{"executor", "persistence", "writer"} {
		t.Run(kind, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			switch kind {
			case "executor":
				m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
					return json.RawMessage(`{"ok":true}`), nil
				}
			case "persistence":
				m.persist = func(path string, data []byte) error { return writeWorkflowDataFile(path, data) }
			case "writer":
				m.writeLifecycle = func(path string, data []byte, previous string) error {
					return writeWorkflowLifecycleFile(path, data, previous)
				}
			}
			job := f.start()
			workflowLifecycleAwait(t, m)
			if _, err := os.Lstat(m.lifecycleReceiptPath(job.ID, "ack")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unobserved source callback produced release ACK")
			}
			if _, err := m.PreviewLifecycleReconciliation(context.Background(), LifecycleReconciliationRequest{}); !errors.Is(err, ErrLifecycleReconciliationUnavailable) {
				t.Fatal("error absence supplied positive proof")
			}
		})
	}
}
func TestWorkflowLifecycleReconciliationShutdownJoinsAcceptedIO(t *testing.T) {
	f, _ := workflowReconciliationFixture(t)
	m := f.manager
	plan := workflowReconciliationPlan(t, m)
	entered, release := f.barrier()
	var once sync.Once
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		lease, err := openWorkflowStoreLease(path)
		if err == nil && filepath.Base(path) == workflowTransactionLockName {
			once.Do(func() { close(entered); release() })
		}
		return lease, err
	}
	result := make(chan error, 1)
	go func() { _, err := m.ApplyLifecycleReconciliation(context.Background(), plan.ID); result <- err }()
	workflowStoreUnitAwait(t, entered, "maintenance I/O did not enter")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := m.Shutdown(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Shutdown dropped accepted maintenance")
	}
	m.mu.Lock()
	done := m.maintenance.done
	m.mu.Unlock()
	if reconciliationDone(done) {
		t.Fatal("unresolved I/O fabricated completion")
	}
	f.unblockAll()
	workflowStoreUnitAwait(t, done, "maintenance did not drain")
	applyErr := <-result
	if !errors.Is(applyErr, context.Canceled) {
		t.Fatalf("maintenance cancellation disappeared: %v", applyErr)
	}
	if err = m.Shutdown(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal("shared shutdown lost maintenance terminal cause")
	}
}

func TestWorkflowLifecycleReconciliationResumeRejectsCandidateSubstitutionAndUnknownStages(t *testing.T) {
	for _, kind := range []string{"candidate-replaced", "unknown-stage", "receipt-corrupt"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := workflowReconciliationFixture(t)
			m := f.manager
			plan := workflowReconciliationPlan(t, m)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m.openStoreLease = func(path string) (workflowStoreLease, error) {
				lease, err := openWorkflowStoreLease(path)
				if err == nil && filepath.Base(path) == workflowTransactionLockName {
					cancel()
				}
				return lease, err
			}
			if _, err := m.ApplyLifecycleReconciliation(ctx, plan.ID); !errors.Is(err, context.Canceled) {
				t.Fatal("finite maintenance interruption unavailable")
			}
			opDir := m.reconciliationPath(plan.OperationID, "")
			switch kind {
			case "candidate-replaced":
				path := filepath.Join(opDir, "ack-candidate.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(path, filepath.Join(f.root, "preserved-candidate")); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-stage":
				if err := os.WriteFile(filepath.Join(opDir, ".lifecycle-unknown.tmp"), []byte("unconfirmed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-corrupt":
				if err := os.WriteFile(filepath.Join(opDir, "receipt.json"), []byte(`{"state":"completed"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fresh := workflowLifecycleFreshManager(f)
			if _, err := fresh.PreviewLifecycleReconciliation(context.Background(), LifecycleReconciliationRequest{OperationID: plan.OperationID}); err == nil {
				t.Fatal("unrecognized/replaced metadata supplied restart proof")
			}
			if _, err := fresh.ReadLifecycleReconciliationReceipt(context.Background(), plan.OperationID); err == nil || errors.Is(err, ErrLifecycleReconciliationPending) {
				t.Fatal("finished malformed evidence reported success or live pending")
			}
		})
	}
}
func TestWorkflowLifecycleReconciliationNoInitAndNoCrashedOwnerInference(t *testing.T) {
	parent := t.TempDir()
	absent := filepath.Join(parent, "absent")
	m := New(absent)
	status, err := m.LifecycleReconciliationStatus(context.Background())
	if err != nil || status.State != "none" {
		t.Fatal("empty read-only status changed")
	}
	if _, err = os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only status initialized store")
	}
	f, job := workflowReconciliationFixture(t)
	fresh := workflowLifecycleFreshManager(f)
	if _, err = fresh.PreviewLifecycleReconciliation(context.Background(), LifecycleReconciliationRequest{Generation: job.ID}); !errors.Is(err, ErrLifecycleReconciliationUnavailable) {
		t.Fatal("free lock/missing ACK invented original-owner witness")
	}
}
func TestWorkflowLifecycleReconciliationExpirationAndFreshGrantBeforeEffects(t *testing.T) {
	f, _ := workflowReconciliationFixture(t)
	m := f.manager
	plan := workflowReconciliationPlan(t, m)
	m.mu.Lock()
	m.reconciliationPlans[plan.ID].Public.ExpiresAt = time.Now().Add(-time.Second)
	m.mu.Unlock()
	if _, err := m.ApplyLifecycleReconciliation(context.Background(), plan.ID); !errors.Is(err, ErrLifecycleReconciliationExpired) {
		t.Fatal("expired review executed")
	}
	plan = workflowReconciliationPlan(t, m)
	m.guard = managed.NewGuard(func() (*managed.Authority, error) { return nil, errors.New("PRIVATE_NEW_POLICY_FAILURE") })
	if _, err := m.ApplyLifecycleReconciliation(context.Background(), plan.ID); err == nil {
		t.Fatal("apply inherited preview grant without fresh authorization")
	}
	if _, err := os.Lstat(filepath.Join(m.storeRoot, reconciliationDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unauthorized/expired review wrote maintenance metadata")
	}
}

func TestWorkflowLifecycleReconciliationWorkflowCancelDoesNotCancelMaintenance(t *testing.T) {
	f, _ := workflowReconciliationFixture(t)
	m := f.manager
	plan := workflowReconciliationPlan(t, m)
	entered, release := f.barrier()
	var once sync.Once
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		lease, err := openWorkflowStoreLease(path)
		if err == nil && filepath.Base(path) == workflowTransactionLockName {
			once.Do(func() { close(entered); release() })
		}
		return lease, err
	}
	result := make(chan error, 1)
	go func() { _, err := m.ApplyLifecycleReconciliation(context.Background(), plan.ID); result <- err }()
	workflowStoreUnitAwait(t, entered, "maintenance did not reach owned I/O")
	m.Cancel()
	m.mu.Lock()
	done := m.maintenance.done
	m.mu.Unlock()
	if reconciliationDone(done) {
		t.Fatal("workflow control abandoned maintenance I/O")
	}
	f.unblockAll()
	workflowStoreUnitAwait(t, done, "reviewed metadata operation did not drain")
	if err := <-result; err != nil {
		t.Fatalf("workflow cancel crossed into independent maintenance: %v", err)
	}
}

func TestWorkflowLifecycleReconciliationSameManagerRetryPreservesDurableIntent(t *testing.T) {
	f, _ := workflowReconciliationFixture(t)
	m := f.manager
	plan := workflowReconciliationPlan(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		lease, err := openWorkflowStoreLease(path)
		if err == nil && filepath.Base(path) == workflowTransactionLockName {
			cancel()
		}
		return lease, err
	}
	if _, err := m.ApplyLifecycleReconciliation(ctx, plan.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("first accepted attempt did not cancel")
	}
	intentPath := m.reconciliationPath(plan.OperationID, "intent.json")
	before, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	m.openStoreLease = nil
	if _, err = m.ApplyLifecycleReconciliation(context.Background(), plan.ID); err != nil {
		t.Fatalf("known same-plan resume failed: %v", err)
	}
	after, err := os.ReadFile(intentPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("same-plan resume overwrote durable intent")
	}
	entries, err := os.ReadDir(m.reconciliationPath(plan.OperationID, ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".lifecycle-") {
			t.Fatal("idempotent retry accumulated failed stages")
		}
	}
}
func TestWorkflowLifecycleReconciliationReceiptWaitsForFinalOwnedClose(t *testing.T) {
	f, _ := workflowReconciliationFixture(t)
	m := f.manager
	plan := workflowReconciliationPlan(t, m)
	entered, release := f.barrier()
	count := 0
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		lease, err := openWorkflowStoreLease(path)
		if err != nil || filepath.Base(path) != workflowTransactionLockName {
			return lease, err
		}
		count++
		if count != 2 {
			return lease, nil
		}
		return &workflowStoreUnitLease{close: func() error { err := lease.Close(); close(entered); release(); return err }}, nil
	}
	result := make(chan error, 1)
	go func() { _, err := m.ApplyLifecycleReconciliation(context.Background(), plan.ID); result <- err }()
	workflowStoreUnitAwait(t, entered, "final actual Close did not enter")
	if _, err := os.Lstat(m.reconciliationPath(plan.OperationID, "receipt.json")); err != nil {
		t.Fatal("fixture did not reach published receipt boundary")
	}
	if _, err := m.ReadLifecycleReconciliationReceipt(context.Background(), plan.OperationID); !errors.Is(err, ErrLifecycleReconciliationPending) {
		t.Fatal("receipt escaped while accepted operation still owned I/O")
	}
	f.unblockAll()
	m.mu.Lock()
	done := m.maintenance.done
	m.mu.Unlock()
	workflowStoreUnitAwait(t, done, "final owned Close did not drain")
	if err := <-result; err != nil {
		t.Fatal("confirmed final Close failed")
	}
	if _, err := m.ReadLifecycleReconciliationReceipt(context.Background(), plan.OperationID); err != nil {
		t.Fatal("terminal receipt unavailable")
	}
}

func TestWorkflowLifecycleReconciliationWriterDoesNotAdoptChangedClosedStage(t *testing.T) {
	dir := t.TempDir()
	original := []byte("source intended ACK metadata")
	changed := []byte("modified foreign closed bytes")
	var stagePath string
	observation := writeLifecycleObserved(filepath.Join(dir, "ack.json"), original, "", func(stage, target, previous string) error {
		stagePath = stage
		file, err := os.OpenFile(stage, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		n, writeErr := file.Write(changed)
		syncErr := file.Sync()
		closeErr := file.Close()
		if n != len(changed) {
			writeErr = errors.Join(writeErr, errors.New("fixture short write"))
		}
		return errors.Join(errors.New("publication refused"), writeErr, syncErr, closeErr)
	})
	if observation.Known || observation.Stage != nil || !errors.Is(observation.Err, ErrLifecycleReconciliationConflict) {
		t.Fatal("actual writer adopted changed stage payload as its own positive proof")
	}
	data, err := os.ReadFile(stagePath)
	if err != nil || !bytes.Equal(data, changed) {
		t.Fatal("unknown modified evidence was not preserved")
	}
}
