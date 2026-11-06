package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/profile"
)

func workflowLifecycleFreshManager(f *workflowShutdownFixture) *Manager {
	manager := NewWithGuard(f.root, f.manager.guard)
	manager.platform = "windows"
	manager.requireAdmin = func() error { return nil }
	manager.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		return json.RawMessage(`{"fixture":true}`), nil
	}
	// Registered after the primary fixture cleanup, so every secondary owner
	// drains first. A failed assertion must never let primary RemoveAll race
	// a still-unconfirmed generation sharing the same storage root.
	f.t.Cleanup(func() {
		manager.Cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_ = manager.Shutdown(ctx) // Expected terminal errors are checked by cases.
		cancel()
		if done := workflowShutdownDone(manager); done != nil {
			select {
			case <-done:
			default:
				f.preserve = true
				f.t.Error("secondary workflow completion unconfirmed; fixture preserved")
			}
		}
	})
	return manager
}
func workflowLifecycleReadCurrent(t *testing.T, m *Manager) workflowLifecycleReceipt {
	t.Helper()
	pointer, receipt, err := m.readWorkflowLifecycleCurrent(context.Background())
	if err != nil || pointer == nil {
		t.Fatal("local lifecycle chain unavailable")
	}
	return receipt
}
func workflowLifecycleAwait(t *testing.T, m *Manager) {
	t.Helper()
	workflowStoreUnitAwait(t, m.done, "local lifecycle completion did not join")
}

func TestWorkflowLifecycleStatusNeverInitializesStore(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "absent")
	status, err := New(path).LifecycleStatus(context.Background())
	if err != nil || status.State != "none" || status.AdmissionBlocked || status.Protection != "retirement-unavailable" {
		t.Fatal("empty local lifecycle status changed")
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only lifecycle initialized storage")
	}
}

func TestWorkflowLifecycleIntentPrecedesJobAndWorkdir(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	var persisted atomic.Int32
	m.persist = func(path string, b []byte) error {
		receipt := workflowLifecycleReadCurrent(t, m)
		if receipt.Seal != nil || receipt.Ack != nil {
			t.Fatal("admission intent already appeared terminal")
		}
		if persisted.Add(1) == 1 {
			if _, err := os.Lstat(filepath.Join(m.root, receipt.Intent.Generation)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("workdir preceded durable intent")
			}
		}
		return profile.AtomicWrite(path, b)
	}
	m.execute = func(_ context.Context, path string, _ Request) (json.RawMessage, error) {
		if err := os.Mkdir(path, 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(path, "owned.bin"), []byte("retained owned bytes"), 0600); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"fixture":true}`), nil
	}
	job := f.start()
	workflowLifecycleAwait(t, m)
	receipt := workflowLifecycleReadCurrent(t, m)
	if receipt.Intent.Generation != job.ID || receipt.Seal == nil || receipt.Ack == nil || !receipt.Ack.LocalOwnersReleased || !receipt.Seal.LocalReleasePermitted {
		t.Fatal("local release chain was not completed")
	}
	record, err := os.ReadFile(filepath.Join(m.root, job.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Seal.RecordSHA256 != workflowLifecycleHash(record) || receipt.SealSHA256 != workflowLifecycleJSONHash(*receipt.Seal) || receipt.Ack.SealSHA256 != receipt.SealSHA256 {
		t.Fatal("seal did not bind actual record and acknowledgement")
	}
	manifest := receipt.Seal.Manifest
	if manifest.Classification != "observed" || manifest.Count != 1 || manifest.LogicalBytes != int64(len("retained owned bytes")) || !historyHex(manifest.SHA256, 64) || receipt.Seal.Protection != "retirement-unavailable" {
		t.Fatal("actual artifact observation or protection was lost")
	}
	var total int64
	for _, phase := range []string{"intent", "seal", "ack"} {
		info, err := os.Stat(m.lifecycleReceiptPath(job.ID, phase))
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > workflowLifecycleMaxReceiptBytes {
		t.Fatal("generation metadata exceeded aggregate cap")
	}
	fresh := workflowLifecycleFreshManager(f)
	plan := workflowStoreReviewedPlan(t, fresh)
	if _, err = fresh.Start(plan.ID); err != nil {
		t.Fatal("validated local release did not permit next admission")
	}
	workflowLifecycleAwait(t, fresh)
}

func TestWorkflowLifecycleFailedExecutionCanAcknowledgeKnownLocalRelease(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause := errors.New("owned execution failure")
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) { return nil, cause }
	job := f.start()
	workflowLifecycleAwait(t, m)
	receipt := workflowLifecycleReadCurrent(t, m)
	if m.Snapshot().State != "failed" || !errors.Is(m.TerminalError(job.ID), cause) || receipt.Ack == nil || receipt.Seal.Protection != "retirement-unavailable" {
		t.Fatal("failed execution was confused with unknown local cleanup")
	}
	fresh := workflowLifecycleFreshManager(f)
	plan := workflowStoreReviewedPlan(t, fresh)
	if _, err := fresh.Start(plan.ID); err != nil {
		t.Fatal("ordinary confirmed local failure permanently blocked storage")
	}
	workflowLifecycleAwait(t, fresh)
}

func TestWorkflowLifecycleCleanupUncertaintyBlocksNewGenerationAndPreservesReads(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause := errors.New("PRIVATE_CLEANUP_CAUSE")
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		return nil, workflowFailure(ErrWorkflowCleanup, cause)
	}
	job := f.start()
	workflowLifecycleAwait(t, m)
	receipt := workflowLifecycleReadCurrent(t, m)
	if receipt.Seal == nil || receipt.Seal.LocalReleasePermitted || receipt.Ack != nil || !errors.Is(m.TerminalError(job.ID), cause) {
		t.Fatal("uncertain local cleanup was acknowledged")
	}
	fresh := workflowLifecycleFreshManager(f)
	var executed atomic.Bool
	fresh.execute = func(context.Context, string, Request) (json.RawMessage, error) { executed.Store(true); return nil, nil }
	plan := workflowStoreReviewedPlan(t, fresh)
	_, err := fresh.Start(plan.ID)
	if !errors.Is(err, ErrWorkflowLifecyclePending) || !errors.Is(err, ErrWorkflowAdmission) || executed.Load() || strings.Contains(err.Error(), "PRIVATE_") {
		t.Fatal("unresolved intent did not privately refuse new execution")
	}
	inventory, err := fresh.CaptureHistoryInventory(context.Background())
	if err != nil || inventory.Count != 1 {
		t.Fatal("uncertain lifecycle blocked read-only evidence inventory")
	}
	page, err := fresh.HistoryPage(context.Background(), HistoryPageQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("uncertain lifecycle hid retained evidence")
	}
	raw, err := fresh.ReadHistoryRecordRaw(context.Background(), page.Items[0].RecordRef, page.Items[0].Revision)
	if err != nil || len(raw) == 0 {
		t.Fatal("uncertain lifecycle blocked exact raw export")
	}
}

func TestWorkflowLifecycleCloseAcknowledgementGapRefusesWithoutAnotherIntent(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	entered, release := f.barrier()
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		lease, err := openWorkflowStoreLease(path)
		if err != nil || filepath.Base(path) != workflowActiveLockName {
			return lease, err
		}
		return &workflowStoreUnitLease{close: func() error { err := lease.Close(); close(entered); release(); return err }}, nil
	}
	f.start()
	workflowStoreUnitAwait(t, entered, "local active owner did not reach acknowledged-release gap")
	fresh := workflowLifecycleFreshManager(f)
	plan := workflowStoreReviewedPlan(t, fresh)
	_, err := fresh.Start(plan.ID)
	if !errors.Is(err, ErrWorkflowLifecyclePending) {
		t.Fatal("new owner entered between Close and acknowledgement")
	}
	if _, err = os.Lstat(fresh.lifecycleReceiptPath(plan.ID, "intent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused gap admission wrote another intent")
	}
	f.unblockAll()
	workflowLifecycleAwait(t, m)
	if _, err = fresh.Start(plan.ID); err != nil {
		t.Fatal("known local acknowledgement did not unblock reviewed retry")
	}
	workflowLifecycleAwait(t, fresh)
}

func TestWorkflowLifecycleOrphanPointerAndFailedAckRemainBlocking(t *testing.T) {
	for _, phase := range []string{"pointer", "ack"} {
		t.Run(phase, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			cause := errors.New("PRIVATE_METADATA_CAUSE")
			m.writeLifecycle = func(path string, b []byte, previous string) error {
				if phase == "pointer" && filepath.Base(path) == workflowLifecycleCurrent || phase == "ack" && strings.HasSuffix(path, ".ack.json") {
					return cause
				}
				return writeWorkflowLifecycleFile(path, b, previous)
			}
			plan := f.plan()
			_, err := m.Start(plan.ID)
			if phase == "pointer" {
				if !errors.Is(err, cause) || !errors.Is(err, ErrWorkflowLifecycle) {
					t.Fatal("pointer failure lost fixed/private cause")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				workflowLifecycleAwait(t, m)
				if !errors.Is(m.TerminalError(plan.ID), cause) {
					t.Fatal("acknowledgement failure disappeared")
				}
			}
			fresh := workflowLifecycleFreshManager(f)
			status, statusErr := fresh.LifecycleStatus(context.Background())
			if !status.AdmissionBlocked || phase == "pointer" && !errors.Is(statusErr, ErrWorkflowLifecyclePending) {
				t.Fatal("orphan/current incomplete chain appeared released")
			}
			next := workflowStoreReviewedPlan(t, fresh)
			_, err = fresh.Start(next.ID)
			if !errors.Is(err, ErrWorkflowLifecyclePending) {
				t.Fatal("incomplete immutable evidence did not block admission")
			}
			if _, err = os.Lstat(fresh.lifecycleReceiptPath(next.ID, "intent")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("blocked admission multiplied metadata")
			}
		})
	}
}

func TestWorkflowLifecycleUnknownManifestDoesNotInventUncertainOwners(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	m.execute = func(_ context.Context, path string, _ Request) (json.RawMessage, error) {
		for depth := 0; depth < workflowLifecycleManifestDepth+2; depth++ {
			if err := os.Mkdir(path, 0700); err != nil {
				return nil, err
			}
			path = filepath.Join(path, "owned")
		}
		return json.RawMessage(`{"fixture":true}`), nil
	}
	f.start()
	workflowLifecycleAwait(t, m)
	receipt := workflowLifecycleReadCurrent(t, m)
	if receipt.Seal.Manifest.Classification != "unknown" || receipt.Seal.Manifest.SHA256 != "" || receipt.Seal.Manifest.Count != 0 || receipt.Ack == nil || m.TerminalError(m.Snapshot().ID) != nil {
		t.Fatal("bounded unknown manifest was truncated or confused with owner uncertainty")
	}
}

func TestWorkflowLifecycleUnknownMetadataIsNeverOverwritten(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	dir := filepath.Join(f.root, workflowLifecycleDirectory)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".lifecycle-owned-unknown.tmp")
	before := []byte("retained uncertain metadata")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := m.Start(f.plan().ID)
	if !errors.Is(err, ErrWorkflowLifecyclePending) {
		t.Fatal("unknown metadata did not block admission")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unknown metadata was changed or deleted")
	}
}

func TestWorkflowLifecycleInitialPersistenceRetainsExactReturnCause(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause := errors.New("owned initial persistence failure")
	m.persist = func(string, []byte) error { return cause }
	plan := f.plan()
	_, err := m.Start(plan.ID)
	if err != cause || !errors.Is(m.TerminalError(plan.ID), cause) {
		t.Fatal("initial persistence lost exact legacy return identity")
	}
	receipt := workflowLifecycleReadCurrent(t, m)
	if receipt.Seal == nil || receipt.Seal.RecordState != "unavailable" || receipt.Ack != nil {
		t.Fatal("missing durable record was falsely acknowledged")
	}
}

func TestWorkflowLifecycleImmutablePublicationNeverOverwritesUnknownDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.intent.json")
	before := []byte("retained unknown destination")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	err := writeWorkflowLifecycleFile(path, []byte(`{"version":1}`), "")
	if !errors.Is(err, os.ErrExist) {
		t.Fatal("immutable publication did not exclusively refuse existing destination")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("immutable publication changed unknown destination")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("uncertain metadata stage was not preserved")
	}
	absent := filepath.Join(dir, "over-limit.json")
	if err := writeWorkflowLifecycleFile(absent, make([]byte, workflowLifecycleMaxReceiptBytes+1), ""); !errors.Is(err, ErrWorkflowLifecycle) {
		t.Fatal("oversized lifecycle metadata was admitted")
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("metadata byte cap was checked after destination creation")
	}
}

func TestWorkflowLifecycleResultUncertaintyRetainsCofailureAndRefusesAcknowledgement(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause := errors.New("owned execution cofailure")
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		return json.RawMessage(`{"incomplete":`), cause
	}
	job := f.start()
	workflowLifecycleAwait(t, m)
	receipt := workflowLifecycleReadCurrent(t, m)
	terminal := m.TerminalError(job.ID)
	if receipt.Seal == nil || receipt.Ack != nil || receipt.Seal.LocalReleasePermitted || !errors.Is(terminal, cause) || !errors.Is(terminal, ErrWorkflowExecution) || !errors.Is(terminal, ErrWorkflowResult) || !errors.Is(terminal, ErrWorkflowLifecyclePending) {
		t.Fatal("result uncertainty erased a cofailure or claimed known local release")
	}
	status, err := m.LifecycleStatus(context.Background())
	if err != nil || status.State != "sealed" || !status.AdmissionBlocked {
		t.Fatal("result uncertainty status was not retained")
	}
}

func TestWorkflowLifecycleCancellationAfterPublicationBoundaryDrainsRealOutcome(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "finish-publication", true: "retain-io-cofailure"}[failWrite], func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			entered, release := f.barrier()
			cause := errors.New("owned lifecycle publication failure")
			var executed atomic.Bool
			m.execute = func(context.Context, string, Request) (json.RawMessage, error) { executed.Store(true); return nil, nil }
			m.writeLifecycle = func(path string, b []byte, previous string) error {
				if strings.HasSuffix(path, ".intent.json") {
					close(entered)
					release()
					if failWrite {
						return cause
					}
				}
				return writeWorkflowLifecycleFile(path, b, previous)
			}
			result, started := f.startAsync(f.plan())
			workflowStoreUnitAwait(t, entered, "source intent publication did not enter owned boundary")
			m.Cancel()
			select {
			case <-m.done:
				t.Fatal("cancel abandoned in-flight publication")
			default:
			}
			f.unblockAll()
			workflowStoreUnitAwait(t, started, "source publication did not join")
			startErr := <-result
			workflowLifecycleAwait(t, m)
			terminal := m.TerminalError(m.Snapshot().ID)
			if executed.Load() {
				t.Fatal("canceled source publication executed a native workflow")
			}
			if failWrite {
				if !errors.Is(startErr, cause) || !errors.Is(terminal, cause) || !errors.Is(terminal, context.Canceled) || !errors.Is(terminal, ErrWorkflowLifecycle) {
					t.Fatal("publication I/O cofailure was normalized into cooperative cancellation")
				}
			} else {
				receipt := workflowLifecycleReadCurrent(t, m)
				if startErr != nil || terminal != nil || receipt.Ack == nil {
					t.Fatal("accepted publication did not finish durable canceled local closure")
				}
			}
		})
	}
}
