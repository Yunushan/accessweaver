package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Yunushan/accessweaver/internal/privatefile"
)

func TestWorkflowControllerStorageStatusDoesNotInitialize(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	status, err := New(root).ControllerStorageStatus(context.Background())
	if err != nil || status.State != "uninitialized" || status.Scope != "tracked-controller-evidence-only" || status.LegacyAccounting != "not-included" || status.AggregateQuotaEnforced || status.PhysicalCapacityGuaranteed || status.NativeWritersContained || status.WorkerJournalBounded {
		t.Fatal("read-only controller storage projection changed")
	}
	if _, err = os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("controller status initialized storage")
	}
}

// Failures delegate to a real source-owned File first. No fake successful
// Close/Sync is used to manufacture source ownership observations.
type controllerFaultFile struct {
	*os.File
	fault  string
	cause  error
	writes *atomic.Int32
}

func (f *controllerFaultFile) Write(b []byte) (int, error) {
	f.writes.Add(1)
	if f.fault == "write" {
		n, err := f.File.Write(b[:1])
		return n, errors.Join(err, f.cause)
	}
	return f.File.Write(b)
}
func (f *controllerFaultFile) Sync() error {
	err := f.File.Sync()
	if f.fault == "sync" {
		return errors.Join(err, f.cause)
	}
	return err
}
func (f *controllerFaultFile) Close() error {
	err := f.File.Close()
	if f.fault == "close" {
		return errors.Join(err, f.cause)
	}
	return err
}

func TestWorkflowControllerStorageCountBeforeWriteAndPreserveFaults(t *testing.T) {
	for _, kind := range []string{"capacity", "write", "sync", "close", "publication", "complete"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "request.json")
			data := []byte("controller-private-fixture")
			fault := errors.New("source-owned storage fault")
			var writes atomic.Int32
			opened := 0
			stage := ""
			hooks := &controllerSnapshotHooks{open: func(dir, pattern string) (controllerSnapshotFile, error) {
				opened++
				f, err := privatefile.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				stage = f.Name()
				return &controllerFaultFile{f, kind, fault, &writes}, nil
			}}
			if kind == "publication" {
				hooks.afterClosed = func(string, string) error { return fault }
			}
			allowance := int64(len(data))
			if kind == "capacity" {
				allowance--
			}
			err := writeControllerSnapshotObserved(path, data, allowance, hooks)
			if kind == "capacity" {
				if !errors.Is(err, ErrWorkflowStorageCapacity) || opened != 0 || writes.Load() != 0 {
					t.Fatal("capacity overflow reached a physical writer")
				}
				return
			}
			if kind == "complete" {
				body, e := os.ReadFile(path)
				if err != nil || e != nil || !bytes.Equal(body, data) {
					t.Fatal("counted snapshot did not publish complete bytes")
				}
				if _, e = os.Lstat(stage); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("successful source stage remained")
				}
				return
			}
			if !errors.Is(err, fault) || writes.Load() != 1 {
				t.Fatal("actual writer failure lost its cause")
			}
			if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("uncertain writer promoted a destination")
			}
			if info, e := os.Lstat(stage); e != nil || !info.Mode().IsRegular() {
				t.Fatal("failed source stage was discarded")
			}
		})
	}
}

func TestWorkflowControllerStorageNoReplaceOrUnknownCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.json")
	original := []byte("retained-source-evidence")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal("fixture unavailable")
	}
	if err := writeControllerSnapshot(path, []byte("replacement"), 64); !errors.Is(err, ErrWorkflowStoragePending) {
		t.Fatal("existing snapshot was adopted")
	}
	if body, err := os.ReadFile(path); err != nil || !bytes.Equal(body, original) {
		t.Fatal("existing destination changed")
	}
	fresh := filepath.Join(dir, "workflow.ps1")
	var retained string
	hooks := &controllerSnapshotHooks{afterClosed: func(stage, _ string) error {
		retained = stage
		return os.WriteFile(stage, []byte("unexpected-same-sized-data"), 0600)
	}}
	if err := writeControllerSnapshotObserved(fresh, []byte("controller-original-value"), 64, hooks); !errors.Is(err, ErrWorkflowStoragePending) {
		t.Fatal("changed closed stage was promoted")
	}
	if _, err := os.Lstat(retained); err != nil {
		t.Fatal("unknown changed stage was deleted")
	}
}

func TestWorkflowControllerStorageRoleCreditsCannotBorrowFinalization(t *testing.T) {
	p := &preparedWorkflowInput{Script: []byte("script"), Input: []byte("request")}
	initial := []byte("initial")
	roles, err := controllerStoragePlan(p, initial)
	if err != nil {
		t.Fatal("role plan unavailable")
	}
	b := &controllerStorageBudget{reservation: controllerStorageReservation{Roles: roles, ScriptSHA256: workflowLifecycleHash(p.Script), InputSHA256: workflowLifecycleHash(p.Input)}}
	if _, err = b.chargeSnapshot("script", append(p.Script, '!')); !errors.Is(err, ErrWorkflowStorageCapacity) {
		t.Fatal("script exceeded its immutable allocation")
	}
	if _, err = b.chargeSnapshot("script", p.Script); err != nil {
		t.Fatal("valid script credit unavailable")
	}
	if _, err = b.chargeSnapshot("script", p.Script); !errors.Is(err, ErrWorkflowStorageCapacity) {
		t.Fatal("script allocation was reusable")
	}
	if err = b.chargeRecord(append(initial, '!')); !errors.Is(err, ErrWorkflowStorageCapacity) {
		t.Fatal("initial record borrowed terminal credit")
	}
	if err = b.chargeRecord(initial); err != nil {
		t.Fatal("initial credit unavailable")
	}
	if err = b.chargeRecord([]byte("terminal")); err != nil {
		t.Fatal("independent terminal credit unavailable")
	}
	if err = b.chargeRecord([]byte("retry")); !errors.Is(err, ErrWorkflowStorageCapacity) {
		t.Fatal("automatic second terminal attempt admitted")
	}
}

func TestWorkflowControllerStorageReservationPrecedesIntentAndCancellationDrains(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	var seen atomic.Bool
	m.controllerStorageHooks = &controllerStorageHooks{afterReserved: func() {
		m.mu.Lock()
		b := m.controllerBudget
		m.mu.Unlock()
		if b == nil {
			t.Error("reservation missing before intent")
			return
		}
		if _, err := os.Lstat(m.lifecycleReceiptPath(b.reservation.Generation, "intent")); !errors.Is(err, os.ErrNotExist) {
			t.Error("intent preceded controller reservation")
		}
		if _, err := os.Lstat(filepath.Join(m.root, b.reservation.Generation)); !errors.Is(err, os.ErrNotExist) {
			t.Error("workdir preceded controller reservation")
		}
		p, err := m.readControllerPointer(context.Background())
		if err != nil || p == nil || p.digest() != b.binding.digest() {
			t.Error("reservation was not physically published")
		}
		seen.Store(true)
		m.Cancel()
	}}
	job := f.start()
	workflowLifecycleAwait(t, m)
	if !seen.Load() || m.Snapshot().State != "failed" {
		t.Fatal("post-reservation cancellation did not preserve original failure")
	}
	status, err := m.ControllerStorageStatus(context.Background())
	if err != nil || status.State != "tracked" || status.Generation != job.ID || status.ReservedBytes != 0 || status.UncertainBytes != 0 || status.RetainedChargeBytes == 0 {
		t.Fatal("known never-called cancellation failed to release linked commitment")
	}
}

func TestWorkflowControllerStorageRetainedChainAcrossManagersAndReplacementRefusal(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	job := f.start()
	workflowLifecycleAwait(t, f.manager)
	first, err := f.manager.ControllerStorageStatus(context.Background())
	if err != nil || first.State != "tracked" || first.GenerationsTracked != 1 {
		t.Fatal("initial retained controller charge unavailable")
	}
	fresh := workflowLifecycleFreshManager(f)
	plan, err := fresh.Preview(Request{Action: "discover"})
	if err != nil {
		t.Fatal("fresh preview unavailable")
	}
	if _, err = fresh.Start(plan.ID); err != nil {
		t.Fatal("released controller chain prevented fresh admission")
	}
	workflowLifecycleAwait(t, fresh)
	second, err := fresh.ControllerStorageStatus(context.Background())
	if err != nil || second.GenerationsTracked != 2 || second.RetainedChargeBytes <= first.RetainedChargeBytes {
		t.Fatal("cross-manager retained commitments were reset")
	}
	// Replace the immutable reservation with byte-identical newly created data.
	// Persisted native ID is a conflict detector, never proof of owner release.
	path := fresh.controllerStoragePath(plan.ID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("source reservation unavailable")
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal("fixture binding unavailable")
	}
	original, err := held.Stat()
	if err != nil {
		_ = held.Close()
		t.Fatal("fixture binding unavailable")
	}
	_ = os.SameFile(original, original)
	if err = held.Close(); err != nil {
		f.preserve = true
		t.Fatal("fixture close unconfirmed")
	}
	moved := path + ".retained"
	if err = os.Rename(path, moved); err != nil {
		t.Fatal("fixture replacement unavailable")
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("fixture replacement unavailable")
	}
	if _, err = fresh.ControllerStorageStatus(context.Background()); !errors.Is(err, ErrWorkflowStoragePending) {
		t.Fatal("same-bytes replaced reservation gained source authority")
	}
	if body, e := os.ReadFile(filepath.Join(f.manager.root, job.ID+".json")); e != nil || len(body) == 0 {
		t.Fatal("prior evidence was unavailable")
	}
}

func TestWorkflowControllerStorageCanonicalControlsAndUnknownNames(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	f.start()
	workflowLifecycleAwait(t, f.manager)
	pointer, err := os.ReadFile(filepath.Join(f.root, controllerStorageCurrent))
	if err != nil {
		t.Fatal("source pointer unavailable")
	}
	var p controllerStoragePointer
	if json.Unmarshal(pointer, &p) != nil {
		t.Fatal("source pointer invalid")
	}
	malformed := append([]byte(" "), pointer...)
	if err = os.WriteFile(filepath.Join(f.root, controllerStorageCurrent), malformed, 0600); err != nil {
		t.Fatal("fixture unavailable")
	}
	if _, err = f.manager.ControllerStorageStatus(context.Background()); !errors.Is(err, ErrWorkflowStoragePending) {
		t.Fatal("noncanonical controller pointer accepted")
	}
}

func TestWorkflowControllerStorageCrashPreservesReservationAndBlocksFreshGrowth(t *testing.T) {
	f := newWorkflowStoreSourceFixture(t)
	f.launch("storage-reservation")
	m, _ := f.manager()
	status, err := m.ControllerStorageStatus(context.Background())
	if !errors.Is(err, ErrWorkflowStoragePending) || status.State != "pending" || status.UncertainBytes == 0 {
		t.Fatal("unpublished lifecycle reservation was not pending")
	}
	if !f.finishChild(true) {
		t.Fatal("source reservation child was not reaped")
	}
	dir := filepath.Join(f.root, controllerStorageDirectory)
	before, err := os.ReadDir(dir)
	if err != nil || len(before) != 1 {
		t.Fatal("source crash reservation unavailable")
	}
	known := filepath.Join(dir, before[0].Name())
	bytesBefore, err := os.ReadFile(known)
	if err != nil {
		t.Fatal("source evidence unavailable")
	}
	for attempt := 0; attempt < 4; attempt++ {
		fresh, calls := f.manager()
		p, err := fresh.Preview(Request{Action: "discover"})
		if err != nil {
			t.Fatal("fresh preview unavailable")
		}
		_, err = fresh.Start(p.ID)
		if !errors.Is(err, ErrWorkflowStoragePending) || calls.Load() != 0 {
			t.Fatal("free OS lease authorized unknown crashed reservation")
		}
	}
	after, err := os.ReadDir(dir)
	if err != nil || len(after) != 1 {
		t.Fatal("failed captures accumulated controller stages")
	}
	if actual, err := os.ReadFile(known); err != nil || !bytes.Equal(actual, bytesBefore) {
		t.Fatal("crashed reservation evidence changed")
	}
}

var _ io.Writer = (*controllerFaultFile)(nil)

func TestWorkflowControllerStorageStatusDetectsPhysicallyClosedOrphan(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	first := f.start()
	workflowLifecycleAwait(t, f.manager)
	pointerPath := filepath.Join(f.root, controllerStorageCurrent)
	oldPointer, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal("source pointer unavailable")
	}
	oldRecord, err := os.ReadFile(filepath.Join(f.manager.root, first.ID+".json"))
	if err != nil {
		t.Fatal("source evidence unavailable")
	}
	cause := errors.New("PRIVATE_CONTROLLER_POINTER_PUBLICATION_FAILURE")
	f.manager.controllerStorageHooks = &controllerStorageHooks{beforePublish: func(stage, target string) error {
		if filepath.Base(target) == controllerStorageCurrent {
			return cause
		}
		return nil
	}}
	p := f.plan()
	_, err = f.manager.Start(p.ID)
	if !errors.Is(err, cause) || !errors.Is(err, ErrWorkflowStoragePending) {
		t.Fatal("physical pointer publication failure was lost")
	}
	// The next immutable reservation was actually written/synced/closed, while
	// the current pointer deliberately still denotes an older released owner.
	if _, err = os.Lstat(f.manager.controllerStoragePath(p.ID)); err != nil {
		t.Fatal("actual closed orphan was discarded")
	}
	status, err := f.manager.ControllerStorageStatus(context.Background())
	if !errors.Is(err, ErrWorkflowStoragePending) || status.State != "pending" {
		t.Fatal("old released pointer concealed new orphan")
	}
	if now, e := os.ReadFile(pointerPath); e != nil || !bytes.Equal(now, oldPointer) {
		t.Fatal("failed pointer publication changed old pointer")
	}
	if now, e := os.ReadFile(filepath.Join(f.manager.root, first.ID+".json")); e != nil || !bytes.Equal(now, oldRecord) {
		t.Fatal("new reservation changed old job evidence")
	}
}

func TestWorkflowControllerStorageLiveStatusDoesNotSwallowInvalidReceipt(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	entered, hold := f.barrier()
	f.manager.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		observeWorkflowNoNativeOwners(ctx)
		close(entered)
		hold()
		return json.RawMessage(`{"ok":true}`), nil
	}
	job := f.start()
	workflowStoreUnitAwait(t, entered, "source callback did not enter")
	status, err := f.manager.ControllerStorageStatus(context.Background())
	if err != nil || status.State != "tracked" || status.ReservedBytes == 0 || status.UncertainBytes != 0 {
		t.Fatal("genuine known active reservation was not retained")
	}
	path := f.manager.lifecycleReceiptPath(job.ID, "intent")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("source intent unavailable")
	}
	defer func() {
		if e := os.WriteFile(path, original, 0600); e != nil {
			f.preserve = true
			t.Error("owned intent restoration failed")
		}
		f.unblockAll()
	}()
	if err = os.WriteFile(path, append(original, ' '), 0600); err != nil {
		t.Fatal("fixture intent corruption unavailable")
	}
	status, err = f.manager.ControllerStorageStatus(context.Background())
	if !errors.Is(err, ErrWorkflowStoragePending) || status.State != "pending" || status.UncertainBytes == 0 || status.ReservedBytes != 0 {
		t.Fatal("in-memory running state concealed invalid durable proof")
	}
}

func TestWorkflowControllerStorageValidPendingProjectionDoesNotRelease(t *testing.T) {
	f, job := workflowReconciliationFixture(t)
	original := f.manager.TerminalError(job.ID)
	status, err := f.manager.ControllerStorageStatus(context.Background())
	if err != nil || status.State != "pending" || status.Generation != job.ID || status.UncertainBytes == 0 || status.ReservedBytes != 0 || status.FinalizationReservedBytes != 0 {
		t.Fatal("valid incomplete source chain did not project pending commitments")
	}
	if receipt := workflowLifecycleReadCurrent(t, f.manager); receipt.Ack != nil || f.manager.TerminalError(job.ID) != original || f.manager.Snapshot().State != "failed" {
		t.Fatal("pending projection modified original release/outcome")
	}
	fresh := workflowLifecycleFreshManager(f)
	p := workflowStoreReviewedPlan(t, fresh)
	if _, err = fresh.Start(p.ID); !errors.Is(err, ErrWorkflowLifecyclePending) {
		t.Fatal("pending status was treated as admission authority")
	}
}
