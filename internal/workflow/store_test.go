package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/filelock"
)

type workflowStoreUnitLease struct{ close func() error }

func (l *workflowStoreUnitLease) Close() error { return l.close() }

func workflowStoreUnitAwait(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}

func TestWorkflowStoreBusyKeepsReviewedPlanAndHistoryUntouched(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	held, err := openWorkflowStoreLease(filepath.Join(f.root, workflowActiveLockName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	var executed atomic.Int32
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		executed.Add(1)
		return json.RawMessage(`{"fixture":true}`), nil
	}
	plan := f.plan()
	_, err = m.Start(plan.ID)
	if !errors.Is(err, ErrWorkflowBusy) || !errors.Is(err, ErrWorkflowStore) || !errors.Is(err, ErrWorkflowAdmission) || !errors.Is(err, filelock.ErrBusy) {
		t.Fatal("busy admission lost its fixed typed causes")
	}
	if strings.Contains(err.Error(), f.root) || !strings.Contains(err.Error(), ErrWorkflowBusy.Error()) {
		t.Fatal("busy admission exposed a path or hid its reason")
	}
	if executed.Load() != 0 {
		t.Fatal("busy admission executed a workflow")
	}
	if _, err := os.Stat(m.root); !os.IsNotExist(err) {
		t.Fatal("busy admission created a workflow history")
	}
	m.mu.Lock()
	_, retained := m.plans[plan.ID]
	m.mu.Unlock()
	if !retained || m.Snapshot().State != "failed" {
		t.Fatal("busy admission consumed its reviewed plan or left a running generation")
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(plan.ID); err != nil {
		t.Fatal("explicit retry of still-reviewed plan failed")
	}
	workflowStoreUnitAwait(t, m.done, "retried workflow did not complete")
	if executed.Load() != 1 || m.Snapshot().State != "succeeded" {
		t.Fatal("reviewed retry did not execute exactly once")
	}
}

func TestWorkflowStoreAcquisitionRetainsShutdownGeneration(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	entered, release := f.barrier()
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		if filepath.Base(path) == workflowActiveLockName {
			close(entered)
			release()
		}
		return openWorkflowStoreLease(path)
	}
	var executed atomic.Bool
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) { executed.Store(true); return nil, nil }
	startResult, started := f.startAsync(f.plan())
	workflowStoreUnitAwait(t, entered, "active acquisition did not reach its source barrier")
	if m.Snapshot().State != "running" || m.Summary().State != "running" {
		t.Fatal("pending acquisition lost its reserved generation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := m.Shutdown(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shutdown claimed completion while acquisition was pending")
	}
	select {
	case <-m.done:
		t.Fatal("reserved completion closed before acquisition returned")
	default:
	}
	f.unblockAll()
	workflowStoreUnitAwait(t, started, "admission did not join after acquisition release")
	if err := <-startResult; err != nil {
		t.Fatal(err)
	}
	workflowStoreUnitAwait(t, m.done, "cancelled acquisition did not finish persistence and release")
	if err := m.Shutdown(context.Background()); err != nil || executed.Load() {
		t.Fatal("pure cooperative acquisition cancellation executed or lost clean completion")
	}
	lease, err := openWorkflowStoreLease(filepath.Join(f.root, workflowActiveLockName))
	if err != nil {
		t.Fatal("completed reservation did not release its actual lease")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowStoreAcquisitionFailureHidesPrivateCause(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause := errors.New("PRIVATE_STORE_OS_CAUSE")
	native := &os.PathError{Op: "open", Path: "PRIVATE_STORE_PATH", Err: cause}
	m.openStoreLease = func(string) (workflowStoreLease, error) { return nil, native }
	var executed atomic.Bool
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) { executed.Store(true); return nil, nil }
	_, err := m.Start(f.plan().ID)
	var retained *os.PathError
	if !errors.Is(err, ErrWorkflowAdmission) || !errors.Is(err, ErrWorkflowStore) || !errors.Is(err, cause) || !errors.As(err, &retained) || retained != native {
		t.Fatal("acquisition lost its admission category or original local cause")
	}
	if strings.Contains(err.Error(), "PRIVATE_") || strings.Contains(m.Snapshot().Error, "PRIVATE_") || executed.Load() {
		t.Fatal("acquisition exposed private OS data or executed after refusal")
	}
	if _, err := os.Stat(m.root); !os.IsNotExist(err) {
		t.Fatal("failed acquisition persisted a running record")
	}
	if !errors.Is(m.TerminalError(m.Snapshot().ID), cause) {
		t.Fatal("reserved failure lost its authoritative terminal cause")
	}
}

func TestWorkflowStoreActiveCloseRetainsPublicationAndPoisonsAdmission(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "cancel"
		if shutdown {
			name = "shutdown"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			m := f.manager
			entered, release := f.barrier()
			cause := errors.New(strings.Repeat("PRIVATE_STORE_CLOSE", 4096))
			var closes, opens atomic.Int32
			m.openStoreLease = func(path string) (workflowStoreLease, error) {
				opens.Add(1)
				real, err := openWorkflowStoreLease(path)
				if err != nil {
					return nil, err
				}
				if filepath.Base(path) != workflowActiveLockName {
					return real, nil
				}
				return &workflowStoreUnitLease{close: func() error { closes.Add(1); close(entered); release(); return errors.Join(real.Close(), cause) }}, nil
			}
			job := f.start()
			workflowStoreUnitAwait(t, entered, "active close did not reach its source barrier")
			if m.Snapshot().State != "running" {
				t.Fatal("terminal publication preceded active lease cleanup")
			}
			if !errors.Is(m.TerminalError(job.ID), ErrWorkflowOutcomeUnavailable) {
				t.Fatal("pending close was exposed as terminal")
			}
			path := filepath.Join(m.root, job.ID+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var durable Job
			if json.Unmarshal(before, &durable) != nil || durable.State != "succeeded" {
				t.Fatal("active lease close preceded attempted terminal persistence")
			}
			if lease, err := openWorkflowStoreLease(filepath.Join(f.root, workflowActiveLockName)); !errors.Is(err, filelock.ErrBusy) {
				if lease != nil {
					_ = lease.Close()
				}
				t.Fatal("active reservation was released during its close barrier")
			}
			if shutdown {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				err := m.Shutdown(ctx)
				cancel()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("shutdown completed during active lease close")
				}
			} else {
				m.Cancel()
			}
			select {
			case <-m.done:
				t.Fatal("completion preceded active close")
			default:
			}
			f.unblockAll()
			workflowStoreUnitAwait(t, m.done, "active close did not finish its exact generation")
			result := m.TerminalError(job.ID)
			if !errors.Is(result, ErrWorkflowStore) || !errors.Is(result, ErrWorkflowCleanup) || !errors.Is(result, cause) || strings.Contains(result.Error(), "PRIVATE_") || m.Snapshot().State != "failed" || closes.Load() != 1 {
				t.Fatal("lease close failure was erased, repeated or printed privately")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("record was rewritten after uncertain lease release")
			}
			if !shutdown {
				previousOpens := opens.Load()
				_, err := m.Start(f.plan().ID)
				if !errors.Is(err, ErrWorkflowAdmission) || !errors.Is(err, ErrWorkflowStore) || !errors.Is(err, cause) || opens.Load() != previousOpens {
					t.Fatal("poisoned manager attempted another acquisition")
				}
			} else if !errors.Is(m.Shutdown(context.Background()), cause) {
				t.Fatal("captured shutdown lost the exact cleanup failure")
			}
		})
	}
}

func TestWorkflowStoreTransactionCloseFailurePreventsExecution(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause := errors.New("PRIVATE_TRANSACTION_CLOSE")
	var executed atomic.Bool
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) { executed.Store(true); return nil, nil }
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		real, err := openWorkflowStoreLease(path)
		if err != nil {
			return nil, err
		}
		if filepath.Base(path) != workflowTransactionLockName {
			return real, nil
		}
		return &workflowStoreUnitLease{close: func() error { return errors.Join(real.Close(), cause) }}, nil
	}
	_, err := m.Start(f.plan().ID)
	if !errors.Is(err, ErrWorkflowAdmission) || !errors.Is(err, ErrWorkflowPersistence) || !errors.Is(err, ErrWorkflowCleanup) || !errors.Is(err, ErrWorkflowStore) || !errors.Is(err, cause) || strings.Contains(err.Error(), "PRIVATE_") || executed.Load() {
		t.Fatal("transaction close failure executed or lost its typed safe admission outcome")
	}
	if m.Snapshot().State != "failed" {
		t.Fatal("failed transaction was published as running")
	}
	lease, err := openWorkflowStoreLease(filepath.Join(f.root, workflowActiveLockName))
	if err != nil {
		t.Fatal("initial persistence failure retained the successfully closed active lease")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowStoreTransactionDoesNotCoverExecution(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		transaction, err := openWorkflowStoreLease(filepath.Join(f.root, workflowTransactionLockName))
		if err != nil {
			return nil, errors.New("transaction lock remained held during execution")
		}
		if err := transaction.Close(); err != nil {
			return nil, err
		}
		active, err := openWorkflowStoreLease(filepath.Join(f.root, workflowActiveLockName))
		if active != nil {
			_ = active.Close()
		}
		if !errors.Is(err, filelock.ErrBusy) {
			return nil, errors.New("active lock was not held during execution")
		}
		return json.RawMessage(`{"fixture":true}`), nil
	}
	var writes atomic.Int32
	persist := m.persist
	m.persist = func(path string, data []byte) error {
		writes.Add(1)
		transaction, err := openWorkflowStoreLease(filepath.Join(f.root, workflowTransactionLockName))
		if transaction != nil {
			_ = transaction.Close()
		}
		if !errors.Is(err, filelock.ErrBusy) {
			return errors.New("record write did not hold its transaction lock")
		}
		return persist(path, data)
	}
	job := f.start()
	workflowStoreUnitAwait(t, m.done, "coordinated workflow did not finish")
	if err := m.TerminalError(job.ID); err != nil || writes.Load() != 2 {
		t.Fatal("active and short transaction ownership were not composed around both real record writes")
	}
}

func TestWorkflowStoreFailedOpenerLeaseCloseIsObserved(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	cause, closeCause := errors.New("PRIVATE_OPEN_FAILURE"), errors.New("PRIVATE_OPEN_CLOSE_FAILURE")
	var closes atomic.Int32
	var once sync.Once
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		real, err := openWorkflowStoreLease(path)
		if err != nil {
			return nil, err
		}
		return &workflowStoreUnitLease{close: func() error {
			closes.Add(1)
			var err error
			once.Do(func() { err = real.Close() })
			return errors.Join(err, closeCause)
		}}, cause
	}
	_, err := m.Start(f.plan().ID)
	if !errors.Is(err, cause) || !errors.Is(err, closeCause) || !errors.Is(err, ErrWorkflowAdmission) || !errors.Is(err, ErrWorkflowCleanup) || closes.Load() != 1 || strings.Contains(err.Error(), "PRIVATE_") {
		t.Fatal("failed composed opener lost its owner or cleanup cofailure")
	}
	_, err = m.Start(f.plan().ID)
	if !errors.Is(err, ErrWorkflowStore) || !errors.Is(err, closeCause) || closes.Load() != 1 {
		t.Fatal("failed opener close did not poison same-manager admission")
	}
}

func TestWorkflowStoreAdmissionCancellationDuringCloseRetained(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	entered, release := f.barrier()
	writeCause := errors.New("fixture admission storage failure")
	m.persist = func(string, []byte) error { return writeCause }
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		real, err := openWorkflowStoreLease(path)
		if err != nil {
			return nil, err
		}
		if filepath.Base(path) != workflowActiveLockName {
			return real, nil
		}
		return &workflowStoreUnitLease{close: func() error { close(entered); release(); return real.Close() }}, nil
	}
	result, started := f.startAsync(f.plan())
	workflowStoreUnitAwait(t, entered, "failed admission did not retain active lease through close")
	if m.Snapshot().State != "running" {
		t.Fatal("failed admission completed before lease close")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := m.Shutdown(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shutdown escaped failed admission close")
	}
	f.unblockAll()
	workflowStoreUnitAwait(t, started, "failed admission did not return after close")
	if err := <-result; err != writeCause {
		t.Fatal("successful lease cleanup changed the original storage error identity")
	}
	err = m.Shutdown(context.Background())
	if !errors.Is(err, writeCause) || !errors.Is(err, context.Canceled) || !errors.Is(err, ErrWorkflowAdmission) || !errors.Is(err, ErrWorkflowPersistence) {
		t.Fatal("cancellation during admission close lost its independent co-cause")
	}
}
