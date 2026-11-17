package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

type controllerStoragePointer struct {
	Version    int                  `json:"version"`
	Generation string               `json:"generation"`
	Object     closedLifecycleStage `json:"object"`
}
type controllerStorageReservation struct {
	Version                  int                       `json:"version"`
	Generation               string                    `json:"generation"`
	Action                   string                    `json:"action"`
	NamespaceSHA256          string                    `json:"namespaceSHA256"`
	RootSHA256               string                    `json:"rootSHA256"`
	RequestSHA256            string                    `json:"requestSHA256"`
	ScriptSHA256             string                    `json:"scriptSHA256"`
	InputSHA256              string                    `json:"inputSHA256"`
	Roles                    controllerStorageRoles    `json:"roles"`
	Previous                 *controllerStoragePointer `json:"previous,omitempty"`
	GenerationsTracked       uint64                    `json:"generationsTracked"`
	PriorRetainedChargeBytes int64                     `json:"priorRetainedChargeBytes"`
}

// A private nil-default observation boundary follows actual private reservation
// publication and checked TX Close. It cannot supply writer/owner proof.
type controllerStorageHooks struct {
	afterReserved func()
	beforePublish func(string, string) error
}
type controllerStorageBudget struct {
	mu           sync.Mutex
	reservation  controllerStorageReservation
	binding      controllerStoragePointer
	recordWrites int
	snapshots    map[string]bool
}

func controllerStorageError(cause error) error {
	if cause == nil {
		return nil
	}
	return workflowFailure(ErrWorkflowStoragePending, cause)
}
func (m *Manager) controllerStoragePath(id string) string {
	return filepath.Join(m.storeRoot, controllerStorageDirectory, id+".reservation.json")
}
func (p controllerStoragePointer) digest() string { return workflowLifecycleJSONHash(p) }
func (r controllerStorageReservation) retained() (int64, error) {
	n, err := r.Roles.total()
	if err != nil {
		return 0, err
	}
	// Initial-record replacement credit is no longer outstanding after genuine
	// local release. Other roles retain their conservative full allowances.
	return n - r.Roles.InitialRecordBytes, nil
}
func validControllerReservation(r controllerStorageReservation) bool {
	_, err := r.Roles.total()
	return err == nil && r.Version == 1 && historyHex(r.Generation, 48) && knownWorkflowLifecycleAction(r.Action) && historyHex(r.RootSHA256, 64) && historyHex(r.NamespaceSHA256, 64) && historyHex(r.RequestSHA256, 64) && historyHex(r.ScriptSHA256, 64) && historyHex(r.InputSHA256, 64) && r.GenerationsTracked > 0 && r.GenerationsTracked <= workflowLifecycleMaxGenerations && r.PriorRetainedChargeBytes >= 0 && r.Roles.TerminalRecordBytes == maxHistoryRecordBytes && r.Roles.ReportBytes == maxResultBytes && r.Roles.LogPoolBytes == controllerStorageLogBytes && r.Roles.ControlBytes == controllerStorageControlBytes && r.Roles.InitialRecordBytes > 0 && r.Roles.InitialRecordBytes <= maxHistoryRecordBytes && r.Roles.ScriptBytes > 0 && r.Roles.RequestBytes > 0 && ((r.Previous == nil && r.GenerationsTracked == 1 && r.PriorRetainedChargeBytes == 0) || (r.Previous != nil && r.GenerationsTracked > 1))
}
func (m *Manager) readControllerPointer(ctx context.Context) (*controllerStoragePointer, error) {
	b, err := readWorkflowLifecycleFile(ctx, filepath.Join(m.storeRoot, controllerStorageCurrent), controllerStorageMetadataMax)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p controllerStoragePointer
	if err = decodeWorkflowLifecycle(b, &p); err != nil {
		return nil, err
	}
	if p.Version != 1 || !historyHex(p.Generation, 48) || p.Object.Name != p.Generation+".reservation.json" || p.Object.Size <= 0 || p.Object.Size > controllerStorageMetadataMax || !historyHex(p.Object.SHA256, 64) || p.Object.Identity == "" || p.Object.Links != 1 {
		return nil, ErrWorkflowStoragePending
	}
	return &p, nil
}
func (m *Manager) readControllerReservation(ctx context.Context, p controllerStoragePointer) (controllerStorageReservation, error) {
	var r controllerStorageReservation
	if p.Version != 1 || !historyHex(p.Generation, 48) || p.Object.Name != p.Generation+".reservation.json" {
		return r, ErrWorkflowStoragePending
	}
	path := m.controllerStoragePath(p.Generation)
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode()&os.ModeType != os.ModeDir {
		return r, errors.Join(ErrWorkflowStoragePending, err)
	}
	object, err := inspectLifecycleObject(path)
	if err != nil {
		return r, err
	}
	object.Name = filepath.Base(path)
	if object != p.Object {
		return r, ErrWorkflowStoragePending
	}
	data, err := readWorkflowLifecycleFile(ctx, path, controllerStorageMetadataMax)
	if err != nil {
		return r, err
	}
	if int64(len(data)) != object.Size || workflowLifecycleHash(data) != object.SHA256 {
		return r, ErrWorkflowStoragePending
	}
	if err = decodeWorkflowLifecycle(data, &r); err != nil {
		return r, err
	}
	if !validControllerReservation(r) || r.Generation != p.Generation {
		return r, ErrWorkflowStoragePending
	}
	after, err := inspectLifecycleObject(path)
	after.Name = filepath.Base(path)
	if err != nil || after != object {
		return r, errors.Join(ErrWorkflowStoragePending, err)
	}
	now, err := os.Lstat(filepath.Dir(path))
	if err != nil || now.Mode()&os.ModeType != os.ModeDir || !os.SameFile(parent, now) {
		return r, errors.Join(ErrWorkflowStoragePending, err)
	}
	return r, nil
}
func (m *Manager) controllerReleased(ctx context.Context, p controllerStoragePointer, r controllerStorageReservation) (bool, error) {
	receipt, err := m.readWorkflowLifecycleChain(ctx, r.Generation)
	if err != nil {
		return false, err
	}
	if receipt.Intent.ControllerStorageSHA256 != p.digest() || receipt.Intent.RequestSHA256 != r.RequestSHA256 || receipt.Intent.Action != r.Action {
		return false, ErrWorkflowStoragePending
	}
	return receipt.Ack != nil && receipt.Ack.LocalOwnersReleased, nil
}

// This scan reads directory metadata only. It includes unknown entries in
// its fixed bound, observes Close, and never follows a substituted component.
func (m *Manager) controllerStorageNames(ctx context.Context) (map[string]bool, error) {
	dir := filepath.Join(m.storeRoot, controllerStorageDirectory)
	named, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrWorkflowStoragePending, err)
	}
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	entries, readErr := f.ReadDir(workflowLifecycleMaxGenerations + 1)
	closeErr := f.Close()
	if statErr != nil || (readErr != nil && readErr != io.EOF) || closeErr != nil || len(entries) > workflowLifecycleMaxGenerations || !os.SameFile(named, opened) {
		return nil, errors.Join(ErrWorkflowStoragePending, statErr, readErr, workflowFailure(ErrWorkflowCleanup, closeErr))
	}
	names := make(map[string]bool, len(entries))
	for _, e := range entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		n := e.Name()
		if len(n) != 48+len(".reservation.json") || !strings.HasSuffix(n, ".reservation.json") || !historyHex(strings.TrimSuffix(n, ".reservation.json"), 48) || !e.Type().IsRegular() {
			return nil, ErrWorkflowStoragePending
		}
		names[n] = true
	}

	now, err := os.Lstat(dir)
	if err != nil || now.Mode()&os.ModeType != os.ModeDir || !os.SameFile(named, now) {
		return nil, errors.Join(ErrWorkflowStoragePending, err)
	}
	return names, nil
}

func controllerNamesDigest(names map[string]bool) string {
	keys := make([]string, 0, len(names))
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return workflowLifecycleJSONHash(keys)
}

// Admission validates the bounded immutable chain and all names, not just the
// mutable current pointer. An orphan/unknown stage never authorizes allocation.
func (m *Manager) inspectControllerStorageAdmission(ctx context.Context) (*controllerStoragePointer, *controllerStorageReservation, error) {
	p, err := m.readControllerPointer(ctx)
	if err != nil {
		return nil, nil, err
	}
	names, err := m.controllerStorageNames(ctx)
	if err != nil {
		return nil, nil, err
	}
	if p == nil {
		if len(names) == 0 {
			return nil, nil, nil
		}
		return nil, nil, ErrWorkflowStoragePending
	}
	root, err := m.reconciliationRoot()
	if err != nil {
		return nil, nil, err
	}
	namespace := controllerNamesDigest(names)
	cursor := p
	var latest *controllerStorageReservation
	var newer *controllerStorageReservation
	for cursor != nil {
		if err = ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !names[cursor.Generation+".reservation.json"] {
			return nil, nil, ErrWorkflowStoragePending
		}
		delete(names, cursor.Generation+".reservation.json")
		r, e := m.readControllerReservation(ctx, *cursor)
		if e != nil || r.RootSHA256 != root || (newer == nil && r.NamespaceSHA256 != namespace) {
			return nil, nil, errors.Join(ErrWorkflowStoragePending, e)
		}
		released, e := m.controllerReleased(ctx, *cursor, r)
		if e != nil || !released {
			return nil, nil, errors.Join(ErrWorkflowStoragePending, e)
		}
		if newer != nil {
			retained, e := r.retained()
			if e != nil || r.PriorRetainedChargeBytes > math.MaxInt64-retained || newer.PriorRetainedChargeBytes != r.PriorRetainedChargeBytes+retained || newer.GenerationsTracked != r.GenerationsTracked+1 {
				return nil, nil, ErrWorkflowStoragePending
			}
		} else {
			copy := r
			latest = &copy
		}
		newer = &r
		cursor = r.Previous
	}
	if len(names) != 0 {
		return nil, nil, ErrWorkflowStoragePending
	}
	return p, latest, nil
}

func (m *Manager) reserveControllerStorage(ctx context.Context, job Job, prepared *preparedWorkflowInput) (budget *controllerStorageBudget, err error) {
	initial, cause := encodeJob(job)
	if cause != nil {
		return nil, cause
	}
	roles, cause := controllerStoragePlan(prepared, initial)
	if cause != nil {
		return nil, cause
	}
	tx, cause := m.acquireWorkflowStoreLease(workflowTransactionLockName)
	if cause != nil {
		return nil, cause
	}
	defer func() {
		if closeErr := m.closeWorkflowStoreLease(tx); closeErr != nil {
			err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
		}
	}()
	// Check lifecycle/orphans BEFORE allocating the reservation component.
	generations, cause := m.inspectWorkflowLifecycleAdmission(ctx)
	if cause == context.Canceled || cause == context.DeadlineExceeded {
		return nil, cause
	}
	if cause != nil {
		return nil, workflowLifecyclePending(cause)
	}
	if generations >= workflowLifecycleMaxGenerations {
		return nil, workflowLifecyclePending(ErrHistoryCapacity)
	}
	previous, last, cause := m.inspectControllerStorageAdmission(ctx)
	if cause != nil {
		return nil, controllerStorageError(cause)
	}
	root, cause := m.reconciliationRoot()
	if cause != nil {
		return nil, controllerStorageError(cause)
	}
	names, nameErr := m.controllerStorageNames(ctx)
	if nameErr != nil {
		return nil, controllerStorageError(nameErr)
	}
	names[job.ID+".reservation.json"] = true
	r := controllerStorageReservation{NamespaceSHA256: controllerNamesDigest(names), Version: 1, Generation: job.ID, Action: job.Action, RootSHA256: root, RequestSHA256: prepared.RequestSHA256, ScriptSHA256: prepared.ScriptSHA256, InputSHA256: prepared.InputSHA256, Roles: roles, Previous: previous, GenerationsTracked: 1}
	if last != nil {
		retained, e := last.retained()
		if e != nil || last.PriorRetainedChargeBytes > math.MaxInt64-retained {
			return nil, ErrWorkflowStorageCapacity
		}
		r.PriorRetainedChargeBytes = last.PriorRetainedChargeBytes + retained
		r.GenerationsTracked = last.GenerationsTracked + 1
	}
	if !validControllerReservation(r) {
		return nil, ErrWorkflowStorageCapacity
	}
	if cause = ctx.Err(); cause != nil {
		return nil, cause
	}
	data, cause := json.Marshal(r)
	if cause != nil || len(data) > controllerStorageMetadataMax {
		return nil, ErrWorkflowStorageCapacity
	}
	dir := filepath.Join(m.storeRoot, controllerStorageDirectory)
	if cause = os.Mkdir(dir, 0700); cause != nil && !errors.Is(cause, os.ErrExist) {
		return nil, controllerStorageError(cause)
	}
	// From the first physical write onward, finish/retain this exact owner even
	// when the caller cancels. Publication failure cannot be retried blindly.
	var publish func(string, string, string) error
	if m.controllerStorageHooks != nil && m.controllerStorageHooks.beforePublish != nil {
		publish = func(stage, target, previous string) error {
			if e := m.controllerStorageHooks.beforePublish(stage, target); e != nil {
				return e
			}
			return physicalLifecyclePublish(stage, target, previous)
		}
	}
	observed := writeLifecycleObserved(m.controllerStoragePath(job.ID), data, "", publish)
	if observed.Err != nil || !observed.Known || !observed.Published {
		return nil, controllerStorageError(errors.Join(ErrWorkflowStoragePending, observed.Err))
	}
	object, cause := inspectLifecycleObject(m.controllerStoragePath(job.ID))
	if cause != nil {
		return nil, controllerStorageError(cause)
	}
	object.Name = job.ID + ".reservation.json"
	if object.Size != int64(len(data)) || object.SHA256 != workflowLifecycleHash(data) {
		return nil, controllerStorageError(ErrWorkflowStoragePending)
	}
	pointer := controllerStoragePointer{1, job.ID, object}
	b, _ := json.Marshal(pointer)
	if len(b) > controllerStorageMetadataMax {
		return nil, controllerStorageError(ErrWorkflowStorageCapacity)
	}
	old := ""
	if previous != nil {
		old = workflowLifecycleJSONHash(*previous)
	}
	observed = writeLifecycleObserved(filepath.Join(m.storeRoot, controllerStorageCurrent), b, old, publish)
	if observed.Err != nil || !observed.Known || !observed.Published {
		return nil, controllerStorageError(errors.Join(ErrWorkflowStoragePending, observed.Err))
	}
	return &controllerStorageBudget{reservation: r, binding: pointer}, nil
}

// A single admission record and a single terminal record have independent
// credits. This does not permit an automatic second terminal-result attempt.
func (b *controllerStorageBudget) chargeRecord(data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.reservation.Roles.InitialRecordBytes
	if b.recordWrites == 1 {
		limit = b.reservation.Roles.TerminalRecordBytes
	}
	if b.recordWrites >= 2 || int64(len(data)) > limit {
		return ErrWorkflowStorageCapacity
	}
	b.recordWrites++
	return nil
}

func (m *Manager) ControllerStorageStatus(ctx context.Context) (ControllerStorageStatus, error) {
	status := ControllerStorageStatus{State: "uninitialized", Scope: "tracked-controller-evidence-only", LegacyAccounting: "not-included"}
	p, err := m.readControllerPointer(ctx)
	names, nameErr := m.controllerStorageNames(ctx)
	if err == nil {
		err = nameErr
	}
	if err == nil && p == nil {
		if len(names) == 0 {
			return status, nil
		}
		err = ErrWorkflowStoragePending
	}

	if err != nil {
		status.State = "pending"
		return status, controllerStorageError(err)
	}
	r, err := m.readControllerReservation(ctx, *p)
	if err != nil {
		status.State = "pending"
		return status, controllerStorageError(err)
	}
	if uint64(len(names)) != r.GenerationsTracked || !names[r.Generation+".reservation.json"] || controllerNamesDigest(names) != r.NamespaceSHA256 {
		status.State = "pending"
		return status, controllerStorageError(ErrWorkflowStoragePending)
	}
	root, err := m.reconciliationRoot()
	if err != nil || root != r.RootSHA256 {
		status.State = "pending"
		return status, controllerStorageError(errors.Join(ErrWorkflowStoragePending, err))
	}
	total, _ := r.Roles.total()
	status.Generation = r.Generation
	status.Action = r.Action
	status.GenerationsTracked = r.GenerationsTracked
	status.RetainedChargeBytes = r.PriorRetainedChargeBytes
	status.FinalizationReservedBytes = r.Roles.TerminalRecordBytes + r.Roles.ControlBytes
	released, err := m.controllerReleased(ctx, *p, r)
	if err != nil || !released {
		m.mu.Lock()
		live := m.job.ID == r.Generation && m.job.State == "running" && m.done != nil
		if live {
			select {
			case <-m.done:
				live = false
			default:
			}
		}
		m.mu.Unlock()
		if live && err == nil {
			status.State = "tracked"
			status.ReservedBytes = total
			return status, nil
		}
		status.State = "pending"
		status.UncertainBytes = total
		status.ReservedBytes = 0
		status.FinalizationReservedBytes = 0
		// A valid incomplete chain is a normal read-only pending projection.
		// Unknown/corrupt/unreadable proof remains an error, not a released view.
		if err != nil {
			return status, controllerStorageError(err)
		}
		return status, nil
	}
	retained, _ := r.retained()
	if status.RetainedChargeBytes > math.MaxInt64-retained {
		return status, controllerStorageError(ErrWorkflowStorageCapacity)
	}
	status.RetainedChargeBytes += retained
	status.FinalizationReservedBytes = 0
	status.State = "tracked"
	return status, nil
}

// Snapshot allowances are bound to immutable preparation, not supplied anew by
// each writer. A repeated or mismatched role cannot consume finalization credit.
type controllerStorageBudgetKey struct{}

func (b *controllerStorageBudget) chargeSnapshot(role string, data []byte) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.snapshots == nil {
		b.snapshots = map[string]bool{}
	}
	if b.snapshots[role] {
		return 0, ErrWorkflowStorageCapacity
	}
	var limit int64
	var hash string
	switch role {
	case "script":
		limit = b.reservation.Roles.ScriptBytes
		hash = b.reservation.ScriptSHA256
	case "request":
		limit = b.reservation.Roles.RequestBytes
		hash = b.reservation.InputSHA256
	default:
		return 0, ErrWorkflowStorageCapacity
	}
	if int64(len(data)) != limit || workflowLifecycleHash(data) != hash {
		return 0, ErrWorkflowStorageCapacity
	}
	b.snapshots[role] = true
	return limit, nil
}
func snapshotAllowance(ctx context.Context, role string, data []byte) (int64, error) {
	if b, _ := ctx.Value(controllerStorageBudgetKey{}).(*controllerStorageBudget); b != nil {
		return b.chargeSnapshot(role, data)
	}
	// Internal standalone executor tests have no Manager admission. They use
	// the same counted writer, but cannot issue a durable storage certificate.
	return int64(len(data)), nil
}
