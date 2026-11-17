package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Yunushan/accessweaver/internal/managed"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const reconciliationDirectory = ".workflow-reconciliation"
const reconciliationCurrent = ".workflow-reconciliation.current"
const reconciliationMaxOperations = 128
const reconciliationMaxObjects = 8

type reconciliationCompletion struct {
	done      chan struct{}
	cancel    context.CancelFunc
	err       error
	operation string
}
type privateReconciliationPlan struct {
	Public        LifecycleReconciliationPlan
	Intent        reconciliationIntent
	Authorization *managed.Authorization
	Live          *localReleaseWitness
}
type reconciliationIntent struct {
	Version                int                      `json:"version"`
	OperationID            string                   `json:"operationId"`
	Generation             string                   `json:"generation"`
	Contract               string                   `json:"contract"`
	Root                   string                   `json:"root"`
	CurrentSHA256          string                   `json:"currentSHA256"`
	Receipt                workflowLifecycleReceipt `json:"receipt"`
	Objects                []closedLifecycleStage   `json:"objects"`
	OriginalOwnersReleased bool                     `json:"originalOwnersReleased"`
	AckCandidate           *closedLifecycleStage    `json:"ackCandidate,omitempty"`
	AckBefore              *closedLifecycleStage    `json:"ackBefore,omitempty"`
}

func reconciliationError(category, cause error) error {
	if cause == nil {
		return category
	}
	return workflowFailure(category, cause)
}
func reconciliationPending(cause error) error {
	return reconciliationError(ErrLifecycleReconciliationPending, cause)
}
func (m *Manager) reconciliationPath(op, name string) string {
	return filepath.Join(m.storeRoot, reconciliationDirectory, op, name)
}
func (m *Manager) reconciliationRoot() (string, error) {
	path, err := filepath.Abs(m.storeRoot)
	if err != nil {
		return "", err
	}
	named, err := os.Lstat(path)
	if err != nil || named.Mode()&os.ModeType != os.ModeDir {
		return "", errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	info, statErr := file.Stat()
	identity, _, identityErr := reconciliationFileIdentity(file)
	closeErr := file.Close()
	if statErr != nil || identityErr != nil || closeErr != nil || !os.SameFile(named, info) {
		return "", errors.Join(ErrLifecycleReconciliationConflict, statErr, identityErr, workflowFailure(ErrWorkflowCleanup, closeErr))
	}
	return workflowLifecycleHash([]byte(filepath.Clean(path) + "\x00" + identity)), nil
}
func (m *Manager) readReconciliationJSON(ctx context.Context, path string, value any) error {
	b, err := m.readReconciliationBytes(ctx, path)
	if err != nil {
		return err
	}
	return decodeReconciliationJSON(b, value)
}
func (m *Manager) writeReconciliationJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil || len(b) > workflowLifecycleMaxReceiptBytes {
		return errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	return writeWorkflowLifecycleFile(path, b, "")
}
func closedStagePublic(generation string, object closedLifecycleStage) LifecycleReconciliationObject {
	return LifecycleReconciliationObject{Ref: workflowLifecycleJSONHash(struct {
		Generation string
		Object     closedLifecycleStage
	}{generation, object}), Role: "closed-ack-stage", Size: object.Size, SHA256: object.SHA256}
}
func reconciliationObjects(intent reconciliationIntent) []LifecycleReconciliationObject {
	result := []LifecycleReconciliationObject{}
	for _, object := range intent.Objects {
		result = append(result, closedStagePublic(intent.Generation, object))
	}
	return result
}
func validReconciliationIntent(intent reconciliationIntent) bool {
	if intent.Version != 1 || intent.Contract != "positive-original-local-release-v1" || !intent.OriginalOwnersReleased || !historyHex(intent.OperationID, 48) || !historyHex(intent.Generation, 48) || !historyHex(intent.Root, 64) || !historyHex(intent.CurrentSHA256, 64) || !validWorkflowLifecycleReceipt(intent.Receipt) || intent.Receipt.Intent.Generation != intent.Generation || intent.Receipt.Seal == nil || !intent.Receipt.Seal.LocalReleasePermitted || len(intent.Objects) > reconciliationMaxObjects {
		return false
	}
	if intent.AckCandidate != nil && (intent.AckCandidate.Name != "ack-candidate.json" || !validReconciliationObject(*intent.AckCandidate) || intent.AckCandidate.SHA256 != workflowLifecycleJSONHash(workflowLifecycleAck{1, intent.Receipt.IntentSHA256, intent.Receipt.SealSHA256, true, reconciliationProtection})) {
		return false
	}
	if intent.AckBefore != nil && (intent.AckBefore.Name != intent.Generation+".ack.json" || !validReconciliationObject(*intent.AckBefore) || len(intent.Objects) != 1 || intent.AckBefore.Identity != intent.Objects[0].Identity || intent.AckBefore.SHA256 != workflowLifecycleJSONHash(workflowLifecycleAck{1, intent.Receipt.IntentSHA256, intent.Receipt.SealSHA256, true, reconciliationProtection})) {
		return false
	}
	seen := map[string]bool{}
	for _, object := range intent.Objects {
		if filepath.Base(object.Name) != object.Name || !strings.HasPrefix(object.Name, ".lifecycle-") || !strings.HasSuffix(object.Name, ".tmp") || len(object.Name) > 128 || strings.ContainsAny(object.Name, "/\\\x00") || object.Identity == "" || len(object.Identity) > 128 || object.Size < 0 || object.Size > workflowLifecycleMaxReceiptBytes || !historyHex(object.SHA256, 64) || object.Links < 1 || object.Links > 2 || seen[object.Name] {
			return false
		}
		seen[object.Name] = true
	}
	return true
}
func (m *Manager) currentReconciliation(ctx context.Context) (string, error) {
	var pointer struct {
		Version      int    `json:"version"`
		OperationID  string `json:"operationId"`
		IntentSHA256 string `json:"intentSHA256"`
	}
	err := m.readReconciliationJSON(ctx, filepath.Join(m.storeRoot, reconciliationCurrent), &pointer)
	if errors.Is(err, os.ErrNotExist) {
		return m.pendingReconciliation(ctx)
	}
	if err != nil || pointer.Version != 1 || !historyHex(pointer.OperationID, 48) || !historyHex(pointer.IntentSHA256, 64) {
		return "", reconciliationPending(err)
	}
	var intent reconciliationIntent
	if err = m.readReconciliationJSON(ctx, m.reconciliationPath(pointer.OperationID, "intent.json"), &intent); err != nil || !validReconciliationIntent(intent) || workflowLifecycleJSONHash(intent) != pointer.IntentSHA256 {
		return "", reconciliationPending(err)
	}
	pending, scanErr := m.pendingReconciliation(ctx)
	if scanErr != nil {
		return "", scanErr
	}
	if pending != "" {
		return pending, nil
	}
	return pointer.OperationID, nil
}
func (m *Manager) checkReconciliationAdmission(ctx context.Context) error {
	op, err := m.currentReconciliation(ctx)
	if err != nil {
		return workflowLifecyclePending(err)
	}
	if op == "" {
		return nil
	}
	_, err = m.ReadLifecycleReconciliationReceipt(ctx, op)
	if err != nil {
		return workflowLifecyclePending(err)
	}
	return nil
}
func (m *Manager) validateReconciliation(ctx context.Context, intent reconciliationIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := m.reconciliationRoot()
	if err != nil || root != intent.Root {
		return reconciliationError(ErrLifecycleReconciliationConflict, err)
	}
	b, err := readWorkflowLifecycleFile(ctx, filepath.Join(m.storeRoot, workflowLifecycleCurrent), workflowLifecycleMaxReceiptBytes)
	if err != nil || workflowLifecycleHash(b) != intent.CurrentSHA256 {
		return reconciliationError(ErrLifecycleReconciliationConflict, err)
	}
	pointer, current, err := m.readWorkflowLifecycleCurrent(ctx)
	if err != nil || pointer == nil || pointer.Generation != intent.Generation || current.IntentSHA256 != intent.Receipt.IntentSHA256 || current.SealSHA256 != intent.Receipt.SealSHA256 {
		return reconciliationError(ErrLifecycleReconciliationConflict, err)
	}
	if current.Ack != nil {
		expected := workflowLifecycleAck{1, current.IntentSHA256, current.SealSHA256, true, reconciliationProtection}
		if *current.Ack != expected {
			return ErrLifecycleReconciliationConflict
		}
	}
	record, err := readWorkflowLifecycleFile(ctx, filepath.Join(m.root, intent.Generation+".json"), maxHistoryRecordBytes)
	if err != nil || workflowLifecycleHash(record) != intent.Receipt.Seal.RecordSHA256 {
		return reconciliationError(ErrLifecycleReconciliationConflict, err)
	}
	return nil
}
func (m *Manager) reconciliationOperationClean(ctx context.Context, intent reconciliationIntent) error {
	dir := m.reconciliationPath(intent.OperationID, "")
	named, err := os.Lstat(dir)
	if err != nil || named.Mode()&os.ModeType != os.ModeDir {
		return errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	entries, readErr := file.ReadDir(17)
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil && readErr != io.EOF || statErr != nil || closeErr != nil || len(entries) > 16 || opened != nil && !os.SameFile(named, opened) {
		return errors.Join(ErrLifecycleReconciliationConflict, readErr, statErr, workflowFailure(ErrWorkflowCleanup, closeErr))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch entry.Name() {
		case "intent.json", "receipt.json", "ack-candidate.json":
			if !info.Mode().IsRegular() {
				return ErrLifecycleReconciliationConflict
			}
		case "quarantine":
			if info.Mode()&os.ModeType != os.ModeDir {
				return ErrLifecycleReconciliationConflict
			}
			q, err := os.Open(filepath.Join(dir, "quarantine"))
			if err != nil {
				return err
			}
			children, readErr := q.ReadDir(reconciliationMaxObjects + 1)
			closeErr := q.Close()
			if readErr != nil && readErr != io.EOF || closeErr != nil || len(children) > reconciliationMaxObjects {
				return errors.Join(ErrLifecycleReconciliationConflict, readErr, workflowFailure(ErrWorkflowCleanup, closeErr))
			}
			allowed := map[string]bool{}
			for _, object := range reconciliationObjects(intent) {
				allowed[object.Ref+".metadata"] = true
			}
			for _, child := range children {
				if !allowed[child.Name()] {
					return ErrLifecycleReconciliationConflict
				}
				info, err := child.Info()
				if err != nil || !info.Mode().IsRegular() {
					return errors.Join(ErrLifecycleReconciliationConflict, err)
				}
			}
		default:
			return ErrLifecycleReconciliationUnavailable
		}
	}
	if intent.AckCandidate != nil {
		candidate, err := inspectLifecycleObject(m.reconciliationPath(intent.OperationID, "ack-candidate.json"))
		if err != nil || !sameReconciliationContent(candidate, *intent.AckCandidate) {
			return errors.Join(ErrLifecycleReconciliationConflict, err)
		}
	}
	return ctx.Err()
}

func (m *Manager) PreviewLifecycleReconciliation(ctx context.Context, request LifecycleReconciliationRequest) (result LifecycleReconciliationPlan, failure error) {
	var empty LifecycleReconciliationPlan
	if request.Generation != "" && !historyHex(request.Generation, 48) || request.OperationID != "" && !historyHex(request.OperationID, 48) || request.Generation != "" && request.OperationID != "" {
		return empty, ErrLifecycleReconciliationInvalidRequest
	}
	authorization, err := m.guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		return empty, err
	}
	binding, err := authorization.ReviewBinding()
	if err != nil {
		return empty, err
	}
	m.startMu.Lock()
	defer m.startMu.Unlock()
	m.mu.Lock()
	closing := m.closing
	witness := m.releaseWitness
	running := m.maintenance != nil && !reconciliationDone(m.maintenance.done)
	storeErr := m.storeFailure
	m.mu.Unlock()
	if closing || running || storeErr != nil {
		return empty, reconciliationError(ErrLifecycleReconciliationUnavailable, storeErr)
	}
	owned, cancel := context.WithCancel(ctx)
	completion := &reconciliationCompletion{done: make(chan struct{}), cancel: cancel}
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		cancel()
		return empty, ErrLifecycleReconciliationUnavailable
	}
	m.maintenance = completion
	m.mu.Unlock()
	defer func() { cancel(); m.mu.Lock(); completion.err = failure; close(completion.done); m.mu.Unlock() }()
	ctx = owned
	active, err := m.acquireWorkflowStoreLease(workflowActiveLockName)
	if err != nil {
		return empty, err
	}
	defer func() {
		if closeErr := m.closeWorkflowStoreLease(active); closeErr != nil {
			result = LifecycleReconciliationPlan{}
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, closeErr))
		}
	}()
	var intent reconciliationIntent
	resume := request.OperationID != ""
	if resume {
		if err = m.readReconciliationJSON(ctx, m.reconciliationPath(request.OperationID, "intent.json"), &intent); err != nil || !validReconciliationIntent(intent) || intent.OperationID != request.OperationID {
			return empty, reconciliationError(ErrLifecycleReconciliationUnavailable, err)
		}
		if _, err = m.ReadLifecycleReconciliationReceipt(ctx, request.OperationID); err == nil {
			return empty, ErrLifecycleReconciliationConflict
		}
		if _, receiptErr := os.Lstat(m.reconciliationPath(request.OperationID, "receipt.json")); !errors.Is(receiptErr, os.ErrNotExist) {
			return empty, reconciliationError(ErrLifecycleReconciliationConflict, receiptErr)
		}
		if intent.AckCandidate == nil {
			return empty, ErrLifecycleReconciliationUnavailable
		}
		if err = m.reconciliationOperationClean(ctx, intent); err != nil {
			return empty, reconciliationError(ErrLifecycleReconciliationUnavailable, err)
		}
	} else {
		if witness == nil || !reconciliationDone(witness.Done) || !witness.Ack.TransactionClosed || !witness.Ack.Write.Known || witness.Ack.Write.Err == nil || request.Generation != "" && request.Generation != witness.Receipt.Intent.Generation {
			return empty, ErrLifecycleReconciliationUnavailable
		}
		if op, readErr := m.currentReconciliation(ctx); readErr != nil {
			return empty, readErr
		} else if op != "" {
			if _, readErr = m.ReadLifecycleReconciliationReceipt(ctx, op); readErr != nil {
				return empty, ErrLifecycleReconciliationPending
			}
		}
		root, rootErr := m.reconciliationRoot()
		if rootErr != nil {
			return empty, reconciliationError(ErrLifecycleReconciliationUnavailable, rootErr)
		}
		current, readErr := readWorkflowLifecycleFile(ctx, filepath.Join(m.storeRoot, workflowLifecycleCurrent), workflowLifecycleMaxReceiptBytes)
		if readErr != nil {
			return empty, reconciliationError(ErrLifecycleReconciliationUnavailable, readErr)
		}
		op, randomErr := newHistoryRevision()
		if randomErr != nil {
			return empty, reconciliationError(ErrLifecycleReconciliationUnavailable, randomErr)
		}
		intent = reconciliationIntent{Version: 1, OperationID: op, Generation: witness.Receipt.Intent.Generation, Contract: "positive-original-local-release-v1", Root: root, CurrentSHA256: workflowLifecycleHash(current), Receipt: witness.Receipt, Objects: []closedLifecycleStage{}, OriginalOwnersReleased: true}
		if object := witness.Ack.Write.Stage; object != nil {
			fresh, inspectErr := inspectLifecycleObject(filepath.Join(m.storeRoot, workflowLifecycleDirectory, object.Name))
			if inspectErr != nil || !sameLifecycleObject(*object, fresh) {
				return empty, reconciliationError(ErrLifecycleReconciliationConflict, inspectErr)
			}
			intent.Objects = append(intent.Objects, *object)
		}
	}
	if !resume {
		ack, ackErr := inspectLifecycleObject(m.lifecycleReceiptPath(intent.Generation, "ack"))
		if ackErr == nil {
			if len(intent.Objects) != 1 || ack.Identity != intent.Objects[0].Identity || ack.SHA256 != workflowLifecycleJSONHash(workflowLifecycleAck{1, intent.Receipt.IntentSHA256, intent.Receipt.SealSHA256, true, reconciliationProtection}) {
				return empty, ErrLifecycleReconciliationConflict
			}
			intent.AckBefore = &ack
		} else if !errors.Is(ackErr, os.ErrNotExist) {
			return empty, reconciliationError(ErrLifecycleReconciliationConflict, ackErr)
		}
	}
	if err = m.validateReconciliation(ctx, intent); err != nil {
		return empty, err
	}
	if err = m.validateReconciliationObjects(intent, false); err != nil {
		return empty, reconciliationError(ErrLifecycleReconciliationConflict, err)
	}
	id, err := newHistoryRevision()
	if err != nil {
		return empty, reconciliationError(ErrLifecycleReconciliationUnavailable, err)
	}
	public := LifecycleReconciliationPlan{ID: id, OperationID: intent.OperationID, Generation: intent.Generation, Action: reconciliationAction, ExpiresAt: time.Now().Add(5 * time.Minute).UTC(), IntentSHA256: intent.Receipt.IntentSHA256, SealSHA256: intent.Receipt.SealSHA256, Objects: reconciliationObjects(intent), Resume: resume, Scope: reconciliationScope, Protection: reconciliationProtection}
	public.ReviewRevision = workflowLifecycleJSONHash(struct {
		Intent        reconciliationIntent
		Authorization string
	}{intent, binding})
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return empty, ErrLifecycleReconciliationUnavailable
	}
	if m.reconciliationPlans == nil {
		m.reconciliationPlans = map[string]*privateReconciliationPlan{}
	}
	for key, plan := range m.reconciliationPlans {
		if time.Now().After(plan.Public.ExpiresAt) {
			delete(m.reconciliationPlans, key)
		}
	}
	if len(m.reconciliationPlans) >= 16 {
		return empty, ErrLifecycleReconciliationUnavailable
	}
	m.reconciliationPlans[id] = &privateReconciliationPlan{Public: public, Intent: intent, Authorization: authorization, Live: witness}
	return public, nil
}
func reconciliationDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (m *Manager) ReadLifecycleReconciliationReceipt(ctx context.Context, op string) (LifecycleReconciliationReceipt, error) {
	var receipt LifecycleReconciliationReceipt
	if !historyHex(op, 48) {
		return receipt, ErrLifecycleReconciliationInvalidRequest
	}
	m.mu.Lock()
	running := m.maintenance != nil && m.maintenance.operation == op && !reconciliationDone(m.maintenance.done)
	m.mu.Unlock()
	if running {
		return receipt, ErrLifecycleReconciliationPending
	}
	err := m.readReconciliationJSON(ctx, m.reconciliationPath(op, "receipt.json"), &receipt)
	if errors.Is(err, os.ErrNotExist) {
		m.mu.Lock()
		running := m.maintenance != nil && m.maintenance.operation == op && !reconciliationDone(m.maintenance.done)
		m.mu.Unlock()
		if running {
			return receipt, ErrLifecycleReconciliationPending
		}
		return receipt, ErrLifecycleReconciliationUnavailable
	}
	if err != nil {
		return LifecycleReconciliationReceipt{}, reconciliationError(ErrLifecycleReconciliationUnavailable, err)
	}
	if receipt.OperationID != op || !historyHex(receipt.Generation, 48) || receipt.State != "completed" || receipt.Action != reconciliationAction || !historyHex(receipt.IntentSHA256, 64) || !historyHex(receipt.SealSHA256, 64) || !historyHex(receipt.AckSHA256, 64) || receipt.CompletedAt.IsZero() || receipt.Scope != reconciliationScope || receipt.Protection != reconciliationProtection || receipt.Quarantined == nil || len(receipt.Quarantined) > reconciliationMaxObjects {
		return LifecycleReconciliationReceipt{}, ErrLifecycleReconciliationUnavailable
	}
	if err = m.validateReconciliationReceipt(ctx, receipt); err != nil {
		return LifecycleReconciliationReceipt{}, reconciliationError(ErrLifecycleReconciliationUnavailable, err)
	}
	return receipt, nil
}
func (m *Manager) LifecycleReconciliationStatus(ctx context.Context) (LifecycleReconciliationStatus, error) {
	status := LifecycleReconciliationStatus{State: "none", Scope: reconciliationScope, Protection: reconciliationProtection}
	op, err := m.currentReconciliation(ctx)
	if err != nil {
		return status, err
	}
	if op != "" {
		var intent reconciliationIntent
		if err = m.readReconciliationJSON(ctx, m.reconciliationPath(op, "intent.json"), &intent); err != nil {
			return status, reconciliationPending(err)
		}
		status.OperationID = op
		status.Generation = intent.Generation
		if _, err = m.ReadLifecycleReconciliationReceipt(ctx, op); err == nil {
			status.State = "completed"
			return status, nil
		}
		status.State = "pending"
		m.mu.Lock()
		active := m.maintenance != nil && !reconciliationDone(m.maintenance.done)
		m.mu.Unlock()
		_, receiptErr := os.Lstat(m.reconciliationPath(op, "receipt.json"))
		status.ResumeAvailable = errors.Is(receiptErr, os.ErrNotExist) && !active && intent.AckCandidate != nil && validReconciliationIntent(intent) && m.reconciliationOperationClean(ctx, intent) == nil && m.validateReconciliation(ctx, intent) == nil && m.validateReconciliationObjects(intent, true) == nil
		return status, nil
	}
	m.mu.Lock()
	witness := m.releaseWitness
	m.mu.Unlock()
	if witness != nil && reconciliationDone(witness.Done) {
		status.Generation = witness.Receipt.Intent.Generation
		if witness.Ack.TransactionClosed && witness.Ack.Write.Known && witness.Ack.Write.Err != nil {
			status.State = "available"
			status.CanPreview = true
		} else {
			status.State = "unavailable"
		}
	}
	return status, nil
}
