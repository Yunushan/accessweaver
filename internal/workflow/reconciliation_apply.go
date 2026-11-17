package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

func (m *Manager) pendingReconciliation(ctx context.Context) (string, error) {
	dir := filepath.Join(m.storeRoot, reconciliationDirectory)
	named, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || named.Mode()&os.ModeType != os.ModeDir {
		return "", reconciliationPending(err)
	}
	file, err := os.Open(dir)
	if err != nil {
		return "", reconciliationPending(err)
	}
	entries, readErr := file.ReadDir(reconciliationMaxOperations + 1)
	closeErr := file.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > reconciliationMaxOperations {
		return "", reconciliationPending(errors.Join(readErr, workflowFailure(ErrWorkflowCleanup, closeErr)))
	}
	pending := ""
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		if !historyHex(entry.Name(), 48) || !entry.IsDir() {
			return "", ErrLifecycleReconciliationPending
		}
		var intent reconciliationIntent
		if err = m.readReconciliationJSON(ctx, m.reconciliationPath(entry.Name(), "intent.json"), &intent); err != nil || !validReconciliationIntent(intent) || intent.AckCandidate == nil {
			return "", reconciliationPending(err)
		}
		if _, err = m.ReadLifecycleReconciliationReceipt(ctx, entry.Name()); err != nil {
			if pending != "" {
				return "", ErrLifecycleReconciliationPending
			}
			pending = entry.Name()
		}
	}
	return pending, nil
}
func sameReconciliationContent(a, b closedLifecycleStage) bool {
	return a.Identity == b.Identity && a.Size == b.Size && a.SHA256 == b.SHA256
}
func (m *Manager) validateReconciliationObjects(intent reconciliationIntent, moving bool) error {
	for _, object := range intent.Objects {
		source := filepath.Join(m.storeRoot, workflowLifecycleDirectory, object.Name)
		ref := closedStagePublic(intent.Generation, object).Ref
		target := m.reconciliationPath(intent.OperationID, filepath.Join("quarantine", ref+".metadata"))
		a, aerr := inspectLifecycleObject(source)
		b, berr := inspectLifecycleObject(target)
		if aerr != nil && !errors.Is(aerr, os.ErrNotExist) {
			return aerr
		}
		if berr != nil && !errors.Is(berr, os.ErrNotExist) {
			return berr
		}
		if aerr == nil && !sameReconciliationContent(a, object) || berr == nil && !sameReconciliationContent(b, object) {
			return ErrLifecycleReconciliationConflict
		}
		if aerr != nil && berr != nil {
			return ErrLifecycleReconciliationConflict
		}
		expected := object.Links
		if aerr == nil && berr == nil {
			expected++
		}
		if aerr == nil && a.Links != expected || berr == nil && b.Links != expected {
			return ErrLifecycleReconciliationConflict
		}
		if !moving && intent.AckCandidate == nil && berr == nil {
			return ErrLifecycleReconciliationConflict
		}
	}
	ack, err := inspectLifecycleObject(m.lifecycleReceiptPath(intent.Generation, "ack"))
	if errors.Is(err, os.ErrNotExist) {
		if intent.AckBefore != nil {
			return ErrLifecycleReconciliationConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	expected := intent.AckBefore
	if expected == nil {
		expected = intent.AckCandidate
	}
	if expected == nil || !sameReconciliationContent(ack, *expected) {
		return ErrLifecycleReconciliationConflict
	}
	return nil
}
func (m *Manager) ApplyLifecycleReconciliation(ctx context.Context, id string) (receipt LifecycleReconciliationReceipt, failure error) {
	if !historyHex(id, 48) {
		return receipt, ErrLifecycleReconciliationInvalidRequest
	}
	m.startMu.Lock()
	defer m.startMu.Unlock()
	m.mu.Lock()
	plan := m.reconciliationPlans[id]
	closing := m.closing
	storeErr := m.storeFailure
	busy := m.maintenance != nil && !reconciliationDone(m.maintenance.done)
	m.mu.Unlock()
	if plan == nil {
		return receipt, ErrLifecycleReconciliationExpired
	}
	if closing || busy || storeErr != nil {
		return receipt, reconciliationError(ErrLifecycleReconciliationUnavailable, storeErr)
	}
	freshAuthorization, grantErr := m.guard.AuthorizeLifecycleReconciliation()
	if grantErr != nil {
		return receipt, grantErr
	}
	oldBinding, bindingErr := plan.Authorization.ReviewBinding()
	if bindingErr != nil {
		return receipt, bindingErr
	}
	freshBinding, bindingErr := freshAuthorization.ReviewBinding()
	if bindingErr != nil {
		return receipt, bindingErr
	}
	if oldBinding != freshBinding {
		return receipt, ErrLifecycleReconciliationConflict
	}
	if err := plan.Authorization.Check(); err != nil {
		return receipt, err
	}
	if time.Now().After(plan.Public.ExpiresAt) {
		return receipt, ErrLifecycleReconciliationExpired
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	if done, err := m.ReadLifecycleReconciliationReceipt(ctx, plan.Public.OperationID); err == nil {
		return done, nil
	}
	if !plan.Public.Resume {
		m.mu.Lock()
		same := m.releaseWitness == plan.Live
		m.mu.Unlock()
		if !same || plan.Live == nil || !reconciliationDone(plan.Live.Done) {
			return receipt, ErrLifecycleReconciliationUnavailable
		}
	}
	owned, cancel := context.WithCancel(ctx)
	completion := &reconciliationCompletion{done: make(chan struct{}), cancel: cancel, operation: plan.Public.OperationID}
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		cancel()
		return receipt, ErrLifecycleReconciliationUnavailable
	}
	m.maintenance = completion
	m.mu.Unlock()
	defer func() { cancel(); m.mu.Lock(); completion.err = failure; close(completion.done); m.mu.Unlock() }()
	active, err := m.acquireWorkflowStoreLease(workflowActiveLockName)
	if err != nil {
		return receipt, err
	}
	activeClosed := false
	defer func() {
		if !activeClosed {
			if closeErr := m.closeWorkflowStoreLease(active); closeErr != nil {
				failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, closeErr))
				receipt = LifecycleReconciliationReceipt{}
			}
		}
	}()
	if err = m.validateReconciliation(owned, plan.Intent); err != nil {
		return receipt, err
	}
	if err = m.validateReconciliationObjects(plan.Intent, true); err != nil {
		return receipt, reconciliationError(ErrLifecycleReconciliationConflict, err)
	}
	if err = plan.Authorization.Check(); err != nil {
		return receipt, err
	}
	dir := filepath.Join(m.storeRoot, reconciliationDirectory)
	if err = os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return receipt, reconciliationPending(err)
	}
	named, err := os.Lstat(dir)
	if err != nil || named.Mode()&os.ModeType != os.ModeDir {
		return receipt, reconciliationPending(err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return receipt, reconciliationPending(err)
	}
	entries, readErr := directory.ReadDir(reconciliationMaxOperations + 1)
	closeErr := directory.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > reconciliationMaxOperations {
		return receipt, reconciliationPending(errors.Join(readErr, workflowFailure(ErrWorkflowCleanup, closeErr)))
	}
	operationDir := m.reconciliationPath(plan.Public.OperationID, "")
	if !plan.Public.Resume {
		if len(entries) >= reconciliationMaxOperations {
			return receipt, ErrLifecycleReconciliationUnavailable
		}
		if err = os.Mkdir(operationDir, 0700); err != nil && !(errors.Is(err, os.ErrExist) && plan.Intent.AckCandidate != nil) {
			return receipt, reconciliationPending(err)
		}
		if plan.Intent.AckCandidate == nil {
			candidatePath := m.reconciliationPath(plan.Public.OperationID, "ack-candidate.json")
			ack := workflowLifecycleAck{1, plan.Intent.Receipt.IntentSHA256, plan.Intent.Receipt.SealSHA256, true, reconciliationProtection}
			if err = m.writeReconciliationJSON(candidatePath, ack); err != nil {
				return receipt, reconciliationPending(err)
			}
			candidate, inspectErr := inspectLifecycleObject(candidatePath)
			if inspectErr != nil {
				return receipt, reconciliationPending(inspectErr)
			}
			plan.Intent.AckCandidate = &candidate
		}
		if err = m.reconciliationOperationClean(owned, plan.Intent); err != nil {
			return receipt, reconciliationPending(err)
		}
		if err = plan.Authorization.Check(); err != nil {
			return receipt, err
		}
		intentPath := m.reconciliationPath(plan.Public.OperationID, "intent.json")
		var saved reconciliationIntent
		readIntentErr := m.readReconciliationJSON(owned, intentPath, &saved)
		if readIntentErr == nil {
			if workflowLifecycleJSONHash(saved) != workflowLifecycleJSONHash(plan.Intent) {
				return receipt, ErrLifecycleReconciliationConflict
			}
		} else if errors.Is(readIntentErr, os.ErrNotExist) {
			if err = m.writeReconciliationJSON(intentPath, plan.Intent); err != nil {
				return receipt, reconciliationPending(err)
			}
		} else {
			return receipt, reconciliationPending(readIntentErr)
		}
	}
	if !validReconciliationIntent(plan.Intent) || plan.Intent.AckCandidate == nil {
		return receipt, ErrLifecycleReconciliationUnavailable
	}
	if err = m.reconciliationOperationClean(owned, plan.Intent); err != nil {
		return receipt, reconciliationPending(err)
	}
	if err = m.setReconciliationCurrent(owned, plan.Intent); err != nil {
		return receipt, reconciliationPending(err)
	}
	if err = os.Mkdir(m.reconciliationPath(plan.Public.OperationID, "quarantine"), 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return receipt, reconciliationPending(err)
	}
	if err = m.reconciliationOperationClean(owned, plan.Intent); err != nil {
		return receipt, reconciliationPending(err)
	}
	transaction, err := m.acquireWorkflowStoreLease(workflowTransactionLockName)
	if err != nil {
		return receipt, err
	}
	transactionClosed := false
	defer func() {
		if !transactionClosed {
			if closeErr := m.closeWorkflowStoreLease(transaction); closeErr != nil {
				failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, closeErr))
				receipt = LifecycleReconciliationReceipt{}
			}
		}
	}()
	for _, object := range plan.Intent.Objects {
		if err = owned.Err(); err != nil {
			return receipt, err
		}
		if err = plan.Authorization.Check(); err != nil {
			return receipt, err
		}
		if err = m.validateReconciliationObjects(plan.Intent, true); err != nil {
			return receipt, reconciliationPending(err)
		}
		source := filepath.Join(m.storeRoot, workflowLifecycleDirectory, object.Name)
		target := m.reconciliationPath(plan.Public.OperationID, filepath.Join("quarantine", closedStagePublic(plan.Intent.Generation, object).Ref+".metadata"))
		if _, err = os.Lstat(target); errors.Is(err, os.ErrNotExist) {
			if err = os.Link(source, target); err != nil {
				return receipt, reconciliationPending(err)
			}
		} else if err != nil {
			return receipt, reconciliationPending(err)
		}
		if err = m.validateReconciliationObjects(plan.Intent, true); err != nil {
			return receipt, reconciliationPending(err)
		}
		if _, err = os.Lstat(source); err == nil {
			if err = os.Remove(source); err != nil {
				return receipt, reconciliationPending(err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return receipt, reconciliationPending(err)
		}
	}
	if err = owned.Err(); err != nil {
		return receipt, err
	}
	if err = plan.Authorization.Check(); err != nil {
		return receipt, err
	}
	candidatePath := m.reconciliationPath(plan.Public.OperationID, "ack-candidate.json")
	candidate, err := inspectLifecycleObject(candidatePath)
	if err != nil || !sameReconciliationContent(candidate, *plan.Intent.AckCandidate) {
		return receipt, reconciliationPending(err)
	}
	ackPath := m.lifecycleReceiptPath(plan.Intent.Generation, "ack")
	if _, err = os.Lstat(ackPath); errors.Is(err, os.ErrNotExist) {
		if err = os.Link(candidatePath, ackPath); err != nil {
			return receipt, reconciliationPending(err)
		}
	} else if err != nil {
		return receipt, reconciliationPending(err)
	}
	if err = m.validateReconciliationObjects(plan.Intent, true); err != nil {
		return receipt, reconciliationPending(err)
	}
	transactionClosed = true
	if err = m.closeWorkflowStoreLease(transaction); err != nil {
		return receipt, workflowFailure(ErrWorkflowCleanup, err)
	}
	activeClosed = true
	if err = m.closeWorkflowStoreLease(active); err != nil {
		return receipt, workflowFailure(ErrWorkflowCleanup, err)
	}
	if err = owned.Err(); err != nil {
		return receipt, err
	}
	if err = plan.Authorization.Check(); err != nil {
		return receipt, err
	}
	// Final publication uses a fresh short lease; original maintenance data/lease
	// owners are already observed closed. This writer's last Close is not a
	// recursive certification of itself.
	final, err := m.acquireWorkflowStoreLease(workflowTransactionLockName)
	if err != nil {
		return receipt, err
	}
	defer func() {
		if closeErr := m.closeWorkflowStoreLease(final); closeErr != nil {
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, closeErr))
			receipt = LifecycleReconciliationReceipt{}
		}
	}()
	receipt = LifecycleReconciliationReceipt{OperationID: plan.Intent.OperationID, Generation: plan.Intent.Generation, State: "completed", Action: reconciliationAction, IntentSHA256: plan.Intent.Receipt.IntentSHA256, SealSHA256: plan.Intent.Receipt.SealSHA256, AckSHA256: workflowLifecycleJSONHash(workflowLifecycleAck{1, plan.Intent.Receipt.IntentSHA256, plan.Intent.Receipt.SealSHA256, true, reconciliationProtection}), Quarantined: reconciliationObjects(plan.Intent), CompletedAt: time.Now().UTC(), Scope: reconciliationScope, Protection: reconciliationProtection}
	if err = m.writeReconciliationJSON(m.reconciliationPath(plan.Intent.OperationID, "receipt.json"), receipt); err != nil {
		return LifecycleReconciliationReceipt{}, reconciliationPending(err)
	}
	m.mu.Lock()
	if m.releaseWitness == plan.Live {
		m.releaseWitness = nil
	}
	m.mu.Unlock()
	return receipt, nil
}
func (m *Manager) setReconciliationCurrent(ctx context.Context, intent reconciliationIntent) error {
	path := filepath.Join(m.storeRoot, reconciliationCurrent)
	previous := ""
	b, err := readWorkflowLifecycleFile(ctx, path, workflowLifecycleMaxReceiptBytes)
	if err == nil {
		previous = workflowLifecycleHash(b)
		var pointer struct {
			Version      int    `json:"version"`
			OperationID  string `json:"operationId"`
			IntentSHA256 string `json:"intentSHA256"`
		}
		if decodeWorkflowLifecycle(b, &pointer) != nil {
			return ErrLifecycleReconciliationConflict
		}
		if pointer.OperationID == intent.OperationID && pointer.IntentSHA256 == workflowLifecycleJSONHash(intent) {
			return nil
		}
		if _, err = m.ReadLifecycleReconciliationReceipt(ctx, pointer.OperationID); err != nil {
			return ErrLifecycleReconciliationPending
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	value := struct {
		Version      int    `json:"version"`
		OperationID  string `json:"operationId"`
		IntentSHA256 string `json:"intentSHA256"`
	}{1, intent.OperationID, workflowLifecycleJSONHash(intent)}
	encoded, _ := json.Marshal(value)
	return writeWorkflowLifecycleFile(path, encoded, previous)
}
