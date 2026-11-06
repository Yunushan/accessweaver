package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

// Reads are confined to the retained config root and reject symlinked metadata
// ancestors. Native IDs detect replacement; they never establish owner closure.
func (m *Manager) readReconciliationBytes(ctx context.Context, path string) (data []byte, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(m.storeRoot, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, ErrLifecycleReconciliationConflict
	}
	root, err := os.OpenRoot(m.storeRoot)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := root.Close(); err != nil {
			data = nil
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, err))
		}
	}()
	parts := strings.Split(relative, string(filepath.Separator))
	parents := make([]os.FileInfo, 0, len(parts)-1)
	for n := 1; n < len(parts); n++ {
		info, err := root.Lstat(filepath.Join(parts[:n]...))
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeType != os.ModeDir {
			return nil, ErrLifecycleReconciliationConflict
		}
		parents = append(parents, info)
	}
	named, err := root.Lstat(relative)
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() || named.Size() < 0 || named.Size() > workflowLifecycleMaxReceiptBytes {
		return nil, ErrLifecycleReconciliationConflict
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			data = nil
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, err))
		}
	}()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(named, opened) {
		return nil, errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	data, err = io.ReadAll(io.LimitReader(file, workflowLifecycleMaxReceiptBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := root.Lstat(relative)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(after, current) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(data)) != after.Size() || len(data) > workflowLifecycleMaxReceiptBytes {
		return nil, errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	for n, before := range parents {
		now, err := root.Lstat(filepath.Join(parts[:n+1]...))
		if err != nil || now.Mode()&os.ModeType != os.ModeDir || !os.SameFile(before, now) {
			return nil, errors.Join(ErrLifecycleReconciliationConflict, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}
func validReconciliationObject(object closedLifecycleStage) bool {
	return object.Identity != "" && len(object.Identity) <= 128 && object.Size >= 0 && object.Size <= workflowLifecycleMaxReceiptBytes && historyHex(object.SHA256, 64) && object.Links >= 1 && object.Links <= 2
}
func (m *Manager) validateReconciliationReceipt(ctx context.Context, receipt LifecycleReconciliationReceipt) error {
	var intent reconciliationIntent
	if err := m.readReconciliationJSON(ctx, m.reconciliationPath(receipt.OperationID, "intent.json"), &intent); err != nil {
		return err
	}
	if !validReconciliationIntent(intent) || intent.OperationID != receipt.OperationID || intent.AckCandidate == nil || receipt.Generation != intent.Generation || receipt.IntentSHA256 != intent.Receipt.IntentSHA256 || receipt.SealSHA256 != intent.Receipt.SealSHA256 || !reflect.DeepEqual(receipt.Quarantined, reconciliationObjects(intent)) {
		return ErrLifecycleReconciliationConflict
	}
	root, err := m.reconciliationRoot()
	if err != nil || root != intent.Root {
		return errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	chain, err := m.readWorkflowLifecycleChain(ctx, intent.Generation)
	if err != nil || chain.IntentSHA256 != intent.Receipt.IntentSHA256 || chain.SealSHA256 != intent.Receipt.SealSHA256 || chain.Ack == nil || receipt.AckSHA256 != workflowLifecycleJSONHash(*chain.Ack) {
		return errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	if err = m.reconciliationOperationClean(ctx, intent); err != nil {
		return err
	}
	if err = m.validateReconciliationObjects(intent, true); err != nil {
		return err
	}
	for _, object := range intent.Objects {
		if _, err = os.Lstat(filepath.Join(m.storeRoot, workflowLifecycleDirectory, object.Name)); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrLifecycleReconciliationConflict, err)
		}
		target := m.reconciliationPath(intent.OperationID, filepath.Join("quarantine", closedStagePublic(intent.Generation, object).Ref+".metadata"))
		current, err := inspectLifecycleObject(target)
		if err != nil || !sameReconciliationContent(current, object) {
			return errors.Join(ErrLifecycleReconciliationConflict, err)
		}
	}
	return nil
}

// Canonical encoding makes intent/receipt revisions independent of decoder
// unknown-field or duplicate-key behavior.
func decodeReconciliationJSON(data []byte, value any) error {
	if err := decodeWorkflowLifecycle(data, value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil || string(canonical) != string(data) {
		return errors.Join(ErrLifecycleReconciliationConflict, err)
	}
	return nil
}
