package workflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

func (m *Manager) openHistorySourceRoot() (*os.Root, os.FileInfo, error) {
	named, err := os.Lstat(m.root)
	if err != nil {
		return nil, nil, err
	}
	if !named.IsDir() || named.Mode()&os.ModeSymlink != 0 {
		return nil, nil, ErrHistoryRecordUnavailable
	}
	root, err := os.OpenRoot(m.root)
	if err != nil {
		return nil, nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(named, opened) {
		closeErr := root.Close()
		return nil, nil, errors.Join(ErrHistoryRecordUnavailable, err, closeErr)
	}
	return root, named, nil
}
func (m *Manager) verifyHistorySourceRoot(named os.FileInfo) error {
	now, err := os.Lstat(m.root)
	if err != nil {
		return err
	}
	if !now.IsDir() || now.Mode()&os.ModeSymlink != 0 || !os.SameFile(named, now) {
		return ErrHistoryInventoryStale
	}
	return nil
}

type historyCountingReader struct {
	reader io.Reader
	total  *int64
}

func (r historyCountingReader) Read(p []byte) (int, error) {
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	if remaining := historyMaxInputBytes - *r.total; int64(len(p)) > remaining+1 {
		p = p[:int(remaining+1)]
	}
	n, err := r.reader.Read(p)
	*r.total += int64(n)
	if *r.total > historyMaxInputBytes {
		return n, ErrHistoryCapacity
	}
	return n, err
}

func readHistorySource(ctx context.Context, root *os.Root, leaf string, total *int64) (data []byte, err error) {
	if cause := ctx.Err(); cause != nil {
		return nil, cause
	}
	named, cause := root.Lstat(leaf)
	if cause != nil {
		return nil, cause
	}
	if !named.Mode().IsRegular() || named.Size() < 0 || named.Size() > maxHistoryRecordBytes {
		return nil, ErrHistoryRecordUnavailable
	}
	file, cause := root.Open(leaf)
	if cause != nil {
		return nil, cause
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			data = nil
			err = errors.Join(err, closeErr)
		}
	}()
	opened, cause := file.Stat()
	if cause != nil {
		return nil, cause
	}
	if !opened.Mode().IsRegular() || !os.SameFile(named, opened) {
		return nil, ErrHistoryInventoryStale
	}
	reader := io.Reader(file)
	if total != nil {
		reader = historyCountingReader{reader: reader, total: total}
	}
	data, cause = readBoundedContext(ctx, reader, maxHistoryRecordBytes)
	if cause != nil {
		return nil, cause
	}
	after, cause := file.Stat()
	if cause != nil {
		return nil, cause
	}
	namedAfter, cause := root.Lstat(leaf)
	if cause != nil {
		return nil, cause
	}
	if !namedAfter.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(opened, namedAfter) || opened.Size() != after.Size() || opened.Size() != int64(len(data)) || !opened.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(namedAfter.ModTime()) {
		return nil, ErrHistoryInventoryStale
	}
	return data, nil
}

type historyResultPresence struct{ data []byte }

func (p *historyResultPresence) UnmarshalJSON(data []byte) error { p.data = data; return nil }

type historyErrorPresence struct{ present, bounded bool }

func (p *historyErrorPresence) UnmarshalJSON(data []byte) error {
	p.bounded = true
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	p.present = !bytes.Equal(data, []byte(`""`))
	if len(data) > 6*maxJobErrorBytes+2 || len(data) == 0 || data[0] != '"' {
		p.bounded = false
		return nil
	}
	var text string
	if json.Unmarshal(data, &text) != nil || len(text) > maxJobErrorBytes {
		p.bounded = false
	}
	return nil
}

type historyJobMetadata struct {
	ID         string                `json:"id"`
	Action     string                `json:"action"`
	State      string                `json:"state"`
	StartedAt  time.Time             `json:"startedAt"`
	FinishedAt time.Time             `json:"finishedAt"`
	Error      historyErrorPresence  `json:"error"`
	Result     historyResultPresence `json:"result"`
}

func knownHistoryAction(action string) bool {
	for _, item := range Catalog() {
		if item.ID == action {
			return true
		}
	}
	return false
}
func knownHistoryTopFields(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return false
		}
		switch key {
		case "id", "action", "state", "startedAt", "finishedAt", "error", "result":
		default:
			return false
		}
		seen[key] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return false
		}
	}
	return true
}
func capturedHistorySummary(leaf string, data []byte) HistoryRecordSummary {
	digest := sha256.Sum256(data)
	summary := HistoryRecordSummary{Revision: hex.EncodeToString(digest[:]), Size: int64(len(data)), Classification: "legacy", Protection: "retirement-unavailable", State: "unknown", RawAvailable: true}
	name := strings.TrimSuffix(leaf, ".json")
	if strings.HasSuffix(leaf, ".json") && historyHex(name, 48) {
		summary.ID = name
	}
	trimmed := bytes.TrimSpace(data)
	if !utf8.Valid(data) || !json.Valid(data) || len(trimmed) == 0 || trimmed[0] != '{' {
		summary.Classification = "malformed"
		return summary
	}
	var metadata historyJobMetadata
	metadata.Error.bounded = true
	if json.Unmarshal(data, &metadata) != nil {
		return summary
	}
	if len(metadata.Action) <= 64 && knownHistoryAction(metadata.Action) {
		summary.Action = metadata.Action
	}
	switch metadata.State {
	case "succeeded", "failed":
		summary.State = metadata.State
	case "running":
		summary.State = "interrupted"
	}
	summary.StartedAt = metadata.StartedAt
	summary.FinishedAt = metadata.FinishedAt
	summary.ErrorPresent = metadata.Error.present
	summary.ResultPresent = len(metadata.Result.data) > 0
	validTimes := !metadata.StartedAt.IsZero() && (metadata.State == "running" && metadata.FinishedAt.IsZero() || (metadata.State == "succeeded" || metadata.State == "failed") && !metadata.FinishedAt.IsZero())
	if summary.ID != "" && metadata.ID == summary.ID && summary.Action != "" && summary.State != "unknown" && validTimes && metadata.Error.bounded && len(metadata.Result.data) <= maxResultBytes && validateResult(metadata.Result.data) == nil && knownHistoryTopFields(data) {
		summary.Classification = "canonical"
	}
	return summary
}

func (m *Manager) captureHistoryInventory(ctx context.Context) (inventory HistoryInventory, err error) {
	if cause := ctx.Err(); cause != nil {
		return inventory, historyError(ErrHistoryUnavailable, cause)
	}
	m.mu.Lock()
	closing, storeFailure := m.closing, m.storeFailure
	m.mu.Unlock()
	if storeFailure != nil {
		return inventory, storeFailure
	}
	if closing {
		return inventory, historyError(ErrHistoryUnavailable, errors.New("workflow manager is shutting down"))
	}
	active, cause := m.acquireWorkflowStoreLease(workflowActiveLockName)
	if cause != nil {
		return inventory, cause
	}
	defer func() {
		if closeErr := m.closeWorkflowStoreLease(active); closeErr != nil {
			inventory = HistoryInventory{}
			err = historyError(ErrHistoryUnavailable, errors.Join(err, closeErr))
		}
	}()
	// Inspect the existing derived index outside the short transaction.
	prior, cause := inspectHistoryStage(filepath.Join(m.storeRoot, historyIndexName), historyStageMaxBytes, nil, nil)
	if cause != nil && !errors.Is(cause, os.ErrNotExist) {
		return inventory, historyStagePending(cause)
	}
	transaction, cause := m.acquireWorkflowStoreLease(workflowTransactionLockName)
	if cause != nil {
		return inventory, cause
	}
	cause = m.historyStageScan(ctx)
	var revision string
	if cause == nil {
		revision, cause = m.readWorkflowStoreRevision()
	}
	if errors.Is(cause, os.ErrNotExist) {
		var beforeEpochPublish func(string, string) error
		if hooks := m.historyStagingHooks; hooks != nil {
			beforeEpochPublish = hooks.beforeEpochPublish
		}
		cause = m.bumpWorkflowStoreRevisionObserved(beforeEpochPublish)
		if cause == nil {
			revision, cause = m.readWorkflowStoreRevision()
		}
	}
	snapshot, randomErr := newHistoryRevision()
	if cause == nil {
		cause = randomErr
	}
	var reservation *historyStageReservation
	if cause == nil {
		reservation, cause = m.reserveHistoryStage(ctx, snapshot, revision, prior)
	}
	closeErr := m.closeWorkflowStoreLease(transaction)
	if cause != nil || closeErr != nil {
		combined := errors.Join(cause, closeErr)
		if reservation == nil && closeErr == nil && !errors.Is(cause, ErrHistoryStagingPending) {
			if historyDiscardableStageError(combined) || errors.Is(cause, errHistoryCaptureClosing) {
				return inventory, historyError(ErrHistoryUnavailable, combined)
			}
			// Failed epoch bootstrap may already own a retained private49byte stage.
			// Observe names only; never infer closure or remove it from the failure tag.
			if scanErr := m.historyStageScan(context.Background()); scanErr == nil {
				return inventory, historyError(ErrHistoryUnavailable, combined)
			} else {
				combined = errors.Join(combined, scanErr)
			}
		}
		return inventory, historyStagePending(combined)
	}
	defer func() {
		if err != nil && ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
			err = errors.Join(err, ctx.Err())
		}
		err = reservation.FinishFailure(err)
		if err != nil {
			inventory = HistoryInventory{}
		}
	}()
	inventory = HistoryInventory{Snapshot: snapshot, StoreRevision: revision, CreatedAt: time.Now().UTC()}
	temporary, cause := reservation.Create()
	if cause != nil {
		return HistoryInventory{}, cause
	}
	// Never repair or delete the source history.
	if _, cause = temporary.Write(make([]byte, historyHeaderBytes)); cause != nil {
		return HistoryInventory{}, historyError(ErrHistoryUnavailable, cause)
	}
	source, named, cause := m.openHistorySourceRoot()
	if cause != nil && !errors.Is(cause, os.ErrNotExist) {
		return HistoryInventory{}, historyError(ErrHistoryUnavailable, cause)
	}
	if source != nil {
		directory, openErr := source.Open(".")
		if openErr != nil {
			return HistoryInventory{}, historyError(ErrHistoryUnavailable, errors.Join(openErr, source.Close()))
		}
		scanErr := func() error {
			for {
				if cause := ctx.Err(); cause != nil {
					return cause
				}
				entries, readErr := directory.ReadDir(128)
				if readErr != nil && !errors.Is(readErr, io.EOF) {
					return readErr
				}
				for _, entry := range entries {
					if inventory.Count == historyMaxEntries {
						return ErrHistoryCapacity
					}
					if cause := ctx.Err(); cause != nil {
						return cause
					}
					leaf := entry.Name()
					leafBytes := []byte(leaf)
					leafDigest := sha256.Sum256(leafBytes)
					row := historyIndexRow{Leaf: base64.RawURLEncoding.EncodeToString(leafBytes), LeafHash: hex.EncodeToString(leafDigest[:]), Summary: HistoryRecordSummary{State: "unknown", Classification: "special", Protection: "retirement-unavailable"}}
					if base := strings.TrimSuffix(leaf, ".json"); strings.HasSuffix(leaf, ".json") && historyHex(base, 48) {
						row.Summary.ID = base
					}
					info, infoErr := source.Lstat(leaf)
					switch {
					case infoErr != nil:
						row.Summary.Classification = "unreadable"
					case !info.Mode().IsRegular():
						row.Summary.Classification = "special"
					default:
						row.Summary.Size = info.Size()
						if info.Size() < 0 {
							return ErrHistoryUnavailable
						}
						if !strings.HasSuffix(leaf, ".json") {
							row.Summary.Classification = "legacy"
						} else if info.Size() > maxHistoryRecordBytes {
							row.Summary.Classification = "oversized"
						} else {
							data, readErr := readHistorySource(ctx, source, leaf, &inventory.TotalBytes)
							if readErr != nil {
								if errors.Is(readErr, ErrHistoryCapacity) || ctx.Err() != nil {
									return readErr
								}
								row.Summary.Classification = "unreadable"
							} else {
								row.Summary = capturedHistorySummary(leaf, data)
							}
						}
					}
					frame, frameErr := historyFrame(row, historySlotBytes)
					if frameErr != nil {
						return frameErr
					}
					if _, writeErr := temporary.Write(frame); writeErr != nil {
						return writeErr
					}
					inventory.Count++
				}
				if errors.Is(readErr, io.EOF) {
					return nil
				}
			}
		}()
		scanErr = errors.Join(scanErr, directory.Close(), source.Close(), m.verifyHistorySourceRoot(named))
		if scanErr != nil {
			return HistoryInventory{}, historyError(ErrHistoryUnavailable, scanErr)
		}
	}
	if cause = ctx.Err(); cause != nil {
		return HistoryInventory{}, historyError(ErrHistoryUnavailable, cause)
	}
	header, cause := historyFrame(historyIndexHeader{1, inventory}, historyHeaderBytes)
	if cause != nil {
		return HistoryInventory{}, historyError(ErrHistoryUnavailable, cause)
	}
	if _, cause = temporary.WriteAt(header, 0); cause != nil {
		return HistoryInventory{}, historyError(ErrHistoryUnavailable, cause)
	}
	if cause = temporary.Sync(); cause != nil {
		return HistoryInventory{}, historyError(ErrHistoryUnavailable, cause)
	}
	if cause = temporary.Close(); cause != nil {
		return HistoryInventory{}, historyStagePending(cause)
	}
	if cause = reservation.Prepared(); cause != nil {
		return HistoryInventory{}, cause
	}
	if cause = reservation.Publish(ctx); cause != nil {
		return HistoryInventory{}, cause
	}
	return inventory, nil
}

// Ignore only the fixed outer category while deciding whether all underlying
// causes prove a clean pre-publication cancellation/capacity refusal.
func historyDiscardableStageError(err error) bool {
	if err == nil {
		return false
	}
	if fixed, ok := err.(*historyFailure); ok {
		return historyDiscardableStageError(fixed.cause)
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !historyDiscardableStageError(cause) {
				return false
			}
		}
		return true
	}
	return err == context.Canceled || err == context.DeadlineExceeded || err == ErrHistoryCapacity
}
