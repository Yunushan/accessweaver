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
	"path/filepath"
	"unicode/utf8"
)

func (m *Manager) selectedHistoryRow(ctx context.Context, reference, revision string, raw bool) (row historyIndexRow, snapshot string, err error) {
	var ref historyReference
	if cause := decodeHistoryOpaque(reference, &ref); cause != nil {
		return row, "", cause
	}
	if ref.Version != 1 || !historyHex(ref.Snapshot, 48) || ref.Slot >= historyMaxEntries || revision != "" && !historyHex(revision, 64) || raw && !historyHex(revision, 64) {
		return row, "", ErrHistoryInvalidRequest
	}
	file, header, cause := m.openHistoryIndex(ctx)
	if cause != nil {
		return row, "", cause
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			row = historyIndexRow{}
			snapshot = ""
			err = historyError(ErrHistoryUnavailable, errors.Join(err, closeErr))
		}
	}()
	if header.Inventory.Snapshot != ref.Snapshot {
		return row, "", ErrHistoryInventoryStale
	}
	if ref.Slot >= header.Inventory.Count {
		return row, "", ErrHistoryInvalidRequest
	}
	row, cause = readHistoryRow(file, ref.Slot)
	if cause != nil {
		return row, "", historyError(ErrHistoryUnavailable, cause)
	}
	if row.Summary.RawAvailable && revision == "" {
		return historyIndexRow{}, "", ErrHistoryInvalidRequest
	}
	if row.Summary.Revision != revision {
		return historyIndexRow{}, "", ErrHistoryInventoryStale
	}
	if raw && !row.Summary.RawAvailable {
		return historyIndexRow{}, "", ErrHistoryRecordUnavailable
	}
	row.Summary.RecordRef = historyRecordReference(ref.Snapshot, ref.Slot)
	if cause = m.verifyHistorySnapshot(ctx, ref.Snapshot, false); cause != nil {
		return historyIndexRow{}, "", cause
	}
	return row, ref.Snapshot, nil
}
func (m *Manager) selectedHistoryBytes(ctx context.Context, row historyIndexRow, snapshot string) (data []byte, err error) {
	if !row.Summary.RawAvailable {
		return nil, ErrHistoryRecordUnavailable
	}
	leafBytes, cause := base64.RawURLEncoding.DecodeString(row.Leaf)
	if cause != nil || filepath.Ext(string(leafBytes)) != ".json" {
		return nil, ErrHistoryUnavailable
	}
	root, named, cause := m.openHistorySourceRoot()
	if cause != nil {
		return nil, historyError(ErrHistoryRecordUnavailable, cause)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			data = nil
			err = historyError(ErrHistoryRecordUnavailable, errors.Join(err, closeErr))
		}
	}()
	data, cause = readHistorySource(ctx, root, string(leafBytes), nil)
	if cause != nil {
		return nil, historyError(ErrHistoryRecordUnavailable, cause)
	}
	digest := sha256.Sum256(data)
	if int64(len(data)) != row.Summary.Size || hex.EncodeToString(digest[:]) != row.Summary.Revision {
		return nil, ErrHistoryInventoryStale
	}
	if cause = m.verifyHistorySourceRoot(named); cause != nil {
		return nil, historyError(ErrHistoryRecordUnavailable, cause)
	}
	// Selected immutable bytes remain useful while an unrelated workflow bumps
	// the global revision. A replaced inventory itself still invalidates refs.
	if cause = m.verifyHistorySnapshot(ctx, snapshot, false); cause != nil {
		return nil, cause
	}
	return data, nil
}
func (m *Manager) readHistoryRecordRaw(ctx context.Context, reference, revision string) ([]byte, error) {
	row, snapshot, err := m.selectedHistoryRow(ctx, reference, revision, true)
	if err != nil {
		return nil, err
	}
	return m.selectedHistoryBytes(ctx, row, snapshot)
}
func (m *Manager) readHistoryRecord(ctx context.Context, reference, revision string) (HistoryRecordDetail, error) {
	row, snapshot, err := m.selectedHistoryRow(ctx, reference, revision, false)
	if err != nil {
		return HistoryRecordDetail{}, err
	}
	detail := HistoryRecordDetail{Record: row.Summary, RawAvailable: row.Summary.RawAvailable}
	if !row.Summary.RawAvailable {
		return detail, nil
	}
	data, err := m.selectedHistoryBytes(ctx, row, snapshot)
	if err != nil {
		return HistoryRecordDetail{}, err
	}
	trimmed := bytes.TrimSpace(data)
	if utf8.Valid(data) && len(trimmed) > 0 && trimmed[0] == '{' {
		var job Job
		if json.Unmarshal(data, &job) == nil && validateResult(job.Result) == nil && knownHistoryTopFields(data) {
			detail.Job = &job
			// Whole-envelope preflight can reject valid standalone values too
			// deep or expanded to embed. Preserve raw-only access, never clip.
			if _, _, err := prepareHistoryDetail(detail); err != nil {
				detail.Job = nil
			}
		}
	}
	return detail, nil
}

type historyDetailBudget struct{ written int64 }

func (w *historyDetailBudget) Write(p []byte) (int, error) {
	if int64(len(p)) > historyMaxDetailBytes-w.written {
		return 0, ErrHistoryCapacity
	}
	w.written += int64(len(p))
	return len(p), nil
}
func writeHistoryDetailBody(out io.Writer, detail HistoryRecordDetail, metadata []byte, prepared *jobOutput) error {
	for _, part := range [][]byte{[]byte(`{"record":`), metadata} {
		if err := writeOutput(out, part); err != nil {
			return err
		}
	}
	if prepared != nil {
		if err := writeOutput(out, []byte(`,"job":`)); err != nil {
			return err
		}
		if err := prepared.writeTo(out); err != nil {
			return err
		}
	}
	ending := []byte(",\"rawAvailable\":false}\n")
	if detail.RawAvailable {
		ending = []byte(",\"rawAvailable\":true}\n")
	}
	return writeOutput(out, ending)
}
func prepareHistoryDetail(detail HistoryRecordDetail) ([]byte, *jobOutput, error) {
	metadata, err := json.Marshal(detail.Record)
	if err != nil {
		return nil, nil, err
	}
	if len(metadata) > historySlotBytes {
		return nil, nil, ErrHistoryCapacity
	}
	var prepared *jobOutput
	if detail.Job != nil {
		job, err := prepareJobOutput(*detail.Job, 2)
		if err != nil {
			return nil, nil, err
		}
		prepared = &job
	}
	if err := writeHistoryDetailBody(&historyDetailBudget{}, detail, metadata, prepared); err != nil {
		return nil, nil, err
	}
	return metadata, prepared, nil
}
func writeHistoryRecordDetailJSON(out io.Writer, detail HistoryRecordDetail) error {
	metadata, prepared, err := prepareHistoryDetail(detail)
	if err != nil {
		return err
	}
	return writeHistoryDetailBody(out, detail, metadata, prepared)
}
