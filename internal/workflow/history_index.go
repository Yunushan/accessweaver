package workflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yunushan/accessweaver/internal/profile"
)

const (
	historyIndexName            = ".workflow-history.index"
	historyRevisionName         = ".workflow-store-revision"
	historyHeaderBytes          = 4096
	historySlotBytes            = 2048
	historyMaxEntries           = 65536
	historyMaxInputBytes  int64 = 8 << 30
	historyMaxDetailBytes int64 = 128 << 20
)

type historyIndexHeader struct {
	Version   int              `json:"version"`
	Inventory HistoryInventory `json:"inventory"`
}
type historyIndexRow struct {
	Leaf     string               `json:"leaf"` // Exact filename bytes, base64, never a caller path.
	LeafHash string               `json:"leafHash"`
	Summary  HistoryRecordSummary `json:"summary"`
}
type historyReference struct {
	Version  int    `json:"v"`
	Snapshot string `json:"snapshot"`
	Slot     uint64 `json:"slot"`
}
type historyCursor struct {
	Version  int    `json:"v"`
	Snapshot string `json:"snapshot"`
	Next     uint64 `json:"next"`
}

func historyHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func newHistoryRevision() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// The revision is an intent: invalidate captured inventories BEFORE attempting
// a coordinated record mutation, even when that mutation subsequently fails.
// Caller owns the short transaction lease; GET never invokes this function.
func (m *Manager) bumpWorkflowStoreRevision() error {
	path := filepath.Join(m.storeRoot, historyRevisionName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return workflowStoreError(ErrHistoryUnavailable)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return workflowStoreError(err)
	}
	revision, err := newHistoryRevision()
	if err != nil {
		return workflowStoreError(err)
	}
	return workflowStoreError(profile.AtomicWrite(path, []byte(revision+"\n")))
}
func (m *Manager) readWorkflowStoreRevision() (string, error) {
	b, err := readWorkflowFile(filepath.Join(m.storeRoot, historyRevisionName), 49)
	if err != nil {
		return "", err
	}
	if len(b) != 49 || b[48] != '\n' || !historyHex(string(b[:48]), 48) {
		return "", ErrHistoryUnavailable
	}
	return string(b[:48]), nil
}

func historyFrame(value any, size int) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(payload) > size-36 {
		return nil, ErrHistoryCapacity
	}
	frame := make([]byte, size)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	digest := sha256.Sum256(payload)
	copy(frame[4:36], digest[:])
	copy(frame[36:], payload)
	return frame, nil
}
func decodeHistoryFrame(frame []byte, value any) error {
	if len(frame) < 36 {
		return ErrHistoryUnavailable
	}
	length := int(binary.BigEndian.Uint32(frame[:4]))
	if length < 2 || length > len(frame)-36 {
		return ErrHistoryUnavailable
	}
	payload := frame[36 : 36+length]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(frame[4:36], digest[:]) {
		return ErrHistoryUnavailable
	}
	for _, b := range frame[36+length:] {
		if b != 0 {
			return ErrHistoryUnavailable
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrHistoryUnavailable
	}
	return nil
}
func historyOpaque(value any) string {
	b, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(b)
}
func decodeHistoryOpaque(text string, value any) error {
	if len(text) == 0 || len(text) > 256 {
		return ErrHistoryInvalidRequest
	}
	b, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != text {
		return ErrHistoryInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrHistoryInvalidRequest
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrHistoryInvalidRequest
	}
	if historyOpaque(value) != text {
		return ErrHistoryInvalidRequest
	}
	return nil
}
func historyRecordReference(snapshot string, slot uint64) string {
	return historyOpaque(historyReference{1, snapshot, slot})
}

func (m *Manager) openHistoryIndex(ctx context.Context) (file *os.File, header historyIndexHeader, err error) {
	if cause := ctx.Err(); cause != nil {
		return nil, header, historyError(ErrHistoryUnavailable, cause)
	}
	path := filepath.Join(m.storeRoot, historyIndexName)
	named, cause := os.Lstat(path)
	if errors.Is(cause, os.ErrNotExist) {
		return nil, header, ErrHistoryInventoryNeeded
	}
	if cause != nil {
		return nil, header, historyError(ErrHistoryUnavailable, cause)
	}
	if !named.Mode().IsRegular() {
		return nil, header, ErrHistoryUnavailable
	}
	file, cause = os.Open(path)
	if cause != nil {
		return nil, header, historyError(ErrHistoryUnavailable, cause)
	}
	fail := func(cause error) (*os.File, historyIndexHeader, error) {
		closeErr := file.Close()
		return nil, header, historyError(ErrHistoryUnavailable, errors.Join(cause, closeErr))
	}
	opened, cause := file.Stat()
	if cause != nil {
		return fail(cause)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(named, opened) || opened.Size() < historyHeaderBytes || opened.Size() > historyHeaderBytes+int64(historyMaxEntries)*historySlotBytes {
		return fail(ErrHistoryUnavailable)
	}
	frame := make([]byte, historyHeaderBytes)
	if _, cause = io.ReadFull(file, frame); cause != nil {
		return fail(cause)
	}
	if cause = decodeHistoryFrame(frame, &header); cause != nil {
		return fail(cause)
	}
	inventory := header.Inventory
	if header.Version != 1 || !historyHex(inventory.Snapshot, 48) || !historyHex(inventory.StoreRevision, 48) || inventory.CreatedAt.IsZero() || inventory.Count > historyMaxEntries || inventory.TotalBytes < 0 || inventory.TotalBytes > historyMaxInputBytes || opened.Size() != historyHeaderBytes+int64(inventory.Count)*historySlotBytes {
		return fail(ErrHistoryUnavailable)
	}
	return file, header, nil
}
func readHistoryRow(file *os.File, slot uint64) (historyIndexRow, error) {
	var row historyIndexRow
	if slot >= historyMaxEntries {
		return row, ErrHistoryInvalidRequest
	}
	frame := make([]byte, historySlotBytes)
	if _, err := file.ReadAt(frame, historyHeaderBytes+int64(slot)*historySlotBytes); err != nil {
		return row, err
	}
	if err := decodeHistoryFrame(frame, &row); err != nil {
		return row, err
	}
	name, err := base64.RawURLEncoding.DecodeString(row.Leaf)
	if err != nil || len(name) == 0 || len(name) > 1024 || base64.RawURLEncoding.EncodeToString(name) != row.Leaf {
		return row, ErrHistoryUnavailable
	}
	leaf := string(name)
	if leaf == "." || leaf == ".." || filepath.Base(leaf) != leaf || filepath.IsAbs(leaf) || bytes.IndexByte(name, 0) >= 0 {
		return row, ErrHistoryUnavailable
	}
	digest := sha256.Sum256(name)
	if row.LeafHash != hex.EncodeToString(digest[:]) || row.Summary.RecordRef != "" || row.Summary.Protection != "retirement-unavailable" || row.Summary.Size < 0 || len(row.Summary.ID) > 48 || len(row.Summary.Action) > 64 || len(row.Summary.State) > 16 {
		return row, ErrHistoryUnavailable
	}
	switch row.Summary.Classification {
	case "canonical", "legacy", "malformed", "oversized", "special", "unreadable":
	default:
		return row, ErrHistoryUnavailable
	}
	switch row.Summary.State {
	case "running", "succeeded", "failed", "interrupted", "unknown":
	default:
		return row, ErrHistoryUnavailable
	}
	stem := strings.TrimSuffix(leaf, ".json")
	expectedID := ""
	if strings.HasSuffix(leaf, ".json") && historyHex(stem, 48) {
		expectedID = stem
	}
	if row.Summary.ID != expectedID || row.Summary.Action != "" && !knownHistoryAction(row.Summary.Action) {
		return row, ErrHistoryUnavailable
	}
	if row.Summary.RawAvailable && (!historyHex(row.Summary.Revision, 64) || filepath.Ext(leaf) != ".json" || row.Summary.Size > maxHistoryRecordBytes) || !row.Summary.RawAvailable && row.Summary.Revision != "" {
		return row, ErrHistoryUnavailable
	}
	return row, nil
}
func (m *Manager) verifyHistorySnapshot(ctx context.Context, snapshot string, strictRevision bool) error {
	file, header, err := m.openHistoryIndex(ctx)
	if err != nil {
		return err
	}
	closeErr := file.Close()
	if closeErr != nil {
		return historyError(ErrHistoryUnavailable, closeErr)
	}
	if header.Inventory.Snapshot != snapshot {
		return ErrHistoryInventoryStale
	}
	if strictRevision {
		revision, err := m.readWorkflowStoreRevision()
		if err != nil {
			return historyError(ErrHistoryInventoryStale, err)
		}
		if revision != header.Inventory.StoreRevision {
			return ErrHistoryInventoryStale
		}
	}
	return nil
}

func (m *Manager) readHistoryPage(ctx context.Context, query HistoryPageQuery) (page HistoryPage, err error) {
	if query.Limit == 0 {
		query.Limit = 64
	}
	if query.Limit < 1 || query.Limit > 128 || query.Snapshot != "" && !historyHex(query.Snapshot, 48) {
		return page, ErrHistoryInvalidRequest
	}
	cursor := historyCursor{Version: 1, Snapshot: query.Snapshot}
	if query.Cursor != "" {
		if cause := decodeHistoryOpaque(query.Cursor, &cursor); cause != nil {
			return page, cause
		}
		if cursor.Version != 1 || !historyHex(cursor.Snapshot, 48) || cursor.Next > historyMaxEntries || query.Snapshot != "" && query.Snapshot != cursor.Snapshot {
			return page, ErrHistoryInvalidRequest
		}
	}
	file, header, cause := m.openHistoryIndex(ctx)
	if cause != nil {
		return page, cause
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			page = HistoryPage{}
			err = historyError(ErrHistoryUnavailable, errors.Join(err, closeErr))
		}
	}()
	inventory := header.Inventory
	if cursor.Snapshot != "" && cursor.Snapshot != inventory.Snapshot {
		return page, ErrHistoryInventoryStale
	}
	if cursor.Next > inventory.Count {
		return page, ErrHistoryInvalidRequest
	}
	if cause = m.verifyHistorySnapshot(ctx, inventory.Snapshot, true); cause != nil {
		return page, cause
	}
	page.Inventory = inventory
	page.Items = make([]HistoryRecordSummary, 0, query.Limit)
	next := cursor.Next
	for next < inventory.Count && len(page.Items) < query.Limit {
		if cause := ctx.Err(); cause != nil {
			return HistoryPage{}, historyError(ErrHistoryUnavailable, cause)
		}
		row, cause := readHistoryRow(file, next)
		if cause != nil {
			return HistoryPage{}, historyError(ErrHistoryUnavailable, cause)
		}
		row.Summary.RecordRef = historyRecordReference(inventory.Snapshot, next)
		page.Items = append(page.Items, row.Summary)
		next++
	}
	if next < inventory.Count {
		page.NextCursor = historyOpaque(historyCursor{1, inventory.Snapshot, next})
	}
	if cause = m.verifyHistorySnapshot(ctx, inventory.Snapshot, true); cause != nil {
		return HistoryPage{}, cause
	}
	return page, nil
}
