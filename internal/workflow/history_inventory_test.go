package workflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func historyUnitRecord(t *testing.T, m *Manager, leaf string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.root, leaf), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func historyUnitJob(t *testing.T, id string) []byte {
	t.Helper()
	now := time.Date(2026, 11, 1, 1, 2, 3, 0, time.UTC)
	data, err := json.Marshal(Job{ID: id, Action: "discover", State: "succeeded", StartedAt: now, FinishedAt: now.Add(time.Second), Result: json.RawMessage(`{"fixture":"complete"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func historyUnitCapture(t *testing.T, m *Manager) HistoryInventory {
	t.Helper()
	inventory, err := m.CaptureHistoryInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}
func historyUnitAll(t *testing.T, m *Manager, snapshot string) []HistoryRecordSummary {
	t.Helper()
	var rows []HistoryRecordSummary
	cursor := ""
	for {
		page, err := m.HistoryPage(context.Background(), HistoryPageQuery{Limit: 1, Snapshot: snapshot, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 1 {
			t.Fatal("page exceeded requested row budget")
		}
		rows = append(rows, page.Items...)
		cursor = page.NextCursor
		if cursor == "" {
			return rows
		}
	}
}

func TestWorkflowHistoryReadOnlyMissingIndexCreatesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	m := New(root)
	if _, err := m.HistoryPage(context.Background(), HistoryPageQuery{}); !errors.Is(err, ErrHistoryInventoryNeeded) {
		t.Fatal("missing page did not require explicit capture")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.HistoryPage(canceled, HistoryPageQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatal("ended page did not retain its context cause")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("GET initialized a missing history store")
	}
}

func TestWorkflowHistoryInventoryProtectsLegacyAndExactRawBytes(t *testing.T) {
	root := t.TempDir()
	m := New(root)
	id := strings.Repeat("a", 48)
	canonical := historyUnitJob(t, id)
	odd := historyUnitJob(t, "unrelated-json-id")
	malformed := []byte{'{', '"', 'x', '"', ':', 0xff, '}'}
	historyUnitRecord(t, m, id+".json", canonical)
	historyUnitRecord(t, m, "odd.json", odd)
	historyUnitRecord(t, m, "invalid.json", malformed)
	historyUnitRecord(t, m, "scratch", []byte("unrelated retained evidence"))
	if err := os.Mkdir(filepath.Join(m.root, "special.json"), 0700); err != nil {
		t.Fatal(err)
	}
	inventory := historyUnitCapture(t, m)
	if inventory.Count != 5 || inventory.TotalBytes != int64(len(canonical)+len(odd)+len(malformed)) {
		t.Fatal("inventory omitted observed evidence or miscounted source bytes")
	}
	rows := historyUnitAll(t, New(root), inventory.Snapshot)
	counts := map[string]int{}
	var selected HistoryRecordSummary
	for _, row := range rows {
		counts[row.Classification]++
		if row.Protection != "retirement-unavailable" {
			t.Fatal("inventory granted retirement authority")
		}
		if row.ID == id {
			selected = row
			if row.Classification != "canonical" || row.Action != "discover" || !row.ResultPresent || row.ErrorPresent {
				t.Fatal("canonical bounded metadata was lost")
			}
		}
		detail, err := New(root).ReadHistoryRecord(context.Background(), row.RecordRef, row.Revision)
		if err != nil {
			t.Fatal(err)
		}
		if !row.RawAvailable {
			if detail.Job != nil || detail.RawAvailable {
				t.Fatal("special entry became a typed/raw record")
			}
			if _, err := m.ReadHistoryRecordRaw(context.Background(), row.RecordRef, ""); !errors.Is(err, ErrHistoryInvalidRequest) {
				t.Fatal("raw request accepted no revision")
			}
		}
	}
	if counts["canonical"] != 1 || counts["legacy"] != 2 || counts["malformed"] != 1 || counts["special"] != 1 {
		t.Fatal("protected evidence classifications changed")
	}
	raw, err := New(root).ReadHistoryRecordRaw(context.Background(), selected.RecordRef, selected.Revision)
	if err != nil || !bytes.Equal(raw, canonical) {
		t.Fatal("fresh manager did not return captured exact bytes")
	}
	detail, err := m.ReadHistoryRecord(context.Background(), selected.RecordRef, selected.Revision)
	if err != nil || detail.Job == nil {
		t.Fatal("canonical typed detail unavailable")
	}
	var encoded bytes.Buffer
	if err := WriteHistoryRecordDetailJSON(&encoded, detail); err != nil || !json.Valid(encoded.Bytes()) {
		t.Fatal("detail envelope did not stream valid complete JSON")
	}
	var decoded struct {
		Job Job `json:"job"`
	}
	if json.Unmarshal(encoded.Bytes(), &decoded) != nil || !bytes.Equal(decoded.Job.Result, json.RawMessage(`{"fixture":"complete"}`)) {
		t.Fatal("typed detail changed retained result values")
	}
	changed := append([]byte(nil), canonical...)
	changed[len(changed)-2] ^= 1
	if err := os.WriteFile(filepath.Join(m.root, id+".json"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadHistoryRecordRaw(context.Background(), selected.RecordRef, selected.Revision); !errors.Is(err, ErrHistoryInventoryStale) {
		t.Fatal("fresh content hash accepted external source drift")
	}
}

func TestWorkflowHistoryPagesDoNotReadSourceRecords(t *testing.T) {
	m := New(t.TempDir())
	id := strings.Repeat("b", 48)
	historyUnitRecord(t, m, id+".json", historyUnitJob(t, id))
	inventory := historyUnitCapture(t, m)
	if err := os.RemoveAll(m.root); err != nil {
		t.Fatal(err)
	} // Only this test-owned source tree.
	page, err := m.HistoryPage(context.Background(), HistoryPageQuery{Snapshot: inventory.Snapshot})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != id {
		t.Fatal("metadata page reread or required original payload files")
	}
	if _, err := m.ReadHistoryRecordRaw(context.Background(), page.Items[0].RecordRef, page.Items[0].Revision); !errors.Is(err, ErrHistoryRecordUnavailable) {
		t.Fatal("exact detail ignored missing source evidence")
	}
}

func TestWorkflowHistoryFailedWriteInvalidatesPageButNotUnchangedSelection(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	id := strings.Repeat("c", 48)
	original := historyUnitJob(t, id)
	historyUnitRecord(t, m, id+".json", original)
	inventory := historyUnitCapture(t, m)
	row := historyUnitAll(t, m, inventory.Snapshot)[0]
	cause := errors.New("fixture original persistence failure")
	m.persist = func(string, []byte) error {
		revision, err := m.readWorkflowStoreRevision()
		if err != nil || revision == inventory.StoreRevision {
			t.Error("mutation intent was not durable before record write")
		}
		return cause
	}
	if _, err := m.Start(f.plan().ID); err != cause {
		t.Fatal("successful coordination changed original failed-write error identity")
	}
	if _, err := m.HistoryPage(context.Background(), HistoryPageQuery{Snapshot: inventory.Snapshot}); !errors.Is(err, ErrHistoryInventoryStale) {
		t.Fatal("failed coordinated write did not invalidate cursor epoch")
	}
	raw, err := New(f.root).ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("unrelated epoch change prevented exact unchanged evidence export")
	}
}

func TestWorkflowHistoryOversizeEntryHasMetadataOnlyDetail(t *testing.T) {
	m := New(t.TempDir())
	historyUnitRecord(t, m, "large.json", nil)
	path := filepath.Join(m.root, "large.json")
	if err := os.Truncate(path, maxHistoryRecordBytes+1); err != nil {
		t.Fatal(err)
	}
	inventory := historyUnitCapture(t, m)
	row := historyUnitAll(t, m, inventory.Snapshot)[0]
	if row.Classification != "oversized" || row.RawAvailable || row.Revision != "" || inventory.TotalBytes != 0 {
		t.Fatal("oversized record was read or omitted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	detail, err := m.ReadHistoryRecord(context.Background(), row.RecordRef, "")
	if err != nil || detail.Job != nil || detail.Record.Classification != "oversized" {
		t.Fatal("metadata-only detail touched unavailable source bytes")
	}
}

func TestWorkflowHistoryUntrustedIndexNamesAndMetadataAreRejected(t *testing.T) {
	m := New(t.TempDir())
	id := strings.Repeat("d", 48)
	historyUnitRecord(t, m, id+".json", historyUnitJob(t, id))
	inventory := historyUnitCapture(t, m)
	indexPath := filepath.Join(m.storeRoot, historyIndexName)
	original, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := m.openHistoryIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row, err := readHistoryRow(file, 0)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("source index unavailable")
	}
	for _, kind := range []string{"escape", "wrong-id", "unknown-action"} {
		t.Run(kind, func(t *testing.T) {
			changed := row
			switch kind {
			case "escape":
				changed.Leaf = base64.RawURLEncoding.EncodeToString([]byte("../outside.json"))
			case "wrong-id":
				changed.Summary.ID = strings.Repeat("e", 48)
			case "unknown-action":
				changed.Summary.Action = "PRIVATE_UNKNOWN_ACTION"
			}
			frame, err := historyFrame(changed, historySlotBytes)
			if err != nil {
				t.Fatal(err)
			}
			modified := append([]byte(nil), original...)
			copy(modified[historyHeaderBytes:], frame)
			if err := os.WriteFile(indexPath, modified, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.HistoryPage(context.Background(), HistoryPageQuery{Snapshot: inventory.Snapshot}); !errors.Is(err, ErrHistoryUnavailable) || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("untrusted index escaped fixed metadata rules")
			}
			if err := os.WriteFile(indexPath, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkflowHistoryUnixBackslashFilenameRemainsInspectable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("backslash is a native separator on Windows")
	}
	m := New(t.TempDir())
	data := []byte(`{"private":"odd filename evidence"}`)
	historyUnitRecord(t, m, `odd\name.json`, data)
	inventory := historyUnitCapture(t, m)
	row := historyUnitAll(t, m, inventory.Snapshot)[0]
	raw, err := m.ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
	if err != nil || !bytes.Equal(raw, data) || row.Classification != "legacy" {
		t.Fatal("valid native odd filename produced an unreadable inventory")
	}
}

func TestWorkflowHistoryKnownCancellationDiscardsOnlyOwnedMetadataStage(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "owned"
		if replacement {
			name = "replaced"
		}
		t.Run(name, func(t *testing.T) {
			m := New(t.TempDir())
			id := strings.Repeat("f", 48)
			body := historyUnitJob(t, id)
			historyUnitRecord(t, m, id+".json", body)
			historyUnitCapture(t, m)
			indexPath := filepath.Join(m.storeRoot, historyIndexName)
			before, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transactions := 0
			replacementPath := ""
			m.openStoreLease = func(path string) (workflowStoreLease, error) {
				if filepath.Base(path) == workflowTransactionLockName {
					transactions++
					if transactions == 2 {
						if replacement {
							stages, err := filepath.Glob(filepath.Join(m.storeRoot, ".workflow-history-*.tmp"))
							if err != nil || len(stages) != 1 {
								t.Error("owned source stage unavailable")
							} else {
								replacementPath = stages[0]
								if os.Rename(replacementPath, replacementPath+".retained") != nil || os.WriteFile(replacementPath, []byte("PRIVATE_UNRELATED"), 0600) != nil {
									t.Error("stage replacement fixture unavailable")
								}
							}
						}
						cancel()
					}
				}
				return openWorkflowStoreLease(path)
			}
			if _, err := m.CaptureHistoryInventory(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled capture lost its caller cause")
			}
			after, err := os.ReadFile(indexPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("cancelled capture replaced previous inventory")
			}
			if replacement {
				retained, err := os.ReadFile(replacementPath)
				if err != nil || string(retained) != "PRIVATE_UNRELATED" {
					t.Fatal("capture deleted an unknown replacement stage")
				}
			} else {
				stages, err := filepath.Glob(filepath.Join(m.storeRoot, ".workflow-history-*.tmp"))
				if err != nil || len(stages) != 0 {
					t.Fatal("clean cancellation accumulated derived staging data")
				}
			}
			retained, err := os.ReadFile(filepath.Join(m.root, id+".json"))
			if err != nil || !bytes.Equal(retained, body) {
				t.Fatal("capture cancellation changed original evidence")
			}
		})
	}
}

func TestWorkflowHistoryDeepAndExtendedRecordsOfferExactRawOnly(t *testing.T) {
	m := New(t.TempDir())
	id := strings.Repeat("1", 48)
	deep := []byte(`{"id":"` + id + `","action":"discover","state":"succeeded","startedAt":"2026-11-01T00:00:00Z","finishedAt":"2026-11-01T00:00:01Z","result":` + strings.Repeat("[", 9999) + "0" + strings.Repeat("]", 9999) + "}")
	if !json.Valid(deep) {
		t.Fatal("source deep fixture is not a valid standalone record")
	}
	extended := []byte(`{"id":"legacy","action":"discover","state":"succeeded","future":true}`)
	historyUnitRecord(t, m, id+".json", deep)
	historyUnitRecord(t, m, "extended.json", extended)
	inventory := historyUnitCapture(t, m)
	for _, row := range historyUnitAll(t, m, inventory.Snapshot) {
		detail, err := m.ReadHistoryRecord(context.Background(), row.RecordRef, row.Revision)
		if err != nil || detail.Job != nil || !detail.RawAvailable {
			t.Fatal("unembeddable or extended record was silently truncated")
		}
		var encoded bytes.Buffer
		if err := WriteHistoryRecordDetailJSON(&encoded, detail); err != nil || !json.Valid(encoded.Bytes()) {
			t.Fatal("raw-only detail envelope is invalid")
		}
		raw, err := m.ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
		if err != nil || !bytes.Equal(raw, deep) && !bytes.Equal(raw, extended) {
			t.Fatal("raw-only fallback changed retained bytes")
		}
	}
}

type historyUnitShortWriter struct{}

func (historyUnitShortWriter) Write(p []byte) (int, error) { return 0, nil }
func TestWorkflowHistoryDetailPreflightAndOutputFailure(t *testing.T) {
	var output bytes.Buffer
	detail := HistoryRecordDetail{Job: &Job{Result: json.RawMessage("{")}}
	if err := WriteHistoryRecordDetailJSON(&output, detail); err == nil || output.Len() != 0 {
		t.Fatal("invalid nested job wrote a partial success envelope")
	}
	if err := WriteHistoryRecordDetailJSON(historyUnitShortWriter{}, HistoryRecordDetail{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("detail output short write was ignored")
	}
}
