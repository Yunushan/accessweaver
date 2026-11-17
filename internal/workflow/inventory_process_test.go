package workflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These fixtures use only captured source records, independent Managers and an
// inert executor. No Windows worker, service, vendor or network action runs.
func workflowHistoryIntegrationSeed(t *testing.T, files map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	if os.Mkdir(filepath.Join(root, "workflows"), 0700) != nil {
		t.Fatal("private inventory fixture unavailable")
	}
	for name, data := range files {
		if filepath.Base(name) != name {
			t.Fatal("invalid source fixture leaf")
		}
		if os.WriteFile(filepath.Join(root, "workflows", name), data, 0600) != nil {
			t.Fatal("private inventory fixture record unavailable")
		}
	}
	return root
}
func workflowHistoryIntegrationJob(t *testing.T, id, value string) []byte {
	t.Helper()
	result, err := json.Marshal(map[string]string{"fixture": value})
	if err != nil {
		t.Fatal("private result fixture encoding failed")
	}
	data, err := json.Marshal(Job{ID: id, Action: "discover", State: "succeeded", StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC), Result: result})
	if err != nil {
		t.Fatal("private record fixture encoding failed")
	}
	return data
}

func workflowHistoryIntegrationDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestWorkflowHistoryInventoryCrossManagerOpaqueRecordsAndExactBytes(t *testing.T) {
	first, second := strings.Repeat("a", 48), strings.Repeat("b", 48)
	files := map[string][]byte{
		first + ".json":       workflowHistoryIntegrationJob(t, first, "PRIVATE_CANONICAL_RESULT"),
		second + ".json":      workflowHistoryIntegrationJob(t, "../../PRIVATE_OTHER_ID", "PRIVATE_LEGACY_RESULT"),
		"opaque-fixture.json": append([]byte{0xff, 0xfe}, []byte("INVALID_PRIVATE_SOURCE\n")...),
	}
	root := workflowHistoryIntegrationSeed(t, files)
	captured, err := New(root).CaptureHistoryInventory(context.Background())
	if err != nil || captured.Count != 3 {
		t.Fatal("explicit inventory did not capture all source evidence")
	}
	// Reopening with an independent Manager must not need process-local maps
	// or assume a filesystem directory-enumeration bookmark.
	reader := New(root)
	originals := map[string][]byte{}
	for _, data := range files {
		originals[workflowHistoryIntegrationDigest(data)] = data
	}
	seen := map[string]bool{}
	cursor := ""
	for {
		page, err := reader.HistoryPage(context.Background(), HistoryPageQuery{Limit: 1, Cursor: cursor, Snapshot: captured.Snapshot})
		if err != nil || page.Inventory.Snapshot != captured.Snapshot || len(page.Items) != 1 {
			t.Fatal("bounded cross-Manager page was unavailable")
		}
		public, _ := json.Marshal(page)
		if bytes.Contains(public, []byte("PRIVATE_")) {
			t.Fatal("metadata page exposed record content or an untrusted ID")
		}
		row := page.Items[0]
		if seen[row.RecordRef] || len(row.RecordRef) > 256 || row.RecordRef == "" || !row.RawAvailable {
			t.Fatal("captured reference was duplicated or unavailable")
		}
		seen[row.RecordRef] = true
		expected, ok := originals[row.Revision]
		if !ok {
			t.Fatal("inventory revision did not bind captured source bytes")
		}
		raw, err := New(root).ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
		if err != nil || !bytes.Equal(raw, expected) {
			t.Fatal("independent selected raw export changed evidence bytes")
		}
		detail, err := New(root).ReadHistoryRecord(context.Background(), row.RecordRef, row.Revision)
		if err != nil || detail.Record.RecordRef != row.RecordRef || detail.Record.Revision != row.Revision || !detail.RawAvailable {
			t.Fatal("exact selected detail lost its captured binding")
		}
		if row.ID == first {
			if row.Classification != "canonical" || detail.Job == nil || detail.Job.ID != first || !bytes.Contains(detail.Job.Result, []byte("PRIVATE_CANONICAL_RESULT")) {
				t.Fatal("canonical detail lost its complete private result")
			}
			var out bytes.Buffer
			if WriteHistoryRecordDetailJSON(&out, detail) != nil || !json.Valid(out.Bytes()) || !bytes.Contains(out.Bytes(), []byte("PRIVATE_CANONICAL_RESULT")) {
				t.Fatal("selected typed detail was incomplete or invalid JSON")
			}
		} else if row.ID == second && row.Classification == "canonical" {
			t.Fatal("mismatched persisted ID became filename authority")
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
		if len(seen) > 3 {
			t.Fatal("inventory cursor did not terminate")
		}
	}
	if len(seen) != 3 {
		t.Fatal("inventory omitted retained source evidence")
	}
	for name, before := range files {
		after, err := os.ReadFile(filepath.Join(root, "workflows", name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("inventory or inspection modified a source record")
		}
	}
}

func TestWorkflowHistoryExactReadRejectsInPlaceChangeWithoutEpochMutation(t *testing.T) {
	id := strings.Repeat("c", 48)
	original := workflowHistoryIntegrationJob(t, id, "one")
	changed := workflowHistoryIntegrationJob(t, id, "two")
	if len(changed) != len(original) {
		t.Fatal("source byte-length fixture changed")
	}
	root := workflowHistoryIntegrationSeed(t, map[string][]byte{id + ".json": original})
	m := New(root)
	captured, err := m.CaptureHistoryInventory(context.Background())
	if err != nil {
		t.Fatal("source inventory capture failed")
	}
	page, err := m.HistoryPage(context.Background(), HistoryPageQuery{Snapshot: captured.Snapshot})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("source inventory row unavailable")
	}
	row := page.Items[0]
	file := filepath.Join(root, "workflows", id+".json")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal("source identity fixture unavailable")
	}
	if os.WriteFile(file, changed, 0600) != nil || os.Chtimes(file, info.ModTime(), info.ModTime()) != nil {
		t.Fatal("source drift fixture unavailable")
	}
	// Size and timestamp alone are not an exact-byte revision. Neither edit
	// participates in the cooperating writer epoch, so content hashing matters.
	raw, err := New(root).ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
	if raw != nil || !errors.Is(err, ErrHistoryInventoryStale) {
		t.Fatal("selected export accepted changed bytes under the captured revision")
	}
	if _, err := New(root).ReadHistoryRecord(context.Background(), row.RecordRef, row.Revision); !errors.Is(err, ErrHistoryInventoryStale) {
		t.Fatal("selected detail accepted changed bytes")
	}
}

func TestWorkflowHistoryWriterInvalidatesPageAndKeepsUnchangedExactEvidenceReadable(t *testing.T) {
	first, second := strings.Repeat("d", 48), strings.Repeat("e", 48)
	originals := map[string][]byte{first + ".json": workflowHistoryIntegrationJob(t, first, "first"), second + ".json": workflowHistoryIntegrationJob(t, second, "second")}
	root := workflowHistoryIntegrationSeed(t, originals)
	m := New(root)
	captured, err := m.CaptureHistoryInventory(context.Background())
	if err != nil {
		t.Fatal("initial source inventory unavailable")
	}
	page, err := m.HistoryPage(context.Background(), HistoryPageQuery{Limit: 1, Snapshot: captured.Snapshot})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal("initial source page/cursor unavailable")
	}
	row := page.Items[0]
	writer := workflowStoreSourceManager(root)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if writer.Shutdown(ctx) != nil {
			t.Error("source workflow did not drain")
		}
	})
	plan, err := writer.Preview(Request{Action: "discover"})
	if err != nil || !plan.Ready {
		t.Fatal("inert source workflow preview unavailable")
	}
	if _, err := writer.Start(plan.ID); err != nil {
		t.Fatal("inert source workflow admission unavailable")
	}
	workflowStoreAwaitDone(t, writer)
	if writer.TerminalError(plan.ID) != nil {
		t.Fatal("inert source workflow outcome unavailable")
	}
	if _, err := New(root).HistoryPage(context.Background(), HistoryPageQuery{Limit: 1, Cursor: page.NextCursor}); !errors.Is(err, ErrHistoryInventoryStale) {
		t.Fatal("coordinated writer did not invalidate the old page cursor")
	}
	raw, err := New(root).ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
	if err != nil || workflowHistoryIntegrationDigest(raw) != row.Revision {
		t.Fatal("unrelated store mutation blocked exact unchanged private evidence")
	}
	fresh, err := New(root).CaptureHistoryInventory(context.Background())
	if err != nil || fresh.Snapshot == captured.Snapshot || fresh.Count != 3 {
		t.Fatal("explicit refresh did not capture the changed store")
	}
	if _, err := New(root).ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision); !errors.Is(err, ErrHistoryInventoryStale) {
		t.Fatal("replaced inventory accepted an old opaque reference")
	}
}

func TestWorkflowHistoryInventoryBrowsesAboveLegacyDirectoryLimit(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "workflows")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("over-limit source fixture unavailable")
	}
	const count = maxHistoryDirectoryEntries + 17
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("legacy-%05d.json", i)
		if os.WriteFile(filepath.Join(directory, name), []byte("null"), 0600) != nil {
			t.Fatal("over-limit source record unavailable")
		}
	}
	m := New(root)
	if jobs, err := m.History(); err == nil || jobs != nil {
		t.Fatal("legacy full export silently raised or truncated its directory limit")
	}
	captured, err := m.CaptureHistoryInventory(context.Background())
	if err != nil || captured.Count != count {
		t.Fatal("explicit inventory did not capture the already-over-legacy-limit store")
	}
	seen := make(map[string]bool, count)
	cursor := ""
	for {
		page, err := New(root).HistoryPage(context.Background(), HistoryPageQuery{Limit: 128, Snapshot: captured.Snapshot, Cursor: cursor})
		if err != nil || len(page.Items) > 128 {
			t.Fatal("bounded over-limit inventory page unavailable")
		}
		for _, item := range page.Items {
			if seen[item.RecordRef] || item.RecordRef == "" || item.Classification != "malformed" || !item.RawAvailable {
				t.Fatal("over-limit inventory omitted, duplicated or misclassified a record")
			}
			seen[item.RecordRef] = true
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
		if len(seen) > count {
			t.Fatal("over-limit inventory cursor did not terminate")
		}
	}
	if len(seen) != count {
		t.Fatal("over-limit inventory silently omitted retained records")
	}
	if jobs, err := m.History(); err == nil || jobs != nil {
		t.Fatal("inventory changed the legacy full-export guard")
	}
}
