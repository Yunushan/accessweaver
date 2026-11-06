package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestHistoryBrowserRetainedStageRefusesNewCaptureAndKeepsExactReads(t *testing.T) {
	raw := []byte{0xff, '{', 0, 'X'}
	server := historyBrowserFixture(t, map[string][]byte{"source-malformed.json": raw})
	inventory := historyBrowserCapture(t, server)
	page := historyBrowserPage(t, server, "?snapshot="+inventory.Snapshot)
	row := historyBrowserFind(t, page, historyBrowserSHA(raw))
	indexPath := filepath.Join(server.Store.Root, ".workflow-history.index")
	index, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal("source prior index unavailable")
	}
	stage := filepath.Join(server.Store.Root, ".workflow-history-"+strings.Repeat("b", 48)+".tmp")
	original := []byte("retained-source-stage-not-an-owner-proof")
	file, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("source retained-stage setup unavailable")
	}
	n, writeErr := file.Write(original)
	syncErr, closeErr := file.Sync(), file.Close()
	if n != len(original) || writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal("source retained stage not written completely")
	}
	entries, err := os.ReadDir(server.Store.Root)
	if err != nil {
		t.Fatal("source retained-stage count unavailable")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			server.Workflows = workflow.NewWithGuard(server.Store.Root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
		}
		response := request(t, server, http.MethodPost, "/api/v1/system/history/inventory", map[string]any{}, server.Token, "127.0.0.1")
		var refusal map[string]string
		if response.Code != http.StatusConflict || json.Unmarshal(response.Body.Bytes(), &refusal) != nil || len(refusal) != 2 || refusal["code"] != "history-staging-pending" || refusal["error"] != workflow.ErrHistoryStagingPending.Error() || bytes.Contains(response.Body.Bytes(), []byte(server.Store.Root)) {
			t.Fatal("retained stage did not produce a fixed bounded refusal")
		}
		current, readErr := os.ReadDir(server.Store.Root)
		if readErr != nil || len(current) != len(entries) {
			t.Fatal("repeated refused capture allocated another staging/control object")
		}
		retained, readErr := os.ReadFile(stage)
		if readErr != nil || !bytes.Equal(retained, original) {
			t.Fatal("refused capture modified retained stage")
		}
		after, readErr := os.ReadFile(indexPath)
		if readErr != nil || !bytes.Equal(after, index) {
			t.Fatal("refused capture rewrote prior valid index")
		}
		preserved := historyBrowserPage(t, server, "?snapshot="+inventory.Snapshot)
		if len(preserved.Items) != 1 || preserved.Items[0].RecordRef != row.RecordRef || preserved.Items[0].Revision != row.Revision {
			t.Fatal("prior exact captured page became unreadable")
		}
		exported := request(t, server, http.MethodGet, "/api/v1/system/history/records/"+row.RecordRef+"/export?revision="+row.Revision, nil, server.Token, "127.0.0.1")
		if exported.Code != http.StatusOK || !bytes.Equal(exported.Body.Bytes(), raw) || exported.Header().Get("X-AccessWeaver-Revision") != row.Revision {
			t.Fatal("retained stage blocked or changed exact raw evidence reads")
		}
	}
	if _, err := server.Workflows.HistoryPage(context.Background(), workflow.HistoryPageQuery{Snapshot: inventory.Snapshot}); err != nil {
		t.Fatal("fresh Manager lost read-only prior snapshot")
	}
}
