package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

var historyBrowserWireSources = []string{
	"go.mod", "go.sum",
	"internal/fileinput/fileinput.go", "internal/fileinput/native_unix.go", "internal/fileinput/native_windows.go",
	"internal/api/history_lifecycle.go", "internal/api/history.go", "internal/api/history_browser.go", "internal/api/history_browser_test.go", "internal/api/history_staging_test.go", "internal/api/history_browser_interop_test.go", "internal/api/server.go", "internal/api/workflow_json.go", "internal/api/workflows.go", "internal/api/audit.go", "internal/api/mutations.go",
	"internal/workflow/lifecycle.go", "internal/workflow/lifecycle_manifest.go", "internal/workflow/history.go", "internal/workflow/history_capture.go", "internal/workflow/history_staging.go", "internal/workflow/history_index.go", "internal/workflow/history_inventory.go", "internal/workflow/history_record.go", "internal/workflow/history_replace_unix.go", "internal/workflow/history_replace_windows.go", "internal/workflow/manager.go", "internal/workflow/outcome.go", "internal/workflow/persistence_observation.go", "internal/workflow/output.go", "internal/workflow/result.go", "internal/workflow/store.go",
	"web/system.js", "web/app.js", "web/locales.js", "web/index.html", "web/app.css", "web/app.test.cjs",
}

type historyBrowserWireSource struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type historyBrowserWireFile struct {
	Name                  string `json:"name"`
	Status                int    `json:"status"`
	Size                  int    `json:"size"`
	SHA256                string `json:"sha256"`
	ContentType           string `json:"contentType"`
	ETag                  string `json:"etag,omitempty"`
	XAccessWeaverRevision string `json:"xAccessWeaverRevision,omitempty"`
}

type historyBrowserWireExpected struct {
	Snapshot          string `json:"snapshot"`
	CanonicalRef      string `json:"canonicalRef"`
	CanonicalRevision string `json:"canonicalRevision"`
	CanonicalID       string `json:"canonicalID"`
	RawRef            string `json:"rawRef"`
	RawRevision       string `json:"rawRevision"`
}

type historyBrowserWireManifest struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Sources       []historyBrowserWireSource `json:"sources"`
	Files         []historyBrowserWireFile   `json:"files"`
	Expected      historyBrowserWireExpected `json:"expected"`
}

func historyBrowserWireHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func historyBrowserWireSourceHashes(t *testing.T, repository string) []historyBrowserWireSource {
	t.Helper()
	out := make([]historyBrowserWireSource, 0, len(historyBrowserWireSources))
	for _, name := range historyBrowserWireSources {
		path := filepath.Join(repository, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8<<20 {
			t.Fatal("history wire source binding file was unavailable")
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			t.Fatal("history wire source binding could not be opened")
		}
		opened, statErr := file.Stat()
		data, readErr := io.ReadAll(io.LimitReader(file, (8<<20)+1))
		final, finalErr := file.Stat()
		closeErr := file.Close()
		named, nameErr := os.Lstat(path)
		if statErr != nil || readErr != nil || finalErr != nil || closeErr != nil || nameErr != nil || len(data) > 8<<20 ||
			!os.SameFile(info, opened) || !os.SameFile(opened, final) || !os.SameFile(final, named) ||
			!opened.Mode().IsRegular() || !final.Mode().IsRegular() || !named.Mode().IsRegular() ||
			opened.Size() != int64(len(data)) || final.Size() != int64(len(data)) || named.Size() != int64(len(data)) {
			t.Fatal("history wire source binding could not be read")
		}
		out = append(out, historyBrowserWireSource{Name: name, SHA256: historyBrowserWireHash(data)})
	}
	return out
}

func historyBrowserWireSameSources(a, b []historyBrowserWireSource) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Test-only bridge: actual Handler response bytes feed the optional Node UI
// consumer. This is source integration, not native worker/vendor qualification.
// The caller owns the existing empty output directory; never repair, overwrite
// or remove that directory or any unknown object on success or failure.
func TestHistoryBrowserSourceWireInterop(t *testing.T) {
	outputPath := os.Getenv("ACCESSWEAVER_HISTORY_INTEROP")
	if outputPath == "" {
		t.Skip("optional source history wire directory is not configured")
	}
	if !filepath.IsAbs(outputPath) || filepath.Clean(outputPath) != outputPath || strings.HasPrefix(outputPath, `\\`) {
		t.Fatal("history wire directory must be an absolute ordinary path")
	}
	resolved, err := filepath.EvalSymlinks(outputPath)
	if err != nil || resolved != outputPath && !(runtime.GOOS == "windows" && strings.EqualFold(resolved, outputPath)) {
		t.Fatal("history wire directory aliases are not accepted")
	}
	named, err := os.Lstat(outputPath)
	if err != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 {
		t.Fatal("history wire caller directory was unavailable")
	}
	entries, err := os.ReadDir(outputPath)
	if err != nil || len(entries) != 0 {
		t.Fatal("history wire caller directory must be empty")
	}
	root, err := os.OpenRoot(outputPath)
	if err != nil {
		t.Fatal("history wire directory could not be retained")
	}
	defer func() {
		if root.Close() != nil {
			t.Error("history wire directory close was not confirmed")
		}
	}()
	opened, err := root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(named, opened) {
		t.Fatal("history wire directory changed during retention")
	}
	checkRoot := func() {
		t.Helper()
		current, err := os.Lstat(outputPath)
		if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(named, current) {
			t.Fatal("changed history wire directory was preserved")
		}
	}
	write := func(name string, data []byte) {
		t.Helper()
		checkRoot()
		if len(data) > 2<<20 {
			t.Fatal("synthetic history wire file exceeded its fixed bound")
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("history wire exclusive file creation failed")
		}
		n, writeErr := file.Write(data)
		if writeErr == nil && n != len(data) {
			writeErr = io.ErrShortWrite
		}
		var syncErr error
		if writeErr == nil {
			syncErr = file.Sync()
		}
		closeErr := file.Close()
		if errors.Join(writeErr, syncErr, closeErr) != nil {
			t.Fatal("history wire write or close was not confirmed; output retained")
		}
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("history wire repository root was unavailable")
	}
	sources := historyBrowserWireSourceHashes(t, repository)
	canonicalID := strings.Repeat("a", 48)
	canonical, err := json.Marshal(workflow.Job{
		ID: canonicalID, Action: "discover", State: "succeeded",
		StartedAt: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), FinishedAt: time.Date(2025, 1, 2, 3, 4, 6, 0, time.UTC),
		Result: json.RawMessage(`{"message":"wire-source-fixture","values":[1,true,null]}`),
	})
	if err != nil {
		t.Fatal("history wire canonical source fixture was invalid")
	}
	raw := []byte{0xff, '{', 0, 'X'}
	server := historyBrowserFixture(t, map[string][]byte{canonicalID + ".json": canonical, "wire-malformed.json": raw})
	lifecycleResponse := request(t, server, http.MethodGet, "/api/v1/system/history/lifecycle", nil, server.Token, "127.0.0.1")
	var lifecycle workflow.WorkflowLifecycleStatus
	if lifecycleResponse.Code != http.StatusOK || json.Unmarshal(lifecycleResponse.Body.Bytes(), &lifecycle) != nil || lifecycle.State != "none" || lifecycle.AdmissionBlocked || lifecycle.Protection != "retirement-unavailable" {
		t.Fatal("history wire lifecycle read did not preserve actual uninitialized metadata")
	}
	inventoryResponse := request(t, server, http.MethodPost, "/api/v1/system/history/inventory", map[string]any{}, server.Token, "127.0.0.1")
	var inventory workflow.HistoryInventory
	if inventoryResponse.Code != http.StatusOK || json.Unmarshal(inventoryResponse.Body.Bytes(), &inventory) != nil || inventory.Count != 2 {
		t.Fatal("history wire capture did not produce the real two-row inventory")
	}
	firstResponse := request(t, server, http.MethodGet, "/api/v1/system/history/page?limit=1&snapshot="+inventory.Snapshot, nil, server.Token, "127.0.0.1")
	var first workflow.HistoryPage
	if firstResponse.Code != http.StatusOK || json.Unmarshal(firstResponse.Body.Bytes(), &first) != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatal("history wire first page did not expose its actual cursor")
	}
	lastResponse := request(t, server, http.MethodGet, "/api/v1/system/history/page?limit=1&snapshot="+inventory.Snapshot+"&cursor="+first.NextCursor, nil, server.Token, "127.0.0.1")
	var last workflow.HistoryPage
	var lastFields map[string]json.RawMessage
	if lastResponse.Code != http.StatusOK || json.Unmarshal(lastResponse.Body.Bytes(), &last) != nil || json.Unmarshal(lastResponse.Body.Bytes(), &lastFields) != nil || len(last.Items) != 1 || last.NextCursor != "" {
		t.Fatal("history wire last page did not terminate the actual catalog")
	}
	if _, present := lastFields["nextCursor"]; present {
		t.Fatal("history wire fixture must retain the real omitted final cursor")
	}
	rows := append(append([]workflow.HistoryRecordSummary(nil), first.Items...), last.Items...)
	canonicalRow := historyBrowserFind(t, workflow.HistoryPage{Items: rows}, historyBrowserWireHash(canonical))
	rawRow := historyBrowserFind(t, workflow.HistoryPage{Items: rows}, historyBrowserWireHash(raw))
	if canonicalRow.ID != canonicalID || canonicalRow.Classification != "canonical" || rawRow.Classification != "malformed" {
		t.Fatal("history wire captured roles did not match the source fixtures")
	}
	detailResponse := request(t, server, http.MethodGet, "/api/v1/system/history/records/"+canonicalRow.RecordRef+"?revision="+canonicalRow.Revision, nil, server.Token, "127.0.0.1")
	var detail workflow.HistoryRecordDetail
	if detailResponse.Code != http.StatusOK || json.Unmarshal(detailResponse.Body.Bytes(), &detail) != nil || detail.Job == nil || detail.Job.ID != canonicalID || !bytes.Equal(detail.Job.Result, []byte(`{"message":"wire-source-fixture","values":[1,true,null]}`)) {
		t.Fatal("history wire canonical detail did not preserve the real typed response")
	}
	rawResponse := request(t, server, http.MethodGet, "/api/v1/system/history/records/"+rawRow.RecordRef+"/export?revision="+rawRow.Revision, nil, server.Token, "127.0.0.1")
	if rawResponse.Code != http.StatusOK || !bytes.Equal(rawResponse.Body.Bytes(), raw) || rawResponse.Header().Get("ETag") != `"`+rawRow.Revision+`"` || rawResponse.Header().Get("X-AccessWeaver-Revision") != rawRow.Revision {
		t.Fatal("history wire raw response did not preserve exact bytes and revision headers")
	}
	// This source-owned foreign stage is deliberately not granted closure or
	// cleanup authority. The actual capture route must refuse another allocation
	// while the already captured page and selected raw bytes remain readable.
	stagePath := filepath.Join(server.Store.Root, ".workflow-history-"+strings.Repeat("b", 48)+".tmp")
	stageBytes := []byte("source-interop-retained-stage-not-an-owner-proof")
	stage, stageErr := os.OpenFile(stagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if stageErr != nil {
		t.Fatal("history wire retained stage unavailable")
	}
	n, stageWriteErr := stage.Write(stageBytes)
	stageSyncErr, stageCloseErr := stage.Sync(), stage.Close()
	if n != len(stageBytes) || stageWriteErr != nil || stageSyncErr != nil || stageCloseErr != nil {
		t.Fatal("history wire controlled stage did not close completely")
	}
	pendingResponse := request(t, server, http.MethodPost, "/api/v1/system/history/inventory", map[string]any{}, server.Token, "127.0.0.1")
	var pending map[string]string
	if pendingResponse.Code != http.StatusConflict || pendingResponse.Body.Len() > 4096 || json.Unmarshal(pendingResponse.Body.Bytes(), &pending) != nil || len(pending) != 2 || pending["code"] != "history-staging-pending" || pending["error"] != workflow.ErrHistoryStagingPending.Error() {
		t.Fatal("history wire actual retained-stage refusal unavailable")
	}
	pageAfter := request(t, server, http.MethodGet, "/api/v1/system/history/page?limit=1&snapshot="+inventory.Snapshot, nil, server.Token, "127.0.0.1")
	if pageAfter.Code != http.StatusOK || !bytes.Equal(pageAfter.Body.Bytes(), firstResponse.Body.Bytes()) {
		t.Fatal("history wire pending allocation changed prior actual page")
	}
	rawAfter := request(t, server, http.MethodGet, "/api/v1/system/history/records/"+rawRow.RecordRef+"/export?revision="+rawRow.Revision, nil, server.Token, "127.0.0.1")
	if rawAfter.Code != http.StatusOK || !bytes.Equal(rawAfter.Body.Bytes(), rawResponse.Body.Bytes()) {
		t.Fatal("history wire pending allocation changed prior exact raw evidence")
	}
	retained, stageReadErr := os.ReadFile(stagePath)
	if stageReadErr != nil || !bytes.Equal(retained, stageBytes) {
		t.Fatal("history wire pending allocation changed retained stage")
	}
	responses := []struct {
		name     string
		response *httptest.ResponseRecorder
	}{{"lifecycle-none.json", lifecycleResponse}, {"inventory.json", inventoryResponse}, {"page-first.json", firstResponse}, {"page-last.json", lastResponse}, {"detail.json", detailResponse}, {"raw.bin", rawResponse}, {"pending-error.json", pendingResponse}}
	manifest := historyBrowserWireManifest{SchemaVersion: 1, Sources: sources, Expected: historyBrowserWireExpected{
		Snapshot: inventory.Snapshot, CanonicalRef: canonicalRow.RecordRef, CanonicalRevision: canonicalRow.Revision, CanonicalID: canonicalID,
		RawRef: rawRow.RecordRef, RawRevision: rawRow.Revision,
	}}
	for _, item := range responses {
		data := item.response.Body.Bytes()
		entry := historyBrowserWireFile{Name: item.name, Status: item.response.Code, Size: len(data), SHA256: historyBrowserWireHash(data), ContentType: item.response.Header().Get("Content-Type")}
		if item.name == "raw.bin" {
			entry.ETag = item.response.Header().Get("ETag")
			entry.XAccessWeaverRevision = item.response.Header().Get("X-AccessWeaver-Revision")
		}
		manifest.Files = append(manifest.Files, entry)
		write(item.name, data)
	}
	if !historyBrowserWireSameSources(sources, historyBrowserWireSourceHashes(t, repository)) {
		t.Fatal("history wire source changed during response production; files retained")
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal("history wire manifest could not be encoded")
	}
	write("manifest.json", append(encoded, '\n'))
	checkRoot()
	entries, err = os.ReadDir(outputPath)
	if err != nil || len(entries) != 8 {
		t.Fatal("history wire output contains unknown entries; all files retained")
	}
}
