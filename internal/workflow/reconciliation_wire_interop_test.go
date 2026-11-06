package workflow_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/privatefile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

var reconciliationWireDirectories = []string{"internal/api", "internal/workflow", "internal/managed", "internal/fileidentity", "internal/privatefile", "internal/filelock", "internal/nativeprocess", "internal/nativepath"}
var reconciliationWireFixedSources = []string{"go.mod", "go.sum", "internal/workflow/windows.ps1", "internal/workflow/reconciliation_test.go", "internal/workflow/lifecycle_test.go", "internal/workflow/shutdown_test.go", "internal/workflow/reconciliation_export_test.go", "internal/workflow/reconciliation_http_interop_test.go", "internal/workflow/reconciliation_wire_interop_test.go", "web/system.js", "web/app.js", "web/index.html", "web/app.css", "web/locales.js", "web/app.test.cjs"}

type reconciliationWireSource struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type reconciliationWireFile struct {
	Name        string `json:"name"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
}

func reconciliationWireHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func reconciliationWireSources(t *testing.T, repository string) []reconciliationWireSource {
	t.Helper()
	names := append([]string(nil), reconciliationWireFixedSources...)
	for _, directory := range reconciliationWireDirectories {
		entries, err := os.ReadDir(filepath.Join(repository, filepath.FromSlash(directory)))
		if err != nil || len(entries) > 256 {
			t.Fatal("source reconciliation binding directory unavailable")
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			names = append(names, directory+"/"+entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) < 16 || len(names) > 256 {
		t.Fatal("source reconciliation binding count unavailable")
	}
	sources := make([]reconciliationWireSource, 0, len(names))
	for i, name := range names {
		if i > 0 && name == names[i-1] {
			t.Fatal("source reconciliation binding duplicated")
		}
		path := filepath.Join(repository, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8<<20 {
			t.Fatal("source reconciliation binding file unavailable")
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("source reconciliation binding open unavailable")
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
			t.Fatal("source reconciliation binding read unavailable")
		}
		sources = append(sources, reconciliationWireSource{Name: name, SHA256: reconciliationWireHash(data)})
	}
	return sources
}

func TestLifecycleReconciliationDesktopWireInterop(t *testing.T) {
	directory := os.Getenv("ACCESSWEAVER_RECONCILIATION_INTEROP")
	if directory == "" {
		t.Skip("source-generated reconciliation desktop fixtures not requested")
	}
	rootInfo, err := os.Lstat(directory)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("source reconciliation fixture requires an ordinary caller-created directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("source reconciliation fixture requires an empty directory")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source reconciliation repository binding unavailable")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	sources := reconciliationWireSources(t, repository)
	files := []reconciliationWireFile{}
	write := func(name string, response *httptest.ResponseRecorder) {
		t.Helper()
		limit := 64 << 10
		if strings.Contains(name, "status") || name == "available.json" {
			limit = 4096
		}
		data := response.Body.Bytes()
		if len(data) < 2 || len(data) > limit || !json.Valid(data) {
			t.Fatal("actual reconciliation response is unbounded or invalid")
		}
		if response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatal("actual reconciliation response type unavailable")
		}
		current, err := os.Lstat(directory)
		if err != nil || !current.IsDir() || !os.SameFile(rootInfo, current) {
			t.Fatal("source reconciliation fixture directory changed")
		}
		output, err := privatefile.Create(filepath.Join(directory, name))
		if err != nil {
			t.Fatal("private exclusive reconciliation fixture file unavailable")
		}
		n, writeErr := output.Write(data)
		syncErr := output.Sync()
		closeErr := output.Close()
		if n != len(data) || writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal("source reconciliation fixture file did not close completely")
		}
		files = append(files, reconciliationWireFile{Name: name, Size: len(data), SHA256: reconciliationWireHash(data), Status: response.Code, ContentType: response.Header().Get("Content-Type")})
	}
	manager, root, generation := workflow.NewReconciliationHTTPFixtureForTest(t)
	server := reconciliationHTTPServer(t, root, manager)
	available := reconciliationHTTPRequest(t, server, http.MethodGet, "/api/v1/system/history/reconciliation", nil)
	if available.Code != http.StatusOK {
		t.Fatal("actual live status unavailable")
	}
	write("available.json", available)
	foreign := reconciliationHTTPServer(t, root, workflow.NewWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })))
	unavailable := reconciliationHTTPRequest(t, foreign, http.MethodPost, "/api/v1/system/history/reconciliation/preview", map[string]string{})
	if unavailable.Code != http.StatusConflict {
		t.Fatal("fresh Manager invented source positive proof")
	}
	write("unavailable.json", unavailable)
	preview := reconciliationHTTPRequest(t, server, http.MethodPost, "/api/v1/system/history/reconciliation/preview", map[string]string{"generation": generation})
	var plan workflow.LifecycleReconciliationPlan
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &plan) != nil || plan.Resume {
		t.Fatal("actual live preview unavailable")
	}
	write("live-plan.json", preview)
	completed := reconciliationHTTPRequest(t, server, http.MethodPost, "/api/v1/system/history/reconciliation/apply", map[string]any{"planId": plan.ID, "confirm": true})
	if completed.Code != http.StatusOK {
		t.Fatal("actual live apply unavailable")
	}
	write("completed.json", completed)
	completeStatus := reconciliationHTTPRequest(t, server, http.MethodGet, "/api/v1/system/history/reconciliation", nil)
	if completeStatus.Code != http.StatusOK {
		t.Fatal("actual completed status unavailable")
	}
	write("completed-status.json", completeStatus)
	released := reconciliationHTTPRequest(t, server, http.MethodGet, "/api/v1/system/history/lifecycle", nil)
	if released.Code != http.StatusOK {
		t.Fatal("actual source lifecycle status unavailable")
	}
	write("lifecycle-released.json", released)
	resumedManager, resumeRoot, resumeGeneration, resumeOperation := workflow.NewReconciliationResumeHTTPFixtureForTest(t)
	resumeServer := reconciliationHTTPServer(t, resumeRoot, resumedManager)
	pending := reconciliationHTTPRequest(t, resumeServer, http.MethodGet, "/api/v1/system/history/reconciliation", nil)
	if pending.Code != http.StatusOK {
		t.Fatal("actual durable pending status unavailable")
	}
	write("pending-status.json", pending)
	resumePreview := reconciliationHTTPRequest(t, resumeServer, http.MethodPost, "/api/v1/system/history/reconciliation/preview", map[string]string{"operationId": resumeOperation})
	var resume workflow.LifecycleReconciliationPlan
	if resumePreview.Code != http.StatusOK || json.Unmarshal(resumePreview.Body.Bytes(), &resume) != nil || !resume.Resume || resume.OperationID != resumeOperation {
		t.Fatal("actual explicit resume preview unavailable")
	}
	write("resume-plan.json", resumePreview)
	resumed := reconciliationHTTPRequest(t, resumeServer, http.MethodPost, "/api/v1/system/history/reconciliation/apply", map[string]any{"planId": resume.ID, "confirm": true})
	if resumed.Code != http.StatusOK {
		t.Fatal("actual durable resume apply unavailable")
	}
	write("resumed.json", resumed)
	resumeReleased := reconciliationHTTPRequest(t, resumeServer, http.MethodGet, "/api/v1/system/history/lifecycle", nil)
	if resumeReleased.Code != http.StatusOK {
		t.Fatal("actual resumed lifecycle status unavailable")
	}
	write("resume-lifecycle-released.json", resumeReleased)
	before, _ := json.Marshal(sources)
	after, _ := json.Marshal(reconciliationWireSources(t, repository))
	if string(before) != string(after) {
		t.Fatal("source reconciliation bindings changed during production")
	}
	manifest := struct {
		SchemaVersion int                        `json:"schemaVersion"`
		Sources       []reconciliationWireSource `json:"sources"`
		Files         []reconciliationWireFile   `json:"files"`
		Expected      struct {
			Generation        string `json:"generation"`
			OperationID       string `json:"operationId"`
			ResumeGeneration  string `json:"resumeGeneration"`
			ResumeOperationID string `json:"resumeOperationId"`
		} `json:"expected"`
	}{SchemaVersion: 1, Sources: sources, Files: files}
	manifest.Expected.Generation = generation
	manifest.Expected.OperationID = plan.OperationID
	manifest.Expected.ResumeGeneration = resumeGeneration
	manifest.Expected.ResumeOperationID = resumeOperation
	data, err := json.Marshal(manifest)
	if err != nil || len(data) > 128<<10 {
		t.Fatal("source reconciliation manifest encoding unavailable")
	}
	output, err := privatefile.Create(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal("source reconciliation manifest file unavailable")
	}
	n, writeErr := output.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := output.Sync()
	closeErr := output.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal("source reconciliation manifest did not close completely")
	}
	final, err := os.ReadDir(directory)
	if err != nil || len(final) != 11 {
		t.Fatal("source reconciliation fixture set is not exact")
	}
}
