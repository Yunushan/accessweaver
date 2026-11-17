package workflow_test

import (
	"context"
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

var controllerStorageWireExtraSources = []string{"internal/workflow/controller_storage_wire_interop_test.go", "internal/api/controller_storage_test.go", "cmd/accessweaver/system_storage.go", "cmd/accessweaver/system_storage_test.go", "cmd/accessweaver/system.go"}

func controllerStorageWireSources(t *testing.T, repository string) []reconciliationWireSource {
	t.Helper()
	sources := reconciliationWireSources(t, repository)
	names := append([]string(nil), controllerStorageWireExtraSources...)
	for _, dir := range []string{"internal/logfile", "internal/profile"} {
		entries, err := os.ReadDir(filepath.Join(repository, filepath.FromSlash(dir)))
		if err != nil || len(entries) > 256 {
			t.Fatal("controller wire source directory unavailable")
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
				names = append(names, dir+"/"+entry.Name())
			}
		}
	}
	for _, name := range names {
		path := filepath.Join(repository, filepath.FromSlash(name))
		named, err := os.Lstat(path)
		if err != nil || !named.Mode().IsRegular() || named.Size() < 1 || named.Size() > 8<<20 {
			t.Fatal("controller wire bounded source unavailable")
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("controller wire source open unavailable")
		}
		opened, statErr := file.Stat()
		data, readErr := io.ReadAll(io.LimitReader(file, (8<<20)+1))
		final, finalErr := file.Stat()
		closeErr := file.Close()
		current, nameErr := os.Lstat(path)
		if statErr != nil || readErr != nil || finalErr != nil || closeErr != nil || nameErr != nil || len(data) > 8<<20 || !os.SameFile(named, opened) || !os.SameFile(opened, final) || !os.SameFile(final, current) || !opened.Mode().IsRegular() || !final.Mode().IsRegular() || !current.Mode().IsRegular() || opened.Size() != int64(len(data)) || final.Size() != int64(len(data)) || current.Size() != int64(len(data)) {
			t.Fatal("controller wire source changed or read did not close")
		}
		sources = append(sources, reconciliationWireSource{Name: name, SHA256: reconciliationWireHash(data)})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	if len(sources) > 256 {
		t.Fatal("controller wire source count exceeded")
	}
	for i := 1; i < len(sources); i++ {
		if sources[i].Name == sources[i-1].Name {
			t.Fatal("controller wire source duplicated")
		}
	}
	return sources
}

func controllerStorageActualStatuses(t *testing.T) (map[string]*httptest.ResponseRecorder, string) {
	t.Helper()
	responses := map[string]*httptest.ResponseRecorder{}
	emptyRoot := t.TempDir()
	missing := filepath.Join(emptyRoot, "uninitialized")
	empty := reconciliationHTTPServer(t, emptyRoot, workflow.NewWithGuard(missing, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })))
	responses["uninitialized.json"] = reconciliationHTTPRequest(t, empty, http.MethodGet, "/api/v1/system/storage", nil)
	var uninitialized workflow.ControllerStorageStatus
	if responses["uninitialized.json"].Code != http.StatusOK || json.Unmarshal(responses["uninitialized.json"].Body.Bytes(), &uninitialized) != nil || uninitialized.State != "uninitialized" {
		t.Fatal("actual uninitialized controller status unavailable")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("actual controller status initialized missing storage")
	}
	manager, root, generation := workflow.NewReconciliationHTTPFixtureForTest(t)
	server := reconciliationHTTPServer(t, root, manager)
	responses["pending.json"] = reconciliationHTTPRequest(t, server, http.MethodGet, "/api/v1/system/storage", nil)
	var pending workflow.ControllerStorageStatus
	if responses["pending.json"].Code != http.StatusOK || json.Unmarshal(responses["pending.json"].Body.Bytes(), &pending) != nil || pending.State != "pending" || pending.Generation != generation || pending.GenerationsTracked != 1 || pending.UncertainBytes <= 0 || pending.ReservedBytes != 0 || pending.FinalizationReservedBytes != 0 {
		t.Fatal("actual completed failed-ACK controller commitment was not uncertain")
	}
	preview := reconciliationHTTPRequest(t, server, http.MethodPost, "/api/v1/system/history/reconciliation/preview", map[string]string{"generation": generation})
	var plan workflow.LifecycleReconciliationPlan
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &plan) != nil {
		t.Fatal("actual reviewed source-owner retry unavailable")
	}
	applied := reconciliationHTTPRequest(t, server, http.MethodPost, "/api/v1/system/history/reconciliation/apply", map[string]any{"planId": plan.ID, "confirm": true})
	if applied.Code != http.StatusOK {
		t.Fatal("actual source-owner acknowledgement retry unavailable")
	}
	fresh := reconciliationHTTPServer(t, root, workflow.NewWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })))
	responses["tracked.json"] = reconciliationHTTPRequest(t, fresh, http.MethodGet, "/api/v1/system/storage", nil)
	var tracked workflow.ControllerStorageStatus
	if responses["tracked.json"].Code != http.StatusOK || json.Unmarshal(responses["tracked.json"].Body.Bytes(), &tracked) != nil || tracked.State != "tracked" || tracked.Generation != generation || tracked.GenerationsTracked != 1 || tracked.RetainedChargeBytes <= 0 || tracked.UncertainBytes != 0 || tracked.ReservedBytes != 0 || tracked.FinalizationReservedBytes != 0 {
		t.Fatal("actual linked genuine ACK did not retain released source charge")
	}
	for _, value := range []workflow.ControllerStorageStatus{uninitialized, pending, tracked} {
		if value.Scope != "tracked-controller-evidence-only" || value.LegacyAccounting != "not-included" || value.AggregateQuotaEnforced || value.PhysicalCapacityGuaranteed || value.NativeWritersContained || value.WorkerJournalBounded {
			t.Fatal("actual controller projection invented whole-store guarantees")
		}
	}
	if manager.Snapshot().State != "failed" || manager.TerminalError(generation) == nil {
		t.Fatal("storage status/ACK retry cleared original failed outcome")
	}
	if _, err := manager.LifecycleStatus(context.Background()); err != nil {
		t.Fatal("actual source lifecycle projection unavailable")
	}
	return responses, generation
}
func TestControllerStorageActualAPITracksOnlyGenuineLinkedAcknowledgement(t *testing.T) {
	controllerStorageActualStatuses(t)
}

func TestControllerStorageDesktopWireInterop(t *testing.T) {
	directory := os.Getenv("ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP")
	if directory == "" {
		t.Skip("optional actual controller storage desktop fixture not requested")
	}
	rootInfo, err := os.Lstat(directory)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("controller wire requires ordinary caller-owned directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("controller wire requires empty caller-owned directory")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("controller wire source repository unavailable")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	sources := controllerStorageWireSources(t, repository)
	responses, generation := controllerStorageActualStatuses(t)
	files := []reconciliationWireFile{}
	write := func(name string, data []byte) {
		t.Helper()
		current, err := os.Lstat(directory)
		if err != nil || !current.IsDir() || !os.SameFile(rootInfo, current) {
			t.Fatal("controller wire output directory changed")
		}
		output, err := privatefile.Create(filepath.Join(directory, name))
		if err != nil {
			t.Fatal("controller wire private exclusive output unavailable")
		}
		n, writeErr := output.Write(data)
		syncErr, closeErr := output.Sync(), output.Close()
		if n != len(data) || writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal("controller wire output did not close completely")
		}
	}
	for _, name := range []string{"uninitialized.json", "pending.json", "tracked.json"} {
		response := responses[name]
		data := response.Body.Bytes()
		contentType := response.Header().Get("Content-Type")
		if response.Code != http.StatusOK || len(data) < 2 || len(data) > 4096 || !json.Valid(data) || contentType != "application/json; charset=utf-8" {
			t.Fatal("controller actual wire response invalid or unbounded")
		}
		files = append(files, reconciliationWireFile{Name: name, Size: len(data), SHA256: reconciliationWireHash(data), Status: response.Code, ContentType: contentType})
		write(name, data)
	}
	before, _ := json.Marshal(sources)
	after, _ := json.Marshal(controllerStorageWireSources(t, repository))
	if string(before) != string(after) {
		t.Fatal("controller wire sources changed during production")
	}
	manifest := struct {
		SchemaVersion int                        `json:"schemaVersion"`
		Sources       []reconciliationWireSource `json:"sources"`
		Files         []reconciliationWireFile   `json:"files"`
		Expected      struct {
			Generation string `json:"generation"`
		} `json:"expected"`
	}{SchemaVersion: 1, Sources: sources, Files: files}
	manifest.Expected.Generation = generation
	data, err := json.Marshal(manifest)
	if err != nil || len(data) > 128<<10 {
		t.Fatal("controller wire manifest invalid or unbounded")
	}
	write("manifest.json", data)
	entries, err = os.ReadDir(directory)
	if err != nil || len(entries) != 4 {
		t.Fatal("controller wire output set changed")
	}
}
