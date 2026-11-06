package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func storageAPIManager(root string) *workflow.Manager {
	return workflow.NewWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
}
func assertStorageAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body map[string]string
	if response.Code != status || response.Body.Len() > 4096 || json.Unmarshal(response.Body.Bytes(), &body) != nil || body["code"] != code || body["error"] == "" || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE_")) {
		t.Fatal("storage API did not retain fixed bounded category")
	}
}
func TestControllerStorageAPIMissingAndLegacyReadDoesNotInitialize(t *testing.T) {
	server := makeServer(t)
	root := filepath.Join(t.TempDir(), "absent")
	server.Workflows = storageAPIManager(root)
	response := request(t, server, http.MethodGet, "/api/v1/system/storage", nil, server.Token, "127.0.0.1")
	var value workflow.ControllerStorageStatus
	if response.Code != http.StatusOK || response.Body.Len() > 4096 || json.Unmarshal(response.Body.Bytes(), &value) != nil || value.State != "uninitialized" || value.Scope != "tracked-controller-evidence-only" || value.LegacyAccounting != "not-included" || value.AggregateQuotaEnforced || value.PhysicalCapacityGuaranteed || value.NativeWritersContained || value.WorkerJournalBounded {
		t.Fatal("uninitialized status invented storage guarantees")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("readonly storage GET initialized missing root")
	}
	if err := os.MkdirAll(filepath.Join(root, "workflows"), 0700); err != nil {
		t.Fatal(err)
	}
	private := []byte("PRIVATE_LEGACY_RECORD")
	legacy := filepath.Join(root, "workflows", "legacy.json")
	if err := os.WriteFile(legacy, private, 0600); err != nil {
		t.Fatal(err)
	}
	response = request(t, server, http.MethodGet, "/api/v1/system/storage", nil, server.Token, "127.0.0.1")
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || value.State != "uninitialized" || value.LegacyAccounting != "not-included" || bytes.Contains(response.Body.Bytes(), private) {
		t.Fatal("untracked legacy bytes became claimed disk usage or leaked")
	}
	for _, name := range []string{".workflow-controller-storage", ".workflow-controller-storage.current", ".workflow-active.lock", ".workflow-store.lock"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("storage GET created private metadata or locks")
		}
	}
	after, err := os.ReadFile(legacy)
	if err != nil || !bytes.Equal(after, private) {
		t.Fatal("readonly storage changed legacy evidence")
	}
}
func TestControllerStorageAPIRejectsQuerySessionAndProfileOnlyMode(t *testing.T) {
	server := makeServer(t)
	root := filepath.Join(t.TempDir(), "missing")
	server.Workflows = storageAPIManager(root)
	for _, suffix := range []string{"?generation=" + strings.Repeat("a", 48), "?force=true", "?x=1&x=2", "?" + strings.Repeat("x", 4097)} {
		assertStorageAPIError(t, request(t, server, http.MethodGet, "/api/v1/system/storage"+suffix, nil, server.Token, "127.0.0.1"), http.StatusBadRequest, "workflow-storage-invalid")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid query initialized storage")
	}
	unauth := request(t, server, http.MethodGet, "/api/v1/system/storage", nil, "", "127.0.0.1")
	if unauth.Code != http.StatusForbidden {
		t.Fatal("storage GET bypassed session")
	}
	audited, _, _ := auditedAPIFixture(t)
	audited.Workflows = storageAPIManager(root)
	if denied := request(t, audited, http.MethodGet, "/api/v1/system/storage", nil, audited.Token, "127.0.0.1"); denied.Code != http.StatusForbidden {
		t.Fatal("profile-only mode exposed controller storage")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("denied inspection initialized storage")
	}
}
func TestControllerStorageAPIFixedErrorsAndStatusEncodingBound(t *testing.T) {
	for _, item := range []struct {
		err    error
		read   bool
		status int
		code   string
	}{
		{workflow.ErrWorkflowStorageCapacity, false, 409, "workflow-storage-capacity"},
		{workflow.ErrWorkflowStoragePending, false, 409, "workflow-storage-pending"},
		{workflow.ErrWorkflowStoragePending, true, 503, "workflow-storage-pending"},
		{workflow.ErrWorkflowBusy, true, 503, "workflow-storage-busy"},
		{context.Canceled, true, 408, "workflow-storage-request-ended"},
		{managed.ErrDenied, true, 403, "workflow-storage-denied"},
		{managed.ErrUnavailable, true, 503, "workflow-storage-policy-unavailable"},
		{errors.Join(workflow.ErrWorkflowStoragePending, managed.ErrDenied), false, 403, "workflow-storage-denied"},
		{errors.Join(workflow.ErrWorkflowStoragePending, workflow.ErrWorkflowStore), false, 503, "workflow-storage-unavailable"},
		{errors.New("PRIVATE_STORAGE_OS_CAUSE"), true, 503, "workflow-storage-unavailable"},
	} {
		response := httptest.NewRecorder()
		failControllerStorage(response, errors.Join(item.err, errors.New("PRIVATE_CONTROLLER_ROOT")), item.read)
		assertStorageAPIError(t, response, item.status, item.code)
	}
	for _, category := range []error{workflow.ErrWorkflowStoragePending, workflow.ErrWorkflowStorageCapacity} {
		response := httptest.NewRecorder()
		failWorkflowStart(response, errors.Join(category, errors.New("PRIVATE_START")))
		if response.Code != 409 || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE_")) {
			t.Fatal("start lost fixed storage refusal")
		}
	}
	oversized := httptest.NewRecorder()
	writeControllerStorageMetadata(oversized, workflow.ControllerStorageStatus{Action: strings.Repeat("PRIVATE_STORAGE_BODY", 4096)})
	assertStorageAPIError(t, oversized, 503, "workflow-storage-unavailable")
}

type storageBlockingResponse struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
	once             sync.Once
}

func (w *storageBlockingResponse) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.ResponseRecorder.Write(data)
}
func TestControllerStorageAPIReadSlotRetainsOutputWithoutBlockingCancel(t *testing.T) {
	server := makeServer(t)
	server.Workflows = storageAPIManager(filepath.Join(t.TempDir(), "missing"))
	blocked := &storageBlockingResponse{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/storage", nil)
	r.Header.Set("X-AccessWeaver-Token", server.Token)
	done := make(chan struct{})
	go func() { defer close(done); server.Handler().ServeHTTP(blocked, r) }()
	defer func() {
		close(blocked.release)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("storage output did not drain")
		}
	}()
	select {
	case <-blocked.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("storage response did not reach actual output")
	}
	busy := request(t, server, http.MethodGet, "/api/v1/system/storage", nil, server.Token, "127.0.0.1")
	assertStorageAPIError(t, busy, 503, "workflow-storage-busy")
	if busy.Header().Get("Retry-After") != "1" {
		t.Fatal("storage busy lacked bounded feedback")
	}
	canceled := request(t, server, http.MethodPost, "/api/v1/system/cancel", map[string]any{}, server.Token, "127.0.0.1")
	if canceled.Code != http.StatusOK {
		t.Fatal("storage response held current-job Cancel admission")
	}
}
