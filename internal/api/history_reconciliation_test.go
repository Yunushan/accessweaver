package api

import (
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

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func reconciliationAPIRequest(s *Server, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "127.0.0.1:54321"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AccessWeaver-Token", s.Token)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	return response
}
func assertReconciliationAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body map[string]string
	if response.Code != status || json.Unmarshal(response.Body.Bytes(), &body) != nil || body["code"] != code || body["error"] == "" || len(body["error"]) > 256 || strings.Contains(response.Body.String(), "PRIVATE") {
		t.Fatal("reconciliation API did not return the fixed bounded non-success contract")
	}
}

func TestLifecycleReconciliationAPIRejectsAmbiguousJSONAndQueryBeforeBackend(t *testing.T) {
	server := makeServer(t)
	id := strings.Repeat("a", 48)
	cases := []struct{ path, body string }{
		{"preview", "null"}, {"preview", "[]"}, {"preview", ""}, {"preview", `{} {}`}, {"preview", `{"force":true}`}, {"preview", `{"generation":null}`}, {"preview", `{"generation":""}`},
		{"preview", `{"Generation":"` + id + `"}`}, {"preview", `{"generation":"` + id + `","operationId":"` + id + `"}`}, {"preview", `{"generation":"` + id + `","gener\u0061tion":"` + id + `"}`},
		{"preview", `{"operationId":"../private"}`}, {"preview", `{"generation":"` + strings.Repeat("A", 48) + `"}`},
		{"preview", string(append(append([]byte(`{"generation":"`), byte(255)), []byte(`"}`)...))},
		{"apply", `{}`}, {"apply", `{"planId":"` + id + `"}`}, {"apply", `{"planId":"` + id + `","confirm":false}`}, {"apply", `{"planId":"` + id + `","confirm":null}`},
		{"apply", `{"planId":"` + id + `","Confirm":true}`}, {"apply", `{"planId":"` + id + `","confirm":"true"}`}, {"apply", `{"planId":"` + id + `","confirm":true,"confirm":true}`},
		{"apply", `{"planId":"` + id + `","confirm":true,"force":true}`}, {"apply", `{"planId":null,"confirm":true}`}, {"apply", `{"planId":"../../private","confirm":true}`},
		{"preview", `{"generation":"` + strings.Repeat("a", 4096) + `"}`},
	}
	for _, item := range cases {
		assertReconciliationAPIError(t, reconciliationAPIRequest(server, http.MethodPost, "/api/v1/system/history/reconciliation/"+item.path, item.body), http.StatusBadRequest, "reconciliation-invalid")
	}
	for _, path := range []string{"/api/v1/system/history/reconciliation?x=1", "/api/v1/system/history/reconciliation/receipts/" + id + "?x=1", "/api/v1/system/history/reconciliation/receipts/not-an-id"} {
		assertReconciliationAPIError(t, reconciliationAPIRequest(server, http.MethodGet, path, ""), http.StatusBadRequest, "reconciliation-invalid")
	}
	for _, name := range []string{".workflow-active.lock", ".workflow-store.lock", ".workflow-lifecycle", ".workflow-reconciliation", ".workflow-reconciliation.current"} {
		if _, err := os.Lstat(filepath.Join(server.Store.Root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid reconciliation input initialized metadata or root locks")
		}
	}
}

func TestLifecycleReconciliationAPIStatusDoesNotInitializeOrGrantProof(t *testing.T) {
	server := makeServer(t)
	response := reconciliationAPIRequest(server, http.MethodGet, "/api/v1/system/history/reconciliation", "")
	var status workflow.LifecycleReconciliationStatus
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.State != "none" || status.CanPreview || status.ResumeAvailable || status.Scope != "original-local-owners-only" || status.Protection != "retirement-unavailable" {
		t.Fatal("absent reconciliation status became a permission or failed read")
	}
	for _, name := range []string{".workflow-active.lock", ".workflow-store.lock", ".workflow-lifecycle", ".workflow-reconciliation", ".workflow-reconciliation.current"} {
		if _, err := os.Lstat(filepath.Join(server.Store.Root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("readonly reconciliation status initialized metadata")
		}
	}
	assertReconciliationAPIError(t, reconciliationAPIRequest(server, http.MethodPost, "/api/v1/system/history/reconciliation/preview", `{}`), http.StatusConflict, "reconciliation-unavailable")
}

func TestLifecycleReconciliationAPIDefaultDenialAndSessionBoundary(t *testing.T) {
	server := makeServer(t)
	authority := apiPolicy(t, managed.Policy{AllowProfileChanges: true, AllowWorkflowHistoryRetirement: true})
	guard := managed.NewGuard(func() (*managed.Authority, error) { return authority, nil })
	server.Policy = guard
	server.Workflows = workflow.NewWithGuard(server.Store.Root, guard)
	assertReconciliationAPIError(t, reconciliationAPIRequest(server, http.MethodPost, "/api/v1/system/history/reconciliation/preview", `{}`), http.StatusForbidden, "reconciliation-denied")
	paths := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/system/history/reconciliation", ""},
		{http.MethodGet, "/api/v1/system/history/reconciliation/receipts/" + strings.Repeat("a", 48), ""},
		{http.MethodPost, "/api/v1/system/history/reconciliation/preview", `{}`},
		{http.MethodPost, "/api/v1/system/history/reconciliation/apply", `{"planId":"` + strings.Repeat("a", 48) + `","confirm":true}`},
	}
	for _, item := range paths {
		request := httptest.NewRequest(item.method, item.path, strings.NewReader(item.body))
		request.Host = "127.0.0.1:54321"
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatal("unauthenticated reconciliation route bypassed session boundary")
		}
	}
	// Only the mode flag is needed to exercise route denial. No storage recorder
	// is initialized and no native policy/audit provider is consulted here.
	server.profileAudit = &audit.Recorder{}
	for _, item := range paths {
		if response := reconciliationAPIRequest(server, item.method, item.path, item.body); response.Code != http.StatusForbidden {
			t.Fatal("profile-only mode admitted history reconciliation")
		}
	}
}

func TestLifecycleReconciliationAPIFixedErrorsAndMetadataLimits(t *testing.T) {
	cases := []struct {
		cause  error
		read   bool
		status int
		code   string
	}{
		{workflow.ErrLifecycleReconciliationInvalidRequest, false, 400, "reconciliation-invalid"},
		{workflow.ErrLifecycleReconciliationUnavailable, false, 409, "reconciliation-unavailable"}, {workflow.ErrLifecycleReconciliationUnavailable, true, 503, "reconciliation-unavailable"},
		{workflow.ErrLifecycleReconciliationConflict, false, 409, "reconciliation-conflict"}, {workflow.ErrLifecycleReconciliationExpired, false, 409, "reconciliation-expired"}, {workflow.ErrLifecycleReconciliationPending, true, 409, "reconciliation-pending"},
		{managed.ErrDenied, false, 403, "reconciliation-denied"}, {managed.ErrUnavailable, false, 503, "reconciliation-policy-unavailable"},
		{workflow.ErrWorkflowBusy, true, 503, "reconciliation-busy"}, {workflow.ErrWorkflowStore, false, 503, "reconciliation-store-unavailable"},
		{context.Canceled, false, 408, "reconciliation-request-ended"}, {context.DeadlineExceeded, true, 408, "reconciliation-request-ended"},
	}
	for _, item := range cases {
		response := httptest.NewRecorder()
		failReconciliation(response, errors.Join(item.cause, errors.New("PRIVATE_PATH_OR_PAYLOAD")), item.read)
		assertReconciliationAPIError(t, response, item.status, item.code)
	}
	response := httptest.NewRecorder()
	writeReconciliationMetadata(response, map[string]string{"private": strings.Repeat("PRIVATE", 1024)}, 4096)
	assertReconciliationAPIError(t, response, http.StatusInternalServerError, "reconciliation-unavailable")
}

type reconciliationSlowResponse struct {
	header  http.Header
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *reconciliationSlowResponse) Header() http.Header { return w.header }
func (*reconciliationSlowResponse) WriteHeader(int)       {}
func (w *reconciliationSlowResponse) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(data), nil
}

func TestLifecycleReconciliationAPIReadBackpressureKeepsCancelIndependent(t *testing.T) {
	server := makeServer(t)
	writer := &reconciliationSlowResponse{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() {
		unblock.Do(func() { close(writer.release) })
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned reconciliation response did not drain")
		}
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/history/reconciliation", nil)
	request.Host = "127.0.0.1:54321"
	request.Header.Set("X-AccessWeaver-Token", server.Token)
	go func() { defer close(done); server.Handler().ServeHTTP(writer, request) }()
	select {
	case <-writer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("reconciliation status did not reach bounded response writer")
	}
	response := reconciliationAPIRequest(server, http.MethodGet, "/api/v1/system/history/reconciliation", "")
	assertReconciliationAPIError(t, response, http.StatusServiceUnavailable, "reconciliation-busy")
	if response.Header().Get("Retry-After") != "1" {
		t.Fatal("reconciliation read backpressure omitted retry guidance")
	}
	response = reconciliationAPIRequest(server, http.MethodPost, "/api/v1/system/cancel", `{}`)
	if response.Code != http.StatusOK {
		t.Fatal("slow reconciliation read blocked unrelated workflow cancellation")
	}
	unblock.Do(func() { close(writer.release) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("bounded reconciliation response did not finish after release")
	}
}
