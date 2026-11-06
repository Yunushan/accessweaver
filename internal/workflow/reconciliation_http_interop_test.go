package workflow_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func reconciliationHTTPServer(t *testing.T, root string, manager *workflow.Manager) *api.Server {
	t.Helper()
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	store, err := profile.NewStoreWithGuard(root, guard)
	if err != nil {
		t.Fatal("source reconciliation API fixture store unavailable")
	}
	server, err := api.New(store, engine.NewManagerWithGuard(root, guard), nil)
	if err != nil {
		t.Fatal("source reconciliation API fixture server unavailable")
	}
	server.Policy = guard
	server.Workflows = manager
	return server
}
func reconciliationHTTPRequest(t *testing.T, server *api.Server, method, path string, input any) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			t.Fatal("source reconciliation request encoding unavailable")
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Host = "127.0.0.1:54321"
	request.Header.Set("X-AccessWeaver-Token", server.Token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func TestLifecycleReconciliationActualAPIPreservesFailedEvidenceAndRecoversReceipt(t *testing.T) {
	manager, root, generation := workflow.NewReconciliationHTTPFixtureForTest(t)
	server := reconciliationHTTPServer(t, root, manager)
	recordPath := filepath.Join(root, "workflows", generation+".json")
	original, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal("source original record unavailable")
	}
	response := reconciliationHTTPRequest(t, server, http.MethodGet, "/api/v1/system/history/reconciliation", nil)
	var status workflow.LifecycleReconciliationStatus
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.State != "available" || !status.CanPreview {
		t.Fatalf("actual source API did not expose known positive witness: status%d", response.Code)
	}
	// The same on-disk seal and released OS locks do not give a fresh Manager the
	// original live capability. Its authenticated API must refuse preview.
	foreign := reconciliationHTTPServer(t, root, workflow.NewWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })))
	refused := reconciliationHTTPRequest(t, foreign, http.MethodPost, "/api/v1/system/history/reconciliation/preview", map[string]string{})
	if refused.Code != http.StatusConflict || bytes.Contains(refused.Body.Bytes(), []byte(root)) {
		t.Fatal("fresh API invented closure or exposed a private root")
	}
	response = reconciliationHTTPRequest(t, server, http.MethodPost, "/api/v1/system/history/reconciliation/preview", map[string]string{"generation": generation})
	var plan workflow.LifecycleReconciliationPlan
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &plan) != nil || plan.Generation != generation || plan.OperationID == "" || plan.ReviewRevision == "" || len(plan.Objects) != 1 || plan.Resume {
		t.Fatalf("actual closed-stage preview failed: status%d", response.Code)
	}
	response = reconciliationHTTPRequest(t, server, http.MethodPost, "/api/v1/system/history/reconciliation/apply", map[string]any{"planId": plan.ID, "confirm": true})
	var receipt workflow.LifecycleReconciliationReceipt
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &receipt) != nil || receipt.OperationID != plan.OperationID || receipt.State != "completed" || receipt.Generation != generation || receipt.Scope != "original-local-owners-only" || receipt.Protection != "retirement-unavailable" {
		t.Fatalf("actual API reviewed apply failed: status%d", response.Code)
	}
	recovered := reconciliationHTTPRequest(t, foreign, http.MethodGet, "/api/v1/system/history/reconciliation/receipts/"+plan.OperationID, nil)
	if recovered.Code != http.StatusOK || !bytes.Equal(recovered.Body.Bytes(), response.Body.Bytes()) {
		t.Fatalf("fresh source API did not recover immutable receipt: status%d", recovered.Code)
	}
	replay := reconciliationHTTPRequest(t, server, http.MethodPost, "/api/v1/system/history/reconciliation/apply", map[string]any{"planId": plan.ID, "confirm": true})
	if replay.Code != http.StatusOK || !bytes.Equal(replay.Body.Bytes(), response.Body.Bytes()) {
		t.Fatal("replayed apply repeated work or changed immutable receipt")
	}
	after, err := os.ReadFile(recordPath)
	if err != nil || !bytes.Equal(original, after) || manager.Snapshot().State != "failed" {
		t.Fatal("local completion repair rewrote the original failed workflow")
	}
	if manager.TerminalError(generation) == nil {
		t.Fatal("original native/metadata failure was cleared instead of retained")
	}
	current, err := manager.LifecycleStatus(context.Background())
	if err != nil || current.State != "released" || current.AdmissionBlocked {
		t.Fatal("actual reviewed local release was not visible after receipt")
	}
	if _, err := os.Lstat(filepath.Join(root, "workflows", generation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no-execute API source fixture created a native workdir")
	}
}
