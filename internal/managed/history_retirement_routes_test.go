package managed_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

// Actual HTTP routing and workflow validation are composed only in memory.
// The fresh signing pair is test-only; no enrollment, native worker or network.
func TestHistoryRetirementPermissionDoesNotExposeAnActionOrRoute(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("source signing fixture unavailable")
	}
	now := time.Now().UTC()
	payload, err := json.Marshal(managed.Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), AllowWorkflowHistoryRetirement: true})
	if err != nil {
		t.Fatal("source policy unavailable")
	}
	envelope, err := managed.Sign(payload, private, now)
	if err != nil {
		t.Fatal("source policy could not be signed")
	}
	installation, err := managed.PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		t.Fatal("source policy could not be prepared")
	}
	authority, err := managed.DecodeInstallation(installation, now)
	if err != nil {
		t.Fatal("source policy could not be authenticated")
	}
	guard := managed.NewGuard(func() (*managed.Authority, error) { return authority, nil })
	root := t.TempDir()
	server, err := api.New(&profile.Store{Root: root}, nil, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("inert source fixture")}})
	if err != nil {
		t.Fatal("in-memory source server unavailable")
	}
	server.Policy = guard
	server.Workflows = workflow.NewWithGuard(root, guard)
	handler := server.Handler()
	for _, path := range []string{"/api/v1/system/history/retirement/preview", "/api/v1/system/history/retirement/apply"} {
		request := httptest.NewRequest(http.MethodPost, "http://localhost"+path, strings.NewReader("{}"))
		request.Header.Set("X-AccessWeaver-Token", server.Token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatal("permission exposed an unimplemented retirement route")
		}
	}
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/system/preview", strings.NewReader(`{"action":"history-retirement"}`))
	request.Header.Set("X-AccessWeaver-Token", server.Token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatal("permission added a native workflow action")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("unimplemented action or route mutated source storage")
	}
}
