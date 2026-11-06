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

	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestHistoryLifecycleMissingRootReadDoesNotInitialize(t *testing.T) {
	s := makeServer(t)
	missing := filepath.Join(t.TempDir(), "missing")
	s.Workflows = systemLifecycleManager(missing)
	response := request(t, s, http.MethodGet, "/api/v1/system/history/lifecycle", nil, s.Token, "127.0.0.1")
	var status workflow.WorkflowLifecycleStatus
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.State != "none" || status.JobID != "" || status.AdmissionBlocked || status.Protection != "retirement-unavailable" {
		t.Fatal("uninitialized lifecycle read did not return the actual protected projection")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only lifecycle status initialized missing storage")
	}
	for _, suffix := range []string{"?limit=1", "?unknown=x", "?x=1&x=2", "?" + strings.Repeat("x", 4097)} {
		response = request(t, s, http.MethodGet, "/api/v1/system/history/lifecycle"+suffix, nil, s.Token, "127.0.0.1")
		if response.Code != 400 {
			t.Fatal("completion status accepted unexpected query input")
		}
	}
}

func systemLifecycleManager(root string) *workflow.Manager { return workflow.New(root) }

func TestHistoryLifecycleErrorsAndAdmissionCodesRemainPrivate(t *testing.T) {
	s := makeServer(t)
	private := []byte("PRIVATE_LIFECYCLE_PATH_AND_PAYLOAD")
	if err := os.WriteFile(filepath.Join(s.Store.Root, ".workflow-lifecycle.current"), private, 0600); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, http.MethodGet, "/api/v1/system/history/lifecycle", nil, s.Token, "127.0.0.1")
	if response.Code != 409 || !strings.Contains(response.Body.String(), workflowLifecyclePendingCode) || bytes.Contains(response.Body.Bytes(), private) || strings.Contains(response.Body.String(), "released") {
		t.Fatal("uncertain receipt became a clean status or disclosed private input")
	}
	for _, err := range []error{workflow.ErrWorkflowLifecyclePending, errors.Join(workflow.ErrWorkflowAdmission, workflow.ErrWorkflowLifecyclePending, errors.New(string(private)))} {
		w := httptest.NewRecorder()
		failWorkflowStart(w, err)
		if w.Code != 409 || bytes.Contains(w.Body.Bytes(), private) || !strings.Contains(w.Body.String(), workflowLifecyclePendingCode) {
			t.Fatal("pending start/folder error lost its closed public category")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/history/lifecycle", nil).WithContext(ctx)
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 408 || strings.Contains(w.Body.String(), "released") {
		t.Fatal("ended lifecycle read fabricated completed status")
	}
}

func TestHistoryLifecycleAdmissionIndependentOfSlowRawAndControls(t *testing.T) {
	s := historyBrowserFixture(t, map[string][]byte{"record.json": []byte("private raw evidence")})
	historyBrowserCapture(t, s)
	row := historyBrowserFind(t, historyBrowserPage(t, s, ""), historyBrowserSHA([]byte("private raw evidence")))
	held := &heldHistoryResponse{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(held.release) }) }
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("held raw history response did not join")
		}
	})
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/history/records/"+row.RecordRef+"/export?revision="+row.Revision, nil)
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	go func() { defer close(done); s.Handler().ServeHTTP(held, r) }()
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("raw response did not reach controlled write barrier")
	}
	for _, path := range []string{"/api/v1/system/history/lifecycle", "/api/v1/system"} {
		w := request(t, s, http.MethodGet, path, nil, s.Token, "127.0.0.1")
		if w.Code != 200 {
			t.Fatal("slow raw download blocked independent metadata status")
		}
	}
	s.lifecycleRead.Lock()
	w := request(t, s, http.MethodGet, "/api/v1/system/history/lifecycle", nil, s.Token, "127.0.0.1")
	s.lifecycleRead.Unlock()
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("completion status failed its own nonqueued single-reader gate")
	}
	w = request(t, s, http.MethodPost, "/api/v1/system/cancel", nil, s.Token, "127.0.0.1")
	if w.Code != 200 {
		t.Fatal("slow history blocked current-job cancellation")
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("raw history response did not drain")
	}
	if held.Code != 200 || held.Body.String() != "private raw evidence" {
		t.Fatal("independent lifecycle read changed raw selected evidence")
	}
}

func TestHistoryLifecycleAuthenticationAndProfileAudit(t *testing.T) {
	for _, boundary := range []string{"token", "host", "origin", "fetch"} {
		s := makeServer(t)
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/history/lifecycle", nil)
		r.Header.Set("X-AccessWeaver-Token", s.Token)
		switch boundary {
		case "token":
			r.Header.Set("X-AccessWeaver-Token", "wrong")
		case "host":
			r.Host = "unrelated.invalid"
		case "origin":
			r.Header.Set("Origin", "http://unrelated.invalid")
		case "fetch":
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("completion status bypassed private session boundary")
		}
	}
	s, journal, _ := auditedAPIFixture(t)
	w := request(t, s, http.MethodGet, "/api/v1/system/history/lifecycle", nil, s.Token, "127.0.0.1")
	if w.Code != 403 || journal.calls != 0 {
		t.Fatal("profile-only audited desktop gained completion history access")
	}
}
