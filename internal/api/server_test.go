package api

import (
	"bytes"
	"encoding/json"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/profile"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func makeServer(t *testing.T) *Server {
	t.Helper()
	st, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(st, engine.NewManager(st.Root), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func request(t *testing.T, s *Server, method, path string, body any, token string, host string) *httptest.ResponseRecorder {
	t.Helper()
	var content []byte
	if body != nil {
		content, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:54321"+path, bytes.NewReader(content))
	r.Host = host
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("X-AccessWeaver-Token", token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestLoopbackAndSessionProtection(t *testing.T) {
	s := makeServer(t)
	badHost := request(t, s, "GET", "/api/bootstrap", nil, "", "evil.invalid:54321")
	if badHost.Code != http.StatusForbidden {
		t.Fatalf("bad host returned %d", badHost.Code)
	}
	badToken := request(t, s, "POST", "/api/v1/stop", map[string]any{}, "invalid", "127.0.0.1:54321")
	if badToken.Code != http.StatusForbidden {
		t.Fatalf("bad token returned %d", badToken.Code)
	}
	good := request(t, s, "POST", "/api/v1/stop", map[string]any{}, s.Token, "127.0.0.1:54321")
	if good.Code != 200 {
		t.Fatalf("authorized request returned %d: %s", good.Code, good.Body.String())
	}
}
func TestProfileAPICRUD(t *testing.T) {
	s := makeServer(t)
	p := profile.New("my-profile", "My Profile", "byedpi")
	w := request(t, s, "PUT", "/api/v1/profiles/my-profile", p, s.Token, "127.0.0.1:54321")
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	w = request(t, s, "GET", "/api/v1/profiles/my-profile", nil, "", "127.0.0.1:54321")
	if w.Code != 200 {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	w = request(t, s, "DELETE", "/api/v1/profiles/my-profile", nil, s.Token, "127.0.0.1:54321")
	if w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
}
func TestCannotStartWithoutConfirmation(t *testing.T) {
	s := makeServer(t)
	p := profile.New("my-profile", "My Profile", "byedpi")
	_ = s.Store.Save(p)
	w := request(t, s, "POST", "/api/v1/start", map[string]any{"id": "my-profile", "confirm": false}, s.Token, "127.0.0.1:54321")
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCrossOriginBootstrapDenied(t *testing.T) {
	s := makeServer(t)
	for _, header := range []struct{ name, value string }{
		{"Origin", "https://evil.invalid"}, {"Sec-Fetch-Site", "cross-site"}, {"Sec-Fetch-Site", "same-site"},
	} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:54321/api/bootstrap", nil)
		r.Header.Set(header.name, header.value)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s=%s returned %d", header.name, header.value, w.Code)
		}
	}
}

func TestPreviewDoesNotLaunchOrSave(t *testing.T) {
	s := makeServer(t)
	p := profile.New("uninstalled-preview", "Preview", "byedpi")
	p.Binary = "/does/not/exist/ciadpi"
	w := request(t, s, "POST", "/api/v1/preview", p, s.Token, "127.0.0.1:54321")
	if w.Code != 200 {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	var plan struct {
		Ready  bool     `json:"ready"`
		Issues []string `json:"issues"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Ready || len(plan.Issues) == 0 {
		t.Fatalf("uninstalled engine marked ready: %s", w.Body.String())
	}
	if s.Manager.Snapshot().State != "stopped" {
		t.Fatal("preview changed process state")
	}
	if _, err := s.Store.Get(p.ID); err == nil {
		t.Fatal("preview saved a profile")
	}
}

func TestProfileRejectsTrailingJSON(t *testing.T) {
	s := makeServer(t)
	p := profile.New("strict", "Strict", "byedpi")
	data, _ := json.Marshal(p)
	r := httptest.NewRequest("PUT", "http://127.0.0.1:54321/api/v1/profiles/strict", bytes.NewReader(append(data, []byte(` {"ignored":true}`)...)))
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("accepted trailing JSON: %d", w.Code)
	}
}

func TestLaunchRequiresReviewedProfileRevision(t *testing.T) {
	s := makeServer(t)
	p := profile.New("reviewed", "Original", "byedpi")
	if err := s.Store.Save(p); err != nil {
		t.Fatal(err)
	}
	reviewed, err := s.Store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "Changed in another tab"
	if err := s.Store.Save(p); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		revision string
		status   int
	}{
		{"", 400}, {reviewed.UpdatedAt.Format(time.RFC3339Nano), 409},
	} {
		w := request(t, s, "POST", "/api/v1/start", map[string]any{"id": p.ID, "confirm": true, "expectedUpdatedAt": tc.revision}, s.Token, "127.0.0.1:54321")
		if w.Code != tc.status {
			t.Fatalf("revision %q: want %d got %d: %s", tc.revision, tc.status, w.Code, w.Body.String())
		}
		if s.Manager.Snapshot().State != "stopped" {
			t.Fatal("stale review launched engine")
		}
	}
}
