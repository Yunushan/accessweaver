package api

import (
	"bytes"
	"encoding/json"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/profile"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestBootstrapUsesRuntimeBuildIdentity(t *testing.T) {
	s := makeServer(t)
	previous := buildinfo.Version
	buildinfo.Version = "2.3.4-rc.1"
	defer func() { buildinfo.Version = previous }()
	w := request(t, s, "GET", "/api/bootstrap", nil, s.Token, "127.0.0.1:54321")
	var response struct {
		Version string         `json:"version"`
		Build   buildinfo.Info `json:"build"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 {
		t.Fatalf("bootstrap: %d %v", w.Code, err)
	}
	if response.Version != buildinfo.Version || response.Build.Version != response.Version || response.Build.Platform == "" || response.Build.SourceState == "" {
		t.Fatalf("inconsistent bootstrap: %+v", response)
	}
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
	w = request(t, s, "GET", "/api/v1/profiles/my-profile", nil, s.Token, "127.0.0.1:54321")
	if w.Code != 200 {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	var saved profile.Profile
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	w = request(t, s, "DELETE", "/api/v1/profiles/my-profile", map[string]any{"expectedUpdatedAt": saved.UpdatedAt}, s.Token, "127.0.0.1:54321")
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

func TestProfileAPIRejectsStaleSavesAndDeletes(t *testing.T) {
	s := makeServer(t)
	p := profile.New("shared-edit", "Original", "byedpi")
	path := "/api/v1/profiles/" + p.ID
	put := func(p profile.Profile) *httptest.ResponseRecorder {
		return request(t, s, "PUT", path, p, s.Token, "127.0.0.1:54321")
	}
	w := put(p)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = put(p); w.Code != 409 {
		t.Fatalf("duplicate creation: %d %s", w.Code, w.Body.String())
	}
	first, err := s.Store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	edit := first.Copy()
	edit.Name = "Saved from another tab"
	if w = put(edit); w.Code != 200 {
		t.Fatalf("current revision edit: %d %s", w.Code, w.Body.String())
	}
	if w = put(first); w.Code != 409 {
		t.Fatalf("stale edit: %d %s", w.Code, w.Body.String())
	}
	w = request(t, s, "DELETE", path, map[string]any{}, s.Token, "127.0.0.1:54321")
	if w.Code != 400 {
		t.Fatalf("unreviewed deletion: %d", w.Code)
	}
	w = request(t, s, "DELETE", path, map[string]any{"expectedUpdatedAt": first.UpdatedAt}, s.Token, "127.0.0.1:54321")
	if w.Code != 409 {
		t.Fatalf("stale deletion: %d", w.Code)
	}
	latest, err := s.Store.Get(p.ID)
	if err != nil || latest.Name != edit.Name {
		t.Fatalf("newer edit lost: %+v %v", latest, err)
	}
	w = request(t, s, "DELETE", path, map[string]any{"expectedUpdatedAt": latest.UpdatedAt}, s.Token, "127.0.0.1:54321")
	if w.Code != 200 {
		t.Fatalf("current revision deletion: %d %s", w.Code, w.Body.String())
	}
	if w = put(latest); w.Code != 409 {
		t.Fatalf("stale resurrection: %d", w.Code)
	}
}

func TestCrossOriginBootstrapDenied(t *testing.T) {
	s := makeServer(t)
	for _, header := range []struct{ name, value string }{
		{"Origin", "https://evil.invalid"}, {"Sec-Fetch-Site", "cross-site"}, {"Sec-Fetch-Site", "same-site"},
	} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:54321/api/bootstrap", nil)
		r.Header.Set(header.name, header.value)
		r.Header.Set("X-AccessWeaver-Token", s.Token)
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

func TestBusyProfileStoreReturnsRetryableResponse(t *testing.T) {
	s := makeServer(t)
	p := profile.New("busy-store", "Retain this profile", "byedpi")
	if err := s.Store.Save(p); err != nil {
		t.Fatal(err)
	}
	saved, err := s.Store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := filelock.TryAcquire(filepath.Join(s.Store.Root, ".profiles.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	w := request(t, s, "DELETE", "/api/v1/profiles/"+p.ID, map[string]any{"expectedUpdatedAt": saved.UpdatedAt}, s.Token, "127.0.0.1:54321")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("store contention: %d %s", w.Code, w.Body.String())
	}
	owner.Close()
	retained, err := s.Store.Get(p.ID)
	if err != nil || !retained.UpdatedAt.Equal(saved.UpdatedAt) {
		t.Fatal("contended deletion changed the profile", err)
	}
}
