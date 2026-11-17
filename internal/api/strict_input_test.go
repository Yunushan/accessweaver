package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/diagnostics"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestCanonicalProfileRequestsRejectAmbiguityWithoutMutation(t *testing.T) {
	server := makeServer(t)
	original := profile.New("canonical-request", "Original", "byedpi")
	if server.Store.Save(original) != nil {
		t.Fatal("fixture profile save failed")
	}
	saved, err := server.Store.Get(original.ID)
	if err != nil {
		t.Fatal("fixture profile unavailable")
	}
	source, err := json.Marshal(saved)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	path := filepath.Join(server.Store.Root, "profiles", saved.ID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("owned fixture read failed")
	}
	for _, body := range []string{
		strings.Replace(string(source), `"id":`, `"id":"canonical-request","id":`, 1),
		strings.Replace(string(source), `"id":`, `"ID":`, 1),
		strings.Replace(string(source), `"name":`, `"\u006eame":"PRIVATE_REJECTED_VALUE","name":`, 1),
		strings.Replace(string(source), `"tls":`, `"tls":false,"tls":`, 1),
		strings.Replace(string(source), `"includeDomains":`, `"IncludeDomains":`, 1),
	} {
		for _, route := range []struct{ method, path string }{{"PUT", "/api/v1/profiles/" + saved.ID}, {"POST", "/api/v1/preview"}} {
			request := httptest.NewRequest(route.method, "http://127.0.0.1:54321"+route.path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-AccessWeaver-Token", server.Token)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "PRIVATE_REJECTED_VALUE") {
				t.Fatal("ambiguous profile request was accepted or disclosed input")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected request changed saved profile bytes")
			}
		}
	}
}

func TestCanonicalJSONRequestShapes(t *testing.T) {
	decode := func(body string, target any) error {
		request := httptest.NewRequest("POST", "http://127.0.0.1/", strings.NewReader(body))
		return readJSON(httptest.NewRecorder(), request, target)
	}
	var diagnostic diagnostics.Request
	if decode(`{"host":"example.invalid","port":443,"tls":false,"timeoutSeconds":5,"path":"socks5","proxy":"127.0.0.1:1080"}`, &diagnostic) != nil || diagnostic.Host != "example.invalid" || diagnostic.TLS || diagnostic.Port != 443 || diagnostic.Path != "socks5" {
		t.Fatal("embedded diagnostic fields lost compatibility")
	}
	var system workflow.Request
	if decode(`{"action":"discover","args":null,"browsers":false,"enabled":false}`, &system) != nil || system.Action != "discover" || system.Args != nil {
		t.Fatal("canonical workflow request lost compatibility")
	}
	var revision struct {
		At time.Time `json:"expectedUpdatedAt"`
	}
	if decode(`{"expectedUpdatedAt":"2026-11-07T12:34:56.123456789Z"}`, &revision) != nil || revision.At.Nanosecond() != 123456789 {
		t.Fatal("revision precision changed")
	}
	var empty map[string]json.RawMessage
	if decode(`{}`, &empty) != nil || empty == nil || len(empty) != 0 {
		t.Fatal("empty history request rejected")
	}
	original := struct {
		Confirm bool   `json:"confirm"`
		ID      string `json:"id"`
	}{true, "unchanged"}
	for _, body := range []string{`{"confirm":false,"confirm":true}`, `{"Confirm":true}`, `{"confirm":null}`, `{"id":"partial","confirm":"invalid"}`} {
		got := original
		if decode(body, &got) == nil || !reflect.DeepEqual(got, original) {
			t.Fatal("invalid action request published confirmation or identity")
		}
	}
}
