package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestPrivateReadsAndBootstrapRequireSessionCredential(t *testing.T) {
	s := makeServer(t)
	for _, path := range []string{"/api/bootstrap", "/api/v1/profiles", "/api/v1/runtime", "/api/v1/engines", "/api/v1/system", "/api/v1/system/history", "/api/v1/system/presets"} {
		for _, method := range []string{"GET", "HEAD"} {
			for _, token := range []string{"", "unrelated-local-account"} {
				response := request(t, s, method, path, nil, token, "127.0.0.1:54321")
				if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), s.Token) {
					t.Fatalf("private read %s %s: %d %s", method, path, response.Code, response.Body.String())
				}
			}
		}
	}
	response := request(t, s, "GET", "/api/bootstrap", nil, s.Token, "127.0.0.1:54321")
	if response.Code != 200 || strings.Contains(response.Body.String(), s.Token) || strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("bootstrap disclosed credential: %d %s", response.Code, response.Body.String())
	}
}

func TestEmptyServerCredentialFailsClosed(t *testing.T) {
	s := makeServer(t)
	s.Token = ""
	response := request(t, s, "GET", "/api/bootstrap", nil, "", "127.0.0.1:54321")
	if response.Code != http.StatusForbidden {
		t.Fatal("empty credential authenticated a caller")
	}
}
