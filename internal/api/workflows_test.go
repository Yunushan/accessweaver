package api

import (
	"encoding/json"
	"testing"
)

func TestSystemWorkflowPreviewAndConfirmation(t *testing.T) {
	s := makeServer(t)
	response := request(t, s, "GET", "/api/v1/system", nil, s.Token, "127.0.0.1:54321")
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	response = request(t, s, "POST", "/api/v1/system/preview", map[string]any{"action": "discover", "injected": true}, s.Token, "127.0.0.1:54321")
	if response.Code != 400 {
		t.Fatal("unknown input accepted")
	}
	response = request(t, s, "POST", "/api/v1/system/preview", map[string]any{"action": "discover"}, s.Token, "127.0.0.1:54321")
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var plan struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	response = request(t, s, "POST", "/api/v1/system/start", map[string]any{"planId": plan.ID, "confirm": false}, s.Token, "127.0.0.1:54321")
	if response.Code != 400 {
		t.Fatal("unconfirmed system change accepted")
	}
	response = request(t, s, "POST", "/api/v1/system/start", map[string]any{"planId": "unknown", "confirm": true}, s.Token, "127.0.0.1:54321")
	if response.Code != 409 {
		t.Fatal("unreviewed system change accepted")
	}
}
