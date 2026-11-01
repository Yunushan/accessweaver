package api

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func apiPolicy(t *testing.T, p managed.Policy) *managed.Authority {
	t.Helper()
	now := time.Now().UTC()
	p.SchemaVersion = 1
	p.Revision = 1
	p.IssuedAt = now.Add(-time.Minute)
	p.ExpiresAt = now.Add(time.Hour)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := private.Public().(ed25519.PublicKey)
	envelope, err := managed.Sign(data, private, now)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := managed.PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := managed.DecodeInstallation(installation, now)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func TestManagedAPIBlocksWritesAndNetworkDiagnostics(t *testing.T) {
	server := makeServer(t)
	p := profile.New("managed-profile", "Original", "byedpi")
	if err := server.Store.Save(p); err != nil {
		t.Fatal(err)
	}
	p, err := server.Store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(server.Store.Root, "profiles", p.ID+".json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	authority := apiPolicy(t, managed.Policy{})
	guard := managed.NewGuard(func() (*managed.Authority, error) { return authority, nil })
	server.Policy = guard
	server.Store, err = profile.NewStoreWithGuard(server.Store.Root, guard)
	if err != nil {
		t.Fatal(err)
	}
	server.Manager = engine.NewManagerWithGuard(server.Store.Root, guard)
	server.Workflows = workflow.NewWithGuard(server.Store.Root, guard)
	p.Name = "Unauthorized"
	for _, test := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "/api/v1/profiles/" + p.ID, p},
		{"DELETE", "/api/v1/profiles/" + p.ID, map[string]any{"expectedUpdatedAt": p.UpdatedAt}},
		{"POST", "/api/v1/diagnose", profile.Probe{Host: "example.invalid", Port: 443, TLS: true, TimeoutSeconds: 1}},
	} {
		response := request(t, server, test.method, test.path, test.body, server.Token, "127.0.0.1:54321")
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s bypassed policy: %d %s", test.path, response.Code, response.Body.String())
		}
	}
	after, err := os.ReadFile(file)
	if err != nil || string(before) != string(after) {
		t.Fatal("denied API mutation changed profile", err)
	}
	response := request(t, server, "GET", "/api/v1/profiles", nil, server.Token, "127.0.0.1:54321")
	if response.Code != http.StatusOK {
		t.Fatal("managed read-only inspection blocked", response.Code)
	}
}
