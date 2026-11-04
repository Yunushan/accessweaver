//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestAuditedProfileControllerProtectedStorageExportRoundTrip(t *testing.T) {
	base := auditedImportDirectory(t)
	directory := filepath.Join(base, "audit")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	start, err := audit.InitializeLocalJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(directory, ".actor-key"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := audit.OpenLocalJournal(context.Background(), directory, start, start)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoints bytes.Buffer
	recorder, err := audit.NewRecorder(context.Background(), journal, start, start, &checkpoints)
	if err != nil {
		journal.Close()
		t.Fatal(err)
	}
	defer recorder.Close()
	store, err := profile.NewStore(filepath.Join(base, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := api.NewProfileAudited(store, engine.NewManager(store.Root), nil, recorder)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	p := profile.New("private-profile", "PRIVATE_PROFILE_NAME", "byedpi")
	call := func(method string, input any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "http://localhost/api/v1/profiles/"+p.ID, bytes.NewReader(body))
		r.Header.Set("X-AccessWeaver-Token", server.Token)
		r.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	response := call("PUT", p)
	if response.Code != 200 {
		t.Fatal("real create failed", response.Code, response.Body.String())
	}
	var saved profile.Profile
	if err := json.Unmarshal(response.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if response := call("PUT", p); response.Code != 409 {
		t.Fatal("stale create accepted", response.Code)
	}
	if response := call("DELETE", map[string]any{"expectedUpdatedAt": saved.UpdatedAt}); response.Code != 200 {
		t.Fatal("real delete failed", response.Code, response.Body.String())
	}
	observed := decodeCheckpointObservations(t, checkpoints.Bytes())
	if len(observed) != 6 || observed[5].Sequence != 6 {
		t.Fatal("missing observed checkpoints")
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	var exported bytes.Buffer
	if err := audit.ExportLocalSegment(context.Background(), directory, start, observed[5], &exported); err != nil {
		t.Fatal(err)
	}
	result, err := audit.VerifySegment(context.Background(), bytes.NewReader(exported.Bytes()), start, observed[5])
	if err != nil || result.Records != 6 {
		t.Fatal("export verification failed", err)
	}
	if bytes.Contains(exported.Bytes(), []byte("PRIVATE")) || bytes.Contains(exported.Bytes(), key) {
		t.Fatal("private source material exported")
	}
	if now, err := os.ReadFile(filepath.Join(directory, ".actor-key")); err != nil || !bytes.Equal(now, key) {
		t.Fatal("actor key changed")
	}
	entries, err := os.ReadDir(filepath.Join(store.Root, "profiles"))
	if err != nil || len(entries) != 0 {
		t.Fatal("unexpected profiles left", err)
	}
	if _, err := os.Stat(filepath.Join(store.Root, "presets-initialized")); !os.IsNotExist(err) {
		t.Fatal("audited desktop seeded profiles")
	}
}
