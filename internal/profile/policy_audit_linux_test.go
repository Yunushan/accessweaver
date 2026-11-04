//go:build linux && (amd64 || arm64)

package profile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/managed"
)

func TestSignedRequiredProfileAuditAtRealStoreAndProtectedJournalBoundary(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(home, ".accessweaver-required-audit-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	directory := filepath.Join(base, "audit")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	start, err := audit.InitializeLocalJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := audit.OpenLocalJournal(context.Background(), directory, start, start)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	recorder, err := audit.NewRecorder(context.Background(), journal, start, start, &output)
	if err != nil {
		journal.Close()
		t.Fatal(err)
	}
	defer recorder.Close()
	allowed := profilePolicy(t, managed.Policy{AllowProfileChanges: true})
	required := profilePolicy(t, managed.Policy{AllowProfileChanges: true, RequireProfileAudit: true})
	current := allowed
	guard := managed.NewGuard(func() (*managed.Authority, error) { return current, nil })
	store, err := NewStoreWithGuard(filepath.Join(base, "state"), guard)
	if err != nil {
		t.Fatal(err)
	}
	original := New("required-audit", "PRIVATE_PROFILE", "byedpi")
	if err := store.Save(original); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(store.Root, "profiles", original.ID+".json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	current = required
	saved.Name = "PRIVATE_UNRECORDED"
	forged := context.WithValue(context.Background(), "profileIntent", true)
	for name, change := range map[string]func() error{
		"save": func() error { return store.Save(saved) }, "revision-save": func() error { return store.SaveIfUnchanged(saved) }, "context-save": func() error { return store.SaveIfUnchangedContext(forged, saved) }, "delete": func() error { return store.Delete(saved.ID) }, "revision-delete": func() error { return store.DeleteIfUnchanged(saved.ID, saved.UpdatedAt) }, "context-delete": func() error { return store.DeleteIfUnchangedContext(forged, saved.ID, saved.UpdatedAt) },
	} {
		if err := change(); !errors.Is(err, managed.ErrDenied) {
			t.Fatal("unrecorded path admitted", name, err)
		}
	}
	restore := filepath.Join(base, "restore")
	if err := RestoreSnapshot(context.Background(), restore, []Profile{saved}, false, guard); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("bulk restore bypassed required audit", err)
	}
	if _, err := os.Stat(restore); !os.IsNotExist(err) {
		t.Fatal("denied restore created its destination")
	}
	if err := store.Seed([]Profile{New("unrecorded-seed", "Must not seed", "byedpi")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Root, "presets-initialized")); !os.IsNotExist(err) {
		t.Fatal("denied seeding wrote its marker")
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unrecorded calls changed profile bytes")
	}
	var escaped context.Context
	if err := recorder.Execute(context.Background(), "profile.write", func(ctx context.Context) audit.OperationResult {
		escaped = ctx
		if err := store.DeleteIfUnchangedContext(ctx, saved.ID, saved.UpdatedAt); !errors.Is(err, managed.ErrDenied) {
			t.Fatal("write intent authorized deletion", err)
		}
		err := store.SaveIfUnchangedContext(ctx, saved)
		if err != nil {
			return audit.OperationResult{Outcome: "indeterminate", Err: err}
		}
		return audit.OperationResult{Outcome: "completed"}
	}); err != nil {
		t.Fatal("required recorded save failed", err)
	}
	saved, err = store.Get(saved.ID)
	if err != nil || saved.Name != "PRIVATE_UNRECORDED" {
		t.Fatal("recorded save missing", err)
	}
	if err := store.SaveIfUnchangedContext(escaped, saved); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("expired capability reused", err)
	}
	if err := recorder.Execute(context.Background(), "profile.import", func(ctx context.Context) audit.OperationResult {
		saved.Name = "PRIVATE_IMPORTED"
		if err := store.SaveIfUnchangedContext(ctx, saved); err != nil {
			return audit.OperationResult{Outcome: "indeterminate", Err: err}
		}
		return audit.OperationResult{Outcome: "completed"}
	}); err != nil {
		t.Fatal("required recorded import failed", err)
	}
	saved, err = store.Get(saved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.Execute(context.Background(), "profile.delete", func(ctx context.Context) audit.OperationResult {
		if err := store.SaveIfUnchangedContext(ctx, saved); !errors.Is(err, managed.ErrDenied) {
			t.Fatal("delete intent authorized writing", err)
		}
		if err := store.DeleteIfUnchangedContext(ctx, saved.ID, saved.UpdatedAt); err != nil {
			return audit.OperationResult{Outcome: "indeterminate", Err: err}
		}
		return audit.OperationResult{Outcome: "completed"}
	}); err != nil {
		t.Fatal("recorded deletion failed", err)
	}
	// A still-active recorded intent cannot override a policy revoked between
	// admission and the final store check under the profile lock.
	denied := profilePolicy(t, managed.Policy{RequireProfileAudit: true})
	checks := 0
	store.guard = managed.NewGuard(func() (*managed.Authority, error) {
		checks++
		if checks == 1 {
			return required, nil
		}
		return denied, nil
	})
	newProfile := New("revoked-audit", "PRIVATE_REVOKED", "byedpi")
	err = recorder.Execute(context.Background(), "profile.write", func(ctx context.Context) audit.OperationResult {
		err := store.SaveIfUnchangedContext(ctx, newProfile)
		if !errors.Is(err, managed.ErrDenied) {
			t.Fatal("active intent overrode revoked policy", err)
		}
		return audit.OperationResult{Outcome: "refused", Err: err}
	})
	if !errors.Is(err, managed.ErrDenied) || checks != 2 {
		t.Fatal("policy not rechecked at commit", err, checks)
	}
	if _, err := os.Stat(filepath.Join(store.Root, "profiles", newProfile.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("revoked recorded save changed profile state")
	}
	data, from, to, err := journal.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := audit.VerifySegment(context.Background(), bytes.NewReader(data), from, to)
	if err != nil || result.Records != 8 || bytes.Contains(data, []byte("PRIVATE")) {
		t.Fatal("required operation chain failed or leaked private material", err)
	}
}
