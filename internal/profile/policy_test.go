package profile

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
)

func profilePolicy(t *testing.T, p managed.Policy) *managed.Authority {
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

func TestMachinePolicyPreservesReadOnlyProfileState(t *testing.T) {
	root := t.TempDir()
	allowed := profilePolicy(t, managed.Policy{AllowProfileChanges: true})
	denied := profilePolicy(t, managed.Policy{})
	var writable atomic.Bool
	writable.Store(true)
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		if writable.Load() {
			return allowed, nil
		}
		return denied, nil
	})
	store, err := NewStoreWithGuard(root, guard)
	if err != nil {
		t.Fatal(err)
	}
	original := New("policy-profile", "Original", "byedpi")
	if err := store.Save(original); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "profiles", original.ID+".json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	writable.Store(false)
	saved.Name = "Unauthorized edit"
	for name, change := range map[string]func() error{"save": func() error { return store.Save(saved) }, "revision save": func() error { return store.SaveIfUnchanged(saved) }, "delete": func() error { return store.Delete(saved.ID) }, "revision delete": func() error { return store.DeleteIfUnchanged(saved.ID, saved.UpdatedAt) }} {
		if err := change(); !errors.Is(err, managed.ErrDenied) {
			t.Fatalf("%s bypassed policy: %v", name, err)
		}
	}
	if err := store.Seed([]Profile{New("new-profile", "Must not seed", "byedpi")}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(before) != string(after) {
		t.Fatal("denied mutation changed saved bytes", err)
	}
	if _, err := os.Stat(filepath.Join(root, "presets-initialized")); !os.IsNotExist(err) {
		t.Fatal("read-only seed wrote completion marker", err)
	}
	items, err := store.List()
	if err != nil || len(items) != 1 || items[0].Name != "Original" {
		t.Fatal("read-only inspection failed", err)
	}
}

func TestProfilePolicyRecheckedAfterStoreLock(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	p := New("locked-profile", "Original", "byedpi")
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	allowed := profilePolicy(t, managed.Policy{AllowProfileChanges: true})
	denied := profilePolicy(t, managed.Policy{})
	var revoked atomic.Bool
	entered := make(chan struct{})
	var once sync.Once
	store.guard = managed.NewGuard(func() (*managed.Authority, error) {
		once.Do(func() { close(entered) })
		if revoked.Load() {
			return denied, nil
		}
		return allowed, nil
	})
	owner, err := store.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	done := make(chan error, 1)
	go func() { p.Name = "Must not replace"; done <- store.Save(p) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("save did not check policy")
	}
	revoked.Store(true)
	owner.Close()
	select {
	case err := <-done:
		if !errors.Is(err, managed.ErrDenied) {
			t.Fatal("revocation while waiting for lock ignored", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("save did not finish")
	}
	current, err := store.Get(p.ID)
	if err != nil || current.Name != "Original" {
		t.Fatal("revoked save changed profile", err)
	}
}
