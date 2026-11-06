package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/backup"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestBackupCLIResumeActualInterruptedRestoreAndPreserveMismatch(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	t.Setenv("ACCESSWEAVER_HOME", source)
	store, e := profile.NewStoreWithGuard(source, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	if e != nil {
		t.Fatal(e)
	}
	p := profile.New("resume-profile", "PRIVATE_RESUME_PROFILE", "byedpi")
	if e = store.Save(p); e != nil {
		t.Fatal(e)
	}
	profiles, e := store.SnapshotContext(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	password := []byte("test-only-resume-passphrase")
	pw := filepath.Join(root, "password")
	if e = os.WriteFile(pw, password, 0600); e != nil {
		t.Fatal(e)
	}
	defer clear(password)
	archive := filepath.Join(root, "archive")
	encrypted, e := backup.Encrypt(profiles, string(password), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(archive, encrypted, 0600); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(root, "recovered")
	marker := filepath.Join(destination, ".restore-incomplete")
	interrupted := errors.New("test-owned interruption after actual marker close")
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		if _, q := os.Lstat(marker); q == nil {
			return nil, interrupted
		}
		return nil, nil
	})
	if e = profile.RestoreSnapshot(context.Background(), destination, profiles, false, guard); !errors.Is(e, interrupted) {
		t.Fatal("real restore did not stop at marker", e)
	}
	original, e := os.ReadFile(marker)
	if e != nil {
		t.Fatal(e)
	}
	args := []string{"backup", "restore", "--archive", archive, "--passphrase-file", pw, "--into", destination, "--resume"}
	// A different authenticated snapshot must not consume the original marker.
	other := profile.New("other-profile", "OTHER_PRIVATE_PROFILE", "byedpi")
	wrong, e := backup.Encrypt([]profile.Profile{other}, string(password), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(archive, wrong, 0600); e != nil {
		t.Fatal(e)
	}
	if e = execute(args); e == nil {
		t.Fatal("wrong snapshot resumed")
	}
	current, e := os.ReadFile(marker)
	if e != nil || !bytes.Equal(current, original) {
		t.Fatal("wrong snapshot changed marker", e)
	}
	if e = os.WriteFile(archive, encrypted, 0600); e != nil {
		t.Fatal(e)
	}
	extra := filepath.Join(destination, "unexpected-owned-evidence")
	evidence := []byte("preserve this test-owned object")
	if e = os.WriteFile(extra, evidence, 0600); e != nil {
		t.Fatal(e)
	}
	if e = execute(args); e == nil {
		t.Fatal("unrelated destination object accepted")
	}
	got, e := os.ReadFile(extra)
	if e != nil || !bytes.Equal(got, evidence) {
		t.Fatal("unexpected evidence changed", e)
	}
	if e = os.Remove(extra); e != nil {
		t.Fatal(e)
	}
	if e = execute(args); e != nil {
		t.Fatal(e)
	}
	restored, e := profile.NewStore(destination)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := restored.SnapshotContext(context.Background())
	if e != nil || !reflect.DeepEqual(actual, profiles) {
		t.Fatal("resumed CLI changed saved values", e)
	}
	if _, e = os.Lstat(marker); !os.IsNotExist(e) {
		t.Fatal("completed marker retained", e)
	}
}
