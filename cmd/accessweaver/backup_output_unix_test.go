//go:build linux || darwin || freebsd || openbsd

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/fileinput"
)

func TestBackupOutputRetainedParentCannotRetargetSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	outside := filepath.Join(root, "outside")
	alias := filepath.Join(root, "alias")
	for _, p := range []string{source, outside} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink(outside, alias); e != nil {
		t.Fatal(e)
	}
	destination, e := prepareBackupOutput(context.Background(), filepath.Join(alias, "archive"), source)
	if e != nil {
		t.Fatal(e)
	}
	defer destination.Close()
	if e = os.Remove(alias); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(source, alias); e != nil {
		t.Fatal(e)
	}
	if e = destination.Write(context.Background(), []byte("ciphertext")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(filepath.Join(source, "archive")); !os.IsNotExist(e) {
		t.Fatal("source was changed by alias retarget", e)
	}
	if data, e := os.ReadFile(filepath.Join(outside, "archive")); e != nil || string(data) != "ciphertext" {
		t.Fatal("held parent not used", e)
	}
}

// A raw alias in the ancestor chain is deliberately outside the helper's
// canonical-parent contract. Production resolves it before calling the helper.
func TestBackupOutputAncestryRejectsUnresolvedAliasAndAcceptsCanonicalParent(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(root, "source")
	outside := filepath.Join(root, "outside")
	child := filepath.Join(outside, "child")
	for _, directory := range []string{source, child} {
		if e = os.MkdirAll(directory, 0700); e != nil {
			t.Fatal(e)
		}
	}
	alias := filepath.Join(root, "alias")
	if e = os.Symlink(outside, alias); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(alias)
	if e != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("owned alias fixture is not a symlink", e)
	}
	sourceState, e := fileinput.StateFromPath(source, false)
	if e != nil {
		t.Fatal(e)
	}
	rawParent := filepath.Join(alias, "child")
	if e = backupOutputAncestry(context.Background(), rawParent, sourceState.ID); !errors.Is(e, os.ErrInvalid) {
		t.Fatal("unresolved symlink ancestor was not refused", e)
	}
	canonical, e := filepath.EvalSymlinks(rawParent)
	if e != nil {
		t.Fatal(e)
	}
	if e = backupOutputAncestry(context.Background(), canonical, sourceState.ID); e != nil {
		t.Fatal("canonical outside parent was refused", e)
	}
}
