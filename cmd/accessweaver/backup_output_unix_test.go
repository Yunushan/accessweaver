//go:build linux || darwin || freebsd || openbsd

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
