package privatefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func createAtTestParent(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := openPrivateAtTestDirectory(path)
	if err != nil {
		t.Fatal("owned parent fixture unavailable")
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error("borrowed parent close failed")
		}
	})
	return file
}
func finishPrivateAtTestFile(t *testing.T, file *os.File, data []byte) {
	t.Helper()
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); err != nil {
				t.Error("owned child close failed")
			}
		}
	}()
	checkPrivateAtTestFile(t, file)
	n, writeErr := file.Write(data)
	if writeErr == nil && n == len(data) {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	closed = true
	if n != len(data) || writeErr != nil || closeErr != nil {
		t.Fatal("owned child output did not finish")
	}
}

func TestPrivateFileCreateAtUsesRetainedParentAfterAliasRetarget(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	source := filepath.Join(root, "source")
	alias := filepath.Join(root, "selected-parent")
	if os.Mkdir(outside, 0700) != nil || os.Mkdir(source, 0700) != nil {
		t.Fatal("owned directories unavailable")
	}
	if err := os.Symlink(outside, alias); err != nil {
		t.Skip("owned directory symlink fixture unavailable")
	}
	parent := createAtTestParent(t, alias)
	// This is the real path retarget after a caller's outside-source check. The
	// constructor receives only the actual retained directory, not this alias.
	if err := os.Remove(alias); err != nil {
		t.Fatal("owned alias removal failed")
	}
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal("owned alias retarget failed")
	}
	name := "retained-parent.awbackup"
	file, err := CreateAt(parent, name)
	if err != nil {
		t.Fatal("relative private creation failed")
	}
	data := []byte("source-owned retained-parent fixture")
	finishPrivateAtTestFile(t, file, data)
	actual, err := os.ReadFile(filepath.Join(outside, name))
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("entry was not created in the retained outside parent")
	}
	entries, err := os.ReadDir(source)
	if err != nil || len(entries) != 0 {
		t.Fatal("retargeted source directory was mutated")
	}
	if info, err := parent.Stat(); err != nil || !info.IsDir() {
		t.Fatal("constructor closed its borrowed parent")
	}
}

func TestPrivateFileCreateAtBadLeavesHaveNoEffects(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "parent")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("owned parent unavailable")
	}
	parent := createAtTestParent(t, dir)
	for _, name := range []string{"", ".", "..", "../outside", "a/b", "a\\b", filepath.Join(root, "absolute-target"), "a:b", "NUL", "con.txt", "COM1.backup", "lpt³.txt", "trailing.", "trailing ", "wild*card", "zero\x00name", "\xff"} {
		file, err := CreateAt(parent, name)
		if err == nil || file != nil {
			if file != nil {
				_ = file.Close()
			}
			t.Fatal("unsafe leaf reached creation")
		}
		if err.Error() != errPrivateCreateAt.Error() {
			t.Fatal("unsafe leaf failure exposed private input")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("unsafe leaf created an entry")
	}
	if _, err := parent.Stat(); err != nil {
		t.Fatal("unsafe leaf closed borrowed parent")
	}
	rootEntries, err := os.ReadDir(root)
	if err != nil || len(rootEntries) != 1 || rootEntries[0].Name() != "parent" {
		t.Fatal("unsafe leaf escaped the owned parent fixture")
	}
}

func TestPrivateFileCreateAtExistingEntryAndParentRemainUnchanged(t *testing.T) {
	dir := t.TempDir()
	parent := createAtTestParent(t, dir)
	name := "existing.awbackup"
	original := []byte("retained existing output fixture")
	if err := os.WriteFile(filepath.Join(dir, name), original, 0600); err != nil {
		t.Fatal("existing fixture unavailable")
	}
	file, err := CreateAt(parent, name)
	if file != nil || !errors.Is(err, os.ErrExist) || err.Error() != errPrivateCreateAt.Error() {
		if file != nil {
			_ = file.Close()
		}
		t.Fatal("existing output was not refused privately")
	}
	actual, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatal("existing output was changed")
	}
	file, err = CreateAt(parent, "fresh.awbackup")
	if err != nil {
		t.Fatal("borrowed parent was unusable after refusal")
	}
	finishPrivateAtTestFile(t, file, []byte("fresh fixture"))
}

func TestPrivateFileCreateAtRejectsNonDirectoryAndClosedParents(t *testing.T) {
	dir := t.TempDir()
	original := []byte("ordinary file fixture")
	path := filepath.Join(dir, "ordinary")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal("file parent fixture unavailable")
	}
	parent, err := os.Open(path)
	if err != nil {
		t.Fatal("file parent fixture unavailable")
	}
	child, createErr := CreateAt(parent, "child")
	closeErr := parent.Close()
	if child != nil || createErr == nil || closeErr != nil {
		if child != nil {
			_ = child.Close()
		}
		t.Fatal("ordinary file was accepted as parent")
	}
	parent, err = openPrivateAtTestDirectory(dir)
	if err != nil {
		t.Fatal("closed parent fixture unavailable")
	}
	if err = parent.Close(); err != nil {
		t.Fatal("closed parent fixture failed")
	}
	child, err = CreateAt(parent, "closed-parent-child")
	if child != nil || err == nil || err.Error() != errPrivateCreateAt.Error() {
		if child != nil {
			_ = child.Close()
		}
		t.Fatal("closed borrowed parent was accepted")
	}
	if child, err = CreateAt(nil, "nil-parent-child"); child != nil || err == nil {
		if child != nil {
			_ = child.Close()
		}
		t.Fatal("nil parent was accepted")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatal("invalid parent refusal changed original data")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("invalid parent refusal created an entry")
	}
}
