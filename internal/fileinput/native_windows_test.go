//go:build windows

package fileinput

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"golang.org/x/sys/windows"
)

func TestBackupInputWindowsHeldFullIDSharingAndRelativeMetadata(t *testing.T) {
	path := inputFile(t, []byte("owned source bytes"))
	f, e := openInput(path)
	if e != nil {
		t.Fatal(e)
	}
	closed := false
	defer func() {
		if !closed {
			if e := f.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	owner, ok := f.(*fileOwner)
	if !ok || owner.metadata == nil {
		t.Fatal("metadata owner absent")
	}
	a, e := StateFromFile(owner.metadata)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.State()
	if e != nil || a.ID != b.ID || a.ID.FileID == ([16]byte{}) || !same(a, b) {
		t.Fatal("same-object full ID binding", e)
	}
	writer, e := os.OpenFile(path, os.O_WRONLY, 0)
	if writer != nil {
		q := writer.Close()
		t.Fatal("held source allowed a data writer", q)
	}
	if !errors.Is(e, windows.ERROR_SHARING_VIOLATION) {
		t.Fatal("unexpected write-sharing refusal", e)
	}
	named, e := StateFromPath(path, false)
	if e != nil || !same(named, b) {
		t.Fatal("named observation", e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	closed = true
	got, e := Read(context.Background(), path, 100)
	if e != nil || string(got) != "owned source bytes" {
		t.Fatal("closed snapshot", e)
	}
	clear(got)
	parent, e := OpenDirectory(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := parent.Close(); e != nil {
			t.Error(e)
		}
	}()
	relative, e := StateAt(parent, filepath.Base(path), false)
	if e != nil || relative.ID != named.ID || relative.Kind != fileidentity.Regular {
		t.Fatal("relative native state", e)
	}
}
func TestBackupInputWindowsRejectsDirectoryAndDeviceBeforeData(t *testing.T) {
	if f, e := openInput(t.TempDir()); e == nil || f != nil {
		if f != nil {
			_ = f.Close()
		}
		t.Fatal("directory data reader accepted")
	}
	for _, name := range []string{"NUL", `\\.\NUL`, `\\?\C:\fixture`, `C:\fixture:stream`} {
		if _, e := AbsoluteName(name); e == nil {
			t.Fatal("nonordinary namespace accepted")
		}
	}
}
func TestBackupInputWindowsOrdinaryUNCSpellingIsNotAuditLocalPolicy(t *testing.T) {
	// Syntax only: no network resource is opened or queried by this test.
	got, e := AbsoluteName(`\\example.invalid\owned-fixture\archive`)
	if e != nil || got != `\\example.invalid\owned-fixture\archive` {
		t.Fatal("ordinary UNC syntax refused", e)
	}
}
