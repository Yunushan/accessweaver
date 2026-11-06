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

// These are lexical path checks only. They never open a device, local source,
// UNC share, socket or network resource.
func TestBackupInputWindowsNamespaceValidationBeforeAndAfterNormalization(t *testing.T) {
	for _, name := range []string{
		"NUL", "nul.txt", "COM1", "a/NUL", `nested\cOm1.TxT`,
		"COM\u00b9", "lpt\u00b2", "COM\u00b3.txt", "child/LPT\u00b9.TxT", "child/CoM\u00b2.log", "LPT\u00b3",
		`\\.\NUL`, `\\?\C:\owned-fixture`, `\??\C:\owned-fixture`,
		`\Device\owned-fixture`, `\GLOBAL??\owned-fixture`, `\DosDevices\owned-fixture`,
		"//./NUL", "/??/C:/owned-fixture", `C:\owned-fixture:stream`,
		"", "owned\x00fixture", string([]byte{0xff}),
	} {
		got, err := AbsoluteName(name)
		if got != "" || !errors.Is(err, ErrUnavailable) {
			t.Fatal("nonordinary Windows namespace accepted")
		}
	}
	for _, name := range []string{
		`owned-fixture\..\archive.awbackup`, "./owned-fixture/passphrase",
		"COM10.txt", "LPT10", "ordinary.nul", "fixture-\u00e9/CONTAINER.txt",
		`C:\owned-fixture\archive.awbackup`, `\\example.invalid\owned-fixture\archive`,
	} {
		want, err := filepath.Abs(name)
		if err != nil {
			t.Fatal("ordinary Windows path normalization unavailable")
		}
		got, err := AbsoluteName(name)
		if err != nil || got != want {
			t.Fatal("ordinary Windows path semantics changed")
		}
	}
}
