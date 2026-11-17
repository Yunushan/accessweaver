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

// This formatter accepts only source-known phases from the private wrapper.
// Unknown errors remain unavailable; their native causes are never printed.
func nativeInputPhaseForTest(err error) string {
	var failure *nativeInputFailure
	if errors.As(err, &failure) && failure != nil {
		switch failure.phase {
		case nativeInputMetadataOpen:
			return "metadata-open"
		case nativeInputMetadataState:
			return "metadata-state"
		case nativeInputSameObjectReopen:
			return "sameobject-reopen"
		case nativeInputReaderState:
			return "reader-state"
		case nativeInputDirectoryName:
			return "directory-name"
		case nativeInputDirectoryMetadataClose:
			return "directory-metadata-close"
		}
	}
	return "unavailable"
}

// Inspect only the already-returned cause against this finite SDK allowlist.
func nativeInputCategoryForTest(err error) string {
	switch {
	case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
		return "ERROR_INVALID_PARAMETER"
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "ERROR_ACCESS_DENIED"
	case errors.Is(err, windows.ERROR_SHARING_VIOLATION):
		return "ERROR_SHARING_VIOLATION"
	case errors.Is(err, windows.ERROR_NOT_SUPPORTED):
		return "ERROR_NOT_SUPPORTED"
	case errors.Is(err, windows.ERROR_INVALID_HANDLE):
		return "ERROR_INVALID_HANDLE"
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return "ERROR_FILE_NOT_FOUND"
	case errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return "ERROR_PATH_NOT_FOUND"
	default:
		return "native-category-unclassified"
	}
}

func nativeInputFailureForTest(err error) string {
	return nativeInputPhaseForTest(err) + " " + nativeInputCategoryForTest(err)
}

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
		t.Fatal(nativeInputFailureForTest(e))
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
	f, e := openInput(t.TempDir())
	if e == nil || f != nil {
		if f != nil {
			_ = f.Close()
		}
		t.Fatal("directory data reader accepted")
	}
	if nativeInputPhaseForTest(e) != "metadata-state" {
		t.Fatal("directory refusal did not retain its failed kind gate")
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

func TestBackupInputWindowsNativePhasesKeepPrivateCausesAndPublicFailure(t *testing.T) {
	for _, test := range []struct {
		phase nativeInputPhase
		code  string
	}{
		{nativeInputMetadataOpen, "metadata-open"},
		{nativeInputMetadataState, "metadata-state"},
		{nativeInputSameObjectReopen, "sameobject-reopen"},
		{nativeInputReaderState, "reader-state"},
		{nativeInputDirectoryName, "directory-name"},
		{nativeInputDirectoryMetadataClose, "directory-metadata-close"},
	} {
		t.Run(test.code, func(t *testing.T) {
			native := &os.PathError{Op: "private-native-operation", Path: "private-selected-path", Err: windows.ERROR_INVALID_PARAMETER}
			closeCause := errors.New("private-owned-close-cause")
			// Models the production wrapper's final composition, after cleanup.
			joined := errors.Join(native, closeCause, context.Canceled, os.ErrNotExist)
			failure := &nativeInputFailure{phase: test.phase, cause: joined}
			if failure.Error() != "selected file input native failure: "+test.code || nativeInputPhaseForTest(failure) != test.code {
				t.Fatal("private failure did not expose only its fixed phase")
			}
			if nativeInputFailureForTest(failure) != test.code+" ERROR_INVALID_PARAMETER" {
				t.Fatal("native failure formatter exposed more than its closed codes")
			}
			if !errors.Is(failure, windows.ERROR_INVALID_PARAMETER) || !errors.Is(failure, closeCause) || !errors.Is(failure, context.Canceled) || !errors.Is(failure, os.ErrNotExist) {
				t.Fatal("fixed phase lost native or cleanup co-causes")
			}
			var original *os.PathError
			if !errors.As(failure, &original) || original != native {
				t.Fatal("fixed phase replaced its original private cause")
			}
			public := fail(failure)
			if public.Error() != ErrUnavailable.Error() || nativeInputPhaseForTest(public) != test.code {
				t.Fatal("public failure changed its privacy contract or lost the phase")
			}
			if !errors.Is(public, ErrUnavailable) || !errors.Is(public, windows.ERROR_INVALID_PARAMETER) || !errors.Is(public, closeCause) || !errors.Is(public, context.Canceled) || !errors.Is(public, os.ErrNotExist) {
				t.Fatal("public wrapper lost original co-causes")
			}
			var retained *nativeInputFailure
			if !errors.As(public, &retained) || retained != failure {
				t.Fatal("public wrapper replaced the original failed phase")
			}
		})
	}
}

func TestBackupInputWindowsNativePhaseFormatterRejectsUnknownErrors(t *testing.T) {
	privateCause := errors.New("private-unclassified-cause")
	unknown := &nativeInputFailure{phase: nativeInputPhase(255), cause: privateCause}
	if unknown.Error() != ErrUnavailable.Error() || nativeInputPhaseForTest(unknown) != "unavailable" || !errors.Is(unknown, privateCause) {
		t.Fatal("unknown phase printed a cause or lost error identity")
	}
	if nativeInputPhaseForTest(privateCause) != "unavailable" || nativeInputPhaseForTest(nil) != "unavailable" {
		t.Fatal("unclassified errors bypassed the fixed phase allowlist")
	}
	var absent *nativeInputFailure
	if absent.Error() != ErrUnavailable.Error() || absent.Unwrap() != nil || nativeInputPhaseForTest(absent) != "unavailable" {
		t.Fatal("absent private failure bypassed the fixed phase allowlist")
	}
}

func TestBackupInputWindowsNativeCategoriesAreClosedAndDoNotFormatCauses(t *testing.T) {
	for _, test := range []struct {
		cause    error
		category string
	}{
		{windows.ERROR_INVALID_PARAMETER, "ERROR_INVALID_PARAMETER"},
		{windows.ERROR_ACCESS_DENIED, "ERROR_ACCESS_DENIED"},
		{windows.ERROR_SHARING_VIOLATION, "ERROR_SHARING_VIOLATION"},
		{windows.ERROR_NOT_SUPPORTED, "ERROR_NOT_SUPPORTED"},
		{windows.ERROR_INVALID_HANDLE, "ERROR_INVALID_HANDLE"},
		{windows.ERROR_FILE_NOT_FOUND, "ERROR_FILE_NOT_FOUND"},
		{windows.ERROR_PATH_NOT_FOUND, "ERROR_PATH_NOT_FOUND"},
	} {
		t.Run(test.category, func(t *testing.T) {
			private := &os.PathError{Op: "private-operation", Path: "private-path", Err: test.cause}
			failure := &nativeInputFailure{phase: nativeInputDirectoryMetadataClose, cause: errors.Join(private, errors.New("private-close-cause"))}
			if nativeInputCategoryForTest(failure) != test.category || nativeInputFailureForTest(failure) != "directory-metadata-close "+test.category {
				t.Fatal("SDK category was lost or private error details were printed")
			}
			if !errors.Is(failure, test.cause) {
				t.Fatal("SDK category inspection changed original cause identity")
			}
		})
	}
	for _, cause := range []error{nil, ErrUnavailable, errors.New("private ERROR_INVALID_PARAMETER text")} {
		if nativeInputCategoryForTest(cause) != "native-category-unclassified" {
			t.Fatal("unclassified error bypassed the SDK allowlist")
		}
	}
}

// These fixtures own only fresh local objects. Failed/uncertain cleanup keeps
// the root; no original input or unrelated directory is removed.
type ntDirectoryFixture struct {
	root     string
	state    fileidentity.State
	preserve bool
}

func newNTDirectoryFixture(t *testing.T) *ntDirectoryFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-nt-directory-")
	if err != nil {
		t.Fatal("owned directory fixture unavailable")
	}
	state, err := StateFromPath(root, false)
	if err != nil {
		t.Fatal("owned directory fixture identity unavailable")
	}
	f := &ntDirectoryFixture{root: root, state: state}
	t.Cleanup(func() {
		if f.preserve {
			t.Error("unconfirmed directory fixture retained")
			return
		}
		state, err := StateFromPath(root, false)
		if err != nil || state.Kind != fileidentity.Directory || state.ID != f.state.ID {
			t.Error("changed directory fixture retained")
			return
		}
		if err = os.RemoveAll(root); err != nil {
			t.Error("owned directory fixture cleanup failed")
		}
	})
	return f
}
func (f *ntDirectoryFixture) close(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); err != nil {
		f.preserve = true
		t.Error("owned directory handle close failed")
	}
}

func TestBackupInputWindowsNTDirectorySelfOpenRetainsRenamedObject(t *testing.T) {
	f := newNTDirectoryFixture(t)
	name := filepath.Join(f.root, "selected")
	moved := filepath.Join(f.root, "retained")
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal("owned source directory unavailable")
	}
	if err := os.WriteFile(filepath.Join(name, "original.txt"), []byte("original owned evidence"), 0600); err != nil {
		t.Fatal("owned source entry unavailable")
	}
	meta, err := metadata(name, false)
	if err != nil {
		t.Fatal("owned metadata handle unavailable")
	}
	defer f.close(t, meta)
	before, err := StateFromFile(meta)
	if err != nil || before.Kind != fileidentity.Directory {
		t.Fatal("owned source directory identity unavailable")
	}
	if err = os.Rename(name, moved); err != nil {
		t.Fatal("owned source directory rename failed")
	}
	if err = os.Mkdir(name, 0700); err != nil {
		t.Fatal("owned replacement directory unavailable")
	}
	if err = os.WriteFile(filepath.Join(name, "replacement.txt"), []byte("replacement owned evidence"), 0600); err != nil {
		t.Fatal("owned replacement entry unavailable")
	}
	replacement, err := StateFromPath(name, false)
	if err != nil || replacement.ID == before.ID {
		t.Fatal("owned replacement identity not distinct")
	}
	reader, err := reopenDirectory(meta, name, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		f.preserve = true
		t.Fatal("held directory self-open failed")
	}
	defer f.close(t, reader)
	after, err := StateFromFile(reader)
	if err != nil || after.Kind != fileidentity.Directory || after.ID != before.ID || after.Size != before.Size || !after.Modified.Equal(before.Modified) {
		t.Fatal("directory self-open lost original native binding")
	}
	entries, err := reader.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "original.txt" {
		t.Fatal("directory enumeration followed replacement pathname")
	}
	stillBorrowed, err := StateFromFile(meta)
	if err != nil || stillBorrowed.ID != before.ID {
		t.Fatal("directory self-open consumed borrowed metadata handle")
	}
}

func TestBackupInputWindowsNTDirectorySelfOpenRefusesOtherKindsAndClosedRoot(t *testing.T) {
	f := newNTDirectoryFixture(t)
	name := filepath.Join(f.root, "ordinary-file")
	const body = "unchanged owned regular file"
	if err := os.WriteFile(name, []byte(body), 0600); err != nil {
		t.Fatal("owned regular fixture unavailable")
	}
	meta, err := metadata(name, false)
	if err != nil {
		t.Fatal("owned regular metadata unavailable")
	}
	defer f.close(t, meta)
	before, err := StateFromFile(meta)
	if err != nil {
		t.Fatal("owned regular identity unavailable")
	}
	unexpected, err := reopenDirectory(meta, name, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if unexpected != nil {
		f.close(t, unexpected)
		t.Fatal("directory-only open accepted regular file")
	}
	if status, ok := err.(windows.NTStatus); !ok || status == 0 || status == windows.STATUS_PENDING {
		f.preserve = true
		t.Fatal("directory-only refusal included unexpected completion or cleanup uncertainty")
	}
	after, err := StateFromFile(meta)
	if err != nil || after.ID != before.ID || after.Kind != before.Kind || after.Size != before.Size || !after.Modified.Equal(before.Modified) {
		t.Fatal("failed directory open changed borrowed source")
	}
	data, err := Read(context.Background(), name, 100)
	if err != nil || string(data) != body {
		t.Fatal("failed directory open changed source bytes")
	}
	clear(data)
	directory, err := metadata(f.root, false)
	if err != nil {
		t.Fatal("owned closed-root fixture unavailable")
	}
	if err = directory.Close(); err != nil {
		f.preserve = true
		t.Fatal("owned closed-root cleanup was not confirmed")
	}
	var probe [1]byte
	n, readErr := directory.Read(probe[:])
	if n != 0 || !errors.Is(readErr, os.ErrClosed) {
		f.preserve = true
		t.Fatal("owned directory was not observably closed")
	}
	result, err := reopenDirectory(directory, f.root, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if result != nil {
		f.close(t, result)
		t.Fatal("closed directory root accepted")
	}
	if err == nil {
		f.preserve = true
		t.Fatal("closed directory root failed without error")
	}
	held, err := OpenDirectory(f.root)
	if err != nil {
		f.preserve = true
		t.Fatal("owned directory observation failed")
	}
	defer f.close(t, held)
	entries, err := held.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "ordinary-file" {
		t.Fatal("failed self-open created or removed fixture entries")
	}
}
