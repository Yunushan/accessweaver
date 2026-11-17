//go:build windows

package fileidentity

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLocalPreviewRead(t *testing.T) {
	requireDisposableWindowsIdentityHost(t)
	directory := t.TempDir()
	source := filepath.Join(directory, "source.txt")
	original := []byte("owned original local bytes")
	if os.WriteFile(source, original, 0600) != nil {
		t.Fatal("local fixture creation failed")
	}
	assertBytes := func(t *testing.T, name string) {
		t.Helper()
		file, err := OpenLocal(name)
		if err != nil || file == nil {
			t.Fatal("local read acquisition failed")
		}
		data, readErr := io.ReadAll(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(data, original) {
			t.Fatal("held local bytes or close failed")
		}
	}
	t.Run("regular-and-local-links", func(t *testing.T) {
		assertBytes(t, source)
		for _, relative := range []bool{true, false} {
			target, name := source, "absolute-link"
			if relative {
				target, name = filepath.Base(source), "relative-link"
			}
			link := filepath.Join(directory, name)
			identityWindowsLink(t, target, link, false)
			assertBytes(t, link)
		}
		link := filepath.Join(directory, "directory-link")
		identityWindowsLink(t, directory, link, true)
		assertBytes(t, filepath.Join(link, filepath.Base(source)))
	})
	t.Run("remote-and-device-refusal", func(t *testing.T) {
		for _, name := range []string{`\\preview-fixture.invalid\no-share\input`, `\\?\C:\input`, `\??\C:\input`, `\Device\Mup\preview-fixture.invalid\input`, directory} {
			file, err := OpenLocal(name)
			if file != nil {
				_ = file.Close()
				t.Fatal("forbidden input returned a reader")
			}
			if err == nil {
				t.Fatal("forbidden input was admitted")
			}
		}
		link := filepath.Join(directory, "remote-link")
		// The existing direct symlink fixture never stats or contacts this target.
		identityWindowsLink(t, `\\preview-fixture.invalid\no-share\input`, link, false)
		if file, err := OpenLocal(link); err == nil || file != nil {
			if file != nil {
				_ = file.Close()
			}
			t.Fatal("remote reparse target returned a reader")
		}
	})
	t.Run("mapped-local-drive", func(t *testing.T) {
		drive := localPreviewOwnedDrive(t, `\??\`+directory)
		assertBytes(t, drive+`\`+filepath.Base(source))
	})
	t.Run("mapped-remote-drive", func(t *testing.T) {
		drive := localPreviewOwnedDrive(t, `\Device\Mup\preview-fixture.invalid\`+filepath.Base(directory))
		file, err := OpenLocal(drive + `\input.txt`)
		if file != nil {
			_ = file.Close()
			t.Fatal("remote drive mapping returned a reader")
		}
		if err != ErrUnavailable {
			t.Fatal("remote drive mapping did not refuse")
		}
	})
	t.Run("reparse-substitution", func(t *testing.T) {
		name := filepath.Join(directory, "reparse-race.txt")
		if os.WriteFile(name, original, 0600) != nil {
			t.Fatal("reparse race fixture creation failed")
		}
		called := false
		_, err := inspectWindowsPath(name, true, func(context windowsContext, parent windows.Handle, component string, observed State) error {
			called = true
			if os.Rename(name, name+".retained") != nil {
				t.Fatal("reparse race rename failed")
			}
			identityWindowsLink(t, `\\preview-fixture.invalid\no-share\input`, name, false)
			handle, openErr := context.openVerifiedRead(parent, component, observed)
			if handle != windows.InvalidHandle {
				_ = context.close(handle)
				t.Fatal("reparse substitution returned a data owner")
			}
			if openErr == nil {
				t.Fatal("reparse substitution was followed")
			}
			return openErr
		})
		if !called || err != ErrUnavailable {
			t.Fatal("reparse substitution did not refuse")
		}
	})
	t.Run("same-parent-name-substitution", func(t *testing.T) {
		name := filepath.Join(directory, "race.txt")
		if os.WriteFile(name, original, 0600) != nil {
			t.Fatal("race fixture creation failed")
		}
		called := false
		_, err := inspectWindowsPath(name, true, func(context windowsContext, parent windows.Handle, component string, observed State) error {
			called = true
			if os.Rename(name, name+".retained") != nil || os.WriteFile(name, []byte("substituted local bytes"), 0600) != nil {
				t.Fatal("race substitution failed")
			}
			file, openErr := context.openVerifiedRead(parent, component, observed)
			if file != windows.InvalidHandle {
				_ = context.close(file)
				t.Fatal("substituted identity returned a data owner")
			}
			if openErr == nil {
				t.Fatal("substituted identity was admitted")
			}
			return openErr
		})
		if !called || err != ErrUnavailable {
			t.Fatal("name substitution did not refuse")
		}
	})
	t.Run("held-reader-survives-name-replacement", func(t *testing.T) {
		name := filepath.Join(directory, "held.txt")
		if os.WriteFile(name, original, 0600) != nil {
			t.Fatal("held fixture creation failed")
		}
		file, err := OpenLocal(name)
		if err != nil {
			t.Fatal("held acquisition failed")
		}
		t.Cleanup(func() {
			if file != nil && file.Close() != nil {
				t.Error("held owner cleanup failed")
			}
		})
		if os.Rename(name, name+".retained") != nil || os.WriteFile(name, []byte("later name bytes"), 0600) != nil {
			t.Fatal("held name replacement failed")
		}
		data, err := io.ReadAll(file)
		if err != nil || !bytes.Equal(data, original) {
			t.Fatal("held reader followed a replaced pathname")
		}
		closeErr := file.Close()
		file = nil
		if closeErr != nil {
			t.Fatal("held reader close failed")
		}
	})
}

// Own one previously absent local-session DOS name. DefineDosDevice uses an
// exact removal target and suppresses broadcasts; no remote target is opened.
// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-definedosdevicew
func localPreviewOwnedDrive(t *testing.T, target string) string {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal, err := principalSnapshot()
	if err != nil || principal.sid == "S-1-5-18" {
		t.Fatal("fixture requires a non-System local device namespace")
	}
	context := windowsContext{principal}
	query := func(name *uint16) (string, bool, error) {
		var buffer [4096]uint16
		var n uint32
		err := context.call(func() (err error) { n, err = windows.QueryDosDevice(name, &buffer[0], uint32(len(buffer))); return err })
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return "", false, nil
		}
		if err != nil || n < 2 || n > uint32(len(buffer)) {
			return "", false, ErrUnavailable
		}
		first := 0
		for first < int(n) && buffer[first] != 0 {
			first++
		}
		if first == int(n) {
			return "", false, ErrUnavailable
		}
		for _, ch := range buffer[first:n] {
			if ch != 0 {
				return "", false, ErrUnavailable
			}
		}
		return windows.UTF16ToString(buffer[:first]), true, nil
	}
	if !strings.HasPrefix(target, `\??\`) && !strings.HasPrefix(target, `\Device\Mup\preview-fixture.invalid\`) {
		t.Fatal("fixture mapping target refused")
	}
	for letter := 'Z'; letter >= 'P'; letter-- {
		drive := string(letter) + ":"
		name, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			t.Fatal("fixture device name conversion failed")
		}
		_, present, err := query(name)
		if err != nil || present {
			continue
		}
		encoded, err := windows.UTF16PtrFromString(target)
		if err != nil {
			t.Fatal("fixture mapping conversion failed")
		}
		flags := uint32(windows.DDD_RAW_TARGET_PATH | windows.DDD_NO_BROADCAST_SYSTEM)
		if context.call(func() error { return windows.DefineDosDevice(flags, name, encoded) }) != nil {
			t.Fatal("fixture device reservation failed")
		}
		t.Cleanup(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			current, present, err := query(name)
			if err != nil || !present || current != target {
				t.Error("owned device binding changed; preserving mapping")
				return
			}
			if context.call(func() error {
				return windows.DefineDosDevice(flags|windows.DDD_REMOVE_DEFINITION|windows.DDD_EXACT_MATCH_ON_REMOVE, name, encoded)
			}) != nil {
				t.Error("owned device removal failed")
				return
			}
			if _, present, err := query(name); err != nil || present {
				t.Error("owned device removal not confirmed")
			}
		})
		current, present, err := query(name)
		if err != nil || !present || current != target {
			t.Fatal("fixture device binding not confirmed")
		}
		return drive
	}
	t.Fatal("no unused fixture device name")
	return ""
}
