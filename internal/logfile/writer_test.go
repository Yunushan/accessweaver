package logfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestRotationRetainsNewestBytesAndBoundsDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	w, err := Open(path, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("000000001111111122222222333333334444")
	if n, err := w.Write(input); err != nil || n != len(input) {
		t.Fatal(n, err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var retained []byte
	for _, suffix := range []string{".2", ".1", ""} {
		data, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 8 {
			t.Fatalf("unbounded file: %d", len(data))
		}
		retained = append(retained, data...)
	}
	if !bytes.Equal(retained, input[16:]) {
		t.Fatalf("retained %q", retained)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatal("extra backup", err)
	}
	if _, err := w.Write([]byte("after close")); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestExistingOversizedLogPreservesTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	if err := os.WriteFile(path, []byte("old-content-new-tail"), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(path, 8, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new-tail" {
		t.Fatalf("%q %v", data, err)
	}
	if _, err := w.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path + ".1")
	if err != nil || string(data) != "new-tail" {
		t.Fatalf("%q %v", data, err)
	}
}

func TestOversizedLogRefusesChangedOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	if err := os.WriteFile(path, []byte("original oversized log"), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	const changed = "independently changed oversized process log"
	if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	w := &Writer{path: path, limit: 8}
	if err := w.retainTail(original); err == nil {
		t.Fatal("accepted a changed source")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != changed {
		t.Fatalf("changed log lost: %q %v", data, err)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("unexpected files after refusal: %v %v", entries, err)
	}
}

func TestOversizedLogRetainsOriginalWhenReplacementIsBlocked(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows open handles can deny replacement")
	}
	path := filepath.Join(t.TempDir(), "engine.log")
	const original = "original oversized log"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	blocker, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Close() })
	if w, err := Open(path, 8, 1); err == nil {
		_ = w.Close()
		t.Fatal("replacement succeeded while an independent handle blocked it")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != original {
		t.Fatalf("original log lost: %q %v", data, err)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("unexpected files after failed replacement: %v %v", entries, err)
	}
	if err := blocker.Close(); err != nil {
		t.Fatal(err)
	}
	w, err := Open(path, 8, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != original[len(original)-8:] {
		t.Fatalf("retry did not retain the newest bytes: %q %v", data, err)
	}
}

func TestRotationPreservesEmptyBackupDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	backup := path + ".2"
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	w, err := Open(path, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if n, err := w.Write([]byte("12345")); err == nil || n != 4 {
		t.Fatalf("expected rotation refusal after four bytes, got %d %v", n, err)
	}
	if info, err := os.Stat(backup); err != nil || !info.IsDir() {
		t.Fatalf("backup directory lost: %v %v", info, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "1234" {
		t.Fatalf("current log changed: %q %v", data, err)
	}
}

func TestConcurrentOutputAndRotationFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	w, err := Open(path, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 50 {
				if _, err := w.Write(bytes.Repeat([]byte("x"), 16)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	group.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".1", ".2"} {
		info, err := os.Stat(path + suffix)
		if err != nil || info.Size() > 64 {
			t.Fatalf("%s: %v %v", suffix, info, err)
		}
	}
	broken := filepath.Join(t.TempDir(), "blocked.log")
	w, err = Open(broken, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := os.Mkdir(broken+".1", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken+".1", "keep"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write([]byte("123456")); err == nil || n != 4 {
		t.Fatalf("rotation failure lost: %d %v", n, err)
	}
	if _, err := w.Write([]byte("again")); err == nil {
		t.Fatal("failed logger silently resumed")
	}
}

func TestCloseRetainsRotationFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	w, err := Open(path, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if err := os.Mkdir(path+".1", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".1", "unrelated"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	n, writeErr := w.Write([]byte("123456"))
	if n != 4 || writeErr == nil {
		t.Fatalf("expected partial output and failed rotation, got %d %v", n, writeErr)
	}
	for range 2 {
		if err := w.Close(); !errors.Is(err, writeErr) {
			t.Fatalf("close lost the output failure: %v", err)
		}
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "1234" {
		t.Fatalf("previous log changed: %q %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(path+".1", "unrelated")); err != nil || string(data) != "keep" {
		t.Fatalf("unrelated data changed: %q %v", data, err)
	}
}

func TestCloseRetainsWriteAndHandleFailures(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "write-and-close"}[write], func(t *testing.T) {
			w, err := Open(filepath.Join(t.TempDir(), "engine.log"), 64, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.file.Close(); err != nil {
				t.Fatal(err)
			}
			var writeErr error
			if write {
				n, err := w.Write([]byte("lost"))
				if n != 0 || !errors.Is(err, os.ErrClosed) {
					t.Fatalf("expected native closed-handle write failure: %d %v", n, err)
				}
				writeErr = err
			}
			for range 2 {
				err := w.Close()
				if !errors.Is(err, os.ErrClosed) || (writeErr != nil && !errors.Is(err, writeErr)) {
					t.Fatalf("close lost write/handle failure: %v", err)
				}
			}
		})
	}
}

func TestSuccessfulCloseRemainsIdempotent(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "engine.log"), 64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write([]byte("retained")); n != 8 || err != nil {
		t.Fatal(n, err)
	}
	for range 2 {
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Write([]byte("late")); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
