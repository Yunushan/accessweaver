package logfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
