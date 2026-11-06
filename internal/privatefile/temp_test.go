package privatefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateFileTempAndExistingDestination(t *testing.T) {
	parent := t.TempDir()
	file, err := CreateTemp(parent, ".source-fixture-*.tmp")
	if err != nil {
		t.Fatal("private temporary file unavailable")
	}
	path := file.Name()
	if filepath.Dir(path) != parent {
		_ = file.Close()
		t.Fatal("temporary file escaped its explicit parent")
	}
	created, err := file.Stat()
	if err != nil || !created.Mode().IsRegular() || created.Size() != 0 {
		_ = file.Close()
		t.Fatal("new private file metadata unavailable")
	}
	if runtime.GOOS != "windows" && created.Mode() != 0600 {
		_ = file.Close()
		t.Fatal("new private file permissions were not private")
	}
	data := []byte("owned private fixture")
	if n, err := file.Write(data); err != nil || n != len(data) {
		_ = file.Close()
		t.Fatal("owned private write failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal("owned private sync failed")
	}
	if err := file.Close(); err != nil {
		t.Fatal("owned private close failed")
	}
	existing, err := Create(path)
	if existing != nil {
		_ = existing.Close()
		t.Fatal("existing destination opened")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatal("existing destination was not exclusively refused")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("exclusive refusal changed existing bytes")
	}
	for _, pattern := range []string{"", ".", "..", "../outside", "two**stars"} {
		if file, err := CreateTemp(parent, pattern); err == nil || file != nil {
			if file != nil {
				_ = file.Close()
			}
			t.Fatal("invalid temporary pattern admitted")
		}
	}
}
