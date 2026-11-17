//go:build darwin && (amd64 || arm64)

package privatefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

// Only fresh owned files are created; existing ACLs or host settings are never
// reset. Actual Darwin execution is restricted to its native source CI job.
func TestPrivateFileDarwinCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-record.bin")
	file, err := Create(path)
	if err != nil {
		t.Fatal("private native export creation failed")
	}
	closed := false
	defer func() {
		if !closed {
			if file.Close() != nil {
				t.Error("owned export close failed")
			}
		}
	}()
	if _, err := darwintrust.Check(file, false, uint32(os.Geteuid())); err != nil {
		t.Fatal("new export ownership or filesystem unavailable")
	}
	if err := darwintrust.CheckEmptyACL(file); err != nil {
		t.Fatal("new export retained an extended ACL grant")
	}
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0600 || info.Size() != 0 {
		t.Fatal("new export was not empty and private")
	}
	payload := []byte("private native source fixture")
	if n, err := file.Write(payload); err != nil || n != len(payload) {
		t.Fatal("owned export write failed")
	}
	if file.Sync() != nil {
		t.Fatal("owned export sync failed")
	}
	closed = true
	if file.Close() != nil {
		t.Fatal("owned export close failed")
	}
	before, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, payload) {
		t.Fatal("owned export content unavailable")
	}
	existing, err := Create(path)
	if existing != nil {
		_ = existing.Close()
		t.Fatal("existing native export was opened")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatal("existing native export was not refused")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing native export changed")
	}
}
