//go:build !windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openPrivateAtTestDirectory(path string) (*os.File, error) { return os.Open(path) }
func checkPrivateAtTestFile(t *testing.T, file *os.File) {
	t.Helper()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 0 {
		t.Fatal("relative child was not private before payload write")
	}
}

func TestPrivateFileCreateAtVerificationFailureRetainsClosedEmptyArtifact(t *testing.T) {
	dir := t.TempDir()
	parent := createAtTestParent(t, dir)
	cause := errors.New("PRIVATE_SOURCE_VALIDATOR_REFUSAL")
	var observed *os.File
	file, err := createAtUnix(parent, "uncertain.awbackup", func(created *os.File) error { observed = created; return cause })
	if file != nil || !errors.Is(err, cause) || err.Error() != errPrivateCreateAt.Error() {
		t.Fatal("verification refusal lost its private cause")
	}
	if observed == nil {
		t.Fatal("actual source creation did not reach validation")
	}
	if _, err = observed.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("failed constructor abandoned its owned child")
	}
	info, err := os.Lstat(filepath.Join(dir, "uncertain.awbackup"))
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0600 {
		t.Fatal("uncertain empty artifact was deleted or repaired")
	}
	if _, err = parent.Stat(); err != nil {
		t.Fatal("verification refusal closed borrowed parent")
	}
	file, err = CreateAt(parent, "uncertain.awbackup")
	if file != nil || !errors.Is(err, os.ErrExist) {
		if file != nil {
			_ = file.Close()
		}
		t.Fatal("retry adopted uncertain output")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("verification refusal accumulated another object")
	}
}
