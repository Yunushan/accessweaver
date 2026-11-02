//go:build darwin

package uiaccess

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDarwinLauncherExclusiveObjectsAndNoFollow(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "session")
	if err := createPrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "start.html")
	file, err := createPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("retained fixture"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if f, err := createPrivateFile(path); err == nil {
		f.Close()
		t.Fatal("existing file was reopened")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "retained fixture" {
		t.Fatal("exclusive refusal changed the existing file", err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if f, err := createPrivateFile(link); err == nil {
		f.Close()
		t.Fatal("symlink file was accepted")
	}
	parentLink := filepath.Join(parent, "alias")
	if err := os.Symlink(directory, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := checkParents(parentLink); err == nil {
		t.Fatal("symlink parent was accepted")
	}
	if err := createPrivateDirectory(directory); !os.IsExist(err) {
		t.Fatal("existing directory was reused", err)
	}
}

func TestDarwinLauncherRefusesMutableParentWithoutChangingACL(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write", parent).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	before, err := exec.Command("/bin/ls", "-lde", parent).Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := createPrivateDirectory(filepath.Join(parent, "session")); err == nil {
		t.Fatal("mutable ACL parent accepted")
	}
	after, err := exec.Command("/bin/ls", "-lde", parent).Output()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal changed an existing ACL", err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "session")); !os.IsNotExist(err) {
		t.Fatal("unsafe parent received a session object", err)
	}
}
