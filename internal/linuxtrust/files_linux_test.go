//go:build linux

package linuxtrust

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLinuxObjectProtectionRejectsMutationAndAliases(t *testing.T) {
	root := t.TempDir()
	owner := uint32(os.Geteuid())
	path := filepath.Join(root, "payload")
	if err := os.WriteFile(path, []byte("protected fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	file, err := OpenRegularAt(parent, "payload", owner)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegularAt(parent, "payload", owner); err == nil {
		file.Close()
		t.Fatal("group-write fixture accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegularAt(parent, "payload", owner+1); err == nil {
		file.Close()
		t.Fatal("unexpected owner accepted")
	}
	if err := os.Link(path, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegularAt(parent, "payload", owner); err == nil {
		file.Close()
		t.Fatal("multiply linked file accepted")
	}
	if err := os.Symlink(path, filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegularAt(parent, "symlink", owner); err == nil {
		file.Close()
		t.Fatal("symlink accepted")
	}
	for _, name := range []string{"", ".", "..", "../payload", path} {
		if file, err := OpenRegularAt(parent, name, owner); err == nil {
			file.Close()
			t.Fatal("non-leaf path accepted", name)
		}
	}
}
func TestLinuxFIFOInspectionNeverWaitsForWriter(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	result := make(chan error, 1)
	go func() {
		file, err := OpenRegularAt(parent, "pipe", uint32(os.Geteuid()))
		if file != nil {
			file.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO accepted as policy")
		}
	case <-time.After(time.Second):
		t.Fatal("inspection blocked waiting for a FIFO writer")
	}
}
func TestLinuxDirectoryChecksRejectSymlinksAndWritableParents(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "directory")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	child, err := OpenDirectoryAt(parent, "directory", uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	if err := os.Chmod(dir, 0775); err != nil {
		t.Fatal(err)
	}
	if child, err := OpenDirectoryAt(parent, "directory", uint32(os.Geteuid())); err == nil {
		child.Close()
		t.Fatal("group-write directory accepted")
	}
	if err := os.Symlink(dir, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if child, err := OpenDirectoryAt(parent, "alias", uint32(os.Geteuid())); err == nil {
		child.Close()
		t.Fatal("directory symlink followed")
	}
}

func TestCreatedObjectsDoNotRetainInheritedNamedACLs(t *testing.T) {
	root := t.TempDir()
	acl := make([]byte, 44)
	binary.LittleEndian.PutUint32(acl, 2)
	entries := [][3]uint32{{1, 7, 0xffffffff}, {2, 0, 65534}, {4, 5, 0xffffffff}, {0x10, 5, 0xffffffff}, {0x20, 5, 0xffffffff}}
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(acl[offset:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(acl[offset+2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(acl[offset+4:], entry[2])
	}
	if err := syscall.Setxattr(root, "system.posix_acl_default", acl, 0); errors.Is(err, syscall.ENOTSUP) {
		t.Skip("fixture filesystem has no POSIX ACLs")
	} else if err != nil {
		t.Fatal(err)
	}
	dirPath := filepath.Join(root, "new-object")
	if err := os.Mkdir(dirPath, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := ResetCreatedACL(dir, true); err != nil {
		t.Fatal(err)
	}
	if err := dir.Chmod(0755); err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if _, err := syscall.Getxattr(dirPath, attribute, nil); !errors.Is(err, syscall.ENODATA) {
			t.Fatal("created directory retained inherited ACL", attribute, err)
		}
	}
}
