//go:build linux || darwin || freebsd || openbsd

package fileidentity

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixMetadataIdentityMatchesHardLinkAndBorrowedFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "source")
	content := []byte("metadata probes preserve this content")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "hard-link")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := FromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, alias} {
		named, err := FromPath(candidate, true)
		if err != nil || named.ID != opened.ID || named.Kind != Regular {
			t.Fatalf("identity mismatch: state=%+v error=%v", named, err)
		}
	}
	if opened.Kind != Regular || opened.Size != int64(len(content)) || !opened.Modified.Equal(before.ModTime()) {
		t.Fatalf("metadata differs from fstat: %+v", opened)
	}
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil || position != 3 {
		t.Fatalf("probe changed offset: offset=%d error=%v", position, err)
	}
	remaining, err := io.ReadAll(file)
	if err != nil || string(remaining) != string(content[3:]) {
		t.Fatalf("borrowed descriptor was closed or changed: data=%q error=%v", remaining, err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || string(stored) != string(content) {
		t.Fatalf("probe changed data: data=%q error=%v", stored, err)
	}
}

func TestUnixMetadataIdentitySeparatesReplacedPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "current")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	old, err := FromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(directory, "retained")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	current, err := FromPath(path, false)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := FromFile(file)
	if err != nil || retained.ID != old.ID || current.ID == old.ID {
		t.Fatalf("replacement was not distinguished: old=%+v current=%+v retained=%+v error=%v", old, current, retained, err)
	}
}

func TestUnixMetadataIdentityHonorsLeafSymlinkPolicy(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "target")
	if err := os.WriteFile(path, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	target, err := FromPath(path, true)
	if err != nil {
		t.Fatal(err)
	}
	followed, err := FromPath(link, true)
	if err != nil || followed.Kind != Regular || followed.ID != target.ID {
		t.Fatalf("followed leaf did not identify target: state=%+v error=%v", followed, err)
	}
	leaf, err := FromPath(link, false)
	if err != nil || leaf.Kind != Reparse || leaf.ID == target.ID {
		t.Fatalf("nofollow leaf did not identify symlink: state=%+v error=%v", leaf, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := FromPath(link, true); err != os.ErrNotExist {
		t.Fatalf("dangling target error=%v", err)
	}
	after, err := FromPath(link, false)
	if err != nil || after.ID != leaf.ID || after.Kind != Reparse {
		t.Fatalf("dangling symlink itself disappeared: state=%+v error=%v", after, err)
	}
}

func TestUnixMetadataIdentityClassifiesDirectoryAndPipe(t *testing.T) {
	directory, err := FromPath(t.TempDir(), false)
	if err != nil || directory.Kind != Directory {
		t.Fatalf("directory state=%+v error=%v", directory, err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	for _, file := range []*os.File{reader, writer} {
		state, err := FromFile(file)
		if err != nil || state.Kind != Other {
			t.Fatalf("pipe state=%+v error=%v", state, err)
		}
	}
}

func TestUnixMetadataIdentityReturnsOnlyRedactedErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "private-path-never-in-error")
	if _, err := FromPath(missing, true); err != os.ErrNotExist {
		t.Fatalf("missing error=%v", err)
	}
	for _, path := range []string{"", missing + "\x00secret"} {
		_, err := FromPath(path, false)
		if err != ErrUnavailable || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid path error=%v", err)
		}
		var native *os.PathError
		if errors.As(err, &native) {
			t.Fatal("native pathname error escaped")
		}
	}
	if _, err := FromFile(nil); err != ErrUnavailable {
		t.Fatalf("nil file error=%v", err)
	}
	file, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := FromFile(file); err != ErrUnavailable {
		t.Fatalf("closed file error=%v", err)
	}
}
