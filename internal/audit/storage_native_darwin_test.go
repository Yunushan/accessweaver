//go:build darwin && (amd64 || arm64)

package audit

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// These native source fixtures use only fresh objects beneath the real owned
// home. /var temporary-directory aliases cannot satisfy the product resolver.
// Resolving the home here selects fixture placement; product paths are never
// resolved or repaired by the fixture.
type darwinAuditNativeFixture struct {
	home, root string
	dev        int32
	ino        uint64
	uid        uint32
	// Preserve the owned root when a journal worker's cleanup is unconfirmed.
	preserve bool
}

func darwinAuditNativeHome(t *testing.T) string {
	t.Helper()
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_AUDIT_TEST") != "1" {
		t.Skip("native Darwin audit storage fixture requires explicit disposable opt-in")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("opted-in native Darwin audit storage fixture requires GitHub-hosted context")
	}
	if os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		t.Fatal("native audit storage fixtures require a genuine ordinary process")
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		t.Fatal("ordinary fixture home unavailable")
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil || filepath.Clean(home) != home || home == "/" {
		t.Fatal("ordinary fixture home is not a canonical existing directory")
	}
	info, err := os.Lstat(home)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("ordinary fixture home is not an existing directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		t.Fatal("ordinary fixture home has an unexpected owner")
	}
	return home
}

func newDarwinAuditNativeFixture(t *testing.T) *darwinAuditNativeFixture {
	t.Helper()
	home := darwinAuditNativeHome(t)
	root, err := os.MkdirTemp(home, ".accessweaver-audit-native-")
	if err != nil {
		t.Fatal("create fresh native audit fixture")
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal("capture fresh native audit fixture")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatal("fresh native audit fixture has unexpected identity")
	}
	f := &darwinAuditNativeFixture{home: home, root: root, dev: stat.Dev, ino: stat.Ino, uid: stat.Uid}
	t.Cleanup(func() {
		if f.preserve {
			t.Error("native audit fixture cleanup is unconfirmed; owned root preserved")
			return
		}
		// An unexpected replacement is preserved. Never recursively remove a
		// changed root or any computed path outside the captured direct home.
		current, err := os.Lstat(f.root)
		if err != nil {
			t.Error("native audit fixture cleanup identity unavailable; preserved")
			return
		}
		now, ok := current.Sys().(*syscall.Stat_t)
		if filepath.Dir(f.root) != f.home || !strings.HasPrefix(filepath.Base(f.root), ".accessweaver-audit-native-") ||
			!ok || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || now.Dev != f.dev || now.Ino != f.ino || now.Uid != f.uid {
			t.Error("native audit fixture root changed; preserved")
			return
		}
		if err := os.RemoveAll(f.root); err != nil {
			t.Error("owned native audit fixture cleanup failed")
		}
	})
	darwinAuditPrepareFreshDirectory(t, root)
	return f
}

func darwinAuditPrepareFreshDirectory(t *testing.T, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("open freshly created fixture directory")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		t.Fatal("retain freshly created fixture directory")
	}
	aclErr := darwintrust.ResetCreatedACL(file)
	modeErr := file.Chmod(0700)
	info, statErr := file.Stat()
	closeErr := file.Close()
	if aclErr != nil || modeErr != nil || statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
		t.Fatal("prepare newly created private fixture directory")
	}
}

func (f *darwinAuditNativeFixture) directory(t *testing.T, parent, name string) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if filepath.Dir(path) != parent || !strings.HasPrefix(path, f.root+string(os.PathSeparator)) {
		t.Fatal("fixture directory escaped its owned root")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal("exclusively create fixture directory")
	}
	darwinAuditPrepareFreshDirectory(t, path)
	return path
}

func darwinAuditTrackFile(t *testing.T, file *os.File) *os.File {
	t.Helper()
	t.Cleanup(func() {
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error("owned native audit file close failed")
		}
	})
	return file
}

func darwinAuditOpenFixtureScope(t *testing.T, path string) *darwinAuditDirectory {
	t.Helper()
	d, err := openDarwinAuditDirectory(path)
	if err != nil || d == nil {
		var rejection *darwinAuditRejection
		if errors.As(err, &rejection) {
			if code := rejection.rejectionCode(); code != "" {
				t.Fatalf("ordinary private native audit directory admission failed: %s", code)
			}
		}
		t.Fatal("ordinary private native audit directory admission failed")
	}
	t.Cleanup(func() {
		if !d.closed {
			if err := d.Close(); err != nil {
				t.Error("owned native audit scope close failed")
			}
		}
	})
	return d
}

func darwinAuditFreshFile(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("exclusively create fixture file")
	}
	aclErr := darwintrust.ResetCreatedACL(file)
	modeErr := file.Chmod(0600)
	var writeErr error
	if aclErr == nil && modeErr == nil {
		_, writeErr = file.Write(data)
	}
	closeErr := file.Close()
	if aclErr != nil || modeErr != nil || writeErr != nil || closeErr != nil {
		t.Fatal("prepare newly created fixture file")
	}
}

func darwinAuditAccessMode(t *testing.T, file *os.File) int {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal("inspect fixture access mode")
	}
	var flags int
	var nativeErr error
	err = raw.Control(func(fd uintptr) {
		flags, nativeErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	})
	if err != nil || nativeErr != nil {
		t.Fatal("read fixture access mode")
	}
	return flags & unix.O_ACCMODE
}

func darwinAuditFixtureBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read owned fixture bytes")
	}
	return data
}

type darwinAuditNativeNode struct {
	dev               int32
	ino               uint64
	mode, links       uint16
	uid, gid          uint32
	size              int64
	flags             uint32
	modified, changed unix.Timespec
}

func darwinAuditFixtureNode(t *testing.T, path string) darwinAuditNativeNode {
	t.Helper()
	var stat unix.Stat_t
	if unix.Lstat(path, &stat) != nil {
		t.Fatal("read owned fixture metadata")
	}
	return darwinAuditNativeNode{stat.Dev, stat.Ino, stat.Mode, stat.Nlink, stat.Uid, stat.Gid, stat.Size, stat.Flags, stat.Mtim, stat.Ctim}
}

func darwinAuditFixtureACLCommand(t *testing.T, path string, arguments ...string) {
	t.Helper()
	arguments = append(arguments, path)
	command := exec.Command("/bin/chmod", arguments...)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	if _, err := command.CombinedOutput(); err != nil {
		t.Fatal("set owned native ACL fixture")
	}
}

func darwinAuditFixtureACL(t *testing.T, path string) []byte {
	t.Helper()
	command := exec.Command("/bin/ls", "-lde", path)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 64<<10 {
		t.Fatal("snapshot owned native ACL fixture")
	}
	return output
}

func TestDarwinAuditStorageNativeCreateReadAndClose(t *testing.T) {
	f := newDarwinAuditNativeFixture(t)
	path := f.directory(t, f.root, "stream")
	d := darwinAuditOpenFixtureScope(t, path)
	if d.checkBinding() != nil || d.requireEmpty() != nil {
		t.Fatal("new native audit scope is not bound and empty")
	}
	for _, name := range []string{actorKeyName, journalName} {
		t.Run(name, func(t *testing.T) {
			file, err := d.createRegular(name)
			if err != nil || file == nil {
				t.Fatal("exclusive private file creation failed")
			}
			darwinAuditTrackFile(t, file)
			if darwinAuditAccessMode(t, file) != unix.O_RDWR {
				t.Fatal("created file cannot support write and verification readback")
			}
			initial, err := d.fileState(file, name)
			if err != nil || initial.size != 0 {
				t.Fatal("new private file state unavailable")
			}
			data := []byte("private native fixture")
			if n, err := file.WriteAt(data, 0); err != nil || n != len(data) {
				t.Fatal("write newly created private file")
			}
			got := make([]byte, len(data))
			if n, err := file.ReadAt(got, 0); err != nil || n != len(got) || !bytes.Equal(got, data) {
				t.Fatal("created private file readback failed")
			}
			written, err := d.fileState(file, name)
			if err != nil || written.id != initial.id || written.size != int64(len(data)) {
				t.Fatal("authorized size change lost its retained native binding")
			}
			if file, err := d.createRegular(name); err == nil {
				file.Close()
				t.Fatal("existing private file was replaced")
			}
			if !bytes.Equal(darwinAuditFixtureBytes(t, filepath.Join(path, name)), data) {
				t.Fatal("exclusive creation refusal changed existing bytes")
			}
			reader, err := d.openRegular(name, false)
			if err != nil || reader == nil {
				t.Fatal("read-only private reopen failed")
			}
			darwinAuditTrackFile(t, reader)
			if darwinAuditAccessMode(t, reader) != unix.O_RDONLY {
				t.Fatal("read-only open acquired write access")
			}
			if _, err := reader.WriteAt([]byte("X"), 0); err == nil {
				t.Fatal("read-only private handle accepted a write")
			}
			if dataRead, err := io.ReadAll(reader); err != nil || !bytes.Equal(dataRead, data) {
				t.Fatal("read-only reopen did not preserve existing bytes")
			}
			writer, err := d.openRegular(name, true)
			if err != nil || writer == nil {
				t.Fatal("writable private reopen failed")
			}
			darwinAuditTrackFile(t, writer)
			if darwinAuditAccessMode(t, writer) != unix.O_RDWR {
				t.Fatal("writable reopen cannot support verification reads")
			}
			if n, err := writer.WriteAt([]byte("!"), int64(len(data))); err != nil || n != 1 {
				t.Fatal("append through admitted writable handle")
			}
			if updated, err := d.fileState(writer, name); err != nil || updated.id != initial.id || updated.size != int64(len(data)+1) {
				t.Fatal("reopened writable file state incorrectly froze its size")
			}
		})
	}
	if d.requireEmpty() == nil {
		t.Fatal("nonempty private directory accepted as empty")
	}
}

func TestDarwinAuditStorageNativeNamesAndLexicalPaths(t *testing.T) {
	f := newDarwinAuditNativeFixture(t)
	path := f.directory(t, f.root, "stream")
	d := darwinAuditOpenFixtureScope(t, path)
	file, err := d.createRegular(actorKeyName)
	if err != nil {
		t.Fatal("create name-admission control file")
	}
	darwinAuditTrackFile(t, file)
	for _, name := range []string{"", ".", "..", "other", ".ACTOR-KEY", "Events.journal", "events.journal/child", "/events.journal", "bad\x00name", strings.Repeat("x", 256)} {
		if created, err := d.createRegular(name); err == nil {
			created.Close()
			t.Fatal("non-fixed child creation accepted")
		}
		for _, writable := range []bool{false, true} {
			if opened, err := d.openRegular(name, writable); err == nil {
				opened.Close()
				t.Fatal("non-fixed child open accepted")
			}
		}
		if _, err := d.fileState(file, name); err == nil {
			t.Fatal("non-fixed child file-state accepted")
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != actorKeyName {
		t.Fatal("rejected child names created additional objects")
	}
	for _, invalid := range []string{"", "relative", path + "/", path + "/.", path + "/../stream", path + "//child", "/bad\x00path", string([]byte{'/', 0xff}), "/" + strings.Repeat("x", 256), "/" + strings.Repeat("a/", 128) + "a", "/" + strings.Join([]string{strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255)}, "/")} {
		if parsed, err := parseDarwinAuditPath(invalid); err == nil {
			t.Fatal("noncanonical or over-bound path accepted", len(parsed))
		}
		if opened, err := openDarwinAuditDirectory(invalid); err == nil {
			opened.Close()
			t.Fatal("noncanonical or over-bound directory opened")
		}
	}
	for _, valid := range []string{"/", "/" + strings.Repeat("x", 255), "/" + strings.Repeat("a/", 127) + "a", "/" + strings.Repeat("x", 255) + "/" + strings.Repeat("x", 255) + "/" + strings.Repeat("x", 255) + "/" + strings.Repeat("x", 254)} {
		if _, err := parseDarwinAuditPath(valid); err != nil {
			t.Fatal("documented lexical boundary rejected")
		}
	}
	alias := filepath.Join(f.root, "alias")
	if err := os.Symlink("stream", alias); err != nil {
		t.Fatal("create owned directory symlink fixture")
	}
	if opened, err := openDarwinAuditDirectory(alias); err == nil {
		opened.Close()
		t.Fatal("symlink directory selected as private storage")
	}
	if opened, err := openDarwinAuditDirectory("/"); err == nil {
		opened.Close()
		t.Fatal("ordinary process accepted root as its private directory")
	}
}

func TestDarwinAuditStorageNativeSpecialFilesAndLinksPreserved(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "directory", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newDarwinAuditNativeFixture(t)
			path := f.directory(t, f.root, "stream")
			d := darwinAuditOpenFixtureScope(t, path)
			source := filepath.Join(f.root, "retained-source")
			data := []byte("unrelated owned fixture must remain unchanged")
			darwinAuditFreshFile(t, source, data)
			target := filepath.Join(path, actorKeyName)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("../retained-source", target)
			case "fifo":
				err = unix.Mkfifo(target, 0600)
			case "directory":
				f.directory(t, path, actorKeyName)
			case "hardlink":
				err = os.Link(source, target)
			}
			if err != nil {
				t.Fatal("create owned special-file fixture")
			}
			before := darwinAuditFixtureNode(t, target)
			for _, writable := range []bool{false, true} {
				if opened, err := d.openRegular(actorKeyName, writable); err == nil {
					opened.Close()
					t.Fatal("special or hard-linked child accepted")
				}
			}
			if created, err := d.createRegular(actorKeyName); err == nil {
				created.Close()
				t.Fatal("exclusive create replaced an existing special child")
			}
			if after := darwinAuditFixtureNode(t, target); after != before || !bytes.Equal(darwinAuditFixtureBytes(t, source), data) {
				t.Fatal("special-file refusal changed identity, metadata or retained bytes")
			}
			if kind == "symlink" {
				if value, err := os.Readlink(target); err != nil || value != "../retained-source" {
					t.Fatal("rejected symlink was repaired")
				}
			}
		})
	}
}

func TestDarwinAuditStorageNativeModesAndSizeRefuseWithoutRepair(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0640, 0660} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newDarwinAuditNativeFixture(t)
			path := f.directory(t, f.root, "stream")
			d := darwinAuditOpenFixtureScope(t, path)
			target := filepath.Join(path, actorKeyName)
			data := []byte("retained private bytes")
			darwinAuditFreshFile(t, target, data)
			if err := os.Chmod(target, mode); err != nil {
				t.Fatal("set owned mode fixture")
			}
			before := darwinAuditFixtureNode(t, target)
			for _, writable := range []bool{false, true} {
				if opened, err := d.openRegular(actorKeyName, writable); err == nil {
					opened.Close()
					t.Fatal("non-private file mode accepted")
				}
			}
			if created, err := d.createRegular(actorKeyName); err == nil {
				created.Close()
				t.Fatal("existing mode fixture replaced")
			}
			if after := darwinAuditFixtureNode(t, target); after != before || !bytes.Equal(darwinAuditFixtureBytes(t, target), data) {
				t.Fatal("file mode refusal repaired metadata or changed bytes")
			}
		})
	}
	for _, mode := range []os.FileMode{0701, 0750, 0770} {
		t.Run("directory-"+mode.String(), func(t *testing.T) {
			f := newDarwinAuditNativeFixture(t)
			path := f.directory(t, f.root, "stream")
			target := filepath.Join(path, actorKeyName)
			darwinAuditFreshFile(t, target, []byte("retained directory fixture"))
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal("set owned directory mode fixture")
			}
			before := darwinAuditFixtureNode(t, path)
			if opened, err := openDarwinAuditDirectory(path); err == nil {
				opened.Close()
				t.Fatal("non-private directory mode accepted")
			}
			if after := darwinAuditFixtureNode(t, path); after != before || string(darwinAuditFixtureBytes(t, target)) != "retained directory fixture" {
				t.Fatal("directory mode refusal repaired metadata or changed bytes")
			}
		})
	}
	for _, name := range []string{actorKeyName, journalName} {
		t.Run("size-"+name, func(t *testing.T) {
			f := newDarwinAuditNativeFixture(t)
			path := f.directory(t, f.root, "stream")
			d := darwinAuditOpenFixtureScope(t, path)
			file, err := d.createRegular(name)
			if err != nil {
				t.Fatal("create size-bound fixture")
			}
			darwinAuditTrackFile(t, file)
			limit := int64(MaxJournalBytes)
			if name == actorKeyName {
				limit = int64(actorKeyFileBytes)
			}
			if err := file.Truncate(limit + 1); err != nil {
				t.Fatal("prepare bounded sparse oversize fixture")
			}
			before := darwinAuditFixtureNode(t, filepath.Join(path, name))
			if _, err := d.fileState(file, name); err == nil {
				t.Fatal("oversize held file accepted")
			}
			if opened, err := d.openRegular(name, false); err == nil {
				opened.Close()
				t.Fatal("oversize existing file accepted")
			}
			if after := darwinAuditFixtureNode(t, filepath.Join(path, name)); after != before {
				t.Fatal("oversize refusal truncated or repaired existing state")
			}
		})
	}
}

func TestDarwinAuditStorageNativeReadACLsRefuseWithoutRepair(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			f := newDarwinAuditNativeFixture(t)
			path := f.directory(t, f.root, "stream")
			d := darwinAuditOpenFixtureScope(t, path)
			file, err := d.createRegular(actorKeyName)
			if err != nil {
				t.Fatal("create ACL fixture file")
			}
			darwinAuditTrackFile(t, file)
			data := []byte("ACL refusal must preserve existing private bytes")
			if _, err := file.Write(data); err != nil {
				t.Fatal("write ACL fixture bytes")
			}
			target := filepath.Join(path, actorKeyName)
			permission := "everyone allow read,readattr,readextattr,readsecurity"
			if directory {
				target = path
				permission = "everyone allow list,search,readattr,readextattr,readsecurity"
			}
			darwinAuditFixtureACLCommand(t, target, "+a", permission)
			beforeACL := darwinAuditFixtureACL(t, target)
			before := darwinAuditFixtureNode(t, target)
			for attempt := 0; attempt < 2; attempt++ {
				if opened, err := d.openRegular(actorKeyName, false); err == nil {
					opened.Close()
					t.Fatal("private child with a read-grant ACL accepted")
				}
				if _, err := d.fileState(file, actorKeyName); err == nil {
					t.Fatal("read-grant ACL became private file authority")
				}
				if directory {
					if opened, err := openDarwinAuditDirectory(path); err == nil {
						opened.Close()
						t.Fatal("private directory read-grant ACL accepted")
					}
				}
				if !bytes.Equal(darwinAuditFixtureACL(t, target), beforeACL) || darwinAuditFixtureNode(t, target) != before {
					t.Fatal("ACL refusal silently repaired existing state")
				}
			}
			if !bytes.Equal(darwinAuditFixtureBytes(t, filepath.Join(path, actorKeyName)), data) {
				t.Fatal("ACL refusal changed private bytes")
			}
			if directory {
				if err := d.Close(); err == nil {
					t.Fatal("changed private directory ACL was not reflected at scope close")
				}
			}
		})
	}
}

func TestDarwinAuditStorageNativeAncestorReplacementAndCallerOwnership(t *testing.T) {
	f := newDarwinAuditNativeFixture(t)
	parent := f.directory(t, f.root, "parent")
	path := f.directory(t, parent, "stream")
	d := darwinAuditOpenFixtureScope(t, path)
	file, err := d.createRegular(actorKeyName)
	if err != nil {
		t.Fatal("create binding fixture file")
	}
	darwinAuditTrackFile(t, file)
	original := []byte("original retained inode")
	if _, err := file.Write(original); err != nil {
		t.Fatal("write binding fixture file")
	}
	moved := filepath.Join(f.root, "parent-moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal("rename owned ancestor fixture")
	}
	if d.checkBinding() == nil {
		t.Fatal("renamed ancestor binding remained authoritative")
	}
	replacementParent := f.directory(t, f.root, "parent")
	replacementPath := f.directory(t, replacementParent, "stream")
	replacement := filepath.Join(replacementPath, actorKeyName)
	darwinAuditFreshFile(t, replacement, []byte("replacement stays unrelated"))
	for _, writable := range []bool{false, true} {
		if opened, err := d.openRegular(actorKeyName, writable); err == nil {
			opened.Close()
			t.Fatal("replaced ancestor redirected a private file open")
		}
	}
	if d.checkBinding() == nil || d.requireEmpty() == nil {
		t.Fatal("replaced ancestor retained directory authority")
	}
	if created, err := d.createRegular(journalName); err == nil {
		created.Close()
		t.Fatal("replaced ancestor accepted a new private file")
	}
	if _, err := d.fileState(file, actorKeyName); err == nil {
		t.Fatal("replaced ancestor accepted held private file state")
	}
	if string(darwinAuditFixtureBytes(t, replacement)) != "replacement stays unrelated" {
		t.Fatal("binding refusal changed the unrelated replacement")
	}
	held := make([]*os.File, len(d.ancestors))
	for index := range d.ancestors {
		held[index] = d.ancestors[index].file
	}
	closeErr := d.Close()
	if closeErr == nil || d.Close() != closeErr {
		t.Fatal("changed-binding close result was not retained")
	}
	for _, ancestor := range held {
		if _, err := ancestor.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("refused scope retained an owned ancestor descriptor")
		}
	}
	got := make([]byte, len(original))
	if n, err := file.ReadAt(got, 0); err != nil || n != len(got) || !bytes.Equal(got, original) {
		t.Fatal("scope close closed or redirected the caller-owned data handle")
	}
}

func TestDarwinAuditStorageNativeClosedScopeRefusesAndPreservesCallerFile(t *testing.T) {
	f := newDarwinAuditNativeFixture(t)
	path := f.directory(t, f.root, "stream")
	d := darwinAuditOpenFixtureScope(t, path)
	file, err := d.createRegular(journalName)
	if err != nil {
		t.Fatal("create close-ownership fixture")
	}
	darwinAuditTrackFile(t, file)
	if err := d.Close(); err != nil || d.Close() != nil {
		t.Fatal("healthy scope close is not idempotent")
	}
	if d.checkBinding() == nil || d.requireEmpty() == nil {
		t.Fatal("closed scope retained directory authority")
	}
	if created, err := d.createRegular(actorKeyName); err == nil {
		created.Close()
		t.Fatal("closed scope created a file")
	}
	if opened, err := d.openRegular(journalName, false); err == nil {
		opened.Close()
		t.Fatal("closed scope opened a file")
	}
	if _, err := d.fileState(file, journalName); err == nil {
		t.Fatal("closed scope accepted file authority")
	}
	if _, err := file.WriteAt([]byte("caller still owns this handle"), 0); err != nil {
		t.Fatal("scope close closed the caller-owned file")
	}
	if err := file.Close(); err != nil {
		t.Fatal("caller-owned file close failed")
	}
	var absent *darwinAuditDirectory
	if absent.Close() != nil || absent.checkBinding() == nil || absent.requireEmpty() == nil {
		t.Fatal("nil scope acquired directory authority")
	}
}

func TestDarwinAuditStorageNativeFlagsAndUnsafeAncestorPreserved(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file-hidden"
		if directory {
			name = "directory-hidden"
		}
		t.Run(name, func(t *testing.T) {
			f := newDarwinAuditNativeFixture(t)
			path := f.directory(t, f.root, "stream")
			d := darwinAuditOpenFixtureScope(t, path)
			file, err := d.createRegular(actorKeyName)
			if err != nil {
				t.Fatal("create owned flag fixture")
			}
			darwinAuditTrackFile(t, file)
			data := []byte("flag refusal preserves owned bytes")
			if _, err := file.Write(data); err != nil {
				t.Fatal("write owned flag fixture")
			}
			target, flagged := filepath.Join(path, actorKeyName), file
			if directory {
				target = path
				flagged, err = os.Open(path)
				if err != nil {
					t.Fatal("open owned flag directory fixture")
				}
				darwinAuditTrackFile(t, flagged)
			}
			raw, err := flagged.SyscallConn()
			if err != nil {
				t.Fatal("retain owned flag fixture descriptor")
			}
			var flagErr error
			if err := raw.Control(func(fd uintptr) { flagErr = unix.Fchflags(int(fd), unix.UF_HIDDEN) }); err != nil || flagErr != nil {
				t.Fatal("set owned private-object flag fixture")
			}
			before := darwinAuditFixtureNode(t, target)
			if before.flags != unix.UF_HIDDEN {
				t.Fatal("owned private-object flag fixture not established")
			}
			for attempt := 0; attempt < 2; attempt++ {
				for _, writable := range []bool{false, true} {
					if opened, err := d.openRegular(actorKeyName, writable); err == nil {
						opened.Close()
						t.Fatal("flagged private object accepted for open")
					}
				}
				if _, err := d.fileState(file, actorKeyName); err == nil {
					t.Fatal("flagged private object accepted as file authority")
				}
				if created, err := d.createRegular(actorKeyName); err == nil {
					created.Close()
					t.Fatal("flag refusal replaced the existing private object")
				}
				if directory {
					if opened, err := openDarwinAuditDirectory(path); err == nil {
						opened.Close()
						t.Fatal("flagged final directory admitted")
					}
					if d.checkBinding() == nil {
						t.Fatal("flagged final directory retained binding authority")
					}
				}
				if darwinAuditFixtureNode(t, target) != before || !bytes.Equal(darwinAuditFixtureBytes(t, filepath.Join(path, actorKeyName)), data) {
					t.Fatal("flag refusal cleared flags, repaired metadata or changed bytes")
				}
			}
			if directory {
				if err := d.Close(); err == nil {
					t.Fatal("changed final-directory flag was not retained at close")
				}
			}
		})
	}
	t.Run("unsafe-intermediate-directory", func(t *testing.T) {
		f := newDarwinAuditNativeFixture(t)
		parent := f.directory(t, f.root, "parent")
		path := f.directory(t, parent, "stream")
		target := filepath.Join(path, actorKeyName)
		data := []byte("unsafe ancestor refusal preserves this child")
		darwinAuditFreshFile(t, target, data)
		if err := os.Chmod(parent, 0770); err != nil {
			t.Fatal("set owned unsafe intermediate-directory fixture")
		}
		before := darwinAuditFixtureNode(t, parent)
		for attempt := 0; attempt < 2; attempt++ {
			if opened, err := openDarwinAuditDirectory(path); err == nil {
				opened.Close()
				t.Fatal("unsafe intermediate directory admitted")
			}
			if darwinAuditFixtureNode(t, parent) != before || !bytes.Equal(darwinAuditFixtureBytes(t, target), data) {
				t.Fatal("ancestor refusal repaired permissions or changed child bytes")
			}
		}
	})
}

func TestDarwinAuditStorageRejectionCodeContract(t *testing.T) {
	err := darwinAuditRejected(darwinAuditRejectFstat)
	if err == nil || err.Error() != ErrJournalStorage.Error() || !errors.Is(err, ErrJournalStorage) {
		t.Fatal("private rejection changed the generic storage error contract")
	}
	var rejection *darwinAuditRejection
	if !errors.As(err, &rejection) || rejection.rejectionCode() != "fstat" {
		t.Fatal("known rejection lost its fixed diagnostic code")
	}
	// The fixture extracts only the closed code, including through wrapping;
	// the raw error text and native operation details are never printed.
	var wrapped *darwinAuditRejection
	if !errors.As(errors.Join(errors.New("fixed fixture wrapper"), err), &wrapped) || wrapped.rejectionCode() != "fstat" {
		t.Fatal("wrapped rejection lost its fixed diagnostic code")
	}
	for _, unknown := range []darwinAuditRejectionCode{0, 255} {
		err := darwinAuditRejected(unknown)
		var rejected *darwinAuditRejection
		if err != ErrJournalStorage || !errors.Is(err, ErrJournalStorage) || errors.As(err, &rejected) {
			t.Fatal("unknown rejection code escaped the generic refusal")
		}
		if (&darwinAuditRejection{code: unknown}).rejectionCode() != "" {
			t.Fatal("unknown private rejection produced a printable code")
		}
	}
	var missing *darwinAuditRejection
	if missing.rejectionCode() != "" {
		t.Fatal("absent private rejection produced a printable code")
	}
}

func TestDarwinAuditStorageProtectedAncestorNoUnlinkPolicy(t *testing.T) {
	const owner = uint32(1001)
	ancestor := darwinAuditFileState{mode: unix.S_IFDIR | 0700, links: 1, uid: owner, flags: unix.SF_NOUNLINK}
	for _, uid := range []uint32{0, owner} {
		trusted := ancestor
		trusted.uid = uid
		if !darwinAuditDirectorySecurity(trusted, owner, false) {
			t.Fatal("protected no-unlink flag rejected an otherwise trusted ancestor")
		}
	}
	if darwinAuditDirectorySecurity(ancestor, owner, true) {
		t.Fatal("ancestor compatibility admitted a flagged private directory")
	}
	foreign := ancestor
	foreign.uid = owner + 1
	writable := ancestor
	writable.mode |= 0020
	unsupported := ancestor
	unsupported.flags |= unix.UF_COMPRESSED
	userFirmlink := ancestor
	userFirmlink.flags |= unix.SF_FIRMLINK
	for _, refused := range []darwinAuditFileState{foreign, writable, unsupported, userFirmlink} {
		if darwinAuditDirectorySecurity(refused, owner, false) {
			t.Fatal("no-unlink compatibility bypassed an ancestor authority restriction")
		}
	}
	rootFirmlink := userFirmlink
	rootFirmlink.uid = 0
	if !darwinAuditDirectorySecurity(rootFirmlink, owner, false) {
		t.Fatal("protected root-owned firmlink ancestor rejected")
	}
	directory := &darwinAuditDirectory{owner: owner, ancestors: []darwinAuditDirectoryBinding{{state: darwinAuditDirectoryState{id: darwinAuditIdentity{dev: 1, ino: 2}}}}}
	privateFile := darwinAuditFileState{id: darwinAuditIdentity{dev: 1, ino: 3}, mode: unix.S_IFREG | 0600, links: 1, uid: owner, flags: unix.SF_NOUNLINK}
	if directory.privateFileSecurity(privateFile, actorKeyName) || directory.privateFileSecurity(privateFile, journalName) {
		t.Fatal("ancestor compatibility admitted a flagged private data file")
	}
}
