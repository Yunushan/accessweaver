//go:build darwin && (amd64 || arm64)

package darwintrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureParent(t *testing.T) *os.File {
	t.Helper()
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(parent, true, uint32(os.Geteuid())); err != nil {
		parent.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := parent.Close(); err != nil {
			t.Error(err)
		}
	})
	return parent
}
func fixtureFile(t *testing.T, parent *os.File, name string, data []byte) *os.File {
	t.Helper()
	file, err := CreateRegularAt(parent, name, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Chmod(0644); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	return file
}
func chmodFixture(t *testing.T, path string, args ...string) {
	t.Helper()
	args = append(args, path)
	cmd := exec.Command("/bin/chmod", args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("owned ACL fixture: %v %s", err, output)
	}
}

func TestProtectedDarwinObjectsAndAliases(t *testing.T) {
	parent := fixtureParent(t)
	owner := uint32(os.Geteuid())
	file := fixtureFile(t, parent, "policy", []byte("public signed fixture"))
	opened, err := OpenRegularAt(parent, "policy", owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(opened, false, owner+1); err == nil {
		t.Fatal("unexpected owner accepted")
	}
	opened.Close()
	for _, name := range []string{"", ".", "..", "one/two", "bad\x00name"} {
		if f, err := OpenRegularAt(parent, name, owner); err == nil {
			f.Close()
			t.Fatal("file alias accepted", name)
		}
		if f, err := OpenDirectoryAt(parent, name, owner); err == nil {
			f.Close()
			t.Fatal("directory alias accepted", name)
		}
	}
	if err := os.Symlink("policy", filepath.Join(parent.Name(), "link")); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRegularAt(parent, "link", owner); err == nil {
		f.Close()
		t.Fatal("symlink accepted")
	}
	if err := os.Link(filepath.Join(parent.Name(), "policy"), filepath.Join(parent.Name(), "hard")); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRegularAt(parent, "policy", owner); err == nil {
		f.Close()
		t.Fatal("hard-linked source accepted")
	}
	if err := os.Remove(filepath.Join(parent.Name(), "hard")); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0666); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRegularAt(parent, "policy", owner); err == nil {
		f.Close()
		t.Fatal("user-writable source accepted")
	}
	if err := file.Chmod(0644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(parent.Name(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRegularAt(parent, "fifo", owner); err == nil {
		f.Close()
		t.Fatal("FIFO accepted")
	}
	for _, path := range []string{"Library", "/Library/../Library", "/Library/", "/bad\x00path"} {
		if f, err := OpenRootDirectory(path); err == nil {
			f.Close()
			t.Fatal("noncanonical root accepted", path)
		}
	}
}

func TestDarwinACLMutationGrantsRemainBlocked(t *testing.T) {
	for _, permission := range []string{"write", "append", "delete", "writeattr", "writeextattr", "writesecurity", "chown"} {
		t.Run(permission, func(t *testing.T) {
			parent := fixtureParent(t)
			file := fixtureFile(t, parent, "policy", []byte("unchanged signed fixture"))
			path := file.Name()
			chmodFixture(t, path, "+a", "everyone allow "+permission)
			defer chmodFixture(t, path, "-N")
			info, err := file.Stat()
			if err != nil || info.Mode().Perm() != 0644 {
				t.Fatal("fixture changed mode instead of ACL", info, err)
			}
			for i := 0; i < 2; i++ {
				if _, err := Check(file, false, uint32(os.Geteuid())); err == nil {
					t.Fatal("mutation ACL accepted or silently removed")
				}
			}
		})
	}
}

func TestDarwinReadAndDenyACLsAndNewObjectReset(t *testing.T) {
	parent := fixtureParent(t)
	owner := uint32(os.Geteuid())
	file := fixtureFile(t, parent, "read-only", []byte("retained"))
	defer chmodFixture(t, file.Name(), "-N")
	chmodFixture(t, file.Name(), "+a", "everyone allow read,readattr,readextattr,readsecurity")
	chmodFixture(t, file.Name(), "+a", "everyone deny delete")
	if _, err := Check(file, false, owner); err != nil {
		t.Fatal("safe read/deny ACL rejected", err)
	}
	dir, err := CreateDirectoryAt(parent, "new", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	chmodFixture(t, dir.Name(), "+a", "everyone deny read,file_inherit,only_inherit")
	defer chmodFixture(t, dir.Name(), "-N")
	created, err := CreateRegularAt(dir, "policy", owner)
	if err != nil {
		t.Fatal("new inherited ACL not safely reset", err)
	}
	if _, err := created.Write([]byte("intended readable object")); err != nil {
		created.Close()
		t.Fatal(err)
	}
	if err := created.Chmod(0644); err != nil {
		created.Close()
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRegularAt(dir, "policy", owner)
	if err != nil {
		t.Fatal(err)
	}
	opened.Close()
	data, err := os.ReadFile(filepath.Join(dir.Name(), "policy"))
	if err != nil || !bytes.Equal(data, []byte("intended readable object")) {
		t.Fatal("inherited deny survived new-object reset", err)
	}
	fixtureFile(t, parent, "portable", []byte("readable after publication"))
	if err := unix.Renameat(int(parent.Fd()), "portable", int(dir.Fd()), "published"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(dir.Name(), "published"))
	if err != nil || string(data) != "readable after publication" {
		t.Fatal("publication reintroduced a removed inherited deny", err)
	}
	// Exclusive creation refuses an existing file without clearing its ACL.
	if f, err := CreateRegularAt(parent, "read-only", owner); err == nil {
		f.Close()
		t.Fatal("creation replaced an existing object")
	}
	if _, err := Check(file, false, owner); err != nil {
		t.Fatal("failed creation changed existing ACL", err)
	}
}

func TestDarwinDirectoryPublicationPrimitives(t *testing.T) {
	parent := fixtureParent(t)
	owner := uint32(os.Geteuid())
	old, err := CreateDirectoryAt(parent, "active", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	next, err := CreateDirectoryAt(parent, "candidate", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	fixtureFile(t, old, "policy", []byte("old generation"))
	fixtureFile(t, next, "policy", []byte("next generation"))
	if err := RenameDirectories(parent, "candidate", "active", false); !errors.Is(err, syscall.EEXIST) {
		t.Fatal("exclusive publication replaced an existing generation", err)
	}
	if err := RenameDirectories(parent, "candidate", "active", true); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(filepath.Join(parent.Name(), "candidate", "policy"))
	if err != nil || string(retained) != "old generation" {
		t.Fatal("displaced generation lost", err)
	}
	current, err := os.ReadFile(filepath.Join(parent.Name(), "active", "policy"))
	if err != nil || string(current) != "next generation" {
		t.Fatal("new generation not published", err)
	}
	held, err := OpenRegularAt(old, "policy", owner)
	if err != nil {
		t.Fatal(err)
	}
	held.Close()
	if err := RenameDirectories(parent, "missing", "active", true); err == nil {
		t.Fatal("swap accepted a missing source")
	}
	if err := RenameDirectories(parent, "../outside", "active", true); err == nil {
		t.Fatal("swap accepted a path alias")
	}
	current, err = os.ReadFile(filepath.Join(parent.Name(), "active", "policy"))
	if err != nil || string(current) != "next generation" {
		t.Fatal("failed publication changed the current generation", err)
	}
}

func TestDarwinProtectedRootsPreflight(t *testing.T) {
	type checked struct {
		Path    string `json:"path"`
		Owner   uint32 `json:"owner"`
		Mode    string `json:"mode"`
		Trusted bool   `json:"trusted"`
	}
	checks := make([]checked, 0, 3)
	for _, path := range []string{"/", "/Library", "/Library/Preferences"} {
		file, err := OpenRootDirectory(path)
		if err != nil {
			t.Fatalf("existing protected parent %s: %v", path, err)
		}
		info, err := file.Stat()
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		checks = append(checks, checked{path, stat.Uid, fmt.Sprintf("%04o", info.Mode().Perm()), true})
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return
	}
	if os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("unexpected native preflight environment")
	}
	sha := os.Getenv("GITHUB_SHA")
	if len(sha) != 40 {
		t.Fatal("missing source identity")
	}
	report := map[string]any{"schemaVersion": 1, "cgoEnvironment": os.Getenv("CGO_ENABLED"), "sourceCommit": sha, "platform": runtime.GOOS, "arch": runtime.GOARCH, "goVersion": runtime.Version(), "effectiveUID": os.Geteuid(), "checks": checks, "posixAndExtendedACLChecked": true, "localAPFSChecked": true, "readOnlyExistingParents": true, "machinePolicyActivated": false, "productionQualificationComplete": false}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "build", "darwin-trust-checks")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "preflight-"+runtime.GOARCH+".json"), append(data, 10), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinAbsentACLIsDistinctFromInvalidDescriptor(t *testing.T) {
	parent := fixtureParent(t)
	path := filepath.Join(parent.Name(), "no-acl")
	if err := os.WriteFile(path, []byte("POSIX-protected without an extended ACL"), 0600); err != nil {
		t.Fatal(err)
	}
	chmodFixture(t, path, "-N")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(file, false, uint32(os.Geteuid())); err != nil {
		file.Close()
		t.Fatal("absent ACL rejected a protected existing descriptor", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkACL(file); err == nil {
		t.Fatal("invalid descriptor was treated as absent ACL")
	}
}
