//go:build darwin && (amd64 || arm64)

package darwintrust

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func emptyACLFixtureSnapshot(t *testing.T, file *os.File) []byte {
	t.Helper()
	command := exec.Command("/bin/ls", "-lde", file.Name())
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	snapshot, err := command.Output()
	if err != nil {
		t.Fatal("owned ACL snapshot failed")
	}
	return snapshot
}

func emptyACLFixtureBytes(t *testing.T, parent, file *os.File, name string, owner uint32, expected []byte) {
	t.Helper()
	original, err := file.Stat()
	if err != nil {
		t.Fatal("owned fixture identity unavailable")
	}
	reader, err := OpenRegularAt(parent, name, owner)
	if err != nil {
		t.Fatal("owned fixture reader unavailable")
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error("owned fixture reader close failed")
		}
	}()
	opened, err := reader.Stat()
	if err != nil || !os.SameFile(original, opened) {
		t.Fatal("owned fixture reader identity changed")
	}
	actual := make([]byte, len(expected))
	if n, err := reader.ReadAt(actual, 0); err != nil || n != len(expected) || !bytes.Equal(actual, expected) {
		t.Fatal("ACL inspection changed owned fixture bytes")
	}
	info, err := file.Stat()
	if err != nil || info.Size() != int64(len(expected)) {
		t.Fatal("ACL inspection changed owned fixture size")
	}
}

func TestDarwinEmptyACLAcceptsAbsentAndExplicitlyEmpty(t *testing.T) {
	parent := fixtureParent(t)
	payload := []byte("unchanged empty ACL fixture")
	for _, kind := range []string{"absent", "explicitly-empty"} {
		t.Run(kind, func(t *testing.T) {
			file := fixtureFile(t, parent, kind, payload)
			if kind == "absent" {
				chmodFixture(t, file.Name(), "-N")
			} else if err := ResetCreatedACL(file); err != nil {
				t.Fatal("owned new-object empty ACL setup failed")
			}
			before := emptyACLFixtureSnapshot(t, file)
			for attempt := 0; attempt < 2; attempt++ {
				if err := CheckEmptyACL(file); err != nil {
					t.Fatal("absent or empty ACL rejected")
				}
				if err := CheckReadOnlyACL(file); err != nil {
					t.Fatal("read-only ACL contract changed")
				}
			}
			if !bytes.Equal(before, emptyACLFixtureSnapshot(t, file)) {
				t.Fatal("empty ACL inspection changed ACL")
			}
			emptyACLFixtureBytes(t, parent, file, kind, uint32(os.Geteuid()), payload)
			// These 0644 fixtures intentionally demonstrate that the ACL-only check
			// neither enforces private POSIX modes nor establishes confidentiality.
			info, err := file.Stat()
			if err != nil || info.Mode().Perm() != 0644 {
				t.Fatal("ACL inspection changed POSIX mode")
			}
		})
	}
}

func TestDarwinEmptyACLRejectsReadAndDenyEntriesWithoutRepair(t *testing.T) {
	for _, entry := range []string{"everyone allow read,readattr,readextattr,readsecurity", "everyone deny delete"} {
		t.Run(entry, func(t *testing.T) {
			parent := fixtureParent(t)
			payload := []byte("unchanged nonempty ACL fixture")
			file := fixtureFile(t, parent, "nonempty-acl", payload)
			chmodFixture(t, file.Name(), "+a", entry)
			defer chmodFixture(t, file.Name(), "-N")
			before := emptyACLFixtureSnapshot(t, file)
			for attempt := 0; attempt < 2; attempt++ {
				if err := CheckReadOnlyACL(file); err != nil {
					t.Fatal("existing read-only ACL contract changed")
				}
				if err := CheckEmptyACL(file); err == nil {
					t.Fatal("nonempty ACL accepted or silently removed")
				}
			}
			if !bytes.Equal(before, emptyACLFixtureSnapshot(t, file)) {
				t.Fatal("rejected ACL was changed")
			}
			emptyACLFixtureBytes(t, parent, file, "nonempty-acl", uint32(os.Geteuid()), payload)
		})
	}
}

func TestDarwinEmptyACLRejectsClosedDescriptor(t *testing.T) {
	parent := fixtureParent(t)
	file := fixtureFile(t, parent, "closed-acl", []byte("retained"))
	closed, err := os.Open(file.Name())
	if err != nil {
		t.Fatal("owned descriptor setup failed")
	}
	if err := closed.Close(); err != nil {
		t.Fatal("owned descriptor close failed")
	}
	if err := CheckEmptyACL(closed); err == nil {
		t.Fatal("closed descriptor treated as absent ACL")
	}
}

func TestDarwinEmptyACLInspectionRetriesOnlyBoundedTransientReads(t *testing.T) {
	for _, code := range []syscall.Errno{syscall.EINTR, syscall.EBADF, syscall.EACCES, syscall.EIO, syscall.ETIMEDOUT, 0} {
		t.Run(code.Error(), func(t *testing.T) {
			for _, persistent := range []bool{false, true} {
				calls := 0
				api := &nativeAPI{aclGetFD: func(fd, kind int32) (uintptr, syscall.Errno) {
					calls++
					if fd != 42 || kind != aclTypeExtended {
						t.Fatal("native empty ACL inspection parameters changed")
					}
					if !persistent && calls > 1 {
						return 0, syscall.ENOENT
					}
					return 0, code
				}}
				err := checkEmptyACLWithRetry(api, 42)
				want := 1
				if code == syscall.EINTR {
					want = 3
					if !persistent {
						want = 2
					}
				}
				if calls != want {
					t.Fatal("empty ACL inspection exceeded its retry policy")
				}
				if code == syscall.EINTR && !persistent {
					if err != nil {
						t.Fatal("successful empty ACL retry failed")
					}
				} else if err == nil || code != 0 && !errors.Is(err, code) {
					t.Fatal("native empty ACL inspection failure became authority")
				}
			}
		})
	}
	calls := 0
	api := &nativeAPI{aclGetFD: func(fd, kind int32) (uintptr, syscall.Errno) { calls++; return 0, syscall.ENOENT }}
	if err := checkEmptyACLWithRetry(api, 42); err != nil || calls != 1 {
		t.Fatal("absent ACL was not accepted exactly once")
	}
}
