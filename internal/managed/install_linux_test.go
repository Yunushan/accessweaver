//go:build linux && (amd64 || arm64)

package managed

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
)

func linuxFixtureTransaction(t *testing.T, parent string, initial bool) *linuxInstallationTransaction {
	t.Helper()
	dir, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := beginLinuxInstallation(dir, initial, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})
	return tx
}
func linuxFixtureInstall(t *testing.T, parent string, data []byte, now time.Time) {
	t.Helper()
	tx := linuxFixtureTransaction(t, parent, true)
	installed, err := parseInstallation(data)
	if err != nil {
		t.Fatal(err)
	}
	key, err := PublicKey(installed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := commitInstallation(tx, data, key, changeInstall, func() time.Time { return now })
	if err != nil || !result.Committed {
		t.Fatal("temporary fixture install", result, err)
	}
}
func TestLinuxStagingKeepsInitialSourceAbsentAndAbortCleansOwnFiles(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	tx := linuxFixtureTransaction(t, parent, true)
	if err := tx.Stage(prior); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(parent, linuxPolicyDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uncommitted initial source became visible", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(parent)
	if err != nil || len(files) != 1 || files[0].Name() != linuxPolicyLock {
		t.Fatal("abort retained owned staging files", files, err)
	}
	linuxFixtureInstall(t, parent, prior, now)
	for name, mode := range map[string]os.FileMode{linuxPolicyDirectory: 0755, filepath.Join(linuxPolicyDirectory, linuxPolicyFile): 0644, linuxPolicyLock: 0600} {
		info, err := os.Stat(filepath.Join(parent, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("published permissions", name, info, err)
		}
	}
	parentFD, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	if replacement, err := beginLinuxInstallation(parentFD, true, uint32(os.Geteuid())); err == nil {
		replacement.Close()
		t.Fatal("bootstrap replaced an enrolled directory")
	}
}
func TestLinuxPendingUpdateInvisibleAndStaleAdministratorWritePreserved(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	linuxFixtureInstall(t, parent, prior, now)
	tx := linuxFixtureTransaction(t, parent, false)
	if _, present, err := tx.Read(); err != nil || !present {
		t.Fatal(err)
	}
	candidate, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Stage(candidate); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(filepath.Join(parent, linuxPolicyDirectory, linuxPolicyFile))
	if err != nil || !bytes.Equal(current, prior) {
		t.Fatal("pending update published", err)
	}
	changed := []byte("administrator changed this source outside the lock")
	if err := os.WriteFile(filepath.Join(parent, linuxPolicyDirectory, linuxPolicyFile), changed, 0644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("stale candidate overwrote direct administrative change")
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	current, err = os.ReadFile(filepath.Join(parent, linuxPolicyDirectory, linuxPolicyFile))
	if err != nil || !bytes.Equal(current, changed) {
		t.Fatal("failed candidate changed administrative bytes", err)
	}
	files, err := os.ReadDir(filepath.Join(parent, linuxPolicyDirectory))
	if err != nil || len(files) != 1 {
		t.Fatal("abort did not retain exactly the published source", files, err)
	}
}
func TestLinuxInitialPublishNeverReplacesConcurrentlyCreatedDirectory(t *testing.T) {
	prior, _, _, _, _ := renewalFixture(t)
	parent := t.TempDir()
	tx := linuxFixtureTransaction(t, parent, true)
	if err := tx.Stage(prior); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(parent, linuxPolicyDirectory)
	if err := os.Mkdir(published, 0755); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); !errors.Is(err, syscall.EEXIST) {
		t.Fatal("initial publication replaced an existing directory", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(published)
	if err != nil || len(entries) != 0 {
		t.Fatal("existing empty directory changed", err)
	}
}
func TestLinuxPolicyLockSerializesUpdatesAndReadersStayAvailable(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	linuxFixtureInstall(t, parent, prior, now)
	first := linuxFixtureTransaction(t, parent, false)
	if _, _, err := first.Read(); err != nil {
		t.Fatal(err)
	}
	candidate, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Stage(candidate); err != nil {
		t.Fatal(err)
	}
	outcomes := make(chan error, 1)
	go func() {
		fd, err := os.Open(parent)
		if err != nil {
			outcomes <- err
			return
		}
		second, err := beginLinuxInstallation(fd, false, uint32(os.Geteuid()))
		if err != nil {
			outcomes <- err
			return
		}
		_, err = commitInstallation(second, next, nil, changeUpdate, func() time.Time { return now })
		outcomes <- err
	}()
	select {
	case err := <-outcomes:
		t.Fatal("competing writer bypassed held lock", err)
	case <-time.After(40 * time.Millisecond):
	}
	dir, err := os.Open(filepath.Join(parent, linuxPolicyDirectory))
	if err != nil {
		t.Fatal(err)
	}
	bytesRead, err := readLinuxInstallation(dir, uint32(os.Geteuid()), false)
	dir.Close()
	if err != nil || !bytes.Equal(bytesRead, prior) {
		t.Fatal("reader blocked or saw pending data", err)
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-outcomes:
		if err == nil {
			t.Fatal("second same-revision update committed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not resume after ownership released")
	}
}
func TestLinuxMalformedSourceAndLockDoNotRedirectWrites(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	for _, kind := range []string{"source-symlink", "source-hardlink", "source-fifo", "source-writable", "lock-symlink", "lock-readable"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			linuxFixtureInstall(t, parent, prior, now)
			source := filepath.Join(parent, linuxPolicyDirectory, linuxPolicyFile)
			lock := filepath.Join(parent, linuxPolicyLock)
			target := filepath.Join(t.TempDir(), "unrelated")
			original := []byte("unrelated data must remain intact")
			if err := os.WriteFile(target, original, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "source-symlink":
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, source); err != nil {
					t.Fatal(err)
				}
			case "source-hardlink":
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, source); err != nil {
					t.Fatal(err)
				}
			case "source-fifo":
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(source, 0600); err != nil {
					t.Fatal(err)
				}
			case "source-writable":
				if err := os.Chmod(source, 0664); err != nil {
					t.Fatal(err)
				}
			case "lock-symlink":
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, lock); err != nil {
					t.Fatal(err)
				}
			case "lock-readable":
				if err := os.Chmod(lock, 0644); err != nil {
					t.Fatal(err)
				}
			}
			parentFD, err := os.Open(parent)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := beginLinuxInstallation(parentFD, false, uint32(os.Geteuid()))
			if err == nil {
				_, _, err = tx.Read()
				tx.Close()
			}
			if err == nil {
				t.Fatal("malformed trust/coordination object accepted")
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("unrelated target changed", err)
			}
		})
	}
}
func TestLinuxReadOnlySourceInspectionDoesNotCreatePolicy(t *testing.T) {
	_, _, err := readMachineInstallation()
	if err != nil {
		t.Fatal("cannot inspect fixed protected machine source", err)
	}
	if _, err := linuxtrust.OpenRootDirectory("/etc/../tmp"); err == nil {
		t.Fatal("directory alias accepted")
	}
}

func abandonLinuxFixtureTransaction(t *testing.T, tx *linuxInstallationTransaction) {
	t.Helper()
	for _, file := range []*os.File{tx.dir, tx.lock, tx.parent} {
		if file != nil {
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	tx.dir = nil
	tx.lock = nil
	tx.parent = nil
}
func TestLinuxAbandonedStagingIsReclaimedOnlyUnderPersistentWriterLock(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	initial := linuxFixtureTransaction(t, parent, true)
	if err := initial.Stage(prior); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(parent, initial.directoryName)
	abandonLinuxFixtureTransaction(t, initial)
	linuxFixtureInstall(t, parent, prior, now)
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatal("abandoned bootstrap directory retained", err)
	}
	tx := linuxFixtureTransaction(t, parent, false)
	if _, _, err := tx.Read(); err != nil {
		t.Fatal(err)
	}
	candidate, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Stage(candidate); err != nil {
		t.Fatal(err)
	}
	orphan = filepath.Join(parent, linuxPolicyDirectory, tx.stageName)
	abandonLinuxFixtureTransaction(t, tx)
	nextTx := linuxFixtureTransaction(t, parent, false)
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatal("abandoned update file retained", err)
	}
	result, err := commitInstallation(nextTx, next, nil, changeUpdate, func() time.Time { return now })
	if err != nil || result.Revision != 3 {
		t.Fatal("update after cleanup failed", result, err)
	}
	if _, err := os.Stat(filepath.Join(parent, linuxPolicyLock)); err != nil {
		t.Fatal("coordination inode was removed", err)
	}
}
func TestLinuxStagingCleanupLeavesUnexpectedObjectsUntouched(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	linuxFixtureInstall(t, parent, prior, now)
	target := filepath.Join(t.TempDir(), "important")
	contents := []byte("preserve this unrelated object")
	if err := os.WriteFile(target, contents, 0600); err != nil {
		t.Fatal(err)
	}
	malicious := filepath.Join(parent, linuxPolicyDirectory, ".installation-00000000000000000000000000000000")
	if err := os.Symlink(target, malicious); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := beginLinuxInstallation(fd, false, uint32(os.Geteuid()))
	if err == nil {
		tx.Close()
		t.Fatal("cleanup accepted a staging symlink")
	}
	after, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(after, contents) {
		t.Fatal("cleanup changed unrelated contents", err)
	}
	if info, err := os.Lstat(malicious); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("unexpected staging object was removed", err)
	}
}
