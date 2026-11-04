//go:build linux && (amd64 || arm64)

package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func journalFixture(t *testing.T) (*os.File, Checkpoint) {
	t.Helper()
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	if err := dir.Chmod(0700); err != nil {
		t.Fatal(err)
	}
	start, err := NewStream(fixtureProducer())
	if err != nil {
		t.Fatal(err)
	}
	return dir, start
}
func createJournalFixture(t *testing.T) (*LinuxJournal, *os.File, Checkpoint) {
	t.Helper()
	dir, start := journalFixture(t)
	j, err := CreateLinuxJournal(dir, start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, dir, start
}
func journalBytes(t *testing.T, dir *os.File) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir.Name(), journalName))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func requireJournalRefusal(t *testing.T, dir *os.File, start, end Checkpoint) {
	t.Helper()
	before := journalBytes(t, dir)
	j, err := OpenLinuxJournal(context.Background(), dir, start, end)
	if err == nil {
		_ = j.Close()
		t.Fatal("invalid journal reopened")
	}
	if !bytes.Equal(before, journalBytes(t, dir)) {
		t.Fatal("refused journal changed")
	}
}

func TestLinuxJournalDurableReopenAndConcurrentAppend(t *testing.T) {
	j, dir, start := createJournalFixture(t)
	// Closing the caller's descriptor must not revoke the journal's own handle.
	copyDir, err := os.Open(dir.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = copyDir.Close() })
	dir = copyDir
	const count = 24
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := j.Append(context.Background(), fixtureEvent(i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	data, from, to, err := j.Snapshot(context.Background())
	if err != nil || from != start || to.Sequence != count {
		t.Fatalf("snapshot: %v %+v", err, to)
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(data), from, to); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(context.Background(), fixtureEvent(0)); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal(err)
	}
	opened, err := OpenLinuxJournal(context.Background(), dir, from, to)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	again, _, head, err := opened.Snapshot(context.Background())
	if err != nil || head != to || !bytes.Equal(data, again) {
		t.Fatal("reopen changed evidence", err)
	}
	if _, err := CreateLinuxJournal(dir, start); !errors.Is(err, ErrJournalStorage) {
		t.Fatal("creation replaced a stream", err)
	}
}
func TestLinuxJournalLocksRefusesStaleHeadAndPreservesPartialInitialization(t *testing.T) {
	j, dir, start := createJournalFixture(t)
	before := journalBytes(t, dir)
	other, err := OpenLinuxJournal(context.Background(), dir, start, start)
	if other != nil || !errors.Is(err, ErrJournalBusy) {
		t.Fatal("second writer admitted", err)
	}
	if !bytes.Equal(before, journalBytes(t, dir)) {
		t.Fatal("contender changed storage")
	}
	end, err := j.Append(context.Background(), fixtureEvent(0))
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	requireJournalRefusal(t, dir, start, start)
	wrong := end
	wrong.SHA256 = strings.Repeat("f", 64)
	requireJournalRefusal(t, dir, start, wrong)
	foreign, _ := NewStream(fixtureProducer())
	requireJournalRefusal(t, dir, foreign, end)
	// An exclusive creation interrupted before its genesis write is retained.
	emptyDir, genesis := journalFixture(t)
	if err := os.WriteFile(filepath.Join(emptyDir.Name(), journalName), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if created, err := CreateLinuxJournal(emptyDir, genesis); err == nil {
		created.Close()
		t.Fatal("partial initialization replaced")
	}
	requireJournalRefusal(t, emptyDir, genesis, genesis)
}

type faultJournalDisk struct {
	file          *os.File
	mode          string
	writes, syncs int
}

func (f *faultJournalDisk) WriteAt(data []byte, offset int64) (int, error) {
	f.writes++
	if f.mode == "enospc" {
		return 0, syscall.ENOSPC
	}
	if f.mode == "partial" || f.mode == "short-no-error" {
		n, err := f.file.WriteAt(data[:len(data)/2], offset)
		if err != nil {
			return n, err
		}
		if f.mode == "short-no-error" {
			return n, nil
		}
		return n, io.ErrShortWrite
	}
	return f.file.WriteAt(data, offset)
}
func (f *faultJournalDisk) Sync() error {
	f.syncs++
	if f.mode == "sync" {
		return syscall.EIO
	}
	return f.file.Sync()
}
func TestLinuxJournalUncertainWritesReturnNoHeadAndNeverRetryOrRepair(t *testing.T) {
	for _, mode := range []string{"enospc", "partial", "short-no-error", "sync"} {
		t.Run(mode, func(t *testing.T) {
			j, dir, start := createJournalFixture(t)
			prior := journalBytes(t, dir)
			disk := &faultJournalDisk{file: j.file, mode: mode}
			j.disk = disk
			got, err := j.Append(context.Background(), fixtureEvent(0))
			if !errors.Is(err, ErrJournalUncertain) || got != (Checkpoint{}) || disk.writes != 1 {
				t.Fatalf("uncertain write: %+v %v", got, err)
			}
			if _, err := j.Append(context.Background(), fixtureEvent(1)); !errors.Is(err, ErrJournalUnavailable) || disk.writes != 1 {
				t.Fatal("failed append retried", err)
			}
			if data, _, _, err := j.Snapshot(context.Background()); data != nil || !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("poisoned journal exported", err)
			}
			retained := journalBytes(t, dir)
			_ = j.Close()
			if !bytes.HasPrefix(retained, prior) {
				t.Fatal("prior evidence damaged")
			}
			switch mode {
			case "enospc":
				if !bytes.Equal(prior, retained) || disk.syncs != 0 {
					t.Fatal("failed admission wrote data")
				}
				opened, err := OpenLinuxJournal(context.Background(), dir, start, start)
				if err != nil {
					t.Fatal(err)
				}
				opened.Close()
			case "partial", "short-no-error":
				if len(retained) <= len(prior) || disk.syncs != 0 {
					t.Fatal("partial bytes absent")
				}
				requireJournalRefusal(t, dir, start, start)
			case "sync":
				if disk.syncs != 1 {
					t.Fatal("sync retry")
				}
				requireJournalRefusal(t, dir, start, start)
				// Test-only independent reconciliation supplies the exact complete head.
				// Production must not derive a new trusted endpoint from an unknown tail.
				_, expected, _ := Append(start, fixtureEvent(0))
				opened, err := OpenLinuxJournal(context.Background(), dir, start, expected)
				if err != nil {
					t.Fatal(err)
				}
				opened.Close()
			}
			if !bytes.Equal(retained, journalBytes(t, dir)) {
				t.Fatal("reconciliation changed journal bytes")
			}
		})
	}
}
func TestLinuxJournalCancellationInvalidEventsAndCapacityDoNotWrite(t *testing.T) {
	j, dir, start := createJournalFixture(t)
	before := journalBytes(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := j.Append(ctx, fixtureEvent(0)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	invalid := fixtureEvent(0)
	invalid.Action = "secret profile path"
	if _, err := j.Append(context.Background(), invalid); err == nil || strings.Contains(err.Error(), invalid.Action) {
		t.Fatal("invalid/private event accepted or exposed", err)
	}
	if !bytes.Equal(before, journalBytes(t, dir)) {
		t.Fatal("refused admission wrote bytes")
	}
	_ = j.Close()
	// Populate a full canonical fixture independently of the journal appender.
	head := start
	data := append([]byte(nil), before...)
	for i := 0; i < MaxSegmentRecords; i++ {
		line, next, err := Append(head, fixtureEvent(i%60))
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, line...)
		head = next
	}
	if err := os.WriteFile(filepath.Join(dir.Name(), journalName), data, 0600); err != nil {
		t.Fatal(err)
	}
	full, err := OpenLinuxJournal(context.Background(), dir, start, head)
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	if _, err := full.Append(context.Background(), fixtureEvent(0)); !errors.Is(err, ErrJournalFull) {
		t.Fatal(err)
	}
	if !bytes.Equal(data, journalBytes(t, dir)) {
		t.Fatal("full journal modified")
	}
}
func TestLinuxJournalRejectsAliasesPermissionsReplacementAndMalformedData(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "fifo", "public-file", "public-directory", "replaced", "changed-record", "extra-tail", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			j, dir, start := createJournalFixture(t)
			end, err := j.Append(context.Background(), fixtureEvent(0))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir.Name(), journalName)
			before := journalBytes(t, dir)
			switch mode {
			case "symlink":
				if err := os.Rename(path, path+".preserved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".preserved", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Rename(path, path+".preserved"); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := dir.Chmod(0750); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				if err := os.Rename(path, path+".preserved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-record":
				changed := bytes.Replace(before, []byte("profile.write"), []byte("profile.delet"), 1)
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-tail":
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = file.Write([]byte("partial"))
				file.Close()
			case "oversize":
				if err := os.Truncate(path, MaxJournalBytes+1); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := j.Append(context.Background(), fixtureEvent(1)); err == nil || got != (Checkpoint{}) {
				t.Fatal("changed storage admitted", err)
			}
			_ = j.Close()
			// A byte-identical replacement under an independently trusted private
			// directory is acceptable to a new handle, but never to the original one.
			if mode == "replaced" {
				opened, err := OpenLinuxJournal(context.Background(), dir, start, end)
				if err != nil {
					t.Fatal(err)
				}
				opened.Close()
				return
			}
			opened, err := OpenLinuxJournal(context.Background(), dir, start, end)
			if err == nil {
				opened.Close()
				t.Fatal("unsafe storage reopened")
			}
			if strings.Contains(err.Error(), dir.Name()) {
				t.Fatal("private storage path in error")
			}
		})
	}
}

type interruptedJournalDisk struct {
	file    *os.File
	partial bool
}

func (d interruptedJournalDisk) WriteAt(data []byte, offset int64) (int, error) {
	if d.partial {
		data = data[:len(data)/2]
	}
	n, err := d.file.WriteAt(data, offset)
	if err != nil {
		return n, err
	}
	_, _ = os.Stdout.WriteString("written-before-sync\n")
	select {} // Parent kills this source-built test process at the actual write.
}
func (d interruptedJournalDisk) Sync() error { panic("interruption fixture reached sync") }

func TestLinuxJournalInterruptedWriterChild(t *testing.T) {
	mode := os.Getenv("ACCESSWEAVER_AUDIT_TEST_CHILD")
	if mode == "" {
		return
	}
	wire, err := base64.StdEncoding.DecodeString(os.Getenv("ACCESSWEAVER_AUDIT_TEST_GENESIS"))
	if err != nil {
		t.Fatal(err)
	}
	start, err := DecodeCheckpoint(wire)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(os.Getenv("ACCESSWEAVER_AUDIT_TEST_DIRECTORY"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	j, err := OpenLinuxJournal(context.Background(), dir, start, start)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.disk = interruptedJournalDisk{j.file, mode == "partial"}
	_, _ = j.Append(context.Background(), fixtureEvent(0))
	t.Fatal("interrupted append returned")
}
func TestLinuxJournalProcessKillRetainsUnacknowledgedBytesAndReleasesLock(t *testing.T) {
	for _, mode := range []string{"partial", "complete"} {
		t.Run(mode, func(t *testing.T) {
			j, dir, start := createJournalFixture(t)
			prior := journalBytes(t, dir)
			_ = j.Close()
			wire, _ := EncodeCheckpoint(start)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxJournalInterruptedWriterChild$")
			child.Env = append(os.Environ(), "ACCESSWEAVER_AUDIT_TEST_CHILD="+mode, "ACCESSWEAVER_AUDIT_TEST_GENESIS="+base64.StdEncoding.EncodeToString(wire), "ACCESSWEAVER_AUDIT_TEST_DIRECTORY="+dir.Name())
			output, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if child.Process != nil {
					_ = child.Process.Kill()
				}
			})
			line, err := bufio.NewReader(output).ReadString('\n')
			if err != nil || line != "written-before-sync\n" {
				_ = child.Process.Kill()
				_ = child.Wait()
				t.Fatal("child did not reach actual write", err, line)
			}
			if _, err := OpenLinuxJournal(context.Background(), dir, start, start); !errors.Is(err, ErrJournalBusy) {
				_ = child.Process.Kill()
				_ = child.Wait()
				t.Fatal("child did not hold lock", err)
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := child.Wait(); err == nil {
				t.Fatal("child unexpectedly exited successfully")
			}
			retained := journalBytes(t, dir)
			if len(retained) <= len(prior) || !bytes.HasPrefix(retained, prior) {
				t.Fatal("interrupted bytes or prior checkpoint lost")
			}
			requireJournalRefusal(t, dir, start, start)
			if mode == "complete" {
				_, end, _ := Append(start, fixtureEvent(0))
				reconciled, err := OpenLinuxJournal(context.Background(), dir, start, end)
				if err != nil {
					t.Fatal("explicit endpoint reconciliation or lock release failed", err)
				}
				reconciled.Close()
			}
			if !bytes.Equal(retained, journalBytes(t, dir)) {
				t.Fatal("interrupted evidence repaired or discarded")
			}
		})
	}
}

func TestLinuxJournalRejectsVolatileStorage(t *testing.T) {
	path, err := os.MkdirTemp("/dev/shm", "accessweaver-audit-volatile-")
	if err != nil {
		t.Skip("no private volatile filesystem fixture available")
	}
	defer os.Remove(path)
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	var filesystem syscall.Statfs_t
	if syscall.Fstatfs(int(dir.Fd()), &filesystem) != nil || uint64(filesystem.Type) != 0x01021994 {
		t.Skip("fixture is not tmpfs")
	}
	start, err := NewStream(fixtureProducer())
	if err != nil {
		t.Fatal(err)
	}
	if j, err := CreateLinuxJournal(dir, start); !errors.Is(err, ErrJournalStorage) {
		if j != nil {
			j.Close()
		}
		t.Fatal("volatile storage admitted", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused storage was modified", err)
	}
}

type cancelAfterWriteDisk struct {
	file   *os.File
	cancel context.CancelFunc
}

func (d cancelAfterWriteDisk) WriteAt(data []byte, offset int64) (int, error) {
	return d.file.WriteAt(data, offset)
}
func (d cancelAfterWriteDisk) Sync() error { d.cancel(); return d.file.Sync() }
func TestLinuxJournalCancellationDuringCommitReportsActualDurableOutcome(t *testing.T) {
	j, _, start := createJournalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j.disk = cancelAfterWriteDisk{j.file, cancel}
	head, err := j.Append(ctx, fixtureEvent(0))
	if err != nil || head.Sequence != start.Sequence+1 || ctx.Err() != context.Canceled {
		t.Fatal("committed record reported as absent", err)
	}
	_, _, retained, err := j.Snapshot(context.Background())
	if err != nil || retained != head {
		t.Fatal("committed record lost", err)
	}
}
func TestLinuxJournalZeroValueUnavailable(t *testing.T) {
	var j LinuxJournal
	if _, err := j.Append(context.Background(), fixtureEvent(0)); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal(err)
	}
	if _, _, _, err := j.Snapshot(context.Background()); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
}
