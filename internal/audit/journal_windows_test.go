//go:build windows && (amd64 || arm64)

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
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func windowsJournalTestDirectory(t *testing.T) (*nativeAuditFixture, *windowsAuditDirectory) {
	t.Helper()
	if _, optedIn := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST"); !optedIn {
		t.Skip("requires explicit disposable hosted Windows audit storage opt-in")
	}
	owner, err := nativeAuditHost()
	if err != nil {
		t.Fatalf("invalid native journal test host: %v", err)
	}
	name := strings.NewReplacer("/", "-", "\\", "-").Replace(t.Name())
	f := &nativeAuditFixture{owner: owner, cleanupOK: true, reportName: "journal-" + name, scope: "native-journal"}
	t.Cleanup(func() { f.finish(t) })
	if err := f.createRoot(); err != nil {
		t.Fatal("exclusive private journal fixture root unavailable", err)
	}
	path := filepath.Join(f.root, "private")
	if err := f.directory(path); err != nil {
		t.Fatal(err)
	}
	dir, err := f.openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	return f, dir
}

func windowsJournalFixture(t *testing.T) (*windowsJournal, *windowsAuditDirectory, Checkpoint) {
	t.Helper()
	f, dir := windowsJournalTestDirectory(t)
	producer := fixtureProducer()
	producer.Target = "windows/" + runtime.GOARCH
	start, err := NewStream(producer)
	if err != nil {
		t.Fatal(err)
	}
	j, err := createWindowsJournal(dir, start)
	if err != nil {
		t.Fatal(err)
	}
	f.track(j.Close)
	if err := f.record(filepath.Join(dir.path, journalName), false); err != nil {
		t.Fatal("could not register the backend-created journal identity", err)
	}
	return j, dir, start
}

func windowsJournalHandleBytes(t *testing.T, file *os.File) []byte {
	t.Helper()
	data, err := io.ReadAll(io.NewSectionReader(file, 0, MaxJournalBytes+1))
	if err != nil || len(data) > MaxJournalBytes {
		t.Fatal("bounded journal fixture read failed", err)
	}
	return data
}

func windowsJournalDiskBytes(t *testing.T, dir *windowsAuditDirectory) []byte {
	t.Helper()
	file, err := dir.openRegular(journalName, false)
	if err != nil {
		t.Fatal(err)
	}
	data := windowsJournalHandleBytes(t, file)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return data
}

func windowsJournalRefusalPreservesBytes(t *testing.T, dir *windowsAuditDirectory, start, head Checkpoint) {
	t.Helper()
	before := windowsJournalDiskBytes(t, dir)
	opened, err := openWindowsJournal(context.Background(), dir, start, head)
	if opened != nil || err == nil {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("unreconciled journal was admitted")
	}
	if !bytes.Equal(before, windowsJournalDiskBytes(t, dir)) {
		t.Fatal("refused journal bytes changed")
	}
	if strings.Contains(err.Error(), dir.path) {
		t.Fatal("journal refusal disclosed its private path")
	}
}

func TestWindowsJournalCommitReadbackReopenAndConcurrency(t *testing.T) {
	j, dir, start := windowsJournalFixture(t)
	genesis, _ := EncodeCheckpoint(start)
	if got := windowsJournalHandleBytes(t, j.file); !bytes.Equal(got, genesis) {
		t.Fatal("initialization did not persist exactly the enrolled genesis")
	}
	const count = 12
	var wg sync.WaitGroup
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			if _, err := j.Append(context.Background(), fixtureEvent(index)); err != nil {
				t.Error(err)
			}
		}(index)
	}
	wg.Wait()
	segment, from, head, err := j.Snapshot(context.Background())
	if err != nil || from != start || head.Sequence != count {
		t.Fatal("concurrent append or snapshot failed", err)
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(segment), start, head); err != nil {
		t.Fatal(err)
	}
	retained := windowsJournalHandleBytes(t, j.file)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dir.checkBinding(); err != nil {
		t.Fatal("journal closed its borrowed directory", err)
	}
	if got, err := j.Append(context.Background(), fixtureEvent(0)); got != (Checkpoint{}) || err != ErrJournalUnavailable {
		t.Fatal("closed journal accepted append", err)
	}
	opened, err := openWindowsJournal(context.Background(), dir, start, head)
	if err != nil {
		t.Fatal(err)
	}
	again, _, reopenedHead, snapshotErr := opened.Snapshot(context.Background())
	closeErr := opened.Close()
	if snapshotErr != nil || closeErr != nil || reopenedHead != head || !bytes.Equal(segment, again) || !bytes.Equal(retained, windowsJournalDiskBytes(t, dir)) {
		t.Fatal("reopen changed verified evidence", snapshotErr, closeErr)
	}
	if created, err := createWindowsJournal(dir, start); created != nil || err != ErrJournalStorage {
		if created != nil {
			_ = created.Close()
		}
		t.Fatal("exclusive initialization replaced a journal", err)
	}
}

func TestWindowsJournalNativeByteRangeLocks(t *testing.T) {
	j, dir, start := windowsJournalFixture(t)
	other, err := dir.openRegular(journalName, true)
	if err != nil {
		t.Fatal("sharing flags prevented opening the lock contender", err)
	}
	if err := lockWindowsAuditJournal(other, true); err != ErrJournalBusy {
		t.Fatal("second data handle obtained exclusive lock", err)
	}
	if err := lockWindowsAuditJournal(other, false); err != ErrJournalBusy {
		t.Fatal("reader bypassed the writer lock", err)
	}
	if _, err := other.ReadAt(make([]byte, 1), 0); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatal("writer lock did not protect bytes through another handle", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := openWindowsJournal(context.Background(), dir, start, start); opened != nil || err != ErrJournalBusy {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("second writer admitted", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := dir.openRegular(journalName, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := dir.openRegular(journalName, false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := lockWindowsAuditJournal(first, false); err != nil {
		t.Fatal(err)
	}
	if err := lockWindowsAuditJournal(second, false); err != nil {
		t.Fatal("shared readers blocked each other", err)
	}
	if opened, err := openWindowsJournal(context.Background(), dir, start, start); opened != nil || err != ErrJournalBusy {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("writer bypassed shared reader locks", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := openWindowsJournal(context.Background(), dir, start, start)
	if err != nil {
		t.Fatal("closing readers did not release native locks", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

type windowsFaultJournalDisk struct {
	file                    *os.File
	mode                    string
	writes, syncs           int
	offset                  int64
	written                 []byte
	beforeWrite, beforeSync func()
}

func (disk *windowsFaultJournalDisk) WriteAt(data []byte, offset int64) (int, error) {
	disk.writes++
	disk.offset = offset
	disk.written = append([]byte(nil), data...)
	if disk.beforeWrite != nil {
		disk.beforeWrite()
	}
	switch disk.mode {
	case "disk-full":
		return 0, windows.ERROR_DISK_FULL
	case "partial", "short-no-error":
		n, err := disk.file.WriteAt(data[:len(data)/2], offset)
		if err != nil || disk.mode == "short-no-error" {
			return n, err
		}
		return n, io.ErrShortWrite
	case "acknowledged-without-write":
		return len(data), nil
	case "wrong-bytes":
		changed := append([]byte(nil), data...)
		changed[len(changed)-2] ^= 1
		return disk.file.WriteAt(changed, offset)
	default:
		return disk.file.WriteAt(data, offset)
	}
}

func (disk *windowsFaultJournalDisk) Sync() error {
	disk.syncs++
	if disk.beforeSync != nil {
		disk.beforeSync()
	}
	if disk.mode == "sync" {
		return windows.ERROR_WRITE_FAULT
	}
	return disk.file.Sync()
}

func TestWindowsJournalUncertainWritesPoisonAndPreserve(t *testing.T) {
	for _, mode := range []string{"disk-full", "partial", "short-no-error", "sync", "acknowledged-without-write", "wrong-bytes"} {
		t.Run(mode, func(t *testing.T) {
			j, dir, start := windowsJournalFixture(t)
			prior := windowsJournalHandleBytes(t, j.file)
			disk := &windowsFaultJournalDisk{file: j.file, mode: mode}
			j.disk = disk
			got, err := j.Append(context.Background(), fixtureEvent(0))
			if got != (Checkpoint{}) || err != ErrJournalUncertain || disk.writes != 1 || j.head != start || j.size != int64(len(prior)) {
				t.Fatal("uncertain write published a head or retried", err)
			}
			retained := windowsJournalHandleBytes(t, j.file)
			if !bytes.HasPrefix(retained, prior) {
				t.Fatal("prior acknowledged bytes changed")
			}
			if got, err := j.Append(context.Background(), fixtureEvent(1)); got != (Checkpoint{}) || err != ErrJournalUnavailable || disk.writes != 1 {
				t.Fatal("poisoned writer retried", err)
			}
			if data, from, head, err := j.Snapshot(context.Background()); data != nil || from != (Checkpoint{}) || head != (Checkpoint{}) || err != ErrJournalUnavailable {
				t.Fatal("poisoned journal released a snapshot", err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "disk-full", "acknowledged-without-write":
				if !bytes.Equal(prior, retained) {
					t.Fatal("zero-write fault changed bytes")
				}
				opened, err := openWindowsJournal(context.Background(), dir, start, start)
				if err != nil {
					t.Fatal(err)
				}
				if err := opened.Close(); err != nil {
					t.Fatal(err)
				}
			case "sync":
				windowsJournalRefusalPreservesBytes(t, dir, start, start)
				_, expected, _ := Append(start, fixtureEvent(0))
				opened, err := openWindowsJournal(context.Background(), dir, start, expected)
				if err != nil {
					t.Fatal("explicit complete-head reconciliation refused", err)
				}
				if err := opened.Close(); err != nil {
					t.Fatal(err)
				}
			default:
				windowsJournalRefusalPreservesBytes(t, dir, start, start)
			}
			wantSyncs := 1
			if mode == "disk-full" || mode == "partial" || mode == "short-no-error" {
				wantSyncs = 0
			}
			if disk.syncs != wantSyncs || !bytes.Equal(retained, windowsJournalDiskBytes(t, dir)) {
				t.Fatal("fault retried, repaired, or discarded bytes")
			}
		})
	}
}

func TestWindowsJournalCommitOrderingAndCancellationAfterFlush(t *testing.T) {
	j, _, start := windowsJournalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	priorSize := j.size
	disk := &windowsFaultJournalDisk{file: j.file}
	disk.beforeWrite = func() {
		if j.head != start || j.size != priorSize {
			t.Error("head published before write")
		}
	}
	disk.beforeSync = func() {
		if j.head != start || j.size != priorSize {
			t.Error("head published before flush")
		}
		cancel()
	}
	j.disk = disk
	expectedLine, expected, err := Append(start, fixtureEvent(0))
	if err != nil {
		t.Fatal(err)
	}
	head, err := j.Append(ctx, fixtureEvent(0))
	if err != nil || head != expected || ctx.Err() != context.Canceled || disk.writes != 1 || disk.syncs != 1 || disk.offset != priorSize || !bytes.Equal(disk.written, expectedLine) {
		t.Fatal("committed record was canceled, retried, or written at the wrong offset", err)
	}
	segment, from, retained, err := j.Snapshot(context.Background())
	if err != nil || from != start || retained != expected || !bytes.Equal(segment, expectedLine) {
		t.Fatal("verified committed record was not published", err)
	}
}

func TestWindowsJournalInvalidCanceledAndFullAdmissionsDoNotWrite(t *testing.T) {
	j, dir, start := windowsJournalFixture(t)
	prior := windowsJournalHandleBytes(t, j.file)
	disk := &windowsFaultJournalDisk{file: j.file}
	j.disk = disk
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := j.Append(ctx, fixtureEvent(0)); got != (Checkpoint{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("prewrite cancellation accepted", err)
	}
	if data, from, head, err := j.Snapshot(ctx); data != nil || from != (Checkpoint{}) || head != (Checkpoint{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled snapshot returned evidence", err)
	}
	invalid := fixtureEvent(0)
	invalid.Action = "private profile path"
	if got, err := j.Append(context.Background(), invalid); got != (Checkpoint{}) || err == nil || strings.Contains(err.Error(), invalid.Action) {
		t.Fatal("invalid event accepted or disclosed", err)
	}
	if disk.writes != 0 || disk.syncs != 0 || j.unavailable || !bytes.Equal(prior, windowsJournalHandleBytes(t, j.file)) {
		t.Fatal("prewrite refusal changed or poisoned storage")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// Populate a complete canonical fixture independently, preserving its native
	// creation ACL and file identity. This does not infer a production endpoint.
	head := start
	fullBytes := append([]byte(nil), prior...)
	for index := 0; index < MaxSegmentRecords; index++ {
		line, next, err := Append(head, fixtureEvent(index%60))
		if err != nil {
			t.Fatal(err)
		}
		fullBytes, head = append(fullBytes, line...), next
	}
	file, err := dir.openRegular(journalName, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitJournalBytes(file, fullBytes, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	full, err := openWindowsJournal(context.Background(), dir, start, head)
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	fullDisk := &windowsFaultJournalDisk{file: full.file}
	full.disk = fullDisk
	if got, err := full.Append(context.Background(), fixtureEvent(0)); got != (Checkpoint{}) || err != ErrJournalFull || fullDisk.writes != 0 || fullDisk.syncs != 0 || !bytes.Equal(fullBytes, windowsJournalHandleBytes(t, full.file)) {
		t.Fatal("full journal accepted or changed bytes", err)
	}
}

func TestWindowsJournalIndependentEndpointsAndPartialInitialization(t *testing.T) {
	j, dir, start := windowsJournalFixture(t)
	head, err := j.Append(context.Background(), fixtureEvent(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	windowsJournalRefusalPreservesBytes(t, dir, start, start)
	wrong := head
	if wrong.SHA256[0] == 'f' {
		wrong.SHA256 = "e" + wrong.SHA256[1:]
	} else {
		wrong.SHA256 = "f" + wrong.SHA256[1:]
	}
	windowsJournalRefusalPreservesBytes(t, dir, start, wrong)
	foreign, err := NewStream(start.Producer)
	if err != nil {
		t.Fatal(err)
	}
	windowsJournalRefusalPreservesBytes(t, dir, foreign, head)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := windowsJournalDiskBytes(t, dir)
	if opened, err := openWindowsJournal(ctx, dir, start, head); opened != nil || !errors.Is(err, context.Canceled) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("canceled open was admitted", err)
	}
	if !bytes.Equal(before, windowsJournalDiskBytes(t, dir)) {
		t.Fatal("canceled open changed bytes")
	}
	emptyFixture, emptyDir := windowsJournalTestDirectory(t)
	empty, err := emptyDir.createRegular(journalName)
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	if err := emptyFixture.record(filepath.Join(emptyDir.path, journalName), false); err != nil {
		t.Fatal("could not register the deliberately empty journal identity", err)
	}
	if created, err := createWindowsJournal(emptyDir, start); created != nil || err != ErrJournalStorage {
		if created != nil {
			_ = created.Close()
		}
		t.Fatal("interrupted initialization was replaced", err)
	}
	windowsJournalRefusalPreservesBytes(t, emptyDir, start, start)
}

func TestWindowsJournalPrewriteCorruptionPoisonsWithoutMutation(t *testing.T) {
	for _, operation := range []string{"append", "snapshot"} {
		t.Run(operation, func(t *testing.T) {
			j, _, _ := windowsJournalFixture(t)
			if _, err := j.Append(context.Background(), fixtureEvent(0)); err != nil {
				t.Fatal(err)
			}
			prior := windowsJournalHandleBytes(t, j.file)
			changed := bytes.Replace(prior, []byte("profile.write"), []byte("profile.delet"), 1)
			if bytes.Equal(prior, changed) || len(prior) != len(changed) {
				t.Fatal("corruption fixture did not change an equal-sized record")
			}
			if err := commitJournalBytes(j.file, changed, 0); err != nil {
				t.Fatal(err)
			}
			disk := &windowsFaultJournalDisk{file: j.file}
			j.disk = disk
			if operation == "append" {
				if got, err := j.Append(context.Background(), fixtureEvent(1)); got != (Checkpoint{}) || err != ErrJournalStorage {
					t.Fatal("prewrite corruption accepted", err)
				}
			} else if data, from, head, err := j.Snapshot(context.Background()); data != nil || from != (Checkpoint{}) || head != (Checkpoint{}) || err != ErrJournalStorage {
				t.Fatal("corrupt snapshot released evidence", err)
			}
			if disk.writes != 0 || disk.syncs != 0 || !bytes.Equal(changed, windowsJournalHandleBytes(t, j.file)) {
				t.Fatal("corruption refusal wrote, flushed, or repaired bytes")
			}
			if got, err := j.Append(context.Background(), fixtureEvent(2)); got != (Checkpoint{}) || err != ErrJournalUnavailable {
				t.Fatal("corrupt writer was reusable", err)
			}
		})
	}
}

func TestWindowsJournalIdentityMismatchBeforeAndAfterWrite(t *testing.T) {
	t.Run("before write", func(t *testing.T) {
		j, dir, _ := windowsJournalFixture(t)
		prior := windowsJournalHandleBytes(t, j.file)
		disk := &windowsFaultJournalDisk{file: j.file}
		j.disk = disk
		principal := dir.principal
		dir.principal.class = "changed-test-expectation"
		got, err := j.Append(context.Background(), fixtureEvent(0))
		dir.principal = principal
		if got != (Checkpoint{}) || err != ErrProcessIdentity || disk.writes != 0 || disk.syncs != 0 || !j.unavailable || !bytes.Equal(prior, windowsJournalHandleBytes(t, j.file)) {
			t.Fatal("changed principal expectation reached storage mutation", err)
		}
	})
	t.Run("after write", func(t *testing.T) {
		j, dir, start := windowsJournalFixture(t)
		priorSize := j.size
		principal := dir.principal
		defer func() { dir.principal = principal }()
		disk := &windowsFaultJournalDisk{file: j.file, beforeSync: func() { dir.principal.class = "changed-test-expectation" }}
		j.disk = disk
		got, err := j.Append(context.Background(), fixtureEvent(0))
		dir.principal = principal
		if got != (Checkpoint{}) || err != ErrJournalUncertain || !j.unavailable || j.head != start || j.size != priorSize || disk.writes != 1 || disk.syncs != 1 {
			t.Fatal("postwrite identity mismatch published an endpoint", err)
		}
		retained := windowsJournalHandleBytes(t, j.file)
		if int64(len(retained)) <= priorSize {
			t.Fatal("postwrite identity failure discarded bytes")
		}
		if err := j.Close(); err != nil {
			t.Fatal(err)
		}
		windowsJournalRefusalPreservesBytes(t, dir, start, start)
		_, expected, _ := Append(start, fixtureEvent(0))
		opened, err := openWindowsJournal(context.Background(), dir, start, expected)
		if err != nil {
			t.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(retained, windowsJournalDiskBytes(t, dir)) {
			t.Fatal("identity reconciliation changed bytes")
		}
	})
}

func TestWindowsJournalCloseCachesFailureAndBorrowsDirectory(t *testing.T) {
	f, dir := windowsJournalTestDirectory(t)
	producer := fixtureProducer()
	producer.Target = "windows/" + runtime.GOARCH
	start, err := NewStream(producer)
	if err != nil {
		t.Fatal(err)
	}
	j, err := createWindowsJournal(dir, start)
	if err != nil {
		t.Fatal(err)
	}
	f.track(func() error {
		// This case deliberately closes the file before the journal. The file
		// is already released, and the cached error is the asserted behavior.
		if err := j.Close(); err != ErrJournalStorage {
			return ErrJournalStorage
		}
		return nil
	})
	if err := f.record(filepath.Join(dir.path, journalName), false); err != nil {
		t.Fatal("could not register the close-fault journal identity", err)
	}
	if err := j.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != ErrJournalStorage {
		t.Fatal("close failure was hidden", err)
	}
	if err := j.Close(); err != ErrJournalStorage {
		t.Fatal("first close error was not retained", err)
	}
	if err := dir.checkBinding(); err != nil {
		t.Fatal("close failure revoked the borrowed directory", err)
	}
}

func TestWindowsJournalZeroValueUnavailable(t *testing.T) {
	var j windowsJournal
	if got, err := j.Append(context.Background(), fixtureEvent(0)); got != (Checkpoint{}) || err != ErrJournalUnavailable {
		t.Fatal(err)
	}
	if data, from, head, err := j.Snapshot(context.Background()); data != nil || from != (Checkpoint{}) || head != (Checkpoint{}) || err != ErrJournalUnavailable {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
}

type windowsInterruptedJournalDisk struct {
	file    *os.File
	partial bool
}

func (disk windowsInterruptedJournalDisk) WriteAt(data []byte, offset int64) (int, error) {
	if disk.partial {
		data = data[:len(data)/2]
	}
	n, err := disk.file.WriteAt(data, offset)
	if err != nil {
		return n, err
	}
	if _, err := os.Stdout.WriteString("written-before-sync\n"); err != nil {
		return n, err
	}
	for {
		time.Sleep(time.Second) // Keep a timer alive until the parent kills this fixture.
	}
}

func (windowsInterruptedJournalDisk) Sync() error { panic("interruption fixture reached sync") }

func TestWindowsJournalInterruptedWriterChild(t *testing.T) {
	mode := os.Getenv("ACCESSWEAVER_WINDOWS_AUDIT_JOURNAL_CHILD")
	if mode == "" {
		return
	}
	if mode != "partial" && mode != "complete" {
		t.Fatal("invalid source-built journal child mode")
	}
	if _, err := nativeAuditHost(); err != nil {
		t.Fatal("invalid disposable native child host", err)
	}
	wire, err := base64.StdEncoding.DecodeString(os.Getenv("ACCESSWEAVER_WINDOWS_AUDIT_JOURNAL_GENESIS"))
	if err != nil {
		t.Fatal("invalid child checkpoint encoding")
	}
	start, err := DecodeCheckpoint(wire)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := openWindowsAuditDirectory(os.Getenv("ACCESSWEAVER_WINDOWS_AUDIT_JOURNAL_DIRECTORY"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	j, err := openWindowsJournal(context.Background(), dir, start, start)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.disk = windowsInterruptedJournalDisk{j.file, mode == "partial"}
	_, _ = j.Append(context.Background(), fixtureEvent(0))
	t.Fatal("interrupted append returned")
}

func TestWindowsJournalKilledWriterPreservesBytesAndReleasesLock(t *testing.T) {
	for _, mode := range []string{"partial", "complete"} {
		t.Run(mode, func(t *testing.T) {
			j, dir, start := windowsJournalFixture(t)
			prior := windowsJournalHandleBytes(t, j.file)
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			wire, _ := EncodeCheckpoint(start)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsJournalInterruptedWriterChild$")
			child.Env = append(os.Environ(), "ACCESSWEAVER_WINDOWS_AUDIT_JOURNAL_CHILD="+mode, "ACCESSWEAVER_WINDOWS_AUDIT_JOURNAL_GENESIS="+base64.StdEncoding.EncodeToString(wire), "ACCESSWEAVER_WINDOWS_AUDIT_JOURNAL_DIRECTORY="+dir.path)
			output, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := child.Start(); err != nil {
				t.Fatal("source-built interruption child did not start")
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
				t.Fatal("child did not reach the actual write")
			}
			if opened, err := openWindowsJournal(context.Background(), dir, start, start); opened != nil || err != ErrJournalBusy {
				if opened != nil {
					_ = opened.Close()
				}
				_ = child.Process.Kill()
				_ = child.Wait()
				t.Fatal("interrupted child did not retain its native lock", err)
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal("could not interrupt source-built writer")
			}
			if err := child.Wait(); err == nil || ctx.Err() != nil {
				t.Fatal("interruption fixture exited successfully or timed out")
			}
			retained := windowsJournalDiskBytes(t, dir)
			if len(retained) <= len(prior) || !bytes.HasPrefix(retained, prior) {
				t.Fatal("interrupted bytes or prior checkpoint were lost")
			}
			windowsJournalRefusalPreservesBytes(t, dir, start, start)
			_, expected, _ := Append(start, fixtureEvent(0))
			if mode == "partial" {
				windowsJournalRefusalPreservesBytes(t, dir, start, expected)
			} else {
				reconciled, err := openWindowsJournal(context.Background(), dir, start, expected)
				if err != nil {
					t.Fatal("explicit complete-head reconciliation or lock release failed", err)
				}
				if err := reconciled.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(retained, windowsJournalDiskBytes(t, dir)) {
				t.Fatal("interrupted evidence was repaired or discarded")
			}
		})
	}
}
