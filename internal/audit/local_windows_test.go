//go:build windows && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"golang.org/x/sys/windows"
)

func windowsLocalTestDirectory(t *testing.T) (*nativeAuditFixture, string) {
	t.Helper()
	if _, optedIn := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST"); !optedIn {
		t.Skip("requires explicit disposable hosted Windows audit storage opt-in")
	}
	owner, err := nativeAuditHost()
	if err != nil {
		t.Fatal("invalid native local journal test host")
	}
	name := strings.NewReplacer("/", "-", "\\", "-", ":", "-").Replace(t.Name())
	f := &nativeAuditFixture{owner: owner, cleanupOK: true, reportName: "local-" + name, scope: "native-local-backend"}
	t.Cleanup(func() { f.finish(t) })
	if err := f.createRoot(); err != nil {
		t.Fatal("private local fixture root unavailable")
	}
	path := filepath.Join(f.root, "private")
	if err := f.directory(path); err != nil {
		t.Fatal("private local fixture directory unavailable")
	}
	return f, path
}

func windowsLocalFixture(t *testing.T) (*nativeAuditFixture, string, Checkpoint, Checkpoint, []byte) {
	t.Helper()
	f, directory := windowsLocalTestDirectory(t)
	start, err := initializeWindowsLocalJournal(directory)
	if err != nil {
		t.Fatal("local initialization failed", err)
	}
	for _, name := range []string{actorKeyName, journalName} {
		if err := f.record(filepath.Join(directory, name), false); err != nil {
			t.Fatal("initialized file cleanup identity unavailable")
		}
	}
	j, err := openWindowsLocalJournal(context.Background(), directory, start, start)
	if err != nil {
		t.Fatal("local open failed", err)
	}
	f.track(j.Close)
	head, err := j.Append(context.Background(), fixtureEvent(0))
	if err != nil {
		t.Fatal("local append failed", err)
	}
	segment, from, to, err := j.Snapshot(context.Background())
	if err != nil || from != start || to != head {
		t.Fatal("local snapshot endpoints differ")
	}
	if err := j.Close(); err != nil {
		t.Fatal("local close failed")
	}
	return f, directory, start, head, segment
}

func windowsLocalRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("owned fixture bytes unavailable")
	}
	return data
}

func TestWindowsLocalNativeRoundTripAndExactHead(t *testing.T) {
	f, directory, start, head, segment := windowsLocalFixture(t)
	key := windowsLocalRead(t, filepath.Join(directory, actorKeyName))
	defer clear(key)
	journal := windowsLocalRead(t, filepath.Join(directory, journalName))
	if len(key) != actorKeyFileBytes || bytes.Contains(segment, key[len(actorKeyPrefix):]) {
		t.Fatal("actor key framing or privacy differs")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(segment), start, head); err != nil {
		t.Fatal("retained local segment fails verification")
	}
	if other, err := openWindowsLocalJournal(context.Background(), directory, start, start); err == nil || other != nil {
		t.Fatal("unknown complete tail admitted")
	}
	if got, err := initializeWindowsLocalJournal(directory); err == nil || got != (Checkpoint{}) {
		t.Fatal("existing initialization replaced")
	}
	if !bytes.Equal(journal, windowsLocalRead(t, filepath.Join(directory, journalName))) || !bytes.Equal(key, windowsLocalRead(t, filepath.Join(directory, actorKeyName))) {
		t.Fatal("refusal changed retained journal or key")
	}
	j, err := openWindowsLocalJournal(context.Background(), directory, start, head)
	if err != nil {
		t.Fatal("exact-head reopen failed", err)
	}
	f.track(j.Close)
	if other, err := openWindowsLocalJournal(context.Background(), directory, start, head); other != nil || !errors.Is(err, ErrJournalBusy) {
		t.Fatal("second local writer admitted")
	}
	var out bytes.Buffer
	if err := exportWindowsLocalSegment(context.Background(), directory, start, head, &out); !errors.Is(err, ErrJournalBusy) || out.Len() != 0 {
		t.Fatal("export ignored active writer")
	}
	if err := j.Close(); err != nil || j.Close() != nil {
		t.Fatal("local repeated close failed")
	}
	if _, err := j.Append(context.Background(), fixtureEvent(1)); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("closed local writer admitted")
	}
	if err := exportWindowsLocalSegment(context.Background(), directory, start, head, &out); err != nil || !bytes.Equal(out.Bytes(), segment) {
		t.Fatal("closed current stream historical export failed", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatal("unexpected local initialization entries")
	}
}

func TestWindowsLocalNativeKeyLossAndHistoricalExport(t *testing.T) {
	for _, kind := range []string{"missing", "changed", "short", "zero", "build"} {
		t.Run(kind, func(t *testing.T) {
			f, directory, start, head, expected := windowsLocalFixture(t)
			j, err := openWindowsLocalJournal(context.Background(), directory, start, head)
			if err != nil {
				t.Fatal("fixture reopen failed")
			}
			f.track(j.Close)
			journalPath, keyPath := filepath.Join(directory, journalName), filepath.Join(directory, actorKeyName)
			key := windowsLocalRead(t, keyPath)
			defer clear(key)
			commit, state := buildinfo.Commit, buildinfo.SourceState
			defer func() { buildinfo.Commit, buildinfo.SourceState = commit, state }()
			switch kind {
			case "missing":
				err = os.Remove(keyPath)
				if err == nil {
					err = f.forget(keyPath)
				}
			case "changed":
				key[len(actorKeyPrefix)] ^= 0x80
				err = os.WriteFile(keyPath, key, 0600)
			case "short":
				err = os.WriteFile(keyPath, key[:len(key)-1], 0600)
			case "zero":
				clear(key[len(actorKeyPrefix):])
				err = os.WriteFile(keyPath, key, 0600)
			case "build":
				buildinfo.Commit, buildinfo.SourceState = strings.Repeat("e", 40), "clean"
			}
			if err != nil {
				t.Fatal("key-loss fixture mutation failed")
			}
			if got, err := j.Append(context.Background(), fixtureEvent(1)); err == nil || got != (Checkpoint{}) {
				t.Fatal("changed key or producer admitted")
			}
			if _, err := j.Append(context.Background(), fixtureEvent(1)); !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("poisoned local identity retried")
			}
			if err := j.Close(); err != nil {
				t.Fatal("identity-refused journal close failed")
			}
			before := windowsLocalRead(t, journalPath)
			if other, err := openWindowsLocalJournal(context.Background(), directory, start, head); err == nil || other != nil {
				t.Fatal("changed key or producer reopened current stream")
			}
			var out bytes.Buffer
			if err := exportWindowsLocalSegment(context.Background(), directory, start, head, &out); err != nil || !bytes.Equal(expected, out.Bytes()) {
				t.Fatal("historical export depends on key contents or current build", err)
			}
			if !bytes.Equal(before, windowsLocalRead(t, journalPath)) {
				t.Fatal("identity refusal or historical export changed journal")
			}
			if kind == "missing" {
				if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing key was recreated")
				}
			}
		})
	}
}

type windowsLocalChangedKeyDisk struct {
	file journalCommitter
	path string
}

func (d windowsLocalChangedKeyDisk) WriteAt(p []byte, off int64) (int, error) {
	return d.file.WriteAt(p, off)
}
func (d windowsLocalChangedKeyDisk) Sync() error {
	if err := d.file.Sync(); err != nil {
		return err
	}
	key := append([]byte(actorKeyPrefix), make([]byte, 32)...)
	defer clear(key)
	key[len(actorKeyPrefix)] = 1
	return os.WriteFile(d.path, key, 0600)
}
func TestWindowsLocalNativePostCommitKeyChangeSuppressesHead(t *testing.T) {
	f, directory, start, head, _ := windowsLocalFixture(t)
	raw, err := openWindowsLocalJournal(context.Background(), directory, start, head)
	if err != nil {
		t.Fatal("postcommit fixture reopen failed")
	}
	f.track(raw.Close)
	j := raw.(*localWindowsJournal)
	j.journal.disk = windowsLocalChangedKeyDisk{j.journal.file, filepath.Join(directory, actorKeyName)}
	got, err := j.Append(context.Background(), fixtureEvent(1))
	if !errors.Is(err, ErrJournalUncertain) || got != (Checkpoint{}) {
		t.Fatal("postcommit key change released successor")
	}
	if _, _, _, err := j.Snapshot(context.Background()); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("uncertain local session reused")
	}
	if err := j.Close(); err != nil {
		t.Fatal("uncertain local close failed")
	}
	line, next, err := Append(head, fixtureEvent(1))
	if err != nil {
		t.Fatal("expected successor unavailable")
	}
	if bytes.Count(windowsLocalRead(t, filepath.Join(directory, journalName)), line) != 1 {
		t.Fatal("uncertain bytes not retained exactly once")
	}
	var out bytes.Buffer
	if err := exportWindowsLocalSegment(context.Background(), directory, start, next, &out); err != nil {
		t.Fatal("independently reconciled historical tail refused")
	}
}

func TestWindowsLocalNativePartialInitializationPreserved(t *testing.T) {
	for _, name := range []string{actorKeyName, journalName, "unrelated"} {
		t.Run(name, func(t *testing.T) {
			f, directory := windowsLocalTestDirectory(t)
			path := filepath.Join(directory, name)
			before := []byte("preserve partial initialization")
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal("partial fixture unavailable")
			}
			if err := f.record(path, false); err != nil {
				t.Fatal("partial file cleanup identity unavailable")
			}
			if got, err := initializeWindowsLocalJournal(directory); err == nil || got != (Checkpoint{}) {
				t.Fatal("nonempty initialization admitted")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 || !bytes.Equal(before, windowsLocalRead(t, path)) {
				t.Fatal("partial initialization repaired or deleted")
			}
		})
	}
}

func TestWindowsLocalNativeExportOutputAliases(t *testing.T) {
	for _, name := range []string{actorKeyName, journalName} {
		for _, stream := range []string{"", ":alias-output"} {
			t.Run(name+stream, func(t *testing.T) {
				_, directory, start, head, _ := windowsLocalFixture(t)
				journalPath, keyPath := filepath.Join(directory, journalName), filepath.Join(directory, actorKeyName)
				journal, key := windowsLocalRead(t, journalPath), windowsLocalRead(t, keyPath)
				defer clear(key)
				out, err := os.OpenFile(filepath.Join(directory, name)+stream, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
				if err != nil {
					t.Fatal("native alias output fixture unavailable")
				}
				err = exportWindowsLocalSegment(context.Background(), directory, start, head, out)
				closeErr := out.Close()
				if !errors.Is(err, ErrExportDestination) || closeErr != nil {
					t.Fatal("direct or alternate-stream output alias admitted", err)
				}
				if !bytes.Equal(journal, windowsLocalRead(t, journalPath)) || !bytes.Equal(key, windowsLocalRead(t, keyPath)) {
					t.Fatal("alias refusal changed source bytes")
				}
			})
		}
	}
}

type windowsLocalWriterFunc func([]byte) (int, error)

func (f windowsLocalWriterFunc) Write(p []byte) (int, error) { return f(p) }
func TestWindowsLocalNativeExportRefusalsAndClosedBeforeOutput(t *testing.T) {
	f, directory, start, head, expected := windowsLocalFixture(t)
	var out bytes.Buffer
	if err := exportWindowsLocalSegment(context.Background(), directory, start, start, &out); err == nil || out.Len() != 0 {
		t.Fatal("stale historical endpoint emitted output")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := exportWindowsLocalSegment(ctx, directory, start, head, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("canceled historical export emitted output")
	}
	for _, writer := range []io.Writer{windowsLocalWriterFunc(func([]byte) (int, error) { return 0, nil }), windowsLocalWriterFunc(func([]byte) (int, error) { return 0, io.ErrClosedPipe })} {
		if err := exportWindowsLocalSegment(context.Background(), directory, start, head, writer); !errors.Is(err, ErrExportOutput) {
			t.Fatal("failed or partial output reported success")
		}
	}
	called := false
	writer := windowsLocalWriterFunc(func(p []byte) (int, error) {
		called = true
		j, err := openWindowsLocalJournal(context.Background(), directory, start, head)
		if err != nil {
			t.Fatal("export source still locked during output")
		}
		f.track(j.Close)
		if err := j.Close(); err != nil {
			t.Fatal("output observer close failed")
		}
		if !bytes.Equal(p, expected) {
			t.Fatal("export output changed after verification")
		}
		return len(p), nil
	})
	if err := exportWindowsLocalSegment(context.Background(), directory, start, head, writer); err != nil || !called {
		t.Fatal("export source cleanup/output ordering failed")
	}
}

func TestWindowsLocalNativeHistoricalRegularOutputWithoutReadableKey(t *testing.T) {
	for _, kind := range []string{"missing", "unreadable-content"} {
		t.Run(kind, func(t *testing.T) {
			f, directory, start, head, expected := windowsLocalFixture(t)
			keyPath := filepath.Join(directory, actorKeyName)
			if kind == "missing" {
				if err := os.Remove(keyPath); err != nil {
					t.Fatal("fixture key removal failed")
				}
				if err := f.forget(keyPath); err != nil {
					t.Fatal("removed fixture key registration differs")
				}
			} else {
				// Permit only owner metadata/control/delete, not content reading.
				// The exporter must use its metadata-only key identity probe.
				sd, err := windows.SecurityDescriptorFromString("O:" + f.owner + "D:P(D;;0x00000001;;;" + f.owner + ")(A;;0x001f0190;;;" + f.owner + ")(A;;FA;;;SY)")
				if err != nil || nativeAuditSetDescriptor(keyPath, sd) != nil {
					t.Fatal("unreadable-key fixture descriptor failed")
				}
				if h, err := nativeAuditRawOpen(keyPath, windows.FILE_READ_DATA); err == nil {
					_ = windows.CloseHandle(h)
					t.Fatal("unreadable-key fixture still permits content read")
				} else if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
					t.Fatal("unreadable-key fixture content refusal differs")
				}
			}
			outPath := filepath.Join(f.root, "historical-output.jsonl")
			out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal("historical regular output unavailable")
			}
			closeOutput := f.track(out.Close)
			if err := f.record(outPath, false); err != nil {
				t.Fatal("historical output cleanup identity unavailable")
			}
			if err := exportWindowsLocalSegment(context.Background(), directory, start, head, out); err != nil {
				t.Fatal("historical file export requires key data", err)
			}
			if err := closeOutput(); err != nil || !bytes.Equal(expected, windowsLocalRead(t, outPath)) {
				t.Fatal("historical file output differs")
			}
		})
	}
}

func TestWindowsLocalNativeHistoricalKeyHardlinkOutputRefused(t *testing.T) {
	f, directory, start, head, _ := windowsLocalFixture(t)
	keyPath := filepath.Join(directory, actorKeyName)
	key := windowsLocalRead(t, keyPath)
	defer clear(key)
	aliasPath := filepath.Join(f.root, "owned-key-alias")
	if err := os.Link(keyPath, aliasPath); err != nil {
		t.Fatal("historical key hardlink fixture unavailable")
	}
	if err := f.record(aliasPath, false); err != nil {
		t.Fatal("key alias cleanup identity unavailable")
	}
	out, err := os.OpenFile(aliasPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal("key hardlink output unavailable")
	}
	closeOutput := f.track(out.Close)
	exportErr := exportWindowsLocalSegment(context.Background(), directory, start, head, out)
	if err := closeOutput(); err != nil || !errors.Is(exportErr, ErrExportDestination) || !bytes.Equal(key, windowsLocalRead(t, keyPath)) {
		t.Fatal("historical key hardlink output admitted or mutated")
	}
}
