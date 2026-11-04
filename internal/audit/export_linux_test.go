//go:build linux && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"golang.org/x/sys/unix"
)

func exportFixture(t *testing.T) (string, Checkpoint, Checkpoint, []byte) {
	t.Helper()
	directory := localDirectoryFixture(t)
	start, err := InitializeLocalJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenLocalJournal(context.Background(), directory, start, start)
	if err != nil {
		t.Fatal(err)
	}
	end, err := j.Append(context.Background(), fixtureEvent(0))
	if err != nil {
		t.Fatal(err)
	}
	segment, _, _, err := j.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	return directory, start, end, segment
}
func TestLocalAuditExportHistoricalStreamWithoutKeyContentOrMutation(t *testing.T) {
	directory, start, end, expected := exportFixture(t)
	journalPath, keyPath := filepath.Join(directory, journalName), filepath.Join(directory, actorKeyName)
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	// A historical archive remains verifiable without the private key and under
	// a newer build. This must not silently become permission to append to it.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	commit, state := buildinfo.Commit, buildinfo.SourceState
	buildinfo.Commit, buildinfo.SourceState = strings.Repeat("e", 40), "clean"
	defer func() { buildinfo.Commit, buildinfo.SourceState = commit, state }()
	var out bytes.Buffer
	if err := ExportLocalSegment(context.Background(), directory, start, end, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, out.Bytes()) {
		t.Fatal("export differs from verified event bytes")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(out.Bytes()), start, end); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(journalPath)
	info, statErr := os.Stat(journalPath)
	if err != nil || statErr != nil || !bytes.Equal(before, after) || !original.ModTime().Equal(info.ModTime()) || !os.SameFile(original, info) {
		t.Fatal("read-only export changed journal", err, statErr)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("export recreated private state", err)
	}
	// FIFO identity may be inspected with O_PATH for a file-output guard, but
	// neither a key read nor a normal FIFO open is allowed to block export.
	if err := syscall.Mkfifo(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(localDirectoryFixture(t), "events-")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if err := ExportLocalSegment(context.Background(), directory, start, end, output); err != nil {
		t.Fatal("export read or required actor-key bytes", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatal("export removed key identity", err)
	}
}
func TestLocalAuditExportLockingAndExactEndpointsRefuseWithoutOutput(t *testing.T) {
	directory, start, end, _ := exportFixture(t)
	j, err := OpenLocalJournal(context.Background(), directory, start, end)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := ExportLocalSegment(context.Background(), directory, start, end, &out); !errors.Is(err, ErrJournalBusy) || out.Len() != 0 {
		t.Fatal("active writer ignored", err)
	}
	j.Close()
	held, err := os.Open(filepath.Join(directory, journalName))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := ExportLocalSegment(context.Background(), directory, start, end, &out); err != nil {
		t.Fatal("cooperating readers blocked", err)
	}
	if writer, err := OpenLocalJournal(context.Background(), directory, start, end); !errors.Is(err, ErrJournalBusy) {
		if writer != nil {
			writer.Close()
		}
		t.Fatal("reader did not exclude writer", err)
	}
	held.Close()
	for _, kind := range []string{"stale-head", "wrong-head", "wrong-genesis", "partial-tail", "alias", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			directory, from, to, _ := exportFixture(t)
			path := filepath.Join(directory, journalName)
			switch kind {
			case "stale-head":
				to = from
			case "wrong-head":
				to.SHA256 = strings.Repeat("f", 64)
			case "wrong-genesis":
				from, _ = NewStream(from.Producer)
			case "partial-tail":
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = file.Write([]byte("partial"))
				file.Close()
			case "alias":
				if err := os.Rename(path, path+".preserved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".preserved", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := ExportLocalSegment(context.Background(), directory, from, to, &output); err == nil || output.Len() != 0 || strings.Contains(err.Error(), directory) {
				t.Fatal("invalid snapshot exported or path leaked", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused export changed source", err)
			}
		})
	}
}
func TestLocalAuditExportRejectsSourceOrKeyOutputAliases(t *testing.T) {
	for _, name := range []string{journalName, actorKeyName} {
		t.Run(name, func(t *testing.T) {
			directory, start, end, _ := exportFixture(t)
			path := filepath.Join(directory, name)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			if err := ExportLocalSegment(context.Background(), directory, start, end, out); !errors.Is(err, ErrExportDestination) {
				t.Fatal("output aliased protected input", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("aliased output damaged source", err)
			}
		})
	}
}

type exportFaultWriter struct{ short bool }

func (w exportFaultWriter) Write(data []byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, errors.New("PRIVATE_DESTINATION_ERROR")
}

type exportAfterCloseWriter struct {
	t           *testing.T
	directory   string
	start, head Checkpoint
	bytes.Buffer
}

func (w *exportAfterCloseWriter) Write(data []byte) (int, error) {
	j, err := OpenLocalJournal(context.Background(), w.directory, w.start, w.head)
	if err != nil {
		w.t.Fatal("snapshot writer lock held during destination write", err)
	}
	j.Close()
	return w.Buffer.Write(data)
}
func TestLocalAuditExportOutputFailureCancellationAndClosedSource(t *testing.T) {
	directory, start, end, expected := exportFixture(t)
	source := filepath.Join(directory, journalName)
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, short := range []bool{false, true} {
		if err := ExportLocalSegment(context.Background(), directory, start, end, exportFaultWriter{short}); !errors.Is(err, ErrExportOutput) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("private output failure lost or disclosed", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := ExportLocalSegment(ctx, directory, start, end, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("canceled export emitted data", err)
	}
	receiver := &exportAfterCloseWriter{t: t, directory: directory, start: start, head: end}
	if err := ExportLocalSegment(context.Background(), directory, start, end, receiver); err != nil || !bytes.Equal(expected, receiver.Bytes()) {
		t.Fatal("verified closed snapshot differs", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("output failure changed source", err)
	}
	var _ io.Writer = receiver
}
