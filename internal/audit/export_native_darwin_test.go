//go:build darwin && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type darwinExportWriterFunc func([]byte) (int, error)

func (write darwinExportWriterFunc) Write(data []byte) (int, error) { return write(data) }

func darwinExportFixture(t *testing.T) (*darwinJournalFixture, Checkpoint, []byte) {
	t.Helper()
	f := newDarwinJournalFixture(t)
	journal := f.create(t)
	head, err := journal.Append(context.Background(), fixtureEvent(0))
	if err != nil {
		t.Fatal("prepare historical export event")
	}
	data, start, retained, err := journal.Snapshot(context.Background())
	if err != nil || start != f.start || retained != head || len(data) == 0 {
		t.Fatal("prepare historical export endpoints")
	}
	if journal.Close() != nil {
		t.Fatal("close historical export fixture writer")
	}
	return f, head, data
}

func TestDarwinExportHistoricalRoundTripClosesBeforeOutput(t *testing.T) {
	f, head, expected := darwinExportFixture(t)
	before := f.bytes(t)
	calls := 0
	writer := darwinExportWriterFunc(func(data []byte) (int, error) {
		calls++
		// A separately opened writer can acquire the actual data lock only after
		// export has released its SH owner. No inherited descriptor is used.
		file, err := f.dir.openRegular(journalName, true)
		if err != nil {
			t.Fatal("reopen data at export output boundary")
		}
		lockErr := lockDarwinAuditJournal(file, true)
		closeErr := file.Close()
		if lockErr != nil || closeErr != nil {
			t.Fatal("export retained a source data lock during output")
		}
		if !bytes.Equal(data, expected) {
			t.Fatal("historical export changed canonical event bytes")
		}
		return len(data), nil
	})
	if exportDarwinLocalSegment(context.Background(), f.path, f.start, head, writer) != nil || calls != 1 {
		t.Fatal("historical export failed its single output boundary")
	}
	if !bytes.Equal(before, f.bytes(t)) || f.dir.checkBinding() != nil {
		t.Fatal("historical export changed source storage")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(expected), f.start, head); err != nil {
		t.Fatal("historical export endpoints did not verify")
	}
}

func TestDarwinExportIgnoresHistoricalKeyContents(t *testing.T) {
	for _, mode := range []string{"absent", "framed", "truncated", "zero", "wrong-prefix", "unsafe-mode", "fifo", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			f, head, expected := darwinExportFixture(t)
			keyPath := filepath.Join(f.path, actorKeyName)
			var original []byte
			switch mode {
			case "absent":
			case "fifo":
				if unix.Mkfifo(keyPath, 0600) != nil {
					t.Fatal("prepare owned historical key FIFO")
				}
			case "symlink":
				target := filepath.Join(f.fixture.root, "historical-key-target")
				if os.WriteFile(target, []byte("historical-key-sentinel"), 0600) != nil || os.Symlink(target, keyPath) != nil {
					t.Fatal("prepare owned historical key symlink")
				}
			default:
				key := fixtureActorKey()
				original = append([]byte(actorKeyPrefix), key[:]...)
				clear(key[:])
				switch mode {
				case "truncated":
					original = original[:len(original)-1]
				case "zero":
					clear(original[len(actorKeyPrefix):])
				case "wrong-prefix":
					original[0] = '['
				}
				if os.WriteFile(keyPath, original, 0600) != nil {
					t.Fatal("prepare owned historical actor file")
				}
				if mode == "unsafe-mode" && os.Chmod(keyPath, 0644) != nil {
					t.Fatal("prepare historical actor mode")
				}
			}
			defer clear(original)

			var keyBefore darwinAuditNativeNode
			if mode != "absent" {
				keyBefore = darwinAuditFixtureNode(t, keyPath)
			}
			// A real regular destination exercises the metadata-only optional-key
			// probe even for FIFO and symlink keys. No key is opened for content.
			outputPath := filepath.Join(f.fixture.root, "archive.out")
			output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal("create owned historical output")
			}
			exportErr := exportDarwinLocalSegment(context.Background(), f.path, f.start, head, output)
			closeErr := output.Close()
			if exportErr != nil || closeErr != nil {
				t.Fatal("historical export depended on actor-key contents or admission")
			}
			actual, err := os.ReadFile(outputPath)
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatal("historical regular-file output differs")
			}
			if mode == "absent" {
				if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("historical export created an absent actor key")
				}
			} else if darwinAuditFixtureNode(t, keyPath) != keyBefore {
				t.Fatal("historical export changed actor-key metadata or identity")
			}
			if len(original) != 0 {
				retained, err := os.ReadFile(keyPath)
				same := bytes.Equal(retained, original)
				clear(retained)
				if err != nil || !same {
					t.Fatal("historical export changed actor-key bytes")
				}
			}
			if mode == "symlink" {
				retained, err := os.ReadFile(filepath.Join(f.fixture.root, "historical-key-target"))
				if err != nil || string(retained) != "historical-key-sentinel" {
					t.Fatal("historical export changed symlink target")
				}
			}
		})
	}
}

func TestDarwinExportRejectsDirectAndSymlinkOutputAliases(t *testing.T) {
	for _, name := range []string{journalName, actorKeyName} {
		for _, link := range []bool{false, true} {
			label := name
			if link {
				label += "-via-link"
			}
			t.Run(label, func(t *testing.T) {
				f, head, _ := darwinExportFixture(t)
				key := fixtureActorKey()
				keyBytes := append([]byte(actorKeyPrefix), key[:]...)
				clear(key[:])
				defer clear(keyBytes)
				if os.WriteFile(filepath.Join(f.path, actorKeyName), keyBytes, 0600) != nil {
					t.Fatal("prepare owned alias-control key")
				}
				before := f.bytes(t)
				target := filepath.Join(f.path, name)
				if link {
					alias := filepath.Join(f.fixture.root, "output-alias")
					if os.Symlink(target, alias) != nil {
						t.Fatal("prepare owned output alias")
					}
					target = alias
				}
				output, err := os.OpenFile(target, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal("open owned alias output without truncation")
				}
				exportErr := exportDarwinLocalSegment(context.Background(), f.path, f.start, head, output)
				closeErr := output.Close()
				retained, readErr := os.ReadFile(filepath.Join(f.path, actorKeyName))
				same := bytes.Equal(retained, keyBytes)
				clear(retained)
				if !errors.Is(exportErr, ErrExportDestination) || closeErr != nil || readErr != nil || !same || !bytes.Equal(before, f.bytes(t)) {
					t.Fatal("output alias refusal changed protected source bytes")
				}
			})
		}
	}
}

func TestDarwinExportRefusesBusyUnknownAndInvalidEndpointsWithoutOutput(t *testing.T) {
	f, head, _ := darwinExportFixture(t)
	before := f.bytes(t)
	writerCalls := 0
	output := darwinExportWriterFunc(func(data []byte) (int, error) { writerCalls++; return len(data), nil })
	held, err := openDarwinJournal(context.Background(), f.dir, f.start, head)
	if err != nil {
		t.Fatal("hold independent export exclusion writer")
	}
	f.track(t, held)
	if !errors.Is(exportDarwinLocalSegment(context.Background(), f.path, f.start, head, output), ErrJournalBusy) || writerCalls != 0 {
		t.Fatal("export wrote while an exclusive writer was held")
	}
	if held.Close() != nil {
		t.Fatal("release export exclusion writer")
	}
	foreign := f.start
	if foreign.StreamID[0] == 'f' {
		foreign.StreamID = "0" + foreign.StreamID[1:]
	} else {
		foreign.StreamID = "f" + foreign.StreamID[1:]
	}
	for _, endpoints := range [][2]Checkpoint{{{}, head}, {head, head}, {f.start, f.start}, {foreign, head}} {
		if exportDarwinLocalSegment(context.Background(), f.path, endpoints[0], endpoints[1], output) == nil || writerCalls != 0 {
			t.Fatal("export emitted bytes for unretained endpoints")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(exportDarwinLocalSegment(ctx, f.path, f.start, head, output), context.Canceled) || writerCalls != 0 {
		t.Fatal("precanceled export emitted output")
	}
	if !bytes.Equal(before, f.bytes(t)) {
		t.Fatal("export refusal changed journal storage")
	}
}

func TestDarwinExportPipeAndOutputFailures(t *testing.T) {
	f, head, expected := darwinExportFixture(t)
	before := f.bytes(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("create owned export output pipe")
	}
	defer darwinJournalClosePipe(t, reader)
	defer darwinJournalClosePipe(t, writer)
	if reader.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		t.Fatal("export output pipe deadline unavailable")
	}
	if exportDarwinLocalSegment(context.Background(), f.path, f.start, head, writer) != nil || writer.Close() != nil {
		t.Fatal("export refused a nonregular output descriptor")
	}
	actual, err := io.ReadAll(io.LimitReader(reader, int64(len(expected)+1)))
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("historical pipe output differs")
	}
	for _, mode := range []string{"short", "error", "zero"} {
		calls := 0
		output := darwinExportWriterFunc(func(data []byte) (int, error) {
			calls++
			switch mode {
			case "short":
				return len(data) / 2, nil
			case "error":
				return 0, os.ErrPermission
			default:
				return 0, nil
			}
		})
		if !errors.Is(exportDarwinLocalSegment(context.Background(), f.path, f.start, head, output), ErrExportOutput) || calls != 1 {
			t.Fatal("failed export output was retried or acknowledged")
		}
	}
	if !errors.Is(exportDarwinLocalSegment(context.Background(), f.path, f.start, head, nil), ErrExportOutput) {
		t.Fatal("nil historical output was admitted")
	}
	closed, err := os.OpenFile(filepath.Join(f.fixture.root, "closed.out"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil || closed.Close() != nil {
		t.Fatal("prepare closed export output")
	}
	if !errors.Is(exportDarwinLocalSegment(context.Background(), f.path, f.start, head, closed), ErrExportOutput) {
		t.Fatal("closed historical output was admitted")
	}
	if !bytes.Equal(before, f.bytes(t)) {
		t.Fatal("failed output changed source storage")
	}
}
