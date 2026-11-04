//go:build linux && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

func localDirectoryFixture(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(home, ".accessweaver-audit-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	return base
}
func TestLocalAuditInitializationReopensOnlyNativeKeyAndRetainedHead(t *testing.T) {
	directory := localDirectoryFixture(t)
	start, err := InitializeLocalJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if start.Sequence != 0 || !validProducer(start.Producer) {
		t.Fatal("invalid initialization")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatal("initialization created unexpected entries", err)
	}
	keyFile := filepath.Join(directory, actorKeyName)
	originalKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(originalKey) != actorKeyFileBytes {
		t.Fatal("key framing differs")
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("private initialization mode differs", err)
		}
	}
	j, err := OpenLocalJournal(context.Background(), directory, start, start)
	if err != nil {
		t.Fatal(err)
	}
	end, err := j.Append(context.Background(), fixtureEvent(0))
	if err != nil {
		t.Fatal(err)
	}
	data, from, to, err := j.Snapshot(context.Background())
	if err != nil || from != start || to != end {
		t.Fatal(err)
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(data), from, to); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, originalKey) || bytes.Contains(data, originalKey[len(actorKeyPrefix):]) {
		t.Fatal("private key in event output")
	}
	if other, err := OpenLocalJournal(context.Background(), directory, start, end); other != nil || !errors.Is(err, ErrJournalBusy) {
		t.Fatal("second local writer admitted", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, journalName))
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenLocalJournal(context.Background(), directory, start, start); err == nil {
		other.Close()
		t.Fatal("unknown tail adopted")
	}
	if _, err := InitializeLocalJournal(directory); err == nil {
		t.Fatal("existing initialization replaced")
	}
	after, _ := os.ReadFile(filepath.Join(directory, journalName))
	keyAfter, _ := os.ReadFile(keyFile)
	if !bytes.Equal(before, after) || !bytes.Equal(originalKey, keyAfter) {
		t.Fatal("refusal changed existing state")
	}
	reopened, err := OpenLocalJournal(context.Background(), directory, start, end)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}
func TestLocalAuditInitializationRefusesUnsafeOrNonemptyPathsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"nonempty", "partial-key", "missing", "relative", "alias", "writable-parent", "public-final"} {
		t.Run(kind, func(t *testing.T) {
			base := localDirectoryFixture(t)
			directory := filepath.Join(base, "audit")
			if kind != "missing" {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "nonempty":
				if err := os.WriteFile(filepath.Join(directory, "unrelated"), []byte("preserved"), 0600); err != nil {
					t.Fatal(err)
				}
			case "partial-key":
				if err := os.WriteFile(filepath.Join(directory, actorKeyName), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "relative":
				directory = "."
			case "alias":
				path := filepath.Join(base, "alias")
				if err := os.Symlink(directory, path); err != nil {
					t.Fatal(err)
				}
				directory = path
			case "writable-parent":
				if err := os.Chmod(base, 0770); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(base, 0700)
			case "public-final":
				if err := os.Chmod(directory, 0750); err != nil {
					t.Fatal(err)
				}
			}
			got, err := InitializeLocalJournal(directory)
			if !errors.Is(err, ErrJournalStorage) || got != (Checkpoint{}) || strings.Contains(err.Error(), base) {
				t.Fatal("unsafe initialization admitted or disclosed its path", err)
			}
			if kind == "missing" {
				if _, err := os.Stat(directory); !os.IsNotExist(err) {
					t.Fatal("missing path created")
				}
			}
			if kind == "nonempty" {
				data, _ := os.ReadFile(filepath.Join(directory, "unrelated"))
				if string(data) != "preserved" {
					t.Fatal("unrelated data changed")
				}
			}
			if kind == "partial-key" {
				data, err := os.ReadFile(filepath.Join(directory, actorKeyName))
				if err != nil || len(data) != 0 {
					t.Fatal("partial key repaired")
				}
			}
		})
	}
}
func TestLocalAuditKeyChangesRefuseBeforeAppendingAndPreserveJournal(t *testing.T) {
	for _, kind := range []string{"permissions", "missing", "key-change", "prefix", "short", "oversize", "zero", "alias", "hardlink", "build-change"} {
		t.Run(kind, func(t *testing.T) {
			directory := localDirectoryFixture(t)
			start, err := InitializeLocalJournal(directory)
			if err != nil {
				t.Fatal(err)
			}
			j, err := OpenLocalJournal(context.Background(), directory, start, start)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			path := filepath.Join(directory, actorKeyName)
			key, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(directory, journalName))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "permissions":
				err = os.Chmod(path, 0640)
			case "missing":
				err = os.Remove(path)
			case "key-change":
				key[len(key)-1] ^= 1
				err = os.WriteFile(path, key, 0600)
			case "prefix":
				key[0] ^= 1
				err = os.WriteFile(path, key, 0600)
			case "short":
				err = os.WriteFile(path, key[:len(key)-1], 0600)
			case "oversize":
				err = os.WriteFile(path, append(key, 0), 0600)
			case "zero":
				clear(key[len(actorKeyPrefix):])
				err = os.WriteFile(path, key, 0600)
			case "alias":
				err = os.Rename(path, path+".preserved")
				if err == nil {
					err = os.Symlink(path+".preserved", path)
				}
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "build-change":
				commit, state := buildinfo.Commit, buildinfo.SourceState
				buildinfo.Commit, buildinfo.SourceState = strings.Repeat("d", 40), "clean"
				defer func() { buildinfo.Commit, buildinfo.SourceState = commit, state }()
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := j.Append(context.Background(), fixtureEvent(0)); err == nil || got != (Checkpoint{}) {
				t.Fatal("changed key/producer admitted", err)
			}
			if _, err := j.Append(context.Background(), fixtureEvent(1)); !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("unavailable session retried", err)
			}
			after, err := os.ReadFile(filepath.Join(directory, journalName))
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("identity refusal changed journal", err)
			}
		})
	}
}
