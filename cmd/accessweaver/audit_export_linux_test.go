//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestAuditExportCLIRealImportedRecordsVerifyAndNeverIncludeKeyOrProfile(t *testing.T) {
	base := auditedImportDirectory(t)
	directory := filepath.Join(base, "audit")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "profiles")
	t.Setenv("ACCESSWEAVER_HOME", root)
	start, err := audit.InitializeLocalJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	fromPath, toPath, inputPath := filepath.Join(base, "genesis.json"), filepath.Join(base, "head.json"), filepath.Join(base, "PRIVATE_PROFILE.json")
	writeRetainedCheckpoint(t, fromPath, start)
	writeRetainedCheckpoint(t, toPath, start)
	p := profile.New("exported-audit-test", "PRIVATE_PROFILE_NAME", "gost")
	p.Args = []string{"PRIVATE_PROFILE_TOKEN"}
	input, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, input, 0600); err != nil {
		t.Fatal(err)
	}
	checkpoints, err := captureAuditExecute(t, []string{"import", "--directory", directory, "--from", fromPath, "--to", toPath, "--profile", inputPath})
	if err != nil {
		t.Fatal(err)
	}
	head := decodeCheckpointObservations(t, checkpoints)[1]
	writeRetainedCheckpoint(t, toPath, head)
	journalPath, keyPath := filepath.Join(directory, "events.journal"), filepath.Join(directory, ".actor-key")
	originalJournal, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	profileBefore, err := os.ReadFile(filepath.Join(root, "profiles", p.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	command := []string{"export", "--directory", directory, "--from", fromPath, "--to", toPath, "--consent", "metadata-only"}
	events, err := captureAuditExecute(t, command)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.Split(bytes.TrimSuffix(events, []byte{'\n'}), []byte{'\n'})) != 2 || bytes.Contains(events, []byte("PRIVATE")) || bytes.Contains(events, key) {
		t.Fatal("export shape or redaction differs")
	}
	exported := filepath.Join(base, "events.jsonl")
	if err := os.WriteFile(exported, events, 0600); err != nil {
		t.Fatal(err)
	}
	verification, err := captureAuditExecute(t, []string{"verify", "--events", exported, "--from", fromPath, "--to", toPath})
	if err != nil {
		t.Fatal(err)
	}
	var report audit.Verification
	if err := json.Unmarshal(verification, &report); err != nil || report.Records != 2 || !report.CheckpointHashesMatched {
		t.Fatal("export did not round-trip verifier", err)
	}
	afterJournal, _ := os.ReadFile(journalPath)
	afterKey, _ := os.ReadFile(keyPath)
	afterProfile, _ := os.ReadFile(filepath.Join(root, "profiles", p.ID+".json"))
	if !bytes.Equal(originalJournal, afterJournal) || !bytes.Equal(key, afterKey) || !bytes.Equal(profileBefore, afterProfile) {
		t.Fatal("export mutated source/key/profile")
	}
	// A stale retained endpoint emits no prefix of a success artifact.
	writeRetainedCheckpoint(t, toPath, start)
	if data, err := captureAuditExecute(t, command); err == nil || len(data) != 0 {
		t.Fatal("stale-head export emitted data", err)
	}
	writeRetainedCheckpoint(t, toPath, head)
	// Reject direct stdout aliases even when append mode preserves input until
	// the command begins. Shell truncation before process start is external.
	for _, path := range []string{fromPath, toPath, journalPath, keyPath} {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		commandErr := auditExportCommand(command, out)
		closeErr := out.Close()
		if !errors.Is(commandErr, audit.ErrExportDestination) || closeErr != nil {
			t.Fatal("input/storage stdout alias admitted", commandErr, closeErr)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("export stdout alias damaged input", err)
		}
	}
	// Key loss does not force an archive exporter to create/rewrite private state.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if data, err := captureAuditExecute(t, command); err != nil || !bytes.Equal(data, events) {
		t.Fatal("archive export required or recreated private key", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("export recreated key", err)
	}
	j, err := audit.OpenLinuxJournal(context.Background(), mustOpenAuditDirectory(t, directory), start, head)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
}
func mustOpenAuditDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}
