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

func auditedImportDirectory(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".accessweaver-audit-command-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	return root
}
func writeRetainedCheckpoint(t *testing.T, path string, checkpoint audit.Checkpoint) {
	t.Helper()
	data, err := audit.EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func decodeCheckpointObservations(t *testing.T, data []byte) []audit.Checkpoint {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
	checkpoints := []audit.Checkpoint{}
	for _, line := range lines {
		checkpoint, err := audit.DecodeCheckpoint(append(append([]byte(nil), line...), '\n'))
		if err != nil {
			t.Fatal("invalid canonical checkpoint output", err)
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	return checkpoints
}
func TestAuditedImportRealProfileWriteRevisionRefusalAndRetainedEndpoints(t *testing.T) {
	base := auditedImportDirectory(t)
	directory := filepath.Join(base, "audit")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "private-profiles")
	t.Setenv("ACCESSWEAVER_HOME", root)
	data, err := captureAuditExecute(t, []string{"initialize", "--directory", directory})
	if err != nil {
		t.Fatal(err)
	}
	initial := decodeCheckpointObservations(t, data)
	if len(initial) != 1 || initial[0].Sequence != 0 {
		t.Fatal("missing canonical genesis")
	}
	start := initial[0]
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("initialization created profile data")
	}
	fromPath, toPath, inputPath := filepath.Join(base, "retained-genesis.json"), filepath.Join(base, "retained-head.json"), filepath.Join(base, "PRIVATE_PROFILE_INPUT.json")
	writeRetainedCheckpoint(t, fromPath, start)
	writeRetainedCheckpoint(t, toPath, start)
	p := profile.New("audited-import", "PRIVATE_PROFILE_NAME", "gost")
	p.Args = []string{"PRIVATE_PROFILE_TOKEN"}
	input, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, input, 0600); err != nil {
		t.Fatal(err)
	}
	command := []string{"import", "--directory", directory, "--from", fromPath, "--to", toPath, "--profile", inputPath}
	data, err = captureAuditExecute(t, command)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := decodeCheckpointObservations(t, data)
	if len(checkpoints) != 2 || checkpoints[0].Sequence != 1 || checkpoints[1].Sequence != 2 {
		t.Fatal("missing intent/result observations")
	}
	end := checkpoints[1]
	if bytes.Contains(data, []byte("PRIVATE")) {
		t.Fatal("profile content in checkpoint output")
	}
	store, err := profile.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.Get(p.ID)
	if err != nil || saved.Name != p.Name || saved.Args[0] != p.Args[0] {
		t.Fatal("real profile import failed", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "profiles"))
	if err != nil || len(entries) != 1 {
		t.Fatal("import seeded unsolicited profiles", err)
	}
	checkJournal := func(head audit.Checkpoint, count int, wantLast string) {
		t.Helper()
		j, err := audit.OpenLocalJournal(context.Background(), directory, start, head)
		if err != nil {
			t.Fatal(err)
		}
		defer j.Close()
		segment, from, to, err := j.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		result, err := audit.VerifySegment(context.Background(), bytes.NewReader(segment), from, to)
		if err != nil || result.Records != count {
			t.Fatal("real journal verification failed", err)
		}
		if bytes.Contains(segment, []byte("PRIVATE")) {
			t.Fatal("profile content in audit journal")
		}
		rows := bytes.Split(bytes.TrimSuffix(segment, []byte{'\n'}), []byte{'\n'})
		var last struct {
			Event audit.Event `json:"event"`
		}
		if err := json.Unmarshal(rows[len(rows)-1], &last); err != nil || last.Event.Action != "profile.import" || last.Event.Outcome != wantLast {
			t.Fatal("actual terminal outcome differs", err)
		}
	}
	checkJournal(end, 2, "completed")
	writeRetainedCheckpoint(t, toPath, end)
	originalRevision := saved.UpdatedAt
	saved.Name = "PRIVATE_REVIEWED_EDIT"
	updated, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, updated, 0600); err != nil {
		t.Fatal(err)
	}
	data, err = captureAuditExecute(t, command)
	if err != nil {
		t.Fatal(err)
	}
	end = decodeCheckpointObservations(t, data)[1]
	current, err := store.Get(p.ID)
	if err != nil || current.Name != saved.Name || current.UpdatedAt.Equal(originalRevision) {
		t.Fatal("reviewed revision not applied", err)
	}
	checkJournal(end, 4, "completed")
	// A valid journal endpoint does not authorize overwriting a stale profile.
	writeRetainedCheckpoint(t, toPath, end)
	before, err := os.ReadFile(filepath.Join(root, "profiles", p.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	data, err = captureAuditExecute(t, command)
	if !errors.Is(err, errAuditImportRefused) {
		t.Fatal("stale reviewed profile overwrote current data", err)
	}
	end = decodeCheckpointObservations(t, data)[1]
	after, err := os.ReadFile(filepath.Join(root, "profiles", p.ID+".json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused import changed current profile", err)
	}
	checkJournal(end, 6, "refused")
	// A stale endpoint must refuse before even adding an audit intent.
	journalBefore, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil {
		t.Fatal(err)
	}
	writeRetainedCheckpoint(t, toPath, start)
	data, err = captureAuditExecute(t, command)
	if err == nil || len(data) != 0 {
		t.Fatal("stale endpoint adopted unknown records", err)
	}
	journalAfter, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil || !bytes.Equal(journalBefore, journalAfter) {
		t.Fatal("stale endpoint changed audit state", err)
	}
	inputAfter, err := os.ReadFile(inputPath)
	if err != nil || !bytes.Equal(updated, inputAfter) {
		t.Fatal("import changed its input file", err)
	}
}
func TestAuditedImportInvalidProfileRecordsRefusalWithoutCreatingProfileRoot(t *testing.T) {
	base := auditedImportDirectory(t)
	directory := filepath.Join(base, "audit")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "must-remain-absent")
	t.Setenv("ACCESSWEAVER_HOME", root)
	start, err := audit.InitializeLocalJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	checkpointPath, inputPath := filepath.Join(base, "retained.json"), filepath.Join(base, "PRIVATE_PROFILE.json")
	writeRetainedCheckpoint(t, checkpointPath, start)
	if err := os.WriteFile(inputPath, []byte(`{"id":"PRIVATE_INVALID"}`), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := captureAuditExecute(t, []string{"import", "--directory", directory, "--from", checkpointPath, "--to", checkpointPath, "--profile", inputPath})
	if !errors.Is(err, errAuditImportRefused) || bytes.Contains([]byte(err.Error()), []byte("PRIVATE")) || bytes.Contains(data, []byte("PRIVATE")) {
		t.Fatal("invalid import leaked or succeeded", err)
	}
	checkpoints := decodeCheckpointObservations(t, data)
	if len(checkpoints) != 2 || checkpoints[1].Sequence != 2 {
		t.Fatal("invalid input refusal was not recorded")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("refused malformed profile created data directories", err)
	}
	j, err := audit.OpenLocalJournal(context.Background(), directory, start, checkpoints[1])
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
}
func TestAuditInitializeOutputFailurePreservesExclusiveInitialization(t *testing.T) {
	directory := auditedImportDirectory(t)
	out := &importCheckpointWriter{failAt: 1}
	if err := auditInitializeCommand([]string{"initialize", "--directory", directory}, out); err == nil || bytes.Contains([]byte(err.Error()), []byte("PRIVATE")) {
		t.Fatal("initialization output failure leaked or disappeared", err)
	}
	keyBefore, err := os.ReadFile(filepath.Join(directory, ".actor-key"))
	if err != nil {
		t.Fatal(err)
	}
	journalBefore, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := auditInitializeCommand([]string{"initialize", "--directory", directory}, &bytes.Buffer{}); err == nil {
		t.Fatal("output failure retried by replacing the stream")
	}
	keyAfter, _ := os.ReadFile(filepath.Join(directory, ".actor-key"))
	journalAfter, _ := os.ReadFile(filepath.Join(directory, "events.journal"))
	if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(journalBefore, journalAfter) {
		t.Fatal("failed initialization output replaced persisted state")
	}
}
