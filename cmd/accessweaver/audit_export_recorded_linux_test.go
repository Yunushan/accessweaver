//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
)

func captureRecordedExportCLI(t *testing.T, args []string) ([]byte, []byte, error) {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "events")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	observations, err := os.CreateTemp(t.TempDir(), "checkpoints")
	if err != nil {
		t.Fatal(err)
	}
	defer observations.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = out, observations
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	commandErr := execute(append([]string{"audit"}, args...))
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	checkpoints, err := os.ReadFile(observations.Name())
	if err != nil {
		t.Fatal(err)
	}
	return data, checkpoints, commandErr
}

func recordedExportNativeFixture(t *testing.T) (string, string, string, string, audit.Checkpoint) {
	t.Helper()
	base := auditedImportDirectory(t)
	directory := filepath.Join(base, "journal")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	start, err := audit.InitializeLocalJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	from, to := filepath.Join(base, "genesis.json"), filepath.Join(base, "head.json")
	writeRetainedCheckpoint(t, from, start)
	writeRetainedCheckpoint(t, to, start)
	return base, directory, from, to, start
}
func recordedExportNativeArgs(directory, from, to string) []string {
	return []string{"export-recorded", "--directory", directory, "--from", from, "--to", to, "--consent", "metadata-only"}
}

func TestRecordedExportRealCLIProtectedJournalAndSubsequentAccessRecords(t *testing.T) {
	base, directory, from, to, start := recordedExportNativeFixture(t)
	absent := filepath.Join(base, "no-profile-store")
	t.Setenv("ACCESSWEAVER_HOME", absent)
	j, err := audit.OpenLocalJournal(context.Background(), directory, start, start)
	if err != nil {
		t.Fatal(err)
	}
	// Canonical synthetic seed records provide a nonempty prior segment; only the
	// following access records describe actual commands performed by this test.
	for _, outcome := range []string{"intent", "completed"} {
		if _, err := j.Append(context.Background(), audit.Event{OccurredAt: time.Now().UTC(), OperationID: strings.Repeat("d", 32), Action: "profile.write", Outcome: outcome}); err != nil {
			j.Close()
			t.Fatal(err)
		}
	}
	prior, _, head, err := j.Snapshot(context.Background())
	if err != nil {
		j.Close()
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	writeRetainedCheckpoint(t, to, head)
	args := recordedExportNativeArgs(directory, from, to)
	events, observed, err := captureRecordedExportCLI(t, args)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(events, prior) {
		t.Fatal("recorded export included its own access or changed prior segment")
	}
	if verified, err := audit.VerifySegment(context.Background(), bytes.NewReader(events), start, head); err != nil || verified.Records != 2 {
		t.Fatal("recorded prior segment failed verification", err)
	}
	pair := decodeCheckpointObservations(t, observed)
	if len(pair) != 2 || pair[0].Sequence != 3 || pair[1].Sequence != 4 || pair[1].Producer != start.Producer {
		t.Fatal("recorded export checkpoints differ")
	}
	journalPath, keyPath := filepath.Join(directory, "events.journal"), filepath.Join(directory, ".actor-key")
	beforeJournal, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	data, checkpoints, err := captureRecordedExportCLI(t, args)
	if err == nil || len(data) != 0 || len(checkpoints) != 0 {
		t.Fatal("stale retained head exported or adopted a tail", err)
	}
	afterJournal, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(beforeJournal, afterJournal) {
		t.Fatal("stale export changed journal")
	}
	writeRetainedCheckpoint(t, to, pair[1])
	archived, second, err := captureRecordedExportCLI(t, args)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := audit.VerifySegment(context.Background(), bytes.NewReader(archived), start, pair[1]); err != nil || verified.Records != 4 {
		t.Fatal("second export did not include prior access pair", err)
	}
	records := bytes.Split(bytes.TrimSuffix(archived, []byte{'\n'}), []byte{'\n'})
	var intent, result struct {
		Event audit.Event `json:"event"`
	}
	if err := json.Unmarshal(records[2], &intent); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(records[3], &result); err != nil {
		t.Fatal(err)
	}
	if intent.Event.Action != "audit.export" || result.Event.Action != "audit.export" || intent.Event.Outcome != "intent" || result.Event.Outcome != "completed" || intent.Event.OperationID != result.Event.OperationID {
		t.Fatal("actual export access pairing differs")
	}
	next := decodeCheckpointObservations(t, second)
	if len(next) != 2 || next[0].Sequence != 5 || next[1].Sequence != 6 {
		t.Fatal("second observed access head differs")
	}
	writeRetainedCheckpoint(t, to, next[1])
	original, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	args[0] = "export"
	archive, err := captureAuditExecute(t, args)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := audit.VerifySegment(context.Background(), bytes.NewReader(archive), start, next[1]); err != nil || v.Records != 6 {
		t.Fatal("archive export lost latest access records", err)
	}
	afterJournal, err = os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(original, afterJournal) {
		t.Fatal("ordinary archive export became a mutation")
	}
	afterKey, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(key, afterKey) {
		t.Fatal("export altered actor key")
	}
	for _, output := range [][]byte{events, observed, archived, second, archive} {
		for _, private := range [][]byte{key, []byte(base), []byte(absent)} {
			if bytes.Contains(output, private) {
				t.Fatal("private storage identity escaped")
			}
		}
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatal("recorded export opened profile storage")
	}
}

func TestRecordedExportDirectAndHardLinkOutputsRefuseBeforeMutation(t *testing.T) {
	base, directory, from, to, _ := recordedExportNativeFixture(t)
	args := recordedExportNativeArgs(directory, from, to)
	for _, path := range []string{from, to, filepath.Join(directory, "events.journal"), filepath.Join(directory, ".actor-key")} {
		for _, hardLink := range []bool{false, true} {
			target := path
			if hardLink {
				target = filepath.Join(base, "output-alias")
				if err := os.Link(path, target); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			alias, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, swap := range []bool{false, true} {
				var out, observations io.Writer = alias, &bytes.Buffer{}
				if swap {
					out, observations = observations, out
				}
				if err := auditRecordedExportCommand(args, out, observations); !errors.Is(err, audit.ErrExportDestination) {
					t.Fatal("protected output alias admitted", path, hardLink, swap, err)
				}
			}
			if err := alias.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("output alias modified protected input")
			}
			if hardLink {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	mixed, err := os.CreateTemp(base, "mixed-output")
	if err != nil {
		t.Fatal(err)
	}
	defer mixed.Close()
	if err := auditRecordedExportCommand(args, mixed, mixed); !errors.Is(err, audit.ErrExportDestination) {
		t.Fatal("mixed checkpoint/event destination admitted", err)
	}
	if info, err := mixed.Stat(); err != nil || info.Size() != 0 {
		t.Fatal("mixed-output refusal emitted bytes")
	}
}

func TestRecordedExportRequiresCurrentActorKeyWithoutArchiveFallback(t *testing.T) {
	_, directory, from, to, _ := recordedExportNativeFixture(t)
	args := recordedExportNativeArgs(directory, from, to)
	keyPath, journalPath := filepath.Join(directory, ".actor-key"), filepath.Join(directory, "events.journal")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	key[len(key)-1] ^= 1
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	events, observations, err := captureRecordedExportCLI(t, args)
	if err == nil || len(events) != 0 || len(observations) != 0 {
		t.Fatal("changed actor key used historical producer", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("changed-key refusal mutated journal")
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	events, observations, err = captureRecordedExportCLI(t, args)
	if err == nil || len(events) != 0 || len(observations) != 0 {
		t.Fatal("missing key fell back to unrecorded export", err)
	}
	args[0] = "export"
	if data, err := captureAuditExecute(t, args); err != nil || len(data) != 0 {
		t.Fatal("ordinary empty archive export stopped supporting key loss", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("export recreated actor key")
	}
	after, err = os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("missing-key refusal changed journal")
	}
}
