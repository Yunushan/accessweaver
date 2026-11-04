package main

import (
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

func auditCommandFixture(t *testing.T) ([]string, []string) {
	t.Helper()
	base := t.TempDir()
	from, err := audit.NewStream(audit.Producer{ActorClass: "user", ActorSHA256: strings.Repeat("a", 64), SourceCommit: strings.Repeat("b", 40), SourceState: "clean", Target: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	line, to, err := audit.Append(from, audit.Event{OccurredAt: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), OperationID: strings.Repeat("c", 32), Action: "profile.write", Outcome: "intent"})
	if err != nil {
		t.Fatal(err)
	}
	fromData, _ := audit.EncodeCheckpoint(from)
	toData, _ := audit.EncodeCheckpoint(to)
	files := []string{filepath.Join(base, "from.json"), filepath.Join(base, "to.json"), filepath.Join(base, "events.jsonl")}
	for i, data := range [][]byte{fromData, toData, line} {
		if err := os.WriteFile(files[i], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"verify", "--events", files[2], "--from", files[0], "--to", files[1]}, files
}
func captureAuditExecute(t *testing.T, args []string) ([]byte, error) {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	previous := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = previous }()
	commandErr := execute(append([]string{"audit"}, args...))
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	return data, commandErr
}
func TestAuditCLIVerifiesWithoutCreatingProfilesOrChangingInputs(t *testing.T) {
	args, files := auditCommandFixture(t)
	home := filepath.Join(t.TempDir(), "must-remain-absent")
	t.Setenv("ACCESSWEAVER_HOME", home)
	original := map[string]string{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		original[path] = string(data)
	}
	data, err := captureAuditExecute(t, args)
	if err != nil {
		t.Fatal(err)
	}
	var report audit.Verification
	if err = json.Unmarshal(data, &report); err != nil || report.Records != 1 || !report.CheckpointHashesMatched || report.Scope != "checkpoint-matched-segment" {
		t.Fatal(string(data), err)
	}
	if _, err = os.Stat(home); !os.IsNotExist(err) {
		t.Fatal("audit created a profile root", err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != original[path] {
			t.Fatal("audit modified input", err)
		}
	}
	// Wrong final checkpoint never emits a partial success JSON.
	start, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(files[1], start, 0600); err != nil {
		t.Fatal(err)
	}
	data, err = captureAuditExecute(t, args)
	if err == nil || len(data) != 0 {
		t.Fatal("wrong head emitted success", string(data), err)
	}
	private := "PRIVATE_TOKEN /private/profile"
	if err = os.WriteFile(files[2], []byte(private), 0600); err != nil {
		t.Fatal(err)
	}
	data, err = captureAuditExecute(t, args)
	if err == nil || len(data) != 0 || strings.Contains(err.Error(), private) {
		t.Fatal("private malformed input escaped", err)
	}
}
func TestAuditArgumentsRefuseAmbiguityBeforeAnyRead(t *testing.T) {
	args, _ := auditCommandFixture(t)
	calls := 0
	reader := func(context.Context, string, int64) ([]byte, error) {
		calls++
		return nil, errors.New("should not read")
	}
	cases := [][]string{nil, {"verify"}, {"record", "--events", "private", "--from", "private", "--to", "private"}, append(append([]string{}, args...), "extra"), {"verify", "--events", "x", "--from", "y", "--from", "z"}, {"verify", "--token", "SECRET", "--from", "y", "--to", "z"}, {"verify", "--events", "", "--from", "y", "--to", "z"}}
	for _, args := range cases {
		report, err := verifyAuditArguments(context.Background(), args, reader)
		if err == nil || report != (audit.Verification{}) || calls != 0 || strings.Contains(err.Error(), "SECRET") {
			t.Fatal("ambiguous flags read data or leaked values", report, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifyAuditArguments(ctx, args, reader); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(err)
	}
}
func TestAuditInputSnapshotsRefuseAliasesAndLimitsWithoutRepair(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "PRIVATE_INPUT")
	if err := os.WriteFile(path, []byte("four"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readAuditInput(context.Background(), path, 4)
	if err != nil || string(data) != "four" {
		t.Fatal(string(data), err)
	}
	for _, input := range []string{path, root, filepath.Join(root, "PRIVATE_MISSING")} {
		data, err := readAuditInput(context.Background(), input, 3)
		if err == nil || data != nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid input accepted or path leaked", err)
		}
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(root, "link")
		if err := os.Symlink(path, link); err != nil {
			t.Skip("host cannot create test symlink")
		}
		if data, err := readAuditInput(context.Background(), link, 100); err == nil || data != nil {
			t.Fatal("symlink input accepted")
		}
	})
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "four" {
		t.Fatal("refusal repaired input", err)
	}
}
func TestAuditReadBudgetStopsBlockedWorkerAndPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		data, err := readAuditInputUsing(ctx, func() ([]byte, error) {
			close(entered)
			defer close(finished)
			<-release
			return []byte("late"), nil
		})
		if data != nil {
			result <- errors.New("late data returned")
			return
		}
		result <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read held command after cancellation")
	}
	close(release)
	<-finished
	called := false
	if data, err := readAuditInputUsing(ctx, func() ([]byte, error) { called = true; return nil, nil }); !errors.Is(err, context.Canceled) || data != nil || called {
		t.Fatal("pre-canceled command started a worker")
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := readAuditInputUsing(deadline, func() ([]byte, error) { t.Fatal("expired deadline read data"); return nil, nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestAuditOutputFailureDoesNotExposePrivateOutputPath(t *testing.T) {
	args, _ := auditCommandFixture(t)
	output, err := os.CreateTemp(t.TempDir(), "PRIVATE_AUDIT_OUTPUT")
	if err != nil {
		t.Fatal(err)
	}
	if err = output.Close(); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = previous }()
	for _, command := range [][]string{args, {"help"}} {
		err := auditCommand(command)
		if err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("output failure lost or exposed a private path", err)
		}
	}
}
