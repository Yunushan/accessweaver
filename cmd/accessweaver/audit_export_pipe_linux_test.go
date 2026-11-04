//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// Test-only subprocess entry. Exit directly after the command: the Go test
// runner's own trailing PASS output must not write to the intentionally dead FD.
// The parent owns all fixture cleanup; no installed or elevated product runs.
func TestRecordedExportClosedStandardPipeWorker(t *testing.T) {
	mode := os.Getenv("ACCESSWEAVER_TEST_EXPORT_PIPE_MODE")
	if mode == "" {
		t.Skip("source-built closed-pipe subprocess only")
	}
	root := os.Getenv("ACCESSWEAVER_TEST_EXPORT_PIPE_ROOT")
	// Establish default handling in this disposable source-test process only.
	signal.Reset(syscall.SIGPIPE)
	args := recordedExportNativeArgs(filepath.Join(root, "journal"), filepath.Join(root, "genesis.json"), filepath.Join(root, "head.json"))
	var err error
	switch mode {
	case "events", "observations":
		err = execute(append([]string{"audit"}, args...))
	case "restore":
		if auditRecordedExportCommand(args, io.Discard, io.Discard) != nil {
			os.Exit(80)
		}
		_, _ = os.Stdout.Write([]byte("x"))
		os.Exit(81) // Must terminate with SIGPIPE after scope restoration.
	case "import":
		err = execute([]string{"audit", "import", "--directory", filepath.Join(root, "journal"), "--from", filepath.Join(root, "genesis.json"), "--to", filepath.Join(root, "head.json"), "--profile", filepath.Join(root, "profile.json")})
	case "policy":
		err = execute([]string{"audit", "policy-update", "--directory", filepath.Join(root, "journal"), "--from", filepath.Join(root, "genesis.json"), "--to", filepath.Join(root, "head.json"), "--input", filepath.Join(root, "policy.json")})
	case "initialize":
		err = execute([]string{"audit", "initialize", "--directory", filepath.Join(root, "new-journal")})
		if err == nil || !strings.HasPrefix(err.Error(), "audit initialization output unavailable;") {
			os.Exit(80)
		}
		os.Exit(79)
	case "ui":
		err = execute([]string{"audit", "ui", "--directory", filepath.Join(root, "journal"), "--from", filepath.Join(root, "genesis.json"), "--to", filepath.Join(root, "head.json")})
		if err == nil || err.Error() != "desktop startup output unavailable" {
			os.Exit(80)
		}
		lock, lockErr := filelock.TryAcquire(filepath.Join(os.Getenv("ACCESSWEAVER_HOME"), ".controller.lock"))
		if lockErr != nil {
			os.Exit(82)
		}
		if lock.Close() != nil {
			os.Exit(82)
		}
		os.Exit(79)
	default:
		os.Exit(83)
	}
	expected := audit.ErrRecordedUncertain
	if mode == "observations" || mode == "policy" {
		expected = audit.ErrRecorderUnavailable
	}
	if mode == "import" {
		expected = errAuditImportAdmission
	}
	if !errors.Is(err, expected) {
		os.Exit(80)
	}
	os.Exit(79)
}

func TestRecordedExportClosedStdoutAndStderrRetainAccurateOutcome(t *testing.T) {
	for _, mode := range []string{"events", "observations", "import", "policy", "initialize", "ui", "restore"} {
		t.Run(mode, func(t *testing.T) {
			base, directory, _, to, start := recordedExportNativeFixture(t)
			j, err := audit.OpenLocalJournal(context.Background(), directory, start, start)
			if err != nil {
				t.Fatal(err)
			}
			// A nonempty synthetic prior segment forces an actual stdout write.
			for _, outcome := range []string{"intent", "completed"} {
				if _, err := j.Append(context.Background(), audit.Event{OccurredAt: time.Now().UTC(), OperationID: strings.Repeat("e", 32), Action: "profile.write", Outcome: outcome}); err != nil {
					j.Close()
					t.Fatal(err)
				}
			}
			_, _, head, err := j.Snapshot(context.Background())
			if err != nil {
				j.Close()
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			writeRetainedCheckpoint(t, to, head)
			p := profile.New("pipe-denied-import", "PRIVATE_PIPE_PROFILE", "gost")
			p.Args = []string{"PRIVATE_PIPE_TOKEN"}
			profileBytes, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "profile.json"), profileBytes, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "policy.json"), []byte("PRIVATE_POLICY_MUST_NOT_DISPATCH"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(base, "new-journal"), 0700); err != nil {
				t.Fatal(err)
			}
			journalPath := filepath.Join(directory, "events.journal")
			before, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			defer writer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecordedExportClosedStandardPipeWorker$", "-test.count=1")
			profileRoot := filepath.Join(base, "no-profile-mutation")
			child.Env = append(os.Environ(), "ACCESSWEAVER_TEST_EXPORT_PIPE_MODE="+mode, "ACCESSWEAVER_TEST_EXPORT_PIPE_ROOT="+base, "ACCESSWEAVER_HOME="+profileRoot, "ACCESSWEAVER_NO_BROWSER=1")
			var events, observations bytes.Buffer
			if mode == "observations" || mode == "ui" {
				child.Stdout = &events
				child.Stderr = writer
			} else {
				child.Stdout = writer
				child.Stderr = &observations
			}
			runErr := child.Run()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(runErr, &exit) {
				t.Fatal("closed-pipe worker did not finish", mode, runErr, ctx.Err())
			}
			if mode == "restore" {
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGPIPE {
					t.Fatal("command leaked changed SIGPIPE handling", runErr)
				}
			} else if exit.ExitCode() != 79 {
				t.Fatal("closed standard pipe prevented conservative outcome return", mode, runErr)
			}
			after, err := os.ReadFile(journalPath)
			if err != nil || !bytes.HasPrefix(after, before) {
				t.Fatal("closed pipe changed prior journal bytes", err)
			}
			if mode == "initialize" {
				if !bytes.Equal(before, after) {
					t.Fatal("initialization changed another stream")
				}
				raw, err := os.ReadFile(filepath.Join(base, "new-journal", "events.journal"))
				if err != nil {
					t.Fatal("lost initialized journal", err)
				}
				initialized, err := audit.DecodeCheckpoint(raw)
				if err != nil || initialized.Sequence != 0 {
					t.Fatal("lost initialization genesis", err)
				}
				if _, err := os.Stat(filepath.Join(base, "new-journal", ".actor-key")); err != nil {
					t.Fatal("lost initialized actor key", err)
				}
				return
			}
			if mode == "ui" {
				if !bytes.Equal(before, after) || events.Len() != 0 {
					t.Fatal("startup-output refusal recorded or dispatched a profile mutation")
				}
				return
			}
			if mode == "import" || mode == "policy" {
				if _, err := os.Stat(profileRoot); !os.IsNotExist(err) {
					t.Fatal("unobserved intent dispatched profile storage")
				}
			}
			// Read-only assertions do not adopt an unknown tail or authenticate a head.
			lines := bytes.Split(bytes.TrimSuffix(after, []byte{'\n'}), []byte{'\n'})
			if len(lines) != 5 {
				t.Fatal("closed pipe did not retain both access records")
			}
			var intent, result struct {
				Event audit.Event `json:"event"`
			}
			if err := json.Unmarshal(lines[3], &intent); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(lines[4], &result); err != nil {
				t.Fatal(err)
			}
			outcome, action := "refused", "audit.export"
			if mode == "events" {
				outcome = "indeterminate"
			}
			if mode == "restore" {
				outcome = "completed"
			}
			if mode == "import" {
				action = "profile.import"
			}
			if mode == "policy" {
				action = "policy.update"
			}
			if intent.Event.Action != action || intent.Event.Outcome != "intent" || result.Event.Action != action || result.Event.Outcome != outcome || intent.Event.OperationID != result.Event.OperationID {
				t.Fatal("closed pipe outcome differs", mode)
			}
			if mode == "observations" && events.Len() != 0 {
				t.Fatal("export dispatched without observed intent")
			}
			if mode == "events" {
				pair := decodeCheckpointObservations(t, observations.Bytes())
				if len(pair) != 2 || pair[0].Sequence != 3 || pair[1].Sequence != 4 {
					t.Fatal("closed event pipe lost available observations")
				}
			}
			if bytes.Contains(after, []byte("PRIVATE_")) || bytes.Contains(observations.Bytes(), []byte("PRIVATE_")) {
				t.Fatal("private fixture input escaped audit output")
			}
		})
	}
}
