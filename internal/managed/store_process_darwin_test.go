//go:build darwin && (amd64 || arm64)

package managed

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type darwinProcessFixture struct {
	Parent     string
	Initial    bool
	Publish    bool
	Source     []byte
	Acceptance []byte
	Checkpoint string
}

// This helper receives only an owned temporary fixture. It never selects the
// fixed machine source, and intentionally does not register transaction cleanup.
func TestNativeDarwinPolicyProcessHelper(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DARWIN_PROCESS_FIXTURE") != "1" {
		return
	}
	var fixture darwinProcessFixture
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 4*MaxInstallationBytes)).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(fixture.Parent) || !strings.HasPrefix(filepath.Base(fixture.Parent), "accessweaver-policy-process-") {
		t.Fatal("refusing non-fixture parent")
	}
	parent, err := os.Open(fixture.Parent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := beginDarwinInstallationObserved(parent, fixture.Initial, uint32(os.Geteuid()), func(tx *darwinInstallationTransaction, checkpoint string) {
		if checkpoint == fixture.Checkpoint {
			waitForDarwinProcessKill(t, tx)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tx.Read(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tx.ReadAcceptance(); err != nil {
		t.Fatal(err)
	}
	if err := tx.StageAccepted(fixture.Source, fixture.Acceptance); err != nil {
		t.Fatal(err)
	}
	if fixture.Publish {
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if !tx.Published() {
			t.Fatal("publication outcome missing")
		}
	}
	if fixture.Checkpoint != "" {
		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("selected transaction boundary was not reached", fixture.Checkpoint)
	}
	waitForDarwinProcessKill(t, tx)
}

func waitForDarwinProcessKill(t *testing.T, tx *darwinInstallationTransaction) {
	t.Helper()
	if _, err := fmt.Fprintln(os.Stdout, "policy-process-ready"); err != nil {
		t.Fatal(err)
	}
	// The parent retains this pipe until SIGKILL, so no Close/defer path runs.
	_, copyErr := io.Copy(io.Discard, os.Stdin)
	runtime.KeepAlive(tx) // Keep file finalizers from releasing the lock while waiting.
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	t.Fatal("fixture exited without the expected forced termination")
}

func TestDarwinPairSurvivesProcessTermination(t *testing.T) {
	for _, initial := range []bool{true, false} {
		for _, publish := range []bool{false, true} {
			name := fmt.Sprintf("initial=%t/published=%t", initial, publish)
			t.Run(name, func(t *testing.T) {
				prior, next, public, private, now := renewalFixture(t)
				parent, err := os.MkdirTemp(t.TempDir(), "accessweaver-policy-process-")
				if err != nil {
					t.Fatal(err)
				}
				before := machineSnapshot{}
				candidate := prior
				if !initial {
					darwinFixtureInstall(t, parent, prior, now)
					before = darwinStoredPair(t, parent)
					candidate, _, err = installationTransition(before.source, next, nil, false, now)
					if err != nil {
						t.Fatal(err)
					}
				}
				source, acceptance, err := prepareNativeAcceptance(candidate, now)
				if err != nil {
					t.Fatal(err)
				}
				expected := before
				if publish {
					expected = machineSnapshot{source: source, acceptance: acceptance, present: true, acceptancePresent: true}
				}
				lockInfo := killDarwinTransactionChild(t, darwinProcessFixture{Parent: parent, Initial: initial, Publish: publish, Source: source, Acceptance: acceptance})

				parentFD, err := os.Open(parent)
				if err != nil {
					t.Fatal(err)
				}
				observed, readErr := readDarwinSnapshotAt(parentFD, uint32(os.Geteuid()))
				if err := errors.Join(readErr, parentFD.Close()); err != nil {
					t.Fatal(err)
				}
				if observed.present != expected.present || !equalDarwinPair(observed, expected) {
					t.Fatal("forced exit exposed a missing, mixed or unexpected generation")
				}
				if observed.present {
					if _, history, err := decodeMachineSnapshot(observed, now); err != nil || history == nil {
						t.Fatal("active pair lost accepted history", err)
					}
				}
				stages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
				if err != nil {
					t.Fatal(err)
				}
				wantStages := 1
				if initial && publish {
					wantStages = 0
				}
				if len(stages) != wantStages {
					t.Fatalf("abandoned stage count: got %d want %d", len(stages), wantStages)
				}
				var stageInfo os.FileInfo
				var abandoned machineSnapshot
				if len(stages) == 1 {
					stageInfo, err = os.Lstat(stages[0])
					if err != nil {
						t.Fatal(err)
					}
					dir, err := os.Open(stages[0])
					if err != nil {
						t.Fatal(err)
					}
					abandoned, readErr = readDarwinPolicyPair(dir, uint32(os.Geteuid()))
					if err := errors.Join(readErr, dir.Close()); err != nil {
						t.Fatal(err)
					}
					want := machineSnapshot{source: source, acceptance: acceptance, acceptancePresent: true}
					if publish {
						want = before
					}
					if !equalDarwinPair(abandoned, want) {
						t.Fatal("abandoned generation changed")
					}
					// A restart must preserve even an independently changed abandoned stage.
					abandoned.source = append(bytes.Clone(abandoned.source), ' ')
					if err := os.WriteFile(filepath.Join(stages[0], darwinPolicyFile), abandoned.source, 0644); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(stages[0], "unrelated"), []byte("preserve"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				retry := darwinFixtureTransaction(t, parent, initial && !publish)
				currentLock, err := retry.lock.Stat()
				if err != nil || !os.SameFile(lockInfo, currentLock) {
					t.Fatal("restart replaced the coordination namespace", err)
				}
				operation := changeUpdate
				input := next
				if initial && !publish {
					operation = changeInstall
					input = prior
				}
				if !initial && publish {
					payload, err := json.Marshal(Policy{SchemaVersion: 1, Revision: 4, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
					if err != nil {
						t.Fatal(err)
					}
					input, err = Sign(payload, private, now)
					if err != nil {
						t.Fatal(err)
					}
				}
				result, err := commitInstallation(retry, input, public, operation, func() time.Time { return now })
				if err != nil || !result.Committed {
					t.Fatal("restart could not commit after writer death", result, err)
				}
				if _, history, err := decodeMachineSnapshot(darwinStoredPair(t, parent), now); err != nil || history == nil || history.revision != result.Revision {
					t.Fatal("restart pair invalid", err)
				}
				if len(stages) == 1 {
					after, err := os.Lstat(stages[0])
					if err != nil || !os.SameFile(stageInfo, after) {
						t.Fatal("restart removed or replaced abandoned identity", err)
					}
					dir, err := os.Open(stages[0])
					if err != nil {
						t.Fatal(err)
					}
					retained, readErr := readDarwinPolicyPair(dir, uint32(os.Geteuid()))
					if err := errors.Join(readErr, dir.Close()); err != nil || !equalDarwinPair(retained, abandoned) {
						t.Fatal("restart changed abandoned pair", err)
					}
					if value, err := os.ReadFile(filepath.Join(stages[0], "unrelated")); err != nil || string(value) != "preserve" {
						t.Fatal("restart removed unrelated bytes", err)
					}
				}
				afterStages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
				if err != nil || len(afterStages) != wantStages {
					t.Fatal("restart changed the abandoned namespace", err)
				}
			})
		}
	}
}

func killDarwinTransactionChild(t *testing.T, fixture darwinProcessFixture) os.FileInfo {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestNativeDarwinPolicyProcessHelper$", "-test.timeout=25s")
	child.Env = append(os.Environ(), "ACCESSWEAVER_DARWIN_PROCESS_FIXTURE=1")
	var stderr bytes.Buffer
	child.Stderr = &stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			child.Process.Kill()
			child.Wait()
		}
	}()
	if err := json.NewEncoder(stdin).Encode(fixture); err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(stdout, 512)).ReadString('\n')
		if err == nil && line != "policy-process-ready\n" {
			err = fmt.Errorf("unexpected helper output %q", line)
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal("helper did not reach its boundary", err)
		}
	case <-ctx.Done():
		t.Fatal("helper boundary timed out", ctx.Err())
	}
	lock, err := os.OpenFile(filepath.Join(fixture.Parent, darwinPolicyLock), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lockInfo, err := lock.Stat()
	if err != nil {
		lock.Close()
		t.Fatal(err)
	}
	lockErr := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if lockErr == nil {
		unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	}
	lock.Close()
	if !errors.Is(lockErr, unix.EWOULDBLOCK) && !errors.Is(lockErr, unix.EAGAIN) {
		t.Fatal("child did not hold writer lock", lockErr)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	waited = true
	var exited *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exited) {
		t.Fatalf("expected forced exit: %v; %s", err, stderr.Bytes())
	}
	status, ok := exited.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected termination: %v; %s", err, stderr.Bytes())
	}
	return lockInfo
}
