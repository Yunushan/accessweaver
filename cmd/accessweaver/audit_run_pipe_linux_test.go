//go:build linux && (amd64 || arm64)

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"golang.org/x/sys/unix"
)

// Both gates ultimately write the worker's real failed standard descriptor.
// Waiting for an owned PID avoids racing cleanup against the inert child's init;
// the second-checkpoint gate also lets the parent deterministically close FD1.
// Neither gate fabricates EPIPE or supplies an engine/audit implementation.
type recordedEngineStandardOutput struct {
	file               *os.File
	pid, closed        string
	acceptedCheckpoint bool
	writes             int
}

func (w *recordedEngineStandardOutput) Write(data []byte) (int, error) {
	w.writes++
	if !w.acceptedCheckpoint || w.writes == 2 {
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, pidErr := os.Stat(w.pid)
			closed := w.closed == ""
			if !closed {
				_, err := os.Stat(w.closed)
				closed = err == nil
			}
			if pidErr == nil && closed {
				break
			}
			if time.Now().After(deadline) {
				return 0, errors.New("source-test pipe gate was not released")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	return w.file.Write(data)
}

func TestRecordedEngineClosedStandardPipeWorker(t *testing.T) {
	mode := os.Getenv("ACCESSWEAVER_TEST_RECORDED_ENGINE_PIPE_MODE")
	if mode == "" {
		t.Skip("source-built closed-standard-descriptor subprocess only")
	}
	if mode != "intent" && mode != "accepted" && mode != "notice" {
		t.Fatal("invalid source-test pipe mode")
	}
	base := os.Getenv("ACCESSWEAVER_TEST_RECORDED_ENGINE_PIPE_ROOT")
	pidFile := filepath.Join(base, "owned-child.pid")
	signal.Reset(syscall.SIGPIPE) // Isolated source-test process only.
	args := []string{"run", "--directory", filepath.Join(base, "journal"), "--from", filepath.Join(base, "genesis.json"), "--to", filepath.Join(base, "head.json"), "--profile", filepath.Join(base, "PRIVATE_ENGINE_PROFILE.json"), "--consent", "metadata-only"}
	var commandErr error
	switch mode {
	case "intent":
		// Exercise actual CLI dispatch with FD1 closed before command startup.
		commandErr = execute(append([]string{"audit"}, args...))
	case "accepted":
		out := &recordedEngineStandardOutput{file: os.Stdout, pid: pidFile, closed: filepath.Join(base, "stdout-reader-closed"), acceptedCheckpoint: true}
		commandErr = auditRunCommand(args, out, os.Stderr)
	case "notice":
		notice := &recordedEngineStandardOutput{file: os.Stderr, pid: pidFile}
		commandErr = auditRunCommand(args, os.Stdout, notice)
	}
	if mode == "intent" {
		if !errors.Is(commandErr, audit.ErrRecorderUnavailable) {
			t.Fatal("unobserved intent lost its no-dispatch admission failure", commandErr)
		}
	} else if !errors.Is(commandErr, audit.ErrRecordedUncertain) {
		t.Fatal("post-launch pipe loss falsely reported a no-dispatch or successful outcome", commandErr)
	}
	if mode == "notice" && !errors.Is(commandErr, errEngineLaunchOutput) {
		t.Fatal("failed notice lost its fixed local output error", commandErr)
	}
	if mode == "intent" {
		if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
			t.Fatal("unobserved intent dispatched an inert child")
		}
	} else {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatal("pipe failure never reached an actual running inert child", err)
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil || pid <= 0 {
			t.Fatal("invalid owned inert PID")
		}
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatal("pipe failure left the owned inert child alive or unreaped", err)
		}
	}
	assertRecordedEngineNoInventory(t, os.Getenv("ACCESSWEAVER_HOME"))
	for _, path := range []string{filepath.Join(base, "journal", "events.journal"), filepath.Join(os.Getenv("ACCESSWEAVER_HOME"), ".controller.lock")} {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal("command did not leave its expected owned coordination file", err)
		}
		lockErr := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if lockErr == nil {
			lockErr = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		}
		closeErr := file.Close()
		if lockErr != nil || closeErr != nil {
			t.Fatal("pipe command released output before native journal/controller cleanup", lockErr, closeErr)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "pipe-cleanup-proved"), []byte(mode+": no child remains and both owning scopes closed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Production scope restoration must precede return. A fresh write to that
	// same failed standard descriptor must now use default SIGPIPE behavior.
	if mode == "notice" {
		_, _ = os.Stderr.Write([]byte("scope restored\n"))
	} else {
		_, _ = os.Stdout.Write([]byte("scope restored\n"))
	}
	os.Exit(81)
}

// Failure-only test cleanup never sends a numeric PID/group signal. Open a
// pidfd and validate the private fixture executable before signaling that exact
// process object. A reused PID cannot redirect this signal to another process.
func cleanupRecordedEngineNativeChild(base string) {
	data, err := os.ReadFile(filepath.Join(base, "owned-child.pid"))
	if err != nil || len(data) > 20 {
		return
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 0 {
		return
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil || executable != filepath.Join(base, "ciadpi") {
		return
	}
	_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

func TestRecordedEngineClosedStdoutAndStderrReapBeforeScopeRestoration(t *testing.T) {
	for _, mode := range []string{"intent", "accepted", "notice"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecordedEngineNativeFixture(t, "recorded-engine-wait")
			t.Cleanup(func() { cleanupRecordedEngineNativeChild(f.base) })
			before, err := os.ReadFile(filepath.Join(f.directory, "events.journal"))
			if err != nil {
				t.Fatal(err)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			if mode != "accepted" {
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, executable, "-test.run=^TestRecordedEngineClosedStandardPipeWorker$", "-test.count=1")
			command.Env = append(os.Environ(), "ACCESSWEAVER_TEST_RECORDED_ENGINE_PIPE_MODE="+mode, "ACCESSWEAVER_TEST_RECORDED_ENGINE_PIPE_ROOT="+f.base)
			var observations, notice bytes.Buffer
			if mode == "notice" {
				command.Stdout = &observations
				command.Stderr = writer
			} else {
				command.Stdout = writer
				command.Stderr = &notice
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					cancel()
					_ = command.Wait()
				}
			}()
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "accepted" && !t.Run("intent-checkpoint", func(t *testing.T) {
				line, err := bufio.NewReader(reader).ReadBytes('\n')
				if err != nil {
					t.Fatal("intent checkpoint did not reach the real pipe reader", err)
				}
				checkpoint, err := audit.DecodeCheckpoint(line)
				if err != nil || checkpoint.Sequence != 1 {
					t.Fatal("first real stdout observation was not the intent head", err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.base, "stdout-reader-closed"), []byte("closed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}) {
				return
			}
			var runErr error
			if !t.Run("worker-completion", func(t *testing.T) {
				runErr = command.Wait()
				waited = true
				if ctx.Err() != nil {
					t.Fatal("recorded engine pipe worker did not finish", ctx.Err())
				}
			}) {
				return
			}
			if !t.Run("scope-cleanup", func(t *testing.T) {
				proof, err := os.ReadFile(filepath.Join(f.base, "pipe-cleanup-proved"))
				if err != nil || !strings.HasPrefix(string(proof), mode+":") {
					t.Fatal("worker exited before proving owned child and scope cleanup", err, notice.String())
				}
			}) {
				return
			}
			if !t.Run("sigpipe-restoration", func(t *testing.T) {
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) {
					t.Fatal("restored failed pipe did not terminate source-test worker", runErr)
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGPIPE {
					t.Fatal("recorded command leaked altered SIGPIPE behavior", runErr)
				}
			}) {
				return
			}
			t.Run("journal-integrity", func(t *testing.T) {
				events, _, raw := readRecordedEngineNativeEvents(t, f.directory, f.start)
				if !bytes.HasPrefix(raw, before) || bytes.Contains(raw, []byte("PRIVATE_")) || bytes.Contains(raw, f.key) {
					t.Fatal("pipe failure rewrote the prior stream or exposed private source material")
				}
				if mode == "intent" {
					if len(events) != 2 || events[0].Outcome != "intent" || events[1].Outcome != "refused" || events[0].OperationID != events[1].OperationID || events[0].Action != "engine.start" || events[1].Action != "engine.start" {
						t.Fatal("unobserved intent did not retain a truthful no-dispatch refusal")
					}
					if _, err := os.Stat(f.pid); !os.IsNotExist(err) {
						t.Fatal("closed intent stdout dispatched an inert process")
					}
				} else {
					assertRecordedEngineNativeLifecycle(t, events, "failed")
					if mode == "notice" {
						checkpoints := decodeCheckpointObservations(t, observations.Bytes())
						if len(checkpoints) != 3 || checkpoints[0].Sequence != 1 || checkpoints[1].Sequence != 2 || checkpoints[2].Sequence != 3 {
							t.Fatal("failed notice lost healthy canonical terminal observations")
						}
					}
				}
				assertRecordedEngineNoInventory(t, f.profiles)
			})
		})
	}
}

// This bounded repetition is opt-in in disposable hosted Linux CI. It keeps the
// same real descriptors, assertions, per-worker deadline and owned cleanup as
// the ordinary regression; a repeat pass cannot explain an earlier failure.
func TestRecordedEngineClosedStandardPipeRepeated(t *testing.T) {
	optIn := os.Getenv("ACCESSWEAVER_CLOSED_PIPE_REPEAT")
	if optIn == "" {
		t.Skip("bounded hosted closed-standard-pipe repetition only")
	}
	if optIn != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Linux" {
		t.Fatal("closed-standard-pipe repetition requires the disposable hosted Linux scope")
	}
	for attempt := 1; attempt <= 20; attempt++ {
		if !t.Run("attempt-"+strconv.Itoa(attempt), TestRecordedEngineClosedStdoutAndStderrReapBeforeScopeRestoration) {
			return
		}
	}
}

var _ io.Writer = (*recordedEngineStandardOutput)(nil)
