//go:build linux

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const workflowCommandFixtureEnv = "ACCESSWEAVER_WORKFLOW_COMMAND_SOURCE_FIXTURE"
const workflowCommandFixtureArg = "workflow-command-cancel-source-helper"
const workflowCommandReady = "source-workflow-child-ready\n"

func init() {
	if os.Getenv(workflowCommandFixtureEnv) != "1" || len(os.Args) != 2 || os.Args[1] != workflowCommandFixtureArg {
		return
	}
	if n, err := io.WriteString(os.Stdout, workflowCommandReady); err != nil || n != len(workflowCommandReady) {
		os.Exit(91)
	}
	// The source helper opens no sockets, settings, registry or product files.
	// Its own fixed failure bound also prevents an indefinitely orphaned helper.
	<-time.After(30 * time.Second)
	os.Exit(92)
}

type workflowCommandReadiness struct {
	mu      sync.Mutex
	data    []byte
	ready   chan struct{}
	once    sync.Once
	invalid bool
}

func (w *workflowCommandReadiness) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.data)+len(data) > 128 {
		w.invalid = true
		return len(data), nil
	}
	w.data = append(w.data, data...)
	if bytes.Equal(w.data, []byte(workflowCommandReady)) {
		w.once.Do(func() { close(w.ready) })
	}
	return len(data), nil
}
func (w *workflowCommandReadiness) valid() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.invalid && bytes.Equal(w.data, []byte(workflowCommandReady))
}

type workflowCommandProof struct {
	runErr, cleanup, killErr error
	callbacks                int32
	valid                    bool
}

// This executes only the source-built Linux test image. The cleanup error is
// synthetic; the ready child, Go Cancel callback, sole Cmd.Run/Wait and native
// ExitError precedence are real. It does not qualify Windows tree cleanup.
func TestLinuxWorkflowRealWaitMasksSyntheticCancelErrorButShutdownRetainsIt(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("source command image unavailable")
	}
	ready := make(chan struct{})
	proofs := make(chan workflowCommandProof, 1)
	synthetic := errors.New("PRIVATE_SYNTHETIC_CANCEL_TREE_FAILURE")
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		childContext, cancelChild := context.WithCancel(ctx)
		defer cancelChild()
		cmd := exec.CommandContext(childContext, executable, workflowCommandFixtureArg)
		cmd.Env = append(os.Environ(), workflowCommandFixtureEnv+"=1")
		output := &workflowCommandReadiness{ready: make(chan struct{})}
		cmd.Stdout, cmd.Stderr = output, io.Discard
		cmd.WaitDelay = time.Second
		var callbacks atomic.Int32
		killed := make(chan error, 1)
		cmd.Cancel = func() error {
			callbacks.Add(1)
			killErr := cmd.Process.Kill() // Go-owned child handle; never a raw PID/group.
			killed <- killErr
			if killErr != nil {
				return errors.Join(synthetic, killErr)
			}
			return synthetic
		}
		observation := captureCommandCancellation(cmd)
		runDone := make(chan error, 1)
		go func() { runDone <- cmd.Run() }() // Exactly one consuming Run/Wait owner.
		var runErr error
		select {
		case <-output.ready:
			close(ready)
			runErr = <-runDone
		case runErr = <-runDone:
		case <-time.After(8 * time.Second):
			cancelChild()
			// Execute retains its real command until the only Run has returned; a
			// diagnostic timeout cannot publish a falsely completed workflow.
			runErr = <-runDone
		}
		var killErr error
		select {
		case killErr = <-killed:
		default:
		}
		cleanup := observation.failure()
		proofs <- workflowCommandProof{runErr: runErr, cleanup: cleanup, killErr: killErr, callbacks: callbacks.Load(), valid: output.valid()}
		return json.RawMessage(`{"sourceCommand":true}`), errors.Join(runErr, cleanup)
	}
	f.start()
	select {
	case <-ready:
	case <-time.After(8 * time.Second):
		t.Fatal("real source command readiness was not observed")
	}
	terminal := workflowShutdownFinal(t, m)
	proof := <-proofs
	var exit *exec.ExitError
	if !proof.valid || proof.callbacks != 1 || proof.killErr != nil || !errors.As(proof.runErr, &exit) || errors.Is(proof.runErr, synthetic) {
		t.Fatal("real Go Wait did not establish source Cancel error precedence")
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("real source child wait did not retain its owned Kill status")
	}
	if !errors.Is(proof.cleanup, ErrWorkflowCleanup) || !errors.Is(proof.cleanup, synthetic) {
		t.Fatal("production observer lost the masked synthetic cancellation failure")
	}
	var retained *exec.ExitError
	if !errors.As(terminal, &retained) || retained != exit || !errors.Is(terminal, ErrWorkflowCleanup) || !errors.Is(terminal, ErrWorkflowExecution) || !errors.Is(terminal, synthetic) {
		t.Fatal("workflow shutdown erased actual exit or masked cleanup cofailure")
	}
	workflowShutdownPublic(t, terminal, synthetic.Error(), f.root)
	if !bytes.Contains([]byte(terminal.Error()), []byte(ErrWorkflowCleanup.Error())) {
		t.Fatal("real source masking lost actionable fixed cleanup warning")
	}
	if job := m.Snapshot(); job.State != "failed" || job.FinishedAt.IsZero() || string(job.Result) != `{"sourceCommand":true}` {
		t.Fatal("real source masking lost terminal workflow result")
	}
}
