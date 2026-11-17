//go:build linux

package workflow

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const workflowExitFixtureEnv = "ACCESSWEAVER_WORKFLOW_EXIT_SOURCE_FIXTURE"
const workflowExitFixtureArg = "workflow-owned-exit-source-helper"
const workflowExitFixtureOutput = "source-owned-exit\n"

func init() {
	if os.Getenv(workflowExitFixtureEnv) != "1" || len(os.Args) != 2 || os.Args[1] != workflowExitFixtureArg {
		return
	}
	if n, err := io.WriteString(os.Stdout, workflowExitFixtureOutput); err != nil || n != len(workflowExitFixtureOutput) {
		os.Exit(91)
	}
	os.Exit(23)
}

// The exact source-owned child is observed without consuming status. Go Wait
// remains the only reaper. This test seam does not qualify Windows handles.
func workflowObserveSourceExit(pid int, reaped bool) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
		if reaped && errors.Is(err, unix.ECHILD) {
			return nil
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return errors.New("source child observation failed")
		}
		if !reaped && err == nil && info.Signo != 0 {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("source child observation timed out")
}

type workflowDrainBarrier struct {
	entered, release chan struct{}
	once             sync.Once
	bytes            atomic.Int64
}

func (w *workflowDrainBarrier) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	w.bytes.Add(int64(len(p)))
	return len(p), nil
}

func workflowAwaitSource(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(8 * time.Second):
		t.Fatal(message)
	}
}

func workflowSourceImage(t *testing.T) string {
	t.Helper()
	image, err := os.Executable()
	if err != nil {
		t.Fatal("source test executable unavailable")
	}
	return image
}

func TestLinuxWorkflowOwnerCoversExitedChildBindingAndActualOutputDrain(t *testing.T) {
	cmd := exec.Command(workflowSourceImage(t), workflowExitFixtureArg)
	cmd.Env = append(os.Environ(), workflowExitFixtureEnv+"=1")
	writer := &workflowDrainBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = writer, io.Discard
	cmd.WaitDelay = time.Second
	bound := make(chan *os.Process, 1)
	releaseBind := make(chan struct{})
	closed := make(chan struct{})
	var closeBeforeWait atomic.Bool
	owner := &workflowTestCommandOwner{
		bind:  func(p *os.Process) error { bound <- p; <-releaseBind; return nil },
		close: func() error { closeBeforeWait.Store(cmd.ProcessState == nil); close(closed); return nil },
	}
	done := make(chan struct{})
	var result error
	var bindOnce, writerOnce sync.Once
	t.Cleanup(func() {
		bindOnce.Do(func() { close(releaseBind) })
		writerOnce.Do(func() { close(writer.release) })
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Error("accepted source child was not joined")
		}
	})
	go func() { result = runWorkflowCommand(cmd, owner); close(done) }()
	var process *os.Process
	select {
	case process = <-bound:
	case <-time.After(8 * time.Second):
		t.Fatal("accepted source child was not bound")
	}
	workflowAwaitSource(t, writer.entered, "source output did not enter its destination")
	if err := workflowObserveSourceExit(process.Pid, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
		t.Fatal("owner closed before binding and actual wait")
	default:
	}
	bindOnce.Do(func() { close(releaseBind) })
	if err := workflowObserveSourceExit(process.Pid, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
		t.Fatal("owner closed while actual output was still draining")
	default:
	}
	select {
	case <-done:
		t.Fatal("blocked destination was abandoned")
	default:
	}
	writerOnce.Do(func() { close(writer.release) })
	workflowAwaitSource(t, done, "real output drain did not finish")
	var exit *exec.ExitError
	if !errors.As(result, &exit) || exit.ExitCode() != 23 || closeBeforeWait.Load() || writer.bytes.Load() != int64(len(workflowExitFixtureOutput)) {
		t.Fatal("actual wait/output completion or original exit status was lost")
	}
	workflowAwaitSource(t, closed, "owner was not released after actual wait/output")
}

func TestLinuxWorkflowBindingFailureStillWaitsAcceptedChild(t *testing.T) {
	cmd := exec.Command(workflowSourceImage(t), workflowCommandFixtureArg)
	cmd.Env = append(os.Environ(), workflowCommandFixtureEnv+"=1")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	bindingFailure := errors.New("PRIVATE_BINDING_FAILURE")
	closeFailure := errors.New("PRIVATE_CLOSE_FAILURE")
	var killErr error
	closedAfterWait := false
	owner := &workflowTestCommandOwner{
		bind:  func(p *os.Process) error { killErr = p.Kill(); return errors.Join(bindingFailure, killErr) },
		close: func() error { closedAfterWait = cmd.ProcessState != nil; return closeFailure },
	}
	result := runWorkflowCommand(cmd, owner)
	var exit *exec.ExitError
	if killErr != nil || !closedAfterWait || !errors.As(result, &exit) || !errors.Is(result, bindingFailure) || !errors.Is(result, closeFailure) || !errors.Is(result, ErrWorkflowCleanup) {
		t.Fatal("binding failure abandoned the accepted child or lost cleanup uncertainty")
	}
}

func TestLinuxWorkflowCancellationDuringBindJoinsWatcherBeforeOwnerClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, workflowSourceImage(t), workflowCommandFixtureArg)
	cmd.Env = append(os.Environ(), workflowCommandFixtureEnv+"=1")
	ready := &workflowCommandReadiness{ready: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = ready, io.Discard
	cmd.WaitDelay = time.Second
	bound, releaseBind := make(chan struct{}), make(chan struct{})
	cancelEntered, cancelFinished := make(chan struct{}), make(chan struct{})
	synthetic := errors.New("PRIVATE_SYNTHETIC_GATED_CANCEL_FAILURE")
	var process *os.Process
	var killErr error
	var closedAfterWait, closedAfterCancel bool
	owner := &workflowTestCommandOwner{
		bind: func(p *os.Process) error { process = p; close(bound); <-releaseBind; return nil },
		close: func() error {
			closedAfterWait = cmd.ProcessState != nil
			select {
			case <-cancelFinished:
				closedAfterCancel = true
			default:
			}
			return nil
		},
	}
	cmd.Cancel = func() error {
		close(cancelEntered)
		<-releaseBind
		<-bound
		killErr = process.Kill() // Go-owned source child only; never a raw PID.
		close(cancelFinished)
		return errors.Join(synthetic, killErr)
	}
	observation := captureCommandCancellation(cmd)
	done := make(chan struct{})
	var result error
	var releaseOnce sync.Once
	t.Cleanup(func() {
		cancel()
		releaseOnce.Do(func() { close(releaseBind) })
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Error("canceled source child/watcher was not joined")
		}
	})
	go func() { result = runWorkflowCommand(cmd, owner); close(done) }()
	workflowAwaitSource(t, bound, "accepted child did not reach binding barrier")
	workflowAwaitSource(t, ready.ready, "source child did not reach readiness")
	cancel()
	workflowAwaitSource(t, cancelEntered, "Go context watcher did not enter gated cancellation")
	select {
	case <-done:
		t.Fatal("pending cancellation was abandoned")
	default:
	}
	releaseOnce.Do(func() { close(releaseBind) })
	workflowAwaitSource(t, done, "owned cancellation and wait did not complete")
	var exit *exec.ExitError
	if !ready.valid() || killErr != nil || !closedAfterWait || !closedAfterCancel || !errors.As(result, &exit) || !errors.Is(observation.failure(), synthetic) || !errors.Is(observation.failure(), ErrWorkflowCleanup) {
		t.Fatal("actual cancellation/wait join or separately retained cleanup error was lost")
	}
}

func TestLinuxWorkflowActualExitMasksCopyErrorButOutputObserverRetainsIt(t *testing.T) {
	cmd := exec.Command(workflowSourceImage(t), workflowExitFixtureArg)
	cmd.Env = append(os.Environ(), workflowExitFixtureEnv+"=1")
	sentinel := errors.New("PRIVATE_ACTUAL_COPY_FAILURE")
	calls := 0
	output := &startupLog{writer: startupWriterFunc(func(p []byte) (int, error) {
		calls++
		if calls == 1 {
			return len(p), nil
		}
		return 0, sentinel
	}), started: time.Now()}
	cmd.Stdout, cmd.Stderr = output, io.Discard
	cmd.WaitDelay = time.Second
	result := runWorkflowCommand(cmd, nil)
	var exit *exec.ExitError
	if !errors.As(result, &exit) || exit.ExitCode() != 23 || errors.Is(result, sentinel) {
		t.Fatal("source command did not establish real Go Wait copy-error precedence")
	}
	retained := workflowFailure(ErrWorkflowPersistence, output.failure())
	if !errors.Is(retained, sentinel) || !errors.Is(retained, ErrWorkflowPersistence) {
		t.Fatal("actual source output failure was hidden by abnormal exit")
	}
}
