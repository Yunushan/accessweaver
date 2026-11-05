//go:build linux

package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"golang.org/x/sys/unix"
)

// WNOWAIT observes only this fixture's child; the production Cmd.Wait remains
// its sole consuming waiter. ECHILD here is evidence of that wait's real reap.
func lifetimeLinuxWait(pid, options int, wantReaped bool) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, options|unix.WNOWAIT|unix.WNOHANG, nil)
		if wantReaped && errors.Is(err, unix.ECHILD) {
			return nil
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return errors.New("fixture nonconsuming child observation failed")
		}
		if !wantReaped && err == nil && info.Signo != 0 {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("fixture nonconsuming child observation timed out")
}

func TestLinuxLifetimeRejectsSignalsInsideActualReapToOutputDrain(t *testing.T) {
	f := newLifetimeFixture(t)
	writer := &lifetimeBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(writer.release) }) })
	f.output = writer
	var admissions atomic.Int64
	f.start("output", func(owner *ownedProcess) {
		owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
	}, nil)
	lifetimeAwait(t, writer.entered, "actual output copy did not enter destination writer")
	f.write('q')
	if lifetimeLinuxWait(f.owner.cmd.Process.Pid, unix.WEXITED, true) != nil {
		t.Fatal("actual child reap was not witnessed during output drain")
	}
	before := admissions.Load()
	var stale atomic.Int64
	refused := func(*os.Process) error { stale.Add(1); return nil }
	if err := f.manager.stop(refused, refused, 0, 0); err == nil {
		t.Fatal("blocked output drain falsely completed")
	}
	if stale.Load() != 0 || admissions.Load() != before {
		t.Fatal("reaped child reached stale native dispatch")
	}
	select {
	case <-f.run.Done():
		t.Fatal("blocked destination writer was abandoned")
	default:
	}
	once.Do(func() { close(writer.release) })
	result := waitTracked(t, f.run)
	if result.LifecycleErr != nil || result.PolicyErr != nil || writer.bytes.Load() != int64(len("lifetime-output-marker\n")) {
		t.Fatal("actual output drain lost bytes or lifetime status")
	}
	if !f.owner.cmd.ProcessState.Success() {
		t.Fatal("original process exit status was not retained")
	}
	if result.WaitErr != nil && !errors.Is(result.WaitErr, exec.ErrWaitDelay) {
		t.Fatal("output wait returned an unexpected failure")
	}
}

func TestLinuxLifetimeAdmittedSignalKeepsActuallyExitedChildUnreaped(t *testing.T) {
	f := newLifetimeFixture(t)
	entered, release, beforeWait := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f.start("term", func(owner *ownedProcess) { owner.beforeWait = func() { close(beforeWait) } }, nil)
	stopped := make(chan error, 1)
	go func() {
		stopped <- f.manager.stop(func(process *os.Process) error {
			err := interruptProcess(process)
			close(entered)
			<-release
			return err
		}, killProcess, 3*time.Second, time.Second)
	}()
	lifetimeAwait(t, entered, "native dispatch did not enter its owned barrier")
	f.read('t')
	if lifetimeLinuxWait(f.owner.cmd.Process.Pid, unix.WEXITED, false) != nil {
		t.Fatal("exited child was not retained waitable during admitted dispatch")
	}
	select {
	case <-beforeWait:
		t.Fatal("exited child reaped before dispatch returned")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal("retained native dispatch did not finish")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("retained native dispatch did not drain")
	}
	lifetimeExit(t, f.run, RunStopped, 0)
}

func TestLinuxLifetimeImmediateExitBeforeObserverBind(t *testing.T) {
	f := newLifetimeFixture(t)
	f.write('q')
	var observed atomic.Bool
	f.launch("controlled", func(owner *ownedProcess) {
		owner.observer = &lifetimeFaultObserver{base: owner.observer, beforeBind: func(pid int) error {
			if err := lifetimeLinuxWait(pid, unix.WEXITED, false); err != nil {
				return err
			}
			observed.Store(true)
			return nil
		}}
	}, nil)
	result := lifetimeExit(t, f.run, RunExited, 0)
	if !observed.Load() || result.LifecycleErr != nil {
		t.Fatal("already-exited unreaped child was not observed correctly")
	}
}

func TestLinuxLifetimeStoppedChildIsNotAnExit(t *testing.T) {
	f := newLifetimeFixture(t)
	var consuming atomic.Int64
	f.start("controlled", func(owner *ownedProcess) { owner.beforeWait = func() { consuming.Add(1) } }, nil)
	f.write('s')
	f.read('s')
	if lifetimeLinuxWait(f.owner.cmd.Process.Pid, unix.WSTOPPED, false) != nil {
		t.Fatal("controlled child stop was not observed")
	}
	if consuming.Load() != 0 {
		t.Fatal("job stop was mistaken for exit")
	}
	select {
	case <-f.run.Done():
		t.Fatal("job stop published terminal completion")
	default:
	}
	if err := f.owner.dispatch(func(process *os.Process) error { return syscall.Kill(process.Pid, syscall.SIGCONT) }); err != nil {
		t.Fatal("owned stopped child could not resume")
	}
	f.write('q')
	lifetimeExit(t, f.run, RunExited, 0)
}

func TestLinuxLifetimeAuthorizationRevocationAfterActualReapCannotSignal(t *testing.T) {
	f := newLifetimeFixture(t)
	var revoked atomic.Bool
	f.guard = managed.NewGuard(func() (*managed.Authority, error) {
		if revoked.Load() {
			return nil, managed.ErrUnavailable
		}
		return nil, nil
	})
	f.authorization = make(chan context.Context, 1)
	writer := &lifetimeBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(writer.release) }) })
	f.output = writer
	var admissions atomic.Int64
	f.start("output", func(owner *ownedProcess) {
		owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
	}, nil)
	var authorization context.Context
	select {
	case authorization = <-f.authorization:
	case <-time.After(5 * time.Second):
		t.Fatal("actual authorization context unavailable")
	}
	lifetimeAwait(t, writer.entered, "real output writer did not block")
	f.write('q')
	if lifetimeLinuxWait(f.owner.cmd.Process.Pid, unix.WEXITED, true) != nil {
		t.Fatal("authorization fixture actual reap was not observed")
	}
	before := admissions.Load()
	revoked.Store(true)
	lifetimeAwait(t, authorization.Done(), "actual managed authorization did not revoke")
	if !managed.IsPolicyError(context.Cause(authorization)) {
		t.Fatal("actual revocation cause was not retained")
	}
	if admissions.Load() != before {
		t.Fatal("revoked authorization signaled a reaped numeric process group")
	}
	select {
	case <-f.run.Done():
		t.Fatal("policy revocation abandoned blocked real output")
	default:
	}
	once.Do(func() { close(writer.release) })
	result := waitTracked(t, f.run)
	if result.Reason != RunPolicyRevoked || !managed.IsPolicyError(result.PolicyErr) || result.LifecycleErr != nil || !f.owner.cmd.ProcessState.Success() {
		t.Fatal("late authorization revocation lost actual wait and policy cause")
	}
	if result.WaitErr != nil && !errors.Is(result.WaitErr, exec.ErrWaitDelay) {
		t.Fatal("late authorization output wait lost its actual error")
	}
	if admissions.Load() != before || writer.bytes.Load() != int64(len("lifetime-output-marker\n")) {
		t.Fatal("late authorization retirement lost bytes or admitted native dispatch")
	}
}
