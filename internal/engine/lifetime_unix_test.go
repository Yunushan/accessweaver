//go:build linux || darwin || freebsd || openbsd

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"golang.org/x/sys/unix"
)

const lifetimeFixturePrefix = "engine-lifetime-fixture-"

// Only the source-built inert engine image consumes this closed fixture mode.
// Control and replies use anonymous inherited pipes, never process discovery.
func init() {
	if os.Getenv("ACCESSWEAVER_FIXTURE") != "1" {
		return
	}
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, lifetimeFixturePrefix) {
			os.Exit(lifetimeFixtureMain(strings.TrimPrefix(arg, lifetimeFixturePrefix)))
		}
	}
}

func lifetimeFixtureMain(mode string) (status int) {
	for _, fd := range []int{3, 4} {
		var st unix.Stat_t
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		want := unix.O_RDONLY
		if fd == 4 {
			want = unix.O_WRONLY
		}
		if err != nil || flags&unix.O_ACCMODE != want || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || unix.SetNonblock(fd, true) != nil {
			return 71
		}
		unix.CloseOnExec(fd)
	}
	request, reply := os.NewFile(3, "lifetime-request"), os.NewFile(4, "lifetime-reply")
	if request == nil || reply == nil {
		return 71
	}
	defer func() {
		if request.Close() != nil {
			status = 72
		}
		if reply.Close() != nil {
			status = 72
		}
	}()
	if request.SetReadDeadline(time.Now().Add(15*time.Second)) != nil || reply.SetWriteDeadline(time.Now().Add(15*time.Second)) != nil {
		return 73
	}
	terms := make(chan os.Signal, 4)
	signal.Notify(terms, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(terms)
	commands := make(chan byte, 8)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(commands)
		var b [1]byte
		for {
			if _, err := io.ReadFull(request, b[:]); err != nil {
				return
			}
			commands <- b[0]
		}
	}()
	defer func() { _ = request.SetReadDeadline(time.Now()); <-readerDone }()
	send := func(b byte) bool { n, err := reply.Write([]byte{b}); return n == 1 && err == nil }
	switch mode {
	case "controlled", "term", "stubborn", "output", "outside", "descendant":
	default:
		return 74
	}
	if mode == "descendant" {
		return lifetimeDescendantFixture(commands, terms, reply)
	}
	if mode == "output" {
		if _, err := io.WriteString(os.Stdout, "lifetime-output-marker\n"); err != nil {
			return 75
		}
	}
	if !send('r') {
		return 76
	}
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return 77
		case <-terms:
			if mode == "term" {
				if !send('t') {
					return 76
				}
				return 0
			}
			if !send('t') {
				return 76
			}
		case b, ok := <-commands:
			if !ok {
				return 78
			}
			switch b {
			case 'q':
				return 0
			case 'f':
				return 23
			case 's':
				if !send('s') || unix.Kill(os.Getpid(), unix.SIGSTOP) != nil {
					return 79
				}
			case 'i':
				if !lifetimeWriteIdentity(reply) {
					return 80
				}
			case 'j':
				if mode != "outside" {
					return 81
				}
				var target [8]byte
				// The reader owns request; receive the fixed-width target through commands.
				for i := range target {
					value, open := <-commands
					if !open {
						return 78
					}
					target[i] = value
				}
				err := unix.Setpgid(0, int(binary.BigEndian.Uint64(target[:])))
				if !errors.Is(err, unix.EPERM) {
					return 82
				}
				if !send('p') {
					return 76
				}
			default:
				return 83
			}
		}
	}
}

func lifetimeWriteIdentity(reply *os.File) bool {
	sid, err := unix.Getsid(0)
	pgid, groupErr := unix.Getpgid(0)
	if err != nil || groupErr != nil {
		return false
	}
	var data [24]byte
	binary.BigEndian.PutUint64(data[0:8], uint64(os.Getpid()))
	binary.BigEndian.PutUint64(data[8:16], uint64(sid))
	binary.BigEndian.PutUint64(data[16:24], uint64(pgid))
	n, err := reply.Write(data[:])
	return err == nil && n == len(data)
}

func lifetimeDescendantFixture(commands <-chan byte, terms <-chan os.Signal, reply *os.File) (status int) {
	executable, err := os.Executable()
	if err != nil {
		return 84
	}
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		return 84
	}
	replyRead, replyWrite, err := os.Pipe()
	if err != nil {
		_ = requestRead.Close()
		_ = requestWrite.Close()
		return 84
	}
	child := exec.Command(executable, lifetimeFixturePrefix+"term")
	child.ExtraFiles = []*os.File{requestRead, replyWrite}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if child.Start() != nil {
		_ = requestRead.Close()
		_ = requestWrite.Close()
		_ = replyRead.Close()
		_ = replyWrite.Close()
		return 84
	}
	requestClose, replyClose := requestRead.Close(), replyWrite.Close()
	if requestClose != nil || replyClose != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		_ = requestWrite.Close()
		_ = replyRead.Close()
		return 84
	}
	waitStarted := false
	defer func() {
		if !waitStarted {
			_ = child.Process.Kill()
			waitStarted = true
			if child.Wait() != nil {
				status = 85
			}
		}
		if requestWrite.Close() != nil {
			status = 85
		}
		if replyRead.Close() != nil {
			status = 85
		}
	}()
	if replyRead.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		return 85
	}
	var b [1]byte
	if _, err := io.ReadFull(replyRead, b[:]); err != nil || b[0] != 'r' {
		return 85
	}
	if n, err := reply.Write([]byte{'r'}); err != nil || n != 1 {
		return 85
	}
ready:
	for {
		select {
		case <-terms:
			if _, err := io.ReadFull(replyRead, b[:]); err != nil || b[0] != 't' {
				return 85
			}
			break ready
		case control, ok := <-commands:
			if !ok {
				return 85
			}
			if control == 'i' {
				if !lifetimeWriteIdentity(reply) {
					return 85
				}
				continue
			}
			if control != 'q' {
				return 85
			}
			if n, err := requestWrite.Write([]byte{'q'}); err != nil || n != 1 {
				return 85
			}
			break ready
		case <-time.After(10 * time.Second):
			return 85
		}
	}

	// The real parent alone consumes its descendant's status. No signal follows.
	waitStarted = true
	if child.Wait() != nil {
		return 85
	}
	if n, err := reply.Write([]byte{'w'}); err != nil || n != 1 {
		return 85
	}
	return 0
}

type lifetimeFixture struct {
	guard                                            *managed.Guard
	authorization                                    chan context.Context
	t                                                *testing.T
	root                                             string
	rootInfo                                         os.FileInfo
	p                                                profile.Profile
	manager                                          *Manager
	run                                              *Run
	owner                                            *ownedProcess
	requestRead, requestWrite, replyRead, replyWrite *os.File
	preserve                                         bool
	output                                           io.Writer
}

func newLifetimeFixture(t *testing.T) *lifetimeFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-lifetime-")
	if err != nil {
		t.Fatal("lifetime fixture directory unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("lifetime fixture directory invalid")
	}
	f := &lifetimeFixture{t: t, root: root, rootInfo: info}
	t.Cleanup(f.close)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("lifetime fixture image unavailable")
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal("lifetime fixture image unavailable")
	}
	path := filepath.Join(root, "ciadpi")
	if os.WriteFile(path, data, 0700) != nil {
		t.Fatal("lifetime fixture image unavailable")
	}
	f.p = profile.New("lifetime-fixture", "Lifetime fixture", "byedpi")
	f.p.Binary = path
	t.Setenv("ACCESSWEAVER_FIXTURE", "1")
	t.Setenv("ACCESSWEAVER_FIXTURE_RECORD", filepath.Join(root, "unused-ready.json"))
	f.requestRead, f.requestWrite, err = os.Pipe()
	if err != nil {
		t.Fatal("lifetime fixture pipe unavailable")
	}
	f.replyRead, f.replyWrite, err = os.Pipe()
	if err != nil {
		t.Fatal("lifetime fixture pipe unavailable")
	}
	if f.requestWrite.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil || f.replyRead.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		t.Fatal("lifetime fixture pipe deadline unavailable")
	}
	return f
}
func (f *lifetimeFixture) start(mode string, decorate func(*ownedProcess), observedWait func()) {
	f.t.Helper()
	f.launch(mode, decorate, observedWait)
	f.read('r')
}
func (f *lifetimeFixture) launch(mode string, decorate func(*ownedProcess), observedWait func()) {
	f.t.Helper()
	f.p.Args = []string{lifetimeFixturePrefix + mode}
	f.manager = NewManager(filepath.Join(f.root, "state"))
	if f.guard != nil {
		f.manager.guard = f.guard
	}
	f.manager.output = f.output
	f.manager.prepareLifetime = func(cmd *exec.Cmd) (processLifetime, error) {
		cmd.ExtraFiles = []*os.File{f.requestRead, f.replyWrite}
		lifetime, err := prepareProcessLifetime(cmd)
		if err != nil {
			return nil, err
		}
		var ok bool
		f.owner, ok = lifetime.(*ownedProcess)
		if !ok {
			return nil, errors.New("lifetime owner unavailable")
		}
		if decorate != nil {
			decorate(f.owner)
		}
		if f.authorization != nil {
			return &lifetimeContextTap{processLifetime: lifetime, observed: f.authorization}, nil
		}
		return lifetime, nil
	}
	run, err := f.manager.startTracked(f.p, observedWait)
	f.run = run
	requestClose, replyClose := f.requestRead.Close(), f.replyWrite.Close()
	if requestClose != nil || replyClose != nil {
		f.t.Fatal("lifetime fixture inherited endpoint close failed")
	}
	f.requestRead, f.replyWrite = nil, nil
	if err != nil || run == nil {
		f.t.Fatal("lifetime fixture launch failed")
	}
}
func (f *lifetimeFixture) write(b byte) {
	f.t.Helper()
	if n, err := f.requestWrite.Write([]byte{b}); err != nil || n != 1 {
		f.t.Fatal("lifetime fixture control write failed")
	}
}
func (f *lifetimeFixture) read(want byte) {
	f.t.Helper()
	var b [1]byte
	if _, err := io.ReadFull(f.replyRead, b[:]); err != nil || b[0] != want {
		f.t.Fatal("lifetime fixture control reply failed")
	}
}
func (f *lifetimeFixture) identity() (pid, sid, pgid int) {
	f.t.Helper()
	f.write('i')
	var data [24]byte
	if _, err := io.ReadFull(f.replyRead, data[:]); err != nil {
		f.t.Fatal("lifetime fixture identity reply failed")
	}
	return int(binary.BigEndian.Uint64(data[0:8])), int(binary.BigEndian.Uint64(data[8:16])), int(binary.BigEndian.Uint64(data[16:24]))
}
func (f *lifetimeFixture) close() {
	if f.run != nil {
		if f.manager != nil {
			_ = f.manager.RetryCleanup(f.run)
			_ = f.manager.Stop()
		}
		select {
		case <-f.run.Done():
		case <-time.After(8 * time.Second):
			f.preserve = true
			f.t.Error("lifetime fixture completion unconfirmed")
		}
	}
	for _, file := range []*os.File{f.requestRead, f.requestWrite, f.replyRead, f.replyWrite} {
		if file != nil && file.Close() != nil {
			f.t.Error("lifetime fixture endpoint close failed")
		}
	}
	if f.preserve {
		f.t.Error("lifetime fixture preserved after unconfirmed completion")
		return
	}
	info, err := os.Lstat(f.root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !os.SameFile(info, f.rootInfo) {
		f.t.Error("lifetime fixture directory binding changed")
		return
	}
	if os.RemoveAll(f.root) != nil {
		f.t.Error("lifetime fixture removal failed")
	}
}
func lifetimeAwait(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal(message)
	}
}
func lifetimeExit(t *testing.T, run *Run, reason RunReason, exitCode int) RunResult {
	t.Helper()
	result := waitTracked(t, run)
	if result.Reason != reason {
		t.Fatal("lifetime fixture terminal reason differs")
	}
	if exitCode == 0 {
		if result.WaitErr != nil {
			t.Fatal("lifetime fixture successful wait lost")
		}
	} else {
		var native *exec.ExitError
		if !errors.As(result.WaitErr, &native) || native.ExitCode() != exitCode {
			t.Fatal("lifetime fixture original exit status lost")
		}
	}
	return result
}

type lifetimeBlockedWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	bytes   atomic.Int64
}

func (w *lifetimeBlockedWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	w.bytes.Add(int64(len(data)))
	return len(data), nil
}

func TestUnixLifetimeRetiresSignalsAcrossWaitAndPublication(t *testing.T) {
	for _, stage := range []string{"before-wait", "after-wait"} {
		t.Run(stage, func(t *testing.T) {
			f := newLifetimeFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			var admissions atomic.Int64
			observe := func() { close(entered); <-release }
			var after func()
			if stage == "after-wait" {
				after = observe
			}
			f.start("controlled", func(owner *ownedProcess) {
				owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
				if stage == "before-wait" {
					owner.beforeWait = observe
				}
			}, after)
			f.write('q')
			lifetimeAwait(t, entered, "lifetime wait barrier was not reached")
			before := admissions.Load()
			var stale atomic.Int64
			refused := func(*os.Process) error { stale.Add(1); return nil }
			if err := f.manager.stop(refused, refused, 0, 0); err == nil {
				t.Fatal("blocked terminal publication falsely completed")
			}
			if stale.Load() != 0 || admissions.Load() != before {
				t.Fatal("retired signal reached native admission")
			}
			select {
			case <-f.run.Done():
				t.Fatal("blocked wait published completion")
			default:
			}
			if next, err := f.manager.StartTracked(f.p); err == nil || next != nil {
				t.Fatal("unpublished owned launch admitted replacement")
			}
			releaseOnce.Do(func() { close(release) })
			result := lifetimeExit(t, f.run, RunExited, 0)
			if result.LifecycleErr != nil || result.PolicyErr != nil {
				t.Fatal("retired refusal changed original terminal outcome")
			}
			// A completed old owner remains retired even after manager publication.
			if err := f.owner.dispatch(refused); !errors.Is(err, os.ErrProcessDone) || stale.Load() != 0 {
				t.Fatal("completed owner admitted a stale native signal")
			}
		})
	}
}

func TestUnixLifetimeAdmittedSignalResolvesBeforeConsumingWait(t *testing.T) {
	f := newLifetimeFixture(t)
	signalEntered, releaseSignal, beforeWait := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(releaseSignal) }) })
	f.start("term", func(owner *ownedProcess) { owner.beforeWait = func() { close(beforeWait) } }, nil)
	stopped := make(chan error, 1)
	go func() {
		stopped <- f.manager.stop(func(process *os.Process) error {
			err := interruptProcess(process)
			close(signalEntered)
			<-releaseSignal
			return err
		}, killProcess, 3*time.Second, time.Second)
	}()
	lifetimeAwait(t, signalEntered, "lifetime signal admission was not entered")
	f.read('t')
	select {
	case <-beforeWait:
		t.Fatal("consuming wait overlapped unresolved native dispatch")
	default:
	}
	select {
	case <-f.run.Done():
		t.Fatal("unresolved native dispatch published completion")
	default:
	}
	// Snapshot uses Manager.mu and must not depend on the blocked native owner.
	snap := make(chan Snapshot, 1)
	go func() { snap <- f.manager.Snapshot() }()
	select {
	case <-snap:
	case <-time.After(time.Second):
		t.Fatal("native dispatch held manager state mutex")
	}
	once.Do(func() { close(releaseSignal) })
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal("owned graceful stop failed")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("owned graceful stop did not drain")
	}
	lifetimeAwait(t, beforeWait, "consuming wait did not follow resolved signal")
	result := lifetimeExit(t, f.run, RunStopped, 0)
	if result.LifecycleErr != nil || result.PolicyErr != nil {
		t.Fatal("resolved native dispatch lost actual graceful status")
	}
}

func TestUnixLifetimeCleanupFaultRetainsOwnershipUntilExplicitRetry(t *testing.T) {
	f := newLifetimeFixture(t)
	var refuse atomic.Bool
	refuse.Store(true)
	var consuming atomic.Int64
	f.start("controlled", func(owner *ownedProcess) {
		real := owner.nativeSignal
		owner.nativeSignal = func(pgid int, sig syscall.Signal) error {
			if refuse.Load() {
				return syscall.EPERM
			}
			return real(pgid, sig)
		}
		owner.beforeWait = func() { consuming.Add(1) }
	}, nil)
	t.Cleanup(func() { refuse.Store(false) })
	f.write('q')
	lifetimeAwait(t, f.run.Fault(), "cleanup fault was not published")
	if !errors.Is(f.run.PendingError(), ErrProcessCleanupPending) || consuming.Load() != 0 {
		t.Fatal("cleanup fault lost pending ownership")
	}
	select {
	case <-f.run.Done():
		t.Fatal("cleanup fault falsely published terminal completion")
	default:
	}
	if state := f.manager.Snapshot(); state.State != "error" || state.PID != 0 || !state.LifecyclePending || state.LastError != ErrProcessCleanupPending.Error() {
		t.Fatal("cleanup fault snapshot was not fixed and immediate")
	}
	if next, err := f.manager.StartTracked(f.p); !errors.Is(err, ErrProcessCleanupPending) || next != nil {
		t.Fatal("cleanup fault admitted replacement")
	}
	if err := f.manager.Stop(); !errors.Is(err, ErrProcessCleanupPending) {
		t.Fatal("cleanup fault stop did not remain pending")
	}
	if err := f.manager.RetryCleanup(&Run{}); !errors.Is(err, ErrRunUnavailable) {
		t.Fatal("cleanup retry accepted unrelated generation")
	}
	refuse.Store(false)
	if err := f.manager.RetryCleanup(f.run); err != nil {
		t.Fatal("retained cleanup retry failed")
	}
	result := lifetimeExit(t, f.run, RunFailed, 0)
	if !errors.Is(result.LifecycleErr, ErrProcessLifecycle) || consuming.Load() != 1 {
		t.Fatal("recovered cleanup fault lost actual wait or sticky uncertainty")
	}
	if f.manager.Snapshot().LifecyclePending {
		t.Fatal("completed cleanup kept transient pending state")
	}
}

type lifetimeFaultObserver struct {
	base              exitObserver
	bindErr, closeErr error
	beforeBind        func(int) error
}

func (o *lifetimeFaultObserver) bind(pid int) error {
	if o.beforeBind != nil {
		if err := o.beforeBind(pid); err != nil {
			return err
		}
	}
	if o.bindErr != nil {
		return o.bindErr
	}
	return o.base.bind(pid)
}
func (o *lifetimeFaultObserver) waitExit() error { return o.base.waitExit() }
func (o *lifetimeFaultObserver) close() error    { return errors.Join(o.base.close(), o.closeErr) }

func TestUnixLifetimeObserverBindFailureKeepsAcceptedRun(t *testing.T) {
	f := newLifetimeFixture(t)
	f.launch("controlled", func(owner *ownedProcess) {
		owner.observer = &lifetimeFaultObserver{base: owner.observer, bindErr: syscall.EIO}
	}, nil)
	if f.run == nil {
		t.Fatal("post-start observer failure erased accepted launch")
	}
	result := waitTracked(t, f.run)
	if result.WaitErr == nil || !errors.Is(result.LifecycleErr, ErrProcessLifecycle) || result.Reason != RunFailed {
		t.Fatal("post-start observer failure lost native wait and uncertainty")
	}
}
func TestUnixLifetimeObserverCloseFailureRetainsActualExit(t *testing.T) {
	f := newLifetimeFixture(t)
	f.start("controlled", func(owner *ownedProcess) {
		owner.observer = &lifetimeFaultObserver{base: owner.observer, closeErr: syscall.EIO}
	}, nil)
	f.write('f')
	result := lifetimeExit(t, f.run, RunFailed, 23)
	if !errors.Is(result.LifecycleErr, ErrProcessLifecycle) {
		t.Fatal("late observer close failure lost lifetime uncertainty")
	}
}

func TestUnixLifetimeRealDescendantWaitAcknowledgedBeforeLeaderExit(t *testing.T) {
	f := newLifetimeFixture(t)
	f.start("descendant", nil, nil)
	pid, sid, pgid := f.identity()
	if pid <= 1 || pid != sid || pid != pgid {
		t.Fatal("engine fixture did not own an isolated session")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- f.manager.Stop() }()
	f.read('w')
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal("descendant graceful group stop failed")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("descendant group stop did not finish")
	}
	result := lifetimeExit(t, f.run, RunStopped, 0)
	if result.LifecycleErr != nil {
		t.Fatal("parent-acknowledged descendant wait became uncertain")
	}
}

type lifetimeDirect struct {
	t              *testing.T
	cmd            *exec.Cmd
	request, reply *os.File
	waiting        bool
	done           chan error
	finished       bool
	preserve       *bool
}

func newLifetimeOutside(t *testing.T, f *lifetimeFixture) *lifetimeDirect {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("outside helper pipe unavailable")
	}
	rr, rw, err := os.Pipe()
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		t.Fatal("outside helper pipe unavailable")
	}
	cmd := exec.Command(f.p.Binary, lifetimeFixturePrefix+"outside")
	cmd.ExtraFiles = []*os.File{r, rw}
	d := &lifetimeDirect{t: t, cmd: cmd, request: w, reply: rr, preserve: &f.preserve}
	if cmd.Start() != nil {
		_ = r.Close()
		_ = w.Close()
		_ = rr.Close()
		_ = rw.Close()
		t.Fatal("outside helper launch failed")
	}
	t.Cleanup(d.close)
	requestClose, replyClose := r.Close(), rw.Close()
	if requestClose != nil || replyClose != nil || rr.SetReadDeadline(time.Now().Add(8*time.Second)) != nil || w.SetWriteDeadline(time.Now().Add(8*time.Second)) != nil {
		t.Fatal("outside helper endpoints unavailable")
	}
	var b [1]byte
	if _, err := io.ReadFull(rr, b[:]); err != nil || b[0] != 'r' {
		t.Fatal("outside helper readiness unavailable")
	}
	return d
}
func (d *lifetimeDirect) identity() (int, int, int) {
	d.t.Helper()
	if n, err := d.request.Write([]byte{'i'}); err != nil || n != 1 {
		d.t.Fatal("outside helper control unavailable")
	}
	var data [24]byte
	if _, err := io.ReadFull(d.reply, data[:]); err != nil {
		d.t.Fatal("outside helper identity unavailable")
	}
	return int(binary.BigEndian.Uint64(data[0:8])), int(binary.BigEndian.Uint64(data[8:16])), int(binary.BigEndian.Uint64(data[16:24]))
}
func (d *lifetimeDirect) wait() {
	d.t.Helper()
	d.waiting = true
	d.done = make(chan error, 1)
	go func() { d.done <- d.cmd.Wait() }()
	select {
	case err := <-d.done:
		d.finished = true
		if err != nil {
			d.t.Fatal("outside helper native wait failed")
		}
	case <-time.After(8 * time.Second):
		*d.preserve = true
		d.t.Fatal("outside helper completion unconfirmed")
	}
}
func (d *lifetimeDirect) close() {
	if !d.waiting {
		_ = d.cmd.Process.Kill()
		d.waiting = true
		d.done = make(chan error, 1)
		go func() { d.done <- d.cmd.Wait() }()
	}
	if !d.finished {
		select {
		case <-d.done:
			d.finished = true
		case <-time.After(8 * time.Second):
			*d.preserve = true
			d.t.Error("outside helper completion unconfirmed")
		}
	}
	requestErr, replyErr := d.request.Close(), d.reply.Close()
	if requestErr != nil || replyErr != nil {
		d.t.Error("outside helper endpoint close failed")
	}
}
func TestUnixLifetimeOutsideSessionCannotJoinEngineGroup(t *testing.T) {
	f := newLifetimeFixture(t)
	f.start("controlled", nil, nil)
	pid, sid, pgid := f.identity()
	if pid <= 1 || pid != sid || pid != pgid {
		t.Fatal("engine session identity differs")
	}
	outside := newLifetimeOutside(t, f)
	outsidePID, outsideSID, outsidePGID := outside.identity()
	if outsidePID <= 1 || outsideSID == sid {
		t.Fatal("outside helper unexpectedly joined engine session")
	}
	var request [9]byte
	request[0] = 'j'
	binary.BigEndian.PutUint64(request[1:], uint64(pgid))
	if n, err := outside.request.Write(request[:]); err != nil || n != len(request) {
		t.Fatal("outside join control failed")
	}
	var reply [1]byte
	if _, err := io.ReadFull(outside.reply, reply[:]); err != nil || reply[0] != 'p' {
		t.Fatal("cross-session group join was not refused with EPERM")
	}
	afterPID, afterSID, afterPGID := outside.identity()
	if afterPID != outsidePID || afterSID != outsideSID || afterPGID != outsidePGID {
		t.Fatal("refused outside join changed native identity")
	}
	if n, err := outside.request.Write([]byte{'q'}); err != nil || n != 1 {
		t.Fatal("outside helper completion control failed")
	}
	outside.wait()
	f.write('q')
	lifetimeExit(t, f.run, RunExited, 0)
}

func TestUnixLifetimeCanceledWaitAndShutdownDoNotAbandonAdmittedSignal(t *testing.T) {
	f := newLifetimeFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f.start("term", nil, nil)
	stopped := make(chan error, 1)
	go func() {
		stopped <- f.manager.stop(func(*os.Process) error { close(entered); <-release; return syscall.EPERM }, func(*os.Process) error { return syscall.EPERM }, 0, 0)
	}()
	lifetimeAwait(t, entered, "owned signal admission unavailable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := f.run.Wait(ctx); !errors.Is(err, context.Canceled) || got != (RunResult{}) {
		t.Fatal("canceled waiter replaced terminal result")
	}
	if err := f.manager.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("shutdown caller cancellation was not bounded")
	}
	select {
	case <-f.run.Done():
		t.Fatal("caller timeout abandoned admitted signal")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case err := <-stopped:
		if !errors.Is(err, ErrProcessCleanupPending) {
			t.Fatal("failed native force lost pending ownership")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("admitted failed signal did not resolve")
	}
	lifetimeAwait(t, f.run.Fault(), "shutdown did not retain failed cleanup")
	if !errors.Is(f.run.PendingError(), ErrProcessCleanupPending) {
		t.Fatal("shutdown lost pending fault")
	}
	if err := f.manager.RetryCleanup(f.run); err != nil {
		t.Fatal("shutdown retained cleanup could not be retried")
	}
	result := lifetimeExit(t, f.run, RunFailed, -1)
	var exit *exec.ExitError
	if !errors.As(result.WaitErr, &exit) || !errors.Is(result.LifecycleErr, ErrProcessLifecycle) {
		t.Fatal("shutdown recovery lost actual forced wait")
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("shutdown recovery replaced native SIGKILL status")
	}
	if next, err := f.manager.StartTracked(f.p); err == nil || next != nil {
		t.Fatal("shutdown admitted a late replacement")
	}
}

// This fixture tap delegates every lifetime operation and records the actual
// managed authorization context supplied to the real native owner.
type lifetimeContextTap struct {
	processLifetime
	observed chan<- context.Context
}

func (o *lifetimeContextTap) wait(ctx context.Context) (error, error) {
	o.observed <- ctx
	return o.processLifetime.wait(ctx)
}

func TestUnixLifetimeAlreadyExitedChildBeforeNativeObserverBinding(t *testing.T) {
	f := newLifetimeFixture(t)
	var sawExit atomic.Bool
	f.launch("controlled", func(owner *ownedProcess) {
		owner.observer = &lifetimeFaultObserver{base: owner.observer, beforeBind: func(pid int) error {
			witness, err := newExitObserver()
			if err != nil {
				return err
			}
			if err := witness.bind(pid); err != nil {
				return errors.Join(err, witness.close())
			}
			n, writeErr := f.requestWrite.Write([]byte{'q'})
			if writeErr != nil || n != 1 {
				return errors.Join(errors.New("fixture exit control failed"), witness.close())
			}
			waitErr := witness.waitExit()
			closeErr := witness.close()
			if waitErr != nil || closeErr != nil {
				return errors.Join(waitErr, closeErr)
			}
			sawExit.Store(true)
			return nil
		}}
	}, nil)
	result := lifetimeExit(t, f.run, RunExited, 0)
	if !sawExit.Load() || result.LifecycleErr != nil {
		t.Fatal("late native observer registration lost original exit")
	}
}

func TestUnixLifetimeObserverAllocationFailureStartsNoChild(t *testing.T) {
	f := newLifetimeFixture(t)
	manager := NewManager(filepath.Join(f.root, "state"))
	refused := errors.New("fixture observer allocation refused")
	manager.prepareLifetime = func(*exec.Cmd) (processLifetime, error) { return nil, refused }
	run, err := manager.StartTracked(f.p)
	if run != nil || !errors.Is(err, refused) || manager.Snapshot().PID != 0 {
		t.Fatal("observer allocation failure admitted a child")
	}
}

// This is a synthetic admission contract only. No child is launched, no wait
// begins and every injected callback is non-native; it does not simulate theft
// of actual child status or claim native ownership-loss qualification.
func TestUnixLifetimeSyntheticOwnershipLossPermanentlyClosesAdmission(t *testing.T) {
	for _, item := range []struct {
		name    string
		failure error
	}{{"missing-child", syscall.ECHILD}, {"lost-sentinel", ErrProcessOwnershipLost}} {
		t.Run(item.name, func(t *testing.T) {
			failure := item.failure
			var admissions, callbacks, native atomic.Int64
			owner := &ownedProcess{cmd: &exec.Cmd{}, pid: os.Getpid(), faulted: make(chan struct{}), signalClosed: make(chan struct{}), retryReady: make(chan struct{})}
			owner.nativeSignal = func(int, syscall.Signal) error { native.Add(1); return nil }
			owner.admittedDispatch = func(_ int, invoke func() error) error { admissions.Add(1); return invoke() }
			if err := owner.dispatch(func(*os.Process) error { callbacks.Add(1); return failure }); !errors.Is(err, ErrProcessOwnershipLost) {
				t.Fatal("synthetic lost ownership was not fixed")
			}
			refused := func(*os.Process) error { callbacks.Add(1); return nil }
			if err := owner.dispatch(refused); !errors.Is(err, ErrProcessOwnershipLost) {
				t.Fatal("synthetic lost owner reopened dispatch")
			}
			if err := owner.retryCleanup(); !errors.Is(err, ErrProcessOwnershipLost) {
				t.Fatal("synthetic lost owner accepted retry")
			}
			owner.policySignal()
			if admissions.Load() != 1 || callbacks.Load() != 1 || native.Load() != 0 || !errors.Is(owner.pendingError(), ErrProcessOwnershipLost) {
				t.Fatal("synthetic lost ownership entered another native admission")
			}
			select {
			case <-owner.signalClosed:
			default:
				t.Fatal("synthetic lost owner kept signal admission open")
			}
			select {
			case <-owner.faultSignal():
			default:
				t.Fatal("synthetic lost owner did not publish fixed fault")
			}
		})
	}
}

func TestUnixLifetimeEscalationFailureReturnsPendingFault(t *testing.T) {
	f := newLifetimeFixture(t)
	f.start("controlled", nil, nil)
	err := f.manager.stop(func(*os.Process) error { return nil }, func(*os.Process) error { return syscall.EPERM }, 0, time.Second)
	if !errors.Is(err, ErrProcessCleanupPending) {
		t.Fatal("forced escalation hid fixed cleanup fault")
	}
	lifetimeAwait(t, f.run.Fault(), "forced escalation did not publish pending fault")
	select {
	case <-f.run.Done():
		t.Fatal("failed forced escalation published completion")
	default:
	}
	if next, err := f.manager.StartTracked(f.p); err == nil || next != nil {
		t.Fatal("failed forced escalation admitted replacement")
	}
	if err := f.manager.RetryCleanup(f.run); err != nil {
		t.Fatal("failed forced escalation recovery failed")
	}
	result := lifetimeExit(t, f.run, RunFailed, -1)
	if !errors.Is(result.LifecycleErr, ErrProcessLifecycle) {
		t.Fatal("failed forced escalation recovery lost sticky uncertainty")
	}
}

// This manager integration case also has no child and no native callback. It
// verifies that an ownership error from TERM cannot fall through to raw KILL.
func TestUnixLifetimeSyntheticLostTermNeverCallsFallback(t *testing.T) {
	for _, item := range []struct {
		name    string
		failure error
	}{{"missing-child", syscall.ECHILD}, {"lost-sentinel", ErrProcessOwnershipLost}} {
		t.Run(item.name, func(t *testing.T) {
			cmd := &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
			owner := &ownedProcess{cmd: cmd, pid: os.Getpid(), faulted: make(chan struct{}), signalClosed: make(chan struct{}), retryReady: make(chan struct{})}
			var native, fallback atomic.Int64
			owner.nativeSignal = func(int, syscall.Signal) error { native.Add(1); return nil }
			manager := NewManager("")
			state := &runState{done: make(chan struct{}), owner: owner}
			manager.cmd, manager.run = cmd, state
			err := manager.stop(func(*os.Process) error { return item.failure }, func(*os.Process) error { fallback.Add(1); return nil }, 0, 0)
			if !errors.Is(err, ErrProcessOwnershipLost) || fallback.Load() != 0 || native.Load() != 0 || !manager.Snapshot().LifecyclePending {
				t.Fatal("synthetic lost TERM reached native fallback or lost pending fault")
			}
			if err := manager.RetryCleanup(&Run{state: state}); !errors.Is(err, ErrProcessOwnershipLost) {
				t.Fatal("synthetic lost TERM reopened cleanup")
			}
		})
	}
}
