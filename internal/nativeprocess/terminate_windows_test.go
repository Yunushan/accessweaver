//go:build windows

package nativeprocess

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Only the source-built test image dispatches these fixed inert modes. There
// are no product, service, firewall, policy or AppControl operations here.
func TestNativeWindowsOwnerHelper(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "--" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	args := os.Args[marker+1:]
	if len(args) != 1 {
		os.Exit(81)
	}
	os.Exit(treeWindowsHelper(args[0]))
}
func treeWindowsHelper(mode string) int {
	send := func(value byte) bool { n, err := os.Stdout.Write([]byte{value}); return n == 1 && err == nil }
	switch mode {
	case "leaf":
		if !send('r') {
			return 82
		}
		time.Sleep(45 * time.Second)
		return 83
	case "controlled", "tree":
	default:
		return 84
	}
	if !send('r') {
		return 82
	}
	controls := make(chan byte, 4)
	go func() {
		defer close(controls)
		var value [1]byte
		for {
			if _, err := io.ReadFull(os.Stdin, value[:]); err != nil {
				return
			}
			controls <- value[0]
		}
	}()
	select {
	case value, ok := <-controls:
		if !ok {
			return 85
		}
		if value == 'q' {
			return 0
		}
		if mode != "tree" || value != 'g' {
			return 85
		}
	case <-time.After(30 * time.Second):
		return 86
	}
	child := exec.Command(os.Args[0], "-test.run=^TestNativeWindowsOwnerHelper$", "--", "leaf")
	ready := &treeWindowsOutput{events: make(chan byte, 8)}
	child.Stdout, child.Stderr = ready, io.Discard
	if child.Start() != nil {
		return 87
	}
	waitStarted := false
	defer func() {
		if !waitStarted {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	select {
	case value := <-ready.events:
		if value != 'r' {
			return 87
		}
	case <-time.After(8 * time.Second):
		return 87
	}
	if !send('t') {
		return 82
	}
	waitStarted = true
	// This source parent alone consumes its child status. The outer test never
	// reopens the child's PID or claims to perform this parent's Wait.
	if child.Wait() != nil {
		return 88
	}
	return 0
}

type treeWindowsOutput struct {
	mu      sync.Mutex
	events  chan byte
	bytes   int
	invalid bool
}

func (w *treeWindowsOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bytes += len(data)
	if w.bytes > 64 {
		w.invalid = true
		return len(data), nil
	}
	for _, value := range data {
		if value != 'r' && value != 't' {
			w.invalid = true
		}
		select {
		case w.events <- value:
		default:
			w.invalid = true
		}
	}
	return len(data), nil
}
func (w *treeWindowsOutput) valid() bool { w.mu.Lock(); defer w.mu.Unlock(); return !w.invalid }

type treeObservedWindowsBackend struct {
	treeBackend
	mu                          sync.Mutex
	duplicateHandle             uintptr
	duplicates, closes, helpers int
	duplicateErr                error
	treeFn                      func(uintptr, int) error
}

func (b *treeObservedWindowsBackend) duplicate(original uintptr) (uintptr, error) {
	b.mu.Lock()
	b.duplicates++
	injected := b.duplicateErr
	b.mu.Unlock()
	if injected != nil {
		return 0, injected
	}
	handle, err := b.treeBackend.duplicate(original)
	if err == nil {
		b.mu.Lock()
		b.duplicateHandle = handle
		b.mu.Unlock()
	}
	return handle, err
}
func (b *treeObservedWindowsBackend) close(handle uintptr) error {
	b.mu.Lock()
	b.closes++
	b.mu.Unlock()
	return b.treeBackend.close(handle)
}
func (b *treeObservedWindowsBackend) tree(handle uintptr, pid int) error {
	b.mu.Lock()
	b.helpers++
	fn := b.treeFn
	b.mu.Unlock()
	if fn != nil {
		return fn(handle, pid)
	}
	return b.treeBackend.tree(handle, pid)
}
func (b *treeObservedWindowsBackend) snapshot() (uintptr, int, int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.duplicateHandle, b.duplicates, b.closes, b.helpers
}

// Layout of JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (four LARGE_INTEGER values
// followed by four DWORDs), per the Microsoft Win32 definition:
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information
// ActiveProcesses can include retained process references, so zero is checked
// only after both the Go handle and owner duplicate have been released.
type treeWindowsJobAccounting struct {
	times                                 [4]int64
	pageFaults, total, active, terminated uint32
}

func treeWindowsActive(job windows.Handle) (uint32, error) {
	var info treeWindowsJobAccounting
	if unsafe.Sizeof(info) != 48 {
		return 0, errors.New("source job accounting layout unavailable")
	}
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	return info.active, err
}
func treeWindowsAwaitEmpty(t *testing.T, job windows.Handle) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		active, err := treeWindowsActive(job)
		if err != nil {
			t.Fatal("owned source job accounting unavailable")
		}
		if active == 0 {
			return
		}
		time.Sleep(time.Millisecond * 5)
	}
	t.Fatal("owned source job did not become empty")
}

var treeGetHandleInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")

func treeWindowsHandleFlags(handle uintptr) (uint32, error) {
	var flags uint32
	ok, _, err := treeGetHandleInformation.Call(handle, uintptr(unsafe.Pointer(&flags)))
	runtime.KeepAlive(&flags)
	if ok == 0 {
		return 0, err
	}
	return flags, nil
}

type treeWindowsFixture struct {
	t                                                *testing.T
	cmd                                              *exec.Cmd
	owner                                            *TreeOwner
	backend                                          *treeObservedWindowsBackend
	job                                              windows.Handle
	input                                            io.WriteCloser
	output                                           *treeWindowsOutput
	cancel                                           context.CancelFunc
	started, assigned, bindingAttempted, waitStarted bool
	waitDone                                         chan struct{}
	waitErr                                          error
	releases                                         []func()
}

func newTreeWindowsFixture(t *testing.T, mode string, decorate func(*treeObservedWindowsBackend), cancelEntered chan struct{}) *treeWindowsFixture {
	t.Helper()
	backend := &treeObservedWindowsBackend{treeBackend: windowsTreeBackend{}}
	if decorate != nil {
		decorate(backend)
	}
	f := &treeWindowsFixture{t: t, backend: backend, owner: newTreeOwnerWithBackend(backend), output: &treeWindowsOutput{events: make(chan byte, 8)}}
	t.Cleanup(f.close)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal("private source job unavailable")
	}
	f.job = job
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		t.Fatal("private source job cleanup limit unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeWindowsOwnerHelper$", "--", mode)
	f.cmd.Cancel = func() error {
		if cancelEntered != nil {
			close(cancelEntered)
		}
		return f.owner.Cancel()
	}
	f.cmd.WaitDelay = time.Second
	f.cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	f.cmd.Stdout, f.cmd.Stderr = f.output, io.Discard
	input, err := f.cmd.StdinPipe()
	if err != nil {
		t.Fatal("source control pipe unavailable")
	}
	f.input = input
	if f.cmd.Start() != nil {
		t.Fatal("owned source process did not start")
	}
	f.started = true
	var assignedErr error
	borrowErr := f.cmd.Process.WithHandle(func(handle uintptr) { assignedErr = windows.AssignProcessToJobObject(job, windows.Handle(handle)) })
	if borrowErr != nil || assignedErr != nil {
		t.Fatal("exact source parent could not enter private job")
	}
	f.assigned = true
	f.read('r')
	return f
}
func (f *treeWindowsFixture) bind() error {
	f.t.Helper()
	f.bindingAttempted = true
	return f.owner.Bind(f.cmd.Process)
}
func (f *treeWindowsFixture) read(want byte) {
	f.t.Helper()
	select {
	case value := <-f.output.events:
		if value != want {
			f.t.Fatal("source readiness protocol mismatch")
		}
	case <-time.After(8 * time.Second):
		f.t.Fatal("source readiness protocol timed out")
	}
}
func (f *treeWindowsFixture) write(value byte) {
	f.t.Helper()
	if n, err := f.input.Write([]byte{value}); err != nil || n != 1 {
		f.t.Fatal("source control write failed")
	}
}
func (f *treeWindowsFixture) beginWait() {
	f.t.Helper()
	if !f.bindingAttempted {
		f.t.Fatal("source Wait attempted before binding decision")
	}
	if f.waitStarted {
		f.t.Fatal("source process Wait repeated")
	}
	f.waitStarted = true
	f.waitDone = make(chan struct{})
	go func() { defer close(f.waitDone); f.waitErr = f.cmd.Wait() }()
}
func (f *treeWindowsFixture) wait() {
	f.t.Helper()
	if !f.waitStarted {
		f.beginWait()
	}
	waitTreeProtocol(f.t, f.waitDone, "owned source Wait did not finish")
}
func (f *treeWindowsFixture) close() {
	for i := len(f.releases) - 1; i >= 0; i-- {
		f.releases[i]()
	}
	if !f.started {
		_ = f.owner.Close()
		if f.cancel != nil {
			f.cancel()
		}
		if f.input != nil {
			_ = f.input.Close()
		}
		if f.job != 0 {
			_ = windows.CloseHandle(f.job)
		}
		return
	}
	if !f.bindingAttempted {
		_ = f.bind()
	}
	// This is an exact unnamed kernel job owned only by this source fixture, not
	// a raw process/PID signal. It also contains the source parent's descendants.
	if f.assigned {
		if windows.TerminateJobObject(f.job, 1) != nil {
			f.t.Error("owned source job cleanup failed")
		}
	} else if !f.waitStarted {
		var terminateErr error
		borrowErr := f.cmd.Process.WithHandle(func(handle uintptr) { terminateErr = windows.TerminateProcess(windows.Handle(handle), 1) })
		if borrowErr != nil || terminateErr != nil {
			f.t.Error("unassigned exact source parent cleanup failed")
		}
	}
	if !f.waitStarted {
		f.beginWait()
	}
	select {
	case <-f.waitDone:
	case <-time.After(10 * time.Second):
		f.t.Error("source Wait unconfirmed; native handles retained")
		return
	}
	if f.owner.Close() != nil {
		f.t.Error("source owner duplicate close failed")
	}
	if f.cancel != nil {
		f.cancel()
	}
	if f.input != nil {
		if err := f.input.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			f.t.Error("source control endpoint close failed")
		}
	}
	if f.job != 0 {
		if windows.CloseHandle(f.job) != nil {
			f.t.Error("source private job close failed")
		}
		f.job = 0
	}
}

func TestNativeWindowsTerminationKillsOwnedTree(t *testing.T) {
	parent := newTreeWindowsFixture(t, "tree", nil, nil)
	if parent.bind() != nil {
		t.Fatal("source tree binding failed")
	}
	parent.beginWait() // Every duplicate and job binding is established first.
	parent.write('g')
	parent.read('t')
	if active, err := treeWindowsActive(parent.job); err != nil || active != 2 {
		t.Fatal("private source job did not contain the exact inert tree")
	}
	unrelated := newTreeWindowsFixture(t, "controlled", nil, nil)
	if unrelated.bind() != nil {
		t.Fatal("unrelated source binding failed")
	}
	unrelatedHandle, _, _, _ := unrelated.backend.snapshot()
	if parent.owner.Cancel() != nil {
		t.Fatal("native tree helper did not terminate the owned source tree")
	}
	parent.wait()
	if parent.waitErr == nil {
		t.Fatal("native owned tree termination lost its real Wait error")
	}
	if parent.owner.Close() != nil {
		t.Fatal("native tree owner did not close after actual Wait")
	}
	treeWindowsAwaitEmpty(t, parent.job)
	state, err := windows.WaitForSingleObject(windows.Handle(unrelatedHandle), 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("distinct source process was terminated by tree cleanup")
	}
	if !parent.output.valid() || !unrelated.output.valid() {
		t.Fatal("native source output exceeded closed protocol")
	}
}

func TestNativeWindowsDuplicatePinsIdentityAfterGoWaitAndIsNoninheritable(t *testing.T) {
	f := newTreeWindowsFixture(t, "controlled", func(b *treeObservedWindowsBackend) {
		b.treeFn = func(handle uintptr, pid int) error {
			actual, err := windows.GetProcessId(windows.Handle(handle))
			if err != nil || int(actual) != pid {
				return errTreeBinding
			}
			return nil
		}
	}, nil)
	if f.bind() != nil {
		t.Fatal("native source duplicate binding failed")
	}
	handle, duplicates, _, _ := f.backend.snapshot()
	if handle == 0 || duplicates != 1 {
		t.Fatal("native duplicate was not retained exactly once")
	}
	flags, err := treeWindowsHandleFlags(handle)
	if err != nil || flags&windows.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("native retained duplicate was inheritable")
	}
	before, err := windows.GetProcessId(windows.Handle(handle))
	if err != nil || int(before) != f.cmd.Process.Pid {
		t.Fatal("native duplicate did not identify its exact source parent")
	}
	f.beginWait()
	f.write('q')
	f.wait()
	if f.waitErr != nil {
		t.Fatal("source zero exit lost actual Go Wait result")
	}
	after, err := windows.GetProcessId(windows.Handle(handle))
	if err != nil || after != before {
		t.Fatal("retained native duplicate did not survive the sole Go Wait")
	}
	state, err := windows.WaitForSingleObject(windows.Handle(handle), 0)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("retained duplicate did not refer to the terminated source process")
	}
	if err := f.cmd.Process.WithHandle(func(uintptr) { t.Error("retired Go handle unexpectedly remained borrowable") }); err == nil {
		t.Fatal("Go Wait did not retire the original handle")
	}
	if f.owner.Cancel() != nil {
		t.Fatal("source-only helper observer lost retained identity after Wait")
	}
	if f.owner.Close() != nil || f.owner.Close() != nil {
		t.Fatal("native duplicate close was not idempotent")
	}
	treeProtocolUnavailable(t, f.owner.Cancel(), nil)
	_, _, closes, helpers := f.backend.snapshot()
	if closes != 1 || helpers != 1 {
		t.Fatal("retired native owner repeated helper or duplicate close")
	}
	treeWindowsAwaitEmpty(t, f.job)
}

func TestNativeWindowsCancellationBeforeBindWaitsForVerifiedHandle(t *testing.T) {
	entered := make(chan struct{})
	f := newTreeWindowsFixture(t, "controlled", nil, entered)
	f.cancel()
	waitTreeProtocol(t, entered, "source cancellation did not reach pre-bind gate")
	if _, _, _, helpers := f.backend.snapshot(); helpers != 0 {
		t.Fatal("native helper dispatched before handle binding")
	}
	if f.bind() != nil {
		t.Fatal("native canceled-before-bind identity was not established")
	}
	f.wait()
	if f.waitErr == nil {
		t.Fatal("native cancellation did not retain actual process exit")
	}
	if f.owner.Close() != nil {
		t.Fatal("native canceled-before-bind close failed")
	}
	_, _, closes, helpers := f.backend.snapshot()
	if closes != 1 || helpers != 1 {
		t.Fatal("native pre-bind cancellation repeated or skipped its helper")
	}
	treeWindowsAwaitEmpty(t, f.job)
}

func TestNativeWindowsBindFailureDrainsStartedParentWithoutNumericHelper(t *testing.T) {
	failure := errors.New("PRIVATE_TREE_DUPLICATE_FAILURE")
	f := newTreeWindowsFixture(t, "controlled", func(b *treeObservedWindowsBackend) { b.duplicateErr = failure }, nil)
	treeProtocolUnavailable(t, f.bind(), failure)
	treeProtocolUnavailable(t, f.owner.Cancel(), failure)
	f.wait()
	if f.waitErr == nil {
		t.Fatal("failed binding did not drain its successfully started source parent")
	}
	if f.owner.Close() != nil {
		t.Fatal("failed native binding close failed")
	}
	handle, _, closes, helpers := f.backend.snapshot()
	if handle != 0 || closes != 0 || helpers != 0 {
		t.Fatal("failed native binding dispatched numeric helper or invented duplicate")
	}
	treeWindowsAwaitEmpty(t, f.job)
}

func TestNativeWindowsCloseWaitsForActiveHelperAfterActualGoWait(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f := newTreeWindowsFixture(t, "controlled", func(b *treeObservedWindowsBackend) {
		b.treeFn = func(handle uintptr, pid int) error {
			before, err := windows.GetProcessId(windows.Handle(handle))
			if err != nil || int(before) != pid {
				return errTreeBinding
			}
			close(entered)
			<-release
			after, err := windows.GetProcessId(windows.Handle(handle))
			if err != nil || after != before {
				return errTreeBinding
			}
			return nil
		}
	}, nil)
	f.releases = append(f.releases, unblock)
	if f.bind() != nil {
		t.Fatal("native helper retention binding failed")
	}
	canceled := startTreeProtocolCall(f.owner.Cancel)
	t.Cleanup(func() { unblock(); joinTreeProtocolCall(t, canceled) })
	waitTreeProtocol(t, entered, "native helper did not enter retained scope")
	f.beginWait()
	f.write('q')
	f.wait()
	if f.waitErr != nil {
		t.Fatal("native helper observer changed source zero exit")
	}
	closed := startTreeProtocolCall(f.owner.Close)
	t.Cleanup(func() { unblock(); joinTreeProtocolCall(t, closed) })
	select {
	case <-closed.done:
		t.Fatal("native owner closed while helper still retained PID identity")
	default:
	}
	if _, _, closes, _ := f.backend.snapshot(); closes != 0 {
		t.Fatal("native duplicate closed before active helper returned")
	}
	unblock()
	if joinTreeProtocolCall(t, canceled) != nil || joinTreeProtocolCall(t, closed) != nil {
		t.Fatal("native helper or duplicate close did not finish")
	}
	_, _, closes, helpers := f.backend.snapshot()
	if closes != 1 || helpers != 1 {
		t.Fatal("native helper/close generation executed more than once")
	}
	treeWindowsAwaitEmpty(t, f.job)
}

func TestNativeWindowsHelperFailureUsesRetainedParentAndKeepsUncertainty(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "missing.exe")
	f := newTreeWindowsFixture(t, "controlled", func(b *treeObservedWindowsBackend) {
		b.treeFn = func(handle uintptr, _ int) error {
			return terminateCommand(terminationCommand{executable: missing}, time.Second, func() error { return b.treeBackend.terminate(handle) })
		}
	}, nil)
	if f.bind() != nil {
		t.Fatal("native helper-failure binding failed")
	}
	f.beginWait()
	first := f.owner.Cancel()
	treeProtocolUnavailable(t, first, nil)
	if !errors.Is(first, os.ErrNotExist) && !errors.Is(first, exec.ErrNotFound) {
		t.Fatal("native helper failure lost actual launch cause")
	}
	f.wait()
	if f.waitErr == nil {
		t.Fatal("native helper-failure fallback did not terminate exact source parent")
	}
	if f.owner.Cancel() != first {
		t.Fatal("native failed helper result was retried or changed")
	}
	if f.owner.Close() != nil {
		t.Fatal("native failed helper duplicate close failed")
	}
	_, _, closes, helpers := f.backend.snapshot()
	if closes != 1 || helpers != 1 {
		t.Fatal("native failed helper or close executed repeatedly")
	}
	treeWindowsAwaitEmpty(t, f.job)
}

func TestNativeWindowsLegacyLateCallCannotReopenRetiredPID(t *testing.T) {
	f := newTreeWindowsFixture(t, "controlled", nil, nil)
	if f.bind() != nil {
		t.Fatal("legacy guard fixture binding failed")
	}
	f.beginWait()
	f.write('q')
	f.wait()
	if f.waitErr != nil {
		t.Fatal("legacy guard fixture did not exit cleanly")
	}
	treeProtocolUnavailable(t, TerminateTree(f.cmd.Process), nil)
	if f.owner.Close() != nil {
		t.Fatal("legacy guard fixture close failed")
	}
	treeWindowsAwaitEmpty(t, f.job)
}
