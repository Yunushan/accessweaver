package nativeprocess

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// These handles and PIDs are virtual protocol values. Every operation is an
// instance-local fake callback; this suite performs no native handle or process
// lookup and provides no Windows runtime qualification.
const treeVirtualOriginal uintptr = 11
const treeVirtualDuplicate uintptr = 22
const treeVirtualPID = 37

type treeProtocolBackend struct {
	mu                                                                                    sync.Mutex
	withErr, duplicateErr, originalIDErr, duplicateIDErr, treeErr, terminateErr, closeErr error
	originalID, duplicateID                                                               int
	withCalls, duplicateCalls                                                             int
	queries                                                                               []uintptr
	terminated, closed                                                                    []uintptr
	helpers                                                                               []struct {
		handle uintptr
		pid    int
	}
	treeEntered chan struct{}
	treeRelease <-chan struct{}
}

func newTreeProtocolBackend() *treeProtocolBackend {
	return &treeProtocolBackend{originalID: treeVirtualPID, duplicateID: treeVirtualPID}
}
func (b *treeProtocolBackend) withHandle(_ *os.Process, fn func(uintptr)) error {
	b.mu.Lock()
	b.withCalls++
	err := b.withErr
	b.mu.Unlock()
	if err != nil {
		return err
	}
	fn(treeVirtualOriginal)
	return nil
}
func (b *treeProtocolBackend) duplicate(handle uintptr) (uintptr, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.duplicateCalls++
	if handle != treeVirtualOriginal {
		return 0, errors.New("virtual original handle mismatch")
	}
	if b.duplicateErr != nil {
		return 0, b.duplicateErr
	}
	return treeVirtualDuplicate, nil
}
func (b *treeProtocolBackend) processID(handle uintptr) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.queries = append(b.queries, handle)
	switch handle {
	case treeVirtualOriginal:
		return b.originalID, b.originalIDErr
	case treeVirtualDuplicate:
		return b.duplicateID, b.duplicateIDErr
	}
	return 0, errors.New("unknown virtual query handle")
}
func (b *treeProtocolBackend) terminate(handle uintptr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.terminated = append(b.terminated, handle)
	return b.terminateErr
}
func (b *treeProtocolBackend) close(handle uintptr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = append(b.closed, handle)
	return b.closeErr
}
func (b *treeProtocolBackend) tree(handle uintptr, pid int) error {
	b.mu.Lock()
	b.helpers = append(b.helpers, struct {
		handle uintptr
		pid    int
	}{handle, pid})
	entered, release, err := b.treeEntered, b.treeRelease, b.treeErr
	b.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return err
}
func (b *treeProtocolBackend) counts() (helpers, terminations, closes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.helpers), len(b.terminated), len(b.closed)
}

type treeProtocolCall struct {
	done chan struct{}
	err  error
}

func startTreeProtocolCall(fn func() error) *treeProtocolCall {
	call := &treeProtocolCall{done: make(chan struct{})}
	go func() { defer close(call.done); call.err = fn() }()
	return call
}
func joinTreeProtocolCall(t *testing.T, call *treeProtocolCall) error {
	t.Helper()
	select {
	case <-call.done:
		return call.err
	case <-time.After(8 * time.Second):
		t.Fatal("virtual tree owner operation did not finish")
		return nil
	}
}
func waitTreeProtocol(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal(message)
	}
}
func treeProtocolUnavailable(t *testing.T, err error, cause error) {
	t.Helper()
	if !errors.Is(err, ErrTreeOwnerUnavailable) {
		t.Fatal("tree protocol did not retain fixed ownership uncertainty")
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatal("tree protocol discarded original failure")
	}
	if len(err.Error()) > 256 || strings.Contains(err.Error(), "PRIVATE_TREE_") {
		t.Fatal("tree protocol exposed private failure detail")
	}
}

func TestTreeOwnerProtocolCancellationWaitsForPreWaitBinding(t *testing.T) {
	backend := newTreeProtocolBackend()
	owner := newTreeOwnerWithBackend(backend)
	canceled := startTreeProtocolCall(owner.Cancel)
	t.Cleanup(func() { _ = owner.Close(); joinTreeProtocolCall(t, canceled) })
	select {
	case <-canceled.done:
		t.Fatal("virtual pre-bind cancellation bypassed readiness gate")
	default:
	}
	if helpers, _, _ := backend.counts(); helpers != 0 {
		t.Fatal("virtual helper ran before binding")
	}
	process := &os.Process{Pid: treeVirtualPID}
	if err := owner.Bind(process); err != nil {
		t.Fatal("virtual pre-Wait binding failed")
	}
	if err := joinTreeProtocolCall(t, canceled); err != nil {
		t.Fatal("virtual cancellation did not continue after binding")
	}
	backend.mu.Lock()
	valid := len(backend.helpers) == 1 && backend.helpers[0].handle == treeVirtualDuplicate && backend.helpers[0].pid == treeVirtualPID
	backend.mu.Unlock()
	if !valid {
		t.Fatal("virtual helper did not receive exact retained binding")
	}
	if err := owner.Close(); err != nil {
		t.Fatal("virtual retained owner close failed")
	}
	if err := owner.Close(); err != nil {
		t.Fatal("virtual owner close was not idempotent")
	}
	treeProtocolUnavailable(t, owner.Cancel(), nil)
	if helpers, _, closes := backend.counts(); helpers != 1 || closes != 1 {
		t.Fatal("virtual retired owner repeated a helper or handle close")
	}
}

func TestTreeOwnerProtocolFailedStartCloseReleasesPendingCancellation(t *testing.T) {
	backend := newTreeProtocolBackend()
	owner := newTreeOwnerWithBackend(backend)
	canceled := startTreeProtocolCall(owner.Cancel)
	t.Cleanup(func() { _ = owner.Close(); joinTreeProtocolCall(t, canceled) })
	first := owner.Close()
	second := owner.Close()
	if first != second {
		t.Fatal("virtual failed-start close changed its result")
	}
	treeProtocolUnavailable(t, joinTreeProtocolCall(t, canceled), nil)
	backend.mu.Lock()
	calls := backend.withCalls + backend.duplicateCalls + len(backend.helpers) + len(backend.terminated) + len(backend.closed)
	backend.mu.Unlock()
	if calls != 0 {
		t.Fatal("unbound virtual owner attempted a native operation")
	}
}

func TestTreeOwnerProtocolUsesImmutableHandleDerivedPID(t *testing.T) {
	backend := newTreeProtocolBackend()
	owner := newTreeOwnerWithBackend(backend)
	t.Cleanup(func() { _ = owner.Close() })
	process := &os.Process{Pid: treeVirtualPID}
	if owner.Bind(process) != nil {
		t.Fatal("virtual immutable binding failed")
	}
	// This is synthetic data only, never a kernel PID or live os.Process.
	process.Pid = treeVirtualPID + 1
	if owner.Cancel() != nil {
		t.Fatal("virtual retained identity followed mutable Process.Pid")
	}
	backend.mu.Lock()
	valid := len(backend.helpers) == 1 && backend.helpers[0].pid == treeVirtualPID && backend.helpers[0].handle == treeVirtualDuplicate
	backend.mu.Unlock()
	if !valid {
		t.Fatal("virtual numeric target was reconstructed from mutable process data")
	}
}

func TestTreeOwnerProtocolBindingFailureCannotDispatchNumericHelper(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*treeProtocolBackend, error)
		fallback  bool
	}{
		{"borrow-refused", func(b *treeProtocolBackend, e error) { b.withErr = e }, false},
		{"duplicate-refused", func(b *treeProtocolBackend, e error) { b.duplicateErr = e }, true},
		{"duplicate-query-refused", func(b *treeProtocolBackend, e error) { b.duplicateIDErr = e }, true},
		{"mismatched-duplicate", func(b *treeProtocolBackend, _ error) { b.duplicateID = treeVirtualPID + 1 }, true},
		{"invalid-duplicate-id", func(b *treeProtocolBackend, _ error) { b.duplicateID = 0 }, true},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			backend := newTreeProtocolBackend()
			cause := errors.New("PRIVATE_TREE_BIND_FAILURE")
			item.configure(backend, cause)
			owner := newTreeOwnerWithBackend(backend)
			t.Cleanup(func() { _ = owner.Close() })
			err := owner.Bind(&os.Process{Pid: treeVirtualPID})
			treeProtocolUnavailable(t, err, nil)
			treeProtocolUnavailable(t, owner.Cancel(), nil)
			backend.mu.Lock()
			helperCount := len(backend.helpers)
			terminated := append([]uintptr(nil), backend.terminated...)
			duplicated := backend.duplicateCalls > 0 && backend.duplicateErr == nil
			backend.mu.Unlock()
			if helperCount != 0 {
				t.Fatal("invalid virtual binding dispatched numeric helper")
			}
			if item.fallback {
				if len(terminated) != 1 || terminated[0] != treeVirtualOriginal {
					t.Fatal("binding failure did not use only the proven original handle fallback")
				}
			} else if len(terminated) != 0 {
				t.Fatal("borrow failure invented a parent fallback handle")
			}
			if owner.Close() != nil {
				t.Fatal("failed virtual binding did not release owned duplicate")
			}
			_, _, closed := backend.counts()
			want := 0
			if duplicated {
				want = 1
			}
			if closed != want {
				t.Fatal("failed virtual binding leaked or repeated duplicate close")
			}
		})
	}
}

func TestTreeOwnerProtocolCloseWaitsForActiveHelper(t *testing.T) {
	backend := newTreeProtocolBackend()
	entered, release := make(chan struct{}), make(chan struct{})
	backend.treeEntered, backend.treeRelease = entered, release
	owner := newTreeOwnerWithBackend(backend)
	var once sync.Once
	var canceled, closed, again *treeProtocolCall
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		_ = owner.Close()
		for _, call := range []*treeProtocolCall{canceled, closed, again} {
			if call != nil {
				joinTreeProtocolCall(t, call)
			}
		}
	})
	if owner.Bind(&os.Process{Pid: treeVirtualPID}) != nil {
		t.Fatal("virtual active-helper binding failed")
	}
	canceled = startTreeProtocolCall(owner.Cancel)
	waitTreeProtocol(t, entered, "virtual helper was not admitted")
	closed = startTreeProtocolCall(owner.Close)
	again = startTreeProtocolCall(owner.Cancel)
	select {
	case <-closed.done:
		t.Fatal("virtual owner closed while helper still used its retained handle")
	default:
	}
	if _, _, closes := backend.counts(); closes != 0 {
		t.Fatal("virtual helper handle was released before helper completion")
	}
	once.Do(func() { close(release) })
	if joinTreeProtocolCall(t, canceled) != nil {
		t.Fatal("virtual admitted helper did not complete")
	}
	if joinTreeProtocolCall(t, closed) != nil {
		t.Fatal("virtual Close did not join admitted helper")
	}
	// The concurrent repeat may join the first result or observe retirement.
	if err := joinTreeProtocolCall(t, again); err != nil && !errors.Is(err, ErrTreeOwnerUnavailable) {
		t.Fatal("virtual repeated cancellation returned an unrelated error")
	}
	if helpers, _, closes := backend.counts(); helpers != 1 || closes != 1 {
		t.Fatal("concurrent virtual calls repeated helper or close")
	}
}

func TestTreeOwnerProtocolHelperFailureRetainsFixedUncertainty(t *testing.T) {
	backend := newTreeProtocolBackend()
	cause := errors.New("PRIVATE_TREE_HELPER_FAILURE" + strings.Repeat("x", 32<<10))
	backend.treeErr = cause
	owner := newTreeOwnerWithBackend(backend)
	t.Cleanup(func() { _ = owner.Close() })
	if owner.Bind(&os.Process{Pid: treeVirtualPID}) != nil {
		t.Fatal("virtual helper-failure binding failed")
	}
	first := owner.Cancel()
	treeProtocolUnavailable(t, first, cause)
	if second := owner.Cancel(); second != first {
		t.Fatal("virtual helper failure was retried or changed")
	}
	// The backend owns its helper/fallback transaction. The outer protocol
	// caches its failure without adding an independent second parent kill.
	if _, terminations, _ := backend.counts(); terminations != 0 {
		t.Fatal("owner invented another fallback outside the backend transaction")
	}
	if owner.Close() != nil {
		t.Fatal("virtual failed helper did not release retained handle")
	}
	if helpers, _, closes := backend.counts(); helpers != 1 || closes != 1 {
		t.Fatal("failed virtual helper was repeated or duplicate was closed twice")
	}
}

func TestTreeOwnerProtocolCloseFailureIsFixedAndExactlyOnce(t *testing.T) {
	backend := newTreeProtocolBackend()
	cause := errors.New("PRIVATE_TREE_CLOSE_FAILURE")
	backend.closeErr = cause
	owner := newTreeOwnerWithBackend(backend)
	if owner.Bind(&os.Process{Pid: treeVirtualPID}) != nil {
		t.Fatal("virtual close-failure binding failed")
	}
	first := owner.Close()
	treeProtocolUnavailable(t, first, cause)
	if owner.Close() != first {
		t.Fatal("virtual close failure was not retained")
	}
	treeProtocolUnavailable(t, owner.Cancel(), nil)
	if helpers, _, closes := backend.counts(); helpers != 0 || closes != 1 {
		t.Fatal("retired virtual owner repeated helper or failed Close")
	}
}

func TestTreeOwnerProtocolInvalidRetainedIdentityForbidsHelperAndFallback(t *testing.T) {
	backend := newTreeProtocolBackend()
	owner := newTreeOwnerWithBackend(backend)
	t.Cleanup(func() { _ = owner.Close() })
	if owner.Bind(&os.Process{Pid: treeVirtualPID}) != nil {
		t.Fatal("virtual retained identity binding failed")
	}
	backend.mu.Lock()
	backend.duplicateID = treeVirtualPID + 1
	backend.mu.Unlock()
	first := owner.Cancel()
	treeProtocolUnavailable(t, first, nil)
	if owner.Cancel() != first {
		t.Fatal("invalid virtual identity was retried")
	}
	if helpers, terminations, _ := backend.counts(); helpers != 0 || terminations != 0 {
		t.Fatal("invalid retained identity dispatched helper or speculative fallback")
	}
}

func TestTreeOwnerProtocolRejectsRebindingAndRetiredGeneration(t *testing.T) {
	backend := newTreeProtocolBackend()
	owner := newTreeOwnerWithBackend(backend)
	if owner.Bind(&os.Process{Pid: treeVirtualPID}) != nil {
		t.Fatal("virtual generation binding failed")
	}
	treeProtocolUnavailable(t, owner.Bind(&os.Process{Pid: treeVirtualPID + 1}), nil)
	if owner.Cancel() != nil {
		t.Fatal("rejected rebinding changed original virtual ownership")
	}
	if owner.Close() != nil {
		t.Fatal("virtual generation close failed")
	}
	treeProtocolUnavailable(t, owner.Bind(&os.Process{Pid: treeVirtualPID}), nil)
	backend.mu.Lock()
	calls := backend.withCalls
	valid := len(backend.helpers) == 1 && backend.helpers[0].pid == treeVirtualPID
	backend.mu.Unlock()
	if calls != 1 || !valid {
		t.Fatal("virtual generation rebound or changed helper target")
	}
}
