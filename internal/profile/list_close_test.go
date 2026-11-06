package profile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
)

// These fixtures own ordinary files and actual OS leases. Reported close
// cofailures are injected only AFTER the real lease Close has returned nil.
// They are not native kernel faults or an impersonated-user experiment.
type listCloseFixture struct {
	root     string
	store    *Store
	original Profile
	preserve atomic.Bool
	leases   []*listCloseLease
}
type listCloseLease struct {
	fixture   *listCloseFixture
	t         *testing.T
	lock      *filelock.Lock
	attempted atomic.Bool
	calls     atomic.Int32
}

func newListCloseFixture(t *testing.T) *listCloseFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-list-close-")
	if err != nil {
		t.Fatal("owned list-close fixture unavailable")
	}
	state, err := fileidentity.FromPath(root, false)
	if err != nil {
		t.Fatal("owned list-close fixture identity unavailable")
	}
	f := &listCloseFixture{root: root}
	t.Cleanup(func() {
		// A canceled caller can return before its fresh background worker has
		// finished. Caller/manual-close cleanup runs first; join that final owner
		// outside listMu before inspecting or removing this fixture root.
		if f.store != nil {
			f.store.listMu.Lock()
			active := f.store.listing
			f.store.listMu.Unlock()
			if active != nil {
				active.cancel()
				listCloseCleanupWait(t, f, active.done)
			}
			f.store.listMu.Lock()
			stillOwned := f.store.listing != nil
			f.store.listMu.Unlock()
			if stillOwned {
				f.preserve.Store(true)
				t.Error("unfinished list worker fixture retained")
			}
		}
		if f.preserve.Load() {
			t.Error("unconfirmed list-close fixture retained")
			return
		}
		for _, lease := range f.leases {
			if !lease.attempted.Load() {
				_ = lease.close()
			}
		}
		if f.preserve.Load() {
			t.Error("unconfirmed list-close fixture retained")
			return
		}
		current, err := fileidentity.FromPath(root, false)
		if err != nil || current.Kind != state.Kind || current.ID != state.ID {
			t.Error("changed list-close fixture retained")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned list-close fixture cleanup failed")
		}
	})
	f.store, err = NewStoreWithGuard(filepath.Join(root, "source"), managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Save(New("close-profile", "Original list profile", "byedpi")); err != nil {
		f.preserve.Store(true)
		t.Fatal("owned list fixture save failed")
	}
	f.original, err = f.store.Get("close-profile")
	if err != nil {
		f.preserve.Store(true)
		t.Fatal("owned list fixture read failed")
	}
	return f
}
func (f *listCloseFixture) acquire(t *testing.T) *listCloseLease {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lock, err := f.store.lock(ctx)
	if err != nil {
		f.preserve.Store(true)
		t.Fatal("actual list lease acquisition failed")
	}
	lease := &listCloseLease{fixture: f, t: t, lock: lock}
	f.leases = append(f.leases, lease)
	return lease
}
func (l *listCloseLease) close() error {
	l.calls.Add(1)
	if !l.attempted.CompareAndSwap(false, true) {
		l.fixture.preserve.Store(true)
		l.t.Error("actual list lease Close repeated")
		return errors.New("fixture close repeated")
	}
	err := l.lock.Close()
	if err != nil {
		l.fixture.preserve.Store(true)
		l.t.Error("actual list lease Close failed before injection")
	}
	return err
}
func (f *listCloseFixture) busy(t *testing.T) {
	t.Helper()
	lease, err := filelock.TryAcquire(filepath.Join(f.store.Root, ".profiles.lock"))
	if err == filelock.ErrBusy {
		return
	}
	if lease != nil {
		if closeErr := lease.Close(); closeErr != nil {
			f.preserve.Store(true)
		}
	}
	f.preserve.Store(true)
	t.Fatal("actual original list lease was not held")
}
func listCloseWait(t *testing.T, f *listCloseFixture, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		f.preserve.Store(true)
		t.Fatal("owned list-close operation did not finish")
	}
}
func listCloseCleanupWait(t *testing.T, f *listCloseFixture, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		f.preserve.Store(true)
		t.Error("unconfirmed list-close operation retained")
	}
}
func listCloseRows(t *testing.T, f *listCloseFixture) []Profile {
	t.Helper()
	rows, err := f.store.listLocked(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal("actual fixture list read failed")
	}
	return rows
}
func listCloseInstall(f *listCloseFixture) (*listRead, context.CancelFunc) {
	_, cancel := context.WithCancel(context.Background())
	read := &listRead{done: make(chan struct{}), cancel: cancel}
	f.store.listMu.Lock()
	f.store.listing = read
	f.store.listMu.Unlock()
	return read, cancel
}
func TestListCloseCompletionWithholdsProfilesAndHidesJoinedPrivateCauses(t *testing.T) {
	f := newListCloseFixture(t)
	lease := f.acquire(t)
	rows := listCloseRows(t, f)
	read, cancel := listCloseInstall(f)
	defer cancel()
	bodyCause, closeCause := errors.New("body cause"), errors.New("close cause")
	body := &os.PathError{Op: "read", Path: "PRIVATE_LIST_BODY", Err: bodyCause}
	closed := &os.PathError{Op: "close", Path: "PRIVATE_LIST_CLOSE", Err: closeCause}
	f.store.publishList(read, rows, body)
	f.store.completeList(read, func() error {
		if err := lease.close(); err != nil {
			return err
		}
		return closed
	})
	listCloseWait(t, f, read.done)
	if read.profiles != nil || !errors.Is(read.err, bodyCause) || !errors.Is(read.err, closeCause) {
		t.Fatal("close/body cofailure was lost or data adopted")
	}
	if read.err.Error() != "profile list cleanup could not be confirmed" || strings.Contains(read.err.Error(), "PRIVATE_LIST") {
		t.Fatal("private list failure appeared in public error")
	}
	if lease.calls.Load() != 1 {
		t.Fatal("native lease Close was not attempted once")
	}
	f.store.listMu.Lock()
	free := f.store.listing == nil
	f.store.listMu.Unlock()
	if !free {
		t.Fatal("completed list slot was not released")
	}
}
func TestListCloseCleanCompletionPreservesBodyIdentityAndSuccessfulRows(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "body-error"}[failed], func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			rows := listCloseRows(t, f)
			read, cancel := listCloseInstall(f)
			defer cancel()
			var body error
			if failed {
				body = errors.New("exact body identity")
			}
			f.store.publishList(read, rows, body)
			f.store.completeList(read, lease.close)
			listCloseWait(t, f, read.done)
			if read.err != body {
				t.Fatal("clean Close changed body error identity")
			}
			if failed && read.profiles != nil {
				t.Fatal("failed body retained adoptable profiles")
			}
			if !failed && !reflect.DeepEqual(read.profiles, rows) {
				t.Fatal("clean completion changed rows")
			}
		})
	}
}
func TestListCloseSynchronousHelperRetainsReadCloseCancellationCofailures(t *testing.T) {
	f := newListCloseFixture(t)
	lease := f.acquire(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bodyCause, closeCause := errors.New("body cause"), errors.New("close cause")
	body := &os.PathError{Op: "read", Path: "PRIVATE_SYNC_BODY", Err: bodyCause}
	closed := &os.PathError{Op: "close", Path: "PRIVATE_SYNC_CLOSE", Err: closeCause}
	reads := 0
	rows, err := readListSynchronously(ctx, func(context.Context) ([]Profile, error) { reads++; return listCloseRows(t, f), body }, func() error {
		actual := lease.close()
		cancel()
		if actual != nil {
			return actual
		}
		return closed
	})
	if rows != nil || !errors.Is(err, bodyCause) || !errors.Is(err, closeCause) || !errors.Is(err, context.Canceled) || reads != 1 || lease.calls.Load() != 1 {
		t.Fatal("synchronous cofailure was lost or adopted")
	}
	if err.Error() != "profile list cleanup could not be confirmed" {
		t.Fatal("synchronous private causes escaped")
	}
}
func TestListCloseSynchronousCleanIdentityAndExistingCancellationArePreserved(t *testing.T) {
	for _, mode := range []string{"success", "body", "already-canceled-cause"} {
		t.Run(mode, func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var body error
			if mode == "body" {
				body = errors.New("exact body error")
			}
			if mode == "already-canceled-cause" {
				body = errors.Join(errors.New("existing failure"), context.Canceled)
			}
			rows, err := readListSynchronously(ctx, func(context.Context) ([]Profile, error) { return listCloseRows(t, f), body }, func() error {
				actual := lease.close()
				if mode == "already-canceled-cause" {
					cancel()
				}
				return actual
			})
			if err != body {
				t.Fatal("clean Close or duplicate cancellation changed error identity")
			}
			if body != nil && rows != nil {
				t.Fatal("body error adopted rows")
			}
			if body == nil && (len(rows) != 1 || rows[0].ID != f.original.ID) {
				t.Fatal("clean synchronous read changed profiles")
			}
		})
	}
}
func TestListCloseGatedCompletionKeepsCohortAndLateReaderOwnership(t *testing.T) {
	f := newListCloseFixture(t)
	lease := f.acquire(t)
	rows := listCloseRows(t, f)
	read, workCancel := listCloseInstall(f)
	firstCtx, firstCancel := context.WithCancel(context.Background())
	secondCtx, secondCancel := context.WithCancel(context.Background())
	lateCtx, lateCancel := context.WithCancel(context.Background())
	firstDone, secondDone, lateDone, closeDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	gate, entered := make(chan struct{}), make(chan struct{})
	var gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(gate) }) }
	var first, second, late listed
	firstStarted, secondStarted, lateStarted, closeStarted := false, false, false, false
	t.Cleanup(func() {
		firstCancel()
		secondCancel()
		lateCancel()
		workCancel()
		release()
		if !closeStarted {
			f.store.completeList(read, lease.close)
		} else {
			listCloseCleanupWait(t, f, closeDone)
		}
		if firstStarted {
			listCloseCleanupWait(t, f, firstDone)
		}
		if secondStarted {
			listCloseCleanupWait(t, f, secondDone)
		}
		if lateStarted {
			listCloseCleanupWait(t, f, lateDone)
		}
	})
	firstStarted = true
	go func() { first.profiles, first.err = f.store.ListContext(firstCtx); close(firstDone) }()
	secondStarted = true
	go func() { second.profiles, second.err = f.store.ListContext(secondCtx); close(secondDone) }()
	waitListing(t, f.store, 2)
	bodyCause, closeCause := errors.New("read cofailure"), errors.New("close cofailure")
	f.store.publishList(read, rows, bodyCause)
	updated := f.original.Copy()
	updated.Name = "Committed after original lease closed"
	closeStarted = true
	go func() {
		f.store.completeList(read, func() error {
			close(entered)
			<-gate
			if err := lease.close(); err != nil {
				return err
			}
			if err := f.store.Save(updated); err != nil {
				f.preserve.Store(true)
				t.Error("post-unlock fixture writer failed")
				return err
			}
			return closeCause
		})
		close(closeDone)
	}()
	listCloseWait(t, f, entered)
	f.busy(t)
	firstCancel()
	listCloseWait(t, f, firstDone)
	if first.profiles != nil || !errors.Is(first.err, context.Canceled) {
		t.Fatal("canceled cohort reader adopted data or waited for Close")
	}
	waiting := &inventoryWaitContext{Context: lateCtx, entered: make(chan struct{})}
	lateStarted = true
	go func() { late.profiles, late.err = f.store.ListContext(waiting); close(lateDone) }()
	listCloseWait(t, f, waiting.entered)
	f.store.listMu.Lock()
	retained := f.store.listing == read && read.finishing && read.waiters == 1
	f.store.listMu.Unlock()
	if !retained {
		t.Fatal("late reader joined or replaced the finishing cohort")
	}
	select {
	case <-secondDone:
		t.Fatal("active cohort received data before Close")
	case <-lateDone:
		t.Fatal("late reader escaped finishing wait")
	default:
	}
	release()
	listCloseWait(t, f, closeDone)
	listCloseWait(t, f, secondDone)
	listCloseWait(t, f, lateDone)
	if second.profiles != nil || !errors.Is(second.err, bodyCause) || !errors.Is(second.err, closeCause) {
		t.Fatal("cohort adopted old data or lost close cause")
	}
	if late.err != nil || len(late.profiles) != 1 || late.profiles[0].Name != updated.Name {
		t.Fatal("fresh cohort did not acquire/read the actual newer revision")
	}
	if lease.calls.Load() != 1 {
		t.Fatal("original native lease Close repeated")
	}
}
func TestListCloseAbandonedCohortRetainsAdmissionUntilRealCloseReturns(t *testing.T) {
	f := newListCloseFixture(t)
	lease := f.acquire(t)
	rows := listCloseRows(t, f)
	read, workCancel := listCloseInstall(f)
	ctx, cancel := context.WithCancel(context.Background())
	done, closed := make(chan struct{}), make(chan struct{})
	entered, gate := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var got listed
	started := false
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() {
		cancel()
		workCancel()
		release()
		if !started {
			f.store.completeList(read, lease.close)
		} else {
			listCloseCleanupWait(t, f, closed)
		}
		listCloseCleanupWait(t, f, done)
	})
	go func() { got.profiles, got.err = f.store.ListContext(ctx); close(done) }()
	waitListing(t, f.store, 1)
	f.store.publishList(read, rows, nil)
	fault := errors.New("reported close cofailure")
	started = true
	go func() {
		f.store.completeList(read, func() error {
			close(entered)
			<-gate
			if err := lease.close(); err != nil {
				return err
			}
			return fault
		})
		close(closed)
	}()
	listCloseWait(t, f, entered)
	cancel()
	listCloseWait(t, f, done)
	if got.profiles != nil || !errors.Is(got.err, context.Canceled) {
		t.Fatal("abandoned caller adopted results")
	}
	f.store.listMu.Lock()
	abandoned := f.store.listing == read && read.abandoned && read.waiters == 0
	f.store.listMu.Unlock()
	if !abandoned {
		t.Fatal("abandoned close lost its existing slot")
	}
	if retry, err := f.store.ListContext(context.Background()); retry != nil || !errors.Is(err, ErrStoreBusy) {
		t.Fatal("retry replaced an abandoned in-flight close")
	}
	release()
	listCloseWait(t, f, closed)
	if read.profiles != nil || !errors.Is(read.err, fault) {
		t.Fatal("abandoned close error was discarded")
	}
	fresh, err := f.store.ListContext(context.Background())
	if err != nil || len(fresh) != 1 || fresh[0].ID != f.original.ID {
		t.Fatal("fresh cohort did not reacquire after actual close")
	}
}

func TestListCloseSynchronousBodyPanicStillClosesRealLeaseAndPreservesPanic(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "close-cofailure"}[fault], func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			originalPanic := &struct{ label string }{label: "PRIVATE_BODY_PANIC"}
			closeCause := errors.New("reported close cofailure")
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, _ = readListSynchronously(context.Background(), func(context.Context) ([]Profile, error) {
					_ = listCloseRows(t, f)
					panic(originalPanic)
				}, func() error {
					actual := lease.close()
					if actual != nil {
						return actual
					}
					if fault {
						return &os.PathError{Op: "close", Path: "PRIVATE_PANIC_CLOSE", Err: closeCause}
					}
					return nil
				})
				t.Error("body panic did not propagate")
			}()
			if recovered != originalPanic {
				t.Fatal("synchronous body panic was replaced or swallowed")
			}
			if lease.calls.Load() != 1 {
				t.Fatal("body panic skipped or repeated real lease Close")
			}
			// A separate native acquisition verifies the actual owned lease release;
			// neither the injected error nor the recovered panic is release authority.
			next, err := filelock.TryAcquire(filepath.Join(f.store.Root, ".profiles.lock"))
			if err != nil {
				f.preserve.Store(true)
				t.Fatal("fresh native acquisition failed after recovered body panic")
			}
			observed := &listCloseLease{fixture: f, t: t, lock: next}
			f.leases = append(f.leases, observed)
			if err := observed.close(); err != nil {
				t.Fatal("fresh lease Close failed")
			}
		})
	}
}
