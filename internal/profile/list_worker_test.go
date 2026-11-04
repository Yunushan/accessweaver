package profile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAbandonedInventoryWorkerOwnsSlotUntilNativeReadReturns(t *testing.T) {
	store, original := listingFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseRead := func() { releaseOnce.Do(func() { close(release) }) }
	var active *listRead
	t.Cleanup(func() {
		releaseRead()
		if active != nil {
			select {
			case <-active.done:
			case <-time.After(3 * time.Second):
				t.Error("inventory worker did not clean up")
			}
		}
	})
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	result := make(chan listed, 1)
	var loads atomic.Int32
	go func() {
		rows, err := store.listContext(first, func(context.Context) ([]Profile, error) {
			loads.Add(1)
			close(entered)
			<-release // Deliberately cannot cooperate with cancellation, like native I/O.
			return []Profile{original}, nil
		}, 5*time.Second)
		result <- listed{rows, err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native-read seam did not start")
	}
	active = waitListing(t, store, 1)
	cancelFirst()
	select {
	case got := <-result:
		if !errors.Is(got.err, context.Canceled) || got.profiles != nil {
			t.Fatal("canceled reader received a result", got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceling caller waited for non-cooperative I/O")
	}
	store.listMu.Lock()
	retained := store.listing == active && active.abandoned && active.waiters == 0
	store.listMu.Unlock()
	if !retained {
		t.Fatal("canceled native reader lost its worker slot")
	}
	for range 32 {
		retry, stop := context.WithTimeout(context.Background(), time.Second)
		rows, err := store.ListContext(retry)
		stop()
		if !errors.Is(err, ErrStoreBusy) || rows != nil {
			t.Fatal("retry joined or replaced abandoned native work", err)
		}
		store.listMu.Lock()
		same := store.listing == active && active.waiters == 0
		store.listMu.Unlock()
		if !same {
			t.Fatal("retry allocated another inventory slot")
		}
	}
	if loads.Load() != 1 {
		t.Fatal("multiple native readers started", loads.Load())
	}
	alreadyCanceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := store.ListContext(alreadyCanceled); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled retry lost its cancellation", err)
	}
	releaseRead()
	select {
	case <-active.done:
	case <-time.After(3 * time.Second):
		t.Fatal("native reader did not release its slot")
	}
	updated := original
	updated.Name = "Committed after abandoned inventory"
	if err := store.Save(updated); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List()
	if err != nil || len(rows) != 1 || rows[0].Name != updated.Name {
		t.Fatal("new inventory reused abandoned snapshot or failed to recover", err)
	}
}

// Done is observed only when ListContext waits for the finishing transaction.
// It provides a deterministic wait marker without sleeping or changing the store.
type inventoryWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *inventoryWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestHealthyFinishingInventoryWaitsForFreshTransaction(t *testing.T) {
	store, original := listingFixture(t)
	lock, err := store.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	read := &listRead{done: make(chan struct{}), cancel: cancel}
	store.listMu.Lock()
	store.listing = read
	store.listMu.Unlock()
	first := make(chan listed, 1)
	reader, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	go func() { rows, err := store.ListContext(reader); first <- listed{rows, err} }()
	waitListing(t, store, 1)
	store.publishList(read, []Profile{original}, nil)
	closing, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseClose := func() { releaseOnce.Do(func() { close(release) }) }
	updated := original
	updated.Name = "Committed while previous read finishes"
	var cleanupErr error
	go func() {
		store.completeList(read, func() error {
			close(closing)
			<-release
			if err := lock.Close(); err != nil {
				cleanupErr = err
				return err
			}
			// This legitimate writer commits after unlock but before the old reader's
			// completion notification. A later caller must not receive its old snapshot.
			cleanupErr = store.Save(updated)
			return cleanupErr
		})
		close(finished)
	}()
	t.Cleanup(func() {
		releaseClose()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("native close seam did not return")
		}
	})
	select {
	case <-closing:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not enter native close")
	}
	lateCtx, stopLate := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopLate()
	waiting := &inventoryWaitContext{Context: lateCtx, entered: make(chan struct{})}
	late := make(chan listed, 1)
	go func() { rows, err := store.ListContext(waiting); late <- listed{rows, err} }()
	select {
	case <-waiting.entered:
	case got := <-late:
		t.Fatal("healthy cleanup returned instead of waiting", got.err)
	case <-time.After(time.Second):
		t.Fatal("cleanup held the inventory control mutex")
	}
	store.listMu.Lock()
	unjoined := store.listing == read && read.waiters == 1
	store.listMu.Unlock()
	if !unjoined {
		t.Fatal("late reader joined the finished snapshot or replaced its worker")
	}
	select {
	case got := <-late:
		t.Fatal("late reader returned before cleanup", got.err)
	default:
	}
	// Cancellation remains independent of the original reader and cleanup.
	canceled, stopCanceled := context.WithCancel(context.Background())
	cancelWaiting := &inventoryWaitContext{Context: canceled, entered: make(chan struct{})}
	cancelResult := make(chan error, 1)
	go func() { _, err := store.ListContext(cancelWaiting); cancelResult <- err }()
	select {
	case <-cancelWaiting.entered:
	case <-time.After(time.Second):
		stopCanceled()
		t.Fatal("cancelable caller did not wait")
	}
	stopCanceled()
	select {
	case err := <-cancelResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cleanup waiting lost cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for native cleanup")
	}
	// The deterministic budget seam avoids a five-second unit-test sleep while
	// exercising the same bounded admission branch used by the public method.
	if rows, err := store.listContext(context.Background(), store.listLocked, 0); !errors.Is(err, ErrStoreBusy) || !errors.Is(err, context.DeadlineExceeded) || rows != nil {
		t.Fatal("stuck healthy cleanup admitted a worker or waited without a budget", err)
	}
	select {
	case <-first:
		t.Fatal("original reader woke before cleanup returned")
	default:
	}
	releaseClose()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not finish")
	}
	if cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	select {
	case got := <-first:
		if got.err != nil || len(got.profiles) != 1 || got.profiles[0].Name != original.Name {
			t.Fatal("original read lost its consistent snapshot", got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original reader was not notified")
	}
	select {
	case got := <-late:
		if got.err != nil || len(got.profiles) != 1 || got.profiles[0].Name != updated.Name {
			t.Fatal("healthy later reader failed or reused the finished snapshot", got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("healthy later reader did not start a fresh transaction")
	}
}
