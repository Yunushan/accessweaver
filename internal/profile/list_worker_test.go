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
		})
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

func TestPublishedInventoryCannotBeJoinedBeforeCleanupCompletes(t *testing.T) {
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
	result := make(chan listed, 1)
	reader, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	go func() { rows, err := store.ListContext(reader); result <- listed{rows, err} }()
	waitListing(t, store, 1)
	// Stage the real locked snapshot, then hold the cleanup function used by
	// the production completion path. The slot must outlive that native call.
	store.publishList(read, []Profile{original}, nil)
	closing, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseClose := func() { releaseOnce.Do(func() { close(release) }) }
	go func() {
		store.completeList(read, func() error { close(closing); <-release; return lock.Close() })
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
	for range 8 {
		retry, stop := context.WithTimeout(context.Background(), time.Second)
		answer := make(chan listed, 1)
		go func() { rows, err := store.ListContext(retry); answer <- listed{rows, err} }()
		select {
		case got := <-answer:
			stop()
			if !errors.Is(got.err, ErrStoreBusy) || got.profiles != nil {
				t.Fatal("published read was joined before native cleanup", got.err)
			}
		case <-time.After(time.Second):
			stop()
			t.Fatal("cleanup held the inventory control mutex")
		}
	}
	select {
	case <-result:
		t.Fatal("reader woke before cleanup returned")
	default:
	}
	releaseClose()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not finish")
	}
	select {
	case got := <-result:
		if got.err != nil || len(got.profiles) != 1 || got.profiles[0].Name != original.Name {
			t.Fatal("original reader lost its consistent snapshot", got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cleaned reader was not notified")
	}
	updated := original
	updated.Name = "New transaction after cleanup"
	if err := store.Save(updated); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List()
	if err != nil || len(rows) != 1 || rows[0].Name != updated.Name {
		t.Fatal("completed slot leaked a stale result", err)
	}
}
