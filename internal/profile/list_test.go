package profile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type listed struct {
	profiles []Profile
	err      error
}

func listingFixture(t *testing.T) (*Store, Profile) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := New("shared-profile", "Shared profile", "byedpi")
	p.Args = []string{"--split", "2"}
	p.Routing.IncludeDomains = []string{"example.com"}
	p.Routing.ExcludeDomains = []string{"other.example.com"}
	p.Routing.Applications = []string{"fixture.exe"}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	original, err := store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	return store, original
}

func waitListing(t *testing.T, s *Store, count int) *listRead {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		s.listMu.Lock()
		read := s.listing
		ready := read != nil && read.waiters == count
		s.listMu.Unlock()
		if ready {
			return read
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("readers did not join one pending transaction")
	return nil
}

func TestConcurrentListsShareTransactionButOwnTheirResults(t *testing.T) {
	s, original := listingFixture(t)
	hold, err := s.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	const readers = 12
	results := make(chan listed, readers)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range readers {
		go func() { rows, err := s.ListContext(ctx); results <- listed{rows, err} }()
	}
	waitListing(t, s, readers)
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	first := <-results
	if first.err != nil || len(first.profiles) != 1 || !reflect.DeepEqual(first.profiles[0], original) {
		t.Fatal("first snapshot", first.err)
	}
	first.profiles[0].Name = "changed"
	first.profiles[0].Args[0] = "changed"
	first.profiles[0].Routing.IncludeDomains[0] = "changed"
	first.profiles[0].Routing.ExcludeDomains[0] = "changed"
	first.profiles[0].Routing.Applications[0] = "changed"
	for range readers - 1 {
		got := <-results
		if got.err != nil || len(got.profiles) != 1 || !reflect.DeepEqual(got.profiles[0], original) {
			t.Fatal("shared mutable profile escaped", got.err)
		}
	}
	if actual, err := s.Get(original.ID); err != nil || !reflect.DeepEqual(actual, original) {
		t.Fatal("caller changed saved profile", err)
	}
}

func TestListCancellationIsIndependentAndAbandonedReadStops(t *testing.T) {
	s, _ := listingFixture(t)
	hold, err := s.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	following, cancelFollowing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFollowing()
	a, b := make(chan error, 1), make(chan listed, 1)
	go func() { _, err := s.ListContext(first); a <- err }()
	waitListing(t, s, 1)
	go func() { rows, err := s.ListContext(following); b <- listed{rows, err} }()
	waitListing(t, s, 2)
	cancelFirst()
	if err := <-a; !errors.Is(err, context.Canceled) {
		t.Fatalf("first caller cancellation: %v", err)
	}
	select {
	case <-b:
		t.Fatal("canceling first caller canceled the follower")
	default:
	}
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-b; got.err != nil || len(got.profiles) != 1 {
		t.Fatal("follower failed", got.err)
	}
	// Every waiter leaving must cancel the pending OS-lock acquisition.
	hold, err = s.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	abandoned, cancelAbandoned := context.WithCancel(context.Background())
	end := make(chan error, 1)
	go func() { _, err := s.ListContext(abandoned); end <- err }()
	read := waitListing(t, s, 1)
	cancelAbandoned()
	if err := <-end; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-read.done:
	case <-time.After(time.Second):
		t.Fatal("abandoned transaction kept waiting for the file lock")
	}
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.List(); err != nil || len(rows) != 1 {
		t.Fatal("fresh request joined abandoned read", err)
	}
}

func TestCancelingFollowerPreservesFirstReader(t *testing.T) {
	s, _ := listingFixture(t)
	hold, err := s.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	leader, cancelLeader := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelLeader()
	follower, cancelFollower := context.WithCancel(context.Background())
	defer cancelFollower()
	a, b := make(chan listed, 1), make(chan error, 1)
	go func() { rows, err := s.ListContext(leader); a <- listed{rows, err} }()
	waitListing(t, s, 1)
	go func() { _, err := s.ListContext(follower); b <- err }()
	waitListing(t, s, 2)
	cancelFollower()
	if err := <-b; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-a:
		t.Fatal("follower canceled the first reader")
	default:
	}
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-a; got.err != nil || len(got.profiles) != 1 {
		t.Fatal("first reader failed", got.err)
	}
}

func TestCompletedListsNeverCacheMutationsErrorsOrCallerChanges(t *testing.T) {
	s, p := listingFixture(t)
	writer, err := NewStore(s.Root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}
	p.Name = "Updated on disk"
	if err := writer.Save(p); err != nil {
		t.Fatal(err)
	}
	rows, err := s.List()
	if err != nil || len(rows) != 1 || rows[0].Name != p.Name {
		t.Fatal("stale completed read", err)
	}
	file := filepath.Join(s.Root, "profiles", p.ID+".json")
	if err := os.WriteFile(file, []byte("broken JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("completed result hid corrupt storage")
	}
	if err := writer.Save(p); err != nil {
		t.Fatal(err)
	}
	if rows, err = s.List(); err != nil || len(rows) != 1 {
		t.Fatal("completed error was retained", err)
	}
	if err := writer.Delete(p.ID); err != nil {
		t.Fatal(err)
	}
	if rows, err = s.List(); err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("stale or null empty result", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ListContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request returned data", err)
	}
}

func TestListsStayFreshAcrossConcurrentCompletedWrites(t *testing.T) {
	s, p := listingFixture(t)
	writer, err := NewStore(s.Root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	end := make(chan error, 1)
	go func() {
		for {
			if _, err := s.ListContext(ctx); err != nil {
				end <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	defer func() {
		cancel()
		select {
		case err := <-end:
			if !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("reader did not stop")
		}
		final, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		lock, err := s.lock(final)
		if err != nil {
			t.Error(err)
		} else {
			lock.Close()
		}
	}()
	for i := 0; i < 30; i++ {
		p.Name = fmt.Sprintf("Committed revision %d", i)
		if err := writer.Save(p); err != nil {
			t.Fatal(err)
		}
		rows, err := s.List()
		if err != nil || len(rows) != 1 || rows[0].Name != p.Name {
			t.Fatalf("a completed write was hidden by an older read: %v", err)
		}
	}
}
