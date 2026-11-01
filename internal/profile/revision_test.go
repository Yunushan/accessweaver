package profile

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCheckedWritesRejectStaleAndDeletedRevisions(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	draft := New("revision-test", "First", "byedpi")
	if err = s.SaveIfUnchanged(draft); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveIfUnchanged(draft); !errors.Is(err, ErrConflict) {
		t.Fatalf("creation replaced an existing profile: %v", err)
	}
	first, err := s.Get(draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	edit := first.Copy()
	edit.Name = "Latest edit"
	if err = s.SaveIfUnchanged(edit); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveIfUnchanged(first); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit accepted: %v", err)
	}
	if err = s.DeleteIfUnchanged(first.ID, first.UpdatedAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale deletion accepted: %v", err)
	}
	latest, err := s.Get(first.ID)
	if err != nil || latest.Name != "Latest edit" {
		t.Fatalf("newer data lost: %+v %v", latest, err)
	}
	if err = s.DeleteIfUnchanged(latest.ID, latest.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveIfUnchanged(latest); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale editor resurrected a deleted profile: %v", err)
	}
	if _, err = s.Get(latest.ID); !os.IsNotExist(err) {
		t.Fatalf("deleted profile returned: %v", err)
	}
}

func TestCheckedConcurrentSavesHaveOneWinner(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := New("concurrent-edit", "Original", "byedpi")
	if err = s.Save(p); err != nil {
		t.Fatal(err)
	}
	p, err = s.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 12)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			edit := p.Copy()
			edit.Name = "Edited"
			results <- s.SaveIfUnchanged(edit)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent save winners: %d", winners)
	}
}

func TestCheckedWritePreservesCorruptProfile(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Root, "profiles", "corrupt-test.json")
	if err = os.WriteFile(path, []byte("retain damaged data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveIfUnchanged(New("corrupt-test", "Replacement", "byedpi")); err == nil {
		t.Fatal("corrupt profile overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "retain damaged data" {
		t.Fatal("corrupt data was not preserved", err)
	}
}
