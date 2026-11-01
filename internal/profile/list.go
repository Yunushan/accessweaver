package profile

import (
	"context"
	"slices"
)

// Only overlapping readers share a transaction. Completed results are never
// cached: a new request always observes a new acquisition of the OS store lock.
type listRead struct {
	done     chan struct{}
	cancel   context.CancelFunc
	waiters  int
	profiles []Profile
	err      error
}

func (s *Store) ListContext(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !canShareListRead() {
		// An impersonated Windows caller's access checks belong to its locked
		// OS thread. Never move that read to the process identity or let it join
		// another principal's transaction.
		lock, err := s.lock(ctx)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		return s.listLocked(ctx)
	}
	s.listMu.Lock()
	read := s.listing
	if read == nil {
		work, cancel := context.WithCancel(context.Background())
		read = &listRead{done: make(chan struct{}), cancel: cancel}
		s.listing = read
		go s.readList(work, read)
	}
	read.waiters++
	s.listMu.Unlock()
	select {
	case <-ctx.Done():
		s.releaseList(read)
		return nil, ctx.Err()
	case <-read.done:
		s.releaseList(read)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if read.err != nil {
			return nil, read.err
		}
		// API callers and support summaries must not share mutable profile slices.
		out := slices.Clone(read.profiles)
		for i := range out {
			out[i].Args = slices.Clone(out[i].Args)
			out[i].Routing.IncludeDomains = slices.Clone(out[i].Routing.IncludeDomains)
			out[i].Routing.ExcludeDomains = slices.Clone(out[i].Routing.ExcludeDomains)
			out[i].Routing.Applications = slices.Clone(out[i].Routing.Applications)
		}
		return out, nil
	}
}

func (s *Store) releaseList(read *listRead) {
	s.listMu.Lock()
	defer s.listMu.Unlock()
	read.waiters--
	if read.waiters == 0 {
		read.cancel()
		// Another request must not join an abandoned, canceled transaction.
		if s.listing == read {
			s.listing = nil
		}
	}
}

func (s *Store) readList(ctx context.Context, read *listRead) {
	lock, err := s.lock(ctx)
	if err != nil {
		s.completeList(read, nil, err)
		return
	}
	defer lock.Close()
	profiles, err := s.listLocked(ctx)
	// Detach and publish WHILE the OS lock is held. Otherwise a writer could
	// commit between unlock and publication and a later reader receive stale data.
	s.completeList(read, profiles, err)
}

func (s *Store) completeList(read *listRead, profiles []Profile, err error) {
	s.listMu.Lock()
	defer s.listMu.Unlock()
	read.profiles, read.err = profiles, err
	if s.listing == read {
		s.listing = nil
	}
	close(read.done)
}
