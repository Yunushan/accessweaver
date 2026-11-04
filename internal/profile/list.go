package profile

import (
	"context"
	"slices"
)

// Only overlapping readers share a transaction. Completed results are never
// cached: a new transaction acquires the OS store lock again.
type listRead struct {
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int
	profiles  []Profile
	err       error
	abandoned bool
	finishing bool
}

func (s *Store) ListContext(ctx context.Context) ([]Profile, error) {
	return s.listContext(ctx, s.listLocked)
}

// The private reader seam permits deterministic tests of non-cooperative native
// I/O. Production always selects the store reader above, never request input.
func (s *Store) listContext(ctx context.Context, readLocked func(context.Context) ([]Profile, error)) ([]Profile, error) {
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
		return readLocked(ctx)
	}
	s.listMu.Lock()
	read := s.listing
	if read != nil && (read.abandoned || read.finishing) {
		s.listMu.Unlock()
		return nil, ErrStoreBusy
	}
	if read == nil {
		work, cancel := context.WithCancel(context.Background())
		read = &listRead{done: make(chan struct{}), cancel: cancel}
		s.listing = read
		go s.readList(work, read, readLocked)
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
		// Cancellation cannot interrupt every native read/open/close. Retain the
		// worker slot until actual cleanup so retries cannot accumulate workers.
		read.abandoned = true
	}
}

func (s *Store) readList(ctx context.Context, read *listRead, readLocked func(context.Context) ([]Profile, error)) {
	lock, err := s.lock(ctx)
	if err != nil {
		s.publishList(read, nil, err)
		s.completeList(read, nil)
		return
	}
	// Native Close can also block. Keep the slot through cleanup, without
	// holding listMu; controls and canceled waiters remain responsive.
	defer s.completeList(read, lock.Close)
	profiles, err := readLocked(ctx)
	// Mark the result non-joinable WHILE holding the OS lock. A later caller
	// cannot join this snapshot after a writer commits a newer revision.
	s.publishList(read, profiles, err)
}

func (s *Store) publishList(read *listRead, profiles []Profile, err error) {
	s.listMu.Lock()
	defer s.listMu.Unlock()
	read.profiles, read.err = profiles, err
	read.finishing = true
}

func (s *Store) completeList(read *listRead, closeLock func() error) {
	if closeLock != nil {
		// Preserve the existing read-close error policy. The slot bounds active
		// cleanup attempts; Close returning is not proof of native release success.
		_ = closeLock()
	}
	s.listMu.Lock()
	defer s.listMu.Unlock()
	if s.listing == read {
		s.listing = nil
	}
	close(read.done)
}
