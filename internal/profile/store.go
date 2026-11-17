package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
)

// Store coordinates one profile root. Do not copy a Store after its first use.
type Store struct {
	Root    string
	guard   *managed.Guard
	listMu  sync.Mutex
	listing *listRead
}

// ErrConflict means the caller's reviewed revision no longer names the saved
// profile. A zero revision denotes creation, never an unconditional overwrite.
var ErrConflict = errors.New("profile changed, was removed, or its ID already exists; reload the saved profile before retrying and export any unsaved edits you need to keep")

func DefaultRoot() (string, error) {
	p, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(p, "AccessWeaver"), nil
}
func NewStore(root string) (*Store, error) { return NewStoreWithGuard(root, managed.NewGuard(nil)) }

func NewStoreWithGuard(root string, guard *managed.Guard) (*Store, error) {
	if err := checkRestoreState(root); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "profiles"), 0700); err != nil {
		return nil, err
	}
	return &Store{Root: root, guard: guard}, nil
}
func (s *Store) filename(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", errors.New("invalid profile ID")
	}
	return filepath.Join(s.Root, "profiles", id+".json"), nil
}

// lock coordinates all profile reads and mutations across Store instances and
// processes. Keep the file in place even after a crash; OS handles own the lock.
func (s *Store) lock(ctx context.Context) (*filelock.Lock, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, err := filelock.Acquire(ctx, filepath.Join(s.Root, ".profiles.lock"))
	if errors.Is(err, filelock.ErrCloseUncertain) {
		return nil, profileReadUnavailable(err)
	}
	if errors.Is(err, filelock.ErrBusy) {
		return nil, fmt.Errorf("%w: %w", ErrStoreBusy, err)
	}
	if err == nil {
		if restoreErr := checkRestoreState(s.Root); restoreErr != nil {
			_, refusal := readProfileSynchronously(ctx, func(context.Context) (Profile, error) {
				return Profile{}, restoreErr
			}, lock.Close)
			return nil, refusal
		}
	}
	return lock, err
}

var ErrStoreBusy = errors.New("profile store busy; wait for the other operation and retry")

func (s *Store) Get(id string) (Profile, error) {
	return s.GetContext(context.Background(), id)
}

func (s *Store) GetContext(ctx context.Context, id string) (Profile, error) {
	lock, err := s.lock(ctx)
	if err != nil {
		return Profile{}, err
	}
	return readProfileSynchronously(ctx, func(ctx context.Context) (Profile, error) {
		return s.getLockedContext(ctx, id)
	}, lock.Close)
}

func (s *Store) List() ([]Profile, error) {
	return s.ListContext(context.Background())
}

func (s *Store) listLocked(ctx context.Context) ([]Profile, error) {
	dir := filepath.Join(s.Root, "profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(entries))
	for _, f := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
			continue
		}
		id := f.Name()[:len(f.Name())-5]
		p, err := s.getLockedContext(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Store) Save(p Profile) error {
	if err := s.guard.ProfileChanges(); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	lock, err := s.lock(context.Background())
	if err != nil {
		return err
	}
	return mutateProfileSynchronously(context.Background(), func(ctx context.Context, progress *mutationProgress) error {
		return s.saveLockedContext(ctx, p, progress)
	}, lock.Close)
}

// SaveIfUnchanged compares and replaces under the shared OS lock. CLI import
// intentionally uses Save for explicit replacement. Manual file writes and
// filesystems without working OS locks remain outside this coordination.
func (s *Store) SaveIfUnchanged(p Profile) error {
	return s.SaveIfUnchangedContext(context.Background(), p)
}

func (s *Store) SaveIfUnchangedContext(ctx context.Context, p Profile) error {
	return s.saveIfUnchangedContext(ctx, p, s.getLockedContext)
}

func (s *Store) saveIfUnchangedContext(ctx context.Context, p Profile, read func(context.Context, string) (Profile, error)) error {
	if err := s.guard.ProfileMutation(ctx, "write"); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	lock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	return mutateProfileSynchronously(ctx, func(ctx context.Context, progress *mutationProgress) error {
		return s.saveIfUnchangedLockedContext(ctx, p, read, progress)
	}, lock.Close)
}

func (s *Store) saveIfUnchangedLockedContext(ctx context.Context, p Profile, read func(context.Context, string) (Profile, error), progress *mutationProgress) error {
	current, err := read(ctx, p.ID)
	if errors.Is(err, ErrReadUnavailable) {
		return err
	}
	if errors.Is(err, fs.ErrNotExist) {
		if !p.UpdatedAt.IsZero() {
			return ErrConflict
		}
	} else if err != nil {
		return err
	} else if p.UpdatedAt.IsZero() || !p.UpdatedAt.Equal(current.UpdatedAt) {
		return ErrConflict
	}
	return s.saveLockedContext(ctx, p, progress)
}

func (s *Store) saveLockedContext(ctx context.Context, p Profile, progress *mutationProgress) error {
	if err := s.guard.ProfileMutation(ctx, "write"); err != nil {
		return err
	}
	p.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path, err := s.filename(p.ID)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return errors.New("refusing to overwrite non-regular file")
	}
	progress.effectsAttempted = true
	return AtomicWrite(path, b)
}
func (s *Store) Delete(id string) error {
	if err := s.guard.ProfileChanges(); err != nil {
		return err
	}
	lock, err := s.lock(context.Background())
	if err != nil {
		return err
	}
	return mutateProfileSynchronously(context.Background(), func(_ context.Context, progress *mutationProgress) error {
		return s.deleteLocked(id, progress)
	}, lock.Close)
}

func (s *Store) deleteLocked(id string, progress *mutationProgress) error {
	file, err := s.filename(id)
	if err != nil {
		return err
	}
	if err := s.guard.ProfileChanges(); err != nil {
		return err
	}
	progress.effectsAttempted = true
	return os.Remove(file)
}

// DeleteIfUnchanged prevents a stale browser from deleting a newer revision.
func (s *Store) DeleteIfUnchanged(id string, expected time.Time) error {
	return s.DeleteIfUnchangedContext(context.Background(), id, expected)
}

func (s *Store) DeleteIfUnchangedContext(ctx context.Context, id string, expected time.Time) error {
	return s.deleteIfUnchangedContext(ctx, id, expected, s.getLockedContext)
}

func (s *Store) deleteIfUnchangedContext(ctx context.Context, id string, expected time.Time, read func(context.Context, string) (Profile, error)) error {
	if err := s.guard.ProfileMutation(ctx, "delete"); err != nil {
		return err
	}
	lock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	return mutateProfileSynchronously(ctx, func(ctx context.Context, progress *mutationProgress) error {
		return s.deleteIfUnchangedLockedContext(ctx, id, expected, read, progress)
	}, lock.Close)
}

func (s *Store) deleteIfUnchangedLockedContext(ctx context.Context, id string, expected time.Time, read func(context.Context, string) (Profile, error), progress *mutationProgress) error {
	current, err := read(ctx, id)
	if errors.Is(err, ErrReadUnavailable) {
		return err
	}
	if errors.Is(err, fs.ErrNotExist) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if expected.IsZero() || !expected.Equal(current.UpdatedAt) {
		return ErrConflict
	}
	file, err := s.filename(id)
	if err != nil {
		return err
	}
	if err := s.guard.ProfileMutation(ctx, "delete"); err != nil {
		return err
	}
	progress.effectsAttempted = true
	return os.Remove(file)
}

func (s *Store) Seed(samples []Profile) error {
	if err := s.guard.ProfileChanges(); err != nil {
		if errors.Is(err, managed.ErrDenied) {
			return nil
		}
		return err
	}
	lock, err := s.lock(context.Background())
	if err != nil {
		return err
	}
	return mutateProfileSynchronously(context.Background(), func(ctx context.Context, progress *mutationProgress) error {
		return s.seedLockedContext(ctx, samples, progress)
	}, lock.Close)
}

func (s *Store) seedLockedContext(ctx context.Context, samples []Profile, progress *mutationProgress) error {
	// Seeding is first-run initialization, not synchronization. Once the user
	// deletes a bundled profile it must stay deleted on subsequent launches.
	marker := filepath.Join(s.Root, "presets-initialized")
	if info, err := os.Lstat(marker); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("preset initialization marker must be a regular file")
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, p := range samples {
		f, err := s.filename(p.ID)
		if err != nil {
			return err
		}
		_, err = os.Stat(f)
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := p.Validate(); err != nil {
			return err
		}
		if err := s.saveLockedContext(ctx, p, progress); err != nil {
			return err
		}
	}
	if err := s.guard.ProfileChanges(); err != nil {
		return err
	}
	progress.effectsAttempted = true
	return AtomicWrite(marker, []byte("1\n"))
}
