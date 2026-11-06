package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/filelock"
)

// These per-call operations compose real owned resources. They are not a
// runtime selector, and ordinary callers always use the physical defaults.
type snapshotIO struct {
	acquire       func(context.Context, string, bool) (io.Closer, error)
	openDirectory func(string) (*os.File, error)
	readDirectory func(*os.File, int) ([]os.DirEntry, error)
	named         func(string) (fileidentity.State, error)
	opened        func(*os.File) (fileidentity.State, error)
	readFile      func(context.Context, string, int64) ([]byte, error)
	close         func(io.Closer) error
}

func physicalSnapshotIO() snapshotIO {
	return snapshotIO{
		acquire: func(ctx context.Context, name string, immediate bool) (io.Closer, error) {
			if immediate {
				return filelock.TryAcquire(name)
			}
			return filelock.Acquire(ctx, name)
		},
		openDirectory: fileinput.OpenDirectory,
		readDirectory: func(f *os.File, n int) ([]os.DirEntry, error) { return f.ReadDir(n) },
		named:         func(name string) (fileidentity.State, error) { return fileinput.StateFromPath(name, false) },
		opened:        fileinput.StateFromFile,
		readFile:      fileinput.Read,
		close:         func(owned io.Closer) error { return owned.Close() },
	}
}

func snapshotJoin(first, next error) error {
	if first == nil {
		return next
	}
	if next == nil || errors.Is(first, next) {
		return first
	}
	return errors.Join(first, next)
}
func snapshotClose(ctx context.Context, ops snapshotIO, owned io.Closer, failure *error) {
	*failure = snapshotJoin(*failure, ops.close(owned))
	*failure = snapshotJoin(*failure, ctx.Err())
}
func snapshotDirectoryBinding(a, b fileidentity.State) bool {
	return a.Kind == fileidentity.Directory && b.Kind == fileidentity.Directory && a.ID == b.ID
}
func snapshotDirectoryUnchanged(a, b fileidentity.State) bool {
	return snapshotDirectoryBinding(a, b) && a.Size == b.Size && a.Modified.Equal(b.Modified)
}
func snapshotOpenDirectory(ctx context.Context, path string, ops snapshotIO) (dir *os.File, state fileidentity.State, failure error) {
	if err := ctx.Err(); err != nil {
		return nil, state, err
	}
	named, err := ops.named(path)
	if err != nil {
		return nil, state, err
	}
	if named.Kind != fileidentity.Directory {
		return nil, state, errors.New("snapshot requires a real directory")
	}
	dir, err = ops.openDirectory(path)
	if err != nil {
		return nil, state, err
	}
	opened, err := ops.opened(dir)
	if err == nil && !snapshotDirectoryUnchanged(named, opened) {
		err = errors.New("snapshot directory changed during open")
	}
	err = snapshotJoin(err, ctx.Err())
	if err != nil {
		snapshotClose(ctx, ops, dir, &err)
		return nil, state, err
	}
	return dir, opened, nil
}
func snapshotCheckDirectory(ctx context.Context, path string, dir *os.File, state fileidentity.State, ops snapshotIO) error {
	opened, err := ops.opened(dir)
	if err != nil {
		return err
	}
	named, err := ops.named(path)
	if err != nil {
		return err
	}
	if !snapshotDirectoryUnchanged(state, opened) || !snapshotDirectoryUnchanged(opened, named) {
		return errors.New("snapshot directory changed during read")
	}
	return ctx.Err()
}
func snapshotStoreLock(ctx context.Context, root string, ops snapshotIO) (io.Closer, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, err := ops.acquire(ctx, filepath.Join(root, ".profiles.lock"), false)
	if errors.Is(err, filelock.ErrBusy) {
		return nil, fmt.Errorf("%w: %w", ErrStoreBusy, err)
	}
	if err != nil {
		return nil, err
	}
	if err = checkRestoreState(root); err != nil {
		snapshotClose(ctx, ops, lock, &err)
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		snapshotClose(ctx, ops, lock, &err)
		return nil, err
	}
	return lock, nil
}
func snapshotContext(ctx context.Context, store *Store, ops snapshotIO) (profiles []Profile, failure error) {
	defer func() {
		failure = snapshotJoin(failure, ctx.Err())
		if failure != nil {
			profiles = nil
		}
	}()
	lock, err := snapshotStoreLock(ctx, store.Root, ops)
	if err != nil {
		return nil, err
	}
	defer func() {
		snapshotClose(ctx, ops, lock, &failure)
		if failure != nil {
			profiles = nil
		}
	}()
	path := filepath.Join(store.Root, "profiles")
	dir, state, err := snapshotOpenDirectory(ctx, path, ops)
	if err != nil {
		return nil, err
	}
	defer func() {
		snapshotClose(ctx, ops, dir, &failure)
		if failure != nil {
			profiles = nil
		}
	}()
	profiles = make([]Profile, 0)
	scanned, size := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, readErr := ops.readDirectory(dir, 128)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		if len(entries) > 128 || len(entries) > 4096-scanned {
			return nil, errors.New("snapshot directory exceeds 4096 entries")
		}
		scanned += len(entries)
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			if len(profiles) >= MaxSnapshotProfiles {
				return nil, errors.New("snapshot exceeds 256 profiles")
			}
			id := entry.Name()[:len(entry.Name())-5]
			name, err := store.filename(id)
			if err != nil {
				return nil, err
			}
			data, err := ops.readFile(ctx, name, 1<<20)
			if err != nil {
				clear(data)
				return nil, err
			}
			p, err := Decode(bytes.NewReader(data))
			clear(data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			if p.ID != id {
				return nil, errors.New("profile id does not match filename")
			}
			encoded, err := json.Marshal(p)
			if err != nil {
				return nil, err
			}
			if len(encoded) > MaxSnapshotBytes-size {
				return nil, errors.New("snapshot exceeds 8 MiB")
			}
			size += len(encoded)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			profiles = append(profiles, p)
		}
		if readErr == io.EOF {
			break
		}
	}
	if err := snapshotCheckDirectory(ctx, path, dir, state, ops); err != nil {
		return nil, err
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles, nil
}
func restoreDirectoryContext(ctx context.Context, path string, ops snapshotIO) (entries []os.DirEntry, failure error) {
	defer func() {
		failure = snapshotJoin(failure, ctx.Err())
		if failure != nil {
			entries = nil
		}
	}()
	dir, state, err := snapshotOpenDirectory(ctx, path, ops)
	if err != nil {
		return nil, err
	}
	defer func() {
		snapshotClose(ctx, ops, dir, &failure)
		if failure != nil {
			entries = nil
		}
	}()
	const maximum = MaxSnapshotProfiles + 5
	entries, err = ops.readDirectory(dir, maximum+1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, errors.New("unexpected restore directory contents")
	}
	if err := snapshotCheckDirectory(ctx, path, dir, state, ops); err != nil {
		return nil, err
	}
	return entries, nil
}

// Sync and Close are separate observed outcomes; a sync error must not erase
// a second close failure. The platform helper supplies the actual owned file.
func syncSnapshotOwned(owned interface {
	Sync() error
	Close() error
}) error {
	syncErr := owned.Sync()
	closeErr := owned.Close()
	return snapshotJoin(syncErr, closeErr)
}
