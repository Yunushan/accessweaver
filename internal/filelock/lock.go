// Package filelock coordinates cooperating local processes using OS-owned locks.
// Lock files remain in place: deleting one would let callers lock different files
// under the same name. The OS releases a lock when its handle or process closes.
package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

var ErrBusy = errors.New("another process holds the file lock")

type Lock struct {
	file     *os.File
	once     sync.Once
	closeErr error
}

// TryAcquire takes an exclusive lock without waiting. All participants must
// use this API and must not remove/replace the lock file while it is in use.
func TryAcquire(path string) (*Lock, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("lock must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Lock, error) { _ = f.Close(); return nil, err }
	if err = tryLock(f); err != nil {
		return fail(err)
	}
	opened, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	named, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	if !opened.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(opened, named) {
		return fail(errors.New("lock file changed during acquisition"))
	}
	return &Lock{file: f}, nil
}

// Acquire waits for contention only until ctx ends. It does not turn filesystem
// or unsupported-lock errors into retries, and it never steals a stale PID lock.
func Acquire(ctx context.Context, path string) (*Lock, error) {
	contended := false
	for {
		if err := ctx.Err(); err != nil {
			if contended {
				return nil, errors.Join(ErrBusy, err)
			}
			return nil, err
		}
		lock, err := TryAcquire(path)
		if err == nil {
			if canceled := ctx.Err(); canceled != nil {
				_ = lock.Close()
				return nil, canceled
			}
			return lock, nil
		}
		if !errors.Is(err, ErrBusy) {
			return nil, fmt.Errorf("acquire file lock: %w", err)
		}
		contended = true
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(ErrBusy, ctx.Err())
		case <-timer.C:
		}
	}
}

// Close is safe to call repeatedly or concurrently. Closing the OS handle
// releases ownership without deleting the persistent coordination file.
func (l *Lock) Close() error {
	l.once.Do(func() { l.closeErr = l.file.Close() })
	return l.closeErr
}
