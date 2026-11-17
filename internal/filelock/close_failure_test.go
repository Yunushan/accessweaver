package filelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
)

type acquisitionCloseFixture struct {
	root     string
	preserve bool
}

func newAcquisitionCloseFixture(t *testing.T) *acquisitionCloseFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-acquisition-close-")
	if err != nil {
		t.Fatal("owned acquisition fixture unavailable")
	}
	state, err := fileidentity.FromPath(root, false)
	if err != nil || state.Kind != fileidentity.Directory {
		t.Fatal("owned acquisition fixture identity unavailable")
	}
	f := &acquisitionCloseFixture{root: root}
	t.Cleanup(func() {
		if f.preserve {
			t.Error("unconfirmed acquisition fixture retained")
			return
		}
		current, err := fileidentity.FromPath(root, false)
		if err != nil || current.ID != state.ID || current.Kind != state.Kind {
			t.Error("changed acquisition fixture retained")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned acquisition fixture cleanup failed")
		}
	})
	return f
}

func (f *acquisitionCloseFixture) closeFile(t *testing.T, file *os.File) error {
	t.Helper()
	err := file.Close()
	if err != nil {
		f.preserve = true
		t.Error("actual acquisition file close failed before injection")
	}
	return err
}

func (f *acquisitionCloseFixture) ownLock(t *testing.T, lock *Lock) {
	t.Helper()
	t.Cleanup(func() { f.closeLock(t, lock) })
}

func (f *acquisitionCloseFixture) closeLock(t *testing.T, lock *Lock) error {
	t.Helper()
	err := lock.Close()
	if err != nil {
		f.preserve = true
		t.Error("actual acquisition lock close unconfirmed")
	}
	return err
}

func (f *acquisitionCloseFixture) acquire(t *testing.T, path string) *Lock {
	t.Helper()
	lock, err := TryAcquire(path)
	if err != nil {
		f.preserve = true
		t.Fatal("actual acquisition fixture lock unavailable")
	}
	f.ownLock(t, lock)
	return lock
}

func TestAcquisitionClosePreservesExactPrimaryWhenClean(t *testing.T) {
	primary := errors.New("primary storage error")
	if got := joinLockClose(primary, nil); got != primary {
		t.Fatal("clean close changed exact primary identity")
	}
	f := newAcquisitionCloseFixture(t)
	path := filepath.Join(f.root, "lock")
	f.acquire(t, path)
	closes := 0
	other, e := tryAcquire(path, func(file *os.File) error {
		closes++
		return f.closeFile(t, file)
	})
	if other != nil {
		f.ownLock(t, other)
	}
	if e != ErrBusy || closes != 1 {
		t.Fatal("clean failed acquisition changed native contention sentinel", e, closes)
	}
}

func TestAcquisitionCloseCofailureStopsContentionRetry(t *testing.T) {
	f := newAcquisitionCloseFixture(t)
	path := filepath.Join(f.root, "lock")
	owner := f.acquire(t, path)
	cause := errors.New("owned close observation failure")
	attempts, closes := 0, 0
	var closed *os.File
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, e := acquire(ctx, path, func(name string) (*Lock, error) {
		attempts++
		return tryAcquire(name, func(file *os.File) error {
			closed = file
			closes++
			if err := f.closeFile(t, file); err != nil {
				return err
			}
			// The synthetic cofailure follows a successful actual Close.
			return cause
		})
	}, func(lock *Lock) error { return f.closeLock(t, lock) })
	if got != nil {
		f.ownLock(t, got)
	}
	if got != nil || !errors.Is(e, ErrBusy) || !errors.Is(e, cause) || errors.Is(e, context.DeadlineExceeded) || attempts != 1 || closes != 1 {
		t.Fatal("close uncertainty retried or co-cause lost", e, attempts, closes)
	}
	if closed == nil {
		t.Fatal("fixture never observed the contender file")
	}
	// Read checks the Go file's closed state before native I/O on every OS.
	// Windows Stat instead queries the retired native handle directly.
	if n, q := closed.Read(make([]byte, 1)); n != 0 || !errors.Is(q, os.ErrClosed) {
		f.preserve = true
		t.Fatal("fault fixture did not actually close its owned file", n, q)
	}
	// The original owner is unaffected by the failed contender's Close.
	if other, q := TryAcquire(path); q != ErrBusy {
		if other != nil {
			f.ownLock(t, other)
			f.closeLock(t, other)
		}
		f.preserve = true
		t.Fatal("original ownership lost", q)
	}
	if e = f.closeLock(t, owner); e != nil {
		t.Fatal("original owner close unconfirmed")
	}
	next := f.acquire(t, path)
	if e = f.closeLock(t, next); e != nil {
		t.Fatal("fresh acquisition close unconfirmed")
	}
}

func TestCanceledAfterRealAcquisitionRetainsCloseCofailure(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "close-failure"}[fault], func(t *testing.T) {
			f := newAcquisitionCloseFixture(t)
			path := filepath.Join(f.root, "lock")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("owned lock close failure")
			closes, attempts := 0, 0
			var actual *Lock
			result, e := acquire(ctx, path, func(name string) (*Lock, error) {
				attempts++
				lock, q := TryAcquire(name)
				if q == nil {
					actual = lock
					f.ownLock(t, lock)
					cancel()
				} else {
					f.preserve = true
				}
				return lock, q
			}, func(lock *Lock) error {
				closes++
				if q := f.closeLock(t, lock); q != nil {
					return q
				}
				if fault {
					// The synthetic cofailure follows a successful actual Close.
					return cause
				}
				return nil
			})
			if result != nil || !errors.Is(e, context.Canceled) || closes != 1 || attempts != 1 {
				t.Fatal("canceled accepted acquisition leaked or lost cancellation", e, closes, attempts)
			}
			if !fault && e != context.Canceled {
				t.Fatal("clean close changed exact cancellation identity", e)
			}
			if fault && !errors.Is(e, cause) {
				t.Fatal("close cofailure erased", e)
			}
			if actual == nil {
				t.Fatal("fixture never owned a real lock")
			}
			if n, q := actual.file.Read(make([]byte, 1)); n != 0 || !errors.Is(q, os.ErrClosed) {
				f.preserve = true
				t.Fatal("actual accepted lock not closed", n, q)
			}
			next := f.acquire(t, path)
			if q := f.closeLock(t, next); q != nil {
				t.Fatal("fresh acquisition close unconfirmed")
			}
		})
	}
}
