package filelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquisitionClosePreservesExactPrimaryWhenClean(t *testing.T) {
	primary := errors.New("primary storage error")
	if got := joinLockClose(primary, nil); got != primary {
		t.Fatal("clean close changed exact primary identity")
	}
	root := t.TempDir()
	path := filepath.Join(root, "lock")
	owner, e := TryAcquire(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := owner.Close(); e != nil {
			t.Error(e)
		}
	}()
	closes := 0
	_, e = tryAcquire(path, func(f *os.File) error { closes++; return f.Close() })
	if e != ErrBusy || closes != 1 {
		t.Fatal("clean failed acquisition changed native contention sentinel", e, closes)
	}
}
func TestAcquisitionCloseCofailureStopsContentionRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	owner, e := TryAcquire(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := owner.Close(); e != nil {
			t.Error(e)
		}
	}()
	cause := errors.New("owned close observation failure")
	attempts, closes := 0, 0
	var closed *os.File
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, e := acquire(ctx, path, func(name string) (*Lock, error) {
		attempts++
		return tryAcquire(name, func(f *os.File) error { closed = f; closes++; return errors.Join(f.Close(), cause) })
	}, func(l *Lock) error { return l.Close() })
	if got != nil || !errors.Is(e, ErrBusy) || !errors.Is(e, cause) || errors.Is(e, context.DeadlineExceeded) || attempts != 1 || closes != 1 {
		t.Fatal("close uncertainty retried or co-cause lost", e, attempts, closes)
	}
	if _, q := closed.Stat(); !errors.Is(q, os.ErrClosed) {
		t.Fatal("fault fixture did not actually close its owned file", q)
	}
	// The original owner is unaffected by the failed contender's Close.
	if other, q := TryAcquire(path); q != ErrBusy {
		if other != nil {
			if z := other.Close(); z != nil {
				t.Error(z)
			}
		}
		t.Fatal("original ownership lost", q)
	}
	if e = owner.Close(); e != nil {
		t.Fatal(e)
	}
	next, e := TryAcquire(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = next.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestCanceledAfterRealAcquisitionRetainsCloseCofailure(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "close-failure"}[fault], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock")
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
					t.Cleanup(func() {
						if q := lock.Close(); q != nil {
							t.Error(q)
						}
					})
					cancel()
				}
				return lock, q
			}, func(lock *Lock) error {
				closes++
				q := lock.Close()
				if fault {
					return errors.Join(q, cause)
				}
				return q
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
			if _, q := actual.file.Stat(); !errors.Is(q, os.ErrClosed) {
				t.Fatal("actual accepted lock not closed", q)
			}
			next, q := TryAcquire(path)
			if q != nil {
				t.Fatal("canceled accepted owner retained OS lock", q)
			}
			if q = next.Close(); q != nil {
				t.Fatal(q)
			}
		})
	}
}
