package filelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquisitionCloseUncertainCategoryPreservesCausesAndFixedText(t *testing.T) {
	primary := errors.New("private acquisition cause")
	closeCause := errors.New("private native close cause")
	closeErr := &os.PathError{Op: "private-close", Path: "private-owned-path", Err: closeCause}
	for _, body := range []error{nil, primary} {
		failure := joinLockClose(body, closeErr)
		if failure.Error() != ErrCloseUncertain.Error() || !errors.Is(failure, ErrCloseUncertain) || !errors.Is(failure, closeCause) {
			t.Fatal("close uncertainty lost its fixed category or private cause")
		}
		if body != nil && !errors.Is(failure, body) {
			t.Fatal("close uncertainty lost the original primary cause")
		}
		var retained *os.PathError
		if !errors.As(failure, &retained) || retained != closeErr {
			t.Fatal("close uncertainty replaced the actual close error")
		}
	}
	if clean := joinLockClose(primary, nil); clean != primary || errors.Is(clean, ErrCloseUncertain) {
		t.Fatal("clean close changed exact primary identity or invented uncertainty")
	}
	if clean := joinLockClose(nil, nil); clean != nil {
		t.Fatal("clean nil outcome invented an error")
	}
}

func TestAcquisitionCloseUncertainAfterRealContenderCloseDoesNotRetry(t *testing.T) {
	f := newAcquisitionCloseFixture(t)
	path := filepath.Join(f.root, "lock")
	owner := f.acquire(t, path)
	cause := &os.PathError{Op: "semantic-close", Path: "private-contender-path", Err: errors.New("private semantic close cause")}
	attempts, closes := 0, 0
	var retired *os.File
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, failure := acquire(ctx, path, func(name string) (*Lock, error) {
		attempts++
		return tryAcquire(name, func(file *os.File) error {
			retired = file
			closes++
			if err := f.closeFile(t, file); err != nil {
				return err
			}
			// The category models an observed cofailure after actual Close.
			return cause
		})
	}, func(lock *Lock) error { return f.closeLock(t, lock) })
	if result != nil {
		f.ownLock(t, result)
	}
	if result != nil || !errors.Is(failure, ErrCloseUncertain) || !errors.Is(failure, ErrBusy) || !errors.Is(failure, cause) || errors.Is(failure, context.DeadlineExceeded) || attempts != 1 || closes != 1 {
		t.Fatal("acquisition close uncertainty retried or lost a co-cause")
	}
	if failure.Error() != "acquire file lock: "+ErrCloseUncertain.Error() {
		t.Fatal("acquisition close uncertainty printed a private cause")
	}
	if retired == nil {
		t.Fatal("fixture did not observe its real contender file")
	}
	if n, err := retired.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		f.preserve = true
		t.Fatal("contender file was not actually closed")
	}
	other, err := TryAcquire(path)
	if other != nil {
		f.ownLock(t, other)
	}
	if err != ErrBusy {
		f.preserve = true
		t.Fatal("contender cleanup changed the original native owner")
	}
	if err := f.closeLock(t, owner); err != nil {
		t.Fatal("original owner close unconfirmed")
	}
	next := f.acquire(t, path)
	if err := f.closeLock(t, next); err != nil {
		t.Fatal("fresh native owner close unconfirmed")
	}
}

func TestAcquisitionCloseUncertainAfterRealAcceptedCancellation(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "semantic-close-failure"}[fault], func(t *testing.T) {
			f := newAcquisitionCloseFixture(t)
			path := filepath.Join(f.root, "lock")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("private accepted-lock close cause")
			attempts, closes := 0, 0
			var accepted *Lock
			result, failure := acquire(ctx, path, func(name string) (*Lock, error) {
				attempts++
				accepted = f.acquire(t, name)
				cancel()
				return accepted, nil
			}, func(lock *Lock) error {
				closes++
				if err := f.closeLock(t, lock); err != nil {
					return err
				}
				if fault {
					// Never add the synthetic error before actual Close succeeds.
					return cause
				}
				return nil
			})
			if result != nil || !errors.Is(failure, context.Canceled) || attempts != 1 || closes != 1 {
				t.Fatal("canceled real acquisition lost its owner or cancellation")
			}
			if fault {
				if !errors.Is(failure, ErrCloseUncertain) || !errors.Is(failure, cause) || failure.Error() != ErrCloseUncertain.Error() {
					t.Fatal("accepted acquisition lost its fixed close category or cause")
				}
			} else if failure != context.Canceled || errors.Is(failure, ErrCloseUncertain) {
				t.Fatal("clean accepted close changed exact cancellation identity")
			}
			if accepted == nil {
				t.Fatal("fixture did not own a real accepted lock")
			}
			if n, err := accepted.file.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
				f.preserve = true
				t.Fatal("accepted file was not actually closed")
			}
			next := f.acquire(t, path)
			if err := f.closeLock(t, next); err != nil {
				t.Fatal("fresh native acquisition close unconfirmed")
			}
		})
	}
}
