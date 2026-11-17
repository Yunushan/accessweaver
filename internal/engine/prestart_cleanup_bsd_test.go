//go:build darwin || freebsd || openbsd

package engine

import (
	"errors"
	"golang.org/x/sys/unix"
	"testing"
)

func TestPreStartBSDObserverSetupFailureChecksActualClose(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		label := "clean"
		if uncertain {
			label = "uncertain"
		}
		t.Run(label, func(t *testing.T) {
			setupCause := errors.New("PRIVATE_SETUP_CAUSE")
			closeCause := errors.New("PRIVATE_CLOSE_CAUSE")
			creates, configures, closes := 0, 0, 0
			var actualClose error
			owner, err := newBSDExitObserverWith(func() (int, error) { creates++; return unix.Kqueue() }, func(fd int) error {
				configures++
				if _, e := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); e != nil {
					return e
				}
				return setupCause
			}, func(fd int) error {
				closes++
				actualClose = unix.Close(fd)
				if actualClose != nil {
					return actualClose
				}
				if uncertain {
					return closeCause
				}
				return nil
			})
			if owner != nil || !errors.Is(err, ErrProcessLifecycle) || !errors.Is(err, setupCause) || creates != 1 || configures != 1 || closes != 1 || actualClose != nil {
				t.Fatal("actual BSD setup cleanup or original cause lost")
			}
			expected := ErrProcessLifecycle
			if uncertain {
				expected = ErrPreparationCleanupUncertain
				if !errors.Is(err, closeCause) {
					t.Fatal("actual-close cofailure lost")
				}
			}
			if err.Error() != expected.Error() {
				t.Fatal("private BSD initialization details exposed")
			}
		})
	}
}

func TestPreStartBSDObserverCloseOnlyOnce(t *testing.T) {
	for _, mode := range []string{"clean", "reported-error", "panic-after-close"} {
		t.Run(mode, func(t *testing.T) {
			closes := 0
			var actualClose error
			closeCause := errors.New("PRIVATE_CLOSE_CAUSE")
			original := &struct{ tag string }{"PRIVATE_PANIC"}
			owner, err := newBSDExitObserverWith(unix.Kqueue, func(fd int) error { _, e := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); return e }, func(fd int) error {
				closes++
				actualClose = unix.Close(fd)
				if actualClose != nil {
					return actualClose
				}
				if mode == "reported-error" {
					return closeCause
				}
				if mode == "panic-after-close" {
					panic(original)
				}
				return nil
			})
			if err != nil || owner == nil {
				t.Fatal("owned BSD observer unavailable")
			}
			var first error
			var recovered any
			func() { defer func() { recovered = recover() }(); first = owner.close() }()
			second := owner.close()
			if closes != 1 || actualClose != nil {
				t.Fatal("actual BSD descriptor close retried or unconfirmed")
			}
			switch mode {
			case "clean":
				if recovered != nil || first != nil || second != nil {
					t.Fatal("clean BSD close changed")
				}
			case "reported-error":
				if recovered != nil || !errors.Is(first, closeCause) || !errors.Is(second, closeCause) {
					t.Fatal("BSD close cofailure not retained")
				}
			case "panic-after-close":
				if recovered != original || !errors.Is(second, ErrPreparationCleanupUncertain) {
					t.Fatal("Close panic lost or later call claimed success")
				}
			}
		})
	}
}

func TestPreStartBSDObserverCreateFailureOwnsNoDescriptor(t *testing.T) {
	cause := errors.New("PRIVATE_CREATE_CAUSE")
	configured, closed := 0, 0
	owner, err := newBSDExitObserverWith(func() (int, error) { return -1, cause }, func(int) error { configured++; return nil }, func(int) error { closed++; return nil })
	if owner != nil || !errors.Is(err, ErrProcessLifecycle) || !errors.Is(err, cause) || configured != 0 || closed != 0 || err.Error() != ErrProcessLifecycle.Error() {
		t.Fatal("failed creation fabricated descriptor ownership or lost cause")
	}
}
