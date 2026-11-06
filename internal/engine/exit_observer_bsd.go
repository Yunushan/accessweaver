//go:build darwin || freebsd || openbsd

package engine

import (
	"errors"
	"golang.org/x/sys/unix"
	"sync"
	"syscall"
)

type bsdExitObserver struct {
	fd, pid   int
	early     bool
	closeOnce sync.Once
	closeErr  error
	closeFD   func(int) error
}

func newExitObserver() (exitObserver, error) {
	return newBSDExitObserverWith(unix.Kqueue, func(fd int) error { _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); return err }, unix.Close)
}

// The callbacks are fixed per call, private to native defaults and source tests.
// Keep fork exclusion until close-on-exec succeeds or the acquired owner closes.
func newBSDExitObserverWith(create func() (int, error), configure func(int) error, closeFD func(int) error) (result exitObserver, failure error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := create()
	if err != nil {
		return nil, &processPreparationFailure{category: ErrProcessLifecycle, cause: err}
	}
	owner := &bsdExitObserver{fd: fd, closeFD: closeFD}
	retained := false
	defer func() {
		if !retained {
			failure = preparationCleanupFailure(failure, owner.close(), owner)
		}
	}()
	if err := configure(fd); err != nil {
		return nil, &processPreparationFailure{category: ErrProcessLifecycle, cause: err}
	}
	retained = true
	return owner, nil
}

func (o *bsdExitObserver) bind(pid int) error {
	if pid <= 1 {
		return ErrProcessOwnershipLost
	}
	o.pid = pid
	var change unix.Kevent_t
	unix.SetKevent(&change, pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ENABLE|unix.EV_ONESHOT|unix.EV_RECEIPT)
	change.Fflags = unix.NOTE_EXIT
	var events [1]unix.Kevent_t
	for {
		n, err := unix.Kevent(o.fd, []unix.Kevent_t{change}, events[:], nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ESRCH) {
			o.early = true
			return nil
		}
		if err != nil {
			return err
		}
		if n != 1 || uint64(events[0].Ident) != uint64(pid) || events[0].Filter != unix.EVFILT_PROC || events[0].Flags&unix.EV_ERROR == 0 {
			return ErrProcessLifecycle
		}
		if events[0].Data == int64(unix.ESRCH) {
			o.early = true
			return nil
		}
		if events[0].Data != 0 {
			return ErrProcessLifecycle
		}
		return nil
	}
}
func (o *bsdExitObserver) waitExit() error {
	// Only a successfully started, exclusively unreaped own child may use this
	// late-attachment ESRCH rule. It is not liveness inference for arbitrary PIDs.
	if o.early {
		return nil
	}
	var events [1]unix.Kevent_t
	for {
		n, err := unix.Kevent(o.fd, nil, events[:], nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n != 1 || uint64(events[0].Ident) != uint64(o.pid) || events[0].Filter != unix.EVFILT_PROC || events[0].Flags&unix.EV_ERROR != 0 || events[0].Fflags&unix.NOTE_EXIT == 0 {
			return ErrProcessLifecycle
		}
		return nil
	}
}
func (o *bsdExitObserver) close() error {
	o.closeOnce.Do(func() {
		// If an internal callback panics, a later call cannot falsely claim success
		// or retry a descriptor number which may already have been reused.
		o.closeErr = ErrPreparationCleanupUncertain
		o.closeErr = o.closeFD(o.fd)
	})
	return o.closeErr
}
