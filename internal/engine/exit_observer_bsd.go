//go:build darwin || freebsd || openbsd

package engine

import (
	"errors"
	"golang.org/x/sys/unix"
	"syscall"
)

type bsdExitObserver struct {
	fd, pid int
	early   bool
}

func newExitObserver() (exitObserver, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Kqueue()
	if err != nil {
		syscall.ForkLock.RUnlock()
		return nil, ErrProcessLifecycle
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		unix.Close(fd)
		syscall.ForkLock.RUnlock()
		return nil, ErrProcessLifecycle
	}
	syscall.ForkLock.RUnlock()
	return &bsdExitObserver{fd: fd}, nil
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
func (o *bsdExitObserver) close() error { return unix.Close(o.fd) }
