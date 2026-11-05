//go:build linux

package engine

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

type linuxExitObserver struct{ pid int }

func newExitObserver() (exitObserver, error) {
	// Exact self PID cannot be our child; this nonconsuming availability check
	// must return ECHILD and cannot steal another component's child status.
	var info unix.Siginfo
	var err error
	for {
		err = unix.Waitid(unix.P_PID, os.Getpid(), &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if !errors.Is(err, unix.ECHILD) {
		return nil, ErrProcessLifecycle
	}
	return &linuxExitObserver{}, nil
}
func (o *linuxExitObserver) bind(pid int) error {
	if pid <= 1 {
		return ErrProcessOwnershipLost
	}
	o.pid = pid
	return nil
}
func (o *linuxExitObserver) waitExit() error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, o.pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		// Linux siginfo child codes CLD_EXITED/KILLED/DUMPED. A ptrace/job stop
		// must never authorize the consuming wait or final lifecycle publication.
		if info.Code < 1 || info.Code > 3 {
			return ErrProcessLifecycle
		}
		return nil
	}
}
func (o *linuxExitObserver) close() error { return nil }
