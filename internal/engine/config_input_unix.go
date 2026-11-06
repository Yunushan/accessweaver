//go:build linux || darwin || freebsd || openbsd

package engine

import (
	"golang.org/x/sys/unix"
	"os"
)

// Follow the same names as os.Open, but do not wait for a substituted FIFO's
// writer or acquire a controlling terminal before the held-kind check.
func openConfigInput(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
