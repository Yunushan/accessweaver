//go:build !windows

package privatefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// createAtUnix borrows parent only during the synchronous call. Parent identity
// is checked without demanding an unchanged directory modification time.
func createAtUnix(parent *os.File, name string, extra func(*os.File) error) (file *os.File, failure error) {
	if err := privateCreateAtParent(parent, name); err != nil {
		return nil, err
	}
	owner := os.Geteuid()
	if owner < 0 || owner != os.Getuid() {
		return nil, privateCreateAtFailure(nil)
	}
	connection, err := parent.SyscallConn()
	if err != nil {
		return nil, privateCreateAtFailure(err)
	}
	var child *os.File
	defer func() {
		if failure != nil && child != nil {
			failure = privateCreateAtFailure(errors.Join(failure, child.Close()))
			file = nil
		}
	}()
	var operationErr error
	controlErr := connection.Control(func(parentFD uintptr) {
		var initialParent unix.Stat_t
		if err := unix.Fstat(int(parentFD), &initialParent); err != nil {
			operationErr = err
			return
		}
		if initialParent.Mode&unix.S_IFMT != unix.S_IFDIR {
			operationErr = errPrivateCreateAt
			return
		}
		fd, err := unix.Openat(int(parentFD), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			operationErr = err
			return
		}
		// Name is only a diagnostic label. All lookups use the borrowed parent FD.
		child = os.NewFile(uintptr(fd), name)
		if child == nil {
			operationErr = errors.Join(errPrivateCreateAt, unix.Close(fd))
			return
		}
		private := func(st *unix.Stat_t) bool {
			return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && uint32(st.Uid) == uint32(owner) && st.Nlink == 1 && st.Size == 0
		}
		var initial, named, after, finalParent unix.Stat_t
		if err = unix.Fstat(fd, &initial); err != nil {
			operationErr = err
			return
		}
		if !private(&initial) {
			operationErr = errPrivateCreateAt
			return
		}
		if extra != nil {
			if err = extra(child); err != nil {
				operationErr = err
				return
			}
		}
		if err = unix.Fstatat(int(parentFD), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			operationErr = err
			return
		}
		if err = unix.Fstat(fd, &after); err != nil {
			operationErr = err
			return
		}
		if err = unix.Fstat(int(parentFD), &finalParent); err != nil {
			operationErr = err
			return
		}
		if !private(&named) || !private(&after) || initial.Dev != named.Dev || initial.Ino != named.Ino || initial.Dev != after.Dev || initial.Ino != after.Ino || finalParent.Mode&unix.S_IFMT != unix.S_IFDIR || initialParent.Dev != finalParent.Dev || initialParent.Ino != finalParent.Ino || os.Getuid() != owner || os.Geteuid() != owner {
			operationErr = errPrivateCreateAt
		}
	})
	if controlErr != nil || operationErr != nil {
		return nil, privateCreateAtFailure(errors.Join(controlErr, operationErr))
	}
	file, child = child, nil
	return file, nil
}
