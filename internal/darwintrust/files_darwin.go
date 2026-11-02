//go:build darwin && (amd64 || arm64)

// Package darwintrust checks native policy and input objects. Runtime authority
// requires root ownership; only in-process fixtures may use their own test UID.
package darwintrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/") && strings.IndexByte(name, 0) < 0
}

func CheckPersistent(file *os.File) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return err
	}
	return checkPersistentFS(&fs)
}

func checkPersistentFS(fs *unix.Statfs_t) error {
	var name []byte
	for _, c := range fs.Fstypename {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	if string(name) != "apfs" || fs.Flags&unix.MNT_LOCAL == 0 || fs.Flags&unix.MNT_IGNORE_OWNERSHIP != 0 {
		return fmt.Errorf("managed storage requires local APFS with ownership enabled; got %q", string(name))
	}
	return nil
}

func Check(file *os.File, directory bool, owner uint32) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("native ownership metadata unavailable")
	}
	if stat.Uid != owner {
		return nil, fmt.Errorf("managed object has owner %d; require %d", stat.Uid, owner)
	}
	if info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("managed object has unsafe POSIX permissions")
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return nil, errors.New("managed object has the wrong type")
	}
	if !directory && stat.Nlink != 1 {
		return nil, errors.New("managed regular files require exactly one hard link")
	}
	if err := CheckPersistent(file); err != nil {
		return nil, err
	}
	if err := checkACL(file); err != nil {
		return nil, err
	}
	return info, nil
}

func OpenDirectoryAt(parent *os.File, name string, owner uint32) (*os.File, error) {
	if !validName(name) {
		return nil, errors.New("expected one directory name")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	if _, err := Check(file, true, owner); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func OpenRootDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("managed directory requires a canonical absolute path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if _, err := Check(current, true, 0); err != nil {
		current.Close()
		return nil, err
	}
	if path == "/" {
		return current, nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := OpenDirectoryAt(current, part, 0)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func OpenRegularAt(parent *os.File, name string, owner uint32) (*os.File, error) {
	if !validName(name) {
		return nil, errors.New("expected one regular-file name")
	}
	// Reject special files before opening them. Parent protection prevents an
	// ordinary user from replacing the entry; NOFOLLOW also rejects a link race.
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != owner || before.Nlink != 1 || before.Mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 {
		return nil, errors.New("managed file has unsafe type, ownership, links or mode")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	after, err := Check(file, false, owner)
	if err != nil {
		file.Close()
		return nil, err
	}
	stat := after.Sys().(*syscall.Stat_t)
	if int64(stat.Dev) != int64(before.Dev) || uint64(stat.Ino) != uint64(before.Ino) {
		file.Close()
		return nil, errors.New("managed file changed while opening")
	}
	return file, nil
}

// CreateDirectoryAt creates exactly one private owned staging directory. The
// caller tracks this reserved name for cleanup even if a later step fails.
func CreateDirectoryAt(parent *os.File, name string, owner uint32) (*os.File, error) {
	if !validName(name) {
		return nil, errors.New("expected one new directory name")
	}
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return prepareCreated(os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name)), true, owner)
}

func CreateRegularAt(parent *os.File, name string, owner uint32) (*os.File, error) {
	if !validName(name) {
		return nil, errors.New("expected one new regular-file name")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return prepareCreated(os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name)), false, owner)
}

func prepareCreated(file *os.File, directory bool, owner uint32) (*os.File, error) {
	info, err := file.Stat()
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != owner || (directory && !info.IsDir()) || (!directory && (!info.Mode().IsRegular() || stat.Nlink != 1)) {
			err = errors.New("new object identity is unsafe")
		}
	}
	if err == nil {
		err = ResetCreatedACL(file)
	}
	if err == nil {
		_, err = Check(file, directory, owner)
	}
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}
