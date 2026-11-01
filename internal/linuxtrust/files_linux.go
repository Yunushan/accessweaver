//go:build linux

// Package linuxtrust checks protected local policy and input objects. Runtime
// authority always uses owner 0; in-process fixtures may use their test UID.
package linuxtrust

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const pathOnly = 0x200000

func Check(file *os.File, directory bool, owner uint32) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("managed object requires trusted ownership and no group/other write or set-ID permissions")
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return nil, errors.New("managed object has the wrong file type")
	}
	if !directory && stat.Nlink != 1 {
		return nil, errors.New("managed regular files require exactly one hard link")
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		return nil, err
	}
	// These local Linux filesystems use POSIX mode/ACL-mask semantics. Other
	// filesystem permission models need independent qualification.
	switch uint64(filesystem.Type) {
	case 0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630:
	default:
		return nil, fmt.Errorf("managed storage filesystem %#x is not qualified", filesystem.Type)
	}
	return info, nil
}
func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/") && strings.IndexByte(name, 0) < 0
}
func OpenDirectoryAt(parent *os.File, name string, owner uint32) (*os.File, error) {
	if !validName(name) {
		return nil, errors.New("expected one directory name")
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if _, err := Check(file, true, owner); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func OpenRootDirectory(path string) (*os.File, error) {
	if !strings.HasPrefix(path, "/") || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("managed directory must be absolute")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
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
	// O_PATH inspects FIFOs/devices/symlinks without opening a driver or waiting.
	fd, err := syscall.Openat(int(parent.Fd()), name, pathOnly|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	probe := os.NewFile(uintptr(fd), name)
	before, err := Check(probe, false, owner)
	probe.Close()
	if err != nil {
		return nil, err
	}
	fd, err = syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	after, err := Check(file, false, owner)
	if err != nil || !os.SameFile(before, after) {
		file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("managed file changed while opening")
	}
	return file, nil
}

// Machine authority must survive ordinary restarts. Volatile and layered
// filesystems require separate persistence qualification, even if modes work.
func CheckPersistent(file *os.File) error {
	var filesystem syscall.Statfs_t
	if err := syscall.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		return err
	}
	switch uint64(filesystem.Type) {
	case 0xef53, 0x58465342, 0x9123683e:
		return nil
	}
	return fmt.Errorf("machine policy needs qualified persistent storage; filesystem %#x is unsupported", filesystem.Type)
}

// ResetCreatedACL is only for newly created product objects, never a reader or
// an existing administrator-owned source. Explicit modes alone can retain an
// inherited named-user entry that denies a desktop user the intended read.
func ResetCreatedACL(file *os.File, directory bool) error {
	names := []string{"system.posix_acl_access"}
	if directory {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		value, err := syscall.BytePtrFromString(name)
		if err != nil {
			return err
		}
		_, _, code := syscall.Syscall(syscall.SYS_FREMOVEXATTR, file.Fd(), uintptr(unsafe.Pointer(value)), 0)
		if code != 0 && !errors.Is(code, syscall.ENODATA) && !errors.Is(code, syscall.ENOTSUP) {
			return code
		}
	}
	return nil
}
