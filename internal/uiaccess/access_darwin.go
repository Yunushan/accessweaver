//go:build darwin

package uiaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

func RequireUnelevated() error {
	if os.Geteuid() == 0 {
		return errors.New("run the dashboard as your normal desktop user; use separately authorized CLI elevation for administrative operations")
	}
	return nil
}

// Inspect each actual ancestor through a no-follow descriptor. Read/search ACLs
// may be legitimate on ancestors; mutation grants cannot protect a private child.
func openLauncherParent(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("dashboard session parent must be a canonical absolute directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	check := func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) ||
			(info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return errors.New("dashboard session parent is writable or owned by another user")
		}
		return darwintrust.CheckReadOnlyACL(file)
	}
	if err := check(current); err != nil {
		current.Close()
		return nil, err
	}
	if path == "/" {
		return current, nil
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		fd, err := unix.Openat(int(current.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			current.Close()
			return nil, err
		}
		next := os.NewFile(uintptr(fd), filepath.Join(current.Name(), name))
		current.Close()
		if err := check(next); err != nil {
			next.Close()
			return nil, fmt.Errorf("untrusted dashboard session parent: %w", err)
		}
		current = next
	}
	return current, nil
}

func checkParents(path string) error {
	parent, err := openLauncherParent(path)
	if err != nil {
		return err
	}
	return parent.Close()
}

func createPrivateDirectory(path string) error {
	parent, err := openLauncherParent(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	created := os.NewFile(uintptr(fd), path)
	return errors.Join(preparePrivateObject(created, true), created.Close())
}

func createPrivateFile(path string) (*os.File, error) {
	parent, err := openLauncherParent(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	created := os.NewFile(uintptr(fd), path)
	if err := preparePrivateObject(created, false); err != nil {
		return nil, errors.Join(err, created.Close())
	}
	return created, nil
}

// Only exclusively created objects reach this function. Clear inherited access
// and disable reinheritance on the held object before any credential is written.
// Never change a preexisting cache or ancestor ACL.
func preparePrivateObject(file *os.File, directory bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != mode ||
		(directory && !info.IsDir()) || (!directory && (!info.Mode().IsRegular() || stat.Nlink != 1)) {
		return errors.New("new dashboard session object has unsafe identity or permissions")
	}
	return darwintrust.ResetCreatedACL(file)
}
