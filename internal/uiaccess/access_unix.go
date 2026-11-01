//go:build !windows

package uiaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func RequireUnelevated() error {
	if os.Geteuid() == 0 {
		return errors.New("run the dashboard as your normal desktop user; use separately authorized CLI elevation for administrative operations")
	}
	return nil
}

func checkParents(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("dashboard session parent must be a real directory: %s", path)
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("dashboard session parent is writable or owned by another user: %s", path)
		}
		next := filepath.Dir(path)
		if next == path {
			return nil
		}
		path = next
	}
}

func createPrivateDirectory(path string) error { return os.Mkdir(path, 0700) }
