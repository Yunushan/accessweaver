//go:build darwin && (amd64 || arm64)

package privatefile

import (
	"errors"
	"os"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

var errHistoryExportPrivate = errors.New("private workflow history export file is unavailable")

func Create(path string) (*os.File, error) {
	owner := os.Geteuid()
	if owner < 0 || owner != os.Getuid() {
		return nil, errHistoryExportPrivate
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*os.File, error) {
		return nil, errors.Join(errHistoryExportPrivate, cause, file.Close())
	}
	before, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || stat.Uid != uint32(owner) || stat.Nlink != 1 || stat.Flags != 0 || before.Size() != 0 {
		return fail(nil)
	}
	// Reject every inherited ACE while the exclusive file is still empty.
	// Clearing a read grant cannot revoke a reader admitted before that reset.
	if _, err := darwintrust.Check(file, false, uint32(owner)); err != nil {
		return fail(err)
	}
	if err := darwintrust.CheckEmptyACL(file); err != nil {
		return fail(err)
	}
	after, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	named, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	final, ok := after.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != owner || os.Getuid() != owner || !os.SameFile(before, after) || !os.SameFile(after, named) || !named.Mode().IsRegular() || after.Size() != 0 || after.Mode().Perm() != 0600 || final.Uid != uint32(owner) || final.Nlink != 1 || final.Flags != 0 {
		return fail(nil)
	}
	return file, nil
}
