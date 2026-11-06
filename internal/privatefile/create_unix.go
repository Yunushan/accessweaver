//go:build !windows && !darwin

package privatefile

import (
	"errors"
	"os"
	"syscall"
)

var errPrivateFileUnavailable = errors.New("private file is unavailable")

func Create(path string) (*os.File, error) {
	owner := os.Geteuid()
	if owner < 0 || owner != os.Getuid() {
		return nil, errPrivateFileUnavailable
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*os.File, error) {
		// Preserve the exclusively created empty file on uncertain validation.
		return nil, errors.Join(errPrivateFileUnavailable, cause, file.Close())
	}
	private := func(info os.FileInfo) bool {
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && info.Mode().IsRegular() && info.Mode() == 0600 &&
			stat.Uid == uint32(owner) && stat.Nlink == 1 && info.Size() == 0
	}
	before, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !private(before) {
		return fail(nil)
	}
	named, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	after, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if os.Geteuid() != owner || os.Getuid() != owner || !private(after) || !private(named) ||
		!os.SameFile(before, after) || !os.SameFile(after, named) {
		return fail(nil)
	}
	return file, nil
}
