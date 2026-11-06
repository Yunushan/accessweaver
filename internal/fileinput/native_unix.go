//go:build linux || darwin || freebsd || openbsd

package fileinput

import (
	"encoding/binary"
	"errors"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func absoluteName(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return "", ErrUnavailable
	}
	if filepath.IsAbs(path) {
		return path, nil
	}
	cwd, e := os.Getwd()
	if e != nil {
		return "", e
	}
	return cwd + string(os.PathSeparator) + path, nil
}
func unixState(info os.FileInfo) (fileidentity.State, error) {
	if info == nil {
		return fileidentity.State{}, ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fileidentity.State{}, ErrUnavailable
	}
	var id fileidentity.ID
	id.Volume = uint64(st.Dev)
	binary.LittleEndian.PutUint64(id.FileID[:8], uint64(st.Ino))
	kind := fileidentity.Other
	switch mode := info.Mode(); {
	case mode&os.ModeSymlink != 0:
		kind = fileidentity.Reparse
	case mode.IsRegular():
		kind = fileidentity.Regular
	case mode.IsDir():
		kind = fileidentity.Directory
	}
	return fileidentity.State{ID: id, Kind: kind, Size: info.Size(), Modified: info.ModTime()}, nil
}
func stateFromFile(f *os.File) (s fileidentity.State, e error) {
	if f == nil {
		return s, ErrUnavailable
	}
	c, e := f.SyscallConn()
	if e != nil {
		return s, e
	}
	var q error
	e = c.Control(func(_ uintptr) {
		info, cause := f.Stat()
		if cause != nil {
			q = cause
			return
		}
		s, q = unixState(info)
	})
	return s, errors.Join(e, q)
}
func stateFromPath(path string, follow bool) (fileidentity.State, error) {
	stat := os.Lstat
	if follow {
		stat = os.Stat
	}
	info, e := stat(path)
	if e != nil {
		return fileidentity.State{}, e
	}
	return unixState(info)
}
func openInput(path string) (input, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if e != nil {
		return nil, e
	}
	return &fileOwner{File: f}, nil
}
func openDirectory(path string) (*os.File, error) {
	name, e := absoluteName(path)
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if e != nil {
		return nil, e
	}
	s, e := stateFromFile(f)
	if e != nil || s.Kind != fileidentity.Directory {
		return nil, errors.Join(ErrUnavailable, e, f.Close())
	}
	return f, nil
}
func stateAt(parent *os.File, name string, follow bool) (s fileidentity.State, err error) {
	c, e := parent.SyscallConn()
	if e != nil {
		return s, e
	}
	var st unix.Stat_t
	var query error
	flags := 0
	if !follow {
		flags = unix.AT_SYMLINK_NOFOLLOW
	}
	e = c.Control(func(fd uintptr) { query = unix.Fstatat(int(fd), name, &st, flags) })
	if e != nil || query != nil {
		return s, errors.Join(e, query)
	}
	kind := fileidentity.Other
	switch uint32(st.Mode) & unix.S_IFMT {
	case unix.S_IFREG:
		kind = fileidentity.Regular
	case unix.S_IFDIR:
		kind = fileidentity.Directory
	case unix.S_IFLNK:
		kind = fileidentity.Reparse
	}
	var id fileidentity.ID
	id.Volume = uint64(st.Dev)
	binary.LittleEndian.PutUint64(id.FileID[:8], uint64(st.Ino))
	return fileidentity.State{ID: id, Kind: kind, Size: st.Size, Modified: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC()}, nil
}
