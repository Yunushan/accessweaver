//go:build linux || darwin || freebsd || openbsd

package fileidentity

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
)

func fromFile(file *os.File) (State, error) {
	if file == nil {
		return State{}, ErrUnavailable
	}
	defer runtime.KeepAlive(file)
	connection, err := file.SyscallConn()
	if err != nil {
		return State{}, ErrUnavailable
	}
	var result State
	var queryErr error
	// Control retains the borrowed descriptor. File.Stat obtains every field
	// from one fstat snapshot and never reads data or changes the file offset.
	// Its nested descriptor reference is safe; a concurrent Close may refuse.
	err = connection.Control(func(_ uintptr) {
		info, err := file.Stat()
		if err != nil {
			queryErr = ErrUnavailable
			return
		}
		result, queryErr = unixState(info)
	})
	if err != nil || queryErr != nil {
		return State{}, ErrUnavailable
	}
	return result, nil
}

func fromPath(path string, followLinks bool) (State, error) {
	if path == "" || strings.ContainsRune(path, '\x00') {
		return State{}, ErrUnavailable
	}
	// Stat and Lstat issue metadata syscalls. In particular they never open a
	// FIFO, device, or ordinary file for data, even for a nonregular leaf.
	stat := os.Lstat
	if followLinks {
		stat = os.Stat
	}
	info, err := stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, os.ErrNotExist
		}
		return State{}, ErrUnavailable
	}
	return unixState(info)
}

func unixState(info os.FileInfo) (State, error) {
	if info == nil {
		return State{}, ErrUnavailable
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native == nil {
		return State{}, ErrUnavailable
	}
	var id ID
	id.Volume = uint64(native.Dev)
	binary.LittleEndian.PutUint64(id.FileID[:8], uint64(native.Ino))
	kind := Other
	switch mode := info.Mode(); {
	case mode&os.ModeSymlink != 0:
		kind = Reparse
	case mode.IsRegular():
		kind = Regular
	case mode.IsDir():
		kind = Directory
	}
	return State{ID: id, Kind: kind, Size: info.Size(), Modified: info.ModTime()}, nil
}
